//! Fake for the [`RunLock`] port: an in-memory lease table driven by a
//! [`Clock`], so expiry is a test's to command — hand it a [`FakeClock`],
//! advance the clock, and watch a lease die — plus the conformance kit every
//! adapter must pass.
//!
//! [`Clock`]: ks_core::ports::clock::Clock
//! [`FakeClock`]: crate::clock::FakeClock

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::clock::Clock;
use ks_core::ports::run_lock::{Lease, LockError, LockKey, RunLock};

/// Every key's state: the current lease (live, or expired but not yet
/// replaced), and the highest fencing token ever granted. The token count
/// outlives the lease — releasing must not hand the key's next holder a
/// token the previous one already saw.
#[derive(Default)]
struct State {
    leases: BTreeMap<LockKey, Lease>,
    tokens: BTreeMap<LockKey, u64>,
}

/// An in-memory [`RunLock`] — the stand-in for the hosted adapter's Durable
/// Object per (account, module)
/// ([#175](https://github.com/Keep-Shipping/harness/issues/175)). Leases
/// expire on the [`Clock`] the fake is built on, so a test drives a takeover
/// by advancing a [`FakeClock`](crate::clock::FakeClock) instead of waiting.
///
/// ```
/// use std::sync::Arc;
/// use std::time::Duration;
/// use ks_core::ids::RunId;
/// use ks_core::ports::run_lock::{LockKey, RunLock};
/// use ks_testing::{block_on, clock::FakeClock, run_lock::MemoryRunLock};
///
/// let clock = Arc::new(FakeClock::new());
/// let lock = MemoryRunLock::new(clock.clone());
/// let key = LockKey::new("platform", "network").expect("a valid key");
/// let holder = RunId::from_parts(0, 1);
/// let lease = block_on(lock.acquire(&key, &holder, Duration::from_secs(60)))
///     .expect("a free key is granted");
/// assert_eq!(lease.token, 1);
/// let again = block_on(lock.acquire(&key, &holder, Duration::from_secs(60)))
///     .expect("the holder asks again");
/// assert_eq!(again, lease, "a holder's re-acquire is idempotent");
/// ```
pub struct MemoryRunLock {
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
}

impl MemoryRunLock {
    /// Creates an empty fake whose leases expire on `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> MemoryRunLock {
        MemoryRunLock { clock, state: Mutex::new(State::default()) }
    }

    /// One `ttl` from `now`, or [`LockError::Unavailable`] for a ttl the
    /// clock cannot represent — the port promises `LockError`, never a panic.
    fn expiry(&self, now: SystemTime, ttl: Duration) -> Result<SystemTime, LockError> {
        now.checked_add(ttl).ok_or_else(|| LockError::Unavailable {
            message: "the ttl overflows the clock".to_string(),
        })
    }
}

/// A poisoned mutex is not the fake's business: the guard comes back even if
/// another thread panicked while holding it, and the port contract stays
/// intact.
fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl RunLock for MemoryRunLock {
    fn acquire<'a>(
        &'a self,
        key: &'a LockKey,
        holder: &'a RunId,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<Lease, LockError>> {
        let result = {
            let now = self.clock.now();
            let mut state = lock_or_recover(&self.state);
            // `.cloned()` detaches the borrow, so a fresh grant below can
            // insert into the map.
            match state.leases.get(key).filter(|lease| lease.expires_at > now).cloned() {
                // The holder asking again is the Worker-restarted-mid-run
                // case: the same lease comes back, nothing is extended.
                Some(lease) if lease.holder == *holder => Ok(lease),
                Some(lease) => {
                    Err(LockError::Held { holder: lease.holder, until: lease.expires_at })
                }
                None => self.expiry(now, ttl).map(|expires_at| {
                    let token = state.tokens.get(key).copied().unwrap_or(0) + 1;
                    let lease =
                        Lease { key: key.clone(), holder: holder.clone(), token, expires_at };
                    state.tokens.insert(key.clone(), token);
                    state.leases.insert(key.clone(), lease.clone());
                    lease
                }),
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn renew<'a>(
        &'a self,
        lease: &'a Lease,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<Lease, LockError>> {
        let result = {
            let now = self.clock.now();
            let mut state = lock_or_recover(&self.state);
            match state.leases.get_mut(&lease.key) {
                Some(live)
                    if live.expires_at > now
                        && live.token == lease.token
                        && live.holder == lease.holder =>
                {
                    match self.expiry(now, ttl) {
                        Ok(expires_at) => {
                            live.expires_at = expires_at;
                            Ok(live.clone())
                        }
                        Err(error) => Err(error),
                    }
                }
                _ => Err(LockError::Lost),
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn release<'a>(&'a self, lease: &'a Lease) -> BoxFuture<'a, Result<(), LockError>> {
        let result = {
            let now = self.clock.now();
            let mut state = lock_or_recover(&self.state);
            let live = state.leases.get(&lease.key).is_some_and(|current| {
                current.expires_at > now
                    && current.token == lease.token
                    && current.holder == lease.holder
            });
            // The token count stays behind on purpose: the next grant must
            // never reuse a token this key has already handed out.
            if live {
                state.leases.remove(&lease.key);
                Ok(())
            } else {
                Err(LockError::Lost)
            }
        };
        Box::pin(std::future::ready(result))
    }
}

/// The `RunLock` conformance kit: this fake and every real adapter — the
/// Durable Object per (account, module) in the hosted deployment, a lockfile
/// in a local one — must pass it.
///
/// `clock` must be the same clock the adapter derives [`Lease::expires_at`]
/// from, so the kit can drive expiry: on a
/// [`FakeClock`](crate::clock::FakeClock) a lease dies the instant the kit
/// advances the clock, on a real one it waits out the second it leases for.
///
/// The kit leaves no live leases behind: it releases everything it still
/// holds before returning, so it can be re-run against a persistent adapter
/// — a retried CI job against the same Durable Object starts clean.
pub async fn conformance(lock: &dyn RunLock, clock: &dyn Clock) {
    let holder = RunId::from_parts(1_700_000_000_000, 1);
    let other = RunId::from_parts(1_700_000_000_000, 2);
    let long = Duration::from_secs(3_600);
    let short = Duration::from_secs(1);
    let acquire = async |key: &LockKey, run: &RunId, ttl| match lock.acquire(key, run, ttl).await {
        Ok(lease) => lease,
        Err(error) => panic!("run_lock conformance: acquire {key} failed: {error}"),
    };

    // At most one live lease per key — and the holder's own re-acquire is
    // idempotent, which is the workflow-resumed-after-a-restart case.
    let key = LockKey::new("platform", "network").expect("conformance: a valid key");
    let first = acquire(&key, &holder, long).await;
    let again = acquire(&key, &holder, long).await;
    assert_eq!(
        again, first,
        "conformance: a holder's re-acquire must return its live lease unchanged"
    );

    // A second run is held, and told by whom until when.
    let held = lock.acquire(&key, &other, long).await;
    assert!(
        matches!(
            &held,
            Err(LockError::Held { holder, until })
                if *holder == first.holder && *until == first.expires_at
        ),
        "conformance: a contended acquire must be Held by the live holder, got {held:?}"
    );

    // A different module, and a different account: independent locks, never
    // one global gate — and neither grant disturbs the lease on `key`.
    let database = LockKey::new("platform", "database").expect("conformance: a valid key");
    let elsewhere = acquire(&database, &other, long).await;
    let next_door = LockKey::new("elsewhere", "network").expect("conformance: a valid key");
    let next_account = acquire(&next_door, &other, long).await;
    let still = lock.acquire(&key, &other, long).await;
    assert!(
        matches!(&still, Err(LockError::Held { holder, .. }) if *holder == first.holder),
        "conformance: grants elsewhere must not disturb the live lease, got {still:?}"
    );

    // Renewal keeps the token and moves the expiry.
    clock.sleep(Duration::from_secs(10)).await;
    let renewed = lock
        .renew(&first, long)
        .await
        .unwrap_or_else(|error| panic!("run_lock conformance: a live lease renews: {error}"));
    assert_eq!(renewed.token, first.token, "conformance: renewal must not mint a token");
    assert!(renewed.expires_at > first.expires_at, "conformance: renewal must move the expiry");

    // Release, then the key is grantable again — at a strictly higher token.
    lock.release(&renewed)
        .await
        .unwrap_or_else(|error| panic!("run_lock conformance: the holder releases: {error}"));
    let reissued = acquire(&key, &other, long).await;
    assert!(reissued.token > first.token, "conformance: every grant mints a higher fencing token");
    let twice = lock.release(&renewed).await;
    assert!(
        matches!(twice, Err(LockError::Lost)),
        "conformance: releasing twice must be Lost, got {twice:?}"
    );

    // Expiry: a lapsed lease is taken over, and the old holder's renew and
    // release are Lost — its token is stale. The stale release must not free
    // the new holder's lease.
    let queue = LockKey::new("platform", "queue").expect("conformance: a valid key");
    let mortal = acquire(&queue, &holder, short).await;
    clock.sleep(short + short).await;
    let takeover = acquire(&queue, &other, long).await;
    assert!(
        takeover.token > mortal.token,
        "conformance: a takeover mints a higher token than the lease it replaced"
    );
    let stale_renew = lock.renew(&mortal, long).await;
    assert!(
        matches!(stale_renew, Err(LockError::Lost)),
        "conformance: an expired holder's renew must be Lost, got {stale_renew:?}"
    );
    let stale_release = lock.release(&mortal).await;
    assert!(
        matches!(stale_release, Err(LockError::Lost)),
        "conformance: an expired holder's release must be Lost, got {stale_release:?}"
    );
    assert!(
        lock.renew(&takeover, long).await.is_ok(),
        "conformance: a stale release must not free the new holder's lease"
    );

    // A lease the adapter never issued is Lost, not acted on.
    let forged = Lease { key: key.clone(), holder, token: 0, expires_at: clock.now() + long };
    let forged_renew = lock.renew(&forged, long).await;
    assert!(
        matches!(forged_renew, Err(LockError::Lost)),
        "conformance: a lease the adapter never issued must be Lost, got {forged_renew:?}"
    );

    // The race: many threads ask for one key at once; exactly one lease
    // exists afterwards, and every loser was told it is held by the winner.
    const RACERS: usize = 8;
    let raced = LockKey::new("platform", "race").expect("conformance: a valid key");
    let raced = &raced;
    let outcomes: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..RACERS)
            .map(|n| {
                scope.spawn(move || {
                    let run = RunId::from_parts(1_700_000_000_000, n as u128 + 10);
                    crate::block_on(lock.acquire(raced, &run, long))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("conformance: the racer joins"))
            .collect::<Vec<_>>()
    });
    let granted: Vec<&Lease> =
        outcomes.iter().filter_map(|outcome| outcome.as_ref().ok()).collect();
    assert_eq!(
        granted.len(),
        1,
        "conformance: a race on one key grants exactly one lease, got {outcomes:?}"
    );
    let winner = &granted[0].holder;
    for refused in outcomes.iter().filter_map(|outcome| outcome.as_ref().err()) {
        assert!(
            matches!(refused, LockError::Held { holder, .. } if holder == winner),
            "conformance: every loser must be Held by the winner, got {refused}"
        );
    }

    // Nothing stays held: a persistent adapter must come out of the kit the
    // way it went in, or the kit could never run twice against it.
    for lease in [granted[0], &elsewhere, &next_account, &reissued, &takeover] {
        let released = lock.release(lease).await;
        assert!(
            released.is_ok(),
            "conformance: the cleanup release of {} must succeed: {released:?}",
            lease.key
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;
    use crate::clock::FakeClock;

    #[test]
    fn the_fake_passes_conformance() {
        let clock = Arc::new(FakeClock::new());
        let lock = MemoryRunLock::new(clock.clone());
        block_on(conformance(&lock, clock.as_ref()));
        // A second run against the same, now-populated lock: the kit's
        // cleanup left nothing held, and the climbing token counts hold.
        block_on(conformance(&lock, clock.as_ref()));
    }
}
