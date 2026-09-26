//! Fake for the [`Clock`] port: a fixed clock you advance by hand. Sleeps are
//! instant and recorded.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use ks_core::ports::BoxFuture;
use ks_core::ports::clock::Clock;

/// A [`Clock`] that only moves when the test moves it.
///
/// Starts at `2023-11-14T22:13:20Z` (Unix time 1_700_000_000 — the default
/// [`FakeClock::new`] instant, so fixtures read the same everywhere), and
/// [`sleep`](Clock::sleep) returns immediately after advancing the clock and
/// recording the duration.
///
/// ```
/// use std::time::Duration;
/// use ks_core::ports::clock::Clock;
/// use ks_testing::{block_on, clock::FakeClock};
///
/// let clock = FakeClock::new();
/// block_on(clock.sleep(Duration::from_secs(5)));
/// assert_eq!(clock.elapsed_since_start(), Duration::from_secs(5));
/// assert_eq!(clock.sleeps(), vec![Duration::from_secs(5)]);
/// ```
pub struct FakeClock {
    now: Mutex<SystemTime>,
    sleeps: Mutex<Vec<Duration>>,
}

impl Default for FakeClock {
    fn default() -> FakeClock {
        FakeClock {
            now: Mutex::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            sleeps: Mutex::new(Vec::new()),
        }
    }
}

impl FakeClock {
    /// Creates a fake clock at Unix time 1_700_000_000.
    pub fn new() -> FakeClock {
        FakeClock::default()
    }

    /// Moves the clock forward by `duration`.
    pub fn advance(&self, duration: Duration) {
        let mut now = self.now.lock().expect("fake clock");
        *now = now.checked_add(duration).expect("the fake clock would overflow SystemTime");
    }

    /// Every duration passed to [`sleep`](Clock::sleep), oldest first.
    pub fn sleeps(&self) -> Vec<Duration> {
        self.sleeps.lock().expect("fake clock sleep record").clone()
    }

    /// Time since the clock's start instant.
    pub fn elapsed_since_start(&self) -> Duration {
        self.now().duration_since(FakeClock::default_start()).expect("the clock never moves back")
    }

    /// The instant a fresh [`FakeClock`] starts at.
    pub fn default_start() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        *self.now.lock().expect("fake clock")
    }

    fn sleep<'a>(&'a self, duration: Duration) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.advance(duration);
            self.sleeps.lock().expect("fake clock sleep record").push(duration);
        })
    }
}

/// The `Clock` conformance kit: time never moves backwards across a sleep,
/// and a zero sleep returns immediately.
pub async fn conformance(clock: &dyn Clock) {
    let before = clock.now();
    clock.sleep(Duration::ZERO).await;
    let after = clock.now();
    assert!(after >= before, "clock conformance: `now` must never go backwards within a run");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    #[test]
    fn sleep_advances_time_instantly_and_records() {
        let clock = FakeClock::new();
        assert_eq!(clock.now(), FakeClock::default_start());
        block_on(clock.sleep(Duration::from_secs(2)));
        block_on(clock.sleep(Duration::from_millis(500)));
        assert_eq!(clock.now(), FakeClock::default_start() + Duration::from_millis(2_500));
        assert_eq!(clock.sleeps(), vec![Duration::from_secs(2), Duration::from_millis(500)]);
    }

    #[test]
    fn the_fake_passes_conformance() {
        block_on(conformance(&FakeClock::new()));
    }
}
