//! The [`Clock`] port: time and sleeping, as a dependency rather than ambient.
//!
//! The engine reads time only through this port, so backoff, timeouts and the
//! run log's timestamps are reproducible in tests: `ks-testing`'s
//! [`FakeClock`] starts at a fixed instant, and `sleep` advances it instantly
//! while recording the requested duration.
//!
//! [`FakeClock`]: https://docs.rs/ks-testing/latest/ks_testing/clock/struct.FakeClock.html

use std::time::{Duration, SystemTime};

use super::BoxFuture;

/// The `Clock` port: what time is it, and wait a bit.
///
/// Within a run, [`Clock::now`] must never go backwards — the run log's
/// ordering depends on it. Wall-clock adjustments land in the next run, not
/// mid-run.
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> SystemTime;

    /// Waits (at least) `duration`. Implementations may wake early only for
    /// [`Duration::ZERO`], which returns immediately.
    fn sleep<'a>(&'a self, duration: Duration) -> BoxFuture<'a, ()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_clock_trait_is_dyn_compatible() {
        assert_send_sync::<dyn Clock>();
    }
}
