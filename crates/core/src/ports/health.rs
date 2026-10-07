//! The shared health vocabulary: the states every deploy target reports, so
//! `wait: healthy, 5m` means the same thing on a cluster, a shell and a
//! function host
//! ([#52](https://github.com/Keep-Shipping/harness/issues/52),
//! [#78](https://github.com/Keep-Shipping/harness/issues/78)).
//!
//! Each port owns its own idea of what "up" means — a Kubernetes rollout has
//! available replicas, a host has a probe exit code, a function host has
//! invocation results. Without one shared vocabulary a step that says
//! `wait: healthy` would mean three different things, and a workflow that
//! deploys to two targets could gate on one and silently skip the other. So
//! every port's health method returns a [`HealthReport`], and every adapter
//! maps its target's signals onto [`Health`].
//!
//! # Why the states are exactly these five
//!
//! [`Health`] splits the question a health gate actually asks — *has it
//! settled, and did it land healthy?* — from the question it must never ask
//! implicitly — *is it healthy right now?* An adapter that has not talked to
//! its target yet has an answer to neither, and must say
//! [`Health::NoData`] rather than guess.
//!
//! # Silence is not health
//!
//! [`HealthReport::satisfies`] matches states exactly, so [`Health::NoData`]
//! never satisfies [`Health::Healthy`]. This is the load-bearing rule of the
//! module: a brand-new deployment, an unreachable endpoint behind a load
//! balancer, or a probe that has not run yet all look like "nothing to
//! report", and a gate that treats silence as success will pass a deploy that
//! never served a request. Adapters must report [`Health::NoData`] rather
//! than an optimistic default when they genuinely have no observation, and a
//! waiter keeps polling until the deadline instead of accepting it.

use std::fmt;

/// What a deploy target reports about itself.
///
/// Adapters translate their target's signals into exactly one of these; the
/// engine and steps only ever compare them for equality — deliberately no
/// `Ord`, because any derived ranking puts [`Health::NoData`] last, and a
/// gate written as `state >= Health::Failed` would then treat silence as
/// worse than a hard failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Health {
    /// Serving normally and past every readiness gate. The only state that
    /// satisfies a `wait: healthy` gate.
    Healthy,
    /// Still moving towards its goal — a rollout replacing pods, a version
    /// warming its first instance. Not a failure, and not yet a success:
    /// waiters keep polling.
    Progressing,
    /// Serving, but below the target's own bar: some replicas failing,
    /// elevated error rate, a degraded dependency. Distinct from
    /// [`Health::Failed`], because a degraded target can still take traffic
    /// and the caller may choose to roll back rather than stop.
    Degraded,
    /// The rollout did not reach a healthy state and is no longer expected
    /// to. A waiter that sees this stops immediately instead of burning the
    /// rest of its deadline.
    Failed,
    /// The adapter has no observation — the target does not exist yet, the
    /// probe has not run, or the reporting call itself found nothing to say.
    ///
    /// It is not [`Health::Healthy`] and must never be treated as such (see
    /// the [module documentation](self)); a gate that passes on silence is
    /// the bug this variant exists to prevent.
    NoData,
}

impl Health {
    /// The state's lowercase name, as it appears in run output, e.g.
    /// `"no-data"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Health::Healthy => "healthy",
            Health::Progressing => "progressing",
            Health::Degraded => "degraded",
            Health::Failed => "failed",
            Health::NoData => "no-data",
        }
    }

    /// Whether the target has stopped moving: [`Health::Healthy`] or
    /// [`Health::Failed`]. A waiter uses this to stop early — a rollout is
    /// done when it settles, not when its deadline expires.
    ///
    /// [`Health::Progressing`], [`Health::Degraded`] and [`Health::NoData`]
    /// are all still moving, or not moving *enough* to call either way, so
    /// all three keep the waiter polling.
    pub fn is_settled(&self) -> bool {
        matches!(self, Health::Healthy | Health::Failed)
    }
}

impl fmt::Display for Health {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One observation of a deploy target: the state, and why.
///
/// Adapters construct these and callers compare them; both halves are private
/// so a report cannot claim a state it did not observe, or lose the reason
/// that made a `Degraded` distinguishable from a `Progressing`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    state: Health,
    reason: Option<String>,
}

impl HealthReport {
    /// A report of `state` with no further explanation.
    pub fn new(state: Health) -> Self {
        HealthReport { state, reason: None }
    }

    /// A report of `state` explained by `reason`, e.g. `"3 of 5 replicas
    /// ready"` or `"probe exited 1"`. The reason is what a run log shows
    /// next to a waiting gate, so an adapter should record the target's own
    /// wording rather than an interpretation of it.
    pub fn with_reason(state: Health, reason: impl Into<String>) -> Self {
        HealthReport { state, reason: Some(reason.into()) }
    }

    pub fn state(&self) -> Health {
        self.state
    }

    /// Why the state is what it is, if the adapter said.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Whether this report satisfies a gate waiting for `want` — an exact
    /// state match, never a "close enough".
    ///
    /// The exactness is the contract. In particular
    /// [`Health::NoData`] does **not** satisfy [`Health::Healthy`]: a target
    /// that has not reported anything (newly created, unreachable behind a
    /// load balancer, probe never run) has not been shown to work, and a
    /// gate that lets it through reports a successful deploy that served
    /// nothing. Adapters that have no observation must say
    /// [`Health::NoData`] and let the waiter run out its deadline or fail.
    pub fn satisfies(&self, want: Health) -> bool {
        self.state == want
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_health_vocabulary_is_send_and_sync() {
        // No trait here — the ports that return these hold them across an
        // await, so the shapes themselves must cross threads.
        assert_send_sync::<Health>();
        assert_send_sync::<HealthReport>();
    }

    #[test]
    fn states_report_their_wire_names() {
        assert_eq!(Health::Healthy.as_str(), "healthy");
        assert_eq!(Health::Progressing.as_str(), "progressing");
        assert_eq!(Health::Degraded.as_str(), "degraded");
        assert_eq!(Health::Failed.as_str(), "failed");
        assert_eq!(Health::NoData.as_str(), "no-data");
        for state in
            [Health::Healthy, Health::Progressing, Health::Degraded, Health::Failed, Health::NoData]
        {
            assert_eq!(state.to_string(), state.as_str());
        }
    }

    #[test]
    fn only_healthy_and_failed_have_settled() {
        assert!(Health::Healthy.is_settled());
        assert!(Health::Failed.is_settled());
        assert!(!Health::Progressing.is_settled());
        assert!(!Health::Degraded.is_settled());
        assert!(!Health::NoData.is_settled());
    }

    #[test]
    fn no_data_never_passes_a_healthy_gate() {
        // The point of the module: silence is not success.
        let silent = HealthReport::with_reason(Health::NoData, "no traffic yet");
        assert!(!silent.satisfies(Health::Healthy));
        assert!(!silent.satisfies(Health::Progressing));
        assert!(!silent.satisfies(Health::Degraded));
        assert!(!silent.satisfies(Health::Failed));
        // It does satisfy a gate that explicitly asks for no-data.
        assert!(silent.satisfies(Health::NoData));
        // And it is not settled, so a waiter keeps polling rather than
        // declaring the rollout done.
        assert!(!silent.state().is_settled());
    }

    #[test]
    fn satisfies_is_an_exact_match_not_a_ranking() {
        assert!(HealthReport::new(Health::Healthy).satisfies(Health::Healthy));
        // Healthy is not "good enough" for a gate asking for a different
        // state, and nothing is good enough for everything.
        assert!(!HealthReport::new(Health::Healthy).satisfies(Health::Degraded));
        assert!(!HealthReport::new(Health::Degraded).satisfies(Health::Healthy));
        assert!(HealthReport::new(Health::Degraded).satisfies(Health::Degraded));
        assert!(HealthReport::new(Health::Failed).satisfies(Health::Failed));
    }

    #[test]
    fn states_compare_by_equality_only() {
        // There is deliberately no Ord: the states do not form a severity
        // order (NoData is not "worse" than Failed, it is a different
        // question), so a gate can only ask for one exact state.
        let states = [
            Health::Healthy,
            Health::Progressing,
            Health::Degraded,
            Health::Failed,
            Health::NoData,
        ];
        for (i, a) in states.iter().enumerate() {
            for (j, b) in states.iter().enumerate() {
                assert_eq!(*a == *b, i == j, "{a:?} vs {b:?}");
            }
        }
    }

    #[test]
    fn reports_carry_their_reason_verbatim() {
        let bare = HealthReport::new(Health::Progressing);
        assert_eq!(bare.state(), Health::Progressing);
        assert_eq!(bare.reason(), None);

        let explained = HealthReport::with_reason(Health::Degraded, "2 of 5 replicas ready");
        assert_eq!(explained.state(), Health::Degraded);
        assert_eq!(explained.reason(), Some("2 of 5 replicas ready"));
    }

    #[test]
    fn a_failed_report_settles_so_a_waiter_can_stop_early() {
        let failed = HealthReport::with_reason(Health::Failed, "CrashLoopBackOff");
        assert!(failed.satisfies(Health::Failed));
        assert!(failed.state().is_settled());
        assert_eq!(failed.reason(), Some("CrashLoopBackOff"));
    }
}
