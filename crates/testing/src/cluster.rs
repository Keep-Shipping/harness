//! Fake for the [`Cluster`] port: scripted apply, upgrade, rollout and
//! rollback, plus a health script that walks a workload through a rollout and
//! holds at the last state. Never touches the filesystem.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::Mutex;

use ks_core::ports::BoxFuture;
use ks_core::ports::cluster::{
    AuthMethod, Cluster, ClusterError, ClusterRef, Manifest, Revision, Rollout,
};
use ks_core::ports::health::{Health, HealthReport};

/// The kubeconfig context a fresh [`FakeCluster`] reports.
pub const DEFAULT_CONTEXT: &str = "fake-context";
/// The API server a fresh [`FakeCluster`] reports.
pub const DEFAULT_ENDPOINT: &str = "https://fake-cluster.invalid:6443";
/// The first revision a fresh [`FakeCluster`] hands out.
pub const FIRST_REVISION: u32 = 1;

/// Why the fake reports [`Health::NoData`] for a workload it has never been
/// asked to apply: the same wording a real adapter would report for a workload
/// that does not exist yet.
const NO_OBSERVATION: &str = "workload does not exist in this cluster yet";
/// Why the fake reports [`Health::NoData`] once a script is exhausted without
/// ever naming a state — the "the reporting call found nothing" case.
const NOTHING_TO_REPORT: &str = "the fake has no observation for this workload";

/// One call a test can observe on the [`FakeCluster`], oldest first via
/// [`FakeCluster::calls`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterCall {
    /// [`Cluster::apply`] was given these manifest names, in the order given.
    Apply {
        /// The manifest names passed to `apply`.
        names: Vec<String>,
    },
    /// [`Cluster::upgrade`] upgraded this release.
    Upgrade {
        /// The release that was upgraded.
        release: String,
    },
    /// [`Cluster::rollout`] read this workload's rollout.
    Rollout {
        /// The workload that was read.
        name: String,
    },
    /// [`Cluster::health`] was asked about this workload.
    Health {
        /// The workload health was asked about.
        name: String,
    },
    /// [`Cluster::rollback`] asked to move this workload to a revision.
    Rollback {
        /// The workload to roll back.
        name: String,
        /// The revision asked for.
        revision: Revision,
    },
}

/// The fake's mutable state; every accessor goes through one mutex, so the
/// fake is `Send + Sync`.
#[derive(Default)]
struct State {
    /// The health script; the last entry repeats. Every workload walks it from the
    /// start.
    script: VecDeque<HealthReport>,
    /// Workload name -> how far through `script` `health` has walked for *that*
    /// workload. Per workload, never global: one workload's polls must not
    /// consume another workload's rollout.
    cursors: BTreeMap<String, usize>,
    /// Workloads `apply` has accepted.
    applied: BTreeSet<String>,
    /// Revisions the fake still retains; anything else is
    /// [`ClusterError::RevisionUnknown`].
    retained: Vec<Revision>,
    /// Explicit rollouts, by workload name.
    rollouts: BTreeMap<String, Rollout>,
    /// The error the next `apply` fails with, if one is scripted.
    manifest_error: Option<ClusterError>,
    /// The error the next `upgrade` fails with, if one is scripted.
    upgrade_error: Option<ClusterError>,
    /// Every call, oldest first.
    calls: Vec<ClusterCall>,
}

/// A [`Cluster`] you script per test — the stand-in for real Kubernetes
/// adapters
/// ([#52](https://github.com/Keep-Shipping/harness/issues/52)).
///
/// The headline feature is the **health script**:
/// [`with_health_script`](FakeCluster::with_health_script) queues the states
/// `health` answers with, one per call, holding at the last. A test can
/// therefore walk a workload from `Progressing` to `Healthy` and see a waiter
/// poll its way out, or stop at `Degraded` and see it keep waiting. The script
/// is **per workload** — each workload walks it from the start with its own
/// cursor, so polling `Deployment/a` never consumes `Deployment/b`'s rollout.
/// The script only advances once that workload has been
/// [`applied`](Cluster::apply): before that the fake has genuinely observed
/// nothing and answers [`Health::NoData`], which is the silence-is-not-health
/// rule the port is built on.
///
/// Everything else is scripted too — releases to upgrade, an apply that is
/// rejected, the revisions a rollback may name — and every call is recorded.
///
/// ```
/// use ks_core::ports::cluster::{Cluster, Manifest};
/// use ks_core::ports::health::{Health, HealthReport};
/// use ks_testing::{block_on, cluster::FakeCluster};
///
/// let cluster = FakeCluster::new()
/// .with_health_script([Health::Progressing, Health::Progressing, Health::Healthy]);
/// let manifests = [Manifest::new("Deployment/api", b"kind: Deployment").expect("non-empty")];
///
/// // Before the apply there is nothing to report, and silence is not healthy.
/// let silent = block_on(cluster.health("Deployment/api")).expect("a report, not an error");
/// assert!(!silent.satisfies(Health::Healthy));
///
/// block_on(cluster.apply(&manifests)).expect("the manifests are accepted");
/// let states: Vec<Health> = (0..4)
/// .map(|_| block_on(cluster.health("Deployment/api")).expect("a report").state())
/// .collect();
/// assert_eq!(
/// states,
/// vec![Health::Progressing, Health::Progressing, Health::Healthy, Health::Healthy],
/// "the script advances once per call and then holds"
/// );
/// ```
///
/// All mutable state sits behind one mutex, so the fake is `Send + Sync`.
pub struct FakeCluster {
    handle: ClusterRef,
    releases: BTreeMap<String, Rollout>,
    state: Mutex<State>,
}

impl Default for FakeCluster {
    /// The default fake reports the context [`DEFAULT_CONTEXT`] at the endpoint
    /// [`DEFAULT_ENDPOINT`], authenticating by workload identity, retains only
    /// revision [`FIRST_REVISION`], and has no scripted health: an applied
    /// workload reports [`Health::Healthy`] and an unapplied one
    /// [`Health::NoData`].
    fn default() -> FakeCluster {
        FakeCluster {
            handle: ClusterRef::new(
                DEFAULT_CONTEXT,
                DEFAULT_ENDPOINT,
                AuthMethod::WorkloadIdentity,
            )
            .expect("the default handle is well formed"),
            releases: BTreeMap::new(),
            state: Mutex::new(State {
                script: VecDeque::from([HealthReport::new(Health::Healthy)]),
                retained: vec![Revision::new(FIRST_REVISION)],
                ..State::default()
            }),
        }
    }
}

impl FakeCluster {
    /// Creates a fake with nothing applied and no scripted health — until
    /// scripted.
    pub fn new() -> FakeCluster {
        FakeCluster::default()
    }

    /// Queues the states [`Cluster::health`] answers with, one per call; the
    /// last repeats, so a `wait` that polls past the script holds rather than
    /// falling off the end. The script only advances for a workload that has
    /// been applied — an unapplied one always reports [`Health::NoData`].
    ///
    /// The script is **per workload**: every workload walks it from the start,
    /// so polling one workload says nothing about another's rollout. Installing
    /// a script rewinds every workload's cursor, so a fresh transition replays
    /// from its first state.
    ///
    /// An empty script leaves the fake with nothing to report, which is the
    /// "the reporting call found nothing" case rather than a healthy target.
    pub fn with_health_script(self, states: impl IntoIterator<Item = Health>) -> FakeCluster {
        let script: VecDeque<HealthReport> = states.into_iter().map(HealthReport::new).collect();
        {
            let mut state = self.state.lock().expect("fake cluster state");
            state.script = script;
            state.cursors.clear();
        }
        self
    }

    /// Like [`with_health_script`](FakeCluster::with_health_script), but each
    /// state carries the reason a run log would show next to the waiting gate.
    pub fn with_health_reports(
        self,
        reports: impl IntoIterator<Item = HealthReport>,
    ) -> FakeCluster {
        let script: VecDeque<HealthReport> = reports.into_iter().collect();
        {
            let mut state = self.state.lock().expect("fake cluster state");
            state.script = script;
            state.cursors.clear();
        }
        self
    }

    /// The rollout [`Cluster::upgrade`] reports for `release` when it succeeds.
    pub fn with_release(mut self, release: impl Into<String>, rollout: Rollout) -> FakeCluster {
        self.releases.insert(release.into(), rollout);
        self
    }

    /// The rollout [`Cluster::rollout`] reports for `name`, overriding the one
    /// `apply` would have recorded.
    pub fn with_rollout(self, name: impl Into<String>, rollout: Rollout) -> FakeCluster {
        self.state.lock().expect("fake cluster state").rollouts.insert(name.into(), rollout);
        self
    }

    /// Every [`Cluster::apply`] fails with `error` — the rejected-manifest
    /// path, e.g. an admission failure.
    pub fn with_manifest_error(self, error: ClusterError) -> FakeCluster {
        self.state.lock().expect("fake cluster state").manifest_error = Some(error);
        self
    }

    /// Every [`Cluster::upgrade`] fails with `error`.
    pub fn with_upgrade_error(self, error: ClusterError) -> FakeCluster {
        self.state.lock().expect("fake cluster state").upgrade_error = Some(error);
        self
    }

    /// Adds a revision the fake still retains, so [`Cluster::rollback`] may
    /// name it. Any revision not added — or not added by the test — is
    /// [`ClusterError::RevisionUnknown`], never a silent fall back to
    /// whatever is running now.
    pub fn with_rollback_revision(self, revision: Revision) -> FakeCluster {
        {
            let mut state = self.state.lock().expect("fake cluster state");
            state.retained.push(revision);
            state.retained.sort_unstable();
        }
        self
    }

    /// Every call made against the fake, oldest first.
    #[must_use]
    pub fn calls(&self) -> Vec<ClusterCall> {
        self.state.lock().expect("fake cluster state").calls.clone()
    }

    /// The workload names [`Cluster::apply`] has accepted, so far.
    #[must_use]
    pub fn applied_names(&self) -> Vec<String> {
        self.state.lock().expect("fake cluster state").applied.iter().cloned().collect()
    }

    /// The next entry in `name`'s walk through the health script: advancing one
    /// step, holding at the last. Each workload keeps its own cursor, so one
    /// workload's polls never consume another's rollout. A script with nothing
    /// in it is [`Health::NoData`].
    fn next_report(state: &mut State, name: &str) -> HealthReport {
        let Some(last) = state.script.back().cloned() else {
            return HealthReport::with_reason(Health::NoData, NOTHING_TO_REPORT);
        };
        let cursor = state.cursors.entry(name.to_string()).or_insert(0);
        if *cursor >= state.script.len() {
            return last;
        }
        let report = state.script.get(*cursor).cloned();
        *cursor += 1;
        report.unwrap_or(last)
    }

    /// The latest revision the fake retains — the one a successful apply or
    /// upgrade reports when the test scripted no explicit rollout.
    fn latest_revision(state: &State) -> Revision {
        state.retained.last().copied().unwrap_or(Revision::new(FIRST_REVISION))
    }
}

impl fmt::Debug for FakeCluster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().expect("fake cluster state");
        f.debug_struct("FakeCluster")
            .field("releases", &self.releases.len())
            .field("script", &state.script.len())
            .field("cursors", &state.cursors.len())
            .field("applied", &state.applied.len())
            .field("retained", &state.retained.len())
            .field("rollouts", &state.rollouts.len())
            .field("has_manifest_error", &state.manifest_error.is_some())
            .field("has_upgrade_error", &state.upgrade_error.is_some())
            .field("calls", &state.calls.len())
            .finish()
    }
}

impl Cluster for FakeCluster {
    fn apply<'a>(
        &'a self,
        manifests: &'a [Manifest],
    ) -> BoxFuture<'a, Result<Vec<String>, ClusterError>> {
        let result = {
            let mut state = self.state.lock().expect("fake cluster state");
            let names: Vec<String> =
                manifests.iter().map(|manifest| manifest.name().to_string()).collect();
            state.calls.push(ClusterCall::Apply { names: names.clone() });
            match state.manifest_error.clone() {
                // A rejected apply accepts nothing, so the workload stays
                // unapplied and its health stays `NoData`.
                Some(error) => Err(error),
                None => {
                    for name in &names {
                        state.applied.insert(name.clone());
                        // An accepted workload has a rollout to report, even
                        // when the test scripted a different one.
                        if !state.rollouts.contains_key(name) {
                            let revision = FakeCluster::latest_revision(&state);
                            state
                                .rollouts
                                .insert(name.clone(), Rollout::new(revision, Health::Progressing));
                        }
                    }
                    Ok(names)
                }
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn upgrade<'a>(&'a self, release: &'a str) -> BoxFuture<'a, Result<Rollout, ClusterError>> {
        let result = {
            let mut state = self.state.lock().expect("fake cluster state");
            state.calls.push(ClusterCall::Upgrade { release: release.to_string() });
            match state.upgrade_error.clone() {
                Some(error) => Err(error),
                None => Ok(self.releases.get(release).cloned().unwrap_or_else(|| {
                    Rollout::new(FakeCluster::latest_revision(&state), Health::Progressing)
                })),
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn rollout<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Rollout, ClusterError>> {
        let result = {
            let mut state = self.state.lock().expect("fake cluster state");
            state.calls.push(ClusterCall::Rollout { name: name.to_string() });
            // Read-only: polling this must not advance the rollout, so it is
            // answered from stored state and writes nothing back.
            state
                .rollouts
                .get(name)
                .cloned()
                .map(Ok)
                .unwrap_or_else(|| Err(ClusterError::NotFound { name: name.to_string() }))
        };
        Box::pin(std::future::ready(result))
    }

    fn health<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<HealthReport, ClusterError>> {
        let result = {
            let mut state = self.state.lock().expect("fake cluster state");
            state.calls.push(ClusterCall::Health { name: name.to_string() });
            if state.applied.contains(name) {
                Ok(FakeCluster::next_report(&mut state, name))
            } else {
                // Nothing has been applied here, so nothing has been observed:
                // the script does not advance and the answer is silence.
                Ok(HealthReport::with_reason(Health::NoData, NO_OBSERVATION))
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn rollback<'a>(
        &'a self,
        name: &'a str,
        revision: Revision,
    ) -> BoxFuture<'a, Result<Rollout, ClusterError>> {
        let result = {
            let mut state = self.state.lock().expect("fake cluster state");
            state.calls.push(ClusterCall::Rollback { name: name.to_string(), revision });
            if !state.applied.contains(name) {
                Err(ClusterError::NotFound { name: name.to_string() })
            } else if !state.retained.contains(&revision) {
                // Deliberately an error rather than the revision that happens
                // to be running now.
                Err(ClusterError::RevisionUnknown { revision })
            } else {
                let rollout = Rollout::new(revision, Health::Progressing);
                state.rollouts.insert(name.to_string(), rollout.clone());
                Ok(rollout)
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn handle(&self) -> &ClusterRef {
        &self.handle
    }
}

/// How many times a conformance kit polls `health` while waiting for a target
/// to settle — a waiter with no clock, bounded so a broken adapter fails the
/// kit instead of hanging it.
const SETTLE_POLLS: usize = 64;

/// The `Cluster` conformance kit: every adapter — the fake here, real
/// Kubernetes and its equivalents in the adapter job
/// ([#52](https://github.com/Keep-Shipping/harness/issues/52)) — must pass
/// this.
///
/// The kit walks the port's contract in the order a step would:
///
/// - a workload the cluster has never been told about reports
///   [`Health::NoData`] and never [`Health::Healthy`] — silence is not health;
/// - `rollout` on a workload that does not exist is
///   [`ClusterError::NotFound`];
/// - `apply` accepts, returning every manifest name in the order given, and
///   applying the same manifests again is idempotent — the same names, and no
///   new revision;
/// - `health` then settles on [`Health::Healthy`] (polled, because how long a
///   rollout takes is the adapter's business, not the kit's). The kit asserts
///   the *state*, not the absence of a reason: a real adapter is expected to
///   carry the target's own wording, e.g. `"3 of 5 replicas ready"`;
/// - `rollout` is read-only, so polling it changes nothing;
/// - `rollback` to a revision no cluster retains is
///   [`ClusterError::RevisionUnknown`], never the current revision.
///
/// `manifest` must be applicable to a cluster that starts with none of it, and
/// `name` must name the workload it creates.
pub async fn conformance(cluster: &dyn Cluster, name: &str, manifest: &Manifest) {
    let handle = cluster.handle();
    assert!(!handle.context().is_empty(), "cluster conformance: the handle must name a context");
    assert!(!handle.endpoint().is_empty(), "cluster conformance: the handle must name an endpoint");

    let silent = cluster.health(name).await.unwrap_or_else(|error| {
        panic!("cluster conformance: health of an unknown workload must be a report, not an error: {error}")
    });
    assert_eq!(
        silent.state(),
        Health::NoData,
        "cluster conformance: a workload that does not exist yet must report NoData"
    );
    assert!(
        !silent.satisfies(Health::Healthy),
        "cluster conformance: NoData must never satisfy a healthy gate"
    );

    let missing = cluster.rollout(name).await;
    assert!(
        matches!(&missing, Err(ClusterError::NotFound { name: reported } ) if reported == name),
        "cluster conformance: the rollout of a workload that does not exist must be NotFound, got {missing:?}"
    );

    let applied = cluster.apply(std::slice::from_ref(manifest)).await.unwrap_or_else(|error| {
        panic!("cluster conformance: a valid manifest must apply: {error}")
    });
    assert_eq!(
        applied,
        vec![manifest.name().to_string()],
        "cluster conformance: apply must return every manifest name, in the order given"
    );

    let again = cluster.apply(std::slice::from_ref(manifest)).await.unwrap_or_else(|error| {
        panic!("cluster conformance: server-side apply must be idempotent: {error}")
    });
    assert_eq!(
        again, applied,
        "cluster conformance: applying the same manifests again must report the same names"
    );

    let mut report = silent;
    for _ in 0..SETTLE_POLLS {
        report = cluster.health(name).await.unwrap_or_else(|error| {
            panic!("cluster conformance: health after apply must be a report: {error}")
        });
        if report.satisfies(Health::Healthy) {
            break;
        }
        if matches!(report.state(), Health::Failed) {
            panic!(
                "cluster conformance: the workload settled Failed instead of Healthy: {report:?}"
            );
        }
    }
    assert!(
        report.satisfies(Health::Healthy),
        "cluster conformance: an applied workload must settle on Healthy, got {report:?}"
    );
    if let Some(reason) = report.reason() {
        assert!(!reason.trim().is_empty(), "cluster conformance: a reason must say something");
    }

    let first = cluster.rollout(name).await.expect("the applied workload has a rollout");
    let second = cluster.rollout(name).await.expect("the applied workload still has a rollout");
    assert_eq!(
        first, second,
        "cluster conformance: rollout is read-only — polling it must not advance the rollout"
    );

    let unknown = Revision::new(u32::MAX);
    let rolled_back = cluster.rollback(name, unknown).await;
    assert!(
        matches!(&rolled_back, Err(ClusterError::RevisionUnknown { revision }) if *revision == unknown),
        "cluster conformance: an unretained revision must be RevisionUnknown, not the current one, got {rolled_back:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    fn manifest() -> Manifest {
        Manifest::new("Deployment/api", b"kind: Deployment").expect("non-empty manifest")
    }

    fn a_cluster() -> FakeCluster {
        FakeCluster::new().with_health_script([
            Health::Progressing,
            Health::Progressing,
            Health::Healthy,
        ])
    }

    #[test]
    fn an_unscripted_target_reports_no_data_until_applied() {
        let cluster = a_cluster();
        let before = block_on(cluster.health("Deployment/api")).expect("a report, not an error");
        assert_eq!(before.state(), Health::NoData);
        assert!(!before.satisfies(Health::Healthy));
        assert_eq!(cluster.applied_names(), Vec::<String>::new());

        block_on(cluster.apply(&[manifest()])).expect("the manifest applies");
        assert_eq!(cluster.applied_names(), vec!["Deployment/api".to_string()]);
        assert_eq!(
            block_on(cluster.health("Deployment/api")).unwrap().state(),
            Health::Progressing
        );
    }

    #[test]
    fn the_health_script_walks_a_rollout_and_then_holds() {
        let cluster = a_cluster();
        block_on(cluster.apply(&[manifest()])).expect("the manifest applies");
        let states: Vec<Health> = (0..5)
            .map(|_| block_on(cluster.health("Deployment/api")).expect("a report").state())
            .collect();
        assert_eq!(
            states,
            vec![
                Health::Progressing,
                Health::Progressing,
                Health::Healthy,
                Health::Healthy,
                Health::Healthy
            ]
        );
        // And a settled report can carry the target's own wording.
        let explained = FakeCluster::new().with_health_reports([HealthReport::with_reason(
            Health::Healthy,
            "3 of 3 replicas ready",
        )]);
        block_on(explained.apply(&[manifest()])).expect("the manifest applies");
        let report = block_on(explained.health("Deployment/api")).expect("a report");
        assert_eq!(report.reason(), Some("3 of 3 replicas ready"));
    }

    #[test]
    fn each_workload_walks_the_script_from_the_start() {
        let cluster = a_cluster();
        let second =
            Manifest::new("Deployment/web", b"kind: Deployment").expect("non-empty manifest");
        block_on(cluster.apply(&[manifest(), second])).expect("both manifests apply");

        let walk = |name: &str| -> Vec<Health> {
            (0..4).map(|_| block_on(cluster.health(name)).expect("a report").state()).collect()
        };
        assert_eq!(
            walk("Deployment/api"),
            vec![Health::Progressing, Health::Progressing, Health::Healthy, Health::Healthy]
        );
        // A's polls must not have consumed B's rollout: with one global cursor
        // B would have been skipped from the start and answered `Healthy` on
        // its first poll — the silent skip this crate exists to prevent.
        assert_eq!(
            walk("Deployment/web"),
            vec![Health::Progressing, Health::Progressing, Health::Healthy, Health::Healthy]
        );
        // And a workload that was never applied still reports silence.
        assert_eq!(
            block_on(cluster.health("Deployment/nope")).expect("a report").state(),
            Health::NoData
        );
    }

    #[test]
    fn a_fresh_script_replays_the_transition_from_the_start() {
        let mut cluster = a_cluster();
        block_on(cluster.apply(&[manifest()])).expect("the manifest applies");
        // Exhaust the first script.
        let _: Vec<Health> = (0..5)
            .map(|_| block_on(cluster.health("Deployment/api")).expect("a report").state())
            .collect();
        assert_eq!(
            block_on(cluster.health("Deployment/api")).expect("a report").state(),
            Health::Healthy
        );

        cluster =
            cluster.with_health_script([Health::Progressing, Health::Progressing, Health::Healthy]);
        assert_eq!(
            block_on(cluster.health("Deployment/api")).expect("a report").state(),
            Health::Progressing,
            "installing a script must rewind the cursor, or the new transition starts settled"
        );
    }

    #[test]
    fn a_rejected_apply_reports_the_api_message_and_keeps_the_workload_absent() {
        let cluster = FakeCluster::new().with_manifest_error(ClusterError::Apply {
            message: "admission webhook denied the request".to_string(),
        });
        let applied = block_on(cluster.apply(&[manifest()]));
        assert_eq!(
            applied,
            Err(ClusterError::Apply {
                message: "admission webhook denied the request".to_string()
            })
        );
        // Nothing was accepted, so there is still nothing to observe.
        assert_eq!(block_on(cluster.health("Deployment/api")).unwrap().state(), Health::NoData);
        assert!(!block_on(cluster.health("Deployment/api")).unwrap().satisfies(Health::Healthy));
    }

    #[test]
    fn applying_twice_is_idempotent_and_upgrade_reports_its_scripted_rollout() {
        let cluster = FakeCluster::new()
            .with_release("api", Rollout::new(Revision::new(7), Health::Progressing));
        let first = block_on(cluster.apply(&[manifest()])).expect("the first apply");
        let second = block_on(cluster.apply(&[manifest()])).expect("the second apply");
        assert_eq!(first, second);

        let rollout = block_on(cluster.upgrade("api")).expect("the release upgrades");
        assert_eq!(rollout.revision(), Revision::new(7));
        assert_eq!(rollout.state(), Health::Progressing);

        let failed = FakeCluster::new()
            .with_upgrade_error(ClusterError::Upgrade { message: "chart not found".to_string() });
        assert!(matches!(
            block_on(failed.upgrade("missing")),
            Err(ClusterError::Upgrade { message }) if message == "chart not found"
        ));
    }

    #[test]
    fn rollout_is_read_only_and_an_unknown_workload_is_not_found() {
        let cluster = a_cluster()
            .with_rollout("Deployment/api", Rollout::new(Revision::new(3), Health::Degraded));
        block_on(cluster.apply(&[manifest()])).expect("the manifest applies");
        let first = block_on(cluster.rollout("Deployment/api")).expect("a rollout");
        let second = block_on(cluster.rollout("Deployment/api")).expect("the same rollout");
        assert_eq!(first, second);
        assert_eq!(first.state(), Health::Degraded);
        assert!(matches!(
            block_on(cluster.rollout("Deployment/nope")),
            Err(ClusterError::NotFound { name }) if name == "Deployment/nope"
        ));
    }

    #[test]
    fn a_rollback_names_its_revision_and_never_substitutes_one() {
        let cluster = FakeCluster::new().with_rollback_revision(Revision::new(4));
        block_on(cluster.apply(&[manifest()])).expect("the manifest applies");
        let rolled = block_on(cluster.rollback("Deployment/api", Revision::new(4)))
            .expect("revision 4 is retained");
        assert_eq!(rolled.revision(), Revision::new(4));
        assert_eq!(block_on(cluster.rollback("Deployment/api", Revision::new(4))).unwrap(), rolled);

        // An unretained revision is an error, never the revision running now.
        assert_eq!(
            block_on(cluster.rollback("Deployment/api", Revision::new(9))),
            Err(ClusterError::RevisionUnknown { revision: Revision::new(9) })
        );
        // And a workload that was never applied is not found at all.
        assert!(matches!(
            block_on(cluster.rollback("Deployment/nope", Revision::new(4))),
            Err(ClusterError::NotFound { .. })
        ));
    }

    #[test]
    fn every_call_is_recorded_oldest_first() {
        let cluster = a_cluster();
        block_on(cluster.apply(&[manifest()])).expect("the manifest applies");
        block_on(cluster.health("Deployment/api")).expect("a report");
        block_on(cluster.rollback("Deployment/api", Revision::new(FIRST_REVISION)))
            .expect("rollback");
        block_on(cluster.upgrade("api")).expect("upgrade");
        assert_eq!(
            cluster.calls(),
            vec![
                ClusterCall::Apply { names: vec!["Deployment/api".to_string()] },
                ClusterCall::Health { name: "Deployment/api".to_string() },
                ClusterCall::Rollback {
                    name: "Deployment/api".to_string(),
                    revision: Revision::new(FIRST_REVISION),
                },
                ClusterCall::Upgrade { release: "api".to_string() },
            ]
        );
        // `handle` is a synchronous read of the adapter's identity, not a call
        // against the cluster, so it is not in the record at all.
        assert_eq!(cluster.handle().context(), DEFAULT_CONTEXT);
        assert_eq!(cluster.handle().auth(), &AuthMethod::WorkloadIdentity);
    }

    #[test]
    fn the_debug_output_carries_counts_and_never_manifest_contents() {
        let cluster = a_cluster();
        block_on(cluster.apply(&[manifest()])).expect("the manifest applies");
        let debug = format!("{cluster:?}");
        assert!(debug.contains("applied: 1"), "{debug}");
        assert!(!debug.contains("kind: Deployment"), "{debug}");
        assert!(!debug.contains(DEFAULT_ENDPOINT), "{debug}");
    }

    #[test]
    fn the_fake_passes_conformance() {
        let cluster = a_cluster();
        block_on(conformance(&cluster, "Deployment/api", &manifest()));
    }
}
