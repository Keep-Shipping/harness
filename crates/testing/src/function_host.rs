//! Fake for the [`FunctionHost`] port: published versions, scripted traffic
//! splits, per-version health transitions, and a pin that must be checked
//! rather than trusted. Never opens a socket.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Mutex;

use ks_core::ports::BoxFuture;
use ks_core::ports::function_host::{
    Artifact, FunctionHost, FunctionHostError, Pinned, TrafficSplit, Version,
};
use ks_core::ports::health::{Health, HealthReport};

/// The worker name a fresh [`FakeFunctionHost`] pins with, in the
/// Cloudflare-Workers-Version-Overrides header.
pub const DEFAULT_WORKER: &str = "api";
/// The header Cloudflare Workers pins a version with.
pub const VERSION_OVERRIDE_HEADER: &str = "Cloudflare-Workers-Version-Overrides";
/// The id of the first version a fresh [`FakeFunctionHost`] publishes when the
/// test scripts none.
pub const FIRST_VERSION: &str = "v1";

/// Why the fake reports [`Health::NoData`] for a version with an exhausted
/// script: it has an observation, but nothing new to say.
const NOTHING_OBSERVED: &str = "this version has not produced an observation yet";

/// One call a test can observe on the [`FakeFunctionHost`], oldest first via
/// [`FakeFunctionHost::calls`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionHostCall {
    /// [`FunctionHost::publish`] was asked to deploy this artifact.
    Publish {
        /// The artifact uri that was published.
        uri: String,
        /// The digest the artifact was pinned to, if the step gave one — what
        /// the adapter was obliged to verify before shipping.
        digest: Option<String>,
    },
    /// [`FunctionHost::shift`] moved this share onto this version.
    Shift {
        /// The version traffic moved onto.
        version: String,
        /// The share of traffic moved.
        percent: u8,
    },
    /// [`FunctionHost::health`] was asked about this version.
    Health {
        /// The version health was asked about.
        version: String,
    },
    /// [`FunctionHost::keep_warm`] was asked to pre-provision this many.
    KeepWarm {
        /// The version to keep warm.
        version: String,
        /// How many instances to provision.
        count: u32,
    },
    /// [`FunctionHost::rollback`] was asked to return traffic where it was.
    Rollback,
    /// [`FunctionHost::pinned`] built a request pinned to this version.
    Pinned {
        /// The version the request was pinned to.
        version: String,
    },
    /// [`FunctionHost::pin_is_detectable`] was read.
    PinIsDetectable,
}

/// The fake's mutable state; every accessor goes through one mutex, so the
/// fake is `Send + Sync`.
#[derive(Default)]
struct State {
    /// Versions `publish` will hand out, in order; the last repeats.
    queue: VecDeque<Version>,
    /// Every version the fake has published.
    published: Vec<Version>,
    /// Version id -> the share of traffic it receives.
    traffic: BTreeMap<String, u8>,
    /// The version traffic is on now, i.e. the default split.
    current: Option<Version>,
    /// How many instances the fake pretends to hold pre-provisioned.
    warm_versions: u32,
    /// The versions the default split was on, oldest first; the last is where
    /// `rollback` returns to when the test scripted nothing else. Read, never
    /// consumed: a repeated rollback is convergent, not a toggle.
    history: Vec<Version>,
    /// Version id -> its health script; the last entry repeats.
    scripts: BTreeMap<String, VecDeque<HealthReport>>,
    /// Version id -> how far through its script the fake has walked.
    cursors: BTreeMap<String, usize>,
    /// The version `rollback` returns when traffic is not scripted elsewhere.
    rollback_to: Option<Version>,
    /// Every call, oldest first.
    calls: Vec<FunctionHostCall>,
}

/// A [`FunctionHost`] you script per test — the stand-in for real serverless
/// adapters ([#52](https://github.com/Keep-Shipping/harness/issues/52)).
///
/// The fake is the deploy sequence the port describes, and it is deliberately
/// awkward in the two places the port insists a step be:
///
/// - **A cold version is not healthy.** `publish` makes a version exist;
///   nothing makes it run. Until [`shift`](FunctionHost::shift) gives it
///   traffic, [`health`](FunctionHost::health) is
///   [`FunctionHostError::NoTraffic`] — never an optimistic [`Health::Healthy`].
/// - **A pin is checked, not trusted.** [`pinned`](FunctionHost::pinned) builds
///   the Cloudflare Workers version-override header, and
///   [`pin_is_detectable`](FakeFunctionHost::with_pin_detectable) says whether
///   this host would tell you the pin held. With it `false`, a step that only
///   looks for a 200 would smoke-test the old version; the fake's own tests
///   show why the response must be checked.
///
/// ```
/// use ks_core::ports::function_host::{
/// Artifact, FunctionHost, FunctionHostError, TrafficSplit,
/// };
/// use ks_core::ports::health::Health;
/// use ks_testing::{block_on, function_host::FakeFunctionHost};
///
/// let host = FakeFunctionHost::new();
/// let artifact = Artifact::new("oci://registry/api:v7", Some("sha256:abc123".to_string()))
/// .expect("named artifact");
/// let version = block_on(host.publish(&artifact)).expect("the artifact publishes");
///
/// // Published is not running: no traffic, nothing to health-check.
/// assert!(matches!(
/// block_on(host.health(&version)),
/// Err(FunctionHostError::NoTraffic { .. })
/// ));
///
/// block_on(host.shift(&TrafficSplit::new(version.clone(), 100).expect("all of it")))
/// .expect("the split is accepted");
/// assert_eq!(block_on(host.health(&version)).expect("a report").state(), Health::Healthy);
///
/// // The pin names exactly the version that was published.
/// let pinned = host.pinned(&version);
/// assert_eq!(pinned.version(), &version);
/// assert_eq!(pinned.headers()[0].0, "Cloudflare-Workers-Version-Overrides");
/// ```
///
/// All mutable state sits behind one mutex, so the fake is `Send + Sync`.
pub struct FakeFunctionHost {
    worker: String,
    pin_detectable: bool,
    state: Mutex<State>,
}

impl Default for FakeFunctionHost {
    /// The default fake publishes `v1`, `v2`, … for artifacts it is given,
    /// pins with the worker [`DEFAULT_WORKER`], reports
    /// [`FunctionHost::pin_is_detectable`] as `false` — the dangerous case the
    /// port spells out — and has no scripted health: a version with traffic
    /// reports [`Health::Healthy`].
    fn default() -> FakeFunctionHost {
        FakeFunctionHost {
            worker: DEFAULT_WORKER.to_string(),
            pin_detectable: false,
            state: Mutex::new(State::default()),
        }
    }
}

impl FakeFunctionHost {
    /// Creates a fake that publishes `v1`, `v2`, … and pins with the worker
    /// [`DEFAULT_WORKER`] — until scripted.
    pub fn new() -> FakeFunctionHost {
        FakeFunctionHost::default()
    }

    /// Queues `version` as the next [`FunctionHost::publish`] result; the last
    /// queued version repeats, so any number of publishes succeed.
    pub fn with_publish_version(self, version: Version) -> FakeFunctionHost {
        self.state.lock().expect("fake function host state").queue.push_back(version);
        self
    }

    /// Queues the states [`FunctionHost::health`] answers with for `version`,
    /// one per call; the last repeats. Each version walks its own script from
    /// the start, so a test can script a warm-up per version. A version with no
    /// traffic never reaches the script at all.
    pub fn with_health_script(
        self,
        version: &Version,
        states: impl IntoIterator<Item = Health>,
    ) -> FakeFunctionHost {
        let states: VecDeque<HealthReport> = states.into_iter().map(HealthReport::new).collect();
        self.state
            .lock()
            .expect("fake function host state")
            .scripts
            .insert(version.id().to_string(), states);
        self
    }

    /// Puts `split` in place immediately, as though a step had already shifted
    /// traffic — so a test can start from a version that is receiving traffic.
    pub fn with_split(self, split: TrafficSplit) -> FakeFunctionHost {
        self.shift_state(split);
        self
    }

    /// The version [`FunctionHost::rollback`] returns when the fake has no
    /// history of its own to go back to.
    pub fn with_rollback_to(self, version: Version) -> FakeFunctionHost {
        self.state.lock().expect("fake function host state").rollback_to = Some(version);
        self
    }

    /// Reports [`FunctionHost::pin_is_detectable`] as `detectable`.
    ///
    /// `false` is the default and the dangerous case: the request looks fine
    /// and was served by whatever the default split says, so a step that does
    /// not read the answering version out of the response will smoke-test the
    /// old code and pass.
    pub fn with_pin_detectable(mut self, detectable: bool) -> FakeFunctionHost {
        self.pin_detectable = detectable;
        self
    }

    /// How many instances the fake pretends to have pre-provisioned, until a
    /// [`FunctionHost::keep_warm`] asks for another number. Pre-warming is an
    /// optimisation only: it never decides whether a deploy passes.
    pub fn with_warm_versions(self, count: u32) -> FakeFunctionHost {
        self.state.lock().expect("fake function host state").warm_versions = count;
        self
    }

    /// Every call made against the fake, oldest first.
    #[must_use]
    pub fn calls(&self) -> Vec<FunctionHostCall> {
        self.state.lock().expect("fake function host state").calls.clone()
    }

    /// The version ids the fake has published, oldest first, one entry per
    /// [`FunctionHost::publish`] call — so a version republished (a queued
    /// version that repeats) appears as many times as it was published.
    #[must_use]
    pub fn published_ids(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("fake function host state")
            .published
            .iter()
            .map(|version| version.id().to_string())
            .collect()
    }

    /// The version traffic is on now, if any.
    #[must_use]
    pub fn current_split(&self) -> Option<Version> {
        self.state.lock().expect("fake function host state").current.clone()
    }

    /// How many instances the fake is holding pre-provisioned.
    #[must_use]
    pub fn warm_versions(&self) -> u32 {
        self.state.lock().expect("fake function host state").warm_versions
    }

    /// Moves traffic with [`FunctionHost::shift`]'s bookkeeping, minus the
    /// call record — shared by [`with_split`](FakeFunctionHost::with_split) and
    /// the port method.
    fn shift_state(&self, split: TrafficSplit) {
        let mut state = self.state.lock().expect("fake function host state");
        if let Some(current) = state.current.clone() {
            state.history.push(current);
        }
        state.traffic.insert(split.version().id().to_string(), split.percent());
        state.current = Some(split.version().clone());
    }

    /// The next version `publish` hands out: the queued one, or a minted `vN`.
    fn next_version(state: &mut State) -> Version {
        let next = match state.queue.len() {
            0 => None,
            1 => state.queue.front().cloned(),
            _ => state.queue.pop_front(),
        };
        let version = next.unwrap_or_else(|| {
            Version::new(format!("v{}", state.published.len() + 1))
                .expect("the minted version id is not empty")
        });
        state.published.push(version.clone());
        version
    }

    /// The next entry in a version's script: advancing one step, holding at
    /// the last. A script with nothing in it is [`Health::NoData`].
    fn next_report(state: &mut State, id: &str) -> HealthReport {
        let Some(script) = state.scripts.get(id) else {
            return HealthReport::new(Health::Healthy);
        };
        let cursor = state.cursors.entry(id.to_string()).or_insert(0);
        if *cursor < script.len() {
            let report = script.get(*cursor).cloned();
            *cursor += 1;
            if let Some(report) = report {
                return report;
            }
        }
        script
            .back()
            .cloned()
            .unwrap_or_else(|| HealthReport::with_reason(Health::NoData, NOTHING_OBSERVED))
    }
}

impl fmt::Debug for FakeFunctionHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().expect("fake function host state");
        f.debug_struct("FakeFunctionHost")
            .field("queued_versions", &state.queue.len())
            .field("published", &state.published.len())
            .field("with_traffic", &state.traffic.len())
            .field("has_current_split", &state.current.is_some())
            .field("history", &state.history.len())
            .field("scripts", &state.scripts.len())
            .field("has_rollback_to", &state.rollback_to.is_some())
            .field("pin_is_detectable", &self.pin_detectable)
            .field("warm_versions", &state.warm_versions)
            .field("calls", &state.calls.len())
            .finish()
    }
}

impl FunctionHost for FakeFunctionHost {
    fn publish<'a>(
        &'a self,
        artifact: &'a Artifact,
    ) -> BoxFuture<'a, Result<Version, FunctionHostError>> {
        let result = {
            let mut state = self.state.lock().expect("fake function host state");
            state.calls.push(FunctionHostCall::Publish {
                uri: artifact.uri().to_string(),
                digest: artifact.digest().map(str::to_string),
            });
            Ok(FakeFunctionHost::next_version(&mut state))
        };
        Box::pin(std::future::ready(result))
    }

    fn shift<'a>(
        &'a self,
        split: &'a TrafficSplit,
    ) -> BoxFuture<'a, Result<(), FunctionHostError>> {
        {
            let mut state = self.state.lock().expect("fake function host state");
            state.calls.push(FunctionHostCall::Shift {
                version: split.version().id().to_string(),
                percent: split.percent(),
            });
        }
        self.shift_state(split.clone());
        Box::pin(std::future::ready(Ok(())))
    }

    fn health<'a>(
        &'a self,
        version: &'a Version,
    ) -> BoxFuture<'a, Result<HealthReport, FunctionHostError>> {
        let result = {
            let mut state = self.state.lock().expect("fake function host state");
            state.calls.push(FunctionHostCall::Health { version: version.id().to_string() });
            if !state.published.iter().any(|published| published == version) {
                Err(FunctionHostError::UnknownVersion { version: version.id().to_string() })
            } else if state.traffic.get(version.id()).copied().unwrap_or(0) == 0 {
                // Real, but cold: its code has never run, so there is nothing
                // to report and it must not be called healthy.
                Err(FunctionHostError::NoTraffic { version: version.id().to_string() })
            } else {
                Ok(FakeFunctionHost::next_report(&mut state, version.id()))
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn keep_warm<'a>(
        &'a self,
        version: &'a Version,
        count: u32,
    ) -> BoxFuture<'a, Result<(), FunctionHostError>> {
        {
            let mut state = self.state.lock().expect("fake function host state");
            state
                .calls
                .push(FunctionHostCall::KeepWarm { version: version.id().to_string(), count });
            state.warm_versions = count;
        }
        // Purely an optimisation: a host that cannot pre-warm succeeds with no
        // effect rather than failing the deploy.
        Box::pin(std::future::ready(Ok(())))
    }

    fn rollback<'a>(&'a self) -> BoxFuture<'a, Result<Version, FunctionHostError>> {
        let result = {
            let mut state = self.state.lock().expect("fake function host state");
            state.calls.push(FunctionHostCall::Rollback);
            // Where traffic actually was: the scripted target, else the split
            // before this one — never what the caller meant. The history is
            // *read*, not popped, so a rollback that runs twice (a retry, or a
            // cleanup step after an explicit one) converges on the same
            // version instead of toggling onto the one it just abandoned.
            let version = state
                .rollback_to
                .clone()
                .or_else(|| state.history.last().cloned())
                .or_else(|| state.current.clone())
                .or_else(|| state.published.first().cloned());
            match version {
                Some(version) => {
                    // The abandoned version loses its traffic; the restored
                    // one keeps whatever share the previous shift gave it, so
                    // the two differ — or a repeated rollback would revoke the
                    // traffic it is returning.
                    if let Some(current) = state.current.clone()
                        && current != version
                    {
                        state.traffic.insert(current.id().to_string(), 0);
                    }
                    state.current = Some(version.clone());
                    Ok(version)
                }
                None => Err(FunctionHostError::UnknownVersion {
                    version: "nothing has been published".to_string(),
                }),
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn pinned<'a>(&'a self, version: &'a Version) -> Pinned {
        self.state
            .lock()
            .expect("fake function host state")
            .calls
            .push(FunctionHostCall::Pinned { version: version.id().to_string() });
        Pinned::new(
            version.clone(),
            vec![(
                VERSION_OVERRIDE_HEADER.to_string(),
                format!("{}=\"{}\"", self.worker, version.id()),
            )],
            None,
        )
        .expect("the workers override header is well formed")
    }

    fn pin_is_detectable(&self) -> bool {
        self.state
            .lock()
            .expect("fake function host state")
            .calls
            .push(FunctionHostCall::PinIsDetectable);
        self.pin_detectable
    }
}

/// How many times a conformance kit polls `health` while waiting for a version
/// to settle — a waiter with no clock, bounded so a broken adapter fails the
/// kit instead of hanging it.
const SETTLE_POLLS: usize = 64;

/// The artifact the kit publishes: a named uri **with** a digest, so every
/// adapter is handed the pinned-content case rather than the loose one. A kit
/// that published a digest-less artifact would let an adapter that ignores the
/// artifact's digest entirely pass — and verifying it is the port's headline
/// publish invariant.
pub const CONFORMANCE_ARTIFACT: (&str, Option<&str>) = (
    "oci://ks-conformance/api",
    Some("sha256:9f2c1e7a4b6d8035af51c9e27d4b8061fe3a5c928d7b640af19e35c8d02b6714"),
);

/// The `FunctionHost` conformance kit: every adapter — the fake here, real
/// serverless adapters in the adapter job
/// ([#52](https://github.com/Keep-Shipping/harness/issues/52)) — must pass
/// this.
///
/// The kit walks the port's contract in the order a step would:
///
/// - `publish` returns a version with a non-empty id;
/// - that version, having never served a request, is **not healthy**:
///   `health` is [`FunctionHostError::NoTraffic`], never an `Ok` carrying
///   [`Health::Healthy`] or [`Health::NoData`] — its code has never run;
/// - `shift` is accepted, and `health` then settles on [`Health::Healthy`]
///   (polled, because how long a cold start takes is the adapter's business);
/// - `keep_warm` succeeds: a host that cannot pre-warm must not fail the
///   deploy;
/// - `pinned` round-trips the version it was given and addresses exactly that
///   version — the pin's *payload* (its headers or its url) must differ
///   between two versions, or it pins nothing;
/// - `rollback` returns where traffic actually was: a version **other than**
///   the one the kit just shifted onto, so an adapter whose `rollback` is a
///   no-op fails the kit.
///
/// # What the kit cannot check
///
/// Two of the port's obligations are outside what a kit handed only a
/// `&dyn FunctionHost` can observe, and both stay the **adapter author's
/// responsibility**:
///
/// - **Digest verification.** The kit publishes [`CONFORMANCE_ARTIFACT`], which
///   carries a digest, so every adapter is handed the pinned-content case. But
///   publishing a digest-bearing artifact succeeds whether or not the adapter
///   looked at the digest: the kit has no way to hand the adapter a bundle
///   whose bytes *disagree* with the digest, so it cannot see a mismatch
///   being caught. An adapter must verify the digest itself and fail the
///   publish on a mismatch.
/// - **Whether a pin was honoured.** See [below](#when-the-pin-is-not-detectable).
///
/// # When the pin is not detectable
///
/// The kit reads [`FunctionHost::pin_is_detectable`] once. When it is `false`,
/// the host may ignore the pin and serve the request from the **default
/// split**: a healthy-looking response, from the old version, with nothing
/// wrong with it. A step that trusts a green smoke check in that case is
/// testing code that is not deployed. So the kit cannot verify the pin
/// itself — it asserts only that the pin is well-formed and names one
/// version, and **the step must read the answering version out of the
/// response** and compare it with what it pinned. Only then does a green
/// smoke check mean anything.
pub async fn conformance(host: &dyn FunctionHost) {
    let artifact =
        Artifact::new(CONFORMANCE_ARTIFACT.0, CONFORMANCE_ARTIFACT.1.map(str::to_string))
            .expect("conformance: the conformance artifact is well formed");
    // Traffic is put on a first version before the version under test is
    // published, because "rollback returns where traffic was" is only a
    // meaningful claim when traffic was somewhere else first.
    let previous = host.publish(&artifact).await.unwrap_or_else(|error| {
        panic!("function_host conformance: a valid artifact must publish: {error}")
    });
    assert!(
        !previous.id().is_empty(),
        "function_host conformance: publish must return a version with an id"
    );
    host.shift(&TrafficSplit::new(previous.clone(), 100).expect("conformance: 100% is in range"))
        .await
        .unwrap_or_else(|error| {
            panic!(
                "function_host conformance: shifting all traffic onto a version must be accepted: {error}"
            )
        });

    let version = host.publish(&artifact).await.unwrap_or_else(|error| {
        panic!("function_host conformance: a valid artifact must publish: {error}")
    });
    assert!(
        !version.id().is_empty(),
        "function_host conformance: publish must return a version with an id"
    );

    let cold = host.health(&version).await;
    assert!(
        !matches!(&cold, Ok(report) if report.satisfies(Health::Healthy)),
        "function_host conformance: a version that has never run must never be Healthy, got {cold:?}"
    );
    assert_eq!(
        cold,
        Err(FunctionHostError::NoTraffic { version: version.id().to_string() }),
        "function_host conformance: a published version receiving no traffic must be NoTraffic"
    );

    let split = TrafficSplit::new(version.clone(), 100).expect("conformance: 100% is in range");
    host.shift(&split).await.unwrap_or_else(|error| {
        panic!("function_host conformance: shifting all traffic onto a version must be accepted: {error}")
    });

    host.keep_warm(&version, 2).await.unwrap_or_else(|error| {
        panic!(
            "function_host conformance: pre-warming is an optimisation and must never fail: {error}"
        )
    });

    let mut report = HealthReport::new(Health::Progressing);
    for _ in 0..SETTLE_POLLS {
        report = host.health(&version).await.unwrap_or_else(|error| {
            panic!("function_host conformance: a version receiving traffic must be health-checkable: {error}")
        });
        if report.satisfies(Health::Healthy) {
            break;
        }
        if matches!(report.state(), Health::Failed) {
            panic!(
                "function_host conformance: the version settled Failed instead of Healthy: {report:?}"
            );
        }
    }
    assert!(
        report.satisfies(Health::Healthy),
        "function_host conformance: a version taking traffic must settle on Healthy, got {report:?}"
    );

    let pinned = host.pinned(&version);
    assert_eq!(
        pinned.version(),
        &version,
        "function_host conformance: pinned must round-trip the version it was given"
    );
    assert!(
        !pinned.headers().is_empty() || pinned.url().is_some(),
        "function_host conformance: a pin must address exactly one version — headers, a url, or both"
    );
    // The pin's *payload* must differ between two versions. Comparing the whole
    // `Pinned` could never fail — the `version` field differs by construction —
    // so an adapter returning the same header (a pin that pins nothing) would
    // pass.
    let other = Version::new("ks-conformance-other-version").expect("non-empty id");
    let other_pin = host.pinned(&other);
    assert!(
        pinned.headers() != other_pin.headers() || pinned.url() != other_pin.url(),
        "function_host conformance: a pin's headers or url must differ between two versions — \
         a pin that addresses every version is not a pin"
    );

    // Whether this host honours a pin is not assertable through `&dyn
    // FunctionHost`: nothing here sends a request and reads back which version
    // answered, and with an undetectable pin a broken host looks exactly like a
    // working one. So the kit reads the flag once and asserts nothing about the
    // answer — the step's obligation to read the answering version out of the
    // response is documented above, and that is what makes a green smoke check
    // mean anything.
    let _detectable = host.pin_is_detectable();

    let restored = host.rollback().await.unwrap_or_else(|error| {
        panic!("function_host conformance: rollback must report where traffic went: {error}")
    });
    assert_ne!(
        restored, version,
        "function_host conformance: rollback must name the version traffic went back to, not the \
         version it is still shifted onto — a rollback that does not roll back leaves the target \
         on the version it just abandoned"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    fn artifact() -> Artifact {
        Artifact::new("oci://registry/api:v7", Some("sha256:abc123".to_string()))
            .expect("named artifact")
    }

    fn all_of(version: &Version) -> TrafficSplit {
        TrafficSplit::new(version.clone(), 100).expect("all of it")
    }

    #[test]
    fn a_published_version_is_cold_until_traffic_reaches_it() {
        let host = FakeFunctionHost::new();
        let version = block_on(host.publish(&artifact())).expect("the artifact publishes");
        assert_eq!(version.id(), FIRST_VERSION);
        assert_eq!(host.published_ids(), vec![FIRST_VERSION.to_string()]);

        // Real but cold: not unknown, just never run.
        assert_eq!(
            block_on(host.health(&version)),
            Err(FunctionHostError::NoTraffic { version: FIRST_VERSION.to_string() })
        );
        // And a version that was never published at all is a different error.
        let ghost = Version::new("v999").expect("non-empty");
        assert_eq!(
            block_on(host.health(&ghost)),
            Err(FunctionHostError::UnknownVersion { version: "v999".to_string() })
        );

        block_on(host.shift(&all_of(&version))).expect("the split is accepted");
        assert_eq!(block_on(host.health(&version)).expect("a report").state(), Health::Healthy);
        assert_eq!(host.current_split(), Some(version));
    }

    #[test]
    fn each_version_walks_its_own_health_script_then_holds() {
        let host = FakeFunctionHost::new().with_split(all_of(&Version::new("v1").expect("v1")));
        let v1 = Version::new("v1").expect("v1");
        let v2 = Version::new("v2").expect("v2");
        let host = host
            .with_publish_version(v1.clone())
            .with_publish_version(v2.clone())
            .with_health_script(&v1, [Health::Progressing, Health::Healthy])
            .with_health_script(&v2, [Health::Progressing, Health::Progressing, Health::Healthy]);
        block_on(host.publish(&artifact())).expect("v1 publishes");
        block_on(host.publish(&artifact())).expect("v2 publishes");
        block_on(host.shift(&all_of(&v1))).expect("v1 takes traffic");
        block_on(host.shift(&all_of(&v2))).expect("v2 takes traffic");

        let walk = |version: &Version| -> Vec<Health> {
            (0..3).map(|_| block_on(host.health(version)).expect("a report").state()).collect()
        };
        assert_eq!(walk(&v1), vec![Health::Progressing, Health::Healthy, Health::Healthy]);
        // v1's polls did not consume v2's script: each version has its own
        // cursor, so a waiter watching one version says nothing about another.
        assert_eq!(walk(&v2), vec![Health::Progressing, Health::Progressing, Health::Healthy]);
    }

    #[test]
    fn the_pin_names_exactly_the_version_it_was_given() {
        let host = FakeFunctionHost::new();
        let v1 = block_on(host.publish(&artifact())).expect("v1 publishes");
        let v2 = block_on(host.publish(&artifact())).expect("v2 publishes");

        let pin = host.pinned(&v2);
        assert_eq!(pin.version(), &v2);
        assert_eq!(pin.url(), None);
        assert_eq!(
            pin.headers(),
            [(VERSION_OVERRIDE_HEADER.to_string(), format!("api=\"{}\"", v2.id()))]
        );
        // A pin for one version is not a pin for another — this is the whole
        // point of the override header.
        assert_ne!(host.pinned(&v1).headers(), host.pinned(&v2).headers());
    }

    #[test]
    fn a_host_that_cannot_say_which_version_answered_is_the_dangerous_case() {
        let undetectable = FakeFunctionHost::new().with_pin_detectable(false);
        let detectable = FakeFunctionHost::new().with_pin_detectable(true);
        assert!(!undetectable.pin_is_detectable());
        assert!(detectable.pin_is_detectable());

        // Either way the pin is well-formed and names the version, so a step
        // that reads the answering version out of the response can tell
        // whether the check covered what it published. A step that does not
        // read it gets a healthy-looking response from the old code.
        let version = Version::new("v7").expect("non-empty");
        assert_eq!(undetectable.pinned(&version).version(), &version);
        assert_eq!(detectable.pinned(&version).version(), &version);
    }

    #[test]
    fn rollback_returns_where_traffic_was_not_what_the_caller_meant() {
        let v1 = Version::new("v1").expect("v1");
        let v2 = Version::new("v2").expect("v2");
        let host = FakeFunctionHost::new().with_split(all_of(&v1)).with_publish_version(v2.clone());
        block_on(host.publish(&artifact())).expect("v2 publishes");
        block_on(host.shift(&all_of(&v2))).expect("v2 takes traffic");
        assert_eq!(host.current_split(), Some(v2.clone()));

        assert_eq!(block_on(host.rollback()), Ok(v1.clone()));
        assert_eq!(host.current_split(), Some(v1));

        // With no history of its own, the fake returns the scripted target.
        let scripted = FakeFunctionHost::new().with_rollback_to(v2.clone());
        assert_eq!(block_on(scripted.rollback()), Ok(v2));
    }

    #[test]
    fn a_repeated_rollback_converges_on_the_same_version() {
        let v1 = Version::new("v1").expect("v1");
        let v2 = Version::new("v2").expect("v2");
        let host = FakeFunctionHost::new().with_split(all_of(&v1)).with_publish_version(v2.clone());
        block_on(host.publish(&artifact())).expect("v2 publishes");
        block_on(host.shift(&all_of(&v2))).expect("v2 takes traffic");

        // A cleanup step after an explicit rollback, or a retried rollback, must
        // not leave the target on the version it just abandoned while reporting
        // Ok — the returned version is what the run log records.
        assert_eq!(block_on(host.rollback()), Ok(v1.clone()));
        assert_eq!(block_on(host.rollback()), Ok(v1.clone()));
        assert_eq!(block_on(host.rollback()), Ok(v1.clone()));
        assert_eq!(host.current_split(), Some(v1));
        // And the version that was rolled back away from is still cold.
        assert_eq!(
            block_on(host.health(&v2)),
            Err(FunctionHostError::NoTraffic { version: v2.id().to_string() })
        );
    }

    /// A [`FunctionHost`] that is the fake in every respect but one: its
    /// `rollback` reports the version traffic is *already* on and moves
    /// nothing — the no-op the kit's rollback check exists to catch.
    struct NoOpRollbackHost(FakeFunctionHost);

    impl FunctionHost for NoOpRollbackHost {
        fn publish<'a>(
            &'a self,
            artifact: &'a Artifact,
        ) -> BoxFuture<'a, Result<Version, FunctionHostError>> {
            self.0.publish(artifact)
        }
        fn shift<'a>(
            &'a self,
            split: &'a TrafficSplit,
        ) -> BoxFuture<'a, Result<(), FunctionHostError>> {
            self.0.shift(split)
        }
        fn health<'a>(
            &'a self,
            version: &'a Version,
        ) -> BoxFuture<'a, Result<HealthReport, FunctionHostError>> {
            self.0.health(version)
        }
        fn keep_warm<'a>(
            &'a self,
            version: &'a Version,
            count: u32,
        ) -> BoxFuture<'a, Result<(), FunctionHostError>> {
            self.0.keep_warm(version, count)
        }
        fn rollback<'a>(&'a self) -> BoxFuture<'a, Result<Version, FunctionHostError>> {
            let current = self.0.current_split().expect("the kit shifted traffic onto a version");
            Box::pin(std::future::ready(Ok(current)))
        }
        fn pinned<'a>(&'a self, version: &'a Version) -> Pinned {
            self.0.pinned(version)
        }
        fn pin_is_detectable(&self) -> bool {
            self.0.pin_is_detectable()
        }
    }

    #[test]
    fn the_kit_rejects_a_rollback_that_never_moves_traffic() {
        // The kit's own fake passes; a `rollback` that reports the version it
        // is already on does not, because it never rolled anything back.
        let no_op = NoOpRollbackHost(FakeFunctionHost::new());
        let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(conformance(&no_op))
        }))
        .expect_err("a rollback that never moves traffic must fail the kit");
        let message = error
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| error.downcast_ref::<&str>().copied())
            .unwrap_or_default()
            .to_string();
        assert!(
            message.contains("rollback must name the version traffic went back to"),
            "{message}"
        );
    }

    #[test]
    fn the_conformance_artifact_is_published_with_a_digest_the_fake_records() {
        assert!(
            CONFORMANCE_ARTIFACT.1.is_some_and(|digest| {
                let hex = digest.strip_prefix("sha256:").unwrap_or_default();
                hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
            }),
            "the kit must publish a digest-pinned artifact: {:?}",
            CONFORMANCE_ARTIFACT.1
        );
        block_on(conformance(&FakeFunctionHost::new()));

        let host = FakeFunctionHost::new();
        block_on(conformance(&host));
        assert_eq!(
            host.calls().first(),
            Some(&FunctionHostCall::Publish {
                uri: CONFORMANCE_ARTIFACT.0.to_string(),
                digest: CONFORMANCE_ARTIFACT.1.map(str::to_string),
            }),
            "the fake must round-trip the digest the kit pinned"
        );
    }

    #[test]
    fn a_republished_queued_version_is_listed_once_per_publish() {
        // `published_ids` is one entry per publish call, so a queued version
        // that repeats (the queue's last entry repeats) is listed as many
        // times as it was published. Documented on the accessor; asserted here
        // so the growth is not a surprise.
        let v1 = Version::new("v1").expect("v1");
        let host = FakeFunctionHost::new()
            .with_publish_version(v1.clone())
            .with_publish_version(Version::new("v2").expect("v2"));
        block_on(host.publish(&artifact())).expect("v1 publishes");
        block_on(host.publish(&artifact())).expect("v2 publishes");
        // The queue's last entry repeats, so a third publish hands back v2 a
        // second time: one `published_ids` entry per publish, duplicates and
        // all. Asserted so the growth is a documented shape, not a surprise.
        assert_eq!(block_on(host.publish(&artifact())).expect("v2 again").id(), "v2");
        assert_eq!(
            host.published_ids(),
            vec!["v1".to_string(), "v2".to_string(), "v2".to_string()]
        );
        // An unscripted host mints a fresh id per publish instead.
        let minted = FakeFunctionHost::new();
        assert_eq!(block_on(minted.publish(&artifact())).expect("mints").id(), "v1");
        assert_eq!(block_on(minted.publish(&artifact())).expect("mints").id(), "v2");
    }

    #[test]
    fn keeping_a_version_warm_is_optional_and_never_fails_a_deploy() {
        let host = FakeFunctionHost::new().with_warm_versions(1);
        let version = block_on(host.publish(&artifact())).expect("v1 publishes");
        // A different number than the fake started at, so the assertion would
        // fail if `keep_warm` stopped moving the count.
        block_on(host.keep_warm(&version, 3)).expect("a host that cannot pre-warm still succeeds");
        assert_eq!(host.warm_versions(), 3);
        // Even for a version that does not exist: it is an optimisation, not a
        // contract the deploy depends on.
        let ghost = Version::new("v999").expect("non-empty");
        assert!(block_on(host.keep_warm(&ghost, 2)).is_ok());
    }

    #[test]
    fn every_call_is_recorded_oldest_first() {
        let host = FakeFunctionHost::new();
        let version = block_on(host.publish(&artifact())).expect("v1 publishes");
        block_on(host.shift(&TrafficSplit::new(version.clone(), 50).expect("half")))
            .expect("the split is accepted");
        block_on(host.health(&version)).expect("a report");
        block_on(host.keep_warm(&version, 2)).expect("pre-warm");
        let _ = host.pinned(&version);
        let _ = host.pin_is_detectable();
        block_on(host.rollback()).expect("rollback");
        assert_eq!(
            host.calls(),
            vec![
                FunctionHostCall::Publish {
                    uri: "oci://registry/api:v7".to_string(),
                    digest: Some("sha256:abc123".to_string()),
                },
                FunctionHostCall::Shift { version: FIRST_VERSION.to_string(), percent: 50 },
                FunctionHostCall::Health { version: FIRST_VERSION.to_string() },
                FunctionHostCall::KeepWarm { version: FIRST_VERSION.to_string(), count: 2 },
                FunctionHostCall::Pinned { version: FIRST_VERSION.to_string() },
                FunctionHostCall::PinIsDetectable,
                FunctionHostCall::Rollback,
            ]
        );
    }

    #[test]
    fn the_debug_output_carries_counts_and_never_artifact_uris() {
        let host = FakeFunctionHost::new();
        block_on(host.publish(&artifact())).expect("v1 publishes");
        let debug = format!("{host:?}");
        assert!(debug.contains("published: 1"), "{debug}");
        assert!(!debug.contains("oci://"), "{debug}");
    }

    #[test]
    fn the_fake_passes_conformance() {
        block_on(conformance(&FakeFunctionHost::new()));
    }
}
