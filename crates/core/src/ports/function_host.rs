//! The [`FunctionHost`] port: publishing a version, shifting traffic to it,
//! and pinning a request to it
//! ([#52](https://github.com/Keep-Shipping/harness/issues/52)).
//!
//! Serverless targets do not have pods to watch: a deploy is *publish* a
//! [`Version`], *shift* a [`TrafficSplit`] onto it, *wait* on the shared
//! [`HealthReport`], and *roll back* to the version traffic was on before.
//! This port is that sequence, spelled out.
//!
//! # Smoke checks pin, they do not hope
//!
//! After shifting traffic, a step wants to check the new version without
//! disturbing the shift. [`FunctionHost::pinned`] gives it a [`Pinned`] —
//! either request headers that address exactly one version, or a preview URL
//! that serves it — and the step sends its request through that, rather than
//! re-hitting the production hostname and hoping the split caught up.
//!
//! That "rather than hoping" is load-bearing, because not every host honours
//! a pin. [`FunctionHost::pin_is_detectable`] says whether the host can tell
//! you which version answered. When it is `false` and the host ignores the
//! pin, the request is served by the **default split** — silently, with a
//! perfectly healthy response from the *old* version. A step that assumes the
//! pin held would smoke-test the wrong code and pass. So a step must read the
//! version identifier out of the response and compare it with what it pinned;
//! only then does a green smoke check mean anything.
//!
//! # Rolling back returns where traffic was
//!
//! [`FunctionHost::rollback`] takes no version: the host knows what the split
//! was before the shift, and a caller-supplied version could roll back to
//! something traffic was never on. The adapter returns the version traffic
//! actually went back to, so the run log records the target of the rollback
//! rather than the intent.

use std::fmt;

use super::BoxFuture;
use super::health::HealthReport;

/// A published version, identified by the host's own opaque id.
///
/// Obtained from [`FunctionHost::publish`] or returned by
/// [`FunctionHost::rollback`]; the harness never parses it. Which is why
/// [`Version::new`] rejects an empty id — an adapter that returned nothing for
/// a publish would otherwise hand callers a version that addresses no code.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    id: String,
}

impl Version {
    /// The version the host named `id`, e.g. `"a1b2c3d4-…"` or
    /// `"v173"`. Fails with [`FunctionHostError::Empty`] if the id is empty.
    pub fn new(id: impl Into<String>) -> Result<Self, FunctionHostError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(FunctionHostError::Empty { field: "version id" });
        }
        Ok(Version { id })
    }

    /// The host's identifier for this version, e.g. `"a1b2c3d4"`.
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id)
    }
}

/// A deployable bundle: where the code is, and what it must hash to.
///
/// `digest` is optional because not every host content-addresses, but when it
/// is present the adapter must verify it before publishing — a bundle that
/// does not match was truncated in transit or swapped, and publishing it
/// would ship the wrong code under a green run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    uri: String,
    digest: Option<String>,
}

impl Artifact {
    /// The bundle at `uri`, optionally pinned to `digest` (e.g.
    /// `"sha256:…"`, an OCI digest). With a digest, the adapter verifies the
    /// artifact against it and fails the publish rather than shipping a
    /// mismatch.
    ///
    /// Fails with [`FunctionHostError::Empty`] if `uri` is empty — an artifact
    /// at nowhere publishes whatever the adapter guesses. An empty `digest` is
    /// read as *no* digest rather than as a digest that cannot match: an
    /// optional field left blank means the same thing here as absent.
    pub fn new(uri: impl Into<String>, digest: Option<String>) -> Result<Self, FunctionHostError> {
        let uri = uri.into();
        if uri.trim().is_empty() {
            return Err(FunctionHostError::Empty { field: "artifact uri" });
        }
        let digest = digest.filter(|d| !d.trim().is_empty());
        Ok(Artifact { uri, digest })
    }

    /// Where the bundle is: a path, a container ref, or an object-store URI.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The digest the bundle must hash to, if one was given.
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }
}

/// A share of traffic to move onto one version.
///
/// `percent` is a share of the *host's* traffic, not a ratio with the other
/// versions: 100 means "all of it", 0 means "none of it". The other versions'
/// shares are the host's problem — a step states what it wants of the new
/// version and lets the adapter rebalance the rest, which is why there is no
/// list of every version here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSplit {
    version: Version,
    percent: u8,
}

impl TrafficSplit {
    /// Shifts `percent` of traffic onto `version`. Fails with
    /// [`FunctionHostError::WeightOutOfRange`] above 100 — a percentage over
    /// 100 is a typo or a mis-parsed config, and treating it as "all of it"
    /// would silently send every request to the new version.
    pub fn new(version: Version, percent: u8) -> Result<Self, FunctionHostError> {
        if percent > 100 {
            return Err(FunctionHostError::WeightOutOfRange { percent });
        }
        Ok(TrafficSplit { version, percent })
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    /// This version's share of traffic, 0 to 100.
    pub fn percent(&self) -> u8 {
        self.percent
    }
}

/// A request routed to one specific version, bypassing the traffic split.
///
/// Two shapes, because hosts differ, and a step must not have to know which:
///
/// - **Headers.** Cloudflare Workers pins with
///   `Cloudflare-Workers-Version-Overrides: <worker>="<id>"` on an ordinary
///   request — there is no separate URL.
/// - **A URL.** A Lambda alias or a Cloud Run tag gives the version its own
///   preview endpoint (e.g. `https://api-v7-…a.run.app`), which the step
///   requests instead of production.
///
/// Both may be present. [`FunctionHost::pin_is_detectable`] says whether the
/// response will tell you which version answered; when it will not, a step
/// must not assume the pin held — see the [module
/// documentation](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    version: Version,
    headers: Vec<(String, String)>,
    url: Option<String>,
}

impl Pinned {
    /// A request pinned to `version`: send `headers` (an ordered list, so a
    /// host needing more than one is expressible), and if `url` is set
    /// request it instead of the production hostname.
    ///
    /// Fails with [`FunctionHostError::Empty`] if `url` is `Some` but empty:
    /// a step that set a URL meant to reach one version, and an empty one would
    /// resolve to the production hostname — exactly the unpinned request the
    /// pin exists to replace. A genuine `None` stays `None`.
    pub fn new(
        version: Version,
        headers: Vec<(String, String)>,
        url: Option<String>,
    ) -> Result<Self, FunctionHostError> {
        if url.as_deref().is_some_and(str::is_empty) {
            return Err(FunctionHostError::Empty { field: "pinned url" });
        }
        Ok(Pinned { version, headers, url })
    }

    /// The version this request is pinned to — the one a smoke check must
    /// see answer before it believes the check.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The headers to send, in order, e.g. `[("Cloudflare-Workers-Version-Overrides",
    /// "api=\"a1b2c3d4\"")]`.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }
}

/// Why a [`FunctionHost`] operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionHostError {
    /// The host rejected the upload or the deploy. `message` is the provider's
    /// own wording, safe to print; adapters must let the run's redactor scrub
    /// it first, since a deploy log can quote the artifact's contents.
    Publish {
        /// What the provider reported.
        message: String,
    },
    /// The named version does not exist on this host — usually one a
    /// [`FunctionHost::rollback`] or a pinned check referred to after the
    /// host had already reclaimed it.
    UnknownVersion {
        /// The version id that could not be resolved.
        version: String,
    },
    /// A [`TrafficSplit`] percentage over 100; see
    /// [`TrafficSplit::new`].
    WeightOutOfRange {
        /// The rejected percentage.
        percent: u8,
    },
    /// The version exists but is receiving no traffic, so there is nothing to
    /// health-check — its code has never run. Distinct from
    /// [`FunctionHostError::UnknownVersion`]: the version is real, it is just
    /// cold.
    NoTraffic {
        /// The version receiving nothing.
        version: String,
    },
    /// A required field was empty. Raised by [`Version::new`],
    /// [`Artifact::new`] and [`Pinned::new`] before any call is made.
    Empty {
        /// The empty field's name.
        field: &'static str,
    },
}

impl fmt::Display for FunctionHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FunctionHostError::Publish { message } => {
                write!(f, "publish failed: {message}; check the artifact uri and digest")
            }
            FunctionHostError::UnknownVersion { version } => {
                write!(f, "version {version:?} does not exist on this host; publish it first")
            }
            FunctionHostError::WeightOutOfRange { percent } => {
                write!(f, "traffic weight {percent}% is out of range; use 0 to 100")
            }
            FunctionHostError::NoTraffic { version } => {
                write!(
                    f,
                    "version {version:?} is receiving no traffic, so it has never run; \
                     shift traffic onto it before health-checking"
                )
            }
            FunctionHostError::Empty { field } => {
                write!(f, "{field} must not be empty; set it in the function target")
            }
        }
    }
}

impl std::error::Error for FunctionHostError {}

/// The `FunctionHost` port: an adapter drives a serverless deploy target and
/// answers in the port's typed shapes.
///
/// Adapters must fail with [`FunctionHostError`] rather than panicking, and
/// must not let a publish report success for an artifact whose digest did not
/// match.
pub trait FunctionHost: Send + Sync {
    /// Uploads and deploys `artifact`, returning the version the host created.
    /// When the artifact carries a digest, the adapter must verify it first
    /// and fail the publish on a mismatch — a bundle that is not what the run
    /// recorded must not ship under a green run.
    fn publish<'a>(
        &'a self,
        artifact: &'a Artifact,
    ) -> BoxFuture<'a, Result<Version, FunctionHostError>>;

    /// Shifts `split`'s share of traffic onto that version, rebalancing the
    /// others. Returns once the host has accepted the new weights; whether the
    /// version is *serving* is a [`FunctionHost::health`] question.
    fn shift<'a>(&'a self, split: &'a TrafficSplit)
    -> BoxFuture<'a, Result<(), FunctionHostError>>;

    /// The version's health, in the shared
    /// [`HealthReport`](super::health) vocabulary, so a `wait` step means the
    /// same thing here as on a cluster or a host. A version that exists but
    /// receives no traffic is [`FunctionHostError::NoTraffic`] — it has never
    /// run, and an adapter must not report it healthy on that basis. A version
    /// whose cold start has not produced an observation is
    /// [`Health::NoData`](super::health::Health), not healthy.
    fn health<'a>(
        &'a self,
        version: &'a Version,
    ) -> BoxFuture<'a, Result<HealthReport, FunctionHostError>>;

    /// Asks the host to keep `count` instances of `version` provisioned so the
    /// first real request is not the cold start. Purely an optimisation: a
    /// host that cannot pre-warm must succeed with no effect rather than
    /// failing the deploy.
    fn keep_warm<'a>(
        &'a self,
        version: &'a Version,
        count: u32,
    ) -> BoxFuture<'a, Result<(), FunctionHostError>>;

    /// Returns traffic to the version it was on before the shift, and reports
    /// which version that was — the run log records where traffic actually
    /// went, not what the caller intended. Takes no version argument on
    /// purpose: a caller-supplied one could roll back to a version traffic
    /// was never on.
    fn rollback<'a>(&'a self) -> BoxFuture<'a, Result<Version, FunctionHostError>>;

    /// A request pinned to `version`: the headers and/or preview URL that
    /// address it exactly, bypassing the traffic split. Synchronous — it is
    /// arithmetic over the version, not a call.
    ///
    /// Smoke checks send their request through this rather than at the
    /// production hostname, so a check exercises the version that was just
    /// published.
    fn pinned<'a>(&'a self, version: &'a Version) -> Pinned;

    /// Whether this host reveals *which* version answered a pinned request —
    /// in a response header, a preview URL that only serves one version, or
    /// some other observable.
    ///
    /// When this is `false` and the host ignores the pin, it serves the
    /// request from the **default split** instead: a healthy response, from
    /// the old version, with nothing wrong-looking about it. A step that
    /// assumes its pin held would then smoke-test code that is not deployed
    /// and pass. So when this is `false`, a step must verify which version
    /// answered before believing a green check — and if the host offers no
    /// way to tell, it must not claim the check covered the new version.
    fn pin_is_detectable(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::health::Health;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    fn version(id: &str) -> Version {
        Version::new(id).expect("named version")
    }

    #[test]
    fn the_function_host_trait_is_dyn_compatible() {
        assert_send_sync::<dyn FunctionHost>();
    }

    #[test]
    fn versions_reject_an_empty_id() {
        assert_eq!(Version::new(""), Err(FunctionHostError::Empty { field: "version id" }));
        assert_eq!(Version::new("   "), Err(FunctionHostError::Empty { field: "version id" }));
        assert_eq!(version("a1b2c3d4").id(), "a1b2c3d4");
        assert_eq!(version("v173").to_string(), "v173");
    }

    #[test]
    fn an_artifact_pins_a_digest_only_when_the_step_gave_one() {
        assert_eq!(
            Artifact::new("", None),
            Err(FunctionHostError::Empty { field: "artifact uri" })
        );
        assert_eq!(
            Artifact::new("   ", None),
            Err(FunctionHostError::Empty { field: "artifact uri" })
        );

        let loose = Artifact::new("s3://builds/api.zip", None).expect("named uri");
        assert_eq!(loose.uri(), "s3://builds/api.zip");
        assert_eq!(loose.digest(), None);

        // An empty optional digest means "no digest", not "a digest that can
        // never match".
        let blank = Artifact::new("s3://builds/api.zip", Some(String::new())).expect("named uri");
        assert_eq!(blank.digest(), None);

        let pinned = Artifact::new("oci://registry/api:v7", Some("sha256:abc123".to_string()))
            .expect("named uri");
        assert_eq!(pinned.uri(), "oci://registry/api:v7");
        assert_eq!(pinned.digest(), Some("sha256:abc123"));
    }

    #[test]
    fn a_traffic_split_rejects_a_percentage_over_one_hundred() {
        let half = TrafficSplit::new(version("v7"), 50).expect("half");
        assert_eq!(half.version(), &version("v7"));
        assert_eq!(half.percent(), 50);

        let all = TrafficSplit::new(version("v7"), 100).expect("all");
        assert_eq!(all.percent(), 100);
        let none = TrafficSplit::new(version("v7"), 0).expect("none");
        assert_eq!(none.percent(), 0);

        assert_eq!(
            TrafficSplit::new(version("v7"), 101),
            Err(FunctionHostError::WeightOutOfRange { percent: 101 })
        );
        assert_eq!(
            TrafficSplit::new(version("v7"), 255),
            Err(FunctionHostError::WeightOutOfRange { percent: 255 })
        );
    }

    #[test]
    fn a_pinned_request_takes_either_shape_and_needs_no_host_knowledge() {
        // An empty URL is not "no URL": it would send the check to the
        // production hostname, which is the unpinned request a pin exists to
        // replace.
        assert_eq!(
            Pinned::new(version("v7"), Vec::new(), Some(String::new())),
            Err(FunctionHostError::Empty { field: "pinned url" })
        );

        // Workers: no preview URL, a version-override header instead.
        let by_header = Pinned::new(
            version("a1b2c3d4"),
            vec![(
                "Cloudflare-Workers-Version-Overrides".to_string(),
                "api=\"a1b2c3d4\"".to_string(),
            )],
            None,
        )
        .expect("header pin");
        assert_eq!(by_header.version(), &version("a1b2c3d4"));
        assert_eq!(by_header.url(), None);
        assert_eq!(by_header.headers().len(), 1);
        assert_eq!(
            by_header.headers()[0],
            ("Cloudflare-Workers-Version-Overrides".to_string(), "api=\"a1b2c3d4\"".to_string())
        );

        // A Lambda alias or Cloud Run tag: a URL of its own.
        let by_url =
            Pinned::new(version("v7"), Vec::new(), Some("https://api-v7.run.app".to_string()))
                .expect("url pin");
        assert_eq!(by_url.url(), Some("https://api-v7.run.app"));
        assert!(by_url.headers().is_empty());
        assert_eq!(by_url.version(), &version("v7"));
    }

    #[test]
    fn a_version_that_never_received_traffic_is_not_healthy() {
        // The health gate and the split are separate: an unpinned version that
        // has never served a request cannot answer a health check, so it is
        // NoData, not Healthy.
        let cold = HealthReport::with_reason(Health::NoData, "version has not been invoked");
        assert!(!cold.satisfies(Health::Healthy));
        assert!(
            FunctionHostError::NoTraffic { version: "v7".to_string() }
                .to_string()
                .contains("never run")
        );
    }

    #[test]
    fn function_host_errors_display_actionably() {
        let publish =
            FunctionHostError::Publish { message: "quota exceeded".to_string() }.to_string();
        assert!(publish.contains("quota exceeded") && publish.contains("digest"), "{publish}");

        let unknown = FunctionHostError::UnknownVersion { version: "v9".to_string() }.to_string();
        assert!(unknown.contains("v9") && unknown.contains("publish it first"), "{unknown}");

        let weight = FunctionHostError::WeightOutOfRange { percent: 150 }.to_string();
        assert!(weight.contains("150") && weight.contains("0 to 100"), "{weight}");

        let empty = FunctionHostError::Empty { field: "version id" }.to_string();
        assert!(empty.contains("version id") && empty.contains("must not be empty"), "{empty}");
    }
}
