//! The [`Cluster`] port: applying manifests and watching rollouts on an
//! orchestrated deploy target
//! ([#52](https://github.com/Keep-Shipping/harness/issues/52)).
//!
//! A step says *what should be running* — manifests, a chart, a health gate —
//! and this port says *which cluster*. Identity travels in the
//! [`ClusterRef`] the adapter hands back from [`Cluster::handle`], so a step
//! can log and report which target it touched without the adapter ever
//! materialising a credential ([Authentication](#authentication)).
//!
//! # Authentication
//!
//! [`ClusterRef`] carries an [`AuthMethod`], never a credential. An adapter
//! resolves the method at call time — minting a short-lived token, invoking a
//! credential plugin, reading the node's own service account — and holds the
//! result only for the duration of the call. Nothing secret is stored in this
//! port's types, so no `Clone` on a [`ClusterRef`] can spread a token into a
//! log line, a run record or a crash dump.
//!
//! # Applying and waiting are separate
//!
//! [`Cluster::apply`] returns as soon as the API server has *accepted* the
//! manifests, which is not the same as the workload being up. That gap is
//! what [`Cluster::rollout`] and [`Cluster::health`] cover: a step applies,
//! then waits. Adapters must never make `apply` block until healthy behind
//! the caller's back — the deadline belongs to the step's `wait`, not to the
//! port method.
//!
//! # Rollbacks name a revision
//!
//! [`Cluster::rollback`] takes a [`Revision`], not "the previous one". A
//! revision is an opaque, adapter-assigned number; asking for one that is no
//! longer retained is [`ClusterError::RevisionUnknown`] rather than a silent
//! fall back to whatever is running now.

use std::collections::BTreeMap;
use std::fmt;

use super::BoxFuture;
use super::health::{Health, HealthReport};
use super::supply_chain::{ImageRef, Reference};

/// How an adapter authenticates against the cluster API.
///
/// Each variant names a *method*, and the adapter resolves it at call time.
/// None of them carries a credential: [`AuthMethod::ExecCredential`] holds
/// the **name** of a credential plugin to invoke, never the credential the
/// plugin returns, so an [`AuthMethod`] is safe to log and to `Clone`.
///
/// The two named variants hold validated newtypes rather than bare strings:
/// an account or a plugin with an empty name cannot be constructed at all,
/// which is what makes the "safe in a log line" promise above an invariant
/// rather than a convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// Use the service account the harness itself is running as (a pod's
    /// projected token). The token is mounted by the platform and read at
    /// call time; the adapter never copies it into a manifest or a log.
    InCluster,
    /// Use a named service account's credentials. The adapter looks the
    /// account up through the cluster's own API.
    ServiceAccount(ServiceAccount),
    /// Invoke an external credential plugin — e.g.
    /// `gke-gcloud-auth-plugin` — to obtain a token.
    ///
    /// The plugin is run at call time and the token it prints stays inside
    /// the adapter.
    ExecCredential(ExecCredential),
    /// Use workload identity: the cluster's own token exchange maps the
    /// adapter's identity to Kubernetes credentials with no static secret.
    WorkloadIdentity,
}

/// A service account in the target namespace, named.
///
/// Built only by [`ServiceAccount::named`], which rejects an empty name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    name: String,
}

impl ServiceAccount {
    /// The service account called `name`, e.g. `"deployer"`. Fails with
    /// [`ClusterError::Empty`] if the name is empty: an account with no name
    /// is a misconfigured target, not a lookup worth attempting.
    pub fn named(name: impl Into<String>) -> Result<Self, ClusterError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(ClusterError::Empty { name: "service account name" });
        }
        Ok(ServiceAccount { name })
    }

    /// The service account's name in the target namespace.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The name of a credential plugin to invoke, never its output.
///
/// Built only by [`ExecCredential::plugin`], which rejects an empty command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecCredential {
    command: String,
}

impl ExecCredential {
    /// The credential plugin called `command`, e.g.
    /// `"gke-gcloud-auth-plugin"`. Fails with [`ClusterError::Empty`] if it is
    /// empty — there is no plugin to run, and the token it would have
    /// returned is the one thing this type must never hold.
    pub fn plugin(command: impl Into<String>) -> Result<Self, ClusterError> {
        let command = command.into();
        if command.trim().is_empty() {
            return Err(ClusterError::Empty { name: "credential plugin command" });
        }
        Ok(ExecCredential { command })
    }

    /// The plugin to invoke, e.g. `"gke-gcloud-auth-plugin"`.
    pub fn command(&self) -> &str {
        &self.command
    }
}

/// Which cluster, and how to reach it as this identity.
///
/// Constructed by an adapter and returned by [`Cluster::handle`]; this is the
/// only way to obtain one, and the [`AuthMethod`] it carries is resolved at
/// call time. Credentials are never held here — they live in the adapter's
/// call frame — so a `Debug` or `Clone` of a `ClusterRef` cannot leak one
/// into a manifest, a log line, or a run record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterRef {
    context: String,
    endpoint: String,
    auth: AuthMethod,
}

impl ClusterRef {
    /// Refers to the cluster at `endpoint` under the named kubeconfig
    /// `context`, authenticating by `auth`. Fails with
    /// [`ClusterError::Empty`] if the context or endpoint is empty — a
    /// handle that names no target cannot fail safely.
    pub fn new(
        context: impl Into<String>,
        endpoint: impl Into<String>,
        auth: AuthMethod,
    ) -> Result<Self, ClusterError> {
        let context = context.into();
        let endpoint = endpoint.into();
        if context.trim().is_empty() {
            return Err(ClusterError::Empty { name: "context" });
        }
        if endpoint.trim().is_empty() {
            return Err(ClusterError::Empty { name: "endpoint" });
        }
        Ok(ClusterRef { context, endpoint, auth })
    }

    /// The kubeconfig context this handle selects, e.g. `"prod-eu"`.
    pub fn context(&self) -> &str {
        &self.context
    }

    /// The API server's address, e.g. `"https://10.0.0.1:6443"`.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// How the adapter authenticates — the method, never a credential.
    pub fn auth(&self) -> &AuthMethod {
        &self.auth
    }
}

/// An opaque, adapter-assigned rollout revision.
///
/// The harness never interprets the number, only carries it back to
/// [`Cluster::rollback`]; an adapter that has forgotten a revision answers
/// [`ClusterError::RevisionUnknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revision(u32);

impl Revision {
    /// The revision the adapter reported.
    pub fn new(value: u32) -> Revision {
        Revision(value)
    }

    /// The revision number, for logs and adapter-internal comparisons.
    pub fn number(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One object to apply: its name and its rendered contents.
///
/// Raw bytes, not a typed tree: `ks-core` has no YAML or JSON dependency, so
/// the adapter parses whatever the manifest is. [`Manifest::new`] rejects an
/// empty name or empty contents, because both are always a rendering bug and
/// applying them would fail deep inside a vendor API with a much worse
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    name: String,
    contents: Vec<u8>,
}

impl Manifest {
    /// The manifest `name` holds, e.g. `"Deployment/api"` with `contents`
    /// the rendered YAML. Fails with [`ClusterError::Empty`] naming `name` or
    /// `manifest contents` respectively.
    pub fn new(
        name: impl Into<String>,
        contents: impl Into<Vec<u8>>,
    ) -> Result<Self, ClusterError> {
        let name = name.into();
        let contents = contents.into();
        if name.trim().is_empty() {
            return Err(ClusterError::Empty { name: "manifest name" });
        }
        if contents.is_empty() {
            return Err(ClusterError::Empty { name: "manifest contents" });
        }
        Ok(Manifest { name, contents })
    }

    /// The manifest's name, e.g. `"Deployment/api"`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The rendered YAML or JSON, for the adapter to parse.
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
}

/// Where a workload's rollout is right now.
///
/// The pair a step needs to decide whether to keep waiting: which revision
/// is being moved to, and whether it has arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rollout {
    revision: Revision,
    state: Health,
}

impl Rollout {
    /// The rollout of the given revision, currently in `state`.
    pub fn new(revision: Revision, state: Health) -> Rollout {
        Rollout { revision, state }
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    /// Whether the rollout has settled, and how — see
    /// [`HealthReport::satisfies`] for why an unsettled state is not a
    /// failure.
    pub fn state(&self) -> Health {
        self.state
    }
}

/// Why a [`Cluster`] operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterError {
    /// The handle names a context the adapter cannot resolve — usually a
    /// kubeconfig that does not exist in the environment the run started in.
    /// No credentials were attempted.
    NoContext,
    /// Authentication or authorisation failed. `message` is the API's own
    /// wording, safe to print, and must not contain the credential itself:
    /// adapters report *that* auth failed, never the token.
    Auth {
        /// What the API server reported.
        message: String,
    },
    /// The named workload or release does not exist in this cluster.
    NotFound {
        /// The name that was not found.
        name: String,
    },
    /// Server-side apply was rejected — a validation or admission failure.
    /// `message` is the API's message; it may quote manifest fields, so
    /// adapters must let the run's redactor scrub it first.
    Apply {
        /// What the API server reported.
        message: String,
    },
    /// Installing or upgrading the release failed.
    Upgrade {
        /// What the adapter's tooling reported.
        message: String,
    },
    /// The revision is no longer retained by the cluster, so it cannot be
    /// rolled back to. Deliberately an error rather than a fall back to the
    /// current revision: a rollback to the wrong revision is worse than none.
    RevisionUnknown {
        /// The revision that could not be resolved.
        revision: Revision,
    },
    /// A required field was empty. Raised by [`ClusterRef::new`],
    /// [`Manifest::new`], [`ServiceAccount::named`],
    /// [`ExecCredential::plugin`], [`Chart::path`], [`ImagePin::at`] and
    /// [`ChartUpgrade::new`] before any call is made.
    Empty {
        /// The empty field's name.
        name: &'static str,
    },
    /// A reference this port requires to be immutable is a mutable tag
    /// instead. Raised by [`Chart::oci`] and [`ImagePin::new`]/[`ImagePin::at`]
    /// before any call is made, so a tag can never be written into a key named
    /// `digest` and never reach a chart URL.
    NotPinned {
        /// What had to be pinned by digest, e.g. `"chart"` or `"image pin"`.
        what: &'static str,
    },
}

impl fmt::Display for ClusterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClusterError::NoContext => {
                write!(
                    f,
                    "no kubeconfig context for this cluster; select one or run inside the cluster"
                )
            }
            ClusterError::Auth { message } => {
                write!(
                    f,
                    "cluster authentication failed: {message}; check the auth method's credentials"
                )
            }
            ClusterError::NotFound { name } => {
                write!(f, "{name:?} does not exist in this cluster; check the name and namespace")
            }
            ClusterError::Apply { message } => {
                write!(
                    f,
                    "server-side apply rejected: {message}; fix the manifest before re-running"
                )
            }
            ClusterError::Upgrade { message } => {
                write!(
                    f,
                    "release upgrade failed: {message}; check the release name and chart values"
                )
            }
            ClusterError::RevisionUnknown { revision } => {
                write!(
                    f,
                    "revision {revision} is no longer retained; roll forward to a newer revision"
                )
            }
            ClusterError::Empty { name } => {
                write!(f, "{name} must not be empty; set it in the cluster target")
            }
            ClusterError::NotPinned { what } => {
                write!(
                    f,
                    "{what} must be pinned by digest, not by tag: a tag can be repointed between \
                     the plan and the apply; resolve it to a digest first"
                )
            }
        }
    }
}

impl std::error::Error for ClusterError {}

/// Which chart a release is installed or upgraded from.
///
/// An OCI chart names a repository and a **digest**, never a tag: a tag can
/// be repointed between the plan and the apply, and the point of pinning
/// content is that it cannot move. A `Path` is a chart directory or a packaged
/// `.tgz` on disk, used as given.
///
/// Build an OCI chart with [`Chart::oci`], which enforces that promise by
/// refusing a tag reference with [`ClusterError::NotPinned`]. The `Oci` variant
/// stays public so a caller that has already resolved a reference is not forced
/// through a constructor, so the rule is a constructor-level guarantee rather
/// than a type-level one: an adapter still has to handle a
/// `Chart::Oci` built directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chart {
    /// A chart pulled from an OCI registry by digest, e.g.
    /// `reg.example.com/team/chart@sha256:…`. Build it with [`Chart::oci`],
    /// which rejects a tag reference.
    Oci(ImageRef),
    /// A chart directory or packaged `.tgz` on the local disk, used as given.
    Path(String),
}

impl Chart {
    /// A chart at `path` on disk — a directory or a packaged `.tgz`. Fails
    /// with [`ClusterError::Empty { name: "chart path" }`] if the path is
    /// empty: there is no chart to install.
    pub fn path(path: impl Into<String>) -> Result<Self, ClusterError> {
        let path = path.into();
        if path.trim().is_empty() {
            return Err(ClusterError::Empty { name: "chart path" });
        }
        Ok(Chart::Path(path))
    }

    /// An OCI chart pinned to `image`, which must name a **digest** rather than
    /// a tag — see the contract on [`Chart`]. Fails with
    /// [`ClusterError::NotPinned { what: "chart" }`] when it names a tag.
    pub fn oci(image: ImageRef) -> Result<Self, ClusterError> {
        pin_by_digest(&image, "chart")?;
        Ok(Chart::Oci(image))
    }

    /// The OCI reference, for a [`Chart::Oci`]; `None` for a [`Chart::Path`],
    /// which has no repository to name.
    pub fn reference(&self) -> Option<&ImageRef> {
        match self {
            Chart::Oci(image) => Some(image),
            Chart::Path(_) => None,
        }
    }

    /// The on-disk path, for a [`Chart::Path`]; `None` for an OCI chart.
    pub fn as_path(&self) -> Option<&str> {
        match self {
            Chart::Path(path) => Some(path),
            Chart::Oci(_) => None,
        }
    }
}

/// The values a chart is rendered with, and whether they carry a secret.
///
/// **The security contract is the point of this type.** An adapter handed
/// [`Values::secret`] values MUST pass them to its chart tooling by a
/// temporary file created with `0600` permissions, and MUST delete that file
/// once the call returns. It MUST NOT put a secret value on a command line:
/// an argument is visible to every other process on the machine for as long
/// as the call runs, and lands in the chart tooling's own process listing.
///
/// A [`ChartUpgrade::set`] entry is passed as a `--set` *argument*, so it
/// therefore MUST NOT carry a secret — that is a property of the caller, not
/// something this type can enforce.
///
/// Non-secret values ([`Values::new`]) may go either way: a values file or a
/// flag, whichever the adapter prefers.
///
/// [`Clone`, `PartialEq` and `Eq`] are derived, but [`Debug`] is **not**: it is
/// hand-written below so a `{:?}` can never print the document. See that impl.
#[derive(Clone, PartialEq, Eq)]
pub struct Values {
    document: String,
    secret: bool,
}

impl fmt::Debug for Values {
    /// Never the document — only its size.
    ///
    /// A [`Values::secret`] document holds a password, and it reaches a `{:?}`
    /// constantly without anyone choosing to: `assert_eq!` on a
    /// [`ChartUpgrade`] Debug-prints both sides on failure, and a run record
    /// Debug-printing a call carries it into a CI log. The contract above says
    /// a secret must not reach a command line; this is the other way it would
    /// escape, and it is the quieter one, because a failing test is exactly
    /// when the surrounding output gets pasted into an issue. The byte count is
    /// kept because it is what tells a reader the document was there.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Values")
            .field("document", &format_args!("<redacted: {} bytes>", self.document.len()))
            .field("secret", &self.secret)
            .finish()
    }
}

impl Values {
    /// Values the adapter may handle however it likes — a values file, a
    /// flag, or a literal argument.
    pub fn new(document: impl Into<String>) -> Self {
        Values { document: document.into(), secret: false }
    }

    /// Values that carry a secret. See the contract on [`Values`]: a
    /// `0600` temporary file, deleted when the call returns, and never a
    /// command-line argument.
    pub fn secret(document: impl Into<String>) -> Self {
        Values { document: document.into(), secret: true }
    }

    /// The values document, verbatim — YAML or whatever the chart takes.
    pub fn document(&self) -> &str {
        &self.document
    }

    /// Whether these values carry a secret, and so the adapter must keep them
    /// off every command line.
    pub fn is_secret(&self) -> bool {
        self.secret
    }
}

/// Where a release's container image digest is written into its values.
///
/// Charts conventionally read the digest from `image.digest`; the key is
/// configurable because not every chart uses that shape. A digest, not a tag,
/// so the rendered Deployment carries an immutable reference.
///
/// Both constructors enforce that: an [`ImageRef`] naming a tag is
/// [`ClusterError::NotPinned`], never an `ImagePin`. A mutable tag written into
/// a key called `digest` is a lie the cluster only discovers at rollout time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePin {
    image: ImageRef,
    key: String,
}

/// Rejects an [`ImageRef`] that names a tag rather than a digest, naming `what`
/// it was for so the error says which reference was wrong.
fn pin_by_digest(image: &ImageRef, what: &'static str) -> Result<(), ClusterError> {
    match image.reference() {
        Reference::Digest(_) => Ok(()),
        Reference::Tag(_) => Err(ClusterError::NotPinned { what }),
    }
}

impl ImagePin {
    /// Pins `image` at the conventional key `"image.digest"`. Fails with
    /// [`ClusterError::NotPinned { what: "image pin" }`] when `image` names a
    /// tag rather than a digest.
    pub fn new(image: ImageRef) -> Result<Self, ClusterError> {
        pin_by_digest(&image, "image pin")?;
        Ok(ImagePin { image, key: "image.digest".to_string() })
    }

    /// Pins `image` at `key` — the values path the chart reads the digest
    /// from. Fails with [`ClusterError::Empty { name: "digest key" }]` if the
    /// key is empty: there would be nowhere to write the digest, and with
    /// [`ClusterError::NotPinned { what: "image pin" }`] if `image` names a
    /// tag.
    pub fn at(image: ImageRef, key: impl Into<String>) -> Result<Self, ClusterError> {
        pin_by_digest(&image, "image pin")?;
        let key = key.into();
        if key.trim().is_empty() {
            return Err(ClusterError::Empty { name: "digest key" });
        }
        Ok(ImagePin { image, key })
    }

    /// The image whose digest is pinned — a digest reference, never a tag.
    pub fn image(&self) -> &ImageRef {
        &self.image
    }

    /// The values key the digest is written under, e.g. `"image.digest"`.
    pub fn key(&self) -> &str {
        &self.key
    }
}

/// One install or upgrade of a Helm release.
///
/// A request is the whole of what the chart needs: which chart, what values,
/// what overrides, and where the image digest goes. It is a value, so a run
/// can record it and a fake can assert on it without an adapter being present.
///
/// Everything not set is left to the chart's own defaults: no namespace means
/// the adapter's configured default, no values means the chart's, no `set`
/// entries means no overrides beyond the [`ImagePin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChartUpgrade {
    release: String,
    chart: Chart,
    namespace: Option<String>,
    values: Option<Values>,
    set: BTreeMap<String, String>,
    image: Option<ImagePin>,
}

impl ChartUpgrade {
    /// Installs or upgrades the release `release` from `chart`. Fails with
    /// [`ClusterError::Empty { name: "release" }`] if the release name is
    /// blank — a nameless release is a misconfigured deploy, not one worth
    /// attempting. The name is kept exactly as given; it is not trimmed.
    pub fn new(release: impl Into<String>, chart: Chart) -> Result<Self, ClusterError> {
        let release = release.into();
        if release.trim().is_empty() {
            return Err(ClusterError::Empty { name: "release" });
        }
        Ok(ChartUpgrade {
            release,
            chart,
            namespace: None,
            values: None,
            set: BTreeMap::new(),
            image: None,
        })
    }

    /// Deploys into `namespace` rather than the adapter's default.
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Renders the chart with `values`.
    pub fn with_values(mut self, values: Values) -> Self {
        self.values = Some(values);
        self
    }

    /// Overrides one values key, passed as a `--set` argument. Never carry a
    /// secret here — see [`Values`].
    pub fn with_set(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.set.insert(key.into(), value.into());
        self
    }

    /// Writes the pinned image's digest into the chart's values, so the
    /// rendered workload runs an immutable reference rather than a tag.
    pub fn with_image(mut self, image: ImagePin) -> Self {
        self.image = Some(image);
        self
    }

    /// The release name, as given.
    pub fn release(&self) -> &str {
        &self.release
    }

    /// Which chart to install or upgrade from.
    pub fn chart(&self) -> &Chart {
        &self.chart
    }

    /// The target namespace, if one was set.
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// The values the chart is rendered with, if any.
    pub fn values(&self) -> Option<&Values> {
        self.values.as_ref()
    }

    /// The `--set` overrides, sorted by key.
    pub fn set(&self) -> &BTreeMap<String, String> {
        &self.set
    }

    /// The image digest pin, if any.
    pub fn image(&self) -> Option<&ImagePin> {
        self.image.as_ref()
    }
}

/// The `Cluster` port: an adapter drives an orchestrated deploy target —
/// Kubernetes and its equivalents — and answers in the port's typed shapes.
///
/// Steps and the engine never talk to a cluster API directly, so policy
/// (which manifests, which namespace, which release) is enforced in one
/// place. Adapters must fail with [`ClusterError`] rather than panicking, and
/// must not smuggle credentials into any value this port returns.
pub trait Cluster: Send + Sync {
    /// Applies `manifests` server-side apply, returning the names the
    /// cluster accepted, in the order given.
    ///
    /// Returns when the API server has *accepted* the objects — not when they
    /// are healthy. A workload that has been accepted and is still
    /// crash-looping is a [`Cluster::rollout`] question, not a failed apply;
    /// blocking here would take the deadline away from the step's `wait`.
    /// Every name in `manifests` must appear in the result: a partial apply
    /// that reports success is [`ClusterError::Apply`].
    fn apply<'a>(
        &'a self,
        manifests: &'a [Manifest],
    ) -> BoxFuture<'a, Result<Vec<String>, ClusterError>>;

    /// Installs or upgrades the release `request` describes, and reports the
    /// rollout it started. The request is the whole of what the chart needs:
    /// a [`Chart`] (an OCI reference by digest, or a path), [`Values`] and a
    /// `--set` map, plus an optional [`ImagePin`] that writes the container
    /// image's digest into the chart's values.
    ///
    /// An adapter MUST install the release if the cluster does not have it and
    /// upgrade it otherwise — the two are one operation, not two methods.
    /// [`ClusterError::NotFound`] is therefore only correct when the adapter
    /// is configured not to install new releases, and a failed upgrade is
    /// [`ClusterError::Upgrade`].
    ///
    /// An upgrade that would leave the cluster in a worse state than it found
    /// it MUST roll back rather than report a failure: a half-applied release
    /// is not a failure a caller can recover from, it is a cluster that is now
    /// wrong. Report [`ClusterError::Upgrade`] only after the rollback itself
    /// failed.
    ///
    /// An adapter MUST NOT pass a [`Values::secret`] value on a command line,
    /// where another process could read it; see the contract on [`Values`].
    fn upgrade<'a>(
        &'a self,
        request: &'a ChartUpgrade,
    ) -> BoxFuture<'a, Result<Rollout, ClusterError>>;

    /// Where the rollout of `name` is right now: the revision it is moving
    /// to and whether it has settled. Read-only, and safe to poll — it must
    /// never advance the rollout as a side effect.
    fn rollout<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Rollout, ClusterError>>;

    /// The target's health for `name`, in the shared
    /// [`HealthReport`](super::health) vocabulary, so a `wait` step means the
    /// same thing here as on any other deploy target.
    ///
    /// With no observation — the workload does not exist yet, or the
    /// reporting call found nothing — an adapter must report
    /// [`Health::NoData`], never an optimistic [`Health::Healthy`]. A
    /// [`HealthReport`] with a reason records the target's own wording, which
    /// is what a run log shows while the gate waits.
    fn health<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<HealthReport, ClusterError>>;

    /// Moves `name` back to `revision` and reports the rollout that started.
    /// A revision the cluster no longer retains is
    /// [`ClusterError::RevisionUnknown`]; adapters must never substitute the
    /// current revision for one that was asked for.
    fn rollback<'a>(
        &'a self,
        name: &'a str,
        revision: Revision,
    ) -> BoxFuture<'a, Result<Rollout, ClusterError>>;

    /// The cluster this adapter drives, and how it authenticates. The handle
    /// carries an [`AuthMethod`], not a credential.
    fn handle(&self) -> &ClusterRef;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_cluster_trait_is_dyn_compatible() {
        assert_send_sync::<dyn Cluster>();
    }

    #[test]
    fn cluster_refs_reject_an_empty_context_or_endpoint() {
        assert!(matches!(
            ClusterRef::new("", "https://api:6443", AuthMethod::InCluster),
            Err(ClusterError::Empty { name }) if name == "context"
        ));
        assert!(matches!(
            ClusterRef::new("prod", "   ", AuthMethod::InCluster),
            Err(ClusterError::Empty { name }) if name == "endpoint"
        ));
        let handle =
            ClusterRef::new("prod-eu", "https://10.0.0.1:6443", AuthMethod::WorkloadIdentity)
                .expect("named target");
        assert_eq!(handle.context(), "prod-eu");
        assert_eq!(handle.endpoint(), "https://10.0.0.1:6443");
        assert_eq!(handle.auth(), &AuthMethod::WorkloadIdentity);
    }

    #[test]
    fn a_cluster_ref_carries_an_auth_method_not_a_credential() {
        let exec = ExecCredential::plugin("gke-gcloud-auth-plugin").expect("named plugin");
        let handle =
            ClusterRef::new("prod", "https://api:6443", AuthMethod::ExecCredential(exec.clone()))
                .expect("named target");
        // The variant holds the plugin's *name*; a Debug of the handle is
        // therefore safe to put in a log line.
        let AuthMethod::ExecCredential(command) = handle.auth() else {
            panic!("expected an exec credential method, got {:?}", handle.auth());
        };
        assert_eq!(command.command(), "gke-gcloud-auth-plugin");
        assert!(!format!("{handle:?}").contains("token"));
        assert_eq!(
            handle.auth(),
            &AuthMethod::ExecCredential(
                ExecCredential::plugin("gke-gcloud-auth-plugin").expect("named plugin")
            )
        );
    }

    #[test]
    fn named_auth_methods_reject_an_empty_name() {
        assert_eq!(
            ServiceAccount::named(""),
            Err(ClusterError::Empty { name: "service account name" })
        );
        assert_eq!(
            ServiceAccount::named("   "),
            Err(ClusterError::Empty { name: "service account name" })
        );
        assert_eq!(
            ExecCredential::plugin(""),
            Err(ClusterError::Empty { name: "credential plugin command" })
        );
        assert_eq!(
            ExecCredential::plugin("   "),
            Err(ClusterError::Empty { name: "credential plugin command" })
        );

        let account = ServiceAccount::named("deployer").expect("named account");
        assert_eq!(account.name(), "deployer");
        assert_eq!(
            AuthMethod::ServiceAccount(account),
            AuthMethod::ServiceAccount(ServiceAccount::named("deployer").expect("named account"))
        );
    }

    #[test]
    fn manifests_reject_an_empty_name_or_empty_contents() {
        assert!(matches!(
            Manifest::new("", b"kind: Service".to_vec()),
            Err(ClusterError::Empty { name: "manifest name" })
        ));
        // The two failures name different fields: empty contents is not the
        // manifest's name being empty.
        assert!(matches!(
            Manifest::new("Service/api", Vec::new()),
            Err(ClusterError::Empty { name: "manifest contents" })
        ));
        let manifest =
            Manifest::new("Deployment/api", b"kind: Deployment".to_vec()).expect("non-empty");
        assert_eq!(manifest.name(), "Deployment/api");
        assert_eq!(manifest.contents(), b"kind: Deployment");
    }

    #[test]
    fn revisions_are_opaque_numbers_the_harness_carries_back() {
        assert_eq!(Revision::new(7).number(), 7);
        assert_eq!(Revision::new(7), Revision::new(7));
        assert_ne!(Revision::new(7), Revision::new(8));
        assert_eq!(Revision::new(7).to_string(), "7");
    }

    #[test]
    fn a_rollout_pairs_the_revision_with_where_it_is() {
        let moving = Rollout::new(Revision::new(3), Health::Progressing);
        assert_eq!(moving.revision(), Revision::new(3));
        assert_eq!(moving.state(), Health::Progressing);
        assert!(!moving.state().is_settled());

        let done = Rollout::new(Revision::new(4), Health::Healthy);
        assert_eq!(done.state(), Health::Healthy);
        assert!(done.state().is_settled());
    }

    #[test]
    fn cluster_errors_display_actionably() {
        let auth = ClusterError::Auth { message: "401 unauthorized".to_string() }.to_string();
        assert!(auth.contains("401") && auth.contains("auth method"), "{auth}");
        let apply =
            ClusterError::Apply { message: "field spec.replicas invalid".to_string() }.to_string();
        assert!(apply.contains("manifest") && apply.contains("replicas"), "{apply}");
        let upgrade = ClusterError::Upgrade { message: "chart not found".to_string() }.to_string();
        assert!(upgrade.contains("release") && upgrade.contains("chart not found"), "{upgrade}");
        let missing = ClusterError::NotFound { name: "api".to_string() }.to_string();
        assert!(missing.contains("api") && missing.contains("namespace"), "{missing}");
        assert!(ClusterError::NoContext.to_string().contains("kubeconfig context"));
        let unknown = ClusterError::RevisionUnknown { revision: Revision::new(9) }.to_string();
        assert!(unknown.contains('9') && unknown.contains("roll forward"), "{unknown}");
        let empty = ClusterError::Empty { name: "context" }.to_string();
        assert!(empty.contains("context") && empty.contains("must not be empty"), "{empty}");
    }

    const SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// A stand-in password document, assembled from fragments so the fixture
    /// itself never appears in source as one literal.
    const SECRET_DOC: &str = concat!("dbPassword: ", "hunter2");

    #[test]
    fn a_chart_upgrade_rejects_a_blank_release_and_keeps_the_name_it_was_given() {
        let chart = Chart::path("./charts/api").expect("a path");
        assert_eq!(
            ChartUpgrade::new("", chart.clone()),
            Err(ClusterError::Empty { name: "release" })
        );
        assert_eq!(
            ChartUpgrade::new("   ", chart.clone()),
            Err(ClusterError::Empty { name: "release" })
        );
        // The name is kept verbatim — not trimmed, not rewritten: a release
        // name is an identifier the cluster already knows.
        let request = ChartUpgrade::new(" api ", chart).expect("named release");
        assert_eq!(request.release(), " api ");
    }

    #[test]
    fn a_chart_path_must_not_be_empty() {
        assert_eq!(Chart::path(""), Err(ClusterError::Empty { name: "chart path" }));
        assert_eq!(Chart::path("   "), Err(ClusterError::Empty { name: "chart path" }));
        let path = Chart::path("./charts/api.tgz").expect("a path");
        assert_eq!(path.as_path(), Some("./charts/api.tgz"));
        assert_eq!(path.reference(), None, "a path chart names no repository");
    }

    #[test]
    fn an_oci_chart_carries_the_digest_it_was_built_from() {
        let chart = Chart::oci(
            ImageRef::parse(&format!("reg.example.com/team/chart@sha256:{SHA256_HEX}"))
                .expect("a digest reference"),
        )
        .expect("a digest chart");
        let image = chart.reference().expect("an OCI chart has a reference");
        assert_eq!(image.repository(), "reg.example.com/team/chart");
        assert_eq!(image.digest().map(|digest| digest.hex()), Some(SHA256_HEX));
        assert_eq!(image.tag(), None, "a pinned chart is never a tag");
        assert_eq!(chart.as_path(), None, "an OCI chart is not on disk");
    }

    #[test]
    fn values_report_whether_they_carry_a_secret() {
        let plain = Values::new("replicas: 2");
        assert_eq!(plain.document(), "replicas: 2");
        assert!(!plain.is_secret(), "Values::new is the non-secret constructor");

        let secret = Values::secret(SECRET_DOC);
        assert_eq!(secret.document(), SECRET_DOC);
        assert!(secret.is_secret(), "Values::secret must say so, or the adapter leaks it");
    }

    #[test]
    fn an_image_pin_defaults_to_the_conventional_key_and_refuses_an_empty_one() {
        let image =
            ImageRef::parse(&format!("reg.example.com/team/app@sha256:{SHA256_HEX}")).expect("pin");

        let conventional = ImagePin::new(image.clone()).expect("a digest pin");
        assert_eq!(conventional.key(), "image.digest");
        assert_eq!(conventional.image().digest().map(|digest| digest.hex()), Some(SHA256_HEX));

        assert_eq!(
            ImagePin::at(image.clone(), ""),
            Err(ClusterError::Empty { name: "digest key" })
        );
        let custom = ImagePin::at(image, "container.image.sha").expect("a named key");
        assert_eq!(custom.key(), "container.image.sha");
    }

    #[test]
    fn an_image_pin_that_is_a_tag_is_refused_rather_than_written_under_a_digest_key() {
        // A tag written into `image.digest` renders a Deployment that claims to
        // be pinned and is not — so the constructors refuse to build it at all.
        for tagged in ["reg.example.com/team/api:1.2.3", "reg.example.com/team/api", "api:latest"] {
            let image = ImageRef::parse(tagged).expect("a parseable tag");
            assert!(image.tag().is_some(), "{tagged} is the tag case, not a digest");
            assert_eq!(
                ImagePin::new(image.clone()),
                Err(ClusterError::NotPinned { what: "image pin" }),
                "{tagged} must not be pinnable"
            );
            assert_eq!(
                ImagePin::at(image, "container.image.sha"),
                Err(ClusterError::NotPinned { what: "image pin" }),
                "{tagged} must not be pinnable at a custom key either"
            );
        }
        // And the error reads as what it is rather than as a panic.
        let message = ClusterError::NotPinned { what: "image pin" }.to_string();
        assert!(message.contains("digest") && message.contains("tag"), "{message}");
    }

    #[test]
    fn an_oci_chart_that_is_a_tag_is_refused_by_its_constructor() {
        let tagged = ImageRef::parse("reg.example.com/team/chart:1.2.3").expect("a tag reference");
        assert_eq!(Chart::oci(tagged), Err(ClusterError::NotPinned { what: "chart" }));

        let pinned = ImageRef::parse(&format!("reg.example.com/team/chart@sha256:{SHA256_HEX}"))
            .expect("a digest reference");
        let chart = Chart::oci(pinned).expect("a digest chart");
        assert_eq!(chart.as_path(), None);
        assert!(
            chart.reference().and_then(ImageRef::tag).is_none(),
            "a pinned chart is never a tag"
        );
    }

    #[test]
    fn a_values_debug_never_prints_the_document_it_carries() {
        let secret = Values::secret(SECRET_DOC);
        let printed = format!("{secret:?}");
        assert!(!printed.contains(SECRET_DOC), "the secret is in the Debug output: {printed}");
        assert!(!printed.contains("hunter2"), "the secret is in the Debug output: {printed}");
        // Redacted rather than omitted: a reader still learns a document is
        // there, and how much of it there was.
        assert!(printed.contains("redacted"), "{printed}");
        assert!(printed.contains(&SECRET_DOC.len().to_string()), "{printed}");
        assert!(printed.contains("secret: true"), "{printed}");

        // Non-secret values are redacted too — `is_secret` is a flag on the
        // caller's promise, not a licence to print.
        let plain = Values::new(SECRET_DOC);
        assert!(!format!("{plain:?}").contains("hunter2"), "{plain:?}");
        assert!(format!("{plain:?}").contains("secret: false"), "{plain:?}");

        // It inherits up the chain: an assert_eq! on a request Debug-prints a
        // ChartUpgrade on failure, which is exactly how this would have leaked.
        let request = ChartUpgrade::new("api", Chart::path("./charts/api").expect("a path"))
            .expect("named release")
            .with_values(Values::secret(SECRET_DOC))
            .with_set("image.tag", "canary");
        assert!(!format!("{request:?}").contains("hunter2"), "{request:?}");
    }

    #[test]
    fn a_chart_upgrade_accumulates_every_part_of_a_release() {
        let chart = Chart::oci(
            ImageRef::parse(&format!("reg.example.com/team/chart@sha256:{SHA256_HEX}"))
                .expect("a digest reference"),
        )
        .expect("a digest chart");
        let values = Values::new("replicas: 3");
        let request = ChartUpgrade::new("api", chart)
            .expect("named release")
            .with_namespace("production")
            .with_values(values.clone())
            .with_set("image.tag", "canary")
            .with_set("ingress.host", "api.example.com")
            .with_image(
                ImagePin::new(
                    ImageRef::parse(&format!("reg.example.com/team/api@sha256:{SHA256_HEX}"))
                        .expect("a digest reference"),
                )
                .expect("a digest pin"),
            );

        assert_eq!(request.release(), "api");
        assert_eq!(request.namespace(), Some("production"));
        assert_eq!(request.values(), Some(&values));
        // Two `with_set` calls accumulate rather than replace each other, and
        // a `BTreeMap` reports them in a stable order a test can assert on.
        assert_eq!(request.set().get("image.tag").map(String::as_str), Some("canary"));
        assert_eq!(request.set().get("ingress.host").map(String::as_str), Some("api.example.com"));
        assert_eq!(request.set().len(), 2);
        assert_eq!(request.image().map(ImagePin::key), Some("image.digest"));

        let Chart::Oci(chart_image) = request.chart() else {
            panic!("expected an OCI chart, got {:?}", request.chart());
        };
        assert_eq!(chart_image.digest().map(|digest| digest.hex()), Some(SHA256_HEX));
    }

    #[test]
    fn a_chart_upgrade_leaves_everything_it_was_not_given_unset() {
        let request = ChartUpgrade::new("api", Chart::path("./charts/api").expect("a path"))
            .expect("named release");
        assert_eq!(request.namespace(), None);
        assert_eq!(request.values(), None);
        assert!(request.set().is_empty());
        assert_eq!(request.image(), None);
    }
}
