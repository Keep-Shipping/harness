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

use std::fmt;

use super::BoxFuture;
use super::health::{Health, HealthReport};

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
    /// [`Manifest::new`], [`ServiceAccount::named`] and
    /// [`ExecCredential::plugin`] before any call is made.
    Empty {
        /// The empty field's name.
        name: &'static str,
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
        }
    }
}

impl std::error::Error for ClusterError {}

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

    /// Installs or upgrades the named chart `release` and reports the rollout
    /// it started. A release the cluster does not have is
    /// [`ClusterError::NotFound`] only when the adapter is configured not to
    /// install new releases; installing is the default, and a failed upgrade
    /// is [`ClusterError::Upgrade`].
    fn upgrade<'a>(&'a self, release: &'a str) -> BoxFuture<'a, Result<Rollout, ClusterError>>;

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
}
