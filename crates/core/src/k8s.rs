//! Which cluster a run targets, and how it authenticates — a *method*, never
//! a credential ([#75](https://github.com/Keep-Shipping/harness/issues/75)).
//!
//! A step says *what should be running*; a [`Cluster`] says *where*: a kubeconfig
//! context or an API server URL, an optional namespace, and the method the run
//! authenticates by. The adapter resolves that method at call time — it mints a
//! token, invokes a credential plugin, or reads the node's own projected service
//! account — and holds the result for the length of one call.
//!
//! The same value comes from three places — an IaC output's flat records read by
//! [`Cluster::from_record`], a named kubeconfig context ([`Target::Context`]),
//! an environment setting — which is why it is a type and not a convention.
//! `ks-core` reads none of them: it has no YAML dependency and no file I/O, so
//! the kubeconfig is parsed by the adapter and this module only decides what a
//! target *is*, and refuses what it must not be.
//!
//! # Authentication
//!
//! [`Auth`] names a method, and that is the whole invariant — enforced by the
//! shape rather than by a lint: no variant has a field a token could live in, so
//! a [`Cluster`] is `Clone` and `Debug` and is therefore safe to log, to attach
//! to a run record and to put in a diagnostic. An [`ExecPlugin`] holds the *name*
//! of a plugin and the arguments to call it with; the token the plugin prints is
//! minted at call time and never comes back.
//!
//! The one value that can precede that token is an exec plugin's environment —
//! a profile, a region, and on a misconfigured record a static key — so the
//! plugin's [`Debug`](ExecPlugin) prints the variable names and not their
//! values, and a [`Cluster`] inherits that. Redaction lives there, at the
//! boundary where a value would otherwise escape, rather than in a rule about
//! which variable names look secret: the value is legitimately needed to spawn
//! the plugin, so only printing it has to change.
//!
//! # Inline credentials are refused, not discouraged
//!
//! [`Cluster::from_record`] rejects a record carrying `token`, `bearerToken`,
//! `client-key-data` and the rest of the kubeconfig's inline-credential keys —
//! and says which key it found. *Discouraging* it would be worthless here: an
//! IaC output is state. It is committed, it is in the plan a reviewer reads, it
//! is in the apply log, and it outlives the run that created it. A token written
//! there has to be rotated by hand, and nothing in the run that leaked it will
//! say so. A *path* is fine — `tokenFile`, `client-key`,
//! `certificate-authority-data` — because a path is not a secret, and the CA
//! certificate is public by definition.
//!
//! An exec plugin's command is refused for the same reason a token is: it
//! becomes arbitrary command execution the moment an adapter runs it through a
//! shell. The plugin is spawned directly, so its command is one program name —
//! no whitespace, no metacharacter — which also refuses `sh -c '…'` outright.
//!
//! Validation failures are [`ClusterError`]s: a missing field is
//! [`ClusterError::Empty`], while anything about *how* the run would
//! authenticate — a shell metacharacter, a key that carries a credential, an
//! `auth` value nobody recognises — is [`ClusterError::Auth`], because that is
//! the question its message answers.

use std::collections::BTreeMap;
use std::fmt;

use crate::ports::cluster::{AuthMethod, ClusterError, ClusterRef, ExecCredential, ServiceAccount};

/// The `exec` stanza version used when a record names none.
pub const DEFAULT_EXEC_API_VERSION: &str = "client.authentication.k8s.io/v1beta1";

/// The four values `auth` accepts, as both refusals write them: a record that
/// leaves the method out and a record that invents one are the same mistake
/// told two ways, and the reader is better served by one spelling of the answer.
const AUTH_METHODS: &str = "`in-cluster`, `workload-identity`, `service-account` or `exec`";

/// Record keys whose value would *be* the credential, by their last segment.
/// Matched exactly, so a `tokenFile` or a `client-key` path is unaffected:
/// only inline content is refused.
const INLINE_CREDENTIAL_KEYS: &[&str] = &[
    "token",
    "id-token",
    "idToken",
    "access-token",
    "accessToken",
    "bearerToken",
    "bearer-token",
    "password",
    "username",
    "client-certificate-data",
    "clientCertificateData",
    "client-key-data",
    "clientKeyData",
];

/// Characters that make an exec plugin's command something a shell would read.
const SHELL_METACHARACTERS: &[char] = &[
    '\'', '"', '`', '$', '|', '&', ';', '<', '>', '(', ')', '{', '}', '*', '?', '!', '~', '#', '\\',
];

/// How the cluster is named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A named kubeconfig context — `kind-kind` locally, a cloud provider's own
    /// tool's context in a cluster.
    Context {
        /// The context's name, e.g. `"prod-eu"`.
        context: String,
        /// The kubeconfig to read it from, when not the one the environment
        /// points at. A path, never a credential.
        kubeconfig: Option<String>,
        /// The API server URL, when the source named one. `None` means resolving
        /// it, which means reading a kubeconfig — an adapter's job.
        server: Option<String>,
    },
    /// An API server URL, for a target no kubeconfig names.
    Server {
        /// Where the API server is, e.g. `"https://127.0.0.1:6443"`.
        server: String,
    },
}

impl Target {
    /// The kubeconfig context this names, if it names one.
    pub fn context(&self) -> Option<&str> {
        match self {
            Target::Context { context, .. } => Some(context),
            Target::Server { .. } => None,
        }
    }

    /// The kubeconfig file to read the context from, when one was named.
    pub fn kubeconfig(&self) -> Option<&str> {
        match self {
            Target::Context { kubeconfig, .. } => kubeconfig.as_deref(),
            Target::Server { .. } => None,
        }
    }

    /// The API server URL, directly or as a context's endpoint.
    pub fn server(&self) -> Option<&str> {
        match self {
            Target::Context { server, .. } => server.as_deref(),
            Target::Server { server } => Some(server),
        }
    }
}

impl fmt::Display for Target {
    /// How a log line names the target: `context prod-eu (kubeconfig
    /// /etc/kube/acme.yaml)`, `server https://127.0.0.1:6443` — a name and a
    /// URL, which are not secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Context { context, kubeconfig: Some(file), .. } => {
                write!(f, "context {context} (kubeconfig {file})")
            }
            Target::Context { context, .. } => write!(f, "context {context}"),
            Target::Server { server } => write!(f, "server {server}"),
        }
    }
}

/// How the run will authenticate. A method, resolved at call time — never a
/// credential; see the [module documentation](self#authentication).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    /// The service account the harness itself runs as: a pod's projected token,
    /// mounted by the platform and read by the adapter at call time.
    InCluster,
    /// The platform's own identity — IRSA, Workload Identity Federation, a CI
    /// job's OIDC token — exchanged with no static secret in the run.
    WorkloadIdentity,
    /// A service account in the target namespace, looked up through the
    /// cluster's API. The account is a [`ServiceAccount`], whose fields are
    /// private, so this variant is reachable only through
    /// [`Auth::service_account`] and a blank name never gets past it.
    ServiceAccount(ServiceAccount),
    /// An external credential plugin: EKS's `aws`, GKE's
    /// `gke-gcloud-auth-plugin`, AKS's `kubelogin`.
    ExecPlugin(ExecPlugin),
}

impl Auth {
    /// Authenticate as the named service account, failing with
    /// [`ClusterError::Empty`] on an empty name: an account with no name is a
    /// misconfigured target, not a lookup worth attempting.
    pub fn service_account(name: impl Into<String>) -> Result<Self, ClusterError> {
        Ok(Auth::ServiceAccount(ServiceAccount::named(name)?))
    }

    /// The service account this authenticates as, when it authenticates as one.
    pub fn service_account_name(&self) -> Option<&str> {
        match self {
            Auth::ServiceAccount(account) => Some(account.name()),
            _ => None,
        }
    }

    /// The port's method for this auth, for [`Cluster::to_ref`].
    fn method(&self) -> Result<AuthMethod, ClusterError> {
        match self {
            Auth::InCluster => Ok(AuthMethod::InCluster),
            Auth::WorkloadIdentity => Ok(AuthMethod::WorkloadIdentity),
            Auth::ServiceAccount(account) => Ok(AuthMethod::ServiceAccount(account.clone())),
            Auth::ExecPlugin(plugin) => {
                Ok(AuthMethod::ExecCredential(ExecCredential::plugin(plugin.command.clone())?))
            }
        }
    }
}

/// A credential plugin to invoke, and nothing it ever returned. The command is
/// the *name* of a program the adapter spawns directly, with `args`, in an
/// environment carrying `env`, answering to `api_version`; its output — the
/// token — stays inside the adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecPlugin {
    command: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    api_version: String,
}

impl ExecPlugin {
    /// The plugin at `command`, called with `args`, in an environment carrying
    /// `env`, under `api_version` (see [`DEFAULT_EXEC_API_VERSION`]). Fails with
    /// [`ClusterError::Empty`] for an empty command, api version or variable
    /// name, and with [`ClusterError::Auth`] when the command is not a plain
    /// program name: a credential plugin is spawned directly, never through a
    /// shell, so a command carrying whitespace or a metacharacter — `sh -c '…'`,
    /// `foo;bar`, `$(id)` — is the difference between invoking a plugin and
    /// running whatever the record says, and it is refused here rather than at
    /// spawn time, where the reader has already moved on. The arguments are not
    /// checked: they go to the program, not to a shell, so `eks,get-token` is
    /// exactly right and an argument may hold anything at all.
    pub fn new(
        command: impl Into<String>,
        args: Vec<String>,
        env: Vec<(String, String)>,
        api_version: impl Into<String>,
    ) -> Result<Self, ClusterError> {
        let command = command.into();
        let api_version = api_version.into();
        if command.trim().is_empty() {
            return Err(ClusterError::Empty { name: "exec plugin command" });
        }
        if api_version.trim().is_empty() {
            return Err(ClusterError::Empty { name: "exec plugin api version" });
        }
        if let Some(character) = command.chars().find(|c| Self::forbids(*c)) {
            return Err(ClusterError::Auth {
                message: format!(
                    "exec plugin command {command:?} must be one program name; {character:?} is \
                     read by a shell, but a credential plugin is spawned directly"
                ),
            });
        }
        for (name, _) in &env {
            if name.trim().is_empty() {
                return Err(ClusterError::Empty { name: "exec plugin environment variable name" });
            }
            if !is_env_name(name) {
                return Err(ClusterError::Auth {
                    message: format!(
                        "exec plugin environment variable {name:?} is not a POSIX name \
                         (`[A-Za-z_][A-Za-z0-9_]*`), so no adapter could export it"
                    ),
                });
            }
        }
        Ok(ExecPlugin { command, args, env, api_version })
    }

    /// Whether `character` turns a command into something a shell would read.
    /// Whitespace counts: it is what makes `sh -c '…'` a shell line at all.
    fn forbids(character: char) -> bool {
        character.is_whitespace() || SHELL_METACHARACTERS.contains(&character)
    }

    /// The plugin to spawn, e.g. `"gke-gcloud-auth-plugin"`.
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Its arguments, e.g. `["eks", "get-token", "cluster-name"]`.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// The environment it is called with — configuration, not a credential: a
    /// profile, a region, a path. The secret it authenticates with comes from
    /// the platform's own identity.
    pub fn env(&self) -> &[(String, String)] {
        &self.env
    }

    /// The `exec` stanza's `apiVersion`.
    pub fn api_version(&self) -> &str {
        &self.api_version
    }
}

/// Everything a reader of a diagnostic needs, and no environment value.
///
/// A `Cluster` is `Debug` because a run record and a log line both want one,
/// and that promise has to hold whatever the record said. An `exec` plugin's
/// environment is the one place a value may be a credential the plugin needs
/// before it has minted its own — a static key, a bootstrap token — so the
/// values are replaced by a fixed marker and the names are kept, because the
/// name is what a reader uses to find the variable and decide for themselves
/// where its value came from. The arguments are printed in full: they go to
/// the program, not to a shell, and they are what makes a plugin diagnosable.
impl fmt::Debug for ExecPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let env = self.env.iter().map(|(name, _)| (name, "…"));
        f.debug_struct("ExecPlugin")
            .field("command", &self.command)
            .field("args", &self.args)
            .field("env", &env.collect::<Vec<_>>())
            .field("api_version", &self.api_version)
            .finish()
    }
}

/// Which cluster a run targets, and how it will authenticate — built by hand,
/// or from an IaC record by [`Cluster::from_record`]. Either way it can hold a
/// name, a URL, a namespace and a *method*, never a credential, so a `Debug` or
/// a `Clone` of one is safe to print and [`Cluster::to_ref`] hands the port a
/// handle that is safe to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cluster {
    target: Target,
    namespace: Option<String>,
    auth: Auth,
}

impl Cluster {
    /// The cluster at `target`, optionally scoped to `namespace`, authenticating
    /// by `auth`. Fails with [`ClusterError::Empty`] for a target that names
    /// nothing — an empty context, an empty URL, a present-but-blank namespace.
    /// The namespace lives here rather than on the port's [`ClusterRef`] because
    /// the port applies whatever manifests it is handed: the namespace is part
    /// of what a step decided, not part of how the adapter dials.
    pub fn new(
        target: Target,
        namespace: Option<String>,
        auth: Auth,
    ) -> Result<Self, ClusterError> {
        let blank = match &target {
            Target::Context { context, server, .. } => {
                context.trim().is_empty()
                    || server.as_deref().is_some_and(|server| server.trim().is_empty())
            }
            Target::Server { server } => server.trim().is_empty(),
        };
        if blank {
            return Err(ClusterError::Empty { name: "cluster target" });
        }
        if namespace.as_deref().is_some_and(|namespace| namespace.trim().is_empty()) {
            return Err(ClusterError::Empty { name: "namespace" });
        }
        Ok(Cluster { target, namespace, auth })
    }

    /// Which cluster: a context, or an API server URL.
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// The namespace a step scoped this to, when it named one.
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// The method, never a credential.
    pub fn auth(&self) -> &Auth {
        &self.auth
    }

    /// The port's handle for this cluster, for
    /// [`Cluster::handle`](crate::ports::cluster::Cluster::handle). The port
    /// names a context *and* an endpoint, so one direction is synthesised:
    /// targeting by server, the URL is also the context name — there is no other
    /// name for that cluster; targeting a context that named no endpoint, the
    /// context name stands in as the endpoint, for the adapter to overwrite once
    /// it has read the kubeconfig. An `ExecPlugin` keeps its arguments,
    /// environment and `apiVersion` here — the port's [`ExecCredential`] names
    /// the plugin alone, and the rest is the adapter's to spawn.
    pub fn to_ref(&self) -> Result<ClusterRef, ClusterError> {
        let (context, endpoint) = match &self.target {
            Target::Context { context, server, .. } => {
                (context.clone(), server.clone().unwrap_or_else(|| context.clone()))
            }
            Target::Server { server } => (server.clone(), server.clone()),
        };
        ClusterRef::new(context, endpoint, self.auth.method()?)
    }

    /// The cluster an IaC output describes.
    ///
    /// The record is the flat key/value shape a `tofu.apply` output of type
    /// `k8s.Cluster` carries, flattened by the adapter: `context`, `server`,
    /// `kubeconfig`, `namespace`, `auth`, and for `auth: exec` the
    /// `exec.command`, `exec.args` (comma-separated), `exec.env`
    /// (comma-separated `K=V`) and `exec.apiVersion`. `auth` is required;
    /// `exec.apiVersion` defaults to [`DEFAULT_EXEC_API_VERSION`]. A key that
    /// would carry the credential itself is refused outright, by name, before
    /// anything else is read — see the [module
    /// documentation](self#inline-credentials-are-refused-not-discouraged).
    pub fn from_record(record: &BTreeMap<String, String>) -> Result<Cluster, ClusterError> {
        for key in record.keys() {
            if is_inline_credential(key) {
                return Err(ClusterError::Auth {
                    message: format!(
                        "{key:?} would put the credential itself in the record, and an IaC output \
                         is state: authenticate with an exec plugin or the platform's identity \
                         instead"
                    ),
                });
            }
        }
        let context = field(record, "context");
        let server = field(record, "server");
        let target = match (context.clone(), server) {
            (Some(context), server) => {
                Target::Context { context, kubeconfig: field(record, "kubeconfig"), server }
            }
            (None, Some(server)) => Target::Server { server },
            (None, None) => return Err(ClusterError::Empty { name: "context or server" }),
        };
        Cluster::new(target, field(record, "namespace"), auth_from(record)?)
    }
}

impl TryFrom<&Cluster> for ClusterRef {
    type Error = ClusterError;

    fn try_from(cluster: &Cluster) -> Result<ClusterRef, ClusterError> {
        cluster.to_ref()
    }
}

/// The trimmed value under `key`, or `None` when it is absent or blank — a
/// record that sets `namespace` to nothing has not set a namespace.
fn field(record: &BTreeMap<String, String>, key: &str) -> Option<String> {
    record.get(key).map(|value| value.trim()).filter(|value| !value.is_empty()).map(String::from)
}

/// Whether `key` — compared by its last segment, so `users[0].token` counts —
/// names something that *is* the credential rather than a path to one.
fn is_inline_credential(key: &str) -> bool {
    let leaf = key.rsplit(['.', '[', ']']).find(|part| !part.is_empty()).unwrap_or(key);
    INLINE_CREDENTIAL_KEYS.contains(&leaf)
}

/// Whether `name` is an environment variable a shell could export.
fn is_env_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters.next().is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The auth a record describes. Every branch answers "how", never "with what".
fn auth_from(record: &BTreeMap<String, String>) -> Result<Auth, ClusterError> {
    let Some(method) = field(record, "auth") else {
        return Err(ClusterError::Auth {
            message: format!("a cluster record must name `auth`: {AUTH_METHODS}"),
        });
    };
    match method.as_str() {
        "in-cluster" => Ok(Auth::InCluster),
        "workload-identity" => Ok(Auth::WorkloadIdentity),
        "service-account" => {
            let name = field(record, "serviceAccount")
                .or_else(|| field(record, "service-account"))
                .ok_or(ClusterError::Empty { name: "service account name" })?;
            Auth::service_account(name)
        }
        "exec" => Ok(Auth::ExecPlugin(ExecPlugin::new(
            record.get("exec.command").map(|c| c.trim()).unwrap_or_default(),
            list(record, "exec.args"),
            pairs(record, "exec.env")?,
            record
                .get("exec.apiVersion")
                .or_else(|| record.get("exec.api-version"))
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
                .unwrap_or(DEFAULT_EXEC_API_VERSION),
        )?)),
        other => Err(ClusterError::Auth {
            message: format!("unknown auth method {other:?}: use {AUTH_METHODS}"),
        }),
    }
}

/// A comma-separated list, trimmed, with the empty entries a trailing comma
/// leaves behind dropped.
fn list(record: &BTreeMap<String, String>, key: &str) -> Vec<String> {
    field(record, key)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// A comma-separated `K=V` list, in the order the record wrote it. An entry with
/// no `=` is refused rather than dropped: a plugin called without the variable
/// it was promised fails at the API server, a long way from the record that lost
/// it.
fn pairs(
    record: &BTreeMap<String, String>,
    key: &str,
) -> Result<Vec<(String, String)>, ClusterError> {
    let mut pairs = Vec::new();
    for entry in list(record, key) {
        let Some((name, value)) = entry.split_once('=') else {
            return Err(ClusterError::Auth {
                message: format!("{key} entry {entry:?} is not `NAME=VALUE`"),
            });
        };
        pairs.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An obviously fake secret value for an exec plugin's environment. It is
    /// not credential-shaped at all — the redaction under test does not look at
    /// the value's shape — and it is assembled from fragments so no secret
    /// scanner reads a credential-looking literal out of this file.
    const FAKE_SECRET: &str = concat!("fake", "-secret-", "value", "-not-a-key");

    /// An obviously fake bearer token, three dot-separated parts like a JWT
    /// but none of them base64 JSON, built the same way for the same reason.
    const FAKE_TOKEN: &str = concat!("fake", ".bearer", ".token");

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    /// A flat IaC record.
    fn record(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(key, value)| (key.to_string(), value.to_string())).collect()
    }

    /// The same record for `auth: exec`, with `extra` layered on top.
    fn exec_record(extra: &[(&str, &str)]) -> BTreeMap<String, String> {
        let mut record =
            record(&[("context", "prod-eu"), ("auth", "exec"), ("exec.command", "aws")]);
        for (key, value) in extra {
            record.insert(key.to_string(), value.to_string());
        }
        record
    }

    #[test]
    fn a_cluster_is_send_and_sync() {
        assert_send_sync::<Cluster>();
        assert_send_sync::<ExecPlugin>();
    }

    /// The local case: kind writes one context and an endpoint, and the two
    /// have to survive construction unchanged.
    #[test]
    fn a_kind_context_round_trips() {
        let target = Target::Context {
            context: "kind-kind".to_string(),
            kubeconfig: Some("/etc/kube/acme.yaml".to_string()),
            server: Some("https://127.0.0.1:6443".to_string()),
        };
        let cluster = Cluster::new(target, Some("apps".to_string()), Auth::InCluster)
            .expect("a named target");
        assert_eq!(cluster.target().context(), Some("kind-kind"));
        assert_eq!(cluster.target().server(), Some("https://127.0.0.1:6443"));
        assert_eq!(cluster.target().kubeconfig(), Some("/etc/kube/acme.yaml"));
        assert_eq!(cluster.namespace(), Some("apps"));
        assert_eq!(cluster.auth(), &Auth::InCluster);
        // A `Display` for the target goes in a log line; nothing else does.
        assert_eq!(
            cluster.target().to_string(),
            "context kind-kind (kubeconfig /etc/kube/acme.yaml)"
        );
    }

    /// The EKS shape: the `aws` CLI asked for a token, with the cluster name it
    /// applies to. GKE's and AKS's plugins are as ordinary — the check is on the
    /// command's *shape*, not on a list of known plugins.
    #[test]
    fn an_exec_plugin_reads_back_its_arguments() {
        let plugin = ExecPlugin::new(
            "aws",
            ["eks", "get-token", "--cluster-name", "prod-eu"].map(String::from).to_vec(),
            vec![("AWS_PROFILE".to_string(), "prod".to_string())],
            DEFAULT_EXEC_API_VERSION,
        )
        .expect("a plain command");
        assert_eq!(plugin.command(), "aws");
        assert_eq!(plugin.args(), ["eks", "get-token", "--cluster-name", "prod-eu"]);
        assert_eq!(plugin.env(), [("AWS_PROFILE".to_string(), "prod".to_string())]);
        assert_eq!(plugin.api_version(), DEFAULT_EXEC_API_VERSION);
        for command in
            ["gke-gcloud-auth-plugin", "kubelogin", "/usr/local/bin/aws-iam-authenticator"]
        {
            let plugin = ExecPlugin::new(command, Vec::new(), Vec::new(), DEFAULT_EXEC_API_VERSION)
                .expect("a plain command");
            assert_eq!(plugin.command(), command);
        }
    }

    /// A metacharacter is the whole risk: an adapter that ran the command
    /// through a shell would execute whatever follows it. `sh -c '…'` is refused
    /// for its whitespace — it is a shell line, not a program name.
    #[test]
    fn a_shell_metacharacter_in_a_command_is_refused() {
        for command in ["sh -c 'x'", "foo;bar", "a|b", "$(id)", "aws&&whoami", "foo>out", "a\nb"] {
            let error = ExecPlugin::new(command, Vec::new(), Vec::new(), DEFAULT_EXEC_API_VERSION)
                .expect_err("a shell line is not a plugin");
            assert!(
                matches!(&error, ClusterError::Auth { message }
                    if message.contains("program name") && message.contains("shell")),
                "{error:?}"
            );
        }
        // The arguments are not checked, on purpose: they go to the program, not
        // to a shell, so a metacharacter there is the plugin's own business.
        assert!(
            ExecPlugin::new(
                "aws",
                vec!["get-token; rm -rf /".to_string()],
                Vec::new(),
                DEFAULT_EXEC_API_VERSION
            )
            .is_ok()
        );
    }

    #[test]
    fn an_empty_command_or_api_version_is_refused() {
        let with = |command: &str, api_version: &str| {
            ExecPlugin::new(command, Vec::new(), Vec::new(), api_version).unwrap_err()
        };
        assert_eq!(
            with("  ", DEFAULT_EXEC_API_VERSION),
            ClusterError::Empty { name: "exec plugin command" }
        );
        assert_eq!(with("aws", ""), ClusterError::Empty { name: "exec plugin api version" });
    }

    /// An environment an adapter cannot build is a mistake worth catching here,
    /// where the message can still name the offending variable.
    #[test]
    fn an_unusable_environment_variable_name_is_refused() {
        let with = |name: &str| {
            ExecPlugin::new(
                "aws",
                Vec::new(),
                vec![(name.to_string(), "x".to_string())],
                DEFAULT_EXEC_API_VERSION,
            )
            .unwrap_err()
        };
        assert_eq!(with(""), ClusterError::Empty { name: "exec plugin environment variable name" });
        for name in ["AWS-PROFILE", "1AWS", "AWS PROFILE"] {
            let error = with(name);
            assert!(matches!(error, ClusterError::Auth { .. }), "{error:?}");
        }
    }

    /// Every spelling a kubeconfig uses for a literal credential, refused by
    /// name — and the message says which one, so the record can be fixed.
    #[test]
    fn a_record_never_carries_a_credential() {
        for key in INLINE_CREDENTIAL_KEYS {
            let message = Cluster::from_record(&exec_record(&[(key, "<access key id>")]))
                .expect_err("a literal credential is refused")
                .to_string();
            assert!(message.contains(key), "the message names {key}: {message}");
            assert!(message.contains("state"), "{message}");
        }
        // An empty value is refused too — the key is what carries the meaning.
        assert!(Cluster::from_record(&exec_record(&[("token", "")])).is_err());
        // A nested key counts too: the leaf is what carries the value.
        assert!(
            Cluster::from_record(&record(&[
                ("context", "prod-eu"),
                ("auth", "in-cluster"),
                ("users[0].token", "secret")
            ]))
            .is_err()
        );
    }

    /// The CA certificate is public by definition, and a path to a client key is
    /// not the key. Only inline content is refused.
    #[test]
    fn a_path_and_public_data_are_not_a_credential() {
        let record = exec_record(&[
            ("certificate-authority-data", "LS0tLS1CRUdJTg=="),
            ("tokenFile", "/var/run/secrets/token"),
            ("client-key", "/etc/kube/client.key"),
        ]);
        let cluster = Cluster::from_record(&record).expect("public material is fine");
        assert_eq!(cluster.target().context(), Some("prod-eu"));
    }

    /// The record shape an IaC output flattens into, exec stanza and all.
    #[test]
    fn an_exec_record_builds_the_whole_plugin() {
        let record = record(&[
            ("context", "arn:aws:eks:eu-west-1:1:cluster/prod-eu"),
            ("namespace", "apps"),
            ("auth", "exec"),
            ("exec.command", "aws"),
            // A trailing comma leaves an empty argument behind, and it is not one.
            ("exec.args", "eks,get-token,--cluster-name,prod-eu,"),
            ("exec.env", "AWS_PROFILE=prod,AWS_REGION=eu-west-1"),
        ]);
        let cluster = Cluster::from_record(&record).expect("a well-formed record");
        let Auth::ExecPlugin(plugin) = cluster.auth() else {
            panic!("an exec plugin, got {:?}", cluster.auth());
        };
        assert_eq!(plugin.args(), ["eks", "get-token", "--cluster-name", "prod-eu"]);
        assert_eq!(
            plugin.env(),
            [
                ("AWS_PROFILE".to_string(), "prod".to_string()),
                ("AWS_REGION".to_string(), "eu-west-1".to_string())
            ]
        );
        // No record value for the stanza version, so the one every plugin takes.
        assert_eq!(plugin.api_version(), DEFAULT_EXEC_API_VERSION);
        assert_eq!(cluster.namespace(), Some("apps"));
    }

    #[test]
    fn the_other_auth_methods_build_from_a_record() {
        let named = record(&[
            ("context", "prod-eu"),
            ("auth", "service-account"),
            ("serviceAccount", "deployer"),
        ]);
        let named = Cluster::from_record(&named).expect("a named account");
        assert_eq!(named.auth(), &Auth::service_account("deployer").expect("named"));
        let identity = record(&[("context", "prod-eu"), ("auth", "workload-identity")]);
        let identity = Cluster::from_record(&identity).expect("workload identity");
        assert_eq!(identity.auth(), &Auth::WorkloadIdentity);
        let pod = record(&[("auth", "in-cluster"), ("server", "https://kubernetes.default.svc")]);
        let pod = Cluster::from_record(&pod).expect("the pod's own account");
        assert_eq!(
            pod.target(),
            &Target::Server { server: "https://kubernetes.default.svc".to_string() }
        );
    }

    /// A promise the record lost is caught where the record is still in hand.
    #[test]
    fn a_malformed_record_is_refused_with_a_usable_message() {
        let refused = |record: BTreeMap<String, String>| {
            Cluster::from_record(&record).expect_err("refused").to_string()
        };
        assert_eq!(
            Cluster::from_record(&record(&[("auth", "in-cluster")])).unwrap_err(),
            ClusterError::Empty { name: "context or server" }
        );
        let no_auth = refused(record(&[("context", "prod-eu")]));
        assert!(no_auth.contains("auth"), "{no_auth}");
        let unknown = refused(record(&[("context", "prod-eu"), ("auth", "gke")]));
        assert!(unknown.contains("gke") && unknown.contains("exec"), "{unknown}");
        let no_value = refused(exec_record(&[("exec.env", "AWS_PROFILE")]));
        assert!(no_value.contains("AWS_PROFILE") && no_value.contains("NAME=VALUE"), "{no_value}");
    }

    /// The invariant the type exists for: a cluster describes *how* the run
    /// authenticates, so printing one cannot print a token — neither the token
    /// a record tried to carry inline, which is refused outright, nor one an
    /// exec plugin's environment handed over, which is redacted at `Debug`.
    #[test]
    fn a_clusters_debug_output_carries_no_token() {
        let record = exec_record(&[
            ("exec.args", "eks,get-token"),
            ("exec.env", &format!("AWS_SECRET_ACCESS_KEY={FAKE_SECRET}")),
        ]);
        let printed = format!("{:?}", Cluster::from_record(&record).expect("a method"));
        assert!(printed.contains("prod-eu") && printed.contains("aws"), "{printed}");

        // An environment value is not inspected — it is needed to spawn the
        // plugin — so it reaches the cluster intact and is kept out of the
        // printed form, where the variable's name is what a reader wants.
        let cluster = Cluster::from_record(&record).expect("a method");
        let Auth::ExecPlugin(plugin) = cluster.auth() else {
            panic!("an exec plugin, got {:?}", cluster.auth());
        };
        assert_eq!(plugin.env(), [("AWS_SECRET_ACCESS_KEY".to_string(), FAKE_SECRET.to_string())]);
        assert!(!printed.contains(FAKE_SECRET), "{printed}");
        assert!(printed.contains("AWS_SECRET_ACCESS_KEY"), "{printed}");
        // The plugin itself is diagnosable: what it is, how it is called, under
        // which stanza version.
        assert!(printed.contains(DEFAULT_EXEC_API_VERSION), "{printed}");
        assert!(printed.contains("get-token"), "{printed}");

        // The same record with the token a kubeconfig would have carried is
        // refused, and the failure message names the key — never its value.
        let mut record = record;
        record.insert("token".to_string(), FAKE_TOKEN.to_string());
        let refused = Cluster::from_record(&record).expect_err("a token is refused").to_string();
        assert!(!refused.contains(FAKE_TOKEN), "{refused}");
    }

    /// The plugin on its own has to keep the promise too: a diagnostic can hold
    /// an `ExecPlugin` without the `Cluster` around it.
    #[test]
    fn a_plugins_debug_output_carries_no_environment_value() {
        let plugin = ExecPlugin::new(
            "aws",
            ["eks", "get-token", "--cluster-name", "prod-eu"].map(String::from).to_vec(),
            vec![
                ("AWS_SECRET_ACCESS_KEY".to_string(), FAKE_SECRET.to_string()),
                ("AWS_PROFILE".to_string(), "prod".to_string()),
            ],
            DEFAULT_EXEC_API_VERSION,
        )
        .expect("a plain command");
        let printed = format!("{plugin:?}");
        assert!(!printed.contains(FAKE_SECRET), "{printed}");
        // The names survive, and so does everything a reader needs to tell two
        // plugins apart — the arguments in full, since they are not secrets.
        assert!(printed.contains("AWS_SECRET_ACCESS_KEY"), "{printed}");
        assert!(printed.contains("AWS_PROFILE"), "{printed}");
        assert!(printed.contains("aws"), "{printed}");
        assert!(printed.contains(DEFAULT_EXEC_API_VERSION), "{printed}");
        for argument in ["eks", "get-token", "--cluster-name", "prod-eu"] {
            assert!(printed.contains(argument), "{argument} is missing from {printed}");
        }
        assert_eq!(printed.matches('…').count(), 2, "{printed}");
    }

    /// The list a record gets wrong twice — once for having no `auth`, once for
    /// naming one nobody knows — has to read as a list.
    #[test]
    fn a_rejected_auth_method_lists_the_four_it_accepts() {
        let refused = |record: BTreeMap<String, String>| {
            Cluster::from_record(&record).expect_err("refused").to_string()
        };
        let expected = "`in-cluster`, `workload-identity`, `service-account` or `exec`";
        for message in [
            refused(record(&[("context", "prod-eu")])),
            refused(record(&[("context", "prod-eu"), ("auth", "gke")])),
        ] {
            assert!(message.contains(expected), "{message}");
        }
    }

    /// A blank account name is refused at the only door there is: the field is
    /// private, so `Auth::ServiceAccount { name: … }` does not compile and the
    /// constructor is the whole of the API. That half is the compiler's, not a
    /// test's — what is asserted here is that the door still refuses a blank.
    #[test]
    fn a_blank_service_account_name_is_refused() {
        for blank in ["", "   ", "\t\n"] {
            assert_eq!(
                Auth::service_account(blank).unwrap_err(),
                ClusterError::Empty { name: "service account name" }
            );
        }
        let named = Auth::service_account("deployer").expect("a named account");
        assert_eq!(named.service_account_name(), Some("deployer"));
        assert_eq!(Auth::InCluster.service_account_name(), None);
        // And the account it holds is the port's own, so `to_ref` cannot see a
        // name the constructor would have refused.
        let cluster =
            Cluster::new(Target::Server { server: "https://api:6443".into() }, None, named)
                .expect("a target");
        assert!(matches!(
            cluster.to_ref().expect("a port handle").auth(),
            AuthMethod::ServiceAccount(account) if account.name() == "deployer"
        ));
    }

    #[test]
    fn the_port_handle_carries_the_method_and_nothing_else() {
        let cluster = Cluster::from_record(&exec_record(&[("server", "https://127.0.0.1:6443")]))
            .expect("a method");
        let handle = cluster.to_ref().expect("a port handle");
        assert_eq!(handle.context(), "prod-eu");
        assert_eq!(handle.endpoint(), "https://127.0.0.1:6443");
        match handle.auth() {
            AuthMethod::ExecCredential(plugin) => assert_eq!(plugin.command(), "aws"),
            other => panic!("an exec credential, got {other:?}"),
        }
        assert_eq!(ClusterRef::try_from(&cluster).expect("the same handle"), handle);
    }

    /// Targeting by URL has no context name, so the URL stands in for one; a
    /// context that named no endpoint has none until an adapter reads the
    /// kubeconfig, and the context name stands in until then — see
    /// [`Cluster::to_ref`].
    #[test]
    fn a_stand_in_context_and_endpoint_still_produce_a_handle() {
        let by_url = Target::Server { server: "https://127.0.0.1:6443".to_string() };
        let handle = Cluster::new(by_url, None, Auth::InCluster)
            .expect("a URL is a target")
            .to_ref()
            .unwrap();
        assert_eq!(handle.context(), "https://127.0.0.1:6443");
        assert_eq!(handle.endpoint(), "https://127.0.0.1:6443");

        let by_context =
            Target::Context { context: "prod-eu".to_string(), kubeconfig: None, server: None };
        let handle = Cluster::new(by_context, None, Auth::WorkloadIdentity)
            .expect("a named target")
            .to_ref()
            .expect("a port handle");
        assert_eq!(handle.context(), "prod-eu");
        assert_eq!(handle.endpoint(), "prod-eu");
        assert_eq!(handle.auth(), &AuthMethod::WorkloadIdentity);
    }

    #[test]
    fn a_blank_field_is_empty_not_a_target() {
        let blank = |target| {
            Cluster::new(target, None, Auth::InCluster).expect_err("a target that names nothing")
        };
        let context = |context: &str| Target::Context {
            context: context.to_string(),
            kubeconfig: None,
            server: None,
        };
        assert_eq!(blank(context(" ")), ClusterError::Empty { name: "cluster target" });
        assert_eq!(
            blank(Target::Server { server: String::new() }),
            ClusterError::Empty { name: "cluster target" }
        );
        let named = Target::Server { server: "https://api:6443".to_string() };
        assert_eq!(
            Cluster::new(named, Some(String::new()), Auth::InCluster).unwrap_err(),
            ClusterError::Empty { name: "namespace" }
        );
    }
}
