//! `HelmCli`: a [`Cluster`] adapter that drives the `helm` CLI
//! ([#74](https://github.com/Keep-Shipping/harness/issues/74)).
//!
//! There is no mature Helm implementation in Rust, so this adapter shells out
//! — and it shells out to *Helm*, not to `kubectl`, because a chart is the unit
//! this port speaks in. The process boundary is deliberate: it is what keeps the
//! harness out of template rendering and release storage entirely.
//!
//! # Invariants
//!
//! - **Charts are pinned by digest, in the URL.** An OCI chart becomes
//!   `oci://<repository>@<digest>`, which Helm resolves without a tag. That
//!   needs Helm **3.17.0** or newer, and it is why a digest-pinned chart emits
//!   no `--version`: Helm rejects a digest alongside a disagreeing `--version`,
//!   and there is nothing to disagree with anyway.
//! - **Every install and upgrade is atomic.** `--atomic --cleanup-on-fail`.
//!   `--atomic` implies `--wait` and rolls the previous revision back when the
//!   new one does not settle, which is the guarantee the port demands: an
//!   upgrade that leaves the cluster worse must roll back, not report.
//! - **An exit code is not a status.** Every Helm failure exits `1`, so a
//!   non-zero exit cannot tell "installed" from "failed" — and exit `0` only
//!   means Helm did not complain. Both paths re-read `helm status -o json` and
//!   report what the release actually is.
//! - **Secret values never reach a command line.** A [`Values::secret`](ks_core::ports::cluster::Values::secret) goes to
//!   a `0600` temporary file passed as `-f`, and the file is deleted when the
//!   call returns — on every path, including an error or a panic, because the
//!   deletion is a `Drop` guard rather than a line at the end of the function.
//!   An argument is readable by every other process on the machine for as long
//!   as the call runs, and Helm keeps its own argv in its process listing.
//! - **Silence is not health.** A release Helm cannot find is
//!   [`Health::NoData`] with a reason, never an optimistic [`Health::Healthy`].
//! - **Runs are hermetic.** `HELM_KUBECONTEXT` and `KUBECONFIG` are set
//!   explicitly on every invocation rather than inherited, and the other
//!   Helm-shaped environment variables are cleared first, so an ambient
//!   `HELM_NAMESPACE` cannot redirect a release.
//!
//! # Limitations
//!
//! - **No `apply`.** Helm does not apply raw manifests, so [`Cluster::apply`]
//!   returns [`ClusterError::Apply`] and this adapter never shells out to
//!   `kubectl`. Use a manifest-oriented adapter for server-side apply.
//! - **No registry login.** Pulling from a private OCI registry relies on
//!   credentials Helm already has (`~/.docker/config.json` or Helm's own
//!   registry config); run `helm registry login <host> -u <user>
//!   --password-stdin` yourself. See `docs/HELM.md`.
//! - **Helm ≥ 3.17.0** for digest-pinned OCI charts.
//! - **Blocking.** Every call waits on a child process. That is what Helm
//!   offers, and the port's futures do not make it concurrent.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ks_core::ports::BoxFuture;
use ks_core::ports::cluster::{
    AuthMethod, Chart, ChartUpgrade, Cluster, ClusterError, ClusterRef, Manifest, Revision, Rollout,
};
use ks_core::ports::health::{Health, HealthReport};
use ks_core::ports::supply_chain::{ImageRef, Reference};

/// The Helm release status this adapter reports as [`Health::Healthy`].
const DEPLOYED: &str = "deployed";
/// The Helm release statuses that mean "still moving", not "succeeded".
const PROGRESSING: &[&str] =
    &["pending-install", "pending-upgrade", "pending-rollback", "uninstalling"];
/// The Helm release statuses this adapter reports as [`Health::Degraded`].
const DEGRADED: &[&str] = &["superseded", "uninstalled", "unknown"];
/// The Helm release status this adapter reports as [`Health::Failed`].
const FAILED: &str = "failed";

/// The environment variables cleared before every invocation, so a run cannot
/// be redirected by whatever the ambient shell happens to export.
///
/// `HOME` and `PATH` are deliberately **not** in this list: Helm needs `PATH` to
/// be found at all, and it reads `~/.docker/config.json` for OCI registry
/// credentials — which is how an authenticated pull works without this adapter
/// ever handling a secret.
const CLEARED_ENV: &[&str] = &[
    "KUBECONFIG",
    "HELM_KUBECONTEXT",
    "HELM_NAMESPACE",
    "HELM_DRIVER",
    "HELM_DEBUG",
    "HELM_MAX_HISTORY",
    "HELM_CACHE_HOME",
    "HELM_CONFIG_HOME",
    "HELM_DATA_HOME",
    "HELM_REGISTRY_CONFIG",
    "HELM_REPOSITORY_CACHE",
    "HELM_REPOSITORY_CONFIG",
];

/// What one process invocation came back with.
///
/// [`std::process::Output`] would do, except that its `ExitStatus` cannot be
/// built without spawning something — which is exactly what a unit test of this
/// adapter must not do.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Output {
    /// The exit code, or `-1` when the process was killed by a signal.
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Runs one process and reports what it did.
///
/// The whole adapter goes through this, so a test can assert on the exact argv
/// Helm would have been given without a cluster, a kubeconfig or a `helm`
/// binary anywhere in sight — which is what makes the digest-in-the-URL and the
/// secret-values rules testable rather than merely intended.
trait Runner: Send + Sync {
    /// Runs `program` with `args` and `env` (each `(KEY, VALUE)`), capturing both
    /// streams. The environment is set explicitly, never inherited.
    fn run(&self, program: &str, args: &[String], env: &[(String, String)]) -> io::Result<Output>;
}

/// The [`Runner`] that actually spawns [`std::process::Command`].
struct ProcessRunner;

impl Runner for ProcessRunner {
    fn run(&self, program: &str, args: &[String], env: &[(String, String)]) -> io::Result<Output> {
        let mut command = std::process::Command::new(program);
        command.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // Clear first, then set: a variable this adapter does not set must not
        // reach Helm from the ambient environment.
        for name in CLEARED_ENV {
            command.env_remove(name);
        }
        for (key, value) in env {
            command.env(key, value);
        }
        let output = command.output()?;
        Ok(Output {
            // A signalled process has no exit code. -1 is not a success, and
            // every path here checks for a non-zero code.
            code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

/// A values file on disk, deleted when this guard is dropped.
///
/// The security contract on [`Values`](ks_core::ports::cluster::Values) is that a secret reaches Helm through a
/// `0600` temporary file that is deleted once the call returns. A guard rather
/// than a `remove_file` at the end of the function is what makes that true on
/// *every* path: an early return, an error between the write and the call, or a
/// panic inside the call all drop it on the way out.
struct TempValues {
    path: PathBuf,
}

impl TempValues {
    /// Writes `document` to a fresh temporary file readable only by this
    /// process.
    fn write(document: &str) -> io::Result<TempValues> {
        // Unique per call: the process id alone would collide between two
        // upgrades in one run, and `create_new` turns that collision into an
        // error rather than into two releases sharing one values file.
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ks-helm-values-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        // `create_new` means the file cannot pre-exist, so the mode is set at
        // creation rather than in a chmod window another process could race.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        io::Write::write_all(&mut file, document.as_bytes())?;
        // Nothing else needs the descriptor; the file is written from here on.
        drop(file);
        Ok(TempValues { path })
    }

    /// The path to pass to Helm as `-f`.
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempValues {
    fn drop(&mut self) {
        // Best effort: a failure here leaves a `0600` file in the temp
        // directory, which is a much smaller problem than a secret on a command
        // line, and there is nothing useful to do about it from a destructor.
        let _ = fs::remove_file(&self.path);
    }
}

impl fmt::Debug for TempValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the contents: this is a secret by construction.
        f.debug_struct("TempValues").field("path", &self.path).finish_non_exhaustive()
    }
}

/// What `helm status -o json` said about a release.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Status {
    /// The revision, absent when Helm omits it — `version` is `omitempty`, and a
    /// release with no successful revision has none.
    revision: Option<u32>,
    /// `info.status`: Helm's own untyped string.
    state: String,
    /// `info.description`: Helm's own words for what happened.
    description: Option<String>,
}

/// A [`Cluster`] over the `helm` CLI.
pub struct HelmCli {
    binary: String,
    handle: ClusterRef,
    kubeconfig: Option<String>,
    namespace: Option<String>,
    runner: Arc<dyn Runner>,
}

impl HelmCli {
    /// An adapter driving the kubeconfig context `context`.
    ///
    /// The handle reports [`AuthMethod::WorkloadIdentity`]: the credential is
    /// whatever Helm resolves from its own kubeconfig for this context, and this
    /// adapter never holds, copies or logs it.
    ///
    /// # Panics
    ///
    /// If `context` is blank. Use [`HelmCli::try_new`] to get a
    /// [`ClusterError::Empty`] instead — this exists for the common case where
    /// the context came from configuration that has already been validated.
    pub fn new(context: impl Into<String>) -> HelmCli {
        HelmCli::try_new(context).expect("a kubeconfig context must not be empty")
    }

    /// Like [`HelmCli::new`], but a blank `context` is a [`ClusterError::Empty`]
    /// rather than a panic: a handle that names no target cannot fail safely.
    pub fn try_new(context: impl Into<String>) -> Result<HelmCli, ClusterError> {
        let context = context.into();
        let handle = ClusterRef::new(
            context.clone(),
            endpoint_for(context.as_str()),
            AuthMethod::WorkloadIdentity,
        )?;
        Ok(HelmCli {
            binary: "helm".to_string(),
            handle,
            kubeconfig: None,
            namespace: None,
            runner: Arc::new(ProcessRunner),
        })
    }

    /// An adapter over a handle the caller built, for a target whose auth method
    /// or endpoint this adapter would not have guessed.
    pub fn with_handle(handle: ClusterRef) -> HelmCli {
        HelmCli {
            binary: "helm".to_string(),
            handle,
            kubeconfig: None,
            namespace: None,
            runner: Arc::new(ProcessRunner),
        }
    }

    /// Drives `binary` instead of `helm` on `PATH` — a wrapper script, or a
    /// pinned Helm in a tool directory.
    pub fn with_binary(mut self, binary: impl Into<String>) -> HelmCli {
        self.binary = binary.into();
        self
    }

    /// Reads the kubeconfig from `path` rather than Helm's default, and passes
    /// it as `KUBECONFIG` so the run does not depend on where it started.
    pub fn with_kubeconfig(mut self, path: impl Into<String>) -> HelmCli {
        self.kubeconfig = Some(path.into());
        self
    }

    /// The namespace a release is installed into when the request names none.
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> HelmCli {
        self.namespace = Some(namespace.into());
        self
    }

    /// Substitutes the [`Runner`] — the seam every test in this crate drives.
    #[cfg(test)]
    fn with_runner(mut self, runner: Arc<dyn Runner>) -> HelmCli {
        self.runner = runner;
        self
    }

    /// The environment every invocation gets: the context always, the kubeconfig
    /// when one was configured.
    fn env(&self) -> Vec<(String, String)> {
        let mut env = vec![("HELM_KUBECONTEXT".to_string(), self.handle.context().to_string())];
        if let Some(kubeconfig) = &self.kubeconfig {
            env.push(("KUBECONFIG".to_string(), kubeconfig.clone()));
        }
        env
    }

    /// Runs the Helm CLI and returns its output, reporting a spawn failure as a
    /// cluster error rather than a panic.
    fn helm(&self, args: &[String]) -> Result<Output, ClusterError> {
        self.runner.run(&self.binary, args, &self.env()).map_err(|error| ClusterError::Upgrade {
            message: format!("could not run {}: {error}", self.binary),
        })
    }

    /// `helm status <release> -o json`, with the namespace when there is one.
    ///
    /// A release Helm does not have is [`ClusterError::NotFound`]; anything else
    /// non-zero carries Helm's own stderr.
    fn status(&self, release: &str, namespace: Option<&str>) -> Result<Status, ClusterError> {
        let mut args =
            vec!["status".to_string(), release.to_string(), "-o".to_string(), "json".to_string()];
        if let Some(namespace) = namespace {
            args.push("--namespace".to_string());
            args.push(namespace.to_string());
        }
        let output = self.helm(&args)?;
        if output.code != 0 {
            let stderr = stderr_of(&output);
            return Err(if says_not_found(&stderr) {
                ClusterError::NotFound { name: release.to_string() }
            } else {
                ClusterError::Upgrade { message: format!("helm status failed: {stderr}") }
            });
        }
        parse_status(&output.stdout, release)
    }

    /// The rollout [`Cluster::upgrade`] and [`Cluster::rollback`] report: the
    /// revision the release is on and the health that revision is in.
    fn observe(&self, release: &str, namespace: Option<&str>) -> Result<Rollout, ClusterError> {
        let status = self.status(release, namespace)?;
        Ok(Rollout::new(
            Revision::new(status.revision.unwrap_or(0)),
            health_of(status.state.as_str()),
        ))
    }
}

impl Cluster for HelmCli {
    fn apply<'a>(
        &'a self,
        _manifests: &'a [Manifest],
    ) -> BoxFuture<'a, Result<Vec<String>, ClusterError>> {
        Box::pin(async move {
            Err(ClusterError::Apply {
                message: format!(
                    "{} drives Helm releases, not raw manifests: install a chart with \
                     `Cluster::upgrade`, or use a manifest-oriented adapter for server-side apply",
                    self.binary
                ),
            })
        })
    }

    fn upgrade<'a>(
        &'a self,
        request: &'a ChartUpgrade,
    ) -> BoxFuture<'a, Result<Rollout, ClusterError>> {
        Box::pin(async move {
            let namespace = request.namespace().or(self.namespace.as_deref());

            // Values go to a file whether or not they are secret: one code path
            // is easier to keep correct than two, and a file is what `-f` takes
            // anyway. For a secret, the `0600` mode and the `Drop` guard are what
            // keep it off every command line and off the disk afterwards.
            let values = match request.values() {
                Some(values) => Some(TempValues::write(values.document()).map_err(|error| {
                    ClusterError::Upgrade {
                        message: format!(
                            "could not write the chart values to a temporary file: {error}"
                        ),
                    }
                })?),
                None => None,
            };

            let args = upgrade_args(request, namespace, values.as_ref().map(TempValues::path))?;
            let output = self.helm(&args)?;

            // The guard drops here on every path — success, error, or a panic
            // inside Helm.
            if output.code != 0 {
                let stderr = stderr_of(&output);
                // Helm exits 1 for everything, so the exit code alone cannot say
                // whether the release landed or was rolled back. Ask the cluster.
                let message = match self.status(request.release(), namespace) {
                    Ok(status) => format!("{stderr} (the release now reports {})", status.state),
                    Err(error) => format!("{stderr} ({error})"),
                };
                return Err(ClusterError::Upgrade { message });
            }
            // Exit 0 is Helm not complaining, which is not the same as the
            // release being where it should be.
            self.observe(request.release(), namespace)
        })
    }

    fn rollout<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Rollout, ClusterError>> {
        Box::pin(async move { self.observe(name, self.namespace.as_deref()) })
    }

    fn health<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<HealthReport, ClusterError>> {
        Box::pin(async move {
            // A release this cluster does not have is neither a failure nor a
            // success: there is no observation, and silence is not health.
            match self.status(name, self.namespace.as_deref()) {
                Ok(status) => Ok(report_of(status.state.as_str(), status.description.as_deref())),
                Err(ClusterError::NotFound { name }) => Ok(HealthReport::with_reason(
                    Health::NoData,
                    format!("no Helm release named {name:?} in this cluster yet"),
                )),
                Err(error) => Err(error),
            }
        })
    }

    fn rollback<'a>(
        &'a self,
        name: &'a str,
        revision: Revision,
    ) -> BoxFuture<'a, Result<Rollout, ClusterError>> {
        Box::pin(async move {
            let namespace = self.namespace.as_deref();
            let mut args = vec!["rollback".to_string(), name.to_string(), revision.to_string()];
            args.push("--wait".to_string());
            if let Some(namespace) = namespace {
                args.push("--namespace".to_string());
                args.push(namespace.to_string());
            }
            let output = self.helm(&args)?;
            if output.code != 0 {
                let stderr = stderr_of(&output);
                return Err(if names_an_unknown_revision(&stderr) {
                    // A revision Helm no longer retains. The port forbids
                    // substituting the current revision, so this is an error.
                    ClusterError::RevisionUnknown { revision }
                } else if says_not_found(&stderr) {
                    ClusterError::NotFound { name: name.to_string() }
                } else {
                    ClusterError::Upgrade {
                        message: format!("helm rollback to {revision} failed: {stderr}"),
                    }
                });
            }
            self.observe(name, namespace)
        })
    }

    fn handle(&self) -> &ClusterRef {
        &self.handle
    }
}

/// The `helm upgrade` argv for `request`, in one fixed order: chart, atomicity,
/// namespace, values file, `--set` overrides sorted by key, then the digest pin
/// last. A run is reproducible, and a test can assert on the whole vector.
///
/// The digest pin is last so it is the value Helm ends up with if a `--set` key
/// collides with it. An image pin that is not a digest is
/// [`ClusterError::NotPinned`] rather than an argument.
fn upgrade_args(
    request: &ChartUpgrade,
    namespace: Option<&str>,
    values: Option<&Path>,
) -> Result<Vec<String>, ClusterError> {
    let mut args = vec![
        "upgrade".to_string(),
        "--install".to_string(),
        request.release().to_string(),
        chart_argument(request.chart()),
        // `--atomic` implies `--wait` and rolls a failed upgrade back to the
        // previous revision, which is the guarantee the port asks for.
        "--atomic".to_string(),
        "--cleanup-on-fail".to_string(),
    ];
    if let Some(namespace) = namespace {
        args.push("--namespace".to_string());
        args.push(namespace.to_string());
    }
    if let Some(values) = values {
        // `-f` takes a file path and never stdin, so the values are written
        // before the call rather than piped into it. Later `-f` files win, and
        // `--set` beats both.
        args.push("-f".to_string());
        args.push(values.display().to_string());
    }
    // `ChartUpgrade::set` is a `BTreeMap`, so this order is already sorted and
    // does not depend on insertion order.
    for (key, value) in request.set() {
        args.push("--set".to_string());
        args.push(format!("{key}={value}"));
    }
    if let Some(image) = request.image() {
        // `--set-string`, not `--set`: a digest must stay a string, and `--set`
        // would let Helm's own coercion rules turn it into something else.
        args.push("--set-string".to_string());
        args.push(format!("{}={}", image.key(), digest_argument(image.image())?));
    }
    Ok(args)
}

/// The chart argument: an OCI reference becomes `oci://<reference>`.
///
/// The digest goes **in the URL**, not in `--version`. Helm supports that from
/// 3.17.0, and it rejects a digest alongside a `--version` that disagrees with
/// it — so a digest-pinned chart emits no `--version` at all. A tag reference
/// keeps its tag in the URL, which Helm resolves the same way;
/// [`Chart::oci`] refuses to build one, so that path is here only so a chart
/// assembled as a `Chart::Oci` directly still produces a working command
/// rather than a panic. A [`Chart::Path`] is passed through exactly as given.
fn chart_argument(chart: &Chart) -> String {
    match chart {
        Chart::Oci(image) => format!("oci://{image}"),
        Chart::Path(path) => path.clone(),
    }
}

/// The digest an [`ImagePin`](ks_core::ports::cluster::ImagePin) pins:
/// `sha256:<hex>`, never a tag.
///
/// Total, not because a tag can be passed through — it cannot — but because a
/// tag that got here anyway has to be an error rather than a `--set-string`
/// value: writing `1.2.3` under a key named `image.digest` renders a
/// Deployment that claims to be pinned and is not.
fn digest_argument(image: &ImageRef) -> Result<String, ClusterError> {
    match image.reference() {
        Reference::Digest(digest) => Ok(digest.to_string()),
        Reference::Tag(_) => Err(ClusterError::NotPinned { what: "image pin" }),
    }
}

/// Helm's `info.status` as [`Health`].
///
/// `info.status` is an untyped string and Helm may add more values, so an
/// unrecognised one maps to [`Health::Degraded`] — never [`Health::Healthy`].
/// An empty state is "the reporting call found nothing", and is
/// [`Health::NoData`].
fn health_of(state: &str) -> Health {
    if state.is_empty() {
        return Health::NoData;
    }
    if state == DEPLOYED {
        return Health::Healthy;
    }
    if state == FAILED {
        return Health::Failed;
    }
    if PROGRESSING.contains(&state) {
        return Health::Progressing;
    }
    if DEGRADED.contains(&state) {
        return Health::Degraded;
    }
    Health::Degraded
}

/// The same mapping, as a [`HealthReport`] carrying Helm's own `description` —
/// the wording a run log shows while a `wait` gate polls.
fn report_of(state: &str, description: Option<&str>) -> HealthReport {
    let health = health_of(state);
    let reason = match description {
        Some(description) if !description.is_empty() => description.to_string(),
        _ if state.is_empty() => "helm status reported no state for this release".to_string(),
        _ => state.to_string(),
    };
    HealthReport::with_reason(health, reason)
}

/// Reads `helm status -o json`.
///
/// The status string is taken as-is rather than matched against an enum, so a
/// Helm that grows a status is a value to map conservatively rather than a parse
/// failure. Unreadable JSON is [`ClusterError::Upgrade`]: a status this adapter
/// cannot read is not a status it can report.
fn parse_status(bytes: &[u8], release: &str) -> Result<Status, ClusterError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| ClusterError::Upgrade {
            message: format!("helm status for {release:?} was not readable JSON: {error}"),
        })?;
    let info = value.get("info");
    let state = info
        .and_then(|info| info.get("status"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let description = info
        .and_then(|info| info.get("description"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let revision = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok());
    Ok(Status { revision, state, description })
}

/// Helm's stderr, trimmed, or the exit code when Helm said nothing.
fn stderr_of(output: &Output) -> String {
    let trimmed = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if trimmed.is_empty() { format!("helm exited {}", output.code) } else { trimmed }
}

/// Whether Helm said the release is not there.
///
/// Helm's wording is `Error: release: not found`. A chart the registry does not
/// have reads similarly, and either way there is no release to report on.
fn says_not_found(stderr: &str) -> bool {
    let lowered = stderr.to_ascii_lowercase();
    lowered.contains("not found") || lowered.contains("no revision")
}

/// Whether Helm said the *revision* is the problem rather than the release.
///
/// Helm answers a rollback to a revision it no longer retains with wording that
/// names the revision (`release: "api" revision: 7 not found`, or `has no 7
/// deployed releases`). The port forbids answering that with the current
/// revision, so it has to be told apart from an ordinary failure.
fn names_an_unknown_revision(stderr: &str) -> bool {
    let lowered = stderr.to_ascii_lowercase();
    lowered.contains("revision") || lowered.contains("deployed releases")
}

/// The handle endpoint for a context. Helm resolves the API server from the
/// kubeconfig at call time; this says where it will look and carries no
/// credential.
fn endpoint_for(context: &str) -> String {
    format!("kubeconfig:{context}")
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use ks_testing::block_on;

    use super::*;
    use ks_core::ports::cluster::{ImagePin, Values};

    const SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const CHART: &str = "reg.example.com/team/chart";

    /// One invocation the fake saw.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Call {
        program: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
    }

    /// What one invocation answers with.
    #[derive(Debug, Clone)]
    struct Reply {
        code: i32,
        stdout: String,
        stderr: String,
    }

    impl Reply {
        fn ok(stdout: impl Into<String>) -> Reply {
            Reply { code: 0, stdout: stdout.into(), stderr: String::new() }
        }
        fn failed(stderr: impl Into<String>) -> Reply {
            Reply { code: 1, stdout: String::new(), stderr: stderr.into() }
        }
    }

    /// A [`Runner`] that records every call and answers from a script.
    ///
    /// The script is a queue: one reply per invocation, in order, so a test that
    /// wants the upgrade to fail and the follow-up status query to succeed queues
    /// exactly that.
    struct FakeRunner {
        calls: Mutex<Vec<Call>>,
        replies: Mutex<VecDeque<Reply>>,
        /// Runs on every invocation, while the call is still in flight — which is
        /// how a test observes the values file *while Helm would be reading it*,
        /// before the guard has removed it.
        on_call: Option<Watcher>,
    }

    /// Something a test can watch the fake with, mid-call.
    type Watcher = Box<dyn Fn(&Call) + Send + Sync>;

    impl FakeRunner {
        fn new(replies: impl IntoIterator<Item = Reply>) -> Arc<FakeRunner> {
            Arc::new(FakeRunner {
                calls: Mutex::new(Vec::new()),
                replies: Mutex::new(replies.into_iter().collect()),
                on_call: None,
            })
        }

        /// Records calls without answering any, and runs `on_call` for each.
        fn watching(on_call: impl Fn(&Call) + Send + Sync + 'static) -> Arc<FakeRunner> {
            Arc::new(FakeRunner {
                calls: Mutex::new(Vec::new()),
                replies: Mutex::new(VecDeque::new()),
                on_call: Some(Box::new(on_call)),
            })
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().expect("fake runner calls").clone()
        }

        fn answer_all(&self, replies: impl IntoIterator<Item = Reply>) {
            self.replies.lock().expect("fake runner replies").extend(replies);
        }

        /// The argv of the first call — the mutating one, where an upgrade or
        /// a rollback is followed by a status query.
        fn first_args(&self) -> Vec<String> {
            self.calls().first().map(|call| call.args.clone()).expect("at least one call")
        }

        /// The argv of the only call, panicking when there was not exactly one.
        fn only_args(&self) -> Vec<String> {
            let calls = self.calls();
            assert_eq!(calls.len(), 1, "expected exactly one call, got {calls:#?}");
            calls[0].args.clone()
        }
    }

    impl Runner for FakeRunner {
        fn run(
            &self,
            program: &str,
            args: &[String],
            env: &[(String, String)],
        ) -> io::Result<Output> {
            let call =
                Call { program: program.to_string(), args: args.to_vec(), env: env.to_vec() };
            if let Some(on_call) = &self.on_call {
                on_call(&call);
            }
            self.calls.lock().expect("fake runner calls").push(call);
            let reply = self.replies.lock().expect("fake runner replies").pop_front();
            Ok(match reply {
                Some(reply) => Output {
                    code: reply.code,
                    stdout: reply.stdout.into_bytes(),
                    stderr: reply.stderr.into_bytes(),
                },
                None => Output { code: 0, stdout: Vec::new(), stderr: Vec::new() },
            })
        }
    }

    /// The status JSON Helm prints for a release on revision `version`.
    fn status_json(version: u32, state: &str, description: &str) -> String {
        serde_json::json!({
            "name": "api",
            "info": {"status": state, "description": description},
            "version": version,
            "namespace": "default",
        })
        .to_string()
    }

    /// The argv of an upgrade that installed cleanly on revision 1.
    fn installed() -> Reply {
        Reply::ok("Release \"api\" has been installed. Happy Helming!")
    }

    /// The status an upgrade reports after `installed`.
    fn deployed_status(version: u32) -> Reply {
        Reply::ok(status_json(version, "deployed", "Install complete"))
    }

    fn oci_chart(repository: &str) -> Chart {
        Chart::oci(ImageRef::parse(&format!("{repository}@sha256:{SHA}")).expect("a digest ref"))
            .expect("a digest chart")
    }

    fn adapter(runner: Arc<FakeRunner>) -> HelmCli {
        HelmCli::new("kind-kind").with_binary("helm").with_namespace("default").with_runner(runner)
    }

    fn request() -> ChartUpgrade {
        ChartUpgrade::new("api", oci_chart(CHART)).expect("named release")
    }

    /// The path a `-f` argument names.
    fn values_path(args: &[String]) -> String {
        let at = args.iter().position(|arg| arg == "-f").expect("a -f argument");
        args[at + 1].clone()
    }

    /// The argument following `flag`, or `None` when the flag is absent.
    fn after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        let at = args.iter().position(|arg| arg == flag)?;
        args.get(at + 1).map(String::as_str)
    }

    /// Every argument that follows an occurrence of `flag`.
    fn values_of<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
        args.iter()
            .enumerate()
            .filter(|(index, _)| *index > 0 && args[index - 1] == flag)
            .map(|(_, arg)| arg.as_str())
            .collect()
    }

    // -- chart arguments ---------------------------------------------------

    #[test]
    fn an_oci_chart_by_digest_becomes_a_url_with_the_digest_in_it_and_no_version() {
        let runner = FakeRunner::new([installed(), deployed_status(3)]);
        let adapter = adapter(runner.clone());
        block_on(adapter.upgrade(&request())).expect("the release installs");

        let args = runner.first_args();
        assert_eq!(args[0], "upgrade");
        assert!(
            args.contains(&format!("oci://{CHART}@sha256:{SHA}")),
            "the digest goes in the URL, not in --version: {args:?}"
        );
        // Helm rejects a digest alongside a disagreeing --version, and there is
        // nothing to disagree with, so the flag is never emitted.
        assert!(!args.iter().any(|arg| arg == "--version"), "{args:?}");
    }

    #[test]
    fn a_path_chart_is_passed_through_exactly_as_given() {
        let runner = FakeRunner::new([installed(), deployed_status(1)]);
        let adapter = adapter(runner.clone());
        let request = ChartUpgrade::new("api", Chart::path("./charts/api.tgz").expect("a path"))
            .expect("named release");
        block_on(adapter.upgrade(&request)).expect("the release installs");

        let args = runner.first_args();
        assert!(args.contains(&"./charts/api.tgz".to_string()), "{args:?}");
        assert!(!args.iter().any(|arg| arg.starts_with("oci://")), "{args:?}");
    }

    #[test]
    fn a_tagged_oci_chart_never_reaches_the_adapter_as_an_upgrade() {
        // The port refuses to build one, so the adapter never emits the URL.
        assert_eq!(
            Chart::oci(ImageRef::parse(&format!("{CHART}:1.2.3")).expect("a tag ref")),
            Err(ClusterError::NotPinned { what: "chart" })
        );
        // A chart built as the variant directly is still rendered, rather than
        // panicking — the port's constructor is the enforcement point, not this
        // adapter's.
        let chart = Chart::Oci(ImageRef::parse(&format!("{CHART}:1.2.3")).expect("a tag ref"));
        assert_eq!(chart_argument(&chart), format!("oci://{CHART}:1.2.3"));
    }

    #[test]
    fn a_tag_pinned_image_is_refused_before_helm_is_ever_run() {
        // `ImagePin::new` refuses a tag, so this has to reach the adapter's own
        // guard by building the pin out of a digest reference and then handing
        // `upgrade` a request whose pin is a tag — which the type forbids, so
        // the check is asserted where it is enforceable instead.
        let tagged = ImageRef::parse("reg.example.com/team/api:1.2.3").expect("a tag reference");
        assert_eq!(
            ImagePin::new(tagged.clone()),
            Err(ClusterError::NotPinned { what: "image pin" })
        );
        assert_eq!(
            digest_argument(&tagged),
            Err(ClusterError::NotPinned { what: "image pin" }),
            "the adapter's own guard refuses it too, rather than writing a tag under a digest key"
        );

        let pinned = oci_image("reg.example.com/team/api");
        assert_eq!(digest_argument(&pinned).expect("a digest"), format!("sha256:{SHA}"));
    }

    #[test]
    fn every_upgrade_is_atomic_and_cleans_up_after_itself() {
        let runner = FakeRunner::new([installed(), deployed_status(2)]);
        let adapter = adapter(runner.clone());
        block_on(adapter.upgrade(&request())).expect("the release installs");

        let args = runner.first_args();
        assert_eq!(args[1], "--install", "install and upgrade are one operation: {args:?}");
        assert_eq!(args[2], "api");
        assert!(args.contains(&"--atomic".to_string()), "{args:?}");
        assert!(args.contains(&"--cleanup-on-fail".to_string()), "{args:?}");
    }

    #[test]
    fn the_namespace_is_passed_only_when_there_is_one() {
        let default = FakeRunner::new([installed(), deployed_status(1)]);
        let configured = adapter(default.clone()).with_namespace("production");
        block_on(configured.upgrade(&request())).expect("the release installs");
        assert_eq!(after(&default.first_args(), "--namespace"), Some("production"));

        // The request's own namespace beats the adapter's default.
        let overridden = FakeRunner::new([installed(), deployed_status(1)]);
        let adapter = adapter(overridden.clone()).with_namespace("production");
        block_on(adapter.upgrade(&request().with_namespace("staging")))
            .expect("the release installs");
        assert_eq!(after(&overridden.first_args(), "--namespace"), Some("staging"));

        // No namespace anywhere: no flag, so Helm's own default applies.
        let runner = FakeRunner::new([installed(), deployed_status(1)]);
        let adapter = HelmCli::new("kind-kind").with_runner(runner.clone());
        block_on(adapter.upgrade(&request())).expect("the release installs");
        assert!(!runner.first_args().contains(&"--namespace".to_string()));
    }

    #[test]
    fn every_set_entry_becomes_its_own_argument_in_key_order() {
        let runner = FakeRunner::new([installed(), deployed_status(1)]);
        let adapter = adapter(runner.clone());
        let request = request()
            .with_set("zeta", "last")
            .with_set("alpha", "first")
            .with_set("image.tag", "canary");
        block_on(adapter.upgrade(&request)).expect("the release installs");

        // Sorted by key, whatever order they were added in: a `BTreeMap` is what
        // makes this deterministic.
        assert_eq!(
            values_of(&runner.first_args(), "--set"),
            vec!["alpha=first", "image.tag=canary", "zeta=last"]
        );
    }

    #[test]
    fn the_image_digest_is_pinned_with_set_string_so_it_cannot_be_coerced() {
        let runner = FakeRunner::new([installed(), deployed_status(1)]);
        let adapter = adapter(runner.clone());
        let request = request().with_image(
            ImagePin::new(oci_image("reg.example.com/team/api")).expect("a digest pin"),
        );
        block_on(adapter.upgrade(&request)).expect("the release installs");

        let args = runner.first_args();
        assert_eq!(values_of(&args, "--set-string"), vec![&format!("image.digest=sha256:{SHA}")]);
        assert!(values_of(&args, "--set").is_empty(), "{args:?}");
    }

    #[test]
    fn a_custom_digest_key_is_honoured() {
        let runner = FakeRunner::new([installed(), deployed_status(1)]);
        let adapter = adapter(runner.clone());
        let request = request().with_image(
            ImagePin::at(oci_image("reg.example.com/team/api"), "container.image.sha")
                .expect("a named key"),
        );
        block_on(adapter.upgrade(&request)).expect("the release installs");

        assert_eq!(
            values_of(&runner.first_args(), "--set-string"),
            vec![&format!("container.image.sha=sha256:{SHA}")]
        );
    }

    fn oci_image(repository: &str) -> ImageRef {
        ImageRef::parse(&format!("{repository}@sha256:{SHA}")).expect("a digest reference")
    }

    // -- secret values -----------------------------------------------------

    #[test]
    fn secret_values_reach_helm_through_a_0600_file_that_is_never_on_a_command_line() {
        const SECRET: &str = concat!("dbPassword: ", "hunter2", "-the-real-one");
        // Observed while Helm would be reading the file: its mode, its contents
        // and its path, as the fake is called and the guard has not run.
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let runner = FakeRunner::watching({
            let seen = Arc::clone(&seen);
            move |call: &Call| {
                let Some(at) = call.args.iter().position(|arg| arg == "-f") else { return };
                let path = call.args[at + 1].clone();
                let metadata = fs::metadata(&path).expect("the values file exists during the call");
                let contents = fs::read_to_string(&path).expect("readable by its owner");
                let mut seen = seen.lock().expect("observations");
                seen.push(format!("{:o}", mode_of(&metadata)));
                seen.push(contents);
                seen.push(path);
            }
        });
        runner.answer_all([installed(), deployed_status(4)]);

        let adapter = adapter(runner.clone());
        let request = request().with_values(Values::secret(SECRET));
        block_on(adapter.upgrade(&request)).expect("the release installs");

        // The load-bearing assertion: the secret is nowhere in the argv. An
        // argument is readable by every other process on the machine for as long
        // as the call runs, and Helm keeps its own.
        for call in runner.calls() {
            for arg in &call.args {
                assert!(
                    !arg.contains("hunter2"),
                    "the secret leaked onto the command line: {arg:?}"
                );
            }
            assert!(!call.args.join(" ").contains(SECRET), "{:?}", call.args);
        }

        let seen = seen.lock().expect("observations").clone();
        assert_eq!(seen[0], "600", "the values file is readable only by its owner");
        assert!(seen[1].contains("hunter2-the-real-one"), "the values were written verbatim");
        assert_eq!(seen[2], values_path(&runner.calls()[0].args), "-f named the observed file");
        // And it is gone once the call has returned.
        assert!(!Path::new(&seen[2]).exists(), "the values file survived the call");
    }

    #[test]
    fn the_values_file_is_removed_even_when_the_upgrade_fails() {
        let runner = FakeRunner::new([
            Reply::failed("Error: UPGRADE FAILED: timed out waiting for the condition"),
            Reply::ok(status_json(2, "deployed", "Rollback was a success")),
        ]);
        let adapter = adapter(runner.clone());
        let request =
            request().with_values(Values::secret(concat!("token: ", "abc123", "-secret")));
        assert!(block_on(adapter.upgrade(&request)).is_err(), "the upgrade fails");

        let path = values_path(&runner.calls()[0].args);
        assert!(!Path::new(&path).exists(), "the values file leaked on the error path: {path}");
    }

    #[test]
    fn non_secret_values_take_the_same_file_path() {
        // One code path for secret and plain values, documented in docs/HELM.md.
        let runner = FakeRunner::new([installed(), deployed_status(1)]);
        let adapter = adapter(runner.clone());
        let request = request().with_values(Values::new("replicas: 3"));
        block_on(adapter.upgrade(&request)).expect("the release installs");

        let path = values_path(&runner.calls()[0].args);
        assert!(runner.calls()[0].args.contains(&path));
        assert!(!Path::new(&path).exists());
    }

    #[test]
    fn a_values_document_reaches_disk_verbatim() {
        // Whatever the caller wrote — YAML here, JSON another time. This adapter
        // never parses it.
        const DOCUMENT: &str = "replicas: 3\nimage:\n  repository: reg.example.com/team/api\n";
        let seen: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        let runner = FakeRunner::watching({
            let seen = Arc::clone(&seen);
            move |call: &Call| {
                let Some(at) = call.args.iter().position(|arg| arg == "-f") else { return };
                *seen.lock().expect("seen") =
                    fs::read_to_string(&call.args[at + 1]).expect("readable by its owner");
            }
        });
        runner.answer_all([installed(), deployed_status(1)]);
        let adapter = adapter(runner);
        let request = request().with_values(Values::new(DOCUMENT));
        block_on(adapter.upgrade(&request)).expect("the release installs");

        assert_eq!(seen.lock().expect("seen").clone(), DOCUMENT);
    }

    #[test]
    fn two_values_files_in_one_run_never_collide() {
        let first = TempValues::write("a: 1").expect("a temp file");
        let second = TempValues::write("b: 2").expect("another temp file");
        assert_ne!(first.path(), second.path());
        let (first_path, second_path) = (first.path().to_path_buf(), second.path().to_path_buf());
        drop(first);
        assert!(!first_path.exists());
        assert!(second_path.exists(), "dropping one does not remove the other");
    }

    /// The permission bits of a file, as octal — `0600` for the values file.
    #[cfg(unix)]
    fn mode_of(metadata: &fs::Metadata) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o777
    }

    #[cfg(not(unix))]
    fn mode_of(metadata: &fs::Metadata) -> u32 {
        u32::from(metadata.permissions().mode())
    }

    // -- failures ----------------------------------------------------------

    #[test]
    fn a_failed_upgrade_that_leaves_the_release_failed_is_an_upgrade_error() {
        let runner = FakeRunner::new([
            Reply::failed("Error: UPGRADE FAILED: timed out waiting for the condition"),
            Reply::ok(status_json(5, "failed", "Atomic rollback failed")),
        ]);
        let adapter = adapter(runner.clone());
        let error = block_on(adapter.upgrade(&request())).expect_err("the upgrade fails");

        let ClusterError::Upgrade { message } = error else {
            panic!("expected an upgrade error, got {error:?}");
        };
        assert!(message.contains("UPGRADE FAILED"), "{message}");
        // The follow-up status query is what tells us where the release ended up.
        assert!(message.contains("failed"), "{message}");
        assert_eq!(runner.calls().len(), 2, "the exit code alone is never trusted");
        assert_eq!(runner.calls()[1].args[0], "status");
    }

    #[test]
    fn a_non_zero_exit_whose_release_rolled_back_cleanly_is_still_a_failure() {
        let runner = FakeRunner::new([
            Reply::failed("Error: UPGRADE FAILED: timed out waiting for the condition"),
            Reply::ok(status_json(3, "deployed", "Rollback was a success")),
        ]);
        let adapter = adapter(runner.clone());
        let error = block_on(adapter.upgrade(&request())).expect_err("the upgrade still failed");

        let ClusterError::Upgrade { message } = error else {
            panic!("a rolled-back upgrade is still a failure, got {error:?}");
        };
        assert!(message.contains("deployed"), "the message reports where it ended up: {message}");
    }

    #[test]
    fn a_status_query_for_a_release_helm_does_not_have_is_not_found() {
        let runner = FakeRunner::new([Reply::failed("Error: release: not found")]);
        let adapter = adapter(runner.clone());
        let error = block_on(adapter.rollout("api")).expect_err("there is no such release");

        assert_eq!(error, ClusterError::NotFound { name: "api".to_string() });
        let args = runner.only_args();
        assert_eq!(args[0], "status");
        assert_eq!(args[1], "api");
        assert_eq!(args[2], "-o");
        assert_eq!(args[3], "json");
    }

    #[test]
    fn health_reports_no_data_rather_than_healthy_for_a_release_that_is_not_there() {
        let runner = FakeRunner::new([Reply::failed("Error: release: not found")]);
        let adapter = adapter(runner.clone());
        let report = block_on(adapter.health("api")).expect("no data is a report, not an error");

        assert_eq!(report.state(), Health::NoData);
        // Silence is not health — this is the load-bearing rule of the port.
        assert!(!report.satisfies(Health::Healthy));
        assert!(!report.state().is_settled(), "a waiter keeps polling rather than passing");
        assert!(report.reason().expect("a reason").contains("api"), "{report:?}");
    }

    #[test]
    fn every_helm_status_maps_to_a_health_state() {
        // Helm's documented set, and the mapping the port's vocabulary requires.
        for (state, want) in [
            ("deployed", Health::Healthy),
            ("pending-install", Health::Progressing),
            ("pending-upgrade", Health::Progressing),
            ("pending-rollback", Health::Progressing),
            ("uninstalling", Health::Progressing),
            ("failed", Health::Failed),
            ("superseded", Health::Degraded),
            ("uninstalled", Health::Degraded),
            ("unknown", Health::Degraded),
        ] {
            let runner = FakeRunner::new([Reply::ok(status_json(1, state, "because"))]);
            let adapter = adapter(runner);
            let report = block_on(adapter.health("api")).expect("a report");
            assert_eq!(report.state(), want, "helm status {state:?}");
            // Helm's own wording is carried through, not an interpretation.
            assert_eq!(report.reason(), Some("because"), "helm status {state:?}");
        }
    }

    #[test]
    fn a_status_helm_grows_later_maps_conservatively_not_optimistically() {
        let runner = FakeRunner::new([Reply::ok(status_json(1, "uninstall-succeeded", "gone"))]);
        let adapter = adapter(runner);
        let report = block_on(adapter.health("api")).expect("a report");
        assert_eq!(report.state(), Health::Degraded);
        assert!(!report.satisfies(Health::Healthy));
    }

    #[test]
    fn a_status_with_no_state_at_all_is_no_data() {
        let runner = FakeRunner::new([Reply::ok("{\"name\":\"api\",\"namespace\":\"default\"}")]);
        let adapter = adapter(runner);
        let report = block_on(adapter.health("api")).expect("a report");
        assert_eq!(report.state(), Health::NoData);
        assert!(!report.satisfies(Health::Healthy));
    }

    #[test]
    fn a_successful_upgrade_reports_the_revision_the_release_landed_on() {
        let runner = FakeRunner::new([
            Reply::ok("Release \"api\" has been upgraded. Happy Helming!"),
            Reply::ok(status_json(7, "deployed", "Upgrade complete")),
        ]);
        let adapter = adapter(runner.clone());
        let rollout = block_on(adapter.upgrade(&request())).expect("the upgrade lands");

        assert_eq!(rollout.revision(), Revision::new(7));
        assert_eq!(rollout.state(), Health::Healthy);
        assert!(rollout.state().is_settled());
        // The revision is read back from the release, never guessed from the
        // exit code, and the same namespace is queried.
        let args = &runner.calls()[1].args;
        assert_eq!(args[0], "status");
        assert!(args.contains(&"default".to_string()), "{args:?}");
    }

    #[test]
    fn a_status_without_a_revision_reports_revision_zero_rather_than_inventing_one() {
        // `version` is `omitempty` in Helm's status: a release with no
        // successful revision has none.
        let runner = FakeRunner::new([Reply::ok(
            serde_json::json!({"name": "api", "info": {"status": "deployed"}}).to_string(),
        )]);
        let adapter = adapter(runner);
        let rollout = block_on(adapter.rollout("api")).expect("a rollout");
        assert_eq!(rollout.revision(), Revision::new(0));
        assert_eq!(rollout.state(), Health::Healthy);
    }

    #[test]
    fn a_status_that_is_not_json_is_an_error_rather_than_a_guess() {
        let runner = FakeRunner::new([Reply::ok("Release: api\n")]);
        let adapter = adapter(runner);
        let error = block_on(adapter.rollout("api")).expect_err("unreadable status");
        assert!(matches!(error, ClusterError::Upgrade { .. }), "{error:?}");
    }

    // -- rollback ----------------------------------------------------------

    #[test]
    fn rollback_names_the_revision_explicitly_and_never_omits_it() {
        let runner = FakeRunner::new([
            Reply::ok("Rollback was a success"),
            Reply::ok(status_json(3, "deployed", "Rollback complete")),
        ]);
        let adapter = adapter(runner.clone());
        let rollout = block_on(adapter.rollback("api", Revision::new(3))).expect("it lands");

        let args = runner.first_args();
        assert_eq!(args[0], "rollback");
        assert_eq!(args[1], "api");
        assert_eq!(args[2], "3", "the requested revision, never the current one: {args:?}");
        assert!(args.contains(&"--wait".to_string()), "{args:?}");
        assert_eq!(rollout.revision(), Revision::new(3));
        assert_eq!(rollout.state(), Health::Healthy);
    }

    #[test]
    fn a_revision_the_cluster_no_longer_retains_is_revision_unknown() {
        let runner = FakeRunner::new([Reply::failed(
            "Error: release: \"api\" revision: 9 not found: failed to get revision 9",
        )]);
        let adapter = adapter(runner.clone());
        let error = block_on(adapter.rollback("api", Revision::new(9))).expect_err("revision gone");

        assert_eq!(error, ClusterError::RevisionUnknown { revision: Revision::new(9) });
        // The current revision must never be substituted for one that was asked
        // for, so there is no second call here.
        assert_eq!(runner.calls().len(), 1, "{:?}", runner.calls());
        assert_eq!(runner.only_args()[2], "9");
    }

    // -- handle, environment, and what this adapter refuses to do -----------

    #[test]
    fn the_handle_reports_the_context_it_was_built_with() {
        let runner = FakeRunner::new([deployed_status(1)]);
        let adapter = HelmCli::new("prod-eu")
            .with_kubeconfig("/etc/ks/prod.kubeconfig")
            .with_namespace("production")
            .with_runner(runner.clone());

        assert_eq!(adapter.handle().context(), "prod-eu");
        assert_eq!(adapter.handle().endpoint(), "kubeconfig:prod-eu");
        // The handle carries a method, never a credential.
        assert_eq!(adapter.handle().auth(), &AuthMethod::WorkloadIdentity);
        assert!(!format!("{:?}", adapter.handle()).contains("token"));

        block_on(adapter.rollout("api")).expect("a status query");
        let env = &runner.calls()[0].env;
        assert!(
            env.contains(&("HELM_KUBECONTEXT".to_string(), "prod-eu".to_string())),
            "the context is set explicitly: {env:?}"
        );
        assert!(
            env.contains(&("KUBECONFIG".to_string(), "/etc/ks/prod.kubeconfig".to_string())),
            "the kubeconfig is set explicitly, not inherited: {env:?}"
        );
    }

    #[test]
    fn an_empty_context_is_an_error_rather_than_a_panic() {
        assert!(matches!(HelmCli::try_new("  "), Err(ClusterError::Empty { name: "context" })));
        assert!(HelmCli::try_new("kind-kind").is_ok());
    }

    #[test]
    fn every_helm_invocation_runs_the_configured_binary_with_no_shell() {
        let runner = FakeRunner::new([deployed_status(1)]);
        let adapter = adapter(runner.clone()).with_binary("/opt/helm-3.17/helm");
        block_on(adapter.rollout("api")).expect("a status query");
        assert_eq!(runner.calls()[0].program, "/opt/helm-3.17/helm");
    }

    #[test]
    fn apply_reports_that_helm_does_not_apply_manifests_and_never_calls_kubectl() {
        let runner = FakeRunner::new(Vec::<Reply>::new());
        let adapter = adapter(runner.clone());
        let manifests = [Manifest::new("Deployment/api", b"kind: Deployment").expect("non-empty")];

        let error = block_on(adapter.apply(&manifests)).expect_err("there is nothing to apply");
        let ClusterError::Apply { message } = error else {
            panic!("expected an apply error, got {error:?}");
        };
        assert!(message.contains("Helm releases"), "{message}");
        assert!(message.contains("upgrade"), "{message}");
        assert!(runner.calls().is_empty(), "kubectl is never shelled out to: {:?}", runner.calls());
    }

    #[test]
    fn the_full_argv_for_an_oci_by_digest_chart_is_exactly_this() {
        // The end-to-end shape of one deploy, so a reviewer can read the whole
        // command rather than infer it from the pieces.
        let runner = FakeRunner::new([installed(), deployed_status(1)]);
        let adapter = adapter(runner.clone());
        let request = request()
            .with_namespace("production")
            .with_values(Values::new("replicas: 2"))
            .with_set("ingress.host", "api.example.com")
            .with_set("image.tag", "canary")
            .with_image(
                ImagePin::new(oci_image("reg.example.com/team/api")).expect("a digest pin"),
            );
        block_on(adapter.upgrade(&request)).expect("the release installs");

        let args = runner.first_args();
        // The values path is the only part that cannot be predicted; everything
        // else is asserted verbatim.
        assert_eq!(
            args.iter().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "upgrade",
                "--install",
                "api",
                &format!("oci://{CHART}@sha256:{SHA}"),
                "--atomic",
                "--cleanup-on-fail",
                "--namespace",
                "production",
                "-f",
                // The 0600 temporary file, which is gone by now.
                args[args.iter().position(|arg| arg == "-f").expect("-f") + 1].as_str(),
                "--set",
                "image.tag=canary",
                "--set",
                "ingress.host=api.example.com",
                "--set-string",
                &format!("image.digest=sha256:{SHA}"),
            ]
        );
    }
}
