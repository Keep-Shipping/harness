//! The [`StepKind`] contract: what a step declares, and what it is handed when it runs
//! ([#39](https://github.com/Keep-Shipping/harness/issues/39)).
//!
//! A step declares its ports, schema and action class; [`run`](StepKind::run) receives a
//! [`StepCtx`] holding only what it declared. The harness checks the schema before and after
//! every run, and [`render_steps_markdown`] renders the declared contracts for `docs/STEPS.md`.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ports::BoxFuture;
use crate::ports::clock::Clock;
use crate::ports::run_context::NetworkScope;
use crate::ports::script_host::{Value, ValueType, Values};
use crate::ports::secrets::Redactor;
pub use crate::version::STEP_API;

/// A step contract's semantic version. Hand-rolled: the harness only displays and orders
/// versions, which does not warrant a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Breaking-contract bumps.
    pub major: u32,
    /// Additions.
    pub minor: u32,
    /// Fixes.
    pub patch: u32,
}

impl Version {
    /// Creates a version, e.g. `Version::new(1, 2, 3)`.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Version {
        Version { major, minor, patch }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// One port trait, as a value a step can declare it needs; each variant names a trait in
/// [`crate::ports`]. `#[non_exhaustive]`: matchers outside this crate carry a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Port {
    RunContext,
    Secrets,
    ImageBuilder,
    Registry,
    Signer,
    IacTool,
    HttpClient,
    Clock,
    IdGen,
    ScriptHost,
    ApprovalChannel,
    Directory,
    Cluster,
    RemoteShell,
    FunctionHost,
    DecisionModel,
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Port::RunContext => "RunContext",
            Port::Secrets => "Secrets",
            Port::ImageBuilder => "ImageBuilder",
            Port::Registry => "Registry",
            Port::Signer => "Signer",
            Port::IacTool => "IacTool",
            Port::HttpClient => "HttpClient",
            Port::Clock => "Clock",
            Port::IdGen => "IdGen",
            Port::ScriptHost => "ScriptHost",
            Port::ApprovalChannel => "ApprovalChannel",
            Port::Directory => "Directory",
            Port::Cluster => "Cluster",
            Port::RemoteShell => "RemoteShell",
            Port::FunctionHost => "FunctionHost",
            Port::DecisionModel => "DecisionModel",
        };
        f.write_str(name)
    }
}

/// Fills in the per-port slot, builder, getter and set arms of [`Ports`]. The list must match
/// the [`Port`] variants above, in order.
macro_rules! define_ports {
    ( $( ($module:ident, $trait:ident, $field:ident, $with:ident) ),* $(,)? ) => {
        /// The ports a composition provides: one slot per port trait. A step never receives the
        /// whole set — the harness hands each step only the ports it declared
        /// ([`Ports::restricted_to`]).
        #[derive(Clone, Default)]
        pub struct Ports {
            $( $field: Option<Arc<dyn crate::ports::$module::$trait>>, )*
        }

        impl Ports {
            $(
                #[doc = concat!("Provides the `", stringify!($trait), "` port.")]
                #[must_use]
                pub fn $with(mut self, port: Arc<dyn crate::ports::$module::$trait>) -> Ports {
                    self.$field = Some(port);
                    self
                }

                #[doc = concat!("The provided `", stringify!($trait), "` port, if any.")]
                pub fn $field(&self) -> Option<&Arc<dyn crate::ports::$module::$trait>> {
                    self.$field.as_ref()
                }
            )*

            /// The ports currently provided, as a set.
            pub fn provided(&self) -> BTreeSet<Port> {
                let mut provided = BTreeSet::new();
                $(
                    if self.$field.is_some() {
                        provided.insert(Port::$trait);
                    }
                )*
                provided
            }

            /// A copy of `self` keeping only the listed ports.
            #[must_use]
            pub fn restricted_to(&self, ports: &[Port]) -> Ports {
                let mut restricted = Ports::default();
                for port in ports {
                    match port {
                        $(
                            Port::$trait => restricted.$field = self.$field.clone(),
                        )*
                    }
                }
                restricted
            }
        }
    };
}

define_ports! {
    (run_context, RunContext, run_context, with_run_context),
    (secrets, Secrets, secrets, with_secrets),
    (supply_chain, ImageBuilder, image_builder, with_image_builder),
    (supply_chain, Registry, registry, with_registry),
    (supply_chain, Signer, signer, with_signer),
    (iac, IacTool, iac_tool, with_iac_tool),
    (http, HttpClient, http_client, with_http_client),
    (clock, Clock, clock, with_clock),
    (id_gen, IdGen, id_gen, with_id_gen),
    (script_host, ScriptHost, script_host, with_script_host),
    (approval, ApprovalChannel, approval_channel, with_approval_channel),
    (approval, Directory, directory, with_directory),
    (cluster, Cluster, cluster, with_cluster),
    (remote_shell, RemoteShell, remote_shell, with_remote_shell),
    (function_host, FunctionHost, function_host, with_function_host),
    (decision_model, DecisionModel, decision_model, with_decision_model),
}

/// What a step run *is*, for policy purposes
/// ([#101](https://github.com/Keep-Shipping/harness/issues/101)): an action kind plus,
/// optionally, the environment it acts on. A step computes this from its inputs — `deploy` in
/// `prod` reads very differently from `deploy` in `dev` — and the checker reads it before
/// deciding what may run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionClass {
    pub kind: ActionKind,
    /// The environment it acts on, when the step knows one.
    pub env: Option<String>,
}

impl ActionClass {
    /// Classifies a run by its kind alone.
    pub fn new(kind: ActionKind) -> ActionClass {
        ActionClass { kind, env: None }
    }

    /// Names the environment the action acts on, e.g. `.in_env("prod")`.
    pub fn in_env(mut self, env: impl Into<String>) -> ActionClass {
        self.env = Some(env.into());
        self
    }

    /// The class this action really is, given what the plan it acts on would
    /// do ([#101](https://github.com/Keep-Shipping/harness/issues/101)).
    ///
    /// An [`ActionKind::Apply`] whose plan destroys anything — a replacement
    /// counts, since a replace is a delete followed by a create — is a
    /// [`ActionKind::Destroy`], and the environment is kept so `apply` in
    /// `prod` still reads as what it acts on.
    ///
    /// Everything else is returned unchanged, including a destroy that stays a
    /// destroy: the count cannot make an apply more destructive than a destroy
    /// already is, and the file's `before: destroy` rule must keep matching it.
    #[must_use]
    pub fn with_plan_destroys(self, destroys: usize) -> ActionClass {
        match self.kind {
            ActionKind::Apply if destroys > 0 => ActionClass { kind: ActionKind::Destroy, ..self },
            _ => self,
        }
    }
}

impl fmt::Display for ActionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind.as_str())?;
        if let Some(env) = &self.env {
            write!(f, " {env}")?;
        }
        Ok(())
    }
}

/// The kind of thing a step run does. Drives policy — an `Apply` needs an approval a `Read`
/// does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    /// Builds content: an image, an artifact.
    Build,
    /// Plans a change without applying it.
    Plan,
    /// Applies a planned change.
    Apply,
    /// Deploys content somewhere.
    Deploy,
    /// Tears something down.
    Destroy,
    /// Reads secrets.
    ReadSecrets,
    /// Anything else.
    Other,
}

impl ActionKind {
    /// The kind's name, as it appears in logs and docs, e.g. `"build"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionKind::Build => "build",
            ActionKind::Plan => "plan",
            ActionKind::Apply => "apply",
            ActionKind::Deploy => "deploy",
            ActionKind::Destroy => "destroy",
            ActionKind::ReadSecrets => "read-secrets",
            ActionKind::Other => "other",
        }
    }

    /// The action a step *kind* is, from its name alone: what the checker
    /// reads before a step runs, and what a block's signature carries for
    /// the steps it hides ([#80](https://github.com/Keep-Shipping/harness/issues/80)).
    /// Anything the catalog does not name is `Other`, so an unknown kind
    /// asserts nothing policy can forbid.
    #[must_use]
    pub fn of_kind(kind: &str) -> ActionKind {
        match kind {
            "oci.image" | "oci.artifact" => ActionKind::Build,
            "tofu.plan" => ActionKind::Plan,
            "tofu.apply" => ActionKind::Apply,
            "k8s.rollout" => ActionKind::Deploy,
            _ => ActionKind::Other,
        }
    }
}

/// What a step *needs* from its environment — as the step declares it. Distinct from
/// [`run_context::Capabilities`](crate::ports::run_context::Capabilities), which is what a run
/// *has*: the checker refuses (or flags) needs exceeding capabilities before anything executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepCapabilities {
    /// The step refuses to run off CI.
    pub ci_only: bool,
    /// The step needs to mint OIDC tokens.
    pub oidc: bool,
    /// The network the step needs to reach.
    pub network: NetworkScope,
}

impl Default for StepCapabilities {
    /// Local-safe: no CI requirement, no OIDC, no network.
    fn default() -> StepCapabilities {
        StepCapabilities { ci_only: false, oidc: false, network: NetworkScope::None }
    }
}

/// The values handed to a step, keyed by input name.
pub type Inputs = Values;
/// The values a step returns, keyed by output name.
pub type Outputs = Values;

/// The type of a schema field: a builtin [`ValueType`], or a named [`TypeDef`] registered on
/// the harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeRef {
    /// One of the JSON-ish builtin types.
    Builtin(ValueType),
    /// A named type; must match a [`TypeDef`] registered on the harness.
    Named(&'static str),
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeRef::Builtin(ty) => ty.fmt(f),
            TypeRef::Named(name) => f.write_str(name),
        }
    }
}

/// A named type registered on the harness — the vocabulary schemas share, e.g. `digest` =
/// string: documentation plus a base [`ValueType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeDef {
    pub name: &'static str,
    pub base: ValueType,
    /// What the type means, shown in generated docs.
    pub doc: &'static str,
}

/// One declared field of a [`StepSchema`].
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub name: &'static str,
    pub ty: TypeRef,
    /// Absent means the field takes whatever the step works out for itself — see
    /// [`Field::optional`].
    pub default: Option<Value>,
    /// Whether the field may be left out. A field with no default is required unless this
    /// says otherwise.
    pub optional: bool,
    /// What the field means, shown in generated docs.
    pub doc: &'static str,
}

impl Field {
    /// Declares a required field, e.g. `Field::new("tag", ty, "which tag")`.
    pub fn new(name: &'static str, ty: TypeRef, doc: &'static str) -> Field {
        Field { name, ty, default: None, optional: false, doc }
    }

    /// Makes the field optional with `default`.
    pub fn with_default(mut self, default: Value) -> Field {
        self.default = Some(default);
        self
    }

    /// Makes the field optional with no value of its own: a run that leaves it out is not an
    /// error, and the step works out what it means. For a field whose absence carries meaning —
    /// a context that defaults to the Dockerfile's own directory, not to a fixed `.`.
    pub fn optional(mut self) -> Field {
        self.optional = true;
        self
    }
}

/// A step's declared contract: what it takes, what it owes. Carries docs, defaults and named
/// types — it is what `Harness::build` and the engine check against.
#[derive(Debug, Clone, PartialEq)]
pub struct StepSchema {
    /// What the step is for, shown in generated docs.
    pub doc: &'static str,
    /// In declaration order.
    pub inputs: Vec<Field>,
    /// In declaration order.
    pub outputs: Vec<Field>,
}

/// Why a step could not run, or failed.
///
/// These messages reach run diagnostics *without* passing through the redactor, so they must
/// never embed a secret value.
#[derive(Debug, Clone, PartialEq)]
pub enum StepError {
    /// No step under this name is registered on the harness.
    UnknownStep(String),
    /// An input was missing, unknown or wrongly typed — the engine checks this before the step
    /// runs.
    InvalidInput { field: String, reason: String },
    /// A declared output was missing or wrongly typed, or an undeclared one was returned — the
    /// engine checks this after the step runs.
    InvalidOutput { field: String, reason: String },
    /// The run was cancelled before the step started.
    Cancelled,
    /// A port the step declared failed underneath it.
    Port { port: Port, message: String },
    /// The step itself failed.
    Failed(String),
}

impl fmt::Display for StepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StepError::UnknownStep(name) => write!(f, "unknown step {name:?}"),
            StepError::InvalidInput { field, reason } => {
                write!(f, "invalid input {field:?}: {reason}")
            }
            StepError::InvalidOutput { field, reason } => {
                write!(f, "invalid output {field:?}: {reason}")
            }
            StepError::Cancelled => f.write_str("the run was cancelled before this step"),
            StepError::Port { port, message } => write!(f, "{port} port failed: {message}"),
            StepError::Failed(message) => write!(f, "step failed: {message}"),
        }
    }
}

impl std::error::Error for StepError {}

/// Cooperative cancellation: a flag steps poll between units of work. Polling only, on purpose
/// — no runtime dependency; a waker-based future is future work.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Creates an un-cancelled token.
    pub fn new() -> CancellationToken {
        CancellationToken(Arc::new(AtomicBool::new(false)))
    }

    /// Cancels: every holder of the token sees it.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether [`cancel`](CancellationToken::cancel) has been called.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// How severe a log record is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Detail for debugging.
    Debug,
    /// Normal progress.
    Info,
    /// Something looks off, but the step carried on.
    Warn,
    /// Something failed.
    Error,
}

/// One structured log line from a step: a message plus `key = value` fields, already redacted.
#[derive(Debug, Clone, PartialEq)]
pub struct LogRecord {
    pub step: String,
    pub level: LogLevel,
    /// The message, already redacted by the run's [`Redactor`].
    pub message: String,
    /// The structured fields, names and values already redacted.
    pub fields: Vec<(String, String)>,
}

/// Where step logs go. The engine wires this to the run log; tests record.
pub trait LogSink: Send + Sync {
    /// Handles one record.
    fn record(&self, record: LogRecord);
}

/// A step's logger: messages, field names and field values all go through the run's
/// [`Redactor`] before the sink sees them, so a registered secret can never reach a log line.
#[derive(Clone)]
pub struct StepLog {
    step: String,
    redactor: Arc<Redactor>,
    sink: Arc<dyn LogSink>,
}

impl StepLog {
    /// A logger for `step`, redacting with `redactor` and writing to `sink`.
    pub fn new(
        step: impl Into<String>,
        redactor: Arc<Redactor>,
        sink: Arc<dyn LogSink>,
    ) -> StepLog {
        StepLog { step: step.into(), redactor, sink }
    }

    /// The name of the step this logger belongs to.
    pub fn step(&self) -> &str {
        &self.step
    }

    /// Redacts and records one log line.
    pub fn log(&self, level: LogLevel, message: &str, fields: &[(&str, &str)]) {
        let record = LogRecord {
            step: self.step.clone(),
            level,
            message: self.redactor.redact(message),
            fields: fields
                .iter()
                .map(|(name, value)| (self.redactor.redact(name), self.redactor.redact(value)))
                .collect(),
        };
        self.sink.record(record);
    }

    /// Logs at [`LogLevel::Info`].
    pub fn info(&self, message: &str, fields: &[(&str, &str)]) {
        self.log(LogLevel::Info, message, fields);
    }
}

impl fmt::Debug for StepLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StepLog").field("step", &self.step).finish()
    }
}

/// What the harness hands a step when it runs: the ports the step declared, the harness clock,
/// the run's cancellation token and its redacting logger.
#[derive(Clone)]
pub struct StepCtx {
    ports: Ports,
    clock: Arc<dyn Clock>,
    cancel: CancellationToken,
    log: StepLog,
}

impl StepCtx {
    /// Assembles a context; the engine does this, steps receive it.
    pub fn new(
        ports: Ports,
        clock: Arc<dyn Clock>,
        cancel: CancellationToken,
        log: StepLog,
    ) -> StepCtx {
        StepCtx { ports, clock, cancel, log }
    }

    /// The ports this step declared. Nothing else is reachable.
    pub fn ports(&self) -> &Ports {
        &self.ports
    }

    /// The harness clock: the only source of time in a step.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The run's cancellation token.
    pub fn cancel(&self) -> &CancellationToken {
        &self.cancel
    }

    /// The step's redacting logger.
    pub fn log(&self) -> &StepLog {
        &self.log
    }
}

impl fmt::Debug for StepCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StepCtx").field("ports", &self.ports.provided()).finish()
    }
}

/// Whether — and by what — a step's work may be skipped when nothing changed
/// ([#43](https://github.com/Keep-Shipping/harness/issues/43)).
///
/// The default everywhere is [`Caching::Never`]: opting in is a step's own statement that its
/// output is a pure function of the inputs the cache key covers. `oci.image` does (a build of
/// the same context is the same bytes); `tofu.plan` and `deploy` do not — the world they read
/// can change between runs, so they never participate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caching {
    /// Never skip this step's work.
    Never,
    /// The work may be skipped when the key matches; these are the extra inputs the key covers
    /// beyond the resolved inputs the engine already hashes.
    Keyed(Vec<CacheInput>),
}

/// One thing a step's cache key covers, on top of the resolved inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheInput {
    /// A file or directory whose contents the engine hashes — e.g. an image build context. The
    /// path itself is not hashed: the same context at two checkouts is the same input.
    File(PathBuf),
    /// A tool and the version that will run — e.g. the tofu binary. The step supplies the
    /// version, so it should take it from its pinned toolchain: a version that does not match
    /// the tool actually used is a wrong hit.
    Tool { name: String, version: String },
    /// Any other named value the step depends on, e.g. the base image ref.
    Value { name: String, value: String },
}

/// Whether a cache entry may still be trusted. The `String` is the human evidence the skip (or
/// the rebuild) rests on, e.g. `"sha256:… present in ghcr.io/acme/api"` — it goes into the run
/// log, so it must never carry a secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheCheck {
    /// The cached outputs are still there and usable: skip the work.
    Valid(String),
    /// They are not: run the step again.
    Stale(String),
}

/// A step kind: the unit a workflow composes. Everything but [`run`](StepKind::run) is
/// declaration, checked for free: the harness refuses a composition whose steps need ports
/// nobody provides, and the engine checks every run's inputs and outputs against
/// [`schema`](StepKind::schema).
pub trait StepKind: Send + Sync + 'static {
    /// The step's stable name, e.g. `oci.image`. Dots namespace families; names are unique per
    /// harness.
    fn name(&self) -> &'static str;

    /// The step's own version, shown in docs and the run log.
    fn version(&self) -> Version;

    /// The [`STEP_API`] this step was built against. Override only when building against a
    /// newer contract; a mismatch is refused at
    /// [`HarnessBuilder::build`](crate::harness::HarnessBuilder::build).
    fn step_api(&self) -> u32 {
        STEP_API
    }

    /// The step's declared input and output contract.
    fn schema(&self) -> StepSchema;

    /// The ports without which the step cannot run.
    fn requires(&self) -> &'static [Port];

    /// The ports the step uses when present but does not need.
    fn optional(&self) -> &'static [Port] {
        &[]
    }

    /// What this run is, for policy. May be computed from the (already prepared) inputs —
    /// `deploy` in `prod` is a different approval than in `dev`.
    fn action(&self, inputs: &Inputs) -> ActionClass;

    /// What the step needs from its environment. Defaults to local-safe.
    fn capabilities(&self) -> StepCapabilities {
        StepCapabilities::default()
    }

    /// Whether this step's work may be skipped when nothing changed
    /// ([#43](https://github.com/Keep-Shipping/harness/issues/43)). Defaults to
    /// [`Caching::Never`]: a step participates only by saying so, and only for a run whose work
    /// is a pure function of what the key covers.
    fn caching(&self, _inputs: &Inputs) -> Caching {
        Caching::Never
    }

    /// Checks cached outputs are still true before the engine skips the work — e.g. that the
    /// image the key stands for is still in the registry. Defaults to [`CacheCheck::Stale`], so
    /// a step that opts into caching but forgets verification never skips.
    fn verify_cached<'a>(
        &'a self,
        _ctx: StepCtx,
        _outputs: &'a Outputs,
    ) -> BoxFuture<'a, Result<CacheCheck, StepError>> {
        Box::pin(std::future::ready(Ok(CacheCheck::Stale(
            "step does not verify cached outputs".to_string(),
        ))))
    }

    /// Runs the step. Inputs arrive prepared against the schema (present, typed, defaults
    /// applied); the engine checks the returned outputs against it afterwards. Error messages
    /// bypass the run's redactor: they must not contain secret values.
    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>>;
}

/// Renders step kinds as deterministic Markdown for `docs/STEPS.md`, sorted by name. Action
/// classes are rendered for empty inputs, so steps that compute the class from inputs show
/// their base kind.
pub fn render_steps_markdown(steps: &[&dyn StepKind]) -> String {
    let mut out = String::from(
        "<!--\n\
         Generated from the built-in step kinds; do not edit by hand.\n\
         Regenerate with: KS_BLESS=1 cargo test -p ks-engine --test steps_doc\n\
         -->\n\n\
         # Built-in steps\n\n\
         Every step kind the harness ships, with its declared schema. Inputs are\n\
         checked against the schema before the step runs; outputs, after.\n\n",
    );
    if steps.is_empty() {
        out.push_str("_No step kinds are built in yet._\n");
        return out;
    }
    let mut sorted: Vec<&dyn StepKind> = steps.to_vec();
    sorted.sort_by_key(|step| step.name());
    for step in sorted {
        let schema = step.schema();
        push_line(&mut out, &format!("\n## `{}` (v{})\n", step.name(), step.version()));
        push_line(&mut out, &md_cell(schema.doc));
        push_line(&mut out, "");
        push_line(&mut out, &format!("- Action: {}", step.action(&Inputs::new())));
        push_line(&mut out, &format!("- Requires: {}", join_ports(step.requires())));
        if !step.optional().is_empty() {
            push_line(&mut out, &format!("- Optional: {}", join_ports(step.optional())));
        }
        out.push_str(
            "\nInputs:\n\n| Name | Type | Default | Description |\n| --- | --- | --- | --- |\n",
        );
        for field in &schema.inputs {
            let default =
                field.default.as_ref().map(render_value).unwrap_or_else(|| "-".to_string());
            let row = format!(
                "| `{}` | {} | {} | {} |",
                md_cell(field.name),
                md_cell(&field.ty.to_string()),
                md_cell(&default),
                md_cell(field.doc),
            );
            push_line(&mut out, &row);
        }
        out.push_str("\nOutputs:\n\n| Name | Type | Description |\n| --- | --- | --- |\n");
        for field in &schema.outputs {
            let row = format!(
                "| `{}` | {} | {} |",
                md_cell(field.name),
                md_cell(&field.ty.to_string()),
                md_cell(field.doc),
            );
            push_line(&mut out, &row);
        }
    }
    out
}

/// Appends `line` plus a newline; writing to a `String` cannot fail.
fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

/// Escapes one Markdown table cell: backslash and pipe are backslash-escaped, newlines become
/// `<br>`, so a value can never break the table it renders into.
fn md_cell(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' | '|' => {
                out.push('\\');
                out.push(character);
            }
            '\n' | '\r' => out.push_str("<br>"),
            other => out.push(other),
        }
    }
    out
}

fn join_ports(ports: &[Port]) -> String {
    if ports.is_empty() {
        return "none".to_string();
    }
    ports.iter().map(|port| port.to_string()).collect::<Vec<_>>().join(", ")
}

/// A compact, deterministic rendering of a default value for the docs tables. Non-finite
/// numbers render as `NaN`/`inf`/`-inf`, which is table-safe.
fn render_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => format!("`{text}`"),
        Value::List(items) => {
            format!("[{}]", items.iter().map(render_value).collect::<Vec<_>>().join(", "))
        }
        Value::Map(entries) => format!(
            "{{{}}}",
            entries
                .iter()
                .map(|(name, value)| format!("{name}: {}", render_value(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Fakes shared by this crate's unit tests.

    use std::time::{Duration, SystemTime};

    use super::*;

    /// A [`Clock`] fixed at the Unix epoch.
    pub(crate) struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }

        fn sleep<'a>(&'a self, _duration: Duration) -> BoxFuture<'a, ()> {
            Box::pin(std::future::ready(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step::test_support::FixedClock;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_step_kind_trait_is_dyn_compatible() {
        assert_send_sync::<dyn StepKind>();
        assert_send_sync::<dyn LogSink>();
    }

    #[test]
    fn displays_are_short_and_predictable() {
        let shown = [
            (Version::new(1, 2, 3).to_string(), "1.2.3"),
            (Port::Registry.to_string(), "Registry"),
            (ActionClass::new(ActionKind::Deploy).in_env("prod").to_string(), "deploy prod"),
            (ActionClass::new(ActionKind::ReadSecrets).to_string(), "read-secrets"),
            (TypeRef::Builtin(ValueType::String).to_string(), "string"),
            (TypeRef::Named("digest").to_string(), "digest"),
            (StepError::UnknownStep("nope.step".into()).to_string(), r#"unknown step "nope.step""#),
            (StepError::Cancelled.to_string(), "the run was cancelled before this step"),
            (
                StepError::Port { port: Port::Registry, message: "down".into() }.to_string(),
                "Registry port failed: down",
            ),
        ];
        for (actual, expected) in shown {
            assert_eq!(actual, expected);
        }
        // Versions order like semver.
        assert!(Version::new(1, 2, 3) < Version::new(1, 3, 0));
        assert!(Version::new(2, 0, 0) > Version::new(1, 99, 99));
    }

    #[test]
    fn ports_report_what_is_provided_and_cut_down_on_request() {
        let ports = Ports::default().with_clock(Arc::new(FixedClock));
        assert_eq!(ports.provided(), BTreeSet::from([Port::Clock]));
        assert!(ports.clock().is_some());
        assert!(ports.registry().is_none());

        let restricted = ports.restricted_to(&[Port::Registry]);
        assert_eq!(restricted.provided(), BTreeSet::new(), "only declared ports survive");
        assert_eq!(
            restricted.restricted_to(&[Port::Registry]).provided(),
            restricted.provided(),
            "cutting down twice changes nothing"
        );
    }

    #[test]
    fn step_capabilities_default_to_local_safe() {
        let capabilities = StepCapabilities::default();
        assert!(!capabilities.ci_only);
        assert!(!capabilities.oidc);
        assert_eq!(capabilities.network, NetworkScope::None);
    }

    #[test]
    fn cancellation_tokens_share_one_flag() {
        let token = CancellationToken::new();
        let copy = token.clone();
        assert!(!token.is_cancelled());
        copy.cancel();
        assert!(token.is_cancelled() && copy.is_cancelled());
    }

    /// A step whose only job is to carry a schema into the renderer.
    struct DocStep(StepSchema);

    impl StepKind for DocStep {
        fn name(&self) -> &'static str {
            "doc.step"
        }

        fn version(&self) -> Version {
            Version::new(1, 0, 0)
        }

        fn schema(&self) -> StepSchema {
            self.0.clone()
        }

        fn requires(&self) -> &'static [Port] {
            &[]
        }

        fn action(&self, _inputs: &Inputs) -> ActionClass {
            ActionClass::new(ActionKind::Other)
        }

        fn run(&self, _ctx: StepCtx, _inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
            Box::pin(std::future::ready(Ok(Outputs::new())))
        }
    }

    #[test]
    fn rendered_markdown_escapes_every_cell() {
        let step = DocStep(StepSchema {
            doc: "tags one image | per run",
            inputs: vec![
                Field::new("tag", TypeRef::Builtin(ValueType::String), "which tag | branch")
                    .with_default(Value::from("a|b")),
                Field::new("ratio", TypeRef::Builtin(ValueType::Number), "share of traffic")
                    .with_default(Value::from(f64::NAN)),
            ],
            outputs: Vec::new(),
        });
        let markdown = render_steps_markdown(&[&step]);
        assert!(markdown.contains("tags one image \\| per run"), "{markdown}");
        assert!(markdown.contains("which tag \\| branch"), "{markdown}");
        assert!(markdown.contains("| `a\\|b` |"), "{markdown}");
        assert!(markdown.contains("| NaN |"), "{markdown}");
    }
}
