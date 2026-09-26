//! The [`IacTool`] port: planning and applying infrastructure as code with
//! OpenTofu or Terraform
//! ([#51](https://github.com/Keep-Shipping/harness/issues/51)).
//!
//! The contract is built around one rule: *you cannot apply what you have not
//! planned*. [`IacTool::plan`] initialises the directory against a
//! [`Backend`] and writes a saved plan to disk, returning it as a
//! [`SavedPlan`] — the plan file's path plus the sha256 it had as written.
//! [`IacTool::apply`] takes *only* a `SavedPlan` (so "apply without a plan"
//! does not type-check), must apply exactly that file, and must re-hash it
//! first: a file that no longer digests to [`SavedPlan::sha256`] is
//! [`IacError::PlanTampered`], and a plan written before the state last
//! changed is [`IacError::StalePlan`] — apply stops and the caller is asked
//! to plan again ([#67](https://github.com/Keep-Shipping/harness/issues/67)).
//!
//! `ks-core` has no serde, so the JSON never crosses the port:
//! [`IacTool::show`] parses `tofu show -json` into the typed [`PlanJson`],
//! and [`OutputValue`]s carry raw JSON text. The conformance kit for adapters
//! (real OpenTofu and Terraform,
//! [#69](https://github.com/Keep-Shipping/harness/issues/69)) lives in
//! `ks-testing`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use super::BoxFuture;

/// Which infrastructure-as-code tool an [`IacTool`] adapter drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IacKind {
    /// OpenTofu, the fork this harness prefers.
    OpenTofu,
    /// HashiCorp Terraform.
    Terraform,
}

impl IacKind {
    /// The tool's lowercase name, as it appears in logs and run output.
    pub fn as_str(&self) -> &'static str {
        match self {
            IacKind::OpenTofu => "opentofu",
            IacKind::Terraform => "terraform",
        }
    }
}

/// What [`IacTool::tool`] reports about the adapter's tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInfo {
    /// Which tool the adapter drives.
    pub kind: IacKind,
    /// The tool's version string, e.g. `1.9.0`.
    pub version: String,
}

/// Where the tool's state lives, e.g. an S3 bucket or a local directory.
///
/// The adapter translates `kind` and `config` into the tool's backend block;
/// the port stays tool-agnostic. `config` iterates sorted, so generated
/// backend configuration is reproducible.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Backend {
    /// The backend kind, e.g. `s3`, `azurerm`, `local`.
    pub kind: String,
    /// Backend configuration values, e.g. bucket and key names.
    pub config: BTreeMap<String, String>,
}

impl Backend {
    /// A backend of `kind` with no configuration; add entries through the
    /// public `config` map.
    pub fn new(kind: impl Into<String>) -> Backend {
        Backend { kind: kind.into(), config: BTreeMap::new() }
    }
}

/// A saved plan file: where it is, and the digest it must still hash to.
///
/// Constructed by the adapter in [`IacTool::plan`] and the *only* argument
/// [`IacTool::apply`] accepts. Apply must use exactly
/// [`path`](SavedPlan::path) — never a re-planned or differently-named file —
/// after re-hashing it against [`sha256`](SavedPlan::sha256).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedPlan {
    path: PathBuf,
    sha256: String,
}

impl SavedPlan {
    /// Records a plan saved at `path` whose file hashed to `sha256` when the
    /// adapter wrote it. Fails with [`IacError::InvalidDigest`] unless
    /// `sha256` is 64 lowercase hex digits — a malformed digest would
    /// silently disable tamper detection.
    pub fn new(path: impl Into<PathBuf>, sha256: impl Into<String>) -> Result<SavedPlan, IacError> {
        let sha256 = sha256.into();
        let is_digest = sha256.len() == 64
            && sha256.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
        if !is_digest {
            return Err(IacError::InvalidDigest { value: sha256 });
        }
        Ok(SavedPlan { path: path.into(), sha256 })
    }

    /// The plan file to apply, exactly.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The sha256 the file must still hash to (64 lowercase hex digits).
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// One action a plan takes on a resource, from `tofu show -json`.
///
/// A replace is *two* actions on one resource (`delete` then `create`), which
/// is why a [`ResourceChange`] carries a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeAction {
    /// The resource is untouched.
    NoOp,
    /// The resource is created.
    Create,
    /// The resource is read (data sources).
    Read,
    /// The resource is updated in place.
    Update,
    /// The resource is destroyed.
    Delete,
}

impl ChangeAction {
    /// The action's name in `tofu show -json`, e.g. `"no-op"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeAction::NoOp => "no-op",
            ChangeAction::Create => "create",
            ChangeAction::Read => "read",
            ChangeAction::Update => "update",
            ChangeAction::Delete => "delete",
        }
    }
}

/// One resource's planned change, keyed by its full address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceChange {
    /// The resource address, e.g. `module.net.aws_subnet.app`.
    pub address: String,
    /// The planned actions, in the tool's order (a replace is two).
    pub actions: Vec<ChangeAction>,
}

/// The parsed plan ([`IacTool::show`]): what would change, and nothing else.
///
/// The adapter fills this from `tofu show -json`; the shape is typed so the
/// checker and the engine can reason about blast radius without a JSON
/// dependency.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlanJson {
    /// One entry per resource the plan touches.
    pub changes: Vec<ResourceChange>,
}

impl PlanJson {
    /// Whether the plan changes nothing (a pure refresh).
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// How many resources the plan creates.
    pub fn creates(&self) -> usize {
        self.count(ChangeAction::Create)
    }

    /// How many resources the plan updates in place.
    pub fn updates(&self) -> usize {
        self.count(ChangeAction::Update)
    }

    /// How many resources the plan destroys.
    pub fn destroys(&self) -> usize {
        self.count(ChangeAction::Delete)
    }

    fn count(&self, action: ChangeAction) -> usize {
        self.changes.iter().filter(|change| change.actions.contains(&action)).count()
    }
}

/// One root-module output: its raw JSON text, and whether it is sensitive.
///
/// Sensitivity is a flag rather than a
/// [`SecretValue`](crate::ports::secrets::SecretValue) on purpose: outputs
/// must keep flowing to dependent steps as plain data, and `SecretValue` is
/// deliberately un-`Clone`. Instead the engine registers every `sensitive`
/// value with the run's [`Redactor`](crate::ports::secrets::Redactor) when it
/// collects outputs, so the value still cannot survive into logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputValue {
    /// The output's value as raw JSON text (a string output is quoted, a list
    /// is `[...]`); the consumer owns decoding.
    pub value: String,
    /// Whether the tool marks the output sensitive.
    pub sensitive: bool,
}

/// The root module's outputs, keyed by output name (iterates sorted).
pub type Outputs = BTreeMap<String, OutputValue>;

/// What an apply did, as the tool's change summary reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApplyResult {
    /// Resources created.
    pub added: usize,
    /// Resources updated in place.
    pub changed: usize,
    /// Resources destroyed.
    pub destroyed: usize,
}

/// Why an [`IacTool`] operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IacError {
    /// The saved plan no longer matches the state: it was written before the
    /// last apply, or another writer moved the state. Its own variant so the
    /// engine must stop and ask for a fresh plan — never apply through it
    /// ([#67](https://github.com/Keep-Shipping/harness/issues/67)).
    StalePlan,
    /// The plan file's digest no longer matches the [`SavedPlan`] — the file
    /// changed (or was swapped) after `plan` wrote it. Never apply; plan again.
    PlanTampered {
        /// The digest the plan was saved with.
        expected: String,
        /// The digest of the file as found.
        actual: String,
    },
    /// The tool ran and failed (configuration error, bad backend, …).
    /// `message` is the tool's own output, safe to print; adapters must let
    /// the run's redactor scrub it first, tool output can echo secrets.
    Tool {
        /// What the tool reported.
        message: String,
        /// The tool's exit code, if it exited at all.
        exit_code: Option<i32>,
    },
    /// A [`SavedPlan`] was constructed with something that is not a sha256
    /// hex digest; see [`SavedPlan::new`].
    InvalidDigest {
        /// The rejected value.
        value: String,
    },
}

impl fmt::Display for IacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IacError::StalePlan => {
                write!(f, "saved plan is stale: the state changed after it was written; plan again")
            }
            IacError::PlanTampered { expected, actual } => {
                write!(
                    f,
                    "plan file no longer matches its digest: expected sha256 {expected}, found {actual}"
                )
            }
            IacError::Tool { message, exit_code } => {
                write!(f, "iac tool failed")?;
                if let Some(code) = exit_code {
                    write!(f, " (exit code {code})")?;
                }
                write!(f, ": {message}")
            }
            IacError::InvalidDigest { value } => {
                write!(f, "{value:?} is not a sha256 digest (want 64 lowercase hex digits)")
            }
        }
    }
}

impl std::error::Error for IacError {}

/// The `IacTool` port: an adapter drives OpenTofu or Terraform as a
/// subprocess and answers in the port's typed shapes. Steps and the engine
/// never shell out themselves, so policy — which directories, which backends
/// — is enforced in one place.
///
/// Adapters must fail with [`IacError`] rather than panicking, and must be
/// deterministic per state: the same directory, vars and backend plan to the
/// same digest unless the state or configuration moved.
pub trait IacTool: Send + Sync {
    /// Initialises `dir` against `backend` — the `init` step; there is no
    /// separate port method, because a plan made against the wrong backend is
    /// not a plan worth saving — then plans `dir` with `vars` and saves the
    /// plan to disk. `vars` are passed in sorted key order so plans are
    /// reproducible. The returned [`SavedPlan`] must digest the file as
    /// written.
    fn plan<'a>(
        &'a self,
        dir: &'a Path,
        vars: &'a BTreeMap<String, String>,
        backend: &'a Backend,
    ) -> BoxFuture<'a, Result<SavedPlan, IacError>>;

    /// Parses the saved plan into a [`PlanJson`] (`show -json`), touching
    /// neither the state nor any resource.
    fn show<'a>(&'a self, plan: &'a SavedPlan) -> BoxFuture<'a, Result<PlanJson, IacError>>;

    /// Applies exactly `plan`'s file — after re-hashing it
    /// ([`PlanTampered`](IacError::PlanTampered)) and checking the state has
    /// not moved since the plan was written
    /// ([`StalePlan`](IacError::StalePlan)). Never re-plans implicitly; on
    /// `StalePlan` the caller plans again.
    fn apply<'a>(&'a self, plan: &'a SavedPlan) -> BoxFuture<'a, Result<ApplyResult, IacError>>;

    /// The root module's outputs for the state in `dir`.
    fn outputs<'a>(&'a self, dir: &'a Path) -> BoxFuture<'a, Result<Outputs, IacError>>;

    /// Which tool the adapter drives, and its version.
    fn tool(&self) -> ToolInfo;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_iac_tool_trait_is_dyn_compatible() {
        assert_send_sync::<dyn IacTool>();
    }

    #[test]
    fn saved_plans_reject_malformed_digests() {
        let plan = SavedPlan::new("/ws/plan.tfplan", "a".repeat(64)).expect("64 hex digits");
        assert_eq!(plan.path(), Path::new("/ws/plan.tfplan"));
        assert_eq!(plan.sha256(), "a".repeat(64));
        for bad in ["", "abc", &"A".repeat(64)[..], &"g".repeat(64)[..]] {
            assert!(
                matches!(
                    SavedPlan::new("/ws/plan.tfplan", bad),
                    Err(IacError::InvalidDigest { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn plan_json_counts_changes_by_action() {
        let plan = PlanJson {
            changes: vec![
                ResourceChange {
                    address: "aws_subnet.app".to_string(),
                    actions: vec![ChangeAction::Create],
                },
                ResourceChange {
                    address: "aws_instance.web".to_string(),
                    // A replace is a destroy and a create of one resource.
                    actions: vec![ChangeAction::Delete, ChangeAction::Create],
                },
                ResourceChange {
                    address: "data.aws_ami.base".to_string(),
                    actions: vec![ChangeAction::NoOp],
                },
            ],
        };
        assert!(!plan.is_empty());
        assert_eq!((plan.creates(), plan.updates(), plan.destroys()), (2, 0, 1));
        assert!(PlanJson::default().is_empty());
    }

    #[test]
    fn iac_errors_display_actionably() {
        let stale = IacError::StalePlan.to_string();
        assert!(stale.contains("stale") && stale.contains("plan again"), "{stale}");
        let tampered =
            IacError::PlanTampered { expected: "a".repeat(64), actual: "b".repeat(64) }.to_string();
        assert!(tampered.contains("digest") && tampered.contains('b'), "{tampered}");
        let tool =
            IacError::Tool { message: "backend down".to_string(), exit_code: Some(2) }.to_string();
        assert!(tool.contains("2") && tool.contains("backend down"), "{tool}");
        let tool = IacError::Tool { message: "killed".to_string(), exit_code: None }.to_string();
        assert!(tool.contains("killed"), "{tool}");
    }
}
