//! Fake for the [`IacTool`] port: scripted plans, a state serial that makes
//! stale plans detectable, tamper detection, and a record of every call.
//! Never touches the filesystem.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use ks_core::ports::BoxFuture;
use ks_core::ports::iac::{
    ApplyResult, Backend, IacError, IacKind, IacTool, OutputValue, Outputs, PlanJson,
    ResourceChange, SavedPlan, ToolInfo,
};

/// What the plan file is allowed to digest to, according to this fake: a
/// [`SavedPlan`] whose digest no issued plan carries was swapped after
/// `plan` ([`IacError::PlanTampered`]).
const NO_SUCH_PLAN: &str = "no plan with this digest was issued by this fake";

/// One call a test can observe on the [`FakeIacTool`], oldest first via
/// [`FakeIacTool::calls`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IacCall {
    /// [`IacTool::plan`] ran init and saved a plan.
    Plan,
    /// [`IacTool::show`] parsed the plan with this digest.
    Show {
        /// The digest of the plan shown.
        sha256: String,
    },
    /// [`IacTool::apply`] applied the plan with this digest.
    Apply {
        /// The digest of the plan applied.
        sha256: String,
    },
    /// [`IacTool::outputs`] read the root outputs.
    Outputs,
}

/// The fake's mutable state; every accessor goes through one mutex, so the
/// fake is `Send + Sync` and [`FakeIacTool::drift`] works on `&self`.
#[derive(Default)]
struct State {
    /// Bumped by every apply and by [`FakeIacTool::drift`].
    serial: u64,
    /// How many saved plans `plan` has issued (names their fake paths).
    plans_issued: u64,
    /// Scripted plans; the last entry repeats.
    queue: VecDeque<PlanJson>,
    /// digest -> (the plan, the state serial it was planned against).
    issued: BTreeMap<String, (PlanJson, u64)>,
    /// Every call, oldest first.
    calls: Vec<IacCall>,
}

/// An [`IacTool`] you script per test — the stand-in for real OpenTofu and
/// Terraform adapters ([#69](https://github.com/Keep-Shipping/harness/issues/69)).
///
/// [`with_plan`](FakeIacTool::with_plan) queues the [`PlanJson`] the next
/// `plan` returns (the last one repeats); each issued
/// [`SavedPlan`] gets a fake path and the sha256 of a deterministic
/// serialisation of the plan plus the state serial it was planned against.
/// `apply` records the plan, bumps the serial, and reports the plan's change
/// counts — so:
///
/// - a plan applied after `drift()` or another apply is
///   [`StalePlan`](IacError::StalePlan), mirroring the real tools'
///   "Saved plan is stale";
/// - a `SavedPlan` whose digest the fake never issued is
///   [`PlanTampered`](IacError::PlanTampered).
///
/// ```
/// use std::collections::BTreeMap;
/// use std::path::Path;
/// use ks_core::ports::iac::{Backend, ChangeAction, IacTool, ResourceChange};
/// use ks_testing::{block_on, iac::FakeIacTool};
///
/// let tool = FakeIacTool::new().with_plan(vec![ResourceChange {
///     address: "aws_subnet.app".to_string(),
///     actions: vec![ChangeAction::Create],
/// }]);
/// let dir = Path::new("/ws/infra");
/// let backend = Backend::new("local");
/// let plan = block_on(tool.plan(dir, &BTreeMap::new(), &backend))
///     .expect("the plan is scripted");
/// assert_eq!(block_on(tool.show(&plan)).expect("the plan parses").creates(), 1);
/// ```
///
/// All mutable state sits behind one mutex, so the fake is `Send + Sync`
/// and `drift` works on `&self`.
pub struct FakeIacTool {
    tool_info: ToolInfo,
    outputs: Outputs,
    state: Mutex<State>,
}

impl Default for FakeIacTool {
    /// The default fake reports OpenTofu `0.0.0-fake`, plans an empty change
    /// set, and exposes no outputs.
    fn default() -> FakeIacTool {
        FakeIacTool {
            tool_info: ToolInfo { kind: IacKind::OpenTofu, version: "0.0.0-fake".to_string() },
            outputs: Outputs::new(),
            state: Mutex::new(State::default()),
        }
    }
}

impl FakeIacTool {
    /// Creates a fake that reports OpenTofu `0.0.0-fake`, plans an empty
    /// change set, and exposes no outputs — until scripted.
    pub fn new() -> FakeIacTool {
        FakeIacTool::default()
    }

    /// Queues a plan with `changes` as the next [`PlanJson`] `plan` returns;
    /// the last queued plan repeats, so any number of plans succeed.
    pub fn with_plan(self, changes: Vec<ResourceChange>) -> FakeIacTool {
        self.state.lock().expect("fake iac state").queue.push_back(PlanJson { changes });
        self
    }

    /// Exposes one root output.
    pub fn with_output(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        sensitive: bool,
    ) -> FakeIacTool {
        self.outputs.insert(name.into(), OutputValue { value: value.into(), sensitive });
        self
    }

    /// Replaces what [`IacTool::tool`] reports.
    pub fn with_tool(mut self, kind: IacKind, version: impl Into<String>) -> FakeIacTool {
        self.tool_info = ToolInfo { kind, version: version.into() };
        self
    }

    /// Simulates an out-of-band state change — someone applied elsewhere, a
    /// console edit, another pipeline. Every plan issued before this call is
    /// [`StalePlan`](IacError::StalePlan) from now on.
    pub fn drift(&self) {
        self.state.lock().expect("fake iac state").serial += 1;
    }

    /// Every call made against the fake, oldest first.
    pub fn calls(&self) -> Vec<IacCall> {
        self.state.lock().expect("fake iac state").calls.clone()
    }
}

impl fmt::Debug for FakeIacTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().expect("fake iac state");
        f.debug_struct("FakeIacTool")
            .field("tool_info", &self.tool_info)
            .field("outputs", &self.outputs.len())
            .field("scripted", &state.queue.len())
            .field("issued", &state.issued.len())
            .field("serial", &state.serial)
            .field("calls", &state.calls.len())
            .finish()
    }
}

/// The fake's plan digest: sha256 over a canonical serialisation of the plan
/// plus the state serial it was planned against, so every issued plan has
/// its own digest and staleness is detectable from the digest alone.
fn digest_of(plan: &PlanJson, serial: u64) -> String {
    let mut canonical: Vec<String> = plan
        .changes
        .iter()
        .map(|change| {
            let actions =
                change.actions.iter().map(|action| action.as_str()).collect::<Vec<_>>().join("+");
            format!("{}={}", change.address, actions)
        })
        .collect();
    canonical.sort();
    let text = format!("serial={serial};plan={}", canonical.join(";"));
    Sha256::digest(text.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

impl IacTool for FakeIacTool {
    fn plan<'a>(
        &'a self,
        dir: &'a Path,
        vars: &'a BTreeMap<String, String>,
        backend: &'a Backend,
    ) -> BoxFuture<'a, Result<SavedPlan, IacError>> {
        // The fake has no working tree, backend or vars to honour.
        let _ = (dir, vars, backend);
        let mut state = self.state.lock().expect("fake iac state");
        let plan_json = match state.queue.len() {
            0 => PlanJson::default(),
            1 => state.queue.front().expect("queue is non-empty").clone(),
            _ => state.queue.pop_front().expect("queue is non-empty"),
        };
        state.plans_issued += 1;
        let serial = state.serial;
        let path =
            PathBuf::from(format!("/ks-testing/fake-iac/plan-{}.tfplan", state.plans_issued));
        let digest = digest_of(&plan_json, serial);
        state.issued.insert(digest.clone(), (plan_json, serial));
        state.calls.push(IacCall::Plan);
        let saved = SavedPlan::new(path, digest).expect("fake digests are well formed");
        Box::pin(std::future::ready(Ok(saved)))
    }

    fn show<'a>(&'a self, plan: &'a SavedPlan) -> BoxFuture<'a, Result<PlanJson, IacError>> {
        let result = {
            let mut state = self.state.lock().expect("fake iac state");
            state.calls.push(IacCall::Show { sha256: plan.sha256().to_string() });
            match state.issued.get(plan.sha256()) {
                Some((plan_json, _serial)) => Ok(plan_json.clone()),
                None => Err(IacError::PlanTampered {
                    expected: plan.sha256().to_string(),
                    actual: NO_SUCH_PLAN.to_string(),
                }),
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn apply<'a>(&'a self, plan: &'a SavedPlan) -> BoxFuture<'a, Result<ApplyResult, IacError>> {
        let result = {
            let mut state = self.state.lock().expect("fake iac state");
            state.calls.push(IacCall::Apply { sha256: plan.sha256().to_string() });
            match state.issued.get(plan.sha256()).cloned() {
                None => Err(IacError::PlanTampered {
                    expected: plan.sha256().to_string(),
                    actual: NO_SUCH_PLAN.to_string(),
                }),
                Some((plan_json, planned_at)) if planned_at == state.serial => {
                    // The plan is current: apply it, and the state moves on.
                    state.serial += 1;
                    Ok(ApplyResult {
                        added: plan_json.creates(),
                        changed: plan_json.updates(),
                        destroyed: plan_json.destroys(),
                    })
                }
                Some((_plan_json, _planned_at)) => Err(IacError::StalePlan),
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn outputs<'a>(&'a self, dir: &'a Path) -> BoxFuture<'a, Result<Outputs, IacError>> {
        let _ = dir;
        let result = {
            let mut state = self.state.lock().expect("fake iac state");
            state.calls.push(IacCall::Outputs);
            Ok(self.outputs.clone())
        };
        Box::pin(std::future::ready(result))
    }

    fn tool(&self) -> ToolInfo {
        self.tool_info.clone()
    }
}

/// The `IacTool` conformance kit: every adapter — the fake here, real
/// OpenTofu and Terraform in the adapter job
/// ([#69](https://github.com/Keep-Shipping/harness/issues/69)) — must pass
/// this.
///
/// `dir` must contain a configuration the tool accepts, and `plan` runs
/// against a `local` backend with no vars. The kit walks the port's whole
/// contract: `plan` saves a digest-bearing plan, `show` parses it, `apply`
/// succeeds, outputs are available — and then the two invariants the port
/// exists to enforce: applying the *same* `SavedPlan` a second time is
/// [`StalePlan`](IacError::StalePlan) (true of the real tools too: the saved
/// plan predates the new state), and applying a tampered plan — same path,
/// different sha256 — is [`PlanTampered`](IacError::PlanTampered).
pub async fn conformance(tool: &dyn IacTool, dir: &Path) {
    let info = tool.tool();
    assert!(!info.version.is_empty(), "conformance: IacTool::tool must report a version");
    assert!(
        matches!(info.kind, IacKind::OpenTofu | IacKind::Terraform),
        "conformance: unknown tool kind"
    );

    let backend = Backend::new("local");
    let plan = tool
        .plan(dir, &BTreeMap::new(), &backend)
        .await
        .unwrap_or_else(|error| panic!("conformance: plan failed: {error}"));
    let shown = tool
        .show(&plan)
        .await
        .unwrap_or_else(|error| panic!("conformance: show must parse the saved plan: {error}"));
    let _ = shown.is_empty(); // parsed well enough to ask

    tool.apply(&plan)
        .await
        .unwrap_or_else(|error| panic!("conformance: the fresh plan must apply: {error}"));
    tool.outputs(dir).await.unwrap_or_else(|error| {
        panic!("conformance: outputs must be available after apply: {error}")
    });

    let second = tool.apply(&plan).await;
    assert!(
        matches!(&second, Err(IacError::StalePlan)),
        "conformance: applying the same SavedPlan twice must be StalePlan, got {second:?}"
    );

    let tampered = SavedPlan::new(plan.path().to_path_buf(), "0".repeat(64))
        .expect("conformance: the tampering digest is well formed");
    let applied = tool.apply(&tampered).await;
    assert!(
        matches!(&applied, Err(IacError::PlanTampered { expected, .. }) if expected == tampered.sha256()),
        "conformance: a swapped plan file must be PlanTampered, got {applied:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;
    use ks_core::ports::iac::ChangeAction;

    fn one_create() -> Vec<ResourceChange> {
        vec![ResourceChange {
            address: "aws_subnet.app".to_string(),
            actions: vec![ChangeAction::Create],
        }]
    }

    #[test]
    fn an_unscripted_fake_plans_an_empty_change_set() {
        let tool = FakeIacTool::new();
        let backend = Backend::new("local");
        let plan = block_on(tool.plan(Path::new("/ws/infra"), &BTreeMap::new(), &backend)).unwrap();
        let shown = block_on(tool.show(&plan)).unwrap();
        assert!(shown.is_empty());
        assert_eq!(tool.tool().kind, IacKind::OpenTofu);
    }

    #[test]
    fn the_fake_passes_conformance() {
        let tool = FakeIacTool::new().with_plan(one_create());
        block_on(conformance(&tool, Path::new("/ws/conformance")));
    }
}
