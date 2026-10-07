//! The `tofu.plan` step kind: what a change would do, before anything does it
//! ([#65](https://github.com/Keep-Shipping/harness/issues/65)).
//!
//! The step plans a directory, reads the plan back, and owes the run three
//! things: the plan file with the digest [`IacTool::apply`](ks_core::ports::iac::IacTool::apply)
//! must later match, the counts a reviewer reads (`+2 ~1 -0`), and a summary in
//! plain terms. It changes nothing, so it needs no approval of its own; what
//! needs one is the apply downstream.
//!
//! Two things deliberately never leave the step: the plan file's contents and
//! the `show -json` document. The log line carries the digest and the counts, so
//! a run's log can say what a plan would do without becoming a copy of the plan.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use ks_core::plan_summary::{Limits, PlanChange, Target, summarize};
use ks_core::ports::BoxFuture;
use ks_core::ports::iac::{Backend, ChangeAction, PlanJson, ResourceChange};
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::step::{
    ActionClass, ActionKind, Field, Inputs, Outputs, Port, StepCtx, StepError, StepKind,
    StepSchema, TypeRef, Version,
};

/// Plans a directory with the [`IacTool`](ks_core::ports::iac::IacTool) port,
/// and counts what it would do.
#[derive(Debug, Default)]
pub struct TofuPlan;

impl StepKind for TofuPlan {
    fn name(&self) -> &'static str {
        "tofu.plan"
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        let map = TypeRef::Builtin(ValueType::Map);
        let text = TypeRef::Builtin(ValueType::String);
        let flag = TypeRef::Builtin(ValueType::Bool);
        let int = TypeRef::Named("int");
        StepSchema {
            doc: "Plans an infrastructure directory, and reports what it would change.",
            inputs: vec![
                Field::new("dir", TypeRef::Named("path"), "the directory to plan"),
                Field::new("backend", text, "the backend kind").with_default(Value::from("local")),
                Field::new("backend_config", map, "backend settings for `tofu init`")
                    .with_default(Value::Map(BTreeMap::new())),
                Field::new("vars", map, "the input variables the plan is made with")
                    .with_default(Value::Map(BTreeMap::new())),
            ],
            outputs: vec![
                Field::new("file", map, "the saved plan as `{ path, sha256 }`"),
                Field::new("changes", map, "the plan's resources, and the three counts"),
                Field::new("adds", int, "how many it creates, replacements included"),
                Field::new("changes_count", int, "how many it updates in place"),
                Field::new("destroys", int, "how many it destroys, replacements included"),
                Field::new("empty", flag, "whether it changes nothing"),
                Field::new("summary", text, "the plan in plain terms"),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::IacTool]
    }

    /// Planning touches no resource, so it is not an apply: what needs an
    /// approval is whatever consumes the plan.
    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Plan)
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let Some(iac) = ctx.ports().iac_tool() else {
                return Err(StepError::Port {
                    port: Port::IacTool,
                    message: "no iac tool was provided".to_string(),
                });
            };
            let dir = text(&inputs, "dir");
            let mut backend = Backend::new(text(&inputs, "backend"));
            backend.config = strings(&inputs, "backend_config")?;
            let saved = iac
                .plan(Path::new(dir), &strings(&inputs, "vars")?, &backend)
                .await
                .map_err(|error| StepError::Port {
                    port: Port::IacTool,
                    message: format!("planning {dir} failed: {error}"),
                })?;
            // The plan is the long unit of work; a run cancelled while it was
            // made stops here rather than reading a plan nobody will apply.
            if ctx.cancel().is_cancelled() {
                return Err(StepError::Cancelled);
            }
            let shown = iac.show(&saved).await.map_err(|error| StepError::Port {
                port: Port::IacTool,
                message: format!("reading the plan back failed: {error}"),
            })?;

            let (adds, updates, destroys) = (shown.creates(), shown.updates(), shown.destroys());
            ctx.log().info(
                &format!("plan +{adds} ~{updates} -{destroys}"),
                &[("sha256", saved.sha256())],
            );

            let summary =
                summarize(&shown.changes.iter().map(PlanChange::from).collect::<Vec<_>>())
                    .render(Target::Plain, &Limits::default());
            let file = BTreeMap::from([
                ("path".to_string(), Value::from(saved.path().display().to_string())),
                ("sha256".to_string(), Value::from(saved.sha256())),
            ]);
            let mut outputs = Outputs::new();
            outputs.insert("file".to_string(), Value::Map(file));
            outputs.insert("changes".to_string(), changes_value(&shown, adds, updates, destroys));
            outputs.insert("adds".to_string(), Value::from(adds as f64));
            outputs.insert("changes_count".to_string(), Value::from(updates as f64));
            outputs.insert("destroys".to_string(), Value::from(destroys as f64));
            outputs.insert("empty".to_string(), Value::from(adds + updates + destroys == 0));
            outputs.insert("summary".to_string(), Value::from(summary));
            Ok(outputs)
        })
    }
}

/// The first `&str` input under `name`; inputs arrive prepared, so a wrong type
/// never reaches a step.
fn text<'a>(inputs: &'a Inputs, name: &str) -> &'a str {
    match inputs.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

/// The `name: value` string map under `name`. Anything that is not a string is
/// a bad input, not a value to coerce: a plan made with a silently stringified
/// number is a plan nobody reviewed.
fn strings(inputs: &Inputs, name: &'static str) -> Result<BTreeMap<String, String>, StepError> {
    let Some(Value::Map(entries)) = inputs.get(name) else {
        return Ok(BTreeMap::new());
    };
    entries
        .iter()
        .map(|(key, value)| match value {
            Value::String(text) => Ok((key.clone(), text.clone())),
            other => Err(StepError::InvalidInput {
                field: name.to_string(),
                reason: format!("`{key}` is a {}, not a string", other.value_type()),
            }),
        })
        .collect()
}

/// The `changes` output: every resource the plan touches but the no-ops, with
/// its action, type and module, plus the three counts.
fn changes_value(plan: &PlanJson, adds: usize, updates: usize, destroys: usize) -> Value {
    let resources = plan
        .changes
        .iter()
        .filter_map(|change| {
            let action = action_of(&change.actions)?;
            let (module, kind) = address_parts(&change.address);
            Some(Value::Map(BTreeMap::from([
                ("address".to_string(), Value::from(change.address.clone())),
                ("action".to_string(), Value::from(action)),
                ("type".to_string(), Value::from(kind)),
                ("module".to_string(), Value::from(module)),
            ])))
        })
        .collect();
    Value::Map(BTreeMap::from([
        ("resources".to_string(), Value::List(resources)),
        ("adds".to_string(), Value::from(adds as f64)),
        ("changes".to_string(), Value::from(updates as f64)),
        ("destroys".to_string(), Value::from(destroys as f64)),
    ]))
}

/// The one word a change is reported under, or `None` when it changes nothing:
/// a no-op resource is not part of the plan a reviewer reads.
fn action_of(actions: &[ChangeAction]) -> Option<&'static str> {
    let has = |action| actions.contains(&action);
    match (has(ChangeAction::Delete), has(ChangeAction::Create)) {
        // A replace is two actions on one resource, and reads as one word.
        (true, true) => Some("replace"),
        (_, true) => Some("create"),
        _ if has(ChangeAction::Update) => Some("update"),
        (true, false) => Some("delete"),
        // A data source read is a real change to the plan, but not to a
        // resource: it is neither added nor destroyed.
        _ if has(ChangeAction::Read) => Some("read"),
        _ => None,
    }
}

/// An address's module path and resource type, as tofu spells them:
/// `module.a.module.b["x"].aws_subnet.c` is type `aws_subnet` in module
/// `module.a.module.b["x"]`, `data.aws_vpc.main` is type `aws_vpc` in the root,
/// and an index key's dots are part of the key, not separators.
#[must_use]
pub fn address_parts(address: &str) -> (String, String) {
    let parts = split_address(address);
    let mut index = 0;
    let mut module = String::new();
    while parts.get(index) == Some(&"module") {
        let Some(name) = parts.get(index + 1) else { break };
        if !module.is_empty() {
            module.push('.');
        }
        module.push_str("module.");
        module.push_str(name);
        index += 2;
    }
    if parts.get(index) == Some(&"data") {
        index += 1;
    }
    (module, parts.get(index).map_or_else(String::new, |kind| (*kind).to_string()))
}

/// Splits an address on the dots between its parts, leaving the dots inside an
/// index key (`a["eu.west-1a"]`) with the key they belong to.
fn split_address(address: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (at, character) in address.char_indices() {
        match character {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            '.' if depth == 0 => {
                parts.push(&address[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    parts.push(&address[start..]);
    parts
}

/// Parses `tofu show -json <planfile>` into the port's [`PlanJson`].
///
/// This is the parser an [`IacTool`](ks_core::ports::iac::IacTool) adapter runs
/// its `show` through — the port says the adapter parses, so the engine carries
/// one implementation. Only `resource_changes` is read: a plan document is
/// large, and the engine wants addresses and actions, nothing else. A document
/// with no `resource_changes` is an empty plan; anything else it cannot read is
/// an error, never an empty plan.
pub fn parse_show_json(json: &str) -> Result<PlanJson, ShowError> {
    let document: serde_json::Value =
        serde_json::from_str(json).map_err(|error| ShowError::Malformed(error.to_string()))?;
    let Some(entries) = document.get("resource_changes") else {
        return Ok(PlanJson::default());
    };
    let entries = entries
        .as_array()
        .ok_or_else(|| ShowError::Malformed("`resource_changes` is not a list".to_string()))?;
    let mut changes = Vec::with_capacity(entries.len());
    for entry in entries {
        let address = entry
            .get("address")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ShowError::Malformed("a resource change has no address".to_string()))?;
        let mut actions = Vec::new();
        // A resource change with no `actions` at all is one the tool wrote no
        // action for; it stays in the plan and reads as a change of nothing.
        if let Some(list) = entry.get("change").and_then(|change| change.get("actions")) {
            let list = list
                .as_array()
                .ok_or_else(|| ShowError::Malformed("`actions` is not a list".to_string()))?;
            for action in list {
                let name = action
                    .as_str()
                    .ok_or_else(|| ShowError::Malformed("an action is not a string".into()))?;
                actions.push(parse_action(name)?);
            }
        }
        changes.push(ResourceChange { address: address.to_string(), actions });
    }
    Ok(PlanJson { changes })
}

/// One action name from `tofu show -json`, or the error for a name this parser
/// does not know — an unrecognised action would otherwise read as "no change".
fn parse_action(name: &str) -> Result<ChangeAction, ShowError> {
    match name {
        "no-op" => Ok(ChangeAction::NoOp),
        "create" => Ok(ChangeAction::Create),
        "read" => Ok(ChangeAction::Read),
        "update" => Ok(ChangeAction::Update),
        "delete" => Ok(ChangeAction::Delete),
        other => Err(ShowError::UnknownAction { action: other.to_string() }),
    }
}

/// Why a `tofu show -json` document could not be read as a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShowError {
    /// The document is not JSON, or is not shaped like a plan.
    Malformed(String),
    /// An action name the parser does not know, quoted from the document.
    UnknownAction {
        /// The action name as the tool wrote it.
        action: String,
    },
}

impl fmt::Display for ShowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShowError::Malformed(reason) => {
                write!(f, "the plan document is not readable: {reason}")
            }
            ShowError::UnknownAction { action: a } => {
                write!(f, "{a:?} is not an action this parser knows")
            }
        }
    }
}

impl std::error::Error for ShowError {}
