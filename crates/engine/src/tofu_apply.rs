//! The `tofu.apply` step kind: applies exactly the plan a human approved, or
//! nothing at all ([#66](https://github.com/Keep-Shipping/harness/issues/66)).
//!
//! The step's only input is a [`SavedPlan`], which carries the digest the
//! approval was bound to, and applying it is the
//! [`IacTool`](ks_core::ports::iac::IacTool) port's job: the port re-hashes the
//! file before it applies anything and refuses with [`IacError::PlanTampered`]
//! when the bytes no longer match ([#51](https://github.com/Keep-Shipping/harness/issues/51)).
//! So a plan edited between the approval and this step cannot reach the world —
//! the refusal is the point, and it happens before anything is created.
//!
//! `ActionKind::Apply` is what policy reads to demand an approval, and what the
//! run loop reads to refuse a retry: re-running one can leave infrastructure
//! half-changed.

use std::collections::BTreeMap;
use std::path::Path;

use ks_core::ports::BoxFuture;
use ks_core::ports::iac::{ApplyResult, IacError, OutputValue, Outputs as IacOutputs, SavedPlan};
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::step::{
    ActionClass, ActionKind, Field, Inputs, Outputs, Port, StepCtx, StepError, StepKind,
    StepSchema, TypeRef, Version,
};

/// The `tofu.PlanFile` `tofu.plan` emits as `file`: the [`SavedPlan`] to apply
/// and the module directory whose outputs the run reads afterwards.
///
/// A missing, wrongly typed or unparseable member is refused as an invalid
/// `plan` — the step will not guess which file a run meant to apply.
struct PlanFile {
    saved: SavedPlan,
    dir: String,
}

/// Parses the `plan` input into the plan to apply. The digest is checked here
/// as well as by the port: a malformed one would otherwise reach the tool and
/// disable the tamper check the port performs on every apply.
fn parse_plan(inputs: &Inputs) -> Result<PlanFile, StepError> {
    let invalid = |reason: String| StepError::InvalidInput { field: "plan".to_string(), reason };
    let Some(Value::Map(map)) = inputs.get("plan") else {
        return Err(invalid(
            "expected the `tofu.PlanFile` `tofu.plan` wrote, as {path, sha256, dir}".to_string(),
        ));
    };
    let member = |key: &str| -> Result<String, StepError> {
        match map.get(key) {
            Some(Value::String(text)) if !text.is_empty() => Ok(text.clone()),
            Some(Value::String(_)) => Err(invalid(format!("`{key}` is empty"))),
            _ => Err(invalid(format!("`{key}` is missing or is not a string"))),
        }
    };
    let path = member("path")?;
    let sha256 = member("sha256")?;
    let saved = SavedPlan::new(&path, &sha256)
        .map_err(|error| invalid(format!("`sha256` is not a digest: {error}")))?;
    Ok(PlanFile { saved, dir: member("dir")? })
}

/// How an apply reads, the way `tofu` prints it: `3 resources`, `1 resource`.
fn summary(applied: usize) -> String {
    if applied == 1 { "1 resource".to_string() } else { format!("{applied} resources") }
}

/// One root output's raw JSON text, decoded into a [`Value`].
///
/// The value crosses the port as JSON text (`ks-core` has no serde); the engine
/// does, so the decoding happens here rather than in every consumer. Text that
/// is not JSON at all — which a tool should not emit — passes through as a
/// string rather than failing the step over an output nobody asked for.
fn output_value(output: &OutputValue) -> Value {
    serde_json::from_str::<serde_json::Value>(&output.value)
        .map(|json| output_json(&json))
        .unwrap_or_else(|_| Value::String(output.value.clone()))
}

/// One decoded JSON value, at any depth. JSON has no NaN or infinity, so a
/// number always has a finite `f64` to go out as.
fn output_json(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(value) => Value::Bool(*value),
        serde_json::Value::Number(number) => Value::Number(number.as_f64().unwrap_or_default()),
        serde_json::Value::String(text) => Value::String(text.clone()),
        serde_json::Value::Array(items) => Value::List(items.iter().map(output_json).collect()),
        serde_json::Value::Object(entries) => Value::Map(
            entries.iter().map(|(name, json)| (name.clone(), output_json(json))).collect(),
        ),
    }
}

/// The root outputs as the step returns them: the non-sensitive ones by name,
/// and how many sensitive ones were withheld.
///
/// Sensitive outputs are counted, never quoted: a step cannot register a value
/// with the run's [`Redactor`](ks_core::ports::secrets::Redactor), and a
/// `StepError` bypasses it, so anything it named would reach the CI log in the
/// clear.
fn collect(outputs: &IacOutputs) -> (BTreeMap<String, Value>, usize) {
    let mut out = BTreeMap::new();
    let mut sensitive = 0;
    for (name, output) in outputs {
        if output.sensitive {
            sensitive += 1;
            continue;
        }
        out.insert(name.clone(), output_value(output));
    }
    (out, sensitive)
}

/// Why the port failed, in words that name no tool output: an
/// [`IacError::Tool`]'s own message is raw tool output, which only the adapter
/// may scrub, and a `StepError` bypasses the run's redactor. Everything else
/// carries no tool output, so the port's own wording is the clearest one.
fn cause(error: &IacError) -> String {
    match error {
        IacError::Tool { exit_code: Some(code), .. } => {
            format!("the infrastructure tool failed (exit code {code})")
        }
        IacError::Tool { exit_code: None, .. } => "the infrastructure tool failed".to_string(),
        other => other.to_string(),
    }
}

/// Why an apply did not happen, as the step reports it.
fn refused(error: &IacError) -> StepError {
    let message = match error {
        // The port refuses before it touches anything, so nothing was created
        // and the fix is a fresh plan and a fresh approval. #67 wraps
        // `StalePlan`: it stops the run and asks for that new approval rather
        // than letting anything apply through it.
        IacError::PlanTampered { .. } | IacError::StalePlan | IacError::InvalidDigest { .. } => {
            format!(
                "refusing to apply: {}; nothing was applied — plan again and ask for the new \
                 plan to be approved",
                cause(error)
            )
        }
        // The tool ran and failed partway through, so what exists now is not
        // knowable from here: a human has to look before applying anything else.
        IacError::Tool { .. } => format!(
            "the apply failed: {}; infrastructure may be half-changed — check the state before \
             applying anything else",
            cause(error)
        ),
    };
    StepError::Port { port: Port::IacTool, message }
}

/// Logs the apply the way `tofu` prints it — `3 resources` — with the counts,
/// and once the outputs have been read, how many sensitive ones were withheld.
fn log_applied(ctx: &StepCtx, result: &ApplyResult, sensitive: Option<usize>) {
    let mut fields = vec![
        ("added".to_string(), result.added.to_string()),
        ("changed".to_string(), result.changed.to_string()),
        ("destroyed".to_string(), result.destroyed.to_string()),
    ];
    if let Some(count) = sensitive {
        fields.push(("sensitive_outputs".to_string(), count.to_string()));
    }
    let borrowed: Vec<(&str, &str)> =
        fields.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let applied = result.added + result.changed + result.destroyed;
    ctx.log().info(&summary(applied), &borrowed);
}

/// Applies exactly the approved plan file.
#[derive(Debug, Default)]
pub struct TofuApply;

impl StepKind for TofuApply {
    fn name(&self) -> &'static str {
        "tofu.apply"
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Applies exactly the plan file an approval was bound to, refusing if its sha256 \
                  no longer matches.",
            inputs: vec![Field::new(
                "plan",
                TypeRef::Builtin(ValueType::Map),
                "the `tofu.PlanFile` `tofu.plan` emitted as `file`: `{path, sha256, dir}`, with \
                 `sha256` the digest the approval was bound to",
            )],
            outputs: vec![
                Field::new(
                    "out",
                    TypeRef::Builtin(ValueType::Map),
                    "the root module's non-sensitive outputs, by name; sensitive ones are counted \
                     in the log, never returned",
                ),
                Field::new(
                    "applied",
                    TypeRef::Builtin(ValueType::Number),
                    "how many resources the apply changed (created, updated and destroyed)",
                ),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::IacTool]
    }

    /// Creating and destroying infrastructure is exactly what needs an
    /// approval, and what must never be retried.
    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Apply)
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let Some(tool) = ctx.ports().iac_tool() else {
                return Err(StepError::Port {
                    port: Port::IacTool,
                    message: "no infrastructure tool was provided".to_string(),
                });
            };
            let plan = parse_plan(&inputs)?;
            // The port re-hashes the file before it applies anything: this is
            // where a plan edited after the approval is caught.
            let result = tool.apply(&plan.saved).await.map_err(|error| refused(&error))?;
            let applied = result.added + result.changed + result.destroyed;

            // The outputs are read last, and a failure to read them must not
            // read as "nothing happened": by now the world has changed, so the
            // log says so first, and the failure says not to apply again.
            let (out, sensitive) = match tool.outputs(Path::new(&plan.dir)).await {
                Ok(outputs) => collect(&outputs),
                Err(error) => {
                    log_applied(&ctx, &result, None);
                    return Err(StepError::Port {
                        port: Port::IacTool,
                        message: format!(
                            "the plan was applied ({}), but the root outputs could not be read \
                             ({}); do not apply it again — check the state and read the outputs \
                             from the module directory",
                            summary(applied),
                            cause(&error)
                        ),
                    });
                }
            };

            log_applied(&ctx, &result, Some(sensitive));
            let mut returned = Outputs::new();
            returned.insert("out".to_string(), Value::Map(out));
            returned.insert("applied".to_string(), Value::Number(applied as f64));
            Ok(returned)
        })
    }
}
