//! Running one step kind through a [`Harness`] — the funnel every caller, today's tests and
//! tomorrow's DAG planner alike, goes through
//! ([#39](https://github.com/Keep-Shipping/harness/issues/39)).
//!
//! [`run_step`] checks, in order: the step exists, the run is not cancelled, the inputs match
//! the schema (defaults applied), and the outputs match what was promised. Between the checks
//! it hands the step a [`StepCtx`] holding only its declared ports, and logs the action class.
//! One more check came with scripts ([#91](https://github.com/Keep-Shipping/harness/issues/91)):
//! what a step returns may not contain a secret it was given.

use std::sync::Arc;

use ks_core::harness::Harness;
use ks_core::ports::BoxFuture;
use ks_core::ports::secrets::Redactor;
use ks_core::step::{
    CancellationToken, Inputs, LogSink, Outputs, Port, StepCtx, StepError, StepKind, StepLog,
    reject_secret_outputs,
};

/// Runs the step `name` from `harness` with `inputs`; `log` receives every record the engine
/// and the step emit, all redacted through `redactor` — which must already hold the run's
/// resolved secrets.
pub fn run_step<'a>(
    harness: &'a Harness,
    name: &'a str,
    inputs: Inputs,
    cancel: CancellationToken,
    log: Arc<dyn LogSink>,
    redactor: Arc<Redactor>,
) -> BoxFuture<'a, Result<Outputs, StepError>> {
    Box::pin(async move {
        let step = harness.step(name).ok_or_else(|| StepError::UnknownStep(name.to_string()))?;
        if cancel.is_cancelled() {
            return Err(StepError::Cancelled);
        }
        let inputs = harness.prepare_inputs(step.as_ref(), inputs)?;
        execute(harness, name, step.as_ref(), inputs, cancel, log, redactor).await
    })
}

/// The context a step runs in — and the one it verifies cached outputs in: only the ports it
/// declared, the harness clock, the run's cancellation token and a redacting logger.
pub(crate) fn step_ctx(
    harness: &Harness,
    step: &dyn StepKind,
    name: &str,
    cancel: CancellationToken,
    log: Arc<dyn LogSink>,
    redactor: Arc<Redactor>,
) -> StepCtx {
    let declared: Vec<Port> = step.requires().iter().chain(step.optional()).copied().collect();
    StepCtx::new(
        harness.ports().restricted_to(&declared),
        Arc::clone(harness.clock()),
        cancel,
        StepLog::new(name, redactor, log),
    )
}

/// Logs the action class, runs an already-prepared step, and checks what it returned — against
/// the schema, and against the run's secrets.
pub(crate) async fn execute(
    harness: &Harness,
    name: &str,
    step: &dyn StepKind,
    inputs: Inputs,
    cancel: CancellationToken,
    log: Arc<dyn LogSink>,
    redactor: Arc<Redactor>,
) -> Result<Outputs, StepError> {
    let ctx = step_ctx(harness, step, name, cancel, log, Arc::clone(&redactor));
    ctx.log().info("step started", &[("action", step.action(&inputs).to_string().as_str())]);
    let outputs = step.run(ctx, inputs).await?;
    // Before the schema check, not after: `check_outputs` names an undeclared output in its
    // error, and that name reaches diagnostics unredacted — so a step that named an output
    // after a secret would have it read straight back out.
    reject_secret_outputs(&redactor, &outputs)?;
    harness.check_outputs(step, &outputs)?;
    Ok(outputs)
}
