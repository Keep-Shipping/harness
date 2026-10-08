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
    CancellationToken, Inputs, LogSink, Outputs, Port, Ports, StepCtx, StepError, StepKind,
    StepLog, reject_secret_outputs,
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
    step_ctx_for(harness, declared_ports(harness, step), name, cancel, log, redactor)
}

/// The ports a step gets: the ones it declared, and nothing else.
pub(crate) fn declared_ports(harness: &Harness, step: &dyn StepKind) -> Ports {
    let declared: Vec<Port> = step.requires().iter().chain(step.optional()).copied().collect();
    harness.ports().restricted_to(&declared)
}

/// [`step_ctx`] with the ports chosen by the caller: the policy gate hands out the same
/// restriction with the `Secrets` port wrapped ([#103](https://github.com/Keep-Shipping/harness/issues/103)),
/// so there is still exactly one place a step's context is assembled.
pub(crate) fn step_ctx_for(
    harness: &Harness,
    ports: Ports,
    name: &str,
    cancel: CancellationToken,
    log: Arc<dyn LogSink>,
    redactor: Arc<Redactor>,
) -> StepCtx {
    StepCtx::new(ports, Arc::clone(harness.clock()), cancel, StepLog::new(name, redactor, log))
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
    execute_with_ports(
        harness,
        name,
        step,
        inputs,
        cancel,
        log,
        redactor,
        declared_ports(harness, step),
    )
    .await
}

/// [`execute`] against ports the caller chose — the policy gate passes the step's declared ports
/// with the `Secrets` slot gated, so the same check-and-run is used either way.
#[allow(clippy::too_many_arguments)] // `execute`'s arguments, plus the ports they choose
pub(crate) async fn execute_with_ports(
    harness: &Harness,
    name: &str,
    step: &dyn StepKind,
    inputs: Inputs,
    cancel: CancellationToken,
    log: Arc<dyn LogSink>,
    redactor: Arc<Redactor>,
    ports: Ports,
) -> Result<Outputs, StepError> {
    let ctx = step_ctx_for(harness, ports, name, cancel, log, Arc::clone(&redactor));
    ctx.log().info("step started", &[("action", step.action(&inputs).to_string().as_str())]);
    let outputs = step.run(ctx, inputs).await?;
    // Before the schema check, not after: `check_outputs` names an undeclared output in its
    // error, and that name reaches diagnostics unredacted — so a step that named an output
    // after a secret would have it read straight back out.
    reject_secret_outputs(&redactor, &outputs)?;
    harness.check_outputs(step, &outputs)?;
    Ok(outputs)
}
