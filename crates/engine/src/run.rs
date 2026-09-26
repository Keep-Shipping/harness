//! Running one step kind through a [`Harness`] — the funnel every caller, today's tests and
//! tomorrow's DAG planner alike, goes through
//! ([#39](https://github.com/Keep-Shipping/harness/issues/39)).
//!
//! [`run_step`] checks, in order: the step exists, the run is not cancelled, the inputs match
//! the schema (defaults applied), and the outputs match what was promised. Between the checks
//! it hands the step a [`StepCtx`] holding only its declared ports, and logs the action class.

use std::sync::Arc;

use ks_core::harness::Harness;
use ks_core::ports::BoxFuture;
use ks_core::ports::secrets::Redactor;
use ks_core::step::{
    CancellationToken, Inputs, LogSink, Outputs, Port, StepCtx, StepError, StepLog,
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
        let step_log = StepLog::new(name, Arc::clone(&redactor), log);
        step_log.info("step started", &[("action", step.action(&inputs).to_string().as_str())]);
        let declared: Vec<Port> = step.requires().iter().chain(step.optional()).copied().collect();
        let ctx = StepCtx::new(
            harness.ports().restricted_to(&declared),
            Arc::clone(harness.clock()),
            cancel,
            step_log,
        );
        let outputs = step.run(ctx, inputs).await?;
        harness.check_outputs(step.as_ref(), &outputs)?;
        Ok(outputs)
    })
}
