//! Fake for the [`RunLog`] port ([#46](https://github.com/Keep-Shipping/harness/issues/46)): it
//! keeps every entry, in order, so "this transition emitted exactly one event" is an
//! assertion rather than a hope — the same job [`RecordingSink`] does for a step's log lines.
//!
//! [`RecordingSink`]: crate::step::RecordingSink

use std::fmt;
use std::sync::Mutex;

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::run_log::{RunEvent, RunLog, RunLogError};

/// A [`RunLog`] that keeps every `(run, event)` it is handed, in order.
///
/// `Send + Sync`, so an `Arc<RecordingRunLog>` is the `Arc<dyn RunLog>` the engine journals
/// through. `Debug` prints the entry count, never an entry: a run's log must not become a way
/// to print one.
///
/// ```
/// use std::sync::Arc;
/// use ks_core::ids::RunId;
/// use ks_core::ports::run_log::{RunEvent, RunLog};
/// use ks_testing::{block_on, run_log::RecordingRunLog};
///
/// let log = Arc::new(RecordingRunLog::new());
/// let run = RunId::from_parts(0, 0);
/// block_on(log.append(&run, RunEvent::StepStarted { step: "build".to_string() })).unwrap();
///
/// assert_eq!(log.events().len(), 1);
/// assert_eq!(format!("{log:?}"), "RecordingRunLog { entries: 1 }");
/// ```
#[derive(Default)]
pub struct RecordingRunLog {
    entries: Mutex<Vec<(RunId, RunEvent)>>,
}

impl RecordingRunLog {
    /// Creates an empty log.
    pub fn new() -> RecordingRunLog {
        RecordingRunLog::default()
    }

    /// Every event so far, in order, across all runs.
    #[must_use]
    pub fn events(&self) -> Vec<RunEvent> {
        self.entries
            .lock()
            .expect("recording run log poisoned")
            .iter()
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// Every `(run, event)` pair so far, in order.
    #[must_use]
    pub fn entries(&self) -> Vec<(RunId, RunEvent)> {
        self.entries.lock().expect("recording run log poisoned").clone()
    }
}

impl RunLog for RecordingRunLog {
    fn append<'a>(
        &'a self,
        run: &'a RunId,
        event: RunEvent,
    ) -> BoxFuture<'a, Result<(), RunLogError>> {
        Box::pin(async move {
            self.entries.lock().expect("recording run log poisoned").push((run.clone(), event));
            Ok(())
        })
    }
}

impl fmt::Debug for RecordingRunLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.entries.lock().expect("recording run log poisoned").len();
        f.debug_struct("RecordingRunLog").field("entries", &count).finish()
    }
}
