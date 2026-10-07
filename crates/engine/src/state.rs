//! Run state: what a run writes down before it exits, and what a later job
//! reads to carry on ([#42](https://github.com/Keep-Shipping/harness/issues/42)).
//! A run reaching an approval parks — record and plan bytes to a
//! [`StateStore`] — and the process exits. Resuming is a new job.
//!
//! [`RunState`] is hand-serialised through [`serde_json::Value`] so its shape is
//! visible here, and carries a `"version": 1` that [`RunState::from_json`]
//! refuses to guess past. [`LocalStateStore`] writes it as `state.json` under
//! `<root>/.keepshipping/runs/<run-id>/`, plans as `plan-<sha256>` (the name
//! *is* the digest binding), via a temporary file and a rename.
//!
//! Resume re-computes two digests rather than trusting the record: `ship.ks`
//! still hashes to `RunState::file_sha256` ([`resume`]) and the fetched plan
//! still hashes to [`PlanRef::sha256`] ([`fetch_plan`]). Image digests in
//! `outputs` are **not** re-verified here — re-binding a published artifact is
//! the producing port's job (`IacTool::apply` re-hashes the plan it is handed),
//! and the plan is the only thing crossing the job boundary.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::iac::{IacError, SavedPlan};
use ks_core::ports::state_store::{
    Sensitivity, StateError, StateStore, StateSummary, check_key, is_valid_key,
};

/// The key the run record is parked under.
pub const STATE_KEY: &str = "state.json";

/// The record's JSON version. Bumping it is a format change; decoding any
/// other value fails rather than guessing.
const RECORD_VERSION: u64 = 1;

/// The sha256 of `bytes` as 64 lowercase hex digits — the one digest primitive
/// in the engine, matching what the ports hash with.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A saved plan as the record refers to it: the digest its bytes had when
/// parked, never the bytes. [`fetch_plan`] turns this back into a
/// [`SavedPlan`], after checking the store still returns bytes digesting to
/// `sha256`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRef {
    /// The step the plan belongs to, e.g. `tofu.plan`.
    pub step: String,
    /// The sha256 the plan bytes must still hash to.
    pub sha256: String,
}

/// One completed step: what it produced, as digests and references only —
/// contents live in the store under their own digest (see
/// [`CompletedStep::plans`]), and the record outlives the job that wrote it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompletedStep {
    pub name: String,
    /// Output name → digest or reference.
    pub outputs: BTreeMap<String, String>,
    pub plans: Vec<PlanRef>,
}

/// An approval a run received, bound to the step it unblocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The step being approved.
    pub step: String,
    /// Who approved it — a handle, an actor from the `RunContext` port.
    pub by: String,
}

/// Why a resume or a plan fetch was refused. Every message names the run and
/// says what to do instead; a refusal that only says "invalid" sends the
/// caller back to the workflow file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeError {
    /// The store holds no state for this run — it never parked, or it is gone.
    NotFound { run: RunId },
    /// The `ship.ks` behind the parked run no longer hashes to what it did.
    FileChanged { run: RunId, expected: String, actual: String },
    /// The record could not be read: malformed JSON, a `version` this build does
    /// not speak, or a plan whose bytes are gone or no longer hash to what the
    /// record names. `expected`/`actual` are set only for that last case.
    Decode { run: RunId, reason: String, expected: Option<String>, actual: Option<String> },
    /// The approval was for a step other than the one parked on, or the run is
    /// not waiting on anything.
    NotParkedAt { run: RunId, step: String, waiting: Option<String> },
    /// The step already has output recorded — it ran, so there is nothing left
    /// to approve.
    AlreadyCompleted { run: RunId, step: String },
    /// The store itself failed — a full disk, a revoked credential.
    Store { message: String },
    /// The fetched plan could not be turned into something apply accepts.
    Plan { message: String },
    /// The fetched plan could not be written to the destination path.
    PlanWrite { dest: String, message: String },
}

impl fmt::Display for ResumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResumeError::NotFound { run } => {
                write!(f, "no parked state for run {run}: nothing to resume; start a new run")
            }
            ResumeError::FileChanged { run, expected, actual } => write!(
                f,
                "refusing to resume run {run}: ship.ks changed since the run parked \
                 (sha256 {expected} then, {actual} now); start a new run"
            ),
            ResumeError::Decode { run, reason, expected, actual } => {
                write!(f, "run {run} cannot be resumed: {reason}")?;
                match (expected, actual) {
                    (Some(expected), Some(actual)) => {
                        write!(
                            f,
                            " (sha256 {expected} parked, {actual} found); refusing to apply it"
                        )
                    }
                    _ => write!(f, "; start a new run"),
                }
            }
            ResumeError::NotParkedAt { run, step, waiting } => {
                write!(f, "run {run} is not waiting for approval of {step}")?;
                match waiting {
                    Some(waiting) => write!(f, "; it is parked at {waiting}"),
                    None => write!(f, "; the run has already finished"),
                }
            }
            ResumeError::AlreadyCompleted { run, step } => write!(
                f,
                "run {run} already completed {step}; it cannot be waited on or approved again"
            ),
            ResumeError::Store { message } => write!(f, "the state store failed: {message}"),
            ResumeError::Plan { message } => {
                write!(f, "the fetched plan is unusable: {message}")
            }
            ResumeError::PlanWrite { dest, message } => {
                write!(f, "could not write the fetched plan to {dest}: {message}")
            }
        }
    }
}

impl std::error::Error for ResumeError {}

impl From<StateError> for ResumeError {
    fn from(error: StateError) -> ResumeError {
        ResumeError::Store { message: error.to_string() }
    }
}

impl From<IacError> for ResumeError {
    fn from(error: IacError) -> ResumeError {
        ResumeError::Plan { message: error.to_string() }
    }
}

/// A decode failure: the reason, plus the two digests only when the failure *is*
/// a digest mismatch.
fn undecodable(run: &RunId, reason: String) -> ResumeError {
    ResumeError::Decode { run: run.clone(), reason, expected: None, actual: None }
}

/// Everything a run needs to be picked up by another job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunState {
    pub run: RunId,
    /// The sha256 of the `ship.ks` that started the run — the binding
    /// [`resume`] re-checks.
    pub file_sha256: String,
    /// The trigger event the run started from.
    pub event: String,
    pub context: BTreeMap<String, String>,
    pub completed: Vec<CompletedStep>,
    pub approvals: Vec<Approval>,
    /// The step the run is waiting on; `None` when it has finished.
    pub next: Option<String>,
}

impl RunState {
    /// A fresh record for `run`, bound to `ship_ks_source`.
    pub fn new(run: RunId, ship_ks_source: &[u8], event: impl Into<String>) -> RunState {
        RunState {
            run,
            file_sha256: sha256_hex(ship_ks_source),
            event: event.into(),
            context: BTreeMap::new(),
            completed: Vec::new(),
            approvals: Vec::new(),
            next: None,
        }
    }

    /// Records a context value resolved at the start of the run.
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> RunState {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Marks `step` complete with `outputs` and the plans it produced, and
    /// leaves the run waiting on nothing — the step just recorded is not one to
    /// wait on. Say what the run waits on with [`RunState::park_at`], or leave
    /// it as it is when the run has finished.
    pub fn record(&mut self, step: CompletedStep) {
        self.next = None;
        self.completed.push(step);
    }

    /// Parks the run waiting on `step`. Fails with
    /// [`ResumeError::AlreadyCompleted`] unless the step has not run yet, so an
    /// approval gate is never sat in front of a step that already produced its
    /// output.
    pub fn park_at(&mut self, step: impl Into<String>) -> Result<(), ResumeError> {
        let step = step.into();
        if self.completed.iter().any(|done| done.name == step) {
            return Err(ResumeError::AlreadyCompleted { run: self.run.clone(), step });
        }
        self.next = Some(step);
        Ok(())
    }

    /// Records the approval of `step` by `by` and leaves the run parked on the
    /// step after it. Fails with [`ResumeError::NotParkedAt`] unless the run is
    /// waiting on exactly `step`, so an approval for a step the run has moved
    /// past cannot silently advance it, and with
    /// [`ResumeError::AlreadyCompleted`] for a step that has already run.
    pub fn approve(&mut self, step: &str, by: impl Into<String>) -> Result<(), ResumeError> {
        if self.completed.iter().any(|done| done.name == step) {
            return Err(ResumeError::AlreadyCompleted {
                run: self.run.clone(),
                step: step.to_string(),
            });
        }
        if self.next.as_deref() != Some(step) {
            return Err(ResumeError::NotParkedAt {
                run: self.run.clone(),
                step: step.to_string(),
                waiting: self.next.clone(),
            });
        }
        self.approvals.push(Approval { step: step.to_string(), by: by.into() });
        self.next = None;
        Ok(())
    }

    /// The plan refs recorded for `step`.
    pub fn plans_for(&self, step: &str) -> Vec<&PlanRef> {
        self.completed.iter().filter(|d| d.name == step).flat_map(|d| d.plans.iter()).collect()
    }

    /// The record as JSON, with its version.
    pub fn to_json(&self) -> Value {
        json!({
            "version": RECORD_VERSION,
            "run": self.run.to_string(),
            "file_sha256": self.file_sha256,
            "event": self.event,
            "context": self.context,
            "completed": self.completed.iter().map(|step| json!({
                "name": step.name,
                "outputs": step.outputs,
                "plans": step.plans.iter().map(|p| json!({ "step": p.step, "sha256": p.sha256 }))
                    .collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "approvals": self.approvals.iter().map(|a| json!({ "step": a.step, "by": a.by }))
                .collect::<Vec<_>>(),
            "next": self.next,
        })
    }

    /// Decodes a record written by [`RunState::to_json`], refusing an unknown
    /// `version` and malformed JSON rather than decoding a record whose meaning
    /// has moved.
    pub fn from_json(value: &Value) -> Result<RunState, ResumeError> {
        // Failures before the run id is read carry a placeholder; [`resume`]
        // re-stamps them with the real one.
        let anonymous = |reason: String| undecodable(&RunId::from_parts(0, 0), reason);
        let version = value
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| anonymous("the record has no numeric `version` field".to_string()))?;
        if version != RECORD_VERSION {
            return Err(anonymous(format!(
                "the record is version {version}; this harness reads {RECORD_VERSION}"
            )));
        }
        let run = value
            .get("run")
            .and_then(Value::as_str)
            .ok_or_else(|| anonymous("the record has no `run` id".to_string()))
            .and_then(|text| {
                RunId::parse(text)
                    .map_err(|error| anonymous(format!("`run` is not a run id: {error}")))
            })?;
        let bad = |reason: String| undecodable(&run, reason);
        let required = |name: &str| -> Result<String, ResumeError> {
            value
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| bad(format!("the record has no `{name}` string")))
        };
        let list = |name: &str| -> Vec<Value> {
            value.get(name).and_then(Value::as_array).cloned().unwrap_or_default()
        };
        let completed = list("completed")
            .iter()
            .map(|step| {
                Ok(CompletedStep {
                    name: step
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| bad("a completed step has no `name`".to_string()))?
                        .to_string(),
                    outputs: strings_of(step.get("outputs"))
                        .map_err(|reason| bad(format!("a completed step's `outputs`: {reason}")))?,
                    plans: step
                        .get("plans")
                        .and_then(Value::as_array)
                        .map(|plans| {
                            plans
                                .iter()
                                .map(|p| PlanRef {
                                    step: text(p, "step"),
                                    sha256: text(p, "sha256"),
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>, ResumeError>>()?;
        let approvals: Vec<Approval> = list("approvals")
            .iter()
            .map(|a| Approval { step: text(a, "step"), by: text(a, "by") })
            .collect();
        // Read before `run` moves into the record: the closures above borrow it.
        let file_sha256 = required("file_sha256")?;
        let event = required("event")?;
        let context = strings_of(value.get("context"))
            .map_err(|reason| bad(format!("`context`: {reason}")))?;
        Ok(RunState {
            run,
            file_sha256,
            event,
            context,
            completed,
            approvals,
            next: value.get("next").and_then(Value::as_str).map(str::to_string),
        })
    }
}

/// The string under `name` in `value`, or the empty string — for the optional
/// leaf fields of a plan ref and an approval.
fn text(value: &Value, name: &str) -> String {
    value.get(name).and_then(Value::as_str).unwrap_or_default().to_string()
}

/// The string map in `value`. A non-string entry is a decode error, not
/// something to drop: a record that quietly loses a field looks like one that
/// never had it.
fn strings_of(value: Option<&Value>) -> Result<BTreeMap<String, String>, String> {
    let map = match value.and_then(Value::as_object) {
        Some(map) => map,
        None => return Ok(BTreeMap::new()),
    };
    map.iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|text| (key.clone(), text.to_string()))
                .ok_or_else(|| format!("`{key}` is {value}, not a string"))
        })
        .collect()
}

/// The key a plan's bytes live under: `plan-<sha256>`. Content-addressed, so
/// the key names the binding — a store returning the wrong bytes for it fails
/// [`fetch_plan`]'s hash check rather than applying something else.
pub fn plan_key(sha256: &str) -> String {
    format!("plan-{sha256}")
}

/// Stores `bytes` as `run`'s plan for `step` and returns the reference to
/// record. The blob is written before the caller parks, so a resume always finds
/// the bytes the record points at.
pub async fn save_plan(
    store: &dyn StateStore,
    run: &RunId,
    step: &str,
    bytes: &[u8],
) -> Result<PlanRef, ResumeError> {
    let sha256 = sha256_hex(bytes);
    // Plan bytes are `Secretish` (#55): a plan spells out every resource and
    // argument in the change about to be applied to the customer's
    // infrastructure. The store records the classification; with the local
    // adapter that is a sidecar file beside the blob in the run's own
    // directory, because the bytes are already sitting in the customer's own
    // working directory.
    store.put(run, &plan_key(&sha256), bytes, Sensitivity::Secretish).await?;
    Ok(PlanRef { step: step.to_string(), sha256 })
}

/// Writes `state`'s record under [`STATE_KEY`], overwriting whatever was parked
/// before — parking twice is how a run advances.
///
/// [`STATE_KEY`] is written [`Sensitivity::Plain`]: the record holds step names,
/// output digests, the event the run started from, and the handle of whoever
/// approved something — no plan bytes and no secret values, which the run
/// resolved through the secrets port and never wrote down.
pub async fn park(store: &dyn StateStore, state: &RunState) -> Result<(), ResumeError> {
    let bytes = serde_json::to_vec(&state.to_json())
        .map_err(|error| ResumeError::Store { message: error.to_string() })?;
    store.put(&state.run, STATE_KEY, &bytes, Sensitivity::Plain).await?;
    Ok(())
}

/// Loads `run`'s parked record and re-verifies its binding:
/// [`ResumeError::NotFound`] if nothing is parked, [`ResumeError::FileChanged`]
/// if `ship_ks_source` no longer hashes to the recorded digest.
pub async fn resume(
    store: &dyn StateStore,
    run: &RunId,
    ship_ks_source: &[u8],
) -> Result<RunState, ResumeError> {
    let bytes = store
        .get(run, STATE_KEY)
        .await?
        .ok_or_else(|| ResumeError::NotFound { run: run.clone() })?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        undecodable(run, format!("the parked state is not valid JSON: {error}"))
    })?;
    let state = RunState::from_json(&value).map_err(|error| match error {
        ResumeError::Decode { reason, .. } => undecodable(run, reason),
        other => other,
    })?;
    let actual = sha256_hex(ship_ks_source);
    if actual != state.file_sha256 {
        return Err(ResumeError::FileChanged {
            run: run.clone(),
            expected: state.file_sha256,
            actual,
        });
    }
    if state.run != *run {
        return Err(undecodable(run, format!("the record is for run {} instead", state.run)));
    }
    Ok(state)
}

/// Fetches the plan `plan_ref` names, checks it still digests to
/// [`PlanRef::sha256`], writes it to `dest` and returns it as the [`SavedPlan`]
/// [`IacTool::apply`](ks_core::ports::iac::IacTool::apply) accepts.
///
/// Bytes absent and bytes of the wrong digest both refuse with
/// [`ResumeError::Decode`] — the first saying to plan again, the second carrying
/// both digests — and neither writes to `dest`, so a refused resume leaves no
/// plan file for a later apply to pick up.
pub async fn fetch_plan(
    store: &dyn StateStore,
    run: &RunId,
    plan_ref: &PlanRef,
    dest: &Path,
) -> Result<SavedPlan, ResumeError> {
    let bytes = match store.get(run, &plan_key(&plan_ref.sha256)).await? {
        Some(bytes) => bytes,
        None => {
            return Err(undecodable(
                run,
                format!(
                    "the plan sha256 {} is not in the state store; run the plan step again",
                    plan_ref.sha256
                ),
            ));
        }
    };
    let actual = sha256_hex(&bytes);
    if actual != plan_ref.sha256 {
        return Err(ResumeError::Decode {
            run: run.clone(),
            reason: "the plan no longer matches the digest the run was parked with".to_string(),
            expected: Some(plan_ref.sha256.clone()),
            actual: Some(actual),
        });
    }
    write_atomically(dest, &bytes).map_err(|error| ResumeError::PlanWrite {
        dest: dest.display().to_string(),
        message: error.to_string(),
    })?;
    Ok(SavedPlan::new(dest, actual)?)
}

/// A [`StateStore`] over `<root>/.keepshipping/runs/<run-id>/<key>`, `<root>`
/// being the customer's working directory — state lives in storage the customer
/// owns, and there is no hosted adapter for it.
///
/// Keys are validated by the port's [`check_key`] before they touch the
/// filesystem. Writes go to a temporary file in the same directory, are
/// fsynced and renamed into place, so a crash mid-write leaves the old object
/// or the new one. The I/O is synchronous, before the returned future resolves.
///
/// # Sensitivity sidecars
///
/// A blob is stored as its bytes and nothing else, so the [`Sensitivity`] a
/// [`StateStore::put`] recorded has nowhere to live in the file itself — the
/// bytes are the plan, and prepending anything to them would break the
/// `plan-<sha256>` digest binding that makes a resume safe. It is therefore
/// written beside them, one small file per key, inside the run's own directory:
///
/// ```text
/// <root>/.keepshipping/runs/<run-id>/
///   state.json                     the parked record, as its own bytes
///   .state.json.sensitivity        what that key was declared to be
///   plan-<sha256>                  a saved plan, as its own bytes
///   .plan-<sha256>.sensitivity     ditto, for the plan
/// ```
///
/// A sidecar holds the one word [`Sensitivity::as_str`] spells, and nothing
/// else. One file per key rather than one index file is what makes the resume
/// model safe: a resume is two processes over one checkout, so writers of
/// *different* keys never touch the same file, and the ratchet on one key is a
/// single exclusive create against that key's own file rather than a
/// read-modify-write of a shared map whose rename can silently drop a key
/// written in between.
///
/// The leading dot puts a sidecar in space no key can name: [`check_key`]
/// refuses a key starting with anything but `[a-z0-9]`, so no `put` or `get`
/// can address it, collide with it, or overwrite it. `list` skips dotted names
/// for the same reason, which also steps over the `.{name}.{pid}.{n}.tmp` files
/// [`write_atomically`] leaves behind only for the length of a write.
/// [`LocalStateStore::delete_run`] removes the whole directory, so the sidecars
/// go with the blobs they describe.
///
/// # What an absent sidecar does and does not mean
///
/// A key with no sidecar reads as [`Sensitivity::Plain`]. That covers a run
/// written before #55 existed, a directory someone made or copied by hand, and a
/// run directory whose sidecars did not travel with its blobs — `cp -r
/// runs/<id>/*`, an rsync or tar rule that skips dotfiles, a checkout that
/// excludes them. Those copies are ordinary and they lose a sidecar silently,
/// so **absence is not proof that nothing under that key was ever secret**: a
/// sidecar has to travel with its blob, or a later read answers `Plain` for
/// bytes that were declared secretish. This store cannot tell those cases apart.
///
/// It does at least write a sidecar for every key it stores — `plain` is a
/// sidecar like any other — so in a directory this build wrote itself, a key with
/// no sidecar is one no `put` here has ever claimed.
///
/// A sidecar that exists but cannot be read or parsed is *not* read as plain: it
/// is [`StateError::Unavailable`], because a store that cannot remember what it
/// was told must not answer with the weaker promise.
#[derive(Debug, Clone)]
pub struct LocalStateStore {
    root: PathBuf,
}

/// The half of a key's sensitivity sidecar name that does not depend on the key:
/// `.{key}.sensitivity`. The dot is added in
/// [`LocalStateStore::sensitivity_path`], where the key is known.
const SENSITIVITY_SUFFIX: &str = "sensitivity";

impl LocalStateStore {
    /// A store rooted at `root`; nothing is created until the first write.
    pub fn new(root: impl Into<PathBuf>) -> LocalStateStore {
        LocalStateStore { root: root.into() }
    }

    /// The directory holding `run`'s objects.
    pub fn run_dir(&self, run: &RunId) -> PathBuf {
        self.root.join(".keepshipping").join("runs").join(run.as_str())
    }

    /// Where `run`'s record of what `key` was declared to be lives. Dot-prefixed
    /// and suffixed, so [`check_key`] makes it unreachable by key and `list`
    /// steps over it.
    fn sensitivity_path(&self, run: &RunId, key: &str) -> PathBuf {
        self.run_dir(run).join(format!(".{key}.{SENSITIVITY_SUFFIX}"))
    }

    /// What `key` is currently declared to be.
    ///
    /// A missing sidecar is [`Sensitivity::Plain`] — see the type's documentation
    /// for what that does and does not prove. A sidecar that is present and
    /// unreadable is an error, not the default: the store was told something
    /// about this key once and cannot now say what.
    fn sensitivity(&self, run: &RunId, key: &str) -> Result<Sensitivity, StateError> {
        let path = self.sensitivity_path(run, key);
        let recorded = match std::fs::read_to_string(&path) {
            Ok(recorded) => recorded,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Sensitivity::Plain);
            }
            Err(error) => return Err(unavailable(&path, error)),
        };
        match recorded.trim() {
            recorded if recorded == Sensitivity::Plain.as_str() => Ok(Sensitivity::Plain),
            recorded if recorded == Sensitivity::Secretish.as_str() => Ok(Sensitivity::Secretish),
            other => Err(StateError::Unavailable {
                message: format!(
                    "{}: it records {other:?}, which is not a sensitivity",
                    path.display()
                ),
            }),
        }
    }

    /// Records `key`'s classification in that key's own sidecar, refusing to
    /// write [`Sensitivity::Plain`] over a key already held as
    /// [`Sensitivity::Secretish`].
    ///
    /// The create is exclusive, which is what makes the ratchet atomic against
    /// another writer: of two processes writing the *same* key, whichever
    /// creates the sidecar owns that key's first classification and the other
    /// reads it back and ratchets against *that*, rather than against a reading
    /// taken before the create. Neither can see the sidecar missing and both
    /// proceed. Writers of different keys never open the same file.
    fn record_sensitivity(
        &self,
        run: &RunId,
        key: &str,
        sensitivity: Sensitivity,
    ) -> Result<(), StateError> {
        let path = self.sensitivity_path(run, key);
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let recorded = (|| {
                    file.write_all(sensitivity.as_str().as_bytes())?;
                    file.sync_all()
                })();
                if let Err(error) = recorded {
                    // A sidecar that exists but says nothing is refused from
                    // then on; a key that was never classified must not be the
                    // reason it is.
                    let _ = std::fs::remove_file(&path);
                    return Err(unavailable(&path, error));
                }
                sync_dir(path.parent().unwrap_or_else(|| Path::new(".")));
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let recorded = self.sensitivity(run, key)?;
                if recorded.is_secretish() {
                    if !sensitivity.is_secretish() {
                        return Err(StateError::Downgrade { key: key.to_string() });
                    }
                } else if sensitivity.is_secretish() {
                    // The only move left is up, so the stronger promise wins over
                    // the weaker one already on disk.
                    write_atomically(&path, sensitivity.as_str().as_bytes())
                        .map_err(|error| unavailable(&path, error))?;
                }
                Ok(())
            }
            Err(error) => Err(unavailable(&path, error)),
        }
    }
}

/// A filesystem failure at `path`.
fn unavailable(path: &Path, error: std::io::Error) -> StateError {
    StateError::Unavailable { message: format!("{}: {error}", path.display()) }
}

/// Writes `bytes` to `path` through a temporary file in the same directory:
/// flushed to disk before the rename, so a reader sees the old bytes or the new
/// ones and a crash leaves no half-written object behind. The temp name carries
/// the process id and a counter, so two writers racing on the same path do not
/// share one file.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let temp = dir.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written?;
    sync_dir(dir);
    Ok(())
}

/// Best-effort fsync of `dir`, so the rename survives a crash too. Where a
/// directory cannot be opened for sync the file's own fsync is what there is.
#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

/// `check_key` as a [`StateError`], so a bad key names the rule it broke.
fn reject_key(key: &str) -> Result<(), StateError> {
    check_key(key).map_err(|reason| StateError::InvalidKey { key: key.to_string(), reason })
}

impl StateStore for LocalStateStore {
    fn put<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a str,
        bytes: &'a [u8],
        sensitivity: Sensitivity,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        let result = (|| {
            reject_key(key)?;
            let dir = self.run_dir(run);
            std::fs::create_dir_all(&dir).map_err(|error| unavailable(&dir, error))?;
            // The classification is recorded before the bytes, not after. A crash
            // between the two then leaves a key classified secretish whose bytes
            // are missing or stale — over-classified, and the ratchet still holds
            // — where the other order would leave freshly written secret bytes
            // recorded as plain, which is the one direction that loses a promise.
            //
            // This is a best-effort preference, not a guarantee: it holds where
            // the run's directory can itself be fsynced, which [`sync_dir`] asks
            // for and does not insist on. Where it cannot, a sidecar can reach
            // the disk after the bytes it describes, and the ordering buys
            // nothing — the ratchet is then only as good as the last sidecar that
            // did land.
            self.record_sensitivity(run, key, sensitivity)?;
            let final_path = dir.join(key);
            write_atomically(&final_path, bytes).map_err(|error| unavailable(&final_path, error))
        })();
        Box::pin(std::future::ready(result))
    }

    fn get<'a>(
        &'a self,
        run: &'a RunId,
        key: &'a str,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StateError>> {
        let result = (|| {
            reject_key(key)?;
            let path = self.run_dir(run).join(key);
            match std::fs::read(&path) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(unavailable(&path, error)),
            }
        })();
        Box::pin(std::future::ready(result))
    }

    fn list<'a>(&'a self, run: &'a RunId) -> BoxFuture<'a, Result<Vec<StateSummary>, StateError>> {
        let result = (|| {
            let dir = self.run_dir(run);
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                // A run that stored nothing has no directory, and that is the
                // same answer as a run whose keys are all gone: an empty list.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(error) => return Err(unavailable(&dir, error)),
            };
            let mut summaries = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|error| unavailable(&dir, error))?;
                let name = entry.file_name().to_string_lossy().into_owned();
                // Dotted names are not keys: a key's sensitivity sidecar, and the
                // temporary files a write in flight leaves behind.
                if name.starts_with('.') {
                    continue;
                }
                // A directory left inside a run's directory is not a blob, and
                // naming it in a listing would advertise something `get` can
                // never return. Neither is a file whose name `check_key` refuses
                // — a `README`, or a `State.json` from a case-insensitive
                // filesystem, dropped in here would be listed and then refused by
                // both `get` and `put`.
                let metadata =
                    entry.metadata().map_err(|error| unavailable(&entry.path(), error))?;
                if !metadata.is_file() || !is_valid_key(&name) {
                    continue;
                }
                summaries.push(StateSummary {
                    sensitivity: self.sensitivity(run, &name)?,
                    len: metadata.len() as usize,
                    key: name,
                });
            }
            // `read_dir` hands back whatever order the filesystem feels like;
            // the port promises sorted, so sort here rather than hoping.
            summaries.sort_by(|left, right| left.key.cmp(&right.key));
            Ok(summaries)
        })();
        Box::pin(std::future::ready(result))
    }

    fn delete_run<'a>(&'a self, run: &'a RunId) -> BoxFuture<'a, Result<(), StateError>> {
        let dir = self.run_dir(run);
        let result = match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            // Already gone is the normal case for cleaning up after a run that
            // never parked, not a failure to clean up.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(unavailable(&dir, error)),
        };
        Box::pin(std::future::ready(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run with one completed step that produced one plan.
    fn a_run() -> RunState {
        let mut state = RunState::new(RunId::from_parts(0, 1), b"ship.ks", "push");
        state.record(CompletedStep {
            name: "tofu.plan".to_string(),
            outputs: BTreeMap::from([("digest".to_string(), "sha256:abc".to_string())]),
            plans: vec![PlanRef { step: "tofu.plan".to_string(), sha256: "a".repeat(64) }],
        });
        state
    }

    #[test]
    fn a_record_round_trips_and_only_the_parked_step_can_be_approved() {
        let mut state = a_run();
        assert_eq!(RunState::from_json(&state.to_json()).expect("the record decodes"), state);
        state.park_at("tofu.apply").expect("the run parks at a step it has not run");
        assert!(state.approve("tofu.plan", "ada").is_err(), "a completed step cannot be approved");
        state.approve("tofu.apply", "ada").expect("the run is parked there");
        assert_eq!(state.approvals, vec![Approval { step: "tofu.apply".into(), by: "ada".into() }]);
        assert_eq!(state.next, None);
        assert!(state.approve("tofu.apply", "grace").is_err(), "already approved");
        assert!(state.approve("deploy", "grace").is_err(), "wrong step");
        assert_eq!(state.approvals.len(), 1, "a refused approval records nothing");
    }

    #[test]
    fn a_step_that_already_ran_is_never_approved_again() {
        let mut state = a_run();
        assert!(state.park_at("tofu.plan").is_err(), "a completed step is not one to wait on");
        assert_eq!(state.next, None, "recording a step leaves the run waiting on nothing");

        // A record claiming to wait on a completed step — hand-edited, or
        // written by an older build — is refused the same way.
        let mut value = state.to_json();
        value["next"] = json!("tofu.plan");
        let mut loaded = RunState::from_json(&value).expect("the record decodes");
        let error = loaded.approve("tofu.plan", "ada").expect_err("it already ran");
        assert!(matches!(error, ResumeError::AlreadyCompleted { .. }), "{error:?}");
        assert!(error.to_string().contains("tofu.plan"), "{error}");
        assert!(loaded.approvals.is_empty(), "a refused approval records nothing");
    }

    #[test]
    fn a_record_of_another_shape_is_refused() {
        let mut value = a_run().to_json();
        value["version"] = json!(2);
        for (value, expected) in
            [(value, "version 2"), (json!({"version": 1}), "`run`"), (json!({}), "`version`")]
        {
            assert!(RunState::from_json(&value).unwrap_err().to_string().contains(expected));
        }
    }

    #[test]
    fn resume_errors_name_the_run_and_the_way_out() {
        let run = RunId::from_parts(0, 1);
        let message = ResumeError::FileChanged {
            run: run.clone(),
            expected: "a".repeat(64),
            actual: "b".repeat(64),
        }
        .to_string();
        for fragment in ["ship.ks changed", run.as_str(), "start a new run"] {
            assert!(message.contains(fragment), "{fragment} missing from {message}");
        }
        let tampered = ResumeError::Decode {
            run,
            reason: "the plan no longer matches".to_string(),
            expected: Some("a".repeat(64)),
            actual: Some("b".repeat(64)),
        }
        .to_string();
        assert!(
            tampered.contains(&"a".repeat(64)) && tampered.contains(&"b".repeat(64)),
            "{tampered}"
        );
    }
}
