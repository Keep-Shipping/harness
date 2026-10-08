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
//! still hashes to [`PlanRef::sha256`] ([`fetch_plan`]). An [`Approval`] is
//! checked two ways before anything is released through it, and both are made
//! by [`resume`] against the clock it is given: the approval must not have
//! expired ([`ResumeError::ApprovalExpired`]), and every artifact it was bound
//! to must still be held by the run ([`RunState::check_bound`], which
//! re-derives them with [`recorded_artifacts`](RunState::recorded_artifacts) and
//! so refuses a rebuilt image or a re-planned plan — a rebuild replaces the
//! approved artifact, while an artifact recorded after the answer adds to what
//! the run holds and invalidates nothing that was approved). The binding is
//! never passed in by the caller — an approval records what the run had when
//! the answer arrived, so "the same artifacts" is a fact about the record
//! rather than a claim a caller could get wrong.
//!
//! "The same artifacts" means the same *kinds* of artifacts, not merely the same
//! digests: an approval was bound to the plan file it showed, and a digest
//! that reappears under another label is a different thing wearing the same
//! hex ([#121](https://github.com/Keep-Shipping/harness/issues/121)). So the
//! comparison is on whole [`Artifact`]s, which is also what
//! [`ApprovalRequest::accepts`](ks_core::ports::approval::ApprovalRequest::accepts)
//! required of every verdict at answer time — the check at resume is the same
//! contract the port already enforces, and it used to be weaker than it.
//!
//! Image digests in `outputs` are **not** re-verified here — re-binding a
//! published artifact is the producing port's job (`IacTool::apply` re-hashes
//! the plan it is handed), and the plan is the only thing crossing the job
//! boundary.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::approval::{Artifact, ArtifactKind};
use ks_core::ports::iac::{IacError, SavedPlan};
use ks_core::ports::state_store::{StateError, StateStore, check_key};
use ks_core::ports::supply_chain::Digest as ContentDigest;
use ks_core::sensitivity::{PLAN_KEY_PREFIX, SENSITIVE_DIR_MODE, Sensitivity};

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

/// An instant as RFC 3339 (`2023-11-14T22:13:20Z`) — the form every timestamp a
/// record or a step output carries.
///
/// Hand-rolled because a calendar is arithmetic once the leap-year rule is
/// stated: `civil_from_days` is Howard Hinnant's, and `ks-engine` keeps its
/// dependencies to the two it already needs.
pub fn rfc3339(at: SystemTime) -> String {
    let seconds = at.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    let rest = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// The proleptic Gregorian date `days` after 1970-01-01, as `(year, month,
/// day)`. Era-based, so it never depends on how many days a month has.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_of_year = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_of_year + 2) / 5 + 1;
    let month = if month_of_year < 10 { month_of_year + 3 } else { month_of_year - 9 };
    (
        if month <= 2 { year_of_era + era * 400 + 1 } else { year_of_era + era * 400 },
        month as u32,
        day as u32,
    )
}

/// The exact inverse of [`civil_from_days`]: days since 1970-01-01 for a
/// proleptic Gregorian date. Same post, same era arithmetic — the two have to
/// round-trip, which is why they sit next to each other rather than one of
/// them being rewritten.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 }.div_euclid(400);
    let year_of_era = year - era * 400; // [0, 399]
    let month_of_year = if month > 2 { month - 3 } else { month + 9 }; // [0, 11]
    let day_of_year = (153 * month_of_year + 2) / 5 + day - 1; // [0, 365]
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse of [`rfc3339`]: `2023-11-14T22:13:20Z` as a [`SystemTime`].
///
/// The UTC `Z` form only, because that is all [`rfc3339`] writes and a record
/// is read back by the same code that wrote it. `None` for anything else — a
/// malformed `expires_at` is a decode failure, never a silent default, since
/// defaulting would turn "the approval's end is unreadable" into "the approval
/// never expires".
fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let bytes = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| -> Option<i64> { text.get(range)?.parse().ok() };
    let laid_out = matches!(bytes.get(4), Some(b'-'))
        && matches!(bytes.get(7), Some(b'-'))
        && matches!(bytes.get(10), Some(b'T'))
        && matches!(bytes.get(13), Some(b':'))
        && matches!(bytes.get(16), Some(b':'))
        && matches!(bytes.get(19), Some(b'Z'));
    if bytes.len() != 20 || !laid_out {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let (hour, minute, second) = (digits(11..13)?, digits(14..16)?, digits(17..19)?);
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Day-of-month is checked against the month's length, so `2026-02-30` is
    // refused rather than read as the 2nd of March.
    let length = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(year) => 29,
        _ => 28,
    };
    if day > length {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    if seconds < 0 {
        return None;
    }
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))
}

/// The proleptic Gregorian leap rule: divisible by 4, except centuries,
/// except every 400th.
fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
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

/// An approval a run received, bound to the step it unblocks **and** to the
/// exact artifacts it was given for.
///
/// The two extra fields are what an approval that expired or was given for a
/// rebuilt image has to be caught by: an approval is a statement about specific
/// bytes at a specific time, so both travel with it — through the
/// [`StateStore`] with everything else, since a parked run is resumed by a
/// different job. A record written before they existed decodes to no artifacts
/// and no expiry — see [`RunState::from_json`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Approval {
    /// The step being approved.
    pub step: String,
    /// Who approved it — a handle, an actor from the `RunContext` port.
    pub by: String,
    /// The exact artifacts the answer was bound to, as
    /// [`recorded_artifacts`](RunState::recorded_artifacts) derived them when
    /// it arrived. Empty for an approval recorded without a binding.
    pub artifacts: Vec<Artifact>,
    /// When the approval stops being good, as the `expires` it was asked under.
    pub expires_at: Option<SystemTime>,
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
    /// The approval a gated step is about to rely on expired before the run
    /// picked up again.
    ApprovalExpired { run: RunId, step: String, by: String, expired_at: SystemTime },
    /// The run holds no approval for the step that gates the artifacts it is
    /// about to use.
    NotApproved { run: RunId, step: String },
    /// An artifact a gated step's approval was bound to is no longer what the
    /// run holds — a rebuilt image, a re-planned plan, or the same bytes
    /// relabelled as something else.
    ArtifactsChanged {
        /// The gate being checked.
        step: String,
        /// The artifact that was approved and is gone, named by kind and
        /// digest: the one the operator has to go and look at.
        artifact: Artifact,
        /// What the run holds now, so the refusal reads as "this became that"
        /// rather than as an unexplained mismatch.
        using: Vec<Artifact>,
    },
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
            ResumeError::ApprovalExpired { run, step, by, expired_at } => write!(
                f,
                "run {run} cannot resume: the approval of {step} by {by} expired at {}; nothing \
                 was deployed — ask for a new approval",
                rfc3339(*expired_at)
            ),
            ResumeError::NotApproved { run, step } => write!(
                f,
                "run {run} holds no approval for {step}; ask for one before the step it gates runs"
            ),
            ResumeError::ArtifactsChanged { step, artifact, using } => {
                write!(
                    f,
                    "an artifact of {step} was approved and is no longer what the run holds: \
                     approved {}, but the run now has {}; nothing was deployed — ask again on \
                     the current artifacts",
                    artifact_label(artifact),
                    if using.is_empty() {
                        "nothing at all".to_string()
                    } else {
                        using.iter().map(artifact_label).collect::<Vec<_>>().join(", ")
                    }
                )
            }
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
    ///
    /// The approval is bound to [`recorded_artifacts`](Self::recorded_artifacts)
    /// as they stand now and never expires; an approval step that was asked
    /// under an `expires:` records both with
    /// [`approve_until`](Self::approve_until).
    pub fn approve(&mut self, step: &str, by: impl Into<String>) -> Result<(), ResumeError> {
        self.record_approval(step, by, None)
    }

    /// [`approve`](Self::approve), recording that the answer expires `expires`
    /// after `now`.
    ///
    /// The clock is a parameter rather than read here: the engine does not read
    /// one, so a test can put an expiry in the past without waiting for it.
    pub fn approve_until(
        &mut self,
        step: &str,
        by: impl Into<String>,
        expires: Duration,
        now: SystemTime,
    ) -> Result<(), ResumeError> {
        let expires_at = now.checked_add(expires);
        self.record_approval(step, by, expires_at)
    }

    /// The body both [`approve`](Self::approve) and
    /// [`approve_until`](Self::approve_until) share.
    ///
    /// What the answer is bound to is *derived* from the record rather than
    /// passed in: the run's own [`recorded_artifacts`](Self::recorded_artifacts)
    /// at the moment the answer arrived. A caller that named the list itself
    /// could bind an approval to something the run never had, and the check at
    /// resume would then be comparing a lie with a lie.
    fn record_approval(
        &mut self,
        step: &str,
        by: impl Into<String>,
        expires_at: Option<SystemTime>,
    ) -> Result<(), ResumeError> {
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
        let artifacts = self.recorded_artifacts();
        self.approvals.push(Approval {
            step: step.to_string(),
            by: by.into(),
            artifacts,
            expires_at,
        });
        self.next = None;
        Ok(())
    }

    /// The artifacts this run has produced: every output value that parses as
    /// a content digest (an image digest, a chart digest) plus every saved
    /// plan's sha256. Where a step ran twice — a rebuild — only its latest
    /// outputs count, so the list follows what the run currently has rather
    /// than what it ever had.
    ///
    /// Sorted by digest, so the same run always derives the same list and a
    /// comparison never turns on the order outputs happened to be recorded in.
    pub fn recorded_artifacts(&self) -> Vec<Artifact> {
        let mut artifacts = Vec::new();
        for (index, step) in self.completed.iter().enumerate() {
            // A step that ran twice has two records, and only the later one is
            // what the run has now: a rebuild supersedes the build before it,
            // which is exactly the difference the binding has to notice.
            if self.completed[index + 1..].iter().any(|later| later.name == step.name) {
                continue;
            }
            for (key, value) in &step.outputs {
                // An output that is not a digest is not an artifact: a version
                // string or a tag has nothing an approval could bind to.
                if let Ok(digest) = ContentDigest::parse(value) {
                    artifacts.push(Artifact::new(ArtifactKind::Other(key.clone()), digest));
                }
            }
            for plan in &step.plans {
                // A plan's digest is recorded by [`save_plan`], which hashed
                // the bytes itself, and [`from_json`](Self::from_json) refuses
                // a record whose digest is not one — so this only drops a plan
                // a caller built in memory by hand, never one read back from a
                // parked record.
                if let Ok(digest) = ContentDigest::sha256_from_hex(&plan.sha256) {
                    artifacts.push(Artifact::new(ArtifactKind::PlanFile, digest));
                }
            }
        }
        artifacts.sort_by_key(|artifact| artifact.digest.to_string());
        artifacts
    }

    /// Whether the approval of `approval_step` still covers the artifacts this
    /// run now has — the check [`resume`] makes before it releases anything
    /// through it.
    ///
    /// The binding is a *subset* rule, not equality: every artifact the
    /// approval was given for must still be among the run's. Re-deriving with
    /// [`recorded_artifacts`](Self::recorded_artifacts) and comparing whole
    /// [`Artifact`]s catches a rebuilt image or a re-planned plan — a rebuild
    /// replaces artifact A with artifact B, so A is gone and this refuses with
    /// [`ResumeError::ArtifactsChanged`], naming the artifact by kind and
    /// digest and saying nothing was deployed. An artifact *added* after the
    /// answer does not invalidate anything that was approved, which is what
    /// lets the step the approval granted go on to produce output of its own.
    ///
    /// The comparison is on the whole artifact, kind included, because that is
    /// what an approval is bound to: the approver was shown a *plan file*, and
    /// a digest that reappears under a different kind is a different thing
    /// wearing the same hex. Treating the kind as display metadata — which this
    /// used to do — makes the binding satisfiable by a relabelled artifact, so
    /// the thing that runs is not the thing that was shown. This is the
    /// check the port already demands of a verdict
    /// ([`ApprovalRequest::accepts`](ks_core::ports::approval::ApprovalRequest::accepts));
    /// the record has moved on since the answer, and resume is where that has
    /// to be noticed.
    pub fn check_bound(&self, approval_step: &str) -> Result<(), ResumeError> {
        let Some(approval) = self.approvals.iter().find(|approval| approval.step == approval_step)
        else {
            return Err(ResumeError::NotApproved {
                run: self.run.clone(),
                step: approval_step.to_string(),
            });
        };
        // Subset, not equality: what the approval was given for has to still be
        // there. The gated step may have produced more since — that is the
        // approval doing its job, not the ground shifting under it — but a
        // rebuild replaces the approved artifact rather than adding to it, and
        // that is a change the approver never saw.
        let using = self.recorded_artifacts();
        let Some(artifact) = approval.artifacts.iter().find(|artifact| !using.contains(artifact))
        else {
            return Ok(());
        };
        Err(ResumeError::ArtifactsChanged {
            step: approval_step.to_string(),
            artifact: artifact.clone(),
            using,
        })
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
            "approvals": self.approvals.iter().map(|a| json!({
                "step": a.step,
                "by": a.by,
                "artifacts": a.artifacts.iter().map(|artifact| json!({
                    "kind": artifact_kind(&artifact.kind),
                    "digest": artifact.digest.to_string(),
                })).collect::<Vec<_>>(),
                "expires_at": a.expires_at.map(rfc3339),
            })).collect::<Vec<_>>(),
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
                let name = step
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("a completed step has no `name`".to_string()))?
                    .to_string();
                let plans = match step.get("plans").and_then(Value::as_array) {
                    Some(plans) => plans
                        .iter()
                        .map(|p| {
                            let sha256 = text(p, "sha256");
                            // A digest that is not 64 lowercase hex characters is
                            // a corrupt record, not an empty binding. Decoding it
                            // as a plan with no digest would leave
                            // `recorded_artifacts` to drop it, quietly shrinking
                            // the set every approval is checked against — so a
                            // truncated or tampered record would make a *changed*
                            // plan look unchanged. Fail here instead.
                            ContentDigest::sha256_from_hex(&sha256).map_err(|error| {
                                bad(format!(
                                    "step {name} recorded the plan sha256 {sha256:?}, which is not \
                                     a sha256 digest ({error})"
                                ))
                            })?;
                            Ok(PlanRef { step: text(p, "step"), sha256 })
                        })
                        .collect::<Result<Vec<_>, ResumeError>>()?,
                    None => Vec::new(),
                };
                Ok(CompletedStep {
                    name,
                    outputs: strings_of(step.get("outputs"))
                        .map_err(|reason| bad(format!("a completed step's `outputs`: {reason}")))?,
                    plans,
                })
            })
            .collect::<Result<Vec<_>, ResumeError>>()?;
        let approvals: Vec<Approval> = list("approvals")
            .iter()
            .map(|a| {
                Ok(Approval {
                    step: text(a, "step"),
                    by: text(a, "by"),
                    artifacts: artifacts_of(a.get("artifacts"))
                        .map_err(|reason| bad(format!("an approval's `artifacts`: {reason}")))?,
                    expires_at: match a.get("expires_at") {
                        // Absent or null: a record written before approvals
                        // carried an expiry, which is one that never expires.
                        None | Some(Value::Null) => None,
                        Some(value) => {
                            let at = value.as_str().unwrap_or_default();
                            Some(parse_rfc3339(at).ok_or_else(|| {
                                bad(format!("`expires_at` is {at:?}, not an RFC 3339 instant"))
                            })?)
                        }
                    },
                })
            })
            .collect::<Result<Vec<_>, ResumeError>>()?;
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

/// An [`ArtifactKind`] as one string, so a record carries the discriminant and
/// `Other`'s name without the two being told apart by how they are spelled.
fn artifact_kind(kind: &ArtifactKind) -> String {
    match kind {
        ArtifactKind::PlanFile => "PlanFile".to_string(),
        ArtifactKind::Image => "Image".to_string(),
        ArtifactKind::Other(name) => format!("other:{name}"),
    }
}

/// The [`ArtifactKind`] [`artifact_kind`] wrote; `None` for anything else, so
/// a record from a build that speaks another vocabulary is refused rather than
/// read as a kind it never meant.
fn parse_artifact_kind(text: &str) -> Option<ArtifactKind> {
    match text {
        "PlanFile" => Some(ArtifactKind::PlanFile),
        "Image" => Some(ArtifactKind::Image),
        _ => text.strip_prefix("other:").map(|name| ArtifactKind::Other(name.to_string())),
    }
}

/// An [`Artifact`] as one phrase an operator can act on: the kind in words and
/// the digest, so a refusal names *which* thing to go and look at rather than
/// a hex string that could be any of several — ``plan file sha256:…``,
/// ``image sha256:…``, ```output `sbom` sha256:…```.
fn artifact_label(artifact: &Artifact) -> String {
    let kind = match &artifact.kind {
        ArtifactKind::PlanFile => "plan file".to_string(),
        ArtifactKind::Image => "image".to_string(),
        ArtifactKind::Other(name) => format!("output `{name}`"),
    };
    format!("{kind} {}", artifact.digest)
}

/// The artifacts an approval is bound to. Absent decodes to none — a record
/// parked before the binding existed binds nothing — while a list that does not
/// read as artifacts is a decode error rather than a silently emptied one.
fn artifacts_of(value: Option<&Value>) -> Result<Vec<Artifact>, String> {
    let entries = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(value) => value.as_array().ok_or("`artifacts` is not a list")?,
    };
    entries
        .iter()
        .map(|entry| {
            let kind = entry
                .get("kind")
                .and_then(Value::as_str)
                .and_then(parse_artifact_kind)
                .ok_or("an artifact has no `kind` this build reads")?;
            let digest = entry
                .get("digest")
                .and_then(Value::as_str)
                .and_then(|at| ContentDigest::parse(at).ok())
                .ok_or("an artifact has no `digest` this build reads")?;
            Ok(Artifact::new(kind, digest))
        })
        .collect()
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
/// [`fetch_plan`]'s hash check rather than applying something else. The
/// [`PLAN_KEY_PREFIX`] namespace is also what makes the blob
/// [`Sensitivity::Secretish`], so
/// plan bytes are stored owner-only (#122).
pub fn plan_key(sha256: &str) -> String {
    format!("{PLAN_KEY_PREFIX}{sha256}")
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
    store.put(run, &plan_key(&sha256), bytes).await?;
    Ok(PlanRef { step: step.to_string(), sha256 })
}

/// Writes `state`'s record under [`STATE_KEY`], overwriting whatever was parked
/// before — parking twice is how a run advances.
pub async fn park(store: &dyn StateStore, state: &RunState) -> Result<(), ResumeError> {
    let bytes = serde_json::to_vec(&state.to_json())
        .map_err(|error| ResumeError::Store { message: error.to_string() })?;
    store.put(&state.run, STATE_KEY, &bytes).await?;
    Ok(())
}

/// Loads `run`'s parked record and re-verifies its binding: nothing parked is
/// [`ResumeError::NotFound`], a `ship_ks_source` that no longer hashes to
/// [`RunState::file_sha256`] is [`ResumeError::FileChanged`], and an approval
/// that has expired or no longer covers what the run holds is refused — see
/// [`resume_at`], which this is.
pub async fn resume(
    store: &dyn StateStore,
    run: &RunId,
    ship_ks_source: &[u8],
) -> Result<RunState, ResumeError> {
    resume_at(store, run, ship_ks_source, SystemTime::now()).await
}

/// [`resume`], deciding expiry against `now` instead of the wall clock, so a
/// test can put an approval's expiry in the past without waiting for it.
///
/// Expiry is judged here rather than when the approval was recorded, because
/// the two happen in different jobs: an answer given at 09:00 for one hour is
/// still good when the run picks up at 09:30 and is not at 10:01, and only the
/// resume knows which.
pub async fn resume_at(
    store: &dyn StateStore,
    run: &RunId,
    ship_ks_source: &[u8],
    now: SystemTime,
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
    for approval in &state.approvals {
        // Expiry before binding: an approval that ran out of time is refused
        // for that reason whatever the run now holds, and the message names
        // the time it lapsed.
        if let Some(expired_at) = approval.expires_at
            && now >= expired_at
        {
            return Err(ResumeError::ApprovalExpired {
                run: run.clone(),
                step: approval.step.clone(),
                by: approval.by.clone(),
                expired_at,
            });
        }
        // The step name is cloned so the borrow of `approvals` does not reach
        // into `check_bound`'s `&self`.
        let step = approval.step.clone();
        state.check_bound(&step)?;
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
    write_atomically(dest, &bytes, Sensitivity::Secretish).map_err(|error| {
        ResumeError::PlanWrite { dest: dest.display().to_string(), message: error.to_string() }
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
#[derive(Debug, Clone)]
pub struct LocalStateStore {
    root: PathBuf,
}

impl LocalStateStore {
    /// A store rooted at `root`; nothing is created until the first write.
    pub fn new(root: impl Into<PathBuf>) -> LocalStateStore {
        LocalStateStore { root: root.into() }
    }

    /// The directory holding `run`'s objects.
    pub fn run_dir(&self, run: &RunId) -> PathBuf {
        self.root.join(".keepshipping").join("runs").join(run.as_str())
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
///
/// The temp file is created with `sensitivity`'s mode rather than tightened
/// afterwards: the rename is what publishes the object, so setting the mode
/// before it means there is no window in which plan bytes sit under the umask
/// (#122).
fn write_atomically(path: &Path, bytes: &[u8], sensitivity: Sensitivity) -> std::io::Result<()> {
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
        let mut file = create_with_mode(&temp, sensitivity)?;
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

/// Creates `path` — a fresh temporary file, so the mode is this call's and the
/// umask cannot take it away.
#[cfg(unix)]
fn create_with_mode(path: &Path, sensitivity: Sensitivity) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(sensitivity.file_mode())
        .open(path)
}

/// Where there are no unix modes the file is created as the platform would; an
/// adapter on a non-local backend must encrypt at rest instead (#122).
#[cfg(not(unix))]
fn create_with_mode(path: &Path, _sensitivity: Sensitivity) -> std::io::Result<std::fs::File> {
    std::fs::File::create(path)
}

/// Restricts `dir` to its owner, so the names of the blobs inside it are not
/// enumerable by another local user.
#[cfg(unix)]
fn owner_only_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(SENSITIVE_DIR_MODE))
}

/// No-op where there are no unix modes.
#[cfg(not(unix))]
fn owner_only_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Restricts an already-written blob to its owner, for a read that finds one
/// left wider than it should be — written before the mode was set, or by hand.
/// Best effort: a resume must not fail because a file it is only reading could
/// not be chmod-ed.
fn tighten(path: &Path, sensitivity: Sensitivity) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if sensitivity == Sensitivity::Secretish {
            let _ = std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(sensitivity.file_mode()),
            );
        }
    }
    #[cfg(not(unix))]
    let _ = (path, sensitivity);
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
    ) -> BoxFuture<'a, Result<(), StateError>> {
        let result = (|| {
            reject_key(key)?;
            let sensitivity = Sensitivity::of_key(key);
            let dir = self.run_dir(run);
            std::fs::create_dir_all(&dir).map_err(|error| unavailable(&dir, error))?;
            // A secretish blob's directory is owner-only, so an inherited umask
            // cannot leave the plan files inside it enumerable (#122).
            if sensitivity == Sensitivity::Secretish {
                owner_only_dir(&dir).map_err(|error| unavailable(&dir, error))?;
            }
            let final_path = dir.join(key);
            write_atomically(&final_path, bytes, sensitivity)
                .map_err(|error| unavailable(&final_path, error))
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
                Ok(bytes) => {
                    tighten(&path, Sensitivity::of_key(key));
                    Ok(Some(bytes))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(unavailable(&path, error)),
            }
        })();
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

    /// A `sha256:` digest as an output value would be reported in.
    fn digest_of(hex: char) -> String {
        format!("sha256:{}", hex.to_string().repeat(64))
    }

    /// A run parked at `at`, having built an image with digest `hex`.
    fn a_run_that_built(hex: char) -> RunState {
        let mut state = RunState::new(RunId::from_parts(0, 1), b"ship.ks", "push");
        state.record(CompletedStep {
            name: "build".to_string(),
            outputs: BTreeMap::from([
                ("digest".to_string(), digest_of(hex)),
                // Not a digest: a tag is mutable policy, not an artifact an
                // approval could bind to, so it contributes nothing.
                ("tag".to_string(), "v1".to_string()),
            ]),
            plans: Vec::new(),
        });
        state.park_at("review").expect("the run parks at the approval");
        state
    }

    #[test]
    fn a_record_round_trips_and_only_the_parked_step_can_be_approved() {
        let mut state = a_run();
        assert_eq!(RunState::from_json(&state.to_json()).expect("the record decodes"), state);
        state.park_at("tofu.apply").expect("the run parks at a step it has not run");
        assert!(state.approve("tofu.plan", "ada").is_err(), "a completed step cannot be approved");
        state.approve("tofu.apply", "ada").expect("the run is parked there");
        assert_eq!(
            state.approvals,
            vec![Approval {
                step: "tofu.apply".into(),
                by: "ada".into(),
                // `approve` binds what the run has and never expires; the
                // `expires_at` shape matters more than its value here.
                artifacts: state.recorded_artifacts(),
                expires_at: None,
            }]
        );
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
    fn an_approval_is_bound_to_what_the_run_had_when_it_was_given() {
        let mut state = a_run_that_built('a');
        state.approve("review", "ada").expect("the run is parked at the approval");

        // The binding is derived from the record, not supplied by the caller,
        // so it is exactly what the run held at that moment — and a tag, which
        // is not a digest, is not in it.
        assert_eq!(state.approvals[0].artifacts, state.recorded_artifacts());
        assert_eq!(state.approvals[0].artifacts.len(), 1, "the image digest and nothing else");
        assert_eq!(
            state.approvals[0].artifacts[0].digest.to_string(),
            digest_of('a'),
            "the digest the approval is bound to"
        );
        assert_eq!(state.approvals[0].expires_at, None, "`approve` records no expiry");
    }

    #[test]
    fn a_rebuild_after_the_approval_refuses_the_deploy() {
        let mut state = a_run_that_built('a');
        state.approve("review", "ada").expect("the run is parked at the approval");

        // The same step name, a new digest: a rebuild. Only the later record
        // counts, so the run now holds image b and no longer the image that
        // was approved. The binding asks whether a is still there, and it is
        // not — a rebuild replaces what was approved rather than adding to it.
        state.record(CompletedStep {
            name: "build".to_string(),
            outputs: BTreeMap::from([("digest".to_string(), digest_of('b'))]),
            plans: Vec::new(),
        });

        let error = state.check_bound("review").expect_err("the image was rebuilt");
        assert!(matches!(error, ResumeError::ArtifactsChanged { .. }), "{error:?}");
        let message = error.to_string();
        for fragment in ["review", &digest_of('a'), &digest_of('b'), "nothing was deployed"] {
            assert!(message.contains(fragment), "{fragment} missing from {message}");
        }
        // Both lists are named, so whoever reads the refusal can see which is
        // which without re-deriving anything.
        assert!(message.contains("ask again"), "{message}");
    }

    #[test]
    fn an_artifact_the_approval_granted_the_run_to_produce_does_not_invalidate_it() {
        let mut state = a_run_that_built('a');
        state.approve("review", "ada").expect("the run is parked at the approval");

        // The step the approval unblocks then produces output of its own — the
        // receipt, the digest of what it pushed. Adding to what the run holds
        // takes nothing away from what was approved, so the binding is
        // untouched and the multi-stage run carries on rather than refusing a
        // deploy the approver asked for.
        state.record(CompletedStep {
            name: "deploy".to_string(),
            outputs: BTreeMap::from([("receipt".to_string(), digest_of('c'))]),
            plans: Vec::new(),
        });

        assert!(state.check_bound("review").is_ok(), "the approved image is still held");
        assert!(
            state.recorded_artifacts().iter().any(|a| a.digest.to_string() == digest_of('c')),
            "and the new artifact really is one the run holds"
        );
    }

    #[test]
    fn a_rebuild_after_the_approval_refuses_the_deploy_however_much_the_run_added_since() {
        let mut state = a_run_that_built('a');
        state.approve("review", "ada").expect("the run is parked at the approval");

        // Both at once: the build runs again for another image *and* the gated
        // step records its own artifact. The extra artifact does not rescue
        // the run, because a is still the digest that went missing.
        state.record(CompletedStep {
            name: "build".to_string(),
            outputs: BTreeMap::from([("digest".to_string(), digest_of('b'))]),
            plans: Vec::new(),
        });
        state.record(CompletedStep {
            name: "deploy".to_string(),
            outputs: BTreeMap::from([("receipt".to_string(), digest_of('c'))]),
            plans: Vec::new(),
        });

        let error = state.check_bound("review").expect_err("the approved image is gone");
        assert!(matches!(error, ResumeError::ArtifactsChanged { .. }), "{error:?}");
        match &error {
            ResumeError::ArtifactsChanged { step, artifact, using } => {
                assert_eq!(step, "review");
                // Named by kind as well as digest: the refusal has to say *what*
                // moved, or the operator is left hunting through hex.
                assert_eq!(artifact.kind, ArtifactKind::Other("digest".to_string()));
                assert_eq!(artifact.digest.to_string(), digest_of('a'), "what was approved");
                // The run holds b and c, and names both, so the reader can see
                // that adding to the list did not bring a back.
                assert_eq!(
                    using.iter().map(|held| held.digest.to_string()).collect::<Vec<_>>(),
                    vec![digest_of('b'), digest_of('c')]
                );
            }
            other => panic!("a rebuilt image must be ArtifactsChanged, got {other:?}"),
        }
        let message = error.to_string();
        for fragment in ["review", &digest_of('a'), "nothing was deployed", "ask again"] {
            assert!(message.contains(fragment), "{fragment} missing from {message}");
        }
    }

    #[test]
    fn a_step_with_no_approval_is_not_approved() {
        let state = a_run_that_built('a');
        let error = state.check_bound("review").expect_err("nothing was approved");
        assert!(matches!(error, ResumeError::NotApproved { .. }), "{error:?}");
        let message = error.to_string();
        assert!(message.contains("review") && message.contains("ask for one"), "{message}");
    }

    #[test]
    fn the_binding_and_the_expiry_survive_being_parked() {
        let expires = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut state = a_run_that_built('a');
        state
            .approve_until("review", "ada", Duration::from_secs(3600), SystemTime::UNIX_EPOCH)
            .expect("the run is parked at the approval");
        // An adapter-named kind, whose name is only in the string, so the
        // round trip has to carry it or the artifact comes back anonymous.
        state.approvals[0].artifacts.push(Artifact::new(
            ArtifactKind::Other("sbom".to_string()),
            ContentDigest::sha256_from_hex(&"b".repeat(64)).expect("64 hex digits"),
        ));
        state.approvals[0].expires_at = Some(expires);

        let decoded = RunState::from_json(&state.to_json()).expect("the record decodes");
        assert_eq!(decoded.approvals[0].artifacts, state.approvals[0].artifacts, "the binding");
        assert_eq!(decoded.approvals[0].expires_at, Some(expires), "the expiry");
        assert_eq!(
            decoded.approvals[0].artifacts.last().map(|a| &a.kind),
            Some(&ArtifactKind::Other("sbom".to_string())),
            "the adapter's own name survives being parked"
        );
    }

    #[test]
    fn a_record_parked_before_the_binding_existed_still_decodes() {
        // What a build without `artifacts`/`expires_at` wrote. It must decode
        // cleanly rather than refuse: a run parked under an older build is
        // still a run.
        let mut value = a_run().to_json();
        value["approvals"] = json!([{ "step": "review", "by": "ada" }]);
        let decoded = RunState::from_json(&value).expect("an older record still decodes");
        assert_eq!(decoded.approvals[0].step, "review");
        assert_eq!(decoded.approvals[0].by, "ada");
        assert!(decoded.approvals[0].artifacts.is_empty(), "no binding was recorded");
        assert_eq!(decoded.approvals[0].expires_at, None, "and no expiry");

        // An expiry that does not parse is a different matter: defaulting it
        // to None would turn an unreadable end into "never expires".
        value["approvals"] = json!([{ "step": "review", "by": "ada", "expires_at": "soon" }]);
        let error = RunState::from_json(&value).expect_err("a malformed expiry");
        assert!(matches!(error, ResumeError::Decode { .. }), "{error:?}");
        assert!(error.to_string().contains("expires_at"), "{error}");
    }

    #[test]
    fn rfc3339_reads_back_what_it_wrote() {
        // The parser exists to undo the writer, so it is tested against the
        // writer rather than against hand-written stamps.
        for seconds in [0u64, 1, 86_399, 86_400, 951_782_400, 1_788_000_000] {
            let at = SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
            assert_eq!(parse_rfc3339(&rfc3339(at)), Some(at), "{}", rfc3339(at));
        }
        // A leap day, the case a hand-rolled calendar gets wrong first, and
        // 30 February, which is not a date at all.
        let leap = SystemTime::UNIX_EPOCH + Duration::from_secs(1_709_164_800);
        assert_eq!(rfc3339(leap), "2024-02-29T00:00:00Z");
        assert_eq!(parse_rfc3339("2024-02-29T00:00:00Z"), Some(leap));
        assert_eq!(parse_rfc3339("2023-02-29T00:00:00Z"), None, "2023 was not a leap year");
        assert_eq!(parse_rfc3339("2026-04-31T00:00:00Z"), None, "April has 30 days");
        for bad in ["", "2026-10-08", "2026-10-08 00:00:00Z", "2026-10-08T00:00:00+01:00", "soon"] {
            assert_eq!(parse_rfc3339(bad), None, "{bad:?} is not an instant");
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
