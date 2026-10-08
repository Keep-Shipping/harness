//! The approver-facing commands ([#95](https://github.com/Keep-Shipping/harness/issues/95)):
//! `keepshipping runs pending`, `keepshipping approve RUN-ID` and `keepshipping deny RUN-ID`.
//!
//! A run parks itself when a step needs a person. These three commands are how that person finds
//! the run and answers it:
//!
//! - `keepshipping runs pending` — one line per run waiting on a person, so the queue is visible
//!   from a terminal without knowing any run id;
//! - `keepshipping approve <RUN-ID> [--comment TEXT]` — release the parked step and record the
//!   approval;
//! - `keepshipping deny <RUN-ID> --reason TEXT` — refuse it, and say why.
//!
//! **There is deliberately no `--as`.** The approver is taken from the environment the person is
//! already in, not from an argument they could type. A self-declared approver is exactly what the
//! approval port (`ks_core::ports::approval`) exists to prevent: an agent that could pass
//! `--as ada` would approve on Ada's behalf, and the name in the run log would mean nothing. The
//! name recorded here is a *label for the run log, not a credential* — see [`local_user`].
//!
//! The state is read through the engine's [`LocalStateStore`] rather than
//! `ks_engine::state::resume`: `resume` re-hashes the original `ship.ks` to prove the file has not
//! changed since the run started, and this command has no such bytes. Reading the record directly
//! is honest about what it is doing — approving what is parked, not resuming the run. The engine,
//! when it next picks the run up, re-checks the file itself.
//!
//! A refusal does not advance the run. [`RunState`] has an `approve` and no `deny`, and what a
//! refusal means to a running engine is the engine's business, not this command's: the parked
//! record is left exactly as it was, and the durable part — that a person said no, and who — goes
//! into the run's hash-chained log as `approval.denied`.
//!
//! Exit codes follow the house rules: 0 for a command that did what it was asked, 2 for usage and
//! for a run that is not there or is not waiting.
//!
//! **What these commands do not guarantee.** Nothing here is serialised against another process.
//! Two people answering the same parked run at the same moment can both see `approved`, both have
//! an `approval.granted` in the log, and only one of those approvals survives in `state.json` — the
//! read-modify-write below takes no lock, and [`LocalStateStore`] does not have one to take. And a
//! run log is not safe against concurrent writers either: [`JsonlRunLog`] guards its tip with an
//! in-process mutex only, so approvals and refusals landing at the same instant can fork the hash
//! chain that `log verify` later rejects. Serialising this needs a cross-process lock on the
//! state and the log, which is work for whoever owns those ports, not a patch here.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use ks_core::ids::RunId;
use ks_core::ports::run_log::{RunEvent, RunLog};
use ks_core::ports::state_store::StateStore;
use ks_engine::state::{LocalStateStore, RunState, STATE_KEY};

use crate::args::USAGE;
use crate::run_log::{JsonlRunLog, RUNS_DIR, SystemClock};

/// The channel these decisions came through. The local channel binds nothing: there are no
/// artifacts to attach, and inventing a digest for an event that has no such artifact would be a
/// lie the log could never be caught on.
const CHANNEL: &str = "local";

/// One of the three commands, with its arguments already read.
enum Cmd {
    /// List the runs parked waiting for a person.
    Pending,
    /// Release `run`'s parked step.
    Approve { run: RunId, comment: Option<String> },
    /// Refuse `run`'s parked step, and say why.
    Deny { run: RunId, reason: String },
}

/// The entry point for `keepshipping runs pending|approve|deny`.
pub fn approve(args: &[String]) -> ExitCode {
    let Some(cmd) = parse(args) else { return usage() };
    match cmd {
        Cmd::Pending => pending(),
        Cmd::Approve { run, comment } => grant(&run, comment.as_deref()),
        Cmd::Deny { run, reason } => refuse(&run, &reason),
    }
}

/// `runs pending`, `approve RUN-ID [--comment TEXT]`, `deny RUN-ID --reason TEXT`, or `None` if
/// these are not one of those.
///
/// `deny` insists on a reason. A refusal is the answer that stops a run, so it has to be a
/// *considered* one, and asking the person to type why is what forces the moment of considering it;
/// a bare `no` is one keystroke and no thought. What the reason is not, today, is a durable record:
/// the reason is printed back to the operator, and the durable part is the `approval.denied` run-log
/// event — which names the person and the step but has no field for the reason itself, because
/// [`RunEvent`] is a shared port enum and one command's convenience is not worth changing it. The
/// honest statement is that `approval.denied` records *that* the run was refused and by whom, not
/// why. `--reason` with nothing after it is a typo that would otherwise read as a refusal.
///
/// `--comment` is optional, but `--comment` with no value fails the parse rather than quietly
/// approving without one.
fn parse(args: &[String]) -> Option<Cmd> {
    match args.first().map(String::as_str)? {
        "runs" => (args.len() == 2 && args[1] == "pending").then_some(Cmd::Pending),
        "approve" => {
            let run = RunId::parse(args.get(1)?).ok()?;
            let comment = match &args[2..] {
                [] => None,
                [flag, rest @ ..] if flag == "--comment" => Some(value(rest)?),
                _ => return None,
            };
            Some(Cmd::Approve { run, comment })
        }
        "deny" => {
            let run = RunId::parse(args.get(1)?).ok()?;
            let reason = match &args[2..] {
                [flag, rest @ ..] if flag == "--reason" => value(rest)?,
                _ => return None,
            };
            Some(Cmd::Deny { run, reason })
        }
        _ => None,
    }
}

/// The single value that follows a flag, or `None` if there is none or it is itself a flag:
/// `approve <run> --comment --as` is a typo, not a run whose comment is the string `--as`.
fn value(rest: &[String]) -> Option<String> {
    match rest {
        [text] if !text.starts_with('-') => Some(text.clone()),
        _ => None,
    }
}

/// `runs pending`: the runs parked on a person, one line each — the run id, the step it waits on,
/// and where it is going. Sorted by run id, so the same queue prints the same way twice.
fn pending() -> ExitCode {
    let store = LocalStateStore::new(std::env::current_dir().unwrap_or_default());
    // No `.keepshipping/runs` means nothing has ever run here. That is an empty queue, not a
    // failure.
    let Ok(entries) = std::fs::read_dir(Path::new(RUNS_DIR)) else {
        println!("nothing is waiting for approval");
        return ExitCode::SUCCESS;
    };
    let mut lines: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        // A run's directory is named for its id; anything else in there is not a parked run.
        let Some(run) = entry.file_name().to_str().and_then(|name| RunId::parse(name).ok()) else {
            continue;
        };
        // A record that cannot be read is not one this listing can say anything useful about.
        let Ok(Some(bytes)) = wait(store.get(&run, STATE_KEY)) else { continue };
        let Some(state) = decode(&bytes) else { continue };
        let Some(step) = state.next.as_deref() else { continue };
        // Where the run is going, if the record says: the environment it resolved at the start,
        // else the trigger it started from.
        let where_to = state
            .context
            .get("environment")
            .or_else(|| state.context.get("env"))
            .map_or(state.event.as_str(), String::as_str);
        lines.push(format!("{run}  {step:<12}  {where_to}"));
    }
    if lines.is_empty() {
        println!("nothing is waiting for approval");
        return ExitCode::SUCCESS;
    }
    lines.sort();
    for line in lines {
        println!("{line}");
    }
    ExitCode::SUCCESS
}

/// `approve RUN-ID [--comment TEXT]`: record the approval, clear the park, and say so. The log entry
/// comes first, chained off whatever tip the run's file already has, and the state write second.
///
/// The order matters and it is the log-first order. A logged approval for a run that is still
/// parked is *recoverable*: run `approve` again and it records the state. A state that says
/// approved with nothing in the log is not — the run is no longer waiting, so the re-run refuses
/// with "is not waiting for approval", and the hash-chained audit record permanently lacks the
/// `approval.granted` entry with no way to append it. So if the state write fails below, the log
/// says the honest thing and the run says no; that is recoverable, the other way round is not.
fn grant(run: &RunId, comment: Option<&str>) -> ExitCode {
    let Some((store, mut state)) = read_parked(run) else { return ExitCode::from(2) };
    let Some(step) = waiting(&state) else { return ExitCode::from(2) };
    let step = step.to_string();
    let who = local_user();
    // `approve` re-checks that the run really is parked at this step, so a run that moved between
    // the listing and this command is refused rather than advanced. This is validation, not the
    // write: it happens before anything is appended, so a run that is not parked logs nothing.
    if let Err(error) = state.approve(&step, who.clone()) {
        eprintln!("error: {error}");
        return ExitCode::from(2);
    }
    let granted = RunEvent::ApprovalGranted {
        step: step.clone(),
        approver: who.clone(),
        channel: CHANNEL.into(),
        artifacts: Vec::new(),
    };
    if let Err(error) = record(&state.run, granted) {
        eprintln!("error: the approval could not be written to the run log ({error})");
        return ExitCode::from(2);
    }
    if let Err(error) = wait(ks_engine::state::park(&store, &state)) {
        eprintln!(
            "error: the approval is in the run log but the state could not be updated ({error}); \
             run `approve` again to record it"
        );
        return ExitCode::from(2);
    }
    // The comment is the person's, printed back to them, and that is the whole of what is done
    // with it: the `approval.granted` event has no field for it, and `RunEvent` is a shared port
    // enum — one CLI's convenience is not worth changing it. It is not recorded anywhere.
    match comment {
        Some(comment) => println!("approved {run} at {step} as {who} — {comment}"),
        None => println!("approved {run} at {step} as {who}"),
    }
    ExitCode::SUCCESS
}

/// `deny RUN-ID --reason TEXT`: record the refusal in the run log and leave the run parked.
///
/// The run stays parked because the engine, not this command, decides what a refusal means for the
/// run: a refused step may still be approved later after a fix, and only the engine can tell that
/// from a step that is gone. What this command owns is the durable record — `approval.denied`, in
/// the run's hash-chained log, naming the person and the step — and that the state on disk is
/// exactly what it was, so the run is still the run an approver sees in `runs pending`.
fn refuse(run: &RunId, reason: &str) -> ExitCode {
    let Some((_, state)) = read_parked(run) else { return ExitCode::from(2) };
    let Some(step) = waiting(&state) else { return ExitCode::from(2) };
    let who = local_user();
    let denied = RunEvent::ApprovalDenied {
        step: step.to_string(),
        approver: who.clone(),
        channel: CHANNEL.into(),
        artifacts: Vec::new(),
        reason: reason.to_string(),
    };
    if let Err(error) = record(&state.run, denied) {
        eprintln!("error: the refusal could not be written to the run log ({error})");
        return ExitCode::from(2);
    }
    println!("denied {run} at {step} as {who} — {reason}");
    ExitCode::SUCCESS
}

/// Who the local run is: `$USER`, then `$USERNAME`, then `local` — the same three-line fallback
/// `drive.rs` uses for the person a terminal run asked.
///
/// A name here is a **label for the run log, not a credential**. Nothing is authenticated by it and
/// nothing is unlocked by it: an approval made in this shell is an approval by whoever holds this
/// shell, and the environment variable is simply the name that command has to write down. That is
/// why there is no `--as` — see the module docs. A real approver identity comes from the approval
/// port, which is what `channel` names in the log this is written to.
fn local_user() -> String {
    ["USER", "USERNAME"]
        .into_iter()
        .find_map(|var| std::env::var(var).ok())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "local".to_string())
}

/// The run's parked record and the store it came from, or `None` with the reason already printed:
/// no such run, or a record this build cannot read.
fn read_parked(run: &RunId) -> Option<(LocalStateStore, RunState)> {
    let store = LocalStateStore::new(std::env::current_dir().unwrap_or_default());
    let bytes = match wait(store.get(run, STATE_KEY)) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            eprintln!("error: run {run} has no parked state");
            return None;
        }
        Err(error) => {
            eprintln!("error: the parked state of run {run} cannot be read ({error})");
            return None;
        }
    };
    let Some(state) = decode(&bytes) else {
        eprintln!("error: the parked state of run {run} cannot be read");
        return None;
    };
    // The record was read from `<run>`'s directory but `park` writes to `state.run`. A record whose
    // `run` field names a different run — a hand edit, or a copy of somebody else's directory —
    // would send this approval into that run's state and destroy the record it holds. Refuse
    // before anything is mutated rather than write to the wrong run.
    if state.run != *run {
        eprintln!("error: the parked state in {run} is for run {}", state.run);
        return None;
    }
    Some((store, state))
}

/// The step `state` is parked on, or `None` with the reason already printed. A finished run is not
/// waiting on a person, and a second `approve` must not move it.
fn waiting(state: &RunState) -> Option<&str> {
    if state.next.is_none() {
        eprintln!("error: run {} is not waiting for approval", state.run);
        return None;
    }
    state.next.as_deref()
}

/// The record as JSON, or `None` when the bytes are not a record this build reads. A record whose
/// meaning has moved is refused rather than half-understood.
fn decode(bytes: &[u8]) -> Option<RunState> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    RunState::from_json(&value).ok()
}

/// Appends `event` to `run`'s log, over the file's own tip so the chain continues rather than
/// forking.
fn record(run: &RunId, event: RunEvent) -> Result<(), String> {
    let log = JsonlRunLog::new(PathBuf::from(RUNS_DIR), Arc::new(SystemClock));
    wait(log.append(run, event)).map_err(|e| e.to_string())
}

/// Runs a future to completion. Every port call here does its blocking I/O before the future
/// resolves, so a busy poll on a noop waker terminates. The same shape `blocks.rs` uses, written
/// out again rather than shared, so this module stands on its own.
fn wait<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    loop {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "error: expected `runs pending`, `approve <RUN-ID> [--comment TEXT]` or \
         `deny <RUN-ID> --reason TEXT`"
    );
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec's example ULID, so a parsed id is a known one.
    const RUN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    fn args(text: &[&str]) -> Vec<String> {
        text.iter().map(|s| s.to_string()).collect()
    }

    /// What the parse takes, as (which command, the rest of it), so each row says what it expects
    /// rather than what it happens to hold.
    fn parse_parts(text: &[&str]) -> Option<(String, Option<String>)> {
        match parse(&args(text)) {
            Some(Cmd::Pending) => Some(("pending".into(), None)),
            Some(Cmd::Approve { run, comment }) if run.as_str() == RUN => {
                Some(("approve".into(), comment))
            }
            Some(Cmd::Deny { run, reason }) if run.as_str() == RUN => {
                Some(("deny".into(), Some(reason)))
            }
            Some(_) => None,
            None => None,
        }
    }

    /// The three forms, and the ways of getting them wrong. What must parse: the listing with no
    /// arguments, an approval bare or with a comment, a refusal with its reason. What must not: a
    /// comment or a reason with no value after it, a refusal with no reason at all (the whole point
    /// of `--reason`), a second id, an unknown flag — `--as` especially, which must never parse —
    /// and an id that is not a ULID, since it cannot name a directory.
    #[test]
    fn the_three_forms_and_their_misuse() {
        for (given, command, extra) in [
            (&["runs", "pending"][..], "pending", None),
            (&["approve", RUN][..], "approve", None),
            (&["approve", RUN, "--comment", "ship it"][..], "approve", Some("ship it")),
            (&["deny", RUN, "--reason", "not this week"][..], "deny", Some("not this week")),
        ] {
            let (said, rest) = parse_parts(given).unwrap_or_else(|| panic!("{given:?}"));
            assert_eq!((said.as_str(), rest.as_deref()), (command, extra), "{given:?}");
        }

        for bad in [
            vec![],
            vec!["nope"],
            vec!["runs"],
            vec!["runs", "pending", "extra"],
            vec!["approve"],
            vec!["approve", RUN, "--comment"],
            vec!["approve", RUN, "--comment", "a", "--comment", "b"],
            vec!["approve", RUN, "--as", "ada"],
            vec!["approve", "not-a-ulid"],
            vec!["approve", RUN, RUN],
            vec!["deny"],
            vec!["deny", RUN],
            vec!["deny", RUN, "--reason"],
            vec!["deny", RUN, "--reason", "no", "--reason", "no"],
            vec!["deny", "not-a-ulid", "--reason", "no"],
        ] {
            assert!(parse_parts(&bad).is_none(), "{bad:?} should not parse");
        }
    }

    /// A flag with nothing after it is a typo, and a flag after `--comment` or `--reason` is a
    /// different typo: the next flag is not the value. Without this, `approve <run> --comment --as`
    /// parses, exits 0, and records the approver's comment as the literal string `--as` — the
    /// command taking its own flag as a person's words. A missing value and a flag-shaped value are
    /// the same error: a usage error.
    #[test]
    fn a_value_that_is_itself_a_flag_is_not_a_value() {
        for bad in [
            vec!["approve", RUN, "--comment", "--as"],
            vec!["approve", RUN, "--comment", "-x"],
            vec!["approve", RUN, "--comment", "-"],
            vec!["deny", RUN, "--reason", "--as"],
            vec!["deny", RUN, "--reason", "-x"],
            vec!["deny", RUN, "--reason", "-"],
        ] {
            assert!(parse_parts(&bad).is_none(), "{bad:?} should not parse");
        }

        // And the shapes that must still parse, unchanged.
        assert_eq!(
            parse_parts(&["approve", RUN, "--comment", "ship it"]),
            Some(("approve".into(), Some("ship it".into())))
        );
        assert_eq!(
            parse_parts(&["deny", RUN, "--reason", "not yet"]),
            Some(("deny".into(), Some("not yet".into())))
        );
        assert!(parse_parts(&["approve", RUN]).is_some());
    }

    /// The refusal is required in `parse`, so no path reaches `refuse` with a reason it does not
    /// have, and a `--comment` is carried only as long as it has a value.
    #[test]
    fn a_reason_is_required_and_a_comment_is_optional() {
        assert!(parse_parts(&["deny", RUN]).is_none());
        assert!(parse_parts(&["deny", RUN, "--reason", "no"]).is_some());
        assert!(parse_parts(&["approve", RUN]).is_some());
        assert!(parse_parts(&["approve", RUN, "--comment", "yes"]).is_some());
    }
}
