//! The local [`RunLog`] adapter: one JSONL file per run under `.keepshipping/runs/`, append-only
//! and hash-chained ([#46](https://github.com/Keep-Shipping/harness/issues/46)). One line, one
//! entry, in a sorted key order:
//!
//! ```text
//! {"at":1700000000000,"hash":"…","prev":"…","run":"01H…","seq":0,"type":"run.started", …}
//! ```
//!
//! `seq` counts from zero, `prev` is the previous entry's `hash` (sixty-four zeros for the first),
//! and `hash` is the sha256 of the object *without* `hash`. Every entry therefore names the one
//! before it: editing line 3 changes its hash, deleting it makes line 4 point at the wrong
//! predecessor, reordering two puts each `prev` where it cannot be. [`verify`] reports the first
//! line that does not hold — the one to look at. This is where the chain lives; nothing else
//! restates it. What it cannot see is a truncation from the end, which leaves an intact prefix,
//! nor a writer that recomputes the chain as it goes: both need a signature over the tip
//! ([#112](https://github.com/Keep-Shipping/harness/issues/112)).
//!
//! The hash is over a canonical form with every object's keys sorted by hand: `crates/cli` does not
//! enable `preserve_order`, but a workspace build does (the waitlist venture pulls in `schemars`),
//! so a chain hashed in insertion order would depend on which crates were compiled in.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::clock::Clock;
use ks_core::ports::run_log::{RunEvent, RunLog, RunLogError};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// Where a run's entries live, relative to the directory the run happened in.
pub const RUNS_DIR: &str = ".keepshipping/runs";

/// The `prev` of a run's first entry: nothing came before it.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The host clock, for a run outside a test. Nothing builds this yet — `keepshipping run` does not
/// execute (#45), the same note as `github_actions_run_context` in main.rs applies.
#[allow(dead_code)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep<'a>(&'a self, duration: Duration) -> BoxFuture<'a, ()> {
        Box::pin(async move { std::thread::sleep(duration) })
    }
}

/// The last entry written to a run's file: what the next entry links to.
struct Tip {
    seq: u64,
    hash: String,
}

/// The local [`RunLog`]: a file per run, appended to under a lock. The tip is cached per run, but
/// the cache is filled from whatever is on disk, so a second adapter over the same directory — or a
/// run resumed after the process died — continues the chain rather than forking it.
pub struct JsonlRunLog {
    dir: PathBuf,
    clock: Arc<dyn Clock>,
    tips: Mutex<HashMap<RunId, Tip>>,
}

impl JsonlRunLog {
    /// A log keeping runs in `dir`, timing entries from `clock`.
    #[allow(dead_code)]
    pub fn new(dir: PathBuf, clock: Arc<dyn Clock>) -> JsonlRunLog {
        JsonlRunLog { dir, clock, tips: Mutex::new(HashMap::new()) }
    }

    /// Where `run`'s entries are kept.
    pub fn path_for(dir: &Path, run: &RunId) -> PathBuf {
        dir.join(format!("{run}.jsonl"))
    }

    /// The newest run in `dir`, or `None` when nothing has been logged. A ULID sorts by time, so the
    /// greatest that parses is the most recent.
    pub fn latest(dir: &Path) -> Option<RunId> {
        std::fs::read_dir(dir)
            .ok()?
            .filter_map(|entry| {
                entry.ok()?.path().file_stem()?.to_str().and_then(|s| RunId::parse(s).ok())
            })
            .max()
    }

    fn append_sync(&self, run: &RunId, event: RunEvent) -> Result<(), RunLogError> {
        std::fs::create_dir_all(&self.dir).map_err(backend)?;
        let mut entry = event_fields(&event)?;
        let path = JsonlRunLog::path_for(&self.dir, run);

        // Held across reading the tip and the write that consumes it, so two appends from one
        // process cannot both chain off the same predecessor. A poisoned lock means some earlier
        // append panicked with it held; the log's consistency is no longer ours to vouch for, so
        // this is a backend error rather than a second panic.
        let mut tips = self.tips.lock().map_err(|_| RunLogError::Backend {
            message: "the run log lock was poisoned".into(),
        })?;
        let tip = match tips.get(run) {
            Some(tip) => Tip { seq: tip.seq, hash: tip.hash.clone() },
            None => tip_of(&path)?,
        };

        // The event's own fields went in first, so a reserved key can never be shadowed.
        entry.insert("at".into(), Value::from(unix_millis(self.clock.now())));
        entry.insert("prev".into(), Value::String(tip.hash.clone()));
        entry.insert("run".into(), Value::String(run.to_string()));
        entry.insert("seq".into(), Value::from(tip.seq));
        entry.insert("type".into(), Value::from(event.kind()));
        let hash = sha256_hex(&canonical(&entry));
        entry.insert("hash".into(), Value::String(hash.clone()));

        let mut file = OpenOptions::new().create(true).append(true).open(&path).map_err(backend)?;
        writeln!(file, "{}", canonical(&entry)).map_err(backend)?;
        file.flush().map_err(backend)?;
        tips.insert(run.clone(), Tip { seq: tip.seq + 1, hash });
        Ok(())
    }
}

impl RunLog for JsonlRunLog {
    fn append<'a>(
        &'a self,
        run: &'a RunId,
        event: RunEvent,
    ) -> BoxFuture<'a, Result<(), RunLogError>> {
        // The port is async so an adapter can be; this one does blocking I/O inside `send`, the
        // shape `blocks.rs` drives its futures in.
        Box::pin(async move { self.append_sync(run, event) })
    }
}

/// A chain that does not hold, at the first entry that does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    /// The 1-based line in the file.
    pub line: usize,
    /// Why that line does not hold.
    pub reason: String,
}

/// Checks a run's log, returning how many entries the chain has. A line that does not parse, a
/// `hash` that is not the sha256 of the entry's own contents, a `prev` that does not name the
/// entry above, and a `seq` that is not its position each break the chain at that line. Only the
/// first break is reported — everything after it is a consequence.
pub fn verify(text: &str) -> Result<usize, ChainBreak> {
    let mut prev = GENESIS.to_string();
    let mut entries = 0usize;
    for (n, line) in text.lines().enumerate() {
        let at = n + 1;
        let broken = |reason: String| ChainBreak { line: at, reason };
        let value: Value =
            serde_json::from_str(line).map_err(|e| broken(format!("not a JSON object ({e})")))?;
        let Value::Object(entry) = value else {
            return Err(broken("not a JSON object".to_string()));
        };
        let Some(hash) = entry.get("hash").and_then(Value::as_str).map(str::to_string) else {
            return Err(broken("the entry has no `hash`".to_string()));
        };
        if hash != sha256_hex(&canonical(&without_hash(&entry))) {
            return Err(broken(
                "the entry's contents do not hash to its `hash` — it was edited".to_string(),
            ));
        }
        match entry.get("prev").and_then(Value::as_str) {
            Some(found) if found == prev => {}
            Some(found) => {
                return Err(broken(format!(
                    "`prev` is {found}, not the hash of the entry above it — an entry was deleted, added or moved"
                )));
            }
            None => return Err(broken("the entry has no `prev`".to_string())),
        }
        match entry.get("seq").and_then(Value::as_u64) {
            Some(found) if found == entries as u64 => {}
            Some(found) => return Err(broken(format!("`seq` is {found}, not {entries}"))),
            None => return Err(broken("the entry has no `seq`".to_string())),
        }
        prev = hash;
        entries += 1;
    }
    Ok(entries)
}

/// The fields an event contributes, beside the five every entry carries. An event kind this build
/// does not know is a failure, never a line that silently says nothing.
fn event_fields(event: &RunEvent) -> Result<Map<String, Value>, RunLogError> {
    let mut fields = Map::new();
    let mut put = |key: &str, value: Value| {
        fields.insert(key.into(), value);
    };
    let text = |value: &String| Value::String(value.clone());
    match event {
        RunEvent::RunStarted { file_hash, event, actor, is_agent } => {
            put("file_hash", text(file_hash));
            put("trigger", text(event));
            put("actor", text(actor));
            put("is_agent", Value::from(*is_agent));
        }
        RunEvent::StepStarted { step } => {
            put("step", text(step));
        }
        RunEvent::StepFinished { step, ok, outputs, duration_ms, error } => {
            put("step", text(step));
            put("ok", Value::from(*ok));
            put("outputs", strings(outputs));
            put("duration_ms", Value::from(*duration_ms));
            if let Some(error) = error {
                put("error", text(error));
            }
        }
        RunEvent::ApprovalRequested { step, channel, artifacts } => {
            put("step", text(step));
            put("channel", text(channel));
            put("artifacts", strings(artifacts));
        }
        RunEvent::ApprovalGranted { step, approver, channel, artifacts }
        | RunEvent::ApprovalDenied { step, approver, channel, artifacts } => {
            put("step", text(step));
            put("approver", text(approver));
            put("channel", text(channel));
            put("artifacts", strings(artifacts));
        }
        RunEvent::DecideAnswered {
            step,
            model,
            answer,
            confidence,
            probabilities,
            threshold,
            outcome,
        } => {
            put("step", text(step));
            put("model", text(model));
            put("answer", text(answer));
            put("confidence", number(*confidence));
            put(
                "probabilities",
                Value::Array(
                    probabilities
                        .iter()
                        .map(|(l, p)| json!({"label": l, "p": number(*p)}))
                        .collect(),
                ),
            );
            put("threshold", number(*threshold));
            put("outcome", text(outcome));
        }
        RunEvent::PolicyRefused { step, rule } => {
            if let Some(step) = step {
                put("step", text(step));
            }
            put("rule", text(rule));
        }
        RunEvent::RunFinished { status, shipped } => {
            put("status", text(status));
            put("shipped", strings(shipped));
        }
        other => {
            return Err(RunLogError::Backend {
                message: format!("this build has no wire form for the `{}` event", other.kind()),
            });
        }
    }
    Ok(fields)
}

/// The tail of a file that is already there: the entry the next one links to. A missing or empty
/// file is a fresh run, not a broken one.
fn tip_of(path: &Path) -> Result<Tip, RunLogError> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(Tip { seq: 0, hash: GENESIS.to_string() });
    };
    let last = text.lines().next_back().unwrap_or_default();
    let unreadable =
        |what: &str| RunLogError::Backend { message: format!("{what} in {}", path.display()) };
    let Ok(Value::Object(entry)) = serde_json::from_str(last) else {
        return Err(unreadable("the last entry"));
    };
    let Some(hash) = entry.get("hash").and_then(Value::as_str) else {
        return Err(unreadable("the last entry has no `hash`"));
    };
    let seq = entry.get("seq").and_then(Value::as_u64).unwrap_or(0);
    Ok(Tip { seq: seq + 1, hash: hash.to_string() })
}

/// The canonical bytes of a value: serde_json's serialization with every object's keys sorted,
/// whatever map it was built from.
fn canonical(entry: &Map<String, Value>) -> String {
    canonical_value(&Value::Object(entry.clone()))
}

fn canonical_value(value: &Value) -> String {
    match value {
        Value::Object(entry) => {
            let mut keys: Vec<&String> = entry.keys().collect();
            keys.sort_unstable();
            let body: Vec<String> = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("a string key serializes"),
                        canonical_value(&entry[key])
                    )
                })
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(items) => {
            let body: Vec<String> = items.iter().map(canonical_value).collect();
            format!("[{}]", body.join(","))
        }
        scalar => serde_json::to_string(scalar).expect("a json value serializes"),
    }
}

/// The entry without its own `hash` — what the hash is taken over.
fn without_hash(entry: &Map<String, Value>) -> Map<String, Value> {
    let mut entry = entry.clone();
    entry.remove("hash");
    entry
}

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|item| Value::String(item.clone())).collect())
}

/// A float as JSON, or zero when it is not one — a non-finite confidence must not become a value
/// `serde_json` refuses to serialize.
fn number(value: f64) -> Value {
    Value::Number(
        serde_json::Number::from_f64(value).unwrap_or_else(|| serde_json::Number::from(0)),
    )
}

fn unix_millis(now: SystemTime) -> u64 {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|since| u64::try_from(since.as_millis()).ok())
        .unwrap_or(0)
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn backend(error: std::io::Error) -> RunLogError {
    RunLogError::Backend { message: error.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::ports::secrets::{Redactor, SecretValue};
    use ks_engine::journal::Journal;
    use ks_testing::{block_on, clock::FakeClock};

    /// The spec's example ULID, so a run in a test names a known file.
    const RUN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    /// The fake secret the redaction assertion hangs on.
    const SECRET: &str = "s3cr3t-token";

    /// The committed log a real run produces, byte for byte — the golden trick `snapshots.rs` uses,
    /// so a change to the on-disk format is a diff someone reviews. Re-record with
    /// `UPDATE_GOLDEN=1 cargo test -p ks-cli --bin keepshipping`.
    const GOLDEN: &str = include_str!("../tests/fixtures/run-log/golden.jsonl");

    /// An empty log over a directory of this test's own. Every test names its own, so tests running
    /// in parallel cannot share a run's file.
    fn log(name: &str) -> (JsonlRunLog, RunId) {
        let dir =
            std::env::temp_dir().join(format!("keepshipping-runlog-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let clock = FakeClock::new();
        (JsonlRunLog::new(dir, Arc::new(clock)), RunId::parse(RUN).expect("the spec"))
    }

    /// The events a real run emits: one of each kind that has a shape worth a wire form.
    fn events() -> Vec<RunEvent> {
        vec![
            RunEvent::RunStarted {
                file_hash: "sha256:aa".into(),
                event: "push main".into(),
                actor: "ci".into(),
                is_agent: false,
            },
            RunEvent::StepStarted { step: "build".into() },
            RunEvent::StepFinished {
                step: "build".into(),
                ok: true,
                outputs: vec!["digest".into()],
                duration_ms: 1_234,
                error: None,
            },
            RunEvent::ApprovalRequested {
                step: "deploy".into(),
                channel: "github".into(),
                artifacts: vec!["sha256:bb".into()],
            },
            RunEvent::RunFinished { status: "shipped".into(), shipped: vec!["sha256:cc".into()] },
        ]
    }

    fn append_all(log: &JsonlRunLog, run: &RunId) {
        for event in events() {
            block_on(log.append(run, event)).expect("append");
        }
    }

    /// The file a run wrote, as text.
    fn written(log: &JsonlRunLog, run: &RunId) -> String {
        std::fs::read_to_string(JsonlRunLog::path_for(&log.dir, run)).expect("the run's log")
    }

    /// A log whose hash does not depend on the order the keys went in.
    #[test]
    fn the_canonical_form_sorts_keys_whatever_order_they_arrived_in() {
        let mut one = Map::new();
        one.insert("b".into(), Value::from(1));
        one.insert("a".into(), Value::from(2));
        let mut other = Map::new();
        other.insert("a".into(), Value::from(2));
        other.insert("b".into(), Value::from(1));

        assert_eq!(canonical(&one), canonical(&other));
        assert_eq!(canonical(&one), "{\"a\":2,\"b\":1}");
        // And nested objects too, which is where the probabilities list lives.
        assert_eq!(
            canonical_value(&serde_json::json!({"p": {"b": 1, "a": 0.5}})),
            "{\"p\":{\"a\":0.5,\"b\":1}}"
        );
    }

    /// The on-disk format is pinned byte for byte, and the chain it encodes verifies.
    #[test]
    fn the_recorded_log_is_the_documented_one() {
        let (log, run) = log("golden");
        append_all(&log, &run);
        let actual = written(&log, &run);
        assert_eq!(verify(&actual).expect("chain intact"), 5);

        let golden =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/run-log/golden.jsonl");
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(golden, &actual).expect("write golden");
            return;
        }
        assert_eq!(actual, GOLDEN);
    }

    /// Reordering is the one shape of damage `crates/cli/tests/log.rs` does not drive through the
    /// binary — an edit and a deletion are covered there.
    #[test]
    fn a_reordered_entry_breaks_the_chain() {
        let (log, run) = log("reordered");
        append_all(&log, &run);
        let mut lines: Vec<String> = written(&log, &run).lines().map(String::from).collect();
        lines.swap(1, 2);
        assert_eq!(verify(&lines.join("\n")).expect_err("a reordered log").line, 2);
    }

    /// A resumed run continues the chain rather than starting a second one: the tip comes off the
    /// disk, not out of a fresh cache.
    #[test]
    fn a_second_log_over_the_same_file_continues_its_chain() {
        let (first, run) = log("resume");
        block_on(first.append(&run, RunEvent::StepStarted { step: "build".into() }))
            .expect("append");
        let dir = first.dir.clone();
        let second = JsonlRunLog::new(dir.clone(), Arc::new(FakeClock::new()));
        append_all(&second, &run);

        let text =
            std::fs::read_to_string(JsonlRunLog::path_for(&dir, &run)).expect("the run's log");
        assert_eq!(verify(&text).expect("chain intact"), 6);
    }

    /// A secret is scrubbed by the journal before the append, so the bytes on disk cannot carry
    /// one: the adapter is handed an already-redacted event and stores what it is given.
    #[test]
    fn no_secret_reaches_the_log_bytes() {
        let (log, run) = log("redaction");
        let mut redactor = Redactor::new();
        redactor.register(&SecretValue::new(SECRET.as_bytes().to_vec()));
        let path = JsonlRunLog::path_for(&log.dir, &run);
        let journal = Journal::new(Arc::new(log) as Arc<dyn RunLog>, Arc::new(redactor), run);
        block_on(journal.run_started(SECRET, SECRET, SECRET, true)).expect("append");
        block_on(journal.approval_granted("deploy", SECRET, SECRET, vec![SECRET.into()]))
            .expect("append");

        let bytes = std::fs::read_to_string(path).expect("the run's log");
        assert!(!bytes.contains(SECRET), "a secret reached the log bytes: {bytes}");
        assert!(bytes.contains("***"), "it was redacted, not dropped: {bytes}");
        assert_eq!(verify(&bytes).expect("chain intact"), 2);
    }

    #[test]
    fn the_latest_run_is_the_one_with_the_latest_id() {
        let (log, older) = log("latest");
        let newer = RunId::from_parts(1_700_000_000_000, 1);
        for run in [&older, &newer] {
            std::fs::write(JsonlRunLog::path_for(&log.dir, run), "").expect("write");
        }
        // A file that is not a run is not a run.
        std::fs::write(log.dir.join("notes.txt"), "").expect("write");
        assert_eq!(JsonlRunLog::latest(&log.dir), Some(newer));
    }
}
