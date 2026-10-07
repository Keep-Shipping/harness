//! Fake for the [`RunLog`] port: a real hash chain, in memory, that can be
//! sealed, made to fail, and — for the sake of testing `verify` — tampered
//! with.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard};

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::run_log::{LogEntry, LogEvent, LogReport, RunLog, RunLogError, Seq};
use ks_core::ports::supply_chain::Digest;
use sha2::{Digest as _, Sha256};

/// SHA-256 of `bytes`, lowercase hex — the one real hashing helper here.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The [`Digest`] of `bytes`, computed with the real algorithm.
fn digest_of(bytes: &[u8]) -> Digest {
    Digest::sha256_from_hex(&sha256_hex(bytes)).expect("sha256 hex is canonical")
}

/// What one run's log holds, in append order.
#[derive(Default)]
struct RunLogState {
    /// run → its entries, oldest first. Appends push, so the vector is already
    /// ascending by [`Seq`].
    runs: BTreeMap<RunId, Vec<LogEntry>>,
    /// Whether [`sealed`](FakeRunLog::sealed) has been called.
    sealed: bool,
    /// Set by [`failing`](FakeRunLog::failing): every call fails with it.
    failure: Option<String>,
}

/// A [`RunLog`] whose chain is genuinely hash-linked: every entry's `hash` is
/// the real SHA-256 of its [`LogEntry::chained_bytes`], and every entry's
/// `prev` is the `hash` of the entry before it.
///
/// Because the hashes are computed rather than recorded, [`verify`](RunLog::verify)
/// recomputes them the same way a real adapter must, and
/// [`tamper`](FakeRunLog::tamper) can produce a chain that really is broken.
///
/// ```
/// use ks_core::ids::RunId;
/// use ks_core::ports::run_log::{LogEvent, RunLog, Seq};
/// use ks_testing::{block_on, run_log::FakeRunLog};
///
/// let log = FakeRunLog::new();
/// let run = RunId::from_parts(1_700_000_000_000, 7);
/// let first = block_on(log.append(&run, LogEvent::new("run.started", "from ci"))).expect("append");
/// assert_eq!(first, Seq::FIRST);
/// block_on(log.append(&run, LogEvent::new("run.finished", "ok"))).expect("append");
/// assert_eq!(block_on(log.read(&run)).expect("read").len(), 2);
/// assert!(block_on(log.verify(&run)).expect("verify").is_intact());
/// ```
///
/// # What this fake does not model
///
/// - **Append-only across restarts.** Entries live in a `BTreeMap` for the
///   life of the process. An adapter that rewrites its file on every append
///   passes this fake's tests and fails in production; nothing here can catch
///   that, which is why the port's own docs put the obligation on adapters.
/// - **Per-run sealing.** [`sealed`](FakeRunLog::sealed) closes *every* run's
///   log at once, because the fake has one switch. Real adapters seal the run
///   that finished, which is why [`RunLogError::Sealed`] names a run.
/// - **Redaction.** The fake stores `detail` text verbatim; the caller is
///   responsible for having run it through the `Redactor` first, and the
///   conformance kit does not pretend to check redaction.
#[derive(Default)]
pub struct FakeRunLog {
    state: Mutex<RunLogState>,
}

impl FakeRunLog {
    /// Creates a fake with an empty log for every run.
    pub fn new() -> FakeRunLog {
        FakeRunLog::default()
    }

    /// Seals the fake: from now on every [`append`](RunLog::append) fails with
    /// [`RunLogError::Sealed`] naming the run it was called for.
    ///
    /// Reading and verifying still work — a sealed log is a finished record,
    /// not an unreadable one.
    pub fn sealed(mut self) -> FakeRunLog {
        self.lock_mut().sealed = true;
        self
    }

    /// Scripts every call to fail with [`RunLogError::Backend`].
    pub fn failing(mut self, message: impl Into<String>) -> FakeRunLog {
        self.lock_mut().failure = Some(message.into());
        self
    }

    /// Corrupts the stored entry at `seq` so its `hash` no longer matches its
    /// content, and returns `false` if no run has an entry at that `Seq`.
    ///
    /// **This exists only so tests can prove [`verify`](RunLog::verify) catches
    /// tampering.** No production code may call it: an adapter that could edit
    /// its own stored entries would be the exact defect the port exists to
    /// make observable. It rewrites the stored hash only — the event, `seq`
    /// and `prev` links are left alone, so the damage is precisely "the
    /// recorded hash disagrees with the bytes it claims to cover".
    pub fn tamper(&self, seq: u64) -> bool {
        let mut state = self.lock();
        for entries in state.runs.values_mut() {
            if let Some(entry) = entries.iter_mut().find(|entry| entry.seq.get() == seq) {
                entry.hash = flipped(entry.hash.clone());
                return true;
            }
        }
        false
    }

    /// The entries stored for `run` so far, oldest first.
    pub fn entries(&self, run: &RunId) -> Vec<LogEntry> {
        self.lock().runs.get(run).cloned().unwrap_or_default()
    }

    /// Whether [`sealed`](FakeRunLog::sealed) has been called.
    pub fn is_sealed(&self) -> bool {
        self.lock().sealed
    }

    /// How many entries have been appended to `run` so far.
    pub fn appended(&self, run: &RunId) -> usize {
        self.lock().runs.get(run).map(Vec::len).unwrap_or(0)
    }

    fn lock(&self) -> MutexGuard<'_, RunLogState> {
        self.state.lock().expect("fake run log")
    }

    fn lock_mut(&mut self) -> &mut RunLogState {
        self.state.get_mut().expect("fake run log")
    }

    /// Appends `event`, hashing it into the chain — the real SHA-256 of
    /// [`LogEntry::chained_bytes`], not a recorded value.
    fn append_one(&self, run: &RunId, event: LogEvent) -> Result<Seq, RunLogError> {
        let mut state = self.lock();
        if state.sealed {
            return Err(RunLogError::Sealed { run: run.clone() });
        }
        let entries = state.runs.entry(run.clone()).or_default();
        let seq = Seq::new(entries.len() as u64 + 1);
        let prev = entries.last().map(|entry| entry.hash.clone());
        let entry = LogEntry {
            seq,
            event,
            prev,
            // The hash covers seq, event and prev but not itself, so any
            // placeholder works; it is overwritten before the entry is stored.
            hash: digest_of(b""),
        };
        let entry = LogEntry { hash: digest_of(&entry.chained_bytes()), ..entry };
        entries.push(entry.clone());
        Ok(entry.seq)
    }

    /// Recomputes the chain over the stored entries and reports the first
    /// entry that does not verify.
    fn walk(&self, run: &RunId) -> LogReport {
        let state = self.lock();
        let empty = Vec::new();
        let entries = state.runs.get(run).unwrap_or(&empty);
        let mut expected_prev: Option<Digest> = None;
        let mut broken_at = None;
        for entry in entries {
            let recomputed = digest_of(&entry.chained_bytes());
            if entry.prev != expected_prev || entry.hash != recomputed {
                broken_at = Some(entry.seq);
                break;
            }
            expected_prev = Some(entry.hash.clone());
        }
        LogReport {
            entries: entries.len(),
            // The head is the last stored entry's recorded hash. Over a broken
            // chain that digest is exactly what is in doubt, which is what
            // `broken_at` is there to say.
            head: entries.last().map(|entry| entry.hash.clone()),
            broken_at,
        }
    }
}

/// A [`Digest`] that differs from `digest` in its first hex digit — a stored
/// hash that no longer describes the bytes it covers.
fn flipped(digest: Digest) -> Digest {
    let hex = digest.hex();
    let first = if hex.starts_with('0') { '1' } else { '0' };
    Digest::sha256_from_hex(&format!("{first}{}", &hex[1..]))
        .expect("flipping one hex digit keeps the digest well formed")
}

impl RunLog for FakeRunLog {
    fn append<'a>(
        &'a self,
        run: &'a RunId,
        event: LogEvent,
    ) -> BoxFuture<'a, Result<Seq, RunLogError>> {
        // The scripted failure is read and the guard dropped before the work
        // runs, so the call below can take the mutex itself.
        let failure = self.lock().failure.clone();
        let result = match failure {
            Some(message) => Err(RunLogError::Backend { message }),
            None => self.append_one(run, event),
        };
        Box::pin(std::future::ready(result))
    }

    fn read<'a>(&'a self, run: &'a RunId) -> BoxFuture<'a, Result<Vec<LogEntry>, RunLogError>> {
        let failure = self.lock().failure.clone();
        let result = match failure {
            Some(message) => Err(RunLogError::Backend { message }),
            None => Ok(self.entries(run)),
        };
        Box::pin(std::future::ready(result))
    }

    fn verify<'a>(&'a self, run: &'a RunId) -> BoxFuture<'a, Result<LogReport, RunLogError>> {
        let failure = self.lock().failure.clone();
        let result = match failure {
            Some(message) => Err(RunLogError::Backend { message }),
            None => Ok(self.walk(run)),
        };
        Box::pin(std::future::ready(result))
    }
}

/// The `RunLog` conformance kit: every adapter — [`FakeRunLog`] here, the
/// local filesystem and OCI-referrer adapters later
/// ([#55](https://github.com/Keep-Shipping/harness/issues/55)) — must pass
/// this.
///
/// The kit mints its own run ids from a fixed instant ([`RunId::from_parts`]),
/// so it needs no [`IdGen`](ks_core::ports::id_gen::IdGen) and is
/// deterministic; pass adapters that share one fake it does.
///
/// Checks, in order: appends come back as `Seq::FIRST`, then `previous + 1`,
/// one at a time; `read` returns them in ascending `Seq` with no gaps and in
/// the order they were appended; every entry links to its predecessor's hash
/// (`None` at the first) and carries a `sha256` digest; `verify` calls the
/// untampered chain intact with the append count and the last entry's hash as
/// head; and a run that was never appended to reads empty and verifies intact
/// over zero entries.
///
/// Hashes are *not* recomputed here — the kit takes a `&dyn RunLog`, so it
/// cannot hash an adapter's entries without assuming their encoding. The
/// real-SHA-256 recomputation lives in [`FakeRunLog`]'s own tests.
pub async fn conformance(log: &dyn RunLog) {
    let run = RunId::from_parts(1_700_000_000_000, 0x00c0_ffee_0000_0001);
    let kinds = ["run.started", "step.started", "step.succeeded"];

    let mut previous: Option<Seq> = None;
    for kind in kinds {
        let event = LogEvent {
            kind: kind.to_string(),
            at: std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_millis(1_700_000_000_000),
            step: None,
            detail: format!("run log conformance: {kind}"),
        };
        let seq = log
            .append(&run, event)
            .await
            .unwrap_or_else(|error| panic!("run log conformance: append must succeed: {error}"));
        let expected = match previous {
            None => Seq::FIRST,
            Some(previous) => Seq::new(previous.get() + 1),
        };
        assert_eq!(
            seq, expected,
            "run log conformance: append must return Seq::FIRST, then previous + 1"
        );
        previous = Some(seq);
    }

    let entries = log
        .read(&run)
        .await
        .unwrap_or_else(|error| panic!("run log conformance: read must succeed: {error}"));
    assert_eq!(
        entries.len(),
        kinds.len(),
        "run log conformance: read must return every appended entry"
    );
    for (index, entry) in entries.iter().enumerate() {
        let expected = Seq::new(index as u64 + 1);
        assert_eq!(
            entry.seq, expected,
            "run log conformance: read returns entries ascending by Seq with no gaps"
        );
        assert_eq!(
            entry.event.kind, kinds[index],
            "run log conformance: read returns entries in the order they were appended"
        );
    }
    assert_eq!(
        entries[0].prev, None,
        "run log conformance: the first entry of a chain has no prev"
    );
    for pair in entries.windows(2) {
        assert_eq!(
            pair[1].prev,
            Some(pair[0].hash.clone()),
            "run log conformance: every entry links to its predecessor's hash"
        );
    }
    for entry in &entries {
        assert_eq!(
            entry.hash.algorithm(),
            "sha256",
            "run log conformance: the chain is sha256, the only algorithm RunLog::chained_bytes defines"
        );
    }

    let report = log
        .verify(&run)
        .await
        .unwrap_or_else(|error| panic!("run log conformance: verify must succeed: {error}"));
    assert!(
        report.is_intact(),
        "run log conformance: an untouched chain must verify, got {report:?}"
    );
    assert_eq!(report.entries, kinds.len(), "run log conformance: the report counts every entry");
    assert_eq!(
        report.head,
        Some(entries.last().expect("entries were appended").hash.clone()),
        "run log conformance: the head is the last entry's hash"
    );

    // A run nobody appended to: empty, not an error, and intact over nothing.
    let untouched = RunId::from_parts(1_700_000_000_000, 0x00c0_ffee_0000_0002);
    assert_eq!(
        log.read(&untouched).await,
        Ok(Vec::new()),
        "run log conformance: a run that was never appended to reads empty"
    );
    let empty = log
        .verify(&untouched)
        .await
        .unwrap_or_else(|error| panic!("run log conformance: verify must succeed: {error}"));
    assert!(
        empty.is_intact() && empty.entries == 0 && empty.head.is_none(),
        "run log conformance: an empty log verifies intact over zero entries, got {empty:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    fn run(seed: u128) -> RunId {
        RunId::from_parts(1_700_000_000_000, seed)
    }

    fn event(kind: &str) -> LogEvent {
        LogEvent {
            kind: kind.to_string(),
            at: std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_millis(1_700_000_000_123),
            step: None,
            detail: "the detail".to_string(),
        }
    }

    fn append(log: &FakeRunLog, run: &RunId, kind: &str) -> Seq {
        block_on(log.append(run, event(kind))).expect("append succeeds")
    }

    #[test]
    fn a_fresh_fake_has_no_seeded_state() {
        let log = FakeRunLog::new();
        let run = run(1);
        assert_eq!(log.entries(&run), Vec::<LogEntry>::new());
        assert_eq!(log.appended(&run), 0);
        assert!(!log.is_sealed());
    }

    /// The chain must be real hashing, not self-consistency: every stored hash
    /// is recomputed here with `sha2`, from the encoding `ks-core` documents.
    #[test]
    fn every_stored_hash_is_the_sha256_of_its_chained_bytes() {
        let log = FakeRunLog::new();
        let run = run(2);
        append(&log, &run, "run.started");
        append(&log, &run, "step.started");
        append(&log, &run, "step.succeeded");

        let mut previous: Option<Digest> = None;
        for entry in log.entries(&run) {
            assert_eq!(
                entry.hash,
                digest_of(&entry.chained_bytes()),
                "seq {}: the hash must be sha256 of the entry's own chained_bytes",
                entry.seq
            );
            assert_eq!(entry.prev, previous, "seq {} must link to its predecessor", entry.seq);
            previous = Some(entry.hash.clone());
        }
        assert!(previous.is_some());
    }

    #[test]
    fn an_untouched_chain_verifies_and_tampering_breaks_it() {
        let log = FakeRunLog::new();
        let run = run(3);
        append(&log, &run, "run.started");
        append(&log, &run, "step.started");
        append(&log, &run, "step.succeeded");

        let intact = block_on(log.verify(&run)).expect("verify");
        assert!(intact.is_intact(), "{intact:?}");
        assert_eq!(intact.entries, 3);
        assert_eq!(intact.head, Some(log.entries(&run)[2].hash.clone()));

        assert!(log.tamper(2), "seq 2 exists, so it can be tampered with");
        assert!(!log.tamper(99), "no entry sits at seq 99");
        let broken = block_on(log.verify(&run)).expect("verify");
        assert!(!broken.is_intact());
        assert_eq!(broken.broken_at, Some(Seq::new(2)));
    }

    #[test]
    fn reading_is_not_judging() {
        let log = FakeRunLog::new();
        let run = run(4);
        append(&log, &run, "run.started");
        append(&log, &run, "step.started");
        log.tamper(1);
        assert_eq!(
            block_on(log.read(&run)).expect("read").len(),
            2,
            "read returns damaged entries too — hiding them would make a tampered run look quiet"
        );
    }

    #[test]
    fn a_sealed_fake_refuses_appends_but_still_reads() {
        let log = FakeRunLog::new().sealed();
        let run = run(5);
        assert!(log.is_sealed());
        assert_eq!(
            block_on(log.append(&run, event("run.started"))),
            Err(RunLogError::Sealed { run: run.clone() })
        );
        assert_eq!(block_on(log.read(&run)).expect("read"), Vec::new());
        assert!(block_on(log.verify(&run)).expect("verify").is_intact());
    }

    #[test]
    fn a_failing_fake_fails_every_method() {
        let log = FakeRunLog::new().failing("disk full");
        let run = run(6);
        let backend = RunLogError::Backend { message: "disk full".to_string() };
        assert_eq!(block_on(log.append(&run, event("run.started"))), Err(backend.clone()));
        assert_eq!(block_on(log.read(&run)), Err(backend.clone()));
        assert_eq!(block_on(log.verify(&run)), Err(backend));
    }

    #[test]
    fn runs_are_kept_apart() {
        let log = FakeRunLog::new();
        let first = run(7);
        let second = run(8);
        append(&log, &first, "run.started");
        append(&log, &second, "run.started");
        assert_eq!(log.appended(&first), 1);
        assert_eq!(log.appended(&second), 1);
        // Each run's chain starts over at Seq::FIRST.
        assert_eq!(log.entries(&second)[0].seq, Seq::FIRST);
        assert_eq!(log.entries(&second)[0].prev, None);
    }

    #[test]
    fn the_fake_passes_conformance() {
        block_on(conformance(&FakeRunLog::new()));
    }
}
