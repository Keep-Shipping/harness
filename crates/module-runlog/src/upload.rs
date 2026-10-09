//! Batched upload and the verification that decides whether a batch is kept: the
//! round trip the issue asks for, in the order a hosted worker runs it.
//!
//! A runner cannot post a whole run log in one request — a long run is bigger
//! than a request body — so it uploads the log in batches of whole lines, the
//! last one carrying the runner's seal. A batch is kept only when the chain
//! continues from the stored head, every line hashes to what it claims, and the
//! seal — when there is one — verifies under a trusted key.
//!
//! The order of those checks is the order that matters. A body over the cap is
//! refused before it is parsed; every line is parsed before anything is
//! chained, so an edited line dies on the line itself rather than on a chain
//! complaint one batch later; the batch's position is checked before continuity,
//! so a replay is a replay and not a broken chain; and the seal is checked last,
//! after its run, seq and head are known to be the tip's — because a seal that
//! does not match is a different problem from one that does not verify.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use crate::MAX_BATCH_BYTES;
use crate::chain::{Entry, GENESIS};
use crate::seal::{Seal, TrustedKeys};
use crate::store::{Blob, Db, RunIndex, StoreError, blob_key, check_repo, check_run};
use serde_json::Value;

/// One request's worth of a run log: whole lines, in order, and the seal on the
/// last one.
///
/// **This JSON shape is the upload envelope, and it is not the seal sidecar.** A
/// seal crosses the wire here as a field of this object rather than as its own
/// sorted-key line, so a worker's `/v1/runs/:id/batches` request and the
/// runner's `.keepshipping/runs/<RunId>.seals.jsonl` are two different
/// documents, and mixing them up produces a seal nobody can verify:
///
/// * the **envelope** is this `Batch` — `repo`, `run`, `index`, `lines`, `seal`;
/// * the **sidecar line** is [`Seal::to_line`] — `{"head":…,"identity":…,"run":…,
///   "seq":…,"signature":…}`, one per line, sorted keys, no spaces.
///
/// The seal field below *reuses* the sidecar's own key names, so the two cannot
/// drift apart, but it is a field of this object and not a line of that file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    /// The repository the run happened in.
    pub repo: String,
    /// The run the lines belong to.
    pub run: String,
    /// Which batch this is, counting from zero. The first is 0, and each
    /// subsequent one must be exactly the count already stored — so a replayed
    /// or skipped batch is refused rather than concatenated.
    pub index: u64,
    /// Whole JSONL lines, in order. A line is never split across batches.
    pub lines: Vec<String>,
    /// The runner's seal, on the final batch only.
    pub seal: Option<Seal>,
}

// `SignerIdentity` lives in `ks-core` and carries no serde derives, and this crate
// does not get to add them. So the seal is (de)serialized through its own sidecar
// line — which is the wire format the runner already writes, and the one
// [`Seal::parse`] checks hex and key order on. One implementation, so the
// envelope and the sidecar cannot disagree about what a seal looks like.
impl Serialize for Seal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let line = self.to_line();
        let value: Value = serde_json::from_str(&line).expect("a seal line is JSON");
        value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Seal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Seal, D::Error> {
        use serde_json::Value;
        let value = Value::deserialize(deserializer)?;
        Seal::parse(&value.to_string()).map_err(serde::de::Error::custom)
    }
}

/// Splits a whole run log into batches of at most `max_bytes`, never splitting a
/// line. A line longer than `max_bytes` on its own has nowhere to go and is
/// refused, rather than being cut into something that does not parse.
pub fn batches(text: &str, max_bytes: usize) -> Result<Vec<Vec<String>>, BatchError> {
    let mut out = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut size = 0usize;
    for line in text.lines() {
        // The newline counts against the cap — it is in the request body — but is
        // not part of the line the runner reads back.
        let line_bytes = line.len() + 1;
        if line_bytes > max_bytes {
            return Err(BatchError::LineTooLong { bytes: line.len() });
        }
        if size + line_bytes > max_bytes && !current.is_empty() {
            out.push(std::mem::take(&mut current));
            size = 0;
        }
        size += line_bytes;
        current.push(line.to_string());
    }
    if !current.is_empty() {
        out.push(current);
    }
    Ok(out)
}

/// Why a run log could not be split into batches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchError {
    /// One line is over the cap on its own.
    LineTooLong {
        /// How long it was.
        bytes: usize,
    },
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchError::LineTooLong { bytes } => {
                write!(f, "one line is {bytes} bytes, over the batch cap — a line is never split")
            }
        }
    }
}

/// The hosted module: a blob store, an index store, and the keys a seal has to
/// verify under. There is no network in it at all — a worker's routing is the
/// caller's business.
///
/// **A seal does not bind the repository it was uploaded under.** `seal_payload`
/// signs `run`, `seq` and `head`, so a validly signed log can be re-filed under a
/// different repo and renders there as verified. This is inherited from the
/// runner's wire format; see the crate docs.
pub struct Viewer {
    blob: Arc<dyn Blob>,
    db: Arc<dyn Db>,
    keys: Arc<TrustedKeys>,
    /// One lock per run, held across the whole of [`Viewer::accept`]'s
    /// read-check-write. Without it two threads can both read `batches == 0` and
    /// both write, and `Reject::OutOfOrder` is not a mutual-exclusion primitive —
    /// it is a value the other thread has not updated yet. Coarse on purpose: two
    /// runs at different keys still proceed in parallel.
    runs: Arc<Mutex<BTreeMap<String, Arc<Mutex<()>>>>>,
}

impl Viewer {
    /// A viewer over these stores and this keyring.
    pub fn new(blob: Arc<dyn Blob>, db: Arc<dyn Db>, keys: Arc<TrustedKeys>) -> Viewer {
        Viewer { blob, db, keys, runs: Arc::new(Mutex::new(BTreeMap::new())) }
    }

    /// The keyring this viewer verifies seals under.
    pub fn keys(&self) -> &Arc<TrustedKeys> {
        &self.keys
    }

    /// This run's lock, created on first use. The table is never pruned: a
    /// viewer lives as long as the worker holding it and a run id is a ULID, so
    /// it is bounded by the runs that process saw, not by anything an attacker
    /// chooses.
    fn run_lock(&self, key: &str) -> Arc<Mutex<()>> {
        let mut runs = self.runs.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(runs.entry(key.to_string()).or_default())
    }

    /// Checks one batch against what is stored, and keeps it if it holds. The
    /// returned index is the run's after this batch.
    ///
    /// In order: usable repo and run names ([`Reject::BadName`]), because
    /// everything after this composes a key out of them; a body within
    /// [`MAX_BATCH_BYTES`]; every line parsing and hashing to its own `hash`
    /// ([`Reject::BadEntry`]); every entry belonging to the batch's run
    /// ([`Reject::WrongRun`]); the batch's index being the count already stored, so
    /// a replay or a skip is refused ([`Reject::OutOfOrder`]); the first line's
    /// `prev` naming the stored head — [`GENESIS`] at index 0 — and each line after
    /// that its predecessor's `hash`, the continuity check the batch boundary makes
    /// possible and a single line cannot make ([`Reject::BrokenChain`]); nothing
    /// after a seal ([`Reject::AlreadySealed`]); and a seal, which may ride only on
    /// the final batch, being about this run, covering this tip's seq and hash,
    /// sitting on a `run.finished`, and verifying ([`Reject::SealMismatch`],
    /// [`Reject::SealRefused`]).
    pub fn accept(&self, batch: &Batch) -> Result<RunIndex, Reject> {
        // Before the key exists, and so before the lock and either store.
        check_repo(&batch.repo).and_then(|()| check_run(&batch.run)).map_err(Reject::BadName)?;
        let body: usize = batch.lines.iter().map(|line| line.len() + 1).sum();
        if body > MAX_BATCH_BYTES {
            return Err(Reject::TooLarge { found: body, limit: MAX_BATCH_BYTES });
        }
        // Held for the read, the decision and both writes below, so two `accept`s
        // for one run are strictly ordered and the second is refused by
        // `OutOfOrder` rather than racing the first.
        let key = blob_key(&batch.repo, &batch.run);
        let run_lock = self.run_lock(&key);
        let _held = run_lock.lock().unwrap_or_else(PoisonError::into_inner);
        let stored = self.stored(&batch.repo, &batch.run).map_err(Reject::Store)?;
        let (mut index, mut text) = match stored {
            Some((index, text)) => (index, text),
            None => (
                RunIndex {
                    repo: batch.repo.clone(),
                    run: batch.run.clone(),
                    batches: 0,
                    entries: 0,
                    head: GENESIS.to_string(),
                    sealed: false,
                    verified: false,
                    // Overwritten below once the entries parse; a log has no
                    // first entry until there is one.
                    started_at: 0,
                    finished_at: None,
                },
                String::new(),
            ),
        };

        let mut entries: Vec<Entry> = Vec::with_capacity(batch.lines.len());
        for line in &batch.lines {
            let entry = Entry::parse(line).map_err(|break_| Reject::BadEntry {
                line: index.entries as u64 + entries.len() as u64 + 1,
                reason: break_.to_string(),
            })?;
            if entry.run != batch.run {
                return Err(Reject::WrongRun { found: entry.run, run: batch.run.clone() });
            }
            entries.push(entry);
        }
        let Some(tip) = entries.last().cloned() else {
            return Err(Reject::BadEntry {
                line: index.entries as u64 + 1,
                reason: "the batch carries no lines".to_string(),
            });
        };
        if index.sealed {
            return Err(Reject::AlreadySealed { run: batch.run.clone() });
        }
        if batch.index != index.batches {
            return Err(Reject::OutOfOrder { found: batch.index, expected: index.batches });
        }
        // Chain continuity comes next, from the stored head into this batch and within
        // it — neither of which `Entry::parse` can do, since a line does not know
        // what came before it.
        let mut prev = index.head.clone();
        for (offset, entry) in entries.iter().enumerate() {
            // `prev` first and `seq` second, the order `crates/cli`'s `verify`
            // checks them in: a deletion breaks both, and `prev` is the one that
            // says what was removed. `seq` is the position in the *run*, not in
            // the batch, so a batch that skips or repeats a position is refused
            // even though every `prev` lines up.
            if !entry.continues_from(&prev) {
                return Err(Reject::BrokenChain { found: entry.prev.clone(), expected: prev });
            }
            let expected_seq = index.entries as u64 + offset as u64;
            if entry.seq != expected_seq {
                return Err(Reject::BrokenChain {
                    found: format!("seq {}", entry.seq),
                    expected: format!("seq {expected_seq}"),
                });
            }
            prev = entry.hash.clone();
        }

        if let Some(seal) = &batch.seal {
            self.check_seal(seal, batch, &tip)?;
            index.sealed = true;
            index.verified = true;
        }

        // Kept so a failed commit can put the blob back the way it was: the blob
        // is written before the index, so an index write that fails would
        // otherwise leave lines the index does not know about, and a retry would
        // append them a second time.
        let previous = text.clone();
        for entry in &entries {
            // Whole lines, newline-separated: what comes back out of `run` is the
            // runner's log, not a re-join of it.
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(&entry.line);
        }
        if index.entries == 0 {
            index.started_at = entries[0].at;
        }
        index.batches += 1;
        index.entries += entries.len();
        index.head = prev;
        if tip.kind == "run.finished" {
            index.finished_at = Some(tip.at);
        }

        self.commit(&key, &index, &previous, &text)?;
        Ok(index)
    }

    /// Writes a batch's two objects, blob then index, and puts the blob back if
    /// the index write fails.
    ///
    /// Blob first, because the index is what makes a run visible: an unindexed
    /// blob is not a run yet, and that is the lesser mistake. Recovery is the
    /// reverse for the same reason — a failed index write over a written blob
    /// would leave lines the index does not account for, and the retry would
    /// append them a second time, leaving the run permanently un-chainable.
    /// Restoring the previous text leaves the run exactly as the last accepted
    /// batch left it, so that batch may simply be sent again; restoring an empty
    /// body for a run that had none is the same as never having written one,
    /// since the index is untouched and there is nothing to contradict.
    fn commit(
        &self,
        key: &str,
        index: &RunIndex,
        previous: &str,
        text: &str,
    ) -> Result<(), Reject> {
        self.blob.put(key, text.as_bytes()).map_err(Reject::Store)?;
        if let Err(error) = self.db.put_run(index) {
            // A rollback that itself fails leaves the same corruption it was
            // meant to undo, and there is nothing further to try: the original
            // error is the one worth reporting, since it is what the backend
            // actually said.
            let _ = self.blob.put(key, previous.as_bytes());
            return Err(Reject::Store(error));
        }
        Ok(())
    }

    /// The completeness rule `crates/cli`'s `check_seals` enforces: the entry a
    /// seal covers has to be the run's last one. Without it, cutting the tail off
    /// the end leaves a good chain under a good seal — a shorter run that
    /// verifies — so "the run finished" is part of what the seal means.
    fn check_seal(&self, seal: &Seal, batch: &Batch, tip: &Entry) -> Result<(), Reject> {
        if seal.run != batch.run {
            return Err(Reject::SealMismatch {
                reason: format!("it is about run {}, not {}", seal.run, batch.run),
            });
        }
        if seal.seq != tip.seq {
            return Err(Reject::SealMismatch {
                reason: format!("it covers seq {}, not the tip's {}", seal.seq, tip.seq),
            });
        }
        if seal.head != tip.hash {
            return Err(Reject::SealMismatch {
                reason: format!("it covers head {}, not the tip's {}", seal.head, tip.hash),
            });
        }
        if tip.kind != "run.finished" {
            return Err(Reject::SealMismatch {
                reason: format!(
                    "it covers a `{}`, not a `run.finished` — the run went on past it",
                    tip.kind
                ),
            });
        }
        self.keys.verify(seal).map_err(|refusal| Reject::SealRefused(refusal.to_string()))
    }

    /// The run's index and its log text, if it has any.
    ///
    /// The names are checked as [`Viewer::accept`] checks them, for the same
    /// reason: [`blob_key`] is a bare `format!`, so `run("a/b", "c/d")` composes
    /// the key of repo `a/b/c`, run `d` — a reader asking about a name it was
    /// never given would be handed another run's log, whole and unreadably
    /// correct.
    pub fn run(&self, repo: &str, run: &str) -> Result<Option<(RunIndex, String)>, StoreError> {
        check_repo(repo).and_then(|()| check_run(run))?;
        let Some(index) = self.db.get_run(repo, run)? else { return Ok(None) };
        let text = self.text_of(repo, run)?;
        Ok(Some((index, text)))
    }

    /// Every run in a repo, oldest first.
    ///
    /// Checked as [`Viewer::run`] checks, so a caller cannot use this to ask a
    /// question about a name that could mean two keys.
    pub fn runs(&self, repo: &str) -> Result<Vec<RunIndex>, StoreError> {
        check_repo(repo)?;
        self.db.runs_in_repo(repo)
    }

    /// A run's stored log text.
    fn text_of(&self, repo: &str, run: &str) -> Result<String, StoreError> {
        Ok(self
            .blob
            .get(&blob_key(repo, run))?
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default())
    }

    /// What is stored for a run, if anything: the index and the log it names.
    fn stored(&self, repo: &str, run: &str) -> Result<Option<(RunIndex, String)>, StoreError> {
        match self.db.get_run(repo, run)? {
            None => Ok(None),
            Some(index) => Ok(Some((index, self.text_of(repo, run)?))),
        }
    }
}

/// Why a batch was not kept. Each variant is a sentence a hosted page can show,
/// and each names the thing that was wrong rather than the log around it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// The repository or run is not a name this module will store under: a run
    /// holding a `/`, an empty segment, a control character. Refused before
    /// anything is read, because `repo/run` composes the storage key and a name
    /// that could mean two runs *is* a name that means one.
    BadName(StoreError),
    /// The batch is over the per-request cap.
    TooLarge {
        /// How many bytes it was.
        found: usize,
        /// The cap.
        limit: usize,
    },
    /// A line does not hold: not JSON, no `hash`, or an edit that left the hash
    /// stale. The line is 1-based over the run's entries, so the number a reader
    /// is shown is the one they would count in the log itself.
    BadEntry {
        /// The 1-based line in the run.
        line: u64,
        /// Why that line does not hold.
        reason: String,
    },
    /// An entry belongs to another run than the batch claims.
    WrongRun {
        /// The run the entry names.
        found: String,
        /// The run the batch claims.
        run: String,
    },
    /// The batch's index is not the next one, so it is a replay or a skip.
    OutOfOrder {
        /// The index it claimed.
        found: u64,
        /// The index the run is waiting for.
        expected: u64,
    },
    /// The chain does not continue from what is stored.
    BrokenChain {
        /// What the line names as the entry above it.
        found: String,
        /// What that entry's hash actually is.
        expected: String,
    },
    /// The run is already sealed, so nothing more may be appended to it.
    AlreadySealed {
        /// The sealed run.
        run: String,
    },
    /// The seal is about another run, another entry, or sits on something other
    /// than a `run.finished`.
    SealMismatch {
        /// Why the seal does not match the tip.
        reason: String,
    },
    /// The seal does not verify: an untrusted key, a keyless identity, a
    /// substituted key id, or a signature that simply does not check out.
    SealRefused(String),
    /// The store refused.
    Store(StoreError),
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reject::BadName(error) => write!(f, "{error}"),
            Reject::TooLarge { found, limit } => {
                write!(f, "a batch is capped at {limit} bytes, got {found}")
            }
            Reject::BadEntry { line, reason } => write!(f, "line {line}: {reason}"),
            Reject::WrongRun { found, run } => {
                write!(f, "the batch claims run {run}, but an entry names {found}")
            }
            Reject::OutOfOrder { found, expected } => {
                write!(f, "batch {found} arrived where batch {expected} was expected")
            }
            Reject::BrokenChain { found, expected } => {
                write!(f, "the chain does not continue: `prev` is {found}, not {expected}")
            }
            Reject::AlreadySealed { run } => {
                write!(f, "run {run} is sealed — nothing may be appended to it")
            }
            Reject::SealMismatch { reason } => {
                write!(f, "the seal does not match the tip: {reason}")
            }
            Reject::SealRefused(reason) => write!(f, "the seal does not verify: {reason}"),
            Reject::Store(error) => write!(f, "{error}"),
        }
    }
}
