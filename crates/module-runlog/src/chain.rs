//! The hash chain a hosted reader re-checks for itself: the same canonical form
//! `crates/cli`'s `run_log` writes, byte for byte.
//!
//! The chain is what makes an uploaded log worth reading — every entry names the
//! hash of the one before it, so an edited, deleted or reordered entry does not
//! survive a reader that checks. It is *not* what makes it worth trusting: a
//! writer that recomputes the chain as it goes leaves a perfectly self-consistent
//! log. That half is [`seal`](crate::seal)'s job.
//!
//! The canonical form sorts every object's keys by hand rather than relying on
//! `serde_json`'s map order, for the reason `crates/cli/src/run_log.rs` gives: a
//! workspace build turns on `preserve_order`, so a chain hashed in insertion
//! order would depend on which crates happened to be compiled.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The `prev` of a run's first entry: nothing came before it.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The canonical bytes of an entry: compact JSON, every object's keys sorted.
pub fn canonical(entry: &Map<String, Value>) -> String {
    canonical_value(&Value::Object(entry.clone()))
}

/// [`canonical`] for any value, so a nested object sorts too.
pub fn canonical_value(value: &Value) -> String {
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

/// The entry's own hash: sha256 over its canonical form with `hash` removed. The
/// line on disk *includes* `hash`, so the hash is taken over the entry without it
/// and the line is written after.
pub fn entry_hash(entry: &Map<String, Value>) -> String {
    let mut without = entry.clone();
    without.remove("hash");
    sha256_hex(&canonical(&without))
}

/// One line of a run log, parsed but not yet chained to its neighbours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The entry's timestamp, in unix millis, as the runner wrote it.
    pub at: u64,
    /// This entry's `hash`.
    pub hash: String,
    /// The hash of the entry above it — sixty-four zeros for the first.
    pub prev: String,
    /// The run the entry belongs to.
    pub run: String,
    /// The entry's position, counting from zero.
    pub seq: u64,
    /// The entry's `type`: `run.started`, `approval.granted`, …
    pub kind: String,
    /// The line exactly as it was uploaded. Views render this rather than
    /// re-serializing the entry, so what a reader sees is what the runner wrote.
    pub line: String,
}

impl Entry {
    /// Parses one line, refusing a line whose contents do not hash to the `hash`
    /// it carries: an edit that leaves the hash stale dies here rather than
    /// reaching a view. The chain to the entry above is *not* checked — a single
    /// line cannot know it, so [`Viewer`](crate::upload::Viewer) checks that
    /// across the batch boundary.
    pub fn parse(line: &str) -> Result<Entry, ChainBreak> {
        let value: Value =
            serde_json::from_str(line).map_err(|e| ChainBreak::NotJson(e.to_string()))?;
        let Value::Object(entry) = value else {
            return Err(ChainBreak::NotJson("not a JSON object".to_string()));
        };
        let text = |key: &str| entry.get(key).and_then(Value::as_str).map(str::to_string);
        let hash = text("hash").ok_or(ChainBreak::NoHash)?;
        if hash != entry_hash(&entry) {
            return Err(ChainBreak::Edited);
        }
        // `at` is display-only: the hash already covers whatever the line really
        // says, so an absent one is zero rather than a refusal.
        let at = entry.get("at").and_then(Value::as_u64).unwrap_or(0);
        Ok(Entry {
            at,
            hash,
            prev: text("prev").ok_or(ChainBreak::NoPrev)?,
            run: text("run").unwrap_or_default(),
            seq: entry.get("seq").and_then(Value::as_u64).ok_or(ChainBreak::NoSeq)?,
            kind: text("type").unwrap_or_default(),
            line: line.to_string(),
        })
    }

    /// The entry's own fields as JSON, for a view that wants one rather than the
    /// line it arrived as.
    pub fn value(&self) -> Value {
        serde_json::from_str(&self.line).unwrap_or(Value::Null)
    }

    /// Whether `prev` names `hash` — the chain-continuity question, which is the
    /// only thing a batch boundary can be asked.
    pub fn continues_from(&self, hash: &str) -> bool {
        self.prev == hash
    }
}

/// Why a line does not hold. The order and the wording follow
/// `crates/cli/src/run_log.rs`'s own check, so a reader told "the entry's
/// contents do not hash to its `hash`" sees the same sentence it would locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainBreak {
    /// The line is not a JSON object.
    NotJson(String),
    /// The entry carries no `hash`.
    NoHash,
    /// The entry's contents do not hash to its `hash` — it was edited.
    Edited,
    /// The entry carries no `prev`.
    NoPrev,
    /// `prev` does not name the entry above it: something was deleted, added or
    /// moved. Carries what was found and what was expected.
    Broken {
        /// The `prev` the line carries.
        found: String,
        /// The hash the line had to name.
        expected: String,
    },
    /// The entry carries no `seq`.
    NoSeq,
    /// `seq` is not the entry's position.
    Seq {
        /// The `seq` the line carries.
        found: u64,
        /// The position it had to carry.
        expected: u64,
    },
    /// The log does not hold as many entries as its index records — it was cut
    /// short, or entries were added to it, after the index was written.
    Count {
        /// How many entries the log holds.
        found: usize,
        /// How many the index records.
        expected: usize,
    },
    /// The log's last entry is not the head its index records. The log may be a
    /// self-consistent chain the index does not describe — which is what a writer
    /// that recomputed the chain, or spliced another run's entries in, leaves
    /// behind.
    Head {
        /// The hash the log ends at.
        found: String,
        /// The head the index records.
        expected: String,
    },
}

impl std::fmt::Display for ChainBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainBreak::NotJson(message) => write!(f, "not a JSON object ({message})"),
            ChainBreak::NoHash => write!(f, "the entry has no `hash`"),
            ChainBreak::Edited => {
                write!(f, "the entry's contents do not hash to its `hash` — it was edited")
            }
            ChainBreak::NoPrev => write!(f, "the entry has no `prev`"),
            ChainBreak::Broken { found, expected } => write!(
                f,
                "`prev` is {found}, not {expected} — an entry was deleted, added or moved"
            ),
            ChainBreak::NoSeq => write!(f, "the entry has no `seq`"),
            ChainBreak::Seq { found, expected } => write!(f, "`seq` is {found}, not {expected}"),
            ChainBreak::Count { found, expected } => {
                write!(f, "the log holds {found} entries, its index records {expected}")
            }
            ChainBreak::Head { found, expected } => {
                write!(f, "the log ends at {found}, its index records {expected}")
            }
        }
    }
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}
