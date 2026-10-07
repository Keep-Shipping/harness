//! The [`RunLog`] port: the append-only, hash-chained audit record of a run
//! ([#55](https://github.com/Keep-Shipping/harness/issues/55)).
//!
//! Every run answers "what happened?" — and the answer has to survive being
//! shipped somewhere else and being checked again weeks later by someone who
//! was not there. So the log is append-only (there is no update, amend or
//! delete method on this trait, and there never will be one: a correction is
//! a new entry), sequence-numbered from [`Seq::FIRST`], and hash-chained —
//! every [`LogEntry`] carries the [`Digest`] of the one before it, so removing
//! or editing an entry anywhere in the middle breaks every link after it.
//!
//! # The encoding is in `ks-core`, the hashing is not
//!
//! `ks-core` owns the *encoding* of what a chain link covers and nothing
//! else. [`LogEntry::chained_bytes`] returns the exact bytes an adapter hashes
//! to produce an entry's `hash`:
//!
//! ```text
//! hash = sha256(chained_bytes)
//! chained_bytes = (prev.hex() if prev else no bytes at all)
//!                 ++ 0x00 ++ seq (decimal ASCII) ++ 0x00
//!                 ++ kind ++ 0x00
//!                 ++ step (as_str) or nothing ++ 0x00
//!                 ++ detail ++ 0x00
//!                 ++ unix_millis (decimal ASCII)
//! ```
//!
//! where `unix_millis` is `at.duration_since(UNIX_EPOCH)` in milliseconds, or
//! `0` if `at` is before the epoch. Each `0x00` is written unconditionally —
//! including after `detail` — so the encoding is unambiguous: no two different
//! entries can produce the same byte string by shifting a separator into a
//! field. The first entry of a chain contributes *no* `prev` bytes at all,
//! which is what distinguishes "chain start" from "a link to a zero digest".
//!
//! That split is deliberate. `ks-core` has no dependencies and must stay
//! wasm32-clean, so it never hashes; but a local-file adapter and an OCI
//! referrer adapter must produce the *same* `hash` for the same entry or the
//! chain is meaningless across backends. Owning the encoding here, and only
//! the encoding, is what makes that true.
//!
//! # Redaction and sealing are the caller's job
//!
//! Secret *values* never reach this port — a [`LogEvent::detail`] is free
//! text the engine has already run through the
//! [`Redactor`](super::secrets::Redactor), and while a
//! [`SecretRef`](super::secrets::SecretRef) name may appear, its value may
//! not (see [`Secrets`](super::secrets::Secrets)). The port carries whatever text it is
//! handed; it does not inspect or scrub.
//!
//! Sealing is the other end of the append-only obligation. When a run
//! finishes, its log is sealed for shipping and further appends are refused
//! with [`RunLogError::Sealed`] — that is the trait's way of saying the record
//! is finished, without inventing a "finalize" method whose absence of callers
//! would mean nothing.
//!
//! # What this trait does *not* enforce
//!
//! It cannot. Whether an adapter really appends rather than rewrites, whether
//! a stored `hash` field is the truth, whether `detail` was redacted before
//! it arrived — all of that is the adapter's obligation, documented on
//! [`RunLog`] and checked by the conformance kit, not something a trait method
//! signature can guarantee. What the trait *can* do is make the cheating
//! observable: [`RunLog::verify`] recomputes the chain instead of trusting
//! the stored hashes, so an adapter that rewrites history is caught rather
//! than believed.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use super::BoxFuture;
use super::supply_chain::Digest;
use crate::ids::{RunId, StepId};

/// A run log's entry sequence number, counting from [`Seq::FIRST`].
///
/// One-based on purpose: entry zero of "nothing" reads like a valid sequence
/// number, while an empty log having no entry at all is unambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seq(u64);

impl Seq {
    /// The sequence number of the first entry in a run's log.
    pub const FIRST: Seq = Seq(1);

    /// Wraps a sequence number.
    pub fn new(value: u64) -> Seq {
        Seq(value)
    }

    /// The number itself.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Something that happened during a run, as recorded in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    /// What happened, in the log's own adapter-neutral vocabulary — e.g.
    /// `"step.started"`, `"approval.granted"`. Never empty.
    ///
    /// Deliberately a `String`, not an enum: the catalogue of step kinds
    /// evolves, and an audit record written by an old harness must still
    /// verify against a new one. A closed enum would make every added kind a
    /// breaking change to a hash-chained format.
    pub kind: String,
    /// When it happened. The caller stamps this from the
    /// [`Clock`](super::clock::Clock) port; the log never reads ambient time.
    pub at: SystemTime,
    /// The step this concerns, if any.
    pub step: Option<StepId>,
    /// Free text, already redacted. Secret *values* never reach here — only a
    /// [`SecretRef`](super::secrets::SecretRef) name may. The
    /// [`Redactor`](super::secrets::Redactor) is what guarantees that, and it
    /// runs before the event reaches this port.
    pub detail: String,
}

impl LogEvent {
    /// Builds an event stamped with the current ambient time.
    ///
    /// **This reads the clock directly.** Engine code should prefer building
    /// the event with an explicit `at` taken from its
    /// [`Clock`](super::clock::Clock) port, so a test with a
    /// [`FakeClock`](https://docs.rs/ks-testing/latest/ks_testing/clock/struct.FakeClock.html)
    /// produces reproducible timestamps. This constructor is for callers that
    /// genuinely mean "now" and have no clock to hand.
    pub fn new(kind: impl Into<String>, detail: impl Into<String>) -> LogEvent {
        LogEvent { kind: kind.into(), at: SystemTime::now(), step: None, detail: detail.into() }
    }
}

/// One entry of a run's log: the event, where it sits, and the links that
/// make the log tamper-evident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Where this entry sits in the run's log, counting from [`Seq::FIRST`].
    pub seq: Seq,
    /// What it records.
    pub event: LogEvent,
    /// The digest of the entry before this one; `None` for the first entry of
    /// the chain.
    pub prev: Option<Digest>,
    /// This entry's own digest.
    pub hash: Digest,
}

impl LogEntry {
    /// The exact bytes an adapter hashes to produce this entry's [`hash`](Self::hash).
    ///
    /// The recipe, verbatim from the [module documentation](self):
    ///
    /// ```text
    /// hash = sha256(chained_bytes)
    /// chained_bytes = (prev.hex() if prev else no bytes at all)
    ///                 ++ 0x00 ++ seq (decimal ASCII) ++ 0x00
    ///                 ++ kind ++ 0x00
    ///                 ++ step (as_str) or nothing ++ 0x00
    ///                 ++ detail ++ 0x00
    ///                 ++ unix_millis (decimal ASCII)
    /// ```
    ///
    /// where `unix_millis` is [`at`](LogEvent::at) as milliseconds since the
    /// Unix epoch, or `0` if it is before the epoch. Every `0x00` is written
    /// unconditionally, including after `detail`. The first entry of a chain
    /// emits no `prev` bytes at all.
    ///
    /// `ks-core` deliberately does not hash — see the [module
    /// documentation](self) for why the encoding lives here and the hashing
    /// lives in the adapter.
    pub fn chained_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        if let Some(prev) = &self.prev {
            bytes.extend_from_slice(prev.hex().as_bytes());
        }
        bytes.push(0x00);
        bytes.extend_from_slice(self.seq.get().to_string().as_bytes());
        bytes.push(0x00);
        bytes.extend_from_slice(self.event.kind.as_bytes());
        bytes.push(0x00);
        if let Some(step) = &self.event.step {
            bytes.extend_from_slice(step.as_str().as_bytes());
        }
        bytes.push(0x00);
        bytes.extend_from_slice(self.event.detail.as_bytes());
        bytes.push(0x00);
        bytes.extend_from_slice(unix_millis(self.event.at).to_string().as_bytes());
        bytes
    }
}

/// `at` as milliseconds since the Unix epoch, or `0` for a pre-epoch instant.
///
/// A pre-epoch timestamp is not representable as an unsigned count, and
/// hashing the raw `SystemTime` would drag in its platform-specific internal
/// representation. Zero is the encoding's documented answer for "before the
/// epoch"; it is lossy but it is unambiguous, and every real run is post-1970.
fn unix_millis(at: SystemTime) -> u128 {
    match at.duration_since(UNIX_EPOCH) {
        Ok(since) => since.as_millis(),
        Err(_) => 0,
    }
}

/// What [`RunLog::verify`] found when it walked a run's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogReport {
    /// How many entries the run's log holds.
    pub entries: usize,
    /// The chain head — the `hash` of the last entry — or `None` for an empty
    /// log.
    pub head: Option<Digest>,
    /// The sequence number of the *first* entry that does not verify against
    /// the chain, if the log is damaged.
    pub broken_at: Option<Seq>,
}

impl LogReport {
    /// Whether the whole chain verified.
    pub fn is_intact(&self) -> bool {
        self.broken_at.is_none()
    }
}

/// Why a [`RunLog`] call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunLogError {
    /// The run's log is closed: the run finished and the log was sealed for
    /// shipping. This is the append-only contract enforced at the end of a
    /// run — an entry that arrives after the seal is not an error the log can
    /// absorb.
    Sealed {
        /// The run whose log is sealed.
        run: RunId,
    },
    /// The store itself failed: disk, permissions, transport. What the backend
    /// reported, safe to print — this message is what an operator sees.
    Backend {
        /// What went wrong, safe to print.
        message: String,
    },
}

impl fmt::Display for RunLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunLogError::Sealed { run } => {
                write!(f, "run {run}'s log is sealed and no longer accepts appends")
            }
            RunLogError::Backend { message } => write!(f, "run log failed: {message}"),
        }
    }
}

impl std::error::Error for RunLogError {}

/// The `RunLog` port: the append-only audit record of a run.
///
/// # The contract
///
/// - **Append-only by construction.** There is no update, amend or delete
///   method, and there never will be one. A correction is a new entry.
///   [`append`](RunLog::append) returns the entry's [`Seq`], which must equal
///   the previous `Seq + 1`, and [`Seq::FIRST`] for the first entry of a run.
/// - **Reading is not judging.** [`read`](RunLog::read) returns *every* entry
///   in ascending `Seq` with no gaps, *including* entries that no longer chain
///   correctly. Deciding whether the log can be trusted is
///   [`verify`](RunLog::verify)'s job, not `read`'s. That split is what lets a
///   reader show a damaged log instead of pretending it is empty — a caller
///   that filtered silently would make a tampered run look like a quiet one.
/// - **A run that was never appended to is not an error.** `read` returns
///   `Ok(vec![])` and `verify` returns an intact report over zero entries.
/// - **`verify` recomputes.** It must rebuild the chain from
///   [`LogEntry::chained_bytes`] — not compare the stored `hash` fields, which
///   an adapter rewriting history would have rewritten too — and report the
///   *first* entry that does not match in
///   [`LogReport::broken_at`]. An adapter that cannot recompute, e.g. one
///   holding opaque blobs it never encoded, returns
///   [`RunLogError::Backend`]; it must never return a vacuously intact report.
/// - **Redaction is the caller's job, before `append`.** The port carries
///   whatever [`LogEvent::detail`] text it is given.
///
/// # Adapter obligations
///
/// The local filesystem adapter writes JSONL and may store the file as it is:
/// the customer's own disk is the trust boundary (see ADR 0005). An adapter
/// that ships the log somewhere else — an OCI referrer on the shipped digest,
/// hosted storage — must preserve [`Seq`] order and the hash chain *exactly*,
/// as [`LogEntry::chained_bytes`] specifies it, so the same run verifies to
/// the same head digest in either place.
pub trait RunLog: Send + Sync {
    /// Appends `event` to `run`'s log, returning the entry's [`Seq`].
    ///
    /// Fails with [`RunLogError::Sealed`] once the run's log has been sealed.
    fn append<'a>(
        &'a self,
        run: &'a RunId,
        event: LogEvent,
    ) -> BoxFuture<'a, Result<Seq, RunLogError>>;

    /// Reads every entry of `run`'s log, ascending by [`Seq`], gaps and
    /// broken links included.
    ///
    /// `Ok(vec![])` for a run that has never been appended to.
    fn read<'a>(&'a self, run: &'a RunId) -> BoxFuture<'a, Result<Vec<LogEntry>, RunLogError>>;

    /// Recomputes `run`'s chain and reports whether it holds.
    fn verify<'a>(&'a self, run: &'a RunId) -> BoxFuture<'a, Result<LogReport, RunLogError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    /// A digest with 64 hex digits, as an adapter would hand back after
    /// hashing; `ks-core` never hashes.
    fn digest(byte: &str) -> Digest {
        Digest::sha256_from_hex(&byte.repeat(64)).expect("64 hex digits")
    }

    fn entry(seq: u64, prev: Option<Digest>, at: SystemTime) -> LogEntry {
        LogEntry {
            seq: Seq::new(seq),
            event: LogEvent {
                kind: "step.started".to_string(),
                at,
                step: Some(StepId::new("build")),
                detail: "running build".to_string(),
            },
            prev,
            hash: digest("a"),
        }
    }

    #[test]
    fn the_run_log_trait_is_dyn_compatible() {
        assert_send_sync::<dyn RunLog>();
    }

    #[test]
    fn seq_starts_at_one_and_counts_up() {
        assert_eq!(Seq::FIRST.get(), 1);
        assert_eq!(Seq::FIRST.to_string(), "1");
        assert_eq!(Seq::new(42).get(), 42);
        assert!(Seq::FIRST < Seq::new(2));
    }

    #[test]
    fn run_log_errors_display_actionably() {
        let run = RunId::from_parts(1_700_000_000_000, 7);
        let sealed = RunLogError::Sealed { run: run.clone() }.to_string();
        assert!(sealed.contains("sealed") && sealed.contains(&run.to_string()), "{sealed}");
        let backend = RunLogError::Backend { message: "disk full".to_string() }.to_string();
        assert!(backend.contains("run log") && backend.contains("disk full"), "{backend}");
    }

    /// The recipe, byte for byte. A change here changes every hash every run
    /// has ever produced, so the expected bytes are written out literally
    /// rather than assembled the same way the implementation assembles them.
    #[test]
    fn chained_bytes_has_the_documented_layout() {
        let at = UNIX_EPOCH + std::time::Duration::from_millis(1_700_000_000_123);
        let first = entry(1, None, at);
        assert_eq!(
            first.chained_bytes(),
            b"\
\x001\x00\
step.started\x00\
build\x00\
running build\x00\
1700000000123"
                .to_vec()
        );

        let prev = digest("b");
        let second = entry(2, Some(prev.clone()), at);
        let expected_prefix = {
            let mut bytes = prev.hex().as_bytes().to_vec();
            bytes.push(0x00);
            bytes
        };
        assert_eq!(&second.chained_bytes()[..expected_prefix.len()], &expected_prefix[..]);
        assert_eq!(
            &second.chained_bytes()[expected_prefix.len()..],
            &b"2\x00step.started\x00build\x00running build\x001700000000123"[..]
        );
    }

    #[test]
    fn chained_bytes_separates_a_missing_step_from_an_empty_one() {
        let at = UNIX_EPOCH + std::time::Duration::from_millis(5);
        let mut unstepped = entry(1, None, at);
        unstepped.event.step = None;
        let mut empty_step = unstepped.clone();
        empty_step.event.step = Some(StepId::new(""));
        assert_eq!(
            unstepped.chained_bytes(),
            b"\x001\x00step.started\x00\x00running build\x005".to_vec()
        );
        // Both contribute one NUL either way, so the two agree — the kind and
        // detail fields can never slide across the boundary.
        assert_eq!(unstepped.chained_bytes(), empty_step.chained_bytes());
    }

    #[test]
    fn a_pre_epoch_event_encodes_as_zero_millis() {
        let before = UNIX_EPOCH - std::time::Duration::from_millis(1);
        assert_eq!(unix_millis(before), 0);
        assert_eq!(unix_millis(UNIX_EPOCH), 0);
        assert!(unix_millis(UNIX_EPOCH + std::time::Duration::from_millis(7)) == 7);
    }

    #[test]
    fn a_fresh_report_over_an_empty_log_is_intact() {
        let report = LogReport { entries: 0, head: None, broken_at: None };
        assert!(report.is_intact());
        let damaged =
            LogReport { entries: 3, head: Some(digest("a")), broken_at: Some(Seq::new(2)) };
        assert!(!damaged.is_intact());
        assert_eq!(damaged.broken_at, Some(Seq::new(2)));
    }

    #[test]
    fn log_event_new_stamps_the_ambient_clock() {
        let event = LogEvent::new("approval.granted", "by dana");
        assert_eq!(event.kind, "approval.granted");
        assert_eq!(event.detail, "by dana");
        assert!(event.step.is_none());
        assert!(event.at >= UNIX_EPOCH);
    }
}
