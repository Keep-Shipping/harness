//! The hosted run-log viewer
//! ([#148](https://github.com/Keep-Shipping/harness/issues/148)): a runner
//! uploads its run log in batches, this module refuses anything whose chain or
//! seal does not verify, and what survives is browsable per repo.
//!
//! A run log is only worth reading if it is the run that happened.
//! [`chain`] checks the half of that a hash chain can: every entry names the hash
//! of the one before it, so an edit, a deletion or a reorder does not survive.
//! The other half — a truncation off the end, or a writer that recomputes the
//! chain as it goes, both of which leave a perfectly good chain — needs a
//! signature made from outside the writer, and [`seal`] is where that is checked.
//! Neither half is optional here: a log with no seal is *refused*, not passed.
//!
//! # The seal does not bind the repository
//!
//! [`seal_payload`] signs `run`, `seq` and `head`. **`repo` is not in the signed
//! bytes**, so a validly signed run log obtained from repository A can be
//! uploaded under repository B, and it renders in B's listing with a Verified
//! badge: the signature verifies, the chain walks, the index is B's — and
//! nothing anywhere tied any of it to A.
//!
//! This is inherited from the runner's wire format, not introduced here:
//! `crates/cli`'s `seal_payload` signs the same three fields, and this crate
//! reproduces those bytes exactly so that compatibility is not silently broken.
//! **Closing the gap therefore requires a runner-side format change** — `repo`
//! added to the signed payload, and a new seal version — not a check that could
//! be added to [`Viewer::accept`] alone. Until then the name checks in
//! [`store`] stop a *collision* between two spellings of one key, but they do
//! not stop a log being deliberately re-filed under a different repository.
//!
//! The test `a_valid_seal_from_another_repo_is_not_yet_bound_to_its_repo`
//! pins today's behaviour so this stays visible rather than being rediscovered.
//!
//! **Nothing that identifies a secret or carries a plan value ever gets here.**
//! The runner redacts first — `ks_engine::journal` scrubs every event through the
//! run's `Redactor` before it is appended — and only summaries are sent. What
//! arrives is a `ship.ks` run's shape and its digests, so there is nothing here
//! for a secret to leak into.
//!
//! The issue's `Blob` and `Db` are that platform's vocabulary, so [`store`] models
//! them as two traits: a whole-object store for a run's log, capped at
//! [`MAX_BLOB_BYTES`], and a queryable index of the runs a repo has. Both have
//! in-memory implementations here, so every check runs with no network and no
//! service.
//!
//! What leaves the runner is [ADR
//! 0005](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0005-local-first-core-with-optional-hosted-services.md)'s
//! question — see "What leaves the runner" and "What never leaves the runner".

#![forbid(unsafe_code)]

pub mod chain;
pub mod seal;
pub mod store;
pub mod upload;
pub mod view;

/// The cap on one upload request's body, 64 KiB. Cratefield's `/v1` routes cap a
/// request body here, so a batch over it would be refused by the platform before
/// this module was asked; the same number inside [`Viewer`] is a refusal this
/// module makes itself, as [`Reject::TooLarge`], so a caller never has to learn it
/// from a platform error.
pub const MAX_BATCH_BYTES: usize = 64 * 1024;

/// The cap on one stored object, 10 MiB. A run log is stored as one immutable
/// blob — the whole run in one put — so this is the ceiling on how long a run may
/// be before it needs a different shape. Well above [`MAX_BATCH_BYTES`]: batches
/// are the request cap, this is the storage cap.
pub const MAX_BLOB_BYTES: usize = 10 * 1024 * 1024;

pub use chain::{ChainBreak, Entry, GENESIS, canonical, canonical_value, entry_hash};
pub use seal::{
    HEAD_ANNOTATION, KeyError, RUN_ANNOTATION, RUN_LOG_ARTIFACT_TYPE, SEALS_SUFFIX, Seal,
    SealRefusal, TrustedKeys, seal_payload,
};
pub use store::{
    Blob, Db, MemoryBlob, MemoryDb, RunIndex, StoreError, blob_key, check_repo, check_run,
};
pub use upload::{Batch, BatchError, Reject, Viewer, batches};
pub use view::{
    Badge, Decision, RunSummary, Status, Story, badge, index_page, run_page, story, summarize,
};

const _: () = {
    // Batching only makes sense while a request cap is below a storage cap: one
    // batch is meant to fit in one stored object.
    assert!(MAX_BATCH_BYTES < MAX_BLOB_BYTES);
    // Both numbers are named in refusals a reader is shown, so they are checked
    // rather than trusted.
    assert!(MAX_BATCH_BYTES == 65_536);
    assert!(MAX_BLOB_BYTES == 10_485_760);
};
