//! Where a run's log and its index live: two traits, so the worker's R2 and D1
//! can sit behind them and a test can sit behind them too.
//!
//! The split is the issue's: the **body** is one immutable blob per run, capped
//! at [`MAX_BLOB_BYTES`], because a run log is a fact and rewriting one is not an
//! operation anyone should offer. The **index** is the small queryable record —
//! which run, how many entries, what head, sealed and verified — because a view
//! listing a repo's runs must not pull every log to answer it.
//!
//! Both are whole-object put/get. There is no listing, no partial update and no
//! delete here: a batch arriving is appended by [`Viewer`](crate::upload::Viewer),
//! which reads what is stored, checks the new lines against it, and writes the
//! whole thing back. A worker over R2/D1 implements these in a handful of
//! statements; an in-memory one is below.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::MAX_BLOB_BYTES;

/// Where a run's entries are kept, as one immutable object.
pub trait Blob: Send + Sync {
    /// Stores `bytes` under `key`, whole or not at all. A key already taken is
    /// overwritten by the caller that gets there second — never by the store.
    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError>;

    /// The bytes under `key`, or `None` when there are none.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
}

/// Where a run's index is kept, queryable by repo and run.
pub trait Db: Send + Sync {
    /// Writes the index for one run, replacing any earlier one.
    fn put_run(&self, index: &RunIndex) -> Result<(), StoreError>;

    /// One run's index.
    fn get_run(&self, repo: &str, run: &str) -> Result<Option<RunIndex>, StoreError>;

    /// Every run in a repo, oldest first.
    fn runs_in_repo(&self, repo: &str) -> Result<Vec<RunIndex>, StoreError>;
}

/// What the module knows about a run without reading its log: enough for the
/// runs-per-repo table and for deciding whether the next batch is the one that
/// continues the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunIndex {
    /// The repository the run happened in.
    pub repo: String,
    /// The run's id.
    pub run: String,
    /// How many batches have been accepted, so a replayed or skipped one is
    /// refused rather than concatenated.
    pub batches: u64,
    /// How many entries the log holds so far.
    pub entries: usize,
    /// The tip's `hash` — what the next entry's `prev` has to name.
    pub head: String,
    /// A seal over the tip has been accepted.
    pub sealed: bool,
    /// That seal's signature verified against a trusted key.
    pub verified: bool,
    /// The first entry's `at`, in unix millis.
    pub started_at: u64,
    /// The last entry's `at`, when the run has finished and said so.
    pub finished_at: Option<u64>,
}

/// The blob key a run's body is stored under. `repo/run` — one object per run, so
/// the whole log is one put and one get.
///
/// This is injective because the two halves are checked before it is built: a
/// repository is `owner/name` and holds `/`s of its own, a run is one id and
/// holds none, so the last `/` is the only place the two can meet. Left unchecked
/// the shape is ambiguous — `acme` + `platform/RUN` and `acme/platform` + `RUN`
/// are the same key and two different runs — and an unsigned writer that guessed
/// one would write over a run somebody else sealed.
pub fn blob_key(repo: &str, run: &str) -> String {
    format!("{repo}/{run}")
}

/// Why a store refused. The message is safe to show a reader: it names what was
/// wrong, never what was in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The name is empty, or holds something a repository or run id never holds —
    /// a `/` inside a run, a `.` or `..` segment, a control character, a space.
    /// Such a name could escape the directory it sits in, or mean two objects at
    /// once, and it is refused rather than rewritten so a caller finds out.
    BadKey(String),
    /// The object is over [`MAX_BLOB_BYTES`].
    TooLarge {
        /// How many bytes were offered.
        found: usize,
        /// The cap.
        limit: usize,
    },
    /// The store itself refused.
    Backend {
        /// What went wrong, safe to print.
        message: String,
    },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::BadKey(reason) => write!(f, "unusable key: {reason}"),
            StoreError::TooLarge { found, limit } => {
                write!(f, "{found} bytes is over the {limit}-byte object cap")
            }
            StoreError::Backend { message } => write!(f, "the store refused: {message}"),
        }
    }
}

/// The bytes a repository or run id is made of: letters, digits, `-`, `_` and
/// `.`. Everything else is refused rather than rewritten, because a sanitizing
/// rewrite would map two spellings onto one key and hide the caller that built
/// the id wrong.
fn is_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

/// Refuses a repository id that could mean two keys or escape the directory it
/// names. A repository is `owner/name`, so a `/` is part of its shape — what is
/// refused is an empty segment, a `.` or `..` segment, and any byte outside
/// `is_id_byte`, control characters among them.
pub fn check_repo(repo: &str) -> Result<(), StoreError> {
    if repo.is_empty() {
        return Err(StoreError::BadKey("the repository is empty".to_string()));
    }
    for segment in repo.split('/') {
        if segment.is_empty() {
            return Err(StoreError::BadKey("the repository has an empty segment".to_string()));
        }
        if segment == "." || segment == ".." {
            return Err(StoreError::BadKey(format!("the repository has a `{segment}` segment")));
        }
        if let Some(byte) = segment.bytes().find(|byte| !is_id_byte(*byte)) {
            return Err(StoreError::BadKey(format!(
                "the repository holds {:?}, which is not a name character",
                byte as char
            )));
        }
    }
    Ok(())
}

/// Refuses a run id. A run is one id and holds no `/` at all — that is what makes
/// [`blob_key`] injective, since the last `/` in a key is then the only place a
/// repository and a run can meet. `platform/RUN` is refused here for the same
/// reason it is refused there: composing it would name the object belonging to
/// repository `acme/platform`, run `RUN`.
pub fn check_run(run: &str) -> Result<(), StoreError> {
    if run.is_empty() {
        return Err(StoreError::BadKey("the run is empty".to_string()));
    }
    if run.contains('/') {
        return Err(StoreError::BadKey("the run holds a `/`".to_string()));
    }
    // `.` and `..` are name characters and path segments both, and the key is
    // laid out like a path. A run called `..` would compose `acme/platform/..`.
    if run == "." || run == ".." {
        return Err(StoreError::BadKey(format!("the run is `{run}`")));
    }
    if let Some(byte) = run.bytes().find(|byte| !is_id_byte(*byte)) {
        return Err(StoreError::BadKey(format!(
            "the run holds {:?}, which is not a name character",
            byte as char
        )));
    }
    Ok(())
}

/// Refuses a key that could mean two objects or escape its directory. The *last*
/// `/` separates the two halves, so a key is kept only when those halves pass
/// [`check_repo`] and [`check_run`]; an interior `/` inside a run is refused
/// rather than read as a nested key, because a nested key is not one this module
/// ever writes.
fn check_key(key: &str) -> Result<(), StoreError> {
    let Some((repo, run)) = key.rsplit_once('/') else {
        return Err(StoreError::BadKey("it does not name a repository and a run".to_string()));
    };
    check_repo(repo)?;
    check_run(run)
}

/// Refuses an object over the cap, so a caller finds out at the store rather than
/// at whatever the worker's bucket would have said.
pub fn check_size(bytes: &[u8]) -> Result<(), StoreError> {
    match bytes.len() > MAX_BLOB_BYTES {
        true => Err(StoreError::TooLarge { found: bytes.len(), limit: MAX_BLOB_BYTES }),
        false => Ok(()),
    }
}

/// [`Blob`] in a `BTreeMap`, behind a mutex. Cheap to clone — a clone shares the
/// same map, so two clones are the same store rather than two of them.
#[derive(Debug, Clone, Default)]
pub struct MemoryBlob {
    objects: std::sync::Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

impl MemoryBlob {
    /// An empty store.
    pub fn new() -> MemoryBlob {
        MemoryBlob::default()
    }
}

/// The lock, recovering from a panic elsewhere: every update is one critical
/// section that cannot be seen half-done, so a poisoned mutex still guards a
/// consistent map.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Blob for MemoryBlob {
    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        check_key(key)?;
        check_size(bytes)?;
        lock(&self.objects).insert(key.to_string(), bytes.to_vec());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(lock(&self.objects).get(key).cloned())
    }
}

/// [`Db`] in a `BTreeMap`, behind a mutex, keyed by repo and then run.
#[derive(Debug, Clone, Default)]
pub struct MemoryDb {
    runs: std::sync::Arc<Mutex<BTreeMap<String, BTreeMap<String, RunIndex>>>>,
}

impl MemoryDb {
    /// An empty store.
    pub fn new() -> MemoryDb {
        MemoryDb::default()
    }
}

impl Db for MemoryDb {
    fn put_run(&self, index: &RunIndex) -> Result<(), StoreError> {
        check_repo(&index.repo)?;
        check_run(&index.run)?;
        lock(&self.runs)
            .entry(index.repo.clone())
            .or_default()
            .insert(index.run.clone(), index.clone());
        Ok(())
    }

    fn get_run(&self, repo: &str, run: &str) -> Result<Option<RunIndex>, StoreError> {
        Ok(lock(&self.runs).get(repo).and_then(|runs| runs.get(run)).cloned())
    }

    fn runs_in_repo(&self, repo: &str) -> Result<Vec<RunIndex>, StoreError> {
        // The map is ordered by run id, and a run id is a ULID — so this is
        // oldest first without a sort that could disagree with itself.
        Ok(lock(&self.runs)
            .get(repo)
            .map(|runs| runs.values().cloned().collect())
            .unwrap_or_default())
    }
}
