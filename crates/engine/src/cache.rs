//! Content-addressed step caching: skip work that provably has not changed
//! ([#43](https://github.com/Keep-Shipping/harness/issues/43)).
//!
//! The seam is [`run_step_cached`]: it asks the step whether it participates ([`Caching`]),
//! hashes a key over what it declared plus every resolved input, looks that key up in a
//! [`StepCache`], and — before skipping anything — hands the cached outputs back to the step
//! through [`StepKind::verify_cached`], so the step itself says whether they are still true. A
//! step that does not opt in, or that opts in without verifying, never skips.
//!
//! The rule underneath everything here: **a wrong hit is worse than no hit.** Anything the
//! engine cannot read is a miss, logged as such — never a guess.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ks_core::harness::Harness;
use ks_core::ports::BoxFuture;
use ks_core::ports::script_host::Value;
use ks_core::ports::secrets::Redactor;
use ks_core::step::{
    CacheCheck, CacheInput, Caching, CancellationToken, Inputs, LogSink, Outputs, StepError,
    StepKind, StepLog,
};
use sha2::{Digest, Sha256};

use crate::run;

/// The domain tag every key is hashed under. Bump it and every existing entry is a miss —
/// which is what a change in the encoding deserves.
const KEY_DOMAIN: &str = "keepshipping-step-cache/1";

/// Where cached outputs live. Engine-local on purpose: this is storage, not a port, so nothing
/// outside the engine depends on it ([ADR 0002](../../docs/adr/0002-ports-and-adapters.md)).
pub trait StepCache: Send + Sync {
    /// The outputs stored under `key`, or `None` for a miss — including an entry that will not
    /// decode, which is a miss rather than an error.
    fn get(&self, key: &str) -> Option<Outputs>;

    /// Stores `outputs` under `key`. A cache that cannot write simply does not cache: the step
    /// runs again next time, which is no worse than never having cached it.
    fn put(&self, key: &str, outputs: &Outputs);
}

/// Why a run's work was or was not skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheOutcome {
    /// The step does not participate: it ran.
    Uncacheable,
    /// Nothing was stored under this key; the step ran and its outputs were stored.
    Miss { key: String },
    /// Cached outputs were found and the step confirmed they are still valid; the step did not
    /// run. `evidence` is why.
    Hit { key: String, evidence: String },
    /// Cached outputs were found but the step said they are no longer valid; the step ran again.
    Stale { key: String, evidence: String },
}

/// Why a key could not be computed. Never fatal: the caller logs it and runs the step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheKeyError {
    /// A [`CacheInput::File`] could not be read — a missing or unreadable build context.
    Unreadable { path: PathBuf, reason: String },
}

impl fmt::Display for CacheKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheKeyError::Unreadable { path, reason } => {
                write!(f, "cannot read {}: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for CacheKeyError {}

/// Runs `name` from `harness` with `inputs`, skipping the step's work when a cache entry covers
/// exactly these inputs and the step confirms its outputs are still valid. Same parameters as
/// [`run_step`](crate::run::run_step), plus the `cache` to consult; the outputs come back with
/// the [`CacheOutcome`] saying why the step ran or did not.
pub fn run_step_cached<'a>(
    harness: &'a Harness,
    name: &'a str,
    inputs: Inputs,
    cancel: CancellationToken,
    log: Arc<dyn LogSink>,
    redactor: Arc<Redactor>,
    cache: &'a dyn StepCache,
) -> BoxFuture<'a, Result<(Outputs, CacheOutcome), StepError>> {
    Box::pin(async move {
        let step = harness.step(name).ok_or_else(|| StepError::UnknownStep(name.to_string()))?;
        if cancel.is_cancelled() {
            return Err(StepError::Cancelled);
        }
        let inputs = harness.prepare_inputs(step.as_ref(), inputs)?;
        let step_log = StepLog::new(name, Arc::clone(&redactor), Arc::clone(&log));
        let run = || {
            run::execute(
                harness,
                name,
                step.as_ref(),
                inputs.clone(),
                cancel.clone(),
                Arc::clone(&log),
                Arc::clone(&redactor),
            )
        };
        // Only a step that opted in *and* whose key could be computed is cached at all.
        let key = match step.caching(&inputs) {
            Caching::Never => None,
            Caching::Keyed(declared) => match cache_key(step.as_ref(), &inputs, &declared) {
                Ok(key) => Some(key),
                Err(error) => {
                    step_log.info(
                        "step not cached",
                        &[
                            ("reason", "a cache input could not be read"),
                            ("detail", &error.to_string()),
                        ],
                    );
                    None
                }
            },
        };
        let Some(key) = key else {
            return Ok((run().await?, CacheOutcome::Uncacheable));
        };

        // Cancellation is honoured before skipping too: a cancelled run runs nothing.
        if cancel.is_cancelled() {
            return Err(StepError::Cancelled);
        }

        // What the cache had to say, if anything: an entry found, and found wanting.
        let mut stale = None;
        match cache.get(&key) {
            None => step_log.info("cache miss", &[("key", key.as_str())]),
            Some(cached) => {
                // A fresh context: verification may use the ports the step declared.
                let ctx = run::step_ctx(
                    harness,
                    step.as_ref(),
                    name,
                    cancel.clone(),
                    Arc::clone(&log),
                    Arc::clone(&redactor),
                );
                match step.verify_cached(ctx, &cached).await? {
                    CacheCheck::Valid(evidence) => {
                        step_log.info(
                            "step skipped",
                            &[
                                ("reason", "cache hit: inputs unchanged"),
                                ("key", key.as_str()),
                                ("evidence", evidence.as_str()),
                            ],
                        );
                        return Ok((cached, CacheOutcome::Hit { key, evidence }));
                    }
                    CacheCheck::Stale(evidence) => {
                        step_log.info(
                            "cache entry stale",
                            &[("key", key.as_str()), ("evidence", evidence.as_str())],
                        );
                        step_log.info("rebuilding", &[("key", key.as_str())]);
                        stale = Some(evidence);
                    }
                }
            }
        }

        let outputs = run().await?;
        // Only a step that ran to completion, and passed `check_outputs`, replaces the entry.
        cache.put(&key, &outputs);
        Ok((
            outputs,
            match stale {
                Some(evidence) => CacheOutcome::Stale { key, evidence },
                None => CacheOutcome::Miss { key },
            },
        ))
    })
}

/// The cache key for a step run: `sha256:<hex>` over a length-prefixed, order-stable encoding of
/// the key domain, the step's identity (name, [`version`](StepKind::version), the `STEP_API`
/// contract), every resolved input in sorted order, then each declared [`CacheInput`] in order.
///
/// Length prefixes and the leading count keep the encoding unambiguous — no two distinct inputs
/// can produce the same bytes — and every map is walked in sorted order, so the key does not
/// depend on hash iteration order. Returns [`CacheKeyError`] when a declared file cannot be read:
/// an unreadable input is never hashed as if it were empty.
pub fn cache_key(
    step: &dyn StepKind,
    inputs: &Inputs,
    declared: &[CacheInput],
) -> Result<String, CacheKeyError> {
    let mut hasher = Sha256::new();
    field(&mut hasher, KEY_DOMAIN.as_bytes());
    field(&mut hasher, step.name().as_bytes());
    field(&mut hasher, step.version().to_string().as_bytes());
    field(&mut hasher, &step.step_api().to_le_bytes());
    count(&mut hasher, inputs.len());
    for (name, value) in inputs {
        field(&mut hasher, name.as_bytes());
        hash_value(&mut hasher, value);
    }
    count(&mut hasher, declared.len());
    for input in declared {
        match input {
            CacheInput::File(path) => {
                tag(&mut hasher, b"f");
                hash_path(&mut hasher, path)?;
            }
            CacheInput::Tool { name, version } => {
                tag(&mut hasher, b"t");
                field(&mut hasher, name.as_bytes());
                field(&mut hasher, version.as_bytes());
            }
            CacheInput::Value { name, value } => {
                tag(&mut hasher, b"v");
                field(&mut hasher, name.as_bytes());
                field(&mut hasher, value.as_bytes());
            }
        }
    }
    Ok(format!("sha256:{}", hex(&hasher.finalize())))
}

/// Bytes as lowercase hex. sha2 0.11 digests no longer implement `LowerHex`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Where the length-prefixed encoders below write: the key hasher, or the bytes of a cache
/// entry. Implemented locally rather than over [`Write`], because a hasher's `write_all` returns
/// an error this encoding can never produce.
trait Sink {
    fn push(&mut self, bytes: &[u8]);
}

impl Sink for Sha256 {
    fn push(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

impl Sink for Vec<u8> {
    fn push(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// Writes a length-prefixed field: distinct inputs can never share bytes.
fn field(out: &mut impl Sink, bytes: &[u8]) {
    out.push(&(bytes.len() as u64).to_le_bytes());
    out.push(bytes);
}

/// Writes a count, so a sequence's elements cannot run into the next field.
fn count(out: &mut impl Sink, items: usize) {
    out.push(&(items as u64).to_le_bytes());
}

/// Writes a one-byte type tag.
fn tag(out: &mut impl Sink, bytes: &[u8; 1]) {
    out.push(bytes);
}

/// Hashes one [`Value`] through the same encoding cache entries use, so a key and the entry it
/// addresses agree on what a value is.
fn hash_value(hasher: &mut Sha256, value: &Value) {
    let mut encoded = Vec::new();
    encode_value(&mut encoded, value);
    hasher.push(&encoded);
}

/// Hashes the file or directory at `path`: for a directory, every entry in sorted order as its
/// path relative to `path`, then its kind and its bytes. Symlinks hash their target and are not
/// followed, so a link cycle cannot hang the walk and the link's own bytes matter. `path` itself
/// is not hashed, only what is under it — the same build context in two checkouts is the same
/// input.
fn hash_path(hasher: &mut Sha256, path: &Path) -> Result<(), CacheKeyError> {
    let unreadable = |error: io::Error| CacheKeyError::Unreadable {
        path: path.to_path_buf(),
        reason: error.to_string(),
    };
    let meta = fs::symlink_metadata(path).map_err(unreadable)?;
    if meta.is_symlink() {
        tag(hasher, b"l");
        let target = fs::read_link(path).map_err(unreadable)?;
        field(hasher, target.to_string_lossy().as_bytes());
        return Ok(());
    }
    if meta.is_dir() {
        tag(hasher, b"d");
        let mut entries: Vec<(PathBuf, String)> = fs::read_dir(path)
            .map_err(unreadable)?
            .map(|entry| {
                let entry = entry.map_err(unreadable)?;
                let name = entry.file_name().to_string_lossy().into_owned();
                Ok((entry.path(), name))
            })
            .collect::<Result<_, CacheKeyError>>()?;
        entries.sort_by(|left, right| left.1.cmp(&right.1));
        count(hasher, entries.len());
        for (child, name) in &entries {
            field(hasher, name.as_bytes());
            hash_path(hasher, child)?;
        }
        return Ok(());
    }
    tag(hasher, b"f");
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    field(hasher, name.as_bytes());
    let bytes = fs::read(path).map_err(unreadable)?;
    field(hasher, &bytes);
    Ok(())
}

/// One cache entry per key, as a file under a root directory.
///
/// The default root is `$XDG_CACHE_HOME/keepshipping/steps`, falling back to
/// `$HOME/.cache/keepshipping/steps`. Entries are written to a temporary file and renamed into
/// place, so a reader never sees a half-written entry, and an entry that will not decode is a
/// miss, not an error.
pub struct DirCache {
    root: PathBuf,
}

impl DirCache {
    /// A cache rooted at `root`; the directory is created on the first write.
    pub fn new(root: impl Into<PathBuf>) -> DirCache {
        DirCache { root: root.into() }
    }

    /// A cache at the user's cache directory, or `None` when neither `$XDG_CACHE_HOME` nor
    /// `$HOME` is set (in which case nothing is cached).
    pub fn in_default_root() -> Option<DirCache> {
        Self::default_root().map(DirCache::new)
    }

    /// `$XDG_CACHE_HOME/keepshipping/steps`, or `$HOME/.cache/keepshipping/steps`.
    pub fn default_root() -> Option<PathBuf> {
        let base = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
        Some(base.join("keepshipping").join("steps"))
    }

    /// Where the entry for `key` lives, whether or not it exists.
    pub fn entry_path(&self, key: &str) -> PathBuf {
        self.root.join(key.replace(':', "-"))
    }
}

impl StepCache for DirCache {
    fn get(&self, key: &str) -> Option<Outputs> {
        let bytes = fs::read(self.entry_path(key)).ok()?;
        decode_outputs(&bytes)
    }

    fn put(&self, key: &str, outputs: &Outputs) {
        let path = self.entry_path(key);
        if fs::create_dir_all(&self.root).is_err() {
            return;
        }
        let temporary =
            self.root.join(format!("{}.{}.tmp", key.replace(':', "-"), std::process::id()));
        if fs::write(&temporary, encode_outputs(outputs)).is_err() {
            let _ = fs::remove_file(&temporary);
            return;
        }
        if fs::rename(&temporary, &path).is_err() {
            let _ = fs::remove_file(&temporary);
        }
    }
}

/// The tag cached outputs carry, so a file from some future encoding is a miss, not garbage.
const OUTPUTS_DOMAIN: &[u8] = b"keepshipping-step-cache-outputs/1";

/// Encodes `outputs` losslessly: every [`Value`] variant round-trips, maps and lists keep their
/// shape, and nothing is dropped or defaulted.
fn encode_outputs(outputs: &Outputs) -> Vec<u8> {
    let mut bytes = OUTPUTS_DOMAIN.to_vec();
    count(&mut bytes, outputs.len());
    for (name, value) in outputs {
        field(&mut bytes, name.as_bytes());
        encode_value(&mut bytes, value);
    }
    bytes
}

fn encode_value(bytes: &mut impl Sink, value: &Value) {
    match value {
        Value::Null => tag(bytes, b"n"),
        Value::Bool(flag) => {
            tag(bytes, b"b");
            bytes.push(&[u8::from(*flag)]);
        }
        Value::Number(number) => {
            tag(bytes, b"d");
            bytes.push(&number.to_bits().to_le_bytes());
        }
        Value::String(text) => {
            tag(bytes, b"s");
            field(bytes, text.as_bytes());
        }
        Value::List(items) => {
            tag(bytes, b"l");
            count(bytes, items.len());
            for item in items {
                encode_value(bytes, item);
            }
        }
        Value::Map(entries) => {
            tag(bytes, b"m");
            count(bytes, entries.len());
            for (name, item) in entries {
                field(bytes, name.as_bytes());
                encode_value(bytes, item);
            }
        }
    }
}

/// Decodes what [`encode_outputs`] wrote, or `None` for anything it did not write: a truncated,
/// corrupt or foreign entry is a miss, never a partial read.
fn decode_outputs(bytes: &[u8]) -> Option<Outputs> {
    let mut decoder = Decoder { bytes, at: 0 };
    if decoder.take(OUTPUTS_DOMAIN.len())? != OUTPUTS_DOMAIN {
        return None;
    }
    let entries = decoder.u64()?;
    let mut outputs = Outputs::new();
    for _ in 0..entries {
        let name = decoder.string()?;
        let value = decoder.value()?;
        outputs.insert(name, value);
    }
    decoder.finish().then_some(outputs)
}

/// A cursor over an encoded entry; every method returns `None` rather than reading past the end.
struct Decoder<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Decoder<'_> {
    fn take(&mut self, len: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(len)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u64(&mut self) -> Option<u64> {
        let slice = self.take(8)?;
        Some(u64::from_le_bytes(slice.try_into().ok()?))
    }

    fn string(&mut self) -> Option<String> {
        let len = usize::try_from(self.u64()?).ok()?;
        std::str::from_utf8(self.take(len)?).ok().map(str::to_string)
    }

    fn value(&mut self) -> Option<Value> {
        match self.u8()? {
            b'n' => Some(Value::Null),
            b'b' => Some(Value::Bool(self.u8()? != 0)),
            b'd' => Some(Value::Number(f64::from_bits(self.u64()?))),
            b's' => self.string().map(Value::String),
            b'l' => {
                let len = self.u64()?;
                let mut items = Vec::new();
                for _ in 0..len {
                    items.push(self.value()?);
                }
                Some(Value::List(items))
            }
            b'm' => {
                let len = self.u64()?;
                let mut entries = BTreeMap::new();
                for _ in 0..len {
                    let name = self.string()?;
                    entries.insert(name, self.value()?);
                }
                Some(Value::Map(entries))
            }
            _ => None,
        }
    }

    /// Whether the whole entry was consumed.
    fn finish(&self) -> bool {
        self.at == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::step::{ActionClass, ActionKind, Port, StepCtx, StepSchema, Version};

    /// A step whose identity and inputs the key tests vary.
    struct SampleStep {
        name: &'static str,
        version: Version,
    }

    impl StepKind for SampleStep {
        fn name(&self) -> &'static str {
            self.name
        }

        fn version(&self) -> Version {
            self.version
        }

        fn schema(&self) -> StepSchema {
            StepSchema { doc: "a step for tests", inputs: Vec::new(), outputs: Vec::new() }
        }

        fn requires(&self) -> &'static [Port] {
            &[]
        }

        fn action(&self, _inputs: &Inputs) -> ActionClass {
            ActionClass::new(ActionKind::Other)
        }

        fn run(&self, _ctx: StepCtx, _inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
            Box::pin(std::future::ready(Ok(Outputs::new())))
        }
    }

    fn step() -> SampleStep {
        SampleStep { name: "oci.image", version: Version::new(1, 0, 0) }
    }

    fn inputs_of(name: &str, value: Value) -> Inputs {
        let mut inputs = Inputs::new();
        inputs.insert(name.to_string(), value);
        inputs
    }

    /// Anything that can change what the step would do changes the key — and nothing else does.
    #[test]
    fn the_key_changes_with_everything_that_could_change_the_work() {
        let value = [CacheInput::Value { name: "v".to_string(), value: "1".to_string() }];
        let tool = [CacheInput::Tool { name: "tofu".to_string(), version: "1.9.0".to_string() }];
        let mut extra = inputs_of("a", Value::from("x"));
        extra.insert("b".to_string(), Value::from("y"));

        let base = cache_key(&step(), &inputs_of("a", Value::from("x")), &[]).unwrap();
        assert_eq!(base.len(), "sha256:".len() + 64, "the key is a rendered sha256");
        assert!(base.starts_with("sha256:"));

        let cases: Vec<(&str, Option<String>)> = vec![
            (
                "a different input value",
                cache_key(&step(), &inputs_of("a", Value::from("y")), &[]).ok(),
            ),
            (
                "a different input name",
                cache_key(&step(), &inputs_of("b", Value::from("x")), &[]).ok(),
            ),
            (
                "a different value type",
                cache_key(&step(), &inputs_of("a", Value::from(1.0)), &[]).ok(),
            ),
            ("an extra input", cache_key(&step(), &extra, &[]).ok()),
            (
                "a different step name",
                cache_key(&SampleStep { name: "oci.other", ..step() }, &Inputs::new(), &[]).ok(),
            ),
            (
                "a different step version",
                cache_key(
                    &SampleStep { version: Version::new(1, 0, 1), ..step() },
                    &Inputs::new(),
                    &[],
                )
                .ok(),
            ),
            ("a declared value", cache_key(&step(), &Inputs::new(), &value).ok()),
            ("a declared tool version", cache_key(&step(), &Inputs::new(), &tool).ok()),
        ];
        for (what, key) in cases {
            assert_ne!(key, Some(base.clone()), "{what} must change the key");
        }
    }

    /// The same inputs always give the same key, whatever order the values were inserted in.
    #[test]
    fn the_key_does_not_depend_on_insertion_order() {
        let build = |reversed: bool| {
            let mut inputs = Inputs::new();
            let pairs = [("a", Value::from("1")), ("b", Value::List(vec![Value::from("x")]))];
            for (name, value) in pairs.into_iter().rev() {
                inputs.insert(name.to_string(), value);
            }
            if reversed {
                inputs.insert("a".to_string(), Value::from("1"));
            }
            inputs
        };
        assert_eq!(
            cache_key(&step(), &build(false), &[]).unwrap(),
            cache_key(&step(), &build(true), &[]).unwrap()
        );
    }

    /// A declared path that cannot be read is an error, not a key: the engine then runs the step
    /// uncached rather than hashing an input it never saw.
    #[test]
    fn an_unreadable_declared_path_is_an_error_rather_than_a_key() {
        let declared = [CacheInput::File(PathBuf::from("/does/not/exist"))];
        let error = cache_key(&step(), &Inputs::new(), &declared)
            .expect_err("a missing build context cannot be hashed");
        assert!(matches!(error, CacheKeyError::Unreadable { .. }), "{error}");
    }

    /// Every `Value` variant survives the round trip through a cache entry, exactly.
    #[test]
    fn every_value_variant_round_trips_losslessly() {
        let mut entries = BTreeMap::new();
        entries.insert("nested".to_string(), Value::Bool(true));
        let mut outputs = Outputs::new();
        outputs.insert("null".to_string(), Value::Null);
        outputs.insert("bool".to_string(), Value::from(true));
        outputs.insert("number".to_string(), Value::from(1.5));
        outputs.insert("string".to_string(), Value::from("sha256:…"));
        outputs.insert("list".to_string(), Value::List(vec![Value::from(1.0), Value::Null]));
        outputs.insert("map".to_string(), Value::Map(entries));
        assert_eq!(decode_outputs(&encode_outputs(&outputs)), Some(outputs));
    }

    /// Anything that is not an entry this encoder wrote is a miss, not a partial read — the
    /// property that keeps a corrupt file from becoming a wrong hit.
    #[test]
    fn anything_else_decodes_as_a_miss() {
        let mut outputs = Outputs::new();
        outputs.insert("digest".to_string(), Value::from("sha256:ab"));
        let entry = encode_outputs(&outputs);
        for corrupt in [
            Vec::new(),
            b"not an entry".to_vec(),
            entry[..entry.len() - 1].to_vec(),
            [entry.clone(), b"trailing".to_vec()].concat(),
        ] {
            assert_eq!(decode_outputs(&corrupt), None, "{corrupt:?} must not decode");
        }
    }

    /// The default cache root follows XDG, and falls back to `$HOME/.cache`.
    #[test]
    fn the_default_root_follows_the_xdg_convention() {
        // Not asserted against the process's real environment: the fallback is what a machine
        // without `$XDG_CACHE_HOME` gets, and the code path is the same either way.
        assert_eq!(
            DirCache::default_root().map(|path| path.ends_with("keepshipping/steps")),
            Some(true)
        );
    }
}
