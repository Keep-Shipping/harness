//! The local metadata cache behind `blocks search --offline`: one file per
//! search, keyed by (index base url, query text, limit), holding the *verbatim*
//! body the index answered with plus the moment it was fetched.
//!
//! The payload is an envelope, not a re-encoding: the cached bytes are handed
//! straight back to [`crate::blocks_index::parse_response`], so a cached answer
//! gets the same contract validation as a live one — name length, control
//! characters, digests, publisher and signature discriminants — with no second
//! serialisation to keep in step with the wire format. All the cache adds is
//! the domain tag and the timestamp.
//!
//! The house rules from the engine's step cache apply unchanged: the root is
//! `$XDG_CACHE_HOME/keepshipping/blocks` or `$HOME/.cache/keepshipping/blocks`
//! and `None` when neither is set; an entry that will not decode is a miss,
//! not an error; a write that fails is a silent no-op; entries are written to
//! a temporary file and renamed into place, so a reader never sees half an
//! entry.

use std::fs;
use std::path::PathBuf;

use sha2::{Digest as _, Sha256};

/// The tag every cached body carries, so a file written by some other
/// encoding or a future version is a miss rather than garbage.
const TAG: &str = "keepshipping-blocks-cache/1";

/// One search's cached answer: the raw index response body and when it was
/// fetched, as unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedSearch {
    /// The index's response body, byte for byte as it was served.
    pub body: Vec<u8>,
    /// When the entry was written, in unix seconds.
    pub fetched_at: u64,
}

/// One cache entry per search, as a file under a root directory.
pub struct BlocksCache {
    root: PathBuf,
}

impl BlocksCache {
    /// A cache rooted at `root`; the directory is created on the first write.
    pub fn new(root: impl Into<PathBuf>) -> BlocksCache {
        BlocksCache { root: root.into() }
    }

    /// A cache at the user's cache directory, or `None` when neither
    /// `$XDG_CACHE_HOME` nor `$HOME` is set — in which case nothing is cached
    /// and the online path behaves exactly as it did before.
    pub fn in_default_root() -> Option<BlocksCache> {
        default_root().map(BlocksCache::new)
    }

    /// Where entries for one search live, whether or not they exist.
    pub fn entry_path(&self, base: &str, query: &str, limit: u32) -> PathBuf {
        self.root.join(key(base, query, limit))
    }

    /// The cached answer for this search, or `None` when it was never cached
    /// or the entry will not decode. Never an error: a cache is an
    /// optimisation, not a source of truth.
    pub fn get(&self, base: &str, query: &str, limit: u32) -> Option<CachedSearch> {
        let bytes = fs::read(self.entry_path(base, query, limit)).ok()?;
        let (fetched_at, body) = decode(&bytes)?;
        Some(CachedSearch { body: body.to_vec(), fetched_at })
    }

    /// Records this search's answer. Every failure is a no-op: an unwritable
    /// cache costs nothing but the entry.
    pub fn put(&self, base: &str, query: &str, limit: u32, body: &[u8], fetched_at: u64) {
        let path = self.entry_path(base, query, limit);
        if fs::create_dir_all(&self.root).is_err() {
            return;
        }
        let name =
            path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        let temporary = self.root.join(format!("{name}.{}.tmp", std::process::id()));
        if fs::write(&temporary, encode(fetched_at, body)).is_err() {
            let _ = fs::remove_file(&temporary);
            return;
        }
        if fs::rename(&temporary, &path).is_err() {
            let _ = fs::remove_file(&temporary);
        }
    }
}

/// `$XDG_CACHE_HOME/keepshipping/blocks`, or `$HOME/.cache/keepshipping/blocks`,
/// or `None` when the environment names neither. `XDG_CACHE_HOME` counts only
/// when it is absolute, so a relative value cannot smuggle the cache somewhere
/// unexpected.
pub fn default_root() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from).map(|home| home.join(".cache")))?;
    Some(base.join("keepshipping").join("blocks"))
}

/// The entry name for one search: a sha256 over the base url, the trimmed
/// query text and the limit, hex-encoded. The base url is part of the key on
/// purpose — two indexes answer the same query differently, and an offline
/// search must not silently serve one index's answers for another's.
///
/// Each field is hashed as its length followed by its bytes rather than
/// joined by a separator: a separator can appear inside a base url or a query,
/// and no amount of joining then distinguishes `(base "a\x1fb", query "c")`
/// from `(base "a", query "b\x1fc")`. Length-prefixing has no such reading.
pub fn key(base: &str, query: &str, limit: u32) -> String {
    let mut hasher = Sha256::new();
    for field in [base.as_bytes(), query.trim().as_bytes()] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.update(limit.to_le_bytes());
    hex(&hasher.finalize())
}

/// The on-disk envelope: the tag and the fetch time on one line, then the
/// index's own bytes untouched.
pub fn encode(fetched_at: u64, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{TAG} {fetched_at}\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// What [`encode`] wrote: the fetch time and the body's bytes, or `None` for
/// anything else — a foreign file, a truncated one, a header that is not the
/// tag followed by a `u64`. A miss, never a partial read.
pub fn decode(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let newline = bytes.iter().position(|byte| *byte == b'\n')?;
    let header = std::str::from_utf8(&bytes[..newline]).ok()?;
    let timestamp = header.strip_prefix(TAG)?.strip_prefix(' ')?;
    let fetched_at = timestamp.parse::<u64>().ok()?;
    Some((fetched_at, &bytes[newline + 1..]))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &[u8] = br#"{"results":[{"name":"acme/rollout","publisher":{"kind":"key","key_id":"2026-q3"},"versions":[]}]}"#;

    #[test]
    fn the_key_moves_with_the_base_the_query_and_the_limit() {
        let this = key("http://index.example", "rollout", 20);
        assert_eq!(this.len(), 64, "a hex sha256 is 64 characters");
        assert!(this.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(this, key("http://other.example", "rollout", 20));
        assert_ne!(this, key("http://index.example", "rollback", 20));
        assert_ne!(this, key("http://index.example", "rollout", 5));
    }

    #[test]
    fn the_key_is_stable_and_ignores_surrounding_whitespace() {
        assert_eq!(
            key("http://index.example/v1", "rollout", 20),
            key("http://index.example/v1", "  rollout ", 20)
        );
        assert_eq!(
            key("http://index.example", "rollout", 20),
            key("http://index.example", "rollout", 20)
        );
    }

    #[test]
    fn the_key_does_not_conflate_a_separator_inside_a_field() {
        // The pair that collided when the three fields were joined with
        // U+001F: neither the join nor `trim` can see inside a field.
        assert_ne!(
            key("http://h/a\u{1f}b", "c", 20),
            key("http://h/a", "b\u{1f}c", 20),
            "one index's answers must never be served for another's"
        );
        // Nor can a length prefix be faked by shifting bytes across a boundary.
        assert_ne!(key("http://h/ab", "c", 20), key("http://h/a", "bc", 20));
    }

    #[test]
    fn a_round_trip_returns_the_body_byte_for_byte() {
        let encoded = encode(1_700_000_000, BODY);
        let (fetched_at, body) = decode(&encoded).expect("an entry this module wrote");
        assert_eq!(fetched_at, 1_700_000_000);
        assert_eq!(body, BODY);
        // A body that is not valid utf-8 still round-trips: it is the index's
        // bytes, not our text.
        let raw = [0xff_u8, 0x00, b'{'];
        assert_eq!(decode(&encode(1, &raw)).map(|(_, body)| body), Some(&raw[..]));
    }

    #[test]
    fn an_entry_without_the_tag_is_a_miss() {
        assert_eq!(decode(BODY), None);
        assert_eq!(decode(b"keepshipping-step-cache-outputs/1 12\n{}"), None);
        assert_eq!(decode(b""), None);
    }

    #[test]
    fn a_header_that_is_not_a_timestamp_is_a_miss() {
        assert_eq!(decode(b"keepshipping-blocks-cache/1 later\n{}"), None);
        assert_eq!(decode(b"keepshipping-blocks-cache/1 -1\n{}"), None);
        assert_eq!(decode(b"keepshipping-blocks-cache/1\n{}"), None);
        assert_eq!(decode(b"keepshipping-blocks-cache/1 1 2\n{}"), None);
    }

    #[test]
    fn a_truncated_entry_is_a_miss() {
        let full = encode(1_700_000_000, BODY);
        let header = format!("{TAG} 1700000000\n").len();
        // Anything cut inside the header has no terminator left to split on.
        for cut in [1, 20, header - 1] {
            assert_eq!(decode(&full[..cut]), None, "an entry cut at {cut} is not an answer");
        }
        // A body cut short still carries its envelope, so it is the index
        // contract that rejects it — which is the point of storing the body
        // verbatim rather than re-encoding it.
        let (_, truncated) = decode(&full[..full.len() - 2]).expect("the envelope is intact");
        assert!(crate::blocks_index::parse_response(truncated).is_err());
    }

    #[test]
    fn a_cache_round_trips_through_the_filesystem() {
        let root = std::env::temp_dir().join(format!("ks-blocks-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let cache = BlocksCache::new(&root);
        assert_eq!(cache.get("http://index.example", "rollout", 20), None);
        cache.put("http://index.example", "rollout", 20, BODY, 42);
        let hit = cache.get("http://index.example", "rollout", 20).expect("the entry just written");
        assert_eq!(hit.body, BODY);
        assert_eq!(hit.fetched_at, 42);
        // A different base, query or limit is a different entry, never this one.
        assert_eq!(cache.get("http://other.example", "rollout", 20), None);
        assert_eq!(cache.get("http://index.example", "rollback", 20), None);
        assert_eq!(cache.get("http://index.example", "rollout", 5), None);
        // No temporary file is left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&root)
            .expect("the cache directory")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unwritable_root_costs_nothing() {
        // A path under a regular file cannot be created; the put is a no-op
        // rather than a panic, and the get is a miss.
        let root =
            std::env::temp_dir().join(format!("ks-blocks-cache-file-{}", std::process::id()));
        std::fs::write(&root, b"not a directory").expect("a blocking file");
        let cache = BlocksCache::new(root.join("under"));
        cache.put("http://index.example", "rollout", 20, BODY, 1);
        assert_eq!(cache.get("http://index.example", "rollout", 20), None);
        let _ = std::fs::remove_file(&root);
    }
}
