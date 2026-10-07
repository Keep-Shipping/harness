//! `ship.lock`: the pins ADR 0011 settles for a block reference
//! ([#81](https://github.com/Keep-Shipping/harness/issues/81)).
//!
//! `@v3` is the highest published **release** of major 3 and never a
//! prerelease; `@3.1.2` is exact; `@sha256:…` pins the content.
//! `keepshipping blocks update` resolves a reference once and writes the answer
//! here, and every later `check` and `run` reads that answer rather than
//! resolving again — the rule that makes a pin a pin.
//!
//! The format is a strict subset of TOML, one `[[block]]` per reference and one
//! field per line, so an upgrade is two changed lines in a diff. See
//! `docs/LOCKFILE.md` for the field-by-field contract, and `ks_engine::blocks`
//! for resolution and verification.
//!
//! ```
//! use ks_core::lock::{BlockRef, Lock};
//!
//! let lock = Lock::parse(
//!     "lock = 1\n\n[[block]]\n\
//!      name    = \"acme/web-service\"\n\
//!      request = \"v3\"\n\
//!      version = \"3.4.1\"\n\
//!      digest  = \"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"\n",
//! )
//! .expect("a well formed lock file");
//! let entry = lock.get(&BlockRef::parse("acme/web-service@v3").unwrap()).unwrap();
//! assert_eq!(entry.version, "3.4.1");
//! ```

use std::cmp::Ordering;
use std::fmt;

use crate::ports::blocks::BlockVersion;
use crate::ports::supply_chain::Digest;

/// The `ship.lock` format version this build writes and understands.
///
/// A change to a field's meaning, to the required fields or to the canonical
/// layout bumps this; a new *optional* field does not. A build meeting a
/// version it does not know refuses the file.
pub const LOCK_FORMAT: u32 = 1;

/// The first line of every file [`Lock::render`] writes.
const HEADER: &str =
    "# ship.lock: written by `keepshipping blocks update`. Commit it; do not edit by hand.";

/// Why a version, pin, reference or lock file was refused: a message, and the
/// 1-based line when the failure is about one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockError {
    line: Option<usize>,
    message: String,
}

impl LockError {
    /// A failure about line `line` of a lock file.
    fn at(line: usize, message: impl Into<String>) -> LockError {
        LockError { line: Some(line), message: message.into() }
    }

    /// A failure about a version, a pin or a reference: no line to name.
    fn plain(message: impl Into<String>) -> LockError {
        LockError { line: None, message: message.into() }
    }

    /// The 1-based line the failure is about, when it is about one.
    pub fn line(&self) -> Option<usize> {
        self.line
    }

    /// What is wrong, safe to print.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "ship.lock:{line}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for LockError {}

/// A version, ordered by semver precedence rather than by text: `3.10.0`
/// outranks `3.9.0`, `3.5.0` outranks `3.5.0-rc.1`, and `3.4.1` outranks
/// `3.5.0-rc.1` — all three wrong under a string comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<String>,
}

impl Version {
    /// Parses `major.minor.patch[-prerelease]`. A leading `v` is accepted and
    /// not kept (`v3.1.2` renders as `3.1.2`); `+metadata` is ignored, as
    /// precedence ignores it.
    ///
    /// Every character is semver's: digits and `.` in the core, `[0-9A-Za-z-]`
    /// in a prerelease identifier, and no leading zeros. That last rule is not
    /// pedantry — it is what lets [`Ord`] agree with `Eq`, since `rc.01` and
    /// `rc.1` would otherwise be distinct texts with one precedence.
    pub fn parse(text: &str) -> Result<Version, LockError> {
        let malformed =
            |reason: &str| LockError::plain(format!("`{text}` is not a version: {reason}"));
        let trimmed = text.trim();
        let body = trimmed.strip_prefix('v').unwrap_or(trimmed);
        let body = body.split('+').next().unwrap_or(body);
        let (core, pre) = match body.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (body, None),
        };
        if let Some(pre) = pre
            && pre.split('.').any(|id| !is_identifier(id))
        {
            return Err(malformed(
                "a prerelease is dot-separated `[0-9A-Za-z-]` identifiers, none empty and none \
                 with a leading zero",
            ));
        }
        let mut parts = core.split('.');
        let mut numbers = [0u64; 3];
        for number in &mut numbers {
            *number = parts.next().and_then(digits).ok_or_else(|| {
                malformed("expected `major.minor.patch`, digits without leading zeros")
            })?;
        }
        if parts.next().is_some() {
            return Err(malformed("expected `major.minor.patch`, and this has more parts"));
        }
        Ok(Version {
            major: numbers[0],
            minor: numbers[1],
            patch: numbers[2],
            pre: pre.map(str::to_string),
        })
    }

    /// The major number.
    pub fn major(&self) -> u64 {
        self.major
    }

    /// Whether this is a release rather than a prerelease.
    pub fn is_release(&self) -> bool {
        self.pre.is_none()
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.pre {
            Some(pre) => write!(f, "{}.{}.{}-{pre}", self.major, self.minor, self.patch),
            None => write!(f, "{}.{}.{}", self.major, self.minor, self.patch),
        }
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Version) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| cmp_prerelease(self.pre.as_deref(), other.pre.as_deref()))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Version) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Whether `text` is all ASCII digits, whatever its size.
fn is_numeric(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// A run of ASCII digits with no leading zero (`0` alone is fine) that also
/// fits [`u64`]. Rejecting `+3` and `01` here is what keeps [`is_identifier`]
/// and the comparator agreeing about what a number is.
fn digits(text: &str) -> Option<u64> {
    if !is_numeric(text) || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse().ok()
}

/// A semver prerelease identifier: `[0-9A-Za-z-]`, non-empty, and no leading
/// zero when it is all digits. An all-digit identifier may be longer than a
/// [`u64`] — semver bounds its value by nothing, and the comparator compares
/// digit runs by length — so this does not ask [`digits`].
fn is_identifier(text: &str) -> bool {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return false;
    }
    !is_numeric(text) || (text.len() == 1 || !text.starts_with('0'))
}

/// A release outranks a prerelease of the same numbers; two prereleases compare
/// identifier by identifier, numbers below alphanumerics and numbers by value.
fn cmp_prerelease(left: Option<&str>, right: Option<&str>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left), Some(right)) => {
            let mut left_ids = left.split('.');
            let mut right_ids = right.split('.');
            loop {
                match (left_ids.next(), right_ids.next()) {
                    // With leading zeros refused, two identifiers that compare
                    // equal here are the same text, so `Ord` agrees with `Eq`
                    // and this needs no tie-break.
                    (None, None) => return Ordering::Equal,
                    (None, Some(_)) => return Ordering::Less,
                    (Some(_), None) => return Ordering::Greater,
                    (Some(left), Some(right)) => {
                        let order = match (is_numeric(left), is_numeric(right)) {
                            // By value: more digits is a bigger number, and
                            // equal-length digit runs compare as text. This
                            // holds past `u64::MAX` too.
                            (true, true) => {
                                left.len().cmp(&right.len()).then_with(|| left.cmp(right))
                            }
                            (true, false) => Ordering::Less,
                            (false, true) => Ordering::Greater,
                            (false, false) => left.cmp(right),
                        };
                        if order != Ordering::Equal {
                            return order;
                        }
                    }
                }
            }
        }
    }
}

/// What a block reference pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pin {
    /// `@v3` or `@3`: the highest release of that major, and *never* a
    /// prerelease — writing one out is how a repository opts into it.
    Major {
        /// The major number.
        major: u64,
        /// The spelling as written, kept so the lock records the file's own text.
        as_written: String,
    },
    /// `@3.1.2`: exactly that version, prerelease or not.
    Exact(Version),
    /// `@sha256:<hex>`: exactly that content; the version beside it in a lock
    /// entry is a label, not a selector.
    Digest(Digest),
}

impl Pin {
    /// Parses `v3`, `3`, `3.1.2`, `3.5.0-rc.1` or `sha256:<hex>`.
    ///
    /// A partial version like `@3.1` is refused *by name*: three spellings are
    /// settled here, and a fourth would be decided by whoever read the code
    /// first.
    pub fn parse(text: &str) -> Result<Pin, LockError> {
        let text = text.trim();
        let refused = |why: &str| LockError::plain(format!("`{text}` is not a block pin: {why}"));
        if text.is_empty() {
            return Err(LockError::plain(
                "a block reference needs a version — there is no `latest` for a block, so write \
                 `@v3`, `@3.1.2` or `@sha256:<hex>`",
            ));
        }
        let body = text.strip_prefix('v').unwrap_or(text);
        if body.contains(':') {
            return Digest::parse(body)
                .map(Pin::Digest)
                .map_err(|error| refused(&error.to_string()));
        }
        if let Ok(version) = Version::parse(body) {
            return Ok(Pin::Exact(version));
        }
        // `digits`, not `parse::<u64>`: the latter accepts `+3`, and a major is
        // a run of digits here or it is not a major.
        digits(body)
            .map(|major| Pin::Major { major, as_written: text.to_string() })
            .ok_or_else(|| refused("write `@v3` to follow a major, `@3.1.2` for an exact version, or `@sha256:<hex>` to pin the content"))
    }

    /// The major this pin follows, if it follows one.
    pub fn major(&self) -> Option<u64> {
        match self {
            Pin::Major { major, .. } => Some(*major),
            _ => None,
        }
    }

    /// The exact version this pin names, if it names one.
    pub fn exact(&self) -> Option<&Version> {
        match self {
            Pin::Exact(version) => Some(version),
            _ => None,
        }
    }

    /// The digest this pin names, if it names one.
    pub fn digest(&self) -> Option<&Digest> {
        match self {
            Pin::Digest(digest) => Some(digest),
            _ => None,
        }
    }

    /// Whether this pin selects the published `version`/`digest` pair.
    pub fn selects(&self, version: &Version, digest: &Digest) -> bool {
        match self {
            Pin::Major { major, .. } => version.is_release() && version.major() == *major,
            Pin::Exact(exact) => version == exact,
            Pin::Digest(pinned) => pinned == digest,
        }
    }
}

impl fmt::Display for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Pin::Major { as_written, .. } => f.write_str(as_written),
            Pin::Exact(version) => write!(f, "{version}"),
            Pin::Digest(digest) => write!(f, "{digest}"),
        }
    }
}

/// A block reference as `ship.ks` writes it: `owner/name@pin`. The name is
/// validated to the grammar a lock entry's name is validated against too, so a
/// lookup cannot miss on a spelling one side took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRef {
    name: String,
    pin: Pin,
}

impl BlockRef {
    /// Parses `owner/name@pin`, with exactly one `@`.
    pub fn parse(text: &str) -> Result<BlockRef, LockError> {
        let refused =
            |reason: &str| LockError::plain(format!("{text:?} is not a block reference: {reason}"));
        let text = text.trim();
        let Some((name, pin)) = text.rsplit_once('@') else {
            return Err(refused("there is no `@`, and there is no `latest` for a block"));
        };
        if name.contains('@') {
            return Err(refused("a reference carries exactly one `@`"));
        }
        if !is_block_name(name) {
            return Err(refused("the name must be an `owner/name` pair, both parts non-empty"));
        }
        let pin = Pin::parse(pin).map_err(|error| refused(error.message()))?;
        Ok(BlockRef { name: name.to_string(), pin })
    }

    /// The block's name, `owner/name`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What the reference pins.
    pub fn pin(&self) -> &Pin {
        &self.pin
    }
}

impl fmt::Display for BlockRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.pin)
    }
}

/// Whether `name` is `owner/name`, both parts spelled with the characters a
/// registry repository and a block name can carry.
fn is_block_name(name: &str) -> bool {
    let mut parts = name.split('/');
    let owner = parts.next().unwrap_or_default();
    let block = parts.next().unwrap_or_default();
    parts.next().is_none()
        && !owner.is_empty()
        && !block.is_empty()
        && [owner, block].iter().all(|part| {
            part.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

/// The published version a [`Pin`] selects, or `None` if it matches none.
///
/// **A locked version is always a semver.** A published version this build
/// cannot parse is skipped, whatever the pin — including a digest pin, which
/// names content and does not get to smuggle an arbitrary string into the
/// `version` field a run will print. A block published as `2024-10-01` is
/// therefore not lockable at all: the digest is the pin, and a pin the format
/// cannot record is not a pin. The parser holds the same rule, so a lock
/// written by another tool under the same rules re-reads here.
pub fn select<'a>(pin: &Pin, published: &'a [BlockVersion]) -> Option<&'a BlockVersion> {
    let mut best: Option<(Version, &BlockVersion)> = None;
    for candidate in published {
        let Ok(version) = Version::parse(&candidate.version) else {
            continue;
        };
        if !pin.selects(&version, &candidate.digest) {
            continue;
        }
        if best.as_ref().is_none_or(|(current, _)| current < &version) {
            best = Some((version, candidate));
        }
    }
    best.map(|(_, candidate)| candidate)
}

/// One reference as `ship.lock` records it. The digest is the pin; the rest
/// is there so a reviewer can see *why* the digest moved, and so a changed
/// workflow without a changed lock is a visible stale lock, not a silent
/// re-resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockEntry {
    /// The block's name, `owner/name`.
    pub name: String,
    /// The pin as the workflow file spells it, without the `@`.
    pub request: String,
    /// The version the request resolved to, as the source names it.
    pub version: String,
    /// The digest the version's content is addressed by.
    pub digest: Digest,
    /// The repository it resolved from, when the source can name one: `None`
    /// while that mapping is still open
    /// ([#79](https://github.com/Keep-Shipping/harness/issues/79)).
    pub source: Option<String>,
}

impl LockEntry {
    /// The entry's identity: a name *and* a request, which is what lets two
    /// majors of one block be two entries.
    pub fn key(&self) -> (&str, &str) {
        (&self.name, &self.request)
    }
}

impl fmt::Display for LockEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.request)
    }
}

/// A parsed `ship.lock`, its entries sorted by name then request. Sorting
/// makes [`render`](Lock::render) deterministic — two repositories pinning the
/// same blocks produce byte-identical files — and an upgrade a two-line diff.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lock {
    entries: Vec<LockEntry>,
}

impl Lock {
    /// A lock with no entries.
    pub fn new() -> Lock {
        Lock::default()
    }

    /// A lock holding `entries`, sorted by name then request.
    ///
    /// Refuses an entry whose text cannot survive a round trip through
    /// [`render`](Lock::render) and back — a `"`, a `\` or a control character
    /// in any field. This format has no escapes, so such a value could only be
    /// written into a lock file as a second entry or a second field.
    pub fn from_entries(entries: Vec<LockEntry>) -> Result<Lock, LockError> {
        for entry in &entries {
            let fields = [&entry.name, &entry.request, &entry.version];
            for value in fields.into_iter().chain(entry.source.as_ref()) {
                if value.chars().any(|ch| ch == '"' || ch == '\\' || ch.is_control()) {
                    return Err(LockError::plain(format!(
                        "`{}` cannot be written to a lock file: this format has no escapes, so a \
                         value may not hold `\"`, `\\` or a control character",
                        value.escape_debug()
                    )));
                }
            }
        }
        let mut entries = entries;
        entries.sort_by(|left, right| left.key().cmp(&right.key()));
        Ok(Lock { entries })
    }

    /// The entries, sorted by name then request.
    pub fn entries(&self) -> &[LockEntry] {
        &self.entries
    }

    /// The entry a reference resolves to, or `None` for one the lock has never
    /// seen, which is what `keepshipping blocks update` is for.
    pub fn get(&self, reference: &BlockRef) -> Option<&LockEntry> {
        self.entries.iter().find(|entry| {
            entry.name == reference.name() && entry.request == reference.pin().to_string()
        })
    }

    /// The references this lock has no entry for, in the order given: what
    /// `check` walks. Such a reference is a stale lock, and the answer is to
    /// update the lock, not to resolve the version now.
    pub fn missing<'a>(&self, references: &'a [BlockRef]) -> Vec<&'a BlockRef> {
        references.iter().filter(|reference| self.get(reference).is_none()).collect()
    }

    /// Parses `ship.lock`, refusing anything it does not understand.
    ///
    /// Every refusal carries the line it happened on, because a lock file is
    /// read by people: "invalid" is not a line number. Comments are whole
    /// lines; a trailing `#` is not this format.
    pub fn parse(text: &str) -> Result<Lock, LockError> {
        let refused = |line, message: String| LockError::at(line, message);
        let mut format = None;
        let mut table: Option<PendingTable> = None;
        let mut done: Vec<Entryed> = Vec::new();

        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let text = raw.trim();
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            if text == "[[block]]" {
                if format.is_none() {
                    return Err(refused(line, "`[[block]]` before `lock`: it comes first".into()));
                }
                done.extend(table.take().map(finalize).transpose()?);
                table = Some(PendingTable { line, fields: Vec::new() });
                continue;
            }
            if text.starts_with("[[") {
                return Err(refused(line, format!("unknown table `{text}`: only `[[block]]`")));
            }
            let Some((key, value)) = text.split_once('=') else {
                return Err(refused(line, format!("`{text}` is not a `key = value` line")));
            };
            let (key, value) = (key.trim(), value.trim());
            if key == "lock" {
                if format.is_some() {
                    return Err(refused(line, "`lock` is set twice".into()));
                }
                if table.is_some() || !done.is_empty() {
                    return Err(refused(
                        line,
                        "`lock` comes first: it is the format version".into(),
                    ));
                }
                let version = value
                    .parse::<u32>()
                    .map_err(|_| refused(line, format!("`{value}` is not a version number")))?;
                if version != LOCK_FORMAT {
                    return Err(refused(
                        line,
                        format!(
                            "ship.lock format {version}, and this build understands {LOCK_FORMAT}: \
                             upgrade keepshipping to read this lock"
                        ),
                    ));
                }
                format = Some(line);
                continue;
            }
            let value = unquote(value).ok_or_else(|| {
                refused(
                    line,
                    format!("`{value}` is not a quoted string, and this format has no escapes"),
                )
            })?;
            let Some(table) = table.as_mut() else {
                return Err(refused(line, format!("`{key}` is not inside a `[[block]]`")));
            };
            table.fields.push((key, value, line));
        }

        done.extend(table.map(finalize).transpose()?);
        if format.is_none() {
            return Err(LockError::at(1, "no `lock = 1` line: this file is not a ship.lock"));
        }
        done.sort_by(|left, right| left.entry.key().cmp(&right.entry.key()));
        for pair in done.windows(2) {
            if pair[0].entry.key() == pair[1].entry.key() {
                return Err(refused(
                    pair[1].line,
                    format!("`{}` is locked twice: one resolution each", pair[1].entry),
                ));
            }
        }
        Ok(Lock { entries: done.into_iter().map(|entryed| entryed.entry).collect() })
    }

    /// Renders the canonical text: the header, `lock = 1`, then one
    /// `[[block]]` per reference, fields aligned on the `=`. Comments and
    /// blank lines are dropped, so a canonical file re-renders byte-identically.
    pub fn render(&self) -> String {
        let mut out = format!("{HEADER}\nlock = {LOCK_FORMAT}\n");
        for entry in &self.entries {
            out.push_str("\n[[block]]\n");
            out.push_str(&field("name", &entry.name));
            out.push_str(&field("request", &entry.request));
            out.push_str(&field("version", &entry.version));
            out.push_str(&field("digest", &entry.digest.to_string()));
            if let Some(source) = &entry.source {
                out.push_str(&field("source", source));
            }
        }
        out
    }
}

impl fmt::Display for Lock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// One rendered field, aligned on the `=` so values line up in a diff.
fn field(key: &str, value: &str) -> String {
    format!("{key:<7} = \"{value}\"\n")
}

/// The value of a `key = value` line, or `None` when it is not one
/// double-quoted run. Escapes are refused, not decoded: no field holds one.
fn unquote(value: &str) -> Option<&str> {
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    // A `"` or `\` has no escape here, and a control character would not
    // survive being written back out as one line.
    if inner.chars().any(|ch| ch == '"' || ch == '\\' || ch.is_control()) {
        return None;
    }
    Some(inner)
}

/// A `[[block]]` table still being read.
struct PendingTable<'a> {
    line: usize,
    fields: Vec<(&'a str, &'a str, usize)>,
}

/// A finished entry and the line its table started on, so a duplicate is
/// reported against the second table.
struct Entryed {
    entry: LockEntry,
    line: usize,
}

/// Turns one table's fields into an entry, or says which line is wrong.
fn finalize(table: PendingTable<'_>) -> Result<Entryed, LockError> {
    let start = table.line;
    let refused = |message: String| LockError::at(start, message);
    let mut name = None;
    let mut request = None;
    let mut version = None;
    let mut digest = None;
    let mut source = None;
    let mut seen: Vec<&str> = Vec::new();
    for (key, value, line) in table.fields {
        if seen.contains(&key) {
            return Err(LockError::at(line, format!("`{key}` is set twice")));
        }
        seen.push(key);
        match key {
            "name" => name = Some(value.to_string()),
            "request" => request = Some(value.to_string()),
            "version" => version = Some(value.to_string()),
            "digest" => {
                digest = Some(
                    Digest::parse(value).map_err(|error| LockError::at(line, error.to_string()))?,
                );
            }
            "source" => source = Some(value.to_string()),
            other => {
                return Err(LockError::at(
                    line,
                    format!(
                        "unknown field `{other}`: a block is name, request, version, digest and \
                         optionally source"
                    ),
                ));
            }
        }
    }
    let missing = |field: &str| refused(format!("a `[[block]]` has no `{field}`"));
    let entry = LockEntry {
        name: name.ok_or_else(|| missing("name"))?,
        request: request.ok_or_else(|| missing("request"))?,
        version: version.ok_or_else(|| missing("version"))?,
        digest: digest.ok_or_else(|| missing("digest"))?,
        source,
    };
    if !is_block_name(&entry.name) {
        return Err(refused(format!("`{}` is not an `owner/name` block name", entry.name)));
    }
    let pin = Pin::parse(&entry.request).map_err(|error| refused(error.message().to_string()))?;
    // An exact or digest request says in the file itself what the version and
    // digest must be, so a lock that says otherwise is refused rather than
    // read: `check` trusting it would be trusting the wrong pin.
    if let Some(exact) = pin.exact()
        && Version::parse(&entry.version).map(|locked| &locked != exact).unwrap_or(true)
    {
        return Err(refused(format!(
            "`request = {:?}` names {exact} exactly, and `version = {:?}` is not it",
            entry.request, entry.version
        )));
    }
    if let Some(pinned) = pin.digest()
        && &entry.digest != pinned
    {
        return Err(refused(format!(
            "`request = {:?}` pins {pinned}, and `digest` is not it",
            entry.request
        )));
    }
    // A major request does not name a version, but it does constrain one: the
    // recorded version must be a release of that major, and it must be a
    // version at all. `request = "v3"` with `version = "not-a-version"` is a
    // lock that cannot answer what it is pinned to.
    if let Some(major) = pin.major() {
        let holds = Version::parse(&entry.version)
            .is_ok_and(|locked| locked.is_release() && locked.major() == major);
        if !holds {
            return Err(refused(format!(
                "`request = {:?}` follows major {major}, and `version = {:?}` is not a release of it",
                entry.request, entry.version
            )));
        }
    }
    Ok(Entryed { entry, line: start })
}
#[cfg(test)]
mod tests {
    use super::{BlockRef, Lock, LockEntry, Pin, Version, select};
    use crate::ports::blocks::{BlockVersion, SignatureStatus};
    use crate::ports::supply_chain::Digest;

    fn digest_of(byte: char) -> Digest {
        Digest::parse(&format!("sha256:{}", byte.to_string().repeat(64))).expect("a digest")
    }

    fn hex_of(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn published(version: &str, byte: char) -> BlockVersion {
        BlockVersion {
            version: version.to_string(),
            digest: digest_of(byte),
            signature: SignatureStatus::Signed,
        }
    }

    fn entry(name: &str, request: &str, version: &str, byte: char) -> LockEntry {
        LockEntry {
            name: name.to_string(),
            request: request.to_string(),
            version: version.to_string(),
            digest: digest_of(byte),
            source: None,
        }
    }

    #[test]
    fn versions_order_by_precedence_not_by_text() {
        let parsed: Vec<Version> =
            ["3.10.0", "3.9.0", "3.5.0", "3.5.0-rc.1", "3.4.1", "4.0.0-rc.1"]
                .iter()
                .map(|text| Version::parse(text).expect("a version"))
                .collect();
        assert!(parsed[1] < parsed[0], "3.10.0 outranks 3.9.0, which text gets wrong");
        assert!(parsed[3] < parsed[2], "a release outranks its own prerelease");
        assert!(parsed[4] < parsed[3], "3.4.1 outranks 3.5.0-rc.1, which text gets wrong");
        assert!(parsed[0] < parsed[5], "4.0.0-rc.1 outranks 3.10.0");
        assert!(!Version::parse("3.5.0-rc.1").unwrap().is_release());
        assert_eq!(Version::parse("v3.1.2").unwrap().to_string(), "3.1.2", "a `v` is not kept");
        // A numeric identifier past `u64::MAX` still compares by value, not by
        // falling back to text and ranking `abc` above it.
        let huge = Version::parse("1.0.0-18446744073709551616").unwrap();
        let abc = Version::parse("1.0.0-abc").unwrap();
        assert!(huge < abc, "a number is below an alphanumeric, however big");
        assert!(
            Version::parse("1.0.0-9").unwrap() < Version::parse("1.0.0-10").unwrap(),
            "numeric identifiers compare by value"
        );
        // Leading zeros are refused, so `Ord` can agree with `Eq`.
        for text in ["3.01.2", "1.0.0-rc.01", "01.0.0"] {
            assert!(Version::parse(text).is_err(), "{text} has a leading zero");
        }
        // A prerelease identifier is `[0-9A-Za-z-]` and nothing else: a
        // newline here would be written into a lock file verbatim.
        assert!(
            Version::parse("1.0.0-x\n\n[[block]]\nname = \"evil/block\"").is_err(),
            "a version that is not one line cannot be a version"
        );
    }

    #[test]
    fn pins_parse_the_three_spellings_and_display_as_written() {
        assert!(matches!(Pin::parse("v3").unwrap(), Pin::Major { major: 3, .. }));
        assert!(matches!(Pin::parse("3").unwrap(), Pin::Major { major: 3, .. }));
        assert_eq!(Pin::parse("3").unwrap().to_string(), "3", "the lock keeps the file's spelling");
        assert!(matches!(Pin::parse("3.5.0-rc.1").unwrap(), Pin::Exact(_)));
        assert!(matches!(Pin::parse(&format!("sha256:{}", hex_of('a'))).unwrap(), Pin::Digest(_)));
        assert!(Pin::parse("+3").is_err(), "a major is digits, not a signed integer");
        // Both digest algorithms a pin may name round-trip through the lock:
        // `render` writes `sha512:<128 hex>` and `parse` reads it back.
        let sha512 = format!("sha512:{}", "a".repeat(128));
        let locked = Lock::from_entries(vec![LockEntry {
            request: sha512.clone(),
            digest: Digest::parse(&sha512).expect("a sha512 digest"),
            ..entry("acme/web-service", "v3", "3.4.1", 'c')
        }])
        .expect("a sha512 digest is writable");
        let rendered = locked.render();
        assert!(rendered.contains(&sha512), "{rendered}");
        assert_eq!(Lock::parse(&rendered).expect("sha512 round trips"), locked);
    }

    #[test]
    fn a_pin_that_is_not_one_of_the_three_is_refused_by_name() {
        // `@3.1` is not a fourth spelling with an unstated meaning.
        for text in ["3.1", "latest", "v", "not-a-pin"] {
            let error = Pin::parse(text).expect_err("not one of the three");
            assert!(error.message().contains("is not a block pin"), "{text:?}: {error}");
        }
        let empty = Pin::parse("").expect_err("no pin at all");
        assert!(empty.message().contains("no `latest` for a block"), "{empty}");
    }

    #[test]
    fn a_major_pin_never_matches_a_prerelease_and_an_exact_one_can() {
        let major = Pin::parse("v3").unwrap();
        assert!(major.selects(&Version::parse("3.4.1").unwrap(), &digest_of('c')));
        assert!(!major.selects(&Version::parse("3.5.0-rc.1").unwrap(), &digest_of('d')));
        assert!(!major.selects(&Version::parse("2.9.0").unwrap(), &digest_of('a')));
        let exact = Pin::parse("3.5.0-rc.1").unwrap();
        assert!(exact.selects(&Version::parse("3.5.0-rc.1").unwrap(), &digest_of('d')));
        let digest = Pin::parse(&format!("sha256:{}", hex_of('c'))).unwrap();
        assert!(digest.selects(&Version::parse("9.9.9").unwrap(), &digest_of('c')));
    }

    #[test]
    fn a_block_reference_round_trips_and_validates_its_name() {
        let reference = BlockRef::parse("acme/web-service@v3").expect("a reference");
        assert_eq!(reference.name(), "acme/web-service");
        assert_eq!(reference.to_string(), "acme/web-service@v3");
        for text in ["acme@v3", "web-service@v3", "acme/web/service@v3", "acme/web-service"] {
            assert!(BlockRef::parse(text).is_err(), "{text:?} is not a reference");
        }
        assert!(BlockRef::parse("acme/web-service@a@b@v3").is_err(), "exactly one `@`");
    }

    #[test]
    fn select_picks_the_highest_match_for_each_of_the_three_pins() {
        let all = [
            published("4.0.0", 'e'),
            published("3.5.0-rc.1", 'd'),
            published("3.4.1", 'c'),
            published("3.0.0", 'b'),
            published("2.9.0", 'a'),
            published("not-a-version", '0'),
        ];
        for (text, expected) in [
            ("v3", "3.4.1"),
            ("3.4.1", "3.4.1"),
            ("2.9.0", "2.9.0"),
            (&format!("sha256:{}", hex_of('e')), "4.0.0"),
        ] {
            let pin = Pin::parse(text).unwrap();
            assert_eq!(
                select(&pin, &all).map(|entry| entry.version.as_str()),
                Some(expected),
                "{text}"
            );
        }
        assert!(select(&Pin::parse("v9").unwrap(), &all).is_none(), "no 9.x matches");
    }

    #[test]
    fn a_rendered_lock_reads_back_identically_and_re_renders_unchanged() {
        let lock = Lock::from_entries(vec![
            entry("acme/web-service", "v3", "3.4.1", 'c'),
            entry("acme/web-service", "v4", "4.0.0", 'e'),
        ])
        .expect("entries that round trip");
        let text = lock.render();
        assert!(text.starts_with("# ship.lock:"), "{text}");
        assert_eq!(Lock::parse(&text).expect("round trip"), lock);
        assert_eq!(Lock::parse(&lock.to_string()).expect("display").render(), text);
    }

    #[test]
    fn the_render_is_canonical_so_two_repositories_pin_the_same_file_byte_for_byte() {
        let web = |request: &str| entry("acme/web-service", request, "3.4.1", 'c');
        let one =
            Lock::from_entries(vec![web("v3"), web("3.4.1")]).expect("entries that round trip");
        let other =
            Lock::from_entries(vec![web("3.4.1"), web("v3")]).expect("entries that round trip");
        assert_eq!(one.render(), other.render(), "order of resolution does not reach the file");
    }

    #[test]
    fn an_upgrade_touches_only_the_version_and_digest_lines() {
        let before = Lock::from_entries(vec![
            entry("acme/web-service", "v3", "3.4.1", 'c'),
            entry("acme/other-block", "v1", "1.0.0", 'a'),
        ])
        .expect("entries that round trip")
        .render();
        let after = Lock::from_entries(vec![
            entry("acme/web-service", "v3", "3.6.0", 'f'),
            entry("acme/other-block", "v1", "1.0.0", 'a'),
        ])
        .expect("entries that round trip")
        .render();
        let moved: Vec<&str> = before
            .lines()
            .zip(after.lines())
            .filter_map(|(before, after)| (before != after).then_some(after))
            .collect();
        assert_eq!(
            moved,
            vec![
                &"version = \"3.6.0\"".to_string(),
                &format!("digest  = \"sha256:{}\"", hex_of('f'))
            ]
        );
    }

    #[test]
    fn two_majors_of_one_block_are_two_entries_and_both_are_found() {
        let lock = Lock::from_entries(vec![
            entry("acme/web-service", "v3", "3.4.1", 'c'),
            entry("acme/web-service", "v4", "4.0.0", 'e'),
        ])
        .expect("entries that round trip");
        for (request, version) in [("v3", "3.4.1"), ("v4", "4.0.0")] {
            let found = lock.get(&BlockRef::parse(&format!("acme/web-service@{request}")).unwrap());
            assert_eq!(found.map(|entry| entry.version.as_str()), Some(version));
        }
        assert_eq!(lock.entries().len(), 2);
    }

    #[test]
    fn a_reference_with_no_entry_is_reported_as_missing() {
        let lock = Lock::from_entries(vec![entry("acme/web-service", "v3", "3.4.1", 'c')])
            .expect("entries that round trip");
        let references: Vec<BlockRef> = ["acme/web-service@v3", "acme/web-service@v4", "acme/x@v1"]
            .iter()
            .map(|text| BlockRef::parse(text).unwrap())
            .collect();
        let missing = lock.missing(&references);
        assert_eq!(
            missing.iter().map(|reference| reference.to_string()).collect::<Vec<_>>(),
            vec!["acme/web-service@v4", "acme/x@v1"],
            "a stale lock names the references it cannot answer, in the order given"
        );
    }

    #[test]
    fn a_lock_file_is_refused_with_a_line_number_for_every_reason() {
        let table = format!(
            "[[block]]\nname = \"acme/web\"\nrequest = \"v3\"\nversion = \"3.4.1\"\n\
             digest = \"sha256:{}\"\n",
            hex_of('c')
        );
        let valid = format!("lock = 1\n\n{table}");
        let cases: Vec<(&str, String, usize)> = vec![
            ("no format line at all", "\n\n# only comments\n".to_string(), 1),
            ("an unknown format", "lock = 2\n".to_string(), 1),
            ("a quoted format", "lock = \"1\"\n".to_string(), 1),
            ("a table before the format", format!("[[block]]\nlock = 1\n{table}"), 1),
            ("a second format", format!("{valid}\nlock = 1\n"), 9),
            (
                "an unknown table",
                format!("lock = 1\n\n[[artifact]]\n{name} = \"x\"\n", name = table),
                3,
            ),
            ("a line that is not a pair", format!("{valid}\nnonsense\n"), 9),
            ("a field outside a table", "lock = 1\nname = \"acme/web\"\n".to_string(), 2),
            ("an unquoted value", valid.replace("\"v3\"", "v3"), 5),
            ("an escaped value", valid.replace("\"v3\"", "\"v\\\"3\""), 5),
            (
                "an unknown field",
                valid.replace("version = \"3.4.1\"\n", "repository = \"ghcr.io/a/b\"\n"),
                6,
            ),
            (
                "a repeated field",
                valid
                    .replace("version = \"3.4.1\"\n", "version = \"3.4.1\"\nversion = \"3.5.0\"\n"),
                7,
            ),
            ("a missing field", valid.replace("version = \"3.4.1\"\n", ""), 3),
            // A control character inside a value would be written back verbatim
            // and would not survive the round trip.
            ("a value carrying a control character", valid.replace("\"v3\"", "\"v\t3\""), 5),
            ("a malformed digest", valid.replace(&hex_of('c'), "not-hex"), 7),
            ("a malformed name", valid.replace("acme/web", "web"), 3),
            ("a duplicate reference", format!("lock = 1\n\n{table}{table}"), 8),
        ];
        for (what, text, line) in cases {
            let error = Lock::parse(&text).expect_err(what);
            assert_eq!(error.line(), Some(line), "{what}: {error}");
            assert!(
                error.to_string().starts_with(&format!("ship.lock:{line}: ")),
                "{what}: {error}"
            );
        }
        assert!(Lock::parse(&valid).is_ok(), "the fixture itself is a valid lock");
    }

    #[test]
    fn a_lock_entry_that_contradicts_its_own_request_is_refused() {
        let table = |request: &str, version: &str, digest: char| {
            format!(
                "lock = 1\n\n[[block]]\nname = \"acme/web\"\nrequest = \"{request}\"\n\
                 version = \"{version}\"\ndigest = \"sha256:{}\"\n",
                hex_of(digest)
            )
        };
        assert!(Lock::parse(&table("3.4.1", "3.4.1", 'c')).is_ok(), "an exact request that holds");
        assert!(Lock::parse(&table("3.4.1", "3.4.2", 'c')).is_err(), "the version is not the pin");
        assert!(Lock::parse(&table("v3", "3.4.1", 'c')).is_ok(), "3.4.1 is a release of 3");
        assert!(
            Lock::parse(&table(&hex_of('c'), "3.4.1", 'e')).is_err(),
            "the digest is not the pin"
        );
        // A major request constrains the version even though it does not name
        // one: it must be a release of that major, and it must be a version.
        for version in ["not-a-version", "2.9.0", "3.5.0-rc.1", "3.x"] {
            assert!(
                Lock::parse(&table("v3", version, 'c')).is_err(),
                "a major request does not admit version {version:?}"
            );
        }

        // A value that cannot be written back is refused at both doors, so
        // `render` can never emit a lock this parser would reject.
        let injection = "1.0.0-x\n\n[[block]]\nname = \"evil/block\"\nrequest = \"v9\"";
        assert!(
            Lock::from_entries(vec![entry("acme/web", "v3", injection, 'c')]).is_err(),
            "a version carrying a newline is not writable"
        );
        assert!(
            Lock::from_entries(vec![LockEntry {
                source: Some("a\"b".into()),
                ..entry("acme/web", "v3", "3.4.1", 'c')
            }])
            .is_err(),
            "a source carrying a quote is not writable"
        );
        assert!(
            Lock::parse(&table("v3", injection, 'c')).is_err(),
            "and the parser refuses the same text"
        );
    }

    #[test]
    fn whole_line_comments_and_blank_lines_are_read_and_dropped() {
        let text = format!(
            "# a comment\nlock = 1\n\n[[block]]  \n# another\n{name}  \n\nrequest = \"v3\"\n\
             version = \"3.4.1\"\ndigest = \"sha256:{}\"\n",
            hex_of('c'),
            name = "name    = \"acme/web-service\"\n",
        );
        let lock = Lock::parse(&text).expect("comments and blanks are not fields");
        assert_eq!(lock.entries().len(), 1);
        assert_eq!(lock.entries()[0].name, "acme/web-service");
        assert!(!lock.render().contains("another"), "a comment is read, never re-emitted");
    }
}
