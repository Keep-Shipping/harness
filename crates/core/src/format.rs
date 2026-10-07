//! The `ship.ks` file format: the optional `keepshipping:` header that
//! declares it, the versions this build reads, and the migrations that
//! carry a file written for an older one forward.
//!
//! A file with no header is read as the current format, so a new build still
//! runs an old file — but CI says so. A file this build cannot read, or
//! cannot migrate from, is refused instead: guessing what a renamed key
//! meant is how a deploy silently stops deploying.
//!
//! Pre-1.0, format `N` is spelled `0.N` — today's format 1 is
//! `keepshipping: 0.1`; [`spelling`] and [`parse_spelling`] are the only
//! place that spelling exists. A breaking change bumps [`FORMAT_VERSION`],
//! appends one [`Migration`] to [`MIGRATIONS`] with `from` set to the
//! version being left behind, and adds a fixture pair under
//! `crates/core/tests/fixtures/upgrade/`; the guard test in
//! `crates/core/tests/format.rs` fails without all three.

use std::fmt;

use ks_lang::{Atom, Entry, Expr, Parse, Span};

use crate::version::FORMAT_VERSION;

/// The key the format header is written under.
pub const HEADER_KEY: &str = "keepshipping";

/// Format `N` as a file spells it: `0.N`. A future `1.0` changes it here,
/// once.
#[must_use]
pub fn spelling(version: u32) -> String {
    format!("0.{version}")
}

/// The version `0.N` spells, or `None` when `text` is not one. The round
/// trip is exact, so `0.01` and `1.0` are refused rather than quietly read
/// as `0.1` and `1`.
#[must_use]
pub fn parse_spelling(text: &str) -> Option<u32> {
    let n = text.strip_prefix("0.")?;
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let version: u32 = n.parse().ok()?;
    (spelling(version) == text).then_some(version)
}

/// What a file says about the format it is written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Header {
    /// No `keepshipping:` entry: the file is read as the current format.
    Absent,
    /// A well-formed header, on the file's first entry.
    Declared {
        /// The format the file declares; `span` is the header's value.
        version: u32,
        span: Span,
    },
    /// A `keepshipping:` entry whose value is not a format version.
    Malformed { span: Span },
    /// A `keepshipping:` entry that is not the file's first entry.
    NotFirst { span: Span },
}

impl Header {
    /// Where a diagnostic about this header points.
    #[must_use]
    pub fn span(self) -> Span {
        match self {
            Header::Absent => Span::point(0),
            Header::Declared { span, .. }
            | Header::Malformed { span }
            | Header::NotFirst { span } => span,
        }
    }
}

/// Reads the header of `file`.
///
/// The header must be the file's first entry; comments and blank lines
/// before it are trivia and do not count. A `keepshipping:` key anywhere
/// else is [`Header::NotFirst`] rather than ignored, because a header in
/// the wrong place is a file whose author believed they had pinned the
/// format and had not.
#[must_use]
pub fn header(file: ks_lang::File<'_>) -> Header {
    let mut entries = file.entries();
    let first = entries.next();
    // Every later entry, so a header hiding under `steps:` is found.
    for e in entries {
        if e.key_name() == Some(HEADER_KEY) {
            return Header::NotFirst { span: e.key_span() };
        }
    }
    let Some(e) = first.filter(|e| e.key_name() == Some(HEADER_KEY)) else {
        return Header::Absent;
    };
    let span = e.expr().map_or_else(|| e.key_span(), |x| x.span());
    match value_word(e).and_then(parse_spelling) {
        Some(version) => Header::Declared { version, span },
        None => Header::Malformed { span },
    }
}

/// One byte range of a source, replaced by new text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edit {
    /// The bytes to replace, as offsets into the source the migration was
    /// handed.
    pub span: Span,
    pub text: String,
}

impl Edit {
    /// Replaces the source `span` covers with `text`.
    #[must_use]
    pub fn new(span: Span, text: impl Into<String>) -> Self {
        Edit { span, text: text.into() }
    }
}

/// Something a migration saw and could not rewrite: a person finishes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unrewritten {
    pub span: Span,
    pub message: String,
}

/// What one migration made of one file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rewrites {
    /// The edits that rewrite the file, in any order.
    pub edits: Vec<Edit>,
    pub unrewritten: Vec<Unrewritten>,
}

/// One step of the upgrade path: a file written for format `from`, brought to
/// format `from + 1`.
///
/// A plain function over a parse, so the upgrade test can check it against a
/// fixture pair instead of a mock. It edits byte ranges and nothing else:
/// every byte it does not name is copied over exactly, which is how a
/// migration keeps comments and layout instead of reprinting the file.
#[derive(Clone, Copy, Debug)]
pub struct Migration {
    /// The format this migration leaves.
    pub from: u32,
    /// One line naming the change, for the release notes.
    pub summary: &'static str,
    pub rewrite: fn(&Parse) -> Rewrites,
}

/// The formats a build reads and writes, and the path between them.
#[derive(Clone, Copy, Debug)]
pub struct Formats<'a> {
    /// The format this build writes and reads.
    pub current: u32,
    pub migrations: &'a [Migration],
}

/// The built-in upgrade path, empty while format 1 is the first format.
pub const MIGRATIONS: &[Migration] = &[];

/// The formats this build reads: [`FORMAT_VERSION`] and its migrations.
pub const BUILTIN: Formats<'static> = Formats { current: FORMAT_VERSION, migrations: MIGRATIONS };

impl<'a> Formats<'a> {
    /// The migration carrying a format-`from` file to `from + 1`.
    #[must_use]
    pub fn migration(&self, from: u32) -> Option<&'a Migration> {
        self.migrations.iter().find(|m| m.from == from)
    }

    /// Whether this build reads files written for `version`: the current
    /// one, and the previous one when a migration leads out of it. A
    /// version with no migration behind it is not read, however old it is.
    #[must_use]
    pub fn supports(&self, version: u32) -> bool {
        version == self.current || (version < self.current && self.migration(version).is_some())
    }

    /// The formats this build reads, as a diagnostic names them.
    #[must_use]
    pub fn reads(&self) -> String {
        let mut out = spelling(self.current);
        if let Some(from) = self.current.checked_sub(1)
            && self.migration(from).is_some()
        {
            out.push_str(" and ");
            out.push_str(&spelling(from));
        }
        out
    }
}

/// A source rewritten to the current format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upgraded {
    /// The rewritten source, written for [`Formats::current`].
    pub src: String,
    /// The format the file declared before, or the current one when it
    /// declared none.
    pub from: u32,
    /// What the migration could not rewrite, in the rewritten source.
    pub unrewritten: Vec<Unrewritten>,
}

/// Why a file could not be brought to the current format. A refusal, not a
/// recovery: `keepshipping fmt --upgrade` exits non-zero on one rather than
/// writing a file it had to guess at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeError {
    pub span: Span,
    /// Why, phrased for the person who has to fix it.
    pub message: String,
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UpgradeError {}

/// Brings `src` to the current format.
///
/// A file with no header gets one — pinning the format is the point, and a
/// file that has chosen one stops CI warning about it. A file already on the
/// current format comes back unchanged, so `upgrade` is its own inverse.
pub fn upgrade(src: &str, formats: &Formats<'_>) -> Result<Upgraded, UpgradeError> {
    let declared = header(ks_lang::parse(src).file());
    let from = match declared {
        Header::Absent => {
            return Ok(Upgraded {
                src: pin(src, formats.current),
                from: formats.current,
                unrewritten: Vec::new(),
            });
        }
        Header::Declared { version, .. } => version,
        Header::Malformed { span } => {
            return Err(UpgradeError {
                span,
                message: format!("the `{HEADER_KEY}:` value is not a format version"),
            });
        }
        Header::NotFirst { span } => {
            return Err(UpgradeError {
                span,
                message: format!(
                    "the `{HEADER_KEY}:` header must be the file's first entry, \
                     so there is no single format to upgrade from"
                ),
            });
        }
    };
    if !formats.supports(from) {
        return Err(UpgradeError {
            span: declared.span(),
            message: format!(
                "this keepshipping reads {} and cannot migrate from {}",
                formats.reads(),
                spelling(from)
            ),
        });
    }

    let mut text = src.to_string();
    let mut unrewritten = Vec::new();
    let mut version = from;
    while version < formats.current {
        let Some(migration) = formats.migration(version) else {
            return Err(UpgradeError {
                span: declared.span(),
                message: format!(
                    "no migration from format {} to {}",
                    spelling(version),
                    version + 1
                ),
            });
        };
        let rewrites = (migration.rewrite)(&ks_lang::parse(&text));
        unrewritten.extend(rewrites.unrewritten);
        text = apply(&text, rewrites.edits, &mut unrewritten);
        // The header names the format the next migration expects to read.
        text = set_header(&text, version + 1, &mut unrewritten)?;
        version += 1;
    }
    Ok(Upgraded { src: text, from, unrewritten })
}

/// The header line added above a file that has none.
///
/// A byte-order mark stays the file's first bytes and the line ending is the
/// file's own: reordering or renaming either makes a different file.
fn pin(src: &str, version: u32) -> String {
    let (bom, body) = src.strip_prefix('\u{FEFF}').map_or(("", src), |rest| ("\u{FEFF}", rest));
    let eol = if body.contains("\r\n") { "\r\n" } else { "\n" };
    format!("{bom}{HEADER_KEY}: {}{eol}{body}", spelling(version))
}

/// The header's value rewritten to `version`, everything else about the
/// line kept: its key, its spacing, a trailing comment.
fn set_header(
    text: &str,
    version: u32,
    unrewritten: &mut [Unrewritten],
) -> Result<String, UpgradeError> {
    match header(ks_lang::parse(text).file()) {
        Header::Declared { span, .. } => {
            Ok(apply(text, vec![Edit::new(span, spelling(version))], unrewritten))
        }
        _ => Err(UpgradeError {
            span: Span::point(0),
            message: format!("a migration left no `{HEADER_KEY}:` header to update"),
        }),
    }
}

/// `text` with every `edit` applied, and every span in `unrewritten` moved
/// across the same edits so it still indexes the result.
///
/// Edits are byte ranges into `text` and the spans come from a parse of
/// `text`, so they land on character boundaries. An edit that overlaps one
/// already applied, or points outside the source, is dropped: a migration
/// that emits overlapping edits is buggy, and half of one is no better than
/// none of one.
fn apply(text: &str, mut edits: Vec<Edit>, unrewritten: &mut [Unrewritten]) -> String {
    edits.sort_by_key(|e| (e.span.start, e.span.end));
    for u in unrewritten.iter_mut() {
        let by = edits
            .iter()
            .filter(|e| e.span.end <= u.span.start)
            .map(|e| e.text.len() as i64 - e.span.len() as i64)
            .sum::<i64>();
        let start = (u.span.start as i64 + by).max(0) as u32;
        u.span = Span::new(start, (u.span.end as i64 + by).max(start as i64) as u32);
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0usize;
    for edit in edits {
        let (start, end) = (edit.span.start as usize, edit.span.end as usize);
        if start < at || end < start || end > text.len() {
            continue;
        }
        let Some(head) = text.get(at..start) else { continue };
        out.push_str(head);
        out.push_str(&edit.text);
        at = end;
    }
    out.push_str(text.get(at..).unwrap_or_default());
    out
}

/// A header entry's value as the bare word it spells: a quoted string, or a
/// value the parser recovered, is not a format version.
fn value_word(entry: Entry<'_>) -> Option<&str> {
    match entry.expr()? {
        Expr::Atom { atom: Atom::Word(w), .. } => Some(w.text()),
        _ => None,
    }
}
