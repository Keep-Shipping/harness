//! Drift guard for [`docs/PRIVACY.md`](../../../docs/PRIVACY.md) and the three
//! privacy declarations under `ventures/keepshipping/privacy/`.
//!
//! A privacy document's whole value is that it is TRUE, and a hand-maintained
//! table goes stale silently: a migration adds a column, a `RunEvent` variant
//! grows a person's handle, and the notice keeps asserting a calm that is no
//! longer the shape of the service. So each claim here is checked against the
//! code rather than a human's memory — the waitlist declaration against the
//! migrations as they are *at test time*, the run-log declaration against the
//! wire names `RunEvent::kind()` really emits, the allowlist against
//! `redact.rs`, and the declarations against the prose table a reader reads.
//! Every scan is canaried, because a substring search that silently matches
//! nothing goes vacuously green, which is the one failure mode it has.
//!
//! The declarations are parsed here rather than through a `toml` crate on
//! purpose: they are a dead-simple subset — `key = "value"` lines, `[section]`
//! headers, `#` comments — and a real TOML parser would turn the dotted keys
//! (`"request.run"`, `run.started`) into nested tables instead of the flat
//! field names they are. Reading thirty lines by hand keeps the format
//! dependency-free and keeps this file free of any new dependency.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

const PRIVACY_MD: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/PRIVACY.md"));
const RUN_LOG_SRC: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../core/src/ports/run_log.rs"));
const REDACT_SRC: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../core/src/redact.rs"));
const WAITLIST_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ventures/keepshipping/privacy/waitlist.toml"
));
const APPROVALS_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ventures/keepshipping/privacy/approvals.toml"
));
const RUNLOG_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ventures/keepshipping/privacy/runlog.toml"
));

/// Problems found in one sweep, kept so a single run reports all of them.
#[derive(Default)]
struct Findings(Vec<String>);

impl Findings {
    fn push(&mut self, problem: impl Into<String>) {
        self.0.push(problem.into());
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A set that the doc declares but the code does not have.
    fn extra(&mut self, label: &str, keys: &BTreeSet<String>) {
        for key in keys {
            self.push(format!("{label} declares `{key}`, which the code does not have"));
        }
    }

    /// A field the code has but neither declaration nor doc accounts for.
    fn missing(&mut self, label: &str, keys: &BTreeSet<String>, advice: &str) {
        for key in keys {
            self.push(format!("{label} does not account for `{key}`: {advice}"));
        }
    }
}

impl fmt::Display for Findings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "privacy guard found {} problem(s):", self.0.len())?;
        for problem in &self.0 {
            writeln!(f, "  - {problem}")?;
        }
        Ok(())
    }
}

/// The keys under one `[section]` of a declaration, as literal strings.
///
/// A dotted key is kept whole: `run.started` is a wire name, not a nested
/// table, and a parser that believed otherwise would silently return nothing.
fn decl_keys(text: &str, section: &str) -> BTreeSet<String> {
    let mut current = String::new();
    let mut keys = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
            current = name.trim().trim_matches('"').to_string();
            continue;
        }
        let (key, _) = line.split_once('=').unwrap_or_else(|| {
            panic!("{section}: `{line}` is not a comment, a [header] or key = \"value\"")
        });
        if current == section {
            keys.insert(key.trim().trim_matches('"').to_string());
        }
    }
    keys
}

/// The columns of a `CREATE TABLE ... ( ... )` block, table constraints dropped.
fn columns_in(block: &str) -> BTreeSet<String> {
    const CONSTRAINTS: [&str; 5] = ["UNIQUE", "PRIMARY", "CHECK", "FOREIGN", "CONSTRAINT"];
    block
        .lines()
        .filter_map(|line| {
            let first = line.trim().split_whitespace().next()?;
            // A table constraint may open with its paren: `UNIQUE(email_normalized, product)`.
            let word = first.split('(').next().unwrap_or(first);
            (!CONSTRAINTS.contains(&word.to_uppercase().as_str())).then(|| word.to_string())
        })
        .collect()
}

/// Every `waitlist_entries` column the migrations produce, read at test time so a
/// migration added tomorrow is in scope.
///
/// 0005 rebuilds the table through `waitlist_entries_rebuild` and renames it, so
/// the rebuild's column list is the schema that actually runs; the `ALTER TABLE
/// ... ADD COLUMN`s are folded in so a later plain `ADD COLUMN` still counts.
fn waitlist_schema() -> BTreeSet<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ventures/keepshipping/migrations");
    let mut built: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut added: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut migrations = 0;

    for entry in fs::read_dir(&dir).expect("ventures/keepshipping/migrations/ should exist") {
        let path = entry.expect("a migration directory entry should be readable").path();
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
        if !name.ends_with(".sql") {
            continue;
        }
        migrations += 1;
        let sql = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("ventures/keepshipping/migrations/{name} should be readable: {error}")
        });

        for table in built.keys().cloned().collect::<Vec<_>>() {
            let open = format!("CREATE TABLE IF NOT EXISTS {table} (");
            if let Some(at) = sql.find(&open) {
                let body = &sql[at + open.len()..];
                let end = body.find(");").unwrap_or(body.len());
                built.insert(table, columns_in(&body[..end]));
            }
        }
        if let Some(at) = sql.find("CREATE TABLE IF NOT EXISTS waitlist_entries_rebuild (") {
            let body = &sql[at + "CREATE TABLE IF NOT EXISTS waitlist_entries_rebuild (".len()..];
            let end = body.find(");").unwrap_or(body.len());
            built.insert("waitlist_entries_rebuild".to_string(), columns_in(&body[..end]));
        }
        for line in sql.lines() {
            let Some(rest) = line.trim().strip_prefix("ALTER TABLE waitlist_entries ADD COLUMN ")
            else {
                continue;
            };
            let column =
                rest.split_whitespace().next().unwrap_or_default().trim_end_matches(['(', ',']);
            added.entry("waitlist_entries".to_string()).or_default().insert(column.to_string());
        }
    }

    assert!(
        migrations >= 6,
        "found only {migrations} migration files in {dir:?}; the schema scan is looking in the wrong place"
    );
    let mut columns = built
        .get("waitlist_entries_rebuild")
        .or_else(|| built.get("waitlist_entries"))
        .cloned()
        .unwrap_or_else(|| panic!("no migration creates waitlist_entries or waitlist_entries_rebuild; the schema this guard reads has moved"));
    if let Some(extra) = added.get("waitlist_entries") {
        columns.extend(extra.iter().cloned());
    }
    columns
}

/// The dotted wire names `RunEvent::kind()` returns, read off its match arms.
fn wire_names(src: &str) -> BTreeSet<String> {
    let body = src
        .split_once("pub fn kind(&self) -> &'static str {")
        .unwrap_or_else(|| {
            panic!("run_log.rs has no `RunEvent::kind`; the wire-name scan has nothing to read")
        })
        .1;
    let mut names = BTreeSet::new();
    for line in body.lines() {
        if line.trim() == "}" {
            break;
        }
        let Some((_, literal)) = line.split_once("=>") else { continue };
        let literal = literal.trim();
        if !literal.starts_with('"') {
            continue;
        }
        let end = literal[1..].find('"').map_or(literal.len(), |at| at + 1);
        names.insert(literal[1..end].to_string());
    }
    names
}

/// The attribute paths `redact.rs` lets leave the machine, counted from source.
fn value_allowlist(src: &str) -> Vec<String> {
    let body = src
        .split_once("pub const VALUE_ALLOWLIST: &[&str] = &[")
        .unwrap_or_else(|| {
            panic!("redact.rs has no VALUE_ALLOWLIST; the allowlist count has nothing to read")
        })
        .1;
    let body = body.split_once("];").map_or(body, |(head, _)| head);
    body.split('"').skip(1).step_by(2).map(str::to_string).collect()
}

/// The cells of the one data table in the document, plus how many data rows it
/// has (the header and the `---` rule are not data).
fn table_cells(doc: &str) -> (Vec<String>, usize) {
    let (mut cells, mut rows, mut header) = (Vec::new(), 0, false);
    for line in doc.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        if line.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ')) {
            continue;
        }
        let row: Vec<String> =
            line.trim_matches('|').split('|').map(str::trim).map(str::to_string).collect();
        if !header {
            header = true;
            continue;
        }
        rows += 1;
        cells.extend(row);
    }
    (cells, rows)
}

/// Whether some cell in the table is about `key`.
///
/// A dotted field counts when the cell spells the whole name, or when the cell
/// carries the bare segment *and* names the prefix in words — the document
/// writes `slack.team_id` as "Slack `team_id`, `user_id`" in one row.
fn table_covers(cells: &[String], key: &str) -> bool {
    cells.iter().any(|cell| {
        cell.contains(&format!("`{key}`"))
            || key.split_once('.').is_some_and(|(prefix, last)| {
                cell.contains(&format!("`{last}`"))
                    && cell
                        .to_lowercase()
                        .split(|c: char| !c.is_alphanumeric())
                        .any(|word| word == prefix.to_lowercase())
            })
    })
}

/// The waitlist declaration names the schema and nothing else. A missing key
/// means a column exists that the privacy notice does not account for, which is
/// the exact silence this document must not have.
#[test]
fn the_waitlist_declaration_names_exactly_the_columns_the_migrations_produce() {
    let schema = waitlist_schema();
    let declared = decl_keys(WAITLIST_TOML, "holds");

    let mut found = Findings::default();
    found.extra("waitlist.toml", &declared.difference(&schema).cloned().collect());
    found.missing(
        "waitlist.toml [holds], and so docs/PRIVACY.md",
        &schema.difference(&declared).cloned().collect(),
        "a waitlist_entries column with no declaration and no doc row — add both",
    );
    assert!(found.is_empty(), "{found}");

    let mut sorted = schema.iter().map(String::as_str).collect::<Vec<_>>();
    sorted.sort_unstable();
    assert!(
        declared.len() >= 13,
        "the migration scan found only {} columns ({sorted:?}); a schema that shrank would make this \
         guard vacuously green",
        declared.len()
    );
}

/// Every declared field has a row in the document. This is the drift between the
/// machine-readable declaration and the human-readable inventory — the one that
/// actually bit this document in review.
#[test]
fn every_declared_field_appears_in_the_privacy_documents_table() {
    let (cells, rows) = table_cells(PRIVACY_MD);
    assert!(
        rows >= 40,
        "the PRIVACY.md table scan found {rows} data rows; the table moved or was split and this \
         guard is now reading the wrong one"
    );

    let mut found = Findings::default();
    for (label, text) in [
        ("waitlist.toml", WAITLIST_TOML),
        ("approvals.toml", APPROVALS_TOML),
        ("runlog.toml", RUNLOG_TOML),
    ] {
        for key in decl_keys(text, "holds") {
            if !table_covers(&cells, &key) {
                found.push(format!(
                    "{label} declares `{key}` but docs/PRIVACY.md has no table cell for it"
                ));
            }
        }
    }
    assert!(found.is_empty(), "{found}");
}

/// The run-log declaration is the event vocabulary, so it must be `kind()`'s
/// vocabulary: a new variant carrying a person's handle has to add a row or this
/// fails.
#[test]
fn the_run_log_declaration_matches_the_events_the_engine_actually_emits() {
    let emitted = wire_names(RUN_LOG_SRC);
    let declared = decl_keys(RUNLOG_TOML, "holds");

    let mut found = Findings::default();
    found.extra("runlog.toml", &declared.difference(&emitted).cloned().collect());
    found.missing(
        "runlog.toml [holds], and so docs/PRIVACY.md",
        &emitted.difference(&declared).cloned().collect(),
        "a RunEvent::kind() wire name with no declaration — add the row, and say what it carries",
    );
    assert!(found.is_empty(), "{found}");

    assert!(
        emitted.len() >= 18,
        "the kind() scan found only {} wire names ({emitted:?}); a shrunken scan would pass anything",
        emitted.len()
    );
}

/// The document claims a number; the source has to still hold it.
#[test]
fn the_redaction_allowlist_still_names_exactly_the_nine_paths_the_document_claims() {
    let allow = value_allowlist(REDACT_SRC);
    assert_eq!(
        allow.len(),
        9,
        "crates/core/src/redact.rs VALUE_ALLOWLIST holds {} paths ({allow:?}), but runlog.toml says \
         'exactly nine'; either the count in the declaration is stale or the allowlist grew",
        allow.len()
    );
}
