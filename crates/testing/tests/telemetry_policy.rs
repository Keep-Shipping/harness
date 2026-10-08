//! The telemetry payload carries no identity: the schema in `docs/TELEMETRY.md`
//! is parsed here and checked field for field, so the contract cannot erode one
//! plausible-looking field at a time ([#156](https://github.com/Keep-Shipping/harness/issues/156)).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The document under test. `include_str!` so a missing or moved file is a compile error here, not a test that passes by finding nothing.
const DOC: &str = include_str!("../../../docs/TELEMETRY.md");

/// The header row of the field table, matched exactly so a reformat cannot make the extractor find nothing.
const TABLE_HEADER: &str = "| field | type | example | note |";

/// The `type` column is drawn from exactly this set and nothing else: a type outside it is a schema change, which is an ADR, not a table edit.
const FIELD_TYPES: &str = "const semver enum(cli) enum(action) enum(code) count bucket";

/// Substrings that may not appear in a field name, in any spelling. Free text (`body`, `text`, `message`) carries whatever the customer wrote; a location (`path`, `host`, `url`, `ip`, `cwd`) names their infrastructure; a handle (`id`, `uuid`, `token`, `sha`, `branch`) joins two payloads back into one person; a profile (`os`, `arch`, `user_agent`, `fingerprint`) narrows the population the anonymity rests on.
const IDENTITY_WORDS: &str = "path file content body text name host url uri repo user email account org branch commit sha tag image env arg token secret key id uuid address message comment agent os arch platform ip machine install fingerprint user_agent cwd dir";

/// The one pre-existing hit in the workspace's Rust sources, and why it is allowed: it is a JSON-RPC fixture in an LSP test asserting that an unknown notification method is ignored in silence, and the string is a method name *arriving from the client*, not anything this binary sends. Both the path and the fragment have to match, so the day that line means something else the allowlist stops covering it.
const ALLOWED_HITS: [(&str, &str); 1] = [("crates/lsp/src/server.rs", "telemetry/somethingNew")];

/// Words that would mean something is phoning home, in any casing.
const SENDER_WORDS: &str = "telemetry analytics posthog amplitude mixpanel sentry DO_NOT_TRACK";

/// One row of the payload's field table.
struct Field {
    name: String,
    ty: String,
    example: String,
}

/// One `"key": value` pair the JSON scanner read, with the object depth it sits at: 1 is top level, 2 is inside the one nested object the schema permits.
struct Entry {
    depth: usize,
    key: String,
    value: String,
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// The payload's field table, from the header row down. Panics rather than returning an empty table, so a reformat of the document cannot turn every check below into a vacuous pass.
fn field_table() -> Vec<Field> {
    let header = DOC.lines().position(|line| line.trim() == TABLE_HEADER).unwrap_or_else(|| panic!("docs/TELEMETRY.md no longer has the `{TABLE_HEADER}` header this test parses; the payload schema has become unreadable, so nothing below is actually being checked"));
    let mut fields = Vec::new();
    for line in DOC.lines().skip(header + 1) {
        let line = line.trim();
        if !line.starts_with('|') {
            break;
        }
        if line.starts_with("| ---") {
            continue;
        }
        // Outer pipes and backticks stripped: name, type, example, note.
        let row: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().trim_matches('`').to_string())
            .collect();
        assert_eq!(
            row.len(),
            4,
            "row `{line}` has {} cells; a pipe in a note breaks the table",
            row.len()
        );
        fields.push(Field { name: row[0].clone(), ty: row[1].clone(), example: row[2].clone() });
    }
    fields
}

/// A line-oriented reader for the ```json example payload. It understands one object and the one nested object the schema permits, and panics on anything else — an array, a third level, a brace inside a string — because a scanner that quietly skips what it does not understand is worse than no scanner: it would pass a payload carrying a `urls` array.
fn json_entries() -> Vec<Entry> {
    let start = DOC.lines().position(|line| line.trim() == "```json").unwrap_or_else(|| {
        panic!("docs/TELEMETRY.md has no ```json example; the leak test has nothing to scan")
    });
    let lines: Vec<&str> =
        DOC.lines().skip(start + 1).take_while(|l| !l.trim().starts_with("```")).collect();
    assert!(lines.iter().any(|line| line.contains(':')), "the ```json example is empty");
    let mut entries = Vec::new();
    let mut depth = 0usize;
    for line in lines {
        let line = line.trim().trim_end_matches(',');
        if line.is_empty() {
            continue;
        }
        assert!(
            !line.contains(['[', ']']),
            "`{line}` is an array; only counts and maps are allowed"
        );
        if line == "{" {
            depth += 1;
            continue;
        }
        if line == "}" {
            depth -= 1;
            continue;
        }
        let (key, raw) = line
            .split_once(':')
            .unwrap_or_else(|| panic!("`{line}` is neither a brace nor a `\"key\": value` pair"));
        let key = key.trim().trim_matches('"').to_string();
        if raw.trim() == "{" {
            entries.push(Entry { depth, key, value: "{".to_string() });
            depth += 1;
            continue;
        }
        let value = raw.trim();
        assert!(
            value.parse::<u64>().is_ok() || (value.starts_with('"') && value.ends_with('"')),
            "`{line}` is neither an integer nor a quoted string"
        );
        let value = value.trim_matches('"').to_string();
        assert!(
            !value.contains(['{', '}']),
            "`{key}` holds `{value}`, which this scanner cannot read"
        );
        entries.push(Entry { depth, key, value });
    }
    entries
}

/// The text of the bullet beginning with `marker`, up to the next bullet.
fn bullet(marker: &str) -> String {
    let start = DOC.lines().position(|line| line.trim_start().starts_with(marker)).unwrap_or_else(|| panic!("docs/TELEMETRY.md has no bullet starting with `{marker}`; the vocabulary it names is undocumented"));
    let first = DOC.lines().nth(start).expect("the bullet's first line").to_string();
    let rest: String = DOC.lines().skip(start + 1).collect::<Vec<_>>().join("\n");
    let end = rest.find("\n- ").unwrap_or(rest.len());
    format!("{first}\n{}", &rest[..end])
}

/// The words a bullet names after its final colon: the colon that introduces the list ("... fifteen of them: `approve`, ..."), so everything before it is prose and everything after is the vocabulary.
fn listed_words(marker: &str) -> BTreeSet<String> {
    let text = bullet(marker);
    let (_, after) =
        text.rsplit_once(':').unwrap_or_else(|| panic!("the `{marker}` bullet names no list"));
    let words: BTreeSet<String> = after
        .split('`')
        .skip(1)
        .step_by(2)
        .map(|w| w.trim().trim_end_matches(['.', ',']).trim().to_string())
        .filter(|w| !w.is_empty())
        .collect();
    assert!(!words.is_empty(), "the `{marker}` bullet names no vocabulary");
    words
}

/// The top-level words `dispatch()` matches, read from the source. Or-patterns are split on `|`, so `Some("runs" | "approve" | "deny")` yields three words rather than the two a naive scrape would miss.
fn cli_words_in_code() -> BTreeSet<String> {
    let source =
        fs::read_to_string(repo_path("../cli/src/main.rs")).expect("read crates/cli/src/main.rs");
    let body = source
        .split_once("fn dispatch() -> ExitCode {")
        .unwrap_or_else(|| panic!("crates/cli/src/main.rs has no `fn dispatch()`"))
        .1
        .split_once("\n}\n")
        .unwrap_or_else(|| panic!("`dispatch()` has no closing brace at column 0"))
        .0;
    let mut words = BTreeSet::new();
    for line in body.lines() {
        let line = line.trim();
        let Some(pattern) = line.strip_prefix("Some(").filter(|_| line.contains("=>")) else {
            continue;
        };
        let inner = pattern
            .split_once(')')
            .unwrap_or_else(|| panic!("the arm `{line}` has an unterminated pattern"))
            .0;
        for word in inner.split('|') {
            let word = word.trim().trim_matches('"');
            assert!(
                !word.is_empty() && word.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "the arm `{line}` yields `{word}`, not a bare lowercase word"
            );
            words.insert(word.to_string());
        }
    }
    assert!(!words.is_empty(), "no `Some(\"...\") =>` arms found; the scrape broke");
    words
}

/// `KS0001` -> 1. Panics on anything else so a malformed token fails loudly.
fn numeric_code(token: &str) -> u32 {
    token
        .strip_prefix("KS")
        .and_then(|digits| digits.parse().ok())
        .unwrap_or_else(|| panic!("`{token}` is not a `KS` diagnostic code"))
}

/// The diagnostic codes the document names, with the `KS0001`–`KS0005` ranges expanded, so the set is the 33 codes rather than the ten ranges written down.
fn doc_codes() -> BTreeSet<String> {
    // Stand the en dashes off from their neighbours so `KS0001`–`KS0005` reads as three tokens.
    let text = bullet("- `enum(code)`").replace('`', "").replace('\u{2013}', " \u{2013} ");
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let mut codes = BTreeSet::new();
    let mut at = 0usize;
    while at < tokens.len() {
        let first = tokens[at].trim_end_matches(['.', ',']);
        if !first.starts_with("KS") {
            at += 1;
            continue;
        }
        // A dash between two codes is a range and stands for every number between them.
        if tokens.get(at + 1) == Some(&"\u{2013}") {
            let Some(last) = tokens.get(at + 2).copied() else {
                panic!("a range ends with a dash and nothing after it")
            };
            for code in numeric_code(first)..=numeric_code(last.trim_end_matches(['.', ','])) {
                codes.insert(format!("KS{code:04}"));
            }
            at += 3;
        } else {
            codes.insert(first.to_string());
            at += 1;
        }
    }
    // Fewer than 33 means the en-dash range syntax is no longer being read, so
    // the list would be checked against almost nothing.
    assert!(codes.len() >= 33, "{} codes read, at least 33 expected", codes.len());
    codes
}

/// Every `.rs` file under `dir`, skipping build output.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn the_documented_payload_has_only_countable_and_closed_enum_fields() {
    // 8+ rows: below that the extractor has silently stopped finding the
    // table, and every check in this file is passing on nothing.
    let fields = field_table();
    assert!(fields.len() >= 8, "{} rows parsed, 8+ expected", fields.len());
    // A type outside the set is a change of schema, which gets an ADR.
    for field in &fields {
        assert!(
            FIELD_TYPES.split(' ').any(|ty| ty == field.ty),
            "`{}` is typed `{}`, outside the closed set",
            field.name,
            field.ty
        );
    }
}

#[test]
fn no_field_carries_free_text_or_an_identity() {
    for field in field_table() {
        // Text, location, handle and profile all identify, in any spelling.
        for word in IDENTITY_WORDS.split(' ') {
            assert!(!field.name.contains(word), "`{}` contains `{word}`", field.name);
        }
        // A name needing this many characters describes the value it carries.
        assert!(field.name.len() <= 24, "`{}` is {} characters", field.name, field.name.len());
    }
}

#[test]
fn every_json_key_in_the_example_is_a_field_or_a_closed_enum_member() {
    let fields: BTreeSet<String> = field_table().into_iter().map(|f| f.name).collect();
    let actions: BTreeSet<String> =
        ks_core::step::ActionKind::NAMES.iter().map(|n| n.to_string()).collect();
    for entry in json_entries() {
        match entry.depth {
            // An unnamed key is a key nothing constrains.
            1 => assert!(fields.contains(&entry.key), "`{}` is not a declared field", entry.key),
            2 => assert!(
                actions.contains(&entry.key),
                "`{}` is not an `ActionKind::NAMES` member",
                entry.key
            ),
            other => {
                panic!("`{}` nests {other} deep; only one nested object is documented", entry.key)
            }
        }
    }
}

#[test]
fn the_example_values_match_their_declared_types() {
    let fields = field_table();
    let entries = json_entries();
    let schema_const = fields
        .iter()
        .find(|f| f.name == "schema")
        .unwrap_or_else(|| panic!("no `schema` field; the version literal is unconstrained"))
        .example
        .clone();
    let cli_words = cli_words_in_code();
    for field in &fields {
        let entry =
            entries.iter().find(|e| e.depth == 1 && e.key == field.name).unwrap_or_else(|| {
                panic!("the table declares `{}` but the example omits it", field.name)
            });
        match field.ty.as_str() {
            // A `count` is one integer or the one permitted map of them, whose
            // keys the test above checks against `ActionKind::NAMES`.
            "count" if entry.value == "{" => {}
            "count" => assert!(
                entry.value.parse::<u64>().is_ok(),
                "`{}` is `{}`, not a count",
                field.name,
                entry.value
            ),
            "bucket" => {
                // An unbucketed duration is a measurement, and measurements are
                // fingerprints; power-of-two is what makes it a magnitude.
                let ms = entry.value.strip_suffix("ms").unwrap_or_else(|| {
                    panic!("`{}` is `{}`, with no `ms` suffix", field.name, entry.value)
                });
                let number: u32 = ms.parse().unwrap_or_else(|_| {
                    panic!("`{}` is `{}`, not milliseconds", field.name, entry.value)
                });
                assert!(
                    number.is_power_of_two(),
                    "`{}`'s bucket `{}` is not a power of two",
                    field.name,
                    entry.value
                );
            }
            "enum(cli)" => assert!(
                cli_words.contains(entry.value.as_str()),
                "`{}`'s `{}` is not a word `dispatch()` matches",
                field.name,
                entry.value
            ),
            "semver" => assert!(
                entry.value.split('.').count() >= 2
                    && entry.value.split('.').all(|part| part.parse::<u32>().is_ok()),
                "`{}` is `{}`, not a dotted numeric version",
                field.name,
                entry.value
            ),
            // A receiver refuses a version it does not know, so the two must be
            // the same string.
            "const" => assert_eq!(
                entry.value, schema_const,
                "`{}` is `{}`, not the table's `{schema_const}`",
                field.name, entry.value
            ),
            other => panic!("`{}` has type `{other}`, which this test cannot check", field.name),
        }
    }
    // String values under a count map are free text wearing a count's name.
    for entry in entries.iter().filter(|e| e.depth == 2) {
        assert!(
            entry.value.parse::<u64>().is_ok(),
            "the nested `{}` is `{}`, not a count",
            entry.key,
            entry.value
        );
    }
}

#[test]
fn the_documented_vocabularies_are_the_ones_in_the_code() {
    // Both directions: a word the code has and the document omits is as wrong
    // as one the document names and the code dropped.
    assert_eq!(listed_words("- `enum(cli)`"), cli_words_in_code(), "the CLI words have drifted");
    let actions: BTreeSet<String> =
        ks_core::step::ActionKind::NAMES.iter().map(|n| n.to_string()).collect();
    assert_eq!(listed_words("- `enum(action)`"), actions, "the action kinds have drifted");
    let codes: BTreeSet<String> =
        ks_lang::Code::ALL.iter().map(|c| c.as_str().to_string()).collect();
    assert_eq!(doc_codes(), codes, "the diagnostic codes have drifted");
}

#[test]
fn telemetry_is_absent_from_the_tool_today() {
    let mut files = Vec::new();
    for root in ["../../crates", "../../adapters"] {
        rust_sources(&repo_path(root), &mut files);
    }
    // This file necessarily names every sender word it searches for, so it is
    // the one exclusion.
    files.retain(|path| !path.ends_with("tests/telemetry_policy.rs"));
    let workspace = repo_path("../..");
    let mut unexpected = Vec::new();
    let mut checked = 0usize;
    for file in files {
        let Ok(source) = fs::read_to_string(&file) else { continue };
        checked += 1;
        let relative =
            file.strip_prefix(&workspace).unwrap_or(&file).to_string_lossy().into_owned();
        for (index, line) in source.lines().enumerate() {
            for word in SENDER_WORDS
                .split(' ')
                .filter(|w| line.to_ascii_lowercase().contains(&w.to_ascii_lowercase()))
            {
                let allowed = ALLOWED_HITS
                    .iter()
                    .any(|(path, fragment)| relative == *path && line.contains(fragment));
                if !allowed {
                    unexpected.push(format!("{relative}:{}: {word} — {}", index + 1, line.trim()));
                }
            }
        }
    }
    assert!(checked > 0, "no Rust sources were read; the scan looked nowhere");
    assert!(
        unexpected.is_empty(),
        "the decision is no telemetry, but these lines name one:\n  {}\n\nEvery outbound call needs an entry in ADR 0005's *What leaves the runner*",
        unexpected.join("\n  ")
    );
}
