//! ADR guard: keeps `docs/adr/` filenames, headings and the index consistent.
//! Pure functions over (ADR filenames + contents, index text) return one
//! actionable error per problem; the unit tests prove each guard fires.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Lowercase, non-alphanumerics to '-', collapse repeats, trim.
fn slugify(text: &str) -> String {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse `NNNN-kebab-slug.md`; `Err` is a full, fix-naming error message.
fn parse_adr_filename(name: &str) -> Result<(String, String), String> {
    let Some(stem) = name.strip_suffix(".md") else {
        return Err(format!("docs/adr/{name}: not a .md file; rename to NNNN-kebab-slug.md"));
    };
    let b = stem.as_bytes();
    if b.len() < 6 || !b[..4].iter().all(u8::is_ascii_digit) || b[4] != b'-' {
        return Err(format!(
            "docs/adr/{name}: must be NNNN-kebab-slug.md (4 digits, then a kebab slug)"
        ));
    }
    let (number, slug) = (stem[..4].to_string(), stem[5..].to_string());
    if slugify(&slug) != slug {
        return Err(format!(
            "docs/adr/{name}: slug is not kebab-case; rename to NNNN-kebab-slug.md"
        ));
    }
    Ok((number, slug))
}

/// (first 4-digit run in the heading, title after the ':' or after the number).
fn heading_parts(heading: &str) -> (Option<String>, &str) {
    let number =
        heading.split(|c: char| !c.is_ascii_digit()).find(|run| run.len() == 4).map(String::from);
    let title = if let Some(pos) = heading.find(':') {
        heading[pos + 1..].trim()
    } else if let Some(found) = &number {
        heading[heading.find(found.as_str()).unwrap_or(0) + found.len()..]
            .trim_start_matches([' ', '-', ':'])
            .trim()
    } else {
        heading.trim_start_matches([' ', '-', ':'])
    };
    (number, title)
}

/// Check every ADR file and the index; one actionable error per problem.
fn check_adrs(files: &BTreeMap<String, String>, index: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut by_number: BTreeMap<String, String> = BTreeMap::new();
    let mut adrs: Vec<(String, String)> = Vec::new(); // (name, number)

    // Per file: NNNN-kebab-slug.md name, distinct number, heading agrees with file.
    for name in files.keys() {
        let (number, slug) = match parse_adr_filename(name) {
            Ok(parsed) => parsed,
            Err(message) => {
                errors.push(message);
                continue;
            }
        };
        if let Some(previous) = by_number.get(&number) {
            errors.push(format!(
                "docs/adr/{name}: number {number} is already used by docs/adr/{previous}; renumber one of them"
            ));
        }
        by_number.insert(number.clone(), name.clone());
        adrs.push((name.clone(), number.clone()));

        // The file's first `# ` heading must agree with its filename.
        let Some(heading) = files[name].lines().find(|l| l.starts_with("# ")) else {
            errors.push(format!(
                "docs/adr/{name}: no `# ` heading; add one like `# ADR {number}: Title`"
            ));
            continue;
        };
        let (found, title) = heading_parts(heading);
        let heading_slug = slugify(title);
        if heading_slug != slug {
            errors.push(format!(
                "docs/adr/{name}: heading title \"{title}\" slugifies to \"{heading_slug}\" but the filename slug is \"{slug}\"; make the heading and the filename agree"
            ));
        }
        match found {
            None => errors.push(format!(
                "docs/adr/{name}: heading has no 4-digit ADR number; write it like `# ADR {number}: Title`"
            )),
            Some(found) if found != number => errors.push(format!(
                "docs/adr/{name}: heading says ADR {found} but the filename number is {number}; renumber the heading or the file so they match"
            )),
            _ => {}
        }
    }

    // The index must link every ADR exactly once, and only real ADRs.
    for (name, number) in &adrs {
        let count = index.matches(&format!("]({name})")).count();
        if count == 0 {
            errors.push(format!(
                "docs/adr/{name}: missing from the index; add `| [{number}]({name}) | <title> | <status> |` to docs/adr/README.md"
            ));
        } else if count > 1 {
            errors.push(format!(
                "docs/adr/README.md links {name} {count} times; link each ADR exactly once"
            ));
        }
    }

    // Every `](NNNN-....md)` link in the index must point at an existing ADR.
    let mut rest = index;
    while let Some(start) = rest.find("](") {
        let tail = &rest[start + 2..];
        let Some(end) = tail.find(')') else { break };
        let target = &tail[..end];
        let b = target.as_bytes();
        let adr_name = target.ends_with(".md")
            && b.len() > 5
            && b[..4].iter().all(u8::is_ascii_digit)
            && b[4] == b'-';
        if adr_name && !files.contains_key(target) {
            errors.push(format!(
                "docs/adr/README.md links to {target} but no such ADR exists; the link must match an ADR filename in docs/adr/"
            ));
        }
        rest = &tail[end + 1..];
    }

    errors.sort();
    errors
}

/// Two well-formed ADRs plus a matching index, shared by the unit tests.
fn fixture() -> (BTreeMap<String, String>, String) {
    let mut files = BTreeMap::new();
    files.insert("0000-record-decisions.md".into(), "# ADR 0000: Record decisions\n".into());
    files.insert("0001-something-else.md".into(), "# ADR 0001: Something else\n".into());
    let rows = "| [0000](0000-record-decisions.md) | Record decisions | Accepted |\n\
                | [0001](0001-something-else.md) | Something else | Accepted |\n";
    (files, format!("| ADR | Title | Status |\n|---|---|---|\n{rows}"))
}

#[test]
fn clean_fixture_has_no_errors() {
    let (files, index) = fixture();
    assert_eq!(check_adrs(&files, &index), Vec::<String>::new());
}

#[test]
fn rejects_bad_filename() {
    let (mut files, index) = fixture();
    files.insert("notes.md".into(), "# Notes\n".into());
    let errors = check_adrs(&files, &index);
    assert!(errors.iter().any(|e| e.contains("must be NNNN-kebab-slug.md")), "{errors:?}");
}

#[test]
fn rejects_duplicate_numbers() {
    let (mut files, index) = fixture();
    files.insert("0000-duplicate.md".into(), "# ADR 0000: Duplicate\n".into());
    let errors = check_adrs(&files, &index);
    assert!(errors.iter().any(|e| e.contains("0000 is already used by")), "{errors:?}");
}

#[test]
fn rejects_heading_filename_mismatch() {
    let (mut files, index) = fixture();
    files.insert("0001-something-else.md".into(), "# ADR 0002: Another thing\n".into());
    let errors = check_adrs(&files, &index);
    assert!(errors.iter().any(|e| e.contains("filename number is 0001")), "{errors:?}");
    assert!(errors.iter().any(|e| e.contains("slugifies to \"another-thing\"")), "{errors:?}");
}

#[test]
fn rejects_missing_index_entry() {
    let (files, mut index) = fixture();
    index = index.replace("| [0001](0001-something-else.md) | Something else | Accepted |\n", "");
    let errors = check_adrs(&files, &index);
    assert!(errors.iter().any(|e| e.contains("missing from the index")), "{errors:?}");
}

#[test]
fn rejects_duplicate_index_entry() {
    let (files, index) = fixture();
    let errors = check_adrs(&files, &format!("{index}{index}"));
    assert!(
        errors.iter().any(|e| e.contains("links 0000-record-decisions.md 2 times")),
        "{errors:?}"
    );
}

#[test]
fn rejects_dangling_index_link() {
    let (files, index) = fixture();
    let errors = check_adrs(&files, &format!("{index}| [0009](0009-ghost.md) | Ghost | Draft |\n"));
    assert!(
        errors.iter().any(|e| e.contains("links to 0009-ghost.md but no such ADR")),
        "{errors:?}"
    );
}

#[test]
fn docs_adr_directory_and_index_are_consistent() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/adr");
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(&dir).expect("docs/adr/ should exist") {
        let path = entry.expect("docs/adr entry should be readable").path();
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
        if name.ends_with(".md") {
            let content = fs::read_to_string(&path).unwrap_or_else(|error| {
                panic!("docs/adr/{name} should be readable UTF-8: {error}")
            });
            files.insert(name.to_string(), content);
        }
    }
    let index = files.remove("README.md").unwrap_or_else(|| {
        panic!(
            "docs/adr/README.md is missing; create the index and link every ADR like \
             `| [0000](0000-record-architecture-decisions.md) | Record architecture decisions | Accepted |`"
        )
    });
    assert!(
        !files.is_empty(),
        "docs/adr/ contains no ADRs; add 0000-record-architecture-decisions.md"
    );
    let errors = check_adrs(&files, &index);
    assert!(errors.is_empty(), "ADR guard found problems:\n  {}", errors.join("\n  "));
}
