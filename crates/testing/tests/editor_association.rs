//! Editor association guard: the `keepshipping` language is claimed by file
//! name, never by extension (docs/LANGUAGE.md, "File name and association").
//! `.ks` belongs to Red Hat/Fedora Kickstart; a grammar that claims `*.ks`
//! takes those files away from the people who own them. String parsing only:
//! `ks-testing` has no JSON dependency and this file has no need for one.

use std::fs;
use std::path::Path;

/// The `contributes.languages` block's value of `key`, or None if absent. The
/// block is everything between `"languages":` and the next `"grammars":`.
fn language_field<'a>(package: &'a str, key: &str) -> Option<&'a str> {
    let block = package.split_once("\"languages\":")?.1.split_once("\"grammars\":")?.0;
    let (_, rest) = block.split_once(&format!("\"{key}\""))?;
    rest.trim_start().strip_prefix(':').map(str::trim)
}

/// The quoted strings of a JSON array literal, e.g. `["a", "b"]` -> ["a", "b"].
fn json_array(text: &str) -> Vec<String> {
    let text = text.trim();
    let Some(body) = text.strip_prefix('[').and_then(|rest| rest.split(']').next()) else {
        return Vec::new();
    };
    body.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| part.trim_matches(['"', ' ', '\n']).to_string())
        .collect()
}

/// A site file is named `ship.ks` or `*.ship.ks`: an exact basename, or a
/// basename ending in `.ship.ks`. VS Code matches both `filenames` and a
/// `filenamePatterns` entry that holds no path separator against the file
/// name alone (VS Code's `languagesAssociations.ts`, `filepatternOnPath`),
/// so `myship.ks` is not a site file and neither is `ship.ks.bak`.
fn claims(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);
    basename == "ship.ks" || basename.ends_with(".ship.ks")
}

#[test]
fn package_json_registers_ship_ks_by_name_only() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../editors/vscode");
    let package = fs::read_to_string(dir.join("package.json")).unwrap_or_else(|error| {
        panic!("editors/vscode/package.json should be readable UTF-8: {error}")
    });

    assert!(package.contains("\"id\": \"keepshipping\""), "the language id must be `keepshipping`");

    let filenames = language_field(&package, "filenames")
        .unwrap_or_else(|| panic!("the language contribution must declare `filenames`"));
    assert_eq!(json_array(filenames), ["ship.ks"], "only the exact name `ship.ks` may be claimed");

    let patterns = language_field(&package, "filenamePatterns")
        .unwrap_or_else(|| panic!("the language contribution must declare `filenamePatterns`"));
    assert_eq!(json_array(patterns), ["*.ship.ks"], "the only pattern may be `*.ship.ks`");

    assert!(
        language_field(&package, "extensions").is_none(),
        "the language contribution must not claim any extension: `.ks` is Kickstart's"
    );
}

#[test]
fn the_matcher_claims_site_files_and_nothing_else() {
    for path in ["ship.ks", "api.ship.ks", "crates/cli/tests/fixtures/site/ship.ks"] {
        assert!(claims(path), "{path} is a site file and must be claimed");
    }
    for path in ["editors/vscode/test/kickstart.ks", "anaconda-ks.ks", "ship.ks.bak", "myship.ks"] {
        assert!(!claims(path), "{path} is not a site file and must not be claimed");
    }
}

/// The `file-types` array of a `tree-sitter.json`, in the order it is written.
fn file_types(text: &str) -> Vec<String> {
    let (_, rest) = text
        .split_once("\"file-types\":")
        .unwrap_or_else(|| panic!("the grammar must declare `file-types`"));
    json_array(rest.trim_start())
}

/// The tree-sitter grammar must register the same names as the extension:
/// the exact basename and one pattern, and nothing else.
#[test]
fn tree_sitter_grammar_claims_ship_ks_by_name_only() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../editors/tree-sitter-keepshipping/tree-sitter.json");
    let text = fs::read_to_string(&manifest).unwrap_or_else(|error| {
        panic!("the tree-sitter manifest should be readable UTF-8: {error}")
    });

    assert_eq!(
        file_types(&text),
        ["ship.ks", "*.ship.ks"],
        "`ks`, `.ks` and `*.ks` are Kickstart's; the grammar may claim the two site names only"
    );
}
