//! Golden snapshots of the three `--format` outputs on the site fixture —
//! the documented example, byte for byte, colour off (stdout is not a
//! terminal under `cargo test`). Re-run with
//! `UPDATE_GOLDEN=1 cargo test -p ks-cli --test snapshots` after reviewing
//! the diff; the rules the bytes follow live in `docs/DIAGNOSTICS.md`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The site fixture: a directory holding one wrong `ship.ks`, so the
/// default file is found and checked with exit 1.
const SITE: &str = "tests/fixtures/site";

fn check(extra: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("check")
        .args(extra)
        // The golden bytes are the ones from a terminal-less local run; a
        // `CI` in the parent would add the undeclared-format warning to the
        // fixture and rewrite the example this file pins.
        .env_remove("CI")
        .current_dir(SITE)
        .output()
        .expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn golden(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(SITE).join(name)
}

fn read_or_update(path: &Path, actual: &str) -> String {
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::write(path, actual).expect("write golden");
        return actual.to_string();
    }
    fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn human_output_is_the_documented_example() {
    let (code, stdout, stderr) = check(&[]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    // Not just the golden: the headline and the promise must be exactly the
    // site's example, so a stray UPDATE_GOLDEN cannot redefine them.
    assert!(
        stdout.starts_with("✗ ship.ks:21  deploy.image  expected oci.Digest, got string\n"),
        "{stdout}"
    );
    assert_eq!(stdout, read_or_update(&golden("check.human"), &stdout));
}

#[test]
fn json_output_is_schema_v1() {
    let (code, stdout, stderr) = check(&["--format", "json"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert!(
        stdout.starts_with("{\"version\":1,\"code\":\"KS0101\",\"severity\":\"error\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"file\":\"ship.ks\",\"subject\":\"deploy.image\""), "{stdout}");
    assert!(
        stdout.contains("\"line\":21,\"column\":12,\"end_line\":21,\"end_column\":21"),
        "{stdout}"
    );
    // The type-directed fix: rewrite `tag` (the output segment, not the
    // whole reference) to `digest`, machine-applicable.
    assert!(
        stdout.ends_with(
            "\"fixes\":[{\"span\":{\"start\":369,\"end\":372,\"line\":21,\"column\":18,\
             \"end_line\":21,\"end_column\":21},\"replacement\":\"digest\",\
             \"machine_applicable\":true}]}\n"
        ),
        "{stdout}"
    );
    assert_eq!(stdout, read_or_update(&golden("check.json"), &stdout));
}

#[test]
fn github_output_is_one_annotation() {
    let (code, stdout, stderr) = check(&["--format", "github"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert!(
        stdout.starts_with(concat!(
            "::error file=ship.ks,line=21,col=12,endLine=21,endColumn=21,",
            "title=KS0101 deploy.image::expected oci.Digest, got string"
        )),
        "{stdout}"
    );
    assert_eq!(stdout, read_or_update(&golden("check.github"), &stdout));
}
