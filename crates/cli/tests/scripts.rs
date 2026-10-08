//! `keepshipping check` reads what a script step's TypeScript module
//! declares, so a read of `migrate.applied` is typed, and a name the module
//! does not declare is an error here, at check time, rather than a surprise
//! at run time ([#88](https://github.com/Keep-Shipping/harness/issues/88)).
//!
//! Extraction needs `node`; everything here skips itself when there is none,
//! because a machine without `node` is one the check is defined to say
//! nothing on, and these tests are about the machine that has it.

use std::path::{Path, PathBuf};
use std::process::Command;

const SITE: &str = include_str!("fixtures/script/ship.ks");
const MIGRATE: &str = include_str!("fixtures/script/ship/migrate.ts");

fn check_in(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("check")
        .args(args)
        .current_dir(dir)
        // The ambient `CI` widens the "no format declared" warning, which
        // these fixtures are not about.
        .env_remove("CI")
        .output()
        .expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `keepshipping check` with nothing on the path, so the extractor cannot
/// run and only the cache can answer.
fn check_without_node(dir: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("check")
        .args(args)
        .current_dir(dir)
        .env("PATH", "")
        .env_remove("CI")
        .output()
        .expect("run keepshipping");
    (out.status.code().expect("exit code"), String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `node` on the path, or `None` — the check itself does not need one.
fn node() -> Option<PathBuf> {
    let out = Command::new("node").arg("--version").output().ok()?;
    out.status.success().then(|| PathBuf::from("node"))
}

/// The fixture site in a directory of its own: the check writes a cache
/// beside the site file, and a repository is not a place to write one. The
/// directory is removed when the test is done.
fn variant(name: &str, site: &str, module: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("keepshipping-script-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("ship")).expect("create temp dir");
    std::fs::write(dir.join("ship.ks"), site).expect("write the site file");
    std::fs::write(dir.join("ship/migrate.ts"), module).expect("write the module");
    dir
}

fn script_fixture(name: &str) -> PathBuf {
    variant(name, SITE, MIGRATE)
}

/// The one signature the extraction cached beside the site file.
fn cache_file(dir: &Path) -> PathBuf {
    let files: Vec<PathBuf> = std::fs::read_dir(dir.join(".keepshipping/cache/scripts"))
        .expect("the cache the check wrote")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    assert_eq!(files.len(), 1, "one signature cached: {files:?}");
    let file = files.into_iter().next().expect("the file");
    assert_eq!(file.file_stem().expect("a sha").to_string_lossy().len(), 64);
    file
}

#[test]
fn a_site_whose_module_declares_its_outputs_checks_clean() {
    let Some(_) = node() else { return };
    let dir = script_fixture("clean");
    let (code, stdout, stderr) = check_in(&dir, &[]);
    // The extraction is cached beside the site file, keyed by the extractor's
    // own source and the module's bytes.
    cache_file(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.contains("✓ ship.ks"), "{stdout}");
}

#[test]
fn an_output_the_module_does_not_declare_fails_the_check() {
    let Some(_) = node() else { return };
    let dir = variant("typo", &SITE.replace("migrate.applied", "migrate.aplied"), MIGRATE);
    let (json, out, _) = check_in(&dir, &["--format", "json"]);
    let (code, human, _) = check_in(&dir, &[]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(json, 1, "{out}");
    assert!(out.contains("\"code\":\"KS0203\""), "{out}");
    assert_eq!(code, 1, "{human}");
    assert!(human.contains("produces no output `aplied`"), "{human}");
    // The hint names the module it read and the output it meant.
    let flat = human.lines().map(str::trim).collect::<Vec<_>>().join(" ");
    assert!(flat.contains("hint: `./ship/migrate.ts` declares `applied`"), "{human}");
    assert!(flat.contains("did you mean `applied`?"), "{human}");
}

#[test]
fn an_output_declared_as_a_ts_number_is_an_error_saying_which_to_use() {
    let Some(_) = node() else { return };
    let dir = variant("number", SITE, &MIGRATE.replace("applied: int()", "applied: Number"));
    let (json, out, _) = check_in(&dir, &["--format", "json"]);
    let (_, human, _) = check_in(&dir, &[]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(json, 1, "{out}");
    assert!(out.contains("\"code\":\"KS0101\""), "{out}");
    assert!(out.contains("is not a ks type"), "{out}");
    let flat = human.lines().map(str::trim).collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("hint: a TS `number` is ambiguous in ks: declare it `int()` or `float()`"),
        "{human}"
    );
}

#[test]
fn the_second_run_answers_from_the_cache_and_needs_no_node() {
    let Some(_) = node() else { return };
    let dir = script_fixture("cache");
    let (code, stdout, stderr) = check_in(&dir, &[]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    cache_file(&dir);

    // With node off the path the extractor cannot run at all, so what the
    // check still knows came out of the cache under
    // `.keepshipping/cache/scripts`: a name the module does not declare is
    // still an error, and only a cached signature can produce one.
    std::fs::write(dir.join("ship.ks"), SITE.replace("migrate.applied", "migrate.aplied"))
        .expect("misspell the read");
    let (code, out) = check_without_node(&dir, &["--format", "json"]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("\"code\":\"KS0203\""), "{out}");
    assert!(out.contains("produces no output `aplied`"), "{out}");
}

#[test]
fn a_cache_file_that_is_not_a_signature_is_a_miss_not_an_answer() {
    let Some(_) = node() else { return };
    let dir = script_fixture("corrupt");
    let (code, stdout, stderr) = check_in(&dir, &[]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    std::fs::write(cache_file(&dir), "{ truncated").expect("corrupt the cache");
    std::fs::write(dir.join("ship.ks"), SITE.replace("migrate.applied", "migrate.aplied"))
        .expect("misspell the read");
    let (code, out, _) = check_in(&dir, &["--format", "json"]);
    let _ = std::fs::remove_dir_all(&dir);
    // The extractor ran again over the junk and wrote a real answer.
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("produces no output `aplied`"), "{out}");
}

#[test]
fn a_site_with_no_node_at_all_still_checks_clean() {
    // Nothing is known about the module, so nothing is said about its
    // outputs: the file checks the way it did before any of this.
    let dir = script_fixture("no-node");
    let (code, stdout) = check_without_node(&dir, &[]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 0, "{stdout}");
}

#[test]
fn a_module_that_will_not_import_leaves_the_outputs_unchecked() {
    let dir = variant("broken", SITE, "export default { outputs: { applied: ");
    let (code, stdout, stderr) = check_in(&dir, &[]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 0, "{stdout}{stderr}");
}
