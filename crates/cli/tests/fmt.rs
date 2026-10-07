//! End-to-end tests of `keepshipping fmt`: what it rewrites, what `--check`
//! reports instead, and what it refuses. The formatter's own rules are
//! covered in `crates/lang/tests/fmt.rs`; this is the binary's behaviour.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The site's example file, as a fixed point: `fmt --check` must find
/// nothing to change in it.
const CANONICAL: &str = include_str!("fixtures/site/ship.ks");

/// The same file written the way a hurried author writes it: single-space
/// values, an over-indented input, three blank lines and no trailing
/// newline. It parses; only its whitespace is wrong.
const MESSY: &str = concat!(
    "name: api\n",
    "on: push main\n",
    "\n",
    "\n",
    "\n",
    "steps:\n",
    "  build: oci.image\n",
    "      from: ./Dockerfile\n",
    "  deploy: k8s.rollout\n",
    "    image:   build.tag",
);

/// What [`MESSY`] formats to: the value columns of the whole `steps` subtree
/// aligned on the widest key, one blank line, and the trailing newline.
const FORMATTED: &str = concat!(
    "name:  api\n",
    "on:    push main\n",
    "\n",
    "steps:\n",
    "  build:   oci.image\n",
    "    from:  ./Dockerfile\n",
    "  deploy:  k8s.rollout\n",
    "    image: build.tag\n",
);

/// A string that is never closed: the parse fails, so `fmt` refuses the
/// whole file rather than rewriting whitespace around a broken value.
const BROKEN: &str = "\
name: broken
description: \"never closed
steps:
  build: oci.image
    from: ./Dockerfile
";

/// A file under `name` holding `src`. Removed when the returned guard drops.
struct Temp(PathBuf);

impl Temp {
    /// A file in the temp directory, unique to this test process and name.
    fn file(name: &str, src: &str) -> Temp {
        let path =
            std::env::temp_dir().join(format!("keepshipping-fmt-{}-{name}", std::process::id()));
        std::fs::write(&path, src).expect("write temp file");
        Temp(path)
    }

    /// An empty directory, for the walk and the defaults.
    fn dir(name: &str) -> Temp {
        let path =
            std::env::temp_dir().join(format!("keepshipping-fmt-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Temp(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn str(&self) -> &str {
        self.0.to_str().expect("a utf-8 temp path")
    }

    fn read(&self) -> String {
        std::fs::read_to_string(&self.0).expect("read back")
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        // A file and a directory are removed by the same call.
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The exit code, stdout and stderr of one `keepshipping fmt` run. An empty
/// `args` list still runs `fmt`, and `Some(src)` feeds it on stdin.
fn run(args: &[&str], stdin: Option<&str>) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("fmt")
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run keepshipping");
    if let Some(src) = stdin {
        use std::io::Write as _;
        child.stdin.take().expect("stdin").write_all(src.as_bytes()).expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait for keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn fmt_rewrites_a_messy_file_in_place() {
    let f = Temp::file("messy.ks", MESSY);
    let (code, stdout, stderr) = run(&[f.str()], None);
    // Columns aligned, the over-indent fixed, the blank lines collapsed to
    // one, and the trailing newline restored.
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert_eq!(f.read(), FORMATTED);
}

#[test]
fn fmt_is_a_fixed_point() {
    let f = Temp::file("twice.ks", MESSY);
    assert_eq!(run(&[f.str()], None).0, 0);
    let once = f.read();
    assert_eq!(run(&[f.str()], None).0, 0);
    assert_eq!(f.read(), once, "a second pass changed the file again");
}

#[test]
fn fmt_leaves_a_canonical_file_alone_entirely() {
    let f = Temp::file("canonical.ks", FORMATTED);
    let before = std::fs::metadata(f.path()).expect("metadata").modified().expect("mtime");
    std::thread::sleep(std::time::Duration::from_millis(20));
    let (code, _, stderr) = run(&[f.str()], None);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        std::fs::metadata(f.path()).expect("metadata").modified().expect("mtime"),
        before,
        "an unchanged file was rewritten"
    );
}

#[test]
fn fmt_check_reports_a_numbered_diff_and_leaves_the_file_alone() {
    let f = Temp::file("check.ks", MESSY);
    let (code, stdout, stderr) = run(&["--check", f.str()], None);
    assert_eq!(code, 1, "{stderr}");
    assert_eq!(f.read(), MESSY, "--check wrote to the file");
    let name = f.path().display().to_string();
    assert!(stdout.starts_with(&format!("--- {name}\n+++ {name}\n")), "{stdout}");
    // A real unified diff: `patch` and `git apply` both read these headers.
    assert!(stdout.contains("\n@@ -1,10 +1,8 @@\n"), "{stdout}");
    // The ragged lines come out as removals, the aligned ones as additions.
    assert!(stdout.contains("-  build: oci.image\n"), "{stdout}");
    assert!(stdout.contains("+  build:   oci.image\n"), "{stdout}");
    assert!(stdout.contains("-      from: ./Dockerfile\n"), "{stdout}");
    assert!(stdout.contains("+    from:  ./Dockerfile\n"), "{stdout}");
    // The two extra blank lines show up as removed, not silently kept.
    assert!(stdout.contains("-\n-\n"), "{stdout}");
    // And the file that gained a trailing newline says so, on the line it
    // belongs to rather than at the end of the diff.
    assert!(stdout.contains("-    image:   build.tag\n\\ No newline at end of file\n"), "{stdout}");
}

/// Entries whose value column is shared: `    from:` is the widest line in
/// the block, so every value in it starts at column 11. Built, not pasted,
/// so the fixtures stay canonical when the keys change width.
fn block(entries: usize, width: usize) -> Vec<String> {
    let mut lines = vec!["steps:".to_string()];
    for i in 0..entries {
        lines.push(format!("{:10}oci.image", format!("  s{i:0width$}:")));
        lines.push("    from: ./Dockerfile".to_string());
    }
    lines
}

#[test]
fn a_check_diff_has_one_hunk_per_run_of_changes() {
    // Two changes far enough apart that their context cannot overlap.
    let mut lines = block(40, 2);
    // One extra space on the first and the last entry, and nothing else.
    lines[1] = lines[1].replace("oci.image", " oci.image");
    lines[79] = lines[79].replace("oci.image", " oci.image");
    let f = Temp::file("hunks.ks", &(lines.join("\n") + "\n"));

    let (code, stdout, stderr) = run(&["--check", f.str()], None);
    assert_eq!(code, 1, "{stderr}");
    assert_eq!(stdout.matches("\n@@ ").count(), 2, "one hunk per run: {stdout}");
    assert!(stdout.contains("\n@@ -1,5 +1,5 @@\n"), "{stdout}");
    assert!(stdout.contains("\n@@ -77,5 +77,5 @@\n"), "{stdout}");
}

#[test]
fn a_check_diff_on_a_large_file_stays_fast() {
    // ~20k entries: without prefix/suffix stripping the matching table
    // alone would be gigabytes, so this only finishes if the diff is bounded.
    let mut lines = block(10_000, 5);
    lines[10_001] = lines[10_001].replace("oci.image", " oci.image");
    let f = Temp::file("big.ks", &(lines.join("\n") + "\n"));
    assert!(f.read().len() > 400_000, "the fixture is meant to be large");

    let start = std::time::Instant::now();
    let (code, stdout, stderr) = run(&["--check", f.str()], None);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(20),
        "the diff of a 400 KB file took {:?}",
        start.elapsed()
    );
    // A bounded diff, not one hunk swallowing the file.
    assert!(
        stdout.lines().count() < 40,
        "the diff should stay small: {} lines",
        stdout.lines().count()
    );
}

#[test]
fn fmt_check_is_silent_and_successful_on_a_canonical_file() {
    let d = Temp::dir("canonical");
    std::fs::write(d.join("ship.ks"), CANONICAL).expect("write ship.ks");
    let (code, stdout, stderr) = run(&["--check", d.str()], None);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.starts_with('✓'), "{stdout}");
    assert!(!stdout.contains("---"), "no diff for a canonical file: {stdout}");
}

#[test]
fn fmt_check_exits_zero_on_the_site_example() {
    let (code, stdout, stderr) = run(&["--check", "tests/fixtures/site/ship.ks"], None);
    assert_eq!(code, 0, "the site example is a fixed point: {stdout}{stderr}");
}

#[test]
fn fmt_walks_a_directory_for_ship_ks_files() {
    let d = Temp::dir("tree");
    std::fs::create_dir_all(d.join("api")).expect("create nested dir");
    std::fs::write(d.join("api/ship.ks"), MESSY).expect("write nested ship.ks");
    // Not a site file, so not the walk's business.
    std::fs::write(d.join("notes.txt"), "  hello  \n").expect("write notes");

    let (code, _, stderr) = run(&[d.str()], None);
    let formatted = std::fs::read_to_string(d.join("api/ship.ks")).expect("read back");
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(formatted, FORMATTED);
    assert_eq!(std::fs::read_to_string(d.join("notes.txt")).expect("read"), "  hello  \n");
}

#[test]
fn fmt_reads_stdin_and_writes_stdout() {
    let (code, stdout, stderr) = run(&["-"], Some(MESSY));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, FORMATTED);
}

#[test]
fn fmt_stdin_check_reports_a_diff() {
    let (code, stdout, stderr) = run(&["-", "--check"], Some(MESSY));
    assert_eq!(code, 1, "{stderr}");
    assert!(stdout.starts_with("--- <stdin>\n+++ <stdin>\n"), "{stdout}");
    assert!(stdout.contains("\n@@ -1,10 +1,8 @@\n"), "{stdout}");
    assert!(stdout.contains("-  build: oci.image\n"), "{stdout}");
    assert!(stdout.contains("+  build:   oci.image\n"), "{stdout}");
}

#[test]
fn fmt_stdin_echoes_an_already_canonical_source() {
    // `-` is a filter, so it has to pass the text through whether or not the
    // formatter changed anything. Returning early on "nothing to do" would
    // print nothing and silently empty `fmt - > ship.ks`.
    let (code, stdout, stderr) = run(&["-"], Some(CANONICAL));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, CANONICAL, "the canonical source must come back byte-for-byte");
    assert!(stderr.is_empty(), "{stderr}");
}

#[test]
fn fmt_stdin_check_is_silent_on_an_already_canonical_source() {
    let (code, stdout, stderr) = run(&["-", "--check"], Some(CANONICAL));
    assert_eq!(code, 0, "{stderr}");
    assert!(!stdout.contains("---"), "no diff for a canonical source: {stdout}");
    assert!(!stdout.contains("+++"), "no diff for a canonical source: {stdout}");
}

#[test]
fn fmt_stdin_echoes_the_formatted_text_of_a_short_canonical_input() {
    // The smallest canonical source there is, and the exact case that used to
    // print nothing at all.
    let src = "name: api\n";
    let (code, stdout, stderr) = run(&["-"], Some(src));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, src, "expected {src:?}, got {stdout:?}");
}

#[test]
fn fmt_refuses_a_file_that_does_not_parse_and_leaves_it_alone() {
    let f = Temp::file("broken.ks", BROKEN);
    let (code, stdout, stderr) = run(&[f.str()], None);
    assert_eq!(code, 1, "{stdout}");
    assert_eq!(f.read(), BROKEN, "a file that does not parse was rewritten");
    // Only the diagnostics, rendered as `check` renders them.
    assert!(stderr.contains(&format!("{}:2", f.path().display())), "{stderr}");
    assert!(stderr.contains("unclosed string"), "{stderr}");
    assert!(!stderr.contains("not formatted"), "no second, differently worded error: {stderr}");
}

#[test]
fn fmt_refuses_broken_stdin_too() {
    let (code, stdout, stderr) = run(&["-"], Some(BROKEN));
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("<stdin>:2"), "{stderr}");
}

#[test]
fn fmt_defaults_to_ship_ks_in_the_working_directory() {
    let d = Temp::dir("default");
    std::fs::write(d.join("ship.ks"), MESSY).expect("write ship.ks");
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("fmt")
        .current_dir(d.path())
        .output()
        .expect("run keepshipping");
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read_to_string(d.join("ship.ks")).expect("read"), FORMATTED);
}

#[test]
fn fmt_with_no_site_file_to_default_to_is_a_usage_error() {
    let d = Temp::dir("noship");
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("fmt")
        .current_dir(d.path())
        .output()
        .expect("run keepshipping");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("ship.ks"), "the default path is named: {stderr}");
}

#[test]
fn fmt_refuses_a_file_that_is_not_utf8_as_a_usage_error() {
    let f = Temp::file("binary.ks", "");
    std::fs::write(f.path(), [0x61u8, 0x3a, 0x20, 0xff, 0xfe, 0x0a]).expect("write bytes");
    let (code, _, stderr) = run(&[f.str()], None);
    assert_eq!(code, 2, "an unreadable file is a usage error, not a failure: {stderr}");
    assert!(stderr.contains("not valid UTF-8"), "{stderr}");
}

#[test]
fn fmt_rejects_usage_errors_with_exit_two() {
    for args in [
        vec!["--nope"],
        vec!["--all"],
        vec!["--format", "json"],
        vec!["-", "--secrets"],
        vec!["no/such/file.ks"],
    ] {
        let (code, _, stderr) = run(&args, None);
        assert_eq!(code, 2, "{args:?} should be a usage error, not {stderr}");
    }
}

#[test]
fn fmt_writes_nothing_when_a_tree_has_no_site_file() {
    let d = Temp::dir("empty");
    let (code, _, stderr) = run(&["--check", d.str()], None);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("no ship.ks under"), "{stderr}");
}

#[test]
fn fmt_accepts_several_paths_at_once() {
    let a = Temp::file("many-a.ks", MESSY);
    let b = Temp::file("many-b.ks", MESSY);
    let (code, _, stderr) = run(&[a.str(), b.str()], None);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(a.read(), b.read(), "the same input formatted to two different files");
    assert_eq!(a.read(), FORMATTED);
}

#[test]
fn fmt_takes_a_path_after_a_double_dash() {
    // A name that begins with a dash, given relative to its directory: the
    // one case a leading dash cannot be taken for a flag with.
    let d = Temp::dir("dashed");
    std::fs::write(d.join("-weird.ks"), MESSY).expect("write the oddly named file");
    let in_dir = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
            .arg("fmt")
            .args(args)
            .current_dir(d.path())
            .output()
            .expect("run keepshipping");
        (out.status.code().expect("exit code"), String::from_utf8_lossy(&out.stderr).into_owned())
    };

    let (code, stderr) = in_dir(&["-weird.ks"]);
    assert_eq!(code, 2, "without `--` it reads as an unknown flag: {stderr}");
    let (code, stderr) = in_dir(&["--", "-weird.ks"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(std::fs::read_to_string(d.join("-weird.ks")).expect("read"), FORMATTED);
}

/// The site's example file is a fixed point; a real run must not rewrite it.
#[test]
fn the_site_example_is_left_alone_by_a_real_fmt_run() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/site/ship.ks");
    let before = std::fs::read_to_string(&path).expect("read the example");
    assert_eq!(run(&[path.to_str().expect("a utf-8 path")], None).0, 0);
    assert_eq!(std::fs::read_to_string(&path).expect("read back"), before);
}
