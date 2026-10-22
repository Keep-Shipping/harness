//! `keepshipping check --repro`: the Dockerfiles an `oci.image` step names
//! are read and scanned for inputs that can move between two builds. Without
//! the flag the check reads the site file alone, exactly as before.

use std::path::{Path, PathBuf};
use std::process::Command;

const SITE: &str = include_str!("fixtures/repro/ship.ks");

/// The fixture's own Dockerfile: an unpinned base image, an index read in
/// place, and bytes fetched over a URL nobody controls.
const DOCKERFILE: &str = include_str!("fixtures/repro/Dockerfile");

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

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/repro")
}

#[test]
fn repro_warns_on_every_moving_input() {
    let (code, out, _) = check_in(&fixture(), &["--repro"]);
    for finding in [
        "`FROM node:22.23.4` is not pinned to a digest",
        "`apt-get update` is not pinned to a snapshot",
        "`ADD https://example.com/tool.tar.gz` has no checksum",
    ] {
        assert!(out.contains(finding), "--repro must report {finding:?}, got:\n{out}");
    }
    assert!(out.contains("Dockerfile:3"), "the finding names the Dockerfile, got:\n{out}");
    assert!(
        out.contains(DOCKERFILE.lines().nth(2).unwrap()),
        "the snippet is the Dockerfile's own"
    );
    assert_eq!(code, 0, "a warning alone still passes the check");
}

#[test]
fn without_the_flag_the_dockerfile_is_never_read() {
    let (code, out, _) = check_in(&fixture(), &[]);
    assert!(!out.contains("KS0801"), "no reproducibility findings without --repro:\n{out}");
    assert!(!out.contains("Dockerfile"), "the Dockerfile is not read at all:\n{out}");
    assert_eq!(code, 0);
}

#[test]
fn warnings_as_errors_does_fail_on_a_repro_warning() {
    let (code, _, _) = check_in(&fixture(), &["--repro", "--warnings-as-errors"]);
    assert_eq!(code, 1, "KS0801 is a warning, and only `--warnings-as-errors` makes it fail");
}

#[test]
fn every_format_reports_the_dockerfile_as_its_own_file() {
    let (_, json, _) = check_in(&fixture(), &["--repro", "--format", "json"]);
    assert_eq!(json.lines().filter(|l| l.contains("\"code\":\"KS0801\"")).count(), 3);
    assert_eq!(json.lines().filter(|l| l.contains("\"file\":\"Dockerfile\"")).count(), 3);
    assert!(!json.contains("ship.ks"), "a clean site file contributes no JSON line");

    let (_, gh, _) = check_in(&fixture(), &["--repro", "--format", "github"]);
    assert_eq!(gh.lines().filter(|l| l.contains("title=KS0801")).count(), 3);
    assert!(gh.lines().all(|l| l.starts_with("::warning")), "KS0801 is a warning");
}

#[test]
fn a_pinned_dockerfile_is_silent() {
    let dir = std::env::temp_dir().join(format!("keepshipping-repro-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp site dir");
    std::fs::write(dir.join("ship.ks"), SITE).expect("write site file");
    std::fs::write(dir.join("Dockerfile"), PINNED).expect("write Dockerfile");

    let (code, out, _) = check_in(&dir, &["--repro"]);
    assert!(!out.contains("KS0801"), "a pinned Dockerfile has nothing to report:\n{out}");
    assert_eq!(code, 0);
}

#[test]
fn a_dockerfile_two_steps_build_is_reported_once() {
    let dir = std::env::temp_dir().join(format!("keepshipping-repro-twice-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp site dir");
    std::fs::write(
        dir.join("ship.ks"),
        concat!(
            "steps:\n  build: oci.image\n    from: ./Dockerfile\n",
            "  rebuild: oci.image\n    from: ./Dockerfile\n",
        ),
    )
    .expect("write site file");
    std::fs::write(dir.join("Dockerfile"), "FROM node:20\n").expect("write Dockerfile");

    let (_, out, _) = check_in(&dir, &["--repro"]);
    assert_eq!(
        out.matches("is not pinned to a digest").count(),
        1,
        "one Dockerfile, one report:\n{out}"
    );
}

/// Every input pinned: a digest, a snapshot host, a checksum.
const PINNED: &str = concat!(
    "FROM node:20@sha256:1a79a4d60de6718e8e5b326e338ae533b95b6e5b4c7d0b6a9b0e3e6b6c5d4e3f2\n",
    "RUN sed -i s/deb.debian.org/snapshot.debian.org/ /etc/apt/sources.list \\\n",
    " && apt-get update && apt-get install -y --no-install-recommends curl\n",
    "ADD --checksum=sha256:5f1a2b3c4d5e6f708192a3b4c5d6e7f \\\n",
    "    https://example.com/tool.tar.gz /usr/local/bin/tool\n",
);

#[test]
fn a_dockerfile_that_cannot_be_read_is_reported_against_its_from() {
    let dir =
        std::env::temp_dir().join(format!("keepshipping-repro-missing-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp site dir");
    std::fs::write(dir.join("ship.ks"), SITE).expect("write site file");

    let (code, out, _) = check_in(&dir, &["--repro"]);
    // The finding lands on the site file, at the `from:` that names a file
    // nobody can scan: silence there would read as "reproducible".
    assert!(out.contains("`./Dockerfile` cannot be read"), "got:\n{out}");
    assert!(out.contains("ship.ks:4"), "reported against the site file, got:\n{out}");
    assert_eq!(code, 0, "an unreadable Dockerfile is a warning, not a failure");
}
