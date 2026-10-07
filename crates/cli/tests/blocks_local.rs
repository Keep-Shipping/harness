//! `keepshipping check` finds the blocks in the `blocks/` directory beside the
//! file it checks, so a site written `deploy: web-service` is checked against
//! the definition in `blocks/web-service.ks` — the input it leaves out, and
//! the one of the wrong type, fail here rather than at run time
//! ([#80](https://github.com/Keep-Shipping/harness/issues/80)).

use std::path::{Path, PathBuf};
use std::process::Command;

const BLOCK: &str = "\
block: web-service
inputs:
  image:    oci.Digest
  domain:   string
  replicas: int = 2
";

const SITE: &str = "\
envs:
  prod:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: web-service
    image: build.digest
    domain: api.acme.dev
    replicas: 3
";

fn check_in(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .arg("check")
        .args(args)
        .current_dir(dir)
        // The ambient `CI` widens a "no format declared" warning these
        // fixtures are not about.
        .env_remove("CI")
        .output()
        .expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A site with `blocks/web-service.ks` beside it. The directory is removed
/// when the check is done.
fn site(name: &str, src: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("keepshipping-blocks-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("blocks")).expect("create temp dir");
    std::fs::write(dir.join("ship.ks"), src).expect("write the site file");
    std::fs::write(dir.join("blocks/web-service.ks"), BLOCK).expect("write the block file");
    dir
}

#[test]
fn a_use_that_matches_the_local_block_checks_clean() {
    let dir = site("clean", SITE);
    let (code, stdout, stderr) = check_in(&dir, &["--format", "json"]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 0, "{stdout}{stderr}");
}

#[test]
fn a_use_leaving_out_a_required_input_of_the_local_block_fails() {
    let missing = SITE.replace("    domain: api.acme.dev\n", "");
    let dir = site("missing", &missing);
    let (code, stdout, stderr) = check_in(&dir, &["--format", "json"]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 1, "{stdout}{stderr}");
    assert!(stdout.contains("\"code\":\"KS0206\""), "{stdout}");
    assert!(stdout.contains("`domain`"), "{stdout}");
}
