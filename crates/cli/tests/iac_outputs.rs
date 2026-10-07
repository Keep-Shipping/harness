//! `keepshipping check` reads the `.tf` files behind a `tofu.plan`'s `dir:`,
//! so `apply.out.<name>` is typed — and a name the IaC does not declare is
//! an error here, at check time, not a surprise at run time
//! ([#70](https://github.com/Keep-Shipping/harness/issues/70)).

use std::path::{Path, PathBuf};
use std::process::Command;

const HERO: &str = include_str!("fixtures/hero/ship.ks");
const MAIN_TF: &str = include_str!("fixtures/hero/infra/prod/main.tf");

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

fn hero() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hero")
}

/// A site beside the same `.tf` files, with `ship.ks` spelled as `site`. The
/// `infra/prod` directory is copied whole, so the site under test reads real
/// Terraform; the directory is removed when the check is done.
fn variant(name: &str, site: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keepshipping-iac-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("infra/prod")).expect("create temp dir");
    std::fs::write(dir.join("ship.ks"), site).expect("write the site file");
    std::fs::write(dir.join("infra/prod/main.tf"), MAIN_TF).expect("write the .tf files");
    dir
}

#[test]
fn the_hero_file_checks_clean_against_its_own_terraform() {
    let (code, stdout, stderr) = check_in(&hero(), &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("✓ ship.ks"), "{stdout}");
}

#[test]
fn an_output_the_terraform_does_not_declare_fails_the_check() {
    let dir = variant("typo", &HERO.replace("apply.out.cluster", "apply.out.clsuter"));
    let (json, out, _) = check_in(&dir, &["--format", "json"]);
    let (code, human, _) = check_in(&dir, &[]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(json, 1, "{out}");
    assert!(out.contains("\"code\":\"KS0203\""), "{out}");
    assert!(out.contains("produces no output `clsuter`"), "{out}");
    assert_eq!(code, 1, "{human}");
    // The hint names the directory it read and the outputs it declares.
    let flat = human.lines().map(str::trim).collect::<Vec<_>>().join(" ");
    assert!(flat.contains("hint: `./infra/prod` declares `cluster`, `region`"), "{human}");
    assert!(flat.contains("did you mean `cluster`?"), "{human}");
}

#[test]
fn a_terraform_output_of_another_type_is_a_type_error() {
    // `region` is declared `string` in the `.tf`, so it cannot be a cluster.
    let dir = variant("mismatch", &HERO.replace("apply.out.cluster", "apply.out.region"));
    let (code, stdout, _) = check_in(&dir, &[]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.contains("expected k8s.Cluster, got string"), "{stdout}");
}

#[test]
fn an_unreadable_directory_leaves_the_outputs_unchecked() {
    // No `infra/prod` beside this site: nothing to read, so nothing is said
    // about the name — the file checks like it did before.
    let dir = variant("nodir", &HERO.replace("dir:   ./infra/prod", "dir:   ./infra/nowhere"));
    let (code, stdout, stderr) = check_in(&dir, &[]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 0, "{stdout}{stderr}");
}

#[test]
fn the_step_may_name_the_output_types_itself() {
    // The `outputs:` mapping on the apply step wins over the directory, and
    // applies where there is no directory at all.
    let site = HERO.replace(
        "    plan:  plan.file        # the exact plan you approved\n",
        "    plan:  plan.file        # the exact plan you approved\n    outputs:\n      cluster: k8s.Cluster\n",
    );
    let site = site.replace("dir:   ./infra/prod", "dir:   ./infra/nowhere");
    let dir = variant("mapping", &site);
    let (code, stdout, stderr) = check_in(&dir, &[]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 0, "{stdout}{stderr}");

    // And a type that is not a type is a type error, named where it is
    // spelled.
    let bad = site.replace("cluster: k8s.Cluster", "cluster: k8s Cluster");
    let dir = variant("badtype", &bad);
    let (code, stdout, _) = check_in(&dir, &[]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.contains("an output's type is a single name"), "{stdout}");
}
