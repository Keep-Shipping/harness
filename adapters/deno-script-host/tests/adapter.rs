//! Service-free tests of the Deno adapter: the argv the sandbox is made of,
//! the installer, the secret framing, and the refusals that must happen
//! *before* a process is ever started. None of these spawns Deno or opens a
//! socket, so `cargo test --workspace` stays offline.
//!
//! The same crate runs its [`ScriptHost`] conformance kit — and the
//! sandbox acceptance tests — against real Deno in `conformance.rs`.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use ks_core::ports::secrets::{SecretBundle, SecretValue};
use ks_deno_script_host::channel::{decode, frames};
use ks_deno_script_host::{Invocation, Manifest, Mode};

/// The gate on every test below that builds a `DenoScriptHost`:
/// `DenoScriptHost::new` refuses anything but linux-x86_64 as its first
/// statement — ADR 0009 records no verified secret pipe elsewhere — so off that
/// platform such a test asserts the platform check, or panics on an `expect`,
/// rather than the refusal it is named for. It is *gating*, not `#[ignore]`:
/// `cargo test --workspace` on Linux still runs every one of them.
///
/// The three imports below carry the same gate for the same reason: off that
/// platform nothing names them, and an unused import is a warning, and warnings
/// are errors in this repository.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use ks_core::ports::script_host::{ScriptHost, ScriptHostError, ScriptRef};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use ks_deno_script_host::DenoScriptHost;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::sync::Arc;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const WORKSPACE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const BOOTSTRAP: &str = "/cache/host/bootstrap.ts";
const FIFO: &str = "/run/secrets";

/// An invocation with everything named, so each assertion is about one thing.
fn invocation(net: &[&str], manifest: Manifest, mode: Mode) -> Invocation {
    Invocation {
        bootstrap: BOOTSTRAP.into(),
        script: "/workspace/scripts/deploy.ts".into(),
        mode,
        read_grants: vec![
            PathBuf::from("/workspace"),
            PathBuf::from("/cache/host"),
            PathBuf::from(FIFO),
        ],
        deny_read: Vec::new(),
        net_grants: net.iter().map(|host| host.to_string()).collect(),
        manifest,
        secrets: (mode == Mode::Run).then(|| PathBuf::from(FIFO)),
    }
}

/// The argv as plain strings, for assertions a person can read.
fn argv_of(invocation: &Invocation) -> Vec<String> {
    invocation.argv().iter().map(|argument| argument.to_string_lossy().into_owned()).collect()
}

#[test]
fn the_argv_grants_only_the_sandbox_the_adapter_means_to_grant() {
    let argv = argv_of(&invocation(&[], Manifest::None, Mode::Run));
    for forbidden in [
        "--allow-all",
        "--allow-env",
        "--allow-write",
        "--allow-run",
        "--allow-ffi",
        "--allow-sys",
        "--allow-net",
        "--allow-npm",
        "--allow-import",
        "--permission-set",
        "-A",
        "-R",
        "-W",
        "-N",
        "-E",
    ] {
        assert!(
            !argv.iter().any(|argument| argument == forbidden),
            "{forbidden} must not be in {argv:?}"
        );
    }
    // Read is exactly the three named paths, in one `=` argument: Deno's
    // `--allow-read` is variadic, so a separate value would swallow the module
    // path that follows it.
    assert!(
        argv.iter()
            .any(|argument| argument == &format!("--allow-read=/workspace,/cache/host,{FIFO}")),
        "{argv:?}"
    );
    assert!(!argv.iter().any(|argument| argument == "--allow-read"), "{argv:?}");
    // With nothing to deny there is no `--deny-read` at all: it is a grant, so
    // emitting an empty one would be a shape Deno has no documented answer for.
    assert!(!argv.iter().any(|argument| argument.starts_with("--deny-read")), "{argv:?}");
    assert!(argv.iter().any(|argument| argument.starts_with("--seed=")), "{argv:?}");
    assert!(argv.iter().any(|argument| argument == "--no-prompt"), "{argv:?}");
    assert!(argv.iter().any(|argument| argument == "--quiet"), "{argv:?}");
    // Trailing: the bootstrap, the mode, the script, then the FIFO.
    assert_eq!(
        argv[argv.len() - 4..],
        [
            BOOTSTRAP.to_string(),
            "run".to_string(),
            "/workspace/scripts/deploy.ts".to_string(),
            FIFO.to_string(),
        ]
    );
}

#[test]
fn net_is_granted_only_when_a_step_declared_it() {
    let quiet = argv_of(&invocation(&[], Manifest::None, Mode::Describe));
    assert!(!quiet.iter().any(|argument| argument.contains("net")), "{quiet:?}");
    assert!(!quiet.iter().any(|argument| argument == FIFO), "describe reads no secrets");

    let granted =
        argv_of(&invocation(&["api.example:443", "127.0.0.1:8080"], Manifest::None, Mode::Run));
    assert!(
        granted.iter().any(|argument| argument == "--allow-net=api.example:443,127.0.0.1:8080"),
        "{granted:?}"
    );
}

#[test]
fn an_unlocked_script_may_not_reach_out_at_all() {
    let argv = argv_of(&invocation(&[], Manifest::None, Mode::Run));
    for flag in ["--no-config", "--no-lock", "--no-remote", "--no-npm"] {
        assert!(argv.iter().any(|argument| argument == flag), "{flag} must be in {argv:?}");
    }
}

#[test]
fn a_manifest_means_a_lockfile_and_a_frozen_run() {
    let argv = argv_of(&invocation(
        &[],
        Manifest::Locked {
            config: Some("/workspace/scripts/deno.json".into()),
            lock: "/workspace/scripts/deno.lock".into(),
        },
        Mode::Run,
    ));
    assert!(argv.iter().any(|argument| argument == "--frozen-lockfile"), "{argv:?}");
    assert!(
        argv.iter().any(|argument| argument == "--lock=/workspace/scripts/deno.lock"),
        "{argv:?}"
    );
    assert!(argv.iter().any(|argument| argument == "--config"), "{argv:?}");
    assert!(argv.iter().any(|argument| argument == "/workspace/scripts/deno.json"), "{argv:?}");
    // A locked step is not a sealed one: --no-config would ignore the config
    // it just locked against.
    for flag in ["--no-config", "--no-lock"] {
        assert!(!argv.iter().any(|argument| argument == flag), "{flag} must not be in {argv:?}");
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn a_manifest_beside_a_step_without_a_lockfile_is_refused_before_anything_starts() {
    let workspace = scratch("unlocked");
    std::fs::write(workspace.join("deno.json"), "{}").expect("the manifest is writable");
    step(&workspace);
    let host = DenoScriptHost::new(&workspace).expect("a workspace root");
    let error = ks_testing::block_on(host.schema(&ScriptRef::new("step.ts")))
        .expect_err("an unlocked step is not runnable");
    assert!(error.to_string().contains("deno.lock"), "{error}");
    assert!(matches!(error, ScriptHostError::Protocol { .. }), "{error}");
    let _ = std::fs::remove_dir_all(&workspace);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn a_step_outside_the_workspace_is_refused() {
    let root = scratch("roots");
    let workspace = root.join("inside");
    let outside = root.join("outside");
    std::fs::create_dir_all(&workspace).expect("the workspace is writable");
    std::fs::create_dir_all(&outside).expect("the outside is writable");
    std::fs::write(outside.join("escape.ts"), "export default {};")
        .expect("the script is writable");
    let host = DenoScriptHost::new(&workspace).expect("a workspace root");
    let error = ks_testing::block_on(host.schema(&ScriptRef::new("../outside/escape.ts")))
        .expect_err("a step is something the repository ships, not something outside it");
    assert!(error.to_string().contains("outside the workspace"), "{error}");
    let _ = std::fs::remove_dir_all(&root);
}

// Gated for a second reason as well: off linux-x86_64 the constructor refuses
// the *platform* before it ever looks at the path, so this would be a green
// assertion about the platform rather than about the missing directory it is
// named for.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn a_workspace_that_does_not_exist_is_not_a_workspace() {
    let error =
        DenoScriptHost::new("/definitely/not/a/directory").expect_err("there is no such workspace");
    assert!(matches!(error, ScriptHostError::Protocol { .. }), "{error}");
}

#[test]
fn secrets_travel_as_length_prefixed_frames_and_a_terminator() {
    let mut bundle = SecretBundle::new();
    bundle.insert("conformance-token", SecretValue::new(b"hunter2".to_vec()));
    bundle.insert("empty", SecretValue::new(Vec::new()));
    let wire = frames(&bundle);
    let mut expected = Vec::new();
    expected.extend_from_slice(&17u32.to_be_bytes());
    expected.extend_from_slice(b"conformance-token");
    expected.extend_from_slice(&7u32.to_be_bytes());
    expected.extend_from_slice(b"hunter2");
    expected.extend_from_slice(&5u32.to_be_bytes());
    expected.extend_from_slice(b"empty");
    expected.extend_from_slice(&0u32.to_be_bytes());
    expected.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(wire, expected);
    let decoded = decode(&wire).expect("a well-formed wire decodes");
    assert_eq!(decoded["conformance-token"], b"hunter2".to_vec());
    assert_eq!(decoded["empty"], Vec::<u8>::new());
    assert!(!decoded.contains_key(""), "the terminator is not a secret");
}

#[test]
fn the_secret_pipe_is_a_named_fifo_the_step_can_only_read() {
    let mut bundle = SecretBundle::new();
    bundle.insert("token", SecretValue::new(b"hunter2".to_vec()));
    let channel =
        ks_deno_script_host::channel::SecretChannel::open(&bundle).expect("a private FIFO");
    let path = channel.path().to_path_buf();
    assert!(path.is_file() || path.exists());
    let kind = std::fs::symlink_metadata(&path).expect("the FIFO is there");
    assert!(
        std::os::unix::fs::FileTypeExt::is_fifo(&kind.file_type()),
        "{} must be a FIFO, not a regular file: a regular file would put the secrets on disk",
        path.display()
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&path).expect("the FIFO is there").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    // The frames are on their own thread, not in the parent's hands at this
    // point: `open` spawns the filler and returns, because a pipe holds 64 KiB
    // and writing a larger bundle before the child existed would block with
    // nothing on this side able to notice. What the parent still holds is the
    // `O_RDWR` handle, so the child's `open(O_RDONLY)` never blocks and never
    // has to rely on an EOF it may never get. A reader reads exactly the wire
    // and then waits, which is why the wire ends on a terminator frame.
    let mut bundle = SecretBundle::new();
    bundle.insert("token", SecretValue::new(b"hunter2".to_vec()));
    let mut reader = std::fs::OpenOptions::new().read(true).open(&path).expect("readable");
    let mut seen = vec![0; frames(&bundle).len()];
    reader.read_exact(&mut seen).expect("readable");
    assert_eq!(seen, frames(&bundle), "the frames are on the wire as framed");
    drop(reader);
    drop(channel);
    assert!(!Path::new(&path).exists(), "the pipe is gone with the channel");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn a_fetcher_can_be_injected_so_installation_needs_no_network() {
    // The adapter's default transport is `curl`; a test (or an air-gapped
    // machine) hands its own in.
    let mut asked = Vec::new();
    struct Recorder(Arc<std::sync::Mutex<Vec<String>>>);
    impl ks_deno_script_host::Fetcher for Recorder {
        fn fetch(&self, url: &str) -> std::io::Result<Vec<u8>> {
            self.0.lock().expect("the recorder").push(url.to_string());
            Err(std::io::Error::other("nothing to fetch"))
        }
    }
    let seen = Arc::new(std::sync::Mutex::new(asked.split_off(0)));
    let workspace = scratch("fetcher");
    step(&workspace);
    let host = DenoScriptHost::new(&workspace)
        .expect("a workspace root")
        .with_cache_root(scratch("cache"))
        .with_fetcher(Arc::new(Recorder(Arc::clone(&seen))));
    let error = ks_testing::block_on(host.schema(&ScriptRef::new("step.ts")))
        .expect_err("nothing to install from");
    assert!(error.to_string().contains("pre-seed"), "{error}");
    let asked = seen.lock().expect("the recorder").clone();
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert!(asked[0].starts_with("https://dl.deno.land/release/v"), "{asked:?}");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn a_step_with_no_default_export_fails_as_a_script_failure_not_a_crash() {
    // Nothing is spawned here: the host is unbuildable without a Deno, and the
    // refusal is the port's own. What this pins is that the host answers with
    // a `ScriptHostError` rather than a panic.
    let host = DenoScriptHost::new(WORKSPACE).expect("a workspace root");
    let result = ks_testing::block_on(host.schema(&ScriptRef::new("no-such-step.ts")));
    assert!(result.is_err());
    assert!(
        matches!(&result, Err(ScriptHostError::Protocol { message }) if message.contains("no-such-step.ts")),
        "{result:?}"
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn a_link_out_of_the_workspace_is_denied_in_the_argv_rather_than_refused() {
    // What the old scan got fatally wrong: `.venv/bin/python3 -> /usr/bin/python3`,
    // a pnpm store behind `node_modules/.bin`, and the dangling `.bin` entries a
    // half-finished `npm install` leaves are all links that leave the workspace,
    // and refusing the run over any of them is refusing to run the repository.
    // Deno applies `--deny-read` over `--allow-read`, so the step runs with the
    // path refused — which is the property that was worth having.
    //
    // Offline, because `Invocation` is the whole sandbox and `argv` is a pure
    // function of it: nothing here spawns Deno.
    let workspace = scratch("escape");
    let outside = scratch("escape-outside");
    step(&workspace);
    std::fs::write(outside.join("id_ed25519"), "PRIVATE KEY").expect("the fake key is writable");
    let keys = workspace.join("keys");
    std::fs::create_dir_all(&keys).expect("the key directory is writable");
    let escaping = keys.join("id_ed25519");
    std::os::unix::fs::symlink(outside.join("id_ed25519"), &escaping)
        .expect("the link is writable");
    // The other half: a link that stays inside is not a deny grant, and the
    // refusal above must not be passing merely because the workspace has links.
    std::fs::write(workspace.join("real.txt"), "in the workspace").expect("writable");
    std::os::unix::fs::symlink(workspace.join("real.txt"), workspace.join("alias.txt"))
        .expect("the link is writable");

    let host = DenoScriptHost::new(&workspace)
        .expect("a workspace root")
        .with_cache_root(scratch("escape-cache"));
    let argv = argv_of(
        &host
            .invocation(&ScriptRef::new("step.ts"), Mode::Describe, None, &[])
            .expect("a described invocation"),
    );
    let deny = argv
        .iter()
        .find(|argument| argument.starts_with("--deny-read="))
        .unwrap_or_else(|| panic!("the escaping link is denied in the argv: {argv:?}"));
    assert_eq!(deny, &format!("--deny-read={}", escaping.display()), "{argv:?}");
    assert!(
        !deny.contains("alias.txt") && !deny.contains("real.txt"),
        "a link that stays inside is not an escape: {deny}"
    );
    assert!(
        argv.iter().any(|argument| argument
            .starts_with(&format!("--allow-read={},", workspace.display()))),
        "the workspace is still granted: the point is that one path inside it is not readable"
    );

    // And the converse, on a workspace with only inward links: no deny grant at
    // all, so the ordinary case costs nothing on the command line.
    let inward = scratch("inward");
    step(&inward);
    std::fs::write(inward.join("real.txt"), "in the workspace").expect("writable");
    std::os::unix::fs::symlink(inward.join("real.txt"), inward.join("alias.txt"))
        .expect("the link is writable");
    let host = DenoScriptHost::new(&inward)
        .expect("a workspace root")
        .with_cache_root(scratch("inward-cache"));
    let argv = argv_of(
        &host
            .invocation(&ScriptRef::new("step.ts"), Mode::Describe, None, &[])
            .expect("a described invocation"),
    );
    assert!(
        !argv.iter().any(|argument| argument.contains("--deny-read")),
        "nothing leaves the workspace, so nothing is denied: {argv:?}"
    );

    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&outside);
    let _ = std::fs::remove_dir_all(&inward);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn the_host_is_dyn_compatible_and_says_which_platform_it_is_on() {
    fn assert_dyn<T: ?Sized + Send + Sync>() {}
    assert_dyn::<dyn ScriptHost>();
    let host = DenoScriptHost::new(WORKSPACE).expect("a workspace root");
    assert_eq!(host.platform(), std::env::consts::ARCH);
    assert_eq!(host.workspace(), std::fs::canonicalize(WORKSPACE).expect("the fixtures resolve"));
    assert!(format!("{host:?}").contains("DenoScriptHost"));
}

/// A scratch directory, emptied on the way in.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ks-deno-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("the scratch directory is writable");
    path.canonicalize().expect("the scratch directory resolves")
}

/// The smallest step there is. These tests never run it — they are about what
/// the adapter refuses, and a refusal about a file that does not exist would be
/// about the wrong thing.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn step(workspace: &Path) {
    std::fs::write(workspace.join("step.ts"), "export default {};").expect("the step is writable");
}
