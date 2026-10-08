//! What `--as` does to a real run: a declared actor is enforced at check
//! time, and an unrecognised spelling is a usage error. Nothing here asserts
//! the run ships — no step is executable yet — only what each actor may start.

use std::path::Path;
use std::process::{Command, Stdio};

use ks_core::ports::run_context::{AGENT_TYPICAL_ENV, KNOWN_AGENT_MARKERS};

/// A site whose policy forbids agents from reading the secret its step needs:
/// an agent run is refused before anything starts.
const GATED: &str = "\
name: gated
envs:
  prod:
    ci-only: true
steps:
  migrate: db.migrate
    url: secrets.db_url
policy:
  agents:
    never: read secrets
";
/// What the gated policy prints when it refuses a run.
const REFUSED: &str = "policy forbids agents from reading secrets";

/// Runs the binary against a site file, with the environment scrubbed of
/// everything that would make a bare invocation look agent-shaped — `CI`, the
/// agent markers, and the agent-typical variables a CI shell or an editor
/// leaves behind. What is left is a plain laptop, so each case says which
/// actor it means rather than inheriting the machine's.
fn run(args: &[&str], vars: &[(&str, &str)]) -> (i32, String, String) {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("as-agent.ks");
    std::fs::write(&path, GATED).expect("write temp site file");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(args).env_remove("CI").env_remove("GITHUB_ACTIONS");
    for marker in KNOWN_AGENT_MARKERS {
        cmd.env_remove(marker);
    }
    for (name, _) in AGENT_TYPICAL_ENV {
        cmd.env_remove(*name);
    }
    for (name, value) in vars {
        cmd.env(name, value);
    }
    // A `y` on stdin: a run must not be let in by answering its own prompt.
    cmd.arg(path.to_str().expect("site path")).stdin(Stdio::piped());
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn keepshipping");
    use std::io::Write as _;
    child.stdin.take().expect("piped stdin").write_all(b"y\n").expect("write stdin");
    let out = child.wait_with_output().expect("run keepshipping");
    let _ = std::fs::remove_file(&path);
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn what_the_run_is_decides_what_the_policy_lets_through() {
    // (args after `run`, extra env, does the policy refuse it?)
    let cases = [
        (vec!["--as", "agent:claude"], vec![], true),
        (vec!["--as", "human"], vec![], false),
        // A marker binds the same policy with no flag at all.
        (vec![], vec![("CLAUDECODE", "1")], true),
    ];
    for (args, vars, refused) in cases {
        let argv: Vec<&str> = ["run"].into_iter().chain(args.iter().copied()).collect();
        let (code, stdout, stderr) = run(&argv, &vars);
        assert!(stderr.is_empty(), "{stderr}");
        assert_ne!(code, 0, "{stdout}");
        assert_eq!(stdout.contains(REFUSED), refused, "{stdout}");
        // The refused runs say so; the rest start and fail on the step.
        assert_eq!(stdout.contains("environment: prod"), !refused, "{stdout}");
    }

    // An unrecognised spelling never reaches the run at all.
    let (code, stdout, stderr) = run(&["run", "--as", "bogus"], &[]);
    assert_eq!(code, 2, "a usage error, not a run");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("--as human|agent[:name]|ci"), "{stderr}");
}
