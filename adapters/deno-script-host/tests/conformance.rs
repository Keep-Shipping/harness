//! The Deno adapter against a **real** Deno: the `ScriptHost` conformance kit,
//! the secrets channel, the sandbox's refusals, and the determinism the pin
//! exists for ([ADR 0009](../../docs/adr/0009-typescript-escape-hatch-runtime.md)).
//!
//! `KS_DENO_CONFORMANCE=1` runs them; unset — the case in
//! `cargo test --workspace` — they print that they were skipped and return, so
//! the ordinary test run stays offline and service-free. They are Linux-x86_64
//! only, for the reasons in the ADR.
//!
//! The Deno is downloaded into the cache the library itself defaults to —
//! `$XDG_CACHE_HOME/keepshipping/deno`, or `$HOME/.cache/keepshipping/deno` —
//! verified against the compiled-in digest, and reused. See [`host`].

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ks_core::ports::script_host::{
    ScriptHost, ScriptHostError, ScriptRef, Value, ValueType, Values,
};
use ks_core::ports::secrets::{Redactor, SecretBundle, SecretValue};
use ks_core::step::{LogLevel, LogSink, StepLog};
use ks_deno_script_host::{DENO_VERSION, DenoScriptHost};
use ks_testing::block_on;
use ks_testing::script_host::conformance;
use ks_testing::step::RecordingSink;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// A step logger that redacts nothing and keeps nothing, for runs whose log
/// lines are not under test.
fn quiet() -> StepLog {
    StepLog::new("conformance.script", Arc::new(Redactor::new()), Arc::new(RecordingSink::new()))
}

/// Whether these tests should run at all, and why not when they should not.
fn skip(reason: &str) {
    println!("skipping the Deno conformance run: {reason}");
}

#[test]
fn the_script_host_conformance_kit_passes_on_real_deno() {
    if !gated() {
        return;
    }
    let host = host(Path::new(FIXTURES));
    println!("running the ScriptHost conformance kit on Deno {DENO_VERSION}");
    block_on(conformance(&host, |fixture| {
        ScriptRef::new(format!("{FIXTURES}/{}.ts", fixture.name))
    }));
}

#[test]
fn secrets_arrive_on_their_channel_and_never_reach_a_log() {
    if !gated() {
        return;
    }
    let workspace = workspace("secrets");
    write(
        &workspace,
        "step.ts",
        r#"export default {
  inputs: {},
  outputs: { token: "string", length: "number" },
  async run(_inputs: Record<string, unknown>, ctx: any) {
    const token = ctx.secrets.get("conformance-token") ?? "";
    ctx.log("info", "using token " + token);
    return { token, length: token.length };
  },
};
"#,
    );
    let host = host(&workspace);
    let mut secrets = SecretBundle::new();
    secrets.insert("conformance-token", SecretValue::new(b"hunter2".to_vec()));
    // The step's own logger, redacting with the run's redactor: the adapter has
    // no redaction of its own, so this is the only thing between a line and
    // the sink.
    let mut redactor = Redactor::new();
    redactor.register(&SecretValue::new(b"hunter2".to_vec()));
    let sink = Arc::new(RecordingSink::new());
    let log = StepLog::new("app.step", Arc::new(redactor), Arc::clone(&sink) as Arc<dyn LogSink>);
    let outputs = block_on(host.run(&ScriptRef::new("step.ts"), &Values::new(), &secrets, &log))
        .expect("the step runs with its secret");

    assert_eq!(outputs["token"], Value::from("hunter2"), "the value reached the step intact");
    assert_eq!(outputs["length"], Value::Number(7.0));
    let logged = sink.records();
    assert_eq!(logged.len(), 1, "the step logged once: {logged:?}");
    assert_eq!(logged[0].level, LogLevel::Info);
    assert!(!logged[0].message.contains("hunter2"), "the log sink must not see a secret");
    assert!(
        logged[0].message.contains("***"),
        "the secret is redacted in the log: {}",
        logged[0].message
    );
}

#[test]
fn a_step_cannot_read_outside_the_workspace_or_the_environment() {
    if !gated() {
        return;
    }
    let root = workspace("escape");
    let home = workspace("escape-home");
    let key = home.join(".ssh").join("id_ed25519");
    std::fs::create_dir_all(key.parent().expect(".ssh")).expect("the fake home is writable");
    std::fs::write(&key, "PRIVATE KEY").expect("the fake key is writable");

    write(
        &root,
        "escape.ts",
        r#"export default {
  inputs: { what: "string", path: "string" },
  outputs: { read: "string" },
  async run(inputs: Record<string, any>) {
    // No try/catch: the permission error *is* the result under test, and the
    // bootstrap turns it into a nonzero exit with the message on stderr.
    if (inputs.what === "env") return { read: Deno.env.get("HOME") ?? "" };
    return { read: Deno.readTextFileSync(inputs.path as string) };
  },
};
"#,
    );
    let host = host(&root);
    let script = ScriptRef::new("escape.ts");

    for (what, path) in [("file", key.display().to_string()), ("env", String::new())] {
        let inputs: Values =
            [("what".to_string(), Value::from(what)), ("path".to_string(), Value::from(path))]
                .into_iter()
                .collect();
        let error = block_on(host.run(&script, &inputs, &SecretBundle::new(), &quiet()))
            .expect_err("the sandbox refuses both");
        let message = error.to_string();
        assert!(matches!(error, ScriptHostError::ScriptFailed { .. }), "{what}: {message}");
        assert!(message.contains("NotCapable"), "{what}: {message}");
        assert!(
            message.contains("--allow-read") || message.contains("--allow-env"),
            "{what}: {message}"
        );
    }
}

#[test]
fn a_symlink_out_of_the_workspace_is_denied_though_deno_would_allow_it() {
    if !gated() {
        return;
    }
    // The hole the direct-path test above cannot see. Deno checks
    // `--allow-read=<workspace>` against the path a step *names*, not the file
    // behind it, so `readTextFileSync("keys/id_ed25519")` is permitted even
    // though it reads a file outside the workspace. A refusal that only ever
    // sees `/etc/shadow` spelled out in full does not cover this.
    let root = workspace("symlink-escape");
    let outside = workspace("symlink-escape-outside");
    let key = outside.join("id_ed25519");
    std::fs::write(&key, "PRIVATE KEY").expect("the fake key is writable");

    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).expect("the key directory is writable");
    let link = keys.join("id_ed25519");
    std::os::unix::fs::symlink(&key, &link).expect("the link is writable");

    write(
        &root,
        "through-the-link.ts",
        r#"export default {
  inputs: {},
  outputs: { read: "string" },
  async run() {
    // A path inside the workspace, by every measure Deno checks.
    return { read: Deno.readTextFileSync("keys/id_ed25519") };
  },
};
"#,
    );
    let host = host(&root);
    let error = block_on(host.run(
        &ScriptRef::new("through-the-link.ts"),
        &Values::new(),
        &SecretBundle::new(),
        &quiet(),
    ))
    .expect_err("a link out of the workspace is denied");

    // The step *starts* and the step *runs*: that is the half the old scan got
    // wrong, since a stock `.venv` or a pnpm-linked `node_modules` has links
    // that escape too and the repository still has to run. What stops the read
    // is the grant, not the adapter — so the refusal is Deno's `NotCapable`
    // from inside the child, naming the link, and never the file behind it.
    let message = error.to_string();
    assert!(
        matches!(error, ScriptHostError::ScriptFailed { exit_code: Some(1), .. }),
        "the denial is Deno's, mid-step, not the adapter's before any child: {message}"
    );
    assert!(message.contains("NotCapable"), "{message}");
    assert!(message.contains("keys/id_ed25519"), "the refusal names the offending link: {message}");
    assert!(
        !message.contains("PRIVATE KEY"),
        "and never echoes what the link pointed at: {message}"
    );
}

#[test]
fn a_symlink_that_stays_inside_the_workspace_still_runs() {
    if !gated() {
        return;
    }
    // The other half, and the reason the test above is worth having: the
    // control must be about where a link *points*, not about links. Denying
    // every symlink would make the denial above pass for entirely the wrong
    // reason — and would break every repository with a `.venv` in it.
    let workspace = workspace("symlink-inward");
    std::fs::write(workspace.join("real.txt"), "in the workspace").expect("the target is writable");
    std::os::unix::fs::symlink(workspace.join("real.txt"), workspace.join("alias.txt"))
        .expect("the link is writable");

    write(
        &workspace,
        "through-the-link.ts",
        r#"export default {
  inputs: {},
  outputs: { read: "string" },
  async run() {
    return { read: Deno.readTextFileSync("alias.txt") };
  },
};
"#,
    );
    let host = host(&workspace);
    let outputs = block_on(host.run(
        &ScriptRef::new("through-the-link.ts"),
        &Values::new(),
        &SecretBundle::new(),
        &quiet(),
    ))
    .expect("a link within the workspace is not an escape");
    assert_eq!(
        outputs["read"],
        Value::from("in the workspace"),
        "the step read through the link and the adapter let it"
    );
}

#[test]
fn net_reaches_only_a_host_the_step_declared_and_the_operator_allowed() {
    if !gated() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = listener.local_addr().expect("its address").port();
    // The listener exists for the permitted run, and answers the one connection
    // that run makes — so the `pong` below is a socket a real Deno child was
    // permitted to open, not a stubbed response.
    //
    // It deliberately does *not* also count connections. A watch would read
    // stronger than it is: the refused run is stopped in `invocation()` before
    // any child of it exists, and the third run asks for `example.invalid`,
    // which cannot reach a loopback port whatever it is granted. So "exactly one
    // connection" cannot fail while the two error assertions below hold, and an
    // assertion that cannot fail is not evidence. The refusals are evidenced by
    // what they are instead — a `Protocol` error raised where no child has been
    // started, and a `NotCapable` from inside the one that did.
    let answer = std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else { return };
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request);
        let body = "pong";
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
    });

    let workspace = workspace("net");
    // Egress has two halves — the operator's allowlist and the step's own `net`
    // export — and the two steps below take them apart. Both *declare* the
    // loopback, so the operator's answer to that declaration is the same for
    // both; the difference is what the step then reaches for.
    let fetch_step = |fetched: &str| {
        format!(
            r#"export default {{
  inputs: {{}},
  outputs: {{ body: "string" }},
  net: ["127.0.0.1:{port}"],
  async run() {{
    const response = await fetch("{fetched}");
    return {{ body: await response.text() }};
  }},
}};
"#
        )
    };
    write(&workspace, "declared.ts", &fetch_step(&format!("http://127.0.0.1:{port}/")));
    write(&workspace, "undeclared.ts", &fetch_step("http://example.invalid/"));

    let run = |host: &DenoScriptHost, name: &str| {
        block_on(host.run(&ScriptRef::new(name), &Values::new(), &SecretBundle::new(), &quiet()))
    };

    // The permitted half: declared by the step and permitted by the operator.
    let allowed = host(&workspace).with_net_allowlist([format!("127.0.0.1:{port}")]);
    let declared = run(&allowed, "declared.ts").expect("a declared, allowed host is reachable");
    assert_eq!(declared["body"], Value::from("pong"));

    // The refused half: the same step, the same declaration, an operator who
    // granted no egress. The refusal is the adapter's own, and it is raised in
    // `invocation()` — where the `run` argv is assembled and its child has not
    // been started — which is why it is a `Protocol` error and not Deno's
    // mid-step `NotCapable`. The step has run once by then, in `describe`, and
    // the message says so: what is being refused is the invocation that would
    // have carried the FIFO and the grant.
    let error = run(&host(&workspace), "declared.ts").expect_err("a declaration is not a grant");
    assert!(matches!(error, ScriptHostError::Protocol { .. }), "{error}");
    let message = error.to_string();
    assert!(message.contains(&format!("127.0.0.1:{port}")), "{message}");
    assert!(message.contains("was never started"), "{message}");

    // And the half that is Deno's: permitted and declared, but the step reaches
    // for a host it did not declare, so the grant — which is exactly the
    // declaration — does not cover it.
    let error = run(&allowed, "undeclared.ts").expect_err("an undeclared host is not reachable");
    assert!(matches!(error, ScriptHostError::ScriptFailed { .. }), "{error}");
    assert!(error.to_string().contains("NotCapable"), "{error}");

    let _ = answer.join();
}

// The capabilities `adapter.rs` can only assert the *absence* of a flag for:
// subprocess, write, ffi and sys. Asserting that the adapter does not emit
// `--allow-run` proves the adapter has not been edited to emit it; it does not
// prove Deno refuses it. So each one is run against real Deno here, through
// [`escape`], with no try/catch anywhere — the permission error *is* the result
// under test, and the bootstrap turns it into a nonzero exit with the message
// on stderr.
#[test]
fn a_step_cannot_start_a_subprocess_or_write_the_marker_it_was_asked_to_write() {
    if !gated() {
        return;
    }
    // The marker goes outside the workspace, where the read grant cannot reach
    // it either: `--allow-write` is never passed, so a refusal that arrived
    // after the process ran would still leave the file. Asserting it does not
    // exist is what makes this a proof about the permission layer rather than
    // about the wording of the error.
    let outside = workspace("subprocess-outside");
    let marker = outside.join("marker.txt");
    // Quoted, because the marker path comes from `$TMPDIR` and an unquoted
    // redirect through a path with a space in it fails in the shell — leaving
    // the file unwritten and this test passing for the wrong reason. Single
    // quotes are the shell's literal form, which is what a path wants here.
    let (_, error) = escape(
        "subprocess",
        &format!(
            r#"    const output = new Deno.Command("/bin/sh", {{
      args: ["-c", "echo ran > '{}'"],
    }}).outputSync();
    return {{ ok: output.stdout.toString() }};"#,
            marker.display()
        ),
    );
    let message = error.to_string();
    assert!(message.contains("NotCapable"), "{message}");
    assert!(message.contains("--allow-run"), "{message}");
    assert!(!marker.exists(), "the shell must never have run: {}", marker.display());
}

#[test]
fn a_step_cannot_write_a_file_even_inside_its_own_workspace() {
    if !gated() {
        return;
    }
    // A relative path, resolved against the workspace the adapter set as the
    // child's working directory: the one place a step is most likely to expect
    // to be able to write, so the refusal is about the capability and not about
    // where the path points.
    let (workspace, error) = escape(
        "write",
        r#"    Deno.writeTextFileSync("written.txt", "no");
    return { ok: "wrote" };"#,
    );
    let message = error.to_string();
    assert!(message.contains("NotCapable"), "{message}");
    assert!(message.contains("--allow-write"), "{message}");
    assert!(!workspace.join("written.txt").exists(), "inside its own workspace, and absent");
}

#[test]
fn a_step_cannot_load_a_shared_library_through_ffi() {
    if !gated() {
        return;
    }
    // A real library and a real symbol: a refusal here is Deno's permission
    // check, not a path that does not resolve. (`f64`/`parameters` are the
    // spellings 2.9.7 wants; `number`/`params` are `TypeError`s before the
    // permission is ever consulted.)
    let (_, error) = escape(
        "ffi",
        r#"    const lib = Deno.dlopen("/lib/x86_64-linux-gnu/libm.so.6", {
      sin: { symbol: "sin", result: "f64", parameters: [] },
    });
    return { ok: String(lib.symbols.sin(0)) };"#,
    );
    let message = error.to_string();
    assert!(message.contains("NotCapable"), "{message}");
    assert!(message.contains("--allow-ffi"), "{message}");
    assert!(message.contains("libm.so.6"), "the refusal names the library: {message}");
}

#[test]
fn a_step_cannot_ask_the_operating_system_anything() {
    if !gated() {
        return;
    }
    // `Deno.hostname`, not `Deno.osHostname`: on 2.9.7 the latter is not a
    // function at all, so it would have thrown a `TypeError` and proved
    // nothing about permissions.
    let (_, error) = escape("sys", r#"    return { ok: Deno.hostname() };"#);
    let message = error.to_string();
    assert!(message.contains("NotCapable"), "{message}");
    assert!(message.contains("--allow-sys"), "{message}");
}

/// Writes `body` as the whole of a generated step's `run`, runs it, and returns
/// the workspace and the error — after checking that the error is a script
/// failure rather than one of the adapter's own refusals, because the difference
/// is the whole point: a step that reaches its capability and is denied by Deno
/// mid-run is a working sandbox, and a step the adapter never started is a
/// different claim.
fn escape(name: &str, body: &str) -> (PathBuf, ScriptHostError) {
    let workspace = workspace(name);
    write(
        &workspace,
        "step.ts",
        &format!(
            r#"export default {{
  inputs: {{}},
  outputs: {{ ok: "string" }},
  async run() {{
{body}
  }},
}};
"#
        ),
    );
    let error = block_on(host(&workspace).run(
        &ScriptRef::new("step.ts"),
        &Values::new(),
        &SecretBundle::new(),
        &quiet(),
    ))
    .expect_err("the capability is not granted");
    assert!(
        matches!(error, ScriptHostError::ScriptFailed { .. }),
        "the step starts and Deno refuses it mid-run, not the adapter before it: {error}"
    );
    (workspace, error)
}

#[test]
fn the_same_script_and_the_same_lockfile_give_the_same_bytes_twice() {
    if !gated() {
        return;
    }
    let workspace = workspace("determinism");
    write(
        &workspace,
        "clock.ts",
        r#"export default {
  inputs: {},
  outputs: { random: "number", epoch: "string", zone: "string", locale: "string", env: "string" },
  async run(_inputs: Record<string, unknown>) {
    let env: string;
    try {
      env = Deno.env.get("HOME") ?? "";
    } catch (error) {
      env = String(error).startsWith("NotCapable") ? "refused" : String(error);
    }
    return {
      random: Math.random(),
      epoch: new Date(0).toString(),
      zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      locale: Intl.DateTimeFormat().resolvedOptions().locale,
      env,
    };
  },
};
"#,
    );
    let host = host(&workspace);
    let script = ScriptRef::new("clock.ts");
    let first = block_on(host.run(&script, &Values::new(), &SecretBundle::new(), &quiet()))
        .expect("the first run");
    let second = block_on(host.run(&script, &Values::new(), &SecretBundle::new(), &quiet()))
        .expect("the second run");
    assert_eq!(first, second, "two runs of one step must agree");

    // Fixed constants, not just agreement: the seed, TZ=UTC and the empty
    // environment are set by the host, so these hold on a laptop and on a
    // GitHub Actions runner alike.
    assert_eq!(
        first["zone"],
        Value::from("UTC"),
        "the child's clock is UTC whatever the parent's is"
    );
    assert_eq!(first["locale"], Value::from("en-US"));
    assert_eq!(
        first["epoch"],
        Value::from("Thu Jan 01 1970 00:00:00 GMT+0000 (Coordinated Universal Time)")
    );
    assert_eq!(first["env"], Value::from("refused"), "there is no environment to read");
    // V8 is seeded with a fixed non-zero value (`--seed=0` means *unseeded*),
    // so the PRNG is reproducible too, not merely different each time.
    assert_eq!(first["random"], Value::Number(0.16917030546536072));
}

#[test]
fn sdk_style_type_tags_are_normalised_and_secrets_are_not_inputs() {
    if !gated() {
        return;
    }
    let workspace = workspace("tags");
    // The `@keepshipping/sdk` spelling: every field a runtime tag rather than
    // a plain type name, `optional(of)` and `list(of)` included, and one input
    // that is a secret — which is not a schema input at all, because secrets
    // arrive through `ctx.secrets`.
    write(
        &workspace,
        "tagged.ts",
        r#"const int = { kind: "int" };
const float = { kind: "float" };
const string = { kind: "string" };
const optional = (of: unknown) => ({ kind: "optional", of });
const list = (of: unknown) => ({ kind: "list", of });
export default {
  inputs: {
    count: int,
    ratio: optional(float),
    tags: list(string),
    db: { kind: "secret" },
  },
  outputs: { applied: int, url: { kind: "url" }, when: { kind: "duration" } },
  async run() {
    return { applied: 3, url: "https://example.com/apply", when: "PT1M" };
  },
};
"#,
    );
    let host = host(&workspace);
    let schema =
        block_on(host.schema(&ScriptRef::new("tagged.ts"))).expect("the step describes itself");
    assert_eq!(
        schema.inputs,
        [
            ("count".to_string(), ValueType::Number),
            ("ratio".to_string(), ValueType::Number),
            ("tags".to_string(), ValueType::List),
        ]
        .into_iter()
        .collect(),
        "int/float are numbers, optional(of) is the type inside it, and a secret is not an input"
    );
    assert_eq!(
        schema.outputs,
        [
            ("applied".to_string(), ValueType::Number),
            ("url".to_string(), ValueType::String),
            ("when".to_string(), ValueType::String),
        ]
        .into_iter()
        .collect()
    );

    // An unknown kind is a schema nobody can satisfy, not a silent `any`.
    write(
        &workspace,
        "unknown.ts",
        "export default { inputs: { at: { kind: \"whenever\" } }, outputs: {}, async run() { return {}; } };\n",
    );
    let error = block_on(host.schema(&ScriptRef::new("unknown.ts"))).expect_err("no such type");
    let ScriptHostError::InvalidSchema { name } = &error else {
        panic!("an unknown kind is not a schema: {error}");
    };
    assert_eq!(name, "at");
}

#[test]
fn a_step_beside_a_manifest_with_no_lockfile_is_refused() {
    if !gated() {
        return;
    }
    let workspace = workspace("locked");
    write(&workspace, "deno.json", "{}\n");
    write(
        &workspace,
        "step.ts",
        "export default { inputs: {}, outputs: {}, async run() { return {}; } };\n",
    );
    let host = host(&workspace);
    let error =
        block_on(host.schema(&ScriptRef::new("step.ts"))).expect_err("unlocked steps do not run");
    assert!(error.to_string().contains("deno.lock"), "{error}");
}

/// Whether the real-Deno tests should run.
fn gated() -> bool {
    if std::env::var("KS_DENO_CONFORMANCE").as_deref() != Ok("1") {
        skip("KS_DENO_CONFORMANCE is unset");
        return false;
    }
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        skip("the secret channel is Linux-x86_64 only");
        return false;
    }
    true
}

/// A host over `workspace`, sharing one cache so the pinned Deno is installed
/// once for the whole run.
///
/// The cache is the *library's* default — the one `DenoScriptHost::new` picks
/// when nobody calls `with_cache_root` — rather than a path this file works out
/// for itself. An earlier version resolved `$XDG_CACHE_HOME`, and fell back to
/// `std::env::temp_dir()` when that was unset, which is what a GitHub runner
/// does: the tests installed into `/tmp/keepshipping/deno` while CI restored
/// `~/.cache/keepshipping/deno`, so the cache was dead weight and every run
/// re-downloaded the ~40 MB release. Asking the library for its own default is
/// also the stronger test: it is the path production uses.
fn host(workspace: &Path) -> DenoScriptHost {
    DenoScriptHost::new(workspace).expect("a workspace root")
}

/// A scratch directory, emptied on the way in: the workspace a generated step
/// runs in.
fn workspace(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ks-deno-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("the scratch workspace is writable");
    path.canonicalize().expect("the scratch workspace resolves")
}

/// Writes `contents` to `name` inside `workspace`.
fn write(workspace: &Path, name: &str, contents: &str) {
    std::fs::write(workspace.join(name), contents)
        .unwrap_or_else(|error| panic!("{name} is writable: {error}"));
}
