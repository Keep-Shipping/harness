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
use std::sync::{Arc, Mutex};

use ks_core::ports::script_host::{
    ScriptHost, ScriptHostError, ScriptRef, Value, ValueType, Values,
};
use ks_core::ports::secrets::{SecretBundle, SecretValue};
use ks_deno_script_host::{DENO_VERSION, DenoScriptHost};
use ks_testing::block_on;
use ks_testing::script_host::conformance;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

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
    let logged: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&logged);
    let host = host(&workspace).with_log_sink(move |level, message| {
        sink.lock().expect("the log sink").push((level.to_string(), message.to_string()));
    });

    let mut secrets = SecretBundle::new();
    secrets.insert("conformance-token", SecretValue::new(b"hunter2".to_vec()));
    let outputs = block_on(host.run(&ScriptRef::new("step.ts"), &Values::new(), &secrets))
        .expect("the step runs with its secret");

    assert_eq!(outputs["token"], Value::from("hunter2"), "the value reached the step intact");
    assert_eq!(outputs["length"], Value::Number(7.0));
    let logged = logged.lock().expect("the log sink").clone();
    assert_eq!(logged.len(), 1, "the step logged once: {logged:?}");
    assert_eq!(logged[0].0, "info");
    assert!(!logged[0].1.contains("hunter2"), "the log sink must not see a secret");
    assert!(logged[0].1.contains("***"), "the secret is redacted in the log: {}", logged[0].1);
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
        let error = block_on(host.run(&script, &inputs, &SecretBundle::new()))
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
    ))
    .expect("a link within the workspace is not an escape");
    assert_eq!(
        outputs["read"],
        Value::from("in the workspace"),
        "the step read through the link and the adapter let it"
    );
}

#[test]
fn net_is_refused_unless_the_step_declared_the_host() {
    if !gated() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = listener.local_addr().expect("its address").port();
    // Exactly one connection may arrive: the refused fetch never opens one, and
    // Deno's refusal happens before the socket, not after it. So the thread
    // answers once and drops the listener — anything else would hang here
    // rather than fail the assertion.
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
    let fetch_step = |declares: bool| {
        format!(
            r#"export default {{
  inputs: {{ url: "string" }},
  outputs: {{ body: "string" }},
  net: [{}{}],
  async run(inputs: Record<string, any>) {{
    const response = await fetch(inputs.url as string);
    return {{ body: await response.text() }};
  }},
}};
"#,
            if declares { format!("\"127.0.0.1:{port}\"") } else { String::new() },
            if declares { "" } else { "\"example.invalid\"" },
        )
    };
    write(&workspace, "declared.ts", &fetch_step(true));
    write(&workspace, "undeclared.ts", &fetch_step(false));

    let host = host(&workspace);
    let url: Values = [("url".to_string(), Value::from(format!("http://127.0.0.1:{port}/")))]
        .into_iter()
        .collect();

    let declared = block_on(host.run(&ScriptRef::new("declared.ts"), &url, &SecretBundle::new()))
        .expect("a declared host is reachable");
    assert_eq!(declared["body"], Value::from("pong"));

    let error = block_on(host.run(&ScriptRef::new("undeclared.ts"), &url, &SecretBundle::new()))
        .expect_err("an undeclared host is not");
    assert!(error.to_string().contains("NotCapable"), "{error}");

    let _ = answer.join();
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
    let first =
        block_on(host.run(&script, &Values::new(), &SecretBundle::new())).expect("the first run");
    let second =
        block_on(host.run(&script, &Values::new(), &SecretBundle::new())).expect("the second run");
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
