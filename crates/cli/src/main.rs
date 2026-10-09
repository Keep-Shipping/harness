//! The `keepshipping` command-line interface: `check` type-checks a site
//! file (or, with `--all`, every `ship.ks` in a tree); `run` picks an
//! environment and hands off to the engine; `graph` prints the plan the file
//! would follow, without running it; `fmt` rewrites files into their canonical
//! form. Output formats, exit codes and colour rules are pinned in
//! `docs/DIAGNOSTICS.md`.

#![forbid(unsafe_code)]

mod about;
mod actor;
mod approve;
mod args;
mod base_policy;
mod blocks;
mod blocks_cache;
mod blocks_index;
mod blocks_publish;
mod check;
mod decide;
mod decisions;
mod drive;
mod fmt;
// Generic CI mode: any CI that can run a binary (#130). Built from the
// job's environment, so it answers the port without an OIDC token to verify
// and says so on one line before the run starts.
mod generic_ci;
// The GitHub Actions run context (#150) is built and tested here, but the
// command dispatch still has no run context to hand it: wiring CI-versus-local
// selection into `run` waits for the local adapter. Until then nothing in the
// binary names this module.
#[allow(dead_code)]
mod github_actions_run_context;
// The GitLab CI run context (#131), on the same terms: the command dispatch
// still has no run context to hand it, so nothing in the binary names it yet.
#[allow(dead_code)]
mod gitlab_ci_run_context;
mod graph;
mod import;
// The local ed25519 `Signer` for the signed run log (#112).
mod local_key;
mod log;
mod policy;
mod progress;
mod render;
mod resume;
mod run_log;
// The signed run log (#112). `log seal` and `log verify` use the sidecar and
// its signatures; the registry half (`attach`, `verify_from_registry`) is built
// and tested here but has no caller in the binary, which has no registry
// adapter wired in — the same note `github_actions_run_context` carries.
#[allow(dead_code)]
mod seal;
mod upgrade;

use std::io::{IsTerminal, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ks_core::ports::run_context::ActorKind;
use ks_core::ports::script_host::{ScriptHost, ScriptRef, Values};
use ks_core::ports::secrets::{Redactor, SecretBundle};
use ks_core::script_step::{is_script_kind, needing_approval, script_path};
use ks_core::step::{ActionKind, LogRecord, LogSink, StepLog};
use ks_core::{ContextName, Step, Trigger, TriggerKind, ci_only_refusal};
// The binary shares the adapter with the OCI distribution crate's tests, which
// link this package as a library; the module is declared once, in `lib.rs`.
use ks_cli::http_client;
#[cfg(test)]
use ks_cli::test_server;

use crate::args::{
    Command, Input, Options, USAGE, context_of, input_lines, parse_args, parse_inputs,
};
use crate::blocks::wait;
use crate::drive::{Done, Outcome, Parking, StepRunner};
use crate::progress::{Renderer, RunEvent};
use crate::render::Format;

fn main() -> ExitCode {
    // A panic is a bug in keepshipping, not a problem with the user's file:
    // say so plainly and exit 3, not the Rust default 101.
    std::panic::set_hook(Box::new(|info| eprintln!("internal error: {info}")));
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(dispatch)) {
        Ok(code) => code,
        Err(_) => ExitCode::from(3),
    }
}

fn dispatch() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check") => check::check(&args[1..]),
        Some("run") => run(&args[1..]),
        // `fmt --upgrade` migrates a file to the current format version;
        // plain `fmt` (and `fmt --check`, `fmt -`) lays it out canonically.
        Some("fmt") if args[1..].iter().any(|a| a == "--upgrade") => upgrade::fmt(&args[1..]),
        Some("fmt") => fmt::fmt(&args[1..]),
        Some("graph") => graph::graph(&args[1..]),
        Some("blocks") => blocks::blocks(&args[1..]),
        Some("policy") => policy::policy(&args[1..]),
        // `import shell` turns an existing deploy script, and `import
        // github-actions` a workflow, into a starting `.ks` file: best effort,
        // and each says what it did not recognise.
        Some("import") => import::import(&args[1..]),
        // The checker is pure, so the only thing that can know what a
        // `script` step's TypeScript module declares is this one. It is
        // handed over rather than reached for, keeping node and the cache
        // out of the language server.
        Some("lsp") => ks_lsp::serve_with(ks_cli::scripts::script_outputs),
        Some("log") => log::log(&args[1..]),
        // The approver's side of the same story: what is parked, and the answer. The whole
        // argument list, command word and all — `approve` reads the word itself, since which word
        // it is is what picks the form.
        Some("runs" | "approve" | "deny") => approve::approve(&args),
        // The job that carries a parked run on (#97): it re-checks the
        // record's binding, the context gate and policy, then drives the rest.
        Some("resume") => resume::resume(&args[1..]),
        Some("decisions") => decisions::decisions(&args[1..]),
        Some("decide") => decide::decide(&args[1..]),
        // What Keep Shipping itself is built with (#178), from the vendored
        // Factory Zero registry entry — and the binary's `--version`.
        Some("about") => about::about(&args[1..]),
        Some("--version") => about::version(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> ExitCode {
    let Some(o) = parse_args(args, Command::Run) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    // `--input` is parsed once, here, before anything runs: a malformed pair
    // is a mistake in the command line, and the run should not start to find
    // that out. The parsed pairs travel to `--dry-run` from here, so there is
    // no second parse that could disagree with this one.
    let inputs = match parse_inputs(&o.inputs) {
        Ok(inputs) => inputs,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };
    // Parsed before anything is decided about the run: `--event` is a usage
    // error or it is nothing, and generic CI mode wants the answer to build
    // the actor's event.
    let event = match o.event.as_deref().map(parse_event) {
        Some(Ok(t)) => Some(t),
        Some(Err(msg)) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
        None => None,
    };
    // `--sha` is how a generic CI run states the commit its system names no
    // variable for. Without `--ci` there is no run context to state it to, so
    // the flag would parse and then be dropped without a word — which is how a
    // caller ends up believing a run was about a commit it never named.
    if o.sha.is_some() && !o.ci {
        eprintln!("error: --sha is the commit a --ci run states; pass --ci as well");
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    // The dry-run graph is written for people; inside a machine format it
    // would corrupt the stream, the way `check --secrets` would.
    if o.dry_run && o.format != Format::Human {
        eprintln!(
            "error: --dry-run prints a graph for people; it does not combine with --format {}",
            o.format.as_str()
        );
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let path = o.path.as_deref().unwrap_or("ship.ks");
    // `--ci` is the caller saying a CI is in charge, which settles it even
    // where the environment is empty: the flag is the assertion, and it
    // overrides a detected laptop so a job that exports nothing still gets
    // the CI context and every `ci-only:` step it covers.
    let context = if o.ci { ContextName::Ci } else { context_of(&o) };
    // Who is running this, decided once from the declaration, the environment
    // and the organisation's baseline — the latter whatever this environment
    // declares in `KEEPSHIPPING_AGENTS` / `KEEPSHIPPING_REQUIRE_HUMAN`. A
    // stored `PolicyStore` baseline is still to come; until then the
    // environment is the only place an organisation can speak.
    let baseline = actor::ActorBaseline::from_env(&env_snapshot());
    let actor = actor::for_run(o.declared, o.actor_name.as_deref(), interactive(&o), &baseline);
    // Detection alone only ever escalates to an agent; it never pulls a
    // declared `human` or `ci` back down to one. A baseline that requires a
    // human is the other half and may escalate either.
    let actor_kind = if actor.kind == ActorKind::Agent { ActorKind::Agent } else { o.actor };
    let is_agent = actor_kind == ActorKind::Agent;
    // Generic CI mode: what the job's environment says about itself, for the
    // log, the parked record and the one stderr line. It is not handed to any
    // step — dispatch has no run context to give one yet (#130).
    let ci = o.ci.then(|| {
        crate::generic_ci::GenericCiRunContext::from_env(
            &env_snapshot(),
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            crate::generic_ci::Overrides {
                actor: o.declared,
                actor_name: o.actor_name.clone(),
                sha: o.sha.clone(),
                trigger: event.as_ref().map(crate::generic_ci::trigger_from_cli),
            },
        )
    });
    let site = match check::load(Path::new(path), path, actor_kind, o.path.is_none(), context) {
        Ok(site) => site,
        Err(code) => return code,
    };
    let diags = &site.checked.diagnostics;
    if !diags.is_empty() {
        // In json mode even the pre-run diagnostics keep stdout parseable:
        // they are `check`'s human rendering, so a machine stream must not
        // carry them — they go to stderr with every other notice, and stdout
        // stays empty or pure JSON Lines, nothing else.
        if o.format == Format::Json {
            let mut err = std::io::stderr().lock();
            let _ = render::human(&mut err, path, &site.src, diags, render::use_color());
        } else {
            let mut out = std::io::stdout().lock();
            let _ = render::human(&mut out, path, &site.src, diags, render::use_color());
        }
    }
    if check::fails(&o, diags) {
        return ExitCode::from(1);
    }
    // A run bound to fail at a step the context cannot run is refused here,
    // before the environment is even chosen.
    if let Err(code) = refuses_to_run(&site, &o, context) {
        return code;
    }
    match ks_core::select_env(&site.checked.workflow, o.env.as_deref(), event.as_ref()) {
        Ok(ks_core::EnvChoice::Selected(name)) => {
            selected(&o, &site, &name, is_agent, &inputs, ci.as_ref())
        }
        Ok(ks_core::EnvChoice::Ambiguous(names)) => {
            let offered = names.join(", ");
            if interactive(&o) {
                match prompt(&offered, &names) {
                    Some(name) => selected(&o, &site, &name, is_agent, &inputs, ci.as_ref()),
                    None => {
                        eprintln!("error: no environment chosen (expected one of {offered})");
                        ExitCode::from(2)
                    }
                }
            } else {
                eprintln!(
                    "error: this file declares several environments ({offered}); pass --env <name>"
                );
                ExitCode::from(2)
            }
        }
        Err(d) => {
            eprintln!("error: {}", d.message);
            for hint in &d.hints {
                eprintln!("  hint: {hint}");
            }
            ExitCode::from(2)
        }
    }
}

/// The environment is chosen: print the run the file describes, and run it.
/// `is_agent` is what the run decided about itself; an agent's run never
/// reaches a terminal for approval, because an agent cannot approve its own
/// run — it would be approving itself.
fn selected(
    o: &Options,
    site: &check::Site,
    env: &str,
    is_agent: bool,
    inputs: &[Input],
    ci: Option<&crate::generic_ci::GenericCiRunContext>,
) -> ExitCode {
    let workflow = &site.checked.workflow;
    let only: Vec<&str> = o.only.iter().map(String::as_str).collect();
    let skip: Vec<&str> = o.skip.iter().map(String::as_str).collect();
    let steps = match drive::select(workflow, o.until.as_deref(), &only, &skip) {
        Ok(steps) => steps,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };
    // A script step that says nothing about what it does, about to change
    // production as an agent, stops here — over the steps this run actually
    // covers, and before a word is printed, the way the policy gate above
    // stops.
    // The actor the run decided on, so a detected agent is gated like a
    // declared one.
    let actor = if is_agent { ActorKind::Agent } else { o.actor };
    if refuses_scripts(workflow, actor, env, &steps) {
        return ExitCode::from(1);
    }
    // An environment that is `ci-only` — by `ci-only: true`, or by being
    // named `prod` — does not let a laptop apply or deploy into it. Stopped
    // here for the same reason, and at the same moment: before the run has
    // printed anything or resolved a credential.
    if refuses_ci_only(workflow, o, env, &steps) {
        return ExitCode::from(1);
    }
    // What `--ci` detected, said once, before anything runs: which CI this is,
    // and that its identity is self-declared because generic mode verifies no
    // OIDC token (#130). One line, on stderr with the rest of the refusals.
    if let Some(ci) = ci {
        eprintln!("note: {}", ci.note());
    }
    if o.dry_run {
        // The graph and the check, and nothing else: the promise `check`
        // makes still holds, so it closes the report. It is also the one path
        // the default-branch gate below does not touch — a dry run starts
        // nothing, so there is nothing there for a policy to stop, and its
        // output is the graph the check already promised.
        println!("environment: {env}");
        let mut out = std::io::stdout().lock();
        for step in &steps {
            let _ = writeln!(
                out,
                "{}",
                progress::kind_line(&step.name, step.kind.as_deref().unwrap_or("step"))
            );
        }
        // The `--input` overrides this run would carry, and nothing more: none
        // is handed to a step yet, and a `@secret:` value stays a reference,
        // because nothing here resolves it.
        for line in input_lines(inputs) {
            let _ = writeln!(out, "{line}");
        }
        let _ = render::footer(&mut out);
        return ExitCode::SUCCESS;
    }

    // The default branch's `policy:` block, read once, and the gate that folds
    // this file's against it (#118). A branch may only narrow: a step the
    // effective policy refuses is refused before the run says a word, and a
    // step it asks about is a wait, the way an `approval` step is.
    let base = match base_policy::read(&site.file, o.base.as_deref()) {
        Ok(base) => base,
        Err(why) => {
            eprintln!("error: --base {why}");
            return ExitCode::from(2);
        }
    };
    // In json mode the stream opens before the gate, because a refusal is an
    // outcome the closing line states and a stream with no opening line could
    // not be told from one that never got this far. The human environment line
    // stays where it was — after the gate — so a refused run still prints
    // nothing on stdout.
    let what = workflow.name().map(str::to_string).unwrap_or_else(|| stem(&site.file));
    if o.format == Format::Json {
        let mut out = std::io::stdout().lock();
        let _ = progress::json_line(
            &mut out,
            &[("event", "run_started"), ("what", &what), ("env", env)],
            &[],
        );
    }
    let waiting = match policy::gate(
        workflow,
        &steps,
        base.as_ref().map(|b| &b.policy),
        &site.checked.secret_uses,
        actor,
        env,
    ) {
        Some(policy::Gate::Refused { step, why }) => {
            eprintln!("refusing to start: step `{step}` — {why}");
            // The refusal happened before anything ran, so there is no run id
            // and no parking: the step and the rule are all there is to say.
            if o.format == Format::Json {
                let mut out = std::io::stdout().lock();
                let _ = progress::json_line(
                    &mut out,
                    &[
                        ("event", "run_finished"),
                        ("status", "policy_refused"),
                        ("step", &step),
                        ("why", &why),
                    ],
                    &[("exit", u64::from(ks_engine::exec::EXIT_POLICY_REFUSED))],
                );
            }
            return ExitCode::from(ks_engine::exec::EXIT_POLICY_REFUSED);
        }
        Some(policy::Gate::Wait { step, why }) => Some((step, why)),
        None => None,
    };
    if o.format != Format::Json {
        println!("environment: {env}");
    }

    let tty = std::io::stdout().is_terminal() && std::env::var("TERM").is_ok_and(|t| t != "dumb");
    let shared = Mutex::new(renderer(o.format, tty, o.verbose));
    // Where a run that has to wait is written down, so the job can end and
    // `keepshipping resume` pick it up (#97). Nothing touches the disk unless
    // the run actually parks.
    let mut parking = resume::Park::new(
        resume::run_id(),
        site.src.as_bytes(),
        o.event.clone().unwrap_or_else(|| "manual".to_string()),
    )
    .with_context(resume::ACTOR, resume::actor_word(actor))
    .with_context(resume::ENVIRONMENT, env);
    // The base this run was decided against, written down with it: a resume is
    // a different job, on a different machine, and re-detecting would let the
    // policy answer depend on what that machine happened to have checked out.
    if let Some(base) = &base {
        parking = parking.with_context(resume::BASE_REF, &base.git_ref);
    }
    // Which CI parked the run, so a later `runs pending` or `resume` can say
    // where it came from without re-deriving it from the machine it lands on.
    // The key lives here rather than beside `resume::ACTOR` so this change
    // stays off a file another change is already editing. The value is the
    // same name the `--ci` note calls the actor by, so a record and the line
    // that wrote it cannot call one CI two different things (`unknown` where
    // the environment named no system).
    const CI_KEY: &str = "ci";
    let mut parking = match ci {
        Some(ci) => parking.with_context(CI_KEY, &ci.system().to_string()),
        None => parking,
    };
    // A step the effective policy asks about is a wait, and a wait is what an
    // `approval` step is: the run writes itself down with nothing done and the
    // job ends. An agent's run waits on a human decision, because an agent may
    // not answer its own — the same rule, the same two commands.
    if let Some((step, why)) = waiting {
        eprintln!("waiting at {step}: {why}");
        let mut parking = parking.with_context(resume::POLICY_GATE, &step);
        let on = if is_agent {
            drive::WaitReason::AgentDecision { notified: None }
        } else {
            drive::WaitReason::Approval { question: why }
        };
        let Some(run) = parking.park(&step, &[], &on) else {
            return ExitCode::from(1);
        };
        // The stream opened, so it has to close here too: this park never
        // reaches the outcome match below.
        finish_line(
            o.format,
            "waiting_for_approval",
            ks_engine::exec::EXIT_WAITING_FOR_APPROVAL,
            &[("run", run.as_str()), ("step", &step), ("on", on.as_str())],
        );
        return resume::park_notice(&run, &step, &on);
    }
    let mut approver: Box<dyn drive::Approver> = if is_agent {
        // An agent's run parks at its first approval: it may not answer its
        // own. Who to tell comes from the approval's own `ask:`; until that is
        // read here, the run waits without naming anyone.
        Box::new(drive::AgentRun { notified: None, parking: &mut parking })
    } else if interactive(o) {
        Box::new(drive::TtyApprover::new(std::io::stdin().lock()))
    } else {
        // Nobody watching: the run parks rather than declines, and the job
        // ends instead of holding a runner open until it times out (#97).
        Box::new(drive::Unwatched(&mut parking))
    };
    if is_agent {
        // An agent reads the run and acts on it, so its run opens with the
        // check the steps below are standing on.
        if let Ok(mut r) = shared.lock() {
            r.event(&RunEvent::Checked { path: site.path.clone() });
        }
    }
    let started = Instant::now();
    let outcome = drive::with_spinner(tty, &shared, |renderer| {
        drive::drive(
            &steps,
            &mut Steps::default(),
            approver.as_mut(),
            renderer,
            &mut || started.elapsed(),
            &what,
        )
    });
    // The code and the json stream's `exit` are one mapping, the Outcome's
    // own table, read once: the last line states what the exit code states.
    let code = outcome.exit_code();
    let exit = outcome.exit();
    match &outcome {
        Outcome::Shipped => {
            finish_line(o.format, "shipped", exit, &[]);
            code
        }
        // Waiting is not failing: the run parked at an approval, which is the
        // engine's own exit 4, and the notice says what carries it on.
        Outcome::Waiting { run, step, on } => {
            finish_line(
                o.format,
                "waiting_for_approval",
                exit,
                &[("run", run.as_str()), ("step", step.as_str()), ("on", on.as_str())],
            );
            resume::park_notice(run, step, on)
        }
        // A denial keeps its own code: a human's `no`, not a breakage.
        Outcome::Declined => {
            finish_line(o.format, "denied", exit, &[]);
            code
        }
        Outcome::Failed => {
            finish_line(o.format, "failed", exit, &[]);
            code
        }
    }
}

/// The renderer the run's lines go through: JSON Lines in `--format json`,
/// animated at a terminal otherwise, and plain everywhere else.
fn renderer(format: Format, tty: bool, verbose: bool) -> Box<dyn Renderer + Send> {
    // `Stdout` is `Send`, `StdoutLock` is not: the ticker thread holds the
    // renderer behind a lock of its own.
    match format {
        Format::Json => Box::new(progress::Json::new(std::io::stdout())),
        _ => Box::new(progress::Run::new(std::io::stdout(), verbose, tty)),
    }
}

/// The closing `run_finished` Line, in json mode: the status words and the
/// same exit number the process returns, so a reader of stdout alone knows
/// how the run ended. Human output has no such line, and there the call does
/// nothing.
fn finish_line(format: Format, status: &str, exit: u8, extra: &[(&str, &str)]) {
    if format != Format::Json {
        return;
    }
    let mut fields = vec![("event", "run_finished"), ("status", status)];
    fields.extend_from_slice(extra);
    let mut out = std::io::stdout().lock();
    let _ = progress::json_line(&mut out, &fields, &[("exit", u64::from(exit))]);
}

/// The file's name without its extension, for a file that names no workflow.
fn stem(file: &Path) -> String {
    file.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.to_string_lossy().into_owned())
}

/// The process environment, as the map both the CI context and the actor's
/// facts are built from.
///
/// Read through `vars_os`, never `vars`: `vars` panics on a single variable
/// that is not valid UTF-8, and one such variable anywhere in a CI job — which
/// is exactly where they leak in — would take the whole run down over a name
/// this run may not even read. A value that is not UTF-8 is lossily
/// converted: what it said may be mangled, and what it said is not worth a
/// crash.
pub(crate) fn env_snapshot() -> std::collections::BTreeMap<String, String> {
    lossy(std::env::vars_os())
}

/// The environment as `from_env` takes it, whatever it holds. Split out from
/// the read so a test can hand it a variable `vars` would have panicked on.
fn lossy(
    env: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> std::collections::BTreeMap<String, String> {
    env.map(|(name, value)| {
        (name.to_string_lossy().into_owned(), value.to_string_lossy().into_owned())
    })
    .collect()
}

/// A variable that is not valid UTF-8 is lossily read, not fatal: `vars`
/// panics where `vars_os` does not, and CI environments are exactly where they
/// leak in. This pins the read; the binary it feeds is turned on by the
/// non-UTF-8 environment test beside it.
#[test]
#[cfg(unix)]
fn lossy_keeps_a_variable_that_is_not_utf8() {
    use std::os::unix::ffi::OsStringExt;
    let bad = std::ffi::OsString::from_vec(b"WEIRD\xffNAME".to_vec());
    let snapshot = lossy([(bad.clone(), bad.clone())].into_iter());
    // Lossy, not fatal: the name survives as replacement characters, which is
    // all a CI variable this run never reads has to be worth.
    assert_eq!(snapshot.len(), 1, "the variable was read, not dropped");
    let (name, value) = snapshot.iter().next().expect("the one variable");
    assert!(name.contains('\u{fffd}') && value.contains('\u{fffd}'), "{name}={value}");
}

/// The runner the binary runs steps through. A script step goes to the
/// [`ScriptHost`] the run was built with; every other kind stops the run and
/// says why — the engine's built-in steps are still empty, so a run that
/// claimed to have shipped would not have. That is the honest report.
#[derive(Default)]
struct Steps {
    scripts: Option<Arc<dyn ScriptHost>>,
}

impl Steps {
    /// A runner that sends script steps to `host`
    /// ([#90](https://github.com/Keep-Shipping/harness/issues/90)'s adapter).
    // Built and tested here, but the binary has no host to hand it: the Deno
    // adapter is #90's. Until then the run says so, which the test above pins.
    #[cfg_attr(not(test), allow(dead_code))]
    fn with_scripts(mut self, host: Arc<dyn ScriptHost>) -> Steps {
        self.scripts = Some(host);
        self
    }
}

impl StepRunner for Steps {
    fn run(&mut self, step: &Step, log: &mut dyn FnMut(&str)) -> Result<Done, String> {
        let kind = step.kind.as_deref().unwrap_or("steps");
        if !is_script_kind(kind) {
            return Err(format!("`{kind}` steps are not built in yet"));
        }
        // The kind is `./ship/migrate.ts`; the script is at `ship/migrate.ts`
        // relative to the run's workspace root.
        let Some(path) = script_path(kind) else {
            return Err(format!(
                "`{kind}`: script steps need the script runtime, which is not built in yet"
            ));
        };
        let Some(host) = self.scripts.as_deref() else {
            return Err(format!(
                "`{kind}`: script steps need the script runtime, which is not built in yet"
            ));
        };
        // Inputs are passed empty: the step's schema is not read at run time
        // yet (#88), so there is nothing to hand over and nothing to check.
        // The script's log lines come back through the step's own logger. No
        // secrets are resolved here yet, so its redactor holds nothing.
        let sink = Arc::new(CollectingSink::default());
        let step_log =
            StepLog::new(step.name.clone(), Arc::new(Redactor::new()), Arc::clone(&sink) as _);
        let outputs =
            wait(host.run(&ScriptRef::new(path), &Values::new(), &SecretBundle::new(), &step_log))
                .map_err(|e| e.to_string());
        for record in sink.take() {
            log(&record.message);
        }
        let outputs = outputs?;
        Ok(Done::Summary(
            outputs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" "),
        ))
    }
}

/// Keeps a script step's log records until the step returns, so they can be
/// handed to the progress renderer's per-line callback in order.
#[derive(Default)]
struct CollectingSink(Mutex<Vec<LogRecord>>);

impl CollectingSink {
    fn take(&self) -> Vec<LogRecord> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }
}

impl LogSink for CollectingSink {
    fn record(&self, record: LogRecord) {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(record);
    }
}

/// The script-step gate ([#89](https://github.com/Keep-Shipping/harness/issues/89)):
/// an agent about to change production through a script step that never said
/// what it does, with no approval before it, does not start. True when the run
/// was refused; every offending step is named on stderr.
fn refuses_scripts(
    workflow: &ks_core::Workflow,
    actor: ActorKind,
    env: &str,
    steps: &[&Step],
) -> bool {
    let running: Vec<&str> = steps.iter().map(|s| s.name.as_str()).collect();
    let refused = needing_approval(workflow, actor, Some(env), &running);
    if refused.is_empty() {
        return false;
    }
    for step in refused {
        let kind = step.kind.as_deref().unwrap_or("steps");
        eprintln!(
            "refusing to start: step `{}` runs `{kind}`, which declares no `action:`; \
             an agent needs an `approval` step before it in {env}",
            step.name
        );
    }
    eprintln!(
        "  hint: declare `action:` on the script step (one of {}), or put an \
         `approval` step before it",
        ActionKind::NAMES.join(", ")
    );
    true
}

/// The environment gate ([#123](https://github.com/Keep-Shipping/harness/issues/123)):
/// `ci-only` belongs to the environment as much as to the step, so a step that
/// applies or deploys into one is CI-only without saying so. A local run does
/// not start; a run in CI is what the rule is asking for, so it is not asked.
/// True when the run was refused; every offending step is named on stderr.
fn refuses_ci_only(workflow: &ks_core::Workflow, o: &Options, env: &str, steps: &[&Step]) -> bool {
    if context_of(o) == ContextName::Ci {
        return false;
    }
    let Some(target) = workflow.envs().iter().find(|e| e.name == env) else { return false };
    let running: Vec<&str> = steps.iter().map(|s| s.name.as_str()).collect();
    let refusal = ci_only_refusal(workflow, target, &running);
    if refusal.is_empty() {
        return false;
    }
    eprintln!("{refusal}");
    eprintln!(
        "  hint: run it in CI (`--context ci`), or from an approval someone else gives — \
         a local `y` is not a substitute"
    );
    true
}

/// The steps a run would take, in run order, narrowed by `--until`, `--only`
/// and `--skip` the way the run itself narrows them. A name the file does not
/// declare is a usage error — a typo must not quietly widen the run.
fn selection(site: &check::Site, o: &Options) -> Result<Vec<String>, Box<str>> {
    let only: Vec<&str> = o.only.iter().map(String::as_str).collect();
    let skip: Vec<&str> = o.skip.iter().map(String::as_str).collect();
    let steps = drive::select(&site.checked.workflow, o.until.as_deref(), &only, &skip)?;
    Ok(steps.iter().map(|s| s.name.to_string()).collect())
}

/// The context gate ([#34](https://github.com/Keep-Shipping/harness/issues/34)):
/// a run bound to fail at a step this context cannot run does not start
/// unless `--allow-partial` says the caller knows that.
fn refuses_to_run(site: &check::Site, o: &Options, context: ContextName) -> Result<(), ExitCode> {
    let selected = match selection(site, o) {
        Ok(steps) => steps,
        Err(why) => {
            eprintln!("error: {why}");
            eprintln!("{USAGE}");
            return Err(ExitCode::from(2));
        }
    };
    refuses_to_run_at(site, &selected, o.allow_partial, context)
}

/// The gate itself, over an already-chosen selection: a run does not start in
/// a context that cannot run a step it covers. Split from [`refuses_to_run`]
/// so `resume` asks the same question of the steps *it* is about to drive: a
/// run parked on a runner and resumed on a laptop is exactly the case the gate
/// exists for.
fn refuses_to_run_at(
    site: &check::Site,
    selected: &[String],
    allow_partial: bool,
    context: ContextName,
) -> Result<(), ExitCode> {
    let ctx = context.context();
    // `site.unmet` came from the check that already printed the warnings, so
    // the gate agrees with them rather than re-asking the catalog.
    let Some(step) = site.unmet.iter().find(|s| selected.contains(&s.name)) else {
        return Ok(());
    };
    // Counted in run order, like `--until` and the warning's own stop point.
    let order = ks_core::run_order(&site.checked.workflow);
    let at = order.iter().position(|n| *n == step.name).unwrap_or(order.len()) + 1;
    if allow_partial {
        eprintln!(
            "note: continuing with --allow-partial; step `{}` will be skipped or fail",
            step.name
        );
        return Ok(());
    }
    eprintln!(
        "refusing to start: step `{}` ({at} of {}) {}; pass --allow-partial, or {}",
        step.name,
        order.len(),
        step.reason(&ctx),
        step.hint()
    );
    Err(ExitCode::from(1))
}

/// A terminal to ask, the user having allowed it, and no CI in charge.
///
/// `--ci` is a CI in charge however the environment looks, and a non-interactive
/// run parks at its first approval and ends the job instead of holding a runner
/// open until it times out (#97).
fn interactive(o: &Options) -> bool {
    std::io::stdin().is_terminal()
        && !o.non_interactive
        && !o.ci
        && std::env::var_os("CI").is_none()
}

fn prompt(offered: &str, names: &[String]) -> Option<String> {
    print!("environment ({offered}): ");
    std::io::stdout().flush().ok()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok()?;
    let name = line.trim().to_string();
    names.contains(&name).then_some(name)
}

pub(crate) fn parse_event(text: &str) -> Result<Trigger, String> {
    let mut parts = text.split_whitespace();
    let kind = match parts.next() {
        Some("push") => TriggerKind::Push,
        Some("pr") => TriggerKind::Pr,
        Some("tag") => TriggerKind::Tag,
        Some("manual") => TriggerKind::Manual,
        Some(other) => return Err(format!("unknown event `{other}` (push, pr, tag, manual)")),
        None => return Err("empty event".into()),
    };
    Ok(Trigger { kind, glob: parts.next().map(String::from), span: Default::default() })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ks_core::ports::script_host::{StepSchema, Value, ValueType};
    use ks_testing::script_host::FakeScriptHost;

    use super::*;

    /// The one script step these tests run, checked into a step.
    fn migrate() -> Step {
        ks_core::check(&ks_lang::parse("steps:\n  migrate: ./ship/migrate.ts\n"))
            .workflow
            .step("migrate")
            .expect("the step")
            .clone()
    }

    #[test]
    fn a_script_step_without_a_host_says_so_in_its_own_words() {
        let Err(error) = Steps::default().run(&migrate(), &mut |_| {}) else {
            panic!("no runtime yet")
        };
        assert_eq!(
            error,
            "`./ship/migrate.ts`: script steps need the script runtime, which is not built in yet"
        );
    }

    #[test]
    fn a_script_step_with_a_host_reports_its_outputs_as_a_summary() {
        let host: Arc<dyn ScriptHost> = Arc::new(FakeScriptHost::new().with_script(
            &ScriptRef::new("ship/migrate.ts"),
            StepSchema {
                inputs: BTreeMap::new(),
                outputs: BTreeMap::from([("applied".to_string(), ValueType::Number)]),
            },
            BTreeMap::from([("applied".to_string(), Value::from(3.0))]),
        ));
        let mut steps = Steps::default().with_scripts(host);
        match steps.run(&migrate(), &mut |_| {}).expect("the script runs") {
            Done::Summary(summary) => assert_eq!(summary, "applied=3"),
            Done::Ask(question) => panic!("a script step does not ask: {question}"),
        }
    }
}
