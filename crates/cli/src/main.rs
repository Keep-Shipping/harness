//! The `keepshipping` command-line interface: `check` type-checks a site
//! file (or, with `--all`, every `ship.ks` in a tree); `run` picks an
//! environment and hands off to the engine; `graph` prints the plan the file
//! would follow, without running it; `fmt` rewrites files into their canonical
//! form. Output formats, exit codes and colour rules are pinned in
//! `docs/DIAGNOSTICS.md`.

#![forbid(unsafe_code)]

mod actor;
mod approve;
mod args;
mod blocks;
mod blocks_cache;
mod blocks_index;
mod blocks_publish;
mod check;
mod decide;
mod decisions;
mod drive;
mod fmt;
// The GitHub Actions run context (#150) is built and tested here, but the
// command dispatch still has no run context to hand it: wiring CI-versus-local
// selection into `run` waits for the local adapter. Until then nothing in the
// binary names this module.
#[allow(dead_code)]
mod github_actions_run_context;
mod graph;
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
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ks_core::ports::run_context::ActorKind;
use ks_core::ports::script_host::{ScriptHost, ScriptRef, Values};
use ks_core::ports::secrets::{Redactor, SecretBundle};
use ks_core::script_step::{is_script_kind, needing_approval, script_path};
use ks_core::step::{ActionKind, LogRecord, LogSink, StepLog};
use ks_core::{ContextName, Step, Trigger, TriggerKind};
// The binary shares the adapter with the OCI distribution crate's tests, which
// link this package as a library; the module is declared once, in `lib.rs`.
use ks_cli::http_client;
#[cfg(test)]
use ks_cli::test_server;

use crate::args::{
    Command, Input, Options, USAGE, context_of, input_lines, parse_args, parse_inputs,
};
use crate::blocks::wait;
use crate::drive::{Done, Outcome, StepRunner};
use crate::progress::{Renderer, RunEvent};

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
    let path = o.path.as_deref().unwrap_or("ship.ks");
    let context = context_of(&o);
    // Who is running this, decided once from the declaration, the environment
    // and the organisation's baseline — the latter whatever this environment
    // declares in `KEEPSHIPPING_AGENTS` / `KEEPSHIPPING_REQUIRE_HUMAN`. A
    // stored `PolicyStore` baseline is still to come; until then the
    // environment is the only place an organisation can speak.
    let baseline = actor::ActorBaseline::from_env(&std::env::vars().collect());
    let actor = actor::for_run(o.declared, o.actor_name.as_deref(), interactive(&o), &baseline);
    // Detection alone only ever escalates to an agent; it never pulls a
    // declared `human` or `ci` back down to one. A baseline that requires a
    // human is the other half and may escalate either.
    let actor_kind = if actor.kind == ActorKind::Agent { ActorKind::Agent } else { o.actor };
    let is_agent = actor_kind == ActorKind::Agent;
    let site = match check::load(Path::new(path), path, actor_kind, o.path.is_none(), context) {
        Ok(site) => site,
        Err(code) => return code,
    };
    let diags = &site.checked.diagnostics;
    if !diags.is_empty() {
        let mut out = std::io::stdout().lock();
        let _ = render::human(&mut out, path, &site.src, diags, render::use_color());
    }
    if check::fails(&o, diags) {
        return ExitCode::from(1);
    }
    // A run bound to fail at a step the context cannot run is refused here,
    // before the environment is even chosen.
    if let Err(code) = refuses_to_run(&site, &o, context) {
        return code;
    }
    let event = match o.event.as_deref().map(parse_event) {
        Some(Ok(t)) => Some(t),
        Some(Err(msg)) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
        None => None,
    };
    match ks_core::select_env(&site.checked.workflow, o.env.as_deref(), event.as_ref()) {
        Ok(ks_core::EnvChoice::Selected(name)) => selected(&o, &site, &name, is_agent, &inputs),
        Ok(ks_core::EnvChoice::Ambiguous(names)) => {
            let offered = names.join(", ");
            if interactive(&o) {
                match prompt(&offered, &names) {
                    Some(name) => selected(&o, &site, &name, is_agent, &inputs),
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
    println!("environment: {env}");
    if o.dry_run {
        // The graph and the check, and nothing else: the promise `check`
        // makes still holds, so it closes the report.
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

    let what = workflow.name().map(str::to_string).unwrap_or_else(|| stem(&site.file));
    let tty = std::io::stdout().is_terminal() && std::env::var("TERM").is_ok_and(|t| t != "dumb");
    let shared = Mutex::new(renderer(tty, o.verbose));
    // Where a run that has to wait is written down, so the job can end and
    // `keepshipping resume` pick it up (#97). Nothing touches the disk unless
    // the run actually parks.
    let parking = resume::Park::new(
        resume::run_id(),
        site.src.as_bytes(),
        o.event.clone().unwrap_or_else(|| "manual".to_string()),
    )
    .with_context(resume::ACTOR, resume::actor_word(actor))
    .with_context(resume::ENVIRONMENT, env);
    let mut approver: Box<dyn drive::Approver> = if is_agent {
        // An agent's run parks at its first approval: it may not answer its
        // own. Who to tell comes from the approval's own `ask:`; until that is
        // read here, the run waits without naming anyone.
        Box::new(drive::AgentRun { notified: None, parking })
    } else if interactive(o) {
        Box::new(drive::TtyApprover::new(std::io::stdin().lock()))
    } else {
        // Nobody watching: the run parks rather than declines, and the job
        // ends instead of holding a runner open until it times out (#97).
        Box::new(drive::Unwatched(parking))
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
    match outcome {
        Outcome::Shipped => ExitCode::SUCCESS,
        // Waiting is not failing: the run parked at an approval, which is the
        // engine's own exit 4, and the notice says what carries it on.
        Outcome::Waiting { run, step, on } => resume::park_notice(&run, &step, &on),
        Outcome::Declined | Outcome::Failed => ExitCode::from(1),
    }
}

/// The renderer the run's lines go through: animated at a terminal, plain
/// everywhere else.
fn renderer(tty: bool, verbose: bool) -> Box<dyn Renderer + Send> {
    // `Stdout` is `Send`, `StdoutLock` is not: the ticker thread holds the
    // renderer behind a lock of its own.
    Box::new(progress::Run::new(std::io::stdout(), verbose, tty))
}

/// The file's name without its extension, for a file that names no workflow.
fn stem(file: &Path) -> String {
    file.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.to_string_lossy().into_owned())
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
fn interactive(o: &Options) -> bool {
    std::io::stdin().is_terminal() && !o.non_interactive && std::env::var_os("CI").is_none()
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
