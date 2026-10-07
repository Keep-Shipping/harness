//! The `keepshipping` command-line interface: `check` type-checks a site
//! file (or, with `--all`, every `ship.ks` in a tree); `run` picks an
//! environment and hands off to the engine; `graph` prints the plan the file
//! would follow, without running it. Output formats, exit codes and colour
//! rules are pinned in `docs/DIAGNOSTICS.md`.

#![forbid(unsafe_code)]

mod args;
mod blocks;
mod blocks_index;
mod check;
mod drive;
// The GitHub Actions run context (#150) is built and tested here, but the
// command dispatch still has no run context to hand it: wiring CI-versus-local
// selection into `run` waits for the local adapter. Until then nothing in the
// binary names this module.
#[allow(dead_code)]
mod github_actions_run_context;
mod graph;
mod http_client;
mod log;
mod progress;
mod render;
mod run_log;
mod upgrade;

use std::io::{IsTerminal, Write as _};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::Instant;

use ks_core::{ContextName, Step, Trigger, TriggerKind};

use crate::args::{Command, Options, USAGE, context_of, parse_args};
use crate::drive::{Done, Outcome, StepRunner};
use crate::progress::Renderer;

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
        Some("fmt") => upgrade::fmt(&args[1..]),
        Some("graph") => graph::graph(&args[1..]),
        Some("blocks") => blocks::blocks(&args[1..]),
        Some("lsp") => ks_lsp::serve(),
        Some("log") => log::log(&args[1..]),
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
    let path = o.path.as_deref().unwrap_or("ship.ks");
    let context = context_of(&o);
    let site = match check::load(Path::new(path), path, o.actor, o.path.is_none(), context) {
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
        Ok(ks_core::EnvChoice::Selected(name)) => selected(&o, &site, &name),
        Ok(ks_core::EnvChoice::Ambiguous(names)) => {
            let offered = names.join(", ");
            if interactive(&o) {
                match prompt(&offered, &names) {
                    Some(name) => selected(&o, &site, &name),
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
fn selected(o: &Options, site: &check::Site, env: &str) -> ExitCode {
    println!("environment: {env}");
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
        let _ = render::footer(&mut out);
        return ExitCode::SUCCESS;
    }

    let what = workflow.name().map(str::to_string).unwrap_or_else(|| stem(&site.file));
    let tty = std::io::stdout().is_terminal() && std::env::var("TERM").is_ok_and(|t| t != "dumb");
    let shared = Mutex::new(renderer(tty, o.verbose));
    let mut approver: Box<dyn drive::Approver> = if interactive(o) {
        Box::new(drive::TtyApprover::new(std::io::stdin().lock()))
    } else {
        Box::new(drive::Declines)
    };
    let started = Instant::now();
    let outcome = drive::with_spinner(tty, &shared, |renderer| {
        drive::drive(
            &steps,
            &mut Unbuilt,
            approver.as_mut(),
            renderer,
            &mut || started.elapsed(),
            &what,
        )
    });
    if outcome == Outcome::Shipped { ExitCode::SUCCESS } else { ExitCode::from(1) }
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

/// No step kind is executable yet: the engine's built-in steps are still
/// empty, so a run stops on its first step and says why. That is the honest
/// report — a run that claimed to have shipped would not have.
struct Unbuilt;

impl StepRunner for Unbuilt {
    fn run(&mut self, step: &Step, _log: &mut dyn FnMut(&str)) -> Result<Done, String> {
        let kind = step.kind.as_deref().unwrap_or("steps");
        Err(format!("`{kind}` steps are not built in yet"))
    }
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
    let ctx = context.context();
    // `site.unmet` came from the check that already printed the warnings, so
    // the gate agrees with them rather than re-asking the catalog.
    let Some(step) = site.unmet.iter().find(|s| selected.contains(&s.name)) else {
        return Ok(());
    };
    // Counted in run order, like `--until` and the warning's own stop point.
    let order = ks_core::run_order(&site.checked.workflow);
    let at = order.iter().position(|n| *n == step.name).unwrap_or(order.len()) + 1;
    if o.allow_partial {
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
