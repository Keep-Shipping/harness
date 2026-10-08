//! The `keepshipping` command-line interface: `check` type-checks a site
//! file (or, with `--all`, every `ship.ks` in a tree); `run` picks an
//! environment and hands off to the engine; `graph` prints the plan the file
//! would follow, without running it; `fmt` rewrites files into their canonical
//! form. Output formats, exit codes and colour rules are pinned in
//! `docs/DIAGNOSTICS.md`.

#![forbid(unsafe_code)]

mod args;
mod blocks;
mod blocks_index;
mod check;
mod drive;
mod exit;
mod fmt;
// The GitHub Actions run context (#150) is built and tested here, but the
// command dispatch still has no run context to hand it: wiring CI-versus-local
// selection into `run` waits for the local adapter. Until then nothing in the
// binary names this module.
#[allow(dead_code)]
mod github_actions_run_context;
mod graph;
mod log;
mod progress;
mod render;
mod run_id;
mod run_log;
mod upgrade;

use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::Instant;

use ks_core::ports::run_context::ActorKind;
use ks_core::{ContextName, Step, Trigger, TriggerKind};
// The binary shares the adapter with the OCI distribution crate's tests, which
// link this package as a library; the module is declared once, in `lib.rs`.
use ks_cli::http_client;
#[cfg(test)]
use ks_cli::test_server;

use crate::args::{Command, Options, USAGE, context_of, parse_args};
use crate::drive::{Done, StepRunner};
use crate::progress::Renderer;

fn main() -> ExitCode {
    // A panic is a bug in keepshipping, not a problem with the user's file:
    // say so plainly and exit 3, not the Rust default 101.
    std::panic::set_hook(Box::new(|info| eprintln!("internal error: {info}")));
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(dispatch)) {
        Ok(code) => code,
        Err(_) => ExitCode::from(exit::INTERNAL),
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
    let json = o.format == render::Format::Json;
    let diags = &site.checked.diagnostics;
    if !diags.is_empty() {
        let mut out = report_out(json);
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

/// Where a report written for people goes: stdout for one, and stderr in a
/// JSON run, whose stdout is the stream and nothing else. Still rendered for
/// people either way — only the destination moves.
fn report_out(json: bool) -> Box<dyn Write> {
    if json { Box::new(std::io::stderr()) } else { Box::new(std::io::stdout()) }
}

/// The environment is chosen: print the run the file describes, and run it.
fn selected(o: &Options, site: &check::Site, env: &str) -> ExitCode {
    // A JSON run's stdout is the stream and nothing else: the human banner
    // becomes the `run.started` line, so a reader never has to skip a line.
    let json = o.format == render::Format::Json;
    if !json {
        println!("environment: {env}");
    }
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
        let mut out = report_out(json);
        for step in &steps {
            let _ = writeln!(
                out,
                "{}",
                progress::kind_line(&step.name, step.kind.as_deref().unwrap_or("step"))
            );
        }
        let _ = render::footer(&mut out);
        return ExitCode::from(exit::SHIPPED);
    }

    let what = workflow.name().map(str::to_string).unwrap_or_else(|| stem(&site.file));
    // A dry run has no id to report and nothing to be found later; a real one
    // does, and every line of its output carries it.
    let run_id = run_id::mint();
    let teams = approval_teams(&site.src);
    let run = drive::RunInfo { what: &what, id: &run_id, teams: &teams };
    let tty = std::io::stdout().is_terminal() && std::env::var("TERM").is_ok_and(|t| t != "dumb");
    let shared = Mutex::new(renderer(tty, o.verbose, json, &run_id, env));
    let mut approver: Box<dyn drive::Approver> = if interactive(o) {
        Box::new(drive::TtyApprover::new(std::io::stdin().lock()))
    } else {
        Box::new(drive::Declines)
    };
    let started = Instant::now();
    let outcome = drive::with_spinner(tty && !json, &shared, |renderer| {
        drive::drive(
            &steps,
            &mut Unbuilt,
            approver.as_mut(),
            renderer,
            &mut || started.elapsed(),
            &run,
        )
    });
    ExitCode::from(outcome.exit_code())
}

/// The `from:` handle of each `approval` step, by step name. Read off the
/// parse tree the way `check` reads the Dockerfiles an image step names: the
/// workflow's steps carry their kind but not their inputs, so the handle only
/// exists here in the source.
fn approval_teams(src: &str) -> HashMap<String, String> {
    let parse = ks_lang::parse(src);
    let mut teams = HashMap::new();
    for entry in parse.file().entries().filter(|e| e.key_name() == Some("steps")) {
        for step in entry.children() {
            // Only an approval carries a team; `oci.image`'s `from:` is a path.
            if step.expr().as_ref().and_then(handle) != Some("approval") {
                continue;
            }
            let Some(from) = step.children().find(|i| i.key_name() == Some("from")) else {
                continue;
            };
            let team_expr = from.expr();
            let Some(team) = team_expr.as_ref().and_then(handle) else { continue };
            if let Some(name) = step.key_name() {
                teams.insert(name.to_string(), team.to_string());
            }
        }
    }
    teams
}

/// A bare `@handle`, the one word an expression is when it is a handle at all.
/// An approval that names no team has none, and its team is reported as null.
fn handle<'a>(expr: &'a ks_lang::Expr<'a>) -> Option<&'a str> {
    match expr {
        ks_lang::Expr::Atom { atom: ks_lang::Atom::Word(w), .. } => {
            let text = w.text();
            text.starts_with('@').then_some(text)
        }
        _ => None,
    }
}

/// The renderer the run's lines go through: JSON Lines where a tool is
/// reading, and the animated-at-a-terminal, plain-everywhere-else report
/// otherwise.
fn renderer(
    tty: bool,
    verbose: bool,
    json: bool,
    run_id: &ks_core::ids::RunId,
    env: &str,
) -> Box<dyn Renderer + Send> {
    // `Stdout` is `Send`, `StdoutLock` is not: the ticker thread holds the
    // renderer behind a lock of its own.
    if json {
        return Box::new(progress::Json::new(std::io::stdout(), run_id, env));
    }
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
/// `--actor agent` never asks: an agent cannot answer an approval, so it
/// waits for a person instead of blocking on a prompt nobody will ever see.
/// `--format json` never asks either — a prompt on stdout would be a line a
/// JSON reader cannot parse — so an ambiguous file is the usage error it is
/// everywhere else without one.
fn interactive(o: &Options) -> bool {
    o.actor != ActorKind::Agent
        && o.format != render::Format::Json
        && std::io::stdin().is_terminal()
        && !o.non_interactive
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
