//! The `keepshipping` command-line interface: `check` type-checks a site
//! file (or, with `--all`, every `ship.ks` in a tree); `run` picks an
//! environment and hands off to the engine. Output formats, exit codes and
//! colour rules are pinned in `docs/DIAGNOSTICS.md`.

#![forbid(unsafe_code)]

mod args;
mod blocks;
mod blocks_index;
mod check;
// The GitHub Actions run context (#150) is built and tested here, but the
// command dispatch still has no run context to hand it: wiring CI-versus-local
// selection into `run` waits for the local adapter. Until then nothing in the
// binary names this module.
#[allow(dead_code)]
mod github_actions_run_context;
mod http_client;
mod render;
mod upgrade;

use std::io::{IsTerminal, Write as _};
use std::path::Path;
use std::process::ExitCode;

use ks_core::{ContextName, Trigger, TriggerKind};

use crate::args::{Command, Options, USAGE, context_of, parse_args};

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
        Some("blocks") => blocks::blocks(&args[1..]),
        Some("lsp") => ks_lsp::serve(),
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
        Ok(ks_core::EnvChoice::Selected(name)) => selected(&name),
        Ok(ks_core::EnvChoice::Ambiguous(names)) => {
            let offered = names.join(", ");
            if interactive(&o) {
                match prompt(&offered, &names) {
                    Some(name) => selected(&name),
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

fn selected(name: &str) -> ExitCode {
    println!("environment: {name}");
    println!("execution is not implemented yet (ks-engine)");
    ExitCode::SUCCESS
}

/// The steps a run would take, in run order: up to and including `--until`,
/// less every `--skip`. A name the file does not declare is a usage error —
/// a typo must not quietly widen the run.
fn selection(site: &check::Site, o: &Options) -> Result<Vec<String>, Box<str>> {
    let steps = ks_core::run_order(&site.checked.workflow);
    for name in o.skip.iter().chain(o.until.iter()) {
        if !steps.contains(&name.as_str()) {
            return Err(format!("no step named `{name}`").into());
        }
    }
    let until = o
        .until
        .as_deref()
        .and_then(|name| steps.iter().position(|s| *s == name))
        .map(|at| at + 1)
        .unwrap_or(steps.len());
    Ok(steps[..until]
        .iter()
        .filter(|s| !o.skip.iter().any(|k| k == *s))
        .map(|s| (*s).to_string())
        .collect())
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

fn parse_event(text: &str) -> Result<Trigger, String> {
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
