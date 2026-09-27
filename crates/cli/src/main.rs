//! The `keepshipping` command-line interface: `check` type-checks a site
//! file; `run` picks an environment and hands off to the engine.

#![forbid(unsafe_code)]

use std::io::{IsTerminal, Write as _};
use std::process::ExitCode;

use ks_core::ports::run_context::ActorKind;
use ks_core::{Trigger, TriggerKind};
use ks_lang::Diagnostic;

const USAGE: &str = concat!(
    "usage: keepshipping <check|run> [FILE]",
    " [--env NAME] [--event \"push main\"] [--actor human|agent|ci]",
    " [--secrets] [--non-interactive]"
);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check") => check(&args[1..]),
        Some("run") => run(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

struct Options {
    file: String,
    env: Option<String>,
    event: Option<String>,
    /// The actor the command would run as; a human unless `--actor` says
    /// otherwise. Policy rules that bind the actor are enforced at check
    /// time.
    actor: ActorKind,
    secrets: bool,
    non_interactive: bool,
}

/// `--secrets` belongs to `check` alone; `run` rejects it as the unknown
/// flag it is there, like any other unrecognized option.
fn parse_args(args: &[String], secrets: bool) -> Option<Options> {
    let mut o = Options {
        file: "ship.ks".into(),
        env: None,
        event: None,
        actor: ActorKind::Human,
        secrets: false,
        non_interactive: false,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--env" => o.env = Some(flag_value(&mut rest)?),
            "--event" => o.event = Some(flag_value(&mut rest)?),
            "--actor" => o.actor = actor_kind(&flag_value(&mut rest)?)?,
            "--secrets" if secrets => o.secrets = true,
            "--non-interactive" => o.non_interactive = true,
            flag if flag.starts_with('-') => return None,
            file => o.file = file.to_string(),
        }
    }
    Some(o)
}

/// `--actor human|agent|ci`; anything else is a usage error.
fn actor_kind(text: &str) -> Option<ActorKind> {
    match text {
        "human" => Some(ActorKind::Human),
        "agent" => Some(ActorKind::Agent),
        "ci" => Some(ActorKind::Ci),
        _ => None,
    }
}

/// The value after `--env`/`--event`/`--actor`. A missing value, or another
/// flag where a value belongs, is a usage error instead of a silently
/// swallowed option.
fn flag_value(rest: &mut std::slice::Iter<'_, String>) -> Option<String> {
    let value = rest.next()?;
    (!value.starts_with('-')).then(|| value.clone())
}

/// Parse and check `file`, printing every diagnostic as
/// `file:line:col: severity: message`. Fails when the file cannot be read.
/// The check runs as `actor`, so a policy rule binding the actor refuses the
/// file before any run could start.
fn load(file: &str, actor: ActorKind) -> Option<(String, ks_core::Checked)> {
    let src = match std::fs::read_to_string(file) {
        Ok(src) => src,
        Err(e) => {
            eprintln!("error: {file}: {e}");
            return None;
        }
    };
    let catalog = ks_core::Catalog::builtin();
    let options = ks_core::CheckOptions::new(&catalog).actor(actor);
    let checked = ks_core::check_with(&ks_lang::parse(&src), &options);
    let lines = Lines::new(&src);
    for d in &checked.diagnostics {
        let (line, col) = lines.line_col(&src, d.span.start);
        report(file, line, col, d);
    }
    Some((src, checked))
}

fn report(file: &str, line: usize, col: usize, d: &Diagnostic) {
    eprintln!("{file}:{line}:{col}: {}: {}", d.severity.as_str(), d.message);
    if let Some(hint) = &d.hint {
        eprintln!("  hint: {hint}");
    }
}

/// The line starts of a source file, built once: each diagnostic's position
/// is then a binary search plus one short char count, instead of a rescan of
/// the whole file per diagnostic.
struct Lines {
    starts: Vec<u32>,
}

impl Lines {
    fn new(src: &str) -> Self {
        let mut starts: Vec<u32> = src
            .bytes()
            .enumerate()
            .filter(|&(_, b)| b == b'\n')
            .map(|(i, _)| i as u32 + 1)
            .collect();
        starts.insert(0, 0);
        Self { starts }
    }

    /// The 1-based line and column of a byte offset.
    fn line_col(&self, src: &str, offset: u32) -> (usize, usize) {
        let offset = (offset as usize).min(src.len()) as u32;
        let line = self.starts.partition_point(|&s| s <= offset) - 1;
        let col = src[self.starts[line] as usize..offset as usize].chars().count() + 1;
        (line + 1, col)
    }
}

fn check(args: &[String]) -> ExitCode {
    let Some(o) = parse_args(args, true) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some((_, checked)) = load(&o.file, o.actor) else { return ExitCode::from(2) };
    // The listing comes after the diagnostics and does not soften the exit
    // code: a file with errors is still a failed check.
    if o.secrets {
        print_secrets(&checked);
    }
    if has_errors(&checked) {
        ExitCode::from(1)
    } else {
        println!("{}: ok ({} steps)", o.file, checked.workflow.steps().len());
        ExitCode::SUCCESS
    }
}

/// The `--secrets` listing: per environment, the secret references its
/// resolver must serve and the steps that need them. Purely a projection of
/// the checked file — no resolver is ever constructed and no store, env var
/// or backend is read, so the listing is safe to run anywhere.
fn print_secrets(checked: &ks_core::Checked) {
    for env in ks_core::secret_requirements(checked) {
        if env.requirements.is_empty() {
            println!("{}: (none)", env.env);
            continue;
        }
        for r in env.requirements {
            let steps = r.steps.join(", ");
            match &r.reference {
                Some(reference) => println!("{}: {reference} ({steps})", env.env),
                None => println!("{}: {} ({steps}) [no `secrets:` resolver]", env.env, r.key),
            }
        }
    }
}

fn has_errors(checked: &ks_core::Checked) -> bool {
    checked.diagnostics.iter().any(|d| matches!(d.severity, ks_lang::Severity::Error))
}

fn run(args: &[String]) -> ExitCode {
    let Some(o) = parse_args(args, false) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some((_, checked)) = load(&o.file, o.actor) else { return ExitCode::from(2) };
    if has_errors(&checked) {
        return ExitCode::from(1);
    }
    let event = match o.event.as_deref().map(parse_event) {
        Some(Ok(t)) => Some(t),
        Some(Err(msg)) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
        None => None,
    };
    match ks_core::select_env(&checked.workflow, o.env.as_deref(), event.as_ref()) {
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
            if let Some(hint) = &d.hint {
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
