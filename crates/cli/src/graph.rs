//! The `graph` subcommand: the plan — what the file would do, in what order,
//! and what this environment would skip — printed without running anything
//! ([#40](https://github.com/Keep-Shipping/harness/issues/40)).
//!
//! Like `check`, it reads the file and nothing else, so it keeps the same
//! exit codes and the same promise: a file with errors is reported as `check`
//! reports it and exits 1, and no step ever runs.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use ks_core::{EnvChoice, Trigger, Workflow};
use ks_engine::plan::{Gate, Plan, PlanCtx, PlannedStep};

use crate::args::{Command, Options, USAGE, parse_args};
use crate::{check, render};

/// How `graph` prints the plan. `text` is for people; `dot` is Graphviz and
/// `json` is the machine form. The names are the file's, not `check`'s:
/// `human|json|github` describe diagnostics, which `graph` only ever shows
/// when the file does not check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphFormat {
    Text,
    Dot,
    Json,
}

impl GraphFormat {
    pub(crate) fn parse(text: &str) -> Option<GraphFormat> {
        Some(match text {
            "text" => GraphFormat::Text,
            "dot" => GraphFormat::Dot,
            "json" => GraphFormat::Json,
            _ => return None,
        })
    }
}

/// The `--format` `graph` defaults to.
pub const DEFAULT: GraphFormat = GraphFormat::Text;

pub fn graph(args: &[String]) -> ExitCode {
    let Some(o) = parse_args(args, Command::Graph) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let path = o.path.as_deref().unwrap_or("ship.ks");
    let site = match check::load(
        Path::new(path),
        path,
        o.actor,
        o.path.is_none(),
        crate::args::context_of(&o),
    ) {
        Ok(site) => site,
        Err(code) => return code,
    };
    let diags = &site.checked.diagnostics;
    if !diags.is_empty() {
        // `dot` and `json` own stdout, so a parseable stream stays parseable
        // and the diagnostics go to stderr — the same exit code either way.
        if o.graph_format == GraphFormat::Text {
            let mut out = io::stdout().lock();
            let _ = render::human(&mut out, path, &site.src, diags, render::use_color());
        } else {
            let mut err = io::stderr().lock();
            let _ = render::human(&mut err, path, &site.src, diags, render::use_color());
        }
    }
    if check::fails(&o, diags) {
        return ExitCode::from(1);
    }
    let event = match o.event.as_deref() {
        Some(text) => match crate::parse_event(text) {
            Ok(event) => Some(event),
            Err(msg) => {
                eprintln!("error: {msg}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    // An event no trigger reaches would print a route no run takes.
    if let Some(event) = event.as_ref()
        && let Err(msg) = reached(&site.checked.workflow, event)
    {
        eprintln!("error: {msg}");
        return ExitCode::from(2);
    }
    let env = match selected_env(&o, &site, event.as_ref()) {
        Ok(env) => env,
        Err(code) => return code,
    };
    let ctx = PlanCtx { env: env.clone(), event: event.map(|t| t.kind) };
    let plan = Plan::new(&site.checked.workflow, &ctx);
    let mut out = io::stdout().lock();
    let _ = match o.graph_format {
        GraphFormat::Text => text(&mut out, path, &plan),
        GraphFormat::Dot => dot(&mut out, &plan),
        GraphFormat::Json => json(&mut out, path, &plan),
    };
    ExitCode::SUCCESS
}

/// The environment the plan is for: the request wins, then the event, then a
/// file that declares one environment. `graph` never prompts — a listing has
/// no business asking a question of a pipe.
fn selected_env(
    o: &Options,
    site: &check::Site,
    event: Option<&ks_core::Trigger>,
) -> Result<String, ExitCode> {
    match ks_core::select_env(&site.checked.workflow, o.env.as_deref(), event) {
        Ok(EnvChoice::Selected(name)) => Ok(name),
        Ok(EnvChoice::Ambiguous(names)) => {
            let offered = names.join(", ");
            eprintln!(
                "error: this file declares several environments ({offered}); pass --env <name>"
            );
            Err(ExitCode::from(2))
        }
        Err(d) => {
            eprintln!("error: {}", d.message);
            for hint in &d.hints {
                eprintln!("  hint: {hint}");
            }
            Err(ExitCode::from(2))
        }
    }
}

/// Whether the file declares a trigger this event reaches: a plan for an
/// event no `on:` reaches is a route that never runs, printed as if it would.
/// Only the kind is compared — the core matches an environment's triggers
/// against an event, not a file's — so `push` reaches `on: push main`.
fn reached(workflow: &Workflow, event: &Trigger) -> Result<(), String> {
    if workflow.triggers().iter().any(|t| t.kind == event.kind) {
        return Ok(());
    }
    let declared: Vec<String> = workflow
        .triggers()
        .iter()
        .map(|t| match &t.glob {
            Some(glob) => format!("{} {glob}", t.kind.as_str()),
            None => t.kind.as_str().to_string(),
        })
        .collect();
    Err(match declared.is_empty() {
        true => format!(
            "`--event {}` reaches nothing: this file declares no `on:`",
            event.kind.as_str()
        ),
        false => format!(
            "`--event {}` reaches nothing: this file declares `on: {}`",
            event.kind.as_str(),
            declared.join(", ")
        ),
    })
}

/// The sequence numbers of `step`'s dependencies, as step names.
fn deps_of(plan: &Plan, step: &PlannedStep) -> Vec<String> {
    step.deps
        .iter()
        .map(|seq| plan.step(*seq).expect("a plan's dependency is in the plan").name.clone())
        .collect()
}

/// What the gate column says: `run`, why the step is out, or the condition
/// only the run can settle.
fn gate_text(gate: &Gate) -> String {
    match gate {
        Gate::Always => "run".to_string(),
        Gate::Skip { reason } => format!("skip: {reason}"),
        Gate::Runtime { condition } => format!("when: {} (at run time)", condition.source),
    }
}

/// The route: the events that reach the plan, then the steps that would run,
/// in order. Steps ruled out for this environment are not on it. Several
/// events are alternatives, not a chain of steps, so they are separated with
/// `|` rather than by the arrow.
fn route(plan: &Plan) -> String {
    let mut triggers: Vec<&str> = Vec::new();
    for kind in &plan.triggers {
        let name = kind.as_str();
        if !triggers.contains(&name) {
            triggers.push(name);
        }
    }
    let steps: Vec<&str> = plan.running().map(|s| s.name.as_str()).collect();
    match (steps.is_empty(), triggers.is_empty()) {
        // No step to run: the route is the sentence, not a list.
        (true, _) => "route: nothing to run".to_string(),
        // A file with no `on:` has no event to lead with: the steps are the
        // whole route.
        (false, true) => format!("route: {}", steps.join(" → ")),
        (false, false) => format!("route: {} → {}", triggers.join(" | "), steps.join(" → ")),
    }
}

/// The report: one line per step in sequence order, then the route. The
/// columns are as wide as the cells they hold — a header included — so the
/// table reads as a table whatever the file has in it.
fn text(out: &mut impl Write, path: &str, plan: &Plan) -> io::Result<()> {
    let rows: Vec<Vec<String>> = vec![vec![
        "seq".to_string(),
        "step".to_string(),
        "kind".to_string(),
        "deps".to_string(),
        "gate".to_string(),
    ]]
    .into_iter()
    .chain(plan.steps.iter().map(|step| {
        let deps = deps_of(plan, step).join(", ");
        vec![
            step.seq.to_string(),
            step.name.clone(),
            step.kind.as_deref().unwrap_or("—").to_string(),
            if deps.is_empty() { "—".to_string() } else { deps },
            gate_text(&step.gate),
        ]
    }))
    .collect();
    let widths: Vec<usize> = (0..rows[0].len())
        .map(|col| rows.iter().map(|row| row[col].chars().count()).max().unwrap_or(0))
        .collect();
    writeln!(
        out,
        "{path} — {} step{}, env: {}",
        plan.steps.len(),
        if plan.steps.len() == 1 { "" } else { "s" },
        plan.env
    )?;
    for row in &rows {
        let last = row.len() - 1;
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(col, cell)| match col {
                // The gate column ends the line: nothing to line up after it.
                _ if col == last => cell.clone(),
                // Sequence numbers read better right against the header.
                0 => format!("{:>width$}", cell, width = widths[0]),
                _ => format!("{:width$}", cell, width = widths[col]),
            })
            .collect();
        writeln!(out, "{}", cells.join("  "))?;
    }
    writeln!(out)?;
    writeln!(out, "{}", route(plan))?;
    render::footer(out)
}

/// The Graphviz form: a node per step in sequence order, an edge per
/// dependency.
fn dot(out: &mut impl Write, plan: &Plan) -> io::Result<()> {
    writeln!(out, "digraph plan {{")?;
    writeln!(out, "  rankdir=LR;")?;
    for step in &plan.steps {
        let style = if step.gate.is_skipped() { " [style=dashed]" } else { "" };
        writeln!(
            out,
            "  {name} [label=\"{seq} {label}\"]{style};",
            name = dot_quoted(&step.name),
            label = dot_escaped(&step.name),
            seq = step.seq
        )?;
    }
    for step in &plan.steps {
        for dep in deps_of(plan, step) {
            writeln!(
                out,
                "  {dep} -> {name};",
                dep = dot_quoted(&dep),
                name = dot_quoted(&step.name)
            )?;
        }
    }
    writeln!(out, "}}")
}

/// A DOT string in quotes: a name that carries a quote or a backslash must not
/// be able to end the string early.
fn dot_quoted(text: &str) -> String {
    format!("\"{}\"", dot_escaped(text))
}

/// The inside of a DOT string, escaped for the two characters that end one.
fn dot_escaped(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// The machine form: the same plan, with a stable key order. Written out by
/// hand so the keys read in the order they are documented in — a JSON object
/// has no order of its own.
fn json(out: &mut impl Write, path: &str, plan: &Plan) -> io::Result<()> {
    let quoted = |values: Vec<String>| values.join(", ");
    writeln!(out, "{{")?;
    writeln!(out, "  \"version\": 1,")?;
    writeln!(out, "  \"file\": {},", string(path))?;
    writeln!(out, "  \"env\": {},", string(&plan.env))?;
    let triggers: Vec<String> = plan.triggers.iter().map(|t| string(t.as_str())).collect();
    writeln!(out, "  \"triggers\": [{}],", quoted(triggers))?;
    writeln!(out, "  \"steps\": [")?;
    for (i, step) in plan.steps.iter().enumerate() {
        let comma = if i + 1 == plan.steps.len() { "" } else { "," };
        let deps: Vec<String> = deps_of(plan, step).iter().map(|d| string(d)).collect();
        writeln!(
            out,
            "    {{\"seq\": {}, \"name\": {}, \"kind\": {}, \"deps\": [{}], \"gate\": {}}}{comma}",
            step.seq,
            string(&step.name),
            step.kind.as_deref().map_or("null".to_string(), string),
            quoted(deps),
            gate_json(&step.gate),
        )?;
    }
    writeln!(out, "  ]")?;
    writeln!(out, "}}")
}

/// A step's gate as an object: what it is, and why, when there is a why.
fn gate_json(gate: &Gate) -> String {
    match gate {
        Gate::Always => "{\"kind\": \"run\"}".to_string(),
        Gate::Skip { reason } => format!("{{\"kind\": \"skip\", \"reason\": {}}}", string(reason)),
        Gate::Runtime { condition } => {
            format!("{{\"kind\": \"runtime\", \"when\": {}}}", string(&condition.source))
        }
    }
}

/// A JSON string, escaped by serde_json so no name or condition can break
/// out of the object it sits in.
fn string(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_string())
}
