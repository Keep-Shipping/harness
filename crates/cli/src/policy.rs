//! `keepshipping policy explain`: what this file's policy allows, for one
//! actor, with every row attributed to the document that decided it
//! ([#101](https://github.com/Keep-Shipping/harness/issues/101), [ADR
//! 0012](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0012-policy-authority.md)).
//!
//! Offline — it reads the site file and nothing else — so it shares `check`'s
//! loading path and exit codes. The first line states whether a baseline is
//! configured; there is no `PolicyStore` adapter yet, so it always says no.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use ks_core::ports::policy::{ANY_OBJECT, Disposition};
use ks_core::ports::run_context::ActorKind;
use ks_core::step::{ActionClass, ActionKind};
use ks_core::{PolicyDecision, PolicySource, action_kind, action_of, decide_policy_with_base};

use crate::args::{Command, USAGE, context_of, parse_args};
use crate::{base_policy, check, render};

/// The first line of every `explain`. ADR 0012 makes "no baseline configured" a
/// first-class state and saying so up front an acceptance criterion.
const NO_BASELINE: &str = "no baseline configured: the effective policy is this file's own policy";

/// Today `explain` is the only subcommand.
pub fn policy(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("explain") => explain(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn explain(args: &[String]) -> ExitCode {
    let Some(o) = parse_args(args, Command::PolicyExplain) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    // The same loader `check` uses, with the same actor: a file this actor may
    // not run is a file `explain` has something to say about.
    let path = o.path.as_deref().unwrap_or("ship.ks");
    let site = match check::load(Path::new(path), path, o.actor, o.path.is_none(), context_of(&o)) {
        Ok(site) => site,
        Err(code) => return code,
    };
    let diags = &site.checked.diagnostics;
    if !diags.is_empty() {
        let mut out = io::stdout().lock();
        let _ = render::human(&mut out, path, &site.src, diags, render::use_color());
    }
    // Explaining a file that does not check explains a policy nobody can run.
    if check::fails(&o, diags) {
        return ExitCode::from(1);
    }
    let envs = site.checked.workflow.envs();
    let env = match o.env.as_deref() {
        Some(requested) => match envs.iter().find(|e| e.name == requested) {
            Some(found) => Some(found.name.clone()),
            None => {
                let declared: Vec<&str> = envs.iter().map(|e| e.name.as_str()).collect();
                eprintln!(
                    "error: unknown environment `{requested}`; declared: {}",
                    declared.join(", ")
                );
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let base = match base_policy::read(&site.file, o.base.as_deref()) {
        Ok(base) => base,
        Err(why) => {
            eprintln!("error: --base {why}");
            return ExitCode::from(2);
        }
    };
    let mut out = io::stdout().lock();
    if let Err(e) = report(&mut out, &site, o.actor, env.as_deref(), base.as_ref()) {
        eprintln!("error: writing the report failed ({e})");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// One row per step, plus the `destroy` face of every `apply`.
fn report(
    out: &mut impl Write,
    site: &check::Site,
    actor: ActorKind,
    env: Option<&str>,
    base: Option<&base_policy::Base>,
) -> io::Result<()> {
    // A file without `envs:` still classifies, against the implicit `default`.
    let workflow = &site.checked.workflow;
    let policy = workflow.policy();
    // A file without `envs:` still classifies, against the implicit `default`.
    let envs: Vec<String> = workflow.envs().iter().map(|e| e.name.clone()).collect();
    let lines = render::Lines::new(&site.src);
    let source = |d: &PolicyDecision| source_cell(d, &site.path, &site.src, &lines);
    // The decision every row below is attributed to: the file as it stands,
    // folded against the default branch's copy. A base that could not be read
    // is no base, and the fold leaves the file's own answer alone.
    let upstream = base.map(|b| &b.policy);
    let decide =
        |class: &ActionClass| decide_policy_with_base(policy, upstream, None, actor, class);
    let mut rows: Vec<[String; 4]> = vec![[
        "step".to_string(),
        "action".to_string(),
        "decision".to_string(),
        "source".to_string(),
    ]];
    for step in workflow.steps() {
        let kind = action_kind(step.kind.as_deref().unwrap_or(""));
        if kind == ActionKind::Other {
            // Not policy-governed, but still a row: every step in the file
            // appears in the table.
            rows.push([
                step.name.clone(),
                "—".to_string(),
                "not governed".to_string(),
                "—".to_string(),
            ]);
            continue;
        }
        let base = ActionClass::new(kind);
        for class in faces(&base, env, &envs, policy, upstream, actor) {
            let Some(decision) = decide(&class) else { continue };
            rows.push([
                step.name.clone(),
                action_cell(&class),
                decision_cell(&decision),
                source(&decision),
            ]);
        }
        // `destroy` is read from the plan, not the header, so at explain time
        // the plan is unknown: the reclassification is possible, not a fact.
        // The `*` says so, and the footnote under the table spells it out.
        if kind == ActionKind::Apply {
            for class in faces(&base.with_plan_destroys(1), env, &envs, policy, upstream, actor) {
                let Some(decision) = decide(&class) else { continue };
                rows.push([
                    String::new(),
                    format!("{}*", action_cell(&class)),
                    decision_cell(&decision),
                    source(&decision),
                ]);
            }
        }
    }

    writeln!(out, "{NO_BASELINE}")?;
    match base {
        Some(base) if base.has_file => writeln!(
            out,
            "default branch {}: this file may narrow its policy, never widen it",
            base.git_ref
        )?,
        // A base that resolved but has no copy of this file is not a permissive
        // base, and saying only "this file may narrow" would read like one.
        Some(base) => writeln!(
            out,
            "default branch {} has no copy of this file: nothing it grants takes effect",
            base.git_ref
        )?,
        None => writeln!(
            out,
            "no default branch policy read: the effective policy is this file's own policy"
        )?,
    }
    match env {
        Some(name) => writeln!(out, "{} — actor: {}, env: {name}", site.path, actor_name(actor))?,
        None => writeln!(out, "{} — actor: {}", site.path, actor_name(actor))?,
    }
    writeln!(out)?;
    // The columns are as wide as the cells they hold, header included, so the
    // table reads as a table whatever the file has in it.
    let widths: [usize; 4] =
        [0, 1, 2, 3].map(|col| rows.iter().map(|r| r[col].chars().count()).max().unwrap_or(0));
    for row in &rows {
        let cells: Vec<String> =
            (0..4).map(|col| format!("{:width$}", row[col], width = widths[col])).collect();
        writeln!(out, "{}", cells.join("  ").trim_end())?;
    }
    // Only when the file has an apply step that produced the marked row.
    if rows.iter().any(|r| r[1].ends_with('*')) {
        writeln!(out)?;
        writeln!(out, "* an apply whose plan destroys or replaces anything is a destroy")?;
    }
    writeln!(out)?;
    render::footer(out)
}

/// One row per environment the decision differs in, or a single env-less row
/// when they all agree — that class decides too, and a run is always in one.
fn faces(
    base: &ActionClass,
    env: Option<&str>,
    envs: &[String],
    policy: &ks_core::Policy,
    upstream: Option<&ks_core::Policy>,
    actor: ActorKind,
) -> Vec<ActionClass> {
    if let Some(name) = env {
        return vec![base.clone().in_env(name)];
    }
    if envs.is_empty() {
        return vec![base.clone()];
    }
    let per_env: Vec<ActionClass> = envs.iter().map(|name| base.clone().in_env(name)).collect();
    let decides =
        |class: &ActionClass| decide_policy_with_base(policy, upstream, None, actor, class);
    let agrees = per_env.windows(2).all(|w| decides(&w[0]) == decides(&w[1]))
        && per_env.first().is_some_and(|c| decides(c) == decides(base));
    if agrees { vec![base.clone()] } else { per_env }
}

/// The verb, plus the environment or object it names; `*` is no name a reader
/// needs to see.
fn action_cell(class: &ActionClass) -> String {
    match action_of(class) {
        Some((verb, object)) if object != ANY_OBJECT => format!("{verb} {object}"),
        Some((verb, _)) => verb.to_string(),
        None => "—".to_string(),
    }
}

/// `can`, `ask @platform`, or `never`.
fn decision_cell(decision: &PolicyDecision) -> String {
    match decision.disposition {
        Disposition::Allow => "can".to_string(),
        Disposition::Ask => {
            let handles: Vec<String> = decision.ask.iter().map(|h| format!("@{h}")).collect();
            if handles.is_empty() {
                "ask a human".to_string()
            } else {
                format!("ask {}", handles.join(", "))
            }
        }
        Disposition::Never => "never".to_string(),
    }
}

/// Which document decided, and where in it, so "who widened this" is answerable
/// without git history (ADR 0012).
fn source_cell(decision: &PolicyDecision, path: &str, src: &str, lines: &render::Lines) -> String {
    match decision.source {
        PolicySource::File => match decision.rule_span {
            Some(span) => format!("file {}:{}", path, lines.line_col(src, span.start).0),
            None => "file".to_string(),
        },
        other => other.as_str().to_string(),
    }
}

fn actor_name(actor: ActorKind) -> &'static str {
    match actor {
        ActorKind::Human => "human",
        ActorKind::Agent => "agent",
        ActorKind::Ci => "ci",
    }
}

/// What the effective policy says about a run before it starts
/// ([#118](https://github.com/Keep-Shipping/harness/issues/118)).
///
/// `before:` and `can:` are inert at run time today — a run waits only at an
/// explicit `approval` step — and this is where the default branch's half of
/// the policy starts to bite. A step the effective policy refuses is refused
/// (exit 5), the way a `never:` already is. A step it asks about is a wait
/// (exit 4), the way an approval is: the run writes itself down and a human
/// carries it on.
///
/// One ask is deliberately not a wait: [`PolicySource::Default`], the leash
/// nobody wrote down. Every action an agent takes is an ask unless some
/// document named it, and reading the leash as "no run may ever start" would
/// stop every run in every repository that has no policy at all. The leash is
/// enforced where it belongs — in `check` and in what the run may do, not in
/// whether it may begin. It is only ever the file's own silence that reads as
/// the leash: when the default branch is the one declining to grant something,
/// [`PolicySource::DefaultBranch`] says so and the run waits.
///
/// Two things this does not decide, deliberately. The org baseline is not
/// consulted here — there is no `PolicyStore` adapter yet, so a run starts
/// against the file and the default branch alone, and resume's own engine gate
/// re-checks with the conservative built-in baseline where one exists. And a
/// plan's `destroy` face is not decided here: whether an apply destroys is
/// read out of the plan, which does not exist at run start, so the engine
/// decides it at apply time.
pub enum Gate {
    /// The run will not start: this step is `never` under the effective
    /// policy.
    Refused { step: String, why: String },
    /// The run stops here and waits for a human, as at an `approval` step.
    Wait { step: String, why: String },
}

/// Walks `steps` in run order and returns the first thing that stops the run.
///
/// The faces are the ones `explain` shows: a step's own actions, plus the
/// `read secrets` face of every step the file resolves a secret for — a step
/// nobody named is still a step a policy can refuse.
pub fn gate(
    workflow: &ks_core::Workflow,
    steps: &[&ks_core::Step],
    base: Option<&ks_core::Policy>,
    secret_uses: &[ks_core::SecretUse],
    actor: ActorKind,
    env: &str,
) -> Option<Gate> {
    let policy = workflow.policy();
    // Two passes, because a refusal anywhere beats a wait found first: a step
    // whose apply is asked about and whose secrets read is refused has to be
    // refused, or the run would park on the softer half of the answer.
    let mut waiting = None;
    for refusal_only in [true, false] {
        for step in steps {
            let needs_secrets = secret_uses.iter().any(|use_| use_.step == step.name);
            let mut classes = step.actions.clone();
            // A step the catalog could not classify still answers to the rule
            // about secrets when it reads one.
            if classes.is_empty() && needs_secrets {
                classes.push(ActionClass::new(ActionKind::Other));
            }
            if needs_secrets {
                classes.push(ActionClass::new(ActionKind::ReadSecrets));
            }
            for class in classes {
                // A deploy or destroy in the environment this run resolved: the
                // class the run will report, which is the one the rules name.
                let class = match class.kind {
                    ActionKind::Deploy | ActionKind::Destroy if class.env.is_none() => {
                        class.clone().in_env(env)
                    }
                    _ => class,
                };
                let Some(decision) = decide_policy_with_base(policy, base, None, actor, &class)
                else {
                    continue;
                };
                let Some((verb, object)) = action_of(&class) else { continue };
                let named = if object == ANY_OBJECT {
                    verb.to_string()
                } else {
                    format!("{verb} {object}")
                };
                let why = format!(
                    "`{named}` is {} for {} ({}){}",
                    verb_word(&decision),
                    actor_name(actor),
                    decision.source,
                    // The rule's own `ask:`, so the notice names who the
                    // default branch said to ask rather than only that there
                    // is somebody to ask.
                    if decision.ask.is_empty() {
                        String::new()
                    } else {
                        let handles: Vec<String> =
                            decision.ask.iter().map(|who| format!("@{who}")).collect();
                        format!(" — ask {}", handles.join(", "))
                    }
                );
                match decision.disposition {
                    Disposition::Never => {
                        return Some(Gate::Refused { step: step.name.clone(), why });
                    }
                    // The leash's own default is not somebody's rule: a step
                    // nobody wrote down still runs, which is what an agent
                    // driving an approved pipeline depends on.
                    Disposition::Ask
                        if !refusal_only && decision.source != PolicySource::Default =>
                    {
                        waiting =
                            waiting.or_else(|| Some(Gate::Wait { step: step.name.clone(), why }));
                    }
                    Disposition::Allow | Disposition::Ask => {}
                }
            }
        }
        if !refusal_only {
            break;
        }
    }
    waiting
}

/// The word a disposition is refused or asked with, as the refusal reads.
fn verb_word(decision: &PolicyDecision) -> &'static str {
    match decision.disposition {
        Disposition::Never => "never allowed",
        Disposition::Ask => "asked about",
        Disposition::Allow => "allowed",
    }
}
