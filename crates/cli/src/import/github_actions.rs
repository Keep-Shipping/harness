//! `keepshipping import github-actions`: GitHub Actions workflows in, a
//! `ship.ks` and an `IMPORT-REPORT.md` out.
//!
//! The translation is best effort and says so: a construct it cannot carry over
//! is listed in the report, and a step it could not translate becomes a script
//! stub whose `run` throws, so an un-ported step can never quietly pass a
//! deploy. What it does write always checks, so the report is the one file a
//! reader has to read.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_yaml_ng::{Mapping, Value};

use crate::args::USAGE;

const USAGE_IMPORT: &str =
    "usage: keepshipping import github-actions [<workflow.yml | dir>] [--out DIR] [--force]";

/// The starter workflows' placeholder for the repository's own default branch:
/// not a branch name, so not one this can write down as a trigger.
const DEFAULT_BRANCH: &str = "$default-branch";

/// How long a name may get. A step name is read in a plan and in a report, so
/// it stops where it stops being one.
const MAX_SLUG: usize = 32;

/// What this translation reads of each mapping it is given. Every other key
/// under a workflow, a job or a step is named in the report, so nothing
/// disappears quietly — see `unhandled`.
const WORKFLOW_KEYS: &[&str] = &["name", "on", "jobs", "env"];
const JOB_KEYS: &[&str] = &["name", "needs", "steps", "environment", "defaults", "env", "uses"];
// The only keys of a step this translation reads. Every other key a GitHub
// Actions step may carry — `id`, `shell`, `continue-on-error`,
// `timeout-minutes` — is listed in the report by name, whether the step was
// translated or stubbed. `if:` is read, not ignored: it becomes a `when:` and a
// TODO. `env:` and `with:` are walked key by key by `step_unhandled`.
const STEP_KEYS: &[&str] = &["name", "uses", "run", "with", "working-directory", "if"];

/// What a folded step was carried into.
#[derive(Clone, Copy, PartialEq)]
enum Fold {
    Image,
    Plan,
}

/// What one original step turned into: `count` indexes the step counts
/// (translated, folded, dropped, stubbed), `fold` a step this job emits
/// elsewhere, `steps` what was emitted here.
struct Class {
    count: usize,
    fold: Option<Fold>,
    steps: Vec<Step>,
    note: String,
}

fn class(count: usize, fold: Option<Fold>, steps: Vec<Step>, note: impl Into<String>) -> Class {
    Class { count, fold, steps, note: note.into() }
}

/// One emitted step, kept structured until the file is whole: the ordering
/// edges are decided once every step of the job has a name.
struct Step {
    name: String,
    kind: String,
    inputs: Vec<(String, String)>,
    todos: Vec<String>,
    after: Vec<String>,
}

impl Step {
    fn render(&self, out: &mut String) {
        let _ = writeln!(out, "  {}: {}", self.name, self.kind);
        for todo in &self.todos {
            let _ = writeln!(out, "    # {todo}");
        }
        for (key, value) in &self.inputs {
            let _ = writeln!(out, "    {key}: {value}");
        }
        if !self.after.is_empty() {
            let _ = writeln!(out, "    after: {}", self.after.join(", "));
        }
        out.push('\n');
    }
}

/// One report row: what an original step became.
struct Row {
    original: String,
    became: String,
    notes: String,
}

/// A job, as the workflow declares it and as it will be written.
struct Job {
    id: String,
    needs: Vec<String>,
    environment: Option<String>,
    steps: Vec<Step>,
    rows: Vec<Row>,
    sign: bool,
}

/// One workflow, translated: the file it becomes, and what the report says.
struct Workflow {
    source: String,
    stem: String,
    out_name: String,
    name: String,
    on: Vec<String>,
    triggers: Vec<(String, String)>,
    jobs: Vec<Job>,
    untranslated: Vec<String>,
    stubs: Vec<(String, String)>,
    counts: [usize; 4],
}

impl Workflow {
    fn note(&mut self, where_: String, what: impl Into<String>) {
        let line = format!("{where_} — {}", what.into());
        if !self.untranslated.contains(&line) {
            self.untranslated.push(line);
        }
    }

    /// The file this workflow becomes: the header the language wants, what it
    /// came from, the triggers that came across, and every step of every job.
    fn render(&self) -> String {
        // A workflow's name is free text: it lands in a comment and in a value,
        // so it is put on one line and quoted rather than read as a reference.
        let name = one_line(&self.name);
        let name = if name.contains(['{', '}', '"']) { quoted(&name) } else { scalar(&name, "") };
        let mut out = format!(
            "keepshipping: 0.1\n\n# {}, imported from {}. Untranslated: IMPORT-REPORT.md.\n\n\
             name: {name}\n",
            name,
            one_line(&self.source)
        );
        if !self.on.is_empty() {
            let _ = writeln!(out, "\non: {}\n", self.on.join(", "));
        }
        out.push_str("\nsteps:\n");
        for step in self.jobs.iter().flat_map(|j| &j.steps) {
            step.render(&mut out);
        }
        out
    }
}

/// What one job's translation needs to know about the job around it.
struct Ctx<'a> {
    id: &'a str,
    env: &'a Mapping,
    /// The `tofu.plan` this job has already emitted: an apply applies that
    /// exact plan, and one that follows it has not planned anything yet.
    plan: Option<String>,
    /// Where this step runs: its own `working-directory`, or the job's.
    working_dir: Option<String>,
    /// Whether this file also runs on a pull request: a condition this build
    /// cannot carry over is then written as `when: pr.number == null`, which
    /// narrows the step to a run that is not a review.
    on_pr: bool,
    used: &'a mut HashSet<String>,
}

/// `keepshipping import github-actions [<path>] [--out DIR] [--force]`, handed
/// the arguments after the word: [`import`](super::import) reads the word, as
/// `blocks` reads its own.
pub(super) fn github_actions(args: &[String]) -> ExitCode {
    match parse(args) {
        Ok(o) => import_into(&o).unwrap_or_else(failed),
        Err(message) => usage(message),
    }
}

struct Opts {
    input: PathBuf,
    out: PathBuf,
    force: bool,
}

/// The arguments this form accepts, read here rather than in `args.rs`: its two
/// flags mean nothing to any other subcommand, and a shared parser would have
/// to grow a variant for a form with one implementation.
fn parse(args: &[String]) -> Result<Opts, String> {
    let mut out = PathBuf::from(".");
    let mut force = false;
    let mut input: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--force" => force = true,
            "--out" => {
                i += 1;
                let Some(dir) = args.get(i) else {
                    return Err("--out needs a directory".into());
                };
                out = PathBuf::from(dir);
            }
            flag if flag.starts_with('-') => return Err(format!("unknown flag `{flag}`")),
            word if input.is_none() => input = Some(word.to_string()),
            word => return Err(format!("`{word}` is a second input; import takes one")),
        }
        i += 1;
    }
    let input = input.map_or_else(|| PathBuf::from(".github").join("workflows"), PathBuf::from);
    Ok(Opts { input, out, force })
}

fn usage(message: impl std::fmt::Display) -> ExitCode {
    let message = message.to_string();
    if !message.is_empty() {
        eprintln!("error: {message}");
    }
    eprintln!("{USAGE_IMPORT}\n{USAGE}");
    ExitCode::from(2)
}

/// Everything this refuses is the caller's file, never this build: exit 3 is for
/// a bug in keepshipping, and a workflow somebody wrote is not one.
fn failed(message: String) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::from(1)
}

/// The whole of `import`: read, translate, refuse what cannot be written. Every
/// file this run would write is known before any of them is, so a run that
/// would overwrite something writes nothing at all.
fn import_into(o: &Opts) -> Result<ExitCode, String> {
    let workflows = read(o)?;
    let mut planned: Vec<PathBuf> = vec![o.out.join("IMPORT-REPORT.md")];
    for (_, wf) in &workflows {
        planned.push(o.out.join(&wf.out_name));
        planned.extend(wf.stubs.iter().map(|(path, _)| o.out.join(path)));
    }
    if !o.force {
        let existing: Vec<String> =
            planned.iter().filter(|p| p.exists()).map(|p| p.display().to_string()).collect();
        if !existing.is_empty() {
            let named = existing.join(", ");
            return Err(format!("{named} would be overwritten; pass --force"));
        }
    }
    let refs: Vec<&Workflow> = workflows.iter().map(|(_, wf)| wf).collect();
    let body = report(&refs);
    for (src, wf) in &workflows {
        // `ship/` is where the stubs go, so it exists only when there is one.
        if !wf.stubs.is_empty() {
            std::fs::create_dir_all(o.out.join("ship")).map_err(|e| e.to_string())?;
        }
        for (path, module) in &wf.stubs {
            write(&o.out.join(path), module)?;
        }
        write(&o.out.join(&wf.out_name), src)?;
    }
    let at = o.out.join("IMPORT-REPORT.md");
    write(&at, &body)?;

    println!("imported {} workflow(s) into {}", workflows.len(), o.out.display());
    for (_, wf) in &workflows {
        let counts = wf.counts;
        let total: usize = counts.iter().sum();
        println!(
            "  {} -> {} ({total} step(s): {} translated, {} folded, {} dropped, {} stubbed)",
            wf.source, wf.out_name, counts[0], counts[1], counts[2], counts[3],
        );
    }
    let untranslated: usize = workflows.iter().map(|(_, wf)| wf.untranslated.len()).sum();
    println!("report: {} ({untranslated} untranslated construct(s))", at.display());
    Ok(ExitCode::SUCCESS)
}

/// Every workflow under the input, read and translated, each with the file it
/// would become. A file this build cannot write as ship.ks never reaches disk.
fn read(o: &Opts) -> Result<Vec<(String, Workflow)>, String> {
    let sources = workflow_files(&o.input)?;
    if sources.is_empty() {
        let at = o.input.display();
        return Err(format!("no `*.yml` or `*.yaml` workflow under {at}"));
    }
    let mut workflows = Vec::new();
    for source in &sources {
        let display = source.display().to_string();
        let body = std::fs::read_to_string(source).map_err(|e| format!("{display}: {e}"))?;
        let doc: Value = serde_yaml_ng::from_str(&body)
            .map_err(|e| format!("{display}: not a workflow this build can read: {e}"))?;
        let Some(doc) = doc.as_mapping() else {
            return Err(format!("{display}: a workflow is a mapping, not a list"));
        };
        let stem = safe(source.file_stem().and_then(|s| s.to_str()).unwrap_or(""), "workflow");
        let out_name = if o.input.is_dir() { format!("{stem}.ks") } else { "ship.ks".into() };
        let wf = translate(doc, &display, &stem, out_name);
        // Nothing this build cannot check ever reaches disk.
        match ks_lang::format(&wf.render()) {
            Ok(src) => workflows.push((src, wf)),
            Err(e) => {
                return Err(format!("{display}: the translation does not parse: {e}"));
            }
        }
    }
    // Two workflows whose stems agree would write one file twice, the second
    // overwriting the first without ever having asked.
    let mut names: Vec<&str> = workflows.iter().map(|(_, wf)| wf.out_name.as_str()).collect();
    names.sort_unstable();
    if let Some([name, _]) = names.windows(2).find(|pair| pair[0] == pair[1]) {
        let named =
            format!("two workflows both become `{name}`; import one at a time, or rename one");
        return Err(named);
    }
    Ok(workflows)
}

fn workflow_files(input: &Path) -> Result<Vec<PathBuf>, String> {
    if input.is_file() {
        return Ok(vec![input.to_path_buf()]);
    }
    if !input.is_dir() {
        return Err(format!("{} is neither a workflow nor a directory", input.display()));
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(input)
        .map_err(|e| format!("{}: {e}", input.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")))
        .collect();
    files.sort();
    Ok(files)
}

fn write(path: &Path, body: &str) -> Result<(), String> {
    std::fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

/// The workflow as a ship file, plus everything the report says about it.
fn translate(doc: &Mapping, source: &str, stem: &str, out_name: String) -> Workflow {
    let triggers = triggers(doc);
    let mut wf = Workflow {
        source: source.to_string(),
        stem: stem.to_string(),
        out_name,
        name: str_of(doc, "name").unwrap_or(stem).to_string(),
        // A trigger that did not come across is not a trigger this file has.
        on: triggers
            .iter()
            .map(|(_, to)| to.clone())
            .filter(|to| !to.contains("not translated"))
            .collect(),
        triggers: triggers.clone(),
        jobs: Vec::new(),
        untranslated: unhandled(doc, WORKFLOW_KEYS, "", source),
        stubs: Vec::new(),
        counts: [0; 4],
    };
    let wf_env = sub(doc, "env").unwrap_or_default();
    wf.untranslated.extend(unhandled(&wf_env, &[], "env.", source));
    let skipped: Vec<String> = wf
        .triggers
        .iter()
        .filter(|(_, to)| to.contains("not translated"))
        .map(|(from, to)| format!("{from} — {to}"))
        .collect();
    for line in skipped {
        wf.note(source.to_string(), line);
    }
    scan_secrets(doc, "", source, &mut wf.untranslated);

    let on_pr = wf.on.iter().any(|on| on.starts_with("pr"));
    let mut used = HashSet::new();
    let jobs = sub(doc, "jobs").unwrap_or_default();
    for id in order(&jobs) {
        let Some(job) = get(&jobs, &id).and_then(Value::as_mapping) else {
            continue;
        };
        // The first step of a job is after the last step of every job it needs.
        let needs = get(job, "needs").map(needs_of).unwrap_or_default();
        let done: Vec<String> = wf
            .jobs
            .iter()
            .filter(|j| needs.contains(&j.id))
            .filter_map(|j| j.steps.last().map(|s| s.name.clone()))
            .collect();
        let working_dir = sub(job, "defaults")
            .and_then(|d| sub(&d, "run"))
            .and_then(|r| str_of(&r, "working-directory").map(str::to_string));
        let env = job_env(&wf_env, job);
        let mut ctx = Ctx { id: &id, env: &env, plan: None, working_dir, on_pr, used: &mut used };
        let translated = translate_job(job, &mut ctx, &done, &mut wf);
        wf.jobs.push(translated);
    }
    // A workflow with no steps anywhere has no `steps:` to write, and a ship file
    // with an empty `steps:` is not a ship file: it gets the same throwing stub
    // an unrecognised step gets.
    if wf.jobs.iter().all(|j| j.steps.is_empty()) {
        let empty = Mapping::new();
        let mut ctx = Ctx {
            id: "import",
            env: &empty,
            plan: None,
            working_dir: None,
            on_pr,
            used: &mut used,
        };
        let mut job = Job {
            id: "import".into(),
            needs: Vec::new(),
            environment: None,
            steps: Vec::new(),
            rows: Vec::new(),
            sign: false,
        };
        let name = stub(&mut job, &[], &mut ctx, &mut wf);
        job.rows.push(Row {
            original: "the whole workflow".into(),
            became: format!("`{name}`"),
            notes: "nothing in this workflow was translated, so the file cannot be trusted to do anything"
                .into(),
        });
        wf.jobs.push(job);
    }
    // The image a rollout pins and the sign a cosign run asks for may name a
    // step in another job, so they are decided once every job has been read.
    let images: Vec<String> = wf.jobs.iter().filter_map(|j| named(&j.steps, "oci.image")).collect();
    let signed: Vec<String> = wf
        .jobs
        .iter()
        .filter(|j| j.sign)
        .filter_map(|j| named(&j.steps, "oci.image").or_else(|| images.first().cloned()))
        .collect();
    for name in signed {
        let step = wf.jobs.iter_mut().flat_map(|j| j.steps.iter_mut()).find(|s| s.name == name);
        match step {
            Some(step) => step.inputs.push(("sign".into(), "true".into())),
            None => wf.note(
                source.to_string(),
                "a `cosign sign` run — there is no `oci.image` step to sign",
            ),
        }
    }
    for step in wf.jobs.iter_mut().flat_map(|j| j.steps.iter_mut()) {
        if step.kind != "k8s.rollout" || step.inputs.iter().any(|(k, _)| k == "image") {
            continue;
        }
        match images.as_slice() {
            [only] => step.inputs.insert(0, ("image".into(), format!("{only}.digest"))),
            many => step.todos.push(format!(
                "TODO: `image:` — the workflow builds {} `oci.image` step(s)",
                many.len()
            )),
        }
    }
    wf
}

/// The first step of that kind a job emitted, by name: what folded steps landed
/// in, and what a rollout pins.
fn named(steps: &[Step], kind: &str) -> Option<String> {
    steps.iter().find(|s| s.kind == kind).map(|s| s.name.clone())
}

/// One job, in the order its steps were written.
fn translate_job(job: &Mapping, ctx: &mut Ctx, needs_done: &[String], wf: &mut Workflow) -> Job {
    let where_ = format!("{} › job `{}`", wf.source, ctx.id);
    let default_dir = ctx.working_dir.clone();
    let mut out = Job {
        id: ctx.id.to_string(),
        needs: get(job, "needs").map(needs_of).unwrap_or_default(),
        environment: job_environment(job),
        steps: Vec::new(),
        rows: Vec::new(),
        sign: false,
    };
    let env = sub(job, "env");
    let defaults = sub(job, "defaults");
    for (map, read, prefix) in [
        (Some(job), JOB_KEYS, ""),
        (env.as_ref(), &[][..], "env."),
        (defaults.as_ref(), &[][..], "defaults."),
    ] {
        if let Some(map) = map {
            wf.untranslated.extend(unhandled(map, read, prefix, &where_));
        }
    }
    if let Some(run) = sub(job, "defaults").and_then(|d| sub(&d, "run")) {
        wf.untranslated.extend(unhandled(&run, &["working-directory"], "defaults.run.", &where_));
    }
    // A job that calls a reusable workflow carries its work in another
    // repository's file, which is not a step this build can write.
    if let Some(uses) = str_of(job, "uses") {
        let why = format!("`uses: {uses}` — a reusable workflow call is not translated");
        wf.note(where_.clone(), &why);
    }
    // A condition on the whole job is a condition on every step of it. This
    // build cannot carry it, so each step says so and, where the file also runs
    // on a pull request, is held back from one.
    let job_if = str_of(job, "if").map(str::to_string);

    let steps = get(job, "steps").and_then(Value::as_sequence).cloned().unwrap_or_default();
    let mut pending: Vec<&Mapping> = Vec::new();
    let mut folds: Vec<(usize, Fold)> = Vec::new();
    for (n, step) in steps.iter().enumerate() {
        let Some(step) = step.as_mapping() else {
            continue;
        };
        let label = label(step);
        let here = format!("{where_} › step {n} (`{}`)", one_line(&label));
        ctx.working_dir =
            str_of(step, "working-directory").map(str::to_string).or(default_dir.clone());
        let c = classify(step, &label, ctx);
        if c.count == 3 {
            pending.push(step);
            continue;
        }
        // The run of steps nothing recognised became its stub where it stood:
        // one written at the end of the job would move the work after it.
        if !pending.is_empty() {
            stub(&mut out, &pending, ctx, wf);
            pending.clear();
        }
        let first = out.steps.len();
        out.steps.extend(c.steps);
        ctx.plan = named(&out.steps, "tofu.plan");
        for expr in [job_if.as_deref(), str_of(step, "if")].into_iter().flatten() {
            gate_step(out.steps.get_mut(first), ctx.on_pr, expr);
        }
        let emitted: Vec<String> =
            out.steps[first..].iter().map(|s| format!("`{}` ({})", s.name, s.kind)).collect();
        let became = if emitted.is_empty() && c.count == 2 {
            "dropped".to_string()
        } else {
            emitted.join(", ")
        };
        wf.counts[c.count] += 1;
        out.rows.push(Row { original: label, became, notes: c.note });
        wf.untranslated.extend(step_unhandled(step, with_read(step), &here));
        if let Some(what) = c.fold {
            folds.push((out.rows.len() - 1, what));
        }
    }
    if !pending.is_empty() {
        stub(&mut out, &pending, ctx, wf);
    }
    // A cosign run signs the image this job builds.
    out.sign = steps.iter().filter_map(Value::as_mapping).any(|s| {
        str_of(s, "uses").is_some_and(|u| action_of(u) == "sigstore/cosign-installer")
            || str_of(s, "run").is_some_and(|r| r.contains("cosign sign"))
    });
    for (row, what) in folds {
        let kind = if what == Fold::Image { "oci.image" } else { "tofu.plan" };
        let (of, into) = match what {
            Fold::Image => ("a cosign install", "an `oci.image` step"),
            Fold::Plan => ("a tofu install or init", "a `tofu.plan` step"),
        };
        let row = &mut out.rows[row];
        match named(&out.steps, kind) {
            Some(target) => {
                row.became = format!("folded into `{target}`");
                // An image sign has no note of its own, and here is the only
                // place it can say that the step is asked to sign.
                if what == Fold::Image {
                    row.notes.push_str("; `sign: true` on that step");
                }
            }
            None => {
                let missing = format!("this job has no {into} to fold it into");
                row.became = "not translated".into();
                row.notes = missing.clone();
                let at = format!("{where_} › `{}`", row.original);
                wf.note(at, format!("{of} — {missing}"));
            }
        }
    }
    gate(&mut out, ctx, needs_done);
    chain(&mut out.steps, needs_done);
    // Every step was dropped, or the job had none, or it called a reusable
    // workflow. `steps:` is never empty: the file names the gap instead.
    if out.steps.is_empty() {
        let name = stub(&mut out, &[], ctx, wf);
        out.rows.push(Row {
            original: "this job".into(),
            became: format!("`{name}`"),
            notes: "nothing in this job was translated, so the file does nothing for it".into(),
        });
    }
    out
}

/// What a condition this build cannot carry over does to a step it did translate:
/// the step says so, and where the file also runs on a pull request the step is
/// held back from one. Narrowing is the safe direction — a step that might have
/// been gated off now runs on a push, never the other way round.
fn gate_step(step: Option<&mut Step>, on_pr: bool, expr: &str) {
    let Some(step) = step else {
        return;
    };
    step.todos.push(format!(
        "TODO: `if:` is not translated, so this step runs whenever the file reaches it: `{}`",
        one_line(expr)
    ));
    if on_pr && !step.inputs.iter().any(|(k, _)| k == "when") {
        step.inputs.push(("when".into(), "pr.number == null".into()));
    }
}

/// A GitHub environment gates a job by its reviewers, who live in the
/// repository's settings; an approval with no `show:` is what is left of it.
fn gate(out: &mut Job, ctx: &mut Ctx, needs_done: &[String]) {
    let Some(environment) = out.environment.clone() else {
        return;
    };
    let approvals: Vec<usize> = out
        .steps
        .iter()
        .enumerate()
        .filter(|(_, s)| s.kind == "approval")
        .map(|(i, _)| i)
        .collect();
    if let [at] = approvals[..] {
        // A tofu apply already shows its plan: one approval, two reasons.
        out.steps[at].todos.push(format!(
            "TODO: this also gates the GitHub environment `{environment}`; its reviewers live in the repository's settings"
        ));
        return;
    }
    let mut step = new_step(ctx.id, "gate", "approval", ctx.used);
    step.todos.push(format!(
        "TODO: the GitHub environment `{environment}` gates this job; its reviewers live in the repository's settings, so `from:` is left empty"
    ));
    step.after = needs_done.to_vec();
    out.steps.insert(0, step);
    let row = Row {
        original: format!("environment: {environment}"),
        became: format!("`{}-gate` (approval)", slug(ctx.id)),
        notes: "the environment's own reviewers are not translated".into(),
    };
    out.rows.insert(0, row);
}

/// Order a job's steps: each after the previous one, and the first after the
/// steps the jobs it `needs` ended on.
fn chain(steps: &mut [Step], needs_done: &[String]) {
    let names: Vec<String> = steps.iter().map(|s| s.name.clone()).collect();
    let mut previous: Option<String> = None;
    for (i, step) in steps.iter_mut().enumerate() {
        // A step that already names a predecessor in one of its values does not
        // need the edge as well.
        let reads: Vec<String> = names
            .iter()
            .filter(|n| step.inputs.iter().any(|(_, v)| v.contains(&format!("{n}."))))
            .cloned()
            .collect();
        let before = if i == 0 { needs_done.to_vec() } else { Vec::new() };
        for edge in before.into_iter().chain(previous.clone()).filter(|e| !reads.contains(e)) {
            if !step.after.contains(&edge) {
                step.after.push(edge);
            }
        }
        previous = Some(step.name.clone());
    }
}

/// What one original step is.
fn classify(step: &Mapping, label: &str, ctx: &mut Ctx) -> Class {
    if let Some(uses) = str_of(step, "uses") {
        return by_action(step, uses, label, ctx);
    }
    let Some(run) = str_of(step, "run") else {
        return class(3, None, vec![], "");
    };
    let all: Vec<&str> = run.lines().collect();
    // A multi-line run translated only the line that named the command.
    let rest = |n: usize| (n > 1).then(|| format!("; {} other line(s) are not translated", n - 1));
    for line in &all {
        match tofu(line) {
            Some("init") => {
                return class(
                    1,
                    Some(Fold::Plan),
                    vec![],
                    "`tofu.plan` initialises the directory, so an init step is not needed",
                );
            }
            Some("plan") => {
                let dir = flag(line, "-chdir").map_or_else(
                    || ctx.working_dir.clone().unwrap_or_else(|| ".".into()),
                    str::to_string,
                );
                let mut made = new_step(ctx.id, label, "tofu.plan", ctx.used);
                made.inputs.push(("dir".into(), path(&dir)));
                return class(
                    0,
                    None,
                    vec![made],
                    format!(
                        "`tofu.plan` plans, and initialises the directory first{}",
                        rest(all.len()).unwrap_or_default()
                    ),
                );
            }
            Some("apply") => return tofu_apply(label, all.len(), ctx),
            _ => {}
        }
    }
    if all.iter().any(|l| l.contains("cosign sign")) {
        return class(1, Some(Fold::Image), vec![], "the command line it runs is not translated");
    }
    for line in &all {
        if line.starts_with("kubectl ") && line.contains(" apply ") && flag(line, "-f").is_some() {
            let (manifests, out) = one_of(flag(line, "-f"));
            let made = rollout(ctx.id, label, manifests, None, ctx.used);
            let mut notes = vec!["`kubectl apply`".to_string()];
            notes.extend(into_the_void(out, "-f"));
            return class(0, None, vec![made], notes.join("; "));
        }
        if line.trim_start().starts_with("helm ") && line.contains(" upgrade ") {
            let made = rollout(ctx.id, label, None, flag(line, "--namespace"), ctx.used);
            return class(
                0,
                None,
                vec![made],
                "`helm upgrade`; the chart and its values are not translated",
            );
        }
    }
    class(3, None, vec![], "")
}

/// `tofu apply`: a plan behind it if this job has not planned yet, an approval
/// to read that plan, and the apply of that exact plan file.
fn tofu_apply(label: &str, lines: usize, ctx: &mut Ctx) -> Class {
    let mut made = Vec::new();
    let plan = match ctx.plan.clone() {
        Some(plan) => plan,
        None => {
            let dir = ctx.working_dir.clone().unwrap_or_else(|| ".".into());
            let mut step =
                new_step(ctx.id, &format!("{}-plan", slug(label)), "tofu.plan", ctx.used);
            step.inputs.push(("dir".into(), path(&dir)));
            let name = step.name.clone();
            made.push(step);
            name
        }
    };
    let mut review = new_step(ctx.id, &format!("{}-review", slug(label)), "approval", ctx.used);
    review.inputs.push(("show".into(), format!("{plan}.changes")));
    let mut apply = new_step(ctx.id, label, "tofu.apply", ctx.used);
    apply.inputs.push(("plan".into(), format!("{plan}.file")));
    made.extend([review, apply]);
    let rest = (lines > 1).then(|| format!("; {} other line(s) are not translated", lines - 1));
    let note = format!(
        "`tofu.apply` of the `{plan}` plan, behind its own approval{}",
        rest.unwrap_or_default()
    );
    class(0, None, made, note)
}

/// What a step's `uses:` becomes. Actions that only prepare the runner are
/// dropped: the harness runs in the working tree and `oci.image` drives the
/// build, so they have nothing left to do.
fn by_action(step: &Mapping, uses: &str, label: &str, ctx: &mut Ctx) -> Class {
    let action = action_of(uses);
    let why = match action.as_str() {
        "actions/checkout" => Some("not needed: the harness runs in the working tree"),
        "docker/setup-buildx-action" => Some("not needed: oci.image drives the build"),
        "docker/setup-qemu-action" => Some("not needed: oci.image builds on the runner"),
        _ => None,
    };
    if let Some(why) = why {
        return class(2, None, vec![], why);
    }
    let with = sub(step, "with").unwrap_or_default();
    match action.as_str() {
        "docker/build-push-action" => image_step(label, &with, ctx),
        "azure/k8s-deploy" => {
            let (manifests, out) = one_of(str_of(&with, "manifests"));
            let made = rollout(ctx.id, label, manifests, str_of(&with, "namespace"), ctx.used);
            let mut note = "`azure/k8s-deploy`".to_string();
            if let Some(why) = into_the_void(out, "manifests") {
                note.push_str(&format!("; {why}"));
            }
            class(0, None, vec![made], note)
        }
        "sigstore/cosign-installer" => {
            class(1, Some(Fold::Image), vec![], "the version it installs is not translated")
        }
        "hashicorp/setup-terraform" | "opentofu/setup-opentofu" => {
            class(1, Some(Fold::Plan), vec![], "the version it installs is not translated")
        }
        _ => class(3, None, vec![], ""),
    }
}

/// The `oci.image` a build step becomes: the Dockerfile it names, the context it
/// builds in, and the first tag it pushes, when that tag is a literal.
fn image_step(label: &str, with: &Mapping, ctx: &mut Ctx) -> Class {
    let (context, context_out) = one_of(str_of(with, "context"));
    let (file, file_out) = one_of(str_of(with, "file"));
    let nested = context.filter(|dir| dir != ".");
    let from = file
        .map(|f| path(&f))
        .or_else(|| nested.clone().map(|dir| path(&format!("{dir}/Dockerfile"))))
        .unwrap_or_else(|| "./Dockerfile".into());
    let mut made = new_step(ctx.id, label, "oci.image", ctx.used);
    made.inputs.push(("from".into(), from));
    if let Some(dir) = nested {
        made.inputs.push(("context".into(), path(&dir)));
    }
    // `tags:` is a list, or one string with a tag per line.
    let tags = get(with, "tags").map(list_of).unwrap_or_default();
    let tag = tags.first().and_then(|t| t.lines().next()).map(str::to_string);
    match tag.and_then(|tag| resolve(&tag, ctx.env)) {
        Some(tag) => made.inputs.push(("push".into(), scalar(&tag, ""))),
        None => made.todos.push(
            "TODO: `push:` — the tag is another step's output or an expression, and only a literal can be written here"
                .into(),
        ),
    }
    let read = ["file", "context", "tags", "push"];
    let skipped = with.keys().filter(|k| !read.contains(&as_text(k).as_str())).count();
    let mut notes = vec!["`docker/build-push-action`".to_string()];
    if skipped > 0 {
        notes.push(format!("{skipped} `with:` key(s) are not translated"));
    }
    notes.extend(into_the_void(context_out, "context"));
    notes.extend(into_the_void(file_out, "file"));
    class(0, None, vec![made], notes.join("; "))
}

/// The `k8s.rollout` a deploy becomes. `to:` has no literal form — only a
/// `tofu.apply` output names a cluster — so the file carries a TODO instead.
fn rollout(
    id: &str,
    label: &str,
    manifests: Option<String>,
    namespace: Option<&str>,
    used: &mut HashSet<String>,
) -> Step {
    let mut step = new_step(id, label, "k8s.rollout", used);
    if let Some(dir) = manifests {
        step.inputs.push(("manifests".into(), path(&dir)));
    }
    if let Some(namespace) = namespace {
        step.inputs.push(("namespace".into(), scalar(namespace, "")));
    }
    let todo = "TODO: `to:` — a cluster is named by the environment, never written here";
    step.todos.push(todo.into());
    step
}

/// A run of steps nothing was recognised for becomes one script stub: the
/// original steps are kept verbatim as comments, and `run` throws, so the stub
/// cannot stand in for work it did not port.
fn stub(out: &mut Job, pending: &[&Mapping], ctx: &mut Ctx, wf: &mut Workflow) -> String {
    let job = slug(ctx.id);
    let job = if job == wf.stem { String::new() } else { format!("-{job}") };
    let file = format!("ship/{}{}-stub{}.ts", wf.stem, job, wf.stubs.len() + 1);
    let mut body = String::from(
        "// Imported from a GitHub Actions workflow. Nothing here is wired up yet.\n\
         import { step } from \"@keepshipping/sdk\"\n\n\
         // TODO: port these steps, then delete this throw.\n",
    );
    for step in pending {
        let _ = writeln!(body, "//");
        if let Some(name) = str_of(step, "name") {
            let _ = writeln!(body, "// {}", one_line(name));
        }
        if let Some(uses) = str_of(step, "uses") {
            let _ = writeln!(body, "//   uses: {uses}");
            if let Some(with) = sub(step, "with") {
                let _ = writeln!(body, "//   with:");
                for (key, value) in with {
                    let _ = writeln!(body, "//     {}: {}", as_text(&key), as_text(&value));
                }
            }
        }
        if let Some(run) = str_of(step, "run") {
            for line in run.lines() {
                let _ = writeln!(body, "// {}", one_line(line));
            }
        }
    }
    let names: Vec<String> = pending.iter().map(|s| label(s)).map(|l| one_line(&l)).collect();
    let names = if names.is_empty() {
        "there is nothing here this build translates".to_string()
    } else {
        names.join(", ")
    };
    let _ = writeln!(body, "export default step({{\n  async run() {{");
    let why = quoted(&format!("not yet translated from GitHub Actions: {names}"));
    let _ = writeln!(body, "    throw new Error({why})");
    body.push_str("  },\n})\n");

    // A stubbed step lost everything the others say they lost: its own keys, its
    // `env:`, its `with:`, and any condition it was running under.
    let where_ = format!("{} › job `{}`", wf.source, ctx.id);
    let mut conditions: Vec<String> = Vec::new();
    for step in pending {
        let here = format!("{where_} › step `{}`", one_line(&label(step)));
        wf.untranslated.extend(step_unhandled(step, with_read(step), &here));
        if let Some(expr) = str_of(step, "if") {
            conditions.push(one_line(expr));
        }
    }
    let base = match pending.first() {
        Some(step) => format!("{}-stub", slug(&label(step))),
        None => "stub".to_string(),
    };
    let mut made = new_step(ctx.id, &base, &format!("./{file}"), ctx.used);
    made.inputs.push(("action".into(), "other".into()));
    if !conditions.is_empty() {
        made.todos.push(format!(
            "TODO: `if:` is not translated; this stub runs wherever the file reaches it: `{}`",
            conditions.join("; ")
        ));
    }
    let name = made.name.clone();
    out.steps.push(made);
    for step in pending {
        wf.counts[3] += 1;
        let notes = "kept verbatim as comments in the module; \
                     its `run` throws, so it cannot stand in for the step";
        let row = Row {
            original: label(step),
            became: format!("`{name}` (`{file}`)"),
            notes: notes.into(),
        };
        out.rows.push(row);
    }
    wf.stubs.push((file, body));
    name
}

/// A step name: the job, then the original step's own name where it has one
/// and what it runs where it does not, so two jobs may both have a `build`.
fn new_step(job: &str, base: &str, kind: &str, used: &mut HashSet<String>) -> Step {
    let job = slug(job);
    let base = slug(base);
    // A step of the `terraform` job named `Terraform Plan` is `terraform-plan`:
    // the job's own name is not news.
    let base = base.strip_prefix(&format!("{job}-")).unwrap_or(&base).to_string();
    let mut name = format!("{job}-{base}");
    let mut n = 2;
    while !used.insert(name.clone()) {
        name = format!("{job}-{base}-{n}");
        n += 1;
    }
    Step { name, kind: kind.to_string(), inputs: Vec::new(), todos: Vec::new(), after: Vec::new() }
}

fn slug(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let mut out: String = out.trim_matches('-').chars().take(MAX_SLUG).collect();
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        return "step".to_string();
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        return format!("s{out}");
    }
    out
}

/// A file stem that is safe as a file name and as a step name at once.
fn safe(raw: &str, fallback: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    let out = out.trim_matches('-');
    if out.is_empty() { fallback.to_string() } else { out.to_string() }
}

/// The `on:` block, as (original, became) pairs. Nothing is merged: each
/// workflow is its own file, and merging triggers would change when either
/// deploys.
fn triggers(doc: &Mapping) -> Vec<(String, String)> {
    // A YAML 1.1 reader spells `on:` `true`; a 1.2 one spells it `on`. Either
    // is this key.
    let entries: Vec<(String, Option<Value>)> =
        match get(doc, "on").or_else(|| doc.get(Value::Bool(true))) {
            Some(Value::String(one)) => vec![(one.clone(), None)],
            Some(Value::Sequence(list)) => {
                list.iter().filter_map(|e| text(e).map(|t| (t.to_string(), None))).collect()
            }
            Some(Value::Mapping(map)) => {
                map.iter().map(|(k, v)| (as_text(k), Some(v.clone()))).collect()
            }
            _ => Vec::new(),
        };
    let mut rows: Vec<(String, String)> = Vec::new();
    for (event, filters) in entries {
        if !matches!(event.as_str(), "push" | "pull_request" | "workflow_dispatch") {
            // `pull_request_target` runs with a write token and the repository's
            // secrets on a fork's pull request. It is not a review, so it is
            // never carried across as one.
            let why = if event == "pull_request_target" {
                let s = "`pull_request_target` runs with a write token and the repository's secrets \
                         on a fork's pull request";
                format!("not translated; {s}")
            } else {
                "not translated".into()
            };
            add(&mut rows, format!("on: {event}"), why);
            continue;
        }
        let filters =
            filters.map(|v| v.as_mapping().cloned().unwrap_or_default()).unwrap_or_default();
        // `pull_request` is `pr` whatever it filters on, so its filter is a row
        // that says the filter is gone, not a trigger.
        let is_pr = event.starts_with("pull_request");
        for (key, kind) in [("branches", "push"), ("tags", "tag")] {
            let Some(value) = get(&filters, key) else {
                continue;
            };
            for glob in list_of(value) {
                if is_pr {
                    add(
                        &mut rows,
                        format!("{event}: {key}: {glob}"),
                        "not translated; `pr` is for every branch".into(),
                    );
                    continue;
                }
                let placeholder = glob == DEFAULT_BRANCH;
                let note = if placeholder {
                    format!(" (the `{DEFAULT_BRANCH}` placeholder, read as `main`)")
                } else {
                    String::new()
                };
                let glob = if placeholder { "main".to_string() } else { glob };
                add(
                    &mut rows,
                    format!("{event}: {key}: {glob}{note}"),
                    format!("{kind} {}", scalar(&glob, "")),
                );
            }
        }
        for key in ["branches-ignore", "paths", "paths-ignore", "types"] {
            if let Some(value) = get(&filters, key) {
                let from = format!("{event}: {key}: {}", list_of(value).join(", "));
                add(&mut rows, from, "not translated".into());
            }
        }
        match event.as_str() {
            "workflow_dispatch" => add(&mut rows, event, "manual".into()),
            _ if is_pr => add(&mut rows, event, "pr".into()),
            _ if filters.is_empty() => add(&mut rows, "push".into(), "push".into()),
            _ => {}
        }
    }
    rows
}

fn add(rows: &mut Vec<(String, String)>, from: String, to: String) {
    if !rows.iter().any(|(_, t)| *t == to) {
        rows.push((from, to));
    }
}

/// The jobs in the order a run reaches them: every job after the ones it
/// `needs`. A cycle among them is read in file order.
fn order(jobs: &Mapping) -> Vec<String> {
    let ids: Vec<String> = jobs.keys().map(as_text).collect();
    let needs = |id: &str| {
        get(jobs, id)
            .and_then(Value::as_mapping)
            .and_then(|j| get(j, "needs"))
            .map(needs_of)
            .unwrap_or_default()
    };
    let mut out: Vec<String> = Vec::new();
    while out.len() < ids.len() {
        let ready: Vec<String> = ids
            .iter()
            .filter(|id| !out.contains(id))
            .filter(|id| needs(id).iter().all(|n| out.contains(n) || !ids.contains(n)))
            .cloned()
            .collect();
        // A cycle: the rest is read in file order, and the report says what did
        // not come across.
        let next = if ready.is_empty() {
            ids.iter().filter(|i| !out.contains(i)).cloned().collect()
        } else {
            ready
        };
        out.extend(next);
    }
    out
}

fn needs_of(v: &Value) -> Vec<String> {
    match v {
        Value::String(one) => vec![one.clone()],
        Value::Sequence(list) => list.iter().filter_map(|n| text(n).map(str::to_string)).collect(),
        _ => Vec::new(),
    }
}

/// Every key under `map` that `read` does not cover, named with the path a
/// reader would look for it under, and with what it said. The walk is over the
/// keys that are there, not over the ones expected, so nothing goes missing.
fn unhandled(map: &Mapping, read: &[&str], prefix: &str, here: &str) -> Vec<String> {
    map.keys()
        .map(as_text)
        .filter(|key| !read.contains(&key.as_str()))
        .map(|key| {
            let was = match get(map, &key) {
                Some(Value::String(s)) => format!(" (it was `{}`)", one_line(s)),
                Some(v @ (Value::Bool(_) | Value::Number(_))) => {
                    format!(" (it was `{}`)", as_text(v))
                }
                _ => String::new(),
            };
            format!("{here} — `{prefix}{key}` is not translated{was}")
        })
        .collect()
}

fn with_read(step: &Mapping) -> &'static [&'static str] {
    match str_of(step, "uses").map(action_of).as_deref() {
        Some("docker/build-push-action") => &["file", "context", "tags", "push"],
        Some("azure/k8s-deploy") => &["manifests", "namespace"],
        _ => &[],
    }
}

/// Everything about one step this translation did not carry across: the keys it
/// does not read, its `env`, and whatever of its `with:` its own rule skipped.
fn step_unhandled(step: &Mapping, with_read: &[&str], here: &str) -> Vec<String> {
    let mut out = unhandled(step, STEP_KEYS, "", here);
    if let Some(env) = sub(step, "env") {
        out.extend(unhandled(&env, &[], "env.", here));
    }
    if let Some(with) = sub(step, "with") {
        out.extend(unhandled(&with, with_read, "with.", here));
    }
    out
}

/// Every `${{ secrets.NAME }}` the workflow reads, at the path it read it.
/// Secrets never become strings here, so none of them is carried over.
fn scan_secrets(map: &Mapping, path: &str, source: &str, out: &mut Vec<String>) {
    for (key, value) in map {
        let here = if path.is_empty() { as_text(key) } else { format!("{path}.{}", as_text(key)) };
        match value {
            Value::String(s) => {
                let mut rest = s.as_str();
                while let Some(at) = rest.find("secrets.") {
                    rest = &rest[at + "secrets.".len()..];
                    let name: String =
                        rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    out.push(format!(
                        "{source} › {here} — `${{{{ secrets.{name} }}}}` is not translated; a run reads its secrets from the environment"
                    ));
                }
            }
            Value::Mapping(inner) => scan_secrets(inner, &here, source, out),
            Value::Sequence(list) => {
                let pairs: Mapping =
                    list.iter().enumerate().map(|(i, v)| (Value::from(i), v.clone())).collect();
                scan_secrets(&pairs, &here, source, out);
            }
            _ => {}
        }
    }
}

/// The report: what was written, what each original step became, and every
/// construct that did not come across.
fn report(workflows: &[&Workflow]) -> String {
    let steps: usize = workflows.iter().map(|wf| wf.counts.iter().sum::<usize>()).sum();
    let untranslated: usize = workflows.iter().map(|wf| wf.untranslated.len()).sum();
    let mut out = format!(
        "# Import report\n\n\
         `keepshipping import github-actions` rewrote GitHub Actions workflows into ship files.\n\
         Every original step is in its table below, and every construct that did not come\n\
         across is listed under **Untranslated constructs**. The output is written to pass\n\
         `keepshipping check`, not to be trusted.\n\n\
         {} workflow(s), {steps} step(s), {untranslated} untranslated construct(s).\n",
        workflows.len()
    );
    for wf in workflows {
        let _ = writeln!(out, "\n## {} → {}\n", md(&wf.source), md(&wf.out_name));
        out.push_str("| Original trigger | Became |\n| --- | --- |\n");
        if wf.triggers.is_empty() {
            out.push_str("| — | the workflow has no `on:` block this build reads |\n");
        }
        for (from, to) in &wf.triggers {
            // An untranslated trigger says why, in full: a reader deciding
            // whether to trust this file needs the reason, not the verdict.
            let became =
                if to.contains("not translated") { to.clone() } else { format!("`on: {to}`") };
            let _ = writeln!(out, "| {} | {became} |", md(from));
        }
        for job in &wf.jobs {
            let needs = if job.needs.is_empty() {
                "nothing".to_string()
            } else {
                job.needs.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(", ")
            };
            let _ = writeln!(
                out,
                "\n### job `{}`\n\nNeeds: {needs}. Gate: {}.\n",
                md(&job.id),
                md(job.environment.as_deref().unwrap_or("none"))
            );
            out.push_str("| # | Original step | Became | Notes |\n| --- | --- | --- | --- |\n");
            for (i, row) in job.rows.iter().enumerate() {
                let row = (i + 1, &row.original, &row.became, &row.notes);
                let _ =
                    writeln!(out, "| {} | {} | {} | {} |", row.0, md(row.1), md(row.2), md(row.3));
            }
        }
    }
    out.push_str("\n## Untranslated constructs\n\n");
    let every: Vec<&String> = workflows.iter().flat_map(|wf| &wf.untranslated).collect();
    if every.is_empty() {
        out.push_str("None: every construct in these workflows was carried over.\n");
    }
    for line in every {
        let _ = writeln!(out, "- {}", md(line));
    }
    out
}

/// A value's `owner/name@ref` as its `owner/name`, lowercased: the corpus spells
/// the same action as both `azure/k8s-deploy` and `Azure/k8s-deploy`.
fn action_of(uses: &str) -> String {
    uses.split('@').next().unwrap_or(uses).to_ascii_lowercase()
}

fn get<'a>(map: &'a Mapping, key: &str) -> Option<&'a Value> {
    map.get(Value::String(key.to_string()))
}

fn str_of<'a>(map: &'a Mapping, key: &str) -> Option<&'a str> {
    text(get(map, key)?)
}

fn sub(map: &Mapping, key: &str) -> Option<Mapping> {
    get(map, key).and_then(Value::as_mapping).cloned()
}

fn text(v: &Value) -> Option<&str> {
    match v {
        Value::String(s) => Some(s),
        _ => None,
    }
}

fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        other => one_line(&format!("{other:?}")),
    }
}

fn list_of(v: &Value) -> Vec<String> {
    match v {
        Value::Sequence(list) => list.iter().map(as_text).collect(),
        other => vec![as_text(other)],
    }
}

/// A value on one line: a table cell, a stub comment and a value in the
/// language are all single-line, so a value that is not is rewritten as one.
fn one_line(raw: &str) -> String {
    let flat: String = raw.chars().map(|c| if c.is_whitespace() { ' ' } else { c }).collect();
    flat.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A path the workflow gave us, or the reason it is not one this file can write
/// down: a `dir:` or `manifests:` that leaves the repository names something the
/// ship file has no name for.
fn one_of(raw: Option<&str>) -> (Option<String>, bool) {
    let raw = raw.unwrap_or_default();
    if raw.is_empty() {
        return (None, false);
    }
    match rel_path(raw) {
        Some(p) => (Some(p), false),
        None => (None, true),
    }
}

/// Why a key was left out, or nothing when it was not.
fn into_the_void(out: bool, key: &str) -> Option<String> {
    out.then(|| format!("`{key}` is not a path in this repository, and is not translated"))
}

fn md(raw: &str) -> String {
    one_line(raw).replace('|', "\\|")
}

fn quoted(raw: &str) -> String {
    format!("\"{}\"", one_line(raw).replace('\\', "\\\\").replace('"', "\\\""))
}

/// A value bare or quoted: bare when every character is one a word may carry.
/// `extra` names the characters this value may carry beyond the common set, so
/// a glob, which a `*` makes not a word, is quoted unless the caller allows it.
fn scalar(raw: &str, extra: &str) -> String {
    let bare = !raw.is_empty()
        && !raw.starts_with('-')
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:/@{}~-".contains(c) || extra.contains(c));
    if bare { raw.to_string() } else { quoted(raw) }
}

fn path(dir: &str) -> String {
    let bare = dir == "." || dir == ".." || dir.starts_with('/');
    if bare || dir.starts_with("./") || dir.starts_with("../") {
        dir.to_string()
    } else {
        format!("./{dir}")
    }
}

fn rel_path(raw: &str) -> Option<String> {
    let path = raw.trim();
    // Nothing outside the repository is written into a ship file, and neither is
    // anything the caller wrote as an expression or as a flag.
    let outside = path.is_empty()
        || path.contains("${{")
        || path.contains(['\n', '"'])
        || path.starts_with(['/', '~', '-'])
        || path.split('/').any(|part| part == "..");
    (!outside).then(|| path.trim_start_matches("./").to_string())
}

/// The `terraform`/`tofu` subcommand a line runs, if it runs one.
fn tofu(line: &str) -> Option<&'static str> {
    let mut words = line.split_whitespace();
    // The command is the first word of the line: `echo "terraform apply"` runs no
    // tofu at all. The subcommand is the first word after it that is not a flag,
    // so `tofu -chdir=infra apply` is an apply and `tofu output` is nothing.
    if !matches!(words.next()?, "terraform" | "tofu" | "opentofu" | "terragrunt") {
        return None;
    }
    for word in words {
        if word.starts_with('-') {
            continue;
        }
        return match word {
            "plan" => Some("plan"),
            "apply" => Some("apply"),
            "init" => Some("init"),
            _ => None,
        };
    }
    None
}

/// The value a line gives the flag `name`, whether it wrote `-flag=x` or
/// `-flag x`.
fn flag<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if let Some(value) = word.strip_prefix(&format!("{name}=")) {
            return Some(value);
        }
        if word == name {
            return words.next();
        }
    }
    None
}

/// `${{ … }}` to what this language spells it, where there is a spelling.
/// Anything else — a step's output, a matrix value, a secret — has none, and
/// the caller leaves the value out rather than guess at it.
fn resolve(raw: &str, env: &Mapping) -> Option<String> {
    let mut out = String::new();
    let mut rest = raw;
    while let Some(start) = rest.find("${{") {
        out.push_str(&rest[..start]);
        let end = rest[start..].find("}}")? + start;
        let expr = rest[start + 3..end].trim();
        let spelled = match expr {
            "github.sha" => Some("{git.sha}"),
            "github.ref" | "github.ref_name" => Some("{git.ref}"),
            other => {
                // A value from the workflow's `env:` is data, not a reference:
                // one carrying braces would be read as one at run time.
                let value = str_of(env, other.strip_prefix("env.")?)?;
                if value.contains(['{', '}', '"', '\n']) {
                    return None;
                }
                Some(value)
            }
        };
        out.push_str(spelled?);
        rest = &rest[end + 2..];
    }
    out.push_str(rest);
    Some(out)
}

/// The workflow's `env:` with the job's on top: where a literal `${{ env.X }}`
/// is read from.
fn job_env(wf_env: &Mapping, job: &Mapping) -> Mapping {
    let mut env = wf_env.clone();
    env.extend(sub(job, "env").unwrap_or_default());
    env
}

fn job_environment(job: &Mapping) -> Option<String> {
    match get(job, "environment")? {
        Value::Mapping(map) => {
            let (_, value) = map.iter().find(|(k, _)| as_text(k) == "name")?;
            text(value).map(str::to_string)
        }
        other => text(other).map(str::to_string),
    }
}

fn label(step: &Mapping) -> String {
    str_of(step, "name")
        .or_else(|| str_of(step, "uses"))
        .map(str::to_string)
        .or_else(|| str_of(step, "run").map(|r| r.lines().next().unwrap_or("run").to_string()))
        .unwrap_or_else(|| "a step".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_values_keep_what_a_step_may_carry() {
        assert_eq!(slug("Terraform Plan"), "terraform-plan");
        assert_eq!(slug("9lives"), "s9lives");
        assert_eq!(slug(""), "step");
        assert_eq!(safe("node.js", "workflow"), "node-js");
        assert_eq!(scalar("ghcr.io/acme/api:{git.sha}", ""), "ghcr.io/acme/api:{git.sha}");
        assert_eq!(scalar("has # hash", ""), "\"has # hash\"");
        assert_eq!(scalar("v*.*.*", ""), "\"v*.*.*\"");
    }

    #[test]
    fn expressions_resolve_to_the_context_nameship_has() {
        let mut env = Mapping::new();
        env.insert(Value::String("REGISTRY".into()), Value::String("ghcr.io".into()));
        let at = "${{ env.REGISTRY }}/${{ github.sha }}";
        assert_eq!(resolve(at, &env).unwrap(), "ghcr.io/{git.sha}");
        // Another step's output has no spelling here, so the caller leaves the
        // value out rather than invent one.
        assert_eq!(resolve("${{ steps.meta.outputs.tags }}", &env), None);
        assert_eq!(resolve("${{ secrets.TOKEN }}", &env), None);
    }

    #[test]
    fn a_value_the_ship_file_would_read_as_something_else_is_left_out() {
        let mut env = Mapping::new();
        env.insert(Value::String("TAG".into()), Value::String("v{1}".into()));
        // A `{` here would be read at run time as a reference to `1`.
        assert_eq!(resolve("${{ env.TAG }}", &env), None);
        assert_eq!(rel_path("../secrets"), None);
        assert_eq!(rel_path("/etc/keepshipping"), None);
        assert_eq!(rel_path("k8s/"), Some("k8s/".to_string()));
        // Free text lands in a comment on one line, or the comment ends early.
        assert_eq!(one_line("Odd\nName"), "Odd Name");
        // The subcommand is the first word after the command, so a mention of
        // one in a script is not a run of it.
        assert_eq!(tofu("echo \"terraform apply later\""), None);
        assert_eq!(tofu("terraform -chdir=infra apply"), Some("apply"));
        assert_eq!(tofu("tofu output"), None);
    }

    #[test]
    fn a_step_that_already_reads_its_predecessor_gets_no_extra_edge() {
        let mut used = HashSet::new();
        let mut plan = new_step("job", "plan", "tofu.plan", &mut used);
        plan.inputs.push(("dir".into(), ".".into()));
        let mut review = new_step("job", "review", "approval", &mut used);
        review.inputs.push(("show".into(), "job-plan.changes".into()));
        let mut apply = new_step("job", "apply", "tofu.apply", &mut used);
        apply.inputs.push(("plan".into(), "job-plan.file".into()));
        let mut steps = vec![plan, review, apply];
        chain(&mut steps, &[]);
        assert!(steps[0].after.is_empty());
        assert!(steps[1].after.is_empty(), "the reference is the edge already");
        assert_eq!(steps[2].after, ["job-review".to_string()]);
    }
}
