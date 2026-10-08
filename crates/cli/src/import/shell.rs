//! `keepshipping import shell <script.sh>` — a deployment script in, a `.ks`
//! file out.
//!
//! This is deliberately **not** a shell parser. It is a line-oriented scan
//! that recognises a fixed vocabulary of deploy commands and says, plainly,
//! what it did not recognise. A real parser would have to be right about
//! quoting, subshells, `eval` and redirections to be right about any of it;
//! an importer that is *wrong* about a script is worse than one that is unsure,
//! so everything uncertain ends up in the report and in one script step the
//! operator must write.
//!
//! Two rules make the output honest, and both are enforced by the tests:
//!
//! - **Only real kinds are emitted.** An unknown kind type-checks clean, so a
//!   converter that invented `helm.upgrade` would pass `keepshipping check`
//!   while producing a file that cannot run. Every kind this writes is in
//!   [`ks_core::Catalog::builtin`].
//! - **Nothing is dropped silently.** Every command that was not recognised is
//!   reported by line, with a suggestion. Every piece of control flow is
//!   reported too: `if`/`for`/`while`/`case`/heredocs have no representation
//!   in `.ks` at all, which is exactly why they belong in a script step.
//!
//! What could not be recognised is wrapped in one script step at the end,
//! `action:` set to the most severe action class seen. No `approval` step is
//! emitted: putting the gate in is the operator's call, and an approval that
//! does not cover what follows trips the `UncoveredArtifact` rule anyway.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::args::USAGE;

/// How dangerous the wrapped commands look, as `action:` spells it. The order
/// is the severity ladder, `build` least to `destroy` most.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Action {
    Other,
    Build,
    Plan,
    Apply,
    Deploy,
    Destroy,
}

impl Action {
    /// The word a script step's `action:` is written as.
    fn as_str(self) -> &'static str {
        match self {
            Action::Other => "other",
            Action::Build => "build",
            Action::Plan => "plan",
            Action::Apply => "apply",
            Action::Deploy => "deploy",
            Action::Destroy => "destroy",
        }
    }

    /// The class a command verb belongs to; anything unnamed is [`Action::Other`].
    fn of(word: &str) -> Self {
        match word {
            "build" | "compile" | "package" | "bundle" => Action::Build,
            "plan" | "diff" | "preview" => Action::Plan,
            "apply" | "create" | "update" | "migrate" | "provision" => Action::Apply,
            "deploy" | "rollout" | "restart" | "start" | "publish" | "release" => Action::Deploy,
            "destroy" | "delete" | "rm" | "drop" | "teardown" | "down" | "uninstall" => {
                Action::Destroy
            }
            _ => Action::Other,
        }
    }
}

/// Which of the two OpenTofu/Terraform spellings a command used.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tool {
    Tofu,
    Terraform,
}

impl Tool {
    fn of(word: &str) -> Option<Self> {
        match word {
            "tofu" => Some(Tool::Tofu),
            "terraform" => Some(Tool::Terraform),
            _ => None,
        }
    }

    /// The command that names it, for a message about what it cannot do.
    fn name(self) -> &'static str {
        match self {
            Tool::Tofu => "tofu",
            Tool::Terraform => "terraform",
        }
    }

    /// The plan and apply step kinds this tool's steps are named.
    fn kinds(self) -> (&'static str, &'static str) {
        match self {
            Tool::Tofu => ("tofu.plan", "tofu.apply"),
            Tool::Terraform => ("terraform.plan", "terraform.apply"),
        }
    }
}

/// What a recognised command became.
enum Body {
    /// `docker build`
    Image { from: String, context: Option<String>, push: Option<String> },
    /// `tofu plan` / `terraform plan`
    Plan { tool: Tool, dir: String },
    /// `tofu apply <planfile>` / `terraform apply <planfile>`
    Apply { tool: Tool, plan: String },
    /// `kubectl apply` / `kubectl set image` / `kubectl rollout` / `helm upgrade`
    Rollout { image: String },
    /// `ssh`, hoisted out of whatever loop it was in
    Vm { hosts: Vec<String>, run: Vec<String> },
    /// everything else, for the operator to write
    Script { kind: String, action: Action },
}

impl Body {
    /// A built-in kind, or the `./x.ts` escape hatch.
    fn kind(&self) -> String {
        match self {
            Body::Image { .. } => "oci.image".to_string(),
            Body::Plan { tool, .. } => tool.kinds().0.to_string(),
            Body::Apply { tool, .. } => tool.kinds().1.to_string(),
            Body::Rollout { .. } => "k8s.rollout".to_string(),
            Body::Vm { .. } => "vm.deploy".to_string(),
            Body::Script { kind, .. } => kind.clone(),
        }
    }
}

/// One step of the emitted file.
struct Step {
    id: String,
    body: Body,
    /// Ordering the references do not already imply.
    after: Vec<String>,
}

/// A command that became a step: where it was, what it became, how it was written.
struct Rec {
    line: usize,
    step: String,
    kind: String,
    command: String,
}

/// A command that became nothing, and what it might have become instead.
struct Unrec {
    line: usize,
    command: String,
    suggestion: String,
}

/// Control flow, which has no home in `.ks` and stays in the script step.
struct Flow {
    line: usize,
    text: String,
}

/// Everything one script turned into.
struct Converted {
    name: String,
    steps: Vec<Step>,
    recognised: Vec<Rec>,
    unrecognised: Vec<Unrec>,
    control_flow: Vec<Flow>,
    envs: Vec<(String, usize)>,
    set_flags: Vec<(String, usize)>,
    /// The most severe class among the *unrecognised* commands.
    severity: Action,
    /// One-off notes about what was folded or flattened.
    notes: Vec<String>,
    /// The line that gave the image its `push:`.
    push_line: Option<usize>,
}

impl Converted {
    /// The script step, if one was emitted.
    fn script_step(&self) -> Option<&Step> {
        self.steps.iter().find(|s| matches!(s.body, Body::Script { .. }))
    }

    fn kind_of(&self, id: &str) -> String {
        self.steps.iter().find(|s| s.id == id).map_or_else(String::new, Step::kind)
    }
}

impl Step {
    fn kind(&self) -> String {
        self.body.kind()
    }
}

/// `keepshipping import shell <script.sh> [--out FILE]`.
pub fn shell(args: &[String]) -> ExitCode {
    let Some((script, out)) = parse_args(args) else {
        return usage("import shell needs a script to read, e.g. `import shell deploy.sh`");
    };
    let src = match std::fs::read_to_string(&script) {
        Ok(src) => src,
        Err(e) => return usage(&format!("cannot read {}: {e}", script.display())),
    };
    // A `ship.ks` is the one file in a repository that is never a throwaway:
    // refusing to overwrite is the safe reading of "best effort".
    if out.exists() {
        return usage(&format!("{} already exists: name another file with --out", out.display()));
    }
    let converted = convert(&src, &script);
    if let Err(e) = std::fs::write(&out, render(&converted)) {
        eprintln!("error: cannot write {}: {e}", out.display());
        return ExitCode::from(1);
    }
    let mut stdout = std::io::stdout().lock();
    let _ = report(&mut stdout, &converted, &script, &out);
    ExitCode::SUCCESS
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("{USAGE}");
    if !msg.is_empty() {
        eprintln!("{msg}");
    }
    ExitCode::from(2)
}

/// `<script.sh> [--out FILE]`, hand-parsed — `import` has no global flags.
fn parse_args(args: &[String]) -> Option<(PathBuf, PathBuf)> {
    let mut script: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                let value = args.get(i + 1)?;
                if value.starts_with("--") {
                    return None;
                }
                out = Some(PathBuf::from(value));
                i += 2;
            }
            other if other.starts_with('-') && other != "-" => return None,
            other => {
                if script.is_some() {
                    return None;
                }
                script = Some(PathBuf::from(other));
                i += 1;
            }
        }
    }
    let script = script?;
    let stem = file_stem(&script);
    Some((script, out.unwrap_or_else(|| PathBuf::from(format!("{stem}.ks")))))
}

// ---------------------------------------------------------------------------
// scanning
// ---------------------------------------------------------------------------

/// The scan: a fixed vocabulary, everything outside it reported rather than guessed.
fn convert(src: &str, script: &Path) -> Converted {
    let stem = file_stem(script);
    let mut out = Converted {
        name: stem.clone(),
        steps: Vec::new(),
        recognised: Vec::new(),
        unrecognised: Vec::new(),
        control_flow: Vec::new(),
        envs: Vec::new(),
        set_flags: Vec::new(),
        severity: Action::Other,
        notes: Vec::new(),
        push_line: None,
    };

    // Plan files remembered from `-out`, so a later `apply` can name its step.
    let mut plans: Vec<PlanFile> = Vec::new();
    // `for VAR in a b c` loops, innermost last, so `ssh $VAR` inside one expands.
    let mut loops: Vec<Loop> = Vec::new();
    // The step ids a later step may need to be wired to.
    let mut build: Option<String> = None;
    let mut rollout: Option<String> = None;
    let mut vm: Option<String> = None;
    // The terminator of a heredoc whose body is still being read.
    let mut heredoc: Option<String> = None;

    let lines: Vec<&str> = src.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let raw = lines[index];
        // The line a command *started* on, which is the line the report cites
        // and the line a reader will look up — never a continuation's own line.
        let line = index + 1;
        index += 1;
        if let Some(term) = heredoc.as_ref() {
            if raw.trim() == term {
                heredoc = None;
            }
            continue;
        }
        // A trailing backslash continues the command onto the next line, so the
        // whole logical command is scanned as one. Otherwise `docker build \` /
        // `-f Dockerfile \` / `.` reads as three commands, two of them flags.
        let mut text = strip_comment(raw).trim().to_string();
        while continues(&text) && index < lines.len() {
            text.pop();
            text.push(' ');
            text.push_str(strip_comment(lines[index]).trim());
            index += 1;
        }
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        // A heredoc opener is control flow as far as `.ks` is concerned: the
        // body is text, not commands, and must not be scanned for either.
        if let Some(term) = heredoc_terminator(text) {
            out.control_flow.push(Flow { line, text: first_words(text, 3) });
            heredoc = Some(term);
            continue;
        }
        for command in split_commands(text) {
            scan_command(
                &command,
                text,
                line,
                &mut out,
                &mut plans,
                &mut loops,
                &mut build,
                &mut rollout,
                &mut vm,
            );
        }
    }

    // Everything unrecognised, and every piece of control flow, is what the script step is for.
    if !out.unrecognised.is_empty() || !out.control_flow.is_empty() {
        let kind = format!("./{stem}.ts");
        let id = fresh_id(&out.steps, &stem);
        // Last in the file and after everything: it is the script's tail.
        let after: Vec<String> = out.steps.iter().map(|s| s.id.clone()).collect();
        out.steps.push(Step {
            id: id.clone(),
            body: Body::Script { kind: kind.clone(), action: out.severity },
            after,
        });
        out.notes.push(format!(
            "{id} is a script step: everything this scan did not recognise is inside it, and {kind} \
             does not exist yet — you write it"
        ));
    }
    out
}

/// A plan file a `plan` step wrote, and the step that wrote it.
struct PlanFile {
    tool: Tool,
    file: String,
    step: String,
}

/// A `for VAR in a b c` loop, remembered so `ssh $VAR` inside it can name hosts.
struct Loop {
    var: String,
    items: Vec<String>,
}

/// One command at a time, against the scan's own state.
#[expect(clippy::too_many_arguments, reason = "the scan's state, threaded")]
fn scan_command(
    command: &str,
    // The whole line, which names control flow better than the command it was
    // split into can: `if [ -n "$X" ]; then` keeps its test.
    text: &str,
    line: usize,
    out: &mut Converted,
    plans: &mut Vec<PlanFile>,
    loops: &mut Vec<Loop>,
    build: &mut Option<String>,
    rollout: &mut Option<String>,
    vm: &mut Option<String>,
) {
    let mut words = tokens(command);
    if words.is_empty() {
        return;
    }
    let mut spelling = command.to_string();
    match words[0].as_str() {
        "set" => {
            let flags = words[1..].join(" ");
            if !flags.is_empty() && !out.set_flags.iter().any(|(f, _)| *f == flags) {
                out.set_flags.push((flags, line));
            }
            return;
        }
        "export" => {
            if let Some(name) = words.get(1).and_then(|w| assign_name(w)) {
                note_env(&mut out.envs, name, line);
                return;
            }
        }
        "if" | "for" | "while" | "until" | "case" | "select" | "function" => {
            out.control_flow.push(Flow { line, text: text.trim().to_string() });
            if words[0] == "for" {
                note_loop(&words, line, loops);
            }
            return;
        }
        // The closing half of control flow, and nothing else.
        "fi" | "done" | "esac" | "then" | "else" | "elif" | "do" | "}" | "{" => return,
        _ => {}
    }
    if is_function_definition(&words) {
        out.control_flow.push(Flow { line, text: text.trim().to_string() });
        return;
    }
    if let Some(name) = assign_name(&words[0]) {
        note_env(&mut out.envs, name, line);
        return;
    }
    // `sudo` and `env NAME=v` wrap a command; the wrapper is not it.
    unwrap(&mut words, &mut spelling);

    // `docker push` folds into the build: KS pushes as part of building, and
    // there is no `oci.push` step.
    if words.len() >= 3 && words[0] == "docker" && words[1] == "push" {
        let tag = words[2].clone();
        let folded = build.as_ref().filter(|id| {
            out.steps.iter().any(|s| s.id == **id && matches!(s.body, Body::Image { .. }))
        });
        match folded {
            Some(id) => {
                // First push wins: later ones are usually extra tags or
                // variants, and the first is the tag the build itself named.
                if let Some(step) = out.steps.iter_mut().find(|s| s.id == *id)
                    && let Body::Image { push, .. } = &mut step.body
                    && push.is_none()
                {
                    *push = Some(tag);
                    out.push_line = Some(line);
                }
                out.recognised.push(Rec {
                    line,
                    step: id.clone(),
                    kind: out.kind_of(id),
                    command: spelling,
                });
                if !out.notes.iter().any(|n| n.starts_with("every `docker push`")) {
                    out.notes.push(format!(
                        "every `docker push` was folded into the `oci.image` step's `push:` — the \
                         first one wins, and line {} set it",
                        out.push_line.unwrap_or(line)
                    ));
                }
            }
            None => out.unrecognised.push(Unrec {
                line,
                command: spelling,
                suggestion: "a push with no build before it: KS pushes as part of oci.image, so \
                             put the tag on the docker build"
                    .to_string(),
            }),
        }
        return;
    }

    match recognise(&words, line, out, plans, build, rollout, vm, loops) {
        Ok(rec) => out.recognised.push(rec),
        Err(suggestion) => {
            out.unrecognised.push(Unrec { line, command: spelling, suggestion });
            out.severity = out.severity.max(Action::of(&words[0]));
        }
    }
}

/// Recognise one command, returning the report row when it did. Every arm that
/// returns a row has already pushed its step into `out.steps`.
#[expect(clippy::too_many_arguments, reason = "the scan's state, threaded")]
fn recognise(
    words: &[String],
    line: usize,
    out: &mut Converted,
    plans: &mut Vec<PlanFile>,
    build: &mut Option<String>,
    rollout: &mut Option<String>,
    vm: &mut Option<String>,
    loops: &[Loop],
) -> Result<Rec, String> {
    if words.len() >= 2 && words[0] == "docker" && words[1] == "build" {
        return Ok(docker_build(words, line, out, build));
    }
    if words[0] == "docker" {
        return Err(format!(
            "`docker {}` has no step kind: oci.image is the only docker-shaped thing in KS, and \
             it covers build and push",
            words.get(1).map_or("*", String::as_str)
        ));
    }
    if let Some(tool) = Tool::of(&words[0]) {
        let sub = words.get(1).map_or("", String::as_str);
        return match sub {
            "plan" => Ok(plan(tool, words, line, out, plans)),
            "apply" => apply(tool, words, line, out, plans, build),
            _ => Err(format!(
                "`{} {sub}` is not a step: KS plans with {tool}.plan and applies with {tool}.apply",
                words[0],
                tool = tool.name()
            )),
        };
    }
    if words.first().is_some_and(|w| w == "kubectl" || w == "helm") {
        return kube(words, line, out, build, rollout);
    }
    if words[0] == "ssh" {
        return Ok(ssh(words, line, out, vm, loops));
    }
    Err(suggest(words))
}

/// `docker build [-f FILE] [-t TAG] [CONTEXT]`.
fn docker_build(
    words: &[String],
    line: usize,
    out: &mut Converted,
    build: &mut Option<String>,
) -> Rec {
    let mut tag = None;
    let mut file = None;
    let mut positional = Vec::new();
    for pair in Flag::of(words, 2) {
        match pair {
            Flag::Word(word) => positional.push(word),
            Flag::Short(name, Some(value)) | Flag::Long(name, Some(value))
                if matches!(name.as_str(), "t" | "tag") =>
            {
                tag = Some(value)
            }
            Flag::Short(name, Some(value)) | Flag::Long(name, Some(value))
                if matches!(name.as_str(), "f" | "file") =>
            {
                file = Some(value)
            }
            _ => {}
        }
    }
    let context = positional.first().cloned().unwrap_or_else(|| ".".to_string());
    // With `-f` the file is `from` and the context sits beside it; with no
    // `-f` the context is all the script named.
    let (from, context) = match file {
        Some(file) => (file, Some(context)),
        None => (context, None),
    };
    let id = fresh_id(&out.steps, "build");
    out.steps.push(Step {
        id: id.clone(),
        body: Body::Image { from, context, push: tag.clone() },
        after: Vec::new(),
    });
    if tag.is_some() {
        out.push_line = Some(line);
    }
    *build = Some(id.clone());
    Rec { line, step: id, kind: "oci.image".to_string(), command: spell(words) }
}

/// `tofu plan` / `terraform plan`.
fn plan(
    tool: Tool,
    words: &[String],
    line: usize,
    out: &mut Converted,
    plans: &mut Vec<PlanFile>,
) -> Rec {
    let mut out_file = None;
    let mut positional = Vec::new();
    for pair in Flag::of(words, 2) {
        match pair {
            Flag::Word(word) => positional.push(word),
            Flag::Short(name, Some(value)) | Flag::Long(name, Some(value)) if name == "out" => {
                out_file = Some(value)
            }
            _ => {}
        }
    }
    let dir = positional.first().cloned().unwrap_or_else(|| ".".to_string());
    let id = fresh_id(&out.steps, "plan");
    out.steps.push(Step { id: id.clone(), body: Body::Plan { tool, dir }, after: Vec::new() });
    if let Some(file) = out_file {
        plans.push(PlanFile { tool, file, step: id.clone() });
    }
    Rec { line, step: id, kind: tool.kinds().0.to_string(), command: spell(words) }
}

/// `tofu apply FILE` / `terraform apply FILE`. A plan file is the only way in:
/// a bare `apply` replans, which is not the same run.
fn apply(
    tool: Tool,
    words: &[String],
    line: usize,
    out: &mut Converted,
    plans: &[PlanFile],
    build: &Option<String>,
) -> Result<Rec, String> {
    let file = words.get(2).cloned().unwrap_or_default();
    let Some(plan_file) = plans.iter().find(|p| p.tool == tool && p.file == file) else {
        return Err(if file.is_empty() {
            format!(
                "`{} apply` with no plan file plans and applies in one go: KS wants the plan \
                 reviewed first, so plan it with -out=FILE and apply that file",
                tool.name()
            )
        } else if let Some(other) = plans.iter().find(|p| p.tool != tool && p.file == file) {
            return Err(format!(
                "{file} was written by {}, and the two plan file types are not interchangeable",
                other.tool.name()
            ));
        } else {
            return Err(format!(
                "no step planned {file}: only the file a plan step wrote with -out can be applied"
            ));
        });
    };
    let id = fresh_id(&out.steps, "apply");
    // `plan.file` is already an edge; the build is not.
    let after = build.clone().into_iter().collect();
    out.steps.push(Step {
        id: id.clone(),
        body: Body::Apply { tool, plan: format!("{}.file", plan_file.step) },
        after,
    });
    Ok(Rec { line, step: id, kind: tool.kinds().1.to_string(), command: spell(words) })
}

/// `kubectl apply -f`, `kubectl set image`, `kubectl rollout`, `helm upgrade` —
/// in `.ks`, every one is a rollout of one image.
fn kube(
    words: &[String],
    line: usize,
    out: &mut Converted,
    build: &Option<String>,
    rollout: &mut Option<String>,
) -> Result<Rec, String> {
    // A rollout is an image, and only `oci.image` produces one — so a script
    // that deploys what it did not build has nothing honest to turn into.
    let Some(build) = build.clone() else {
        return Err(
            "KS has no standalone helm or kubectl step: a k8s.rollout needs an image, and only an \
             oci.image step produces one — build and push the image first"
                .to_string(),
        );
    };
    let id = match rollout.clone() {
        Some(id) => id,
        None => {
            let id = fresh_id(&out.steps, "deploy");
            let after = out
                .steps
                .iter()
                .find(|s| matches!(s.body, Body::Apply { .. }))
                .map(|s| s.id.clone())
                .into_iter()
                .collect();
            out.steps.push(Step {
                id: id.clone(),
                // A digest, never the tag: a tag is a moving name.
                body: Body::Rollout { image: format!("{build}.digest") },
                after,
            });
            *rollout = Some(id.clone());
            id
        }
    };
    Ok(Rec { line, step: id, kind: "k8s.rollout".to_string(), command: spell(words) })
}

/// `ssh HOST COMMAND`, wherever in the script it was written.
fn ssh(
    words: &[String],
    line: usize,
    out: &mut Converted,
    vm: &mut Option<String>,
    loops: &[Loop],
) -> Rec {
    let mut i = 1;
    while i < words.len() && words[i].starts_with('-') {
        i += if matches!(
            words[i].as_str(),
            "-i" | "-p"
                | "-o"
                | "-l"
                | "-F"
                | "-c"
                | "-J"
                | "-E"
                | "-b"
                | "-D"
                | "-L"
                | "-R"
                | "-W"
        ) {
            2
        } else {
            1
        };
    }
    let hosts = expand(&words.get(i).cloned().unwrap_or_default(), loops);
    let command: Vec<String> = words[i + 1..].iter().flat_map(|w| expand(w, loops)).collect();
    let id = match vm.clone() {
        Some(id) => id,
        None => {
            let id = fresh_id(&out.steps, "vm");
            out.steps.push(Step {
                id: id.clone(),
                body: Body::Vm { hosts: Vec::new(), run: Vec::new() },
                after: Vec::new(),
            });
            *vm = Some(id.clone());
            id
        }
    };
    if let Some(step) = out.steps.iter_mut().find(|s| s.id == id)
        && let Body::Vm { hosts: all, run } = &mut step.body
    {
        // Every distinct host and command across the script goes into one
        // fleet: `vm.deploy` has no loop of its own.
        let new = hosts.into_iter().filter(|h| !all.contains(h)).collect::<Vec<_>>();
        all.extend(new);
        let commands = command.join(" ");
        if !commands.is_empty() && !run.contains(&commands) {
            run.push(commands);
        }
    }
    Rec { line, step: id, kind: "vm.deploy".to_string(), command: spell(words) }
}

/// A flag-aware walk of a command's arguments: flags are paired with the values
/// they take, and what is left is positional.
enum Flag {
    Short(String, Option<String>),
    Long(String, Option<String>),
    Word(String),
}

impl Flag {
    /// From `start` on, pairing a flag with the value it takes. A flag missing
    /// its value is the script's mistake; guessing at the next word would be
    /// this converter's mistake too.
    fn of(words: &[String], start: usize) -> impl Iterator<Item = Flag> + '_ {
        let mut i = start;
        let mut pending: Option<(String, bool)> = None;
        std::iter::from_fn(move || {
            let word = words.get(i)?;
            i += 1;
            match pending.take() {
                Some((name, long)) if !word.starts_with('-') => {
                    return Some(if long {
                        Flag::Long(name, Some(word.clone()))
                    } else {
                        Flag::Short(name, Some(word.clone()))
                    });
                }
                _ => {}
            }
            if let Some(long) = word.strip_prefix("--") {
                if let Some((name, value)) = long.split_once('=') {
                    return Some(Flag::Long(name.to_string(), Some(value.to_string())));
                }
                return Some(Flag::Long(long.to_string(), None));
            }
            if word.len() > 1 && word.starts_with('-') {
                // A single dash does not mean one letter: the name is the run
                // of letters and the value is whatever follows the `=`.
                let rest = &word[1..];
                let letters =
                    rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_alphabetic()).len();
                let (name, value) = rest.split_at(letters);
                let value = value.strip_prefix('=').map(str::to_string);
                let name = name.to_string();
                if value.is_none() {
                    pending = Some((name.clone(), false));
                }
                return Some(Flag::Short(name, value));
            }
            Some(Flag::Word(word.clone()))
        })
    }
}

/// The command as the script wrote it, from the words we kept.
fn spell(words: &[String]) -> String {
    words.join(" ")
}

fn note_env(envs: &mut Vec<(String, usize)>, name: String, line: usize) {
    if !envs.iter().any(|(n, _)| *n == name) {
        envs.push((name, line));
    }
}

/// `VAR=value` and `export VAR=value`, reported as variables the operator may
/// want under `envs:`. No `envs:` block is invented.
fn assign_name(word: &str) -> Option<String> {
    let (name, _) = word.split_once('=')?;
    let ok = !name.is_empty()
        && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    ok.then(|| name.to_string())
}

fn is_function_definition(words: &[String]) -> bool {
    match words {
        [name, ..] if name.ends_with("()") => true,
        [first, second, ..] if second == "{" => {
            !matches!(first.as_str(), "if" | "for" | "while" | "function" | "until" | "case")
        }
        _ => false,
    }
}

/// `for VAR in a b c; do`, remembered so `ssh $VAR` inside it can name hosts.
fn note_loop(words: &[String], line: usize, loops: &mut Vec<Loop>) {
    let Some(var) = words
        .get(1)
        .filter(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    else {
        return;
    };
    let mut i = 2;
    if words.get(i).is_some_and(|w| w == "in") {
        i += 1;
    }
    let items: Vec<String> = words[i..].to_vec();
    if !items.is_empty() {
        loops.push(Loop { var: var.clone(), items });
    }
    let _ = line;
}

/// The terminator of a heredoc, if this line opens one.
fn heredoc_terminator(text: &str) -> Option<String> {
    let after = text.split_once("<<")?.1.trim_start();
    let word: String = after
        .trim_start_matches('-')
        .trim_start_matches(['\'', '"'])
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, '<' | ';' | '|' | '&'))
        .collect();
    (!word.is_empty() && !word.contains('$') && !word.contains('`')).then_some(word)
}

/// One word with `$VAR` from a `for` loop above it expanded, so `for h in web-1
/// web-2` names two hosts rather than the loop variable.
fn expand(word: &str, loops: &[Loop]) -> Vec<String> {
    for l in loops {
        if word == format!("${{{}}}", l.var) || word == format!("${}", l.var) {
            return l.items.clone();
        }
    }
    vec![word.to_string()]
}

/// `sudo` and `env NAME=v` wrap a command; the wrapper is not it.
fn unwrap(words: &mut Vec<String>, spelling: &mut String) {
    let mut dropped = 0usize;
    loop {
        let head = words.first().map(String::as_str);
        if head == Some("sudo") || head == Some("doas") {
            dropped += 1;
            words.remove(0);
        } else if head == Some("env") && words.get(1).is_some_and(|w| w.contains('=')) {
            dropped += 2;
            words.drain(0..2);
        } else {
            break;
        }
    }
    if dropped > 0 {
        *spelling = words.join(" ");
    }
}

/// What an unrecognised command might have become, by the tool it names.
const SUGGESTIONS: &[(&[&str], &str)] = &[
    (
        &["aws", "gcloud", "az", "doctl"],
        "no step kind talks to a cloud CLI: this is the script step's job",
    ),
    (
        &["npm", "yarn", "pnpm", "make", "cargo", "go", "gradle", "mvn"],
        "a build with no image: oci.image builds a Dockerfile, and nothing else does",
    ),
    (&["curl", "wget"], "no step kind makes an HTTP call: the script step's job"),
    (&["psql", "mysql", "redis-cli"], "no step kind opens a database: the script step's job"),
    (&["git"], "the trigger does this: a push to a branch is what an `on:` line names"),
    (
        &["cd", "pushd"],
        "no step changes directory: the path belongs on the step, as `dir:` or `from:`",
    ),
    (
        &["systemctl", "service", "launchctl"],
        "no step kind restarts a service: vm.deploy runs commands over ssh",
    ),
    (
        &["apt", "apt-get", "yum", "dnf", "brew", "apk"],
        "no step kind installs packages: the script step's job",
    ),
    (&["rm", "rmdir"], "deletion has no step kind: name the class in the script step's `action:`"),
    (&["kubectl", "helm"], "a rollout needs an image, and only oci.image produces one"),
    (
        &["echo", "printf", "true", "false", "pwd", "whoami", "date", "basename"],
        "nothing a pipeline step needs: this line can go",
    ),
    (&["sleep"], "a step waits on `health` and `health_timeout`, not on sleep"),
];

/// What an unrecognised command might have become. A lookup first, a generic
/// answer second.
fn suggest(words: &[String]) -> String {
    let tool = words.first().map_or("", String::as_str);
    if let Some((_, why)) = SUGGESTIONS.iter().find(|(tools, _)| tools.contains(&tool)) {
        return (*why).to_string();
    }
    let sub = words.get(1).map_or("", String::as_str);
    if !sub.is_empty() && tool.chars().all(|c| c.is_ascii_lowercase()) {
        return format!(
            "`{tool} {sub}` has no step kind: KS knows a fixed vocabulary, and this is not in it"
        );
    }
    format!("`{tool}` has no step kind: KS knows a fixed vocabulary, and this is not in it")
}

// ---------------------------------------------------------------------------
// lexical helpers — enough shell to split a line, not enough to be a parser
// ---------------------------------------------------------------------------

/// Whether a line ends in a line continuation: a backslash before the newline
/// that is neither inside single quotes nor itself escaped as `\\`. A backslash
/// inside double quotes is still a continuation — the shell removes the newline
/// and reads on.
fn continues(line: &str) -> bool {
    if !line.ends_with('\\') {
        return false;
    }
    // An even run of trailing backslashes is escaped pairs, not a continuation.
    if line.chars().rev().take_while(|&c| c == '\\').count() % 2 == 0 {
        return false;
    }
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some('\'') if c == '\'' => quote = None,
            Some(_) | None if c == '\\' => {
                chars.next();
            }
            None if c == '\'' || c == '"' => quote = Some(c),
            _ => {}
        }
    }
    quote != Some('\'')
}

/// `#` to end of line, at line start or after whitespace and outside quotes.
fn strip_comment(line: &str) -> String {
    let mut quote: Option<char> = None;
    let mut prev_space = true;
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c == '#' && prev_space => return line[..i].to_string(),
            None => prev_space = c.is_whitespace(),
        }
    }
    line.to_string()
}

/// `&&`, `||`, `;` and a bare `&`, outside quotes. A single `|` is left alone:
/// cutting a pipe in half would invent a command the script does not have.
fn split_commands(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) if c == q => {
                quote = None;
                cur.push(c);
            }
            Some(_) => cur.push(c),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                cur.push(c);
            }
            None if c == ';' || c == '&' || (c == '|' && chars.get(i + 1) == Some(&c)) => {
                parts.push(std::mem::take(&mut cur));
                if chars.get(i + 1) == Some(&c) {
                    i += 1;
                }
            }
            None => cur.push(c),
        }
        i += 1;
    }
    parts.push(cur);
    parts.into_iter().map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect()
}

/// Split a command into words, honouring quotes and backslash escapes. The
/// quote characters go: what a step needs is the value, not the spelling.
fn tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(q) => {
                if c == '\\' && q == '"' {
                    if let Some(next) = chars.next() {
                        cur.push(next);
                    }
                } else {
                    cur.push(c);
                }
            }
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                started = true;
            }
            None if c == '\\' => {
                if let Some(next) = chars.next() {
                    cur.push(next);
                    started = true;
                }
            }
            None if c.is_whitespace() => {
                if started {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            None => {
                cur.push(c);
                started = true;
            }
        }
    }
    if started || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The first `n` words of a line, for naming control flow in the report.
fn first_words(line: &str, n: usize) -> String {
    tokens(line).into_iter().take(n).collect::<Vec<_>>().join(" ")
}

/// A step id that is not taken: the second `plan` is `plan2`, never a second
/// `plan`.
fn fresh_id(steps: &[Step], base: &str) -> String {
    if !steps.iter().any(|s| s.id == base) {
        return base.to_string();
    }
    let mut n = 2;
    loop {
        let id = format!("{base}{n}");
        if !steps.iter().any(|s| s.id == id) {
            return id;
        }
        n += 1;
    }
}

/// The file's stem, reduced to `[a-z0-9_-]` so `./<stem>.ts` is always a kind a
/// `.ks` file can spell.
fn file_stem(path: &Path) -> String {
    let raw =
        path.file_stem().map_or_else(|| "ship".to_string(), |s| s.to_string_lossy().into_owned());
    let mut out = String::new();
    let mut dash = false;
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() { "ship".to_string() } else { trimmed }
}

// ---------------------------------------------------------------------------
// emitting
// ---------------------------------------------------------------------------

/// The `.ks` file, in `keepshipping fmt`'s canonical layout: two value columns,
/// the root entries on the first and everything under `steps:` on the second.
fn render(c: &Converted) -> String {
    // One value column for the root entries, one for everything under
    // `steps:` — however deep it goes. Each is as wide as the widest entry in
    // its group needs, plus the one space that always separates a key from its
    // value.
    //
    // NOTE: this column alignment duplicates the private aligner in
    // `crates/cli/src/fmt.rs`, deliberately not hoisted out for reuse. If `fmt`
    // changes what it does, the two will drift and the file this writes will no
    // longer be fmt-clean — `the_imported_file_type_checks` is what catches it.
    let mut root: Vec<(usize, String, Option<String>)> = vec![
        (0, "keepshipping".to_string(), Some("0.1".to_string())),
        (0, "name".to_string(), Some(c.name.clone())),
    ];
    if !c.steps.is_empty() {
        root.push((0, "steps".to_string(), None));
    }
    let root_col = column(&root.iter().map(|(i, k, _)| (*i, k.len())).collect::<Vec<_>>());

    // (indent, key, value) — a comment is a key beginning with `#`, and a
    // blank line between steps is an entry with no key.
    let mut nested: Vec<(usize, String, String)> = Vec::new();
    for (i, step) in c.steps.iter().enumerate() {
        if i > 0 {
            nested.push((0, String::new(), String::new()));
        }
        if let Body::Script { kind, .. } = &step.body {
            // On its own line, above the step it is about: it is about the file
            // rather than the step's kind, and fmt has no comment column to
            // guess at for a line that is only a comment.
            nested.push((2, format!("# you must write {kind} yourself"), String::new()));
        }
        nested.push((2, step.id.clone(), step.body.kind()));
        for (key, value) in inputs_of(step) {
            nested.push((4, key, value));
        }
    }
    let nested_col = column(
        &nested
            .iter()
            .filter(|(_, k, _)| !k.is_empty() && !k.starts_with('#'))
            .map(|(i, k, _)| (*i, k.len()))
            .collect::<Vec<_>>(),
    );

    let mut out = String::new();
    for (indent, key, value) in &root {
        write_entry(&mut out, *indent, key, value.as_deref().unwrap_or(""), root_col);
    }
    for (indent, key, value) in &nested {
        if key.is_empty() {
            let _ = writeln!(out);
            continue;
        }
        if key.starts_with('#') {
            let _ = writeln!(out, "{}{key}", " ".repeat(*indent));
            continue;
        }
        write_entry(&mut out, *indent, key, value, nested_col);
    }
    out
}

/// The value column for a group of entries: the widest any of them needs — the
/// key, its colon, and the one space that always separates the two — so every
/// value in the group starts in the same place.
fn column(entries: &[(usize, usize)]) -> usize {
    entries.iter().map(|(indent, key)| indent + key + 2).max().unwrap_or(2)
}

fn write_entry(out: &mut String, indent: usize, key: &str, value: &str, col: usize) {
    // A key with nothing after it — `steps:` — carries no padding; trailing
    // whitespace is not what fmt would leave behind.
    let pad =
        " ".repeat(if value.is_empty() { 0 } else { col.saturating_sub(indent + key.len() + 1) });
    let _ = writeln!(out, "{}{key}:{pad}{value}", " ".repeat(indent));
}

/// A path as `.ks` spells one. A bare `Dockerfile` gains its `./`: same file,
/// different spelling.
fn as_path(value: &str) -> String {
    if value.starts_with(['.', '/', '~']) || value.is_empty() {
        value.to_string()
    } else {
        format!("./{value}")
    }
}

/// The inputs of one step, in the order they should be written.
fn inputs_of(step: &Step) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if !step.after.is_empty() {
        out.push(("after".to_string(), step.after.join(", ")));
    }
    match &step.body {
        Body::Image { from, context, push } => {
            out.push(("from".to_string(), as_path(from)));
            if let Some(context) = context {
                out.push(("context".to_string(), as_path(context)));
            }
            if let Some(push) = push {
                out.push(("push".to_string(), push.clone()));
            }
        }
        Body::Plan { dir, .. } => out.push(("dir".to_string(), as_path(dir))),
        Body::Apply { plan, .. } => out.push(("plan".to_string(), plan.clone())),
        Body::Rollout { image } => out.push(("image".to_string(), image.clone())),
        Body::Vm { hosts, run } => {
            out.push(("hosts".to_string(), hosts.join(", ")));
            if !run.is_empty() {
                out.push(("run".to_string(), run.join(", ")));
            }
        }
        Body::Script { action, .. } => {
            out.push(("action".to_string(), action.as_str().to_string()))
        }
    }
    out
}

// ---------------------------------------------------------------------------
// reporting
// ---------------------------------------------------------------------------

/// The report, on stdout: what was written, recognised, not recognised, and
/// what the operator does next. Plain text, the shape `check` prints.
fn report(
    out: &mut impl std::io::Write,
    c: &Converted,
    script: &Path,
    out_path: &Path,
) -> std::io::Result<()> {
    writeln!(out, "wrote {} from {}", out_path.display(), script.display())?;

    if !c.recognised.is_empty() {
        let rows: Vec<Vec<String>> =
            std::iter::once(vec![
                "line".to_string(),
                "step".to_string(),
                "kind".to_string(),
                "command".to_string(),
            ])
            .chain(c.recognised.iter().map(|r| {
                vec![r.line.to_string(), r.step.clone(), r.kind.clone(), r.command.clone()]
            }))
            .collect();
        section(out, "recognised")?;
        for row in table(&rows) {
            writeln!(out, "  {row}")?;
        }
    }

    if !c.unrecognised.is_empty() {
        section(out, "unrecognised")?;
        let lines: Vec<String> = c.unrecognised.iter().map(|u| u.line.to_string()).collect();
        let width = width(lines.iter().map(String::as_str));
        for (u, line) in c.unrecognised.iter().zip(&lines) {
            writeln!(out, "  {line:>width$}  {command}", width = width, command = u.command)?;
            writeln!(
                out,
                "  {blank:>width$}  {why}",
                blank = "",
                width = width,
                why = u.suggestion
            )?;
        }
    }

    if !c.control_flow.is_empty() {
        section(out, "control flow")?;
        let lines: Vec<String> = c.control_flow.iter().map(|f| f.line.to_string()).collect();
        let width = width(lines.iter().map(String::as_str));
        for (f, line) in c.control_flow.iter().zip(&lines) {
            writeln!(out, "  {line:>width$}  {text}", width = width, text = f.text)?;
        }
        writeln!(
            out,
            "  .ks has no if, for, while, case or heredoc: every line above stays in the script step"
        )?;
    }

    if !c.envs.is_empty() {
        section(out, "environment variables")?;
        for (name, line) in &c.envs {
            writeln!(out, "  {name}  (line {line})")?;
        }
        writeln!(out, "  none were invented: declare the ones the steps need under `envs:`")?;
    }

    if !c.set_flags.is_empty() {
        section(out, "set flags")?;
        for (flags, line) in &c.set_flags {
            writeln!(out, "  set {flags}  (line {line})")?;
        }
        writeln!(out, "  a .ks file has no shell options: they are the script step's to keep")?;
    }

    for note in &c.notes {
        section(out, note)?;
    }

    section(out, "next")?;
    writeln!(out, "  keepshipping check {}", out_path.display())?;
    writeln!(out, "  keepshipping fmt {}", out_path.display())?;
    let mut todo: Vec<String> = Vec::new();
    todo.push(
        "add an `on:` line: without a trigger the file checks but nothing starts it".to_string(),
    );
    if let Some(step) = c.script_step()
        && let Body::Script { kind, action } = &step.body
    {
        todo.push(format!(
            "write {kind}, and check its `action: {action}` is the class it really does",
            action = action.as_str(),
        ));
    }
    let touching = |m: fn(&Body) -> bool| c.steps.iter().any(|s| m(&s.body));
    if touching(|b| matches!(b, Body::Apply { .. } | Body::Rollout { .. } | Body::Vm { .. })) {
        todo.push(
            "add an `approval` before the apply or the deploy: in prod an agent's run will not \
             reach one otherwise"
                .to_string(),
        );
    }
    if touching(|b| matches!(b, Body::Rollout { .. })) {
        todo.push("give the k8s.rollout a `to:` — a k8s.Cluster target you choose".to_string());
    }
    if touching(|b| matches!(b, Body::Vm { .. })) {
        todo.push(
            "vm.deploy hosts each want `address` and a pinned `host_key`, before a run uses them"
                .to_string(),
        );
    }
    if touching(|b| matches!(b, Body::Image { push: None, .. })) {
        todo.push("the build has no tag: oci.image declares `push` as where it goes".to_string());
    }
    for item in todo {
        writeln!(out, "  {item}")?;
    }
    Ok(())
}

/// A blank line, then the section's title. Every section of the report opens
/// the same way.
fn section(out: &mut impl std::io::Write, title: &str) -> std::io::Result<()> {
    writeln!(out)?;
    writeln!(out, "{title}")
}

/// How wide the widest of these is, so a column of them lines up.
fn width<'a>(it: impl Iterator<Item = &'a str>) -> usize {
    it.map(str::len).max().unwrap_or(0)
}

/// Rows in columns: two spaces after the widest cell of each column.
fn table(rows: &[Vec<String>]) -> Vec<String> {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> =
        (0..columns).map(|i| width(rows.iter().map(move |r| r[i].as_str()))).collect();
    rows.iter()
        .map(|row| {
            let mut line = String::new();
            for (i, cell) in row.iter().enumerate() {
                if i + 1 == columns {
                    line.push_str(cell);
                } else {
                    let _ = write!(line, "{cell:<width$}  ", width = widths[i]);
                }
            }
            line
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert_named(src: &str, name: &str) -> Converted {
        convert(src, Path::new(name))
    }

    #[test]
    fn every_emitted_kind_is_a_real_catalog_kind() {
        // The test that makes the rest honest: an unknown kind type-checks
        // clean, so emitting one would pass `keepshipping check` and still be a
        // file that cannot run.
        let catalog = ks_core::Catalog::builtin();
        let src = "\
docker build -f Dockerfile -t ghcr.io/acme/api:x .
docker push ghcr.io/acme/api:x
tofu plan -out=prod.tfplan ./infra
tofu apply prod.tfplan
helm upgrade api ./chart
kubectl apply -f k8s/deploy.yaml
for h in web-1 web-2; do
  ssh $h systemctl restart api
done
aws s3 sync ./dist s3://acme-assets
";
        let c = convert_named(src, "deploy.sh");
        assert!(c.unrecognised.iter().any(|u| u.command.contains("aws")), "aws was not reported");
        assert!(c.script_step().is_some());
        for step in &c.steps {
            let kind = step.kind();
            if ks_core::script_step::is_script_kind(&kind) {
                continue;
            }
            assert!(catalog.step(&kind).is_some(), "`{kind}` is not a built-in step kind");
        }
    }

    #[test]
    fn a_docker_push_folds_into_the_build_before_it() {
        let c = convert_named(
            "docker build -t ghcr.io/acme/api:x .\ndocker push ghcr.io/acme/api:x\n",
            "d.sh",
        );
        assert_eq!(c.steps.len(), 1);
        let Body::Image { push, from, context } = &c.steps[0].body else {
            panic!("expected an image step")
        };
        assert_eq!(push.as_deref(), Some("ghcr.io/acme/api:x"));
        // No `-f`, so the context is what `from` is.
        assert_eq!(from, ".");
        assert!(context.is_none());
    }

    #[test]
    fn a_dash_f_build_names_the_dockerfile_and_keeps_the_context() {
        let c = convert_named("docker build -f Dockerfile.api -t acme/api:dev ./api\n", "d.sh");
        let Body::Image { from, context, .. } = &c.steps[0].body else {
            panic!("expected an image")
        };
        assert_eq!(from, "Dockerfile.api");
        assert_eq!(context.as_deref(), Some("./api"));
    }

    #[test]
    fn a_push_with_no_build_is_reported_not_guessed() {
        let c = convert_named("docker push ghcr.io/acme/api:x\n", "d.sh");
        assert_eq!(c.unrecognised.len(), 1);
        assert!(c.steps.iter().all(|s| matches!(s.body, Body::Script { .. })));
    }

    /// The regression for continuations being read as separate commands: the
    /// `-f` on line 2 used to be silently dropped from the step and reported as
    /// an unknown flag.
    #[test]
    fn a_continued_command_is_one_command_cited_at_the_line_it_started() {
        let c = convert_named(
            "docker build \\\n  -f Dockerfile.prod \\\n  -t a/b:1 .\ndocker push a/b:1\n",
            "d.sh",
        );
        assert_eq!(c.steps.len(), 1, "one image step, got {} steps", c.steps.len());
        let Body::Image { from, context, push } = &c.steps[0].body else {
            panic!("expected an image")
        };
        assert_eq!(from, "Dockerfile.prod");
        assert_eq!(context.as_deref(), Some("."));
        assert_eq!(push.as_deref(), Some("a/b:1"));
        // The flags are no longer loose commands, so nothing is unrecognised.
        let spurious: Vec<&str> = c.unrecognised.iter().map(|u| u.command.as_str()).collect();
        assert!(spurious.is_empty(), "continuations were read as commands: {spurious:?}");
        // And the report cites where the command *started*, not a continuation.
        assert_eq!(c.recognised[0].line, 1);
    }

    /// A continuation is not docker-specific: `tofu plan \` … is joined too.
    #[test]
    fn a_continued_tofu_plan_keeps_its_flags() {
        let c = convert_named(
            "tofu plan \\\n  -out=prod.tfplan \\\n  ./infra\ntofu apply prod.tfplan\n",
            "d.sh",
        );
        let spurious: Vec<&str> = c.unrecognised.iter().map(|u| u.command.as_str()).collect();
        assert!(spurious.is_empty(), "{spurious:?}");
        assert_eq!(c.steps[0].kind(), "tofu.plan");
        assert_eq!(c.steps[1].kind(), "tofu.apply");
        assert_eq!(c.recognised[0].line, 1);
    }

    /// The first push is the tag the build produced; later ones are usually
    /// extra tags, and the report must name the line that actually set it.
    #[test]
    fn the_first_of_several_pushes_wins_and_the_report_says_which_line() {
        let c = convert_named(
            "docker build -f D .\ndocker push first/img:1\ndocker push second/img:2\n",
            "d.sh",
        );
        let Body::Image { push, .. } = &c.steps[0].body else { panic!("expected an image") };
        assert_eq!(push.as_deref(), Some("first/img:1"));
        assert!(
            c.notes.iter().any(|n| n.contains("line 2 set it")),
            "the fold note names the wrong line: {:?}",
            c.notes
        );
        // Both pushes are still recognised — they folded, they did not vanish.
        assert_eq!(c.recognised.len(), 3, "{}", c.recognised.len());
        assert_eq!(c.recognised[2].line, 3);
    }

    #[test]
    fn an_apply_names_the_plan_step_that_wrote_its_file() {
        let c =
            convert_named("tofu plan -out=prod.tfplan ./infra\ntofu apply prod.tfplan\n", "d.sh");
        assert_eq!(c.steps.len(), 2);
        assert_eq!(c.steps[1].kind(), "tofu.apply");
        let Body::Apply { plan, .. } = &c.steps[1].body else { panic!("expected an apply") };
        assert_eq!(plan, "plan.file");
    }

    #[test]
    fn an_apply_of_a_file_no_plan_wrote_is_unrecognised() {
        let c = convert_named("tofu apply other.tfplan\n", "d.sh");
        assert_eq!(c.unrecognised.len(), 1);
        assert!(c.steps.iter().all(|s| matches!(s.body, Body::Script { .. })));
    }

    #[test]
    fn a_terraform_plan_cannot_be_applied_by_tofu() {
        let c = convert_named("terraform plan -out=p.tfplan\ntofu apply p.tfplan\n", "d.sh");
        assert_eq!(c.steps.len(), 2);
        assert!(matches!(c.steps[1].body, Body::Script { .. }));
    }

    #[test]
    fn a_kubectl_without_an_image_is_unrecognised() {
        let c = convert_named("kubectl apply -f k8s/deploy.yaml\n", "d.sh");
        assert_eq!(c.unrecognised.len(), 1);
        assert!(c.unrecognised[0].suggestion.contains("a k8s.rollout needs an image"));
    }

    #[test]
    fn a_loop_over_hosts_becomes_one_vm_deploy() {
        let c = convert_named(
            "for h in web-1 web-2 web-3; do\n  ssh $h systemctl restart api\ndone\n",
            "d.sh",
        );
        let step = c.steps.iter().find(|s| matches!(s.body, Body::Vm { .. })).expect("a vm.deploy");
        let Body::Vm { hosts, run } = &step.body else { unreachable!() };
        assert_eq!(hosts, &["web-1", "web-2", "web-3"]);
        assert_eq!(run, &["systemctl restart api"]);
    }

    #[test]
    fn a_script_with_nothing_recognised_emits_only_the_script_step() {
        let c = convert_named("make build\necho hi\nrsync -a dist/ host:/srv\n", "deploy2.sh");
        assert_eq!(c.steps.len(), 1);
        assert_eq!(c.steps[0].id, "deploy2");
        assert_eq!(c.steps[0].kind(), "./deploy2.ts");
        assert_eq!(c.unrecognised.len(), 3);
        assert!(c.steps[0].after.is_empty());
    }

    #[test]
    fn the_script_step_takes_the_most_severe_action() {
        let c = convert_named("make build\nrm -rf ./dist\n", "d.sh");
        let Body::Script { action, .. } = &c.steps[0].body else {
            panic!("expected a script step")
        };
        assert_eq!(*action, Action::Destroy);
    }

    #[test]
    fn the_script_step_follows_everything_recognised() {
        let c = convert_named("docker build -t acme/api:x .\necho done\n", "d.sh");
        let script = c.script_step().expect("a script step");
        assert_eq!(script.after, vec!["build".to_string()]);
    }

    #[test]
    fn a_stem_is_reduced_to_something_a_kind_can_spell() {
        assert_eq!(file_stem(Path::new("Deploy 2.sh")), "deploy-2");
        assert_eq!(file_stem(Path::new("/tmp/deploy2.sh")), "deploy2");
        assert_eq!(file_stem(Path::new("...")), "ship");
    }

    #[test]
    fn a_quoted_hash_is_not_a_comment() {
        assert_eq!(strip_comment("docker build -t 'a#b' .").trim(), "docker build -t 'a#b' .");
        assert_eq!(strip_comment("docker build . # go").trim(), "docker build .");
    }

    #[test]
    fn a_command_split_on_semicolons_is_two_commands() {
        assert_eq!(split_commands("a; b"), ["a", "b"]);
        assert_eq!(split_commands("a && b"), ["a", "b"]);
        assert_eq!(split_commands("grep x f | wc -l"), ["grep x f | wc -l"]);
    }

    #[test]
    fn a_backslash_before_the_newline_continues_the_line_unless_quoted() {
        assert!(continues("docker build \\"));
        assert!(continues("docker build -f D \\"));
        // Inside double quotes the shell still joins the line.
        assert!(continues("echo \"a\\"));
        // Inside single quotes a backslash is an ordinary character.
        assert!(!continues("echo 'a\\"));
        // `\\` is one escaped backslash, not a continuation.
        assert!(!continues("docker build .\\\\"));
        assert!(!continues("docker build ."));
    }
}
