//! Command-line parsing: one hand-rolled pass over the arguments, shared by
//! `check`, `run`, `graph`, `fmt` and `blocks search`. Anything unrecognizable —
//! flag, value or format — is a usage error, never a silently swallowed
//! option.

use ks_core::ContextName;
use ks_core::ports::run_context::ActorKind;

use crate::graph::{self, GraphFormat};
use crate::render::Format;

/// The most results `blocks search` asks the index for when `--limit` is
/// not given.
pub const DEFAULT_SEARCH_LIMIT: u32 = 20;
/// The environment variable that configures the blocks index when `--index`
/// is absent. `--index` wins.
pub const INDEX_ENV: &str = "KEEPSSHIPPING_BLOCKS_INDEX";

pub const USAGE: &str = "\
usage: keepshipping check [FILE] [--all] [--format human|json|github]
                          [--warnings-as-errors] [--env NAME] [--event \"push main\"]
                          [--actor human|agent|ci] [--context local|ci] [--secrets] [--fix] [--repro]
       keepshipping run [FILE] [--env NAME] [--event \"push main\"] [--actor human|agent|ci]
                        [--as human|agent[:name]|ci] [--base REF]
                        [--context local|ci] [--non-interactive] [--ci] [--sha SHA] [--until STEP]
                        [--only STEP]... [--skip STEP]... [--input KEY=VALUE]... [--allow-partial]
                        [--dry-run] [-v]
       keepshipping graph [FILE] [--env NAME] [--event \"push main\"] [--format text|dot|json]
       keepshipping fmt [PATH...] [--check]
       keepshipping fmt -
       keepshipping fmt --upgrade [PATH...]
       keepshipping blocks search <QUERY> [--index URL] [--limit N] [--offline] [--format human|json]
       keepshipping blocks publish <FILE> --version X.Y.Z --to HOST/NAMESPACE [--readme PATH]
       keepshipping import github-actions [<workflow.yml | dir>] [--out DIR] [--force]
       keepshipping log [RUN-ID] [--format human|json]
       keepshipping log seal [RUN-ID]
       keepshipping log verify [RUN-ID | REPO@DIGEST] [--key FILE]
       keepshipping policy explain [FILE] [--as agent|human|ci] [--env NAME] [--base REF]
       keepshipping import shell <SCRIPT> [--out FILE]
       keepshipping runs pending
       keepshipping approve RUN-ID [--comment TEXT]
       keepshipping deny RUN-ID --reason TEXT
       keepshipping resume RUN-ID [FILE]
       keepshipping decisions report [--json]
       keepshipping decisions export
       keepshipping decide --explain [RUN-ID]
       keepshipping about
       keepshipping lsp
       keepshipping --version";

/// Which subcommand's flags `parse_args` accepts. `--format`, `--all`,
/// `--warnings-as-errors`, `--secrets`, `--fix` and `--repro` belong to `check` alone; `run`
/// rejects them like any other unrecognized option. `--until`, `--skip` and
/// `--allow-partial` belong to `run` alone, and `--context` to both.
/// `blocks search` has its own `--format` (human or json, no github
/// annotations), `--index`, `--limit` and `--offline`. `graph` has its own `--format` —
/// `text|dot|json`, not the diagnostic formats, so `check --format dot` stays
/// the usage error it has always been. `fmt` takes `--check`, the `-` stdin
/// positional, and `--upgrade`; it rejects `--env`, `--event`, `--actor` and
/// `--non-interactive`. `blocks publish` takes `--version`, `--to` and
/// `--readme`, and rejects every other command's flags: publishing a block
/// under a flag that means something else is how a block lands somewhere its
/// publisher did not choose.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Check,
    Run,
    Fmt,
    Graph,
    BlocksSearch,
    PolicyExplain,
    BlocksPublish,
}

/// The parsed command line. `path` is the `FILE` argument: the site file —
/// or, with `--all`, the directory to walk — defaulting to `ship.ks` in the
/// working directory when absent. For `blocks search` the positional is the
/// search text, carried in `query` instead.
pub struct Options {
    pub path: Option<String>,
    pub query: Option<String>,
    pub format: Format,
    /// `graph`'s `--format`: the plan is not a diagnostic, so it has its own
    /// names. `format` above stays at its default for `graph`.
    pub graph_format: GraphFormat,
    pub all: bool,
    pub warnings_as_errors: bool,
    /// `--fix`: apply the machine-applicable fixes and re-check. Never
    /// applied to `policy:`, where the change needs a human.
    pub fix: bool,
    /// `--repro`: also read the Dockerfiles an `oci.image` step names and
    /// warn (KS0801) about inputs that can move between two builds.
    pub repro: bool,
    pub env: Option<String>,
    pub event: Option<String>,
    /// The actor the command would run as; a human unless `--actor` says
    /// otherwise. Policy rules that bind the actor are enforced at check
    /// time.
    pub actor: ActorKind,
    /// What `--actor`/`--as` declared, if either did: `None` when neither was
    /// given, so what the environment says decides instead of a default.
    pub declared: Option<ActorKind>,
    /// The agent named by `--as agent:<name>`: which agent proposed this run,
    /// for the run log. Only an `--as` invocation can name one.
    pub actor_name: Option<String>,
    pub secrets: bool,
    pub non_interactive: bool,
    /// `--context local|ci`: what a run here could do. `None` means
    /// detected from the environment (see [`detect_context`]).
    pub context: Option<ContextName>,
    /// `run --ci`: this invocation is a CI job, whatever the environment
    /// says. It forces the CI context and a non-interactive run, and the
    /// detected CI becomes the run's actor
    /// ([`generic_ci`](crate::generic_ci)).
    pub ci: bool,
    /// `run --sha SHA`: the commit this run is about, for a CI whose
    /// environment names no commit. Beats what was detected. `run` refuses
    /// the flag without `--ci`, which is the context it states it to.
    pub sha: Option<String>,
    /// `run --until STEP`: the step and everything it depends on.
    pub until: Option<String>,
    /// `run --only STEP`: exactly these steps, repeatable.
    pub only: Vec<String>,
    /// `run --skip STEP`: drop these steps and everything downstream,
    /// repeatable.
    pub skip: Vec<String>,
    /// `run --input KEY=VALUE`: an explicit input for the steps this run
    /// takes, repeatable. A value that starts `@secret:` names a secret
    /// instead of carrying one; [`parse_inputs`] rejects a malformed pair
    /// before the run starts.
    ///
    /// Today the flag is inert outside `--dry-run`: `run` checks every pair
    /// and `--dry-run` echoes them, and no step is handed one yet (#92).
    pub inputs: Vec<String>,
    /// `--allow-partial`: start a run whose steps the context cannot run.
    pub allow_partial: bool,
    /// `run --dry-run`: graph the run and check it, run nothing.
    pub dry_run: bool,
    /// `-v`: stream each step's own output instead of its summaries.
    pub verbose: bool,
    /// `--base REF`: the ref whose `policy:` block this file's policy is
    /// folded against — the default branch, by default
    /// ([#118](https://github.com/Keep-Shipping/harness/issues/118)).
    pub base: Option<String>,
    /// The base URL of the blocks index, from `--index`. Absent means the
    /// command falls back to `INDEX_ENV`, and fails when neither is set.
    pub index: Option<String>,
    /// The `--limit` of `blocks search`, at least one.
    pub limit: u32,
    /// `--offline` on `blocks search`: answer from the local metadata cache
    /// and never touch the network.
    pub offline: bool,
    /// `blocks publish --version`: the version to publish at, as written. The
    /// command parses it — a version this build cannot compare is a usage
    /// error, not something to push and discover later.
    pub version: Option<String>,
    /// `blocks publish --to`: `<host>/<namespace>`, where the block's own
    /// name is the last path element.
    pub target: Option<String>,
    /// `blocks publish --readme`: the README to carry with the block. Only when
    /// named — a `README.md` beside the block file may be about something
    /// else, and publishing it would not be the publisher's choice.
    pub readme: Option<String>,
    /// `--upgrade` on `fmt`: rewrite each file to the format this build
    /// writes, rather than laying it out.
    pub upgrade: bool,
    /// `fmt --check`: report what would change instead of rewriting.
    pub check: bool,
    /// `fmt -`: read the source from stdin, write the result to stdout.
    pub stdin: bool,
    /// The files and directories `fmt` was given, in order. Empty means
    /// `ship.ks` in the working directory.
    pub paths: Vec<String>,
}

pub fn parse_args(args: &[String], command: Command) -> Option<Options> {
    let mut o = Options {
        path: None,
        query: None,
        format: Format::Human,
        graph_format: graph::DEFAULT,
        all: false,
        warnings_as_errors: false,
        fix: false,
        repro: false,
        env: None,
        event: None,
        // `explain` defaults to the actor it exists for: the leash. A file
        // that says nothing about an agent reads as "ask", and that answer
        // is the one worth seeing by default.
        actor: if command == Command::PolicyExplain { ActorKind::Agent } else { ActorKind::Human },
        declared: None,
        actor_name: None,
        secrets: false,
        non_interactive: false,
        context: None,
        ci: false,
        sha: None,
        until: None,
        only: Vec::new(),
        skip: Vec::new(),
        inputs: Vec::new(),
        allow_partial: false,
        dry_run: false,
        verbose: false,
        base: None,
        index: None,
        limit: DEFAULT_SEARCH_LIMIT,
        offline: false,
        version: None,
        target: None,
        readme: None,
        upgrade: false,
        check: false,
        stdin: false,
        paths: Vec::new(),
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--format" if command == Command::Graph => {
                o.graph_format = GraphFormat::parse(&flag_value(&mut rest)?)?
            }
            "--format" if matches!(command, Command::Check | Command::BlocksSearch) => {
                o.format = Format::parse(&flag_value(&mut rest)?)?
            }
            "--all" if command == Command::Check => o.all = true,
            "--warnings-as-errors" if command == Command::Check => o.warnings_as_errors = true,
            "--secrets" if command == Command::Check => o.secrets = true,
            "--fix" if command == Command::Check => o.fix = true,
            "--repro" if command == Command::Check => o.repro = true,
            "--env" if command != Command::Fmt => o.env = Some(flag_value(&mut rest)?),
            "--event" if command != Command::Fmt && command != Command::PolicyExplain => {
                o.event = Some(flag_value(&mut rest)?)
            }
            // `policy explain` reads the file for one principal and prints
            // what that principal may do, so `--as` names it rather than
            // `--actor`: there is nothing to run here.
            "--as" if command == Command::PolicyExplain => {
                o.actor = actor_kind(&flag_value(&mut rest)?)?
            }
            "--actor" if command != Command::Fmt && command != Command::PolicyExplain => {
                o.actor = actor_kind(&flag_value(&mut rest)?)?;
                o.declared = Some(o.actor);
            }
            // `--as` is `--actor` plus a name for the agent: which agent is
            // proposing this run, not just what kind of thing it is.
            "--as" if command != Command::Fmt => {
                let (kind, name) = crate::actor::parse_as(&flag_value(&mut rest)?)?;
                o.actor = kind;
                o.declared = Some(kind);
                o.actor_name = name;
            }
            "--non-interactive" if command != Command::Fmt && command != Command::PolicyExplain => {
                o.non_interactive = true
            }
            "--context" if matches!(command, Command::Check | Command::Run) => {
                o.context = Some(ContextName::parse(&flag_value(&mut rest)?)?)
            }
            // `--ci` is the caller saying a CI is in charge, and `--sha` what
            // the run is about where the CI's environment names no commit —
            // which is why `run` rejects `--sha` without `--ci` (see
            // [`Options::sha`]): it would have nowhere to state it.
            "--ci" if command == Command::Run => o.ci = true,
            "--sha" if command == Command::Run => o.sha = Some(flag_value(&mut rest)?),
            "--until" if command == Command::Run => o.until = Some(flag_value(&mut rest)?),
            "--only" if command == Command::Run => o.only.push(flag_value(&mut rest)?),
            "--skip" if command == Command::Run => o.skip.push(flag_value(&mut rest)?),
            "--input" if command == Command::Run => o.inputs.push(flag_value(&mut rest)?),
            "--allow-partial" if command == Command::Run => o.allow_partial = true,
            "--dry-run" if command == Command::Run => o.dry_run = true,
            "-v" | "--verbose" if command == Command::Run => o.verbose = true,
            "--base" if matches!(command, Command::Run | Command::PolicyExplain) => {
                o.base = Some(flag_value(&mut rest)?)
            }
            "--upgrade" if command == Command::Fmt => o.upgrade = true,
            "--check" if command == Command::Fmt => o.check = true,
            // A lone `-` is stdin, the way every Unix filter spells it; it is
            // the one positional that may look like a flag.
            "-" if command == Command::Fmt => o.stdin = true,
            "--index" if command == Command::BlocksSearch => o.index = Some(flag_value(&mut rest)?),
            "--limit" if command == Command::BlocksSearch => {
                let value = flag_value(&mut rest)?;
                o.limit = value.parse().ok().filter(|limit| *limit > 0)?;
            }
            "--offline" if command == Command::BlocksSearch => o.offline = true,
            "--version" if command == Command::BlocksPublish => {
                o.version = Some(flag_value(&mut rest)?)
            }
            "--to" if command == Command::BlocksPublish => o.target = Some(flag_value(&mut rest)?),
            "--readme" if command == Command::BlocksPublish => {
                o.readme = Some(flag_value(&mut rest)?)
            }
            // Everything after `--` is a path, even when it starts with a dash: the
            // one way to name a file called `-weird.ks`.
            "--" if command == Command::Fmt => {
                o.paths.extend(rest.by_ref().cloned());
                break;
            }
            flag if flag.starts_with('-') => return None,
            // `fmt` is the one command that takes a list: a file, a tree, or
            // several of each.
            file if command == Command::Fmt => o.paths.push(file.to_string()),
            // One positional: the site file, the tree with `--all`, the
            // search text, or the block file to publish. A second is almost
            // always a typo, not a list to check.
            file if o.path.is_none()
                && matches!(
                    command,
                    Command::Check | Command::Run | Command::PolicyExplain | Command::BlocksPublish
                ) =>
            {
                o.path = Some(file.to_string())
            }
            text if o.query.is_none() && command == Command::BlocksSearch => {
                o.query = Some(text.to_string())
            }
            _ => return None,
        }
    }
    // GitHub annotations describe source spans; a search result has none.
    if command == Command::BlocksSearch && o.format == Format::Github {
        return None;
    }
    Some(o)
}

/// One `--input KEY=VALUE` override, split at its first `=`. No further than
/// the binary: the fields are private to this module and [`input_lines`] is
/// the only thing that turns one into output. `main.rs` names the type to
/// carry parsed pairs, which is why it is crate-visible and no more.
pub(crate) struct Input<'a> {
    /// What the override is for, ending at the first `=`. One name, with no
    /// whitespace in it: a key with a space in it reads as two things in a
    /// report and names nothing a step could be asked for.
    key: &'a str,
    /// What the step would be handed, or — when `secret` is set — the
    /// reference it names, with the marker already stripped. Carried as
    /// written, so what a user typed is what a future executor receives and
    /// what the report shows.
    value: &'a str,
    /// The value names a secret rather than being one: `@secret:` and the
    /// rest of it. A reference is not secret and may be shown; what it
    /// points at never is ([`ks_core::ports::secrets`]).
    secret: bool,
}

/// The marker a value uses to name a secret instead of carrying one. What
/// follows is the reference itself: a `resolver:key` pair in the shape a
/// `SecretRef` prints, or a bare key for the environment's own resolver.
const SECRET_MARKER: &str = "@secret:";

/// `--input KEY=VALUE`, checked before a run starts. A pair without `=`, a
/// pair with no key, a secret marker that names nothing, and anything that
/// would forge or blur a line of the `--dry-run` report are usage errors:
/// each message names the problem and the way out, the way [`parse_args`]
/// cannot, having only a yes or no to give.
pub(crate) fn parse_inputs(raw: &[String]) -> Result<Vec<Input<'_>>, String> {
    let mut inputs: Vec<Input> = Vec::new();
    for text in raw {
        let input = split_input(text)?;
        // A repeated key is an override, not a second value for the same
        // step: the last `--input` wins, as it does for every other flag.
        match inputs.iter_mut().find(|i| i.key == input.key) {
            Some(seen) => *seen = input,
            None => inputs.push(input),
        }
    }
    Ok(inputs)
}

/// The `--dry-run` lines for the overrides a run was given: the key, and
/// either the value or the secret reference it names, marked as a reference
/// so it cannot be mistaken for a value that was read. The pairs are
/// parsed and checked by the caller, before the run starts, so there is
/// nothing to say about a malformed one here.
pub(crate) fn input_lines(inputs: &[Input]) -> Vec<String> {
    // No `--input`, no lines: a run without the flag says exactly what it
    // said before the flag existed.
    if inputs.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::with_capacity(inputs.len() + 1);
    lines.push("inputs:".to_string());
    lines.extend(inputs.iter().map(|i| {
        if i.secret {
            format!("  input {} = {SECRET_MARKER}{} (reference)", i.key, i.value)
        } else {
            format!("  input {} = {}", i.key, i.value)
        }
    }));
    lines
}

/// `KEY=VALUE`, the smallest grammar that says what it means: the key ends
/// at the first `=`, so a value may contain more of them. A value that
/// starts `@secret:` is a reference, and the rest of it is passed through as
/// written — nothing here resolves a secret, because nothing does yet.
///
/// What the grammar refuses is what would forge or blur a line of the
/// `--dry-run` report, which is line-oriented and prints one input per line:
/// a `\n` or `\r` in a key or a value would put a line of the user's own
/// choosing where a step line should be, and whitespace at either end would
/// print as padding the report cannot show. Everything else is the value's
/// business — `two words` is a legitimate value, and interior whitespace is
/// left alone. The asymmetry with an empty value is deliberate: `k=` says
/// "the value is empty", which is a fact a step can act on, where `@secret:`
/// with nothing after it names nothing at all.
fn split_input(text: &str) -> Result<Input<'_>, String> {
    // A pair that breaks a line is quoted with the break escaped, so the
    // usage error about it stays on one line too.
    let said = if breaks_a_line(text) { text.escape_debug().to_string() } else { text.to_string() };
    let Some((key, value)) = text.split_once('=') else {
        return Err(format!("`--input {said}` has no `=`; write --input KEY=VALUE"));
    };
    if key.is_empty() {
        return Err(format!("`--input {said}` has an empty key; write --input KEY=VALUE"));
    }
    if breaks_a_line(key) {
        return Err(format!(
            "`--input {said}` breaks a line in its key; write --input KEY=VALUE as one line"
        ));
    }
    if padded(key) {
        return Err(format!(
            "`--input {said}` has whitespace around its key; write --input KEY=VALUE with no padding"
        ));
    }
    if key.chars().any(char::is_whitespace) {
        return Err(format!(
            "`--input {said}` has whitespace inside its key; a key is one name, so write it without spaces"
        ));
    }
    if breaks_a_line(value) {
        return Err(format!(
            "`--input {said}` breaks a line in its value; write --input KEY=VALUE as one line"
        ));
    }
    if padded(value) {
        return Err(format!(
            "`--input {said}` has whitespace around its value; write --input KEY=VALUE with no padding"
        ));
    }
    let Some(reference) = value.strip_prefix(SECRET_MARKER) else {
        return Ok(Input { key, value, secret: false });
    };
    if reference.is_empty() {
        return Err(format!(
            "`--input {said}` names no secret; write --input KEY={SECRET_MARKER}RESOLVER:NAME"
        ));
    }
    Ok(Input { key, value: reference, secret: true })
}

/// Whether `part` would end the report line it is printed on: `\n` and `\r`
/// both break it, and both can be written inside a shell argument.
fn breaks_a_line(part: &str) -> bool {
    part.contains(['\n', '\r'])
}

/// Whether `part` carries whitespace at either end, which the report shows
/// as padding between words rather than as the edge of the value.
fn padded(part: &str) -> bool {
    part.trim() != part
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

/// The context a command would run in when `--context` says nothing: CI when
/// the environment says so, a laptop otherwise. GitHub Actions names itself
/// outright; every other CI system sets `CI`, and any value but `false` or `0`
/// means one is in charge — a system that says "not CI" should not have to
/// unset the variable.
pub fn detect_context() -> ContextName {
    let ci = |name: &str| {
        std::env::var(name).ok().is_some_and(|v| {
            let v = v.trim().to_ascii_lowercase();
            !v.is_empty() && v != "false" && v != "0"
        })
    };
    if ci("GITHUB_ACTIONS") || ci("CI") { ContextName::Ci } else { ContextName::Local }
}

/// The context this command line asks for, detected when `--context` is
/// absent.
pub fn context_of(o: &Options) -> ContextName {
    o.context.unwrap_or_else(detect_context)
}

/// The value after `--env`/`--event`/`--actor`/`--format`. A missing value,
/// or another flag where a value belongs, is a usage error instead of a
/// silently swallowed option.
fn flag_value(rest: &mut std::slice::Iter<'_, String>) -> Option<String> {
    let value = rest.next()?;
    (!value.starts_with('-')).then(|| value.clone())
}
