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
                        [--context local|ci] [--non-interactive] [--until STEP]
                        [--only STEP]... [--skip STEP]... [--allow-partial]
                        [--dry-run] [-v]
       keepshipping graph [FILE] [--env NAME] [--event \"push main\"] [--format text|dot|json]
       keepshipping fmt [PATH...] [--check]
       keepshipping fmt -
       keepshipping fmt --upgrade [PATH...]
       keepshipping blocks search <QUERY> [--index URL] [--limit N] [--format human|json]
       keepshipping log [RUN-ID] [--format human|json]
       keepshipping log verify [RUN-ID]
       keepshipping policy explain [FILE] [--as agent|human|ci] [--env NAME]
       keepshipping lsp";

/// Which subcommand's flags `parse_args` accepts. `--format`, `--all`,
/// `--warnings-as-errors`, `--secrets`, `--fix` and `--repro` belong to `check` alone; `run`
/// rejects them like any other unrecognized option. `--until`, `--skip` and
/// `--allow-partial` belong to `run` alone, and `--context` to both.
/// `blocks search` has its own `--format` (human or json, no github
/// annotations), `--index` and `--limit`. `graph` has its own `--format` —
/// `text|dot|json`, not the diagnostic formats, so `check --format dot` stays
/// the usage error it has always been. `fmt` takes `--check`, the `-` stdin
/// positional, and `--upgrade`; it rejects `--env`, `--event`, `--actor` and
/// `--non-interactive`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Check,
    Run,
    Fmt,
    Graph,
    BlocksSearch,
    PolicyExplain,
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
    pub secrets: bool,
    pub non_interactive: bool,
    /// `--context local|ci`: what a run here could do. `None` means
    /// detected from the environment (see [`detect_context`]).
    pub context: Option<ContextName>,
    /// `run --until STEP`: the step and everything it depends on.
    pub until: Option<String>,
    /// `run --only STEP`: exactly these steps, repeatable.
    pub only: Vec<String>,
    /// `run --skip STEP`: drop these steps and everything downstream,
    /// repeatable.
    pub skip: Vec<String>,
    /// `--allow-partial`: start a run whose steps the context cannot run.
    pub allow_partial: bool,
    /// `run --dry-run`: graph the run and check it, run nothing.
    pub dry_run: bool,
    /// `-v`: stream each step's own output instead of its summaries.
    pub verbose: bool,
    /// The base URL of the blocks index, from `--index`. Absent means the
    /// command falls back to `INDEX_ENV`, and fails when neither is set.
    pub index: Option<String>,
    /// The `--limit` of `blocks search`, at least one.
    pub limit: u32,
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
        secrets: false,
        non_interactive: false,
        context: None,
        until: None,
        only: Vec::new(),
        skip: Vec::new(),
        allow_partial: false,
        dry_run: false,
        verbose: false,
        index: None,
        limit: DEFAULT_SEARCH_LIMIT,
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
                o.actor = actor_kind(&flag_value(&mut rest)?)?
            }
            "--non-interactive" if command != Command::Fmt && command != Command::PolicyExplain => {
                o.non_interactive = true
            }
            "--context" if matches!(command, Command::Check | Command::Run) => {
                o.context = Some(ContextName::parse(&flag_value(&mut rest)?)?)
            }
            "--until" if command == Command::Run => o.until = Some(flag_value(&mut rest)?),
            "--only" if command == Command::Run => o.only.push(flag_value(&mut rest)?),
            "--skip" if command == Command::Run => o.skip.push(flag_value(&mut rest)?),
            "--allow-partial" if command == Command::Run => o.allow_partial = true,
            "--dry-run" if command == Command::Run => o.dry_run = true,
            "-v" | "--verbose" if command == Command::Run => o.verbose = true,
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
            // One positional: the site file, the tree with `--all`, or the
            // search text. A second is almost always a typo, not a list to
            // check.
            file if o.path.is_none()
                && matches!(command, Command::Check | Command::Run | Command::PolicyExplain) =>
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
