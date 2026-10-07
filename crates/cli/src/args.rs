//! Command-line parsing: one hand-rolled pass over the arguments, shared by
//! `check`, `run` and `blocks search`. Anything unrecognizable — flag, value
//! or format — is a usage error, never a silently swallowed option.

use ks_core::ports::run_context::ActorKind;

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
                          [--actor human|agent|ci] [--secrets] [--fix]
       keepshipping run [FILE] [--env NAME] [--event \"push main\"] [--actor human|agent|ci]
                        [--non-interactive]
       keepshipping fmt --upgrade [PATH...]
       keepshipping blocks search <QUERY> [--index URL] [--limit N] [--format human|json]";

/// Which subcommand's flags `parse_args` accepts. `--format`, `--all`,
/// `--warnings-as-errors`, `--secrets` and `--fix` belong to `check` alone; `run`
/// rejects them like any other unrecognized option. `blocks search` has its
/// own `--format` (human or json, no github annotations), `--index` and
/// `--limit`. `fmt` takes only `--upgrade` today: the formatter is not
/// written yet, and every other flag it might grow is still a usage error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Check,
    Run,
    Fmt,
    BlocksSearch,
}

/// The parsed command line. `path` is the `FILE` argument: the site file —
/// or, with `--all`, the directory to walk — defaulting to `ship.ks` in the
/// working directory when absent. For `blocks search` the positional is the
/// search text, carried in `query` instead.
pub struct Options {
    pub path: Option<String>,
    pub query: Option<String>,
    pub format: Format,
    pub all: bool,
    pub warnings_as_errors: bool,
    /// `--fix`: apply the machine-applicable fixes and re-check. Never
    /// applied to `policy:`, where the change needs a human.
    pub fix: bool,
    pub env: Option<String>,
    pub event: Option<String>,
    /// The actor the command would run as; a human unless `--actor` says
    /// otherwise. Policy rules that bind the actor are enforced at check
    /// time.
    pub actor: ActorKind,
    pub secrets: bool,
    pub non_interactive: bool,
    /// The base URL of the blocks index, from `--index`. Absent means the
    /// command falls back to `INDEX_ENV`, and fails when neither is set.
    pub index: Option<String>,
    /// The `--limit` of `blocks search`, at least one.
    pub limit: u32,
    /// `--upgrade` on `fmt`: rewrite each file to the format this build
    /// writes. Without it there is no formatter to run.
    pub upgrade: bool,
    /// The paths `fmt --upgrade` was given: files, or directories to walk
    /// for `ship.ks`. Empty means `ship.ks` in the working directory.
    pub paths: Vec<String>,
}

pub fn parse_args(args: &[String], command: Command) -> Option<Options> {
    let mut o = Options {
        path: None,
        query: None,
        format: Format::Human,
        all: false,
        warnings_as_errors: false,
        fix: false,
        env: None,
        event: None,
        actor: ActorKind::Human,
        secrets: false,
        non_interactive: false,
        index: None,
        limit: DEFAULT_SEARCH_LIMIT,
        upgrade: false,
        paths: Vec::new(),
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--format" if command != Command::Run => {
                o.format = Format::parse(&flag_value(&mut rest)?)?
            }
            "--all" if command == Command::Check => o.all = true,
            "--warnings-as-errors" if command == Command::Check => o.warnings_as_errors = true,
            "--secrets" if command == Command::Check => o.secrets = true,
            "--fix" if command == Command::Check => o.fix = true,
            "--env" => o.env = Some(flag_value(&mut rest)?),
            "--event" => o.event = Some(flag_value(&mut rest)?),
            "--actor" => o.actor = actor_kind(&flag_value(&mut rest)?)?,
            "--non-interactive" => o.non_interactive = true,
            "--upgrade" if command == Command::Fmt => o.upgrade = true,
            "--index" if command == Command::BlocksSearch => o.index = Some(flag_value(&mut rest)?),
            "--limit" if command == Command::BlocksSearch => {
                let value = flag_value(&mut rest)?;
                o.limit = value.parse().ok().filter(|limit| *limit > 0)?;
            }
            flag if flag.starts_with('-') => return None,
            // One positional: the site file, the tree with `--all`, or the
            // search text. A second is almost always a typo, not a list to
            // check.
            file if o.path.is_none()
                && command != Command::BlocksSearch
                && command != Command::Fmt =>
            {
                o.path = Some(file.to_string())
            }
            text if o.query.is_none() && command == Command::BlocksSearch => {
                o.query = Some(text.to_string())
            }
            // `fmt` takes a list: it rewrites files, and rewriting several
            // in one run is the whole reason it walks a tree at all.
            path if command == Command::Fmt => o.paths.push(path.to_string()),
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

/// The value after `--env`/`--event`/`--actor`/`--format`. A missing value,
/// or another flag where a value belongs, is a usage error instead of a
/// silently swallowed option.
fn flag_value(rest: &mut std::slice::Iter<'_, String>) -> Option<String> {
    let value = rest.next()?;
    (!value.starts_with('-')).then(|| value.clone())
}
