//! Command-line parsing: one hand-rolled pass over the arguments, shared by
//! `check` and `run`. Anything unrecognizable — flag, value or format — is a
//! usage error, never a silently swallowed option.

use ks_core::ports::run_context::ActorKind;

use crate::render::Format;

pub const USAGE: &str = "\
usage: keepshipping check [FILE] [--all] [--format human|json|github]
                          [--warnings-as-errors] [--env NAME] [--event \"push main\"]
                          [--actor human|agent|ci] [--secrets]
       keepshipping run [FILE] [--env NAME] [--event \"push main\"] [--actor human|agent|ci]
                        [--non-interactive]";

/// Which subcommand's flags `parse_args` accepts. `--format`, `--all`,
/// `--warnings-as-errors` and `--secrets` belong to `check` alone; `run`
/// rejects them like any other unrecognized option.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Check,
    Run,
}

/// The parsed command line. `path` is the `FILE` argument: the site file —
/// or, with `--all`, the directory to walk — defaulting to `ship.ks` in the
/// working directory when absent.
pub struct Options {
    pub path: Option<String>,
    pub format: Format,
    pub all: bool,
    pub warnings_as_errors: bool,
    pub env: Option<String>,
    pub event: Option<String>,
    /// The actor the command would run as; a human unless `--actor` says
    /// otherwise. Policy rules that bind the actor are enforced at check
    /// time.
    pub actor: ActorKind,
    pub secrets: bool,
    pub non_interactive: bool,
}

pub fn parse_args(args: &[String], command: Command) -> Option<Options> {
    let mut o = Options {
        path: None,
        format: Format::Human,
        all: false,
        warnings_as_errors: false,
        env: None,
        event: None,
        actor: ActorKind::Human,
        secrets: false,
        non_interactive: false,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--format" if command == Command::Check => {
                o.format = Format::parse(&flag_value(&mut rest)?)?
            }
            "--all" if command == Command::Check => o.all = true,
            "--warnings-as-errors" if command == Command::Check => o.warnings_as_errors = true,
            "--secrets" if command == Command::Check => o.secrets = true,
            "--env" => o.env = Some(flag_value(&mut rest)?),
            "--event" => o.event = Some(flag_value(&mut rest)?),
            "--actor" => o.actor = actor_kind(&flag_value(&mut rest)?)?,
            "--non-interactive" => o.non_interactive = true,
            flag if flag.starts_with('-') => return None,
            // One positional: the site file, or the tree with `--all`. A
            // second is almost always a typo, not a list to check.
            file if o.path.is_none() => o.path = Some(file.to_string()),
            _ => return None,
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

/// The value after `--env`/`--event`/`--actor`/`--format`. A missing value,
/// or another flag where a value belongs, is a usage error instead of a
/// silently swallowed option.
fn flag_value(rest: &mut std::slice::Iter<'_, String>) -> Option<String> {
    let value = rest.next()?;
    (!value.starts_with('-')).then(|| value.clone())
}
