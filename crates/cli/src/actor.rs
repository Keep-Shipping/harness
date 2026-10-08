//! The actor half of an organisation baseline: who a run says it is, and what
//! the organisation assumes when it says nothing ([#119](https://github.com/Keep-Shipping/harness/issues/119)).
//!
//! The decision lives in the port
//! ([`detect_local_actor`]);
//! this module supplies it with the organisation's [`ActorBaseline`] and the
//! one thing the port cannot supply — a person confirming, at a terminal, that
//! they are one. Guessing "agent" costs a prompt, never a run.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Write};

use ks_core::ports::run_context::{
    Actor, ActorKind, Establishment, LocalRunFacts, UnknownRunPolicy, detect_local_actor,
};

/// The prompt the baseline puts to a terminal before it calls somebody a
/// human, in the same lowercase register as the rest of the CLI's questions.
const CONFIRM_PROMPT: &str = "this baseline needs a person: are you a human? [y/N] ";

/// The value of `--as`: a kind, plus the agent's name when the invocation gave
/// one (`agent:<name>`). Only `agent` takes a name, and only a non-empty one;
/// anything else is [`None`] — an invalid value, to the caller.
pub fn parse_as(text: &str) -> Option<(ActorKind, Option<String>)> {
    match text {
        "human" => Some((ActorKind::Human, None)),
        "ci" => Some((ActorKind::Ci, None)),
        "agent" => Some((ActorKind::Agent, None)),
        _ => {
            let name = text.strip_prefix("agent:")?.trim();
            (!name.is_empty()).then(|| (ActorKind::Agent, Some(name.to_string())))
        }
    }
}

/// The actor half of an organisation baseline: what the organisation declares
/// about agents, and how hard it wants to be about people.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActorBaseline {
    /// GitHub logins the organisation declares are agents, beyond the ones
    /// GitHub already marks as bots itself. Case-insensitive, as GitHub's are.
    pub agents: BTreeSet<String>,
    /// When set, a local run is a human only if it asserts `--as human` *and*
    /// confirms it on a terminal; everything else is an agent.
    pub require_human: bool,
}

/// Decides who a local run is.
///
/// The facts are the ones the port reads; `baseline` supplies the
/// organisation's assumptions and `confirm` the only evidence a terminal can
/// give — that somebody is there to answer — called exactly once, and only for
/// a run that said it was a human and has a terminal to say it on. An
/// `--as agent:<name>` names *which agent proposed this run*; a detected run
/// keeps what its marker already said. A local run is never
/// [`ActorKind::Ci`]: a shell can claim it, never prove it.
pub fn local(
    declared: Option<ActorKind>,
    name: Option<&str>,
    env: BTreeMap<String, String>,
    stdin_is_tty: bool,
    git_user_name: Option<String>,
    baseline: &ActorBaseline,
    confirm: impl FnOnce() -> bool,
) -> Actor {
    let facts = LocalRunFacts { declared, env, stdin_is_tty, git_user_name };
    let policy = if baseline.require_human {
        UnknownRunPolicy::TreatAsAgent
    } else {
        UnknownRunPolicy::TreatAsHuman
    };
    let mut actor = detect_local_actor(&facts, policy);
    // The baseline does not take the port's "a person is driving" at face value:
    // it wants the run to have said so, and a terminal to have agreed.
    // Everything short of that is an assumed agent — a prompt, not a stop.
    if actor.kind == ActorKind::Human && baseline.require_human {
        actor = if declared == Some(ActorKind::Human) && stdin_is_tty && confirm() {
            Actor { established: Establishment::SelfDeclared, ..actor }
        } else {
            Actor { kind: ActorKind::Agent, established: Establishment::AssumedByBaseline, ..actor }
        };
    }
    if actor.kind == ActorKind::Agent
        && let Some(name) = name
    {
        actor.display_name = name.to_string();
    }
    actor
}

/// [`local`] for a real invocation: it reads the facts from this process —
/// environment, terminal, git config — rather than from a caller. `interactive`
/// is the caller's own verdict, folding in `--non-interactive` and `CI`.
pub fn for_run(
    declared: Option<ActorKind>,
    name: Option<&str>,
    interactive: bool,
    baseline: &ActorBaseline,
) -> Actor {
    let facts = std::env::vars().collect();
    let ask = || confirm_human(std::io::stdin().lock(), std::io::stderr());
    local(declared, name, facts, interactive, git_user_name(), baseline, ask)
}

/// `git config user.name`, trimmed, or [`None`] when git cannot say: a run-log
/// label, so a missing one is never worth an error.
fn git_user_name() -> Option<String> {
    let output = std::process::Command::new("git").args(["config", "user.name"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let name = String::from_utf8(output.stdout).ok()?;
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// Asks the person at the terminal the one question the baseline cannot answer
/// for itself: `y` or `yes` — in any case, with or without trailing space —
/// says yes, and everything else, including a closed stdin, says no. The
/// prompt is flushed before the read, or it shows up after the answer, which
/// reads as a question asked too late.
pub fn confirm_human(mut input: impl BufRead, mut out: impl Write) -> bool {
    let _ = out.write_all(CONFIRM_PROMPT.as_bytes()).and_then(|()| out.flush());
    let mut line = String::new();
    // No line at all — a closed stdin, or a failed read — is nobody answering.
    match input.read_line(&mut line) {
        Ok(0) | Err(_) => return false,
        Ok(_) => {}
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Whether a GitHub account is an agent's, so a pull request it opens is an
/// agent's run rather than a person's. GitHub says so itself through the
/// account's `type` or the `[bot]` suffix on its login; the organisation may say
/// so too. Logins compare case-insensitively, as GitHub's are.
pub fn is_agent_account(login: &str, user_type: Option<&str>, baseline: &ActorBaseline) -> bool {
    user_type == Some("Bot")
        || login.ends_with("[bot]")
        || baseline.agents.iter().any(|listed| listed.eq_ignore_ascii_case(login))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// [`local`] on a bare environment with a laptop's git name.
    fn on_laptop(
        baseline: &ActorBaseline,
        declared: Option<ActorKind>,
        name: Option<&str>,
        tty: bool,
        confirm: impl FnOnce() -> bool,
    ) -> Actor {
        local(declared, name, BTreeMap::new(), tty, Some("ada".to_string()), baseline, confirm)
    }

    #[test]
    fn the_as_flag_takes_a_kind_and_only_agents_take_a_name() {
        let cases = [
            ("human", Some((ActorKind::Human, None))),
            ("ci", Some((ActorKind::Ci, None))),
            ("agent", Some((ActorKind::Agent, None))),
            ("agent:claude", Some((ActorKind::Agent, Some("claude")))),
            ("agent:  claude  ", Some((ActorKind::Agent, Some("claude")))),
            // No name after the colon is no agent, and only agents may be named.
            ("agent:", None),
            ("human:ada", None),
            ("", None),
        ];
        for (text, expected) in cases {
            let want = expected.map(|(kind, name)| (kind, name.map(str::to_string)));
            assert_eq!(parse_as(text), want, "{text:?}");
        }
    }

    #[test]
    fn a_baseline_that_requires_a_person_waits_at_every_run_it_cannot_confirm() {
        let strict = ActorBaseline { agents: BTreeSet::new(), require_human: true };
        // (declared human?, terminal?, answered yes?, kind, establishment)
        let cases = [
            // The acceptance criterion: an unattended run with no flag is not
            // asked, and is an agent on the baseline's assumption. Then the
            // ways a run still fails to be believed as a human: it refused, it
            // has no terminal to ask on, or it never said so at all.
            (false, false, false, ActorKind::Agent, Establishment::AssumedByBaseline),
            (true, true, true, ActorKind::Human, Establishment::SelfDeclared),
            (true, true, false, ActorKind::Agent, Establishment::AssumedByBaseline),
            (true, false, true, ActorKind::Agent, Establishment::AssumedByBaseline),
            (false, true, false, ActorKind::Agent, Establishment::AssumedByBaseline),
        ];
        for (declared, tty, yes, kind, established) in cases {
            let asked = Cell::new(0);
            let actor = on_laptop(&strict, declared.then_some(ActorKind::Human), None, tty, || {
                asked.set(asked.get() + 1);
                yes
            });
            let seen = (actor.kind, actor.established, actor.display_name.as_str());
            assert_eq!(seen, (kind, established, "ada"), "{declared}/{tty}/{yes}");
            assert_eq!(asked.get(), usize::from(declared && tty), "{declared}/{tty}");
        }
    }

    #[test]
    fn without_the_requirement_the_port_answers_as_it_always_did() {
        let baseline = ActorBaseline::default();
        // The plain laptop: no flag, no terminal, no evidence — a human, from
        // git config, exactly as before the baseline existed.
        let plain = on_laptop(&baseline, None, None, false, || {
            panic!("nothing is asked when the baseline does not require it")
        });
        let seen = (plain.kind, plain.established, plain.display_name.as_str());
        assert_eq!(seen, (ActorKind::Human, Establishment::LocalGitConfig, "ada"));
        // `--as agent:claude`: an agent, self-declared, named in the run log as
        // the agent that proposed this run. A human never borrows that name.
        for (declared, expected) in [(ActorKind::Agent, "claude"), (ActorKind::Human, "ada")] {
            let actor = on_laptop(&baseline, Some(declared), Some("claude"), true, || false);
            assert_eq!((actor.kind, actor.display_name.as_str()), (declared, expected));
        }
    }

    #[test]
    fn the_question_is_asked_and_only_a_yes_answers_it() {
        for (typed, expected) in
            [("y\n", true), ("YES\n", true), ("  y  \n", true), ("\n", false), ("", false)]
        {
            let mut out: Vec<u8> = Vec::new();
            assert_eq!(confirm_human(typed.as_bytes(), &mut out), expected, "{typed:?}");
            // Asked even of a terminal that can never answer it, and always the
            // same question.
            assert_eq!(String::from_utf8(out).unwrap(), CONFIRM_PROMPT, "{typed:?}");
        }
    }

    #[test]
    fn github_and_the_baseline_both_say_which_accounts_are_agents() {
        let baseline =
            ActorBaseline { agents: BTreeSet::from(["Ada-Bot".to_string()]), require_human: false };
        // GitHub's own two tells, then the organisation's list, which GitHub has
        // no opinion about, then a person.
        let cases = [
            ("dependabot[bot]", None, true),
            ("keepshipping-agent[bot]", Some("Bot"), true),
            ("Ada-Bot", Some("User"), true),
            ("ada-bot", None, true),
            ("ada", Some("User"), false),
        ];
        for (login, user_type, agent) in cases {
            assert_eq!(is_agent_account(login, user_type, &baseline), agent, "{login}");
        }
        // The list is the baseline's alone: the same login under an empty one
        // is a person.
        assert!(!is_agent_account("ada-bot", Some("User"), &ActorBaseline::default()));
    }
}
