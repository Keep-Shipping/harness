//! The effective policy: org baseline ∩ the file's `policy:` block, with
//! destroy-from-plan outside it ([#101](https://github.com/Keep-Shipping/harness/issues/101),
//! [ADR 0012](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0012-policy-authority.md)).
//!
//! Pure — no I/O, no clock — so `explain` and `check` decide identically.

use ks_lang::Span;

use crate::ports::policy::{ANY_OBJECT, Baseline, Disposition};
use crate::ports::run_context::ActorKind;
use crate::step::{ActionClass, ActionKind};
use crate::workflow::{Policy, PolicyRule};

/// The object `read` takes, and the one `never: read secrets` binds.
pub const SECRETS: &str = "secrets";
/// The object `run` takes: `run scripts`.
pub const SCRIPTS: &str = "scripts";
/// The object `publish` takes: `publish blocks`.
pub const BLOCKS: &str = "blocks";

/// Which document decided an action: the file's `policy:` block, the org
/// baseline, the leash, or a hard rule outside the intersection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A rule the file declares, and no baseline rule was stricter.
    File,
    /// A rule from the org baseline, stricter than anything the file says.
    /// The file may not widen it.
    Baseline,
    /// Nobody named this action: the leash for an agent, "nothing says no"
    /// for a human.
    Default,
    /// A hard rule outside the intersection — destroy never reaches an agent
    /// as an allow.
    HardRule,
}

impl Source {
    /// The source's name, as `explain` prints it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Source::File => "file",
            Source::Baseline => "baseline",
            Source::Default => "default",
            Source::HardRule => "hard rule",
        }
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One answer: what happens to an action, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Whether the action may proceed, must be approved, or is refused.
    pub disposition: Disposition,
    /// Who is asked when `disposition` is [`Disposition::Ask`] — the subject's
    /// `ask:` handles, in declaration order. Empty reads as "ask a human".
    pub ask: Vec<String>,
    /// Which document decided it; see [`Source`].
    pub source: Source,
    /// Where the deciding rule sits in the file, when it came from one.
    pub rule_span: Option<Span>,
}

/// The policy verb an action class stands for, and the object it names.
///
/// `None` for [`ActionKind::Other`]: a class outside the vocabulary is not
/// policy-governed — an `approval` step is the ask, and gating it on itself
/// would be circular. A class with no environment yields [`ANY_OBJECT`], which
/// is what makes an env-scoped rule undecidable against it; see [`decide`].
#[must_use]
pub fn action_of(class: &ActionClass) -> Option<(&'static str, String)> {
    let (verb, object) = match class.kind {
        ActionKind::Build => ("build", ANY_OBJECT),
        ActionKind::Plan => ("plan", ANY_OBJECT),
        ActionKind::Apply => ("apply", ANY_OBJECT),
        ActionKind::Deploy => ("deploy", class.env.as_deref().unwrap_or(ANY_OBJECT)),
        ActionKind::Destroy => ("destroy", class.env.as_deref().unwrap_or(ANY_OBJECT)),
        ActionKind::ReadSecrets => ("read", SECRETS),
        ActionKind::Other => return None,
    };
    Some((verb, object.to_string()))
}

/// The `policy:` section a run reads: `agents:` for an agent, `humans:` for
/// everyone else — CI included, since a CI run is a machine somebody else put
/// in the repository on a reviewed branch.
fn subject_for(actor: ActorKind) -> ActorKind {
    match actor {
        ActorKind::Agent => ActorKind::Agent,
        ActorKind::Human | ActorKind::Ci => ActorKind::Human,
    }
}

/// The `policy:` section name an actor reads, as a diagnostic quotes it.
#[must_use]
pub fn section_name(actor: ActorKind) -> &'static str {
    match actor {
        ActorKind::Agent => "agents",
        ActorKind::Human | ActorKind::Ci => "humans",
    }
}

/// Whether a rule's object covers the object the action names: `*` covers
/// every environment, anything else must match exactly.
fn covers(rule_object: &str, object: &str) -> bool {
    rule_object == ANY_OBJECT || rule_object == object
}

/// Whether an action with no environment of its own must still stop short of
/// an allow, because some environment's rule says so.
///
/// `can: deploy staging` grants nothing to a deploy whose environment nobody
/// has named: naming an environment is a decision about that environment. A
/// `before:` or `never:` naming one is different — it says some deploy of that
/// name needs a human or is refused, and the one thing the checker could not
/// answer is which deploy this is. So the env-less decision becomes an ask
/// rather than an allow or a refusal: check time never errors on a rule that
/// only binds some environment, and `explain` still shows the refusal per
/// environment.
fn env_scoped_asks(rule: &PolicyRule, object: &str) -> bool {
    object == ANY_OBJECT
        && rule.disposition != Disposition::Allow
        && rule.object != ANY_OBJECT
        && !matches!(rule.object.as_str(), SECRETS | SCRIPTS | BLOCKS)
}

/// The stricter of two dispositions.
///
/// [`Disposition`]'s `Ord` is `Allow < Ask < Never` — least to most
/// restrictive — so the stricter of two is the **greater** one. Spelled out as
/// a `match` rather than `a.max(b)` so the direction is not a guess.
fn stricter(a: Disposition, b: Disposition) -> Disposition {
    match (a, b) {
        (Disposition::Never, _) | (_, Disposition::Never) => Disposition::Never,
        (Disposition::Ask, _) | (_, Disposition::Ask) => Disposition::Ask,
        (Disposition::Allow, Disposition::Allow) => Disposition::Allow,
    }
}

/// What `actor` may do `class`, given the file's policy and the org baseline.
///
/// `None` for an action class outside the vocabulary; a caller iterating steps
/// should skip those rather than read the absence as a refusal.
///
/// `baseline` is [`None`] when no baseline is configured — a first-class state,
/// not an error — and the effective policy is then the file's own policy,
/// unchanged.
#[must_use]
pub fn decide(
    file: &Policy,
    baseline: Option<&Baseline>,
    actor: ActorKind,
    class: &ActionClass,
) -> Option<Decision> {
    let (verb, object) = action_of(class)?;
    let subject = subject_for(actor);

    // The file's own answer. Several rules can cover one action (`can: deploy`
    // and `never: deploy prod` against a `deploy prod`) and the strictest
    // wins: a file that both allows and refuses is refusing.
    let matched = file
        .rules()
        .iter()
        .filter(|r| r.subject == subject && r.verb == verb)
        .filter_map(|rule| {
            let disposition = if covers(&rule.object, &object) {
                rule.disposition
            } else if env_scoped_asks(rule, &object) {
                Disposition::Ask
            } else {
                return None;
            };
            Some((rule, disposition))
        })
        .fold(None::<(&PolicyRule, Disposition)>, |best, (rule, disposition)| match best {
            None => Some((rule, disposition)),
            Some((_, best_disposition))
                if stricter(disposition, best_disposition) == disposition =>
            {
                Some((rule, disposition))
            }
            keep => keep,
        });
    let (file_disposition, file_span) = match matched {
        Some((rule, disposition)) => (disposition, Some(rule.span)),
        // Unlisted. The leash: an agent asks, a human is allowed. No document
        // said either, so the source is `Default`.
        None if subject == ActorKind::Agent => (Disposition::Ask, None),
        None => (Disposition::Allow, None),
    };

    // The baseline may only narrow: where the two disagree the more
    // restrictive answer wins, and `Baseline` is claimed only when the
    // baseline's own answer is the strict one.
    let mut disposition = file_disposition;
    let mut source = if file_span.is_some() { Source::File } else { Source::Default };
    let mut rule_span = file_span;
    if let Some(baseline) = baseline {
        let from_baseline = baseline.decide(actor, verb, &object);
        if from_baseline != file_disposition
            && stricter(file_disposition, from_baseline) == from_baseline
        {
            disposition = from_baseline;
            source = if baseline.source.is_some() { Source::Baseline } else { Source::Default };
            rule_span = None;
        }
    }

    // Hard rules, outside the intersection: destroy never reaches an agent as
    // an allow, whatever the file and the baseline say.
    if class.kind == ActionKind::Destroy
        && actor == ActorKind::Agent
        && disposition == Disposition::Allow
    {
        disposition = Disposition::Ask;
        source = Source::HardRule;
        rule_span = None;
    }

    Some(Decision {
        disposition,
        ask: file.ask_handles(subject).map(str::to_string).collect(),
        source,
        rule_span,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stricter_means_the_greater_disposition_not_the_smaller_one() {
        assert_eq!(stricter(Disposition::Allow, Disposition::Ask), Disposition::Ask);
        assert_eq!(stricter(Disposition::Ask, Disposition::Allow), Disposition::Ask);
        assert_eq!(stricter(Disposition::Allow, Disposition::Never), Disposition::Never);
        assert_eq!(stricter(Disposition::Never, Disposition::Allow), Disposition::Never);
        assert_eq!(stricter(Disposition::Ask, Disposition::Never), Disposition::Never);
        assert_eq!(stricter(Disposition::Ask, Disposition::Ask), Disposition::Ask);
    }

    #[test]
    fn only_the_named_verbs_are_policy_governed() {
        assert_eq!(action_of(&ActionClass::new(ActionKind::Build)), Some(("build", "*".into())));
        assert_eq!(
            action_of(&ActionClass::new(ActionKind::Deploy).in_env("prod")),
            Some(("deploy", "prod".into()))
        );
        assert_eq!(
            action_of(&ActionClass::new(ActionKind::ReadSecrets)),
            Some(("read", "secrets".into()))
        );
        assert_eq!(action_of(&ActionClass::new(ActionKind::Other)), None);
    }
}
