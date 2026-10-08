//! The `auto:` rule: an expression over `decide` answers and step outputs
//! that grants an approval by policy, and the hard rules no policy may loosen
//! (ADR 0012, `docs/adr/0012-policy-authority.md`).
//!
//! Three halves. [`guards_destroys`] is the check the checker runs over an
//! `auto:` expression, so the file says out loud what the engine already does;
//! [`auto_approves`] is that rule as a boolean, conjoining the destroys guard
//! whether or not the file wrote it; [`resolve`] is the whole decision — the
//! expression against one run's [`Facts`], the hard rules applied whatever it
//! said, and the `else:` actions carried to whoever waits.
//!
//! Pure: no I/O, no adapter, no clock, so it sits on the same offline path as
//! `check` and compiles for `wasm32`.

use std::collections::BTreeMap;
use std::fmt;

use ks_lang::{Atom, CmpOp, Expr, Scalar, Word, WordPart};

use crate::ports::policy::{Baseline, Disposition};
use crate::ports::run_context::ActorKind;
use crate::ports::script_host::Value;
use crate::step::Outputs;

/// What an `auto:` rule decides once the destroys guard has been applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The rule holds and nothing is destroyed: approve without a human.
    AutoApprove,
    /// Anything else — the rule failed, or the plan destroys: ask a human.
    AskHuman,
}

/// The rule, as the engine applies it: the guard is *always* conjoined with
/// the file's expression, whether or not the file wrote it. `rule_holds` is
/// the result of evaluating that expression; a plan with `destroys != 0` goes
/// to a human even when the rule holds.
#[must_use]
pub fn auto_approves(rule_holds: bool, destroys: usize) -> bool {
    rule_holds && destroys == 0
}

/// [`auto_approves`] as the two-outcome decision an approval step acts on.
#[must_use]
pub fn decide(rule_holds: bool, destroys: usize) -> Decision {
    if auto_approves(rule_holds, destroys) { Decision::AutoApprove } else { Decision::AskHuman }
}

/// The message and hint for an `auto:` expression without the guard.
pub const MISSING_GUARD_MESSAGE: &str = "`auto:` could approve a plan that destroys resources; the engine adds `and plan.destroys == 0`";
/// The fix, as the file should spell it.
pub const MISSING_GUARD_HINT: &str = "write the clause yourself: `auto: … and plan.destroys == 0`";

/// Whether the `auto:` expression `e` carries the destroys guard as a
/// top-level conjunct. `is_plan_step` answers whether a step name is one whose
/// kind declares a `destroys` output — `tofu.plan` today — so `risk.destroys
/// == 0` on a `decide` step is not the guard, whatever it reads like.
///
/// Only a top-level conjunct counts: `risk is low ≥ 0.95 and plan.destroys
/// == 0` is guarded, while `risk is low ≥ 0.95 or plan.destroys == 0` and
/// `not (plan.destroys == 0)` are not — the first approves when the plan
/// destroys, the second says so outright. `true` carries no guard either.
#[must_use]
pub fn guards_destroys(e: &Expr<'_>, is_plan_step: &impl Fn(&str) -> bool) -> bool {
    match unparen(e) {
        Expr::And { args, .. } => args.iter().any(|arg| guards_destroys(arg, is_plan_step)),
        other => is_destroys_guard(other, is_plan_step),
    }
}

/// One comparison the guard may be written as: `X.destroys == 0`,
/// `0 == X.destroys`, `X.destroys <= 0` or `X.destroys < 1`, where `X` is a
/// step whose kind declares a `destroys` output.
fn is_destroys_guard(e: &Expr<'_>, is_plan_step: &impl Fn(&str) -> bool) -> bool {
    let Expr::Compare { lhs, op, rhs: Some(rhs), .. } = unparen(e) else { return false };
    let (lhs, rhs) = (unparen(lhs), unparen(rhs));
    match *op {
        CmpOp::Eq => {
            (is_destroys(lhs, is_plan_step) && is_int(rhs, 0))
                || (is_int(lhs, 0) && is_destroys(rhs, is_plan_step))
        }
        CmpOp::Le => is_destroys(lhs, is_plan_step) && is_int(rhs, 0),
        CmpOp::Lt => is_destroys(lhs, is_plan_step) && is_int(rhs, 1),
        _ => false,
    }
}

/// The leftmost path segment a comparison operand reads, ignoring `( … )`.
fn unparen<'a>(e: &'a Expr<'a>) -> &'a Expr<'a> {
    match e {
        Expr::Atom { atom: Atom::Paren { inner: Some(inner), .. }, .. } => unparen(inner),
        _ => e,
    }
}

/// Whether `e` is a dotted path whose last segment is `destroys` and whose
/// first names a step that produces it — the `destroys: Int` output of
/// `tofu.plan`, under whatever name the file gave the step. `risk.destroys`
/// and `plan.out.destroys`-on-an-unknown-kind are not the guard.
fn is_destroys(e: &Expr<'_>, is_plan_step: &impl Fn(&str) -> bool) -> bool {
    let Expr::Atom { atom: Atom::Word(w), .. } = unparen(e) else { return false };
    let Some(segments) = w.segments() else { return false };
    let ends_in_destroys = segments.last().is_some_and(|(seg, _)| *seg == "destroys");
    ends_in_destroys && segments.first().is_some_and(|(base, _)| is_plan_step(base))
}

/// Whether `e` is the integer literal `value` — compared numerically, so `00`
/// and `-0` are zero like `0` is, and `0.0` is not an integer at all.
fn is_int(e: &Expr<'_>, value: i64) -> bool {
    let Expr::Atom { atom: Atom::Word(w), .. } = unparen(e) else { return false };
    w.scalar() == ks_lang::Scalar::Number && w.text().parse::<i64>().ok() == Some(value)
}

// --- the approval decision --------------------------------------------------

/// The approver recorded on an approval the engine granted itself: an audit line
/// that reads like a person said yes is a lie the log cannot correct.
pub const POLICY_AUTO: &str = "policy:auto";

/// The baseline verb that switches `auto:` off in one environment. Baseline verbs
/// are free-form; the closed list belongs to the file's `policy:` block, which is
/// what `auto:` must not reach.
pub const AUTO_VERB: &str = "auto";

/// Whether the org baseline lets `auto:` run in `env`. Only `Never` refuses it:
/// `Ask` is the default for every verb no rule names, so reading that as a denial
/// would leave `auto:` unusable until an org granted it explicitly.
#[must_use]
pub fn baseline_allows_auto(baseline: &Baseline, env: &str) -> bool {
    !matches!(baseline.decide(ActorKind::Agent, AUTO_VERB, env), Disposition::Never)
}

/// Where a decision came from: the one thing about it a file cannot express, and
/// the only one that can approve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionSource {
    Model,
    NoModel,
    Errored,
}

/// One `decide` step's three declared outputs, plus the provenance none of them
/// carries.
#[derive(Clone, Debug, PartialEq)]
pub struct Answered {
    pub answer: String,
    pub confidence: f64,
    pub reason: String,
    pub source: DecisionSource,
}

/// What an `auto:` rule may read. Every value is the engine's, and the destroys
/// count is counted from the outputs rather than handed in, so a caller cannot
/// forget it.
#[derive(Clone, Debug, Default)]
pub struct Facts<'a> {
    pub env: &'a str,
    pub auto_allowed: bool,
    pub answers: BTreeMap<&'a str, Answered>,
    pub outputs: BTreeMap<&'a str, &'a Outputs>,
}

impl<'a> Facts<'a> {
    #[must_use]
    pub fn new(env: &'a str) -> Self {
        Facts { env, auto_allowed: true, ..Facts::default() }
    }

    /// Destroys and replaces, summed over every step that counts them:
    /// replacements are already destroys in `tofu.plan`'s own output. A value that
    /// is not a whole number of resources is an error, not a zero — a plan the
    /// engine cannot count is one no `auto:` waves through.
    fn destroys(&self) -> Result<usize, String> {
        let mut total = 0usize;
        for (step, outputs) in &self.outputs {
            let Some(value) = outputs.get("destroys") else { continue };
            let Value::Number(count) = value else {
                return Err(format!("`{step}.destroys` is a {}", value.value_type().as_str()));
            };
            if !count.is_finite()
                || *count < 0.0
                || count.fract() != 0.0
                || *count > usize::MAX as f64
            {
                return Err(format!("`{step}.destroys` is {count}, not a count of resources"));
            }
            total += *count as usize;
        }
        Ok(total)
    }
}

/// What an `auto:` came to: granted by policy, or the step waits on the people the
/// `else:` names.
#[derive(Clone, Debug, PartialEq)]
pub enum Resolution {
    Approved {
        /// [`POLICY_AUTO`], never a person.
        by: &'static str,
        /// The `auto:` expression's own text.
        rule: String,
        /// Every value the rule read, `(ref, value)`.
        saw: Vec<(String, String)>,
    },
    Ask {
        /// The handles `ask` named, in file order; empty when it named no team,
        /// and the caller falls back to the approval's `from:` or the
        /// environment's approvers.
        teams: Vec<String>,
        /// The references `show` named, and what they read.
        show: Vec<(String, String)>,
        /// Why the rule did not grant the approval.
        why: Why,
    },
}

/// Why an `auto:` did not approve. Every variant fails the same way — a human is
/// asked — and they are kept apart because that human has to be told which rule
/// stopped it.
#[derive(Clone, Debug, PartialEq)]
pub enum Why {
    RuleDidNotHold { saw: Vec<(String, String)> },
    Destroys { count: usize },
    NoModel { step: String },
    Errored { step: String },
    BaselineDenied { env: String },
    Unreadable { message: String },
}

impl fmt::Display for Why {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Why::RuleDidNotHold { saw } => {
                let seen: Vec<String> =
                    saw.iter().map(|(name, value)| format!("{name} = {value}")).collect();
                match seen.is_empty() {
                    true => f.write_str("the `auto:` rule did not hold"),
                    false => write!(f, "the `auto:` rule did not hold: {}", seen.join(", ")),
                }
            }
            Why::Destroys { count } => {
                let plural = if *count == 1 { "" } else { "s" };
                write!(f, "the plan destroys or replaces {count} resource{plural}")
            }
            Why::NoModel { step } => {
                write!(f, "`{step}` answered with `model: none`: no model, no decision")
            }
            Why::Errored { step } => {
                write!(f, "the model call behind `{step}` errored: no decision to trust")
            }
            Why::BaselineDenied { env } => write!(f, "the org baseline disables `auto:` in {env}"),
            Why::Unreadable { message } => {
                write!(f, "the `auto:` rule could not be read: {message}")
            }
        }
    }
}

/// The decision an approval step acts on: the file's `auto:` rule, its `else:`
/// actions, and the facts of one run.
///
/// The hard rules are conjunctions, taken in this order — the org baseline, the
/// provenance of every decide step the rule reads, the rule, then the destroys
/// guard. The guard comes last because it is the clause the engine owns, and
/// because a plan that destroys *and* whose rule failed is better explained by
/// the rule, with the numbers attached.
#[must_use]
pub fn resolve(auto: &Expr<'_>, otherwise: Option<&Expr<'_>>, facts: &Facts<'_>) -> Resolution {
    if !facts.auto_allowed {
        return ask(otherwise, facts, Why::BaselineDenied { env: facts.env.into() });
    }
    let mut saw = Vec::new();
    let verdict = eval(auto, facts, &mut saw);
    // Every decide step the rule read is in `saw`, under its own name or a
    // `risk.confidence` reference, so the first segment is the step. Checking
    // what was read, rather than what the file mentions, is what stops a rule
    // that hides a decision inside a comparison from approving on it.
    for (name, _) in &saw {
        // Longest prefix first: a step named `a.b` is read as `a.b.answer`, and
        // the first segment alone would go looking for a step called `a`.
        let mut named = std::iter::successors(Some(name.as_str()), |s| {
            s.rsplit_once('.').map(|(head, _)| head)
        });
        let Some(step) = named.find(|step| facts.answers.contains_key(*step)) else { continue };
        let Some(answer) = facts.answers.get(step) else { continue };
        let why = match answer.source {
            DecisionSource::Model => continue,
            DecisionSource::NoModel => Why::NoModel { step: step.into() },
            DecisionSource::Errored => Why::Errored { step: step.into() },
        };
        return ask(otherwise, facts, why);
    }
    match verdict {
        Ok(Val::Bool(true)) => {}
        Ok(Val::Bool(false)) => return ask(otherwise, facts, Why::RuleDidNotHold { saw }),
        Ok(other) => {
            let message = format!("it reads as {}, not as a yes or a no", other.kind());
            return ask(otherwise, facts, Why::Unreadable { message });
        }
        Err(message) => return ask(otherwise, facts, Why::Unreadable { message }),
    }
    match facts.destroys() {
        Ok(0) => Resolution::Approved { by: POLICY_AUTO, rule: text_of(auto), saw },
        Ok(count) => ask(otherwise, facts, Why::Destroys { count }),
        Err(message) => ask(otherwise, facts, Why::Unreadable { message }),
    }
}

/// The `Ask` outcome, with the `else:` actions read. A `show` whose reference is
/// not there still shows its name, with `<unreadable>`: a step waiting on a team
/// must still say what it is waiting about.
fn ask(otherwise: Option<&Expr<'_>>, facts: &Facts<'_>, why: Why) -> Resolution {
    let mut teams = Vec::new();
    let mut show = Vec::new();
    let actions = match otherwise {
        Some(Expr::Tuple { items, .. }) => items.iter().collect::<Vec<_>>(),
        Some(other) => vec![other],
        None => Vec::new(),
    };
    for action in actions {
        let atoms = action.atoms();
        let Some(Atom::Word(verb)) = atoms.first() else { continue };
        let words = || {
            atoms[1..].iter().filter_map(|a| match a {
                Atom::Word(w) => Some(w),
                _ => None,
            })
        };
        match verb.text() {
            "ask" => teams.extend(
                words().filter(|w| w.scalar() == Scalar::Handle).map(|w| w.text().to_string()),
            ),
            "show" => show.extend(words().map(|w| {
                let seen = lookup(w, facts).map_or_else(|_| "<unreadable>".into(), |v| v.render());
                (w.text().to_string(), seen)
            })),
            _ => {}
        }
    }
    Resolution::Ask { teams, show, why }
}

/// A value an `auto:` rule can compare. Anything else — a list, a map, a duration,
/// a path — is not one, and reads as an error.
#[derive(Clone, Debug, PartialEq)]
enum Val {
    Num(f64),
    Str(String),
    Bool(bool),
}

impl Val {
    /// The value as `saw` records it: a number the way the file writes one.
    fn render(&self) -> String {
        match self {
            Val::Num(n) if n.is_finite() && n.fract() == 0.0 && n.abs() < 1e15 => {
                format!("{}", *n as i64)
            }
            Val::Num(n) => format!("{n}"),
            Val::Str(s) => s.clone(),
            Val::Bool(b) => b.to_string(),
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Val::Num(_) => "a number",
            Val::Str(_) => "a string",
            Val::Bool(_) => "a boolean",
        }
    }
}

/// Evaluate `e`, recording every value it read in `saw`. Conjunctions and
/// disjunctions do not short-circuit: `saw` exists to show a person what the rule
/// looked at, and stopping at the first `false` would show them half.
fn eval(e: &Expr<'_>, facts: &Facts<'_>, saw: &mut Vec<(String, String)>) -> Result<Val, String> {
    let e = unparen(e);
    match e {
        // Every arm is read; `and` / `or` differ only in the first value.
        Expr::And { args, .. } | Expr::Or { args, .. } => {
            let all = matches!(e, Expr::And { .. });
            let mut so_far = all;
            for arg in args {
                let got = truth(&eval(arg, facts, saw)?)?;
                so_far = if all { so_far & got } else { so_far | got };
            }
            Ok(Val::Bool(so_far))
        }
        Expr::Not { arg, .. } => Ok(Val::Bool(!truth(&eval(arg, facts, saw)?)?)),
        Expr::Compare { lhs, op, rhs: Some(rhs), .. } => {
            compare(*op, &eval(lhs, facts, saw)?, &eval(rhs, facts, saw)?)
        }
        // `plan.ready` on its own is a boolean a file may test directly.
        Expr::Compare { lhs, rhs: None, .. } => eval(lhs, facts, saw),
        Expr::IsTest { subject, answer, threshold, .. } => {
            is_test(subject, answer, threshold.as_ref(), facts, saw)
        }
        Expr::Atom { atom, .. } => atom_val(atom, facts, saw),
        other => Err(format!("`{}` is not something a rule can read", text_of(other))),
    }
}

/// The boolean an operand of `and` / `or` / `not` must be.
fn truth(v: &Val) -> Result<bool, String> {
    match v {
        Val::Bool(b) => Ok(*b),
        other => Err(format!("{} is not a yes or a no", other.kind())),
    }
}

/// `risk is low`, and `risk is low ≥ 0.95` on top of it: the subject is a step
/// with a decision, the answer one it declared, the threshold the confidence it
/// was given with.
fn is_test(
    subject: &Expr<'_>,
    wanted_answer: &Expr<'_>,
    threshold: Option<&(CmpOp, &ks_lang::SyntaxToken, Box<Expr<'_>>)>,
    facts: &Facts<'_>,
    saw: &mut Vec<(String, String)>,
) -> Result<Val, String> {
    let Some(w) = word_of(subject) else {
        return Err("`is` needs a step with a decision as its subject".into());
    };
    let step = w.text();
    let Some(answer) = facts.answers.get(step) else {
        return Err(format!("`{step}` is not a step with a decision in this run"));
    };
    note(saw, step, &Val::Str(answer.answer.clone()));
    let wanted = match unparen(wanted_answer) {
        Expr::Atom { atom: Atom::Word(w), .. } => w.text().to_string(),
        Expr::Atom { atom: Atom::Str(s), .. } => s.value(),
        _ => return Err("the answer of an `is` test is one of its declared answers".into()),
    };
    let mut holds = answer.answer == wanted;
    if let Some((op, _, bound)) = threshold {
        let bound = number(word_of(bound).ok_or("a confidence threshold is a number")?)?;
        note(saw, &format!("{step}.confidence"), &Val::Num(answer.confidence));
        holds &= truth(&compare(*op, &Val::Num(answer.confidence), &Val::Num(bound))?)?;
    }
    Ok(Val::Bool(holds))
}

/// One literal, reference or grouped expression, as a value.
fn atom_val(
    atom: &Atom<'_>,
    facts: &Facts<'_>,
    saw: &mut Vec<(String, String)>,
) -> Result<Val, String> {
    let Atom::Word(w) = atom else {
        return match atom {
            Atom::Str(s) => Ok(Val::Str(s.value())),
            Atom::Paren { inner, .. } => inner
                .as_deref()
                .map_or_else(|| Err("`()` is empty".into()), |e| eval(e, facts, saw)),
            Atom::Word(_) => unreachable!(),
        };
    };
    if w.parts().iter().any(|part| matches!(part, WordPart::Interp(_))) {
        return Err(format!("`{}` interpolates, which a rule may not do", w.text()));
    }
    match w.scalar() {
        Scalar::DottedName => {
            let value = lookup(w, facts)?;
            note(saw, w.text(), &value);
            Ok(value)
        }
        Scalar::Bool => Ok(Val::Bool(w.text() == "true")),
        Scalar::Number => number(w).map(Val::Num),
        // A bare word — `low`, `production` — is the string it reads as, so
        // `risk.answer == low` works as well as `"low"`.
        Scalar::Ident | Scalar::Text => Ok(Val::Str(w.text().to_string())),
        other => Err(format!("`{}` is a {other:?}, not a value", w.text())),
    }
}

/// The value a dotted reference reads, or why it cannot: a decide step is
/// answered from the [`Facts`] record, every other step from its [`Outputs`].
fn lookup(w: &Word<'_>, facts: &Facts<'_>) -> Result<Val, String> {
    let segments = w.segments().ok_or_else(|| format!("`{}` is not a reference", w.text()))?;
    let (step, rest) = (segments[0].0, &segments[1..]);
    let field =
        rest.first().ok_or_else(|| format!("`{}` names a step, not an output", w.text()))?.0;
    if let Some(answer) = facts.answers.get(step) {
        return match field {
            "answer" => Ok(Val::Str(answer.answer.clone())),
            "confidence" => Ok(Val::Num(answer.confidence)),
            "reason" => Ok(Val::Str(answer.reason.clone())),
            other => Err(format!("`{step}` answers, is confident and explains; no `{other}`")),
        };
    }
    let outputs =
        facts.outputs.get(step).ok_or_else(|| format!("no step named `{step}` in this run"))?;
    let mut value =
        outputs.get(field).cloned().ok_or_else(|| format!("`{step}` produced no `{field}`"))?;
    for (segment, _) in &rest[1..] {
        let Value::Map(map) = &value else {
            return Err(format!(
                "`{}` is a {}, not a thing to read `{segment}` from",
                w.text(),
                value.value_type().as_str()
            ));
        };
        value = map
            .get(*segment)
            .cloned()
            .ok_or_else(|| format!("`{}` has no `{segment}`", w.text()))?;
    }
    match &value {
        Value::Bool(b) => Ok(Val::Bool(*b)),
        Value::Number(n) => Ok(Val::Num(*n)),
        Value::String(s) => Ok(Val::Str(s.clone())),
        other => Err(format!(
            "`{}` is a {}; a rule reads numbers, strings and booleans",
            w.text(),
            other.value_type().as_str()
        )),
    }
}

/// The word `e` is, if it is one.
fn word_of<'a>(e: &'a Expr<'a>) -> Option<&'a Word<'a>> {
    match unparen(e) {
        Expr::Atom { atom: Atom::Word(w), .. } => Some(w),
        _ => None,
    }
}

/// The number `w` is, if it parses as one.
fn number(w: &Word<'_>) -> Result<f64, String> {
    w.text().parse::<f64>().map_err(|_| format!("`{}` is not a number", w.text()))
}

/// One comparison, over two values of the same kind. Strings and booleans order
/// only by equality: `risk.reason < "m"` is not a comparison anybody agreed the
/// meaning of.
fn compare(op: CmpOp, lhs: &Val, rhs: &Val) -> Result<Val, String> {
    let holds = |eq: bool| -> Result<Val, String> {
        Ok(Val::Bool(match op {
            CmpOp::Eq => eq,
            CmpOp::Ne => !eq,
            _ => return Err("a string or a boolean compares with `==` and `!=` only".into()),
        }))
    };
    let order = match (lhs, rhs) {
        (Val::Num(a), Val::Num(b)) => a.partial_cmp(b),
        (Val::Str(a), Val::Str(b)) => return holds(a == b),
        (Val::Bool(a), Val::Bool(b)) => return holds(*a == *b),
        _ => return Err(format!("{} does not compare with {}", lhs.kind(), rhs.kind())),
    };
    let Some(order) = order else {
        return Err("a number that is not a number does not compare".into());
    };
    Ok(Val::Bool(match op {
        CmpOp::Eq => order.is_eq(),
        CmpOp::Ne => !order.is_eq(),
        CmpOp::Ge | CmpOp::GeUnicode => order.is_ge(),
        CmpOp::Le | CmpOp::LeUnicode => order.is_le(),
        CmpOp::Lt => order.is_lt(),
        CmpOp::Gt => order.is_gt(),
    }))
}

/// Record a value the rule read, once per reference: `saw` is the set of inputs,
/// not a trace.
fn note(saw: &mut Vec<(String, String)>, name: &str, value: &Val) {
    if !saw.iter().any(|(seen, _)| seen == name) {
        saw.push((name.to_string(), value.render()));
    }
}

/// An expression's own text on one line: a rule spelled over two lines is still
/// one rule, and the audit record should read like the file.
fn text_of(e: &Expr<'_>) -> String {
    e.node().text().split_whitespace().collect::<Vec<_>>().join(" ")
}
