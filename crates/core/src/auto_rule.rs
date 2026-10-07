//! The `auto:` destroys guard — one of the two hard rules no policy may
//! loosen (ADR 0012, `docs/adr/0012-policy-authority.md`): a plan that
//! destroys resources goes to a human, whatever the file says.
//!
//! Two halves live here. [`guards_destroys`] is the syntactic test the
//! checker runs over an `auto:` expression, so the file says out loud what the
//! engine already does. [`auto_approves`] is the rule itself: the engine
//! conjoins the guard whether or not the file wrote it, so a missing clause
//! is a warning about the file, never a hole in the rule.

use ks_lang::{Atom, CmpOp, Expr};

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
