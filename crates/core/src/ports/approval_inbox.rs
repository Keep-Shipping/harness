//! The [`ApprovalInbox`] port: the approver's side of an approval
//! ([#95](https://github.com/Keep-Shipping/harness/issues/95)).
//!
//! [`ApprovalChannel`](super::approval::ApprovalChannel) is one end of an
//! approval: a run asks. This is the other — a person answers. They are the
//! same conversation seen from opposite seats, so both live behind the same
//! adapter, and the split exists because the two callers have different jobs: a
//! step holds the channel and never sees an answer until the engine releases a
//! run, while the CLI holds the inbox and shows a queue of things to do. Like
//! the ports the engine and CLI hold rather than a step
//! ([`run_log`](super::run_log), [`policy`](super::policy)), this one is not in
//! the `Port` enum, so nothing a site file can write holds it.
//!
//! The one rule the port exists to hold is that **an identity here is one an
//! adapter established** — a GitHub OIDC subject, a `gh` token's user — and
//! never a name typed on the command line. There is deliberately no way to
//! pass one in as text: `keepshipping approve` has no `--as` flag, because a
//! self-declared approver is exactly the thing the two rules in
//! [`ApprovalRequest::accepts`](super::approval::ApprovalRequest::accepts)
//! exist to prevent.
//!
//! The second rule is that the approver never supplies artifacts.
//! [`decide`](ApprovalInbox::decide) builds the [`Verdict`] itself and binds
//! it to what the request asked about, so an adapter cannot widen what was
//! approved — and the verdict it returns is checked with
//! [`accepts`](super::approval::ApprovalRequest::accepts) before it is handed
//! over at all, which is what makes a proposer clicking approve on their own
//! run fail at the click rather than at the resume.

use super::BoxFuture;
use super::approval::{ApprovalError, ApprovalRequest, Identity, Outcome, Ticket, Verdict};
use crate::ids::RunId;

/// One open request, as the approver's side sees it: the whole question plus
/// the handle it will be answered through.
///
/// Everything [`ApprovalRequest`] carries is here — run, step, summary,
/// artifacts, team, proposer — because the person deciding has exactly what the
/// run's author had, and no more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The adapter's handle for this request, as
    /// [`request`](super::approval::ApprovalChannel::request) returned it.
    /// Opaque to the engine and to a CLI that only shows people.
    pub ticket: Ticket,
    /// The request as it was asked.
    pub request: ApprovalRequest,
}

/// What an approver decided: who, which way, and why.
///
/// Deliberately carries no artifacts. An approver approves *what they were
/// shown*, so the binding is the inbox's to make from the request it already
/// holds, and a caller cannot widen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The identity an adapter established — GitHub OIDC, a `gh` token — never
    /// a name the caller made up.
    pub approver: Identity,
    /// Approved or refused.
    pub outcome: Outcome,
    /// The approver's own words, if they left any.
    pub comment: Option<String>,
}

impl Decision {
    /// A decision with no comment attached.
    pub fn new(approver: Identity, outcome: Outcome) -> Decision {
        Decision { approver, outcome, comment: None }
    }

    /// The same decision with a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Decision {
        self.comment = Some(comment.into());
        self
    }
}

/// The `ApprovalInbox` port: what is waiting for me, and here is my answer.
///
/// The other end of [`ApprovalChannel`](super::approval::ApprovalChannel), and
/// the only way a person answers a parked run.
pub trait ApprovalInbox: Send + Sync {
    /// The requests `approver` may still decide, oldest first.
    ///
    /// Requests `approver` proposed are excluded: a run never appears in its
    /// own author's inbox, so the refusal is not something a well-meaning
    /// adapter has to remember. Membership of the team is **not** filtered
    /// here either — that stays [`Directory`](super::approval::Directory)'s
    /// answer, enforced by the engine when the verdict comes back, so a stale
    /// roster cannot make a run silently unanswerable.
    fn pending<'a>(
        &'a self,
        approver: &'a Identity,
    ) -> BoxFuture<'a, Result<Vec<Pending>, ApprovalError>>;

    /// Records `decision` against the open request for `run`, returning the
    /// [`Verdict`] the run will see.
    ///
    /// The inbox builds the verdict — bound to the request's own
    /// [`artifacts`](ApprovalRequest::artifacts), stamped, and carrying the
    /// comment — and refuses with the very errors
    /// [`accepts`](ApprovalRequest::accepts) would: a proposer answering their
    /// own run is [`ApproverIsProposer`](ApprovalError::ApproverIsProposer) and
    /// a bot is [`ApproverNotHuman`](ApprovalError::ApproverNotHuman), at the
    /// click rather than at the resume. A run with nothing open against it is
    /// [`NoOpenRequest`](ApprovalError::NoOpenRequest), and one already decided
    /// is the same: a second answer would be filed against a run that has moved
    /// on.
    fn decide<'a>(
        &'a self,
        run: &'a RunId,
        decision: Decision,
    ) -> BoxFuture<'a, Result<Verdict, ApprovalError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_approval_inbox_trait_is_dyn_compatible() {
        assert_send_sync::<dyn ApprovalInbox>();
    }

    #[test]
    fn a_decision_carries_who_and_which_way_and_nothing_else() {
        let decision = Decision::new(Identity::human("grace"), Outcome::Refused)
            .with_comment("the plan touches prod");
        assert_eq!(decision.comment.as_deref(), Some("the plan touches prod"));
        assert_eq!(Decision::new(Identity::human("g"), Outcome::Approved).comment, None);
    }
}
