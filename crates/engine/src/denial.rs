//! Settling a parked run: what the channel's answer meant, and why the run stops
//! ([#99](https://github.com/Keep-Shipping/harness/issues/99)).
//!
//! A run parks at an approval and comes back with one of several endings, and each one has to be
//! *tellable*: a teammate needs to read why their deploy stopped, an agent needs a code it can
//! branch on so it changes course instead of retrying. The endings are named once, here, as
//! [`Reason`], and [`settle`] is the one place that turns one into the run log. There is no ending
//! that leaves the log saying "still parked", and no "nobody answered, keep waiting": the timeout
//! is the point, because a run that waits forever is a run nobody can prove anything about.
//!
//! Pure decision logic over the ports: no clock, no run state.

use std::time::Duration;

use ks_core::ports::approval::{
    ApprovalChannel, ApprovalError, ApprovalRequest, Directory, DirectoryError, Outcome,
};
use ks_core::ports::run_log::RunLogError;

use crate::journal::Journal;

/// Why a parked run will not go on, or that it may.
///
/// The four endings a run can be *told* about — a refusal, a timeout, a call-off, an answer that
/// does not apply — plus the rules an answer can fail, which are separate because an agent that
/// tried to rubber-stamp its own run needs to be told that specifically rather than "rejected".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// A human said no. `comment` is their own words, if they left any.
    Denied { approver: String, comment: Option<String> },
    /// Nobody answered before the deadline: `after` is the timeout the run was asked with, not a
    /// re-derived one.
    Expired { after: Duration },
    /// The proposer called it off while parked.
    Aborted { proposer: String },
    /// The approver is the actor that proposed the run, who can never approve it
    /// ([`ApprovalError::ApproverIsProposer`]).
    ApproverIsProposer { approver: String },
    /// The approver is a machine, not a person ([`ApprovalError::ApproverNotHuman`]).
    ApproverNotHuman { approver: String },
    /// The verdict is bound to different artifacts than the ones asked about
    /// ([`ApprovalError::ArtifactsChanged`]) — the plan moved after it was approved.
    ArtifactsChanged { detail: String },
    /// The approver is not on the team that was asked ([`ApprovalError::NotOnTeam`]). Not part of
    /// [`ApprovalRequest::accepts`](ks_core::ports::approval::ApprovalRequest::accepts): membership
    /// is the roster's answer, and it is checked here, every time.
    NotOnTeam { approver: String, team: String },
    /// An answer was refused by a rule that has no code of its own yet. Kept so a rule added to
    /// [`ApprovalRequest::accepts`](ks_core::ports::approval::ApprovalRequest::accepts) without a
    /// `Reason` beside it is reported rather than dropped.
    Rejected { detail: String },
}

impl Reason {
    /// The stable identifier an agent branches on: `"denied"`, `"expired"`, `"aborted"`,
    /// `"approver_is_proposer"`, `"approver_not_human"`, `"artifacts_changed"`, `"not_on_team"` or
    /// `"rejected"`. **A contract, not a label** — these do not change meaning across versions, so
    /// an agent may switch on them; a new ending is a new code, never a new meaning for one of
    /// these. What each means is the variant it names.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Reason::Denied { .. } => "denied",
            Reason::Expired { .. } => "expired",
            Reason::Aborted { .. } => "aborted",
            Reason::ApproverIsProposer { .. } => "approver_is_proposer",
            Reason::ApproverNotHuman { .. } => "approver_not_human",
            Reason::ArtifactsChanged { .. } => "artifacts_changed",
            Reason::NotOnTeam { .. } => "not_on_team",
            Reason::Rejected { .. } => "rejected",
        }
    }

    /// One line for the proposer, always answering the same question: was this a person, the clock,
    /// or us?
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Reason::Denied { approver, comment: Some(comment) } => {
                format!("denied by {approver}: {comment}")
            }
            Reason::Denied { approver, comment: None } => format!("denied by {approver}"),
            Reason::Expired { after } => format!(
                "nobody answered within {}; ask again, or raise the timeout",
                elapsed(*after)
            ),
            Reason::Aborted { proposer } => format!("called off by {proposer}"),
            Reason::ApproverIsProposer { approver } => format!(
                "{approver} proposed this run and cannot approve it; ask another member of the team"
            ),
            Reason::ApproverNotHuman { approver } => {
                format!("{approver} is not a human, so it cannot approve a run; ask a person")
            }
            // `detail` is the port's own sentence, which already leads with this
            // — prefixing it again printed the same clause twice.
            Reason::ArtifactsChanged { detail } => detail.clone(),
            Reason::NotOnTeam { approver, team } => {
                format!("{approver} is not a member of {team}; ask a member of {team}")
            }
            Reason::Rejected { detail } => format!("the answer does not apply: {detail}"),
        }
    }

    /// The rule `accepts` refused, as a code.
    fn unbound(error: &ApprovalError) -> Reason {
        match error {
            ApprovalError::ApproverIsProposer { approver } => {
                Reason::ApproverIsProposer { approver: approver.clone() }
            }
            ApprovalError::ApproverNotHuman { approver } => {
                Reason::ApproverNotHuman { approver: approver.clone() }
            }
            ApprovalError::ArtifactsChanged { .. } => {
                Reason::ArtifactsChanged { detail: error.to_string() }
            }
            other => Reason::Rejected { detail: other.to_string() },
        }
    }
}

/// A duration the way a person reads it: whole seconds, and milliseconds below one — a 500ms
/// deadline that rendered as `0s` would say the run waited no time at all.
fn elapsed(after: Duration) -> String {
    if after.as_secs() == 0 {
        format!("{}ms", after.as_millis())
    } else {
        format!("{}s", after.as_secs())
    }
}

/// What the channel's answer meant for the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// A verdict the request accepted *and* whose approver the directory says is on the team that
    /// was asked — both checks, because either alone would release a run nobody may release.
    Granted { by: String },
    /// Anything else. The run stops, and this is why.
    Refused(Reason),
}

impl Resolution {
    /// Whether the step may go on: a verdict bound to exactly the artifacts asked about, from a
    /// human who is neither the proposer nor off the team, before the deadline.
    #[must_use]
    pub fn is_granted(&self) -> bool {
        matches!(self, Resolution::Granted { .. })
    }

    /// The reason, when refused. `None` when granted.
    #[must_use]
    pub fn reason(&self) -> Option<&Reason> {
        match self {
            Resolution::Granted { .. } => None,
            Resolution::Refused(reason) => Some(reason),
        }
    }
}

/// Asks the channel once and settles the run. A channel that has not answered by `after` is
/// [`Reason::Expired`], never an indefinite wait — the point of the timeout is that the run ends
/// either way.
///
/// Both halves of the approval contract are checked here, in this order, because the port splits
/// them: [`ApprovalRequest::accepts`] binds the verdict to the artifacts and keeps the run from
/// approving itself, and the [`Directory`] answers whether that approver is on the team that was
/// asked ([`ApprovalError::NotOnTeam`] otherwise). An adapter cannot be trusted to make either
/// check itself, which is the same reason the engine makes them once, here.
///
/// The `Err` case is the one that is *not* a decision. What failed for an infrastructure reason —
/// an unreachable forge, a lost permission, a roster that would not answer — propagates unchanged:
/// the run has not been told no and has not run out of time, and pretending otherwise would log a
/// refusal nobody gave.
pub async fn decide(
    channel: &dyn ApprovalChannel,
    directory: &dyn Directory,
    request: &ApprovalRequest,
    after: Duration,
) -> Result<Resolution, ApprovalError> {
    let ticket = channel.request(request).await?;
    let verdict = match channel.wait(&ticket, after).await {
        Ok(verdict) => verdict,
        // Ours is the deadline the caller named, which is what the reason reports.
        Err(ApprovalError::Undecided { .. }) => {
            return Ok(Resolution::Refused(Reason::Expired { after }));
        }
        Err(error) => return Err(error),
    };
    // The binding check runs on *every* verdict, refused ones included: an answer not bound to
    // this request is not an answer, and reporting it as somebody's refusal would put words in the
    // mouth of an approver who never spoke for this run.
    if let Err(error) = request.accepts(&verdict) {
        return Ok(Resolution::Refused(Reason::unbound(&error)));
    }
    let approver = &verdict.approver;
    match directory.is_member(approver, &request.from).await {
        Ok(true) => {}
        Ok(false) => {
            return Ok(Resolution::Refused(Reason::NotOnTeam {
                approver: approver.handle.clone(),
                team: request.from.to_string(),
            }));
        }
        // A roster that cannot be read is not a refusal: nobody was found off the team, the roster
        // itself failed, and the two must not read the same in a run log.
        Err(error) => return Err(roster(error)),
    }
    match verdict.outcome {
        Outcome::Approved => Ok(Resolution::Granted { by: approver.handle.clone() }),
        Outcome::Refused => Ok(Resolution::Refused(Reason::Denied {
            approver: approver.handle.clone(),
            comment: verdict.comment,
        })),
    }
}

/// A roster failure as the approval backend's own failure, so a caller that already handles
/// [`ApprovalError::Unavailable`] handles this without learning about directories.
fn roster(error: DirectoryError) -> ApprovalError {
    ApprovalError::Unavailable { message: error.to_string() }
}

/// The proposer may call off a parked run at any time. This is always allowed and always logged; it
/// is not an error, and it never needed a verdict.
#[must_use]
pub fn aborted(proposer: &str) -> Resolution {
    Resolution::Refused(Reason::Aborted { proposer: proposer.to_string() })
}

/// Writes the ending a resolution earns, through the [`Journal`]'s fail-closed funnel — this is
/// what the run loop calls once [`decide`] has answered, and the one place that decides which
/// event a resolution becomes. **Everything but [`Granted`](Resolution::Granted) ends the run**:
/// the caller must not run another step afterwards. `channel` is the adapter's name, the same one
/// the `approval.requested` event carried, and it is a parameter because the request names the team
/// rather than the adapter it was sent through.
pub async fn settle(
    journal: &Journal,
    request: &ApprovalRequest,
    channel: &str,
    resolution: Resolution,
) -> Result<(), RunLogError> {
    let artifacts: Vec<String> =
        request.artifacts.iter().map(|artifact| artifact.digest.to_string()).collect();
    let step = request.step.as_str();
    match &resolution {
        Resolution::Granted { by } => journal.approval_granted(step, by, channel, artifacts).await,
        Resolution::Refused(reason) => match reason {
            Reason::Denied { approver, .. } => {
                journal.approval_denied(step, approver, channel, artifacts, &reason.message()).await
            }
            Reason::Expired { .. } => journal.approval_expired(step, channel, artifacts).await,
            Reason::Aborted { proposer } => {
                journal.approval_aborted(step, proposer, channel, artifacts).await
            }
            other => {
                let detail = other.message();
                journal.approval_rejected(step, &detail, channel, artifacts).await
            }
        },
    }
}
