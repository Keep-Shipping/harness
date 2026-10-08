//! The approval ports: [`ApprovalChannel`] and [`Directory`]
//! ([#53](https://github.com/Keep-Shipping/harness/issues/53)).
//!
//! The contract is built around one rule, and it has two halves. An approval
//! is bound to the **exact** artifacts it was asked about — a verdict for plan
//! sha256 A must never release plan sha256 B — and a run can never approve
//! itself: the approver must be a human, must not be the actor who proposed
//! the run, and must be on the team that was asked. Both rules are enforced
//! here, in [`ApprovalRequest::accepts`], and not in each adapter: the same
//! engine rule applies whether the approval arrived from a GitHub review, a
//! Slack thread or a local console, and an adapter that re-derived policy for
//! itself would be one more place for it to be wrong.
//!
//! The other half is *membership*, which is the one check an adapter cannot be
//! spared by refusing: [`Directory`] answers it asynchronously ([#42](https://github.com/Keep-Shipping/harness/issues/42),
//! [#121](https://github.com/Keep-Shipping/harness/issues/121)) because the
//! team roster lives in a forge. So the split is deliberate: a [`Verdict`]
//! carries its own [`bound_artifacts`](Verdict::bound_artifacts) and its own
//! approver, and the synchronous [`accepts`](ApprovalRequest::accepts) check
//! binds them to the request; the asynchronous [`Directory`] lookup says
//! whether that approver is on the team.
//!
//! As in [`supply_chain`](super::supply_chain), a [`Digest`] is *parsed*, never
//! computed: hashing lives in adapters, which is what keeps `ks-core`
//! dependency-free. The conformance kit for adapters (GitHub teams, and the
//! static `.keepshipping/teams` directory, #69) lives in `ks-testing`.

use std::fmt;
use std::time::{Duration, SystemTime};

use super::BoxFuture;
use super::supply_chain::Digest;
use crate::ids::RunId;

/// What an artifact under review is: a plan file, a built image, or something
/// the adapter names itself.
///
/// The kind is metadata; the [`digest`](Artifact::digest) is the identity, and
/// it is what an approval is bound to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArtifactKind {
    /// A saved infrastructure-as-code plan
    /// ([`IacTool`](super::iac::IacTool)).
    PlanFile,
    /// A container image ([`ImageBuilder`](super::supply_chain::ImageBuilder)).
    Image,
    /// Anything else, named by the adapter — a release tarball, a lockfile.
    Other(String),
}

/// One exact artifact an approval is about.
///
/// Constructed by the adapter when it asks, and echoed verbatim in the
/// [`Verdict`] that answers; [`ApprovalRequest::accepts`] compares the two
/// lists, so an approval that names a different digest releases nothing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Artifact {
    /// What sort of artifact this is.
    pub kind: ArtifactKind,
    /// The artifact's content digest, as the producing adapter computed it.
    pub digest: Digest,
}

impl Artifact {
    /// An artifact of `kind` with the given `digest`.
    pub fn new(kind: ArtifactKind, digest: Digest) -> Artifact {
        Artifact { kind, digest }
    }
}

/// The artifacts' digests as printable strings, so a mismatch names the two
/// plans rather than dumping two structs into an error message.
fn digest_labels(artifacts: &[Artifact]) -> Vec<String> {
    artifacts.iter().map(|artifact| artifact.digest.to_string()).collect()
}

/// A team the run asked for approval from, e.g. `@platform`.
///
/// A private-field type because the `@` is load-bearing: a [`Team`] is always
/// displayed, logged and serialized with it, and a handle without one is not a
/// team name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Team(String);

impl Team {
    /// Parses a team handle written `@platform`.
    ///
    /// The leading `@` is required and the remainder must be non-empty
    /// ASCII alphanumerics, `-` or `_`; anything else is
    /// [`ApprovalError::MalformedTeam`], so a typo or a near-miss of another
    /// team's name fails here rather than approving against the wrong roster.
    pub fn parse(team: &str) -> Result<Team, ApprovalError> {
        let Some(handle) = team.strip_prefix('@') else {
            return Err(ApprovalError::MalformedTeam { team: team.to_string() });
        };
        let is_handle = !handle.is_empty()
            && handle
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        if !is_handle {
            return Err(ApprovalError::MalformedTeam { team: team.to_string() });
        }
        Ok(Team(handle.to_string()))
    }

    /// The handle without its `@`, e.g. `platform`.
    pub fn handle(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Team {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.0)
    }
}

/// What sort of thing answered: a person, or a machine acting for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityKind {
    /// A person. Only a human may approve a run
    /// ([`ApprovalError::ApproverNotHuman`]).
    Human,
    /// A bot, a workflow, or a bot acting on a human's behalf.
    Service,
}

/// Who answered an approval request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identity {
    /// The adapter's handle for the answerer, e.g. `ada` or `github-actions`.
    pub handle: String,
    /// Whether the handle belongs to a person or to a machine.
    pub kind: IdentityKind,
}

impl Identity {
    /// A human identity with this handle.
    pub fn human(handle: impl Into<String>) -> Identity {
        Identity { handle: handle.into(), kind: IdentityKind::Human }
    }

    /// A service identity with this handle.
    pub fn service(handle: impl Into<String>) -> Identity {
        Identity { handle: handle.into(), kind: IdentityKind::Service }
    }

    /// Whether this identity may approve a run at all.
    pub fn is_human(&self) -> bool {
        self.kind == IdentityKind::Human
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.handle)
    }
}

/// An adapter-minted handle for one outstanding approval request.
///
/// Opaque to the engine on purpose: the adapter mints it and the engine only
/// passes it back to [`poll`](ApprovalChannel::poll) and
/// [`wait`](ApprovalChannel::wait), so a PR number, a Slack thread timestamp
/// or an internal queue id all fit without the port learning about any of them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ticket(String);

impl Ticket {
    /// A ticket under the adapter's own id scheme.
    pub fn new(id: impl Into<String>) -> Ticket {
        Ticket(id.into())
    }

    /// The adapter's id, as issued.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A request for a human to approve one run's step.
///
/// The request is the *question*: which run, which step, which exact
/// artifacts, which team, and who proposed it. Everything an approver needs to
/// judge is here, and everything a later [`Verdict`] is checked against is
/// here too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// The run being approved — the same id every adapter mints for the run,
    /// so an approval can be filed against it.
    pub run: RunId,
    /// The step within that run that is blocked, e.g. `apply-infra`.
    pub step: String,
    /// What the approver is being asked to approve, in prose — the rendered
    /// diff summary, the plan's resource count, whatever the caller wants a
    /// person to read.
    pub summary: String,
    /// The exact artifacts under review, in order. The list an approver is
    /// shown *is* the list an answer is bound to.
    pub artifacts: Vec<Artifact>,
    /// The team whose members may answer.
    pub from: Team,
    /// Why approval is needed at all, e.g. `production deploy`.
    pub reason: String,
    /// The identity that proposed this run. It can never approve it.
    pub proposed_by: Identity,
}

impl ApprovalRequest {
    /// Whether `verdict` may release this request — **the** binding check.
    ///
    /// In order:
    ///
    /// 1. the approver must not be [`proposed_by`](Self::proposed_by) — a run
    ///    never approves itself ([`ApprovalError::ApproverIsProposer`]);
    /// 2. the approver must be a human
    ///    ([`ApprovalError::ApproverNotHuman`]);
    /// 3. the verdict must be bound to exactly the
    ///    [`artifacts`](Self::artifacts) that were asked about
    ///    ([`ApprovalError::ArtifactsChanged`]).
    ///
    /// This is what the engine checks at resume
    /// ([#42](https://github.com/Keep-Shipping/harness/issues/42),
    /// [#121](https://github.com/Keep-Shipping/harness/issues/121)) before it
    /// unblocks a step. Team membership is *not* checked here: it is a
    /// separate asynchronous [`Directory::is_member`] lookup, so a verdict
    /// that passes this check still needs the roster to say yes.
    pub fn accepts(&self, verdict: &Verdict) -> Result<(), ApprovalError> {
        if verdict.approver == self.proposed_by {
            return Err(ApprovalError::ApproverIsProposer {
                approver: verdict.approver.handle.clone(),
            });
        }
        if !verdict.approver.is_human() {
            return Err(ApprovalError::ApproverNotHuman {
                approver: verdict.approver.handle.clone(),
            });
        }
        if verdict.bound_artifacts != self.artifacts {
            return Err(ApprovalError::ArtifactsChanged {
                approved: digest_labels(&verdict.bound_artifacts),
                requested: digest_labels(&self.artifacts),
            });
        }
        Ok(())
    }
}

/// How an approver answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// Approved, bound to the artifacts that were shown.
    Approved,
    /// Refused, with a comment explaining why.
    Refused,
}

/// One answer to an [`ApprovalRequest`].
///
/// The binding is the point: `bound_artifacts` is what the approver was
/// looking at, and [`ApprovalRequest::accepts`] refuses a verdict whose list
/// differs by one digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Who answered.
    pub approver: Identity,
    /// When they answered (adapter-supplied; the engine does not read a clock).
    pub at: SystemTime,
    /// Whether they approved or refused.
    pub outcome: Outcome,
    /// The approver's free-text comment, if they left one.
    pub comment: Option<String>,
    /// The artifacts the answer is bound to — the request's own
    /// [`artifacts`](ApprovalRequest::artifacts), verbatim.
    pub bound_artifacts: Vec<Artifact>,
}

impl Verdict {
    /// A verdict approving or refusing, bound to exactly `bound_artifacts`.
    pub fn new(
        approver: Identity,
        at: SystemTime,
        outcome: Outcome,
        bound_artifacts: Vec<Artifact>,
    ) -> Verdict {
        Verdict { approver, at, outcome, comment: None, bound_artifacts }
    }

    /// The same verdict with a comment attached.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Verdict {
        self.comment = Some(comment.into());
        self
    }

    /// Whether this verdict approves (as opposed to refuses).
    pub fn is_approved(&self) -> bool {
        self.outcome == Outcome::Approved
    }
}

/// Why an approval could not be asked for, answered, or honoured.
///
/// Every variant names what went wrong *and* what to do next, because these
/// messages reach a person deciding whether to unblock a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    /// A team handle was not `@name`.
    MalformedTeam {
        /// The rejected text, exactly as written.
        team: String,
    },
    /// The approver is the actor that proposed the run; a run never approves
    /// itself.
    ApproverIsProposer {
        /// The handle that both proposed and approved.
        approver: String,
    },
    /// The approver is a service, not a person.
    ApproverNotHuman {
        /// The handle that tried to answer.
        approver: String,
    },
    /// The approver is not on the team that was asked.
    NotOnTeam {
        /// The handle that tried to answer.
        approver: String,
        /// The team whose membership was required.
        team: Team,
    },
    /// The verdict is bound to different artifacts than the ones asked about.
    ArtifactsChanged {
        /// The digests the verdict was bound to.
        approved: Vec<String>,
        /// The digests the request asked about.
        requested: Vec<String>,
    },
    /// No one answered within the timeout.
    Undecided {
        /// The ticket that was still outstanding.
        ticket: String,
        /// How long the caller waited.
        after: Duration,
    },
    /// The ticket was never issued by this channel, so no answer to it can
    /// mean anything.
    UnknownTicket {
        /// The ticket that was asked about, exactly as it was passed in.
        ticket: String,
    },
    /// Nothing is open against this run: it is not parked, it never asked,
    /// or it has already been answered. A second answer is filed against a
    /// run that has moved on, so it is refused rather than recorded.
    NoOpenRequest {
        /// The run that has nothing waiting.
        run: String,
    },
    /// The approval backend itself failed (forge unreachable, no permission…).
    Unavailable {
        /// What went wrong, safe to print.
        message: String,
    },
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalError::MalformedTeam { team } => write!(
                f,
                "{team:?} is not a team handle; a team is written `@name`, e.g. `@platform`"
            ),
            ApprovalError::ApproverIsProposer { approver } => write!(
                f,
                "{approver} proposed this run and cannot approve it; ask another member of the \
                 team that was asked"
            ),
            ApprovalError::ApproverNotHuman { approver } => write!(
                f,
                "{approver} is not a human, so it cannot approve a run; ask a person on the \
                 team that was asked"
            ),
            ApprovalError::NotOnTeam { approver, team } => {
                write!(f, "{approver} is not a member of {team}; ask a member of {team}")
            }
            ApprovalError::ArtifactsChanged { approved, requested } => {
                write!(
                    f,
                    "the artifacts changed after they were approved: approved [{}], asked about \
                     [{}]; ask again on the current artifacts",
                    approved.join(", "),
                    requested.join(", ")
                )
            }
            ApprovalError::Undecided { ticket, after } => write!(
                f,
                "no one answered approval ticket {ticket} within {}s; ask again, or raise the \
                 timeout",
                after.as_secs()
            ),
            ApprovalError::UnknownTicket { ticket } => write!(
                f,
                "no approval ticket {ticket} was ever issued; keep the ticket `request` returned and \
                 pass that one to poll or wait"
            ),
            ApprovalError::NoOpenRequest { run } => write!(
                f,
                "there is nothing waiting for approval on run {run}; list what is pending, and only \
                 answer a run that is still open"
            ),
            ApprovalError::Unavailable { message } => {
                write!(f, "the approval backend is unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for ApprovalError {}

/// Why a [`Directory`] lookup failed.
///
/// A team with no members is *not* an error: it is an empty answer, so a
/// workflow that names a team nobody is in fails with
/// [`NotOnTeam`](ApprovalError::NotOnTeam) rather than a lookup failure that
/// would read like the forge is broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    /// The directory backend itself failed (API down, auth rejected…).
    Unavailable {
        /// What went wrong, safe to print.
        message: String,
    },
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DirectoryError::Unavailable { message } => {
                write!(f, "the team directory is unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for DirectoryError {}

/// The `Directory` port: who is on a team.
///
/// The engine calls [`is_member`](Directory::is_member) for every [`Verdict`]
/// before honouring it, so a verdict from a human who left the team an hour
/// ago releases nothing. Adapters back this with whatever roster they have —
/// GitHub team membership, a static `.keepshipping/teams` file — and resolve
/// `@platform`-style aliases to concrete identities themselves: the port only
/// ever asks about a handle the caller already has.
pub trait Directory: Send + Sync {
    /// Every member of `team`.
    ///
    /// Sorted by handle and de-duplicated: the order and uniqueness are the
    /// adapter's job, so the engine can render "ask any of these" without
    /// sorting or deduping itself, and two adapters never disagree about who
    /// is on a team. An unknown team is an empty list, never an error.
    fn members<'a>(
        &'a self,
        team: &'a Team,
    ) -> BoxFuture<'a, Result<Vec<Identity>, DirectoryError>>;

    /// Whether `identity` is a member of `team`.
    ///
    /// This is the check the engine makes for every [`Verdict`] before it
    /// honours one; `Ok(false)` for an unknown team, so a missing roster reads
    /// as "not a member" rather than as a backend failure.
    fn is_member<'a>(
        &'a self,
        identity: &'a Identity,
        team: &'a Team,
    ) -> BoxFuture<'a, Result<bool, DirectoryError>>;
}

/// The `ApprovalChannel` port: ask a team, and hear back.
///
/// The adapter's one binding obligation is to record the request's
/// [`artifacts`](ApprovalRequest::artifacts) verbatim and return them as the
/// verdict's [`bound_artifacts`](Verdict::bound_artifacts) — an adapter that
/// mints a verdict unbound, or that "helpfully" re-digests what it is
/// approving, is exactly the failure the conformance kit catches. What the
/// adapter must *not* do is consult membership: that is
/// [`ApprovalRequest::accepts`]'s and [`Directory`]'s rule, enforced once by
/// the engine so that it holds identically for every adapter.
pub trait ApprovalChannel: Send + Sync {
    /// Asks `request`'s team to approve, returning a ticket to poll.
    ///
    /// Sending the request is not approving it: nothing has happened to the
    /// run until a [`Verdict`] that passes
    /// [`accepts`](ApprovalRequest::accepts) and
    /// [`is_member`](Directory::is_member) arrives.
    fn request<'a>(
        &'a self,
        request: &'a ApprovalRequest,
    ) -> BoxFuture<'a, Result<Ticket, ApprovalError>>;

    /// The answer so far, if there is one: `Ok(None)` means nobody has
    /// answered yet, which is not an error and not a refusal — it is the
    /// normal state of a ticket nobody has looked at.
    ///
    /// A ticket this channel never issued is
    /// [`ApprovalError::UnknownTicket`], never a scripted answer: an adapter
    /// that answered a fabricated ticket would be reporting an approval nobody
    /// gave.
    fn poll<'a>(
        &'a self,
        ticket: &'a Ticket,
    ) -> BoxFuture<'a, Result<Option<Verdict>, ApprovalError>>;

    /// The answer, waiting up to `timeout` for one.
    ///
    /// `Ok(None)` is not available here: `wait` either returns a verdict or
    /// fails with [`ApprovalError::Undecided`] once `timeout` elapses, so the
    /// caller never mistakes a patient wait for an answer. A ticket this
    /// channel never issued is [`ApprovalError::UnknownTicket`].
    fn wait<'a>(
        &'a self,
        ticket: &'a Ticket,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Verdict, ApprovalError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    fn plan(hex: char) -> Artifact {
        Artifact::new(
            ArtifactKind::PlanFile,
            Digest::sha256_from_hex(&hex.to_string().repeat(64)).expect("64 hex digits"),
        )
    }

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            run: RunId::from_parts(1_700_000_000_000, 1),
            step: "apply-infra".to_string(),
            summary: "3 to create, 1 to destroy".to_string(),
            artifacts: vec![plan('a')],
            from: Team::parse("@platform").expect("a well-formed handle"),
            reason: "production deploy".to_string(),
            proposed_by: Identity::human("ada"),
        }
    }

    #[test]
    fn the_approval_channel_trait_is_dyn_compatible() {
        assert_send_sync::<dyn ApprovalChannel>();
    }

    #[test]
    fn the_directory_trait_is_dyn_compatible() {
        assert_send_sync::<dyn Directory>();
    }

    #[test]
    fn team_handles_require_an_at_sign_and_a_simple_name() {
        let team = Team::parse("@platform").expect("@platform is a team handle");
        assert_eq!(team.handle(), "platform");
        for bad in ["", "platform", "@", "@plat form"] {
            assert!(
                matches!(Team::parse(bad), Err(ApprovalError::MalformedTeam { .. })),
                "{bad:?} must not parse as a team"
            );
        }
    }

    #[test]
    fn teams_display_with_their_at_sign() {
        assert_eq!(Team::parse("@platform").expect("valid").to_string(), "@platform");
    }

    #[test]
    fn only_a_human_identity_can_approve() {
        assert!(Identity::human("ada").is_human());
        assert!(!Identity::service("github-actions").is_human());
        assert_eq!(Identity::human("ada").kind, IdentityKind::Human);
    }

    #[test]
    fn a_verdict_is_accepted_only_for_the_artifacts_it_was_bound_to() {
        let request = request();
        let verdict = Verdict::new(
            Identity::human("grace"),
            SystemTime::UNIX_EPOCH,
            Outcome::Approved,
            request.artifacts.clone(),
        );
        assert_eq!(request.accepts(&verdict), Ok(()));

        // The same verdict, asked about a different plan.
        let mut moved = request.clone();
        moved.artifacts = vec![plan('b')];
        assert!(matches!(moved.accepts(&verdict), Err(ApprovalError::ArtifactsChanged { .. })));
    }

    #[test]
    fn a_run_cannot_approve_itself() {
        let request = request();
        let verdict = Verdict::new(
            request.proposed_by.clone(),
            SystemTime::UNIX_EPOCH,
            Outcome::Approved,
            request.artifacts.clone(),
        );
        assert!(matches!(request.accepts(&verdict), Err(ApprovalError::ApproverIsProposer { .. })));
    }

    #[test]
    fn approval_errors_display_actionably() {
        let proposer =
            ApprovalError::ApproverIsProposer { approver: "ada".to_string() }.to_string();
        assert!(
            proposer.contains("ada")
                && proposer.contains("cannot approve it")
                && proposer.contains("ask another member"),
            "{proposer}"
        );

        let bot =
            ApprovalError::ApproverNotHuman { approver: "github-actions".to_string() }.to_string();
        assert!(bot.contains("github-actions") && bot.contains("not a human"), "{bot}");

        let off_team = ApprovalError::NotOnTeam {
            approver: "mallory".to_string(),
            team: Team::parse("@platform").expect("valid"),
        }
        .to_string();
        assert!(
            off_team.contains("mallory")
                && off_team.contains("@platform")
                && off_team.contains("not a member"),
            "{off_team}"
        );

        let changed = ApprovalError::ArtifactsChanged {
            approved: vec![format!("sha256:{}", "a".repeat(64))],
            requested: vec![format!("sha256:{}", "b".repeat(64))],
        }
        .to_string();
        assert!(
            changed.contains("artifacts changed")
                && changed.contains("ask again")
                && changed.contains('b'),
            "{changed}"
        );

        let undecided =
            ApprovalError::Undecided { ticket: "t-1".to_string(), after: Duration::from_secs(30) }
                .to_string();
        assert!(undecided.contains("t-1") && undecided.contains("30s"), "{undecided}");

        let unknown = ApprovalError::UnknownTicket { ticket: "t-9999".to_string() }.to_string();
        assert!(
            unknown.contains("t-9999") && unknown.contains("`request` returned"),
            "an unknown ticket must name the ticket and the one to keep: {unknown}"
        );

        let nothing_open = ApprovalError::NoOpenRequest { run: "run-42".to_string() }.to_string();
        assert!(
            nothing_open.contains("run-42") && nothing_open.contains("nothing waiting"),
            "a run with nothing open must name the run: {nothing_open}"
        );
    }
}
