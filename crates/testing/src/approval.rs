//! Fakes for the approval ports: a scripted [`FakeApprovalChannel`] that mints
//! tickets and serves verdicts, a [`FakeDirectory`] with a static roster, and
//! the conformance kit both share. Never touches the filesystem or network.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::approval::{
    ApprovalChannel, ApprovalError, ApprovalRequest, Artifact, ArtifactKind, Directory,
    DirectoryError, Identity, Outcome, Team, Ticket, Verdict,
};
use ks_core::ports::supply_chain::Digest;

/// One call a test can observe on the [`FakeApprovalChannel`], oldest first via
/// [`FakeApprovalChannel::calls`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalCall {
    /// [`ApprovalChannel::request`] asked a team about these artifacts.
    Request {
        /// The step within the run that was blocked.
        step: String,
        /// The exact artifacts the request was bound to, as the fake recorded
        /// them — what a later verdict has to come back bound to.
        artifacts: Vec<Artifact>,
        /// The team that was asked.
        from: Team,
    },
}

/// The channel fake's mutable state; every accessor goes through one mutex, so
/// the fake is `Send + Sync` and [`FakeApprovalChannel::approving`] works on
/// `&self`.
#[derive(Default)]
struct State {
    /// How many tickets `request` has minted (names them).
    tickets: u64,
    /// The tickets `request` actually issued, so `poll` and `wait` can refuse
    /// one the fake never minted instead of serving a scripted verdict for it.
    minted: BTreeSet<String>,
    /// Scripted verdicts, in order; the last entry repeats.
    queue: VecDeque<Verdict>,
    /// Every call, oldest first.
    calls: Vec<ApprovalCall>,
}

/// The directory fake's mutable state: team handle -> roster, in insertion
/// order (`with_member` sorts on read instead).
#[derive(Default)]
struct Roster {
    teams: BTreeMap<String, Vec<Identity>>,
    calls: usize,
}

/// An [`ApprovalChannel`] you script per test — the stand-in for the real
/// GitHub and static-directory adapters.
///
/// [`with_verdict`](FakeApprovalChannel::with_verdict) queues the verdicts
/// `poll` and `wait` serve (the last one repeats), and
/// [`approving`](FakeApprovalChannel::approving) queues a *correctly bound*
/// approval for a given request. Tickets are minted `t-1`, `t-2`, … in the
/// order they were asked for.
///
/// With nothing scripted the fake answers exactly as the contract says it
/// must: `poll` is `Ok(None)` (nobody has answered) and `wait` is
/// [`ApprovalError::Undecided`]. It never invents an approval, and it never
/// returns a verdict whose binding it did not script. Only tickets `request`
/// actually minted can be polled or waited on; anything else is
/// [`ApprovalError::UnknownTicket`], so a test that loses its ticket and
/// fabricates one is caught rather than answered.
///
/// ```
/// use ks_core::ids::RunId;
/// use ks_core::ports::approval::{ApprovalChannel, ApprovalRequest, Identity, Team, Ticket};
/// use ks_core::ports::supply_chain::Digest;
/// use ks_testing::{approval::FakeApprovalChannel, block_on};
///
/// let request = ApprovalRequest {
///     run: RunId::from_parts(0, 1),
///     step: "apply-infra".to_string(),
///     summary: "1 to create".to_string(),
///     artifacts: vec![],
///     from: Team::parse("@platform").expect("valid"),
///     reason: "production deploy".to_string(),
///     proposed_by: Identity::human("ada"),
/// };
/// let channel = FakeApprovalChannel::new();
/// channel.approving(Identity::human("grace"), &request);
///
/// let ticket: Ticket = block_on(channel.request(&request)).expect("the request is accepted");
/// assert_eq!(ticket.as_str(), "t-1");
/// assert!(request.accepts(&block_on(channel.poll(&ticket)).expect("a verdict").as_ref().unwrap())
///     .is_ok());
/// ```
///
/// All mutable state sits behind one mutex, so the fake is `Send + Sync` and
/// `approving` works on `&self`.
pub struct FakeApprovalChannel {
    state: Mutex<State>,
}

impl Default for FakeApprovalChannel {
    fn default() -> FakeApprovalChannel {
        FakeApprovalChannel { state: Mutex::new(State::default()) }
    }
}

impl FakeApprovalChannel {
    /// A fake that answers nobody, until scripted.
    pub fn new() -> FakeApprovalChannel {
        FakeApprovalChannel::default()
    }

    /// Queues a verdict as the next answer `poll` and `wait` serve; the last
    /// queued verdict repeats, so any number of polls succeed.
    pub fn with_verdict(self, verdict: Verdict) -> FakeApprovalChannel {
        self.state.lock().expect("fake approval state").queue.push_back(verdict);
        self
    }

    /// Scripts an approval by `approver` bound to exactly `request`'s
    /// artifacts — a correct verdict by construction, so a test only has to
    /// say *who* approved, never *what*. The verdict's
    /// [`approver`](Verdict::approver) is `approver` itself, which is what
    /// the conformance kit checks the answer against.
    pub fn approving(&self, approver: Identity, request: &ApprovalRequest) {
        let verdict = Verdict::new(
            approver,
            SystemTime::UNIX_EPOCH,
            Outcome::Approved,
            request.artifacts.clone(),
        );
        self.state.lock().expect("fake approval state").queue.push_back(verdict);
    }

    /// Every call made against the fake, oldest first.
    pub fn calls(&self) -> Vec<ApprovalCall> {
        self.state.lock().expect("fake approval state").calls.clone()
    }

    /// Whether `request` actually minted `ticket`; otherwise the one error
    /// that must never be answered with a scripted verdict.
    fn known_ticket(state: &State, ticket: &Ticket) -> Result<(), ApprovalError> {
        if state.minted.contains(ticket.as_str()) {
            Ok(())
        } else {
            Err(ApprovalError::UnknownTicket { ticket: ticket.as_str().to_string() })
        }
    }

    /// The next scripted verdict, popping it — or repeating the last one once
    /// the queue holds a single entry.
    fn next_verdict(state: &mut State) -> Option<Verdict> {
        match state.queue.len() {
            0 => None,
            1 => Some(state.queue.front().expect("queue is non-empty").clone()),
            _ => state.queue.pop_front(),
        }
    }
}

impl fmt::Debug for FakeApprovalChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().expect("fake approval state");
        f.debug_struct("FakeApprovalChannel")
            .field("tickets", &state.tickets)
            .field("scripted", &state.queue.len())
            .field("calls", &state.calls.len())
            .finish()
    }
}

impl ApprovalChannel for FakeApprovalChannel {
    fn request<'a>(
        &'a self,
        request: &'a ApprovalRequest,
    ) -> BoxFuture<'a, Result<Ticket, ApprovalError>> {
        let result = {
            let mut state = self.state.lock().expect("fake approval state");
            state.tickets += 1;
            let ticket = format!("t-{}", state.tickets);
            state.minted.insert(ticket.clone());
            state.calls.push(ApprovalCall::Request {
                step: request.step.clone(),
                artifacts: request.artifacts.clone(),
                from: request.from.clone(),
            });
            Ok(Ticket::new(ticket))
        };
        Box::pin(std::future::ready(result))
    }

    fn poll<'a>(
        &'a self,
        ticket: &'a Ticket,
    ) -> BoxFuture<'a, Result<Option<Verdict>, ApprovalError>> {
        // Nobody having answered yet is the normal state, not a failure; a
        // ticket the fake never minted is neither — nothing can answer it.
        let result = {
            let mut state = self.state.lock().expect("fake approval state");
            match Self::known_ticket(&state, ticket) {
                Ok(()) => Ok(Self::next_verdict(&mut state)),
                Err(error) => Err(error),
            }
        };
        Box::pin(std::future::ready(result))
    }

    fn wait<'a>(
        &'a self,
        ticket: &'a Ticket,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Verdict, ApprovalError>> {
        let result = {
            let mut state = self.state.lock().expect("fake approval state");
            match Self::known_ticket(&state, ticket) {
                Err(error) => Err(error),
                Ok(()) => match Self::next_verdict(&mut state) {
                    Some(verdict) => Ok(verdict),
                    None => Err(ApprovalError::Undecided {
                        ticket: ticket.as_str().to_string(),
                        after: timeout,
                    }),
                },
            }
        };
        Box::pin(std::future::ready(result))
    }
}

/// A [`Directory`] with a static roster — the stand-in for GitHub team
/// membership and a checked-in `.keepshipping/teams` file.
///
/// ```
/// use ks_core::ports::approval::{Directory, Identity, Team};
/// use ks_testing::approval::FakeDirectory;
/// use ks_testing::block_on;
///
/// let team = Team::parse("@platform").expect("valid");
/// let directory =
///     FakeDirectory::new().with_member(&team, Identity::human("ada"));
/// assert!(block_on(directory.is_member(&Identity::human("ada"), &team)).expect("answered"));
/// // A team nobody is in is an empty answer, never an error.
/// assert!(block_on(directory.members(&Team::parse("@nobody").expect("valid")))
///     .expect("answered")
///     .is_empty());
/// ```
///
/// All mutable state sits behind one mutex, so the fake is `Send + Sync`.
pub struct FakeDirectory {
    state: Mutex<Roster>,
}

impl Default for FakeDirectory {
    fn default() -> FakeDirectory {
        FakeDirectory { state: Mutex::new(Roster::default()) }
    }
}

impl FakeDirectory {
    /// A fake with no teams at all, until scripted.
    pub fn new() -> FakeDirectory {
        FakeDirectory::default()
    }

    /// Adds one member to a team; repeatable, and the same identity added
    /// twice is one member.
    pub fn with_member(self, team: &Team, identity: Identity) -> FakeDirectory {
        {
            let mut roster = self.state.lock().expect("fake roster");
            let members = roster.teams.entry(team.handle().to_string()).or_default();
            if !members.contains(&identity) {
                members.push(identity);
            }
        }
        self
    }

    /// How many lookups have been made against the fake.
    pub fn lookups(&self) -> usize {
        self.state.lock().expect("fake roster").calls
    }
}

impl fmt::Debug for FakeDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let roster = self.state.lock().expect("fake roster");
        f.debug_struct("FakeDirectory")
            .field("teams", &roster.teams.len())
            .field("lookups", &roster.calls)
            .finish()
    }
}

impl Directory for FakeDirectory {
    fn members<'a>(
        &'a self,
        team: &'a Team,
    ) -> BoxFuture<'a, Result<Vec<Identity>, DirectoryError>> {
        // An unknown team has no members; that is an answer, not a failure.
        let result = {
            let mut state = self.state.lock().expect("fake roster");
            state.calls += 1;
            let mut members = state.teams.get(team.handle()).cloned().unwrap_or_default();
            members.sort_by(|left, right| left.handle.cmp(&right.handle));
            Ok(members)
        };
        Box::pin(std::future::ready(result))
    }

    fn is_member<'a>(
        &'a self,
        identity: &'a Identity,
        team: &'a Team,
    ) -> BoxFuture<'a, Result<bool, DirectoryError>> {
        let result = {
            let mut state = self.state.lock().expect("fake roster");
            state.calls += 1;
            Ok(state.teams.get(team.handle()).is_some_and(|members| members.contains(identity)))
        };
        Box::pin(std::future::ready(result))
    }
}

/// The approval conformance kit: every adapter — the fakes here, real GitHub
/// teams, and the static `.keepshipping/teams` directory — must pass this.
///
/// It walks the two rules the ports exist to enforce, in order. The channel
/// returns a ticket, hands back a verdict, and that verdict is bound to
/// exactly the artifacts that were asked about
/// ([`accepts`](ApprovalRequest::accepts) is `Ok`) — *an adapter that drops the
/// binding, re-digests what it is approving, or mints a verdict unbound fails
/// right here* — and the verdict is **the approver's own**: its
/// [`approver`](Verdict::approver) is the identity the caller named, and the
/// roster says that very approver is on the team, so an adapter that answers
/// with somebody else's verdict fails here too. The directory answers
/// membership sorted, positively for that approver and negatively for a
/// stranger.
pub async fn conformance(
    channel: &dyn ApprovalChannel,
    directory: &dyn Directory,
    team: &Team,
    approver: &Identity,
) {
    let request = ApprovalRequest {
        run: RunId::from_parts(1_700_000_000_000, 1),
        step: "conformance-apply".to_string(),
        summary: "1 to create".to_string(),
        artifacts: vec![Artifact::new(
            ArtifactKind::PlanFile,
            Digest::sha256_from_hex(&"a".repeat(64))
                .expect("64 hex digits is a well-formed sha256"),
        )],
        from: team.clone(),
        reason: "conformance".to_string(),
        // Somebody other than the approver: a run never approves itself.
        proposed_by: Identity::human("conformance-proposer"),
    };

    let ticket = channel
        .request(&request)
        .await
        .unwrap_or_else(|error| panic!("conformance: the request must be accepted: {error}"));
    assert!(!ticket.as_str().is_empty(), "conformance: the ticket must have an id");

    let members = directory
        .members(team)
        .await
        .unwrap_or_else(|error| panic!("conformance: the roster must be readable: {error}"));
    let mut sorted = members.clone();
    sorted.sort_by(|left, right| left.handle.cmp(&right.handle));
    assert_eq!(members, sorted, "conformance: Directory::members must be sorted by handle");

    assert!(
        directory
            .is_member(approver, team)
            .await
            .unwrap_or_else(|error| panic!("conformance: membership must be answerable: {error}")),
        "conformance: {approver} must be a member of {team}"
    );

    let stranger = Identity::human("conformance-stranger");
    assert!(
        !directory
            .is_member(&stranger, team)
            .await
            .unwrap_or_else(|error| panic!("conformance: membership must be answerable: {error}")),
        "conformance: a stranger must not be a member of {team}"
    );

    let verdict = channel
        .wait(&ticket, Duration::from_secs(30))
        .await
        .unwrap_or_else(|error| panic!("conformance: the scripted approval must arrive: {error}"));
    request.accepts(&verdict).unwrap_or_else(|error| {
        panic!("conformance: the verdict must be bound to the artifacts asked about: {error}")
    });

    // The verdict must be *that reviewer's* verdict, not merely a well-formed
    // one: the engine releases nothing until `Directory` says the answer's own
    // approver is on the team, so an adapter that answers with a stranger's
    // verdict would ship a green build and an unapproved run.
    assert_eq!(
        verdict.approver, *approver,
        "conformance: the verdict must be the named approver's, not somebody else's"
    );
    assert!(
        directory.is_member(&verdict.approver, team).await.unwrap_or_else(|error| {
            panic!("conformance: the verdict's approver's membership must be answerable: {error}")
        }),
        "conformance: the verdict's own approver {} must be a member of {team}",
        verdict.approver
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    fn team() -> Team {
        Team::parse("@platform").expect("valid")
    }

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            run: RunId::from_parts(1_700_000_000_000, 1),
            step: "apply-infra".to_string(),
            summary: "3 to create".to_string(),
            artifacts: vec![Artifact::new(
                ArtifactKind::PlanFile,
                Digest::sha256_from_hex(&"a".repeat(64)).expect("64 hex digits"),
            )],
            from: team(),
            reason: "production deploy".to_string(),
            proposed_by: Identity::human("ada"),
        }
    }

    #[test]
    fn an_unscripted_channel_answers_nobody() {
        let channel = FakeApprovalChannel::new();
        let ticket = block_on(channel.request(&request())).expect("the request is accepted");
        assert_eq!(ticket.as_str(), "t-1");
        assert_eq!(block_on(channel.poll(&ticket)), Ok(None));
        let waited = block_on(channel.wait(&ticket, Duration::from_secs(30)));
        assert!(
            matches!(waited, Err(ApprovalError::Undecided { .. })),
            "a wait with nobody scripted must be Undecided, got {waited:?}"
        );
    }

    #[test]
    fn the_channel_mints_tickets_in_order_and_records_requests() {
        let channel = FakeApprovalChannel::new();
        let first = block_on(channel.request(&request())).expect("accepted");
        let second = block_on(channel.request(&request())).expect("accepted");
        assert_eq!((first.as_str(), second.as_str()), ("t-1", "t-2"));

        let calls = channel.calls();
        assert_eq!(calls.len(), 2);
        for call in &calls {
            let ApprovalCall::Request { step, artifacts, from } = call;
            assert_eq!(step, "apply-infra");
            assert_eq!(from, &team());
            assert_eq!(artifacts, &request().artifacts);
        }
    }

    #[test]
    fn a_ticket_the_fake_never_minted_is_never_answered() {
        let channel = FakeApprovalChannel::new();
        // A verdict *is* scripted, so a fake that ignored the ticket would
        // hand it over — which is exactly the bug this refuses.
        channel.approving(Identity::human("grace"), &request());
        let _real = block_on(channel.request(&request())).expect("the request is accepted");
        let fabricated = Ticket::new("t-9999");

        assert_eq!(
            block_on(channel.poll(&fabricated)),
            Err(ApprovalError::UnknownTicket { ticket: "t-9999".to_string() }),
            "a ticket the fake never minted must not be answered"
        );
        assert_eq!(
            block_on(channel.wait(&fabricated, Duration::from_secs(30))),
            Err(ApprovalError::UnknownTicket { ticket: "t-9999".to_string() }),
            "a ticket the fake never minted must not be waited on"
        );
        // And the error names the ticket and what to do about it.
        let message = ApprovalError::UnknownTicket { ticket: "t-9999".to_string() }.to_string();
        assert!(
            message.contains("t-9999") && message.contains("request"),
            "the message must name the ticket and the ticket to keep: {message}"
        );
    }

    #[test]
    fn the_directory_answers_empty_for_a_team_nobody_is_in() {
        let directory = FakeDirectory::new().with_member(&team(), Identity::human("ada"));
        let unknown = Team::parse("@nobody").expect("valid");
        assert!(block_on(directory.members(&unknown)).expect("answered").is_empty());
        assert!(
            !block_on(directory.is_member(&Identity::human("ada"), &unknown)).expect("answered")
        );
    }

    #[test]
    fn the_directory_sorts_and_deduplicates_its_roster() {
        let directory = FakeDirectory::new()
            .with_member(&team(), Identity::human("grace"))
            .with_member(&team(), Identity::human("ada"))
            .with_member(&team(), Identity::human("ada"));
        let members = block_on(directory.members(&team())).expect("answered");
        let handles: Vec<&str> = members.iter().map(|identity| identity.handle.as_str()).collect();
        assert_eq!(handles, vec!["ada", "grace"]);
    }

    #[test]
    fn the_fake_passes_conformance() {
        let team = team();
        let approver = Identity::human("grace");
        let channel = FakeApprovalChannel::new();
        channel.approving(approver.clone(), &request());
        let directory = FakeDirectory::new().with_member(&team, approver.clone());
        block_on(conformance(&channel, &directory, &team, &approver));
    }
}
