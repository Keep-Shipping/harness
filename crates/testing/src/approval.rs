//! Fakes for the approval ports: a scripted [`FakeApprovalChannel`] that mints
//! tickets and serves verdicts, a [`FakeApprovalInbox`] over the same store, a
//! [`FakeDirectory`] with a static roster, and the conformance kits they share.
//! Never touches the filesystem or network.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use ks_core::ids::RunId;
use ks_core::ports::BoxFuture;
use ks_core::ports::approval::{
    ApprovalChannel, ApprovalError, ApprovalRequest, Artifact, ArtifactKind, Directory,
    DirectoryError, Identity, Outcome, Team, Ticket, Verdict,
};
use ks_core::ports::approval_inbox::{ApprovalInbox, Decision, Pending};
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
/// order (`with_member` sorts on read instead), and the answer every lookup
/// gives back once the backend is scripted as down.
#[derive(Default)]
struct Roster {
    teams: BTreeMap<String, Vec<Identity>>,
    calls: usize,
    error: Option<DirectoryError>,
}

/// One call a test can observe on the [`FakeApprovalInbox`], oldest first via
/// [`FakeApprovalInbox::calls`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxCall {
    /// [`ApprovalInbox::pending`] listed what an approver could still decide.
    Pending,
    /// [`ApprovalInbox::decide`] recorded an answer, which the channel then
    /// serves for that run's ticket.
    Decided {
        /// The run that was answered.
        run: RunId,
        /// The decision as the caller made it — before the inbox bound it to
        /// the request's artifacts, which is the binding the verdict carries.
        decision: Decision,
    },
}

/// The two approval fakes' shared mutable state, behind one `Arc`: the requests
/// that are open, the runs that have been answered, and every inbox call.
///
/// It is *shared* so that the two ends of one approval really are one
/// conversation — a request [`FakeApprovalChannel::request`] takes is one
/// [`FakeApprovalInbox::pending`] lists, and a decision the inbox records is
/// the verdict the channel hands back for the same ticket.
#[derive(Default)]
struct Inbox {
    /// Requests nobody has answered yet, oldest first — the queue `pending`
    /// reads. A run leaves it when it is decided.
    open: Vec<Pending>,
    /// The runs that have already been answered, so `pending` never offers a
    /// run twice and `decide` refuses a second answer.
    answered: BTreeSet<RunId>,
    /// The verdicts, keyed by the ticket they were answered through, so the
    /// channel can serve the same answer `decide` recorded.
    verdicts: BTreeMap<String, Verdict>,
    /// Every call, oldest first.
    calls: Vec<InboxCall>,
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
/// `approving` works on `&self`. [`FakeApprovalInbox::sharing`] hands out the
/// approver's end of the same conversation.
pub struct FakeApprovalChannel {
    state: Arc<Mutex<State>>,
    inbox: Arc<Mutex<Inbox>>,
}

impl Default for FakeApprovalChannel {
    fn default() -> FakeApprovalChannel {
        FakeApprovalChannel {
            state: Arc::new(Mutex::new(State::default())),
            inbox: Arc::new(Mutex::new(Inbox::default())),
        }
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

    /// Scripts a refusal by `approver`, bound to exactly `request`'s artifacts — the counterpart
    /// to [`approving`](FakeApprovalChannel::approving). `comment` is the approver's own words
    /// when they left any and `None` when they did not, which is a real shape: plenty of people
    /// press "no" without typing a reason, and the engine has to report that too
    /// ([#99](https://github.com/Keep-Shipping/harness/issues/99)).
    pub fn refusing(&self, approver: Identity, request: &ApprovalRequest, comment: Option<&str>) {
        let verdict = Verdict::new(
            approver,
            SystemTime::UNIX_EPOCH,
            Outcome::Refused,
            request.artifacts.clone(),
        );
        let verdict = match comment {
            Some(comment) => verdict.with_comment(comment),
            None => verdict,
        };
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

    /// The verdict the shared inbox recorded against `ticket`, if an approver
    /// has answered it there.
    fn recorded_verdict(&self, ticket: &Ticket) -> Option<Verdict> {
        self.inbox.lock().expect("fake approval inbox").verdicts.get(ticket.as_str()).cloned()
    }
}

impl fmt::Debug for FakeApprovalChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().expect("fake approval state");
        f.debug_struct("FakeApprovalChannel")
            .field("tickets", &state.tickets)
            .field("scripted", &state.queue.len())
            .field("calls", &state.calls.len())
            .field("open", &self.inbox.lock().expect("fake approval inbox").open.len())
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
            let ticket = Ticket::new(ticket);
            // Asking is what parks the question: the inbox this channel shares
            // lists it as open until somebody answers it.
            self.inbox
                .lock()
                .expect("fake approval inbox")
                .open
                .push(Pending { ticket: ticket.clone(), request: request.clone() });
            Ok(ticket)
        };
        Box::pin(std::future::ready(result))
    }

    fn poll<'a>(
        &'a self,
        ticket: &'a Ticket,
    ) -> BoxFuture<'a, Result<Option<Verdict>, ApprovalError>> {
        // Nobody having answered yet is the normal state, not a failure; a
        // ticket the fake never minted is neither — nothing can answer it.
        let scripted = {
            let mut state = self.state.lock().expect("fake approval state");
            match Self::known_ticket(&state, ticket) {
                Ok(()) => Ok(Self::next_verdict(&mut state)),
                Err(error) => Err(error),
            }
        };
        // An answer the shared inbox recorded for this run is this ticket's
        // answer: the two ends are one conversation, so what a person clicked
        // in the inbox is what the parked step is released by.
        let result = match scripted {
            Ok(None) => Ok(self.recorded_verdict(ticket)),
            other => other,
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
                Ok(()) => {
                    match Self::next_verdict(&mut state).or_else(|| self.recorded_verdict(ticket)) {
                        Some(verdict) => Ok(verdict),
                        None => Err(ApprovalError::Undecided {
                            ticket: ticket.as_str().to_string(),
                            after: timeout,
                        }),
                    }
                }
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

    /// A roster whose backend answers `error` to every lookup — the shape of a
    /// directory that is unreachable, which is *not* an answer of "nobody is on
    /// this team" and must never be mistaken for one
    /// ([#99](https://github.com/Keep-Shipping/harness/issues/99)).
    pub fn failing(self, error: DirectoryError) -> FakeDirectory {
        self.state.lock().expect("fake roster").error = Some(error);
        self
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
        // An unknown team has no members; that is an answer, not a failure —
        // unless the backend itself is down, which outranks every answer.
        let result = {
            let mut state = self.state.lock().expect("fake roster");
            state.calls += 1;
            if let Some(error) = &state.error {
                Err(error.clone())
            } else {
                let mut members = state.teams.get(team.handle()).cloned().unwrap_or_default();
                members.sort_by(|left, right| left.handle.cmp(&right.handle));
                Ok(members)
            }
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
            // A roster that will not answer must not answer `false`: the engine
            // treats `false` as a decision about a person, and an outage is not.
            if let Some(error) = &state.error {
                Err(error.clone())
            } else {
                Ok(state.teams.get(team.handle()).is_some_and(|members| members.contains(identity)))
            }
        };
        Box::pin(std::future::ready(result))
    }
}

/// The approver's side of [`FakeApprovalChannel`], over the same
/// in-memory store — so a request the channel takes is one the inbox can list, and a
/// decision the inbox records is one the channel hands back.
///
/// ```
/// use ks_core::ids::RunId;
/// use ks_core::ports::approval::{ApprovalChannel, ApprovalError, ApprovalRequest, Identity, Outcome, Team};
/// use ks_core::ports::approval_inbox::{ApprovalInbox, Decision};
/// use ks_testing::approval::{FakeApprovalChannel, FakeApprovalInbox};
/// use ks_testing::block_on;
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
/// let ticket = block_on(channel.request(&request)).expect("the request is accepted");
/// let inbox = FakeApprovalInbox::sharing(&channel);
///
/// // Ada's own run is nowhere in her inbox...
/// assert!(block_on(inbox.pending(&Identity::human("ada"))).expect("listed").is_empty());
/// // ...and answering it is refused rather than silently recorded.
/// assert!(matches!(
///     block_on(inbox.decide(&request.run, Decision::new(Identity::human("ada"), Outcome::Approved))),
///     Err(ApprovalError::ApproverIsProposer { .. })
/// ));
///
/// // Somebody else can answer it, and the channel then hands back that very
/// // verdict for the ticket the request was asked under.
/// let listed = block_on(inbox.pending(&Identity::human("grace"))).expect("listed");
/// assert_eq!(listed.len(), 1);
/// let answered = block_on(inbox.decide(
///     &listed[0].request.run,
///     Decision::new(Identity::human("grace"), Outcome::Approved).with_comment("ship it"),
/// ))
/// .expect("a person may answer");
/// assert_eq!(answered.comment.as_deref(), Some("ship it"));
/// assert_eq!(block_on(channel.poll(&ticket)), Ok(Some(answered)));
/// ```
///
/// All mutable state sits behind one mutex behind an `Arc`, so the fake is
/// `Send + Sync` and several handles can share one conversation.
pub struct FakeApprovalInbox {
    shared: Arc<Mutex<Inbox>>,
}

impl Default for FakeApprovalInbox {
    fn default() -> FakeApprovalInbox {
        FakeApprovalInbox { shared: Arc::new(Mutex::new(Inbox::default())) }
    }
}

impl FakeApprovalInbox {
    /// An inbox with nothing open against it, until a channel sharing this
    /// store asks something.
    pub fn new() -> FakeApprovalInbox {
        FakeApprovalInbox::default()
    }

    /// The approver's end of `channel`, over the very same store.
    pub fn sharing(channel: &FakeApprovalChannel) -> FakeApprovalInbox {
        FakeApprovalInbox { shared: Arc::clone(&channel.inbox) }
    }

    /// Every call made against the inbox, oldest first.
    pub fn calls(&self) -> Vec<InboxCall> {
        self.shared.lock().expect("fake approval inbox").calls.clone()
    }
}

impl fmt::Debug for FakeApprovalInbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inbox = self.shared.lock().expect("fake approval inbox");
        f.debug_struct("FakeApprovalInbox")
            .field("open", &inbox.open.len())
            .field("answered", &inbox.answered.len())
            .field("calls", &inbox.calls.len())
            .finish()
    }
}

impl ApprovalInbox for FakeApprovalInbox {
    fn pending<'a>(
        &'a self,
        approver: &'a Identity,
    ) -> BoxFuture<'a, Result<Vec<Pending>, ApprovalError>> {
        let result = {
            let mut inbox = self.shared.lock().expect("fake approval inbox");
            inbox.calls.push(InboxCall::Pending);
            // A run never appears in its own author's inbox, and one that has
            // been answered has already left the queue: the refusals are made
            // here rather than left for an adapter to remember.
            Ok(inbox
                .open
                .iter()
                .filter(|pending| pending.request.proposed_by != *approver)
                .filter(|pending| !inbox.answered.contains(&pending.request.run))
                .cloned()
                .collect())
        };
        Box::pin(std::future::ready(result))
    }

    fn decide<'a>(
        &'a self,
        run: &'a RunId,
        decision: Decision,
    ) -> BoxFuture<'a, Result<Verdict, ApprovalError>> {
        let result =
            {
                let mut inbox = self.shared.lock().expect("fake approval inbox");
                let Some(index) = inbox.open.iter().position(|pending| {
                    pending.request.run == *run && !inbox.answered.contains(run)
                }) else {
                    // Never asked, already answered, or parked elsewhere: there is
                    // nothing to file this against, and an "answer" recorded
                    // against a run that has moved on is worse than a refusal.
                    return Box::pin(std::future::ready(Err(ApprovalError::NoOpenRequest {
                        run: run.as_str().to_string(),
                    })));
                };
                let pending = inbox.open[index].clone();

                // The approver never supplies artifacts: the inbox binds the
                // verdict to what the request asked about, and checks it with the
                // same rule the engine checks at resume — so a proposer clicking
                // approve on their own run fails at the click, and the request
                // stays open for somebody who may answer it.
                let mut verdict = Verdict::new(
                    decision.approver.clone(),
                    SystemTime::now(),
                    decision.outcome,
                    pending.request.artifacts.clone(),
                );
                if let Some(comment) = decision.comment.clone() {
                    verdict = verdict.with_comment(comment);
                }
                if let Err(error) = pending.request.accepts(&verdict) {
                    return Box::pin(std::future::ready(Err(error)));
                }

                inbox.calls.push(InboxCall::Decided { run: run.clone(), decision });
                inbox.verdicts.insert(pending.ticket.as_str().to_string(), verdict.clone());
                inbox.open.remove(index);
                inbox.answered.insert(run.clone());
                Ok(verdict)
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

/// The fake's own approver-side round trip, exercised so the shared store
/// [`FakeApprovalInbox`] and [`FakeApprovalChannel`] keep between them stays
/// honest. **This is not an adapter conformance kit:** the arguments are these
/// two concrete fakes, so a real inbox — the GitHub-backed one, or any other —
/// cannot call this at all. The adapter-wide kit is [`conformance`] above, over
/// `&dyn` ports; an inbox-wide equivalent, over `&dyn ApprovalInbox`, is still
/// to be written.
///
/// What it walks is one approval round trip from the approver's seat, asserting
/// every refusal on the way. The proposer does not see their own run in `pending`,
/// and answering it is [`ApproverIsProposer`](ApprovalError::ApproverIsProposer)
/// at the click; a bot is [`ApproverNotHuman`](ApprovalError::ApproverNotHuman);
/// a human who is not the proposer gets a verdict bound to exactly the
/// artifacts that were asked about — built by the inbox, never supplied by the
/// caller — and the channel hands that very verdict back for the ticket the
/// request was asked under. A second answer is
/// [`NoOpenRequest`](ApprovalError::NoOpenRequest), and the run has left the
/// queue by then.
pub async fn inbox_conformance(channel: &FakeApprovalChannel, inbox: &FakeApprovalInbox) {
    let team = Team::parse("@platform").expect("a well-formed handle");
    let approver = Identity::human("inbox-conformance-approver");
    let proposer = Identity::human("inbox-conformance-proposer");
    let request = ApprovalRequest {
        run: RunId::from_parts(1_700_000_000_000, 7),
        step: "inbox-conformance-apply".to_string(),
        summary: "1 to create".to_string(),
        artifacts: vec![Artifact::new(
            ArtifactKind::PlanFile,
            Digest::sha256_from_hex(&"b".repeat(64))
                .expect("64 hex digits is a well-formed sha256"),
        )],
        from: team.clone(),
        reason: "conformance".to_string(),
        proposed_by: proposer.clone(),
    };

    let ticket = channel
        .request(&request)
        .await
        .unwrap_or_else(|error| panic!("inbox conformance: the request must be accepted: {error}"));

    assert!(
        inbox.pending(&proposer).await.expect("conformance: the queue must be readable").is_empty(),
        "inbox conformance: a run must never appear in its own author's inbox"
    );
    assert!(
        matches!(
            inbox.decide(&request.run, Decision::new(proposer, Outcome::Approved)).await,
            Err(ApprovalError::ApproverIsProposer { .. })
        ),
        "inbox conformance: the proposer must be refused at the click"
    );
    assert!(
        matches!(
            inbox
                .decide(&request.run, Decision::new(Identity::service("ci"), Outcome::Approved))
                .await,
            Err(ApprovalError::ApproverNotHuman { .. })
        ),
        "inbox conformance: a bot must be refused at the click"
    );

    let listed = inbox
        .pending(&approver)
        .await
        .unwrap_or_else(|error| panic!("inbox conformance: the queue must be readable: {error}"));
    assert_eq!(
        listed.len(),
        1,
        "inbox conformance: the requested run must be waiting for {approver}"
    );
    assert_eq!(
        listed[0].request.artifacts, request.artifacts,
        "inbox conformance: the approver must see exactly what the run asked about"
    );

    let verdict = inbox
        .decide(
            &request.run,
            Decision::new(approver.clone(), Outcome::Approved).with_comment("ship it"),
        )
        .await
        .unwrap_or_else(|error| {
            panic!("inbox conformance: a person must be able to answer: {error}")
        });
    request.accepts(&verdict).unwrap_or_else(|error| {
        panic!("inbox conformance: the verdict must be bound to the artifacts asked about: {error}")
    });
    assert_eq!(
        verdict.approver, approver,
        "inbox conformance: the verdict must carry the identity the adapter established"
    );
    assert_eq!(
        verdict.comment.as_deref(),
        Some("ship it"),
        "inbox conformance: the approver's own comment must survive"
    );
    assert_eq!(
        channel.poll(&ticket).await.expect("conformance: the ticket is known"),
        Some(verdict.clone()),
        "inbox conformance: the channel must hand back the verdict the inbox recorded"
    );
    assert!(
        inbox.pending(&approver).await.expect("conformance: the queue must be readable").is_empty(),
        "inbox conformance: an answered run must leave the queue"
    );
    assert!(
        matches!(
            inbox
                .decide(
                    &request.run,
                    Decision::new(approver, Outcome::Refused).with_comment("changed my mind"),
                )
                .await,
            Err(ApprovalError::NoOpenRequest { .. })
        ),
        "inbox conformance: a second answer must be refused, not recorded"
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

    #[test]
    fn a_run_never_appears_in_its_authors_inbox_and_cannot_be_answered_there() {
        let channel = FakeApprovalChannel::new();
        let inbox = FakeApprovalInbox::sharing(&channel);
        let request = request();
        block_on(channel.request(&request)).expect("the request is accepted");

        let proposer = request.proposed_by.clone();
        assert!(block_on(inbox.pending(&proposer)).expect("listed").is_empty());
        assert!(
            matches!(
                block_on(inbox.decide(&request.run, Decision::new(proposer, Outcome::Approved))),
                Err(ApprovalError::ApproverIsProposer { .. })
            ),
            "a proposer must be refused at the click, and nothing recorded"
        );
        // Refused means *not* answered: the request is still somebody else's.
        assert_eq!(block_on(inbox.pending(&Identity::human("grace"))).expect("listed").len(), 1);
        assert!(!inbox.calls().iter().any(|call| matches!(call, InboxCall::Decided { .. })));
    }

    #[test]
    fn a_bot_cannot_answer_and_a_second_answer_is_refused() {
        let channel = FakeApprovalChannel::new();
        let inbox = FakeApprovalInbox::sharing(&channel);
        let request = request();
        block_on(channel.request(&request)).expect("the request is accepted");

        assert!(matches!(
            block_on(
                inbox.decide(
                    &request.run,
                    Decision::new(Identity::service("ci"), Outcome::Approved)
                )
            ),
            Err(ApprovalError::ApproverNotHuman { .. })
        ));

        let approver = Identity::human("grace");
        let verdict = block_on(inbox.decide(
            &request.run,
            Decision::new(approver.clone(), Outcome::Approved).with_comment("ship it"),
        ))
        .expect("a person may answer");
        assert_eq!(verdict.comment.as_deref(), Some("ship it"));
        assert_eq!(verdict.bound_artifacts, request.artifacts);
        assert_eq!(block_on(inbox.pending(&approver)).expect("listed").len(), 0);

        // And the run that moved on takes no second answer.
        assert_eq!(
            block_on(inbox.decide(
                &request.run,
                Decision::new(approver, Outcome::Refused).with_comment("actually no"),
            )),
            Err(ApprovalError::NoOpenRequest { run: request.run.as_str().to_string() })
        );

        let calls = inbox.calls();
        assert_eq!(
            calls,
            vec![
                InboxCall::Decided {
                    run: request.run.clone(),
                    decision: Decision::new(Identity::human("grace"), Outcome::Approved)
                        .with_comment("ship it"),
                },
                InboxCall::Pending,
            ],
            "only successful calls are recorded"
        );
    }

    #[test]
    fn a_run_that_never_asked_has_nothing_to_answer() {
        let channel = FakeApprovalChannel::new();
        let inbox = FakeApprovalInbox::sharing(&channel);
        let run = RunId::from_parts(1_700_000_000_000, 99);
        assert_eq!(
            block_on(
                inbox.decide(&run, Decision::new(Identity::human("grace"), Outcome::Approved))
            ),
            Err(ApprovalError::NoOpenRequest { run: run.as_str().to_string() })
        );
        assert!(inbox.calls().is_empty(), "a refusal records no call");
    }

    #[test]
    fn the_inbox_fake_passes_inbox_conformance() {
        let channel = FakeApprovalChannel::new();
        let inbox = FakeApprovalInbox::sharing(&channel);
        block_on(inbox_conformance(&channel, &inbox));
    }
}
