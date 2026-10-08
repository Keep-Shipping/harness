//! What happens when an approval does not come, and who is told
//! ([#99](https://github.com/Keep-Shipping/harness/issues/99)).
//!
//! The claim under test is not "the code returned a refusal" but "the run log says the same thing":
//! every path asserts the *ordered* sequence of event kinds, so a granted event arriving beside a
//! denial — or a duplicate `approval.requested` on a path that should have one — fails here rather
//! than shipping. A refusal path also asserts nothing follows it, which in a run log is what "no
//! downstream step ran" looks like. Everything is a `ks-testing` fake.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ks_core::ids::RunId;
use ks_core::ports::approval::{
    ApprovalError, ApprovalRequest, Artifact, ArtifactKind, DirectoryError, Identity, Outcome,
    Team, Verdict,
};
use ks_core::ports::run_log::{RunEvent, RunLog};
use ks_core::ports::secrets::Redactor;
use ks_core::ports::supply_chain::Digest;
use ks_engine::denial::{Reason, Resolution, aborted, decide, settle};
use ks_engine::journal::Journal;
use ks_testing::approval::{FakeApprovalChannel, FakeDirectory};
use ks_testing::block_on;
use ks_testing::run_log::RecordingRunLog;

/// The channel the run asks through, as the log names it.
const CHANNEL: &str = "tty";
/// How long a run waits before giving up. Long enough that a scripted answer is never a race — the
/// fake answers from a queue, not from a clock.
const TIMEOUT: Duration = Duration::from_secs(900);
/// The team the request asks.
const TEAM: &str = "@platform";

/// The one approval this run parks on: a plan an agent proposed, about to be applied for real.
fn request() -> ApprovalRequest {
    ApprovalRequest {
        run: RunId::from_parts(1_700_000_000_000, 42),
        step: "apply-infra".to_string(),
        summary: "3 to create, 1 to destroy".to_string(),
        artifacts: vec![plan('a')],
        from: Team::parse(TEAM).expect("@platform is a team handle"),
        reason: "production deploy".to_string(),
        proposed_by: Identity::service("agent-runtime"),
    }
}

fn plan(hex: char) -> Artifact {
    Artifact::new(
        ArtifactKind::PlanFile,
        Digest::sha256_from_hex(&hex.to_string().repeat(64)).expect("64 hex digits"),
    )
}

/// The team's roster, with whoever named on it.
fn directory(member: Option<&str>) -> FakeDirectory {
    let team = Team::parse(TEAM).expect("@platform is a team handle");
    match member {
        Some(member) => FakeDirectory::new().with_member(&team, Identity::human(member)),
        None => FakeDirectory::new(),
    }
}

/// The request's artifacts as the log carries them: digests, never the plan.
fn hashes(request: &ApprovalRequest) -> Vec<String> {
    request.artifacts.iter().map(|artifact| artifact.digest.to_string()).collect()
}

/// A journal over a fresh recording fake; no secrets, so nothing is scrubbed.
fn journal() -> (Journal, Arc<RecordingRunLog>) {
    let log = Arc::new(RecordingRunLog::new());
    let j = Journal::new(
        Arc::clone(&log) as Arc<dyn RunLog>,
        Arc::new(Redactor::new()),
        request().run.clone(),
    );
    (j, log)
}

fn kinds(log: &RecordingRunLog) -> Vec<&'static str> {
    log.events().iter().map(RunEvent::kind).collect()
}

/// Parks on `request` and settles it: ask, settle, write the one event the answer earns. This is
/// the shape the run loop drives, and the reason each path asserts a whole ordered sequence.
async fn park(
    j: &Journal,
    channel: &FakeApprovalChannel,
    roster: &FakeDirectory,
    request: &ApprovalRequest,
) -> Resolution {
    block_on(j.approval_requested(&request.step, CHANNEL, hashes(request))).expect("logged");
    let resolution = decide(channel, roster, request, TIMEOUT).await.expect("asked");
    block_on(settle(j, request, CHANNEL, resolution.clone())).expect("logged");
    resolution
}

#[test]
fn an_approval_releases_the_step_and_logs_granted() {
    let (j, log) = journal();
    let request = request();
    let channel = FakeApprovalChannel::new();
    channel.approving(Identity::human("grace"), &request);

    let resolution = block_on(park(&j, &channel, &directory(Some("grace")), &request));

    assert_eq!(resolution, Resolution::Granted { by: "grace".to_string() });
    assert!(resolution.is_granted());
    assert_eq!(resolution.reason(), None, "a grant has no reason to report");
    assert_eq!(kinds(&log), ["approval.requested", "approval.granted"]);
    let RunEvent::ApprovalGranted { approver, artifacts, .. } = &log.events()[1] else {
        panic!("expected approval.granted, got {:?}", log.events()[1]);
    };
    assert_eq!(approver, "grace");
    assert_eq!(*artifacts, hashes(&request), "bound to the digests asked about");
}

#[test]
fn a_denial_ends_the_run_and_reports_why() {
    let (j, log) = journal();
    let request = request();
    let channel = FakeApprovalChannel::new();
    channel.refusing(Identity::human("grace"), &request, Some("we are not deploying this Friday"));

    let resolution = block_on(park(&j, &channel, &directory(Some("grace")), &request));

    assert!(!resolution.is_granted());
    let reason = resolution.reason().expect("a refusal carries a reason");
    assert_eq!(reason.code(), "denied");
    assert!(
        matches!(reason, Reason::Denied { approver, comment: Some(_) } if approver == "grace"),
        "the refusal names who said no and what they said: {reason:?}"
    );
    // The proposer is told, in one line, in the approver's own words.
    let told = reason.message();
    assert!(
        told.contains("grace") && told.contains("this Friday"),
        "the proposer is told why: {told}"
    );

    // No granted event, and nothing after the denial: that is "no downstream step ran".
    assert_eq!(kinds(&log), ["approval.requested", "approval.denied"]);
    let RunEvent::ApprovalDenied { approver, reason, .. } = &log.events()[1] else {
        panic!("expected approval.denied, got {:?}", log.events()[1]);
    };
    assert_eq!(approver, "grace");
    assert!(reason.contains("this Friday"), "the approver's own words reach the log: {reason}");
}

/// A person who said no without saying why is the commonest refusal of all, and the log must not
/// read as though the reason was lost.
#[test]
fn a_denial_without_a_comment_still_says_who_refused() {
    let (j, log) = journal();
    let request = request();
    let channel = FakeApprovalChannel::new();
    channel.refusing(Identity::human("grace"), &request, None);

    let resolution = block_on(park(&j, &channel, &directory(Some("grace")), &request));

    let reason = resolution.reason().expect("a refusal carries a reason");
    assert_eq!(reason, &Reason::Denied { approver: "grace".to_string(), comment: None });
    assert_eq!(reason.code(), "denied");
    assert_eq!(reason.message(), "denied by grace", "never an empty reason");
    assert_eq!(kinds(&log), ["approval.requested", "approval.denied"]);
    let RunEvent::ApprovalDenied { approver, reason, .. } = &log.events()[1] else {
        panic!("expected approval.denied, got {:?}", log.events()[1]);
    };
    assert_eq!(approver, "grace");
    assert_eq!(reason, "denied by grace");
}

#[test]
fn a_channel_that_never_answers_expires_rather_than_waiting() {
    let (j, log) = journal();
    let request = request();
    // Nothing scripted: `wait` is Undecided, which is what silence really is.
    let channel = FakeApprovalChannel::new();

    let resolution = block_on(park(&j, &channel, &directory(Some("grace")), &request));

    let reason = resolution.reason().expect("an expiry is a refusal");
    assert_eq!(reason.code(), "expired");
    assert_eq!(
        reason,
        &Reason::Expired { after: TIMEOUT },
        "the reason carries the deadline the run asked with"
    );
    assert!(
        reason.message().contains("900s"),
        "the proposer is told how long it waited: {reason:?}"
    );
    assert_eq!(kinds(&log), ["approval.requested", "approval.expired"]);
}

/// A deadline under a second must not read as "no time at all".
#[test]
fn a_sub_second_timeout_is_reported_in_milliseconds() {
    let reason = Reason::Expired { after: Duration::from_millis(500) };
    assert!(reason.message().contains("500ms"), "{}", reason.message());
    assert_eq!(
        Reason::Expired { after: Duration::from_secs(90) }.message().split(';').next(),
        Some("nobody answered within 90s")
    );
}

#[test]
fn the_proposer_may_abort_a_run_it_is_parked_on() {
    let (j, log) = journal();
    let request = request();

    block_on(j.approval_requested(&request.step, CHANNEL, hashes(&request))).expect("logged");
    // Called off while parked, with nobody having answered and no error: the proposer owns the run
    // and may stop asking.
    let resolution = aborted("agent-runtime");
    block_on(settle(&j, &request, CHANNEL, resolution.clone())).expect("logged");

    assert!(!resolution.is_granted(), "an abort releases nothing");
    let reason = resolution.reason().expect("an abort is a refusal");
    assert_eq!(reason.code(), "aborted");
    assert_eq!(reason, &Reason::Aborted { proposer: "agent-runtime".to_string() });
    assert_eq!(kinds(&log), ["approval.requested", "approval.aborted"]);
    // Nobody refused anything, so the log must not blame a teammate who did nothing.
    let RunEvent::ApprovalAborted { proposer, .. } = &log.events()[1] else {
        panic!("expected approval.aborted, got {:?}", log.events()[1]);
    };
    assert_eq!(proposer, "agent-runtime");
}

#[test]
fn a_verdict_the_request_does_not_accept_is_never_taken_as_approval() {
    let (j, log) = journal();
    let request = request();
    // Bound to a different plan than the one asked about.
    let channel = FakeApprovalChannel::new().with_verdict(Verdict::new(
        Identity::human("grace"),
        SystemTime::UNIX_EPOCH,
        Outcome::Approved,
        vec![plan('b')],
    ));

    let resolution = block_on(park(&j, &channel, &directory(Some("grace")), &request));

    assert!(!resolution.is_granted(), "a verdict this request does not accept releases nothing");
    let reason = resolution.reason().expect("an unbound verdict is a refusal");
    assert_eq!(reason.code(), "artifacts_changed", "a code an agent can branch on");
    let Reason::ArtifactsChanged { detail } = reason else {
        panic!("expected ArtifactsChanged, got {reason:?}");
    };
    // The whole sentence, exactly once: the port's own text, with no second copy of its
    // leading clause bolted on by the message layer.
    let expected = format!(
        "the artifacts changed after they were approved: approved [{}], asked about [{}]; \
         ask again on the current artifacts",
        plan('b').digest,
        plan('a').digest
    );
    assert_eq!(detail, &expected);
    assert_eq!(reason.message(), expected, "the message reads once, not twice");
    // The whole sequence, not merely the absence of a grant: this path ends the run, and a log
    // that stopped at `approval.requested` would read as still parked.
    assert_eq!(kinds(&log), ["approval.requested", "approval.rejected"]);
    let RunEvent::ApprovalRejected { detail, .. } = &log.events()[1] else {
        panic!("expected approval.rejected, got {:?}", log.events()[1]);
    };
    assert!(detail.contains("artifacts changed"), "what did not hold reaches the log: {detail}");
}

/// Membership is the half of the contract `accepts` explicitly leaves out, and a run released
/// without it is a run a stranger released.
#[test]
fn somebody_off_the_team_cannot_approve_a_run() {
    let (j, log) = journal();
    let request = request();
    let channel = FakeApprovalChannel::new();
    // A perfectly well-formed verdict from a human: right shape, wrong roster.
    channel.approving(Identity::human("mallory"), &request);

    let resolution = block_on(park(&j, &channel, &directory(Some("grace")), &request));

    assert!(!resolution.is_granted(), "a stranger is not on the team that was asked");
    let reason = resolution.reason().expect("off the team is a refusal");
    assert_eq!(reason.code(), "not_on_team");
    assert_eq!(
        reason,
        &Reason::NotOnTeam { approver: "mallory".to_string(), team: TEAM.to_string() }
    );
    assert!(reason.message().contains(TEAM), "the proposer is told which team: {reason:?}");
    assert_eq!(kinds(&log), ["approval.requested", "approval.rejected"]);
}

/// The rule an agent most needs to be told specifically: it cannot approve its own run.
#[test]
fn a_run_cannot_approve_itself_and_says_so_with_a_code() {
    let (j, log) = journal();
    let mut request = request();
    request.proposed_by = Identity::human("ada");
    let channel = FakeApprovalChannel::new();
    channel.approving(Identity::human("ada"), &request);

    let resolution = block_on(park(&j, &channel, &directory(Some("ada")), &request));

    let reason = resolution.reason().expect("a self-approval is a refusal");
    assert_eq!(reason.code(), "approver_is_proposer");
    assert_eq!(reason, &Reason::ApproverIsProposer { approver: "ada".to_string() });
    assert_eq!(kinds(&log), ["approval.requested", "approval.rejected"]);
    let RunEvent::ApprovalRejected { detail, .. } = &log.events()[1] else {
        panic!("expected approval.rejected, got {:?}", log.events()[1]);
    };
    assert!(detail.contains("cannot approve it"), "the proposer is told why: {detail}");
}

#[test]
fn a_machine_cannot_approve_a_run() {
    let (j, log) = journal();
    let request = request();
    let channel = FakeApprovalChannel::new();
    channel.approving(Identity::service("github-actions"), &request);

    let resolution = block_on(park(&j, &channel, &directory(Some("github-actions")), &request));

    let reason = resolution.reason().expect("a bot's answer is a refusal");
    assert_eq!(reason.code(), "approver_not_human");
    assert_eq!(reason, &Reason::ApproverNotHuman { approver: "github-actions".to_string() });
    assert_eq!(kinds(&log), ["approval.requested", "approval.rejected"]);
}

/// A roster that cannot be read is not an answer about anybody. If it were folded into the
/// membership check as `false`, every forge outage would end a run with `approval.rejected` and
/// read as though a specific colleague had been ruled off the team — so the outage propagates as
/// an error and the log keeps saying the run is still parked, which is what it is.
#[test]
fn a_directory_outage_is_an_error_and_never_a_refusal() {
    let (j, log) = journal();
    let request = request();
    let channel = FakeApprovalChannel::new();
    channel.approving(Identity::human("grace"), &request);
    let down = FakeDirectory::new().failing(DirectoryError::Unavailable {
        message: "the team directory is unreachable".to_string(),
    });

    let error = block_on(j.approval_requested(&request.step, CHANNEL, hashes(&request)));
    assert!(error.is_ok(), "the request still landed");
    let error =
        block_on(decide(&channel, &down, &request, TIMEOUT)).expect_err("the roster is down");

    assert!(
        matches!(&error, ApprovalError::Unavailable { message } if message.contains("unreachable")),
        "an outage is infrastructure, not a decision about a person: {error}"
    );
    assert_eq!(
        kinds(&log),
        ["approval.requested"],
        "nothing may blame an approver for the directory being down"
    );
}

/// `settle` is the one place a resolution becomes an event, so every ending it can be handed is
/// driven through it here.
#[test]
fn settle_writes_exactly_one_event_for_every_ending() {
    let endings: Vec<(Resolution, &str)> = vec![
        (Resolution::Granted { by: "grace".to_string() }, "approval.granted"),
        (
            Resolution::Refused(Reason::Denied {
                approver: "grace".to_string(),
                comment: Some("no".to_string()),
            }),
            "approval.denied",
        ),
        (Resolution::Refused(Reason::Expired { after: TIMEOUT }), "approval.expired"),
        (
            Resolution::Refused(Reason::Aborted { proposer: "agent-runtime".to_string() }),
            "approval.aborted",
        ),
        (
            Resolution::Refused(Reason::NotOnTeam {
                approver: "mallory".to_string(),
                team: TEAM.to_string(),
            }),
            "approval.rejected",
        ),
    ];
    for (resolution, expected) in endings {
        let (j, log) = journal();
        let request = request();
        block_on(j.approval_requested(&request.step, CHANNEL, hashes(&request))).expect("logged");
        block_on(settle(&j, &request, CHANNEL, resolution.clone())).expect("logged");
        assert_eq!(kinds(&log), ["approval.requested", expected], "{expected} is the whole log");
        let artifacts = &log.events()[1];
        let carried = match artifacts {
            RunEvent::ApprovalGranted { artifacts, .. }
            | RunEvent::ApprovalDenied { artifacts, .. }
            | RunEvent::ApprovalExpired { artifacts, .. }
            | RunEvent::ApprovalAborted { artifacts, .. }
            | RunEvent::ApprovalRejected { artifacts, .. } => artifacts,
            other => panic!("expected an approval event, got {other:?}"),
        };
        assert_eq!(*carried, hashes(&request), "{expected} names the digests asked about");
    }
}
