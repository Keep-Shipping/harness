//! Behaviour of the approval ports and their fakes: the two rules that stop a
//! run approving itself and an approval releasing the wrong plan, the
//! `Directory` half, and the conformance kit.

use std::time::{Duration, SystemTime};

use ks_core::ids::RunId;
use ks_core::ports::approval::{
    ApprovalChannel, ApprovalError, ApprovalRequest, Artifact, ArtifactKind, Directory, Identity,
    Outcome, Team, Verdict,
};
use ks_core::ports::supply_chain::Digest;
use ks_testing::approval::{ApprovalCall, FakeApprovalChannel, FakeDirectory, conformance};
use ks_testing::block_on;

fn team() -> Team {
    Team::parse("@platform").expect("@platform is a team handle")
}

/// One request asking `@platform` about a plan whose digest is 64 copies of
/// `hex` — changing the character changes which plan is under review.
fn request_with_digest(hex: char) -> ApprovalRequest {
    ApprovalRequest {
        run: RunId::from_parts(1_700_000_000_000, 7),
        step: "apply-infra".to_string(),
        summary: "3 to create, 1 to destroy".to_string(),
        artifacts: vec![Artifact::new(
            ArtifactKind::PlanFile,
            Digest::sha256_from_hex(&hex.to_string().repeat(64)).expect("64 hex digits"),
        )],
        from: team(),
        reason: "production deploy".to_string(),
        proposed_by: Identity::human("ada"),
    }
}

#[test]
fn a_team_member_can_approve_someone_elses_run() {
    let request = request_with_digest('a');
    let approver = Identity::human("grace");
    let channel = FakeApprovalChannel::new();
    channel.approving(approver.clone(), &request);
    let directory = FakeDirectory::new().with_member(&request.from, approver.clone());

    let ticket = block_on(channel.request(&request)).expect("the team is asked");
    assert!(!ticket.as_str().is_empty(), "a ticket must have an id");

    let verdict =
        block_on(channel.wait(&ticket, Duration::from_secs(30))).expect("a team member answers");
    assert_eq!(verdict.approver, approver);
    assert!(verdict.is_approved());

    // The engine's two checks: the binding, then the roster.
    assert_eq!(request.accepts(&verdict), Ok(()), "the answer is bound to this run's plan");
    assert!(
        block_on(directory.is_member(&verdict.approver, &request.from))
            .expect("the roster answers")
    );

    // And the request was recorded with exactly what it asked about.
    assert_eq!(
        channel.calls(),
        vec![ApprovalCall::Request {
            step: "apply-infra".to_string(),
            artifacts: request.artifacts.clone(),
            from: request.from.clone(),
        }]
    );
}

#[test]
fn the_proposer_cannot_approve_their_own_run() {
    let request = request_with_digest('a');
    // Ada proposed the run *and* is on the team — being a member is not a
    // licence to approve yourself.
    let approver = Identity::human("ada");
    let channel = FakeApprovalChannel::new();
    channel.approving(approver.clone(), &request);
    let directory = FakeDirectory::new().with_member(&request.from, approver.clone());
    assert!(
        block_on(directory.is_member(&approver, &request.from)).expect("answered"),
        "premise: ada is on the team"
    );

    let ticket = block_on(channel.request(&request)).expect("the team is asked");
    let verdict =
        block_on(channel.wait(&ticket, Duration::from_secs(30))).expect("an answer arrives");

    match request.accepts(&verdict) {
        Err(ApprovalError::ApproverIsProposer { approver }) => assert_eq!(approver, "ada"),
        other => panic!("the proposer must not be able to approve their own run, got {other:?}"),
    }
}

#[test]
fn an_approval_for_one_plan_does_not_release_another() {
    let approved = request_with_digest('a');
    let verdict = Verdict::new(
        Identity::human("grace"),
        SystemTime::UNIX_EPOCH,
        Outcome::Approved,
        approved.artifacts.clone(),
    );

    // Accepted against the request it was actually bound to.
    assert_eq!(approved.accepts(&verdict), Ok(()), "the verdict is accepted for its own plan");

    // The same verdict, asked about a different plan, releases nothing.
    let mut moved = request_with_digest('b');
    moved.run = approved.run;
    match moved.accepts(&verdict) {
        Err(ApprovalError::ArtifactsChanged { approved, requested }) => {
            assert_eq!(approved, vec![format!("sha256:{}", "a".repeat(64))]);
            assert_eq!(requested, vec![format!("sha256:{}", "b".repeat(64))]);
        }
        other => panic!("an approval for one plan must not release another, got {other:?}"),
    }
}

#[test]
fn a_bot_cannot_approve_a_run() {
    let request = request_with_digest('a');
    let bot = Identity::service("deploy-bot");
    let verdict = Verdict::new(
        bot.clone(),
        SystemTime::UNIX_EPOCH,
        Outcome::Approved,
        request.artifacts.clone(),
    );

    match request.accepts(&verdict) {
        Err(ApprovalError::ApproverNotHuman { approver }) => assert_eq!(approver, "deploy-bot"),
        other => panic!("a service identity must not approve, got {other:?}"),
    }
}

#[test]
fn an_approver_who_is_not_on_the_team_is_not_a_member() {
    let team = team();
    let request = request_with_digest('a');
    let outsider = Identity::human("mallory");
    let channel = FakeApprovalChannel::new();
    channel.approving(outsider.clone(), &request);
    let directory = FakeDirectory::new().with_member(&team, Identity::human("grace"));

    // The verdict is perfectly bound to the right plan — and still releases
    // nothing, because the roster says the approver was never asked.
    let ticket = block_on(channel.request(&request)).expect("the team is asked");
    let verdict =
        block_on(channel.wait(&ticket, Duration::from_secs(30))).expect("an answer arrives");
    assert_eq!(verdict.approver, outsider, "premise: the fake answered as mallory");
    assert_eq!(request.accepts(&verdict), Ok(()), "premise: the binding itself is correct");
    assert!(
        !block_on(directory.is_member(&verdict.approver, &request.from)).expect("answered"),
        "the roster is the only thing that stops mallory's verdict releasing the run"
    );
}

#[test]
fn the_approval_fakes_pass_their_conformance_kits() {
    let team = team();
    let approver = Identity::human("grace");

    let channel = FakeApprovalChannel::new();
    channel.approving(approver.clone(), &request_with_digest('a'));
    let directory = FakeDirectory::new().with_member(&team, approver.clone());
    block_on(conformance(&channel, &directory, &team, &approver));

    // And through the trait objects, so the fakes really are usable as ports.
    fn assert_send_sync<T: ?Sized + Send + Sync>() {}
    assert_send_sync::<dyn ApprovalChannel>();
    assert_send_sync::<dyn Directory>();
    let dynamic_channel: &dyn ApprovalChannel = &channel;
    let dynamic_directory: &dyn Directory = &directory;
    block_on(conformance(dynamic_channel, dynamic_directory, &team, &approver));
}

/// The kit is the gate for the real adapters, so it must reject one that
/// answers with somebody else's verdict even when the binding is perfect.
#[test]
#[should_panic(expected = "conformance: the verdict must be the named approver's")]
fn the_conformance_kit_rejects_another_reviewers_verdict() {
    let team = team();
    let approver = Identity::human("grace");
    let request = request_with_digest('a');

    let channel = FakeApprovalChannel::new();
    // Mallory is off the roster and is nobody the caller named, yet the
    // binding is exactly right — the only thing left to catch it is the kit
    // checking *whose* verdict came back.
    channel.approving(Identity::human("mallory"), &request);
    let directory = FakeDirectory::new().with_member(&team, approver.clone());
    block_on(conformance(&channel, &directory, &team, &approver));
}
