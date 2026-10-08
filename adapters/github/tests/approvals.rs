//! The end-to-end shape of a parked run ([#96](https://github.com/Keep-Shipping/harness/issues/96)):
//! ask, park, resume on the same plan digest — and what happens when somebody
//! answers who may not.
//!
//! Everything is scripted on a [`FakeHttpClient`], so the PR a run is parked on
//! is a JSON array the test controls: "somebody approves" is "add a row", and
//! the successive pages are what make a poll return nothing and then a verdict.

use std::sync::Arc;
use std::time::Duration;

use ks_core::ids::RunId;
use ks_core::ports::approval::{
    ApprovalChannel, ApprovalError, ApprovalRequest, Artifact, ArtifactKind, Directory, Identity,
    Outcome, Team,
};
use ks_core::ports::http::{HttpClient, HttpMethod, HttpResponse};
use ks_core::ports::supply_chain::Digest;
use ks_github::{GitHubApprovals, GitHubDirectory, Token};
use ks_testing::block_on;
use ks_testing::http::FakeHttpClient;

const API: &str = "https://api.github.com";
const ORG: &str = "keepshipping";
const OWNER: &str = "keep-shipping";
const REPO: &str = "harness";
const PR: u64 = 96;
const TEAM_SLUG: &str = "platform";
/// The id GitHub gives the request comment; the ticket is this string.
const REQUEST_COMMENT: i64 = 900;

fn team() -> Team {
    Team::parse("@platform").expect("valid")
}

fn plan_digest() -> Digest {
    Digest::sha256_from_hex(&"b".repeat(64)).expect("64 hex digits is a sha256")
}

fn request() -> ApprovalRequest {
    ApprovalRequest {
        run: RunId::from_parts(1_700_000_000_000, 7),
        step: "apply-infra".to_string(),
        summary: "3 to create, 1 to destroy".to_string(),
        artifacts: vec![Artifact::new(ArtifactKind::PlanFile, plan_digest())],
        from: team(),
        reason: "production deploy".to_string(),
        proposed_by: Identity::human("ada"),
    }
}

fn comments_url() -> String {
    format!("{API}/repos/{OWNER}/{REPO}/issues/{PR}/comments")
}

fn comments_list_url() -> String {
    format!("{}?per_page=100", comments_url())
}

fn comment_url(id: i64) -> String {
    format!("{API}/repos/{OWNER}/{REPO}/issues/comments/{id}")
}

fn membership_url(user: &str) -> String {
    format!("{API}/orgs/{ORG}/teams/{TEAM_SLUG}/memberships/{user}")
}

fn response(status: u16, body: &[u8]) -> HttpResponse {
    HttpResponse { status, headers: vec![], body: body.to_vec() }
}

fn json_response(status: u16, value: &serde_json::Value) -> HttpResponse {
    response(status, &serde_json::to_vec(value).expect("a scripted body serializes"))
}

/// One comment as the PR comments API serves it.
fn comment(id: i64, login: &str, body: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "body": body,
        "created_at": "2026-10-08T12:34:56Z",
        "html_url": format!("https://github.com/{OWNER}/{REPO}/pull/{PR}#issuecomment-{id}"),
        "user": { "login": login, "type": "User" },
    })
}

/// The bodies of every comment the adapter posted, oldest first.
fn posted_comments(fake: &FakeHttpClient) -> Vec<String> {
    fake.requests()
        .iter()
        .filter(|req| req.method == HttpMethod::Post && req.url == comments_url())
        .filter_map(|req| serde_json::from_slice::<serde_json::Value>(&req.body).ok())
        .filter_map(|value| {
            value.get("body").and_then(serde_json::Value::as_str).map(str::to_string)
        })
        .collect()
}

fn client(fake: Arc<FakeHttpClient>) -> Arc<dyn HttpClient> {
    fake
}

/// Posts `request` against a throwaway fake and returns the body GitHub would
/// have stored, so a later `poll` can be scripted to read back exactly what
/// `request` wrote — the adapter never hands its own formatting to a test.
fn posted_request_body(request: &ApprovalRequest) -> String {
    let fake = Arc::new(FakeHttpClient::new().with_allowed_host("api.github.com").with_response(
        HttpMethod::Post,
        comments_url(),
        response(201, format!(r#"{{"id":{REQUEST_COMMENT}}}"#).as_bytes()),
    ));
    block_on(channel(&fake).request(request)).expect("the request is accepted");
    let mut bodies = posted_comments(&fake);
    assert_eq!(bodies.len(), 1, "a request posts exactly one comment");
    bodies.remove(0)
}

/// A fake scripted with the request comment, the successive comment listings
/// `poll` will read, and a roster of `members` on the team.
fn scripted(
    request_body: &str,
    listings: &[Vec<serde_json::Value>],
    members: &[&str],
) -> FakeHttpClient {
    let mut fake = FakeHttpClient::new()
        .with_allowed_host("api.github.com")
        // Posting a comment mints the ticket, and posting the "ignored" reply
        // goes to the same endpoint — both answer 201 with an id.
        .with_response(
            HttpMethod::Post,
            comments_url(),
            response(201, format!(r#"{{"id":{REQUEST_COMMENT}}}"#).as_bytes()),
        )
        .with_response(
            HttpMethod::Get,
            comment_url(REQUEST_COMMENT),
            json_response(200, &serde_json::json!({ "body": request_body })),
        );
    for listing in listings {
        fake = fake.with_response(
            HttpMethod::Get,
            comments_list_url(),
            json_response(200, &serde_json::json!(listing)),
        );
    }
    for member in members {
        fake = fake.with_response(
            HttpMethod::Get,
            membership_url(member),
            json_response(200, &serde_json::json!({ "state": "active" })),
        );
    }
    // Anybody not named in `members` is off the team, which GitHub says with a
    // 404 — an answer, not an error.
    fake.with_response(HttpMethod::Get, membership_url("mallory"), response(404, b"{}"))
}

/// The channel over `fake`, checking membership against the same fake.
fn channel(fake: &Arc<FakeHttpClient>) -> GitHubApprovals {
    let directory: Arc<dyn Directory> =
        Arc::new(GitHubDirectory::new(client(Arc::clone(fake)), Token::new("t0ken"), ORG));
    GitHubApprovals::new(client(Arc::clone(fake)), Token::new("t0ken"), OWNER, REPO, PR, directory)
}

#[test]
fn a_parked_run_resumes_on_the_digest_it_was_asked_about() {
    let body = posted_request_body(&request());
    let parked = comment(REQUEST_COMMENT, "keep-shipping[bot]", &body);
    let approving = comment(REQUEST_COMMENT + 1, "grace", "/keepshipping approve");
    // Nobody has answered; then grace, who is on the team and is not the
    // proposer, does. The two listings are served in order.
    let fake = Arc::new(scripted(
        &body,
        &[vec![parked.clone()], vec![parked.clone(), approving]],
        &["grace"],
    ));
    let approvals = channel(&fake);

    let ticket = block_on(approvals.request(&request())).expect("the request is accepted");
    assert_eq!(
        ticket.as_str(),
        REQUEST_COMMENT.to_string(),
        "the ticket is the request comment's id"
    );

    assert_eq!(
        block_on(approvals.poll(&ticket)),
        Ok(None),
        "a run nobody has answered must stay parked"
    );

    let verdict = block_on(approvals.poll(&ticket))
        .expect("the poll answers")
        .expect("grace's approve is a verdict");
    assert_eq!(verdict.approver, Identity::human("grace"), "the verdict names its author");
    assert_eq!(verdict.outcome, Outcome::Approved);
    assert_eq!(
        verdict.bound_artifacts,
        request().artifacts,
        "the verdict is bound to the exact artifacts that were asked about"
    );
    assert_eq!(
        request().accepts(&verdict),
        Ok(()),
        "the engine accepts a verdict bound to the plan it parked on"
    );
}

#[test]
fn an_approve_from_off_the_team_is_answered_with_a_reply_and_no_verdict() {
    let body = posted_request_body(&request());
    let parked = comment(REQUEST_COMMENT, "keep-shipping[bot]", &body);
    let stranger = comment(REQUEST_COMMENT + 1, "mallory", "/keepshipping approve");
    let fake = Arc::new(scripted(&body, &[vec![parked, stranger]], &["grace"]));
    let approvals = channel(&fake);

    let ticket = block_on(approvals.request(&request())).expect("the request is accepted");
    assert_eq!(
        block_on(approvals.poll(&ticket)),
        Ok(None),
        "an approve from off the team must not approve the run"
    );

    let replies = posted_comments(&fake);
    let reply = replies.last().expect("the ignored command is answered");
    assert!(
        reply.contains("@mallory") && reply.contains("is not a member of @platform"),
        "the reply names who was refused and why: {reply}"
    );
}

#[test]
fn the_proposer_cannot_approve_their_own_request() {
    let body = posted_request_body(&request());
    let parked = comment(REQUEST_COMMENT, "keep-shipping[bot]", &body);
    let self_approval = comment(REQUEST_COMMENT + 1, "ada", "/keepshipping approve");
    let fake = Arc::new(scripted(&body, &[vec![parked, self_approval]], &["ada", "grace"]));
    let approvals = channel(&fake);

    let ticket = block_on(approvals.request(&request())).expect("the request is accepted");
    assert_eq!(block_on(approvals.poll(&ticket)), Ok(None), "a run never approves itself");

    let replies = posted_comments(&fake);
    let reply = replies.last().expect("the self-approval is answered");
    assert!(
        reply.contains("@ada") && reply.contains("proposed this change"),
        "the reply names the proposer and the rule: {reply}"
    );
}

#[test]
fn an_ignored_command_is_not_answered_twice() {
    let body = posted_request_body(&request());
    let parked = comment(REQUEST_COMMENT, "keep-shipping[bot]", &body);
    let stranger = comment(REQUEST_COMMENT + 1, "mallory", "/keepshipping approve");

    // The first poll has no reply to show for, so it leaves one.
    let first = Arc::new(scripted(&body, &[vec![parked.clone(), stranger.clone()]], &["grace"]));
    let ticket = block_on(channel(&first).request(&request())).expect("accepted");
    assert_eq!(block_on(channel(&first).poll(&ticket)), Ok(None));
    let reply = posted_comments(&first).last().expect("a reply").clone();

    // The second poll sees that reply on the PR, so it must stay quiet — a
    // poll that ran twice (two jobs, two processes) must not spam the author.
    let second = Arc::new(scripted(
        &body,
        &[vec![parked, stranger, comment(REQUEST_COMMENT + 2, "keep-shipping[bot]", &reply)]],
        &["grace"],
    ));
    let approvals = channel(&second);
    let again = block_on(approvals.poll(&ticket)).expect("the poll answers");
    assert_eq!(again, None, "nothing answered the run the second time");
    assert!(
        posted_comments(&second).is_empty(),
        "a command that was already answered must not be answered again"
    );
}

#[test]
fn waiting_with_no_clock_parks_the_run_instead_of_blocking_it() {
    let body = posted_request_body(&request());
    let fake = Arc::new(scripted(&body, &[vec![]], &["grace"]));
    let approvals = channel(&fake);

    let ticket = block_on(approvals.request(&request())).expect("the request is accepted");
    let waited = block_on(approvals.wait(&ticket, Duration::from_secs(300)));
    let error = waited.expect_err("nobody has answered");
    assert!(
        matches!(
            error,
            ApprovalError::Undecided { ref ticket, after: Duration::ZERO }
                if *ticket == REQUEST_COMMENT.to_string()
        ),
        "a clockless wait parks — writes its state and lets a resume job re-poll — and claims \
         it waited for nothing: {error:?}"
    );
}

#[test]
fn a_refusal_from_a_team_member_is_a_verdict_that_does_not_approve() {
    let body = posted_request_body(&request());
    let parked = comment(REQUEST_COMMENT, "keep-shipping[bot]", &body);
    let refusal =
        comment(REQUEST_COMMENT + 1, "grace", "/keepshipping refuse the blast radius is too wide");
    let fake = Arc::new(scripted(&body, &[vec![parked, refusal]], &["grace"]));
    let approvals = channel(&fake);

    let ticket = block_on(approvals.request(&request())).expect("the request is accepted");
    let verdict = block_on(approvals.poll(&ticket))
        .expect("the poll answers")
        .expect("a refusal is a verdict too");
    assert_eq!(verdict.outcome, Outcome::Refused);
    assert!(!verdict.is_approved());
    assert_eq!(
        verdict.comment.as_deref(),
        Some("the blast radius is too wide"),
        "the reason the approver gave travels with the verdict"
    );
}
