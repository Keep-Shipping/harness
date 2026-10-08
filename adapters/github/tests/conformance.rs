//! The approval conformance kit against the **real** GitHub adapters
//! ([#96](https://github.com/Keep-Shipping/harness/issues/96)).
//!
//! Every response the adapters ask for is scripted on one
//! [`FakeHttpClient`], so the whole conversation — post the request comment,
//! read it back, list the PR's comments, check the answerer's team membership
//! — happens without a socket. The one subtlety worth naming: the conformance
//! kit calls [`ApprovalChannel::wait`] on a channel with no clock, which polls
//! exactly once, so the approve comment has to be in the scripted comment list
//! already rather than appearing after the poll.

use std::sync::Arc;

use ks_core::ids::RunId;
use ks_core::ports::approval::{ApprovalRequest, Artifact, ArtifactKind, Identity, Team};
use ks_core::ports::http::{HttpClient, HttpMethod, HttpResponse};
use ks_core::ports::supply_chain::Digest;
use ks_github::{GitHubApprovals, GitHubDirectory, Token, marker_for};
use ks_testing::approval::conformance;
use ks_testing::block_on;
use ks_testing::http::FakeHttpClient;

const API: &str = "https://api.github.com";
const ORG: &str = "keepshipping";
const OWNER: &str = "keep-shipping";
const REPO: &str = "harness";
const PR: u64 = 96;
const TEAM_SLUG: &str = "platform";
const APPROVER: &str = "conformance-approver";
/// The id GitHub hands back when the request comment is posted; it is the
/// ticket, and every later poll addresses this comment.
const REQUEST_COMMENT: i64 = 900;
/// The approve comment, written after the request comment, as GitHub ids them.
const APPROVE_COMMENT: i64 = 901;

fn team() -> Team {
    Team::parse("@platform").expect("valid")
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

fn members_url() -> String {
    format!("{API}/orgs/{ORG}/teams/{TEAM_SLUG}/members?per_page=100")
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

/// One comment as the comments API serves it.
fn comment(id: i64, login: &str, body: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "body": body,
        "created_at": "2026-10-08T12:34:56Z",
        "html_url": format!("https://github.com/{OWNER}/{REPO}/pull/{PR}#issuecomment-{id}"),
        "user": { "login": login, "type": "User" },
    })
}

/// The request comment exactly as the kit's own request would produce it, so
/// `poll` recovers the same team, proposer and digest the kit asserts on.
fn request_comment_body() -> String {
    let request = ApprovalRequest {
        run: RunId::from_parts(1_700_000_000_000, 1),
        step: "conformance-apply".to_string(),
        summary: "1 to create".to_string(),
        artifacts: vec![Artifact::new(
            ArtifactKind::PlanFile,
            Digest::sha256_from_hex(&"a".repeat(64)).expect("64 hex digits is a sha256"),
        )],
        from: team(),
        reason: "conformance".to_string(),
        proposed_by: Identity::human("conformance-proposer"),
    };
    format!("## Approval needed: conformance\n\n{marker}", marker = marker_for(&request))
}

fn scripted() -> FakeHttpClient {
    FakeHttpClient::new().with_allowed_host("api.github.com")
}

fn client(fake: Arc<FakeHttpClient>) -> Arc<dyn HttpClient> {
    fake
}

#[test]
fn the_github_adapters_pass_the_approval_conformance_kit() {
    let fake = Arc::new(
        scripted()
            // Posting the request comment is what mints the ticket.
            .with_response(
                HttpMethod::Post,
                comments_url(),
                response(201, format!(r#"{{"id":{REQUEST_COMMENT}}}"#).as_bytes()),
            )
            // `poll` re-reads that comment to recover the request.
            .with_response(
                HttpMethod::Get,
                comment_url(REQUEST_COMMENT),
                json_response(200, &serde_json::json!({ "body": request_comment_body() })),
            )
            // …and lists the PR to find the answer to it. The approve is
            // already here: a clockless `wait` polls once and parks.
            .with_response(
                HttpMethod::Get,
                comments_list_url(),
                json_response(
                    200,
                    &serde_json::json!([
                        comment(REQUEST_COMMENT, "keep-shipping[bot]", &request_comment_body(),),
                        comment(APPROVE_COMMENT, APPROVER, "/keepshipping approve"),
                    ]),
                ),
            )
            // Deliberately unsorted: `Directory::members` is what sorts them.
            .with_response(
                HttpMethod::Get,
                members_url(),
                json_response(
                    200,
                    &serde_json::json!([
                        { "login": APPROVER, "type": "User" },
                        { "login": "ada", "type": "User" },
                    ]),
                ),
            )
            .with_response(
                HttpMethod::Get,
                membership_url(APPROVER),
                json_response(200, &serde_json::json!({ "state": "active" })),
            )
            // A GitHub 404 on a membership is "not on the team", never an error.
            .with_response(
                HttpMethod::Get,
                membership_url("conformance-stranger"),
                response(404, b"{\"message\":\"Not Found\"}"),
            ),
    );
    let directory = GitHubDirectory::new(client(Arc::clone(&fake)), Token::new("t0ken"), ORG);
    let approvals = GitHubApprovals::new(
        client(Arc::clone(&fake)),
        Token::new("t0ken"),
        OWNER,
        REPO,
        PR,
        Arc::new(GitHubDirectory::new(client(Arc::clone(&fake)), Token::new("t0ken"), ORG)),
    );

    block_on(conformance(&approvals, &directory, &team(), &Identity::human(APPROVER)));
}
