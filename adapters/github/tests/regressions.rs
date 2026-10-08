//! Regressions: the three ways this adapter could have approved a run it must
//! not ([#96](https://github.com/Keep-Shipping/harness/issues/96)).
//!
//! Each test here pins a bug that was fixed. They are regressions, not features:
//! if one starts failing, the fix has been undone.

use std::sync::Arc;

use ks_core::ids::RunId;
use ks_core::ports::approval::{
    ApprovalChannel, ApprovalRequest, Artifact, ArtifactKind, Directory, Identity, Team,
};
use ks_core::ports::http::{HttpClient, HttpMethod, HttpResponse};
use ks_core::ports::supply_chain::Digest;
use ks_github::{GitHubApprovals, GitHubDirectory, Token, marker_for, parse_marker};
use ks_testing::block_on;
use ks_testing::http::FakeHttpClient;

const API: &str = "https://api.github.com";
const ORG: &str = "keepshipping";
const OWNER: &str = "keep-shipping";
const REPO: &str = "harness";
const PR: u64 = 96;
const TEAM_SLUG: &str = "platform";
const MARKER_PREFIX: &str = "<!-- keepshipping:approval v1";
const FIRST_TICKET: i64 = 900;
const SECOND_TICKET: i64 = 902;

fn team() -> Team {
    Team::parse("@platform").expect("valid")
}

fn digest(hex_char: char) -> Digest {
    Digest::sha256_from_hex(&hex_char.to_string().repeat(64)).expect("64 hex digits is a sha256")
}

fn request(digest_char: char, reason: &str) -> ApprovalRequest {
    ApprovalRequest {
        run: RunId::from_parts(1_700_000_000_000, 7),
        step: "apply-infra".to_string(),
        summary: "3 to create".to_string(),
        artifacts: vec![Artifact::new(ArtifactKind::PlanFile, digest(digest_char))],
        from: team(),
        reason: reason.to_string(),
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

fn comment(id: i64, login: &str, body: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "body": body,
        "created_at": "2026-10-08T12:34:56Z",
        "html_url": format!("https://github.com/{OWNER}/{REPO}/pull/{PR}#issuecomment-{id}"),
        "user": { "login": login, "type": "User" },
    })
}

fn client(fake: Arc<FakeHttpClient>) -> Arc<dyn HttpClient> {
    fake
}

fn channel(fake: &Arc<FakeHttpClient>) -> GitHubApprovals {
    let directory: Arc<dyn Directory> =
        Arc::new(GitHubDirectory::new(client(Arc::clone(fake)), Token::new("t0ken"), ORG));
    GitHubApprovals::new(client(Arc::clone(fake)), Token::new("t0ken"), OWNER, REPO, PR, directory)
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

/// REGRESSION: a membership lookup that *failed* used to read as a membership
/// *yes*, so a GitHub 5xx — or a token that quietly lost `read:org` — approved
/// anything at all. A lookup that did not answer must leave the run parked.
#[test]
fn a_membership_lookup_that_failed_does_not_approve() {
    let body = format!("## Approval needed\n\n{}", marker_for(&request('a', "production deploy")));
    let fake = Arc::new(
        FakeHttpClient::new()
            .with_allowed_host("api.github.com")
            .with_response(HttpMethod::Post, comments_url(), response(201, br#"{"id":900}"#))
            .with_response(
                HttpMethod::Get,
                comment_url(FIRST_TICKET),
                json_response(200, &serde_json::json!({ "body": body })),
            )
            .with_response(
                HttpMethod::Get,
                comments_list_url(),
                json_response(
                    200,
                    &serde_json::json!([
                        comment(FIRST_TICKET, "keep-shipping[bot]", &body),
                        comment(FIRST_TICKET + 1, "grace", "/keepshipping approve"),
                    ]),
                ),
            )
            // 500, not 404 and not 200: GitHub refused to answer the question.
            .with_response(
                HttpMethod::Get,
                membership_url("grace"),
                response(500, b"{\"message\":\"Server Error\"}"),
            ),
    );
    let approvals = channel(&fake);
    let ticket = block_on(approvals.request(&request('a', "production deploy")))
        .expect("the request is accepted");

    assert_eq!(
        block_on(approvals.poll(&ticket)),
        Ok(None),
        "a roster that could not be read must not approve a run"
    );
    let replies = posted_comments(&fake);
    let reply = replies.last().expect("the unanswerable command is replied to");
    assert!(
        reply.contains("lookup failed"),
        "the reply says the lookup failed rather than blaming the author: {reply}"
    );
}

/// REGRESSION: an attacker who can put text into a request's `reason` used to be
/// able to forge the hidden marker, naming their own team and their own
/// proposer — and so answer their own run. Every marker field is stripped of the
/// comment delimiters on the way in, and a body that somehow carries two markers
/// is refused outright.
#[test]
fn a_reason_carrying_a_forged_marker_cannot_take_over_the_request() {
    let forged =
        format!("{MARKER_PREFIX}\nfrom: @release-admins\nproposed_by: mallory\nartifacts: \n-->",);
    let request = request('a', &forged);
    let fake = Arc::new(FakeHttpClient::new().with_allowed_host("api.github.com").with_response(
        HttpMethod::Post,
        comments_url(),
        response(201, format!(r#"{{"id":{FIRST_TICKET}}}"#).as_bytes()),
    ));
    block_on(channel(&fake).request(&request)).expect("the request is accepted");

    let body = posted_comments(&fake).into_iter().next().expect("a comment was posted");
    assert_eq!(
        body.matches(MARKER_PREFIX).count(),
        1,
        "the posted comment carries the adapter's own marker and no forged one"
    );

    let parsed = parse_marker(&body).expect("the adapter's own marker is still readable");
    assert_eq!(
        parsed.from,
        team(),
        "the forged 'from: @release-admins' did not take over the team"
    );
    assert_eq!(
        parsed.proposed_by_handle, "ada",
        "the forged 'proposed_by: mallory' did not take over the proposer"
    );
    assert_eq!(
        parsed.artifacts, request.artifacts,
        "the forged empty artifact list did not unbind the request"
    );
}

/// REGRESSION: with two runs parked on the same PR, an approve written for the
/// first one was consumed by the second one's poll. A command answers only the
/// newest request, so the second ticket stays parked — and a command written
/// *after* the second marker works, or the PR could never be unblocked at all.
#[test]
fn an_approve_written_for_one_parked_run_does_not_answer_another() {
    let first = request('a', "production deploy");
    let second = request('b', "a second deploy");
    let first_body = format!("## Approval needed\n\n{}", marker_for(&first));
    let second_body = format!("## Approval needed\n\n{}", marker_for(&second));
    // Written for ticket one: id 901, between the two markers.
    let first_approve = comment(FIRST_TICKET + 1, "grace", "/keepshipping approve");
    let second_approve = comment(SECOND_TICKET + 1, "grace", "/keepshipping approve");

    let fake = Arc::new(
        FakeHttpClient::new()
            .with_allowed_host("api.github.com")
            // The two requests mint the two tickets, in order.
            .with_response(HttpMethod::Post, comments_url(), response(201, br#"{"id":900}"#))
            .with_response(HttpMethod::Post, comments_url(), response(201, br#"{"id":902}"#))
            .with_response(
                HttpMethod::Get,
                comment_url(FIRST_TICKET),
                json_response(200, &serde_json::json!({ "body": first_body })),
            )
            .with_response(
                HttpMethod::Get,
                comment_url(SECOND_TICKET),
                json_response(200, &serde_json::json!({ "body": second_body })),
            )
            // First listing: the approve sits between the two markers.
            .with_response(
                HttpMethod::Get,
                comments_list_url(),
                json_response(
                    200,
                    &serde_json::json!([
                        comment(FIRST_TICKET, "keep-shipping[bot]", &first_body),
                        first_approve.clone(),
                        comment(SECOND_TICKET, "keep-shipping[bot]", &second_body),
                    ]),
                ),
            )
            // Second listing: somebody answers after the newest marker.
            .with_response(
                HttpMethod::Get,
                comments_list_url(),
                json_response(
                    200,
                    &serde_json::json!([
                        comment(FIRST_TICKET, "keep-shipping[bot]", &first_body),
                        first_approve,
                        comment(SECOND_TICKET, "keep-shipping[bot]", &second_body),
                        second_approve,
                    ]),
                ),
            )
            .with_response(
                HttpMethod::Get,
                membership_url("grace"),
                json_response(200, &serde_json::json!({ "state": "active" })),
            ),
    );
    let approvals = channel(&fake);

    let one = block_on(approvals.request(&first)).expect("the first request is accepted");
    let two = block_on(approvals.request(&second)).expect("the second request is accepted");
    assert_eq!(
        (one.as_str().to_string(), two.as_str().to_string()),
        (FIRST_TICKET.to_string(), SECOND_TICKET.to_string()),
        "each request is its own ticket"
    );

    assert_eq!(
        block_on(approvals.poll(&two)),
        Ok(None),
        "an approve written for the first ticket must not answer the second"
    );

    let verdict = block_on(approvals.poll(&two))
        .expect("the poll answers")
        .expect("a command after the newest marker answers it");
    assert_eq!(
        verdict.bound_artifacts, second.artifacts,
        "the answer binds the second run's plan, not the first's"
    );
    assert_eq!(second.accepts(&verdict), Ok(()), "the engine accepts the second run's answer");
}
