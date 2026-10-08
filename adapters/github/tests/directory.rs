//! `GitHubDirectory` over a scripted [`FakeHttpClient`]: the roster GitHub
//! serves, sorted and de-duplicated by the adapter, and the readings a broken
//! or unknown team must give rather than an error.

use std::sync::Arc;

use ks_core::ports::approval::{Directory, Identity, Team};
use ks_core::ports::http::{HttpMethod, HttpResponse};
use ks_github::{GitHubDirectory, Token};
use ks_testing::block_on;
use ks_testing::http::FakeHttpClient;

const API: &str = "https://api.github.com";
const ORG: &str = "keepshipping";
const TEAM_SLUG: &str = "platform";

fn team() -> Team {
    Team::parse("@platform").expect("valid")
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

fn scripted() -> FakeHttpClient {
    FakeHttpClient::new().with_allowed_host("api.github.com")
}

fn directory(fake: Arc<FakeHttpClient>) -> GitHubDirectory {
    GitHubDirectory::new(fake, Token::new("t0ken"), ORG)
}

#[test]
fn the_roster_is_sorted_and_de_duplicated_whatever_order_github_serves_it_in() {
    let page = json_response(
        200,
        &serde_json::json!([
            { "login": "grace", "type": "User" },
            { "login": "ada", "type": "User" },
            // GitHub has been known to repeat a member across paginated
            // answers; the adapter's job is to hand back one handle.
            { "login": "ada", "type": "User" },
            // A bot is a service identity, not a human — a roster may hold one.
            { "login": "release-bot", "type": "Bot" },
        ]),
    );
    let directory =
        directory(Arc::new(scripted().with_response(HttpMethod::Get, members_url(), page)));

    let members = block_on(directory.members(&team())).expect("the roster is readable");
    let handles: Vec<&str> = members.iter().map(|identity| identity.handle.as_str()).collect();
    assert_eq!(handles, vec!["ada", "grace", "release-bot"], "sorted by handle, no repeats");
    assert_eq!(members[2].kind, ks_core::ports::approval::IdentityKind::Service);
}

#[test]
fn a_team_nobody_is_in_is_an_empty_roster_not_an_error() {
    // GitHub answers a team it does not know with a 404, which is an answer:
    // the team exists to the caller, it simply has no members.
    let fake = scripted().with_response(
        HttpMethod::Get,
        members_url(),
        response(404, b"{\"message\":\"Not Found\"}"),
    );
    let directory = directory(Arc::new(fake));
    assert_eq!(
        block_on(directory.members(&team())),
        Ok(vec![]),
        "a 404 team has no members, it is not a broken roster"
    );
}

#[test]
fn a_stranger_and_an_invited_but_not_yet_accepted_handle_are_both_off_the_team() {
    let fake = scripted()
        // Nobody is in: GitHub 404s the membership.
        .with_response(HttpMethod::Get, membership_url("mallory"), response(404, b"{}"))
        // A pending invitation is not a membership yet.
        .with_response(
            HttpMethod::Get,
            membership_url("grace"),
            json_response(200, &serde_json::json!({ "state": "pending" })),
        )
        // An active member.
        .with_response(
            HttpMethod::Get,
            membership_url("ada"),
            json_response(200, &serde_json::json!({ "state": "active" })),
        );
    let directory = directory(Arc::new(fake));

    assert!(
        !block_on(directory.is_member(&Identity::human("mallory"), &team())).expect("answered"),
        "a 404 membership means not on the team"
    );
    assert!(
        !block_on(directory.is_member(&Identity::human("grace"), &team())).expect("answered"),
        "a pending invitation is not a membership yet"
    );
    assert!(
        block_on(directory.is_member(&Identity::human("ada"), &team())).expect("answered"),
        "an active membership is a membership"
    );
}

#[test]
fn a_roster_the_api_will_not_serve_is_an_error_not_an_empty_team() {
    // The distinction that matters: an empty team approves nothing, and so does
    // a roster that could not be read — but only the second is a failure the
    // caller must hear about.
    let directory = directory(Arc::new(scripted().with_response(
        HttpMethod::Get,
        members_url(),
        response(503, b"unavailable"),
    )));
    let error = block_on(directory.members(&team())).expect_err("a broken roster is not a team");
    assert!(error.to_string().contains("503"), "the error names what GitHub answered: {error}");
}
