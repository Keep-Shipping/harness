//! Fork classification: what a run from somebody else's code is allowed to do
//! ([#115](https://github.com/Keep-Shipping/harness/issues/115)).
//!
//! Every case is a payload GitHub actually sends. Nothing here reaches the
//! network: `Origin::of` reads the event name and the parsed event payload, and
//! that is all it reads.

use ks_github::Origin;
use serde_json::{Value, json};

const SELF: i64 = 1296269;
const OTHER: i64 = 991;

fn repo(id: i64, full_name: &str, fork: bool) -> Value {
    json!({ "id": id, "full_name": full_name, "fork": fork })
}

/// This repository, and this repository as its own fork.
fn self_repo(fork: bool) -> Value {
    repo(SELF, "keep-shipping/harness", fork)
}

/// A pull request whose head and base carry the two repositories given.
fn pull_request(head: Value, base: Value) -> Value {
    json!({ "pull_request": { "head": { "repo": head }, "base": { "repo": base } } })
}

fn from_a_fork() -> Value {
    pull_request(repo(OTHER, "mallory/harness", true), self_repo(false))
}

fn origin(event: &str, payload: &Value) -> Origin {
    Origin::of(event, payload)
}

#[test]
fn a_pull_request_from_this_repository_may_apply() {
    let origin = origin("pull_request", &pull_request(self_repo(false), self_repo(false)));
    assert_eq!(origin, Origin::Repository);
    assert!(origin.may_apply() && origin.may_read_secrets());
    assert!(!origin.check_only());
}

#[test]
fn a_pull_request_from_a_fork_is_check_only() {
    let origin = origin("pull_request", &from_a_fork());
    assert_eq!(origin, Origin::Fork);
    assert!(origin.check_only());
    assert!(!origin.may_apply() && !origin.may_read_secrets());
}

#[test]
fn every_pull_request_family_event_judges_the_head_by_the_same_rule() {
    // All four carry the pull request, and all four read a foreign head as a
    // fork — including `pull_request_target`, whose run has the base's secrets.
    for event in [
        "pull_request",
        "pull_request_target",
        "pull_request_review",
        "pull_request_review_comment",
    ] {
        assert_eq!(origin(event, &from_a_fork()), Origin::Fork, "{event} must judge the head");
    }
}

#[test]
fn a_review_comment_is_judged_by_the_pull_request_it_names() {
    let on_this_repo = json!({
        "action": "created",
        "comment": { "pull_request_url": "https://api.github.com/repos/Keep-Shipping/harness/pulls/1" },
        "pull_request": { "head": { "repo": self_repo(false) }, "base": { "repo": self_repo(false) } },
    });
    assert_eq!(origin("pull_request_review_comment", &on_this_repo), Origin::Repository);
    let on_a_fork = json!({
        "action": "created",
        "comment": { "body": "/ks approve" },
        "pull_request": { "head": { "repo": repo(OTHER, "mallory/harness", true) }, "base": { "repo": self_repo(false) } },
    });
    assert_eq!(origin("pull_request_review_comment", &on_a_fork), Origin::Fork);
}

#[test]
fn a_pull_request_from_a_deleted_fork_is_a_fork() {
    assert_eq!(origin("pull_request", &pull_request(Value::Null, self_repo(false))), Origin::Fork);
}

#[test]
fn a_pull_request_event_with_no_pull_request_object_is_a_fork() {
    assert_eq!(origin("pull_request", &json!({ "action": "opened" })), Origin::Fork);
}

#[test]
fn repositories_are_matched_by_name_when_no_usable_id_is_sent() {
    let by_name = pull_request(
        json!({ "full_name": "keep-shipping/harness" }),
        json!({ "full_name": "Keep-Shipping/Harness" }),
    );
    assert_eq!(
        origin("pull_request", &by_name),
        Origin::Repository,
        "without ids the same name, in any case, is the same repository"
    );
    let by_string_id = pull_request(
        json!({ "id": "991", "full_name": "keep-shipping/harness" }),
        self_repo(false),
    );
    assert_eq!(
        origin("pull_request", &by_string_id),
        Origin::Repository,
        "an id that is not a number is no id"
    );
}

#[test]
fn equal_names_under_different_ids_are_different_repositories() {
    let payload = pull_request(repo(OTHER, "keep-shipping/harness", false), self_repo(false));
    assert_eq!(
        origin("pull_request", &payload),
        Origin::Fork,
        "a deleted and recreated repository keeps the name but not the id"
    );
}

#[test]
fn a_head_with_nothing_to_identify_it_is_a_fork() {
    let payload = pull_request(json!({ "id": OTHER }), self_repo(false));
    assert_eq!(
        origin("pull_request", &payload),
        Origin::Fork,
        "the head cannot be shown to be this repository, so it is not"
    );
}

#[test]
fn a_base_that_is_itself_a_fork_does_not_make_the_head_one() {
    let payload = pull_request(self_repo(true), self_repo(true));
    assert_eq!(
        origin("pull_request", &payload),
        Origin::Repository,
        "head.repo.fork is true on both sides and both sides are the same repository"
    );
}

#[test]
fn any_event_that_is_not_pr_family_is_a_ref_of_this_repository() {
    let push = origin("push", &json!({ "ref": "refs/heads/main", "repository": self_repo(false) }));
    assert_eq!(push, Origin::Repository);
    assert!(push.may_apply() && push.may_read_secrets());
    // The trigger decides this one, not the payload: an `issue_comment` run
    // executes a ref of this repository, and the harness does not fetch the
    // pull request the comment names to learn otherwise.
    let payload = json!({
        "action": "created",
        "issue": { "number": 1, "pull_request": { "html_url": "https://github.com/Keep-Shipping/harness/pull/1" } },
        "comment": { "body": "/ks approve" }
    });
    assert_eq!(origin("issue_comment", &payload), Origin::Repository);
}
