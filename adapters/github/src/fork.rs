//! Where the code a run is about to execute came from
//! ([#115](https://github.com/Keep-Shipping/harness/issues/115)).
//!
//! GitHub already withholds secrets, hands `pull_request` runs from forks a
//! read-only `GITHUB_TOKEN` and no OIDC id-token. This classification is the
//! harness's *own* answer to the same question, so what the run may do is not
//! left resting on which trigger the workflow file happened to pick: a
//! `pull_request_target` workflow runs the base's code with the base's secrets
//! but is still building a fork's head, and it reads as [`Origin::Fork`].
//!
//! Every pull-request-family event whose head cannot be shown to come from this
//! repository reads as [`Origin::Fork`]. The rules are small enough to read and
//! to test ([#115](https://github.com/Keep-Shipping/harness/issues/115)).
//!
//! # What this does not do
//!
//! Wiring [`Origin`] into the CLI's GitHub Actions run context is **not done**:
//! that context lives in `crates/cli/src/github_actions_run_context.rs`, which
//! does not depend on this crate. Until it does, an [`Origin`] is a value a
//! caller acts on — the engine does not enforce it by itself.
//!
//! A workflow that classifies as [`Origin::Repository`] and then checks out a PR
//! head itself (the "pwn request" pattern under `issue_comment` or
//! `pull_request_target`) is outside what this classification can see: it reads
//! the event payload, never the checkout.

/// Where the code a GitHub Actions run is about to execute came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// A ref of the repository whose workflow is running.
    Repository,
    /// Somebody else's code: a pull request head from another repository.
    Fork,
}

/// The PR-family events, where the head repository decides the origin. Every
/// other event runs a ref of this repository.
fn is_pull_request_event(event_name: &str) -> bool {
    matches!(
        event_name,
        "pull_request"
            | "pull_request_target"
            | "pull_request_review"
            | "pull_request_review_comment"
    )
}

/// The numeric repository `id`, if the payload carries one. GitHub ids are
/// stable across a rename, so they are the authority.
fn repo_id(repo: &serde_json::Value) -> Option<i64> {
    repo.get("id").and_then(serde_json::Value::as_i64)
}

/// The `owner/name`, compared case-insensitively: GitHub treats repository
/// names case-insensitively, so `Keep-Shipping/harness` and
/// `keep-shipping/harness` name one repository.
fn full_name(repo: &serde_json::Value) -> Option<String> {
    repo.get("full_name").and_then(serde_json::Value::as_str).map(str::to_lowercase)
}

/// Whether the head and base of `pull_request` name the same repository.
///
/// Ids win: when both sides carry one, only equal ids mean the same repository,
/// so a repository that was deleted and recreated under the same name (equal
/// `full_name`, fresh `id`) reads as different. Only when an id is missing on
/// either side does the `full_name` fallback apply.
fn same_repository(head: &serde_json::Value, base: &serde_json::Value) -> bool {
    match (repo_id(head), repo_id(base)) {
        (Some(head_id), Some(base_id)) => head_id == base_id,
        _ => match (full_name(head), full_name(base)) {
            (Some(head_name), Some(base_name)) => head_name == base_name,
            _ => false,
        },
    }
}

impl Origin {
    /// Classify from the event name (`GITHUB_EVENT_NAME`) and the parsed event
    /// payload (`GITHUB_EVENT_PATH`).
    ///
    /// A PR-family event is [`Origin::Repository`] only when
    /// `pull_request.head.repo` and `pull_request.base.repo` can be shown to be
    /// the same repository. Everything else — no `pull_request` object, a null
    /// `head.repo` (a deleted fork), a missing or non-numeric id with no usable
    /// name to fall back on — is [`Origin::Fork`].
    ///
    /// `pull_request_review` and `pull_request_review_comment` are judged the
    /// same way: both payloads carry the `pull_request` object, so a comment on
    /// a same-repository pull request is [`Origin::Repository`].
    ///
    /// `pull_request_target` is judged by the same rule as `pull_request`: it
    /// runs the base's workflow with the base's secrets, but the code it builds
    /// is still the head's, so a cross-repo head is a fork.
    ///
    /// Any other event (`push`, `workflow_dispatch`, `schedule`, `merge_group`,
    /// `issue_comment`, …) is [`Origin::Repository`] whatever its payload says:
    /// the run executes a ref of this repository. A workflow that then checks out
    /// a PR head itself is not something this classification can see. Those four
    /// events are all the pull-request-family events GitHub has; an event
    /// outside the list is trusted as this repository's, so a new PR-family
    /// event would have to be added to it before it was judged by the head.
    ///
    /// `head.repo.fork` is deliberately never read: it is `true` for a same-repo
    /// pull request whose *base* repository is itself a fork.
    pub fn of(event_name: &str, payload: &serde_json::Value) -> Self {
        if !is_pull_request_event(event_name) {
            return Origin::Repository;
        }
        let head = payload.pointer("/pull_request/head/repo");
        let base = payload.pointer("/pull_request/base/repo");
        match (head, base) {
            (Some(head), Some(base)) if same_repository(head, base) => Origin::Repository,
            _ => Origin::Fork,
        }
    }

    /// Whether a run from this origin may resolve secrets. Fork → false.
    pub fn may_read_secrets(self) -> bool {
        matches!(self, Origin::Repository)
    }

    /// Whether a run from this origin may run apply/destroy steps (or request
    /// an approval to). Fork → false.
    pub fn may_apply(self) -> bool {
        matches!(self, Origin::Repository)
    }

    /// Check only: plan/check steps run, nothing is applied and no secret
    /// resolves. Fork → true.
    pub fn check_only(self) -> bool {
        matches!(self, Origin::Fork)
    }
}
