//! `GitHubDirectory` and `GitHubApprovals`: the [`Directory`] and
//! [`ApprovalChannel`] ports over the GitHub REST API
//! ([#96](https://github.com/Keep-Shipping/harness/issues/96)).
//!
//! Both speak plain HTTP through an [`HttpClient`] and nothing else: the
//! socket, the TLS and the host allowlist belong to the client the caller hands
//! them, so this crate holds the *protocol*, not the transport. No `reqwest`,
//! no `ureq`, no service — the same [`FakeHttpClient`] every other adapter
//! tests against scripts these.
//!
//! # Invariants
//!
//! - **The ticket is the request comment's id.** A parked run writes that id
//!   down and exits; the resume job — a different GitHub Actions run — calls
//!   [`poll`](ApprovalChannel::poll) with just the ticket and recovers the
//!   request from a hidden marker in the comment, so the channel is stateless
//!   across processes ([ADR 0005](../../../docs/adr/0005-local-first-core-with-optional-hosted-services.md)).
//! - **The marker is trusted because only the token owner can post it.** The
//!   request comment is posted by this adapter's token; a comment edited by
//!   anyone else would change its body but not its id, so `poll` re-reads the
//!   current body. Injection is closed off from both sides: every
//!   user-controlled field written into the body — `summary`, `reason`, `step`,
//!   and each marker field — is stripped of `<!--` and `-->` (the marker's
//!   fields and the prose fields also lose their newlines), so none of them can
//!   open a second marker or close the real one; the summary is additionally
//!   fenced with more backticks than it contains so it cannot break out of its
//!   code fence; and [`parse_marker`] believes a body only when it carries
//!   exactly one marker.
//! - **A verdict is bound to the request's artifacts.** `poll` recovers the
//!   artifacts from the marker and returns them verbatim as the verdict's
//!   `bound_artifacts`; the engine's [`accepts`](ApprovalRequest::accepts)
//!   check refuses a verdict whose list differs by one digest.
//! - **Membership is the engine's rule, re-checked here first.** `poll` calls
//!   [`Directory::is_member`] for each answerer before minting anything, and
//!   *ignores* (with a reply) anyone who is the proposer, a bot, or off the
//!   team — including when the lookup itself fails, so a broken roster reads
//!   as "not a member" and the run stays parked rather than approved. The
//!   verdict it does return is still checked by the engine.
//! - **A command answers the newest request.** Only comments made after the
//!   most recent marker comment are considered, so an approve written for one
//!   parked request is not consumed by another's poll.
//!
//! - **Fork code is [`Origin::Fork`], whatever the workflow's trigger says.**
//!   [`Origin`] classifies a GitHub Actions run from an event name and payload,
//!   so the harness's own answer does not rest on the trigger
//!   ([#115](https://github.com/Keep-Shipping/harness/issues/115)).
//!
//! [`FakeHttpClient`]: https://docs.rs/ks-testing/latest/ks_testing/http/struct.FakeHttpClient.html

#![forbid(unsafe_code)]

pub mod fork;

pub use fork::Origin;

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ks_core::ports::BoxFuture;
use ks_core::ports::approval::{
    ApprovalChannel, ApprovalError, ApprovalRequest, Artifact, ArtifactKind, Directory,
    DirectoryError, Identity, Outcome, Team, Ticket, Verdict,
};
use ks_core::ports::clock::Clock;
use ks_core::ports::http::{HttpClient, HttpMethod, HttpRequest, HttpResponse};
use ks_core::ports::supply_chain::Digest;

const ACCEPT: &str = "application/vnd.github+json";
const API_VERSION: &str = "2022-11-28";
const DEFAULT_API_BASE: &str = "https://api.github.com";
const DEFAULT_USER_AGENT: &str = "keepshipping";
/// The hidden marker's opening, which `parse_marker` looks for. The summary is
/// stripped of `<!--`, so the only occurrence in a comment body is the real one.
const MARKER_PREFIX: &str = "<!-- keepshipping:approval v1";
const IGNORED_PREFIX: &str = "<!-- keepshipping:ignored";
const PER_PAGE: usize = 100;

/// `base` without a trailing `/`, so the `{base}/orgs/…` URLs this crate
/// builds can never contain a doubled slash.
fn api_base(base: impl Into<String>) -> String {
    base.into().trim_end_matches('/').to_string()
}

/// A bearer token, never printed.
#[derive(Clone)]
pub struct Token(String);

impl Token {
    /// A token carrying `value`.
    pub fn new(value: impl Into<String>) -> Token {
        Token(value.into())
    }
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// Builds an authenticated request. The token never leaves this function in a
/// `Debug` form: it lives only in the `Authorization` header this sets.
fn authed(token: &Token, user_agent: &str, method: HttpMethod, url: &str) -> HttpRequest {
    let mut req = HttpRequest::new(method, url);
    req.headers.push(("Authorization".to_string(), format!("Bearer {}", token.as_str())));
    req.headers.push(("Accept".to_string(), ACCEPT.to_string()));
    req.headers.push(("X-GitHub-Api-Version".to_string(), API_VERSION.to_string()));
    req.headers.push(("User-Agent".to_string(), user_agent.to_string()));
    req
}

// -- Directory ---------------------------------------------------------------

/// A [`Directory`] over GitHub team membership.
///
/// The team handle is the team **slug** (`@platform`), and the organization is
/// configured on the adapter: the port's [`Team`] handle charset excludes `/`,
/// so `@org/slug` is not a representable `Team`. `@platform` resolves to
/// `/orgs/{org}/teams/platform/…`.
pub struct GitHubDirectory {
    http: Arc<dyn HttpClient>,
    token: Token,
    api_base: String,
    org: String,
    user_agent: String,
}

impl GitHubDirectory {
    /// A directory over `org`, authenticated with `token`.
    pub fn new(http: Arc<dyn HttpClient>, token: Token, org: impl Into<String>) -> GitHubDirectory {
        GitHubDirectory {
            http,
            token,
            api_base: DEFAULT_API_BASE.to_string(),
            org: org.into(),
            user_agent: DEFAULT_USER_AGENT.to_string(),
        }
    }

    /// Overrides the API base (for GHES, e.g. `https://github.example/api/v3`).
    pub fn with_api_base(mut self, base: impl Into<String>) -> GitHubDirectory {
        self.api_base = api_base(base);
        self
    }

    /// Overrides the `User-Agent` header.
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> GitHubDirectory {
        self.user_agent = ua.into();
        self
    }

    fn membership_url(&self, team: &Team, username: &str) -> String {
        format!(
            "{}/orgs/{}/teams/{}/memberships/{}",
            self.api_base,
            self.org,
            team.handle(),
            username
        )
    }

    fn members_url(&self, team: &Team) -> String {
        format!(
            "{}/orgs/{}/teams/{}/members?per_page={PER_PAGE}",
            self.api_base,
            self.org,
            team.handle()
        )
    }

    async fn get(&self, url: &str) -> Result<HttpResponse, DirectoryError> {
        let req = authed(&self.token, &self.user_agent, HttpMethod::Get, url);
        self.http.send(req).await.map_err(|error| DirectoryError::Unavailable {
            message: format!("GitHub request failed: {error}"),
        })
    }
}

impl Directory for GitHubDirectory {
    fn members<'a>(
        &'a self,
        team: &'a Team,
    ) -> BoxFuture<'a, Result<Vec<Identity>, DirectoryError>> {
        Box::pin(async move {
            let mut out = Vec::new();
            let mut url = self.members_url(team);
            loop {
                let response = self.get(&url).await?;
                if response.status == 404 {
                    // An unknown team is an empty list, never an error — the
                    // same reading `is_member` gives a missing membership.
                    break;
                }
                if response.status != 200 {
                    return Err(DirectoryError::Unavailable {
                        message: format!(
                            "GitHub answered {} listing team members",
                            response.status
                        ),
                    });
                }
                let page: Vec<serde_json::Value> =
                    serde_json::from_slice(&response.body).map_err(|error| {
                        DirectoryError::Unavailable {
                            message: format!("unreadable members page: {error}"),
                        }
                    })?;
                let len = page.len();
                for user in page {
                    if let Some(identity) = user_identity(&user) {
                        out.push(identity);
                    }
                }
                if len < PER_PAGE {
                    break;
                }
                match next_link(&response) {
                    Some(next) => url = next,
                    None => break,
                }
            }
            out.sort_by(|left, right| left.handle.cmp(&right.handle));
            out.dedup_by(|left, right| left == right);
            Ok(out)
        })
    }

    fn is_member<'a>(
        &'a self,
        identity: &'a Identity,
        team: &'a Team,
    ) -> BoxFuture<'a, Result<bool, DirectoryError>> {
        Box::pin(async move {
            let response = self.get(&self.membership_url(team, &identity.handle)).await?;
            match response.status {
                // `state: "active"` is a member; `"pending"` is not yet.
                200 => Ok(serde_json::from_slice::<serde_json::Value>(&response.body)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("state")
                            .and_then(|state| state.as_str())
                            .map(|state| state == "active")
                    })
                    .unwrap_or(false)),
                404 => Ok(false),
                status => Err(DirectoryError::Unavailable {
                    message: format!("GitHub answered {status} for a membership lookup"),
                }),
            }
        })
    }
}

impl fmt::Debug for GitHubDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubDirectory")
            .field("api_base", &self.api_base)
            .field("org", &self.org)
            .finish_non_exhaustive()
    }
}

// -- Approvals ---------------------------------------------------------------

/// An [`ApprovalChannel`] backed by one pull request's comments.
///
/// The adapter holds a [`Directory`] for membership and an optional [`Clock`]
/// for `wait`: with a clock, `wait` polls `poll` every `poll_interval` until a
/// verdict arrives or the timeout elapses; without one, `wait` parks — it polls
/// once and returns [`ApprovalError::Undecided`] so the run writes its state,
/// exits, and a resume workflow (triggered by the approving comment) re-polls.
pub struct GitHubApprovals {
    http: Arc<dyn HttpClient>,
    token: Token,
    api_base: String,
    owner: String,
    repo: String,
    pr: u64,
    directory: Arc<dyn Directory>,
    user_agent: String,
    clock: Option<Arc<dyn Clock>>,
    poll_interval: Duration,
}

impl GitHubApprovals {
    /// An approvals channel over `owner`/`repo` pull request `pr`, using
    /// `directory` for membership.
    pub fn new(
        http: Arc<dyn HttpClient>,
        token: Token,
        owner: impl Into<String>,
        repo: impl Into<String>,
        pr: u64,
        directory: Arc<dyn Directory>,
    ) -> GitHubApprovals {
        GitHubApprovals {
            http,
            token,
            api_base: DEFAULT_API_BASE.to_string(),
            owner: owner.into(),
            repo: repo.into(),
            pr,
            directory,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            clock: None,
            poll_interval: Duration::from_secs(15),
        }
    }

    /// Overrides the API base (for GHES).
    pub fn with_api_base(mut self, base: impl Into<String>) -> GitHubApprovals {
        self.api_base = api_base(base);
        self
    }

    /// Overrides the `User-Agent` header.
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> GitHubApprovals {
        self.user_agent = ua.into();
        self
    }

    /// Enables in-process polling in `wait` via `clock`, every `interval`.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>, interval: Duration) -> GitHubApprovals {
        self.clock = Some(clock);
        self.poll_interval = interval;
        self
    }

    fn comments_url(&self) -> String {
        format!(
            "{}/repos/{}/{}/issues/{}/comments?per_page={PER_PAGE}",
            self.api_base, self.owner, self.repo, self.pr
        )
    }

    fn comment_url(&self, id: i64) -> String {
        format!("{}/repos/{}/{}/issues/comments/{id}", self.api_base, self.owner, self.repo)
    }

    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, ApprovalError> {
        self.http.send(req).await.map_err(|error| ApprovalError::Unavailable {
            message: format!("GitHub request failed: {error}"),
        })
    }

    async fn get(&self, url: &str) -> Result<HttpResponse, ApprovalError> {
        self.send(authed(&self.token, &self.user_agent, HttpMethod::Get, url)).await
    }

    async fn list_comments(&self) -> Result<Vec<Comment>, ApprovalError> {
        let mut out = Vec::new();
        let mut url = self.comments_url();
        loop {
            let response = self.get(&url).await?;
            if response.status != 200 {
                return Err(ApprovalError::Unavailable {
                    message: format!("GitHub answered {} listing PR comments", response.status),
                });
            }
            let page: Vec<serde_json::Value> =
                serde_json::from_slice(&response.body).map_err(|error| {
                    ApprovalError::Unavailable {
                        message: format!("unreadable comments page: {error}"),
                    }
                })?;
            let len = page.len();
            for entry in page {
                if let Some(comment) = parse_comment(&entry) {
                    out.push(comment);
                }
            }
            if len < PER_PAGE {
                break;
            }
            match next_link(&response) {
                Some(next) => url = next,
                None => break,
            }
        }
        Ok(out)
    }

    /// Posts `body` as a PR comment and returns its id.
    async fn post_comment(&self, body: &str) -> Result<i64, ApprovalError> {
        let url = format!(
            "{}/repos/{}/{}/issues/{}/comments",
            self.api_base, self.owner, self.repo, self.pr
        );
        let mut req = authed(&self.token, &self.user_agent, HttpMethod::Post, &url);
        req.headers.push(("Content-Type".to_string(), "application/json".to_string()));
        req.body = serde_json::to_vec(&serde_json::json!({"body": body})).map_err(|error| {
            ApprovalError::Unavailable {
                message: format!("comment body would not serialize: {error}"),
            }
        })?;
        let response = self.send(req).await?;
        if response.status != 201 {
            return Err(ApprovalError::Unavailable {
                message: format!("GitHub answered {} posting a comment", response.status),
            });
        }
        serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|value| value.get("id").and_then(|id| id.as_i64()))
            .ok_or_else(|| ApprovalError::Unavailable {
                message: "GitHub did not return a comment id".to_string(),
            })
    }
}

impl fmt::Debug for GitHubApprovals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubApprovals")
            .field("api_base", &self.api_base)
            .field("owner", &self.owner)
            .field("repo", &self.repo)
            .field("pr", &self.pr)
            .field("has_clock", &self.clock.is_some())
            .finish_non_exhaustive()
    }
}

impl ApprovalChannel for GitHubApprovals {
    fn request<'a>(
        &'a self,
        request: &'a ApprovalRequest,
    ) -> BoxFuture<'a, Result<Ticket, ApprovalError>> {
        Box::pin(async move {
            let body = comment_body(request);
            let id = self.post_comment(&body).await?;
            Ok(Ticket::new(id.to_string()))
        })
    }

    fn poll<'a>(
        &'a self,
        ticket: &'a Ticket,
    ) -> BoxFuture<'a, Result<Option<Verdict>, ApprovalError>> {
        Box::pin(async move {
            let Ok(comment_id) = ticket.as_str().parse::<i64>() else {
                return Err(ApprovalError::UnknownTicket { ticket: ticket.as_str().to_string() });
            };
            // Recover the request from its own comment, so a resume job in a
            // different process needs only the ticket.
            let response = self.get(&self.comment_url(comment_id)).await?;
            if response.status == 404 {
                return Err(ApprovalError::UnknownTicket { ticket: ticket.as_str().to_string() });
            }
            if response.status != 200 {
                return Err(ApprovalError::Unavailable {
                    message: format!(
                        "GitHub answered {} reading the request comment",
                        response.status
                    ),
                });
            }
            let body = comment_field(&response.body).ok_or_else(|| ApprovalError::Unavailable {
                message: "the request comment has no body".to_string(),
            })?;
            let parsed = parse_marker(&body).ok_or_else(|| ApprovalError::Unavailable {
                message: "the request comment has no keepshipping marker".to_string(),
            })?;

            let comments = self.list_comments().await?;
            // Which command comments already have an "ignored" reply, so we
            // never reply twice across repeated polls or processes.
            let already_replied: BTreeSet<i64> =
                comments.iter().filter_map(|comment| ignored_target(&comment.body)).collect();

            // A command belongs to the most recent request on the PR. With two
            // approvals parked, an approve written for ticket A must not be
            // consumed by ticket B's poll, so only commands *after* the newest
            // marker comment count as answers to this one.
            let newest_marker_id = comments
                .iter()
                .filter(|comment| comment.body.contains(MARKER_PREFIX))
                .map(|comment| comment.id)
                .max()
                .unwrap_or(comment_id);
            let answer_after = comment_id.max(newest_marker_id);

            for comment in comments.iter().filter(|comment| comment.id > answer_after) {
                if already_replied.contains(&comment.id) {
                    continue;
                }
                let Some(command) = parse_command(&comment.body) else { continue };
                if let Some(reason) = self.ignore_reason(comment, &parsed).await {
                    self.post_comment(&reply_body(comment, &reason)).await?;
                    continue;
                }
                // A valid answer from a human member who is not the proposer.
                let outcome = if command.approved { Outcome::Approved } else { Outcome::Refused };
                return Ok(Some(Verdict {
                    approver: Identity::human(comment.author_login.clone()),
                    at: parse_iso8601(&comment.created_at),
                    outcome,
                    comment: command.comment.clone(),
                    bound_artifacts: parsed.artifacts.clone(),
                }));
            }
            Ok(None)
        })
    }

    fn wait<'a>(
        &'a self,
        ticket: &'a Ticket,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Verdict, ApprovalError>> {
        Box::pin(async move {
            if let Some(verdict) = self.poll(ticket).await? {
                return Ok(verdict);
            }
            // No clock: park. The run writes its state, exits, and a resume
            // workflow re-polls; see docs/GITHUB_APPROVALS.md. Nothing was
            // waited for, so `after` says zero rather than claiming the
            // timeout elapsed — the caller re-polls across jobs instead.
            let Some(clock) = self.clock.clone() else {
                return Err(ApprovalError::Undecided {
                    ticket: ticket.as_str().to_string(),
                    after: Duration::ZERO,
                });
            };
            let start = clock.now();
            loop {
                clock.sleep(self.poll_interval).await;
                if let Some(verdict) = self.poll(ticket).await? {
                    return Ok(verdict);
                }
                if clock.now().duration_since(start).unwrap_or(Duration::ZERO) >= timeout {
                    return Err(ApprovalError::Undecided {
                        ticket: ticket.as_str().to_string(),
                        after: timeout,
                    });
                }
            }
        })
    }
}

impl GitHubApprovals {
    /// The reason `comment`'s command must be ignored, if any. `None` means it
    /// is a valid verdict from a human member who is not the proposer.
    async fn ignore_reason(&self, comment: &Comment, parsed: &ParsedMarker) -> Option<String> {
        if comment.author_login == parsed.proposed_by_handle {
            return Some(format!(
                "@{} proposed this change and cannot approve it.",
                comment.author_login
            ));
        }
        if comment.author_type == "Bot" {
            return Some("approvals must come from a human.".to_string());
        }
        let identity = Identity::human(comment.author_login.clone());
        match self.directory.is_member(&identity, &parsed.from).await {
            Ok(true) => None,
            Ok(false) => {
                Some(format!("@{} is not a member of {}.", comment.author_login, parsed.from))
            }
            // A lookup that failed is not a membership *yes*: it keeps the run
            // parked, so a GitHub 5xx or a token that lost `read:org` can
            // never approve anything.
            Err(error) => Some(format!(
                "@{author} is not a member of {team} (lookup failed: {error}).",
                author = comment.author_login,
                team = parsed.from
            )),
        }
    }
}

// -- comment body & marker ---------------------------------------------------

/// The visible PR comment plus the hidden marker that `poll` recovers the
/// request from.
///
/// The prose names the team exactly as the membership check reads it — the
/// [`Team`] handle on its own, with no organization in front of it. `poll`
/// asks `Directory::is_member` about `request.from` against the organization
/// the [`Directory`] was configured with, and that organization is in neither
/// the [`ApprovalRequest`] nor anything an `Arc<dyn Directory>` gives back.
/// Naming the repository owner here instead — as this did — points approvers
/// at a roster that is never consulted whenever owner != org, which is the
/// normal GitHub Enterprise Server shape.
fn comment_body(request: &ApprovalRequest) -> String {
    // Every user-controlled field that reaches the visible prose is stripped of
    // the comment delimiters here too, so it can neither open a second marker
    // nor close the real one.
    let summary = neutralize_summary(&request.summary);
    let reason = sanitize(&request.reason);
    let step = sanitize(&request.step);
    let fence = "`".repeat(max_backtick_run(&summary).max(2) + 1);
    let digests: Vec<String> =
        request.artifacts.iter().map(|artifact| artifact.digest.to_string()).collect();
    let marker = marker_for(request);
    format!(
        "## Approval needed: {reason}\n\n\
         {team} must approve this run before it can continue.\n\n\
         - Run: `{run}`\n\
         - Step: {step}\n\
         - Reason: {reason}\n\
         - Proposed by: @{proposer}\n\
         - Team: {team}\n\
         - Artifacts: {digests}\n\n\
         {fence}\n{summary}\n{fence}\n\n\
         ---\n\n\
         To approve, comment `/keepshipping approve`.\n\
         To refuse, comment `/keepshipping refuse <reason>`.\n\
         You must be a member of {team} and not the proposer.\n\n\
         {marker}",
        reason = reason,
        team = request.from,
        run = request.run,
        step = step,
        proposer = request.proposed_by.handle,
        digests = digests.join(", "),
        fence = fence,
        summary = summary,
        marker = marker,
    )
}

/// The hidden, machine-readable marker. One field per line so values may
/// contain spaces; each value is neutralised so it cannot close the comment
/// (`-->`) or open a nested one (`<!--`).
pub fn marker_for(request: &ApprovalRequest) -> String {
    let artifacts = request.artifacts.iter().map(encode_artifact).collect::<Vec<_>>().join(",");
    format!(
        "<!-- keepshipping:approval v1\n\
         run: {run}\n\
         step: {step}\n\
         from: {from}\n\
         proposed_by: {proposed_by}\n\
         artifacts: {artifacts}\n\
         -->",
        run = sanitize(&request.run.to_string()),
        step = sanitize(&request.step),
        from = sanitize(&request.from.to_string()),
        proposed_by = sanitize(&request.proposed_by.handle),
        artifacts = sanitize(&artifacts),
    )
}

/// What [`marker_for`] wrote, recovered by [`parse_marker`].
pub struct ParsedMarker {
    /// The team whose members may answer.
    pub from: Team,
    /// The proposer's handle; a command from them is ignored.
    pub proposed_by_handle: String,
    /// The artifacts the answer is bound to.
    pub artifacts: Vec<Artifact>,
}

/// Finds and parses the marker in `body`. `None` when there is none — and
/// `None` too when there is more than one, since a body that carries two
/// markers is one whose provenance cannot be established.
pub fn parse_marker(body: &str) -> Option<ParsedMarker> {
    if body.matches(MARKER_PREFIX).count() != 1 {
        return None;
    }
    let start = body.find(MARKER_PREFIX)?;
    let after = &body[start + MARKER_PREFIX.len()..];
    let end = after.find("-->")?;
    let inner = &after[..end];
    let mut from = None;
    let mut proposed_by = None;
    let mut artifacts = None;
    for line in inner.split('\n') {
        let Some((key, value)) = line.split_once(": ") else { continue };
        match key.trim() {
            "from" => from = Some(value.trim().to_string()),
            "proposed_by" => proposed_by = Some(value.trim().to_string()),
            "artifacts" => artifacts = Some(value.trim().to_string()),
            _ => {}
        }
    }
    let from = Team::parse(&from?).ok()?;
    let artifacts = parse_artifacts(&artifacts?)?;
    Some(ParsedMarker { from, proposed_by_handle: proposed_by?, artifacts })
}

fn encode_artifact(artifact: &Artifact) -> String {
    let kind = match &artifact.kind {
        ArtifactKind::PlanFile => "plan".to_string(),
        ArtifactKind::Image => "image".to_string(),
        ArtifactKind::Other(label) => format!("other:{}", base64_encode(label.as_bytes())),
    };
    format!("{}:{}", kind, artifact.digest)
}

fn parse_artifacts(value: &str) -> Option<Vec<Artifact>> {
    if value.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for entry in value.split(',') {
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() < 3 {
            return None;
        }
        let digest = format!("{}:{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        let digest = Digest::parse(&digest).ok()?;
        let kind = match parts[0] {
            "plan" => ArtifactKind::PlanFile,
            "image" => ArtifactKind::Image,
            "other" => {
                let bytes = base64_decode(parts[1])?;
                let label = String::from_utf8(bytes).ok()?;
                ArtifactKind::Other(label)
            }
            _ => return None,
        };
        out.push(Artifact::new(kind, digest));
    }
    Some(out)
}

/// The body of an idempotent "ignored" reply to `comment`.
fn reply_body(comment: &Comment, reason: &str) -> String {
    format!(
        "@{author} {reason} ([comment]({url}))\n\n{prefix} comment={id} -->",
        author = comment.author_login,
        reason = reason,
        url = comment.html_url,
        prefix = IGNORED_PREFIX,
        id = comment.id,
    )
}

/// The comment id an "ignored" reply was left for, if `body` is one.
fn ignored_target(body: &str) -> Option<i64> {
    let prefix_idx = body.find(IGNORED_PREFIX)?;
    let after = &body[prefix_idx + IGNORED_PREFIX.len()..];
    let eq = after.find("comment=")?;
    let rest = &after[eq + "comment=".len()..];
    let end = rest.find("-->").unwrap_or(rest.len());
    rest[..end].trim().parse().ok()
}

// -- parsing GitHub responses ------------------------------------------------

struct Comment {
    id: i64,
    body: String,
    author_login: String,
    author_type: String,
    created_at: String,
    html_url: String,
}

struct Command {
    approved: bool,
    comment: Option<String>,
}

/// The first line of `body`, interpreted as a command. `None` if it is not a
/// `/keepshipping` command.
fn parse_command(body: &str) -> Option<Command> {
    let line = body.lines().next()?.trim_start();
    let rest = line.strip_prefix("/keepshipping ")?;
    let approved = rest.starts_with("approve");
    let refused = rest.starts_with("refuse");
    if !approved && !refused {
        return None;
    }
    // Whatever follows the verb is the approver's note; no note, no comment.
    let arg = rest[if approved { "approve".len() } else { "refuse".len() }..].trim();
    let comment = (!arg.is_empty()).then(|| arg.to_string());
    Some(Command { approved, comment })
}

fn parse_comment(value: &serde_json::Value) -> Option<Comment> {
    Some(Comment {
        id: value.get("id").and_then(serde_json::Value::as_i64)?,
        body: value.get("body").and_then(serde_json::Value::as_str)?.to_string(),
        author_login: value.pointer("/user/login").and_then(serde_json::Value::as_str)?.to_string(),
        author_type: value
            .pointer("/user/type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("User")
            .to_string(),
        created_at: value.get("created_at").and_then(serde_json::Value::as_str)?.to_string(),
        html_url: value.get("html_url").and_then(serde_json::Value::as_str)?.to_string(),
    })
}

fn comment_field(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("body").and_then(serde_json::Value::as_str).map(str::to_string))
}

fn user_identity(value: &serde_json::Value) -> Option<Identity> {
    let handle = value.get("login").and_then(serde_json::Value::as_str)?.to_string();
    let kind = match value.get("type").and_then(serde_json::Value::as_str) {
        Some("Bot") => Identity::service(handle.clone()),
        _ => Identity::human(handle.clone()),
    };
    Some(kind)
}

/// The `rel="next"` URL in a `Link` header, if there is one.
fn next_link(response: &HttpResponse) -> Option<String> {
    let link = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("link"))
        .map(|(_, value)| value.as_str())?;
    for segment in link.split(',') {
        let segment = segment.trim();
        let Some((url_part, rel_part)) = segment.split_once(';') else { continue };
        if rel_part.trim().contains("rel=\"next\"") {
            let url = url_part.trim();
            return Some(url.trim_matches(|c| c == '<' || c == '>').to_string());
        }
    }
    None
}

// -- neutralisation ----------------------------------------------------------

/// Strips `<!--` (so a summary cannot inject a fake marker) from the prose.
fn neutralize_summary(summary: &str) -> String {
    summary.replace("<!--", "")
}

/// Strips comment delimiters and newlines from a marker field value.
fn sanitize(value: &str) -> String {
    value.replace("<!--", "").replace("-->", "").replace(['\n', '\r'], "")
}

/// The longest run of backticks in `text`, for fencing it safely.
fn max_backtick_run(text: &str) -> usize {
    let mut best = 0;
    let mut run = 0;
    for character in text.chars() {
        if character == '`' {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

/// Parses a GitHub `created_at` (`2026-10-08T12:34:56Z`) to a [`SystemTime`].
fn parse_iso8601(text: &str) -> SystemTime {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return SystemTime::UNIX_EPOCH;
    }
    let (y, mo, d) = (
        text[0..4].parse::<u32>().unwrap_or(0),
        text[5..7].parse::<u32>().unwrap_or(0),
        text[8..10].parse::<u32>().unwrap_or(0),
    );
    let (h, mi, s) = (
        text[11..13].parse::<u32>().unwrap_or(0),
        text[14..16].parse::<u32>().unwrap_or(0),
        text[17..19].parse::<u32>().unwrap_or(0),
    );
    let days = days_from_civil(y, mo, d);
    let secs = days.saturating_mul(86400) + u64::from(h) * 3600 + u64::from(mi) * 60 + u64::from(s);
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// Howard Hinnant's days-from-civil, the only date arithmetic worth keeping.
fn days_from_civil(year: u32, month: u32, day: u32) -> u64 {
    let y = if month <= 2 { year as i64 - 1 } else { year as i64 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let month = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * month as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146097 + doe as i64 - 719468) as u64
}

// -- base64 (for `Other` artifact kinds) -------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(B64[(n >> 18 & 0x3f) as usize] as char);
        out.push(B64[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6 & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 0x3f) as usize] as char } else { '=' });
    }
    out
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut bits = 0u32;
    let mut held = 0u32;
    for character in text.trim().chars() {
        if character == '=' {
            break;
        }
        let value = B64.iter().position(|c| *c as char == character)? as u32;
        held = held << 6 | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((held >> bits & 0xff) as u8);
        }
    }
    Some(out)
}
