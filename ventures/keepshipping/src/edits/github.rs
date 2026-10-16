//! The GitHub half of the edits module: the two things the outbox does to
//! the infra repository — open a pull request with the generated files, and
//! fire the `repository_dispatch` that tells the repository's workflow an
//! approved plan may be applied. Plain REST over the [`HttpClient`] port,
//! the same Bearer/`x-github-api-version` conversation
//! `crate-module-approvals` speaks; the API base is configurable so tests
//! (and self-hosted enterprises) point elsewhere.

use cratefield_core::axum::http::{Method, Request, StatusCode, header};
use cratefield_core::{HttpClient, HttpPolicy};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// The public REST root.
pub(crate) const API_BASE: &str = "https://api.github.com";

/// Response ceiling per call, matching the approvals module.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Timeout per call.
const TIMEOUT: Duration = Duration::from_secs(10);

/// A GitHub API failure, and whether retrying can possibly help. 4xx (less
/// 408 and 429) is permanent — the payload itself is wrong; transport
/// trouble, 5xx and rate limits are not.
pub(crate) struct Failure {
    pub reason: String,
    pub permanent: bool,
    /// GitHub refused the call as `403` or `404`: the token cannot see or
    /// change this, which another connection might.
    pub refused: bool,
}

impl Failure {
    pub(crate) fn permanent(reason: impl Into<String>) -> Failure {
        Failure { reason: reason.into(), permanent: true, refused: false }
    }
    pub(crate) fn retryable(reason: impl Into<String>) -> Failure {
        Failure { reason: reason.into(), permanent: false, refused: false }
    }

    /// Classifies a transport error or a response status: 4xx (less 408 and
    /// 429) is permanent, everything else worth another try.
    fn of(kind: &str, status: StatusCode, body: &str) -> Failure {
        let snippet: String = body.chars().take(300).collect();
        let reason = format!("{kind} answered {status}: {snippet}");
        let code = status.as_u16();
        let refused = code == 403 || code == 404;
        if status.is_server_error() || code == 408 || code == 429 {
            Failure::retryable(reason)
        } else {
            Failure { refused, ..Failure::permanent(reason) }
        }
    }
}

impl From<cratefield_core::HttpError> for Failure {
    fn from(error: cratefield_core::HttpError) -> Failure {
        Failure::retryable(format!("the request to GitHub failed: {error}"))
    }
}

/// The pull request an edit's branch ended up as.
pub(crate) struct Pull {
    pub number: u64,
    pub url: String,
    pub head_sha: String,
}

/// A thin GitHub REST client, shared by both outbox topics.
pub(crate) struct GitHub {
    http: Arc<dyn HttpClient>,
    token: String,
    base: String,
}

impl GitHub {
    pub(crate) fn new(http: Arc<dyn HttpClient>, token: String, base: String) -> GitHub {
        GitHub { http, token, base }
    }

    /// One authenticated call; the policy caps the response so a runaway
    /// diff cannot eat the Worker's memory.
    async fn send(
        &self,
        method: Method,
        url: &str,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value), Failure> {
        let builder = Request::builder()
            .method(method)
            .uri(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(header::ACCEPT, "application/vnd.github+json")
            .header(header::USER_AGENT, "keepshipping-waitlist (edits)")
            .header("x-github-api-version", "2022-11-28")
            .extension(HttpPolicy { max_response_bytes: MAX_RESPONSE_BYTES, timeout: TIMEOUT });
        let request = if let Some(body) = body.as_ref() {
            builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(cratefield_core::axum::body::Bytes::from(body.to_string()))
                .expect("a request with a body")
        } else {
            builder.body(cratefield_core::axum::body::Bytes::new()).expect("a request")
        };
        let (status, bytes) = {
            let response = self.http.send(request).await?;
            (response.status(), response.into_body())
        };
        let text = String::from_utf8_lossy(&bytes);
        let parsed = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).map_err(|_| {
                Failure::retryable(format!("GitHub answered {status} with non-JSON"))
            })?
        };
        Ok((status, parsed))
    }

    /// Whether a non-2xx answer is worth turning into a [`Failure`].
    fn check(status: StatusCode, body: &Value, what: &str) -> Result<(), Failure> {
        if status.is_success() {
            return Ok(());
        }
        Err(Failure::of(what, status, &body_to_text(body)))
    }

    /// The head commit of a branch: `GET /repos/{repo}/git/ref/heads/{branch}`.
    pub(crate) async fn ref_sha(&self, repo: &str, branch: &str) -> Result<String, Failure> {
        let url = format!("{}/repos/{}/git/ref/heads/{}", self.base, repo, escape(branch));
        let (status, body) = self.send(Method::GET, &url, None).await?;
        Self::check(status, &body, "reading the branch")?;
        body.pointer("/object/sha")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Failure::retryable("the branch answer carried no head sha".to_owned()))
    }

    /// Creates the edit branch; `422` (a branch a previous attempt already
    /// created) is success, since at-least-once delivery replays.
    pub(crate) async fn create_ref(
        &self,
        repo: &str,
        branch: &str,
        sha: &str,
    ) -> Result<(), Failure> {
        let url = format!("{}/repos/{}/git/refs", self.base, repo);
        let payload = json!({"ref": format!("refs/heads/{branch}"), "sha": sha});
        let (status, body) = self.send(Method::POST, &url, Some(payload)).await?;
        if status == StatusCode::UNPROCESSABLE_ENTITY {
            return Ok(());
        }
        Self::check(status, &body, "creating the branch")
    }

    /// The existing blob sha of a file on a branch, or `None` when the file
    /// is new. The contents PUT needs it to overwrite.
    pub(crate) async fn blob_sha(
        &self,
        repo: &str,
        path: &str,
        branch: &str,
    ) -> Result<Option<String>, Failure> {
        let url = format!(
            "{}/repos/{}/contents/{}?ref={}",
            self.base,
            repo,
            escape(path),
            escape(branch)
        );
        let (status, body) = self.send(Method::GET, &url, None).await?;
        match status {
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::OK => Ok(body.get("sha").and_then(Value::as_str).map(str::to_owned)),
            _ => {
                Self::check(status, &body, "reading the file")?;
                Ok(None)
            }
        }
    }

    /// Writes one file on the branch: `PUT /repos/{repo}/contents/{path}`.
    pub(crate) async fn put_file(
        &self,
        repo: &str,
        path: &str,
        branch: &str,
        content: &str,
        blob_sha: Option<&str>,
        message: &str,
    ) -> Result<(), Failure> {
        let url = format!("{}/repos/{}/contents/{}", self.base, repo, escape(path));
        let mut payload = json!({
            "message": message,
            "content": base64_encode(content.as_bytes()),
            "branch": branch,
        });
        if let Some(sha) = blob_sha {
            payload["sha"] = Value::from(sha);
        }
        let (status, body) = self.send(Method::PUT, &url, Some(payload)).await?;
        Self::check(status, &body, "committing the file")
    }

    /// Opens the pull request; `422` (the branch already has one) falls back
    /// to looking the open PR up, so a replayed delivery adopts it instead
    /// of failing forever.
    pub(crate) async fn create_pull(
        &self,
        repo: &str,
        branch: &str,
        base: &str,
        title: &str,
        body_text: &str,
    ) -> Result<Pull, Failure> {
        let url = format!("{}/repos/{}/pulls", self.base, repo);
        let payload = json!({
            "title": title,
            "body": body_text,
            "head": branch,
            "base": base,
        });
        let (status, body) = self.send(Method::POST, &url, Some(payload)).await?;
        if status == StatusCode::UNPROCESSABLE_ENTITY
            && let Some(pull) = self.open_pull(repo, branch).await?
        {
            return Ok(pull);
        }
        Self::check(status, &body, "opening the pull request")?;
        Ok(Pull {
            number: body.get("number").and_then(Value::as_u64).unwrap_or_default(),
            url: body.get("html_url").and_then(Value::as_str).unwrap_or_default().to_owned(),
            head_sha: body
                .pointer("/head/sha")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        })
    }

    /// The open PR from `branch`, if any.
    async fn open_pull(&self, repo: &str, branch: &str) -> Result<Option<Pull>, Failure> {
        let url = format!(
            "{}/repos/{}/pulls?head={}&state=open",
            self.base,
            repo,
            escape(&format!("{repo}:{branch}")),
        );
        let (status, body) = self.send(Method::GET, &url, None).await?;
        Self::check(status, &body, "looking up the pull request")?;
        let Some(entries) = body.as_array() else {
            return Ok(None);
        };
        Ok(entries.first().map(|entry| Pull {
            number: entry.get("number").and_then(Value::as_u64).unwrap_or_default(),
            url: entry.get("html_url").and_then(Value::as_str).unwrap_or_default().to_owned(),
            head_sha: entry
                .pointer("/head/sha")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        }))
    }

    /// Fires the `repository_dispatch` already enveloped as
    /// `{repo, body:{event_type, client_payload}}` — the approvals module's
    /// envelope, so both modules speak one shape.
    pub(crate) async fn dispatch(&self, envelope: &str) -> Result<(), Failure> {
        let Ok(envelope) = serde_json::from_str::<Value>(envelope) else {
            return Err(Failure::permanent("the dispatch payload is not JSON".to_owned()));
        };
        let repo = envelope
            .get("repo")
            .and_then(Value::as_str)
            .ok_or_else(|| Failure::permanent("the dispatch payload names no repo".to_owned()))?;
        let url = format!("{}/repos/{}/dispatches", self.base, repo);
        let body = envelope.get("body").cloned().unwrap_or(Value::Null);
        let (status, body) = self.send(Method::POST, &url, Some(body)).await?;
        Self::check(status, &body, "firing the repository dispatch")
    }
}

/// Percent-escapes a path segment (branch names carry `/`; the contents and
/// ref endpoints want it `%2F`).
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn body_to_text(body: &Value) -> String {
    if body.is_null() { String::new() } else { body.to_string() }
}

/// Standard base64 (with padding), alphabet standard.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The whole open-a-PR conversation for one outbox record: branch off the
/// base's head, commit the files, open the pull request. Returns the pull
/// request's number, page and head sha for the `edits` row.
pub(crate) async fn open_pr(
    github: &GitHub,
    repo: &str,
    branch: &str,
    base: &str,
    title: &str,
    body_text: &str,
    files: &[(String, String)],
) -> Result<Pull, Failure> {
    let sha = github.ref_sha(repo, base).await?;
    github.create_ref(repo, branch, &sha).await?;
    let commit_message = format!("{title}\n\nAdded by Keep Shipping; see the pull request.");
    for (path, content) in files {
        let blob_sha = github.blob_sha(repo, path, branch).await?;
        github.put_file(repo, path, branch, content, blob_sha.as_deref(), &commit_message).await?;
    }
    github.create_pull(repo, branch, base, title, body_text).await
}

/// Builds the `repository_dispatch` envelope: `repo` plus the
/// `{event_type, client_payload}` body the workflow filters on.
pub(crate) fn dispatch_envelope(repo: &str, event_type: &str, client_payload: Value) -> String {
    json!({
        "repo": repo,
        "body": {
            "event_type": event_type,
            "client_payload": client_payload,
        },
    })
    .to_string()
}
