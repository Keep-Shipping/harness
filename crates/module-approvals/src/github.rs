//! The two GitHub calls: is this person on that team *right now*, and tell the
//! repository what was decided. Both go through the [`HttpClient`] port, so the
//! module holds the protocol and the deployment holds the socket. Every value
//! interpolated into a URL here has been through [`crate::validate`], which is
//! what stops a `?` or a second `/` in a runner's field aiming the token at
//! another repository.

use bytes::Bytes;
use cratefield_core::axum::http;
use cratefield_core::{HttpClient, HttpError, HttpPolicy};
use std::sync::Arc;
use std::time::Duration;

/// GitHub's REST base; configurable (`APPROVALS_GITHUB_API_BASE`) for GitHub
/// Enterprise, which serves the same API from another host.
pub(crate) const API_BASE: &str = "https://api.github.com";

/// The `User-Agent` GitHub requires, saying who is calling.
const USER_AGENT: &str = "keepshipping-approvals";
const ACCEPT: &str = "application/vnd.github+json";

/// The pinned API version, so a change on GitHub's side cannot change what a
/// deployed worker parses.
const API_VERSION: &str = "2022-11-28";

/// Both calls are a single JSON document; a membership page is a few hundred
/// bytes and a dispatch returns none.
const POLICY: HttpPolicy =
    HttpPolicy { max_response_bytes: 64 * 1024, timeout: Duration::from_secs(10) };

/// A GitHub installation this module speaks for.
pub(crate) struct GitHub {
    http: Arc<dyn HttpClient>,
    token: Arc<str>,
    base: Arc<str>,
}

impl GitHub {
    /// The token never reaches a URL: it is a header, where it cannot leak into
    /// an access log or a `Referer`.
    pub(crate) fn new(http: Arc<dyn HttpClient>, token: String, base: String) -> Self {
        Self {
            http,
            token: Arc::from(token),
            base: Arc::from(base.trim_end_matches('/').to_owned()),
        }
    }

    /// One authenticated call. `body` empty for a GET.
    async fn send(
        &self,
        method: &str,
        url: String,
        body: Vec<u8>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let mut request = http::Request::builder()
            .method(method)
            .uri(url)
            .header(http::header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(http::header::ACCEPT, ACCEPT)
            .header(http::header::USER_AGENT, USER_AGENT)
            .header("x-github-api-version", API_VERSION)
            .body(Bytes::from(body))
            .expect("a GitHub request builds");
        request.extensions_mut().insert(POLICY);
        self.http.send(request).await
    }

    /// Whether `login` is an **active** member of `org/team` as of this call.
    ///
    /// The answer is three-valued on purpose. A `404` or a `pending` invitation
    /// is GitHub saying no, and the caller refuses the approver. Anything else —
    /// a transport failure, a `502`, a `429`, a token GitHub will not accept —
    /// is GitHub not answering, and the caller parks the run with a 503. Folding
    /// the second into the first would tell a reviewer their team had rejected
    /// them because of an outage.
    pub(crate) async fn membership(&self, org: &str, team: &str, login: &str) -> Membership {
        let url = format!("{}/orgs/{org}/teams/{team}/memberships/{login}", self.base);
        let response = match self.send("GET", url, Vec::new()).await {
            Ok(response) => response,
            Err(error) => return Membership::Unknown(error.to_string()),
        };
        let status = response.status();
        if status == http::StatusCode::NOT_FOUND {
            return Membership::NotMember;
        }
        if status != http::StatusCode::OK {
            return Membership::Unknown(format!(
                "GitHub answered {status} to the membership lookup"
            ));
        }
        let state = serde_json::from_slice::<serde_json::Value>(response.body())
            .ok()
            .and_then(|body| body.get("state")?.as_str().map(str::to_owned));
        match state.as_deref() {
            Some("active") => Membership::Active,
            _ => Membership::NotMember,
        }
    }
}

/// What GitHub said about a login's membership of a team.
pub(crate) enum Membership {
    Active,
    /// GitHub answered, and the answer is no.
    NotMember,
    /// GitHub could not answer. Never the same as `NotMember`.
    Unknown(String),
}

/// A dispatch that did not go out, and whether trying again could help.
pub(crate) struct DispatchFailure {
    pub reason: String,
    /// GitHub answered in a way that will not change on a retry: no such
    /// repository, no such token, a payload it refuses. Only these stop the
    /// retry loop; a `408` or a `429` is GitHub saying "later".
    pub permanent: bool,
}

/// Delivers one `repository_dispatch` to the repository named in it — the
/// destination travels with the work, so one outbox table serves every
/// repository. Only `body` goes over HTTP; GitHub documents no other top-level
/// property. `Ok(())` on any 2xx (GitHub answers `204`).
pub(crate) async fn dispatch(api: &GitHub, payload: &str) -> Result<(), DispatchFailure> {
    let fail = |why: &str, permanent: bool| DispatchFailure {
        reason: format!("the outbox payload {why}"),
        permanent,
    };
    let record: serde_json::Value =
        serde_json::from_str(payload).map_err(|_| fail("is not JSON", true))?;
    let Some(repo) = record.get("repo").and_then(serde_json::Value::as_str) else {
        return Err(fail("names no repository", true));
    };
    let Some(body) = record.get("body") else {
        return Err(fail("carries no dispatch body", true));
    };
    let url = format!("{}/repos/{repo}/dispatches", api.base);
    let encoded = serde_json::to_vec(body).map_err(|_| fail("did not re-encode", true))?;
    let response =
        api.send("POST", url, encoded).await.map_err(|error| fail(&error.to_string(), false))?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        let later = status == http::StatusCode::REQUEST_TIMEOUT
            || status == http::StatusCode::TOO_MANY_REQUESTS;
        Err(fail(&format!("GitHub answered {status}"), status.is_client_error() && !later))
    }
}
