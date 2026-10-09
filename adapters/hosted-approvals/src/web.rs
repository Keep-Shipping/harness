//! The web review page: what a person reads, and what pressing a button means.
//!
//! Three rules hold the module together. **The approver is the session, never the
//! form** — a [`GitHubSession`] is minted by the venture's GitHub sign-in, and
//! [`submit`] takes the approver from [`GitHubSession::login`] alone, so there is
//! no field a form could put somebody else's name in. **The answer is bound to
//! this session by a token** — a stateless HMAC over the ticket and the login, so
//! a form fetched elsewhere cannot be posted here to approve under the reader's
//! identity. **The verdict binds what the page showed** — every digest is
//! rendered into a hidden field and parsed back on submit, so a plan that moved
//! between render and press fails `ApprovalRequest::accepts`.
//!
//! Membership is not checked here: that is the engine's rule. Everything
//! interpolated into the page is escaped, because a summary is whatever the run
//! put in it and a page that renders it raw is an XSS hole with an approve button
//! beside it.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use ks_core::built_with;
use ks_core::ports::approval::{
    ApprovalError, ApprovalRequest, Artifact, Identity, Outcome, Ticket, Verdict,
};
use sha2::Sha256;

use crate::{
    Channel, Decision, HostedApprovals, artifact_field, artifact_from_field, hex, kind_label, unhex,
};

/// A sign-in that GitHub vouched for. Only the venture's OAuth exchange may
/// construct one: one that did not come from GitHub is a way to approve runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubSession {
    /// The GitHub login the session was issued for, e.g. `ada`.
    pub login: String,
}

impl GitHubSession {
    /// The session GitHub sign-in established for `login`.
    pub fn new(login: impl Into<String>) -> GitHubSession {
        GitHubSession { login: login.into() }
    }
}

/// The fields a submitted review form carries: what the handler parses its
/// request into. No approver — only the outcome, the comment, the digests and the
/// token, none of which says who decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewForm {
    /// The ticket the page was rendered for.
    pub ticket: String,
    /// `approve` or `deny`.
    pub outcome: String,
    /// The comment box, empty meaning none.
    pub comment: String,
    /// One field per artifact the page showed.
    pub shown: Vec<String>,
    /// The form token minted for this session and ticket.
    pub token: String,
}

/// Why a review page could not be answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebError {
    /// The form was unreadable, or its token did not match this session.
    Malformed(String),
    /// The store refused the decision: unknown ticket, or already answered.
    Refused(ApprovalError),
}

impl fmt::Display for WebError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WebError::Malformed(reason) => write!(f, "the review form is unreadable: {reason}"),
            WebError::Refused(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for WebError {}

/// The review page for `request`: the plain-terms summary, the reason, the exact
/// digests, and a form that approves or denies with a comment. The digests are
/// shown in the body *and* carried in hidden fields — an approver compares them
/// against the forge, and the hidden copy is what binds the answer.
pub fn review_page(
    request: &ApprovalRequest,
    ticket: &Ticket,
    session: &GitHubSession,
    key: &[u8],
) -> Result<String, WebError> {
    // Shown for a human to check against the forge, and hidden for the verdict
    // to bind to.
    let mut listed = String::new();
    let mut hidden = String::new();
    for artifact in &request.artifacts {
        listed.push_str(&format!(
            "<li><code>{kind}</code> <code>{digest}</code></li>\n",
            kind = escape(&kind_label(&artifact.kind)),
            digest = escape(&artifact.digest.to_string()),
        ));
        hidden.push_str(&format!(
            "<input type=\"hidden\" name=\"artifact\" value=\"{}\">\n",
            escape(&artifact_field(artifact)),
        ));
    }

    // Everything the run controls, escaped once, before it reaches the page.
    let step = escape(&request.step);
    let run = escape(&request.run.to_string());
    let (reason, proposer, team, summary) = (
        escape(&request.reason),
        escape(&request.proposed_by.handle),
        escape(&request.from.to_string()),
        escape(&request.summary),
    );
    let id = escape(ticket.as_str());
    let token =
        escape(&hex(&form_mac(key, ticket.as_str(), &session.login)?.finalize().into_bytes()));
    Ok(format!(
        "<!doctype html>\n<html lang=\"en\">\n\
<head><meta charset=\"utf-8\"><title>Approve {step} on {run}</title></head>\n<body>\n\
<h1>Approve <code>{step}</code></h1>\n\
<p class=\"reason\">Reason: {reason}</p>\n\
<p class=\"run\">Run <code>{run}</code>, proposed by <code>{proposer}</code>, approved by any \
member of <code>{team}</code>.</p>\n\
<h2>What you are approving</h2>\n<pre class=\"summary\">{summary}</pre>\n\
<h2>Artifacts</h2>\n<ul class=\"artifacts\">\n{listed}</ul>\n\
<form method=\"post\" action=\"/approvals/{id}/answer\">\n\
<input type=\"hidden\" name=\"ticket\" value=\"{id}\">\n\
<input type=\"hidden\" name=\"token\" value=\"{token}\">\n{hidden}\
<label for=\"comment\">Comment</label>\n\
<textarea id=\"comment\" name=\"comment\" rows=\"4\"></textarea>\n\
<button type=\"submit\" name=\"outcome\" value=\"approve\">Approve</button> \
<button type=\"submit\" name=\"outcome\" value=\"deny\">Deny</button>\n\
</form>\n{about}\
</body>\n</html>\n",
        about = about_html(),
    ))
}

/// The quiet "Built with" section at the foot of the review page
/// ([#178](https://github.com/Keep-Shipping/harness/issues/178)): the sister
/// ventures and third parties the product runs on, each labelled live or
/// planned exactly as the Factory Zero registry says, and the subprocessors
/// list it publishes. Vendored into `ks-core`, so rendering fetches nothing.
fn about_html() -> String {
    let entries = built_with::venture()
        .uses
        .iter()
        .map(|u| {
            format!(
                "<a href=\"{url}\" rel=\"noopener noreferrer\">{name}</a> ({status})",
                url = escape(&u.url),
                name = escape(&u.name),
                status = u.status.as_str(),
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "<h2>Built with</h2>\n\
<p class=\"built-with\">{entries}</p>\n\
<p class=\"subprocessors\">Subprocessors: \
<a href=\"{subprocessors}\" rel=\"noopener noreferrer\">factory0.ventures/ventures/keep-shipping/</a></p>\n",
        entries = entries,
        subprocessors = escape(built_with::SUBPROCESSORS_URL),
    )
}

/// Records `form` as the answer `session` gave to `ticket`. The approver is
/// [`GitHubSession::login`] and nothing else, and the form's token must be the one
/// this session and ticket would mint: a form fetched under another session — or
/// with any key — records nothing.
pub fn submit(
    store: &HostedApprovals,
    session: &GitHubSession,
    form: &ReviewForm,
    key: &[u8],
) -> Result<Verdict, WebError> {
    if !token_matches(key, &form.ticket, &session.login, &form.token) {
        return Err(WebError::Malformed("the form token is not this session's".to_string()));
    }
    let outcome = match form.outcome.as_str() {
        "approve" | "approved" => Outcome::Approved,
        "deny" | "denied" => Outcome::Refused,
        other => return Err(WebError::Malformed(format!("{other:?} is not approve or deny"))),
    };
    let shown = form
        .shown
        .iter()
        .map(|field| artifact_from_field(field).map_err(WebError::Malformed))
        .collect::<Result<Vec<Artifact>, WebError>>()?;

    let mut decision =
        Decision::new(Identity::human(session.login.clone()), outcome, shown, Channel::Web);
    decision.comment = match form.comment.trim() {
        "" => None,
        comment => Some(comment.to_string()),
    };
    store.decide(&Ticket::new(form.ticket.clone()), decision).map_err(WebError::Refused)
}

/// The HMAC behind the form token: over `ticket` and `login`, and so needing no
/// store — a page renders from the ticket and the session alone — and unforgeable
/// without `key`. Stateless, so there is nothing to expire or look up; the ticket
/// it names expires on its own.
fn form_mac(key: &[u8], ticket: &str, login: &str) -> Result<Hmac<Sha256>, WebError> {
    if key.is_empty() {
        return Err(WebError::Malformed("no form key is configured".to_string()));
    }
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    // A NUL separator, so no ticket and login pair can be spelled two ways.
    mac.update(ticket.as_bytes());
    mac.update(b"\0");
    mac.update(login.as_bytes());
    Ok(mac)
}

/// Whether `offered` is the token for `ticket` and `login`, compared through the
/// HMAC's own constant-time check so a wrong token leaks no position. An
/// unreadable one fails the same way a wrong one does.
fn token_matches(key: &[u8], ticket: &str, login: &str, offered: &str) -> bool {
    let (Ok(mac), Some(offered)) = (form_mac(key, ticket, login), unhex(offered)) else {
        return false;
    };
    mac.verify_slice(&offered).is_ok()
}

/// Escapes the five characters that can break out of an HTML attribute or text
/// node, and no more. The ampersand goes first, so an escape is never itself
/// escaped again.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    use ks_core::built_with::Status;
    use ks_core::ports::approval::Team;

    /// The section names every use, links it, and labels it with the status
    /// the registry gave it — never the other word — and points at the
    /// subprocessors list.
    #[test]
    fn the_about_section_names_links_and_labels_every_use() {
        let html = about_html();
        for u in &built_with::venture().uses {
            let entry = format!(
                "<a href=\"{}\" rel=\"noopener noreferrer\">{}</a> ({})",
                escape(&u.url),
                escape(&u.name),
                u.status.as_str()
            );
            assert!(html.contains(&entry), "{}: {html}", u.name);
            let other = match u.status {
                Status::Live => "planned",
                Status::Planned => "live",
            };
            // The label sits in the same anchor tail, so checking the entry's
            // own rendered form above already binds it; this catches a second
            // stray copy of the other word slipping in.
            let tail = &html[html.find(&entry).expect("found above") + entry.len()..];
            let next_entry = tail.find("<a href=").map(|at| &tail[..at]).unwrap_or(tail);
            assert!(!next_entry.contains(&format!("({other})")), "{}: {tail}", u.name);
        }
        assert!(html.contains("<h2>Built with</h2>"), "{html}");
        assert!(
            html.contains(&format!(
                "Subprocessors: <a href=\"{}\" rel=\"noopener noreferrer\">\
                 factory0.ventures/ventures/keep-shipping/</a>",
                escape(built_with::SUBPROCESSORS_URL)
            )),
            "{html}"
        );
    }

    /// The section travels with the page, after the form and before the page
    /// closes.
    #[test]
    fn the_review_page_carries_the_about_section() {
        let request = ApprovalRequest {
            run: ks_core::ids::RunId::from_parts(1_700_000_000_000, 7),
            step: "apply-infra".to_string(),
            summary: "3 to create, 1 to destroy".to_string(),
            artifacts: Vec::new(),
            from: Team::parse("@acme-deployers").expect("a well-formed team handle"),
            reason: "production deploy".to_string(),
            proposed_by: Identity::human("ada"),
        };
        let ticket = Ticket::new("t-1".to_string());
        let page = review_page(&request, &ticket, &GitHubSession::new("grace"), b"key")
            .expect("the host has a form key");
        assert!(page.contains("<h2>Built with</h2>"), "{page}");
        // After the form, before the body closes.
        let form = page.find("</form>").expect("the form");
        let about = page.find("<h2>Built with</h2>").expect("the section");
        let body_close = page.find("</body>").expect("the body close");
        assert!(form < about && about < body_close, "{page}");
    }
}
