//! Slack: a message with Approve and Deny buttons, and the identity mapping that
//! makes a button press mean something.
//!
//! Two rules hold the module together. **A Slack user is identified by their
//! immutable Slack ids, never by a name** — `team.id` and `user.id` are assigned by
//! Slack and cannot be edited by the account holder, while every display name is
//! text that holder may change at will, so renaming yourself to a colleague decides
//! nothing and the same id in another workspace is a key with no entry. **Nothing
//! reaches the store unverified** — `handle_interaction` takes the raw request and
//! verifies it itself, so no caller can skip that to reach the store.
//!
//! The buttons carry a hash of the digests *as displayed* rather than the digests:
//! the value stays well inside Slack's size cap however much the run approved, and
//! an answer binds the store's artifacts only while that hash still describes them.

use std::collections::BTreeMap;
use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use ks_core::ports::approval::{
    ApprovalError, ApprovalRequest, Artifact, Identity, Outcome, Ticket, Verdict,
};
use sha2::{Digest as _, Sha256};

use crate::{Channel, Decision, HostedApprovals, artifact_field, hex, kind_label, unhex};

/// Slack's signing scheme: HMAC-SHA256 over `v0:{timestamp}:{body}`, hex, with a
/// `v0=` prefix. <https://api.slack.com/authentication/verifying-requests-from-slack>
const SIGNATURE_VERSION: &str = "v0";

/// How far a request's timestamp may be from ours: Slack's own recommendation, and
/// what stops a captured signature being replayed.
const MAX_SIGNATURE_AGE: i64 = 300;

/// Why Slack could not be understood or trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackError {
    /// A header or the payload was not what Slack says it is.
    Malformed(String),
    /// No signing secret is configured, so every request would verify.
    NoSigningSecret,
    /// Older — or dated ahead — by more than the freshness window, in seconds.
    Stale { skew_seconds: i64 },
    /// The signature did not verify, or was not a `v0=` one.
    BadSignature,
    /// Nobody maps this Slack account to a GitHub identity in this workspace; the
    /// ids from the payload that were not.
    UnmappedUser { team_id: String, user_id: String },
    /// The pressed button was neither approve nor deny.
    UnknownAction(String),
    /// The store refused the decision: unknown ticket, or already answered.
    Refused(ApprovalError),
}

impl fmt::Display for SlackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlackError::Malformed(detail) => write!(f, "the Slack request is unreadable: {detail}"),
            SlackError::NoSigningSecret => write!(f, "no Slack signing secret is configured"),
            SlackError::Stale { skew_seconds } => {
                write!(f, "the Slack request is {skew_seconds}s from now, outside the window")
            }
            SlackError::BadSignature => write!(f, "the Slack signature did not verify"),
            SlackError::UnmappedUser { team_id, user_id } => write!(
                f,
                "Slack user {user_id} in workspace {team_id} is not mapped to a GitHub identity, \
                 so it cannot approve anything"
            ),
            SlackError::UnknownAction(id) => write!(f, "{id:?} is not an approval button"),
            SlackError::Refused(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SlackError {}

/// Checks a request's signature and freshness. `now_unix` is the caller's clock,
/// in seconds, so the check is testable and the adapter reads none. A `v1=`
/// signature is refused rather than reinterpreted, and a stale one even when its
/// HMAC is good.
fn verify_request(
    signing_secret: &[u8],
    timestamp: &str,
    body: &[u8],
    signature_header: &str,
    now_unix: i64,
) -> Result<(), SlackError> {
    if signing_secret.is_empty() {
        return Err(SlackError::NoSigningSecret);
    }
    let sent = timestamp
        .parse::<i64>()
        .map_err(|_| SlackError::Malformed(format!("{timestamp:?} is not a Unix timestamp")))?;
    // A timestamp is attacker-chosen, so the subtraction may not fit; a skew we
    // cannot compute is certainly outside the window, never inside it.
    let skew = now_unix.checked_sub(sent).map_or(i64::MAX, i64::abs);
    if skew > MAX_SIGNATURE_AGE {
        return Err(SlackError::Stale { skew_seconds: skew });
    }
    let offered = signature_header.strip_prefix("v0=").ok_or(SlackError::BadSignature)?;
    let offered = unhex(offered).ok_or(SlackError::BadSignature)?;

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(signing_secret)
        .expect("HMAC-SHA256 takes a key of any length");
    mac.update(format!("{SIGNATURE_VERSION}:{timestamp}:").as_bytes());
    mac.update(body);
    // The crate's constant-time compare: a mismatch leaks no position.
    mac.verify_slice(&offered).map_err(|_| SlackError::BadSignature)
}

/// Which GitHub identity each Slack account is, keyed by immutable ids — a pair
/// that survives a rename. An empty mapping can approve nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlackIdentities {
    handles: BTreeMap<(String, String), String>,
}

impl SlackIdentities {
    /// Maps one Slack account to a GitHub login, builder-style.
    #[must_use]
    pub fn with(
        mut self,
        team_id: impl Into<String>,
        user_id: impl Into<String>,
        github_login: impl Into<String>,
    ) -> SlackIdentities {
        self.handles.insert((team_id.into(), user_id.into()), github_login.into());
        self
    }

    /// The GitHub login this Slack account is, if mapped *in this workspace*.
    pub fn get(&self, team_id: &str, user_id: &str) -> Option<&str> {
        self.handles.get(&(team_id.to_string(), user_id.to_string())).map(String::as_str)
    }
}

/// The Block Kit message for `request`: the summary, the digests, and two
/// buttons whose value names the ticket and a hash of the artifacts as displayed.
#[must_use]
pub fn message(request: &ApprovalRequest, ticket: &Ticket) -> serde_json::Value {
    let text = |body: String| serde_json::json!({ "type": "mrkdwn", "text": body });
    let digests: Vec<serde_json::Value> = request
        .artifacts
        .iter()
        .map(|a| text(format!("*{}* — `{}`", mrkdwn(&kind_label(&a.kind)), a.digest)))
        .collect();
    let value = serde_json::json!({
        "ticket": ticket.as_str(),
        "digest": fingerprint(&request.artifacts),
    })
    .to_string();
    let button = |label: &str, action_id: &str, style: &str| {
        serde_json::json!({
            "type": "button",
            "text": { "type": "plain_text", "text": label },
            "style": style,
            "action_id": action_id,
            "value": value,
        })
    };

    serde_json::json!({
        "text": format!("Approval needed: {} on run {}", mrkdwn(&request.step), request.run),
        "blocks": [
            { "type": "section", "text": text(format!(
                "{}\nRun `{}` — {} — proposed by `{}` — any member of `{}`",
                mrkdwn(&request.summary),
                request.run,
                mrkdwn(&request.reason),
                mrkdwn(&request.proposed_by.handle),
                request.from)) },
            { "type": "section", "fields": digests },
            { "type": "actions", "block_id": format!("approval:{ticket}"), "elements": [
                button("Approve", "approve", "primary"),
                button("Deny", "deny", "danger"),
            ] },
        ],
    })
}

/// Records the decision in a Slack `block_actions` request. The raw request is
/// the input and the signature is checked here, so this is the only route from
/// Slack to the store: one that fails to verify, or names somebody unmapped,
/// records nothing.
pub fn handle_interaction(
    store: &HostedApprovals,
    identities: &SlackIdentities,
    signing_secret: &[u8],
    timestamp: &str,
    signature_header: &str,
    body: &[u8],
    now_unix: i64,
) -> Result<Verdict, SlackError> {
    verify_request(signing_secret, timestamp, body, signature_header, now_unix)?;
    let malformed = SlackError::Malformed;
    let payload: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| malformed(error.to_string()))?;

    // The whole point: identity comes from these two immutable ids alone.
    let team_id =
        string_at(&payload, "team", "id").ok_or_else(|| malformed("no team.id".into()))?;
    let user_id =
        string_at(&payload, "user", "id").ok_or_else(|| malformed("no user.id".into()))?;
    let approver = identities
        .get(&team_id, &user_id)
        .ok_or(SlackError::UnmappedUser { team_id, user_id })?
        .to_string();

    let action = payload
        .get("actions")
        .and_then(serde_json::Value::as_array)
        .and_then(|actions| actions.first())
        .ok_or_else(|| malformed("no actions[0]".into()))?;
    let outcome = match action.get("action_id").and_then(serde_json::Value::as_str) {
        Some("approve") => Outcome::Approved,
        Some("deny") => Outcome::Refused,
        Some(other) => return Err(SlackError::UnknownAction(other.to_string())),
        None => return Err(malformed("actions[0] has no action_id".into())),
    };
    let button: serde_json::Value = action
        .get("value")
        .and_then(serde_json::Value::as_str)
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| malformed(error.to_string()))?
        .ok_or_else(|| malformed("the button carries no value".into()))?;
    let field =
        |name: &str| button[name].as_str().ok_or_else(|| malformed(format!("no {name} in it")));
    let ticket = Ticket::new(field("ticket")?.to_string());
    let offered = field("digest")?;
    // The digests bound are the store's, and only while the button still
    // describes them: anything else binds nothing, so `accepts` refuses the
    // verdict rather than releasing a run over digests nobody saw.
    let shown = store
        .pending(&ticket)
        .filter(|request| fingerprint(&request.artifacts) == offered)
        .map(|request| request.artifacts)
        .unwrap_or_default();

    store
        .decide(&ticket, Decision::new(Identity::human(approver), outcome, shown, Channel::Slack))
        .map_err(SlackError::Refused)
}

/// `value[key][inner]`, if it is a string.
fn string_at(value: &serde_json::Value, key: &str, inner: &str) -> Option<String> {
    value.get(key)?.get(inner)?.as_str().map(str::to_string)
}

/// Hex sha256 over the artifact list in order: what a button carries instead of
/// the list, so it cannot outgrow Slack's limit on a button value.
fn fingerprint(artifacts: &[Artifact]) -> String {
    let mut hasher = Sha256::new();
    for artifact in artifacts {
        hasher.update(artifact_field(artifact).as_bytes());
        hasher.update(b"\n");
    }
    hex(&hasher.finalize())
}

/// Slack's own escaping: `&`, `<` and `>` would otherwise let run-written text
/// raise a channel, a tag or a link. The ampersand goes first, so an escape is
/// never itself escaped again.
fn mrkdwn(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
