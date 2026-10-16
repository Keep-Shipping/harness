//! The GitHub App's webhook: `POST /console/github/webhook`, the one request
//! GitHub sends the console on its own.
//!
//! Every delivery is checked before it is read: the body is capped, and the
//! `X-Hub-Signature-256` header must be the HMAC-SHA256 of the body under the
//! stored webhook secret, compared in constant time. A delivery that fails
//! any check is answered and nothing else. The payload is never logged; only
//! the event's name and the status are.
//!
//! What the console acts on is installations: deleted, suspended, resumed,
//! and a repository selection that changed. The app is public, so anyone can
//! install it: a `created` delivery never adds a row. New installations are
//! recorded only by the signed-in setup callback, which verifies them with the
//! app's own key; the webhook only updates or removes rows already recorded.
//! Pull requests and workflow runs are not acted on yet; their handling
//! (updating onboarding status from the workflow's result) is still to come.

use std::sync::Arc;

use cratefield_core::Database;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;

use super::app::{self, Installation};
use crate::secrets;

/// The largest body the webhook reads. GitHub's installation and workflow
/// payloads are a few kilobytes; a megabyte is a generous ceiling.
pub const MAX_BODY: usize = 1024 * 1024;

/// Whether `header` (`sha256=<hex>`) is the HMAC-SHA256 of `body` under
/// `secret`, compared in constant time. A missing or malformed header is
/// refused.
#[must_use]
pub fn signature_is_valid(secret: &[u8], body: &[u8], header: Option<&str>) -> bool {
    let Some(hex) = header.and_then(|value| value.strip_prefix("sha256=")) else {
        return false;
    };
    let Some(expected) = decode_hex(hex) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// Lowercase or uppercase hex to bytes; `None` for an odd length or a
/// non-hex digit.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok()).collect()
}

/// What a delivery asks the console to do to its own records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Nothing to record (a ping, or an event not acted on yet).
    Nothing,
    /// Refresh an installation the console already records. An id it does not
    /// record is ignored, so a delivery can never add an installation.
    Refresh(Installation),
    /// Forget the installation with this id.
    Remove(i64),
    /// Record a new repository selection for this installation.
    Selection(i64, String),
}

#[derive(Deserialize)]
struct Delivery {
    #[serde(default)]
    action: String,
    installation: Option<DeliveryInstallation>,
}

#[derive(Deserialize)]
struct DeliveryInstallation {
    id: i64,
    account: DeliveryAccount,
    #[serde(default)]
    repository_selection: String,
}

#[derive(Deserialize)]
struct DeliveryAccount {
    login: String,
    #[serde(rename = "type", default)]
    kind: String,
}

/// The effect of one verified delivery, by its event name and body.
///
/// `installation` events suspend, resume and delete installations, and
/// refresh the ones already recorded (a `created` for an unknown id is ignored);
/// `installation_repositories` changes what an installation can see. `ping`
/// and every other event (`pull_request`, `workflow_run`, to come) change
/// nothing here.
///
/// `None` when the body is not the JSON the event needs.
pub fn effect_of(event: &str, body: &[u8]) -> Option<Effect> {
    match event {
        "installation" => {
            let delivery: Delivery = serde_json::from_slice(body).ok()?;
            let installation = delivery.installation?;
            Some(match delivery.action.as_str() {
                "created" | "unsuspend" | "new_permissions_accepted" => {
                    Effect::Refresh(Installation {
                        id: installation.id,
                        account: installation.account.login,
                        account_type: installation.account.kind,
                        selection: selection_or_default(installation.repository_selection),
                    })
                }
                "deleted" | "suspend" => Effect::Remove(installation.id),
                _ => Effect::Nothing,
            })
        }
        "installation_repositories" => {
            let delivery: Delivery = serde_json::from_slice(body).ok()?;
            Some(match delivery.installation {
                Some(installation) if !installation.repository_selection.is_empty() => {
                    Effect::Selection(installation.id, installation.repository_selection)
                }
                _ => Effect::Nothing,
            })
        }
        // TODO: `pull_request` and `workflow_run` update onboarding status once
        // the wizard reads the result of its pull request and its workflow.
        _ => Some(Effect::Nothing),
    }
}

fn selection_or_default(selection: String) -> String {
    if selection.is_empty() { "selected".to_owned() } else { selection }
}

/// Judges one delivery before anything is recorded, in the order that matters:
/// the size, then the event's name, then the signature, then the body. Returns
/// what to record, or the HTTP status to answer with: `413` for an oversized
/// body, `400` for a missing event or a body that does not parse, `401` for a
/// bad signature, `503` when there is no secret to check against.
///
/// # Errors
///
/// The HTTP status to answer with, when the delivery is refused.
pub fn judge(
    secret: Option<&[u8]>,
    event: Option<&str>,
    signature: Option<&str>,
    body: &[u8],
) -> Result<Effect, u16> {
    if body.len() > MAX_BODY {
        return Err(413);
    }
    let Some(event) = event else {
        return Err(400);
    };
    let Some(secret) = secret else {
        return Err(503);
    };
    if !signature_is_valid(secret, body, signature) {
        tracing::warn!(event, "console: a github webhook failed its signature check");
        return Err(401);
    }
    effect_of(event, body).ok_or_else(|| {
        tracing::warn!(event, "console: a verified github webhook did not parse");
        400
    })
}

/// Records one judged effect. Only rows already present are changed:
/// [`Effect::Refresh`] and [`Effect::Selection`] update by id and do nothing
/// for an unknown one.
///
/// # Errors
///
/// [`super::Failed`] when the database refuses the write.
pub async fn apply(
    db: Arc<dyn Database>,
    effect: Effect,
    stamp: &str,
) -> Result<(), super::Failed> {
    match effect {
        Effect::Nothing => Ok(()),
        Effect::Refresh(installation) => app::refresh_installation(db, &installation, stamp).await,
        Effect::Remove(id) => app::remove_installation(db, id).await,
        Effect::Selection(id, selection) => app::set_selection(db, id, &selection).await,
    }
}

/// Answers one delivery and returns its HTTP status: [`judge`], then the
/// effect is recorded. `204` when applied or ignored; `503` when the database
/// refuses the write.
pub async fn handle(
    db: Arc<dyn Database>,
    event: Option<&str>,
    signature: Option<&str>,
    body: &[u8],
    now: i64,
) -> u16 {
    let secret =
        match secrets::read_cached(db.clone(), app::WEBHOOK_SECRET, &secrets::unsealed()).await {
            Ok(secret) => secret.map(secrets::Stored::into_token),
            Err(_) => None,
        };
    let effect = match judge(secret.as_deref().map(str::as_bytes), event, signature, body) {
        Ok(effect) => effect,
        Err(status) => return status,
    };
    let stamp = app::stamp(now);
    match apply(db, effect, &stamp).await {
        Ok(()) => 204,
        Err(failed) => {
            tracing::warn!(message = failed.message, "console: a webhook could not be recorded");
            503
        }
    }
}

#[cfg(test)]
mod tests;
