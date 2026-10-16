//! The Workers side of the Cloudflare collector: the HTTP reads (`worker::Fetch`),
//! the D1 row that holds the sealed token, and the KV snapshot. Every
//! decision worth testing is in the parent module; what is here is the
//! wiring. A missing token, a broken row or an unreadable account is a
//! plain-words [`Failed`] and nothing is written. A refused zone, Pages or
//! Workers listing is a named gap on the page instead, so one missing
//! permission does not hide everything the token can read.
//!
//! The token is only ever in memory here, in a request header, or in the
//! sealed D1 row. It is never logged, never put in a URL and never returned.

use cratefield_core::Clock;
use cratefield_runtime_cloudflare::WorkersClock;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use time::format_description::well_known::Rfc3339;
use worker::wasm_bindgen::JsValue;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit};

use super::seal::{self, Sealed};
use super::{
    Account, AccountError, CertificatePack, Envelope, Inventory, PagesProject, Verify,
    WorkerDomain, WorkerScript, Zone, ZoneRecord, fleet_from, merge, pick_accounts,
    token_is_active,
};
use crate::fleet::Fleet;

/// The KV key the snapshot lives under (binding `FLEET`).
pub const KV_KEY: &str = "fleet.json";

const API: &str = "https://api.cloudflare.com/client/v4";
const PER_PAGE: u32 = 50;
/// A hard stop on pagination: 40 pages of 50 is 2000 items per listing.
const MAX_PAGES: u32 = 40;

/// A failure the connect and refresh pages can show: an HTTP status to
/// answer with, and what to tell the person, in plain words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failed {
    pub status: u16,
    pub message: &'static str,
}

const NETWORK: Failed =
    Failed { status: 502, message: "Could not reach Cloudflare. Try again in a moment." };
const NOT_ACCEPTED: Failed = Failed {
    status: 400,
    message: "Cloudflare did not accept this token. Check that you copied the whole token and \
              that it is still active.",
};
const NO_ACCOUNTS: Failed = Failed {
    status: 400,
    message: "This token cannot list any account. Create it from the link above so it has the \
              listed read permissions.",
};
const NOT_VISIBLE: Failed = Failed {
    status: 400,
    message: "This token cannot see the account named in CF_ACCOUNT_ID. Create the token in that \
              account, or unset CF_ACCOUNT_ID.",
};
const REFUSED: Failed = Failed {
    status: 502,
    message: "Cloudflare refused a read this token should be able to make. Check the token's \
              permissions against the list on the connect page.",
};
const SHAPE: Failed = Failed {
    status: 502,
    message: "Cloudflare answered in a shape this console does not read. Try again later.",
};
const STORE: Failed = Failed { status: 503, message: "The token could not be saved. Try again." };
const WRITE: Failed =
    Failed { status: 503, message: "The fleet snapshot could not be written. Try again." };
pub const NOT_CONNECTED: Failed =
    Failed { status: 409, message: "No Cloudflare token is connected. Connect one first." };

/// The stored row, as D1 returns it.
#[derive(Deserialize)]
struct StoredRow {
    nonce: String,
    ciphertext: String,
    updated_at: String,
}

/// What the connect page shows: when the readable token was saved, or
/// `None` when nothing is stored or it no longer opens (a rotated
/// `HARNESS_SECRET`), which reads the same to the person: connect again.
pub async fn connected_at(env: &Env, secret: &str) -> Result<Option<String>, Failed> {
    Ok(stored(env).await?.and_then(|row| {
        let sealed = Sealed { nonce: row.nonce, ciphertext: row.ciphertext };
        match seal::open(secret, &sealed) {
            Ok(_) => Some(row.updated_at),
            Err(error) => {
                tracing::warn!(?error, "console: stored Cloudflare token does not open");
                None
            }
        }
    }))
}

/// The token as stored, opened; `None` when there is none or it does not open.
async fn load_token(env: &Env, secret: &str) -> Result<Option<String>, Failed> {
    let Some(row) = stored(env).await? else {
        return Ok(None);
    };
    let sealed = Sealed { nonce: row.nonce, ciphertext: row.ciphertext };
    match seal::open(secret, &sealed) {
        Ok(token) => Ok(Some(token)),
        Err(error) => {
            tracing::warn!(?error, "console: stored Cloudflare token does not open");
            Ok(None)
        }
    }
}

async fn stored(env: &Env) -> Result<Option<StoredRow>, Failed> {
    let db = env.d1("DB").map_err(|_| STORE)?;
    db.prepare("SELECT nonce, ciphertext, updated_at FROM console_cloudflare_token WHERE id = 1")
        .first::<StoredRow>(None)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "console: reading the stored token failed");
            STORE
        })
}

async fn store(env: &Env, sealed: &Sealed, now: &str) -> Result<(), Failed> {
    let db = env.d1("DB").map_err(|_| STORE)?;
    let values = [
        JsValue::from_str(&sealed.nonce),
        JsValue::from_str(&sealed.ciphertext),
        JsValue::from_str(now),
    ];
    db.prepare(
        "INSERT INTO console_cloudflare_token (id, nonce, ciphertext, updated_at) \
         VALUES (1, ?, ?, ?) \
         ON CONFLICT(id) DO UPDATE SET nonce = excluded.nonce, \
         ciphertext = excluded.ciphertext, updated_at = excluded.updated_at",
    )
    .bind(&values)
    .map_err(|_| STORE)?
    .run()
    .await
    .map(|_| ())
    .map_err(|error| {
        tracing::warn!(%error, "console: writing the stored token failed");
        STORE
    })
}

/// One send: the status and body, with the token only in the header.
async fn send(token: &str, url: &str) -> Result<(u16, String), Failed> {
    let headers = Headers::new();
    headers.set("authorization", &format!("Bearer {token}")).map_err(|_| NETWORK)?;
    headers.set("accept", "application/json").map_err(|_| NETWORK)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let request = Request::new_with_init(url, &init).map_err(|_| NETWORK)?;
    let mut response = Fetch::Request(request).send().await.map_err(|error| {
        tracing::warn!(%error, "console: cloudflare request did not complete");
        NETWORK
    })?;
    let status = response.status_code();
    let body = response.text().await.map_err(|_| NETWORK)?;
    Ok((status, body))
}

/// One read, decoded from the v4 envelope. Only a 200 that says
/// `success: true` counts; the status alone is logged, never the body.
async fn get<T: DeserializeOwned>(token: &str, url: &str) -> Result<Envelope<T>, Failed> {
    let (status, body) = send(token, url).await?;
    if status != 200 {
        tracing::warn!(status, path = %path_of(url), "console: cloudflare refused a read");
        return Err(REFUSED);
    }
    let envelope: Envelope<T> = serde_json::from_str(&body).map_err(|_| {
        tracing::warn!(path = %path_of(url), "console: cloudflare answer not the expected shape");
        SHAPE
    })?;
    if !envelope.success {
        tracing::warn!(path = %path_of(url), "console: cloudflare answered success=false");
        return Err(REFUSED);
    }
    Ok(envelope)
}

/// The path without its query, for logs.
fn path_of(url: &str) -> &str {
    url.strip_prefix(API).unwrap_or(url).split('?').next().unwrap_or_default()
}

/// Every page of a list endpoint. With `result_info` the pages are counted;
/// without it the endpoint is read once, so a listing that ignores `page`
/// cannot repeat itself.
async fn list<T: DeserializeOwned>(token: &str, path: &str) -> Result<Vec<T>, Failed> {
    let separator = if path.contains('?') { '&' } else { '?' };
    let mut items = Vec::new();
    for page in 1..=MAX_PAGES {
        let url = format!("{API}{path}{separator}page={page}&per_page={PER_PAGE}");
        let envelope: Envelope<Vec<T>> = get(token, &url).await?;
        let total = envelope.result_info.and_then(|info| info.total_pages);
        items.extend(envelope.result.unwrap_or_default());
        match total {
            Some(total) if page < total => continue,
            _ => break,
        }
    }
    Ok(items)
}

/// A listing read once, with no `page`/`per_page`: the account-level Pages
/// and Workers listings reject paging parameters they do not take, and
/// return everything in one answer.
async fn list_all<T: DeserializeOwned>(token: &str, path: &str) -> Result<Vec<T>, Failed> {
    let envelope: Envelope<Vec<T>> = get(token, &format!("{API}{path}")).await?;
    Ok(envelope.result.unwrap_or_default())
}

/// A listing the snapshot can do without: a failure becomes a named gap
/// on the page instead of failing the whole snapshot.
fn or_gap<T>(read: Result<Vec<T>, Failed>, what: &str, gaps: &mut Vec<String>) -> Vec<T> {
    read.unwrap_or_else(|failed| {
        gaps.push(format!("{what} ({})", gap_reason(failed)));
        Vec::new()
    })
}

fn gap_reason(failed: Failed) -> &'static str {
    if failed == REFUSED {
        "Cloudflare refused it: check the token has that read permission"
    } else if failed == SHAPE {
        "Cloudflare answered in a shape this console does not read"
    } else {
        "Cloudflare could not be reached"
    }
}

/// A zone's certificate packs. A failed lookup is logged and reads as
/// unknown on the page; it does not fail the whole snapshot.
async fn certificates(token: &str, zone_id: &str) -> Option<Vec<CertificatePack>> {
    match get::<Vec<CertificatePack>>(
        token,
        &format!("{API}/zones/{zone_id}/ssl/certificate_packs"),
    )
    .await
    {
        Ok(envelope) => Some(envelope.result.unwrap_or_default()),
        Err(_) => None,
    }
}

/// Reads the account: its zones (with certificate status), Pages projects,
/// Workers scripts and their custom domains.
async fn collect(token: &str, account: Account) -> Inventory {
    let mut gaps = Vec::new();
    let zones: Vec<Zone> = or_gap(
        list(token, &format!("/zones?account.id={}", account.id)).await,
        "Zones (Zone: Read)",
        &mut gaps,
    );
    let mut records = Vec::with_capacity(zones.len());
    for zone in zones {
        let certificates = certificates(token, &zone.id).await;
        records.push(ZoneRecord { zone, certificates });
    }
    let pages: Vec<PagesProject> = or_gap(
        list_all(token, &format!("/accounts/{}/pages/projects", account.id)).await,
        "Pages projects (Cloudflare Pages: Read)",
        &mut gaps,
    );
    let scripts: Vec<WorkerScript> = or_gap(
        list_all(token, &format!("/accounts/{}/workers/scripts", account.id)).await,
        "Workers (Workers Scripts: Read)",
        &mut gaps,
    );
    let worker_domains: Vec<WorkerDomain> = or_gap(
        list_all(token, &format!("/accounts/{}/workers/domains", account.id)).await,
        "Workers custom domains (Workers Scripts: Read)",
        &mut gaps,
    );
    Inventory { account, zones: records, pages, scripts, worker_domains, gaps }
}

/// The `CF_ACCOUNT_ID` var, trimmed, blank meaning unset.
fn wanted_account(env: &Env) -> Option<String> {
    env.var("CF_ACCOUNT_ID")
        .ok()
        .map(|value| value.to_string().trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Collects with `token` and writes the snapshot to KV. The previous
/// snapshot stays until a new one is complete.
async fn write_snapshot(env: &Env, token: &str) -> Result<Fleet, Failed> {
    let accounts: Vec<Account> = list(token, "/accounts").await?;
    let picked =
        pick_accounts(&accounts, wanted_account(env).as_deref()).map_err(|error| match error {
            AccountError::NoAccounts => NO_ACCOUNTS,
            AccountError::NotVisible => NOT_VISIBLE,
        })?;
    let now = WorkersClock.now().format(&Rfc3339).map_err(|_| WRITE)?;
    let mut fleets = Vec::with_capacity(picked.len());
    for account in picked {
        fleets.push(fleet_from(&collect(token, account.clone()).await, &now));
    }
    let fleet = merge(fleets, &now);
    let json = serde_json::to_string(&fleet).map_err(|_| WRITE)?;
    env.kv("FLEET")
        .map_err(|_| WRITE)?
        .put(KV_KEY, json.as_str())
        .map_err(|_| WRITE)?
        .execute()
        .await
        .map_err(|error| {
            tracing::warn!(%error, "console: writing fleet.json failed");
            WRITE
        })?;
    Ok(fleet)
}

/// The paste: verify the token, check it can list an account, seal and
/// store it, then take the first snapshot. The snapshot's failure is logged
/// and does not undo a token that was accepted; the fleet page offers a
/// refresh.
pub async fn connect(env: &Env, secret: &str, token: &str) -> Result<(), Failed> {
    // Any answer other than a 200 with an active status is "not accepted":
    // the person's fix is the same (paste it again, or make a new one).
    let (status, body) = send(token, &format!("{API}/user/tokens/verify")).await?;
    if status != 200 {
        return Err(NOT_ACCEPTED);
    }
    let verified: Envelope<Verify> = serde_json::from_str(&body).map_err(|_| SHAPE)?;
    if !verified.success || !verified.result.as_ref().is_some_and(token_is_active) {
        return Err(NOT_ACCEPTED);
    }
    let accounts: Vec<Account> = list(token, "/accounts").await?;
    if accounts.is_empty() {
        return Err(NO_ACCOUNTS);
    }
    let sealed = seal::seal(secret, token).map_err(|_| STORE)?;
    let now = WorkersClock.now().format(&Rfc3339).map_err(|_| STORE)?;
    store(env, &sealed, &now).await?;
    if let Err(failed) = write_snapshot(env, token).await {
        tracing::warn!(message = failed.message, "console: first snapshot after connect failed");
    }
    Ok(())
}

/// Rebuilds the snapshot from the stored token. Used by the refresh button
/// and the hourly cron.
pub async fn refresh(env: &Env, secret: &str) -> Result<Fleet, Failed> {
    let token = load_token(env, secret).await?.ok_or(NOT_CONNECTED)?;
    write_snapshot(env, &token).await
}

/// Forgets the token and the snapshot it produced.
pub async fn disconnect(env: &Env) -> Result<(), Failed> {
    let db = env.d1("DB").map_err(|_| STORE)?;
    db.prepare("DELETE FROM console_cloudflare_token WHERE id = 1")
        .run()
        .await
        .map_err(|_| STORE)?;
    let kv = env.kv("FLEET").map_err(|_| WRITE)?;
    kv.delete(KV_KEY).await.map_err(|_| WRITE)?;
    Ok(())
}
