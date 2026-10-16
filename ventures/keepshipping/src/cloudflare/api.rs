//! The Workers side of the Cloudflare collector: the HTTP reads (`worker::Fetch`),
//! the token in the secrets vault (`src/secrets.rs`), and the KV snapshot.
//! Every decision worth testing is in the parent module; what is here is the
//! wiring. A missing token, a master key that is not configured, or an
//! unreadable account is a
//! plain-words [`Failed`] and nothing is written. A refused zone, Pages or
//! Workers listing is a named gap on the page instead, so one missing
//! permission does not hide everything the token can read.
//!
//! The token is only ever in memory here, in a request header, or in the
//! vault's encrypted row. It is never logged, never put in a URL and never
//! returned.

use cratefield_core::Clock;
use cratefield_runtime_cloudflare::WorkersClock;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use time::format_description::well_known::Rfc3339;
use worker::wasm_bindgen::JsValue;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit};

use super::rollback::{self, Candidate, PagesProjectLive, Panel, Target};
use super::seal;
use super::{
    Account, AccountError, CertificatePack, Envelope, Inventory, PagesDeployment, PagesProject,
    Verify, WorkerDeployments, WorkerDomain, WorkerScript, Zone, ZoneRecord, fleet_from, merge,
    pick_accounts, token_is_active,
};
use crate::fleet::{Fleet, Site};
use crate::secrets::{self, Legacy, Stored, Vault};

/// The KV key the snapshot lives under (binding `FLEET`).
pub const KV_KEY: &str = "fleet.json";

const API: &str = "https://api.cloudflare.com/client/v4";
const PER_PAGE: u32 = 50;
/// A hard stop on pagination: 40 pages of 50 is 2000 items per listing.
const MAX_PAGES: u32 = 40;
/// The preview deployments read per Pages project: one call, newest first.
/// The docs give no maximum `per_page` for this list; 25 is well inside any
/// limit and covers the five branches the snapshot keeps.
const PREVIEW_PER_PAGE: u32 = 25;

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
const NO_MASTER_KEY: Failed = Failed { status: 503, message: secrets::NO_MASTER_KEY_COPY };
const WRITE: Failed =
    Failed { status: 503, message: "The fleet snapshot could not be written. Try again." };
pub const NOT_CONNECTED: Failed =
    Failed { status: 409, message: "No Cloudflare token is connected. Connect one first." };

/// What the connect page shows: when the readable token was saved, or `None`
/// when nothing is connected or the stored one no longer opens (a rotated
/// master key), which reads the same to the person: connect again.
pub async fn connected_at(
    env: &Env,
    legacy_secret: Option<&str>,
) -> Result<Option<String>, Failed> {
    Ok(load(env, Slot::Read, legacy_secret).await?.map(|stored| stored.saved_at().to_owned()))
}

/// The names of the accounts the stored token can list, for the connect
/// page. Empty when there is no token or the listing fails: the page then
/// simply does not say.
pub async fn visible_accounts(env: &Env, legacy_secret: Option<&str>) -> Vec<String> {
    let Ok(Some(token)) = load_token(env, legacy_secret).await else {
        return Vec::new();
    };
    list::<Account>(&token, "/accounts")
        .await
        .map(|accounts| accounts.into_iter().map(|account| account.name).collect())
        .unwrap_or_default()
}

/// The read token as text, when one is stored and opens.
pub(crate) async fn load_token(
    env: &Env,
    legacy_secret: Option<&str>,
) -> Result<Option<String>, Failed> {
    Ok(load(env, Slot::Read, legacy_secret).await?.map(Stored::into_token))
}

/// Which stored token: the read-only one the fleet is built with, or the
/// optional deploy token rollbacks use. Each has its own name in the vault
/// and its own legacy row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Read,
    Deploy,
}

impl Slot {
    fn name(self) -> &'static str {
        match self {
            Slot::Read => secrets::CLOUDFLARE_READ,
            Slot::Deploy => secrets::CLOUDFLARE_DEPLOY,
        }
    }

    /// The old sealed row this token may still be in, and the secret that
    /// opens it when the deployment still has one.
    fn legacy(self, secret: Option<&str>) -> Legacy<'_> {
        match self {
            Slot::Read => Legacy { table: "console_cloudflare_token", info: seal::INFO, secret },
            Slot::Deploy => {
                Legacy { table: "console_cloudflare_deploy_token", info: seal::DEPLOY_INFO, secret }
            }
        }
    }
}

fn vault_failed(error: secrets::Error) -> Failed {
    match error {
        secrets::Error::NoMasterKey => NO_MASTER_KEY,
        secrets::Error::Storage => STORE,
    }
}

/// The token in `slot`, opened, with its save time. `None` when none is
/// connected.
async fn load(
    env: &Env,
    slot: Slot,
    legacy_secret: Option<&str>,
) -> Result<Option<Stored>, Failed> {
    secrets::read(env, slot.name(), &slot.legacy(legacy_secret)).await.map_err(vault_failed)
}

/// Saves `token` in `slot`, replacing what was there.
async fn save(env: &Env, slot: Slot, token: &str) -> Result<(), Failed> {
    let vault = Vault::open(env).await.map_err(vault_failed)?;
    vault.write(slot.name(), token, &slot.legacy(None)).await.map_err(vault_failed)
}

/// Forgets `slot`'s token and any legacy row for it.
async fn forget(env: &Env, slot: Slot) -> Result<(), Failed> {
    secrets::forget(env, slot.name(), &slot.legacy(None)).await.map_err(vault_failed)
}

async fn send(token: &str, url: &str) -> Result<(u16, String), Failed> {
    send_with(token, Method::Get, url, None).await
}

/// [`send`] with a method and an optional JSON body.
pub(crate) async fn send_with(
    token: &str,
    method: Method,
    url: &str,
    body: Option<&str>,
) -> Result<(u16, String), Failed> {
    let headers = Headers::new();
    headers.set("authorization", &format!("Bearer {token}")).map_err(|_| NETWORK)?;
    headers.set("accept", "application/json").map_err(|_| NETWORK)?;
    let mut init = RequestInit::new();
    init.with_method(method).with_headers(headers);
    if let Some(body) = body {
        init.headers.set("content-type", "application/json").map_err(|_| NETWORK)?;
        init.with_body(Some(JsValue::from_str(body)));
    }
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
pub(crate) async fn get<T: DeserializeOwned>(
    token: &str,
    url: &str,
) -> Result<Envelope<T>, Failed> {
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

/// The current time as RFC 3339 for the connect page's "saved" line and the
/// snapshot's `generated_at`. Empty only if formatting fails, which the
/// callers read as "no reference time".
#[must_use]
pub fn now() -> String {
    WorkersClock.now().format(&Rfc3339).unwrap_or_default()
}

/// Each Pages project's recent preview deployments, for the snapshot's
/// preview rows. A failed read is one named gap, not a failed snapshot.
async fn read_previews(
    token: &str,
    account_id: &str,
    pages: &mut [PagesProject],
    gaps: &mut Vec<String>,
) {
    let mut failed = false;
    for project in pages.iter_mut() {
        let path = format!(
            "/accounts/{account_id}/pages/projects/{}/deployments?env=preview&per_page={PREVIEW_PER_PAGE}",
            project.name
        );
        match list_all::<PagesDeployment>(token, &path).await {
            Ok(previews) => project.previews = previews,
            Err(_) => failed = true,
        }
    }
    if failed {
        gaps.push("Pages preview deployments (Cloudflare Pages: Read)".to_owned());
    }
}

/// Each Worker's active deployment (one call per script, `per_page=1`: the
/// first deployment listed is the one serving traffic). A script whose read
/// fails keeps its modified time as its last change. Only when every read
/// fails is that a named gap.
async fn read_worker_versions(
    token: &str,
    account_id: &str,
    scripts: &mut [WorkerScript],
    gaps: &mut Vec<String>,
) {
    let mut failed = 0;
    for script in scripts.iter_mut() {
        let url = format!(
            "{API}/accounts/{account_id}/workers/scripts/{}/deployments?per_page=1",
            script.id
        );
        match get::<WorkerDeployments>(token, &url).await {
            Ok(envelope) => {
                script.active =
                    envelope.result.and_then(|listed| listed.deployments.into_iter().next());
            }
            Err(_) => failed += 1,
        }
    }
    if !scripts.is_empty() && failed == scripts.len() {
        gaps.push("Worker versions (Workers Scripts: Read)".to_owned());
    }
}

/// Reads the account: its zones (with certificate status), Pages projects
/// and their previews, Workers scripts with their active deployment, and
/// their custom domains.
///
/// Subrequests: one zones listing per 50 zones, one certificate read per zone,
/// the Pages listing, one preview read per Pages project, the Workers scripts
/// and domains listings, and one deployments read per Worker script.
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
    let mut pages: Vec<PagesProject> = or_gap(
        list_all(token, &format!("/accounts/{}/pages/projects", account.id)).await,
        "Pages projects (Cloudflare Pages: Read)",
        &mut gaps,
    );
    read_previews(token, &account.id, &mut pages, &mut gaps).await;
    let mut scripts: Vec<WorkerScript> = or_gap(
        list_all(token, &format!("/accounts/{}/workers/scripts", account.id)).await,
        "Workers (Workers Scripts: Read)",
        &mut gaps,
    );
    read_worker_versions(token, &account.id, &mut scripts, &mut gaps).await;
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

/// The paste: verify the token, check it can list an account, store it, then
/// take the first snapshot. The snapshot's failure is logged and does not
/// undo a token that was accepted; the fleet page offers a refresh.
pub async fn connect(env: &Env, token: &str) -> Result<(), Failed> {
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
    save(env, Slot::Read, token).await?;
    if let Err(failed) = write_snapshot(env, token).await {
        tracing::warn!(message = failed.message, "console: first snapshot after connect failed");
    }
    Ok(())
}

/// Rebuilds the snapshot from the stored token. Used by the refresh button
/// and the hourly cron.
pub async fn refresh(env: &Env, legacy_secret: Option<&str>) -> Result<Fleet, Failed> {
    let token = load_token(env, legacy_secret).await?.ok_or(NOT_CONNECTED)?;
    write_snapshot(env, &token).await
}

/// Forgets both tokens and the snapshot the read token produced.
pub async fn disconnect(env: &Env) -> Result<(), Failed> {
    // The deploy token goes too: disconnecting cuts all Cloudflare access.
    for slot in [Slot::Read, Slot::Deploy] {
        forget(env, slot).await?;
    }
    let kv = env.kv("FLEET").map_err(|_| WRITE)?;
    kv.delete(KV_KEY).await.map_err(|_| WRITE)?;
    Ok(())
}

/// When the deploy token was saved, when one is stored and opens.
pub async fn deploy_connected_at(
    env: &Env,
    legacy_secret: Option<&str>,
) -> Result<Option<String>, Failed> {
    Ok(load(env, Slot::Deploy, legacy_secret).await?.map(|stored| stored.saved_at().to_owned()))
}

async fn load_deploy_token(
    env: &Env,
    legacy_secret: Option<&str>,
) -> Result<Option<String>, Failed> {
    Ok(load(env, Slot::Deploy, legacy_secret).await?.map(Stored::into_token))
}

/// The deploy token's paste: verified active and able to list an account,
/// then stored under its own name. No snapshot is taken: the fleet is read
/// with the read-only token.
pub async fn connect_deploy(env: &Env, token: &str) -> Result<(), Failed> {
    let (status, body) = send(token, &format!("{API}/user/tokens/verify")).await?;
    if status != 200 {
        return Err(NOT_ACCEPTED);
    }
    let verified: Envelope<Verify> = serde_json::from_str(&body).map_err(|_| SHAPE)?;
    if !verified.success || !verified.result.as_ref().is_some_and(token_is_active) {
        return Err(NOT_ACCEPTED);
    }
    if list::<Account>(token, "/accounts").await?.is_empty() {
        return Err(NO_ACCOUNTS);
    }
    save(env, Slot::Deploy, token).await
}

/// What a write the onboarding makes can be refused with.
const CHANGE_REFUSED: Failed = Failed {
    status: 502,
    message: "Cloudflare refused that change. Check the token has the permission this step \
              needs, from the list on the setup page.",
};

#[derive(Deserialize)]
struct TokenVerify {
    id: String,
    status: String,
}

#[derive(Deserialize)]
struct PagesProjectSource {
    source: Option<PagesSource>,
}

#[derive(Deserialize)]
struct PagesSource {
    config: Option<PagesSourceConfig>,
}

#[derive(Deserialize)]
struct PagesSourceConfig {
    owner: Option<String>,
    repo_name: Option<String>,
}

/// The GitHub repository a Pages project builds from, as `(owner, name)`, read
/// with the read token. `None` for a project that is not built from GitHub,
/// or when the read fails: the caller then guesses from names instead.
pub(crate) async fn pages_source(
    token: &str,
    account_id: &str,
    project: &str,
) -> Option<(String, String)> {
    let url = format!(
        "{API}/accounts/{}/pages/projects/{}",
        super::rollback::seg(account_id),
        super::rollback::seg(project)
    );
    let envelope: Envelope<PagesProjectSource> = get(token, &url).await.ok()?;
    let config = envelope.result?.source?.config?;
    Some((config.owner?, config.repo_name?))
}

/// Checks the infrastructure token: the account's own verify endpoint first,
/// then the user's, since either can be the one a token answers to. Returns
/// the token's id (the R2 access key id) when it is active.
pub(crate) async fn verify_account_token(token: &str, account_id: &str) -> Result<String, Failed> {
    let urls = [
        format!("{API}/accounts/{}/tokens/verify", super::rollback::seg(account_id)),
        format!("{API}/user/tokens/verify"),
    ];
    for url in urls {
        let (status, body) = send(token, &url).await?;
        if status != 200 {
            continue;
        }
        let verified: Envelope<TokenVerify> = serde_json::from_str(&body).map_err(|_| SHAPE)?;
        return match verified.result {
            Some(result) if verified.success && result.status == "active" => Ok(result.id),
            _ => Err(NOT_ACCEPTED),
        };
    }
    Err(NOT_ACCEPTED)
}

/// Creates an R2 bucket with the infrastructure token. A bucket that already
/// exists is fine: the setup is run again on purpose.
pub(crate) async fn create_bucket(token: &str, account_id: &str, name: &str) -> Result<(), Failed> {
    let body = serde_json::json!({ "name": name }).to_string();
    let url = format!("{API}/accounts/{}/r2/buckets", super::rollback::seg(account_id));
    let (status, answer) = send_with(token, Method::Post, &url, Some(&body)).await?;
    if (200..300).contains(&status) {
        return Ok(());
    }
    if status == 409 || answer.to_ascii_lowercase().contains("already exists") {
        return Ok(());
    }
    tracing::warn!(status, "console: cloudflare refused to create a bucket");
    Err(CHANGE_REFUSED)
}

/// Forgets the deploy token; the fleet and its read-only token stay.
pub async fn disconnect_deploy(env: &Env) -> Result<(), Failed> {
    forget(env, Slot::Deploy).await
}

const NO_DEPLOY_TOKEN: Failed = Failed {
    status: 409,
    message: "No deploy token is connected. Add one on the Cloudflare connection page first.",
};
const NOT_A_CANDIDATE: Failed = Failed {
    status: 409,
    message: "That deployment is not one this site can roll back to now: it may already be \
              live, or no longer listed. Pick one from the list again.",
};
const ROLLBACK_REFUSED: Failed = Failed {
    status: 502,
    message: "Cloudflare refused the rollback. Either the deploy token lacks Pages Edit or \
              Workers Scripts Edit on this account, or Cloudflare cannot deploy that version \
              any more.",
};

/// The live deployment and the earlier ones a site can go back to, read now
/// with the deploy token (which can also read what it can write).
async fn candidates(token: &str, target: &Target) -> Result<Vec<Candidate>, Failed> {
    match target {
        Target::Pages { .. } => {
            let live: Envelope<PagesProjectLive> =
                get(token, &format!("{API}{}", target.live_path().unwrap_or_default())).await?;
            let live = live.result.and_then(|project| project.canonical_deployment);
            let deployments: Envelope<Vec<rollback::PagesDeployment>> =
                get(token, &format!("{API}{}", target.versions_path())).await?;
            Ok(rollback::pages_candidates(
                deployments.result.unwrap_or_default(),
                live.as_ref().map(|live| live.id.as_str()),
            ))
        }
        Target::Worker { .. } => {
            let history: Envelope<super::WorkerDeployments> =
                get(token, &format!("{API}{}", target.versions_path())).await?;
            Ok(rollback::worker_candidates(
                history.result.map(|listed| listed.deployments).unwrap_or_default(),
            ))
        }
    }
}

/// The site page's rollback panel, read live.
pub async fn rollback_panel(env: &Env, legacy_secret: Option<&str>, site: &Site) -> Panel {
    let Some(target) = rollback::target(site) else {
        return Panel::NotSupported;
    };
    let token = match load_deploy_token(env, legacy_secret).await {
        Ok(Some(token)) => token,
        Ok(None) => return Panel::NoDeployToken,
        Err(failed) => return Panel::Unavailable(failed.message),
    };
    match candidates(&token, &target).await {
        Ok(candidates) => Panel::Candidates(candidates),
        Err(failed) => Panel::Unavailable(failed.message),
    }
}

/// The confirmation page's facts: the candidate `to`, and the live one.
pub async fn rollback_choice(
    env: &Env,
    legacy_secret: Option<&str>,
    site: &Site,
    to: &str,
) -> Result<(Candidate, Option<Candidate>), Failed> {
    let target = rollback::target(site).ok_or(NOT_A_CANDIDATE)?;
    let token = load_deploy_token(env, legacy_secret).await?.ok_or(NO_DEPLOY_TOKEN)?;
    let listed = candidates(&token, &target).await?;
    let chosen = rollback::allowed(&listed, to).cloned().ok_or(NOT_A_CANDIDATE)?;
    let live = listed.into_iter().find(|candidate| candidate.live);
    Ok((chosen, live))
}

/// Rolls `site` back to `to`: checked against a fresh listing (listed, not
/// live), then the one documented call. Logged with ids only.
pub async fn roll_back(
    env: &Env,
    legacy_secret: Option<&str>,
    site: &Site,
    to: &str,
) -> Result<(), Failed> {
    let target = rollback::target(site).ok_or(NOT_A_CANDIDATE)?;
    let token = load_deploy_token(env, legacy_secret).await?.ok_or(NO_DEPLOY_TOKEN)?;
    let listed = candidates(&token, &target).await?;
    let chosen = rollback::allowed(&listed, to).ok_or(NOT_A_CANDIDATE)?;
    let (path, body) = target.rollback_request(&chosen.id);
    let (status, answer) =
        send_with(&token, Method::Post, &format!("{API}{path}"), body.as_deref()).await?;
    let ok = (200..300).contains(&status)
        && serde_json::from_str::<Envelope<serde_json::Value>>(&answer)
            .is_ok_and(|envelope| envelope.success);
    if !ok {
        tracing::warn!(status, site = %site.id, "console: cloudflare refused a rollback");
        return Err(ROLLBACK_REFUSED);
    }
    tracing::info!(site = %site.id, to = %chosen.id, "console: rolled back");
    Ok(())
}
