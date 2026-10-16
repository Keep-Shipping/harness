//! The console's GitHub App: the account-level connection that is the
//! console's default way into GitHub, and the one the personal access token
//! falls back from.
//!
//! The app is created with GitHub's manifest flow: the console posts a
//! manifest (its name, its URLs, the permissions it asks for) to GitHub, and
//! GitHub hands back a one-time code that is exchanged for the app's id, its
//! client id and three secrets. A `state` value, stored with a ten-minute
//! expiry and checked once on return, ties the two legs together.
//!
//! Everything GitHub gives back that is secret goes to the secrets store
//! (the secrets store, `src/secrets.rs`): the private key, the webhook secret and the client
//! secret. What the database keeps is non-secret: the app's id and slug, and
//! one row per installation. A token minted for an installation is held in
//! memory for the isolate only, until five minutes before GitHub says it
//! expires.
//!
//! The pure parts (the manifest, the key parsing, the JWT, the installation
//! choice, the state rules) are plain functions tested natively below. The
//! network side goes through the [`HttpClient`] port, so the same code runs
//! on the Worker and under the tests.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, OnceLock};

use base64::Engine as _;
use cratefield_core::axum::body::Bytes;
use cratefield_core::{Database, HttpClient, Statement};
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use worker::Env;

use super::{API, API_VERSION, Failed, NETWORK, REFUSED, SHAPE, USER_AGENT, path, segment};
use crate::onboard::wizard::CONSOLE_URL;
use crate::secrets;

/// Where the manifest's `redirect_url` returns the person: GitHub has just
/// created the app, and the code is exchanged here.
pub const CREATED_PATH: &str = "/console/connect/github/app/created";
/// Where the manifest's `setup_url` returns the person after an installation.
pub const INSTALLED_PATH: &str = "/console/connect/github/app/installed";
/// Where the create form posts: it stores the `state` and shows the page that
/// sends the browser on to GitHub.
pub const CREATE_PATH: &str = "/console/connect/github/app/new";
/// The webhook's path, as the manifest's `hook_attributes` name it.
pub const WEBHOOK_PATH: &str = "/console/github/webhook";
/// Where the connection page's remove button posts: the app is forgotten by
/// the console (not on GitHub).
pub const REMOVE_PATH: &str = "/console/connect/github/app/remove";

/// The secrets-store name of the app's private key (PEM).
pub const PRIVATE_KEY: &str = "github-app/private-key";
/// The secrets-store name of the webhook secret.
pub const WEBHOOK_SECRET: &str = "github-app/webhook-secret";
/// The secrets-store name of the app's OAuth client secret.
pub const CLIENT_SECRET: &str = "github-app/client-secret";
/// Every secret the app keeps, all of which a removal forgets.
pub const SECRET_NAMES: [&str; 3] = [PRIVATE_KEY, WEBHOOK_SECRET, CLIENT_SECRET];

/// How long a manifest `state` is good for, in seconds.
const STATE_TTL_SECS: i64 = 600;
/// The app JWT is backdated a minute, against clock skew with GitHub.
const JWT_BACKDATE_SECS: i64 = 60;
/// The app JWT's lifetime: GitHub allows at most ten minutes.
const JWT_LIFETIME_SECS: i64 = 9 * 60;
/// An installation token is replaced this long before GitHub expires it.
const TOKEN_MARGIN_SECS: i64 = 5 * 60;
/// Used when GitHub's expiry cannot be read: a token is trusted this long.
const FALLBACK_TOKEN_SECS: i64 = 50 * 60;
/// The longest app name the create form accepts (GitHub's own rules apply on
/// top of this).
pub const APP_NAME_MAX: usize = 64;

/// The permissions the app asks for, as the manifest's `default_permissions`.
const PERMISSIONS: [(&str, &str); 7] = [
    ("contents", "write"),
    ("pull_requests", "write"),
    ("workflows", "write"),
    ("secrets", "write"),
    ("administration", "write"),
    ("actions", "read"),
    ("metadata", "read"),
];

/// What the console needs GitHub to have granted, checked against the
/// conversion's `permissions` after the app is created.
pub const REQUIRED: [(&str, &str); 7] = PERMISSIONS;

/// The required permissions GitHub did not grant at the level needed, as
/// `name (level)` words for the page. A missing permission and one granted
/// only `read` where `write` is needed are both listed. Pure.
#[must_use]
pub fn missing_permissions(granted: &serde_json::Value) -> Vec<String> {
    REQUIRED
        .iter()
        .filter(|(name, need)| {
            let have = granted.get(*name).and_then(serde_json::Value::as_str).unwrap_or("");
            level(have) < level(need)
        })
        .map(|(name, need)| format!("{} ({need})", name.replace('_', " ")))
        .collect()
}

/// The rank of a GitHub permission level: none below read, read below write.
fn level(access: &str) -> u8 {
    match access {
        "write" => 2,
        "read" => 1,
        _ => 0,
    }
}

/// The SHA-256 of a person's email, as the state records it. Lower-cased and
/// trimmed first, so the same person always hashes the same.
#[must_use]
pub fn subject_of(email: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(email.trim().to_ascii_lowercase().as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The console's own database refused a read or a write. Not GitHub's trouble.
const DATABASE: Failed = Failed {
    status: 503,
    message: "The console could not read or save its GitHub connection. Try again.",
};
const RANDOM: Failed =
    Failed { status: 503, message: "The server has no random source right now. Try again." };
const ALREADY: Failed = Failed {
    status: 409,
    message: "This console already has its GitHub App. Its installations are listed on this \
              page.",
};
const NOT_CREATED: Failed =
    Failed { status: 400, message: "The GitHub App has not been created yet. Create it first." };
const NOT_THIS_APP: Failed = Failed {
    status: 400,
    message: "That installation belongs to a different GitHub App, not this console's.",
};
const CODE_REFUSED: Failed = Failed {
    status: 400,
    message: "GitHub did not hand over the new app. Start again from the connection page.",
};
/// What the person is told when GitHub's return carries a `state` that is
/// unknown, used or expired.
pub const STATE_REFUSED_COPY: &str =
    "That link has expired or was already used. Start again from the connection page.";
const KEY_UNREADABLE: Failed = Failed {
    status: 503,
    message: "The GitHub App's private key could not be read. Create the app again, or check \
              the secrets store.",
};

/// The app as the console recorded it: non-secret facts only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRow {
    /// GitHub's numeric id for the app; a token's installation must name it.
    pub app_id: i64,
    /// The app's URL name: `https://github.com/apps/<slug>`.
    pub slug: String,
    /// The OAuth client id, the JWT's `iss`.
    pub client_id: String,
    /// The app's page on GitHub.
    pub html_url: String,
    /// The account the app was created under.
    pub owner: String,
    /// The permissions GitHub granted, as the conversion reported them.
    pub permissions: serde_json::Value,
}

impl AppRow {
    /// The required permissions GitHub did not grant, for the page's warning.
    #[must_use]
    pub fn missing_permissions(&self) -> Vec<String> {
        missing_permissions(&self.permissions)
    }
}

/// One installation of the app: an account, and which of its repositories
/// the app can see (`all` or `selected`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installation {
    /// GitHub's installation id.
    pub id: i64,
    /// The account's login.
    pub account: String,
    /// `User` for a personal account, `Organization` for an organisation.
    pub account_type: String,
    /// `all` or `selected`.
    pub selection: String,
}

impl Installation {
    /// Whether the account is a personal one (a user, not an organisation).
    #[must_use]
    pub fn is_user(&self) -> bool {
        self.account_type.eq_ignore_ascii_case("User")
    }
}

/// An installation token and whether its account is a personal one. The
/// `Debug` impl never shows the token.
pub struct AppToken {
    /// The token, for one `Authorization` header.
    pub token: String,
    /// Whether the installation is on a personal account.
    pub user_account: bool,
}

impl std::fmt::Debug for AppToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppToken")
            .field("token", &"[redacted]")
            .field("user_account", &self.user_account)
            .finish()
    }
}

/// The app and its installations, for the connection page.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Overview {
    /// The app, when it has been created.
    pub app: Option<AppRow>,
    /// Its installations, by account login.
    pub installations: Vec<Installation>,
}

// ---------------------------------------------------------------------------
// Pure: the manifest and the create form.
// ---------------------------------------------------------------------------

/// The manifest GitHub's form takes: what the app is called, where its
/// webhook and its return legs point, and the permissions and events it asks
/// for. `public` is true so the app can be installed on any account, including
/// the organisations the operator runs (a private app is installable only on
/// the account that created it). That is safe because only this console holds
/// the app's private key, so only this console can act through the app; the
/// webhook therefore never adds an installation it did not hear about from the
/// signed-in setup callback. Apps created before this change may still be
/// private; their owner can make them public in GitHub's advanced settings.
#[must_use]
pub fn manifest(name: &str) -> serde_json::Value {
    let permissions: serde_json::Map<String, serde_json::Value> = PERMISSIONS
        .iter()
        .map(|(key, access)| ((*key).to_owned(), serde_json::Value::from(*access)))
        .collect();
    serde_json::json!({
        "name": name,
        "url": CONSOLE_URL,
        "hook_attributes": { "url": format!("{CONSOLE_URL}{WEBHOOK_PATH}"), "active": true },
        "redirect_url": format!("{CONSOLE_URL}{CREATED_PATH}"),
        "setup_url": format!("{CONSOLE_URL}{INSTALLED_PATH}"),
        "setup_on_update": true,
        "public": true,
        "default_permissions": permissions,
        "default_events": ["pull_request", "workflow_run"],
    })
}

/// The page the create form's `state` and the manifest are sent to: an
/// organisation's form when one is named, else the signed-in account's own.
#[must_use]
pub fn create_target(org: Option<&str>, state: &str) -> String {
    match org {
        Some(org) => format!(
            "https://github.com/organizations/{}/settings/apps/new?state={}",
            segment(org),
            segment(state)
        ),
        None => format!("https://github.com/settings/apps/new?state={}", segment(state)),
    }
}

/// The organisation the create form names, as GitHub spells it: blank means
/// the personal account. Anything GitHub would refuse as a login is refused
/// here, in words.
///
/// # Errors
///
/// A plain-words refusal when the name is not a valid organisation login.
pub fn owner_of(raw: &str) -> Result<Option<String>, &'static str> {
    let name = raw.trim();
    if name.is_empty() {
        return Ok(None);
    }
    let valid = name.len() <= 39
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if valid { Ok(Some(name.to_owned())) } else { Err(ORG_COPY) }
}

const ORG_COPY: &str = "The organisation name can only use letters, numbers and hyphens, and \
     must match the organisation's name on GitHub. Leave it blank for your own account.";

/// The app's name: the form's value, or the default `Keep Shipping console
/// (<organisation>)`. Printable, and at most [`APP_NAME_MAX`] characters.
///
/// # Errors
///
/// A plain-words refusal when the name is empty after trimming, too long or
/// has a control character in it.
pub fn name_of(org: Option<&str>, raw: &str) -> Result<String, &'static str> {
    let typed = raw.trim();
    let name = if typed.is_empty() {
        format!("Keep Shipping console ({})", org.unwrap_or("personal account"))
    } else {
        typed.to_owned()
    };
    if name.chars().count() > APP_NAME_MAX || name.chars().any(char::is_control) {
        return Err(NAME_COPY);
    }
    Ok(name)
}

const NAME_COPY: &str = "The app name must be 64 characters or fewer, with no line breaks. GitHub \
     also requires app names to be unique across GitHub, so pick another if this one is taken.";

// ---------------------------------------------------------------------------
// Pure: keys and JWTs.
// ---------------------------------------------------------------------------

/// Parses the app's private key. GitHub issues PKCS#1 (`BEGIN RSA PRIVATE
/// KEY`); PKCS#8 (`BEGIN PRIVATE KEY`) is accepted too.
///
/// # Errors
///
/// [`Failed`] when neither parses. The key's text is never in the error.
pub fn parse_private_key(pem: &str) -> Result<RsaPrivateKey, Failed> {
    RsaPrivateKey::from_pkcs1_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem))
        .map_err(|_| KEY_UNREADABLE)
}

/// The app's JWT: RS256, `iss` the client id, issued a minute ago and valid
/// for nine minutes. `now` is unix seconds.
///
/// # Errors
///
/// [`Failed`] when the claims cannot be encoded (never in practice).
pub fn app_jwt(key: &RsaPrivateKey, client_id: &str, now: i64) -> Result<String, Failed> {
    let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "iat": now - JWT_BACKDATE_SECS,
        "exp": now + JWT_LIFETIME_SECS,
        "iss": client_id,
    })
    .to_string();
    let signing_input = format!("{header}.{}", b64url(claims.as_bytes()));
    let signature = SigningKey::<Sha256>::new(key.clone()).sign(signing_input.as_bytes()).to_vec();
    Ok(format!("{signing_input}.{}", b64url(&signature)))
}

/// Base64url without padding (RFC 7515 §2), by the engine's own alphabet.
fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ---------------------------------------------------------------------------
// Pure: reading GitHub's answers.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ConversionBody {
    id: i64,
    slug: String,
    client_id: String,
    html_url: String,
    owner: LoginBody,
    pem: String,
    webhook_secret: String,
    client_secret: String,
    #[serde(default)]
    permissions: serde_json::Value,
}

#[derive(Deserialize)]
struct LoginBody {
    login: String,
}

/// What the manifest conversion returns, with the three secrets. Not `Debug`:
/// nothing may print it.
pub struct Conversion {
    /// The app's public facts.
    pub app: AppRow,
    /// The private key, PEM.
    pub pem: String,
    /// The webhook secret.
    pub webhook_secret: String,
    /// The OAuth client secret.
    pub client_secret: String,
}

/// The conversion's answer (`POST /app-manifests/{code}/conversions`).
///
/// # Errors
///
/// `SHAPE` when a field is missing.
pub fn read_conversion(body: &str) -> Result<Conversion, Failed> {
    let parsed: ConversionBody = serde_json::from_str(body).map_err(|_| SHAPE)?;
    Ok(Conversion {
        app: AppRow {
            app_id: parsed.id,
            slug: parsed.slug,
            client_id: parsed.client_id,
            html_url: parsed.html_url,
            owner: parsed.owner.login,
            permissions: parsed.permissions,
        },
        pem: parsed.pem,
        webhook_secret: parsed.webhook_secret,
        client_secret: parsed.client_secret,
    })
}

#[derive(Deserialize)]
struct InstallationBody {
    id: i64,
    app_id: i64,
    account: AccountBody,
    #[serde(default)]
    repository_selection: String,
}

#[derive(Deserialize)]
struct AccountBody {
    login: String,
    #[serde(rename = "type")]
    kind: String,
}

/// An installation's facts (`GET /app/installations/{id}` or
/// `GET /repos/{o}/{r}/installation`): the id, the app it belongs to, the
/// account and the repository selection.
///
/// # Errors
///
/// `SHAPE` when a field is missing.
pub fn read_installation(body: &str) -> Result<(i64, Installation), Failed> {
    let parsed: InstallationBody = serde_json::from_str(body).map_err(|_| SHAPE)?;
    let selection = if parsed.repository_selection.is_empty() {
        "selected".to_owned()
    } else {
        parsed.repository_selection
    };
    Ok((
        parsed.app_id,
        Installation {
            id: parsed.id,
            account: parsed.account.login,
            account_type: parsed.account.kind,
            selection,
        },
    ))
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
    #[serde(default)]
    expires_at: String,
}

/// An installation token and its expiry, as unix seconds. An expiry that does
/// not parse is trusted for `FALLBACK_TOKEN_SECS` from `now`.
///
/// # Errors
///
/// `SHAPE` when there is no token.
pub fn read_token(body: &str, now: i64) -> Result<(String, i64), Failed> {
    let parsed: TokenBody = serde_json::from_str(body).map_err(|_| SHAPE)?;
    let expires = OffsetDateTime::parse(&parsed.expires_at, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
        .unwrap_or(now + FALLBACK_TOKEN_SECS);
    Ok((parsed.token, expires))
}

/// The installation for an owner: the first whose account login matches,
/// ignoring case. Pure.
#[must_use]
pub fn pick_installation<'a>(rows: &'a [Installation], owner: &str) -> Option<&'a Installation> {
    rows.iter().find(|row| row.account.eq_ignore_ascii_case(owner))
}

/// Whether a cached token may still be used at `now`: it must outlive the
/// refresh margin.
#[must_use]
pub fn token_is_fresh(expires: i64, now: i64) -> bool {
    expires - TOKEN_MARGIN_SECS > now
}

/// GitHub's page for managing one installation.
#[must_use]
pub fn manage_url(installation: &Installation) -> String {
    if installation.is_user() {
        format!("https://github.com/settings/installations/{}", installation.id)
    } else {
        format!(
            "https://github.com/organizations/{}/settings/installations/{}",
            segment(&installation.account),
            installation.id
        )
    }
}

/// GitHub's page for installing the app on another account.
#[must_use]
pub fn install_url(slug: &str) -> String {
    format!("https://github.com/apps/{}/installations/new", segment(slug))
}

/// GitHub's settings page for an app's advanced options, where it is deleted.
/// Built only from the app's stored page address, and only when that address
/// is one of GitHub's two app-page forms with a plain slug (and organisation):
/// anything else is `None`, so no other host or path can reach the page.
#[must_use]
pub fn advanced_url(html_url: &str) -> Option<String> {
    let parts: Vec<&str> = html_url.strip_prefix("https://github.com/")?.split('/').collect();
    match parts.as_slice() {
        ["settings", "apps", slug] if plain(slug, APP_SLUG_MAX) => {
            Some(format!("https://github.com/settings/apps/{slug}/advanced"))
        }
        ["organizations", org, "settings", "apps", slug]
            if plain(org, ORG_MAX) && plain(slug, APP_SLUG_MAX) =>
        {
            Some(format!("https://github.com/organizations/{org}/settings/apps/{slug}/advanced"))
        }
        _ => None,
    }
}

/// The advanced settings link for an app from its slug and owner. GitHub's own
/// `html_url` for an app is its public page (`https://github.com/apps/<slug>`),
/// which has no delete button, so the link is built from the owner instead:
/// an organisation's apps live under `/organizations/<org>/settings/apps`, a
/// personal account's under `/settings/apps`. `None` unless both are plain.
#[must_use]
pub fn advanced_url_for(slug: &str, owner: &str, owner_is_org: bool) -> Option<String> {
    if !plain(slug, APP_SLUG_MAX) || !plain(owner, ORG_MAX) {
        return None;
    }
    let page = if owner_is_org {
        format!("https://github.com/organizations/{owner}/settings/apps/{slug}")
    } else {
        format!("https://github.com/settings/apps/{slug}")
    };
    advanced_url(&page)
}

/// Whether `login` is an organisation, from GitHub's public users endpoint
/// (`type` is `Organization` or `User`). `None` when GitHub cannot say.
pub async fn owner_is_org(login: &str) -> Option<bool> {
    if !plain(login, ORG_MAX) {
        return None;
    }
    let headers = worker::Headers::new();
    headers.set("accept", "application/vnd.github+json").ok()?;
    headers.set("x-github-api-version", "2022-11-28").ok()?;
    headers.set("user-agent", "keepshipping-console").ok()?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Get).with_headers(headers);
    let req =
        worker::Request::new_with_init(&format!("https://api.github.com/users/{login}"), &init)
            .ok()?;
    let mut res = worker::Fetch::Request(req).send().await.ok()?;
    if res.status_code() != 200 {
        return None;
    }
    let body: serde_json::Value = res.json().await.ok()?;
    match body.get("type").and_then(serde_json::Value::as_str) {
        Some("Organization") => Some(true),
        Some("User") => Some(false),
        _ => None,
    }
}

/// The advanced link a redirect carries back, checked: it must be exactly what
/// [`advanced_url`] builds from the app's page address. Anything else is `None`.
#[must_use]
pub fn checked_advanced_url(raw: &str) -> Option<String> {
    let page = raw.strip_suffix("/advanced")?;
    advanced_url(page).filter(|built| built == raw)
}

/// The longest app slug GitHub is taken to allow here.
const APP_SLUG_MAX: usize = 64;
/// The longest organisation login (GitHub's limit).
const ORG_MAX: usize = 39;

/// Whether a slug or login is non-empty, short enough, and made only of the
/// letters, digits and hyphens GitHub uses.
fn plain(text: &str, max: usize) -> bool {
    !text.is_empty()
        && text.len() <= max
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Whether a code from GitHub's redirect is one this console will send: the
/// characters GitHub uses, and a sane length.
#[must_use]
pub fn code_is_plausible(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 128
        && code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// ---------------------------------------------------------------------------
// The manifest state: random, single use, ten minutes.
// ---------------------------------------------------------------------------

/// Issues a `state` for the create form, bound to the person who asked for it
/// (`subject` is their [`subject_of`] hash): 32 random bytes in hex, stored
/// with its expiry. Expired rows are swept on the way in.
///
/// # Errors
///
/// [`Failed`] when there is no random source or the row cannot be stored.
pub async fn issue_state(db: Arc<dyn Database>, now: i64, subject: &str) -> Result<String, Failed> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| RANDOM)?;
    let mut state = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(state, "{byte:02x}");
    }
    db.execute(&Statement::with_values(
        "DELETE FROM console_github_app_state WHERE expires_at <= ?",
        vec![now.into()],
    ))
    .await
    .map_err(|_| DATABASE)?;
    db.execute(&Statement::with_values(
        "INSERT INTO console_github_app_state (state, expires_at, subject_hash) VALUES (?, ?, ?)",
        vec![state.clone().into(), (now + STATE_TTL_SECS).into(), subject.into()],
    ))
    .await
    .map_err(|_| DATABASE)?;
    Ok(state)
}

/// Takes a `state` back: true exactly once, only while it has not expired, and
/// only for the person it was issued to (`subject`, the same [`subject_of`]
/// hash). The row is deleted by the same statement that checks all three, so
/// two returns with one `state` cannot both succeed.
///
/// # Errors
///
/// [`Failed`] when the database cannot answer.
pub async fn take_state(
    db: Arc<dyn Database>,
    state: &str,
    now: i64,
    subject: &str,
) -> Result<bool, Failed> {
    let removed = db
        .execute(&Statement::with_values(
            "DELETE FROM console_github_app_state \
             WHERE state = ? AND expires_at > ? AND subject_hash = ?",
            vec![state.into(), now.into(), subject.into()],
        ))
        .await
        .map_err(|_| DATABASE)?;
    Ok(removed == 1)
}

// ---------------------------------------------------------------------------
// The database: the app row and the installation rows.
// ---------------------------------------------------------------------------

/// The app and its installations.
///
/// # Errors
///
/// [`Failed`] when the database cannot answer.
pub async fn overview(db: Arc<dyn Database>) -> Result<Overview, Failed> {
    Ok(Overview { app: app_row(db.clone()).await?, installations: installations(db).await? })
}

/// The app row, when the console has created its app. A claim still being
/// created (see [`claim_app`]) is not an app yet.
///
/// # Errors
///
/// [`Failed`] when the database cannot answer or the row does not read.
pub async fn app_row(db: Arc<dyn Database>) -> Result<Option<AppRow>, Failed> {
    let rows = db
        .query(&Statement::new(
            "SELECT app_id, slug, client_id, html_url, owner_login, permissions_json \
             FROM console_github_app WHERE id = 1 AND app_id <> 0",
        ))
        .await
        .map_err(|_| DATABASE)?;
    let Some(row) = rows.rows.first() else {
        return Ok(None);
    };
    let read = || -> Option<AppRow> {
        let permissions: String = row.get("permissions_json")?;
        Some(AppRow {
            app_id: row.get("app_id")?,
            slug: row.get("slug")?,
            client_id: row.get("client_id")?,
            html_url: row.get("html_url")?,
            owner: row.get("owner_login")?,
            permissions: serde_json::from_str(&permissions).unwrap_or_default(),
        })
    };
    read().map(Some).ok_or(SHAPE)
}

/// Every installation the console knows of, by account login.
///
/// # Errors
///
/// [`Failed`] when the database cannot answer.
pub async fn installations(db: Arc<dyn Database>) -> Result<Vec<Installation>, Failed> {
    let rows = db
        .query(&Statement::new(
            "SELECT installation_id, account_login, account_type, repository_selection \
             FROM console_github_installation ORDER BY account_login COLLATE NOCASE",
        ))
        .await
        .map_err(|_| DATABASE)?;
    rows.rows.iter().map(installation_of).collect()
}

fn installation_of(row: &cratefield_core::Row) -> Result<Installation, Failed> {
    let read = || -> Option<Installation> {
        Some(Installation {
            id: row.get("installation_id")?,
            account: row.get("account_login")?,
            account_type: row.get("account_type")?,
            selection: row.get("repository_selection")?,
        })
    };
    read().ok_or(SHAPE)
}

/// Refreshes an installation the console already records. An unknown id
/// matches no row and is left alone: the webhook never adds installations.
///
/// # Errors
///
/// [`Failed`] when the database refuses the write.
pub async fn refresh_installation(
    db: Arc<dyn Database>,
    installation: &Installation,
    now: &str,
) -> Result<(), Failed> {
    db.execute(&Statement::with_values(
        "UPDATE console_github_installation SET account_login = ?, account_type = ?, \
         repository_selection = ?, updated_at = ? WHERE installation_id = ?",
        vec![
            installation.account.clone().into(),
            installation.account_type.clone().into(),
            installation.selection.clone().into(),
            now.into(),
            installation.id.into(),
        ],
    ))
    .await
    .map_err(|_| DATABASE)?;
    Ok(())
}

/// Stores or refreshes one installation. Used by the signed-in setup
/// callback, the only path that records a new installation.
///
/// # Errors
///
/// [`Failed`] when the database refuses the write.
pub async fn save_installation(
    db: Arc<dyn Database>,
    installation: &Installation,
    now: &str,
) -> Result<(), Failed> {
    db.execute(&Statement::with_values(
        "INSERT INTO console_github_installation \
         (installation_id, account_login, account_type, repository_selection, updated_at) \
         VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT(installation_id) DO UPDATE SET \
         account_login = excluded.account_login, account_type = excluded.account_type, \
         repository_selection = excluded.repository_selection, updated_at = excluded.updated_at",
        vec![
            installation.id.into(),
            installation.account.clone().into(),
            installation.account_type.clone().into(),
            installation.selection.clone().into(),
            now.into(),
        ],
    ))
    .await
    .map_err(|_| DATABASE)?;
    Ok(())
}

/// Forgets one installation (uninstalled or suspended on GitHub).
///
/// # Errors
///
/// [`Failed`] when the database refuses the write.
pub async fn remove_installation(db: Arc<dyn Database>, id: i64) -> Result<(), Failed> {
    db.execute(&Statement::with_values(
        "DELETE FROM console_github_installation WHERE installation_id = ?",
        vec![id.into()],
    ))
    .await
    .map_err(|_| DATABASE)?;
    Ok(())
}

/// Records the repository selection of an installation the console knows.
///
/// # Errors
///
/// [`Failed`] when the database refuses the write.
pub async fn set_selection(db: Arc<dyn Database>, id: i64, selection: &str) -> Result<(), Failed> {
    db.execute(&Statement::with_values(
        "UPDATE console_github_installation SET repository_selection = ? WHERE installation_id = ?",
        vec![selection.into(), id.into()],
    ))
    .await
    .map_err(|_| DATABASE)?;
    Ok(())
}

/// Takes the app's one row before anything is written to the secrets store:
/// an insert that only succeeds when no app row (claimed or made) exists. A
/// claim left behind by a create that never finished, older than the state's
/// lifetime, is cleared first. `false` means the console already has an app.
///
/// # Errors
///
/// [`Failed`] when the database cannot answer.
pub async fn claim_app(db: Arc<dyn Database>, now: i64) -> Result<bool, Failed> {
    db.execute(&Statement::with_values(
        "DELETE FROM console_github_app WHERE id = 1 AND app_id = 0 AND created_at <= ?",
        vec![stamp(now - STATE_TTL_SECS).into()],
    ))
    .await
    .map_err(|_| DATABASE)?;
    let inserted = db
        .execute(&Statement::with_values(
            "INSERT OR IGNORE INTO console_github_app \
             (id, app_id, slug, client_id, html_url, owner_login, permissions_json, created_at) \
             VALUES (1, 0, '', '', '', '', '{}', ?)",
            vec![stamp(now).into()],
        ))
        .await
        .map_err(|_| DATABASE)?;
    Ok(inserted == 1)
}

/// Records the app a claim was made for, with the permissions GitHub granted.
///
/// # Errors
///
/// [`Failed`] when the database refuses the write.
pub async fn finish_app(db: Arc<dyn Database>, app: &AppRow) -> Result<(), Failed> {
    db.execute(&Statement::with_values(
        "UPDATE console_github_app SET app_id = ?, slug = ?, client_id = ?, html_url = ?, \
         owner_login = ?, permissions_json = ? WHERE id = 1 AND app_id = 0",
        vec![
            app.app_id.into(),
            app.slug.clone().into(),
            app.client_id.clone().into(),
            app.html_url.clone().into(),
            app.owner.clone().into(),
            app.permissions.to_string().into(),
        ],
    ))
    .await
    .map_err(|_| DATABASE)?;
    Ok(())
}

/// Forgets the app in the console's database: every installation row, then
/// the app row, which includes a claim left behind by a create that never
/// finished. The app's secrets are forgotten separately, by the caller.
///
/// # Errors
///
/// [`Failed`] when the database refuses a write.
pub async fn remove_app(db: Arc<dyn Database>) -> Result<(), Failed> {
    db.execute(&Statement::new("DELETE FROM console_github_installation"))
        .await
        .map_err(|_| DATABASE)?;
    db.execute(&Statement::new("DELETE FROM console_github_app WHERE id = 1"))
        .await
        .map_err(|_| DATABASE)?;
    Ok(())
}

/// Gives a claim back, when the create did not finish. Touches nothing that
/// is a finished app.
///
/// # Errors
///
/// [`Failed`] when the database refuses the write.
pub async fn release_claim(db: Arc<dyn Database>) -> Result<(), Failed> {
    db.execute(&Statement::new("DELETE FROM console_github_app WHERE id = 1 AND app_id = 0"))
        .await
        .map_err(|_| DATABASE)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The network: the conversion, the installation lookups, the tokens.
// ---------------------------------------------------------------------------

/// One call to GitHub through the port. The bearer token, when given, is only
/// in the header; the status and body come back and nothing is logged.
async fn call(
    http: &dyn HttpClient,
    method: &str,
    url: &str,
    bearer: Option<&str>,
    body: Option<String>,
) -> Result<(u16, String), Failed> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(url)
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", API_VERSION)
        .header("user-agent", USER_AGENT);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let payload = match body {
        Some(text) => {
            builder = builder.header("content-type", "application/json");
            Bytes::from(text)
        }
        None => Bytes::new(),
    };
    let request = builder.body(payload).map_err(|_| NETWORK)?;
    let response = http.send(request).await.map_err(|error| {
        tracing::warn!(%error, "console: the github app request did not complete");
        NETWORK
    })?;
    Ok((response.status().as_u16(), String::from_utf8_lossy(response.body()).into_owned()))
}

/// A refusal as a plain result: 2xx passes, 5xx is GitHub's trouble, anything
/// else the app cannot do this.
fn ok(status: u16, what: &str) -> Result<(), Failed> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    tracing::warn!(status, what, "console: github refused a github app call");
    Err(if status >= 500 { NETWORK } else { REFUSED })
}

/// Creates the console's app from the manifest's `code`. The app's one row is
/// claimed first, atomically, so two creates cannot both store secrets: the
/// code is exchanged, the three secrets are stored, and the claim is finished
/// with the app's facts. A failure after the claim gives it back.
///
/// # Errors
///
/// [`Failed`] in plain words: the app exists already, GitHub refused the
/// code, the secrets could not be stored.
pub async fn create_from_code(
    env: &Env,
    db: Arc<dyn Database>,
    http: &dyn HttpClient,
    code: &str,
    now: i64,
) -> Result<AppRow, Failed> {
    if !code_is_plausible(code) {
        return Err(CODE_REFUSED);
    }
    if !claim_app(db.clone(), now).await? {
        return Err(ALREADY);
    }
    match convert_and_store(env, http, code).await {
        Ok(conversion) => {
            finish_app(db, &conversion.app).await?;
            Ok(conversion.app)
        }
        Err(failed) => {
            if let Err(error) = release_claim(db).await {
                tracing::warn!(
                    message = error.message,
                    "console: a create claim could not be released"
                );
            }
            Err(failed)
        }
    }
}

/// The conversion and the three secrets, the work [`create_from_code`] does
/// under its claim.
async fn convert_and_store(
    env: &Env,
    http: &dyn HttpClient,
    code: &str,
) -> Result<Conversion, Failed> {
    let url = format!("{API}/app-manifests/{}/conversions", segment(code));
    let (status, body) = call(http, "POST", &url, None, None).await?;
    if !(200..300).contains(&status) {
        tracing::warn!(status, "console: github refused the app manifest code");
        return Err(CODE_REFUSED);
    }
    let conversion = read_conversion(&body)?;
    store_secret(env, PRIVATE_KEY, &conversion.pem).await?;
    store_secret(env, WEBHOOK_SECRET, &conversion.webhook_secret).await?;
    store_secret(env, CLIENT_SECRET, &conversion.client_secret).await?;
    Ok(conversion)
}

/// Stores one of the app's secrets in the secrets store.
async fn store_secret(env: &Env, name: &str, value: &str) -> Result<(), Failed> {
    secrets::put_value(env, name, value).await.map_err(|_| Failed {
        status: 503,
        message: "The app was made on GitHub, but its secrets could not be stored. Try again \
                  from the connection page.",
    })
}

/// Checks an installation the setup redirect names, with the app's own JWT,
/// and records it. Refused when the installation belongs to another app.
///
/// # Errors
///
/// [`Failed`] when the app does not exist, the installation is not this
/// app's, or GitHub or the database refuse.
pub async fn record_installation(
    db: Arc<dyn Database>,
    http: &dyn HttpClient,
    id: i64,
    now: i64,
) -> Result<Installation, Failed> {
    let app = app_row(db.clone()).await?.ok_or(NOT_CREATED)?;
    let key = private_key(db.clone()).await?;
    let jwt = app_jwt(&key, &app.client_id, now)?;
    let (status, body) =
        call(http, "GET", &format!("{API}/app/installations/{id}"), Some(&jwt), None).await?;
    if status == 404 {
        return Err(NOT_THIS_APP);
    }
    ok(status, "the installation")?;
    let (app_id, installation) = read_installation(&body)?;
    if app_id != app.app_id {
        return Err(NOT_THIS_APP);
    }
    save_installation(db, &installation, &stamp(now)).await?;
    Ok(installation)
}

/// The app's private key, from the secrets store for this isolate.
async fn private_key(db: Arc<dyn Database>) -> Result<RsaPrivateKey, Failed> {
    let stored = secrets::read_cached(db, PRIVATE_KEY, &secrets::unsealed())
        .await
        .map_err(|_| KEY_UNREADABLE)?
        .ok_or(KEY_UNREADABLE)?;
    parse_private_key(&stored.into_token())
}

/// Installation tokens this isolate has minted, by installation id, with
/// their unix expiry. Held in memory only.
static TOKENS: OnceLock<Mutex<HashMap<i64, (String, i64)>>> = OnceLock::new();

/// Which installation covers a repository, as this isolate last asked GitHub,
/// by `owner/name` (lower-cased), with the unix time the answer was taken. Only
/// positive answers are kept: a repository that does not exist yet is asked
/// again.
static COVERAGE: OnceLock<Mutex<HashMap<String, (Installation, i64)>>> = OnceLock::new();

/// How long a coverage answer is trusted, in seconds.
const COVERAGE_TTL_SECS: i64 = 300;

fn cached_token(id: i64, now: i64) -> Option<String> {
    let cache = TOKENS.get()?.lock().ok()?;
    let (token, expires) = cache.get(&id)?;
    token_is_fresh(*expires, now).then(|| token.clone())
}

fn remember_token(id: i64, token: &str, expires: i64) {
    if let Ok(mut cache) = TOKENS.get_or_init(Default::default).lock() {
        cache.insert(id, (token.to_owned(), expires));
    }
}

/// Drops the installation tokens and coverage answers this isolate holds, so
/// nothing minted for a removed app is used again here.
pub fn forget_cached() {
    if let Some(Ok(mut tokens)) = TOKENS.get().map(Mutex::lock) {
        tokens.clear();
    }
    if let Some(Ok(mut coverage)) = COVERAGE.get().map(Mutex::lock) {
        coverage.clear();
    }
}

fn coverage_key(owner: &str, name: &str) -> String {
    format!("{}/{}", owner.to_ascii_lowercase(), name.to_ascii_lowercase())
}

fn cached_coverage(key: &str, now: i64) -> Option<Installation> {
    let cache = COVERAGE.get()?.lock().ok()?;
    let (found, taken) = cache.get(key)?;
    (now - taken < COVERAGE_TTL_SECS).then(|| found.clone())
}

fn remember_coverage(key: String, found: Installation, now: i64) {
    if let Ok(mut cache) = COVERAGE.get_or_init(Default::default).lock() {
        cache.insert(key, (found, now));
    }
}

/// A token for the installation that covers `owner`, for a caller with no
/// repository in hand (creating one, or the connection check). The stored row
/// whose account matches; `repo` is only used for the fallback discovery.
/// `None` when no installation covers the owner.
///
/// # Errors
///
/// [`Failed`] when the app cannot sign or GitHub or the database refuse.
pub async fn token_for_owner(
    db: Arc<dyn Database>,
    http: &dyn HttpClient,
    owner: &str,
    now: i64,
) -> Result<Option<AppToken>, Failed> {
    if app_row(db.clone()).await?.is_none() {
        return Ok(None);
    }
    let rows = installations(db.clone()).await?;
    match pick_installation(&rows, owner) {
        Some(row) => {
            let row = row.clone();
            mint(db, http, &row, now).await.map(Some)
        }
        None => Ok(None),
    }
}

/// A token for the installation that covers one repository. An installation
/// on `all` repositories covers the owner's repositories outright. One on
/// `selected` (or an owner with no row) is asked GitHub, with the app's JWT,
/// whether it covers this repository: GitHub answers `404` when it does not,
/// and the answer is kept for a few minutes per isolate. `None` when no
/// installation of this app covers the repository, so the personal token is
/// the one to use.
///
/// # Errors
///
/// [`Failed`] when the app cannot sign or GitHub or the database refuse.
pub async fn token_for_repo(
    db: Arc<dyn Database>,
    http: &dyn HttpClient,
    owner: &str,
    name: &str,
    now: i64,
) -> Result<Option<AppToken>, Failed> {
    if app_row(db.clone()).await?.is_none() {
        return Ok(None);
    }
    let rows = installations(db.clone()).await?;
    if let Some(row) = pick_installation(&rows, owner).filter(|row| row.selection == "all") {
        let row = row.clone();
        return mint(db, http, &row, now).await.map(Some);
    }
    let key = coverage_key(owner, name);
    let covering = match cached_coverage(&key, now) {
        Some(found) => Some(found),
        None => {
            let found = discover(db.clone(), http, owner, name, now).await?;
            if let Some(found) = &found {
                remember_coverage(key, found.clone(), now);
            }
            found
        }
    };
    match covering {
        Some(found) => mint(db, http, &found, now).await.map(Some),
        None => Ok(None),
    }
}

/// The installation of one repository, asked of GitHub with the app's JWT.
/// Returned for use when it belongs to this app, and never stored; `None`
/// when GitHub has no installation for it (`404`).
async fn discover(
    db: Arc<dyn Database>,
    http: &dyn HttpClient,
    owner: &str,
    repo: &str,
    now: i64,
) -> Result<Option<Installation>, Failed> {
    let app = app_row(db.clone()).await?.ok_or(NOT_CREATED)?;
    let key = private_key(db.clone()).await?;
    let jwt = app_jwt(&key, &app.client_id, now)?;
    let url = format!("{API}/repos/{}/installation", path(&format!("{owner}/{repo}")));
    let (status, body) = call(http, "GET", &url, Some(&jwt), None).await?;
    if status == 404 {
        return Ok(None);
    }
    ok(status, "the repository's installation")?;
    covering_installation(&body, app.app_id)
}

/// The installation a repository lookup answered with, when it belongs to
/// `app_id`. Pure and never stored: a coverage answer is used for one token
/// and then forgotten, so a stranger's installation of the public app cannot
/// add a row through the fallback.
///
/// # Errors
///
/// [`Failed`] when the answer does not parse.
pub fn covering_installation(body: &str, app_id: i64) -> Result<Option<Installation>, Failed> {
    let (found_app, installation) = read_installation(body)?;
    Ok((found_app == app_id).then_some(installation))
}

/// The installation's token: cached while fresh, else minted with the app's
/// JWT and cached.
async fn mint(
    db: Arc<dyn Database>,
    http: &dyn HttpClient,
    installation: &Installation,
    now: i64,
) -> Result<AppToken, Failed> {
    let user_account = installation.is_user();
    if let Some(token) = cached_token(installation.id, now) {
        return Ok(AppToken { token, user_account });
    }
    let app = app_row(db.clone()).await?.ok_or(NOT_CREATED)?;
    let key = private_key(db).await?;
    let jwt = app_jwt(&key, &app.client_id, now)?;
    let url = format!("{API}/app/installations/{}/access_tokens", installation.id);
    let (status, body) = call(http, "POST", &url, Some(&jwt), Some("{}".to_owned())).await?;
    ok(status, "the installation token")?;
    let (token, expires) = read_token(&body, now)?;
    remember_token(installation.id, &token, expires);
    Ok(AppToken { token, user_account })
}

/// The first installation the console knows of, for a caller with no owner
/// in hand (the connection check).
///
/// # Errors
///
/// [`Failed`] when the database cannot answer.
pub async fn first_installation(db: Arc<dyn Database>) -> Result<Option<Installation>, Failed> {
    Ok(installations(db).await?.into_iter().next())
}

/// An installation's token by its id, for listing the repositories it can see.
///
/// # Errors
///
/// [`Failed`] as [`token_for_owner`].
pub async fn token_for_installation(
    db: Arc<dyn Database>,
    http: &dyn HttpClient,
    installation: &Installation,
    now: i64,
) -> Result<AppToken, Failed> {
    mint(db, http, installation, now).await
}

/// RFC 3339 for unix seconds, the shape the console stores.
pub fn stamp(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|at| at.format(&Rfc3339).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
