//! The Search Console slice of the Keep Shipping console
//! ([#274](https://github.com/Keep-Shipping/harness/issues/274)): a page
//! that reads a domain's verification and sitemap state live from Google,
//! and the Terraform change that gets a domain there. Reads only — the one
//! thing the module ever "writes" is generated module text; no Google API
//! call mutates anything.
//!
//! Authentication mirrors the engine's `gsc.sitemap_submit` step exactly
//! (`crates/engine/src/gsc_sitemap_submit.rs`): a Google service-account
//! key, an RS256 JWT asserted at the OAuth2 token endpoint, a bearer token
//! spent on plain `webmasters/v3` calls. The key is parsed once at module
//! construction and never leaves this file — not the log, not a response,
//! not an error message.
//!
//! Without the `GOOGLE_SERVICE_ACCOUNT_JSON` secret the status reads
//! degrade to a `not-ready` answer that says so in plain words; generating
//! the Terraform module never needed the secret and keeps working.

use std::fmt::Debug;
use std::sync::Arc;

use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use cratefield_core::axum::body::Bytes;
use cratefield_core::axum::extract::{Query, State};
use cratefield_core::axum::http::{HeaderMap, StatusCode};
use cratefield_core::axum::response::{IntoResponse, Response};
use cratefield_core::axum::routing::{get, post};
use cratefield_core::axum::{Json, Router};
use cratefield_core::{
    Action, AnyError, Audience, Auth, AuthError, BoxFuture, Clock, Config, ConfigError, HttpClient,
    Migrations, Module, ModuleContext, Outcome, Port, Problem, SLUGS, Surface,
};

/// The Search Console API root, as settled in the engine step
/// (https://developers.google.com/webmaster-tools/v1/).
const API_ROOT: &str = "https://www.googleapis.com/webmasters/v3";

/// The OAuth2 scope the assertion asks for: Search Console, nothing else.
const SCOPE: &str = "https://www.googleapis.com/auth/webmasters";

/// Where the assertion is exchanged for a token, when the key names no
/// `token_uri` of its own (Google's own service-account keys do).
const TOKEN_URI_FALLBACK: &str = "https://oauth2.googleapis.com/token";

/// How long the assertion is valid for; Google asks for well under an hour.
const TOKEN_LIFETIME_SECS: i64 = 3600;

/// The OAuth2 grant type of the JWT-bearer exchange, already percent-encoded
/// for the form body (RFC 7523 §2.1).
const GRANT_TYPE: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";

/// The JWT header, as fixed bytes: the algorithm is not a parameter here,
/// it is what this module does.
const ASSERTION_HEADER: &[u8] = b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

/// The name — never the value — of the secret that carries the key.
pub const SECRET_NAME: &str = "GOOGLE_SERVICE_ACCOUNT_JSON";

/// The Terraform providers the generated module pins. Majors checked
/// against the provider sources (2026-10-09): `hashicorp/google` v8 (latest
/// v8.6.0) for the `google_site_verification_*` resources, and
/// `cloudflare/cloudflare` v5 (latest v5.27.0), where the DNS record
/// resource is `cloudflare_dns_record` and its payload argument is
/// `content` (v4's `cloudflare_record`/`value` pair is gone in v5).
const GOOGLE_PROVIDER_VERSION: &str = "~> 8.0";
const CLOUDFLARE_PROVIDER_VERSION: &str = "~> 5.0";

// ---------------------------------------------------------------------------
// The service account

/// The fields of a Google service-account JSON key this module uses. The
/// whole key is parsed out of the secret and never leaves this struct: what
/// travels is the signed assertion and the bearer token, never the key.
/// Deliberately not `Debug` (and `Gsc`'s own `Debug` says nothing either),
/// so no `tracing` or panic path can ever print the key.
#[derive(Clone)]
struct ServiceAccount {
    /// The issuer of the assertion, e.g. `sa@project.iam.gserviceaccount.com`.
    client_email: String,
    /// The PKCS#8 PEM RSA key the assertion is signed with.
    private_key: String,
    /// Where the assertion is exchanged for a token.
    token_uri: String,
}

impl ServiceAccount {
    /// Reads the three fields this module uses out of the service-account
    /// JSON key. The reason never quotes what it found: the field values
    /// are the secret.
    fn parse(credentials: &str) -> Result<ServiceAccount, String> {
        let json: serde_json::Value = serde_json::from_str(credentials)
            .map_err(|_| "the secret is not a Google service-account JSON key".to_owned())?;
        let token_uri = match json.get("token_uri").and_then(serde_json::Value::as_str) {
            Some(uri) if !uri.is_empty() => uri.to_owned(),
            _ => TOKEN_URI_FALLBACK.to_owned(),
        };
        if !token_uri.starts_with("https://") {
            return Err("`token_uri` must be an absolute https URL".to_owned());
        }
        Ok(ServiceAccount {
            client_email: string_field(&json, "client_email")?,
            private_key: string_field(&json, "private_key")?,
            token_uri,
        })
    }
}

/// One required, non-empty string field of the service-account key.
fn string_field(json: &serde_json::Value, name: &str) -> Result<String, String> {
    match json.get(name).and_then(serde_json::Value::as_str) {
        Some(value) if !value.is_empty() => Ok(value.to_owned()),
        _ => Err(format!("the key does not carry a `{name}` string")),
    }
}

/// What the deployment's secret resolved to at module construction.
#[derive(Clone)]
enum Credentials {
    /// No secret (or a blank one): status reads answer not-ready.
    Missing,
    /// A secret was set but it is not a usable key; the text is the
    /// plain-words reason (never a quote of the value).
    Invalid(String),
    /// A parsed key.
    Key(ServiceAccount),
}

// ---------------------------------------------------------------------------
// The client

/// Reads Search Console as a service account, live, on every status request:
/// nothing is cached and nothing is stored. The only write in this module is
/// Terraform text generation, which is pure. `Clone` shares the same client:
/// every field is an `Arc` or plain text.
#[derive(Clone)]
pub struct Gsc {
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    credentials: Credentials,
}

impl Debug for Gsc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The credentials are the secret: the debug output says whether
        // they are there, never what they are.
        let credentials = match &self.credentials {
            Credentials::Missing => "missing",
            Credentials::Invalid(_) => "invalid",
            Credentials::Key(_) => "set",
        };
        f.debug_struct("Gsc").field("credentials", &credentials).finish_non_exhaustive()
    }
}

impl Gsc {
    /// Builds the client over `http` and `clock`, with the raw
    /// service-account JSON secret (blank counts as absent — the same rule
    /// every other secret here reads by).
    #[must_use]
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        credentials: Option<String>,
    ) -> Self {
        let credentials = match credentials {
            None => Credentials::Missing,
            Some(json) => match ServiceAccount::parse(&json) {
                Ok(key) => Credentials::Key(key),
                Err(reason) => {
                    tracing::warn!(reason = %reason, "the Search Console service account secret is unusable");
                    Credentials::Invalid(reason)
                }
            },
        };
        Self { http, clock, credentials }
    }

    /// Reads the domain property's state: is it shared with the service
    /// account (`verified`), and has a sitemap been submitted. Two live
    /// reads, one bearer token, nothing stored.
    pub async fn read_status(&self, zone: &str) -> Result<Status, NotReady> {
        let account = match &self.credentials {
            Credentials::Missing => {
                return Err(NotReady(format!(
                    "Search Console reads aren't set up yet — the {SECRET_NAME} secret is missing"
                )));
            }
            Credentials::Invalid(reason) => {
                return Err(NotReady(format!("Search Console reads aren't set up yet — {reason}")));
            }
            Credentials::Key(account) => account,
        };
        let token = match bearer_token(account, self.clock.as_ref(), self.http.as_ref()).await {
            Ok(token) => token,
            Err(reason) => {
                tracing::warn!(reason = %reason, "the Search Console token exchange failed");
                return Err(not_available());
            }
        };

        // `sites.get`, per https://developers.google.com/webmaster-tools/v1/sites/get:
        // `GET /webmasters/v3/sites/{siteUrl}` answering `{siteUrl,
        // permissionLevel}`. Not shared with the service account is the
        // expected not-yet state, not a failure: 403/404 read as unverified.
        let site = format!("sc-domain:{zone}");
        let sites_url = format!("{API_ROOT}/sites/{}", percent_encode(&site));
        let verified = match read_json(self.http.as_ref(), &sites_url, &token).await {
            Ok(json) => matches!(
                json.get("permissionLevel").and_then(serde_json::Value::as_str),
                Some("siteOwner" | "siteFullUser" | "siteRestrictedUser")
            ),
            Err(ReadError::Status(403 | 404)) => {
                tracing::info!("the domain property is not shared with the service account");
                false
            }
            Err(ReadError::Status(status)) => {
                tracing::warn!(status, "Search Console refused the sites read");
                return Err(not_available());
            }
            Err(ReadError::Transport(reason)) => {
                tracing::warn!(reason = %reason, "the Search Console sites read could not be sent");
                return Err(not_available());
            }
        };

        // `sitemaps.list`, per https://developers.google.com/webmaster-tools/v1/sitemaps/list:
        // `GET /webmasters/v3/sites/{siteUrl}/sitemaps` answering
        // `{sitemap: [...]}`, each entry a `WmxSitemap` whose `path` is the
        // sitemap's URL.
        let sitemaps_url = format!("{API_ROOT}/sites/{}/sitemaps", percent_encode(&site));
        let sitemap = match read_json(self.http.as_ref(), &sitemaps_url, &token).await {
            Ok(json) => json
                .get("sitemap")
                .and_then(serde_json::Value::as_array)
                .and_then(|entries| entries.first())
                .and_then(|entry| entry.get("path"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            Err(ReadError::Status(status)) => {
                tracing::warn!(status, "Search Console refused the sitemaps read");
                return Err(not_available());
            }
            Err(ReadError::Transport(reason)) => {
                tracing::warn!(reason = %reason, "the Search Console sitemaps read could not be sent");
                return Err(not_available());
            }
        };
        Ok(Status {
            verified,
            sitemap_submitted: sitemap.is_some(),
            sitemap,
            last_read_at: iso(now(self.clock.as_ref())),
        })
    }
}

/// What one live read found. The JSON twin serves exactly these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The domain property is shared with the service account at one of the
    /// levels that can read it (`siteOwner`, `siteFullUser`,
    /// `siteRestrictedUser` — `siteUnverifiedUser` is not verified).
    pub verified: bool,
    /// At least one sitemap is on the property.
    pub sitemap_submitted: bool,
    /// The first sitemap's URL, when there is one.
    pub sitemap: Option<String>,
    /// When this was read, RFC 3339 from the injected clock.
    pub last_read_at: String,
}

/// Why a status read cannot answer, in plain words: safe to render on the
/// page and safe to ship as a problem `detail` (nothing here ever quotes
/// upstream bodies or key material — that stays in the log).
#[derive(Debug, Clone)]
pub struct NotReady(String);

impl NotReady {
    /// The problem+json answer a JSON route serves for this.
    #[must_use]
    pub fn problem(self) -> Problem {
        Problem::not_ready(self.0)
    }

    /// The plain words themselves, for the page that renders them.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Search Console itself did not answer as documented: the deployment's
/// 503, the details in the log.
fn not_available() -> NotReady {
    NotReady("Search Console is not available right now".to_owned())
}

/// How one API read went.
enum ReadError {
    /// A non-2xx status.
    Status(u16),
    /// The request never went out or the answer was unreadable.
    Transport(String),
}

/// GETs one Search Console URL with the bearer token, answering the parsed
/// JSON body or how the read failed.
async fn read_json(
    http: &dyn HttpClient,
    url: &str,
    token: &str,
) -> Result<serde_json::Value, ReadError> {
    let request = http::Request::builder()
        .method("GET")
        .uri(url)
        .header("Authorization", format!("Bearer {token}"))
        .body(Bytes::new())
        .map_err(|error| ReadError::Transport(error.to_string()))?;
    let response = send(http, request).await.map_err(ReadError::Transport)?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(ReadError::Status(status));
    }
    serde_json::from_slice(response.body().as_ref())
        .map_err(|_| ReadError::Transport("the answer is not JSON".to_owned()))
}

/// Signs the JWT assertion and exchanges it for a bearer token. The
/// assertion rides only in this one form body; nothing about it is logged
/// or returned. Same flow as the engine's `gsc.sitemap_submit` step.
async fn bearer_token(
    account: &ServiceAccount,
    clock: &dyn Clock,
    http: &dyn HttpClient,
) -> Result<String, String> {
    let assertion = mint_assertion(account, clock)?;
    let request = http::Request::builder()
        .method("POST")
        .uri(&account.token_uri)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Bytes::from(format!("grant_type={GRANT_TYPE}&assertion={assertion}")))
        .map_err(|error| error.to_string())?;
    let response = send(http, request).await?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("the token endpoint refused the service account with HTTP {status}"));
    }
    let token: serde_json::Value = serde_json::from_slice(response.body().as_ref())
        .map_err(|_| "the token endpoint answered with a body that is not JSON".to_owned())?;
    token
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "the token endpoint answered without an `access_token`".to_owned())
}

/// Signs the assertion: two base64url segments joined with a dot, then the
/// RS256 signature as a third. `iat` comes from the injected clock, so a
/// test run stays instant and the same inputs mint the same assertion.
fn mint_assertion(account: &ServiceAccount, clock: &dyn Clock) -> Result<String, String> {
    let key = RsaPrivateKey::from_pkcs8_pem(&account.private_key)
        .map_err(|_| "`private_key` is not a PKCS#8 PEM RSA key".to_owned())?;
    let iat = now(clock).unix_timestamp();
    let claims = serde_json::json!({
        "iss": account.client_email,
        "scope": SCOPE,
        "aud": account.token_uri,
        "iat": iat,
        "exp": iat + TOKEN_LIFETIME_SECS,
    })
    .to_string();
    let header = base64url(ASSERTION_HEADER);
    let claims = base64url(claims.as_bytes());
    let signing_input = format!("{header}.{claims}");
    let signature = SigningKey::<Sha256>::new(key).sign(signing_input.as_bytes()).to_vec();
    Ok(format!("{signing_input}.{}", base64url(&signature)))
}

/// Sends one request, turning a transport refusal into a plain error.
async fn send(
    http: &dyn HttpClient,
    request: http::Request<Bytes>,
) -> Result<http::Response<Bytes>, String> {
    http.send(request).await.map_err(|error| error.to_string())
}

/// The injected clock's instant, in UTC.
fn now(clock: &dyn Clock) -> OffsetDateTime {
    clock.now()
}

/// RFC 3339 for responses: whole seconds, UTC (`Z`) — the same shape the
/// billing module stores.
fn iso(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

/// Percent-encodes every byte outside the RFC 3986 unreserved set, so a
/// site identifier can ride inside one path segment. Same as the engine
/// step.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// The base64url alphabet (RFC 4648 §5), unpadded as JWS requires (RFC 7515
/// §2). Hand-rolled, like the engine step's: a JWT segment does not earn a
/// dependency.
const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let bits = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        out.push(URL_ALPHABET[(bits >> 18) as usize & 63] as char);
        out.push(URL_ALPHABET[(bits >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(URL_ALPHABET[(bits >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(URL_ALPHABET[bits as usize & 63] as char);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Validation

/// The zone the caller asked about: `Ok(None)` when the query named none
/// (the page asks for one), an `Err` problem when it named one that cannot
/// be a domain (400, plain words), `Ok(Some)` when it did. A zone is a
/// lowercase hostname: no scheme, no path, no uppercase, nothing but
/// letters, digits, dots and hyphens with well-formed labels.
fn zone_of(raw: Option<&str>) -> Result<Option<String>, Problem> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(None);
    };
    let refused = |why: &str| Problem::validation_failed(format!("that zone won't work: {why}"));
    if raw.contains("://") || raw.contains("//") {
        return Err(refused("give the domain alone, no `https://`"));
    }
    if raw.contains(['/', '?', '#', ' ', '\t']) {
        return Err(refused("give the domain alone, without a path"));
    }
    if raw != raw.to_ascii_lowercase() {
        return Err(refused("domains are lowercase"));
    }
    if raw.len() > 253
        || !raw.starts_with(|c: char| c.is_ascii_alphanumeric())
        || !raw.ends_with(|c: char| c.is_ascii_alphanumeric())
        || !raw.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(refused("that does not read as a domain name"));
    }
    let labels: Vec<&str> = raw.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
        return Err(refused("that does not read as a domain name"));
    }
    Ok(Some(raw.to_owned()))
}

/// The owners named on the form: comma- or newline-separated, trimmed,
/// deduplicated, none empty.
fn owners_of(raw: &str) -> Result<Vec<String>, Problem> {
    let mut owners: Vec<String> = Vec::new();
    for owner in raw.split([',', '\n']) {
        let owner = owner.trim();
        if !owner.is_empty() && !owners.iter().any(|seen| seen.eq_ignore_ascii_case(owner)) {
            owners.push(owner.to_owned());
        }
    }
    if owners.is_empty() {
        return Err(Problem::validation_failed(
            "name at least one owner — the email the Search Console property is shared with",
        ));
    }
    Ok(owners)
}

/// The sitemap named on the form, when there is one: absolute https, on the
/// zone itself or its `www` alias.
fn sitemap_of(raw: &str, zone: &str) -> Result<Option<String>, Problem> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let refused = |why: &str| Problem::validation_failed(format!("that sitemap won't work: {why}"));
    let rest = raw.strip_prefix("https://").ok_or_else(|| refused("it must be an https URL"))?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = host.rsplit('@').next().unwrap_or_default();
    let host = host.split(':').next().unwrap_or_default();
    let alias = format!("www.{zone}");
    if host.eq_ignore_ascii_case(zone) || host.eq_ignore_ascii_case(alias.as_str()) {
        Ok(Some(raw.to_owned()))
    } else {
        Err(refused(&format!("it must live on {zone} or www.{zone}")))
    }
}

/// Decodes one `application/x-www-form-urlencoded` body into its field
/// values: `+` is a space, `%xx` is a byte. Hand-rolled, like the encoder
/// above — the form has three fields, not a framework's worth.
fn form_fields(body: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(body);
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (percent_decode(name), percent_decode(value)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'+' => {
                out.push(b' ');
                at += 1;
            }
            b'%' if at + 2 < bytes.len() => match u8::from_str_radix(&text[at + 1..at + 3], 16) {
                Ok(byte) => {
                    out.push(byte);
                    at += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    at += 1;
                }
            },
            other => {
                out.push(other);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// The Terraform module generator

/// Generates the `search-console/main.tf` module text: the DNS token Google
/// mints, the Cloudflare TXT record carrying it, the domain property claimed
/// with it, and the human owners who share it. Pure — the same inputs always
/// produce the same bytes, which the tests pin.
///
/// Attribute names and provider majors verified against the provider
/// sources (2026-10-09): `google_site_verification_token` (data source,
/// `google` v8) exports `token`; `google_site_verification_web_resource`
/// takes `site { type, identifier }` and `verification_method`; and in
/// `cloudflare` v5 the record resource is `cloudflare_dns_record` with
/// `zone_id`/`name`/`type`/`content`/`ttl`.
#[must_use]
pub fn search_console_module(zone: &str, owners: &[&str], sitemap: Option<&str>) -> String {
    let owners_block =
        owners.iter().map(|owner| format!("    \"{owner}\",")).collect::<Vec<_>>().join("\n");
    let sitemap_output = match sitemap {
        Some(sitemap) => format!(
            "\n# The sitemap the workflow submits once the property is verified.\n\
             output \"sitemap_url\" {{\n  description = \"The sitemap gsc.sitemap_submit submits.\"\n  value       = \"{sitemap}\"\n}}\n"
        ),
        None => String::new(),
    };
    format!(
        r#"# Search Console domain verification for {zone}.
# Part of the Keep Shipping console (issue #274). The change lands as a
# pull request through the edit-as-code path; nothing is applied directly.
#
# Sitemap submission has no Terraform resource: the workflow runs the
# `gsc.sitemap_submit` step right after `tofu.apply`, pointed at the
# `site_url` output below.

terraform {{
  required_providers {{
    google = {{
      source  = "hashicorp/google"
      version = "{GOOGLE_PROVIDER_VERSION}"
    }}
    cloudflare = {{
      source  = "cloudflare/cloudflare"
      version = "{CLOUDFLARE_PROVIDER_VERSION}"
    }}
  }}
}}

variable "zone" {{
  type        = string
  description = "The domain to verify."
  default     = "{zone}"
}}

variable "owners" {{
  type        = list(string)
  description = "Emails that share ownership of the verified Search Console property."
  default = [
{owners_block}
  ]
}}

variable "cloudflare_zone_id" {{
  type        = string
  description = "The Cloudflare zone id that hosts {zone}'s DNS."
}}

# The verification token Google's Site Verification API mints for the
# service account: the TXT value it looks for on the zone root.
data "google_site_verification_token" "domain" {{
  type                = "INET_DOMAIN"
  identifier          = var.zone
  verification_method = "DNS_TXT"
}}

# The TXT record Google checks, on the zone apex.
resource "cloudflare_dns_record" "search_console_verification" {{
  zone_id = var.cloudflare_zone_id
  name    = var.zone
  type    = "TXT"
  content = data.google_site_verification_token.domain.token
  ttl     = 3600
}}

# Once the record is live, this claims the domain property
# (`sc-domain:var.zone`) for the service account.
resource "google_site_verification_web_resource" "domain" {{
  site {{
    type       = "INET_DOMAIN"
    identifier = var.zone
  }}
  verification_method = "DNS_TXT"
  depends_on          = [cloudflare_dns_record.search_console_verification]
}}

# Everyone named at generation time shares ownership of the property.
resource "google_site_verification_owner" "owners" {{
  for_each        = toset(var.owners)
  web_resource_id = google_site_verification_web_resource.domain.id
  email           = each.value
}}

output "site_url" {{
  description = "The Search Console property the workflow submits sitemaps for."
  value       = "sc-domain:${{var.zone}}"
}}
{sitemap_output}"#
    )
}

// ---------------------------------------------------------------------------
// The module and its routes

/// The console module: mounted at `/v1/console`, so the JSON twin is exactly
/// `GET /v1/console/gsc` and the page and the change generator sit beside it
/// at `/v1/console/search-console` and `/v1/console/search-console/module`.
/// (The harness nests every module under `/v1/<name>` and mounts nothing but
/// `/.well-known`, `/ui` and the `/__*` probes at the root, so `/v1` is the
/// shallowest a served path can be.)
pub struct GscModule {
    gsc: Gsc,
}

/// Builds the console module over a [`Gsc`] client — the composition the
/// worker freezes into its isolate and the tests mount over fakes.
#[must_use]
pub fn gsc_module(gsc: Gsc) -> GscModule {
    GscModule { gsc }
}

struct ModuleState {
    ctx: ModuleContext,
    gsc: Gsc,
}

impl Module for GscModule {
    fn name(&self) -> &'static str {
        "console"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        // Reads go out through the client the module was built with; the
        // database has nothing to do here — nothing is stored.
        &[]
    }

    fn optional(&self) -> &'static [Port] {
        // Auth names the signed-in caller; without the port every route
        // answers a not-ready response rather than serving.
        &[Port::Auth]
    }

    fn tables(&self) -> &'static [&'static str] {
        &[]
    }

    fn migrations(&self) -> Migrations {
        Migrations { sqlite: &[], postgres: &[] }
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        // The service-account secret is optional by design: without it the
        // status reads answer not-ready and the module generator keeps
        // working.
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> Router {
        let state = Arc::new(ModuleState { ctx, gsc: self.gsc.clone() });
        Router::new()
            .route("/search-console", get(search_console_page))
            .route("/gsc", get(gsc_status))
            .route("/search-console/module", post(generate_module))
            .with_state(state)
    }

    fn surface(&self) -> Surface {
        Surface::new()
            .action(
                Action::get("search-console", "/search-console")
                    .audience(Audience::Subject)
                    .outcome(Outcome::Json),
            )
            .action(Action::get("gsc", "/gsc").audience(Audience::Subject).outcome(Outcome::Json))
            .action(
                Action::post("search-console-module", "/search-console/module")
                    .audience(Audience::Subject),
            )
    }

    fn scheduled<'a>(
        &'a self,
        _ctx: &'a ModuleContext,
        _cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async { Ok(()) })
    }
}

/// Who the caller is, in the vocabulary this module's three routes answer
/// with: signed in, not signed in (401), or nobody could know (503). The
/// signed-in variant carries the subject's id, because the change payload
/// names its `author` — the one place the caller's own identity leaves this
/// module. Search Console access itself still runs through the venture's
/// service account, never through the caller's own grant.
enum Caller {
    SignedIn(String),
    NeedsSignIn,
    NotReady(String),
}

/// Resolves the caller through the auth port, exactly as the billing module
/// does: no port is the deployment's misconfiguration (503), an anonymous
/// caller's is their 401, an unreachable provider is no reason to serve
/// anonymously (503).
async fn caller_of(state: &ModuleState, headers: &HeaderMap) -> Caller {
    let Some(auth) = state.ctx.ports.auth.clone() else {
        return Caller::NotReady(
            "the console needs an identity provider to name a caller (no auth port is wired)"
                .to_owned(),
        );
    };
    // The console session cookie counts as the bearer header it carries.
    match auth.identify(&crate::signin::session_credentials(headers)).await {
        Ok(caller) => match caller.id() {
            Some(id) => Caller::SignedIn(id.to_owned()),
            None => Caller::NeedsSignIn,
        },
        Err(AuthError::Unavailable(detail)) => {
            tracing::warn!(%detail, "the identity provider could not be reached");
            Caller::NotReady("the identity provider is unavailable".to_owned())
        }
        Err(_) => Caller::NeedsSignIn,
    }
}

/// `GET /v1/console/search-console?zone=<domain>` — the page. Without a
/// `zone` it asks for one; with one it reads Google live and answers with
/// chips, the one-time setup and the change form.
async fn search_console_page(
    State(state): State<Arc<ModuleState>>,
    Query(query): Query<ZoneQuery>,
    headers: HeaderMap,
) -> Response {
    match caller_of(&state, &headers).await {
        Caller::NotReady(why) => not_ready_page(&why),
        Caller::NeedsSignIn => sign_in_page(),
        Caller::SignedIn(_) => match zone_of(query.zone.as_deref()) {
            Err(problem) => problem.into_response(),
            Ok(None) => html_page(StatusCode::OK, &render_page(None, None)),
            Ok(Some(zone)) => match state.gsc.read_status(&zone).await {
                Ok(status) => html_page(StatusCode::OK, &render_page(Some(&zone), Some(&status))),
                Err(not_ready) => not_ready_page(not_ready.as_str()),
            },
        },
    }
}

/// The `zone` query parameter, optional on both status routes.
#[derive(Debug, serde::Deserialize)]
struct ZoneQuery {
    zone: Option<String>,
}

/// `GET /v1/console/gsc?zone=<domain>` — the JSON twin of the page: the seam
/// the Standard setup page embeds. `{"zone", "verified",
/// "sitemap_submitted", "sitemap", "last_read_at"}`.
async fn gsc_status(
    State(state): State<Arc<ModuleState>>,
    Query(query): Query<ZoneQuery>,
    headers: HeaderMap,
) -> Response {
    match caller_of(&state, &headers).await {
        Caller::NotReady(why) => Problem::not_ready(why).into_response(),
        Caller::NeedsSignIn => Problem::new(&SLUGS.unauthenticated).into_response(),
        Caller::SignedIn(_) => {
            let zone = match zone_of(query.zone.as_deref()) {
                Ok(Some(zone)) => zone,
                Ok(None) => {
                    return Problem::validation_failed(
                        "name the domain to look up: ?zone=example.com",
                    )
                    .into_response();
                }
                Err(problem) => return problem.into_response(),
            };
            match state.gsc.read_status(&zone).await {
                Ok(status) => Json(serde_json::json!({
                    "zone": zone,
                    "verified": status.verified,
                    "sitemap_submitted": status.sitemap_submitted,
                    "sitemap": status.sitemap,
                    "last_read_at": status.last_read_at,
                }))
                .into_response(),
                Err(not_ready) => not_ready.problem().into_response(),
            }
        }
    }
}

/// `POST /v1/console/search-console/module` — generates the Terraform
/// module. Default answer: the module text as a `text/x-terraform`
/// download; with `Accept: application/json`, the edit-as-code change
/// payload instead — `{"zone", "title", "summary_md", "author",
/// "files":[{"path","content"}]}`. Nothing here talks to Google, and so
/// nothing here needs the service-account secret.
async fn generate_module(
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let author = match caller_of(&state, &headers).await {
        Caller::NotReady(why) => return Problem::not_ready(why).into_response(),
        Caller::NeedsSignIn => return Problem::new(&SLUGS.unauthenticated).into_response(),
        Caller::SignedIn(author) => author,
    };
    let form = ModuleForm::from_fields(&form_fields(body.as_ref()));
    let zone = match zone_of(Some(&form.zone)) {
        Ok(Some(zone)) => zone,
        Ok(None) => {
            return Problem::validation_failed("that zone won't work: no domain was given")
                .into_response();
        }
        Err(problem) => return problem.into_response(),
    };
    let owners = match owners_of(&form.owners) {
        Ok(owners) => owners,
        Err(problem) => return problem.into_response(),
    };
    let sitemap = match sitemap_of(&form.sitemap, &zone) {
        Ok(sitemap) => sitemap,
        Err(problem) => return problem.into_response(),
    };
    let owner_refs: Vec<&str> = owners.iter().map(String::as_str).collect();
    let module_text = search_console_module(&zone, &owner_refs, sitemap.as_deref());

    let wants_json = headers
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("application/json"));
    if wants_json {
        // The edit-as-code change payload, shaped exactly for the sibling
        // module's ingest — `edits::propose({zone, title, summary_md,
        // files, author})` (issue #170): this body is what the merge
        // adapter feeds that call, so the keys are its signature, not ours.
        return Json(serde_json::json!({
            "zone": zone,
            "title": format!("Search Console: verify {zone}"),
            "summary_md": format!(
                "Add Search Console domain verification for {zone}\n\n\
                 Generated from the Keep Shipping console (issue #274): the \
                 DNS verification token, the TXT record carrying it, the \
                 sc-domain:{zone} property, and the owners who share it. \
                 Sitemap submission follows as a gsc.sitemap_submit step."
            ),
            "author": author,
            "files": [{ "path": "search-console/main.tf", "content": module_text }],
        }))
        .into_response();
    }
    match http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/x-terraform")
        .header("content-disposition", "attachment; filename=\"search-console.tf\"")
        .body(cratefield_core::axum::body::Body::from(module_text))
    {
        Ok(response) => response.into_response(),
        Err(error) => {
            tracing::warn!(error = %error, "the module download could not be built");
            Problem::internal().into_response()
        }
    }
}

/// The change the form asks for: `zone`, `owners` and `sitemap`,
/// form-encoded. The last value of a repeated field wins, like a browser
/// resubmitting.
struct ModuleForm {
    zone: String,
    owners: String,
    sitemap: String,
}

impl ModuleForm {
    fn from_fields(fields: &[(String, String)]) -> Self {
        let field = |name: &str| {
            fields
                .iter()
                .rfind(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
                .unwrap_or_default()
        };
        Self { zone: field("zone"), owners: field("owners"), sitemap: field("sitemap") }
    }
}

// ---------------------------------------------------------------------------
// The page

/// Renders the console page: status chips in plain words, the one-time setup
/// and the change form, in the venture's design tokens
/// (`src/mail-theme.json`). No Terraform code anywhere on the page — that
/// lives in the pull request / download.
fn render_page(zone: Option<&str>, status: Option<&Status>) -> String {
    let heading_line = zone.map_or_else(|| "your domain".to_owned(), escape);
    let (chips, status_card_heading) = match (zone, status) {
        (Some(zone), Some(status)) => {
            let verified = if status.verified { "Verified" } else { "Not verified yet" };
            let sitemap =
                if status.sitemap_submitted { "Sitemap submitted" } else { "No sitemap yet" };
            let sitemap_line = status.sitemap.as_deref().map_or_else(String::new, |path| {
                format!("<p class=\"mono small\">{}</p>", escape(path))
            });
            (
                format!(
                    "<div class=\"chips\">\
                       <span class=\"chip {}\">{verified}</span>\
                       <span class=\"chip {}\">{sitemap}</span>\
                     </div>\
                     {sitemap_line}\
                     <p class=\"small muted\">Last checked {}</p>",
                    if status.verified { "good" } else { "" },
                    if status.sitemap_submitted { "good" } else { "" },
                    escape(&plain_stamp(&status.last_read_at)),
                ),
                format!("Where {} stands", escape(zone)),
            )
        }
        (Some(_), None) => (String::new(), String::new()),
        (None, _) => (
            "<p class=\"small muted\">Look up a domain to see where it stands.</p>".to_owned(),
            "Where you stand".to_owned(),
        ),
    };
    let zone_value = zone.map(escape).unwrap_or_default();
    document(&format!(
        r#"<h1>Search Console</h1>
<p class="sub">Get {heading_line} into Google search results. Part of Standard setup.</p>

<section class="card" aria-label="Status">
  <h2>{status_card_heading}</h2>
  {chips}
  <form method="get" action="/v1/console/search-console">
    <label for="lookup">Look up a domain</label>
    <input id="lookup" name="zone" class="mono" autocomplete="off" spellcheck="false"
           placeholder="example.com" value="{zone_value}">
    <button type="submit">Look it up</button>
  </form>
</section>

<section class="card" aria-label="One-time setup">
  <h2>One-time setup</h2>
  <ol>
    <li>Create a Google service account for your project.</li>
    <li>In Search Console, open Settings &rarr; Users and add the service
      account's email as an owner of the domain property. This one grant
      needs a human click.</li>
    <li>Give the worker the account's key as its <code>{SECRET_NAME}</code>
      secret. The key file stays with you &mdash; only its name is mentioned
      here.</li>
  </ol>
</section>

<section class="card" aria-label="Make the Terraform change">
  <h2>Make the Terraform change</h2>
  <form method="post" action="/v1/console/search-console/module">
    <label for="zone">Domain</label>
    <input id="zone" name="zone" class="mono" autocomplete="off" spellcheck="false"
           placeholder="example.com" value="{zone_value}" required>
    <label for="owners">Owners</label>
    <input id="owners" name="owners" class="mono" autocomplete="off"
           placeholder="you@example.com, teammate@example.com" required>
    <label for="sitemap">Sitemap URL <span class="muted">(optional)</span></label>
    <input id="sitemap" name="sitemap" class="mono" autocomplete="off"
           placeholder="https://example.com/sitemap.xml">
    <button type="submit">Download the Terraform change</button>
  </form>
  <p class="small muted">The change lands as a pull request through the
  edit-as-code path &mdash; nothing is changed directly.</p>
</section>"#
    ))
}

/// The same shell, for a caller with no session: nothing about any domain,
/// just the sign-in ask (status 401).
fn sign_in_page() -> Response {
    html_page(
        StatusCode::UNAUTHORIZED,
        &document(&format!(
            "<h1>Sign in required</h1>\n<p><a href=\"{}\">Sign in</a> to see your Search \
             Console status.</p>",
            escape(&crate::signin::login_href("/v1/console/search-console"))
        )),
    )
}

/// The same shell, when the deployment cannot answer honestly: the auth port
/// is missing, the provider is down, or Search Console itself is (503).
fn not_ready_page(why: &str) -> Response {
    html_page(
        StatusCode::SERVICE_UNAVAILABLE,
        &document(format!("<h1>Not ready yet</h1>\n<p>{}</p>", escape(why)).as_str()),
    )
}

/// Wraps a rendered page body in the shared HTML document at the given
/// status. The shell stays the shell whether the answer is 200, 401 or 503 —
/// only the body changes.
fn html_page(status: StatusCode, document: &str) -> Response {
    match http::Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .body(cratefield_core::axum::body::Body::from(document.to_owned()))
    {
        Ok(response) => response.into_response(),
        Err(error) => {
            tracing::warn!(error = %error, "the page could not be built");
            Problem::internal().into_response()
        }
    }
}

/// The full HTML document around a page body: the venture's design tokens
/// from `src/mail-theme.json` — Bricolage Grotesque with a system fallback,
/// DM Mono for code, the light and dark palettes, square corners everywhere.
fn document(body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Search Console — Keep Shipping</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400..800&family=DM+Mono&display=swap" rel="stylesheet">
<style>
:root {{
  --bg: #eef0f3; --card: #fbfcfd; --border: #ced1d6; --ink: #11161f;
  --text: #3e434b; --muted: #4e535b; --accent: #1950cc; --button: #1950cc;
  --button-text: #ffffff; --code-bg: #e6efff;
  --font: 'Bricolage Grotesque',system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
  --mono: 'DM Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #11161f; --card: #1a1f29; --border: #3d434d; --ink: #ffffff;
    --text: #d5d7db; --muted: #a1a5ab; --accent: #9cbeff; --button: #4d81eb;
    --button-text: #11161f; --code-bg: #1e2735;
  }}
}}
* {{ box-sizing: border-box; border-radius: 0 !important; }}
body {{
  margin: 0; padding: 24px 16px 48px; background: var(--bg); color: var(--text);
  font-family: var(--font); font-size: 16px; line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}}
main {{ max-width: 640px; margin: 0 auto; }}
h1 {{ color: var(--ink); font-size: 28px; font-weight: 700; margin: 0 0 4px; letter-spacing: -0.01em; }}
h2 {{ color: var(--ink); font-size: 17px; font-weight: 600; margin: 0 0 12px; }}
.sub {{ color: var(--muted); margin: 0 0 24px; }}
.card {{ background: var(--card); border: 1px solid var(--border); padding: 20px; margin: 0 0 16px; }}
.chips {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 12px; }}
.chip {{
  display: inline-block; padding: 3px 10px; border: 1px solid var(--border);
  color: var(--text); font-size: 14px;
}}
.chip.good {{ background: var(--code-bg); border-color: var(--accent); color: var(--accent); }}
.small {{ font-size: 14px; margin: 6px 0; }}
.muted {{ color: var(--muted); }}
.mono {{ font-family: var(--mono); font-size: 13px; word-break: break-all; }}
code {{ font-family: var(--mono); font-size: 0.92em; background: var(--code-bg); padding: 1px 5px; }}
ol {{ margin: 0; padding-left: 20px; }}
li {{ margin: 0 0 10px; }}
li:last-child {{ margin-bottom: 0; }}
label {{ display: block; font-size: 14px; color: var(--muted); margin: 12px 0 4px; }}
input {{
  width: 100%; padding: 10px 12px; border: 1px solid var(--border);
  background: var(--bg); color: var(--ink); font: inherit;
}}
input.mono {{ font-family: var(--mono); font-size: 14px; }}
button {{
  margin-top: 16px; padding: 11px 18px; border: 1px solid var(--button);
  background: var(--button); color: var(--button-text); font: inherit; font-weight: 600;
  cursor: pointer;
}}
form + p {{ margin: 10px 0 0; }}
</style>
</head>
<body>
<main>
{body}
</main>
</body>
</html>
"#
    )
}

/// The status stamp in plain words: `2027-01-15T08:00:00Z` becomes
/// `2027-01-15 08:00 UTC`. A slice-and-format of the RFC 3339 value the
/// JSON endpoint reports (machines keep RFC 3339); when the value does not
/// have that shape, it shows as-is.
fn plain_stamp(rfc3339: &str) -> String {
    let b = rfc3339.as_bytes();
    let digits = |slice: &[u8]| slice.iter().all(u8::is_ascii_digit);
    if b.len() >= 16
        && digits(&b[..4])
        && b[4] == b'-'
        && digits(&b[5..7])
        && b[7] == b'-'
        && digits(&b[8..10])
        && b[10] == b'T'
        && digits(&b[11..13])
        && b[13] == b':'
        && digits(&b[14..16])
    {
        format!("{} {} UTC", &rfc3339[..10], &rfc3339[11..16])
    } else {
        rfc3339.to_owned()
    }
}

/// The five characters that can break out of an HTML text node or attribute,
/// and no more. The ampersand goes first, so no escape is itself escaped.
fn escape(text: &str) -> String {
    let five = [('&', "&amp;"), ('<', "&lt;"), ('>', "&gt;"), ('"', "&quot;"), ('\'', "&#39;")];
    five.iter().fold(text.to_owned(), |out, (from, to)| out.replace(*from, to))
}
