//! The `gsc.sitemap_submit` step kind: submits a sitemap to Google Search
//! Console so indexing starts the moment the domain is verified
//! ([#274](https://github.com/Keep-Shipping/harness/issues/274)).
//!
//! The step runs right after the `tofu.apply` of the domain-verification
//! Terraform module. Authentication is a Google service account without any
//! SDK: a short-lived RS256 JWT is signed with the account's key and
//! exchanged at the OAuth2 token endpoint for a bearer token, which is then
//! spent on one Search Console API call. The call is
//! [`sitemaps.submit`](https://developers.google.com/webmaster-tools/v1/sitemaps/submit),
//! documented as
//! `PUT https://www.googleapis.com/webmasters/v3/sites/{siteUrl}/sitemaps/{feedpath}`
//! with no request body and an empty response body. Submitting a sitemap
//! that is already submitted succeeds on Google's side too, so the step
//! treats any 2xx — and, defensively, a 409 — as done and a re-run is free.

use ks_core::ports::BoxFuture;
use ks_core::ports::clock::Clock;
use ks_core::ports::http::{HttpClient, HttpMethod, HttpRequest, HttpResponse};
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::step::{
    ActionClass, ActionKind, Field, Inputs, Outputs, Port, StepCtx, StepError, StepKind,
    StepSchema, TypeRef, Version,
};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};

/// The first `&str` input under `name`; inputs arrive prepared, so a wrong type
/// never reaches a step.
fn text<'a>(inputs: &'a Inputs, name: &str) -> &'a str {
    match inputs.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

/// The value of a required, non-empty string input.
fn required(inputs: &Inputs, name: &str) -> Result<String, StepError> {
    let value = text(inputs, name);
    if value.is_empty() {
        return Err(StepError::InvalidInput {
            field: name.to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    Ok(value.to_string())
}

/// The OAuth2 grant type of the JWT-bearer exchange, already percent-encoded
/// for the form body (RFC 7523 §2.1).
const GRANT_TYPE: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";

/// The scope the assertion asks for: enough to manage sitemaps, nothing else.
const SCOPE: &str = "https://www.googleapis.com/auth/webmasters";

/// Where the assertion is exchanged for a token, when the key names no
/// `token_uri` of its own (Google's own service-account keys do).
const TOKEN_URI_FALLBACK: &str = "https://oauth2.googleapis.com/token";

/// How long the assertion is valid for; Google asks for well under an hour.
const TOKEN_LIFETIME_SECS: u64 = 3600;

/// The HTTP status Search Console answers with when the sitemap is already
/// submitted, which is the same outcome the step is after.
const ALREADY_SUBMITTED: u16 = 409;

/// The JWT header, as fixed bytes: the algorithm is not a parameter here, it
/// is what the step does.
const ASSERTION_HEADER: &[u8] = b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

/// The fields of a Google service-account JSON key this step uses. The whole
/// key is parsed out of the input string and never leaves this struct: what
/// travels is the signed assertion and the bearer token, never the key.
struct ServiceAccount {
    /// The issuer of the assertion, e.g. `sa@project.iam.gserviceaccount.com`.
    client_email: String,
    /// The PKCS#8 PEM RSA key the assertion is signed with.
    private_key: String,
    /// Where the assertion is exchanged for a token.
    token_uri: String,
}

impl ServiceAccount {
    /// Reads the three fields this step uses out of the service-account JSON
    /// key.
    fn parse(credentials: &str) -> Result<ServiceAccount, StepError> {
        let json: serde_json::Value =
            serde_json::from_str(credentials).map_err(|_| StepError::InvalidInput {
                field: "credentials".to_string(),
                reason: "the value is not a Google service-account JSON key".to_string(),
            })?;
        let token_uri = match json.get("token_uri").and_then(serde_json::Value::as_str) {
            Some(uri) if !uri.is_empty() => uri.to_string(),
            _ => TOKEN_URI_FALLBACK.to_string(),
        };
        if !token_uri.starts_with("https://") {
            return Err(StepError::InvalidInput {
                field: "credentials".to_string(),
                reason: "`token_uri` must be an absolute https URL".to_string(),
            });
        }
        Ok(ServiceAccount {
            client_email: string_field(&json, "client_email")?,
            private_key: string_field(&json, "private_key")?,
            token_uri,
        })
    }
}

/// One required, non-empty string field of the service-account key. The
/// reason never quotes what it found: the field values are the secret.
fn string_field(json: &serde_json::Value, name: &str) -> Result<String, StepError> {
    match json.get(name).and_then(serde_json::Value::as_str) {
        Some(value) if !value.is_empty() => Ok(value.to_string()),
        _ => Err(StepError::InvalidInput {
            field: "credentials".to_string(),
            reason: format!("the key does not carry a `{name}` string"),
        }),
    }
}

/// Signs the JWT assertion and exchanges it for a bearer token. The assertion
/// rides only in this one form body; nothing about it is logged or returned.
async fn bearer_token(
    account: &ServiceAccount,
    clock: &std::sync::Arc<dyn Clock>,
    http: &dyn HttpClient,
) -> Result<String, StepError> {
    let assertion = mint_assertion(account, clock)?;
    let mut request = HttpRequest::new(HttpMethod::Post, account.token_uri.clone());
    request
        .headers
        .push(("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()));
    request.body = format!("grant_type={GRANT_TYPE}&assertion={assertion}").into_bytes();
    let response = send(http, request).await?;
    if !succeeded(response.status) {
        return Err(StepError::Failed(format!(
            "the token endpoint refused the service account with HTTP {}",
            response.status
        )));
    }
    let token: serde_json::Value = serde_json::from_slice(&response.body).map_err(|_| {
        StepError::Failed("the token endpoint answered with a body that is not JSON".to_string())
    })?;
    token.get("access_token").and_then(serde_json::Value::as_str).map(str::to_string).ok_or_else(
        || StepError::Failed("the token endpoint answered without an `access_token`".to_string()),
    )
}

/// Signs the assertion: two base64url segments joined with a dot, then the
/// RS256 signature as a third. `iat` comes from the run's clock, so a test
/// run stays instant and the same inputs mint the same assertion.
fn mint_assertion(
    account: &ServiceAccount,
    clock: &std::sync::Arc<dyn Clock>,
) -> Result<String, StepError> {
    let key = RsaPrivateKey::from_pkcs8_pem(&account.private_key).map_err(|_| {
        StepError::InvalidInput {
            field: "credentials".to_string(),
            reason: "`private_key` is not a PKCS#8 PEM RSA key".to_string(),
        }
    })?;
    let iat = clock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| StepError::Failed("the run clock is set before the unix epoch".to_string()))?
        .as_secs();
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

/// Puts the sitemap to Search Console. Any 2xx is a submission, and so is
/// [`ALREADY_SUBMITTED`]: the sitemap is already there, which is the
/// idempotency a re-run relies on. The response body is deliberately never
/// quoted into an error — `StepError` text bypasses the run's redactor.
async fn submit(
    http: &dyn HttpClient,
    site: &str,
    sitemap: &str,
    token: &str,
) -> Result<(), StepError> {
    // `sitemaps.submit`, per the Search Console API reference
    // (https://developers.google.com/webmaster-tools/v1/sitemaps/submit):
    // `PUT https://www.googleapis.com/webmasters/v3/sites/{siteUrl}/sitemaps/{feedpath}`,
    // no request body, an empty response body, scope `.../auth/webmasters`.
    let mut request = HttpRequest::new(
        HttpMethod::Put,
        format!(
            "https://www.googleapis.com/webmasters/v3/sites/{}/sitemaps/{}",
            percent_encode(site),
            percent_encode(sitemap)
        ),
    );
    request.headers.push(("Authorization".to_string(), format!("Bearer {token}")));
    let response = send(http, request).await?;
    if succeeded(response.status) || response.status == ALREADY_SUBMITTED {
        return Ok(());
    }
    Err(StepError::Failed(format!(
        "Search Console refused to submit the sitemap with HTTP {}",
        response.status
    )))
}

/// Sends one request, turning a transport refusal into a port error.
async fn send(http: &dyn HttpClient, request: HttpRequest) -> Result<HttpResponse, StepError> {
    http.send(request)
        .await
        .map_err(|error| StepError::Port { port: Port::HttpClient, message: error.to_string() })
}

/// Whether a status code is a 2xx.
fn succeeded(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Percent-encodes every byte outside the RFC 3986 unreserved set, so a site
/// identifier or a sitemap URL can ride inside one path segment.
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
/// §2). Hand-rolled, like the standard alphabet in `signing` and
/// `attestation`: the workspace has no base64 crate, and a JWT segment does
/// not earn one.
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

/// Submits a sitemap to Google Search Console as a service account.
#[derive(Debug, Default)]
pub struct GscSitemapSubmit;

impl StepKind for GscSitemapSubmit {
    fn name(&self) -> &'static str {
        "gsc.sitemap_submit"
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Submits a sitemap to Google Search Console so indexing starts as soon as the \
                  domain is verified.",
            inputs: vec![
                Field::new(
                    "credentials",
                    TypeRef::Builtin(ValueType::String),
                    "the Google service-account JSON key used to authenticate; it is never \
                     logged, returned or named in an error",
                ),
                Field::new(
                    "site",
                    TypeRef::Builtin(ValueType::String),
                    "the Search Console site identifier, e.g. `sc-domain:example.com`",
                ),
                Field::new(
                    "sitemap",
                    TypeRef::Builtin(ValueType::String),
                    "absolute https URL of the sitemap, e.g. `https://example.com/sitemap.xml`",
                ),
            ],
            outputs: vec![
                Field::new("site", TypeRef::Builtin(ValueType::String), "the site submitted for"),
                Field::new(
                    "sitemap",
                    TypeRef::Builtin(ValueType::String),
                    "the sitemap that was submitted",
                ),
                Field::new(
                    "submitted",
                    TypeRef::Builtin(ValueType::Bool),
                    "always true when the step returns",
                ),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::HttpClient]
    }

    /// Submitting a sitemap changes nothing anyone depends on — Google polls
    /// it on its own — so the step needs no approval of its own.
    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let Some(http) = ctx.ports().http_client() else {
                return Err(StepError::Port {
                    port: Port::HttpClient,
                    message: "no http client was provided".to_string(),
                });
            };
            let account = ServiceAccount::parse(text(&inputs, "credentials"))?;
            let site = required(&inputs, "site")?;
            let sitemap = {
                let sitemap = required(&inputs, "sitemap")?;
                if !sitemap.starts_with("https://") || sitemap.len() == "https://".len() {
                    return Err(StepError::InvalidInput {
                        field: "sitemap".to_string(),
                        reason: format!("`{sitemap}` is not an absolute https URL"),
                    });
                }
                sitemap
            };
            if ctx.cancel().is_cancelled() {
                return Err(StepError::Cancelled);
            }
            let token = bearer_token(&account, ctx.clock(), http.as_ref()).await?;
            if ctx.cancel().is_cancelled() {
                return Err(StepError::Cancelled);
            }
            submit(http.as_ref(), &site, &sitemap, &token).await?;
            ctx.log().info(
                &format!("submitted {sitemap} to Search Console for {site}"),
                &[("site", site.as_str()), ("sitemap", sitemap.as_str())],
            );
            let mut outputs = Outputs::new();
            outputs.insert("site".to_string(), Value::from(site));
            outputs.insert("sitemap".to_string(), Value::from(sitemap));
            outputs.insert("submitted".to_string(), Value::from(true));
            Ok(outputs)
        })
    }
}
