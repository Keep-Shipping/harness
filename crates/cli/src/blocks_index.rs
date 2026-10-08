//! The client for the hosted blocks index: it implements the
//! [`BlocksIndex`] port on top of an [`HttpClient`], so the same
//! policy-checked plumbing serves the hosted service and any mirror.
//!
//! # Wire contract
//!
//! The index is metadata only; this client never uploads or downloads block
//! contents. A search is
//!
//! ```text
//! GET {base}/v1/blocks/search?q=<percent-encoded query>&limit=<n>
//! ```
//!
//! answered with `200` and a JSON object of one field:
//!
//! ```json
//! {"results": [
//!   {"name": "acme/rollout",
//!    "publisher": {"kind": "keyless", "issuer": "…", "subject": "…"},
//!    "readme": "Rolls out a build.",
//!    "versions": [{"version": "1.2.0", "digest": "sha256:…",
//!                  "signature": "signed"}]}
//! ]}
//! ```
//!
//! `publisher` is keyless (`issuer`, `subject`) or a named key
//! (`key_id`); `signature` is `signed` or `unsigned`; `readme` may be
//! absent. Anything else — an unparsable body, a malformed digest, an
//! unknown signature — is [`BlocksIndexError::InvalidResponse`], never a
//! silently emptied result. Extra fields are ignored, so the index can
//! evolve ahead of the CLI.

use std::fmt::Write as _;
use std::sync::Arc;

use ks_core::ports::BoxFuture;
use ks_core::ports::blocks::{
    BlockEntry, BlockQuery, BlockVersion, BlocksIndex, BlocksIndexError, SignatureStatus,
};
use ks_core::ports::http::{HttpClient, HttpError, HttpMethod, HttpRequest};
use ks_core::ports::supply_chain::{Digest, SignerIdentity};

/// The search endpoint under the configured base URL.
pub const SEARCH_PATH: &str = "/v1/blocks/search";

/// The longest block name accepted from an index response.
const MAX_NAME_CHARS: usize = 256;

/// A [`BlocksIndex`] served over HTTP by the hosted blocks index (or any
/// service speaking the same contract).
pub struct HostedBlocksIndex {
    base: String,
    http: Arc<dyn HttpClient>,
}

impl HostedBlocksIndex {
    /// Points the client at `base` (an absolute `http:`/`https:` URL, any
    /// trailing `/` is dropped) with the policy-checked `http` client it
    /// should speak through.
    pub fn new(base: impl Into<String>, http: Arc<dyn HttpClient>) -> Result<Self, String> {
        let base = base.into();
        let trimmed = base.trim_end_matches('/');
        if crate::http_client::url_host_port(trimmed).is_none() {
            return Err(format!("{base} is not an absolute http(s) url with a host"));
        }
        Ok(HostedBlocksIndex { base: trimmed.to_string(), http })
    }

    /// The base this client actually queries, trailing slashes dropped. The
    /// blocks cache keys entries by it, so two spellings of one index share
    /// one entry.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The URL one search goes to; exposed for tests and diagnostics.
    pub fn search_url(&self, query: &BlockQuery) -> String {
        format!(
            "{base}{SEARCH_PATH}?q={}&limit={}",
            percent_encode(&query.text),
            query.limit,
            base = self.base
        )
    }

    /// The one search request, returning the index's response body verbatim.
    /// The command line caches that body, so the request and its HTTP
    /// failures have exactly one implementation shared with [`BlocksIndex::search`].
    pub fn search_body<'a>(
        &'a self,
        query: &'a BlockQuery,
    ) -> BoxFuture<'a, Result<Vec<u8>, BlocksIndexError>> {
        Box::pin(async move {
            let mut request = HttpRequest::new(HttpMethod::Get, self.search_url(query));
            request.headers.push(("Accept".to_string(), "application/json".to_string()));
            let response = self.http.send(request).await.map_err(Self::backend)?;
            if response.status != 200 {
                return Err(BlocksIndexError::Backend {
                    message: format!("the index answered {}", response.status),
                });
            }
            Ok(response.body)
        })
    }

    /// Maps an [`HttpError`] onto the port's error: from the index's side,
    /// every transport failure is a backend failure, message included.
    fn backend(error: HttpError) -> BlocksIndexError {
        BlocksIndexError::Backend { message: error.to_string() }
    }
}

impl BlocksIndex for HostedBlocksIndex {
    fn search<'a>(
        &'a self,
        query: &'a BlockQuery,
    ) -> BoxFuture<'a, Result<Vec<BlockEntry>, BlocksIndexError>> {
        Box::pin(async move { parse_response(&self.search_body(query).await?) })
    }
}

/// Parses one search response body against the wire contract. Public inside
/// the crate so `blocks search` can validate a cached body with the very same
/// checks a live one gets.
pub(crate) fn parse_response(body: &[u8]) -> Result<Vec<BlockEntry>, BlocksIndexError> {
    let json: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| invalid(format!("the body is not valid json ({e})")))?;
    let results = json
        .get("results")
        .ok_or_else(|| invalid("the body has no `results` field".to_string()))?;
    let results =
        results.as_array().ok_or_else(|| invalid("`results` is not an array".to_string()))?;
    results.iter().enumerate().map(|(position, value)| parse_entry(value, position)).collect()
}

fn parse_entry(value: &serde_json::Value, position: usize) -> Result<BlockEntry, BlocksIndexError> {
    let what = format!("the block at position {position}");
    let object = value.as_object().ok_or_else(|| invalid(format!("{what} is not an object")))?;
    let name = required_string(object, "name", &what)?;
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(invalid(format!("{what} has a name longer than {MAX_NAME_CHARS} characters")));
    }
    let publisher =
        value.get("publisher").ok_or_else(|| invalid(format!("{what} has no publisher")))?;
    let publisher = parse_publisher(publisher, &what)?;
    let readme = match string_field(object, "readme", &what)? {
        Some(readme) => readme.to_string(),
        None => String::new(),
    };
    let versions =
        value.get("versions").ok_or_else(|| invalid(format!("{what} has no versions")))?;
    let versions = versions
        .as_array()
        .ok_or_else(|| invalid(format!("{what} has a `versions` that is not an array")))?;
    let versions = versions
        .iter()
        .enumerate()
        .map(|(at, value)| parse_version(value, &what, at))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BlockEntry { name, publisher, readme, versions })
}

fn parse_publisher(
    value: &serde_json::Value,
    what: &str,
) -> Result<SignerIdentity, BlocksIndexError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} has a publisher that is not an object")))?;
    let kind = required_string(object, "kind", what)?;
    match kind.as_str() {
        "keyless" => {
            let issuer = required_string(object, "issuer", what)?;
            let subject = required_string(object, "subject", what)?;
            Ok(SignerIdentity::Keyless { issuer, subject })
        }
        "key" => Ok(SignerIdentity::Key { key_id: required_string(object, "key_id", what)? }),
        other => Err(invalid(format!("{what} has an unknown publisher kind {other:?}"))),
    }
}

fn parse_version(
    value: &serde_json::Value,
    what: &str,
    at: usize,
) -> Result<BlockVersion, BlocksIndexError> {
    let which = format!("{what} version at position {at}");
    let object = value.as_object().ok_or_else(|| invalid(format!("{which} is not an object")))?;
    let version = required_string(object, "version", &which)?;
    let digest_text = required_string(object, "digest", &which)?;
    let digest = Digest::parse(&digest_text)
        .map_err(|e| invalid(format!("{which} has a malformed digest ({e})")))?;
    let signature = match required_string(object, "signature", &which)?.as_str() {
        "signed" => SignatureStatus::Signed,
        "unsigned" => SignatureStatus::Unsigned,
        other => return Err(invalid(format!("{which} has an unknown signature {other:?}"))),
    };
    Ok(BlockVersion { version, digest, signature })
}

/// A string field that must be there, be a string, and not be empty or
/// carry control characters.
fn required_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    what: &str,
) -> Result<String, BlocksIndexError> {
    let value = string_field(object, key, what)?
        .ok_or_else(|| invalid(format!("{what} has no {key:?}")))?;
    if value.is_empty() {
        return Err(invalid(format!("{what} has an empty {key:?}")));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(invalid(format!("{what} has control characters in {key:?}")));
    }
    Ok(value.to_string())
}

/// An optional string field; a non-string value is a contract breach, an
/// absent one is `None`.
fn string_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
    what: &str,
) -> Result<Option<&'a str>, BlocksIndexError> {
    match object.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| invalid(format!("{what} has a {key:?} that is not a string"))),
    }
}

fn invalid(reason: String) -> BlocksIndexError {
    BlocksIndexError::InvalidResponse { reason }
}

/// Percent-encodes everything outside RFC 3986's unreserved set, byte by
/// byte, so a query text cannot change the URL's shape.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::ports::http::HttpResponse;
    use ks_testing::block_on;
    use ks_testing::http::FakeHttpClient;

    fn index_with(body: &str, status: u16) -> (Arc<FakeHttpClient>, HostedBlocksIndex) {
        let http =
            Arc::new(FakeHttpClient::new().with_allowed_host("index.example").with_response(
                HttpMethod::Get,
                "http://index.example/v1/blocks/search?q=rollout&limit=20",
                HttpResponse { status, headers: vec![], body: body.as_bytes().to_vec() },
            ));
        let index = HostedBlocksIndex::new("http://index.example/", http.clone())
            .expect("a valid base url");
        (http, index)
    }

    fn query() -> BlockQuery {
        BlockQuery { text: "rollout".to_string(), limit: 20 }
    }

    const TWO_ENTRIES: &str = r#"{"results":[
        {"name":"acme/rollout",
         "publisher":{"kind":"keyless","issuer":"https://token.example","subject":"acme/deploy@v1"},
         "readme":"Rolls out a build.\n\nMore.",
         "versions":[
            {"version":"1.2.0","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature":"signed"},
            {"version":"1.1.0","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","signature":"unsigned"}]},
        {"name":"acme/db","publisher":{"kind":"key","key_id":"2026-q3"},"versions":[]}
    ]}"#;

    #[test]
    fn search_builds_the_documented_url_and_parses_the_answer() {
        let (http, index) = index_with(TWO_ENTRIES, 200);
        let found = block_on(index.search(&query())).expect("two entries");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].name, "acme/rollout");
        assert_eq!(
            found[0].publisher,
            SignerIdentity::Keyless {
                issuer: "https://token.example".to_string(),
                subject: "acme/deploy@v1".to_string()
            }
        );
        assert_eq!(found[0].versions.len(), 2);
        assert_eq!(found[0].versions[0].signature, SignatureStatus::Signed);
        assert_eq!(found[0].versions[0].digest.algorithm(), "sha256");
        assert_eq!(found[1].publisher, SignerIdentity::Key { key_id: "2026-q3".to_string() });
        assert!(found[1].readme.is_empty(), "an absent readme is empty, not an error");
        let sent = &http.requests()[0];
        assert_eq!(sent.url, "http://index.example/v1/blocks/search?q=rollout&limit=20");
        assert_eq!(sent.headers, vec![("Accept".to_string(), "application/json".to_string())]);
    }

    #[test]
    fn the_search_text_is_percent_encoded() {
        let http = FakeHttpClient::new();
        let index =
            HostedBlocksIndex::new("http://index.example", Arc::new(http)).expect("valid base");
        let url = index
            .search_url(&BlockQuery { text: "roll out & sign 100% ✓".to_string(), limit: 5 });
        assert_eq!(
            url,
            "http://index.example/v1/blocks/search?q=roll%20out%20%26%20sign%20100%25%20%E2%9C%93&limit=5"
        );
    }

    #[test]
    fn a_base_url_loses_its_trailing_slash_and_rejects_junk() {
        let http = FakeHttpClient::new();
        let index = HostedBlocksIndex::new("http://index.example/prefix//", Arc::new(http))
            .expect("a path-prefixed base is kept");
        assert_eq!(
            index.search_url(&query()),
            "http://index.example/prefix/v1/blocks/search?q=rollout&limit=20"
        );
        assert!(HostedBlocksIndex::new("index.example", Arc::new(FakeHttpClient::new())).is_err());
        assert!(HostedBlocksIndex::new("", Arc::new(FakeHttpClient::new())).is_err());
    }

    #[test]
    fn an_empty_result_set_is_a_normal_answer() {
        let (_, index) = index_with(r#"{"results":[]}"#, 200);
        assert_eq!(block_on(index.search(&query())), Ok(Vec::new()));
    }

    #[test]
    fn an_http_error_status_is_a_backend_failure() {
        let (_, index) = index_with(r#"{"results":[]}"#, 404);
        assert_eq!(
            block_on(index.search(&query())),
            Err(BlocksIndexError::Backend { message: "the index answered 404".to_string() })
        );
    }

    #[test]
    fn transport_failures_are_backend_failures() {
        // No scripted response for the URL: the fake answers Transport.
        let index = HostedBlocksIndex::new(
            "http://index.example",
            Arc::new(FakeHttpClient::new().with_allowed_host("index.example")),
        )
        .expect("valid base");
        assert!(matches!(block_on(index.search(&query())), Err(BlocksIndexError::Backend { .. })));
    }

    #[test]
    fn a_policy_refusal_is_a_backend_failure_naming_the_host() {
        // The fake's default policy allows no hosts, so the send is refused
        // before any scripted answer is consulted.
        let index = HostedBlocksIndex::new(
            "http://index.example",
            Arc::new(FakeHttpClient::new().with_response(
                HttpMethod::Get,
                "http://index.example/v1/blocks/search?q=rollout&limit=20",
                HttpResponse {
                    status: 200,
                    headers: vec![],
                    body: TWO_ENTRIES.as_bytes().to_vec(),
                },
            )),
        )
        .expect("valid base");
        let error = block_on(index.search(&query())).expect_err("refused by policy");
        let BlocksIndexError::Backend { message } = error else {
            panic!("expected a backend error, got {error}");
        };
        assert!(message.contains("allowlist"), "{message}");
    }

    #[test]
    fn responses_that_break_the_contract_are_invalid_never_empty() {
        let cases: Vec<(&str, &str)> = vec![
            ("not json", "the body is not valid json"),
            ("[]", "no `results` field"),
            (r#"{"results":3}"#, "`results` is not an array"),
            (r#"{"nope":1}"#, "no `results` field"),
            (r#"{"results":[1]}"#, "is not an object"),
            (r#"{"results":[{"publisher":{},"versions":[]}]}"#, "no \"name\""),
            (r#"{"results":[{"name":"","publisher":{},"versions":[]}]}"#, "empty \"name\""),
            (r#"{"results":[{"name":3,"publisher":{},"versions":[]}]}"#, "not a string"),
            (r#"{"results":[{"name":"a/b"}]}"#, "no publisher"),
            (
                r#"{"results":[{"name":"a/b","publisher":{"kind":"carrier pigeon"},"versions":[]}]}"#,
                "unknown publisher kind",
            ),
            (
                r#"{"results":[{"name":"a/b","publisher":{"kind":"keyless","issuer":"i"},"versions":[]}]}"#,
                "no \"subject\"",
            ),
            (
                r#"{"results":[{"name":"a/b","publisher":{"kind":"key"},"versions":[]}]}"#,
                "no \"key_id\"",
            ),
            (
                r#"{"results":[{"name":"a/b","publisher":{"kind":"key","key_id":"k"}}]}"#,
                "no versions",
            ),
            (
                r#"{"results":[{"name":"a/b","publisher":{"kind":"key","key_id":"k"},"versions":3}]}"#,
                "not an array",
            ),
            (
                r#"{"results":[{"name":"a/b","publisher":{"kind":"key","key_id":"k"},"versions":[{"version":"1.0","digest":"sha256:zz","signature":"signed"}]}]}"#,
                "malformed digest",
            ),
            (
                r#"{"results":[{"name":"a/b","publisher":{"kind":"key","key_id":"k"},"versions":[{"version":"1.0","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature":"verified-by-everyone"}]}]}"#,
                "unknown signature",
            ),
            (
                r#"{"results":[{"name":"a/b\n","publisher":{"kind":"key","key_id":"k"},"versions":[]}]}"#,
                "control characters",
            ),
        ];
        for (body, expected) in cases {
            let (_, index) = index_with(body, 200);
            let error = block_on(index.search(&query())).expect_err(body);
            let BlocksIndexError::InvalidResponse { reason } = error else {
                panic!("{body}: expected an invalid-response error, got {error}");
            };
            assert!(reason.contains(expected), "{body}: {reason} does not mention {expected:?}");
        }
    }
}
