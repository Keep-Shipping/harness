//! The [`HttpClient`] port: bounded, policy-checked HTTP
//! ([#57](https://github.com/Keep-Shipping/harness/issues/57)).
//!
//! HTTP is not ambient: every client is built with an [`HttpPolicy`] — an
//! allowlist of exact hosts, a timeout and a response-size cap — and adapters
//! get one each (the registry client, Jev, the chat notifier), so a runaway
//! step can only ever talk to the hosts its port was granted. Tests never
//! open sockets: `ks-testing`'s [`FakeHttpClient`] scripts responses and
//! enforces the same policy.
//!
//! [`FakeHttpClient`]: https://docs.rs/ks-testing/latest/ks_testing/http/struct.FakeHttpClient.html

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use super::BoxFuture;

/// The verb of an [`HttpRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpMethod {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
    /// `HEAD`.
    Head,
}

impl HttpMethod {
    /// The HTTP verb, uppercase, as it goes on the wire and into fake keys.
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An outgoing request. The body is raw bytes; adapters own any encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// The verb.
    pub method: HttpMethod,
    /// An absolute `http`/`https` URL.
    pub url: String,
    /// Headers in declaration order; duplicates are allowed.
    pub headers: Vec<(String, String)>,
    /// The request body, possibly empty.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// A headerless, bodyless request.
    pub fn new(method: HttpMethod, url: impl Into<String>) -> HttpRequest {
        HttpRequest { method, url: url.into(), headers: Vec::new(), body: Vec::new() }
    }
}

/// A response, as the port hands it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The HTTP status code.
    pub status: u16,
    /// Response headers in arrival order.
    pub headers: Vec<(String, String)>,
    /// The response body; never truncated — a body larger than
    /// [`HttpPolicy::max_response_bytes`] fails the request with
    /// [`HttpError::ResponseTooLarge`] instead.
    pub body: Vec<u8>,
}

/// What a client may do, decided once at `Harness::build()` time.
///
/// `check` enforces the host allowlist (cheap, pure); the timeout and size
/// cap are enforced by the adapter around the actual transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPolicy {
    /// The exact hosts allowed, lowercase hostnames without ports (the port
    /// is stripped from URLs before matching). A host match is exact:
    /// `api.example.com` does not admit `evil-api.example.com` or its
    /// subdomains. An empty set admits nothing.
    pub allowed_hosts: BTreeSet<String>,
    /// How long a single request may take before the adapter gives up.
    pub timeout: Duration,
    /// The largest response body the adapter will hand back.
    pub max_response_bytes: usize,
}

impl Default for HttpPolicy {
    /// The safe default: an empty allowlist (nothing allowed), a 30-second
    /// timeout and a 1 MiB response cap.
    fn default() -> HttpPolicy {
        HttpPolicy {
            allowed_hosts: BTreeSet::new(),
            timeout: Duration::from_secs(30),
            max_response_bytes: 1024 * 1024,
        }
    }
}

impl HttpPolicy {
    /// Whether `url` may be requested at all: pure, no I/O, run before any
    /// traffic (adapters must call this first — the conformance kit checks
    /// that they do).
    ///
    /// The URL parsing is deliberately minimal and dependency-free: an
    /// absolute `http:`/`https:` URL whose host is a non-empty,
    /// bracketed-IPv6-aware string with userinfo and port stripped, matched
    /// case-insensitively against the allowlist. A URL whose authority
    /// contains a backslash is [`HttpError::InvalidUrl`]: WHATWG parsers (so
    /// `url` and every adapter built on it) treat `\` as an authority
    /// terminator, and this parser refuses to guess where they would end the
    /// host.
    pub fn check(&self, url: &str) -> Result<(), HttpError> {
        let host = host_of(url).ok_or(HttpError::InvalidUrl)?.to_ascii_lowercase();
        if self.allowed_hosts.contains(&host) {
            Ok(())
        } else {
            Err(HttpError::HostNotAllowed { host })
        }
    }
}

/// Extracts the host of an absolute http(s) URL, or `None`.
///
/// Strips the scheme, any userinfo (everything up to the last `@` in the
/// authority), a trailing port and the brackets around IPv6 literals. An
/// authority containing `\` is rejected: WHATWG parsing (so `url`, reqwest
/// and the adapters above them) ends the authority at a backslash in special
/// schemes, so `https://evil.com\@allowed.com/x` really goes to `evil.com`
/// while a naive last-`@` split would read `allowed.com`. The caller
/// lowercases; the returned slice borrows from `url`.
fn host_of(url: &str) -> Option<&str> {
    let after_scheme = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://"))?;
    let authority =
        after_scheme.split(['/', '?', '#']).next().filter(|authority| !authority.is_empty())?;
    if authority.contains('\\') {
        return None;
    }
    let authority = match authority.rsplit_once('@') {
        Some((_userinfo, host)) => host,
        None => authority,
    };
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']')?.0
    } else {
        authority.split(':').next()?
    };
    if host.is_empty() { None } else { Some(host) }
}

/// Why an HTTP call did not happen or did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// The URL was not an absolute http(s) URL with a host. The URL itself is
    /// deliberately not echoed back — query strings often carry tokens.
    InvalidUrl,
    /// The host is not on the client's allowlist. Rejected before any I/O.
    HostNotAllowed {
        /// The offending host (lowercase, port stripped).
        host: String,
    },
    /// The request exceeded the policy timeout.
    Timeout {
        /// The configured timeout.
        after: Duration,
    },
    /// The response body exceeded the policy cap.
    ResponseTooLarge {
        /// The configured cap.
        limit: usize,
    },
    /// Anything else the adapter's transport reports, safe to print.
    Transport {
        /// What went wrong.
        message: String,
    },
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::InvalidUrl => {
                write!(f, "invalid http url (want absolute http/https with a host)")
            }
            HttpError::HostNotAllowed { host } => {
                write!(f, "host {host:?} is not in this client's http allowlist")
            }
            HttpError::Timeout { after } => write!(f, "http request timed out after {after:?}"),
            HttpError::ResponseTooLarge { limit } => {
                write!(f, "http response exceeded the {limit}-byte limit")
            }
            HttpError::Transport { message } => write!(f, "http transport error: {message}"),
        }
    }
}

impl std::error::Error for HttpError {}

/// The `HttpClient` port: adapters (registry, Jev, chat) each get a client
/// bound to their own [`HttpPolicy`]; steps never construct requests for
/// hosts the policy does not name, because [`HttpClient::send`] runs
/// [`HttpPolicy::check`] before any traffic.
pub trait HttpClient: Send + Sync {
    /// The policy this client is bound to.
    fn policy(&self) -> &HttpPolicy;

    /// Sends one request, after checking it against the policy.
    fn send<'a>(&'a self, req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse, HttpError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(hosts: &[&str]) -> HttpPolicy {
        HttpPolicy {
            allowed_hosts: hosts.iter().map(|host| (*host).to_string()).collect(),
            timeout: Duration::from_secs(30),
            max_response_bytes: 1024,
        }
    }

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_http_client_trait_is_dyn_compatible() {
        assert_send_sync::<dyn HttpClient>();
    }

    #[test]
    fn allows_exact_hosts_regardless_of_path_port_or_case() {
        let policy = policy(&["api.example.com"]);
        for url in [
            "https://api.example.com/v1/things?x=1",
            "https://api.example.com:8443/v1/things",
            "https://API.EXAMPLE.com/v1/things",
            "https://user:token@api.example.com/v1/things",
            "http://api.example.com/insecure",
        ] {
            assert_eq!(policy.check(url), Ok(()), "{url}");
        }
    }

    #[test]
    fn allows_bracketed_ipv6_hosts() {
        let policy = policy(&["::1"]);
        assert_eq!(policy.check("http://[::1]:8080/health"), Ok(()));
    }

    #[test]
    fn rejects_hosts_outside_the_allowlist() {
        let policy = policy(&["api.example.com"]);
        // Not a prefix match in either direction: an exact host match only.
        for url in ["https://example.com/", "https://evil-api.example.com/"] {
            assert_eq!(
                policy.check(url),
                Err(HttpError::HostNotAllowed {
                    host: url
                        .trim_start_matches("https://")
                        .split('/')
                        .next()
                        .unwrap()
                        .to_ascii_lowercase()
                }),
                "{url}"
            );
        }
    }

    #[test]
    fn an_empty_allowlist_admits_nothing() {
        let policy = policy(&[]);
        assert!(matches!(policy.check("https://api.example.com/"),
            Err(HttpError::HostNotAllowed { host }) if host == "api.example.com"));
    }

    #[test]
    fn backslash_in_the_authority_is_invalid_rather_than_implicitly_allowed() {
        let policy = policy(&["allowed.com"]);
        // WHATWG parsers end the authority at `\`, so the first URL really
        // goes to evil.com even though a last-`@` split reads allowed.com.
        for url in ["https://evil.com\\@allowed.com/x", "https://allowed.com\\evil.com"] {
            assert_eq!(policy.check(url), Err(HttpError::InvalidUrl), "{url}");
        }
    }

    #[test]
    fn rejects_non_urls() {
        let policy = policy(&["api.example.com"]);
        for url in [
            "",
            "api.example.com/v1",
            "ftp://api.example.com/file",
            "https:/api.example.com/",
            "https://",
            "https:///path",
            "https://user@/path",
            "https://[::1/missing-bracket",
        ] {
            assert_eq!(policy.check(url), Err(HttpError::InvalidUrl), "{url}");
        }
    }

    #[test]
    fn http_errors_display_actionably() {
        let message = HttpError::HostNotAllowed { host: "evil.example".to_string() }.to_string();
        assert!(message.contains("evil.example") && message.contains("allowlist"), "{message}");
        assert!(HttpError::Timeout { after: Duration::from_secs(30) }.to_string().contains("30s"));
        assert!(HttpError::ResponseTooLarge { limit: 1024 }.to_string().contains("1024"));
        assert!(HttpError::Transport { message: "dns".to_string() }.to_string().contains("dns"));
        assert!(HttpError::InvalidUrl.to_string().contains("http"));
    }

    #[test]
    fn verbs_display_as_their_wire_form() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Patch.as_str(), "PATCH");
    }
}
