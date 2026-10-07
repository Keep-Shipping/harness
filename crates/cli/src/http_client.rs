//! A minimal [`HttpClient`] adapter: HTTP/1.1 over `std::net`, plain
//! `http:` only, for the blocks index until the real HTTP adapters land
//! (`adapters/*`).
//!
//! The adapter enforces the port contract the conformance kit checks:
//! [`HttpPolicy::check`] runs *before* any traffic, the policy timeout bounds
//! the whole exchange, and a response body past
//! [`HttpPolicy::max_response_bytes`] fails with
//! [`HttpError::ResponseTooLarge`] rather than being truncated. There is no
//! TLS, no keep-alive and no chunked encoding — an `https:` URL, userinfo in
//! the authority, or a chunked answer is a clear error, never a silent
//! downgrade.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use ks_core::ports::BoxFuture;
use ks_core::ports::http::{
    HttpClient, HttpError, HttpMethod, HttpPolicy, HttpRequest, HttpResponse,
};

/// How many response-header bytes the adapter will read before giving up.
const MAX_HEADER_BYTES: usize = 32 * 1024;
/// Read-timeout granularity: deadlines are checked per syscall, and a zero
/// timeout would be rejected by the socket.
const MIN_SLICE: Duration = Duration::from_millis(1);

/// The host and port of an absolute `http:`/`https:` URL, or [`None`].
///
/// Mirrors the port's own URL rules: the authority ends at the first `/`,
/// `?` or `#`, and one containing `\` is not a URL to trust. A `https:` URL
/// is recognized (so callers can tell the user why it is refused) but the
/// port defaults to `80` only for plain http.
pub fn url_host_port(url: &str) -> Option<(String, u16)> {
    let after_scheme = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://"))?;
    let https = url.starts_with("https://");
    let authority =
        after_scheme.split(['/', '?', '#']).next().filter(|authority| !authority.is_empty())?;
    if authority.contains('\\') {
        return None;
    }
    let default_port = if https { 443 } else { 80 };
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal, optionally `[::1]:8080`.
        let (host, port) = rest.split_once(']')?;
        (host, port.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        None => default_port,
        Some(port) => port.parse().ok()?,
    };
    Some((host.to_string(), port))
}

/// The request target of an absolute `http:`/`https:` URL: the path (plus
/// query), defaulting to `/`, with any fragment dropped.
fn request_target(url: &str) -> Result<String, HttpError> {
    let after_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or(HttpError::InvalidUrl)?;
    let without_fragment = after_scheme.split('#').next().unwrap_or(after_scheme);
    let target = match without_fragment.find(['/', '?']) {
        Some(at) => &without_fragment[at..],
        None => "/",
    };
    if target.starts_with('?') {
        // A bare `?query` is not a valid request target; it rides on `/`.
        return Ok(format!("/{target}"));
    }
    Ok(target.to_string())
}

/// An [`HttpClient`] adapter speaking HTTP/1.1 over one `TcpStream` per
/// request, `Connection: close`.
pub struct TcpHttpClient {
    policy: HttpPolicy,
}

impl TcpHttpClient {
    /// Creates a client bound to `policy`; every request is checked against
    /// it before any traffic.
    pub fn new(policy: HttpPolicy) -> TcpHttpClient {
        TcpHttpClient { policy }
    }

    /// The whole exchange — connect, write, read — bounded by the policy.
    fn send_sync(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        // The port contract: policy first, then traffic.
        self.policy.check(&req.url)?;
        let (host, port) = url_host_port(&req.url).ok_or(HttpError::InvalidUrl)?;
        let is_https = req.url.starts_with("https://");
        if is_https {
            return Err(HttpError::Transport {
                message: "this http client speaks plain http only; https needs the real \
                          http adapter (adapters/*)"
                    .to_string(),
            });
        }
        if req.url.contains('@') {
            // Policy::check strips userinfo when matching hosts, so a URL
            // with credentials would pass the allowlist while the adapter
            // sent them to the wire. Refuse rather than guess intent.
            return Err(HttpError::Transport {
                message: "userinfo in the url is not supported".to_string(),
            });
        }
        let target = request_target(&req.url)?;
        let mut stream = connect(&host, port, self.policy.timeout)?;
        let deadline = Instant::now() + self.policy.timeout;
        write_request(&mut stream, &req, &host, port, &target, self.policy.timeout)?;
        read_response(&mut stream, &self.policy, deadline, req.method)
    }
}

impl HttpClient for TcpHttpClient {
    fn policy(&self) -> &HttpPolicy {
        &self.policy
    }

    fn send<'a>(&'a self, req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse, HttpError>> {
        // The exchange is synchronous inside; the future is ready on its
        // first poll, so a noop-waker loop runs it without an executor.
        Box::pin(std::future::ready(self.send_sync(req)))
    }
}

/// Connects to the first address that answers, within `timeout`.
fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, HttpError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|e| HttpError::Transport { message: format!("cannot resolve {host}: {e}") })?;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                return Err(HttpError::Timeout { after: timeout });
            }
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => continue,
            Err(e) => {
                return Err(HttpError::Transport {
                    message: format!("cannot connect to {host}:{port}: {e}"),
                });
            }
        }
    }
    Err(HttpError::Transport { message: format!("cannot connect to {host}:{port}") })
}

/// Writes one HTTP/1.1 request; `Connection: close` keeps the response
/// framing simple.
fn write_request(
    stream: &mut TcpStream,
    req: &HttpRequest,
    host: &str,
    port: u16,
    target: &str,
    timeout: Duration,
) -> Result<(), HttpError> {
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| HttpError::Transport { message: format!("socket setup failed: {e}") })?;
    let mut request = format!("{method} {target} HTTP/1.1\r\n", method = req.method.as_str());
    let host_header = if port == 80 { host.to_string() } else { format!("{host}:{port}") };
    request.push_str(&format!("Host: {host_header}\r\n"));
    for (name, value) in &req.headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    // A body-carrying verb says how long its body is even when that body is
    // empty: a registry waiting on a `Content-Length` before it answers the
    // `PUT` that commits an upload never gets one otherwise. GET and HEAD
    // have no body to frame.
    let framed = !req.body.is_empty()
        || matches!(req.method, HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch);
    if framed {
        request.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    }
    request.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.write_all(&req.body))
        .map_err(|e| transport_or_timeout(&e, timeout))
}

/// Reads and parses the response, enforcing the policy's size cap and
/// deadline.
fn read_response(
    stream: &mut TcpStream,
    policy: &HttpPolicy,
    deadline: Instant,
    method: HttpMethod,
) -> Result<HttpResponse, HttpError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(at) = find_header_end(&buf) {
            break at;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(HttpError::Transport { message: "response headers exceed 32 KiB".into() });
        }
        let n = read_within(stream, &mut chunk, deadline, policy)?;
        if n == 0 {
            return Err(HttpError::Transport {
                message: "connection closed before the response headers were complete".into(),
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let headers = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| HttpError::Transport { message: "response headers are not utf-8".into() })?;
    let (status, fields) = parse_head(headers)?;
    // A HEAD response carries the headers the matching GET would and no body
    // at all — including the `Content-Length` of that body, and the
    // `Transfer-Encoding` that framed it. Reading to either would wait for
    // bytes the server is never going to send.
    if method == HttpMethod::Head {
        return Ok(HttpResponse { status, headers: fields, body: Vec::new() });
    }
    if fields.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    }) {
        return Err(HttpError::Transport { message: "chunked responses are not supported".into() });
    }
    let mut body = buf[header_end + 4..].to_vec();
    match content_length(&fields) {
        Some(length) => {
            if length > policy.max_response_bytes {
                return Err(HttpError::ResponseTooLarge { limit: policy.max_response_bytes });
            }
            while body.len() < length {
                let n = read_within(stream, &mut chunk, deadline, policy)?;
                if n == 0 {
                    return Err(HttpError::Transport {
                        message: "connection closed before the response body was complete".into(),
                    });
                }
                body.extend_from_slice(&chunk[..n]);
            }
            if body.len() > length {
                return Err(HttpError::Transport {
                    message: "the response carried more bytes than its content-length".into(),
                });
            }
        }
        None => {
            // No content-length: with `Connection: close` the body ends at
            // EOF. The cap still applies, byte by byte.
            while body.len() <= policy.max_response_bytes {
                let n = read_within(stream, &mut chunk, deadline, policy)?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            if body.len() > policy.max_response_bytes {
                return Err(HttpError::ResponseTooLarge { limit: policy.max_response_bytes });
            }
        }
    }
    Ok(HttpResponse { status, headers: fields, body })
}

/// One read inside the deadline; a socket timeout or an expired deadline is
/// [`HttpError::Timeout`].
fn read_within(
    stream: &mut TcpStream,
    chunk: &mut [u8],
    deadline: Instant,
    policy: &HttpPolicy,
) -> Result<usize, HttpError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(HttpError::Timeout { after: policy.timeout })?;
    stream
        .set_read_timeout(Some(remaining.max(MIN_SLICE)))
        .map_err(|e| HttpError::Transport { message: format!("socket setup failed: {e}") })?;
    stream.read(chunk).map_err(|e| transport_or_timeout(&e, policy.timeout))
}

fn transport_or_timeout(e: &std::io::Error, timeout: Duration) -> HttpError {
    if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
        HttpError::Timeout { after: timeout }
    } else {
        HttpError::Transport { message: e.to_string() }
    }
}

/// The offset of the `\r\n\r\n` that ends the headers.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

/// The status code and the header fields of a response head.
fn parse_head(headers: &str) -> Result<(u16, Vec<(String, String)>), HttpError> {
    let mut lines = headers.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line.split_whitespace().nth(1).and_then(|code| code.parse().ok()).ok_or(
        HttpError::Transport { message: format!("malformed status line: {status_line:?}") },
    )?;
    let fields = lines
        .filter(|line| !line.is_empty())
        .map(|line| match line.split_once(':') {
            Some((name, value)) => Ok((name.to_string(), value.trim().to_string())),
            None => Err(HttpError::Transport {
                message: format!("malformed response header: {line:?}"),
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((status, fields))
}

fn content_length(fields: &[(String, String)]) -> Option<usize> {
    fields
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::{spawn as spawn_server, spawn_raw as spawn_server_raw};
    use ks_core::ports::http::HttpMethod;
    use std::sync::atomic::Ordering;

    const BODY: &str = "{\"results\":[]}";

    fn client(host: &str, max_bytes: usize, timeout: Duration) -> TcpHttpClient {
        TcpHttpClient::new(HttpPolicy {
            allowed_hosts: [host.to_string()].into_iter().collect(),
            timeout,
            max_response_bytes: max_bytes,
        })
    }

    fn get(client: &TcpHttpClient, url: &str) -> Result<HttpResponse, HttpError> {
        send(client, HttpMethod::Get, url)
    }

    fn send(
        client: &TcpHttpClient,
        method: HttpMethod,
        url: &str,
    ) -> Result<HttpResponse, HttpError> {
        let mut future = Box::pin(client.send(HttpRequest::new(method, url)));
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        loop {
            if let std::task::Poll::Ready(out) = future.as_mut().poll(&mut context) {
                return out;
            }
        }
    }

    #[test]
    fn fetches_a_content_length_framed_response() {
        let (address, captured, _) = spawn_server("200 OK", BODY, false);
        let client = client("127.0.0.1", 1024, Duration::from_secs(5));
        let response = get(&client, &format!("http://{address}/v1/blocks/search?q=x"))
            .expect("the scripted response");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, BODY.as_bytes());
        let sent = captured.lock().expect("capture").clone();
        assert!(
            sent.iter().any(|line| line.starts_with("GET /v1/blocks/search?q=x HTTP/1.1")),
            "{sent:?}"
        );
        assert!(sent.iter().any(|line| line == &format!("Host: {address}")), "{sent:?}");
        assert!(sent.iter().any(|line| line == "Connection: close"), "{sent:?}");
    }

    #[test]
    fn a_body_carrying_verb_frames_an_empty_body() {
        let (address, captured, _) = spawn_server("201 Created", "", false);
        let client = client("127.0.0.1", 1024, Duration::from_secs(5));
        send(&client, HttpMethod::Put, &format!("http://{address}/v2/app/blobs/uploads/1"))
            .expect("the scripted response");
        let sent = captured.lock().expect("capture").clone();
        assert!(sent.iter().any(|line| line == "Content-Length: 0"), "{sent:?}");
    }

    #[test]
    fn a_head_survives_a_chunked_answer_it_never_reads() {
        // A registry is free to frame a HEAD the way it frames the GET; the
        // client must not refuse the request over a body it is not reading.
        let (address, _, _) = spawn_server_raw(
            "HTTP/1.1 200 OK\r\nDocker-Content-Digest: sha256:\
             abc\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            false,
        );
        let client = client("127.0.0.1", 1024, Duration::from_secs(5));
        let response = send(&client, HttpMethod::Head, &format!("http://{address}/v2/app"))
            .expect("a HEAD has no body to frame");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, Vec::<u8>::new());
    }

    #[test]
    fn policy_refusals_happen_before_any_traffic() {
        let (address, _, connections) = spawn_server("200 OK", BODY, false);
        let client = client("other.example", 1024, Duration::from_secs(5));
        let error = get(&client, &format!("http://{address}/x")).expect_err("refused");
        assert!(matches!(error, HttpError::HostNotAllowed { .. }), "{error}");
        assert_eq!(connections.load(Ordering::SeqCst), 0, "no connection was made");
    }

    #[test]
    fn https_urls_are_refused_not_downgraded() {
        let client = client("index.example", 1024, Duration::from_secs(5));
        let error = get(&client, "https://index.example/v1/blocks/search?q=x")
            .expect_err("https is refused");
        let HttpError::Transport { message } = error else {
            panic!("expected a transport error, got {error}");
        };
        assert!(message.contains("plain http only"), "{message}");
    }

    #[test]
    fn oversized_bodies_fail_without_truncation() {
        let (address, _, _) = spawn_server("200 OK", &"x".repeat(64), false);
        let client = client("127.0.0.1", 32, Duration::from_secs(5));
        assert!(matches!(
            get(&client, &format!("http://{address}/")),
            Err(HttpError::ResponseTooLarge { limit: 32 })
        ));
    }

    #[test]
    fn an_unanswered_connection_times_out() {
        let (address, _, _) = spawn_server("200 OK", BODY, true);
        let client = client("127.0.0.1", 1024, Duration::from_millis(200));
        assert!(matches!(
            get(&client, &format!("http://{address}/")),
            Err(HttpError::Timeout { .. })
        ));
    }

    #[test]
    fn url_helpers_cover_the_shapes_the_cli_can_receive() {
        assert_eq!(url_host_port("http://index.example/v1"), Some(("index.example".into(), 80)));
        assert_eq!(
            url_host_port("http://index.example:8080/"),
            Some(("index.example".into(), 8080))
        );
        assert_eq!(url_host_port("https://[::1]:8443/x"), Some(("::1".into(), 8443)));
        assert_eq!(url_host_port("https://[::1]/x"), Some(("::1".into(), 443)));
        assert_eq!(url_host_port("http://"), None);
        assert_eq!(url_host_port("index.example/x"), None);
        assert_eq!(url_host_port(r"http://evil.com\@good.example/"), None);
        assert_eq!(request_target("http://h/v1/search?q=1#frag").as_deref(), Ok("/v1/search?q=1"));
        assert_eq!(request_target("http://h?a=1").as_deref(), Ok("/?a=1"));
        assert_eq!(request_target("http://h").as_deref(), Ok("/"));
        assert!(request_target("ftp://h/").is_err());
    }

    /// The noop-waker poll loop is exactly what the CLI uses; this compiles
    /// check keeps that contract honest.
    #[test]
    fn the_client_trait_object_is_send_sync() {
        fn assert_send_sync<T: ?Sized + Send + Sync>() {}
        assert_send_sync::<dyn HttpClient>();
    }
}
