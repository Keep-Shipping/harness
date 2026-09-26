//! Fake for the [`HttpClient`] port: scripted responses, enforced policy, and
//! a record of every request. Never opens a socket.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Mutex;

use ks_core::ports::BoxFuture;
use ks_core::ports::http::{
    HttpClient, HttpError, HttpMethod, HttpPolicy, HttpRequest, HttpResponse,
};

/// An [`HttpClient`] whose responses you script per test.
///
/// Responses are keyed by `(method, url)`; several can be queued for the same
/// key (handy for retries), and the queue hands out its entries in order,
/// repeating the last one forever. Unscripted requests fail with
/// [`HttpError::Transport`].
///
/// Every `send` — successful or not — is checked against the
/// [`HttpPolicy`]: non-allowlisted hosts are rejected with
/// [`HttpError::HostNotAllowed`] before any scripted response is consulted,
/// and responses larger than `max_response_bytes` fail with
/// [`HttpError::ResponseTooLarge`]. Every attempt is recorded.
///
/// ```
/// use ks_core::ports::http::{HttpMethod, HttpRequest, HttpResponse, HttpClient};
/// use ks_testing::{block_on, http::FakeHttpClient};
///
/// let client = FakeHttpClient::new()
///     .with_allowed_host("api.example.com")
///     .with_response(
///         HttpMethod::Get,
///         "https://api.example.com/v1/ping",
///         HttpResponse { status: 200, headers: vec![], body: b"pong".to_vec() },
///     );
/// let request = HttpRequest::new(HttpMethod::Get, "https://api.example.com/v1/ping");
/// let response = block_on(client.send(request)).expect("scripted requests succeed");
/// assert_eq!((response.status, response.body.as_slice()), (200, b"pong".as_slice()));
/// ```
/// Scripted responses: a queue per `(method, url)`; the last entry repeats.
type Scripts = BTreeMap<(HttpMethod, String), VecDeque<Result<HttpResponse, HttpError>>>;

#[derive(Default)]
pub struct FakeHttpClient {
    policy: HttpPolicy,
    responses: Mutex<Scripts>,
    requests: Mutex<Vec<HttpRequest>>,
}

impl FakeHttpClient {
    /// Creates a fake with a default policy: nothing allowed, a 30s timeout
    /// and a 1 MiB response cap. Call [`with_allowed_host`](Self::with_allowed_host)
    /// or [`with_policy`](Self::with_policy) before requests can succeed.
    pub fn new() -> FakeHttpClient {
        FakeHttpClient {
            policy: HttpPolicy::default(),
            responses: Mutex::new(BTreeMap::new()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Replaces the whole policy.
    pub fn with_policy(mut self, policy: HttpPolicy) -> FakeHttpClient {
        self.policy = policy;
        self
    }

    /// Adds one exact host to the policy's allowlist.
    pub fn with_allowed_host(mut self, host: impl Into<String>) -> FakeHttpClient {
        self.policy.allowed_hosts.insert(host.into());
        self
    }

    /// Replaces the policy's response-size cap.
    pub fn with_max_response_bytes(mut self, max: usize) -> FakeHttpClient {
        self.policy.max_response_bytes = max;
        self
    }

    /// Queues a scripted success for `(method, url)`. The last entry of a key's
    /// queue repeats, so a single scripted response serves any number of polls.
    pub fn with_response(
        self,
        method: HttpMethod,
        url: impl Into<String>,
        response: HttpResponse,
    ) -> FakeHttpClient {
        self.with_scripted(method, url, Ok(response))
    }

    /// Queues a scripted failure for `(method, url)`, e.g. a
    /// [`HttpError::Timeout`] for a retry test. The last entry of a key's
    /// queue repeats.
    pub fn with_error(
        self,
        method: HttpMethod,
        url: impl Into<String>,
        error: HttpError,
    ) -> FakeHttpClient {
        self.with_scripted(method, url, Err(error))
    }

    fn with_scripted(
        self,
        method: HttpMethod,
        url: impl Into<String>,
        result: Result<HttpResponse, HttpError>,
    ) -> FakeHttpClient {
        self.responses
            .lock()
            .expect("fake http script")
            .entry((method, url.into()))
            .or_default()
            .push_back(result);
        self
    }

    /// Every request made against the fake, oldest first.
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().expect("fake http request record").clone()
    }
}

impl fmt::Debug for FakeHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeHttpClient")
            .field("policy", &self.policy)
            .field("scripted", &self.responses.lock().expect("fake http script").len())
            .field("requests", &self.requests.lock().expect("fake http request record").len())
            .finish()
    }
}

impl HttpClient for FakeHttpClient {
    fn policy(&self) -> &HttpPolicy {
        &self.policy
    }

    fn send<'a>(&'a self, req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse, HttpError>> {
        self.requests.lock().expect("fake http request record").push(req.clone());
        let result = self.policy.check(&req.url).and_then(|()| {
            let mut scripts = self.responses.lock().expect("fake http script");
            let Some(queue) = scripts.get_mut(&(req.method, req.url.clone())) else {
                return Err(HttpError::Transport {
                    message: format!("no scripted response for {} {}", req.method, req.url),
                });
            };
            let scripted = match queue.len() {
                0 | 1 => queue.front().expect("the queue is non-empty").clone(),
                _ => queue.pop_front().expect("the queue is non-empty"),
            };
            match scripted {
                Ok(response) if response.body.len() > self.policy.max_response_bytes => {
                    Err(HttpError::ResponseTooLarge { limit: self.policy.max_response_bytes })
                }
                other => other,
            }
        });
        Box::pin(std::future::ready(result))
    }
}

/// The `HttpClient` conformance kit: every HTTP adapter must pass this.
///
/// It is deliberately I/O-free: it only exercises the policy contract.
/// `send` must run [`HttpPolicy::check`] *before* any traffic, so a host
/// outside the allowlist is refused with [`HttpError::HostNotAllowed`] — from
/// the conformance kit, no socket is ever opened, against a fake or a real
/// adapter alike.
pub async fn conformance(client: &dyn HttpClient) {
    let policy = client.policy();

    // A host the policy does not name is refused, before any I/O, and the
    // pure check agrees with what send reports. The guard itself must hold:
    // a policy that allowlists the probe host would make this kit vacuous.
    let rogue_host = "conformance-not-allowed.invalid";
    assert!(
        !policy.allowed_hosts.contains(rogue_host),
        "conformance: {rogue_host} must not be allowlisted — the refusals below would prove nothing"
    );
    let rogue_url = format!("https://{rogue_host}/conformance");
    assert!(
        matches!(
            client.send(HttpRequest::new(HttpMethod::Get, rogue_url.clone())).await,
            Err(HttpError::HostNotAllowed { .. })
        ),
        "conformance: send must refuse non-allowlisted hosts with HostNotAllowed"
    );
    assert!(
        matches!(policy.check(&rogue_url), Err(HttpError::HostNotAllowed { .. })),
        "conformance: policy().check must agree with send"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    fn ping() -> HttpRequest {
        HttpRequest::new(HttpMethod::Get, "https://api.example.com/v1/ping")
    }

    fn ok(body: &[u8]) -> HttpResponse {
        HttpResponse { status: 200, headers: vec![], body: body.to_vec() }
    }

    #[test]
    fn unscripted_requests_are_transport_errors() {
        let client = FakeHttpClient::new().with_allowed_host("api.example.com");
        assert!(matches!(block_on(client.send(ping())), Err(HttpError::Transport { .. })));
    }

    #[test]
    fn queues_replay_their_last_entry() {
        let client = FakeHttpClient::new().with_allowed_host("api.example.com").with_response(
            HttpMethod::Get,
            "https://api.example.com/v1/ping",
            ok(b"pong"),
        );
        for _ in 0..3 {
            let response = block_on(client.send(ping())).expect("the scripted response repeats");
            assert_eq!(response.body, b"pong");
        }
    }

    #[test]
    fn every_request_is_recorded_even_rejected_ones() {
        let client = FakeHttpClient::new().with_allowed_host("api.example.com");
        let _ = block_on(client.send(HttpRequest::new(HttpMethod::Get, "https://evil.example/")));
        let requests = client.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://evil.example/");
    }

    #[test]
    fn the_fake_passes_conformance() {
        let client = FakeHttpClient::new().with_allowed_host("api.example.com").with_response(
            HttpMethod::Get,
            "https://api.example.com/v1/ping",
            ok(b"pong"),
        );
        block_on(conformance(&client));
    }

    #[test]
    fn conformance_never_passes_vacuously() {
        // A policy that allowlists the probe host must abort the kit, not
        // sail through it.
        let client = FakeHttpClient::new().with_allowed_host("conformance-not-allowed.invalid");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(conformance(&client));
        }));
        assert!(result.is_err(), "conformance must refuse a vacuous policy");
    }
}
