//! The [`HttpClient`] port over `worker::Fetch`: the one socket the onboarding
//! reads a Cloudflare account through, from inside the console Worker.
//!
//! The policy is the only thing this adapter decides. Its allowlist names
//! exactly `api.cloudflare.com`, and [`HttpClient::send`] runs
//! [`HttpPolicy::check`] before a request is built, so a caller handed this
//! client cannot reach any other host through it. Failures are answered with
//! fixed words: `worker::Error` can quote the whole URL, and the reader's
//! requests carry the token in a header, so no error text from the platform
//! is ever stringified.

use std::collections::BTreeSet;

use ks_core::ports::BoxFuture;
use ks_core::ports::http::{
    HttpClient, HttpError, HttpMethod, HttpPolicy, HttpRequest, HttpResponse,
};
use worker::send::IntoSendFuture;
use worker::{Fetch, Headers, Method, Request, RequestInit};

/// The one host the onboarding is allowed to read.
pub const CLOUDFLARE_HOST: &str = "api.cloudflare.com";

/// The [`HttpClient`] the console reads Cloudflare through, on `worker::Fetch`.
#[derive(Debug, Clone)]
pub struct WorkersHttp {
    policy: HttpPolicy,
}

impl Default for WorkersHttp {
    fn default() -> WorkersHttp {
        WorkersHttp::cloudflare()
    }
}

impl WorkersHttp {
    /// A client whose only allowed host is [`CLOUDFLARE_HOST`].
    pub fn cloudflare() -> WorkersHttp {
        WorkersHttp {
            policy: HttpPolicy {
                allowed_hosts: BTreeSet::from([CLOUDFLARE_HOST.to_string()]),
                ..HttpPolicy::default()
            },
        }
    }
}

impl HttpClient for WorkersHttp {
    fn policy(&self) -> &HttpPolicy {
        &self.policy
    }

    fn send<'a>(&'a self, req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse, HttpError>> {
        Box::pin(
            async move {
                // Before any traffic, and before a request object exists.
                self.policy.check(&req.url)?;
                let method = method_of(req.method);
                let headers = Headers::new();
                for (name, value) in &req.headers {
                    headers.append(name, value).map_err(|_| transport())?;
                }
                let mut init = RequestInit::new();
                init.with_method(method).with_headers(headers);
                if !req.body.is_empty() {
                    // The reader only sends JSON; a body that is not UTF-8 is
                    // refused rather than sent as something else.
                    let text = std::str::from_utf8(&req.body).map_err(|_| transport())?;
                    init.with_body(Some(worker::wasm_bindgen::JsValue::from_str(text)));
                }
                let request = Request::new_with_init(&req.url, &init).map_err(|_| transport())?;
                let mut response = Fetch::Request(request).send().await.map_err(|_| transport())?;

                let status = response.status_code();
                let mut out_headers = Vec::new();
                let platform_headers = response.headers();
                for name in platform_headers.keys() {
                    if let Ok(Some(value)) = platform_headers.get(&name) {
                        out_headers.push((name, value));
                    }
                }
                let body = response.bytes().await.map_err(|_| transport())?;
                if body.len() > self.policy.max_response_bytes {
                    return Err(HttpError::ResponseTooLarge {
                        limit: self.policy.max_response_bytes,
                    });
                }
                Ok(HttpResponse { status, headers: out_headers, body })
            }
            .into_send(),
        )
    }
}

/// The platform verb for a port verb.
fn method_of(method: HttpMethod) -> Method {
    match method {
        HttpMethod::Get => Method::Get,
        HttpMethod::Post => Method::Post,
        HttpMethod::Put => Method::Put,
        HttpMethod::Patch => Method::Patch,
        HttpMethod::Delete => Method::Delete,
        HttpMethod::Head => Method::Head,
    }
}

/// The one transport failure, in fixed words. Nothing the platform said is kept.
fn transport() -> HttpError {
    HttpError::Transport { message: "the request to Cloudflare did not complete".to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_cloudflare_is_allowed() {
        let client = WorkersHttp::cloudflare();
        assert_eq!(client.policy().check("https://api.cloudflare.com/client/v4/zones"), Ok(()));
        assert!(matches!(
            client.policy().check("https://evil.example/api.cloudflare.com"),
            Err(HttpError::HostNotAllowed { .. })
        ));
    }

    #[test]
    fn the_timeout_and_cap_are_the_policy_defaults() {
        let policy = WorkersHttp::cloudflare().policy;
        assert_eq!(policy.max_response_bytes, HttpPolicy::default().max_response_bytes);
        assert_eq!(policy.timeout, HttpPolicy::default().timeout);
    }
}
