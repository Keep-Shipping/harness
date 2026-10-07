//! `WWW-Authenticate` challenges: what a registry asks for on a 401, and what
//! we answer with.
//!
//! Two schemes are understood, `Bearer` (the distribution-spec token dance:
//! take a token from the named realm and retry) and `Basic`. Tokens are cached
//! per `(host, scope)` so a push of twenty blobs fetches one token, not twenty.

use std::fmt::Write as _;

/// What a registry asked for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Challenge {
    /// `Bearer realm="…",service="…",scope="…"`: fetch a token from `realm`.
    Bearer {
        /// Where the token is fetched from.
        realm: String,
        /// The `service` parameter, if the challenge named one.
        service: Option<String>,
        /// The `scope` parameter, if the challenge named one.
        scope: Option<String>,
    },
    /// `Basic realm="…"`: the credentials go straight on the retry.
    Basic {
        /// The realm the registry names, for error messages.
        realm: String,
    },
}

impl Challenge {
    /// The cache key a fetched token is stored under: the same scope on the
    /// same host is the same token, and nothing else is.
    pub fn token_key(&self, host: &str) -> String {
        match self {
            Challenge::Bearer { realm, service, scope } => {
                format!(
                    "{host}\u{1}{realm}\u{1}{}\u{1}{}",
                    service.as_deref().unwrap_or(""),
                    scope.as_deref().unwrap_or("")
                )
            }
            Challenge::Basic { realm } => format!("{host}\u{1}basic\u{1}\u{1}{realm}"),
        }
    }

    /// The realm's query string for the token request, percent-encoded: a
    /// scope is `repository:name:pull,push`, which needs both `:` and `,`
    /// escaped.
    pub fn token_query(&self) -> String {
        let Challenge::Bearer { service, scope, .. } = self else {
            return String::new();
        };
        let mut query = String::new();
        for (name, value) in [("service", service), ("scope", scope)] {
            if let Some(value) = value {
                if !query.is_empty() {
                    query.push('&');
                }
                let _ = write!(query, "{name}={}", percent_encode(value));
            }
        }
        query
    }
}

/// Parses the first challenge in a `WWW-Authenticate` header value, or [`None`]
/// when it is not a scheme this adapter speaks.
pub fn parse(header: &str) -> Option<Challenge> {
    let (scheme, rest) = header.split_once(' ')?;
    let parameters = parameters(rest);
    let parameter = |name: &str| {
        parameters
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };
    match scheme.trim().to_ascii_lowercase().as_str() {
        "bearer" => {
            let realm = parameter("realm")?;
            Some(Challenge::Bearer {
                realm,
                service: parameter("service"),
                scope: parameter("scope"),
            })
        }
        "basic" => Some(Challenge::Basic { realm: parameter("realm").unwrap_or_default() }),
        _ => None,
    }
}

/// The `name=value` parameters of a challenge, unquoted, in order.
///
/// Values may be quoted and may contain commas — a scope does — so this
/// splits on commas that are not inside quotes rather than on every comma.
fn parameters(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    let bytes = text.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                push_parameter(&mut out, &text[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    push_parameter(&mut out, &text[start..]);
    out
}

fn push_parameter(out: &mut Vec<(String, String)>, text: &str) {
    let Some((name, value)) = text.split_once('=') else {
        return;
    };
    let value = value.trim();
    let value = value.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')).unwrap_or(value);
    out.push((name.trim().to_string(), value.to_string()));
}

/// Percent-encodes everything outside the unreserved set, so a scope survives
/// a query string intact. Also used for the `digest=` an upload URL carries.
pub(crate) fn percent_encode(text: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bearer_challenge_with_a_multi_scope() {
        let challenge = parse(
            r#"Bearer realm="https://auth.example/token",service="registry.example",scope="repository:app:pull,push""#,
        )
        .expect("a bearer challenge");
        assert_eq!(
            challenge,
            Challenge::Bearer {
                realm: "https://auth.example/token".to_string(),
                service: Some("registry.example".to_string()),
                scope: Some("repository:app:pull,push".to_string()),
            }
        );
        assert_eq!(
            challenge.token_query(),
            "service=registry.example&scope=repository%3Aapp%3Apull%2Cpush"
        );
    }

    #[test]
    fn parses_basic_and_ignores_schemes_it_does_not_speak() {
        assert_eq!(
            parse(r#"Basic realm="registry""#),
            Some(Challenge::Basic { realm: "registry".to_string() })
        );
        assert_eq!(parse("Negotiate"), None);
        assert_eq!(parse(""), None);
    }

    #[test]
    fn unquoted_parameters_and_a_missing_realm_are_handled() {
        let challenge = parse("Bearer realm=https://auth.example/token").expect("unquoted realm");
        assert!(
            matches!(challenge, Challenge::Bearer { realm, .. } if realm == "https://auth.example/token")
        );
        assert_eq!(parse("Bearer service=registry"), None, "a bearer challenge needs a realm");
    }

    #[test]
    fn tokens_are_cached_per_host_and_scope() {
        let pull = Challenge::Bearer {
            realm: "https://auth.example/token".to_string(),
            service: Some("registry.example".to_string()),
            scope: Some("repository:app:pull".to_string()),
        };
        let push = Challenge::Bearer {
            realm: "https://auth.example/token".to_string(),
            service: Some("registry.example".to_string()),
            scope: Some("repository:app:pull,push".to_string()),
        };
        assert_ne!(pull.token_key("registry.example"), push.token_key("registry.example"));
        assert_ne!(pull.token_key("registry.example"), pull.token_key("other.example"));
        assert_eq!(pull.token_key("registry.example"), pull.token_key("registry.example"));
    }
}
