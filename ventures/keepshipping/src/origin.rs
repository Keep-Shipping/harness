//! The write guard: a browser CORS policy is a reading convenience, not an
//! authorisation boundary. `tower-http`'s allowlisted CORS layer only ever
//! *adds* headers to responses — it never refuses a request, so a `curl`
//! POST that simply omits `Origin` sails past it untouched. The waitlist
//! write is free (no card, no login), which makes it exactly the endpoint a
//! scripted fleet would hammer; every write therefore has to name an origin
//! this site actually serves from, or it is refused before the harness runs.
//!
//! The guard is a pure function over `(method, origin, allowlist)` — the
//! unit tests at the bottom prove each rule, and the worker entry point in
//! `lib.rs` consults it before `serve`, so a refused write costs one string
//! comparison, not a D1 round trip or a Turnstile siteverify call.

/// The origins this site is served from: the apex over TLS, its `www`
/// alias, and the worker's own API host — which serves the standard setup
/// console (issue #273), whose HTML forms POST back to the host they were
/// served from. One list, shared by the venture's CORS allowlist and this
/// guard, so a future origin can only be added in one place — and the guard
/// then demands it on writes too.
pub const SITE_ORIGINS: [&str; 3] =
    ["https://keepshipping.run", "https://www.keepshipping.run", "https://api.keepshipping.run"];

/// Whether the request described by `method` + `origin` is refused.
///
/// Writes (`POST`, `PUT`, `PATCH`, `DELETE`) are refused unless their
/// `Origin` header names an allowlisted origin — absent (`None`), empty,
/// whitespace, the sandboxed-document sentinel `"null"`, and foreign origins
/// are all refused. Reads (`GET`, `HEAD`, `OPTIONS`) pass untouched: they
/// carry no side effects, and `GET` navigation links legitimately arrive
/// without an `Origin` header. Comparison is case-insensitive because the
/// scheme and host are case-insensitive in the URL grammar.
pub fn write_origin_rejected(method: &str, origin: Option<&str>, allowed: &[&str]) -> bool {
    if !matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") {
        return false;
    }
    let Some(origin) = origin.map(str::trim).filter(|origin| !origin.is_empty()) else {
        return true;
    };
    !allowed.iter().any(|candidate| candidate.eq_ignore_ascii_case(origin))
}

#[cfg(test)]
mod tests {
    use super::{SITE_ORIGINS, write_origin_rejected};

    #[test]
    fn absent_origin_is_refused_on_writes() {
        // The whole point of the guard: `curl -X POST` sends no `Origin`,
        // and CORS middleware would have let it through.
        assert!(write_origin_rejected("POST", None, &SITE_ORIGINS));
        assert!(write_origin_rejected("POST", Some(""), &SITE_ORIGINS));
        assert!(write_origin_rejected("POST", Some("   "), &SITE_ORIGINS));
    }

    #[test]
    fn null_and_foreign_origins_are_refused() {
        // `Origin: null` is what sandboxed iframes and `file://` pages send.
        assert!(write_origin_rejected("POST", Some("null"), &SITE_ORIGINS));
        assert!(write_origin_rejected(
            "POST",
            Some("https://keepshipping.run.evil.example"),
            &SITE_ORIGINS
        ));
        assert!(write_origin_rejected("POST", Some("http://keepshipping.run"), &SITE_ORIGINS));
    }

    #[test]
    fn allowlisted_origins_pass_case_insensitively() {
        assert!(!write_origin_rejected("POST", Some("https://keepshipping.run"), &SITE_ORIGINS));
        assert!(!write_origin_rejected(
            "POST",
            Some("https://www.keepshipping.run"),
            &SITE_ORIGINS
        ));
        // The setup console's pages are served by the worker itself, so
        // its forms post from the API host.
        assert!(!write_origin_rejected(
            "POST",
            Some("https://api.keepshipping.run"),
            &SITE_ORIGINS
        ));
        assert!(!write_origin_rejected("POST", Some("HTTPS://KEEPSHIPPING.RUN"), &SITE_ORIGINS));
    }

    #[test]
    fn reads_pass_without_an_origin() {
        assert!(!write_origin_rejected("GET", None, &SITE_ORIGINS));
        assert!(!write_origin_rejected("HEAD", None, &SITE_ORIGINS));
        // Browser preflights are OPTIONS without side effects.
        assert!(!write_origin_rejected("OPTIONS", None, &SITE_ORIGINS));
    }

    #[test]
    fn every_write_method_is_guarded() {
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            assert!(write_origin_rejected(method, None, &SITE_ORIGINS), "{method}");
        }
    }
}
