//! The Workers-side console glue (issue #169): method check, auth, the KV
//! read, the security headers. Deliberately thin — every decision worth
//! testing (routing, token and cookie extraction, the allowlist check, all
//! rendering) is a pure function in the parent module, exercised natively
//! by `tests/fleet.rs`; what is left here is only the Workers wiring. It
//! fails closed at every step: an unconfigured console is `503`, a missing
//! or unverifiable token is `401`, an email off the allowlist is `403`.

use std::sync::{Arc, OnceLock};

use cratefield_auth_client::AuthClient;
use cratefield_runtime_cloudflare::{FetchClient, WorkersClock};
use worker::{Env, Headers, Method, Request, Response};

use super::{
    Fleet, Route, bearer_token, cookie_value, email_allowed, notice_page, render_index,
    render_site, route,
};

/// Answers console paths, or `None` when the path is not the console's and
/// the request should fall through to the harness.
pub async fn handle(req: &Request, env: &Env) -> Option<worker::Result<Response>> {
    let route = route(&req.path())?;
    Some(serve(req, env, route).await)
}

async fn serve(req: &Request, env: &Env, route: Route) -> worker::Result<Response> {
    if !matches!(req.method(), Method::Get | Method::Head) {
        return page_with(
            405,
            &notice_page(
                "Method not allowed",
                "The console is read-only: it answers GET and HEAD only.",
                None,
            ),
            &[("allow", "GET, HEAD")],
        );
    }

    // A config value as trimmed text, blank counting as absent — the same
    // rule the secrets are read by. Vars and secrets both qualify: the
    // issuer and client id are public, the allowlist may be sensitive.
    let read = |name: &str| {
        env.var(name)
            .ok()
            .map(|value| value.to_string())
            .or_else(|| env.secret(name).ok().map(|secret| secret.to_string()))
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    let (Some(issuer), Some(client_id), Some(allowlist)) =
        (read("AUTH_ISSUER"), read("AUTH_CLIENT_ID"), read("CONSOLE_EMAILS"))
    else {
        return page(503, &notice_page("Console not configured", CONFIGURED_COPY, None));
    };

    // Who: a bearer token in the header, else the console cookie.
    let headers = req.headers();
    let token = bearer_token(headers.get("authorization").ok().flatten().as_deref())
        .or_else(|| cookie_value(headers.get("cookie").ok().flatten().as_deref(), COOKIE));
    let Some(token) = token else {
        return unauthorized(&issuer);
    };
    let claims = match console_auth(&issuer, &client_id).verify(&token).await {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(%error, "console: token rejected");
            return unauthorized(&issuer);
        }
    };
    let Some(email) = claims.email.filter(|_| claims.email_verified == Some(true)) else {
        return page(403, &notice_page("Not allowed", FORBIDDEN_COPY, None));
    };
    if !email_allowed(&email, &allowlist) {
        return page(403, &notice_page("Not allowed", FORBIDDEN_COPY, None));
    }

    // What: the snapshot the nightly check writes. A missing key is the
    // honest empty state, not an error; a read that fails is a broken
    // console rather than an empty fleet; a snapshot that does not parse
    // is logged and shown as unreadable rather than guessed at.
    let kv = match env.kv("FLEET") {
        Ok(kv) => kv,
        Err(error) => {
            tracing::warn!(%error, "console: FLEET binding missing");
            return page(503, &notice_page("Could not read the fleet", READ_COPY, None));
        }
    };
    let raw = match kv.get("fleet.json").text().await {
        Ok(Some(raw)) => raw,
        Ok(None) => {
            return page(
                200,
                &notice_page(
                    "No fleet snapshot yet",
                    "This view appears after the nightly check writes its first snapshot. \
                     Until then there is nothing to show.",
                    None,
                ),
            );
        }
        Err(error) => {
            tracing::warn!(%error, "console: fleet.json could not be read");
            return page(503, &notice_page("Could not read the fleet", READ_COPY, None));
        }
    };
    let snapshot = match serde_json::from_str::<Fleet>(&raw) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::warn!(%error, "console: fleet.json is not the expected shape");
            return page(200, &notice_page("Snapshot could not be read", BROKEN_COPY, None));
        }
    };
    match route {
        Route::Index => page(200, &render_index(&snapshot)),
        Route::Site(id) => match render_site(&snapshot, &id) {
            Some(html) => page(200, &html),
            None => page(
                404,
                &notice_page(
                    "No such site",
                    "The snapshot has no site with that id.",
                    Some(("/console/fleet", "All sites")),
                ),
            ),
        },
    }
}

/// The token verifier, one per isolate: it caches the issuer's key set, so
/// rebuilding it per request would re-fetch the JWKS on every console view.
/// The config comes from wrangler vars — constant for a deployed isolate —
/// so caching without keying on them is sound.
fn console_auth(issuer: &str, client_id: &str) -> Arc<AuthClient> {
    static CLIENT: OnceLock<Arc<AuthClient>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            Arc::new(AuthClient::new(
                Arc::new(FetchClient),
                Arc::new(WorkersClock),
                issuer,
                client_id,
            ))
        })
        .clone()
}

/// A console page with the console's security headers on it: nothing is
/// cached (private, no-store), nothing may frame it, scripts have no
/// source at all, and only this page's inline stylesheet and the Google
/// Fonts sheet may style it.
fn page(status: u16, html: &str) -> worker::Result<Response> {
    page_with(status, html, &[])
}

/// [`page`] with one extra header on top of the security set (`Allow` on
/// a 405, `WWW-Authenticate` on a 401).
fn page_with(status: u16, html: &str, extra: &[(&str, &str)]) -> worker::Result<Response> {
    let headers = Headers::new();
    headers.set("content-type", "text/html; charset=utf-8")?;
    headers.set("cache-control", "private, no-store")?;
    headers.set(
        "content-security-policy",
        "default-src 'none'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self'; frame-ancestors 'none'",
    )?;
    headers.set("referrer-policy", "no-referrer")?;
    headers.set("x-content-type-options", "nosniff")?;
    for (name, value) in extra {
        headers.set(name, value)?;
    }
    Ok(Response::from_html(html)?.with_status(status).with_headers(headers))
}

/// A 401 that tells the client the scheme it should have used.
fn unauthorized(issuer: &str) -> worker::Result<Response> {
    page_with(
        401,
        &notice_page("Sign in required", SIGN_IN_COPY, sign_in(issuer)),
        &[("www-authenticate", "Bearer")],
    )
}

/// The "Sign in" link target, only for an https issuer.
fn sign_in(issuer: &str) -> Option<(&str, &str)> {
    issuer.starts_with("https://").then_some((issuer, "Sign in"))
}

const COOKIE: &str = "ks_console";
const CONFIGURED_COPY: &str = "This deployment is missing AUTH_ISSUER, AUTH_CLIENT_ID or \
     CONSOLE_EMAILS, so the console is switched off. Set them (see the README) and deploy again.";
const SIGN_IN_COPY: &str = "Open this page signed in to the auth service; your session token is \
     missing or has expired.";
const FORBIDDEN_COPY: &str = "Your account is not on this console's allowlist (CONSOLE_EMAILS). \
     Ask an operator to add it.";
const BROKEN_COPY: &str = "The fleet snapshot in storage is not the shape this page expects. The \
     nightly check may still be writing it; if this persists, the pipeline is writing a bad \
     snapshot.";
const READ_COPY: &str = "The fleet could not be read right now. Try again shortly; if it \
     persists, the worker that serves this view cannot reach its storage.";
