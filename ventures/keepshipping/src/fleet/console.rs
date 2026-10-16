//! The Workers-side console glue (issue #169): method check, auth, the KV
//! read, the security headers. Deliberately thin — every decision worth
//! testing (routing, token and cookie extraction, the allowlist check, all
//! rendering) is a pure function in the parent module, exercised natively
//! by `tests/fleet.rs`; what is left here is only the Workers wiring. It
//! fails closed at every step: an unconfigured console is `503`, a missing
//! or unverifiable token is `401`, an email off the allowlist is `403`.
//!
//! The sign-in routes (`/console/login`, `/console/callback`,
//! `/console/logout`) are wired here too; the flow itself is
//! [`crate::signin`], equally pure and tested natively.

use std::sync::{Arc, OnceLock};

use cratefield_auth_client::AuthClient;
use cratefield_core::{Clock, HmacSigner};
use cratefield_runtime_cloudflare::{FetchClient, WorkersClock};
use worker::{Env, Headers, Method, Request, Response};

use super::{
    Fleet, Route, bearer_token, cookie_value, empty_snapshot_page, notice_page, render_index,
    render_site_with, route,
};
use crate::cloudflare::api::{self, NOT_CONNECTED};
use crate::cloudflare::page::{
    CONNECT_PATH, DEPLOY_CONNECT_PATH, DEPLOY_DISCONNECT_PATH, DISCONNECT_PATH, connect_page,
};
use crate::cloudflare::rollback::{self, Panel};
use crate::signin::{self, CALLBACK_PATH, Client, LOGIN_PATH, LOGOUT_PATH, Reply};

/// `same-origin`, not `no-referrer`: under `no-referrer` Chrome sends
/// `Origin: null` on the console's own form posts, and the write guard in
/// `origin.rs` rightly refuses that. `same-origin` still sends nothing to
/// any other site.
const REFERRER_POLICY: &str = "same-origin";

/// The fleet snapshot's refresh button (a POST, same gate as the fleet).
pub const REFRESH_PATH: &str = "/console/fleet/refresh";

/// Answers console paths, or `None` when the path is not the console's and
/// the request should fall through to the harness. `lib.rs` has already
/// refused cross-site writes (`write_origin_rejected`) before this runs.
pub async fn handle(req: &mut Request, env: &Env) -> Option<worker::Result<Response>> {
    let path = req.path();
    if let Some(step) = sign_in_step(&path) {
        return Some(serve_sign_in(req, env, step).await);
    }
    if let Some(action) = action_for(&path) {
        return Some(serve_action(req, env, action).await);
    }
    let route = route(&path)?;
    Some(serve(req, env, route).await)
}

/// The Cloudflare connect page and the snapshot's write routes.
#[derive(Clone, Copy)]
enum Action {
    /// `GET` shows the page, `POST` stores a pasted token.
    Connect,
    Disconnect,
    Refresh,
    /// `POST` stores a pasted deploy token (rollbacks).
    ConnectDeploy,
    DisconnectDeploy,
}

fn action_for(path: &str) -> Option<Action> {
    match path.trim_end_matches('/') {
        CONNECT_PATH => Some(Action::Connect),
        DISCONNECT_PATH => Some(Action::Disconnect),
        REFRESH_PATH => Some(Action::Refresh),
        DEPLOY_CONNECT_PATH => Some(Action::ConnectDeploy),
        DEPLOY_DISCONNECT_PATH => Some(Action::DisconnectDeploy),
        _ => None,
    }
}

/// The hourly cron's snapshot refresh (issue #169). Runs after the venture's
/// own sweeps and never panics: a missing token is quiet, a failure is a
/// logged warning, and the previous snapshot stays in place.
pub async fn scheduled_refresh(env: &Env) {
    let Some(secret) = read(env, "HARNESS_SECRET") else {
        tracing::warn!("console: no HARNESS_SECRET, fleet snapshot not refreshed");
        return;
    };
    match api::refresh(env, &secret).await {
        Ok(_) => tracing::info!("console: fleet snapshot refreshed"),
        Err(failed) if failed == NOT_CONNECTED => {}
        Err(failed) => tracing::warn!(message = failed.message, "console: fleet refresh failed"),
    }
}

/// The three sign-in routes, matched exactly (trailing slash tolerant).
#[derive(Clone, Copy)]
enum Step {
    Login,
    Callback,
    Logout,
}

fn sign_in_step(path: &str) -> Option<Step> {
    match path.trim_end_matches('/') {
        LOGIN_PATH => Some(Step::Login),
        CALLBACK_PATH => Some(Step::Callback),
        LOGOUT_PATH => Some(Step::Logout),
        _ => None,
    }
}

/// A config value as trimmed text, blank counting as absent — the same rule
/// the secrets are read by. Vars and secrets both qualify: the issuer and
/// client id are public, the allowlist may be sensitive.
pub(crate) fn read(env: &Env, name: &str) -> Option<String> {
    env.var(name)
        .ok()
        .map(|value| value.to_string())
        .or_else(|| env.secret(name).ok().map(|secret| secret.to_string()))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

async fn serve_sign_in(req: &Request, env: &Env, step: Step) -> worker::Result<Response> {
    let allowed = match step {
        Step::Login | Step::Callback => matches!(req.method(), Method::Get),
        // A state change: POST only, behind the worker's origin guard.
        Step::Logout => matches!(req.method(), Method::Post),
    };
    if !allowed {
        let allow = if matches!(step, Step::Logout) { "POST" } else { "GET" };
        return page_with(
            405,
            &notice_page(
                "Method not allowed",
                "This sign-in step does not answer that method.",
                None,
            ),
            &[("allow", allow)],
        );
    }
    let (Some(issuer), Some(client_id), Some(allowlist)) =
        (read(env, "AUTH_ISSUER"), read(env, "AUTH_CLIENT_ID"), read(env, "CONSOLE_EMAILS"))
    else {
        return page(503, &notice_page("Console not configured", CONFIGURED_COPY, None));
    };
    let client_secret = read(env, "AUTH_CLIENT_SECRET");
    let client =
        Client { issuer: &issuer, client_id: &client_id, client_secret: client_secret.as_deref() };
    if matches!(step, Step::Logout) {
        return reply(&signin::logout(&client));
    }
    // The login cookie is signed, and the refresh cookie sealed, with keys
    // from `HARNESS_SECRET`: a console without it cannot sign anyone in.
    let Some((signer, secret)) = signer(env) else {
        return page(503, &notice_page("Console not configured", SIGNER_COPY, None));
    };
    let previous = read(env, "HARNESS_SECRET_PREVIOUS");
    let Some(keys) = signin::Keys::new(&signer, &secret, previous.as_deref()) else {
        return page(503, &notice_page("Console not configured", SIGNER_COPY, None));
    };
    let url = req.url()?;
    let origin = url.origin().ascii_serialization();
    let now = WorkersClock.now().unix_timestamp();
    let cookies = req.headers().get("cookie").ok().flatten();
    let verifier = console_auth(&issuer, &client_id);
    let answer = if matches!(step, Step::Login) {
        let next = url.query_pairs().find(|(name, _)| name == "next").map(|(_, v)| v.into_owned());
        signin::login(
            &client,
            &allowlist,
            &origin,
            next.as_deref(),
            cookies.as_deref(),
            &keys,
            &FetchClient,
            &verifier,
            now,
        )
        .await
    } else {
        signin::finish(
            &client,
            &allowlist,
            &origin,
            url.query(),
            cookies.as_deref(),
            &keys,
            &FetchClient,
            &verifier,
            now,
        )
        .await
    };
    reply(&answer)
}

/// The harness signer over `HARNESS_SECRET` (+ `HARNESS_SECRET_PREVIOUS`),
/// and the secret itself for the refresh cookie's sealer.
fn signer(env: &Env) -> Option<(HmacSigner, String)> {
    let secret = read(env, "HARNESS_SECRET")?;
    let signer = HmacSigner::new(secret.clone(), read(env, "HARNESS_SECRET_PREVIOUS")).ok()?;
    Some((signer.with_clock(Arc::new(WorkersClock)), secret))
}

/// A [`Reply`] as a response: a redirect, or a notice page with the
/// console's security headers; `Set-Cookie` either way.
fn reply(answer: &Reply) -> worker::Result<Response> {
    let response = match (&answer.location, &answer.notice) {
        (Some(location), _) => {
            let headers = Headers::new();
            headers.set("location", location)?;
            headers.set("cache-control", "private, no-store")?;
            headers.set("referrer-policy", REFERRER_POLICY)?;
            Response::empty()?.with_status(answer.status).with_headers(headers)
        }
        (None, Some(notice)) => page(
            answer.status,
            &notice_page(
                &notice.title,
                &notice.message,
                notice.link.as_ref().map(|(href, text)| (href.as_str(), text.as_str())),
            ),
        )?,
        (None, None) => Response::empty()?.with_status(answer.status),
    };
    with_cookies(response, &answer.set_cookies)
}

/// Who is asking, and the cookies to set on the way out.
struct Session {
    set_cookies: Vec<String>,
}

/// The one gate every signed-in console page and write goes through: the
/// configuration (503 when unset), who (a bearer token, else the console
/// cookie, renewed from the refresh cookie when lapsed: 401 otherwise), and
/// whether that person is on the allowlist (403). The `Err` is the finished
/// answer to send instead.
async fn authorize(req: &Request, env: &Env) -> Result<Session, worker::Result<Response>> {
    let (Some(issuer), Some(client_id), Some(allowlist)) =
        (read(env, "AUTH_ISSUER"), read(env, "AUTH_CLIENT_ID"), read(env, "CONSOLE_EMAILS"))
    else {
        return Err(page(503, &notice_page("Console not configured", CONFIGURED_COPY, None)));
    };

    // Who: a bearer token in the header, else the console cookie; a
    // cookie session that has lapsed is renewed from the refresh cookie
    // before the 401 (a bearer header is the caller's own business).
    let headers = req.headers();
    let bearer = bearer_token(headers.get("authorization").ok().flatten().as_deref());
    let cookie_header = headers.get("cookie").ok().flatten();
    let from_cookie = bearer.is_none();
    let token = bearer.or_else(|| cookie_value(cookie_header.as_deref(), COOKIE));
    let here = req.path();
    let verifier = console_auth(&issuer, &client_id);
    let verified = match token {
        Some(token) => match verifier.verify(&token).await {
            Ok(claims) => Some(claims),
            Err(error) => {
                tracing::warn!(%error, "console: token rejected");
                None
            }
        },
        None => None,
    };
    let (claims, set_cookies) = match verified {
        Some(claims) => (claims, Vec::new()),
        None if from_cookie => {
            match renew(env, &issuer, &client_id, cookie_header.as_deref(), &verifier).await {
                signin::Refresh::Renewed { claims, set_cookies } => (claims, set_cookies),
                signin::Refresh::SignedOut { set_cookies } => {
                    return Err(unauthorized(&here)
                        .and_then(|response| with_cookies(response, &set_cookies)));
                }
                signin::Refresh::Unavailable => return Err(unauthorized(&here)),
            }
        }
        None => return Err(unauthorized(&here)),
    };
    if !signin::allowed(&claims, &allowlist) {
        return Err(page(403, &notice_page("Not allowed", FORBIDDEN_COPY, None)));
    }
    Ok(Session { set_cookies })
}

async fn serve(req: &mut Request, env: &Env, route: Route) -> worker::Result<Response> {
    let rollback_post = matches!(route, Route::Rollback(_)) && matches!(req.method(), Method::Post);
    if !rollback_post && !matches!(req.method(), Method::Get | Method::Head) {
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
    let session = match authorize(req, env).await {
        Ok(session) => session,
        Err(answer) => return answer,
    };
    with_cookies(fleet_page(req, env, route).await?, &session.set_cookies)
}

/// The connect page (GET), the paste (POST), disconnect and refresh (POST).
/// Every one is behind [`authorize`]; the methods are checked first.
async fn serve_action(req: &mut Request, env: &Env, action: Action) -> worker::Result<Response> {
    let post = matches!(req.method(), Method::Post);
    let read_only = matches!(req.method(), Method::Get | Method::Head);
    let allowed = match action {
        Action::Connect => post || read_only,
        Action::Disconnect | Action::Refresh | Action::ConnectDeploy | Action::DisconnectDeploy => {
            post
        }
    };
    if !allowed {
        let allow = match action {
            Action::Connect => "GET, HEAD, POST",
            Action::Disconnect
            | Action::Refresh
            | Action::ConnectDeploy
            | Action::DisconnectDeploy => "POST",
        };
        return page_with(
            405,
            &notice_page(
                "Method not allowed",
                "This page answers the methods its form uses.",
                None,
            ),
            &[("allow", allow)],
        );
    }
    let session = match authorize(req, env).await {
        Ok(session) => session,
        Err(answer) => return answer,
    };
    let response = match action {
        Action::Connect if post => connect_save(req, env, false).await?,
        Action::Connect => connect_form(env).await?,
        Action::Disconnect => disconnect(env).await?,
        Action::Refresh => refresh(env).await?,
        Action::ConnectDeploy => connect_save(req, env, true).await?,
        Action::DisconnectDeploy => disconnect_deploy(env).await?,
    };
    with_cookies(response, &session.set_cookies)
}

/// Mirrors the secret's absence: the Cloudflare token is sealed with it, so
/// nothing can be stored without it.
const SEALER_COPY: &str = "This deployment has no HARNESS_SECRET, which seals the stored Cloudflare \
     token, so nothing can be connected. Set it (see the README) and deploy again.";

async fn connect_form(env: &Env) -> worker::Result<Response> {
    let Some(secret) = read(env, "HARNESS_SECRET") else {
        return page(503, &notice_page("Console not configured", SEALER_COPY, None));
    };
    match api::connected_at(env, &secret).await {
        Ok(connected) => {
            let accounts = match connected {
                Some(_) => api::visible_accounts(env, &secret).await,
                None => Vec::new(),
            };
            let deploy = api::deploy_connected_at(env, &secret).await.ok().flatten();
            page(
                200,
                &connect_page(
                    connected.as_deref(),
                    &accounts,
                    deploy.as_deref(),
                    None,
                    &api::now(),
                ),
            )
        }
        Err(failed) => page(
            failed.status,
            &notice_page("Could not check the connection", failed.message, None),
        ),
    }
}

/// The paste: the token is read from the form body, sent to Cloudflare to
/// verify, sealed and stored. Nothing in the answer carries it; a refusal is
/// shown in words and the form is not kept.
/// `deploy` picks the deploy token (rollbacks) over the read-only one.
async fn connect_save(req: &mut Request, env: &Env, deploy: bool) -> worker::Result<Response> {
    let Some(secret) = read(env, "HARNESS_SECRET") else {
        return page(503, &notice_page("Console not configured", SEALER_COPY, None));
    };
    let body = req.text().await?;
    if body.len() > 4096 {
        return page(
            413,
            &notice_page(
                "Token not saved",
                "The form is larger than a token can be.",
                Some((CONNECT_PATH, "Back to the connect page")),
            ),
        );
    }
    let token = form_urlencoded::parse(body.as_bytes())
        .find(|(name, _)| name == "token")
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_default();
    if token.is_empty() {
        return page(
            400,
            &notice_page(
                "Token not saved",
                "Paste the token into the box first.",
                Some((CONNECT_PATH, "Back to the connect page")),
            ),
        );
    }
    let saved = if deploy {
        api::connect_deploy(env, &secret, &token).await
    } else {
        api::connect(env, &secret, &token).await
    };
    match saved {
        Ok(()) if deploy => redirect(303, CONNECT_PATH),
        Ok(()) => redirect(303, "/console/fleet"),
        Err(failed) => page(
            failed.status,
            &notice_page(
                "Token not saved",
                failed.message,
                Some((CONNECT_PATH, "Back to the connect page")),
            ),
        ),
    }
}

async fn disconnect(env: &Env) -> worker::Result<Response> {
    match api::disconnect(env).await {
        Ok(()) => redirect(303, CONNECT_PATH),
        Err(failed) => page(
            failed.status,
            &notice_page(
                "Could not disconnect",
                failed.message,
                Some((CONNECT_PATH, "Back to the connect page")),
            ),
        ),
    }
}

async fn disconnect_deploy(env: &Env) -> worker::Result<Response> {
    match api::disconnect_deploy(env).await {
        Ok(()) => redirect(303, CONNECT_PATH),
        Err(failed) => page(
            failed.status,
            &notice_page(
                "Could not remove the deploy token",
                failed.message,
                Some((CONNECT_PATH, "Back to the connect page")),
            ),
        ),
    }
}

async fn refresh(env: &Env) -> worker::Result<Response> {
    let Some(secret) = read(env, "HARNESS_SECRET") else {
        return page(503, &notice_page("Console not configured", SEALER_COPY, None));
    };
    match api::refresh(env, &secret).await {
        Ok(_) => redirect(303, "/console/fleet"),
        Err(failed) if failed == NOT_CONNECTED => redirect(303, CONNECT_PATH),
        Err(failed) => page(
            failed.status,
            &notice_page("Refresh failed", failed.message, Some(("/console/fleet", "All sites"))),
        ),
    }
}

/// A 303 to `location`, with the console's no-store and referrer headers.
fn redirect(status: u16, location: &str) -> worker::Result<Response> {
    let headers = Headers::new();
    headers.set("location", location)?;
    headers.set("cache-control", "private, no-store")?;
    headers.set("referrer-policy", REFERRER_POLICY)?;
    Ok(Response::empty()?.with_status(status).with_headers(headers))
}

/// A server-side refresh from the `ks_console_refresh` cookie, or signed
/// out when the deployment has no `HARNESS_SECRET` to open it with.
async fn renew(
    env: &Env,
    issuer: &str,
    client_id: &str,
    cookie_header: Option<&str>,
    verifier: &AuthClient,
) -> signin::Refresh {
    let Some((signer, secret)) = signer(env) else {
        return signin::Refresh::Unavailable;
    };
    let previous = read(env, "HARNESS_SECRET_PREVIOUS");
    let Some(keys) = signin::Keys::new(&signer, &secret, previous.as_deref()) else {
        return signin::Refresh::Unavailable;
    };
    let client_secret = read(env, "AUTH_CLIENT_SECRET");
    let client = Client { issuer, client_id, client_secret: client_secret.as_deref() };
    let now = WorkersClock.now().unix_timestamp();
    signin::refresh(&client, cookie_header, &keys, &FetchClient, verifier, now).await
}

/// `Set-Cookie` headers appended to a finished response.
fn with_cookies(mut response: Response, cookies: &[String]) -> worker::Result<Response> {
    for cookie in cookies {
        response.headers_mut().append("set-cookie", cookie)?;
    }
    Ok(response)
}

/// The fleet itself, for a caller already let in.
async fn fleet_page(req: &mut Request, env: &Env, route: Route) -> worker::Result<Response> {
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
            // Connected: offer a refresh. Not connected: point at the connect page.
            let connected = match read(env, "HARNESS_SECRET") {
                Some(secret) => api::connected_at(env, &secret).await.ok().flatten().is_some(),
                None => false,
            };
            return page(200, &empty_snapshot_page(connected));
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
        Route::Index => page(200, &render_index(&snapshot, &api::now())),
        Route::Site(id) => {
            let Some(site) = snapshot.sites.iter().find(|site| site.id == id) else {
                return no_such_site();
            };
            let now = api::now();
            let panel = match read(env, "HARNESS_SECRET") {
                Some(secret) => api::rollback_panel(env, &secret, site).await,
                None => Panel::NotSupported,
            };
            let rolled = query_value(req, "rolled_back").is_some();
            let top = if rolled { ROLLED_BACK } else { "" };
            let panel = rollback::panel_html(site, &panel, &now);
            match render_site_with(&snapshot, &id, &now, top, &panel) {
                Some(html) => page(200, &html),
                None => no_such_site(),
            }
        }
        Route::Rollback(id) => {
            let Some(site) = snapshot.sites.iter().find(|site| site.id == id).cloned() else {
                return no_such_site();
            };
            let Some(secret) = read(env, "HARNESS_SECRET") else {
                return page(503, &notice_page("Console not configured", SEALER_COPY, None));
            };
            let site_path = format!("/console/fleet/{}", super::site_path_segment(&site.id));
            let back = Some((site_path.as_str(), "Back to the site"));
            if matches!(req.method(), Method::Post) {
                let body = req.text().await?;
                let to = form_urlencoded::parse(body.as_bytes())
                    .find(|(name, _)| name == "to")
                    .map(|(_, value)| value.into_owned())
                    .unwrap_or_default();
                return match api::roll_back(env, &secret, &site, &to).await {
                    Ok(()) => redirect(303, &format!("{site_path}?rolled_back=1")),
                    Err(failed) => {
                        page(failed.status, &notice_page("Not rolled back", failed.message, back))
                    }
                };
            }
            let to = query_value(req, "to").unwrap_or_default();
            match api::rollback_choice(env, &secret, &site, &to).await {
                Ok((chosen, live)) => {
                    page(200, &rollback::confirm_page(&site, &chosen, live.as_ref(), &api::now()))
                }
                Err(failed) => {
                    page(failed.status, &notice_page("Cannot roll back", failed.message, back))
                }
            }
        }
    }
}

/// Shown above a site's tiles after a rollback.
const ROLLED_BACK: &str = "<p class=\"callout info\" role=\"status\"><strong>Rolled back.</strong> \
     Cloudflare is serving the deployment you chose. The list of sites catches up on its next \
     refresh.</p>\n";

fn no_such_site() -> worker::Result<Response> {
    page(
        404,
        &notice_page(
            "No such site",
            "The snapshot has no site with that id.",
            Some(("/console/fleet", "All sites")),
        ),
    )
}

/// One query parameter of the request URL.
fn query_value(req: &Request, name: &str) -> Option<String> {
    let url = req.url().ok()?;
    url.query_pairs().find(|(key, _)| key == name).map(|(_, value)| value.into_owned())
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
    headers.set("referrer-policy", REFERRER_POLICY)?;
    headers.set("x-content-type-options", "nosniff")?;
    for (name, value) in extra {
        headers.set(name, value)?;
    }
    Ok(Response::from_html(html)?.with_status(status).with_headers(headers))
}

/// A 401 that tells the client the scheme it should have used, and gives a
/// person the console's own sign-in, coming straight back to `here`.
fn unauthorized(here: &str) -> worker::Result<Response> {
    let href = signin::login_href(here);
    page_with(
        401,
        &notice_page("Sign in required", SIGN_IN_COPY, Some((&href, "Sign in"))),
        &[("www-authenticate", "Bearer")],
    )
}

const COOKIE: &str = "ks_console";
const CONFIGURED_COPY: &str = "This deployment is missing AUTH_ISSUER, AUTH_CLIENT_ID or \
     CONSOLE_EMAILS, so the console is switched off. Set them (see the README) and deploy again.";
const SIGN_IN_COPY: &str = "Your console session is missing or has expired. Sign in to continue.";
const SIGNER_COPY: &str = "This deployment has no HARNESS_SECRET, which signs the sign-in \
     attempt, so nobody can sign in. Set it (see the README) and deploy again.";
const FORBIDDEN_COPY: &str = "Your account is not on this console's allowlist (CONSOLE_EMAILS). \
     Ask an operator to add it.";
const BROKEN_COPY: &str = "The fleet snapshot in storage is not the shape this page expects. The \
     nightly check may still be writing it; if this persists, the pipeline is writing a bad \
     snapshot.";
const READ_COPY: &str = "The fleet could not be read right now. Try again shortly; if it \
     persists, the worker that serves this view cannot reach its storage.";

#[cfg(test)]
mod tests {
    use super::{Action, action_for};
    use crate::fleet::{Route, empty_snapshot_page, route};

    #[test]
    fn the_write_routes_are_matched_exactly_trailing_slash_tolerant() {
        assert!(matches!(action_for("/console/connect/cloudflare"), Some(Action::Connect)));
        assert!(matches!(action_for("/console/connect/cloudflare/"), Some(Action::Connect)));
        assert!(matches!(
            action_for("/console/connect/cloudflare/disconnect"),
            Some(Action::Disconnect)
        ));
        assert!(matches!(action_for("/console/fleet/refresh"), Some(Action::Refresh)));
        // Look-alikes fall through to the harness or the fleet routes.
        assert!(action_for("/console/connect/cloudflarex").is_none());
        assert!(action_for("/console/connect/cloudflare/x/disconnect").is_none());
        assert!(action_for("/console/fleet/refresh/extra").is_none());
    }

    #[test]
    fn refresh_is_claimed_before_the_fleet_route_can_read_it_as_a_site() {
        // `route` would call this a site named "refresh"; `handle` checks
        // `action_for` first, so the POST never reaches the site lookup.
        assert_eq!(route("/console/fleet/refresh"), Some(Route::Site("refresh".into())));
        assert!(matches!(action_for("/console/fleet/refresh"), Some(Action::Refresh)));
    }

    #[test]
    fn the_empty_state_points_at_connect_or_offers_refresh() {
        // The nav bar links the connect page on every page; the body is
        // what differs.
        let main = |page: String| page.split("<main").nth(1).unwrap_or_default().to_owned();
        let disconnected = main(empty_snapshot_page(false));
        assert!(disconnected.contains("href=\"/console/connect/cloudflare\""));
        assert!(!disconnected.contains("action=\"/console/fleet/refresh\""));
        let connected = main(empty_snapshot_page(true));
        assert!(connected.contains("action=\"/console/fleet/refresh\""));
        assert!(!connected.contains("href=\"/console/connect/cloudflare\""));
    }
}
