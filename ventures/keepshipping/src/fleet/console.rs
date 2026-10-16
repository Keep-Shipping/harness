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
    Filter, Fleet, Route, bearer_token, cookie_value, empty_snapshot_page, notice_page,
    render_index, render_site_with, route,
};
use crate::cloudflare::api::{self, NOT_CONNECTED};
use crate::cloudflare::page::{
    CONNECT_PATH, DEPLOY_CONNECT_PATH, DEPLOY_DISCONNECT_PATH, DISCONNECT_PATH, KEYS_REWRAP_PATH,
    connect_page,
};
use crate::cloudflare::rollback;
use crate::github::app as github_app;
use crate::github::page::{
    CONNECT_PATH as GITHUB_CONNECT_PATH, DISCONNECT_PATH as GITHUB_DISCONNECT_PATH,
    Notice as GitHubNotice, State as GitHubState, connect_page_noticed as github_connect_noticed,
    handoff_page, safe_next,
};
use crate::github::{self, webhook};
use crate::onboard::flow::{self, Reply as WizardReply};
use crate::secrets;
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
    // GitHub posts here with its own signature and no session, so the webhook
    // is answered before the sign-in gate that every other write passes.
    if path.trim_end_matches('/') == github_app::WEBHOOK_PATH {
        return Some(github_webhook(req, env).await);
    }
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
    /// `GET` shows the GitHub connection page, `POST` stores a pasted token.
    GitHub,
    GitHubDisconnect,
    /// `POST` stores the manifest's `state` and shows the hand-off to GitHub.
    GitHubAppNew,
    /// `GET`: GitHub has created the app; the code is exchanged here.
    GitHubAppCreated,
    /// `GET`: the app was installed; the installation is verified here.
    GitHubAppInstalled,
    /// `POST` forgets the app and its secrets in the console (not on GitHub).
    GitHubAppRemove,
    /// `POST` re-wraps the stored data keys under the current master key.
    RewrapKeys,
}

fn action_for(path: &str) -> Option<Action> {
    match path.trim_end_matches('/') {
        CONNECT_PATH => Some(Action::Connect),
        DISCONNECT_PATH => Some(Action::Disconnect),
        REFRESH_PATH => Some(Action::Refresh),
        DEPLOY_CONNECT_PATH => Some(Action::ConnectDeploy),
        DEPLOY_DISCONNECT_PATH => Some(Action::DisconnectDeploy),
        GITHUB_CONNECT_PATH => Some(Action::GitHub),
        GITHUB_DISCONNECT_PATH => Some(Action::GitHubDisconnect),
        github_app::CREATE_PATH => Some(Action::GitHubAppNew),
        github_app::CREATED_PATH => Some(Action::GitHubAppCreated),
        github_app::INSTALLED_PATH => Some(Action::GitHubAppInstalled),
        github_app::REMOVE_PATH => Some(Action::GitHubAppRemove),
        KEYS_REWRAP_PATH => Some(Action::RewrapKeys),
        _ => None,
    }
}

/// The hourly cron's snapshot refresh (issue #169). Runs after the venture's
/// own sweeps and never panics: a missing token is quiet, a failure is a
/// logged warning, and the previous snapshot stays in place.
pub async fn scheduled_refresh(env: &Env) {
    let legacy = read(env, "HARNESS_SECRET");
    match api::refresh(env, legacy.as_deref()).await {
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
    /// The signed-in person's email, as the token says it (empty when none).
    email: String,
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
    Ok(Session { set_cookies, email: claims.email.clone().unwrap_or_default() })
}

async fn serve(req: &mut Request, env: &Env, route: Route) -> worker::Result<Response> {
    // The rollback confirmation and the onboarding wizard take POSTs; every
    // other console page is read-only.
    let form_post = matches!(route, Route::Rollback(_) | Route::Code(_))
        && matches!(req.method(), Method::Post);
    if !form_post && !matches!(req.method(), Method::Get | Method::Head) {
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
    with_cookies(fleet_page(req, env, route, &session.email).await?, &session.set_cookies)
}

/// Whether an action answers a request, given whether it is a `POST` and
/// whether it is a `GET` or `HEAD`. Every other action is `POST` only.
fn method_allowed(action: Action, post: bool, read_only: bool) -> bool {
    match action {
        Action::Connect | Action::GitHub => post || read_only,
        Action::GitHubAppCreated | Action::GitHubAppInstalled => read_only,
        _ => post,
    }
}

/// The `Allow` header for an action's refusal: the methods it answers.
fn allowed_methods(action: Action) -> &'static str {
    match action {
        Action::Connect | Action::GitHub => "GET, HEAD, POST",
        Action::GitHubAppCreated | Action::GitHubAppInstalled => "GET, HEAD",
        _ => "POST",
    }
}

/// The connect page (GET), the paste (POST), disconnect and refresh (POST).
/// Every one is behind [`authorize`]; the methods are checked first.
async fn serve_action(req: &mut Request, env: &Env, action: Action) -> worker::Result<Response> {
    let post = matches!(req.method(), Method::Post);
    let read_only = matches!(req.method(), Method::Get | Method::Head);
    if !method_allowed(action, post, read_only) {
        let allow = allowed_methods(action);
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
        Action::GitHub if post => github_save(req, env).await?,
        Action::GitHub => github_form(req, env).await?,
        Action::GitHubDisconnect => github_disconnect(env).await?,
        Action::GitHubAppNew => github_app_new(req, env, &session.email).await?,
        Action::GitHubAppCreated => github_app_created(req, env, &session.email).await?,
        Action::GitHubAppInstalled => github_app_installed(req, env).await?,
        Action::GitHubAppRemove => github_app_remove(env).await?,
        Action::RewrapKeys => rewrap_keys(env).await?,
    };
    with_cookies(response, &session.set_cookies)
}

async fn connect_form(env: &Env) -> worker::Result<Response> {
    // The old HARNESS_SECRET is read only to move a token sealed under it
    // into the vault; a deployment without it still connects.
    let legacy = read(env, "HARNESS_SECRET");
    match api::connected_at(env, legacy.as_deref()).await {
        Ok(connected) => {
            let accounts = match connected {
                Some(_) => api::visible_accounts(env, legacy.as_deref()).await,
                None => Vec::new(),
            };
            let deploy = api::deploy_connected_at(env, legacy.as_deref()).await.ok().flatten();
            let key = secrets::current_key_version(env).await;
            page(
                200,
                &connect_page(
                    connected.as_deref(),
                    &accounts,
                    deploy.as_deref(),
                    None,
                    key,
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
/// verify, stored in the secrets vault and kept there. Nothing in the answer
/// carries it; a refusal is
/// shown in words and the form is not kept.
/// `deploy` picks the deploy token (rollbacks) over the read-only one.
async fn connect_save(req: &mut Request, env: &Env, deploy: bool) -> worker::Result<Response> {
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
        api::connect_deploy(env, &token).await
    } else {
        api::connect(env, &token).await
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

/// The GitHub connection page: the app, its installations, and the personal
/// token fallback. A `next` query names where a successful token paste
/// returns the person.
async fn github_form(req: &Request, env: &Env) -> worker::Result<Response> {
    let next = query_value(req, "next");
    // The removal's notice: the link is taken only when it passes the check.
    let removed = query_value(req, "notice").as_deref() == Some("removed");
    let advanced =
        query_value(req, "advanced").and_then(|raw| github_app::checked_advanced_url(&raw));
    let notice = if removed {
        GitHubNotice::Removed { advanced: advanced.as_deref() }
    } else {
        GitHubNotice::None
    };
    github_page_noticed(env, None, next.as_deref().and_then(safe_next), notice).await
}

/// The GitHub connection page, rendered from what is stored. `app_error` is a
/// plain-words refusal from the app's create form.
async fn github_page(
    env: &Env,
    app_error: Option<&str>,
    next: Option<&str>,
) -> worker::Result<Response> {
    github_page_noticed(env, app_error, next, GitHubNotice::None).await
}

/// [`github_page`], with the notice a redirect carried.
async fn github_page_noticed(
    env: &Env,
    app_error: Option<&str>,
    next: Option<&str>,
    notice: GitHubNotice<'_>,
) -> worker::Result<Response> {
    let db = match secrets::d1(env) {
        Ok(db) => db,
        Err(_) => {
            return page(
                503,
                &notice_page("Could not check the connection", secrets::NO_MASTER_KEY_COPY, None),
            );
        }
    };
    let overview = match github_app::overview(db).await {
        Ok(overview) => overview,
        Err(failed) => {
            return page(
                failed.status,
                &notice_page("Could not check the connection", failed.message, None),
            );
        }
    };
    let legacy = read(env, "HARNESS_SECRET");
    let saved = match github::connected_at(env, legacy.as_deref()).await {
        Ok(saved) => saved,
        Err(failed) => {
            return page(
                failed.status,
                &notice_page("Could not check the connection", failed.message, None),
            );
        }
    };
    let token = match saved {
        Some(saved) => {
            let login = match github::client(env, legacy.as_deref()).await {
                Ok(Some(client)) => client.whoami().await.ok(),
                _ => None,
            };
            Some((login, saved))
        }
        None => None,
    };
    let token_state = match &token {
        Some((login, saved)) => {
            GitHubState::Connected { login: login.as_deref(), saved: saved.as_str() }
        }
        None => GitHubState::Disconnected,
    };
    page(
        200,
        &github_connect_noticed(&overview, app_error, token_state, None, next, notice, &api::now()),
    )
}

/// The app's create form: the organisation and the name, checked, then a
/// `state` stored and a page that hands the browser to GitHub with the
/// manifest.
async fn github_app_new(req: &mut Request, env: &Env, email: &str) -> worker::Result<Response> {
    if email.trim().is_empty() {
        return github_page(
            env,
            Some(
                "Your sign-in has no email on it, so the app cannot be tied to you. Sign in again.",
            ),
            None,
        )
        .await;
    }
    let body = req.text().await?;
    if body.len() > 4096 {
        return github_page(env, Some("The form is larger than it should be."), None).await;
    }
    let field = |name: &str| {
        form_urlencoded::parse(body.as_bytes())
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default()
    };
    let org = match github_app::owner_of(&field("org")) {
        Ok(org) => org,
        Err(message) => return github_page(env, Some(message), None).await,
    };
    let name = match github_app::name_of(org.as_deref(), &field("name")) {
        Ok(name) => name,
        Err(message) => return github_page(env, Some(message), None).await,
    };
    let db = match secrets::d1(env) {
        Ok(db) => db,
        Err(_) => return github_page(env, Some(secrets::NO_MASTER_KEY_COPY), None).await,
    };
    let now = WorkersClock.now().unix_timestamp();
    let subject = github_app::subject_of(email);
    let state = match github_app::issue_state(db, now, &subject).await {
        Ok(state) => state,
        Err(failed) => return github_page(env, Some(failed.message), None).await,
    };
    let manifest = github_app::manifest(&name).to_string();
    let target = github_app::create_target(org.as_deref(), &state);
    page(200, &handoff_page(&name, org.as_deref(), &manifest, &target))
}

/// The redirect after a removal: the connection page with the notice, and
/// GitHub's settings link for the app when it was checked.
fn removed_location(advanced: Option<&str>) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    query.append_pair("notice", "removed");
    if let Some(url) = advanced {
        query.append_pair("advanced", url);
    }
    format!("{GITHUB_CONNECT_PATH}?{}", query.finish())
}

/// Removes the GitHub App from the console: its three secrets are forgotten
/// first, then the installations and the app row, then this isolate's cached
/// tokens. The app itself stays on GitHub, which the notice says. A failure
/// part-way is safe to retry: each step is a plain delete. Behind the same
/// authorisation and origin checks as the other writes here.
async fn github_app_remove(env: &Env) -> worker::Result<Response> {
    let back = Some((GITHUB_CONNECT_PATH, "Back to the GitHub connection"));
    let failed_copy = "The app could not be removed right now. Try again in a moment.";
    let db = match secrets::d1(env) {
        Ok(db) => db,
        Err(_) => {
            return page(
                503,
                &notice_page("Could not remove the app", secrets::NO_MASTER_KEY_COPY, back),
            );
        }
    };
    // The page address is read before the row goes, for the link.
    let advanced = match github_app::app_row(db.clone()).await {
        Ok(Some(app)) => match github_app::owner_is_org(&app.owner).await {
            Some(is_org) => github_app::advanced_url_for(&app.slug, &app.owner, is_org),
            None => None,
        },
        Ok(None) => None,
        Err(failed) => {
            return page(
                failed.status,
                &notice_page("Could not remove the app", failed.message, back),
            );
        }
    };
    for name in github_app::SECRET_NAMES {
        if secrets::forget(env, name, &secrets::unsealed()).await.is_err() {
            return page(503, &notice_page("Could not remove the app", failed_copy, back));
        }
    }
    if github_app::remove_app(db).await.is_err() {
        return page(503, &notice_page("Could not remove the app", failed_copy, back));
    }
    github_app::forget_cached();
    redirect(303, &removed_location(advanced.as_deref()))
}

/// GitHub's redirect after it created the app: the `state` is checked (once,
/// in time), the code is exchanged and the app recorded. The person is then
/// sent to install it.
async fn github_app_created(req: &Request, env: &Env, email: &str) -> worker::Result<Response> {
    let back = Some((GITHUB_CONNECT_PATH, "Back to the GitHub connection"));
    let (Some(code), Some(state)) = (query_value(req, "code"), query_value(req, "state")) else {
        return page(
            400,
            &notice_page(
                "GitHub App not created",
                "GitHub's link did not carry the details this console needs. Start again from \
                 the GitHub connection page.",
                back,
            ),
        );
    };
    let now = WorkersClock.now().unix_timestamp();
    let db = match secrets::d1(env) {
        Ok(db) => db,
        Err(_) => return github_page(env, Some(secrets::NO_MASTER_KEY_COPY), None).await,
    };
    let subject = github_app::subject_of(email);
    match github_app::take_state(db.clone(), &state, now, &subject).await {
        Ok(true) => {}
        Ok(false) => {
            return page(
                400,
                &notice_page("GitHub App not created", github_app::STATE_REFUSED_COPY, back),
            );
        }
        Err(failed) => {
            return page(
                failed.status,
                &notice_page("GitHub App not created", failed.message, back),
            );
        }
    }
    match github_app::create_from_code(env, db, &FetchClient, &code, now).await {
        Ok(app) => redirect(303, &github_app::install_url(&app.slug)),
        Err(failed) => {
            page(failed.status, &notice_page("GitHub App not created", failed.message, back))
        }
    }
}

/// GitHub's redirect after an installation: the installation is verified with
/// the app's own JWT (it must be this app's), recorded, and the person goes
/// back to the connection page.
async fn github_app_installed(req: &Request, env: &Env) -> worker::Result<Response> {
    let back = Some((GITHUB_CONNECT_PATH, "Back to the GitHub connection"));
    let Some(id) = query_value(req, "installation_id").and_then(|id| id.parse::<i64>().ok()) else {
        return page(
            400,
            &notice_page(
                "Installation not recorded",
                "GitHub did not say which installation this is. Install the app again from the \
                 GitHub connection page.",
                back,
            ),
        );
    };
    let now = WorkersClock.now().unix_timestamp();
    let db = match secrets::d1(env) {
        Ok(db) => db,
        Err(_) => return github_page(env, Some(secrets::NO_MASTER_KEY_COPY), None).await,
    };
    match github_app::record_installation(db, &FetchClient, id, now).await {
        Ok(_) => redirect(303, GITHUB_CONNECT_PATH),
        Err(failed) => {
            page(failed.status, &notice_page("Installation not recorded", failed.message, back))
        }
    }
}

/// The GitHub App's webhook: the request's size and headers, then the body
/// read, then [`webhook::handle`] decides. No session: the signature is the
/// proof. Answers an empty body with the status.
async fn github_webhook(req: &mut Request, env: &Env) -> worker::Result<Response> {
    if !matches!(req.method(), Method::Post) {
        return page_with(
            405,
            &notice_page("Method not allowed", "The webhook answers POST only.", None),
            &[("allow", "POST")],
        );
    }
    let declared = req
        .headers()
        .get("content-length")
        .ok()
        .flatten()
        .and_then(|length| length.parse::<usize>().ok());
    if declared.is_some_and(|length| length > webhook::MAX_BODY) {
        return Ok(Response::empty()?.with_status(413));
    }
    let event = req.headers().get("x-github-event").ok().flatten();
    let signature = req.headers().get("x-hub-signature-256").ok().flatten();
    let body = req.bytes().await?;
    let db = match secrets::d1(env) {
        Ok(db) => db,
        Err(_) => return Ok(Response::empty()?.with_status(503)),
    };
    let now = WorkersClock.now().unix_timestamp();
    let status = webhook::handle(db, event.as_deref(), signature.as_deref(), &body, now).await;
    Ok(Response::empty()?.with_status(status))
}

/// The GitHub paste: the token is checked with GitHub, stored in the vault by
/// [`github::connect`]. A refusal is shown in words; the token is never
/// echoed back.
async fn github_save(req: &mut Request, env: &Env) -> worker::Result<Response> {
    let body = req.text().await?;
    if body.len() > 4096 {
        return page(
            413,
            &notice_page(
                "Token not saved",
                "The form is larger than a token can be.",
                Some((GITHUB_CONNECT_PATH, "Back to the GitHub connection")),
            ),
        );
    }
    let fields: Vec<(String, String)> = form_urlencoded::parse(body.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    let token = fields
        .iter()
        .find(|(name, _)| name == "token")
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_default();
    // Where to go next, when the paste came from a page that asked (the
    // wizard): same-origin console paths only.
    let next = fields
        .iter()
        .find(|(name, _)| name == "next")
        .and_then(|(_, value)| safe_next(value))
        .unwrap_or(GITHUB_CONNECT_PATH);
    if token.is_empty() {
        return page(
            400,
            &notice_page(
                "Token not saved",
                "Paste the token into the box first.",
                Some((GITHUB_CONNECT_PATH, "Back to the GitHub connection")),
            ),
        );
    }
    match github::connect(env, &token).await {
        Ok(_) => redirect(303, next),
        Err(failed) => page(
            failed.status,
            &notice_page(
                "Token not saved",
                failed.message,
                Some((GITHUB_CONNECT_PATH, "Back to the GitHub connection")),
            ),
        ),
    }
}

async fn github_disconnect(env: &Env) -> worker::Result<Response> {
    match github::disconnect(env).await {
        Ok(()) => redirect(303, GITHUB_CONNECT_PATH),
        Err(failed) => page(
            failed.status,
            &notice_page(
                "Could not disconnect",
                failed.message,
                Some((GITHUB_CONNECT_PATH, "Back to the GitHub connection")),
            ),
        ),
    }
}

/// The plain-words result of a re-wrap. Numbers and fixed copy only.
fn rewrap_copy(keys: usize, version: Option<u32>) -> String {
    let under = version.map_or_else(
        || "the current master key".to_owned(),
        |version| format!("master key version {version}"),
    );
    let tail = "The tokens themselves did not change. Once the console works, an older master \
                key version can be removed from the Secrets Store.";
    match keys {
        0 => "No stored data key needed re-encrypting: nothing is saved in the console's store \
              yet, so there was nothing to move. The tokens are unchanged."
            .to_owned(),
        1 => format!("Re-wrapped 1 stored data key under {under}. {tail}"),
        n => format!("Re-wrapped {n} stored data keys under {under}. {tail}"),
    }
}

/// Re-wraps the stored data keys under the current master key version, and
/// says in plain words what changed. Behind the same authorisation and origin
/// checks as every other write on this page.
async fn rewrap_keys(env: &Env) -> worker::Result<Response> {
    let back = Some((CONNECT_PATH, "Back to the connect page"));
    match secrets::rewrap(env).await {
        Ok(report) => page(
            200,
            &notice_page(
                "Re-encrypted with the current key",
                &rewrap_copy(report.keys, secrets::key_version_of(&report.key_ref)),
                back,
            ),
        ),
        Err(secrets::Error::NoMasterKey) => {
            page(503, &notice_page("No master key", secrets::NO_MASTER_KEY_COPY, back))
        }
        Err(secrets::Error::Storage) => page(
            503,
            &notice_page(
                "Could not re-encrypt",
                "The stored keys could not be re-encrypted right now. Try again in a moment.",
                back,
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
    let legacy = read(env, "HARNESS_SECRET");
    match api::refresh(env, legacy.as_deref()).await {
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

/// The fleet itself, for a caller already let in. `email` is the signed-in
/// person, recorded as the author of any change the wizard opens.
async fn fleet_page(
    req: &mut Request,
    env: &Env,
    route: Route,
    email: &str,
) -> worker::Result<Response> {
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
            let legacy = read(env, "HARNESS_SECRET");
            let connected =
                api::connected_at(env, legacy.as_deref()).await.ok().flatten().is_some();
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
        Route::Index => {
            let filter = Filter::from_query(
                query_value(req, "view").as_deref(),
                query_value(req, "venture").as_deref(),
            );
            page(200, &render_index(&snapshot, &api::now(), &filter))
        }
        Route::Site(id) => {
            let Some(site) = snapshot.sites.iter().find(|site| site.id == id) else {
                return no_such_site();
            };
            let now = api::now();
            let legacy = read(env, "HARNESS_SECRET");
            let panel = api::rollback_panel(env, legacy.as_deref(), site).await;
            let rolled = query_value(req, "rolled_back").is_some();
            let top = if rolled { ROLLED_BACK } else { "" };
            let panel = rollback::panel_html(site, &panel, &now);
            let onboarding = flow::site_record(env, &id).await;
            match render_site_with(&snapshot, &id, &now, top, &panel, onboarding.as_ref()) {
                Some(html) => page(200, &html),
                None => no_such_site(),
            }
        }
        Route::Code(id) => {
            let Some(site) = snapshot.sites.iter().find(|site| site.id == id).cloned() else {
                return no_such_site();
            };
            // The old HARNESS_SECRET only opens a token sealed under it; the
            // wizard reads the vault like every other page.
            let legacy = read(env, "HARNESS_SECRET");
            let reply = if matches!(req.method(), Method::Post) {
                let body = req.text().await?;
                let form: Vec<(String, String)> = form_urlencoded::parse(body.as_bytes())
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect();
                flow::post(env, legacy.as_deref(), &site, email, &form).await
            } else {
                let again = query_value(req, "again").is_some();
                flow::view(env, legacy.as_deref(), &site, again).await
            };
            match reply {
                WizardReply::Html(status, html) => page(status, &html),
                WizardReply::Redirect(location) => redirect(303, &location),
            }
        }
        Route::Rollback(id) => {
            let Some(site) = snapshot.sites.iter().find(|site| site.id == id).cloned() else {
                return no_such_site();
            };
            let legacy = read(env, "HARNESS_SECRET");
            let site_path = format!("/console/fleet/{}", super::site_path_segment(&site.id));
            let back = Some((site_path.as_str(), "Back to the site"));
            if matches!(req.method(), Method::Post) {
                let body = req.text().await?;
                let to = form_urlencoded::parse(body.as_bytes())
                    .find(|(name, _)| name == "to")
                    .map(|(_, value)| value.into_owned())
                    .unwrap_or_default();
                return match api::roll_back(env, legacy.as_deref(), &site, &to).await {
                    Ok(()) => redirect(303, &format!("{site_path}?rolled_back=1")),
                    Err(failed) => {
                        page(failed.status, &notice_page("Not rolled back", failed.message, back))
                    }
                };
            }
            let to = query_value(req, "to").unwrap_or_default();
            match api::rollback_choice(env, legacy.as_deref(), &site, &to).await {
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
    use super::{
        Action, action_for, allowed_methods, method_allowed, removed_location, rewrap_copy,
    };
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
        assert!(matches!(action_for("/console/connect/keys/rewrap"), Some(Action::RewrapKeys)));
        assert!(matches!(action_for("/console/connect/keys/rewrap/"), Some(Action::RewrapKeys)));
        assert!(action_for("/console/connect/keys/rewrap/extra").is_none());
        assert!(action_for("/console/connect/keys").is_none());
        // The result copy names only numbers and fixed text.
        assert!(rewrap_copy(0, Some(2)).contains("nothing"));
        assert!(
            rewrap_copy(1, Some(2))
                .starts_with("Re-wrapped 1 stored data key under master key version 2.")
        );
        assert!(
            rewrap_copy(3, None)
                .starts_with("Re-wrapped 3 stored data keys under the current master key.")
        );
        for keys in [0, 1, 4] {
            assert!(!rewrap_copy(keys, Some(2)).contains('<'), "no markup in the result copy");
        }
        // Look-alikes fall through to the harness or the fleet routes.
        assert!(action_for("/console/connect/cloudflarex").is_none());
        assert!(action_for("/console/connect/cloudflare/x/disconnect").is_none());
        assert!(action_for("/console/fleet/refresh/extra").is_none());
        assert!(matches!(action_for("/console/connect/github"), Some(Action::GitHub)));
        assert!(matches!(
            action_for("/console/connect/github/disconnect"),
            Some(Action::GitHubDisconnect)
        ));
        assert!(action_for("/console/connect/github/x").is_none());
        // The GitHub App's routes: the create form, and the two GitHub returns.
        assert!(matches!(
            action_for("/console/connect/github/app/new"),
            Some(Action::GitHubAppNew)
        ));
        assert!(matches!(
            action_for("/console/connect/github/app/created"),
            Some(Action::GitHubAppCreated)
        ));
        assert!(matches!(
            action_for("/console/connect/github/app/installed/"),
            Some(Action::GitHubAppInstalled)
        ));
        assert!(action_for("/console/connect/github/app/new/extra").is_none());
        assert!(matches!(
            action_for("/console/connect/github/app/remove"),
            Some(Action::GitHubAppRemove)
        ));
        assert!(matches!(
            action_for("/console/connect/github/app/remove/"),
            Some(Action::GitHubAppRemove)
        ));
        assert!(action_for("/console/connect/github/app/remove/extra").is_none());
        // The webhook is not an action: it is answered before the session gate.
        assert!(action_for("/console/github/webhook").is_none());
    }

    #[test]
    fn the_app_remove_answers_post_only() {
        // A GET (or HEAD) is refused with the Allow header naming POST.
        assert!(method_allowed(Action::GitHubAppRemove, true, false));
        assert!(!method_allowed(Action::GitHubAppRemove, false, true));
        assert_eq!(allowed_methods(Action::GitHubAppRemove), "POST");
        // Like the GitHub disconnect beside it.
        assert!(method_allowed(Action::GitHubDisconnect, true, false));
        assert!(!method_allowed(Action::GitHubDisconnect, false, true));
        // The connection page still takes GET, HEAD and POST.
        assert!(method_allowed(Action::GitHub, true, false));
        assert!(method_allowed(Action::GitHub, false, true));
        assert_eq!(allowed_methods(Action::GitHub), "GET, HEAD, POST");
        assert!(!method_allowed(Action::GitHubAppInstalled, true, false));
    }

    #[test]
    fn the_removal_redirect_names_the_notice_and_only_a_checked_link() {
        assert_eq!(removed_location(None), "/console/connect/github?notice=removed");
        let link =
            "https://github.com/organizations/keep-shipping/settings/apps/kp-console/advanced";
        let located = removed_location(Some(link));
        assert!(located.starts_with("/console/connect/github?notice=removed&advanced="));
        // The link is query-encoded: no raw `:` or `/` survives in the value.
        assert!(!located.contains("https://"), "the link is encoded in the query");
        assert!(located.contains("%3A%2F%2Fgithub.com"));
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
