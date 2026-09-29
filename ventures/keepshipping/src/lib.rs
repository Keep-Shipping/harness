//! Keep Shipping's early-access waitlist — the first hosted venture in this
//! repository ([#146](https://github.com/Keep-Shipping/harness/issues/146)),
//! and the proof that the harness idea holds: every line below is
//! composition, not protocol. The request handling, the double opt-in mail,
//! the captcha gate, the per-IP rate limiter and the admin export all come
//! from published `cratefield` crates; what this crate owns is the
//! business judgement — the venture's name and domain, the product code,
//! the origins writes may come from, and the mail sender.
//!
//! The shape mirrors `ventures/cratefield-waitlist` in the upstream
//! harness repository: a `fetch` entry point that runs the origin guard and
//! then hands the request to the runtime's `serve`, plus a `scheduled`
//! entry point for the module's sweeps. Adapters are assembled per
//! environment — a Workers `Env` only exists per event, so the whole
//! harness is frozen into a `OnceLock` on the first invocation of an
//! isolate. That is not ambient mutable state: nothing in it ever changes
//! after the first call, which the `Arc<(Harness, Cloudflare)>` return type
//! makes plain.
//!
//! Configuration lives in `wrangler.toml` next to this file; the secrets
//! (`RESEND_API_KEY`, `TURNSTILE_SECRET`) are set with
//! `wrangler secret put`. Both adapters are deliberately wired so that a
//! missing secret degrades safely rather than dangerously:
//!
//! * without `TURNSTILE_SECRET` no captcha port exists at all, and the
//!   harness refuses joins in `ENV=production` (fail-closed — see the
//!   module's `verify_human_form`);
//! * without `RESEND_API_KEY` the Resend adapter reports
//!   [`SendOutcome::NotConfigured`](cratefield_core::SendOutcome::NotConfigured),
//!   and the join still succeeds: the entry is captured as `pending` with
//!   no mail sent, so the form keeps working while the sending subdomain
//!   (issue #146's open question) is being verified.

#![forbid(unsafe_code)]

mod origin;

pub use origin::{SITE_ORIGINS, write_origin_rejected};

use std::sync::{Arc, OnceLock};

use cratefield_adapter_resend::Resend;
use cratefield_adapter_turnstile::Turnstile;
use cratefield_core::{Harness, Mailer, Venture};
use cratefield_module_waitlist::Waitlist;
use cratefield_runtime_cloudflare::{
    Cloudflare, FetchClient, WorkersClock, serve, serve_scheduled,
};
use worker::{Context, Env, Request, Response, event};

/// The envelope the confirm links are sent from. `send.` is the Resend
/// sending subdomain the deployment must verify (see the venture README) —
/// mail from the apex itself is exactly how cold mail looks.
const MAIL_FROM: &str = "no-reply@send.keepshipping.run";

/// Turnstile widgets are pinned to the hostname they are served from, and
/// siteverify checks the match server-side; `expected_hostname` is what
/// makes a solved token from a lookalike site useless here.
const CAPTCHA_HOSTNAME: &str = "keepshipping.run";

/// The venture: name, domain, and the origins the form is served from
/// (shared with the origin guard, so writes from anywhere else are
/// refused before the harness runs). Public so the integration tests
/// mount the same venture the worker serves.
#[must_use]
pub fn venture() -> Venture {
    Venture::new("keepshipping-waitlist", "keepshipping.run").cors_origins(SITE_ORIGINS)
}

/// The module composition — deliberately the *same* configuration the
/// integration tests in `tests/` mount, so the tests exercise what ships.
/// `referrals(false)` until the launch page is ready to explain the queue
/// mechanics; no `answers` schema yet — issue #146 defers those fields
/// until the content exists to justify them.
#[must_use]
pub fn module() -> Waitlist {
    Waitlist::new()
        .products(["keepshipping"])
        .referrals(false)
        .status_redirect("https://keepshipping.run/")
}

/// The Turnstile adapter, or `None` when `TURNSTILE_SECRET` is unset —
/// which, in `ENV=production`, makes the harness refuse joins outright.
fn captcha(env: &Env) -> Option<Turnstile> {
    let secret = env.secret("TURNSTILE_SECRET").ok()?.to_string();
    if secret.is_empty() {
        return None;
    }
    Some(
        Turnstile::new(Arc::new(FetchClient), Arc::new(WorkersClock), secret)
            .expected_hostname(CAPTCHA_HOSTNAME),
    )
}

/// The Resend adapter. A missing `RESEND_API_KEY` is not an error: the
/// adapter reports `NotConfigured`, the join is still captured as
/// `pending`, and the runtime logs the skip — see the module docs.
fn mailer(env: &Env) -> Arc<dyn Mailer> {
    let api_key = env
        .secret("RESEND_API_KEY")
        .ok()
        .map(|secret| secret.to_string())
        .filter(|key| !key.is_empty());
    Arc::new(Resend::new(Arc::new(FetchClient), Arc::new(WorkersClock), api_key, MAIL_FROM, None))
}

/// The frozen composition: built once per isolate on first use, immutable
/// after. The runtime is `Clone` for exactly this pattern — one clone goes
/// into the builder (so `build()` validates the module's required ports
/// against the adapters actually wired), the original serves.
fn instance(env: &Env) -> Arc<(Harness, Cloudflare)> {
    static INSTANCE: OnceLock<Arc<(Harness, Cloudflare)>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            let runtime = match captcha(env) {
                Some(captcha) => Cloudflare::new()
                    .db("DB")
                    .rate_limiter("RATE_LIMITER")
                    .mailer_arc(mailer(env))
                    .captcha_arc(Arc::new(captcha)),
                None => {
                    Cloudflare::new().db("DB").rate_limiter("RATE_LIMITER").mailer_arc(mailer(env))
                }
            };
            let harness = Harness::builder()
                .venture(venture())
                .module(module())
                .runtime(runtime.clone())
                .build()
                .expect("the waitlist composition is static and validated in CI");
            Arc::new((harness, runtime))
        })
        .clone()
}

/// The refused-write response: a problem+json body in the same style the
/// harness uses for its own problems.
fn origin_refused() -> worker::Result<Response> {
    Response::from_json(&serde_json::json!({
        "type": "https://keepshipping.run/problems/origin-refused",
        "title": "Missing or disallowed Origin on a write",
        "status": 403,
    }))
    .map(|response| response.with_status(403))
}

/// Every HTTP request lands here. Writes are checked against the site
/// origins before anything else runs; everything else — including browser
/// preflights, which are `OPTIONS` — goes to the harness. A header that
/// cannot even be read counts as absent, and so is refused on writes:
/// fail closed, never error open.
#[event(fetch)]
pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    let origin = req.headers().get("origin").ok().flatten();
    if write_origin_rejected(req.method().as_ref(), origin.as_deref(), &SITE_ORIGINS) {
        return origin_refused();
    }
    let (harness, runtime) = &*instance(&env);
    serve(harness, runtime, req, env, ctx).await
}

/// Cron entry: the module's sweeps (pending-entry retention runs on the
/// `retention_days_pending` clock). No schedule is wired in
/// `wrangler.toml` yet — the first sweeps matter only once mail flows.
#[event(scheduled)]
pub async fn scheduled(event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {
    // Handler errors inside `serve_scheduled` are logged, never a failed
    // cron — the module's sweeps are idempotent by construction.
    let (harness, runtime) = &*instance(&env);
    serve_scheduled(harness, runtime, event, env, ctx).await;
}
