//! Keep Shipping's early-access waitlist — the first hosted venture in this
//! repository ([#146](https://github.com/Keep-Shipping/harness/issues/146)),
//! and the proof that the harness idea holds: every line below is
//! composition, not protocol. The request handling, the double opt-in mail,
//! the captcha gate, the per-IP rate limiter and the admin export all come
//! from published `cratefield` crates; what this crate owns is the
//! business judgement — the venture's name and domain, the product code,
//! the origins writes may come from, the mail sender and the mail theme.
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
//! (`OWLPOST_API_KEY`, `RESEND_API_KEY`, `TURNSTILE_SECRET`) are set with
//! `wrangler secret put`. The adapters are deliberately wired so that a
//! missing secret degrades safely rather than dangerously:
//!
//! * `OWLPOST_API_KEY` selects the preferred Owlpost mailer; when it is
//!   unset the mailer falls back to Resend, which in turn reports
//!   [`SendOutcome::NotConfigured`](cratefield_core::SendOutcome::NotConfigured)
//!   when `RESEND_API_KEY` is unset too — the join still succeeds, the
//!   entry is captured as `pending` with no mail sent, so the form keeps
//!   working while the sending subdomain (issue #146's open question) is
//!   being verified;
//! * without `TURNSTILE_SECRET` no captcha port exists at all, and the
//!   harness refuses joins in `ENV=production` (fail-closed — see the
//!   module's `verify_human_form`);
//! * billing (issue #177, ADR 0202) runs on `POLAR_ACCESS_TOKEN` +
//!   `POLAR_WEBHOOK_SECRET` through the `cratefield-adapter-polar`
//!   adapter: with the token missing the adapter reports `not configured`
//!   and every billing route answers a `not-ready` problem — the
//!   deployment before billing is switched on, never a mis-bill;
//! * the standard setup console (issue #273) runs on `SETUP_GITHUB_REPO`
//!   and `SETUP_GITHUB_TOKEN` (with the optional `SETUP_GITHUB_BASE`):
//!   when either is missing it still serves, saves and answers status,
//!   and says on the page that connecting to GitHub is needed before the
//!   pull request can open — the change is never lost, only unfiled.
//!
//! Mail renders in the venture's own theme ([`mail_theme`], from
//! `src/mail-theme.json`), with the optional `MAIL_THEME` var or secret
//! merged over it field by field; see the venture README for the secrets.

#![forbid(unsafe_code)]

mod billing;
mod edits;
mod gsc;
mod origin;
mod setup;

pub mod signin;

pub mod fleet;

pub use billing::{Billing, DISPUTE_POLL_CRON, Plan, entitlements};
pub use edits::Edits;
pub use gsc::{
    Gsc, GscModule, SECRET_NAME as GSC_SECRET_NAME, Status as GscStatus, gsc_module,
    search_console_module,
};
pub use origin::{SITE_ORIGINS, write_origin_rejected};
pub use setup::{GitHubPullRequests, PullRequests, Setup};

use std::sync::{Arc, OnceLock};

use cratefield_adapter_owlpost::Owlpost;
use cratefield_adapter_polar::{CustomerIds, Polar};
use cratefield_adapter_resend::Resend;
use cratefield_adapter_turnstile::Turnstile;
use cratefield_core::{Harness, HarnessBuilder, Mailer, Template, Venture};
use cratefield_mail_templates::MailTheme;
use cratefield_module_waitlist::Waitlist;
use cratefield_runtime_cloudflare::{
    Cloudflare, FetchClient, WorkersClock, serve, serve_scheduled,
};
use worker::{Context, Env, Request, Response, event};

/// The envelope the confirm links are sent from. `send.` is the sending
/// subdomain the deployment must verify with its mail provider — Owlpost
/// preferred, Resend on the fallback path (see the venture README); mail
/// from the apex itself is exactly how cold mail looks.
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

/// The venture's billing module (issue #177, ADR 0202), mounted next to the
/// waitlist module: paid plans through Polar over the `Payments` port.
/// Public so the integration tests mount the same module the worker serves.
#[must_use]
pub fn billing_module() -> Billing {
    Billing
}

/// The venture's standard setup console (issue #273), mounted next to the
/// other modules. GitHub wiring is optional by design:
/// `SETUP_GITHUB_REPO` (a var, `owner/repo`) and `SETUP_GITHUB_TOKEN` (a
/// secret over the infra repo) open the pull request every change is;
/// `SETUP_GITHUB_BASE` names the branch the pull requests propose into
/// (`main` by default). With either of the required two missing the
/// console still serves, saves and answers status — it just says, on the
/// page, that connecting to GitHub is needed before the change can be
/// filed. Public so the integration tests mount the same module the
/// worker serves.
#[must_use]
pub fn setup_module(env: &Env) -> Setup {
    let read = |reader: fn(&Env, &str) -> worker::Result<String>, name: &str| {
        reader(env, name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    let repo = read(|env, name| env.var(name).map(|value| value.to_string()), "SETUP_GITHUB_REPO");
    let token =
        read(|env, name| env.secret(name).map(|value| value.to_string()), "SETUP_GITHUB_TOKEN");
    let base = read(|env, name| env.var(name).map(|value| value.to_string()), "SETUP_GITHUB_BASE")
        .unwrap_or_else(|| "main".to_owned());
    match (repo, token) {
        (Some(repo), Some(token)) => Setup::new(Some(Arc::new(GitHubPullRequests::new(
            Arc::new(FetchClient),
            repo,
            token,
            base,
        )))),
        _ => Setup::new(None),
    }
}

/// The venture's Search Console console module (issue #274), mounted next
/// to the waitlist module: live verification/sitemap reads as a Google
/// service account plus Terraform module generation — no Google API call
/// mutates anything. With `GOOGLE_SERVICE_ACCOUNT_JSON` unset the status
/// reads answer a `not-ready` page and the module generation keeps working.
fn gsc(env: &Env) -> GscModule {
    // A secret as trimmed text, blank counting as absent — the same rule
    // the mailer and the Polar token read by.
    let secret = env
        .secret(gsc::SECRET_NAME)
        .ok()
        .map(|secret| secret.to_string())
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty());
    gsc::gsc_module(gsc::Gsc::new(Arc::new(FetchClient), Arc::new(WorkersClock), secret))
}

/// The venture's edit-as-code module (issue #170): console forms whose
/// submit is a Terraform pull request in the infrastructure repository.
/// Public so the integration tests mount the same module the worker serves.
#[must_use]
pub fn edits_module() -> Edits {
    Edits
}

/// The Polar adapter the secrets select (ADR 0202): `POLAR_ACCESS_TOKEN` for
/// the Management API and `POLAR_WEBHOOK_SECRET` for webhook signatures;
/// customers are named by the venture's own account id (Polar's
/// `external_customer_id`). A missing token still builds: the adapter reports
/// `not configured` and the billing routes answer a `not-ready` problem —
/// the deployment before billing is switched on, never a panic.
fn payments(env: &Env) -> Arc<Polar> {
    // A secret as trimmed text, blank counting as absent — the same rule
    // the mailer reads by.
    let read = |name: &str| {
        env.secret(name).ok().map(|secret| secret.to_string()).map(|key| key.trim().to_owned())
    };
    Arc::new(
        Polar::new(
            Arc::new(FetchClient),
            Arc::new(WorkersClock),
            cratefield_adapter_polar::Environment::parse(read("POLAR_ENVIRONMENT").as_deref()),
            read("POLAR_ACCESS_TOKEN").unwrap_or_default(),
            read("POLAR_WEBHOOK_SECRET").unwrap_or_default(),
        )
        .with_customer_ids(CustomerIds::External),
    )
}

/// The venture's mail theme: `src/mail-theme.json`, baked into the binary
/// at compile time (the worker never reads a file at runtime). The
/// deployment's optional `MAIL_THEME` config is merged over it per mail,
/// field by field, so a colour can be adjusted without a rebuild.
///
/// # Panics
///
/// Never in practice: the `expect` can only fire if the checked-in JSON is
/// edited into something that is not a [`MailTheme`], which the round-trip
/// test pins.
#[must_use]
pub fn mail_theme() -> MailTheme {
    MailTheme::from_json(include_str!("mail-theme.json"))
        .expect("mail-theme.json is a valid MailTheme")
}

/// The waitlist mail templates rendered in the venture's [`mail_theme`],
/// for `Harness::builder().templates(..)`. The module still merges the
/// deployment's `MAIL_THEME` config over the theme at send time. Public so
/// the integration tests mount exactly the mail the worker sends.
#[must_use]
pub fn templates() -> Vec<(String, Box<dyn Template>)> {
    cratefield_module_waitlist::themed_templates(&mail_theme())
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

/// Which mail provider a deployment's secrets select. Both speak the same
/// Resend-compatible wire shape; the choice is by key *presence*, never by
/// retrying a provider that failed — a failed send must not become two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MailProvider {
    /// `OWLPOST_API_KEY` is set: Owlpost, the preferred provider.
    Owlpost,
    /// No Owlpost key: Resend, whose adapter degrades to `NotConfigured`
    /// when its own key is blank too.
    Resend,
}

/// Picks the provider: Owlpost when a non-blank `OWLPOST_API_KEY` is set,
/// Resend otherwise. Pure and natively testable, so the selection does not
/// need Workers to be exercised.
fn mail_provider(owlpost_key: Option<&str>) -> MailProvider {
    match owlpost_key {
        Some(key) if !key.trim().is_empty() => MailProvider::Owlpost,
        _ => MailProvider::Resend,
    }
}

/// The mail adapter the secrets select (see [`mail_provider`]). Neither
/// key being present is not an error: Resend reports `NotConfigured`, the
/// join is still captured as `pending`, and the runtime logs the skip —
/// see the module docs.
fn mailer(env: &Env) -> Arc<dyn Mailer> {
    // Read a secret as trimmed text, blank counting as absent: a secret
    // that mounted empty (or whitespace) is no key at all on this path,
    // matching how the adapters read it — `Bearer ` would only earn a 401.
    let read = |name: &str| {
        env.secret(name)
            .ok()
            .map(|secret| secret.to_string())
            .map(|key| key.trim().to_owned())
            .filter(|key| !key.is_empty())
    };
    let owlpost_key = read("OWLPOST_API_KEY");
    let resend_key = read("RESEND_API_KEY");
    match mail_provider(owlpost_key.as_deref()) {
        MailProvider::Owlpost => Arc::new(Owlpost::new(
            Arc::new(FetchClient),
            Arc::new(WorkersClock),
            owlpost_key,
            MAIL_FROM,
            None,
        )),
        MailProvider::Resend => Arc::new(Resend::new(
            Arc::new(FetchClient),
            Arc::new(WorkersClock),
            resend_key,
            MAIL_FROM,
            None,
        )),
    }
}

/// The composition without a runtime: venture, modules and themed
/// templates, in the order the builder validates them. Split out of
/// `instance` because the runtime is the only per-isolate leg — the
/// `Env` it reads does not exist until an event brings one — and
/// everything else is static, so a native test can build the very
/// composition the worker serves (`tests/harness.rs` does exactly that)
/// rather than a parallel one.
#[must_use]
pub fn composition() -> HarnessBuilder {
    Harness::builder()
        .venture(venture())
        .module(module())
        .module(edits_module())
        .templates(templates())
}

/// The frozen composition: built once per isolate on first use, immutable
/// after. The runtime is `Clone` for exactly this pattern — one clone goes
/// into the builder (so `build()` validates the module's required ports
/// against the adapters actually wired), the original serves.
fn instance(env: &Env) -> Arc<(Harness, Cloudflare)> {
    static INSTANCE: OnceLock<Arc<(Harness, Cloudflare)>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            let runtime = Cloudflare::new()
                .db("DB")
                .rate_limiter("RATE_LIMITER")
                .mailer_arc(mailer(env))
                .payments_arc(payments(env))
                // Token verification from AUTH_ISSUER + AUTH_CLIENT_ID; with
                // both unset the port is `Unconfigured`, which answers 503 to
                // a presented credential and leaves anonymous calls alone —
                // every pre-auth page keeps working with no auth configured.
                .auth_from_env();
            let runtime = match captcha(env) {
                Some(captcha) => runtime.captcha_arc(Arc::new(captcha)),
                None => runtime,
            };
            // The setup module reads `Env`, so it joins the static
            // composition here rather than inside `composition()`.
            let harness = composition()
                .module(setup_module(env))
                // The Search Console console (#274) also reads `Env`;
                // it nests under its own `/v1/console`.
                .module(gsc(env))
                .runtime(runtime.clone())
                .build()
                .expect("the composition is static; `tests/harness.rs` builds the same one");
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
    // The host the request itself was addressed to: a same-origin form post
    // carries it as `Origin`, and that is as good as the site allowlist.
    let serving = req.url().ok().map(|url| url.origin().ascii_serialization());
    if write_origin_rejected(
        req.method().as_ref(),
        origin.as_deref(),
        req.path().as_str(),
        serving.as_deref(),
        &SITE_ORIGINS,
    ) {
        return origin_refused();
    }
    // The console fleet view (issue #169); `None` falls through.
    if let Some(response) = fleet::handle(&req, &env).await {
        return response;
    }
    let (harness, runtime) = &*instance(&env);
    serve(harness, runtime, req, env, ctx).await
}

/// Cron entry: the modules' sweeps. The hourly trigger wired in
/// `wrangler.toml` (`0 * * * *`) is the billing module's dispute poll
/// (`DISPUTE_POLL_CRON` — Polar sends no dispute webhooks); the waitlist
/// module's pending-entry retention runs on the same dispatch.
#[event(scheduled)]
pub async fn scheduled(event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {
    // Handler errors inside `serve_scheduled` are logged, never a failed
    // cron — the module's sweeps are idempotent by construction.
    let (harness, runtime) = &*instance(&env);
    serve_scheduled(harness, runtime, event, env, ctx).await;
}

#[cfg(test)]
mod tests {
    use super::{MailProvider, mail_provider};

    #[test]
    fn a_set_owlpost_key_selects_owlpost() {
        assert_eq!(mail_provider(Some("op_live_x")), MailProvider::Owlpost);
    }

    #[test]
    fn absent_or_blank_owlpost_key_falls_back_to_resend() {
        assert_eq!(mail_provider(None), MailProvider::Resend);
        assert_eq!(mail_provider(Some("")), MailProvider::Resend);
        assert_eq!(mail_provider(Some("   ")), MailProvider::Resend);
    }
}
