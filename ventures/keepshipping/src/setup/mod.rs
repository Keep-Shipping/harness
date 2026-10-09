//! The Standard setup console (issue #273): one plain-words checklist per
//! domain — Search Console, Postmaster Tools, Bing, and SPF, DKIM, DMARC,
//! MTA-STS, TLS-RPT — with a live chip per item and one button that sends
//! one change, shaped as a pull request, covering everything selected.
//! Every write goes through the PR path; the console never touches a zone
//! API. The pages are worker-served, so the worker's own origin
//! (`api.keepshipping.run`) carries their writes. Trust is single-operator
//! for now: every verified caller is trusted for every domain on file —
//! scoping a caller to the domains they manage is future work.

pub mod change;
pub mod checks;
pub mod page;

use std::collections::BTreeSet;
use std::sync::Arc;

use time::OffsetDateTime;

use cratefield_core::axum::body::Bytes;
use cratefield_core::axum::extract::{Path, State};
use cratefield_core::axum::http::{HeaderMap, StatusCode, Uri, header};
use cratefield_core::axum::response::{IntoResponse, Response};
use cratefield_core::axum::routing::{get, post};
use cratefield_core::axum::{Json, Router};
use cratefield_core::{
    Action, AuthError, Clock, Config, ConfigError, Database, DbError, HttpClient, Migrations,
    Module, ModuleContext, Port, Problem, Row, SLUGS, SqlMigration, Statement, Surface,
    SystemClock,
};

use change::Change;
pub use change::{GitHubPullRequests, PullRequests};
use checks::ItemStatus;
use page::Note;

/// The checklist, in page, storage and status order. The eight `*_on`
/// columns in the migration follow this order, and so does the `on` array
/// in [`Desired`].
pub struct Item {
    pub key: &'static str,
    pub label: &'static str,
    /// The one plain sentence under the name.
    pub explain: &'static str,
    /// An outside service a DNS record cannot finish: the page links out
    /// and offers "I did this" instead.
    pub external: bool,
}

pub const ITEMS: [Item; 8] = [
    Item {
        key: "search_console",
        label: "Google Search Console",
        explain: "Proves to Google that the domain is yours, and unlocks its search reports \
                  for it.",
        external: true,
    },
    Item {
        key: "postmaster",
        label: "Gmail Postmaster Tools",
        explain: "Google's report card for your email: whether mail from this domain arrives \
                  as it should.",
        external: true,
    },
    Item {
        key: "bing",
        label: "Bing Webmaster Tools",
        explain: "The same for Bing's search, and it can copy what Google already knows.",
        external: true,
    },
    Item {
        key: "spf",
        label: "SPF",
        explain: "A record that says which servers may send email as this domain — only \
                  Google, here.",
        external: false,
    },
    Item {
        key: "dkim",
        label: "DKIM",
        explain: "A signature Google adds to every mail, so receivers can check it really \
                  came from this domain.",
        external: false,
    },
    Item {
        key: "dmarc",
        label: "DMARC",
        explain: "Tells inboxes what to do with mail that fails the checks above, and where \
                  the reports go.",
        external: false,
    },
    Item {
        key: "mta_sts",
        label: "MTA-STS",
        explain: "Tells other mail servers to insist on a secure connection when they deliver \
                  to Google.",
        external: false,
    },
    Item {
        key: "tls_rpt",
        label: "TLS-RPT",
        explain: "Collects the reports when a secure delivery to this domain fails.",
        external: false,
    },
];

/// The items an "I did this" click can close out — the outside services.
const EXTERNAL_ITEMS: &[&str] = &["search_console", "postmaster", "bing"];

/// The `Desired::on` positions — the checklist order is also the storage
/// order (the migration's `*_on` columns) and the status answer's.
pub(crate) const SEARCH_CONSOLE: usize = 0;
pub(crate) const SPF: usize = 3;
pub(crate) const DKIM: usize = 4;
pub(crate) const DMARC: usize = 5;
pub(crate) const MTA_STS: usize = 6;
pub(crate) const TLS_RPT: usize = 7;

/// What the checklist says should be true for one domain: the eight
/// switches and the values the records are built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desired {
    /// On/off, per [`ITEMS`] position.
    pub on: [bool; ITEMS.len()],
    pub spf_value: String,
    pub dkim_selector: String,
    pub dkim_key: Option<String>,
    pub dmarc_rua: String,
    pub sitemap_url: String,
}

impl Desired {
    /// The pre-filled defaults a first view seeds.
    #[must_use]
    pub fn seed(domain: &str) -> Self {
        Self {
            on: [true; ITEMS.len()],
            spf_value: "v=spf1 include:_spf.google.com ~all".to_owned(),
            dkim_selector: "google".to_owned(),
            dkim_key: None,
            dmarc_rua: format!("mailto:dmarc-reports@{domain}"),
            sitemap_url: format!("https://{domain}/sitemap.xml"),
        }
    }

    /// The nothing-selected state a diff starts from when the domain has
    /// never been seen: no records published, so every selected item is
    /// an addition.
    #[must_use]
    pub fn absent() -> Self {
        Self {
            on: [false; ITEMS.len()],
            spf_value: String::new(),
            dkim_selector: String::new(),
            dkim_key: None,
            dmarc_rua: String::new(),
            sitemap_url: String::new(),
        }
    }

    /// The stored row. A missing column reads as its default, never a
    /// panic — the migration owns the shape; this only reads it.
    #[must_use]
    pub fn from_row(row: &Row) -> Self {
        let on = ITEMS
            .iter()
            .map(|item| row.get::<i64>(&format!("{}_on", item.key)).unwrap_or(1) != 0)
            .collect::<Vec<_>>();
        Self {
            on: on.try_into().unwrap_or([true; ITEMS.len()]),
            spf_value: row.get::<String>("spf_value").unwrap_or_default(),
            dkim_selector: row.get::<String>("dkim_selector").unwrap_or_default(),
            dkim_key: row.get::<Option<String>>("dkim_key").unwrap_or(None),
            dmarc_rua: row.get::<String>("dmarc_rua").unwrap_or_default(),
            sitemap_url: row.get::<String>("sitemap_url").unwrap_or_default(),
        }
    }

    /// Whether the records a change would publish differ: the eight
    /// switches and the values they carry. The sitemap address is stored
    /// and shown, but no record carries it, so changing only it is not a
    /// change to send.
    #[must_use]
    pub fn differs_records(&self, other: &Desired) -> bool {
        self.on != other.on
            || self.spf_value != other.spf_value
            || self.dkim_selector != other.dkim_selector
            || self.dkim_key != other.dkim_key
            || self.dmarc_rua != other.dmarc_rua
    }
}

/// The setup module, mounted at `/v1/setup`. `pr` is `None` when GitHub is
/// not configured: the console still serves and saves, and says honestly
/// that the pull request cannot open yet.
#[derive(Clone, Default)]
pub struct Setup {
    pr: Option<Arc<dyn PullRequests>>,
}

impl Setup {
    #[must_use]
    pub fn new(pr: Option<Arc<dyn PullRequests>>) -> Self {
        Self { pr }
    }
}

struct ModuleState {
    ctx: ModuleContext,
    pr: Option<Arc<dyn PullRequests>>,
}

impl Module for Setup {
    fn name(&self) -> &'static str {
        "setup"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Auth, Port::HttpClient, Port::Clock, Port::IdGen]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["setup_domains", "setup_changes", "setup_confirmations"]
    }

    fn migrations(&self) -> Migrations {
        // `migrations/0008_setup_init.sql`, embedded: wrangler numbering is
        // 0008, the module's own set starts at 0001.
        const MIGRATIONS: [SqlMigration; 1] = [SqlMigration::new(
            "0001",
            "init",
            include_str!("../../migrations/0008_setup_init.sql"),
        )];
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations { sqlite: &MIGRATIONS, postgres: &[] }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let mut error = ConfigError::new();
        for key in ["SETUP_GITHUB_REPO", "SETUP_GITHUB_TOKEN", "SETUP_GITHUB_BASE"] {
            if let Some(value) = cfg.get(key)
                && value.trim().is_empty()
            {
                error.push(format!("setup config {key} is set but blank"));
            }
        }
        if error.is_empty() { Ok(()) } else { Err(error) }
    }

    fn router(&self, ctx: ModuleContext) -> Router {
        let state = Arc::new(ModuleState { ctx, pr: self.pr.clone() });
        Router::new()
            .route("/", get(index_route))
            .route("/{domain}", get(domain_page).post(submit))
            .route("/{domain}/status", get(status))
            .route("/{domain}/confirmed", post(confirm_item))
            .with_state(state)
    }

    fn surface(&self) -> Surface {
        // Every action verifies its own caller through the Auth port, the
        // way billing's checkout and portal do under the default policy.
        Surface::new()
            .action(Action::get("index", "/"))
            .action(Action::get("domain", "/{domain}"))
            .action(Action::get("status", "/{domain}/status"))
            .action(Action::post("change", "/{domain}"))
            .action(Action::post("confirmed", "/{domain}/confirmed"))
    }
}

// -------------------------------------------------------------------------
// The routes

/// `GET /v1/setup` — the domains on file, and the box that names a new
/// one (`?domain=` navigates to its checklist).
async fn index_route(
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Err(response) = account_of(&state, &headers, true).await {
        return response;
    }
    if let Some(asked) = query_value(uri.query(), "domain") {
        if !valid_domain(&asked) {
            return bad_domain();
        }
        return see_other(&format!("/v1/setup/{asked}"));
    }
    let db = match db_of(&state) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match list_domains(&*db).await {
        Ok(domains) => page::html_response(StatusCode::OK, page::index_page(&domains)),
        Err(error) => {
            tracing::warn!(error = %error, "the domain list could not be read");
            oops()
        }
    }
}

/// `GET /v1/setup/{domain}` — the checklist. The first view of a domain
/// seeds its row with the pre-filled defaults, so the checkboxes start
/// meaning something before anything is sent.
async fn domain_page(
    State(state): State<Arc<ModuleState>>,
    Path(domain): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Err(response) = account_of(&state, &headers, true).await {
        return response;
    }
    if !valid_domain(&domain) {
        return bad_domain();
    }
    let (db, http) = match (db_of(&state), http_of(&state)) {
        (Ok(db), Ok(http)) => (db, http),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    let desired = match load(&*db, &domain).await {
        Ok(Some((desired, _))) => desired,
        Ok(None) => {
            let seeded = Desired::seed(&domain);
            // `version 0` is the seed's CAS: it inserts only while the
            // domain is still unseen, so a race of first views lets the
            // winner's row stand.
            if let Err(error) =
                save(&*db, &domain, &seeded, 0, &change::iso(now_of(&state.ctx))).await
            {
                tracing::warn!(error = %error, "the domain row could not be seeded");
                return oops();
            }
            seeded
        }
        Err(error) => {
            tracing::warn!(error = %error, "the domain row could not be read");
            return oops();
        }
    };
    // The note (if the redirect back carried one) needs the latest
    // change's `pr_url` to say "pull request" instead of a promise.
    let note = match query_value(uri.query(), "note").as_deref() {
        Some("saved") => match latest_change(&*db, &domain).await {
            Ok(latest) => Some(Note::Saved(latest.and_then(|change| change.pr_url))),
            Err(error) => {
                tracing::warn!(error = %error, "the last change could not be read");
                return oops();
            }
        },
        Some("nochange") => Some(Note::NoChange),
        Some("unfiled") => Some(Note::Unfiled),
        _ => None,
    };
    let statuses = board(&*db, &*http, &domain, &desired).await;
    page::html_response(StatusCode::OK, page::checklist_page(&domain, &desired, &statuses, note))
}

/// `GET /v1/setup/{domain}/status` — the JSON the page polls every few
/// seconds.
async fn status(
    State(state): State<Arc<ModuleState>>,
    Path(domain): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = account_of(&state, &headers, false).await {
        return response;
    }
    if !valid_domain(&domain) {
        return Problem::validation_failed(format!(
            "{domain} is not a domain name: lowercase letters, digits and dashes, at least one \
             dot"
        ))
        .into_response();
    }
    let (db, http) = match (db_of(&state), http_of(&state)) {
        (Ok(db), Ok(http)) => (db, http),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    // An unvisited domain answers with its seed defaults and writes
    // nothing: a status poll is a read.
    let desired = match load(&*db, &domain).await {
        Ok(Some((desired, _))) => desired,
        Ok(None) => Desired::seed(&domain),
        Err(error) => {
            tracing::warn!(error = %error, "the domain row could not be read");
            return Problem::internal().into_response();
        }
    };
    let statuses = board(&*db, &*http, &domain, &desired).await;
    Json(page::status_json(&domain, &statuses, &change::iso(now_of(&state.ctx)))).into_response()
}

/// `POST /v1/setup/{domain}` — the "Send one change" click: validate,
/// persist the desired state (compare-and-swap), and if anything material
/// changed, open one pull request and store it. GitHub not connected
/// still stores the change — honestly, with no `pr_url` — and a pull
/// request that failed to open is what the next send of the same board
/// retries.
async fn submit(
    State(state): State<Arc<ModuleState>>,
    Path(domain): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match account_of(&state, &headers, true).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if !valid_domain(&domain) {
        return bad_domain();
    }
    let db = match db_of(&state) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let fields = parse_form(&body);
    // What is on file now, and the `version` the write must match — read
    // first, because a switched-off item's cleared field keeps these
    // values instead of being validated.
    let (prior, version) = match load(&*db, &domain).await {
        Ok(Some(stored)) => stored,
        Ok(None) => (Desired::absent(), 0),
        Err(error) => {
            tracing::warn!(error = %error, "the domain row could not be read");
            return oops();
        }
    };
    let desired = match desired_from_form(&fields, &prior) {
        Ok(desired) => desired,
        Err(message) => {
            return page::error_page(
                StatusCode::BAD_REQUEST,
                "That value doesn't look right",
                &message,
            );
        }
    };
    let stamp = change::iso(now_of(&state.ctx));
    // Persist first, as billing does: the checklist is the truth even
    // when the pull request cannot open.
    match save(&*db, &domain, &desired, version, &stamp).await {
        Ok(changed) if changed > 0 => {}
        Ok(_) => return conflict_page(),
        Err(error) => {
            tracing::warn!(error = %error, "the domain row could not be saved");
            return oops();
        }
    }
    // The branch needs a short id and the change row a full one; both
    // come from the same ULID.
    let Some(id_gen) = state.ctx.ports.id_gen.as_ref() else {
        return Problem::not_ready("the id generator is missing").into_response();
    };
    let ulid = id_gen.ulid();
    let short_id = ulid.chars().take(8).collect::<String>().to_lowercase();
    let submitted = change::build_change(&domain, &desired, &short_id);
    // What is already asked for: the board itself is unchanged, or the
    // last send made exactly this change. Either way there is nothing new
    // to file — except a pull request that never opened.
    let latest = match latest_change(&*db, &domain).await {
        Ok(latest) => latest,
        Err(error) => {
            tracing::warn!(error = %error, "the last change could not be read");
            return oops();
        }
    };
    let unchanged = !prior.differs_records(&desired)
        || latest.as_ref().is_some_and(|stored| stored.matches(&submitted));
    if unchanged {
        if let (Some(pr), Some(_)) =
            (&state.pr, latest.as_ref().filter(|stored| stored.pr_url.is_none()))
        {
            match pr.open(&submitted).await {
                Ok(url) => {
                    // The retry is its own send: it gets its own row, so
                    // the change that finally opened is the one on record.
                    if let Err(error) =
                        insert_change(&*db, &ulid, &domain, &submitted, Some(&url), &stamp, &caller)
                            .await
                    {
                        tracing::warn!(error = %error, "the retried change could not be stored");
                        return oops();
                    }
                    return see_other(&format!("/v1/setup/{domain}?note=saved"));
                }
                Err(error) => {
                    tracing::warn!(error = %error, domain, "the pull request did not open again");
                    return see_other(&format!("/v1/setup/{domain}?note=unfiled"));
                }
            }
        }
        return see_other(&format!("/v1/setup/{domain}?note=nochange"));
    }
    // A fresh change. When GitHub is connected but the open fails, the
    // note says exactly that — not "connect GitHub".
    let (pr_url, note) = match &state.pr {
        Some(pr) => match pr.open(&submitted).await {
            Ok(url) => (Some(url), "saved"),
            Err(error) => {
                tracing::warn!(error = %error, domain, "the pull request did not open");
                (None, "unfiled")
            }
        },
        None => (None, "saved"),
    };
    if let Err(error) =
        insert_change(&*db, &ulid, &domain, &submitted, pr_url.as_deref(), &stamp, &caller).await
    {
        tracing::warn!(error = %error, "the change could not be stored");
        return oops();
    }
    see_other(&format!("/v1/setup/{domain}?note={note}"))
}

/// `POST /v1/setup/{domain}/confirmed` — the "I did this" click for the
/// outside services. Insert-or-ignore: a confirmation is a fact, and
/// clicking twice still says it once.
async fn confirm_item(
    State(state): State<Arc<ModuleState>>,
    Path(domain): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match account_of(&state, &headers, true).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if !valid_domain(&domain) {
        return bad_domain();
    }
    let item = parse_form(&body).get("item").map(String::as_str).unwrap_or_default().to_owned();
    if !EXTERNAL_ITEMS.contains(&item.as_str()) {
        return page::error_page(
            StatusCode::BAD_REQUEST,
            "That item can't be confirmed",
            "Only Search Console, Postmaster Tools and Bing take an \"I did this\".",
        );
    }
    let db = match db_of(&state) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let stamp = change::iso(now_of(&state.ctx));
    if let Err(error) = confirm(&*db, &domain, &item, &caller, &stamp).await {
        tracing::warn!(error = %error, "the confirmation could not be stored");
        return oops();
    }
    see_other(&format!("/v1/setup/{domain}"))
}

// -------------------------------------------------------------------------
// The pieces the routes share

/// Who the verified caller is, for the HTML routes (`html`) and the JSON
/// status route alike. No auth port is the deployment's misconfiguration
/// (503); an anonymous caller's is their 401 — an HTML error page on the
/// pages, problem+json on the API route.
#[expect(
    clippy::result_large_err,
    reason = "a `Response` is the error type across every handler; boxing it would cost an \
              allocation on each refusal for no gain"
)]
async fn account_of(
    state: &ModuleState,
    headers: &HeaderMap,
    html: bool,
) -> Result<String, Response> {
    let Some(auth) = state.ctx.ports.auth.clone() else {
        return Err(refusal(
            html,
            StatusCode::SERVICE_UNAVAILABLE,
            "The identity provider is not wired",
            Problem::not_ready(
                "setup needs an identity provider to name a caller (no auth port is wired)",
            ),
        ));
    };
    match auth.identify(headers).await {
        Ok(caller) => {
            caller.id().map_or_else(|| Err(refuse_anonymous(html)), |id| Ok(id.to_owned()))
        }
        Err(AuthError::Unavailable(detail)) => {
            tracing::warn!(%detail, "the identity provider could not be reached");
            Err(refusal(
                html,
                StatusCode::SERVICE_UNAVAILABLE,
                "The identity provider is unavailable",
                Problem::not_ready("the identity provider is unavailable"),
            ))
        }
        Err(_) => Err(refuse_anonymous(html)),
    }
}

fn refuse_anonymous(html: bool) -> Response {
    refusal(html, StatusCode::UNAUTHORIZED, "Sign in first", Problem::new(&SLUGS.unauthenticated))
}

fn refusal(html: bool, status: StatusCode, title: &str, problem: Problem) -> Response {
    if html {
        page::error_page(status, title, "This console needs a signed-in account.")
    } else {
        problem.into_response()
    }
}

#[expect(clippy::result_large_err)]
fn db_of(state: &ModuleState) -> Result<Arc<dyn Database>, Response> {
    state
        .ctx
        .ports
        .db
        .clone()
        .ok_or_else(|| Problem::not_ready("the database is missing").into_response())
}

#[expect(clippy::result_large_err)]
fn http_of(state: &ModuleState) -> Result<Arc<dyn HttpClient>, Response> {
    state
        .ctx
        .ports
        .http
        .clone()
        .ok_or_else(|| Problem::not_ready("the http client is missing").into_response())
}

fn bad_domain() -> Response {
    page::error_page(
        StatusCode::BAD_REQUEST,
        "That domain doesn't look right",
        "Use lowercase letters, digits and dashes, with at least one dot.",
    )
}

/// 409 for a lost save race: the row moved between this send's read and
/// its write, nothing committed, and reloading the page is the retry.
fn conflict_page() -> Response {
    page::error_page(
        StatusCode::CONFLICT,
        "The page moved as you worked",
        "The domain's setup changed while you were on it — reload and send again.",
    )
}

fn oops() -> Response {
    page::error_page(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong",
        "The change could not be stored. Try again in a moment.",
    )
}

/// The checklist's live board: what is on file, what the outside world
/// can already see, one row per item in checklist order.
async fn board(
    db: &dyn Database,
    http: &dyn HttpClient,
    domain: &str,
    desired: &Desired,
) -> Vec<ItemStatus> {
    let sent = match latest_change(db, domain).await {
        Ok(latest) => latest.is_some(),
        Err(error) => {
            tracing::warn!(error = %error, "the last change could not be read");
            false
        }
    };
    let confirmed = match confirmations(db, domain).await {
        Ok(confirmed) => confirmed,
        Err(error) => {
            tracing::warn!(error = %error, "the confirmations could not be read");
            BTreeSet::new()
        }
    };
    checks::assess(http, domain, desired, sent, &confirmed).await
}

/// `303` back to the page — the browser follows it with a plain GET.
fn see_other(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = header::HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

/// One `key=value` out of the query string, decoded the form way.
fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    let query = query?;
    parse_form(query.as_bytes()).get(key).cloned()
}

/// A lowercase domain of at least two labels over `[a-z0-9-]`, none empty
/// or dashed at the ends — the charset the domain travels in (URLs, DNS
/// names, a branch name) and the only one the pages will serve.
fn valid_domain(domain: &str) -> bool {
    let labels = domain.split('.').collect::<Vec<_>>();
    domain.len() <= 253 && labels.len() >= 2 && labels.iter().all(|label| valid_label(label))
}

/// One DNS label; also the DKIM selector's shape.
fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

/// One printable line — the DKIM key's shape. Spaces are fine (Google's
/// own key text carries them); a control character or an absurd length is
/// not.
fn plain_value(value: &str) -> bool {
    value.len() <= 2048
        && value.chars().all(|character| character.is_ascii_graphic() || character == ' ')
}

/// What a submitted checklist asks for, validated with plain words — the
/// same words the page shows when a value is wrong. A switched-off item's
/// field is not demanded: blank while off means "as stored" (`prior`), so
/// clearing a field never blocks unticking the item. The format rules
/// apply when the item is on; the one-line-of-plain-characters rule
/// applies always, because these values reach the pull-request body and
/// the HCL, where a control character would inject a line of its own.
fn desired_from_form(
    fields: &std::collections::BTreeMap<String, String>,
    prior: &Desired,
) -> Result<Desired, String> {
    let mut on = [false; ITEMS.len()];
    for (index, item) in ITEMS.iter().enumerate() {
        on[index] = fields.contains_key(item.key);
    }
    let field =
        |key: &str| fields.get(key).map(String::as_str).unwrap_or_default().trim().to_owned();
    // Blank while off keeps what is stored. The sitemap's switch is the
    // Search Console's, since that is where a sitemap is used.
    let kept = |switch: usize, submitted: String, stored: &String| -> String {
        if !on[switch] && submitted.is_empty() { stored.clone() } else { submitted }
    };
    let spf_value = kept(SPF, field("spf_value"), &prior.spf_value);
    let dkim_selector = kept(DKIM, field("dkim_selector"), &prior.dkim_selector);
    let dkim_key = field("dkim_key");
    let dmarc_rua = kept(DMARC, field("dmarc_rua"), &prior.dmarc_rua);
    let sitemap_url = kept(SEARCH_CONSOLE, field("sitemap_url"), &prior.sitemap_url);
    if !plain_value(&spf_value) {
        return Err("The SPF record should be one line of plain characters.".to_owned());
    }
    if on[SPF] {
        if !spf_value.starts_with("v=spf1") {
            return Err("The SPF record should start with v=spf1.".to_owned());
        }
        if spf_value.len() > 512 {
            return Err("The SPF record is too long — most inboxes stop reading after 512 \
                        characters."
                .to_owned());
        }
    }
    if on[DKIM] && !valid_label(&dkim_selector) {
        return Err("The DKIM selector should be lowercase letters, digits or dashes.".to_owned());
    }
    if !dkim_key.is_empty() && !plain_value(&dkim_key) {
        return Err("The DKIM key should be one line of plain characters.".to_owned());
    }
    if !plain_value(&dmarc_rua) {
        return Err("The reports address should be one line of plain characters.".to_owned());
    }
    if on[DMARC] && (!dmarc_rua.starts_with("mailto:") || dmarc_rua.len() > 320) {
        return Err("The DMARC reports address should start with mailto:.".to_owned());
    }
    if on[SEARCH_CONSOLE] && (!sitemap_url.starts_with("https://") || sitemap_url.len() > 2048) {
        return Err("The sitemap address should start with https://.".to_owned());
    }
    Ok(Desired {
        on,
        spf_value,
        dkim_selector,
        dkim_key: (!dkim_key.is_empty()).then_some(dkim_key),
        dmarc_rua,
        sitemap_url,
    })
}

/// An `application/x-www-form-urlencoded` body, decoded. The pages are
/// plain HTML forms, so this is the one body shape the write routes read.
fn parse_form(body: &[u8]) -> std::collections::BTreeMap<String, String> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

/// Percent-decoding plus the form's `+`-for-space rule; a bare `%` is
/// itself, never an error.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = char::from(bytes[index + 1]).to_digit(16);
                let low = char::from(bytes[index + 2]).to_digit(16);
                if let (Some(high), Some(low)) = (high, low) {
                    out.push((high * 16 + low) as u8);
                    index += 3;
                } else {
                    out.push(b'%');
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn now_of(ctx: &ModuleContext) -> OffsetDateTime {
    match ctx.ports.clock.as_ref() {
        Some(clock) => clock.now(),
        None => SystemClock.now(),
    }
}

// -------------------------------------------------------------------------
// The store

/// The stored state with the `version` an optimistic write must match.
async fn load(db: &dyn Database, domain: &str) -> Result<Option<(Desired, i64)>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT search_console_on, postmaster_on, bing_on, spf_on, dkim_on, dmarc_on, \
             mta_sts_on, tls_rpt_on, spf_value, dkim_selector, dkim_key, dmarc_rua, \
             sitemap_url, version FROM setup_domains WHERE domain = ?",
            vec![domain.into()],
        ))
        .await?;
    Ok(rows.first().and_then(|row| {
        let version = row.get::<i64>("version")?;
        Some((Desired::from_row(row), version))
    }))
}

/// The conditional write: an upsert whose `WHERE version = ?` is the
/// compare-and-swap, in the shape billing's `state_upsert` keeps. The row
/// count is how a lost race shows: zero rows means someone else moved the
/// domain mid-flight.
async fn save(
    db: &dyn Database,
    domain: &str,
    desired: &Desired,
    version: i64,
    stamp: &str,
) -> Result<u64, DbError> {
    db.execute(&Statement::with_values(
        "INSERT INTO setup_domains \
           (domain, search_console_on, postmaster_on, bing_on, spf_on, dkim_on, dmarc_on, \
            mta_sts_on, tls_rpt_on, spf_value, dkim_selector, dkim_key, dmarc_rua, \
            sitemap_url, updated_at, version) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? + 1) \
         ON CONFLICT(domain) DO UPDATE SET \
           search_console_on = excluded.search_console_on, \
           postmaster_on = excluded.postmaster_on, bing_on = excluded.bing_on, \
           spf_on = excluded.spf_on, dkim_on = excluded.dkim_on, \
           dmarc_on = excluded.dmarc_on, mta_sts_on = excluded.mta_sts_on, \
           tls_rpt_on = excluded.tls_rpt_on, spf_value = excluded.spf_value, \
           dkim_selector = excluded.dkim_selector, dkim_key = excluded.dkim_key, \
           dmarc_rua = excluded.dmarc_rua, sitemap_url = excluded.sitemap_url, \
           version = setup_domains.version + 1, updated_at = excluded.updated_at \
         WHERE setup_domains.version = ?",
        vec![
            domain.into(),
            i64::from(desired.on[0]).into(),
            i64::from(desired.on[1]).into(),
            i64::from(desired.on[2]).into(),
            i64::from(desired.on[3]).into(),
            i64::from(desired.on[4]).into(),
            i64::from(desired.on[5]).into(),
            i64::from(desired.on[6]).into(),
            i64::from(desired.on[7]).into(),
            desired.spf_value.clone().into(),
            desired.dkim_selector.clone().into(),
            desired.dkim_key.clone().into(),
            desired.dmarc_rua.clone().into(),
            desired.sitemap_url.clone().into(),
            stamp.into(),
            version.into(), // the insert's `? + 1`
            version.into(), // the compare-and-swap's WHERE
        ],
    ))
    .await
}

/// The domains on file, alphabetical — the index page's list.
async fn list_domains(db: &dyn Database) -> Result<Vec<String>, DbError> {
    let rows =
        db.query(&Statement::new("SELECT domain FROM setup_domains ORDER BY domain")).await?;
    Ok(rows.rows.iter().filter_map(|row| row.get::<String>("domain")).collect())
}

/// The most recent change for a domain, with the `pr_url` that may have
/// come back for it.
async fn latest_change(db: &dyn Database, domain: &str) -> Result<Option<StoredChange>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT summary_md, files, pr_url FROM setup_changes WHERE domain = ? \
             ORDER BY created_at DESC, id DESC LIMIT 1",
            vec![domain.into()],
        ))
        .await?;
    Ok(rows.first().map(|row| StoredChange {
        summary_md: row.get::<String>("summary_md").unwrap_or_default(),
        files: row.get::<String>("files").unwrap_or_default(),
        pr_url: row.get::<Option<String>>("pr_url").unwrap_or(None),
    }))
}

/// A stored change — the slice a re-send compares against.
struct StoredChange {
    summary_md: String,
    files: String,
    pr_url: Option<String>,
}

impl StoredChange {
    /// Whether the stored change already says exactly what `submitted`
    /// says — same files, same summary — so a second pull request would
    /// be a duplicate ask.
    fn matches(&self, submitted: &Change) -> bool {
        self.summary_md == submitted.summary_md
            && self.files == serde_json::to_string(&submitted.files).unwrap_or_default()
    }
}

async fn insert_change(
    db: &dyn Database,
    id: &str,
    domain: &str,
    submitted: &Change,
    pr_url: Option<&str>,
    stamp: &str,
    created_by: &str,
) -> Result<(), DbError> {
    db.execute(&Statement::with_values(
        "INSERT INTO setup_changes (id, domain, branch, title, summary_md, files, pr_url, \
         created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        vec![
            id.into(),
            domain.into(),
            submitted.branch.clone().into(),
            submitted.title.clone().into(),
            submitted.summary_md.clone().into(),
            serde_json::to_string(&submitted.files).unwrap_or_default().into(),
            pr_url.into(),
            stamp.into(),
            created_by.into(),
        ],
    ))
    .await
    .map(|_| ())
}

async fn confirmations(db: &dyn Database, domain: &str) -> Result<BTreeSet<String>, DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT item FROM setup_confirmations WHERE domain = ?",
            vec![domain.into()],
        ))
        .await?;
    Ok(rows.rows.iter().filter_map(|row| row.get::<String>("item")).collect())
}

async fn confirm(
    db: &dyn Database,
    domain: &str,
    item: &str,
    by: &str,
    stamp: &str,
) -> Result<(), DbError> {
    db.execute(&Statement::with_values(
        "INSERT INTO setup_confirmations (domain, item, confirmed_at, confirmed_by) \
         VALUES (?, ?, ?, ?) ON CONFLICT(domain, item) DO NOTHING",
        vec![domain.into(), item.into(), stamp.into(), by.into()],
    ))
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_needs_two_plain_labels() {
        assert!(valid_domain("example.com"));
        assert!(valid_domain("mail.example.co.uk"));
        assert!(!valid_domain("example")); // no dot
        assert!(!valid_domain("Example.com")); // uppercase
        assert!(!valid_domain("ex ample.com")); // space
        assert!(!valid_domain("-example.com")); // dashed label start
        assert!(!valid_domain("example..com")); // empty label
        assert!(!valid_domain("example-.com")); // dashed label end
    }

    #[test]
    fn a_form_decodes_to_fields() {
        let fields = parse_form(b"spf=on&spf_value=v%3Dspf1+include%3A_spf.google.com+~all");
        assert_eq!(fields.get("spf").map(String::as_str), Some("on"));
        assert_eq!(
            fields.get("spf_value").map(String::as_str),
            Some("v=spf1 include:_spf.google.com ~all")
        );
        assert!(parse_form(b"").is_empty());
        // A bare percent is itself, never an error.
        assert_eq!(parse_form(b"a=100%").get("a").map(String::as_str), Some("100%"));
    }

    #[test]
    fn a_checklist_passes_and_fails_in_plain_words() {
        let mut fields = std::collections::BTreeMap::new();
        for item in ITEMS.iter() {
            fields.insert(item.key.to_owned(), "on".to_owned());
        }
        fields.insert("spf_value".to_owned(), "v=spf1 -all".to_owned());
        fields.insert("dkim_selector".to_owned(), "google".to_owned());
        fields.insert("dmarc_rua".to_owned(), "mailto:dmarc-reports@example.com".to_owned());
        fields.insert("sitemap_url".to_owned(), "https://example.com/sitemap.xml".to_owned());
        let desired = desired_from_form(&fields, &Desired::absent()).expect("a good checklist");
        assert!(desired.on.iter().all(|switch| *switch));
        assert_eq!(desired.dkim_key, None);

        let before = fields.clone();
        fields.insert("spf_value".to_owned(), "allow all".to_owned());
        assert!(desired_from_form(&fields, &Desired::absent()).is_err());
        // A control character in a value that reaches the pull-request
        // body or the HCL is refused even when it starts like a record —
        // a newline would inject a line of its own.
        fields = before.clone();
        fields.insert("spf_value".to_owned(), "v=spf1\ninclude:_spf.attacker.example".to_owned());
        assert!(desired_from_form(&fields, &Desired::absent()).is_err());
        fields = before.clone();
        fields.insert(
            "dmarc_rua".to_owned(),
            "mailto:dmarc@example.com\nBcc: victim@example.com".to_owned(),
        );
        assert!(desired_from_form(&fields, &Desired::absent()).is_err());
        fields = before;
        fields.insert("dkim_key".to_owned(), "line\nbreak".to_owned());
        assert!(desired_from_form(&fields, &Desired::absent()).is_err());
    }

    #[test]
    fn an_unticked_item_does_not_demand_its_value() {
        let prior = Desired::seed("example.com");
        // SPF and DMARC unticked with their fields cleared: the untick
        // stands, and the stored values stay.
        let mut fields = std::collections::BTreeMap::new();
        for (index, item) in ITEMS.iter().enumerate() {
            if matches!(index, SPF | DMARC) {
                continue;
            }
            fields.insert(item.key.to_owned(), "on".to_owned());
        }
        fields.insert("dkim_selector".to_owned(), "google".to_owned());
        fields.insert("sitemap_url".to_owned(), "https://example.com/sitemap.xml".to_owned());
        let desired = desired_from_form(&fields, &prior).expect("cleared fields do not block");
        assert!(!desired.on[SPF]);
        assert!(!desired.on[DMARC]);
        assert_eq!(desired.spf_value, prior.spf_value, "the stored SPF stays");
        assert_eq!(desired.dmarc_rua, prior.dmarc_rua, "the stored reports address stays");
        // A value typed for an off item is kept without the format rules —
        // it is checked again the day the item is ticked back on.
        fields.insert("spf_value".to_owned(), "not a record yet".to_owned());
        let desired = desired_from_form(&fields, &prior).expect("an off item's value is kept");
        assert_eq!(desired.spf_value, "not a record yet");
        fields.insert("spf".to_owned(), "on".to_owned());
        assert!(desired_from_form(&fields, &prior).is_err(), "on, the value is checked");
        // The sitemap's switch is the Search Console's.
        fields.remove("search_console");
        fields.remove("sitemap_url");
        fields.remove("spf");
        let desired = desired_from_form(&fields, &prior).expect("the sitemap is not demanded");
        assert_eq!(desired.sitemap_url, prior.sitemap_url);
    }

    #[test]
    fn the_seed_differs_from_nothing_but_not_from_itself() {
        let seed = Desired::seed("example.com");
        assert!(Desired::absent().differs_records(&seed));
        assert!(!seed.differs_records(&seed.clone()));
        // The sitemap address carries no record, so changing only it is
        // not a change to send.
        let mut moved = seed.clone();
        moved.sitemap_url = "https://example.com/sitemaps/all.xml".to_owned();
        assert!(!seed.differs_records(&moved));
    }
}
