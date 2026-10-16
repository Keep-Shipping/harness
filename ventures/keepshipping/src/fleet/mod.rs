//! The console fleet view (issue #169): one screen of every zone, Pages
//! site and Worker the account's Terraform manages, plus a per-site detail
//! page, rendered from the snapshot the nightly check writes into KV
//! (binding `FLEET`, key `fleet.json`; contract in the venture README).
//!
//! Everything but [`handle`] is pure rendering and helpers — no `worker`
//! types — so `tests/fleet.rs` exercises it natively. The Workers-side
//! glue (method check, auth, the KV read, security headers) lives in
//! `console`.

mod console;

pub use console::{handle, scheduled_refresh};

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Serialize};

/// The compiled stylesheet, inlined into each page's one `<style>` block.
const STYLE: &str = include_str!("style.css");

/// URL path segments built from snapshot strings; `/` stays (repos and
/// paths are multi-segment), everything a URL path cannot carry raw goes,
/// plus `&`, which would start or split a query string.
const PATH: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'&')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'\\')
    .add(b'^')
    .add(b'|');

/// Query values (the zone name in the edit-as-code link): [`PATH`] plus
/// the characters a query string cannot carry raw.
const QUERY: &AsciiSet = &PATH.add(b'=').add(b'+').add(b';').add(b'\'');

/// The fleet snapshot: one account, the Terraform defining it, every site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fleet {
    pub account: String,
    pub generated_at: String,
    /// Absent when the snapshot has no Terraform behind it (the Cloudflare
    /// collector writes none yet); pages then say so instead of linking.
    #[serde(default)]
    pub terraform: Option<Terraform>,
    pub sites: Vec<Site>,
    /// Parts of the account the last collection could not read, in plain
    /// words (a refused or failed listing). The rest of the snapshot is
    /// still shown; these say what is missing from it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<String>,
}

/// The Terraform repository the sites are defined in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Terraform {
    pub repo: String,
    /// The commit the snapshot was taken at (`ref` in the JSON).
    #[serde(rename = "ref")]
    pub revision: String,
}

/// What a site is; `Kind::words` renders it in plain words.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Zone,
    Pages,
    Worker,
}

impl Kind {
    fn words(self) -> &'static str {
        match self {
            Kind::Zone => "Domain",
            Kind::Pages => "Pages site",
            Kind::Worker => "Worker",
        }
    }
}

/// One managed site. The optional fields ([`Site::deploys`], [`Site::tls`],
/// [`Site::dns`], [`Site::baseline`], [`Site::drift`], [`Site::resources`])
/// render as "Not checked yet" / "Never deployed" until the pipeline fills
/// them in; `deploys` is newest first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    /// Empty when the site has no venture (shown as an em dash).
    #[serde(default)]
    pub venture: String,
    #[serde(default)]
    pub domains: Vec<String>,
    /// Absent without Terraform (see [`Fleet::terraform`]).
    #[serde(default)]
    pub defined_at: Option<Location>,
    #[serde(default)]
    pub deploys: Vec<Deploy>,
    #[serde(default)]
    pub tls: Option<Tls>,
    #[serde(default)]
    pub dns: Option<Dns>,
    #[serde(default)]
    pub baseline: Option<Baseline>,
    #[serde(default)]
    pub drift: Option<Drift>,
    #[serde(default)]
    pub resources: Vec<Resource>,
}

/// TLS certificate state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tls {
    pub status: TlsStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TlsStatus {
    Ok,
    Expiring,
    Failing,
    Unknown,
}
/// DNS state, with a plain-words note when there is a problem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dns {
    pub status: DnsStatus,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsStatus {
    Ok,
    Problem,
    Unknown,
}
/// Whether the deployed site matches the Terraform it is defined in.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Drift {
    InSync,
    Drifted,
    Unknown,
}
/// The site's baseline score, with failing checks in plain words.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub score: u16,
    #[serde(default)]
    pub failing: Vec<String>,
}
/// One deploy of the site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deploy {
    pub commit: String,
    pub at: String,
    pub by: String,
}
/// Where in the Terraform a thing is defined.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    pub line: u32,
}
/// One Terraform resource behind a site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub kind: String,
    pub name: String,
    pub defined_at: Location,
}

/// What a console URL asks for: the fleet list, or one site's page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Index,
    Site(String),
}

/// `/console/fleet` and `/console/fleet/<id>`, trailing-slash tolerant.
/// Anything else — deeper paths could smuggle a look-alike id — is `None`,
/// so `fetch` falls through to the harness. The id is percent-decoded and
/// matched exactly against the snapshot's ids at render time.
#[must_use]
pub fn route(path: &str) -> Option<Route> {
    let rest = path.trim_end_matches('/').strip_prefix("/console/fleet")?;
    match rest.strip_prefix('/') {
        None => rest.is_empty().then_some(Route::Index),
        Some(id) if !id.is_empty() && !id.contains('/') => {
            Some(Route::Site(percent_decode_str(id).decode_utf8_lossy().into_owned()))
        }
        Some(_) => None,
    }
}

/// The whole fleet: one row per site, sorted by venture then name so the
/// same snapshot always renders the same page.
#[must_use]
pub fn render_index(snapshot: &Fleet) -> String {
    let mut sites: Vec<&Site> = snapshot.sites.iter().collect();
    sites.sort_by(|a, b| (&a.venture, &a.name).cmp(&(&b.venture, &b.name)));
    let attention = sites.iter().filter(|site| needs_attention(site)).count();
    let count = format!(
        "{} site{} · {} {} attention",
        sites.len(),
        if sites.len() == 1 { "" } else { "s" },
        attention,
        if attention == 1 { "needs" } else { "need" },
    );
    let rows = sites
        .iter()
        .map(|site| site_row(site, snapshot.terraform.as_ref()))
        .collect::<Vec<_>>()
        .join("\n");
    let terraform = match &snapshot.terraform {
        Some(terraform) => format!(
            "Terraform {repo} at <code>{rev}</code>",
            repo = esc(&terraform.repo),
            rev = esc(short(&terraform.revision)),
        ),
        None => "Not managed by Terraform yet".to_owned(),
    };
    let gaps = if snapshot.gaps.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"gaps\"><strong>Not read this time:</strong> {}.</p>\n",
            snapshot.gaps.iter().map(|gap| esc(gap)).collect::<Vec<_>>().join("; ")
        )
    };
    let body = format!(
        "<main id=\"main\">\n<h1>{account} fleet</h1>\n\
         <p class=\"meta\">{count} · checked {when} · {terraform}</p>\n\
         {gaps}\
         <p>{REFRESH_FORM}</p>\n\
         <table>\n\
         <caption class=\"offscreen\">Every site with its last deploy, HTTPS, DNS, baseline and \
         code state</caption>\n\
         <thead><tr><th scope=\"col\">Site</th><th scope=\"col\">Venture</th>\
         <th scope=\"col\">Domains</th><th scope=\"col\">Last deploy</th><th scope=\"col\">HTTPS</th>\
         <th scope=\"col\">DNS</th><th scope=\"col\">Baseline</th><th scope=\"col\">Code</th>\
         <th scope=\"col\">Defined in</th></tr></thead>\n\
         <tbody>\n{rows}</tbody>\n</table>\n</main>\n",
        account = esc(&snapshot.account),
        count = count,
        when = esc(&fmt_time(&snapshot.generated_at)),
        terraform = terraform,
        REFRESH_FORM = REFRESH_FORM,
    );
    signed_in_layout(&format!("{account} fleet", account = snapshot.account), &body)
}

/// The snapshot's refresh button: a POST to the same-origin gate.
pub(crate) const REFRESH_FORM: &str = "<form class=\"refresh\" method=\"post\" \
     action=\"/console/fleet/refresh\"><button type=\"submit\">Refresh now</button></form>";

/// The page for a console with no snapshot yet: connected, it offers the
/// refresh; not connected, it points at the connect page.
#[must_use]
pub(crate) fn empty_snapshot_page(connected: bool) -> String {
    let body = if connected {
        format!(
            "<main id=\"main\">\n<div class=\"notice\">\n<h1>No fleet snapshot yet</h1>\n\
             <p>Your Cloudflare token is connected, but no snapshot has been written yet. \
             Refresh to read the account now.</p>\n{REFRESH_FORM}\n</div>\n</main>\n"
        )
    } else {
        "<main id=\"main\">\n<div class=\"notice\">\n<h1>No fleet snapshot yet</h1>\n\
         <p>The fleet view is built from a read-only Cloudflare token. Connect one to see your \
         domains, Pages sites and Workers.</p>\n\
         <p><a href=\"/console/connect/cloudflare\">Connect Cloudflare</a></p>\n</div>\n</main>\n"
            .to_owned()
    };
    signed_in_layout("No fleet snapshot yet", &body)
}

/// One row. `th scope="row"` makes the site name the row's heading for
/// screen readers; each cell carries a `data-label` so the narrow card
/// layout can name it without JS.
fn site_row(site: &Site, terraform: Option<&Terraform>) -> String {
    let change = if site.kind == Kind::Zone {
        format!(
            " <a class=\"change\" href=\"/v1/edits/new?kind=dns&amp;zone={zone}\">Change</a>",
            zone = utf8_percent_encode(&site.name, QUERY),
        )
    } else {
        String::new()
    };
    format!(
        "<tr>\n\
         <th scope=\"row\"><a href=\"/console/fleet/{id}\">{name}</a> \
         <span class=\"badge\">{kind}</span>{change}</th>\n\
         <td data-label=\"Venture\">{venture}</td>\n\
         <td data-label=\"Domains\">{domains}</td>\n\
         <td data-label=\"Last deploy\">{deploy}</td>\n\
         <td data-label=\"HTTPS\">{tls}</td>\n\
         <td data-label=\"DNS\">{dns}</td>\n\
         <td data-label=\"Baseline\">{baseline}</td>\n\
         <td data-label=\"Code\">{drift}</td>\n\
         <td data-label=\"Defined in\">{defined}</td>\n\
         </tr>\n",
        id = utf8_percent_encode(&site.id, PATH),
        name = esc(&site.name),
        kind = site.kind.words(),
        change = change,
        venture = venture_text(site),
        domains = domains_text(site),
        deploy = deploy_text(site),
        tls = tls_span(site),
        dns = dns_span(site),
        baseline = baseline_text(site),
        drift = drift_span(site),
        defined = defined_link(terraform, site.defined_at.as_ref()),
    )
}

/// The venture column; an empty venture is an em dash, like an empty domain list.
fn venture_text(site: &Site) -> String {
    if site.venture.trim().is_empty() {
        return "<span class=\"unknown\">—</span>".to_owned();
    }
    esc(&site.venture)
}

/// One site: status summary, resources, deploy history, and the exact
/// Terraform file and line it is defined at. `None` when no site in the
/// snapshot has this id — routing never guesses.
#[must_use]
pub fn render_site(snapshot: &Fleet, id: &str) -> Option<String> {
    let site = snapshot.sites.iter().find(|candidate| candidate.id == id)?;
    let terraform = snapshot.terraform.as_ref();
    let failing = site
        .baseline
        .as_ref()
        .filter(|baseline| !baseline.failing.is_empty())
        .map(|baseline| {
            format!(
                "<ul class=\"failing\">\n{items}</ul>\n",
                items = baseline
                    .failing
                    .iter()
                    .map(|check| format!("<li>{}</li>", esc(check)))
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
        })
        .unwrap_or_default();
    let dns = site
        .dns
        .as_ref()
        .and_then(|dns| dns.note.as_deref())
        .map(|note| format!("{} <span class=\"unknown\">{}</span>", dns_span(site), esc(note)))
        .unwrap_or_else(|| dns_span(site));
    let body = format!(
        "<main id=\"main\">\n\
         <p><a href=\"/console/fleet\">&larr; All sites</a></p>\n\
         <h1>{name}</h1>\n<p class=\"meta\">{kind} · {venture} · in {account}</p>\n\
         <dl class=\"summary\">\n\
         <dt>HTTPS</dt><dd>{tls}</dd>\n\
         <dt>DNS</dt><dd>{dns}</dd>\n\
         <dt>Baseline</dt><dd>{baseline}{failing}</dd>\n\
         <dt>Code</dt><dd>{drift}</dd>\n\
         </dl>\n\
         <h2>Defined in</h2>\n\
         <p>{defined}{repo}</p>\n\
         <h2>Resources</h2>\n<ul class=\"plain\">\n{resources}</ul>\n\
         <h2>Deploys</h2>\n<ul class=\"plain\">\n{deploys}</ul>\n\
         </main>\n",
        name = esc(&site.name),
        kind = site.kind.words(),
        venture = venture_text(site),
        account = esc(&snapshot.account),
        tls = tls_span(site),
        dns = dns,
        baseline = baseline_text(site),
        failing = failing,
        drift = drift_span(site),
        defined = defined_link(terraform, site.defined_at.as_ref()),
        repo =
            terraform.map(|terraform| format!(" in {}", esc(&terraform.repo))).unwrap_or_default(),
        resources = resources_list(site, terraform),
        deploys = deploys_list(site),
    );
    Some(signed_in_layout(&site.name, &body))
}

/// The one small-page layout (empty state and every error): title, plain
/// message, optional link.
pub(crate) fn notice_page(title: &str, message: &str, link: Option<(&str, &str)>) -> String {
    let link = link
        .map(|(href, text)| {
            format!("<p><a href=\"{href}\">{text}</a></p>", href = esc(href), text = esc(text))
        })
        .unwrap_or_default();
    layout(
        title,
        &format!(
            "<main id=\"main\">\n<div class=\"notice\">\n<h1>{title}</h1>\n<p>{message}</p>\n\
             {link}</div>\n</main>\n",
            title = esc(title),
            message = esc(message),
        ),
    )
}

/// [`layout`] for a signed-in page: the bar carries the sign-out button, a
/// form posting to `/console/logout` (a POST, so a link elsewhere cannot
/// sign anyone out; the worker's origin guard checks it is same-origin).
pub(crate) fn signed_in_layout(title: &str, body: &str) -> String {
    layout_with(title, body, SIGN_OUT)
}

const SIGN_OUT: &str = "<form class=\"signout\" method=\"post\" action=\"/console/logout\">\
     <button type=\"submit\">Sign out</button></form>";

/// The one layout every console page shares: fonts, the inlined stylesheet,
/// a skip link, the wordmark bar.
fn layout(title: &str, body: &str) -> String {
    layout_with(title, body, "")
}

fn layout_with(title: &str, body: &str, bar_extra: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title} · Keep Shipping fleet</title>\n\
         <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n\
         <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n\
         <link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400;12..96,700&amp;family=DM+Mono:wght@400;500&amp;display=swap\">\n\
         <style>\n{style}</style>\n\
         </head>\n<body>\n\
         <a class=\"skip\" href=\"#main\">Skip to content</a>\n\
         <header class=\"bar\"><span class=\"wordmark\">Keep Shipping</span>\
         <span class=\"section\">Fleet console</span>{bar_extra}</header>\n\
         {body}</body>\n</html>\n",
        title = esc(title),
        style = STYLE,
    )
}

/// The bearer token in an `Authorization` header, if the scheme is Bearer
/// and the token is not blank.
#[must_use]
pub fn bearer_token(header: Option<&str>) -> Option<String> {
    let (scheme, token) = header?.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

/// The value of one cookie out of a `Cookie` header; names compare
/// case-sensitively (RFC 6265), and later duplicates win.
#[must_use]
pub fn cookie_value(header: Option<&str>, name: &str) -> Option<String> {
    header?
        .split(';')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key.trim() == name).then(|| value.trim().to_owned())
        })
        .next_back()
}

/// Whether `email` is on the comma-separated allowlist: case-insensitive,
/// trimmed, never a substring match.
#[must_use]
pub fn email_allowed(email: &str, allowlist: &str) -> bool {
    let email = email.trim();
    !email.is_empty() && allowlist.split(',').any(|entry| entry.trim().eq_ignore_ascii_case(email))
}

fn domains_text(site: &Site) -> String {
    if site.domains.is_empty() {
        return "<span class=\"unknown\">—</span>".to_owned();
    }
    site.domains.iter().map(|domain| esc(domain)).collect::<Vec<_>>().join(", ")
}

fn deploy_text(site: &Site) -> String {
    match site.deploys.first() {
        Some(deploy) => format!(
            "<code>{short}</code> {when} · by {by}",
            short = esc(short(&deploy.commit)),
            when = esc(&fmt_time(&deploy.at)),
            by = esc(&deploy.by),
        ),
        None => "<span class=\"unknown\">Never deployed</span>".to_owned(),
    }
}

fn deploys_list(site: &Site) -> String {
    if site.deploys.is_empty() {
        return "<li class=\"unknown\">Never deployed</li>".to_owned();
    }
    site.deploys
        .iter()
        .map(|deploy| {
            format!(
                "<li><code>{short}</code> · {when} · by {by}</li>",
                short = esc(short(&deploy.commit)),
                when = esc(&fmt_time(&deploy.at)),
                by = esc(&deploy.by),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn resources_list(site: &Site, terraform: Option<&Terraform>) -> String {
    if site.resources.is_empty() {
        return "<li class=\"unknown\">None recorded</li>".to_owned();
    }
    site.resources
        .iter()
        .map(|resource| {
            format!(
                "<li>{kind} <strong>{name}</strong> — {defined}</li>",
                kind = esc(&plain_kind(&resource.kind)),
                name = esc(&resource.name),
                defined = defined_link(terraform, Some(&resource.defined_at)),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn baseline_text(site: &Site) -> String {
    match site.baseline.as_ref() {
        Some(baseline) => format!("{}/100", baseline.score),
        None => "<span class=\"unknown\">Not checked yet</span>".to_owned(),
    }
}

fn tls_span(site: &Site) -> String {
    match site.tls.as_ref().map(|tls| tls.status) {
        Some(TlsStatus::Ok) => span("ok", "Secure"),
        Some(TlsStatus::Expiring) => span("warn", "Expiring soon"),
        Some(TlsStatus::Failing) => span("bad", "Failing"),
        Some(TlsStatus::Unknown) | None => span("unknown", "Not checked yet"),
    }
}

fn dns_span(site: &Site) -> String {
    match site.dns.as_ref().map(|dns| dns.status) {
        Some(DnsStatus::Ok) => span("ok", "Healthy"),
        Some(DnsStatus::Problem) => span("bad", "Problem"),
        Some(DnsStatus::Unknown) | None => span("unknown", "Not checked yet"),
    }
}

fn drift_span(site: &Site) -> String {
    match site.drift {
        Some(Drift::InSync) => span("ok", "Matches code"),
        Some(Drift::Drifted) => span("bad", "Changed outside code"),
        Some(Drift::Unknown) | None => span("unknown", "Not checked yet"),
    }
}

fn span(class: &str, words: &str) -> String {
    format!("<span class=\"status {class}\">{words}</span>")
}

/// A site needs attention when a checked dimension is not fine; an
/// unchecked one does not count, or a fresh account alarms forever.
fn needs_attention(site: &Site) -> bool {
    matches!(
        site.tls.as_ref().map(|tls| tls.status),
        Some(TlsStatus::Expiring | TlsStatus::Failing)
    ) || matches!(site.dns.as_ref().map(|dns| dns.status), Some(DnsStatus::Problem))
        || site.drift == Some(Drift::Drifted)
}

/// The GitHub URL of a file at a line, or `None` when the path cannot be
/// a safe link: a `.` or `..` segment would normalise the address out of
/// the repo, so malformed snapshot data loses its link rather than lying.
fn blob_url(terraform: &Terraform, at: &Location) -> Option<String> {
    let path = at.path.trim_start_matches('/');
    if path.split('/').any(|segment| segment == "." || segment == "..") {
        return None;
    }
    Some(format!(
        "https://github.com/{repo}/blob/{rev}/{path}#L{line}",
        repo = utf8_percent_encode(terraform.repo.trim_matches('/'), PATH),
        rev = utf8_percent_encode(terraform.revision.trim_matches('/'), PATH),
        path = utf8_percent_encode(path, PATH),
        line = at.line,
    ))
}

/// The "Defined in" link: the exact file and line on GitHub, plain text when
/// [`blob_url`] would not make a safe address of the snapshot, and a
/// "not managed" note when there is no Terraform to link to.
fn defined_link(terraform: Option<&Terraform>, at: Option<&Location>) -> String {
    let (Some(terraform), Some(at)) = (terraform, at) else {
        return "<span class=\"unknown\">Not managed by Terraform yet</span>".to_owned();
    };
    match blob_url(terraform, at) {
        Some(url) => format!(
            "<a href=\"{href}\" title=\"{path}\">{file}</a>",
            href = esc(&url),
            path = esc(&at.path),
            file = esc(&file_at(at)),
        ),
        None => format!("<span class=\"unknown\">{}</span>", esc(&file_at(at))),
    }
}

/// `main.tf:12` — the short link text; the full path is the title.
fn file_at(at: &Location) -> String {
    format!("{}:{}", at.path.rsplit('/').next().unwrap_or_default(), at.line)
}

/// Terraform resource kinds in plain words; unknown kinds keep their
/// provider prefix stripped and underscores spelled out.
fn plain_kind(kind: &str) -> String {
    let words = match kind {
        "cloudflare_dns_record" => "DNS record",
        "cloudflare_zone" => "Domain",
        "cloudflare_pages_project" => "Pages site",
        "cloudflare_worker" | "cloudflare_worker_script" => "Worker",
        "cloudflare_r2_bucket" => "R2 bucket",
        "cloudflare_kv_namespace" => "KV namespace",
        other => return other.trim_start_matches("cloudflare_").replace('_', " "),
    };
    words.to_owned()
}

/// `2026-10-08T17:42:00Z` → `2026-10-08 17:42 UTC`; anything not shaped
/// like an ISO timestamp is shown as-is rather than reformatted into a lie.
fn fmt_time(iso: &str) -> String {
    let Some((day, time)) = iso.split_once('T') else {
        return iso.to_owned();
    };
    if day.len() == 10 && time.len() >= 5 && day.is_char_boundary(10) && time.is_char_boundary(5) {
        format!("{day} {} UTC", &time[..5])
    } else {
        iso.to_owned()
    }
}

/// The short commit sha the page shows, unlinked in DM Mono — the snapshot
/// carries no repository for the app repos, so there is nowhere honest to
/// link it.
fn short(commit: &str) -> &str {
    commit.get(..7).unwrap_or(commit)
}

/// Escapes a value for text content and attribute values; every snapshot
/// string passes through here before it reaches the page.
pub(crate) fn esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}
