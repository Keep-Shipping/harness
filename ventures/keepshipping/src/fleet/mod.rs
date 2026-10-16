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
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};

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

/// Site ids in an `/console/fleet/<id>` link: [`PATH`] plus `/`, which a
/// Pages branch can carry (`feature/x`) and the route would otherwise read
/// as a deeper path. The route percent-decodes it back.
const ID: &AsciiSet = &PATH.add(b'/');

/// The Workers environment suffixes a script name can end in (`-staging`).
pub const ENVIRONMENTS: [&str; 4] = ["staging", "test", "dev", "preview"];

/// Splits a Worker script name into its group (`tickets-api`) and its
/// environment (`staging`) when it ends in one of [`ENVIRONMENTS`]; a name
/// with no such suffix, or nothing before it, is its own group.
#[must_use]
pub fn split_environment(name: &str) -> (&str, Option<&'static str>) {
    for environment in ENVIRONMENTS {
        if let Some(base) = name.strip_suffix(environment).and_then(|rest| rest.strip_suffix('-'))
            && !base.is_empty()
        {
            return (base, Some(environment));
        }
    }
    (name, None)
}

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
    /// The environment the site serves: a Worker's `staging`/`test`/`dev`/
    /// `preview` suffix, a Pages preview's branch, or `production` when its
    /// group has other environments. Absent for a lone site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tls {
    pub status: TlsStatus,
    /// Why the state is unknown, in plain words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
/// One deploy of the site. `commit` may be empty (a Worker's last change
/// known only by its modified time). `by` is the trigger as the source
/// reports it (`ad_hoc`, `github:push`, `upload`); the page says it in words.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deploy {
    pub commit: String,
    pub at: String,
    pub by: String,
    /// The git branch a Pages deployment was built from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// The commit message (Pages) or the deploy message (Workers), first
    /// line shown, truncated on the page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// What `commit` names.
    #[serde(default)]
    pub refers_to: DeployRef,
}

/// What a deploy's `commit` names, which sets how much of it the page shows
/// and how it is labelled.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeployRef {
    /// A git commit: its 7-character hash.
    #[default]
    Commit,
    /// A Worker version id: 8 characters.
    Version,
    /// A Pages deployment id with no commit behind it (a Wrangler upload):
    /// 8 characters, labelled "upload".
    Upload,
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
    sites.sort_by_key(|&site| sort_key(site));
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
        .map(|site| site_row(site, snapshot.terraform.as_ref(), &snapshot.generated_at))
        .collect::<Vec<_>>()
        .join("\n");
    let terraform = match &snapshot.terraform {
        Some(terraform) => format!(
            "Terraform {repo} at <code>{rev}</code>",
            repo = esc(&terraform.repo),
            rev = esc(short(&terraform.revision, 7)),
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
        // The snapshot's own time is its reference, so its relative part is
        // "just now" on this page; the deploy times are measured from it.
        when = time_html(&snapshot.generated_at, &snapshot.generated_at),
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
fn site_row(site: &Site, terraform: Option<&Terraform>, reference: &str) -> String {
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
         <span class=\"badge\">{kind}</span>{environment}{change}</th>\n\
         <td data-label=\"Venture\">{venture}</td>\n\
         <td data-label=\"Domains\">{domains}</td>\n\
         <td data-label=\"Last deploy\">{deploy}</td>\n\
         <td data-label=\"HTTPS\">{tls}</td>\n\
         <td data-label=\"DNS\">{dns}</td>\n\
         <td data-label=\"Baseline\">{baseline}</td>\n\
         <td data-label=\"Code\">{drift}</td>\n\
         <td data-label=\"Defined in\">{defined}</td>\n\
         </tr>\n",
        id = utf8_percent_encode(&site.id, ID),
        name = esc(&site.name),
        kind = site.kind.words(),
        environment = environment_badge(site),
        change = change,
        venture = venture_text(site),
        domains = domains_text(site),
        deploy = deploy_text(site, reference),
        tls = tls_span(site),
        dns = dns_span(site),
        baseline = baseline_text(site, terraform),
        drift = drift_span(site, terraform),
        defined = defined_link(terraform, site.defined_at.as_ref()),
    )
}

/// The small environment label after a site's name; empty for a lone site.
fn environment_badge(site: &Site) -> String {
    match site.environment.as_deref() {
        Some(environment) => format!(" <span class=\"badge env\">{}</span>", esc(environment)),
        None => String::new(),
    }
}

/// The index's order: venture, then the group (a Worker's base name, so its
/// staging and test rows sit next to it), production or a lone site before
/// the other environments, then environment, name and id for a stable order.
fn sort_key(site: &Site) -> (String, String, u8, String, String, String) {
    let rank = u8::from(!matches!(site.environment.as_deref(), None | Some("production")));
    (
        site.venture.clone(),
        group_name(site).to_owned(),
        rank,
        site.environment.clone().unwrap_or_default(),
        site.name.clone(),
        site.id.clone(),
    )
}

/// The name a site groups under: a Worker's script name without its
/// environment suffix; every other site's name as it is.
fn group_name(site: &Site) -> &str {
    match site.kind {
        Kind::Worker => split_environment(&site.name).0,
        Kind::Zone | Kind::Pages => &site.name,
    }
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
    let body = format!(
        "<main id=\"main\">\n\
         <p><a href=\"/console/fleet\">&larr; All sites</a></p>\n\
         <h1>{name}</h1>\n<p class=\"meta\">{kind}{environment} · {venture} · in {account}</p>\n\
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
        environment = site
            .environment
            .as_deref()
            .map(|environment| format!(" · {}", esc(environment)))
            .unwrap_or_default(),
        venture = venture_text(site),
        account = esc(&snapshot.account),
        tls = tls_span(site),
        dns = dns_span(site),
        baseline = baseline_text(site, terraform),
        failing = failing,
        drift = drift_span(site, terraform),
        defined = defined_link(terraform, site.defined_at.as_ref()),
        repo =
            terraform.map(|terraform| format!(" in {}", esc(&terraform.repo))).unwrap_or_default(),
        resources = resources_list(site, terraform),
        deploys = deploys_list(site, &snapshot.generated_at),
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
    layout_with(title, body, &format!("{NAV}{SIGN_OUT}"))
}

/// The console's own pages, on every signed-in page's bar.
const NAV: &str = "<nav class=\"consolenav\" aria-label=\"Console\">\
     <a href=\"/console/fleet\">Sites</a>\
     <a href=\"/console/connect/cloudflare\">Cloudflare connection</a></nav>";

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
         <header class=\"bar\"><a class=\"wordmark\" href=\"/console/fleet\">Keep Shipping</a>\
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
    let Some(main) = main_domain(&site.domains) else {
        return "<span class=\"unknown\">—</span>".to_owned();
    };
    let rest: Vec<String> =
        site.domains.iter().filter(|domain| *domain != main).map(|domain| esc(domain)).collect();
    if rest.is_empty() {
        return esc(main);
    }
    format!(
        "{main}<details class=\"more\"><summary>+{count} more</summary>{rest}</details>",
        main = esc(main),
        count = rest.len(),
        rest = rest.join("<br>"),
    )
}

/// The domain a person means by the site: a custom domain over the
/// platform's own (`*.pages.dev`, `*.workers.dev`), the apex over `www.`,
/// then the shortest; the listed order breaks ties.
#[must_use]
pub fn main_domain(domains: &[String]) -> Option<&String> {
    let platform =
        |domain: &str| domain.ends_with(".pages.dev") || domain.ends_with(".workers.dev");
    domains
        .iter()
        .enumerate()
        .min_by_key(|(index, domain)| {
            (platform(domain), domain.starts_with("www."), domain.len(), *index)
        })
        .map(|(_, domain)| domain)
}

fn deploy_text(site: &Site, reference: &str) -> String {
    match site.deploys.first() {
        Some(deploy) => deploy_line(deploy, reference),
        None => "<span class=\"unknown\">Never deployed</span>".to_owned(),
    }
}

/// One deploy in words, `·`-separated: what was deployed (the commit,
/// version or upload id), the branch, the message, the trigger in words, and
/// the time. Parts the snapshot does not carry are left out.
fn deploy_line(deploy: &Deploy, reference: &str) -> String {
    let mut parts = Vec::new();
    if let Some(what) = deployed_ref(deploy) {
        parts.push(what);
    }
    if let Some(branch) = deploy.branch.as_deref().map(str::trim).filter(|b| !b.is_empty()) {
        parts.push(esc(branch));
    }
    if let Some(message) = deploy.message.as_deref().map(message_line).filter(|m| !m.is_empty()) {
        parts.push(esc(&message));
    }
    if !deploy.by.trim().is_empty() {
        parts.push(esc(&trigger_words(&deploy.by)));
    }
    parts.push(time_html(&deploy.at, reference));
    parts.join(" · ")
}

/// The id a deploy names, short, with its label: `4a1f9c2` for a commit,
/// `version 3f9a1c2b`, `upload 0b1c2d3e`. `None` when there is no id.
fn deployed_ref(deploy: &Deploy) -> Option<String> {
    if deploy.commit.trim().is_empty() {
        return None;
    }
    let (len, label) = match deploy.refers_to {
        DeployRef::Commit => (7, ""),
        DeployRef::Version => (8, "version "),
        DeployRef::Upload => (8, "upload "),
    };
    Some(format!("{label}<code>{}</code>", esc(short(&deploy.commit, len))))
}

/// The trigger in words. Pages: `ad_hoc` is an upload with Wrangler,
/// `github:push` a git push. Workers: `upload` and `deployment` are a
/// `wrangler deploy`. Anything else reads verbatim.
#[must_use]
pub fn trigger_words(trigger: &str) -> String {
    match trigger {
        "ad_hoc" => "uploaded with Wrangler".to_owned(),
        "github:push" => "git push".to_owned(),
        "upload" | "deployment" => "wrangler deploy".to_owned(),
        other => other.to_owned(),
    }
}

/// The first line of a commit or deploy message, at most 60 characters
/// (the 60th replaced by an ellipsis when cut).
#[must_use]
pub fn message_line(message: &str) -> String {
    const MAX: usize = 60;
    let first = message.lines().next().unwrap_or_default().trim();
    if first.chars().count() <= MAX {
        first.to_owned()
    } else {
        format!("{}…", first.chars().take(MAX - 1).collect::<String>())
    }
}

fn deploys_list(site: &Site, reference: &str) -> String {
    if site.deploys.is_empty() {
        return "<li class=\"unknown\">Never deployed</li>".to_owned();
    }
    site.deploys
        .iter()
        .map(|deploy| format!("<li>{}</li>", deploy_line(deploy, reference)))
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

/// Shown in place of "Not checked yet" for the baseline and code cells of a
/// snapshot with no Terraform behind it: those checks come from Terraform.
const NEEDS_TERRAFORM: &str = "Needs Terraform";
const NEEDS_TERRAFORM_TITLE: &str =
    "Baseline and code state come from the Terraform checks, which are not connected yet";

fn baseline_text(site: &Site, terraform: Option<&Terraform>) -> String {
    match (site.baseline.as_ref(), terraform) {
        (Some(baseline), _) => format!("{}/100", baseline.score),
        (None, None) => needs_terraform(),
        (None, Some(_)) => "<span class=\"unknown\">Not checked yet</span>".to_owned(),
    }
}

fn needs_terraform() -> String {
    format!("<span class=\"unknown\" title=\"{NEEDS_TERRAFORM_TITLE}\">{NEEDS_TERRAFORM}</span>")
}

fn tls_span(site: &Site) -> String {
    let Some(tls) = site.tls.as_ref() else {
        return span("unknown", "Not checked yet");
    };
    let (class, words) = match tls.status {
        TlsStatus::Ok => ("ok", "Secure"),
        TlsStatus::Expiring => ("warn", "Expiring soon"),
        TlsStatus::Failing => ("bad", "Failing"),
        TlsStatus::Unknown => ("unknown", "Not checked yet"),
    };
    with_note(span(class, words), tls.note.as_deref())
}

fn dns_span(site: &Site) -> String {
    let Some(dns) = site.dns.as_ref() else {
        return span("unknown", "Not checked yet");
    };
    let (class, words) = match dns.status {
        DnsStatus::Ok => ("ok", "Healthy"),
        DnsStatus::Problem => ("bad", "Problem"),
        DnsStatus::Unknown => ("unknown", "Not checked yet"),
    };
    with_note(span(class, words), dns.note.as_deref())
}

/// A status followed by its plain-words note, when there is one.
fn with_note(status: String, note: Option<&str>) -> String {
    match note.map(str::trim).filter(|note| !note.is_empty()) {
        Some(note) => format!("{status} <span class=\"unknown\">{}</span>", esc(note)),
        None => status,
    }
}

fn drift_span(site: &Site, terraform: Option<&Terraform>) -> String {
    match site.drift {
        Some(Drift::InSync) => span("ok", "Matches code"),
        Some(Drift::Drifted) => span("bad", "Changed outside code"),
        _ if terraform.is_none() => needs_terraform(),
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

/// An RFC 3339 timestamp (fractional seconds and `Z` included) in readable
/// words, then how long before `reference` it was, in plain words:
/// `<time datetime="…">16 Oct 2026, 09:24 UTC</time> · 3 days ago`. A
/// `reference` that does not parse leaves the relative part out; a timestamp
/// that does not parse is shown as it came.
#[must_use]
pub(crate) fn time_html(iso: &str, reference: &str) -> String {
    let Ok(at) = OffsetDateTime::parse(iso, &Rfc3339) else {
        return esc(iso);
    };
    let at = at.to_offset(UtcOffset::UTC);
    let relative = OffsetDateTime::parse(reference, &Rfc3339)
        .map(|now| format!(" · {}", ago(at, now.to_offset(UtcOffset::UTC))))
        .unwrap_or_default();
    format!(
        "<time datetime=\"{datetime}\">{words}</time>{relative}",
        datetime = esc(iso),
        words = esc(&words(at)),
        relative = esc(&relative),
    )
}

/// `16 Oct 2026, 09:24 UTC` for a time already in UTC.
fn words(at: OffsetDateTime) -> String {
    at.format(format_description!(
        "[day padding:none] [month repr:short] [year], [hour]:[minute] UTC"
    ))
    .unwrap_or_default()
}

/// The time from `now` to `at` in plain words: `just now` within a minute
/// either side, `3 hours ago`, `1 day ago`, `in 2 hours` for a future time.
#[must_use]
pub fn ago(at: OffsetDateTime, now: OffsetDateTime) -> String {
    let seconds = (now - at).whole_seconds();
    if seconds.abs() < 60 {
        return "just now".to_owned();
    }
    let magnitude = seconds.abs();
    let (count, unit) = match magnitude {
        0..3600 => (magnitude / 60, "minute"),
        3600..86_400 => (magnitude / 3600, "hour"),
        _ => (magnitude / 86_400, "day"),
    };
    let plural = if count == 1 { "" } else { "s" };
    if seconds > 0 {
        format!("{count} {unit}{plural} ago")
    } else {
        format!("in {count} {unit}{plural}")
    }
}

/// The short id the page shows, unlinked in DM Mono — a commit sha, a Worker
/// version, or a Pages deployment id, each cut to `len` characters.
fn short(id: &str, len: usize) -> &str {
    id.get(..len).unwrap_or(id)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn site(id: &str, name: &str, kind: Kind, environment: Option<&str>) -> Site {
        Site {
            id: id.to_owned(),
            name: name.to_owned(),
            kind,
            environment: environment.map(str::to_owned),
            venture: "Factory Zero".to_owned(),
            domains: Vec::new(),
            defined_at: None,
            deploys: Vec::new(),
            tls: None,
            dns: None,
            baseline: None,
            drift: None,
            resources: Vec::new(),
        }
    }

    fn deploy(commit: &str, by: &str, refers_to: DeployRef) -> Deploy {
        Deploy {
            commit: commit.to_owned(),
            at: "2026-10-08T17:42:00Z".to_owned(),
            by: by.to_owned(),
            branch: None,
            message: None,
            refers_to,
        }
    }

    #[test]
    fn a_timestamp_reads_in_words_with_its_relative_part() {
        let html = time_html("2026-10-16T09:24:05.123456Z", "2026-10-19T09:24:06Z");
        assert_eq!(
            html,
            "<time datetime=\"2026-10-16T09:24:05.123456Z\">16 Oct 2026, 09:24 UTC</time> · 3 days ago"
        );
        // An offset is converted to UTC before it is read.
        let offset = time_html("2026-10-16T11:24:00+02:00", "2026-10-16T09:30:00Z");
        assert!(offset.contains(">16 Oct 2026, 09:24 UTC</time>"), "{offset}");
        assert!(offset.ends_with("· 6 minutes ago"), "{offset}");
    }

    #[test]
    fn a_timestamp_that_does_not_parse_is_shown_as_it_came() {
        assert_eq!(time_html("not-a-date", "2026-10-16T09:24:00Z"), "not-a-date");
        assert_eq!(
            time_html("2026-10-16 09:24 UTC", "2026-10-16T09:24:00Z"),
            "2026-10-16 09:24 UTC"
        );
        // A reference that does not parse leaves only the readable part.
        let no_reference = time_html("2026-10-16T09:24:00Z", "later");
        assert_eq!(
            no_reference,
            "<time datetime=\"2026-10-16T09:24:00Z\">16 Oct 2026, 09:24 UTC</time>"
        );
    }

    #[test]
    fn the_relative_part_reads_in_plain_words() {
        let at = OffsetDateTime::parse("2026-10-16T09:00:00Z", &Rfc3339).unwrap();
        let after = |seconds: i64| at + time::Duration::seconds(seconds);
        assert_eq!(ago(at, after(30)), "just now");
        assert_eq!(ago(at, after(-30)), "just now");
        assert_eq!(ago(at, after(60)), "1 minute ago");
        assert_eq!(ago(at, after(2 * 3600)), "2 hours ago");
        assert_eq!(ago(at, after(3600)), "1 hour ago");
        assert_eq!(ago(at, after(3 * 86_400)), "3 days ago");
        assert_eq!(ago(at, after(86_400)), "1 day ago");
        assert_eq!(ago(at, after(-7200)), "in 2 hours");
    }

    #[test]
    fn a_trigger_is_said_in_words_and_unknown_ones_stay_verbatim() {
        assert_eq!(trigger_words("ad_hoc"), "uploaded with Wrangler");
        assert_eq!(trigger_words("github:push"), "git push");
        assert_eq!(trigger_words("upload"), "wrangler deploy");
        assert_eq!(trigger_words("deployment"), "wrangler deploy");
        assert_eq!(trigger_words("deploy_hook"), "deploy_hook");
        assert_eq!(trigger_words("ada"), "ada");
    }

    #[test]
    fn a_message_is_its_first_line_cut_at_sixty_characters() {
        assert_eq!(message_line("fix the form\n\nlong body"), "fix the form");
        assert_eq!(message_line("  padded  "), "padded");
        let sixty = "a".repeat(60);
        assert_eq!(message_line(&sixty), sixty);
        let long = "é".repeat(61);
        let cut = message_line(&long);
        assert_eq!(cut.chars().count(), 60);
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn a_split_environment_names_only_a_real_suffix_on_a_real_base() {
        assert_eq!(split_environment("tickets-api-staging"), ("tickets-api", Some("staging")));
        assert_eq!(split_environment("tickets-api-test"), ("tickets-api", Some("test")));
        assert_eq!(split_environment("tickets-api-dev"), ("tickets-api", Some("dev")));
        assert_eq!(split_environment("tickets-api-preview"), ("tickets-api", Some("preview")));
        assert_eq!(split_environment("tickets-api"), ("tickets-api", None));
        // Not a whole `-suffix`, or nothing before it: no environment.
        assert_eq!(split_environment("latest"), ("latest", None));
        assert_eq!(split_environment("-test"), ("-test", None));
        assert_eq!(split_environment("tickets-testing"), ("tickets-testing", None));
    }

    #[test]
    fn a_deploy_names_its_commit_version_or_upload_with_the_right_length() {
        let line = |deploy: &Deploy| deployed_ref(deploy);
        assert_eq!(
            line(&deploy("4a1f9c2e7b3d", "git", DeployRef::Commit)).as_deref(),
            Some("<code>4a1f9c2</code>")
        );
        assert_eq!(
            line(&deploy("3f9a1c2b-0000", "", DeployRef::Version)).as_deref(),
            Some("version <code>3f9a1c2b</code>")
        );
        assert_eq!(
            line(&deploy("0b1c2d3e4f50", "ad_hoc", DeployRef::Upload)).as_deref(),
            Some("upload <code>0b1c2d3e</code>")
        );
        assert_eq!(deployed_ref(&deploy("", "", DeployRef::Commit)), None);
    }

    #[test]
    fn a_deploy_line_leaves_out_what_the_snapshot_does_not_carry() {
        let mut full = deploy("4a1f9c2e7b3d", "github:push", DeployRef::Commit);
        full.branch = Some("main".to_owned());
        full.message = Some("fix the form".to_owned());
        assert_eq!(
            deploy_line(&full, "2026-10-08T18:42:00Z"),
            "<code>4a1f9c2</code> · main · fix the form · git push · \
             <time datetime=\"2026-10-08T17:42:00Z\">8 Oct 2026, 17:42 UTC</time> · 1 hour ago"
        );
        // A modified time alone: no id, no trigger, just the time.
        let bare = Deploy {
            commit: String::new(),
            at: "2026-10-14T19:05:44.123Z".to_owned(),
            by: String::new(),
            branch: None,
            message: None,
            refers_to: DeployRef::Commit,
        };
        assert_eq!(
            deploy_line(&bare, "2026-10-14T20:05:45Z"),
            "<time datetime=\"2026-10-14T19:05:44.123Z\">14 Oct 2026, 19:05 UTC</time> · 1 hour ago"
        );
    }

    #[test]
    fn the_index_sorts_by_venture_then_group_then_production_first() {
        let mut other = site("w4", "other", Kind::Worker, None);
        other.venture = "Aardvark".to_owned();
        let mut sites = [
            site("w3", "tickets-api-test", Kind::Worker, Some("test")),
            site("w2", "tickets-api-staging", Kind::Worker, Some("staging")),
            site("w1", "tickets-api", Kind::Worker, Some("production")),
            site("p1", "kaje", Kind::Pages, None),
            site("p2", "kaje", Kind::Pages, Some("feature/x")),
            other,
        ];
        sites.sort_by_key(sort_key);
        let ids: Vec<&str> = sites.iter().map(|site| site.id.as_str()).collect();
        assert_eq!(ids, ["w4", "p1", "p2", "w1", "w2", "w3"]);
    }

    #[test]
    fn a_worker_groups_under_its_base_name_and_other_kinds_under_their_own() {
        assert_eq!(
            group_name(&site("w", "tickets-api-staging", Kind::Worker, Some("staging"))),
            "tickets-api"
        );
        assert_eq!(group_name(&site("p", "tickets-staging", Kind::Pages, None)), "tickets-staging");
        assert_eq!(group_name(&site("z", "example.com", Kind::Zone, None)), "example.com");
    }

    #[test]
    fn an_environment_shows_as_a_badge_only_when_there_is_one() {
        assert_eq!(environment_badge(&site("p", "kaje", Kind::Pages, None)), "");
        assert_eq!(
            environment_badge(&site("p", "kaje", Kind::Pages, Some("feature/x"))),
            " <span class=\"badge env\">feature/x</span>"
        );
    }

    #[test]
    fn a_missing_terraform_reads_as_needs_terraform_in_the_checked_cells() {
        let bare = site("z", "example.com", Kind::Zone, None);
        assert!(baseline_text(&bare, None).contains("Needs Terraform"));
        assert!(drift_span(&bare, None).contains("Needs Terraform"));
        assert!(baseline_text(&bare, None).contains("title="));
        // With Terraform, an unchecked cell is still just not checked yet.
        let terraform =
            Terraform { repo: "Factory-Zero/infra".to_owned(), revision: "abc".to_owned() };
        assert!(baseline_text(&bare, Some(&terraform)).contains("Not checked yet"));
        assert!(drift_span(&bare, Some(&terraform)).contains("Not checked yet"));
        // A checked value is shown as itself either way.
        let mut scored = bare.clone();
        scored.baseline = Some(Baseline { score: 92, failing: Vec::new() });
        assert_eq!(baseline_text(&scored, None), "92/100");
    }

    #[test]
    fn a_status_note_follows_its_status_escaped() {
        let mut bare = site("z", "example.com", Kind::Zone, None);
        bare.dns =
            Some(Dns { status: DnsStatus::Problem, note: Some("Zone is <pending>".to_owned()) });
        let cell = dns_span(&bare);
        assert!(cell.contains("Problem"));
        assert!(cell.ends_with("<span class=\"unknown\">Zone is &lt;pending&gt;</span>"), "{cell}");
    }

    #[test]
    fn a_site_id_with_a_slash_links_and_routes_back() {
        let mut preview = site("pages:acct:kaje:feature/x", "kaje", Kind::Pages, Some("feature/x"));
        preview.domains = vec!["feature-x.kaje.pages.dev".to_owned()];
        let row = site_row(&preview, None, "2026-10-16T09:00:00Z");
        assert!(row.contains("href=\"/console/fleet/pages:acct:kaje:feature%2Fx\""), "{row}");
        let Some(Route::Site(id)) = route("/console/fleet/pages:acct:kaje:feature%2Fx") else {
            panic!("the encoded id routes to its site");
        };
        assert_eq!(id, "pages:acct:kaje:feature/x");
    }
}
