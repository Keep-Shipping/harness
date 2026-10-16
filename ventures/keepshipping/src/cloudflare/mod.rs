//! The console's Cloudflare collector (issue #169): a read-only token the
//! operator pastes on the connect page becomes one `Fleet` snapshot in KV
//! (`fleet.json`). This module is the pure half: the Cloudflare response
//! shapes, the token template URL, the account choice, and the mapping to
//! [`crate::fleet::Fleet`]. The Workers glue (HTTP, D1, KV) is [`api`];
//! the token's encryption is [`seal`]; the connect page's HTML is [`page`].
//!
//! Only read endpoints are called. The mapping fills what the API gives:
//! zones, Pages projects and their latest deployment, Workers scripts and
//! their custom domains, and a zone's certificate status. Terraform
//! definitions, DNS health, baseline scores and drift are not available
//! from this API, so those fields stay empty and render as "not checked".

pub mod api;
pub mod page;
pub mod rollback;
pub mod seal;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;

use crate::fleet::{
    Deploy, DeployRef, Dns, DnsStatus, Fleet, Kind, Site, Tls, TlsStatus, split_environment,
};

/// The token's name on Cloudflare's form, and so on the token list.
pub const TOKEN_NAME: &str = "Keep Shipping console (read-only)";

/// The permission groups the token asks for, as `(key, type)` pairs in the
/// shape Cloudflare's template URL takes. Every one is a read; the keys are
/// from Cloudflare's permission reference (`zone`, `dns`,
/// `ssl_and_certificates`, `workers_scripts`, `page` for Pages, and
/// `account_settings`), listed in the docs at
/// <https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/>.
pub const PERMISSIONS: [(&str, &str); 12] = [
    ("zone", "read"),
    ("dns", "read"),
    ("ssl_and_certificates", "read"),
    ("workers_scripts", "read"),
    ("page", "read"),
    ("account_settings", "read"),
    ("zone_settings", "read"),
    ("d1", "read"),
    ("workers_r2", "read"),
    ("workers_kv_storage", "read"),
    ("workers_routes", "read"),
    ("email_routing_rules", "read"),
];

/// The plain-words names of [`PERMISSIONS`], in the same order, for the page.
pub const PERMISSION_WORDS: [&str; 12] = [
    "Zone Read",
    "DNS Read",
    "SSL and Certificates Read",
    "Workers Scripts Read",
    "Pages Read",
    "Account Settings Read",
    "Zone Settings Read",
    "D1 Read",
    "Workers R2 Storage Read",
    "Workers KV Storage Read",
    "Workers Routes Read",
    "Email Routing Rules Read",
];

/// The token name's encoding: everything but letters, digits and `-_.~`
/// (so the name reads as written in the docs' examples).
const NAME: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

/// Cloudflare's pre-filled user-token page. The `permissionGroupKeys` value
/// is the URL-encoded JSON array of `{"key", "type"}` objects, exactly as the
/// docs' template examples build it; `accountId=*&zoneId=all` is the docs'
/// user-token form.
#[must_use]
pub fn template_url() -> String {
    template_url_for(&PERMISSIONS, TOKEN_NAME)
}

/// [`template_url`] for another set of permission groups and token name
/// (the deploy token's, [`rollback::DEPLOY_PERMISSIONS`]).
#[must_use]
pub fn template_url_for(permissions: &[(&str, &str)], name: &str) -> String {
    let groups: Vec<serde_json::Value> = permissions
        .iter()
        .map(|(key, kind)| serde_json::json!({ "key": key, "type": kind }))
        .collect();
    let json = serde_json::Value::Array(groups).to_string();
    format!(
        "https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys={keys}&accountId=*&zoneId=all&name={name}",
        keys = utf8_percent_encode(&json, NON_ALPHANUMERIC),
        name = utf8_percent_encode(name, NAME),
    )
}

/// The envelope every Cloudflare v4 response wraps its payload in.
#[derive(Debug, Deserialize)]
pub struct Envelope<T> {
    #[serde(default)]
    pub success: bool,
    pub result: Option<T>,
    #[serde(default)]
    pub result_info: Option<ResultInfo>,
}

/// Pagination numbers, present on list endpoints.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ResultInfo {
    pub total_pages: Option<u32>,
}

/// `GET /user/tokens/verify` → `{"status": "active"}` for a usable token.
#[derive(Debug, Deserialize)]
pub struct Verify {
    pub status: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    /// `active`, `pending`, `initializing` or `moved` (Cloudflare's zone list).
    #[serde(default)]
    pub status: String,
}

/// One certificate pack of a zone; `status` is `active` for a served pack.
#[derive(Debug, Clone, Deserialize)]
pub struct CertificatePack {
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PagesProject {
    pub name: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub latest_deployment: Option<PagesDeployment>,
    /// The project's recent preview deployments (`env=preview`), read by the
    /// collector; the listing itself does not carry them.
    #[serde(default)]
    pub previews: Vec<PagesDeployment>,
}

/// A Pages deployment (`latest_deployment`, or one of the preview listing).
#[derive(Debug, Clone, Deserialize)]
pub struct PagesDeployment {
    pub id: String,
    #[serde(default)]
    pub created_on: String,
    #[serde(default)]
    pub deployment_trigger: Option<Trigger>,
    /// The deployment's own URL and its aliases (a preview's branch host).
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Trigger {
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub metadata: Option<TriggerMetadata>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TriggerMetadata {
    #[serde(default)]
    pub commit_hash: Option<String>,
    #[serde(default)]
    pub commit_message: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerScript {
    pub id: String,
    #[serde(default)]
    pub modified_on: Option<String>,
    #[serde(default)]
    pub etag: Option<String>,
    /// The deployment serving traffic, read by the collector (one call per
    /// script); absent when that read failed or the script never deployed.
    #[serde(default)]
    pub active: Option<WorkerDeployment>,
}

/// `GET …/workers/scripts/{script}/deployments` → `{"deployments": [...]}`,
/// newest first; the first is the deployment actively serving traffic.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkerDeployments {
    #[serde(default)]
    pub deployments: Vec<WorkerDeployment>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerDeployment {
    #[serde(default)]
    pub created_on: String,
    #[serde(default)]
    pub versions: Vec<WorkerVersion>,
    #[serde(default)]
    pub annotations: Option<WorkerAnnotations>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerVersion {
    pub version_id: String,
}

/// The deployment's annotations: the message and what triggered it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WorkerAnnotations {
    #[serde(rename = "workers/message", default)]
    pub message: Option<String>,
    #[serde(rename = "workers/triggered_by", default)]
    pub triggered_by: Option<String>,
}

/// One custom domain of a Worker: `service` is the script's name.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkerDomain {
    pub hostname: String,
    pub service: String,
}

/// A zone with its certificate packs, or `None` when that lookup failed.
#[derive(Debug, Clone)]
pub struct ZoneRecord {
    pub zone: Zone,
    pub certificates: Option<Vec<CertificatePack>>,
}

/// Everything one collection read, ready to map.
#[derive(Debug, Clone)]
pub struct Inventory {
    pub account: Account,
    pub zones: Vec<ZoneRecord>,
    pub pages: Vec<PagesProject>,
    pub scripts: Vec<WorkerScript>,
    pub worker_domains: Vec<WorkerDomain>,
    /// Listings that could not be read, in plain words.
    pub gaps: Vec<String>,
}

/// Why no account was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountError {
    /// The token sees no account at all.
    NoAccounts,
    /// `CF_ACCOUNT_ID` names an account the token cannot see.
    NotVisible,
}

/// The accounts to read: the one `CF_ACCOUNT_ID` names, else every account
/// the token lists.
pub fn pick_accounts<'a>(
    accounts: &'a [Account],
    wanted: Option<&str>,
) -> Result<Vec<&'a Account>, AccountError> {
    match wanted.map(str::trim).filter(|id| !id.is_empty()) {
        Some(id) => accounts
            .iter()
            .find(|account| account.id == id)
            .map(|account| vec![account])
            .ok_or(AccountError::NotVisible),
        None if accounts.is_empty() => Err(AccountError::NoAccounts),
        None => Ok(accounts.iter().collect()),
    }
}

/// One snapshot from several accounts' snapshots: every site, each already
/// labelled with its account; gaps prefixed with the account they are in
/// when there is more than one.
#[must_use]
pub fn merge(fleets: Vec<Fleet>, generated_at: &str) -> Fleet {
    let several = fleets.len() > 1;
    let account = match fleets.as_slice() {
        [one] => one.account.clone(),
        many => format!("{} Cloudflare accounts", many.len()),
    };
    let mut sites = Vec::new();
    let mut gaps = Vec::new();
    for fleet in fleets {
        gaps.extend(
            fleet
                .gaps
                .into_iter()
                .map(|gap| if several { format!("{}: {gap}", fleet.account) } else { gap }),
        );
        sites.extend(fleet.sites);
    }
    Fleet { account, generated_at: generated_at.to_owned(), terraform: None, sites, gaps }
}

/// Whether a verify answer is a usable token.
#[must_use]
pub fn token_is_active(verify: &Verify) -> bool {
    verify.status == "active"
}

/// Preview branches kept per Pages project: the newest deployment of each of
/// the most recent five branches. Bounds the page and the rows it adds.
pub const MAX_PREVIEW_BRANCHES: usize = 5;

/// Maps one collection to the snapshot the console renders. `generated_at`
/// is the RFC 3339 time of the collection. Sites are emitted zones first,
/// then Pages projects (each followed by its preview branches), then
/// Workers, each in the order the API listed them; the renderer sorts.
#[must_use]
pub fn fleet_from(inventory: &Inventory, generated_at: &str) -> Fleet {
    let account = &inventory.account;
    let mut sites = Vec::new();

    for record in &inventory.zones {
        sites.push(Site {
            id: format!("zone:{}", record.zone.id),
            name: record.zone.name.clone(),
            kind: Kind::Zone,
            environment: None,
            venture: account.name.clone(),
            domains: vec![record.zone.name.clone()],
            defined_at: None,
            deploys: Vec::new(),
            tls: Some(Tls { status: zone_tls(record), note: None }),
            dns: Some(zone_dns(record)),
            baseline: None,
            drift: None,
            resources: Vec::new(),
        });
    }

    for project in &inventory.pages {
        let previews = preview_branches(project.previews.clone());
        let domains = project.domains.clone();
        let (tls, dns) = domain_health(&domains, &inventory.zones);
        sites.push(Site {
            id: format!("pages:{}:{}", account.id, project.name),
            name: project.name.clone(),
            kind: Kind::Pages,
            environment: (!previews.is_empty()).then(|| "production".to_owned()),
            venture: account.name.clone(),
            domains,
            defined_at: None,
            deploys: project.latest_deployment.iter().filter_map(pages_deploy).collect(),
            tls,
            dns,
            baseline: None,
            drift: None,
            resources: Vec::new(),
        });
        for preview in previews {
            let Some(branch) = branch_of(&preview).map(str::to_owned) else {
                continue;
            };
            let domains = preview_domains(&preview);
            let (tls, dns) = domain_health(&domains, &inventory.zones);
            sites.push(Site {
                id: format!("pages:{}:{}:{}", account.id, project.name, branch),
                name: project.name.clone(),
                kind: Kind::Pages,
                environment: Some(branch),
                venture: account.name.clone(),
                domains,
                defined_at: None,
                deploys: pages_deploy(&preview).into_iter().collect(),
                tls,
                dns,
                baseline: None,
                drift: None,
                resources: Vec::new(),
            });
        }
    }

    for script in &inventory.scripts {
        let domains: Vec<String> = inventory
            .worker_domains
            .iter()
            .filter(|domain| domain.service == script.id)
            .map(|domain| domain.hostname.clone())
            .collect();
        let (tls, dns) = domain_health(&domains, &inventory.zones);
        let (_, suffix) = split_environment(&script.id);
        let environment = match suffix {
            Some(environment) => Some(environment.to_owned()),
            None if has_other_environments(&inventory.scripts, &script.id) => {
                Some("production".to_owned())
            }
            None => None,
        };
        sites.push(Site {
            id: format!("worker:{}:{}", account.id, script.id),
            name: script.id.clone(),
            kind: Kind::Worker,
            environment,
            venture: account.name.clone(),
            domains,
            defined_at: None,
            deploys: worker_deploy(script).into_iter().collect(),
            tls,
            dns,
            baseline: None,
            drift: None,
            resources: Vec::new(),
        });
    }

    Fleet {
        account: account.name.clone(),
        generated_at: generated_at.to_owned(),
        terraform: None,
        sites,
        gaps: inventory.gaps.clone(),
    }
}

/// Whether a Worker's group has any environment script besides `base` itself
/// (`tickets-api-staging` for `tickets-api`).
fn has_other_environments(scripts: &[WorkerScript], base: &str) -> bool {
    scripts.iter().any(|other| {
        let (group, environment) = split_environment(&other.id);
        environment.is_some() && group == base
    })
}

/// The newest deployment of each of the most recent [`MAX_PREVIEW_BRANCHES`]
/// branches, newest first. Deployments without a branch are not previews of
/// one. The Pages `created_on` times are RFC 3339 in one format, so they sort
/// as strings.
#[must_use]
pub fn preview_branches(mut deployments: Vec<PagesDeployment>) -> Vec<PagesDeployment> {
    deployments.sort_by(|a, b| b.created_on.cmp(&a.created_on));
    let mut kept: Vec<PagesDeployment> = Vec::new();
    for deployment in deployments {
        let Some(branch) = branch_of(&deployment) else {
            continue;
        };
        if kept.len() == MAX_PREVIEW_BRANCHES {
            break;
        }
        if kept.iter().all(|other| branch_of(other) != Some(branch)) {
            kept.push(deployment);
        }
    }
    kept
}

/// The branch a Pages deployment was built from, when its trigger says so.
fn branch_of(deployment: &PagesDeployment) -> Option<&str> {
    deployment
        .deployment_trigger
        .as_ref()
        .and_then(|trigger| trigger.metadata.as_ref())
        .and_then(|metadata| metadata.branch.as_deref())
        .map(str::trim)
        .filter(|branch| !branch.is_empty())
}

/// A preview's hosts: its aliases, else its own URL, without the scheme.
fn preview_domains(deployment: &PagesDeployment) -> Vec<String> {
    if deployment.aliases.is_empty() {
        return deployment.url.iter().map(|url| host_of(url)).collect();
    }
    deployment.aliases.iter().map(|alias| host_of(alias)).collect()
}

fn host_of(url: &str) -> String {
    url.trim().trim_start_matches("https://").trim_end_matches('/').to_owned()
}

/// One Pages deployment as a deploy row. Its id is the short label when the
/// deployment has no commit behind it (a Wrangler upload). `None` without a
/// creation time: there is no date to show.
fn pages_deploy(deployment: &PagesDeployment) -> Option<Deploy> {
    if deployment.created_on.is_empty() {
        return None;
    }
    let trigger = deployment.deployment_trigger.as_ref();
    let metadata = trigger.and_then(|trigger| trigger.metadata.as_ref());
    let commit = metadata
        .and_then(|metadata| metadata.commit_hash.clone())
        .filter(|hash| !hash.trim().is_empty());
    let (commit, refers_to) = match commit {
        Some(hash) => (hash, DeployRef::Commit),
        None => (deployment.id.clone(), DeployRef::Upload),
    };
    Some(Deploy {
        commit,
        at: deployment.created_on.clone(),
        by: trigger
            .and_then(|trigger| trigger.kind.clone())
            .unwrap_or_else(|| "Cloudflare Pages".to_owned()),
        branch: metadata.and_then(|metadata| metadata.branch.clone()),
        message: metadata.and_then(|metadata| metadata.commit_message.clone()),
        refers_to,
    })
}

/// A Worker's last deploy: its active deployment's version, date, message and
/// trigger when the collector read it; otherwise the script's modified time,
/// with no version to name. `None` when there is neither.
fn worker_deploy(script: &WorkerScript) -> Option<Deploy> {
    match &script.active {
        Some(active) if !active.created_on.is_empty() => {
            let annotations = active.annotations.clone().unwrap_or_default();
            Some(Deploy {
                commit: active
                    .versions
                    .first()
                    .map(|version| version.version_id.clone())
                    .unwrap_or_default(),
                at: active.created_on.clone(),
                by: annotations.triggered_by.unwrap_or_default(),
                branch: None,
                message: annotations.message,
                refers_to: DeployRef::Version,
            })
        }
        _ => script.modified_on.as_ref().filter(|at| !at.is_empty()).map(|at| Deploy {
            commit: String::new(),
            at: at.clone(),
            by: String::new(),
            branch: None,
            message: None,
            refers_to: DeployRef::Commit,
        }),
    }
}

/// A zone's TLS state: secure when a certificate pack is active, unknown when
/// the lookup failed or no pack is active yet.
fn zone_tls(record: &ZoneRecord) -> TlsStatus {
    match &record.certificates {
        Some(packs) if packs.iter().any(|pack| pack.status == "active") => TlsStatus::Ok,
        _ => TlsStatus::Unknown,
    }
}

/// A zone's DNS state: healthy when Cloudflare reports it active, a problem
/// with its status in words otherwise, unknown when no status came back.
fn zone_dns(record: &ZoneRecord) -> Dns {
    match record.zone.status.as_str() {
        "active" => Dns { status: DnsStatus::Ok, note: None },
        "" => Dns { status: DnsStatus::Unknown, note: None },
        status => Dns {
            status: DnsStatus::Problem,
            note: Some(format!("Zone is {status} at Cloudflare")),
        },
    }
}

/// The zone a domain belongs to: the longest zone name the domain is equal to
/// or ends in, compared case-insensitively.
fn zone_for<'a>(domain: &str, zones: &'a [ZoneRecord]) -> Option<&'a ZoneRecord> {
    let domain = domain.to_ascii_lowercase();
    zones
        .iter()
        .filter(|record| {
            let name = record.zone.name.to_ascii_lowercase();
            domain == name || domain.ends_with(&format!(".{name}"))
        })
        .max_by_key(|record| record.zone.name.len())
}

/// Cloudflare's own `*.pages.dev` and `*.workers.dev` names: always served.
fn is_platform_domain(domain: &str) -> bool {
    let domain = domain.to_ascii_lowercase();
    domain.ends_with(".pages.dev") || domain.ends_with(".workers.dev")
}

/// The HTTPS and DNS state of a site from its domains. A platform name reads
/// healthy; a custom domain reads its zone's state, and a domain whose zone
/// is not in the account reads unknown with a note. The worst state across
/// the domains is the site's. No domains means no state at all.
#[must_use]
pub fn domain_health(domains: &[String], zones: &[ZoneRecord]) -> (Option<Tls>, Option<Dns>) {
    if domains.is_empty() {
        return (None, None);
    }
    let mut tls = Vec::with_capacity(domains.len());
    let mut dns = Vec::with_capacity(domains.len());
    for domain in domains {
        if is_platform_domain(domain) {
            tls.push(Tls { status: TlsStatus::Ok, note: None });
            dns.push(Dns { status: DnsStatus::Ok, note: None });
            continue;
        }
        match zone_for(domain, zones) {
            Some(record) => {
                tls.push(Tls { status: zone_tls(record), note: None });
                dns.push(zone_dns(record));
            }
            None => {
                let note = "Zone not in a connected account".to_owned();
                tls.push(Tls { status: TlsStatus::Unknown, note: Some(note.clone()) });
                dns.push(Dns { status: DnsStatus::Unknown, note: Some(note) });
            }
        }
    }
    (
        tls.into_iter().max_by_key(|tls| tls_rank(tls.status)),
        dns.into_iter().max_by_key(|dns| dns_rank(dns.status)),
    )
}

/// How bad a TLS state is, for [`domain_health`]: failing over expiring over
/// unknown over secure.
fn tls_rank(status: TlsStatus) -> u8 {
    match status {
        TlsStatus::Ok => 0,
        TlsStatus::Unknown => 1,
        TlsStatus::Expiring => 2,
        TlsStatus::Failing => 3,
    }
}

/// How bad a DNS state is: a problem over unknown over healthy.
fn dns_rank(status: DnsStatus) -> u8 {
    match status {
        DnsStatus::Ok => 0,
        DnsStatus::Unknown => 1,
        DnsStatus::Problem => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::{render_index, render_site};

    /// Shapes copied by hand from Cloudflare's v4 API reference (the list
    /// responses for accounts, zones, certificate packs, Pages projects,
    /// Workers scripts and Workers domains), trimmed to the fields read.
    const ACCOUNTS: &str = r#"{"success":true,"errors":[],"messages":[],
        "result":[{"id":"023e105f4ecef8ad9ca31a8372d0c353","name":"Factory Zero","type":"standard"},
                  {"id":"9f1c2b3d4e5f60718293a4b5c6d7e8f9","name":"Other"}],
        "result_info":{"page":1,"per_page":20,"count":2,"total_count":2,"total_pages":1}}"#;

    const ZONES: &str = r#"{"success":true,"result":[
        {"id":"372e67954025e0ba6aaa6d586b9e0b59","name":"example.com","status":"active"},
        {"id":"8c2f1d0e9b7a6c5d4e3f2a1b0c9d8e7f","name":"example.org","status":"pending"}],
        "result_info":{"page":1,"per_page":50,"count":2,"total_count":2,"total_pages":1}}"#;

    const CERT_PACKS: &str = r#"{"success":true,"result":[
        {"id":"ab12","type":"universal","hosts":["example.com","*.example.com"],"status":"active"},
        {"id":"cd34","type":"advanced","hosts":["example.com"],"status":"pending_validation"}]}"#;

    const PAGES: &str = r#"{"success":true,"result":[
        {"name":"kaje-site","subdomain":"kaje-site.pages.dev","domains":["kaje.example.com"],
         "production_branch":"main",
         "latest_deployment":{"id":"0b1c2d3e4f5061728394a5b6c7d8e9f0",
            "created_on":"2026-10-15T08:30:12.000000Z",
            "deployment_trigger":{"type":"github:push","metadata":{"branch":"main","commit_hash":"4a1f9c2e7b3d"}}}},
        {"name":"empty-site","subdomain":"empty-site.pages.dev","domains":[],"latest_deployment":null}],
        "result_info":{"page":1,"per_page":10,"count":2,"total_count":2,"total_pages":1}}"#;

    const SCRIPTS: &str = r#"{"success":true,"result":[
        {"id":"tickets-api","etag":"e3b0c44298fc1c14","modified_on":"2026-10-14T19:05:44.123Z","created_on":"2026-01-02T00:00:00Z"},
        {"id":"stub-worker","etag":"","modified_on":null}]}"#;

    const WORKER_DOMAINS: &str = r#"{"success":true,"result":[
        {"id":"d1","hostname":"tickets.example.com","service":"tickets-api","zone_name":"example.com","environment":"production"}]}"#;

    fn parse<T: serde::de::DeserializeOwned>(raw: &str) -> T {
        serde_json::from_str(raw).expect("fixture parses")
    }

    fn inventory() -> Inventory {
        let accounts: Envelope<Vec<Account>> = parse(ACCOUNTS);
        let zones: Envelope<Vec<Zone>> = parse(ZONES);
        let packs: Envelope<Vec<CertificatePack>> = parse(CERT_PACKS);
        let pages: Envelope<Vec<PagesProject>> = parse(PAGES);
        let scripts: Envelope<Vec<WorkerScript>> = parse(SCRIPTS);
        let domains: Envelope<Vec<WorkerDomain>> = parse(WORKER_DOMAINS);
        let account =
            pick_accounts(&accounts.result.expect("accounts"), None).expect("account")[0].clone();
        let zones = zones
            .result
            .expect("zones")
            .into_iter()
            .enumerate()
            .map(|(index, zone)| ZoneRecord {
                zone,
                // The second zone's certificate lookup "failed" in this fixture.
                certificates: (index == 0).then(|| packs.result.clone().unwrap_or_default()),
            })
            .collect();
        Inventory {
            account,
            zones,
            pages: pages.result.expect("pages"),
            scripts: scripts.result.expect("scripts"),
            worker_domains: domains.result.expect("domains"),
            gaps: Vec::new(),
        }
    }

    #[test]
    fn a_gap_in_the_inventory_reaches_the_page() {
        let mut inventory = inventory();
        inventory.gaps = vec!["Pages projects (Cloudflare Pages: Read)".to_owned()];
        let fleet = fleet_from(&inventory, "2026-10-16T00:00:00Z");
        assert_eq!(fleet.gaps, inventory.gaps);
        let html = crate::fleet::render_index(&fleet, "2026-10-16T00:00:00Z", &Default::default());
        assert!(html.contains("Not read this time"), "{html}");
        assert!(html.contains("Pages projects (Cloudflare Pages: Read)"), "{html}");
        let none = fleet_from(&super::Inventory { gaps: Vec::new(), ..inventory }, "t");
        assert!(
            !crate::fleet::render_index(&none, "t", &Default::default())
                .contains("Not read this time")
        );
    }

    #[test]
    fn the_envelope_pagination_is_read() {
        let zones: Envelope<Vec<Zone>> = parse(ZONES);
        assert_eq!(zones.result_info.and_then(|info| info.total_pages), Some(1));
        assert!(zones.success);
    }

    #[test]
    fn every_account_is_read_unless_one_is_named() {
        let accounts: Vec<Account> = parse::<Envelope<Vec<Account>>>(ACCOUNTS).result.unwrap();
        let names =
            |picked: Vec<&Account>| picked.iter().map(|a| a.name.clone()).collect::<Vec<_>>();
        assert_eq!(names(pick_accounts(&accounts, None).unwrap()), ["Factory Zero", "Other"]);
        assert_eq!(names(pick_accounts(&accounts, Some("  ")).unwrap()), ["Factory Zero", "Other"]);
        assert_eq!(
            names(pick_accounts(&accounts, Some("9f1c2b3d4e5f60718293a4b5c6d7e8f9")).unwrap()),
            ["Other"]
        );
        assert_eq!(pick_accounts(&accounts, Some("not-mine")), Err(AccountError::NotVisible));
        assert_eq!(pick_accounts(&[], None), Err(AccountError::NoAccounts));
    }

    #[test]
    fn two_accounts_merge_into_one_snapshot_labelled_by_account() {
        let first = inventory();
        let mut second = inventory();
        second.account = Account { id: "acct2".to_owned(), name: "Other".to_owned() };
        second.gaps = vec!["Zones (Zone: Read)".to_owned()];
        let merged = merge(vec![fleet_from(&first, "t"), fleet_from(&second, "t")], "t");
        assert_eq!(merged.account, "2 Cloudflare accounts");
        assert_eq!(merged.sites.len(), 2 * fleet_from(&first, "t").sites.len());
        assert!(merged.sites.iter().any(|site| site.venture == "Other"));
        let mut ids: Vec<&str> = merged.sites.iter().map(|site| site.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            merged.sites.len() - first.zones.len(),
            "only zone ids repeat in this fixture"
        );
        assert_eq!(merged.gaps, ["Other: Zones (Zone: Read)"]);
        let single = merge(vec![fleet_from(&first, "t")], "t");
        assert_eq!(single.account, first.account.name);
    }

    #[test]
    fn only_an_active_token_is_accepted() {
        assert!(token_is_active(&Verify { status: "active".into() }));
        assert!(!token_is_active(&Verify { status: "disabled".into() }));
        assert!(!token_is_active(&Verify { status: "expired".into() }));
    }

    #[test]
    fn zones_map_with_tls_from_an_active_certificate_pack() {
        let fleet = fleet_from(&inventory(), "2026-10-16T09:00:00Z");
        let zone = fleet.sites.iter().find(|site| site.name == "example.com").expect("zone");
        assert_eq!(zone.kind, Kind::Zone);
        assert_eq!(zone.id, "zone:372e67954025e0ba6aaa6d586b9e0b59");
        assert_eq!(zone.domains, vec!["example.com".to_owned()]);
        assert_eq!(zone.tls.as_ref().map(|tls| tls.status), Some(TlsStatus::Ok));
        assert!(zone.defined_at.is_none() && zone.deploys.is_empty());
    }

    #[test]
    fn a_failed_certificate_lookup_is_unknown_not_failing() {
        let fleet = fleet_from(&inventory(), "2026-10-16T09:00:00Z");
        let zone = fleet.sites.iter().find(|site| site.name == "example.org").expect("zone");
        assert_eq!(zone.tls.as_ref().map(|tls| tls.status), Some(TlsStatus::Unknown));
    }

    #[test]
    fn pages_map_domains_and_the_latest_deployment() {
        let fleet = fleet_from(&inventory(), "2026-10-16T09:00:00Z");
        let site = fleet.sites.iter().find(|site| site.name == "kaje-site").expect("pages");
        assert_eq!(site.kind, Kind::Pages);
        assert_eq!(site.domains, vec!["kaje.example.com".to_owned()]);
        assert_eq!(site.deploys.len(), 1);
        assert_eq!(site.deploys[0].commit, "4a1f9c2e7b3d");
        assert_eq!(site.deploys[0].by, "github:push");
        let empty = fleet.sites.iter().find(|site| site.name == "empty-site").expect("pages");
        assert!(empty.deploys.is_empty(), "no deployment is no deploy row");
    }

    #[test]
    fn a_worker_without_an_active_deployment_shows_its_modified_time() {
        let fleet = fleet_from(&inventory(), "2026-10-16T09:00:00Z");
        let worker = fleet.sites.iter().find(|site| site.name == "tickets-api").expect("worker");
        assert_eq!(worker.kind, Kind::Worker);
        assert_eq!(worker.domains, vec!["tickets.example.com".to_owned()]);
        // The etag is a content hash, not a version: no id is shown for it.
        assert_eq!(worker.deploys.len(), 1);
        assert!(worker.deploys[0].commit.is_empty(), "an etag is not a version");
        assert_eq!(worker.deploys[0].at, "2026-10-14T19:05:44.123Z");
        let stub = fleet.sites.iter().find(|site| site.name == "stub-worker").expect("worker");
        assert!(stub.deploys.is_empty() && stub.domains.is_empty());
    }

    #[test]
    fn a_worker_reads_its_active_version_message_and_trigger() {
        let mut inventory = inventory();
        inventory.scripts[0].active = Some(
            serde_json::from_value(serde_json::json!({
                "id": "dep-1",
                "created_on": "2026-10-15T10:00:00Z",
                "source": "wrangler",
                "versions": [{"version_id": "3f9a1c2b-0000-4000-8000-000000000000", "percentage": 100}],
                "annotations": {"workers/message": "fix the queue", "workers/triggered_by": "deployment"},
                "author_email": "ada@factory0.ventures"
            }))
            .expect("the deployment shape parses"),
        );
        let fleet = fleet_from(&inventory, "t");
        let worker = fleet.sites.iter().find(|site| site.name == "tickets-api").expect("worker");
        let deploy = &worker.deploys[0];
        assert_eq!(deploy.commit, "3f9a1c2b-0000-4000-8000-000000000000");
        assert_eq!(deploy.refers_to, DeployRef::Version);
        assert_eq!(deploy.message.as_deref(), Some("fix the queue"));
        assert_eq!(deploy.by, "deployment");
        assert_eq!(deploy.at, "2026-10-15T10:00:00Z");
    }

    #[test]
    fn worker_environments_are_named_and_the_base_is_production_beside_them() {
        let mut inventory = inventory();
        inventory.scripts =
            ["tickets-api", "tickets-api-staging", "tickets-api-test", "reports-dev", "lone"]
                .iter()
                .map(|id| serde_json::from_value(serde_json::json!({ "id": id })).expect("script"))
                .collect();
        let fleet = fleet_from(&inventory, "t");
        let env = |name: &str| {
            fleet.sites.iter().find(|site| site.name == name).expect("worker").environment.clone()
        };
        assert_eq!(env("tickets-api").as_deref(), Some("production"));
        assert_eq!(env("tickets-api-staging").as_deref(), Some("staging"));
        assert_eq!(env("tickets-api-test").as_deref(), Some("test"));
        // A `-dev` script with no base script still names its environment.
        assert_eq!(env("reports-dev").as_deref(), Some("dev"));
        assert_eq!(env("lone"), None);
    }

    #[test]
    fn a_pages_project_gets_a_row_per_preview_branch_beside_production() {
        let mut inventory = inventory();
        let preview: PagesDeployment = serde_json::from_value(serde_json::json!({
            "id": "p1",
            "created_on": "2026-10-14T08:00:00Z",
            "aliases": ["feature-x.kaje-site.pages.dev"],
            "deployment_trigger": {"type": "github:push", "metadata": {"branch": "feature/x", "commit_hash": "9e8d7c6b5a4f", "commit_message": "wire the form"}}
        }))
        .expect("preview");
        inventory.pages[0].previews = vec![preview];
        let fleet = fleet_from(&inventory, "t");
        let account = "023e105f4ecef8ad9ca31a8372d0c353";
        let production = fleet
            .sites
            .iter()
            .find(|site| site.id == format!("pages:{account}:kaje-site"))
            .expect("production");
        assert_eq!(production.environment.as_deref(), Some("production"));
        let branch = fleet
            .sites
            .iter()
            .find(|site| site.id == format!("pages:{account}:kaje-site:feature/x"))
            .expect("preview row");
        assert_eq!(branch.environment.as_deref(), Some("feature/x"));
        assert_eq!(branch.name, "kaje-site");
        assert_eq!(branch.domains, vec!["feature-x.kaje-site.pages.dev".to_owned()]);
        assert_eq!(branch.tls.as_ref().map(|tls| tls.status), Some(TlsStatus::Ok));
        assert_eq!(branch.deploys[0].branch.as_deref(), Some("feature/x"));
        assert_eq!(branch.deploys[0].message.as_deref(), Some("wire the form"));
    }

    #[test]
    fn a_pages_deploy_without_a_commit_is_an_upload_named_by_its_id() {
        let mut inventory = inventory();
        let upload: PagesDeployment = serde_json::from_value(serde_json::json!({
            "id": "0b1c2d3e4f5061728394a5b6c7d8e9f0",
            "created_on": "2026-10-15T08:30:12.000000Z",
            "deployment_trigger": {"type": "ad_hoc", "metadata": {}}
        }))
        .expect("deployment");
        inventory.pages[1].latest_deployment = Some(upload);
        let fleet = fleet_from(&inventory, "t");
        let site = fleet.sites.iter().find(|site| site.name == "empty-site").expect("pages");
        assert_eq!(site.deploys[0].commit, "0b1c2d3e4f5061728394a5b6c7d8e9f0");
        assert_eq!(site.deploys[0].refers_to, DeployRef::Upload);
        assert_eq!(site.deploys[0].by, "ad_hoc");
    }

    #[test]
    fn the_sites_read_their_zones_for_https_and_dns() {
        let fleet = fleet_from(&inventory(), "t");
        let find = |name: &str| fleet.sites.iter().find(|site| site.name == name).expect("site");
        // A custom domain reads its zone: example.com has an active pack and is active.
        let pages = find("kaje-site");
        assert_eq!(pages.tls.as_ref().map(|tls| tls.status), Some(TlsStatus::Ok));
        assert_eq!(pages.dns.as_ref().map(|dns| dns.status), Some(DnsStatus::Ok));
        // The pending zone's DNS is a problem, in words.
        let dns = find("example.org").dns.clone().expect("zone dns");
        assert_eq!(dns.status, DnsStatus::Problem);
        assert_eq!(dns.note.as_deref(), Some("Zone is pending at Cloudflare"));
        // A site with no domains has no state to read.
        let empty = find("empty-site");
        assert!(empty.tls.is_none() && empty.dns.is_none());
    }

    #[test]
    fn a_zone_status_is_read_in_words_and_active_is_healthy() {
        let record = |status: &str| ZoneRecord {
            zone: Zone { id: "z".into(), name: "example.net".into(), status: status.into() },
            certificates: None,
        };
        assert_eq!(zone_dns(&record("active")), Dns { status: DnsStatus::Ok, note: None });
        assert_eq!(zone_dns(&record("")).status, DnsStatus::Unknown);
        let moved = zone_dns(&record("moved"));
        assert_eq!(moved.status, DnsStatus::Problem);
        assert_eq!(moved.note.as_deref(), Some("Zone is moved at Cloudflare"));
    }

    #[test]
    fn a_domain_reads_its_longest_matching_zone_case_insensitively() {
        let mut zones = inventory().zones;
        zones.push(ZoneRecord {
            zone: Zone {
                id: "z3".into(),
                name: "shop.example.com".into(),
                status: "active".into(),
            },
            certificates: Some(Vec::new()),
        });
        let name = |domain: &str| zone_for(domain, &zones).map(|record| record.zone.name.clone());
        assert_eq!(name("A.Shop.Example.com").as_deref(), Some("shop.example.com"));
        assert_eq!(name("app.shop.example.com").as_deref(), Some("shop.example.com"));
        assert_eq!(name("kaje.example.com").as_deref(), Some("example.com"));
        assert_eq!(name("notexample.com"), None, "a suffix must be a whole label");
        let (tls, dns) = domain_health(&["app.shop.example.com".to_owned()], &zones);
        // The shop zone has no active pack: unknown TLS, healthy DNS.
        assert_eq!(tls, Some(Tls { status: TlsStatus::Unknown, note: None }));
        assert_eq!(dns, Some(Dns { status: DnsStatus::Ok, note: None }));
    }

    #[test]
    fn domain_health_takes_the_worst_domain_and_names_a_zone_it_cannot_see() {
        let zones = inventory().zones;
        let domains = ["kaje.example.com".to_owned(), "shop.other.net".to_owned()];
        let (tls, dns) = domain_health(&domains, &zones);
        let note = Some("Zone not in a connected account".to_owned());
        assert_eq!(tls, Some(Tls { status: TlsStatus::Unknown, note: note.clone() }));
        assert_eq!(dns, Some(Dns { status: DnsStatus::Unknown, note }));
        // A platform name is healthy on its own.
        let (tls, dns) = domain_health(&["site.pages.dev".to_owned()], &zones);
        assert_eq!(tls, Some(Tls { status: TlsStatus::Ok, note: None }));
        assert_eq!(dns, Some(Dns { status: DnsStatus::Ok, note: None }));
        // No domains, no state.
        assert_eq!(domain_health(&[], &zones), (None, None));
    }

    #[test]
    fn previews_keep_the_newest_deployment_of_up_to_five_branches() {
        let deployment = |id: &str, branch: Option<&str>, created: &str| -> PagesDeployment {
            let trigger = branch.map_or(
                serde_json::json!({"type": "ad_hoc"}),
                |branch| serde_json::json!({"type": "github:push", "metadata": {"branch": branch}}),
            );
            serde_json::from_value(serde_json::json!({
                "id": id, "created_on": created, "deployment_trigger": trigger
            }))
            .expect("deployment")
        };
        let kept = preview_branches(vec![
            deployment("a-old", Some("feature/a"), "2026-10-01T00:00:00Z"),
            deployment("a-new", Some("feature/a"), "2026-10-09T00:00:00Z"),
            deployment("b", Some("b"), "2026-10-02T00:00:00Z"),
            deployment("c", Some("c"), "2026-10-03T00:00:00Z"),
            deployment("d", Some("d"), "2026-10-04T00:00:00Z"),
            deployment("e", Some("e"), "2026-10-05T00:00:00Z"),
            deployment("f", Some("f"), "2026-10-06T00:00:00Z"),
            deployment("no-branch", None, "2026-10-10T00:00:00Z"),
        ]);
        let ids: Vec<&str> = kept.iter().map(|deployment| deployment.id.as_str()).collect();
        // Newest first, one per branch, the branchless upload skipped, and the
        // oldest branch (b) cut at five.
        assert_eq!(ids, ["a-new", "f", "e", "d", "c"]);
    }

    #[test]
    fn a_preview_with_no_alias_reads_its_url_host() {
        let preview: PagesDeployment = serde_json::from_value(serde_json::json!({
            "id": "p", "created_on": "t", "url": "https://abc.kaje-site.pages.dev/"
        }))
        .expect("preview");
        assert_eq!(preview_domains(&preview), vec!["abc.kaje-site.pages.dev".to_owned()]);
    }

    #[test]
    fn the_snapshot_carries_no_terraform_and_no_baseline_or_drift() {
        let fleet = fleet_from(&inventory(), "2026-10-16T09:00:00Z");
        assert!(fleet.terraform.is_none());
        assert_eq!(fleet.account, "Factory Zero");
        for site in &fleet.sites {
            assert!(site.baseline.is_none() && site.drift.is_none());
        }
        // Zones always carry their DNS state from the zone list.
        assert!(
            fleet
                .sites
                .iter()
                .filter(|site| site.kind == Kind::Zone)
                .all(|site| site.dns.is_some())
        );
    }

    #[test]
    fn the_mapped_snapshot_renders_without_terraform() {
        let fleet = fleet_from(&inventory(), "2026-10-16T09:00:00Z");
        let index = render_index(&fleet, "2026-10-16T10:00:00Z", &Default::default());
        assert!(index.contains("Refresh now"));
        assert!(!index.contains(">Baseline<"), "no Terraform columns without Terraform");
        let site = fleet.sites.iter().find(|site| site.name == "tickets-api").expect("worker");
        let page = render_site(&fleet, &site.id, "2026-10-16T10:00:00Z").expect("site page");
        assert!(page.contains("Not managed as code yet"));
        assert!(!page.contains(" in Factory-Zero"));
    }

    #[test]
    fn the_template_url_carries_exactly_the_read_only_groups() {
        let url = template_url();
        let (base, query) = url.split_once('?').expect("query");
        assert_eq!(base, "https://dash.cloudflare.com/profile/api-tokens");
        let value = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("permissionGroupKeys="))
            .expect("permissionGroupKeys");
        let decoded = percent_encoding::percent_decode_str(value).decode_utf8().expect("utf8");
        let groups: serde_json::Value = serde_json::from_str(&decoded).expect("json");
        let pairs: Vec<(String, String)> = groups
            .as_array()
            .expect("array")
            .iter()
            .map(|group| {
                (
                    group["key"].as_str().unwrap().to_owned(),
                    group["type"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        let expected: Vec<(String, String)> =
            PERMISSIONS.iter().map(|(key, kind)| (key.to_string(), kind.to_string())).collect();
        assert_eq!(pairs, expected);
        assert!(pairs.iter().all(|(_, kind)| kind == "read"), "every group is read-only");
        assert!(query.contains("name=Keep%20Shipping%20console%20%28read-only%29"));
    }
}
