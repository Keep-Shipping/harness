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
pub mod seal;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;

use crate::fleet::{Deploy, Fleet, Kind, Site, Tls, TlsStatus};

/// The token's name on Cloudflare's form, and so on the token list.
pub const TOKEN_NAME: &str = "Keep Shipping console (read-only)";

/// The permission groups the token asks for, as `(key, type)` pairs in the
/// shape Cloudflare's template URL takes. Every one is a read; the keys are
/// from Cloudflare's permission reference (`zone`, `dns`,
/// `ssl_and_certificates`, `workers_scripts`, `page` for Pages, and
/// `account_settings`), listed in the docs at
/// <https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/>.
pub const PERMISSIONS: [(&str, &str); 6] = [
    ("zone", "read"),
    ("dns", "read"),
    ("ssl_and_certificates", "read"),
    ("workers_scripts", "read"),
    ("page", "read"),
    ("account_settings", "read"),
];

/// The plain-words names of [`PERMISSIONS`], in the same order, for the page.
pub const PERMISSION_WORDS: [&str; 6] = [
    "Zone Read",
    "DNS Read",
    "SSL and Certificates Read",
    "Workers Scripts Read",
    "Pages Read",
    "Account Settings Read",
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
    let groups: Vec<serde_json::Value> = PERMISSIONS
        .iter()
        .map(|(key, kind)| serde_json::json!({ "key": key, "type": kind }))
        .collect();
    let json = serde_json::Value::Array(groups).to_string();
    format!(
        "https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys={keys}&accountId=*&zoneId=all&name={name}",
        keys = utf8_percent_encode(&json, NON_ALPHANUMERIC),
        name = utf8_percent_encode(TOKEN_NAME, NAME),
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct PagesDeployment {
    pub id: String,
    #[serde(default)]
    pub created_on: String,
    #[serde(default)]
    pub deployment_trigger: Option<Trigger>,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerScript {
    pub id: String,
    #[serde(default)]
    pub modified_on: Option<String>,
    #[serde(default)]
    pub etag: Option<String>,
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

/// The account to read: the one `CF_ACCOUNT_ID` names, else the first one
/// the token lists.
pub fn pick_account<'a>(
    accounts: &'a [Account],
    wanted: Option<&str>,
) -> Result<&'a Account, AccountError> {
    match wanted.map(str::trim).filter(|id| !id.is_empty()) {
        Some(id) => {
            accounts.iter().find(|account| account.id == id).ok_or(AccountError::NotVisible)
        }
        None => accounts.first().ok_or(AccountError::NoAccounts),
    }
}

/// Whether a verify answer is a usable token.
#[must_use]
pub fn token_is_active(verify: &Verify) -> bool {
    verify.status == "active"
}

/// Maps one collection to the snapshot the console renders. `generated_at`
/// is the RFC 3339 time of the collection. Sites are emitted zones first,
/// then Pages projects, then Workers, each in the order the API listed them;
/// the renderer sorts.
#[must_use]
pub fn fleet_from(inventory: &Inventory, generated_at: &str) -> Fleet {
    let mut sites = Vec::new();

    for record in &inventory.zones {
        let status = match &record.certificates {
            Some(packs) if packs.iter().any(|pack| pack.status == "active") => TlsStatus::Ok,
            _ => TlsStatus::Unknown,
        };
        sites.push(Site {
            id: format!("zone:{}", record.zone.id),
            name: record.zone.name.clone(),
            kind: Kind::Zone,
            venture: String::new(),
            domains: vec![record.zone.name.clone()],
            defined_at: None,
            deploys: Vec::new(),
            tls: Some(Tls { status }),
            dns: None,
            baseline: None,
            drift: None,
            resources: Vec::new(),
        });
    }

    for project in &inventory.pages {
        let deploys = project
            .latest_deployment
            .iter()
            .map(|deployment| Deploy {
                commit: deployment
                    .deployment_trigger
                    .as_ref()
                    .and_then(|trigger| trigger.metadata.as_ref())
                    .and_then(|metadata| metadata.commit_hash.clone())
                    .unwrap_or_else(|| deployment.id.clone()),
                at: deployment.created_on.clone(),
                by: deployment
                    .deployment_trigger
                    .as_ref()
                    .and_then(|trigger| trigger.kind.clone())
                    .unwrap_or_else(|| "Cloudflare Pages".to_owned()),
            })
            .filter(|deploy| !deploy.at.is_empty())
            .collect();
        sites.push(Site {
            id: format!("pages:{}", project.name),
            name: project.name.clone(),
            kind: Kind::Pages,
            venture: String::new(),
            domains: project.domains.clone(),
            defined_at: None,
            deploys,
            tls: None,
            dns: None,
            baseline: None,
            drift: None,
            resources: Vec::new(),
        });
    }

    for script in &inventory.scripts {
        let domains = inventory
            .worker_domains
            .iter()
            .filter(|domain| domain.service == script.id)
            .map(|domain| domain.hostname.clone())
            .collect();
        // The script's etag is a content hash, not a commit: it is the
        // closest thing to a version the API gives, and the page shows it
        // as one. No timestamp means no deploy row.
        let deploys = match (&script.etag, &script.modified_on) {
            (Some(etag), Some(at)) => vec![Deploy {
                commit: etag.clone(),
                at: at.clone(),
                by: "Cloudflare Workers".to_owned(),
            }],
            _ => Vec::new(),
        };
        sites.push(Site {
            id: format!("worker:{}", script.id),
            name: script.id.clone(),
            kind: Kind::Worker,
            venture: String::new(),
            domains,
            defined_at: None,
            deploys,
            tls: None,
            dns: None,
            baseline: None,
            drift: None,
            resources: Vec::new(),
        });
    }

    Fleet {
        account: inventory.account.name.clone(),
        generated_at: generated_at.to_owned(),
        terraform: None,
        sites,
        gaps: inventory.gaps.clone(),
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
            pick_account(&accounts.result.expect("accounts"), None).expect("account").clone();
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
        let html = crate::fleet::render_index(&fleet);
        assert!(html.contains("Not read this time:"), "{html}");
        assert!(html.contains("Pages projects (Cloudflare Pages: Read)"), "{html}");
        let none = fleet_from(&super::Inventory { gaps: Vec::new(), ..inventory }, "t");
        assert!(!crate::fleet::render_index(&none).contains("Not read this time"));
    }

    #[test]
    fn the_envelope_pagination_is_read() {
        let zones: Envelope<Vec<Zone>> = parse(ZONES);
        assert_eq!(zones.result_info.and_then(|info| info.total_pages), Some(1));
        assert!(zones.success);
    }

    #[test]
    fn an_account_is_chosen_by_id_or_first() {
        let accounts: Vec<Account> = parse::<Envelope<Vec<Account>>>(ACCOUNTS).result.unwrap();
        assert_eq!(pick_account(&accounts, None).unwrap().name, "Factory Zero");
        assert_eq!(pick_account(&accounts, Some("  ")).unwrap().name, "Factory Zero");
        assert_eq!(
            pick_account(&accounts, Some("9f1c2b3d4e5f60718293a4b5c6d7e8f9")).unwrap().name,
            "Other"
        );
        assert_eq!(pick_account(&accounts, Some("not-mine")), Err(AccountError::NotVisible));
        assert_eq!(pick_account(&[], None), Err(AccountError::NoAccounts));
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
    fn workers_map_custom_domains_and_etag_as_their_version() {
        let fleet = fleet_from(&inventory(), "2026-10-16T09:00:00Z");
        let worker = fleet.sites.iter().find(|site| site.name == "tickets-api").expect("worker");
        assert_eq!(worker.kind, Kind::Worker);
        assert_eq!(worker.domains, vec!["tickets.example.com".to_owned()]);
        assert_eq!(worker.deploys[0].commit, "e3b0c44298fc1c14");
        let stub = fleet.sites.iter().find(|site| site.name == "stub-worker").expect("worker");
        assert!(stub.deploys.is_empty() && stub.domains.is_empty());
    }

    #[test]
    fn the_snapshot_carries_no_terraform_and_no_unchecked_state() {
        let fleet = fleet_from(&inventory(), "2026-10-16T09:00:00Z");
        assert!(fleet.terraform.is_none());
        assert_eq!(fleet.account, "Factory Zero");
        for site in &fleet.sites {
            assert!(site.dns.is_none() && site.baseline.is_none() && site.drift.is_none());
        }
    }

    #[test]
    fn the_mapped_snapshot_renders_without_terraform() {
        let fleet = fleet_from(&inventory(), "2026-10-16T09:00:00Z");
        let index = render_index(&fleet);
        assert!(index.contains("Not managed by Terraform yet"));
        assert!(index.contains("Refresh now"));
        let site = fleet.sites.iter().find(|site| site.name == "tickets-api").expect("worker");
        let page = render_site(&fleet, &site.id).expect("site page");
        assert!(page.contains("Not managed by Terraform yet"));
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
