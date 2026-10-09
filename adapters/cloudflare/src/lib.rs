//! `Cloudflare`: read an account through the [`HttpClient`] port, write
//! OpenTofu for the `cloudflare` provider v5 plus `import` blocks
//! ([#167](https://github.com/Keep-Shipping/harness/issues/167)).
//!
//! Two halves that never touch anything but an [`Account`]:
//! [`Cloudflare::read`] speaks the Cloudflare v4 REST API over an [`HttpClient`]
//! the caller supplies — this crate holds the protocol, not the socket, the TLS
//! or the host allowlist, exactly as the GitHub adapter does — and [`generate`]
//! is a pure function from an [`Account`] to files. What sits between those
//! files and a PR is one gate: [`check_empty_plan`] proposes the import only
//! when the plan over the generated directory is empty.
//!
//! # What this refuses to do
//!
//! - **It never writes to Cloudflare.** Every request is a `GET`; this reads an
//!   account and writes local files, it does not deploy.
//! - **It never writes a secret down.** The API token reaches the socket and
//!   nowhere else, and an email routing forward destination is replaced by a
//!   `var.email_routing_destinations[...]` reference *before* it enters the
//!   model, so the address is in neither the files nor the [`Resource`] — see
//!   [`Attr::Expr`].
//! - **It does not import Workers scripts.** Their content is a multipart
//!   download and writing a script out of one is its own problem; each script is
//!   listed in [`Account::not_imported`] by name so nothing disappears quietly.
//! - **It does not flatten the account into one giant module.** Every zone is
//!   its own module and account-level objects live in an `account` module,
//!   because that is the shape a human then has to review.
//!
//! # Invariants
//!
//! - **Output is a pure function of the account.** [`generate`] sorts
//!   everything, deduplicates readable names by suffixing `_2`, `_3`, …, writes
//!   no timestamp and ends every file with a newline, so re-running the import
//!   on an unchanged account produces no diff. The order the API returned
//!   results in cannot reach the output.
//! - **The token is only reachable through `SecretValue::with_bytes`**, goes out
//!   in the `Authorization` header and appears in no [`Debug`], no log line and
//!   no [`Error`]: errors carry Cloudflare's own `errors[].message`, never a
//!   request.
//! - **Only edited zone settings are imported.** A setting still at Cloudflare's
//!   default (`modified_on: null`) would add a resource whose plan argues with
//!   the provider's own defaults, so it is left out.
//! - **A module refers to the account by variable, never by literal**, so a
//!   generated module is reusable: `account_id` is `var.cloudflare_account_id`.
//!   A zone's own id *is* literal inside its zone module — it is not secret, and
//!   every object in that module hangs off it.
//!
//! Two
//! [#168](https://github.com/Keep-Shipping/harness/issues/168) additions sit
//! beside them: [`add_backend`] writes the generated root's R2 state backend,
//! and [`Cloudflare::check_scope`] holds the token's policies against the least
//! privilege the generated modules need, on connect.

#![forbid(unsafe_code)]

mod generate;
mod hcl;
mod plan;
mod state;
mod token;

#[cfg(test)]
mod tests;

pub use generate::generate;
pub use plan::{PlannedChanges, check_empty_plan};
pub use state::{StateBackend, StateError, add_backend};
pub use token::{ScopeError, check_scope, required_groups};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use ks_core::ports::BoxFuture;
use ks_core::ports::http::{HttpClient, HttpMethod, HttpRequest};
use ks_core::ports::secrets::SecretValue;
use serde_json::Value;
use serde_json::json;

/// The Cloudflare v4 API root, and the default [`base`](Cloudflare::with_base).
pub const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// The `cloudflare` provider constraint every generated root module carries.
pub const PROVIDER_VERSION: &str = "~> 5.0";

/// The module account-level objects go in.
pub const ACCOUNT_MODULE: &str = "account";

/// How many results a paginated listing asks for.
const PER_PAGE: usize = 50;

/// The most pages a listing may walk before the reader gives up, so a wrong
/// `result_info` cannot spin forever.
const MAX_PAGES: usize = 1000;

/// The account variable a generated module reads its account id from.
const ACCOUNT_VAR: &str = "cloudflare_account_id";

/// The variable holding email routing forward destinations.
const DESTINATIONS_VAR: &str = "email_routing_destinations";

/// The [`Account::not_imported`] key Workers scripts are listed under.
const SCRIPTS_KIND: &str = "Cloudflare Workers scripts";

/// The [`Account::not_imported`] key optional endpoints an entitlement refused
/// (403 or 404) are listed under, degraded to a note rather than a failure.
const NOT_READABLE: &str = "Not readable with this token";

/// A rule field of a ruleset this slice carries; everything else Cloudflare
/// reports (`id`, `version`, `last_updated`, `ref`) is server-side bookkeeping
/// and would show up as a diff.
const RULE_FIELDS: &[&str] =
    &["action", "action_parameters", "description", "enabled", "expression"];

/// One attribute of a [`Resource`]: a value read off the API, or an HCL
/// expression standing in for something that must not be written down.
///
/// `Expr` is emitted verbatim, so only this crate builds one — always out of a
/// variable name and a slug it generated, never out of anything the API
/// returned. That is how an email routing destination leaves the model without
/// leaving the file.
#[derive(Clone, Debug, PartialEq)]
pub enum Attr {
    /// A literal read off the API.
    Lit(Value),
    /// An HCL expression, emitted as written.
    Expr(String),
    /// An object, written one attribute per line.
    Obj(Vec<(String, Attr)>),
    /// A list.
    List(Vec<Attr>),
}

impl Attr {
    /// A literal.
    pub fn lit(value: Value) -> Attr {
        Attr::Lit(value)
    }

    /// An expression.
    pub fn expr(text: impl Into<String>) -> Attr {
        Attr::Expr(text.into())
    }

    /// Converts JSON read off the API, sorting object keys so what is rendered
    /// does not depend on the order the API serialised them in.
    pub fn from_json(value: &Value) -> Attr {
        match value {
            Value::Object(fields) => {
                // Sorted here rather than relied on: `serde_json`'s map order is
                // a feature choice, and what is rendered must not be.
                let mut sorted: Vec<(&String, &Value)> = fields.iter().collect();
                sorted.sort_by_key(|(key, _)| *key);
                Attr::Obj(
                    sorted
                        .into_iter()
                        .map(|(key, value)| (key.clone(), Attr::from_json(value)))
                        .collect(),
                )
            }
            Value::Array(items) => Attr::List(items.iter().map(Attr::from_json).collect()),
            other => Attr::Lit(other.clone()),
        }
    }
}

/// One imported object: where it goes, what it is, what it is called, and what
/// its resource block needs.
#[derive(Clone, Debug, PartialEq)]
pub struct Resource {
    /// The module it belongs to: a zone slug, or [`ACCOUNT_MODULE`].
    pub module: String,
    /// The `cloudflare` provider v5 resource type.
    pub kind: &'static str,
    /// A readable name, unique within (module, kind): the resource block's local
    /// name, and what a human looks for.
    pub name: String,
    /// The provider's import id for this object.
    pub import_id: String,
    /// The resource block's attributes.
    pub attrs: BTreeMap<String, Attr>,
}

/// One account as read: its resources, the destination keys a human must supply,
/// and what was found but left alone.
#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    /// The account id that was read.
    pub account_id: String,
    /// Every imported object, in no particular order — [`generate`] sorts.
    pub resources: Vec<Resource>,
    /// The keys of the `email_routing_destinations` variable the rules reference.
    pub destinations: BTreeSet<String>,
    /// What the API listed and this slice does not import, by kind, with the
    /// names it found.
    pub not_imported: BTreeMap<&'static str, Vec<String>>,
}

/// Why a read did not finish.
///
/// Every variant is built from the port's own error or from Cloudflare's
/// `errors[].message`. None of them ever holds the token: it is written to the
/// `Authorization` header and nowhere else, and request headers are not carried
/// into an error.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// The [`HttpClient`] refused or failed the request.
    Http {
        /// The port's message.
        message: String,
    },
    /// Cloudflare answered with a status other than 200.
    Status {
        /// The status code.
        status: u16,
        /// What Cloudflare said, if it said anything.
        message: String,
    },
    /// Cloudflare answered `success: false`, or with a body that is not the
    /// envelope every response is wrapped in.
    Api {
        /// The joined `errors[].message` values.
        message: String,
    },
    /// A listing did not end: `result_info` never reached its last page within
    /// a thousand pages.
    TooManyPages {
        /// The listing path that ran away.
        path: String,
    },
    /// The token verified but its permissions do not fit this slice: something
    /// is missing, something extra is granted, or a policy reaches beyond this
    /// account. The message carries permission group names, never the token.
    Scope {
        /// The difference, in plain words.
        message: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Http { message } => write!(f, "Cloudflare request failed: {message}"),
            Error::Status { status, message } => {
                write!(f, "Cloudflare answered {status}: {message}")
            }
            Error::Api { message } => write!(f, "Cloudflare rejected the read: {message}"),
            Error::TooManyPages { path } => {
                write!(f, "Cloudflare listing {path} did not end within {MAX_PAGES} pages")
            }
            Error::Scope { message } => {
                write!(f, "the token's scope does not fit this slice: {message}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// A reader for one Cloudflare account.
pub struct Cloudflare {
    http: Arc<dyn HttpClient>,
    token: SecretValue,
    base: String,
}

impl Cloudflare {
    /// A reader over the real [`API_BASE`].
    pub fn new(http: Arc<dyn HttpClient>, token: SecretValue) -> Cloudflare {
        Cloudflare::with_base(http, token, API_BASE)
    }

    /// A reader over `base` — a test harness points this at its own fake.
    pub fn with_base(
        http: Arc<dyn HttpClient>,
        token: SecretValue,
        base: impl Into<String>,
    ) -> Cloudflare {
        Cloudflare { http, token, base: base.into().trim_end_matches('/').to_string() }
    }

    /// Reads `account_id`: every zone it lists, then the account-level objects
    /// under it.
    pub fn read<'a>(&'a self, account_id: &'a str) -> BoxFuture<'a, Result<Account, Error>> {
        Box::pin(async move {
            let mut account = Account {
                account_id: account_id.to_string(),
                resources: Vec::new(),
                destinations: BTreeSet::new(),
                not_imported: BTreeMap::new(),
            };
            for zone in self.zones(account_id).await? {
                let mut resources =
                    self.zone(&zone, &mut account.destinations, &mut account.not_imported).await?;
                account.resources.append(&mut resources);
            }
            let mut resources = self.account_level(account_id, &mut account).await?;
            account.resources.append(&mut resources);
            Ok(account)
        })
    }

    // -- transport ----------------------------------------------------------

    /// One `GET`, authenticated, unwrapped from the envelope Cloudflare wraps
    /// every response in.
    async fn get(&self, path: &str) -> Result<Value, Error> {
        let mut request = HttpRequest::new(HttpMethod::Get, format!("{}{path}", self.base));
        // The token is read here and nowhere else, and it goes out as a header:
        // it is never formatted into a message, a log or a file.
        self.token.with_bytes(|bytes| {
            let bearer = String::from_utf8_lossy(bytes);
            request.headers.push(("Authorization".to_string(), format!("Bearer {bearer}")));
            request.headers.push(("Accept".to_string(), "application/json".to_string()));
        });
        let response = self
            .http
            .send(request)
            .await
            .map_err(|error| Error::Http { message: format!("{path}: {error}") })?;
        // A body is worth reading whatever the status: a 403 says why in
        // `errors[].message`, and that message is the whole error.
        if response.status != 200 {
            let body = parse(&response.body).unwrap_or(Value::Null);
            return Err(Error::Status { status: response.status, message: messages(&body) });
        }
        // A 200 that is not the envelope is an error, never an empty read: an
        // account silently read as empty would sail through the empty-plan
        // gate. The parse error is serde's position, not the body, so the
        // token cannot be in it.
        let body = parse(&response.body)?;
        if body["success"] == json!(false) {
            return Err(Error::Api { message: messages(&body) });
        }
        Ok(body)
    }

    /// A paginated listing, flattened. A response with no `result_info` is one
    /// page, which is what the non-paginated endpoints answer.
    async fn list(&self, path: &str, query: &str) -> Result<Vec<Value>, Error> {
        let mut out = Vec::new();
        let mut page = 1;
        loop {
            let separator = if query.is_empty() { "" } else { "&" };
            let url = format!("{path}?{query}{separator}page={page}&per_page={PER_PAGE}");
            let body = self.get(&url).await?;
            out.extend(body["result"].as_array().into_iter().flatten().cloned());
            let info = &body["result_info"];
            let total = info["total_pages"].as_u64().unwrap_or(1);
            if info["page"].as_u64().unwrap_or(page as u64) >= total {
                return Ok(out);
            }
            page += 1;
            if page > MAX_PAGES {
                return Err(Error::TooManyPages { path: path.to_string() });
            }
        }
    }

    /// One read of an optional endpoint: an entitlement refusal (403 or 404) is
    /// "not available", recorded in `not_imported` and answered as [`None`]
    /// rather than failing the whole import — an account on a plan without bot
    /// management, say, still imports. The note carries Cloudflare's own
    /// message and the status, never the token; any other error still
    /// propagates.
    async fn optional<T>(
        &self,
        read: impl std::future::Future<Output = Result<T, Error>>,
        what: &str,
        zone_name: &str,
        not_imported: &mut BTreeMap<&'static str, Vec<String>>,
    ) -> Result<Option<T>, Error> {
        match read.await {
            Ok(value) => Ok(Some(value)),
            Err(Error::Status { status, message }) if status == 403 || status == 404 => {
                not_imported
                    .entry(NOT_READABLE)
                    .or_default()
                    .push(format!("zone {zone_name}: {what} ({status}: {message})"));
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    // -- zones --------------------------------------------------------------

    async fn zones(&self, account_id: &str) -> Result<Vec<Zone>, Error> {
        let listed = self.list("/zones", &format!("account.id={}", encode(account_id))).await?;
        let mut zones: Vec<Zone> = listed.iter().filter_map(Zone::read).collect();
        // Read in slug order, not listing order: the destination keys rules
        // claim are handed out in the order zones are read, and that order
        // must not depend on the API.
        zones.sort_by(|a, b| (&a.slug, &a.id).cmp(&(&b.slug, &b.id)));
        Ok(zones)
    }

    /// Everything under one zone: the zone itself, its edited settings, its DNS,
    /// its routes, its email rules, its zone rulesets and its bot management.
    async fn zone(
        &self,
        zone: &Zone,
        destinations: &mut BTreeSet<String>,
        not_imported: &mut BTreeMap<&'static str, Vec<String>>,
    ) -> Result<Vec<Resource>, Error> {
        let mut out = Builder::new(zone.slug.clone());
        let base = format!("/zones/{}", encode(&zone.id));

        out.push(Pending {
            kind: "cloudflare_zone",
            import_id: zone.id.clone(),
            name: zone.slug.clone(),
            attrs: attrs([
                ("account", Attr::expr(format!("{{ id = var.{ACCOUNT_VAR} }}"))),
                ("name", Attr::lit(json!(zone.name))),
                ("type", Attr::lit(json!(zone.kind))),
            ]),
        });

        // Only settings changed away from the default: importing the defaults
        // would add resources that argue with the provider's own.
        let settings = self.get(&format!("{base}/settings")).await?;
        for setting in array(&settings, "result") {
            let Some(id) = field(setting, "id").or_else(|| field(setting, "setting_id")) else {
                continue;
            };
            if setting["editable"] != json!(true) || setting["modified_on"].is_null() {
                continue;
            }
            out.push(Pending {
                kind: "cloudflare_zone_setting",
                import_id: format!("{}/{}", zone.id, id),
                name: slug(&id),
                attrs: attrs([
                    ("zone_id", Attr::lit(json!(zone.id))),
                    ("setting_id", Attr::lit(json!(id))),
                    ("value", Attr::from_json(&setting["value"])),
                ]),
            });
        }

        for record in self.list(&format!("{base}/dns_records"), "").await? {
            let Some(id) = field(&record, "id") else { continue };
            let kind = field(&record, "type").unwrap_or_else(|| "record".to_string());
            let label = relative(field(&record, "name").unwrap_or_default().as_str(), &zone.name);
            out.push(Pending {
                kind: "cloudflare_dns_record",
                import_id: format!("{}/{}", zone.id, id),
                name: format!("{label}_{}", slug(&kind)),
                attrs: json_attrs([
                    ("zone_id", json!(zone.id)),
                    ("name", record["name"].clone()),
                    ("type", record["type"].clone()),
                    ("content", record["content"].clone()),
                    ("ttl", record["ttl"].clone()),
                    ("proxied", record["proxied"].clone()),
                    ("priority", record["priority"].clone()),
                    ("comment", record["comment"].clone()),
                ]),
            });
        }

        let routes = self
            .optional(
                self.get(&format!("{base}/workers/routes")),
                "Workers routes",
                &zone.name,
                not_imported,
            )
            .await?;
        if let Some(routes) = routes {
            for route in array(&routes, "result") {
                let Some(id) = field(route, "id") else { continue };
                out.push(Pending {
                    kind: "cloudflare_workers_route",
                    import_id: format!("{}/{}", zone.id, id),
                    name: slug(&field(route, "pattern").unwrap_or_else(|| id.clone())),
                    attrs: json_attrs([
                        ("zone_id", json!(zone.id)),
                        ("pattern", route["pattern"].clone()),
                        ("script", route["script"].clone()),
                    ]),
                });
            }
        }

        let rules = self
            .optional(
                self.list(&format!("{base}/email/routing/rules"), ""),
                "email routing rules",
                &zone.name,
                not_imported,
            )
            .await?;
        if let Some(mut rules) = rules {
            // A rule's destination key is claimed in the order rules are
            // read, so walk them by id — position breaking ties — and
            // `name` / `name_2` stay attached to the same rules whatever
            // order the API answered in.
            rules.sort_by(|a, b| {
                field(a, "id").unwrap_or_default().cmp(&field(b, "id").unwrap_or_default())
            });
            for rule in rules {
                let Some(id) = field(&rule, "id") else { continue };
                let name = slug(field(&rule, "name").unwrap_or_else(|| id.clone()).as_str());
                out.push(Pending {
                    kind: "cloudflare_email_routing_rule",
                    import_id: format!("{}/{}", zone.id, id),
                    name: name.clone(),
                    attrs: attrs([
                        ("zone_id", Attr::lit(json!(zone.id))),
                        ("name", Attr::from_json(&rule["name"])),
                        ("enabled", Attr::from_json(&rule["enabled"])),
                        ("priority", Attr::from_json(&rule["priority"])),
                        ("matchers", Attr::from_json(&rule["matchers"])),
                        // Where a forward sends is a secret: it leaves here as a
                        // variable reference and never enters the model.
                        ("actions", forwards(&rule["actions"], &name, destinations)),
                    ]),
                });
            }
        }

        let listed = self
            .optional(
                self.get(&format!("{base}/rulesets")),
                "zone rulesets",
                &zone.name,
                not_imported,
            )
            .await?;
        if let Some(listed) = listed {
            for ruleset in array(&listed, "result") {
                // Account and root rulesets are not this slice's: only the ones
                // scoped to the zone, read in full so their rules come across.
                if field(ruleset, "kind").as_deref() != Some("zone") {
                    continue;
                }
                let Some(id) = field(ruleset, "id") else { continue };
                let name = slug(field(ruleset, "name").unwrap_or_else(|| id.clone()).as_str());
                let Some(full) = self
                    .optional(
                        self.get(&format!("{}/rulesets/{}", base, encode(&id))),
                        &format!("zone ruleset {name}"),
                        &zone.name,
                        not_imported,
                    )
                    .await?
                else {
                    continue;
                };
                out.push(Pending {
                    kind: "cloudflare_ruleset",
                    import_id: format!("zones/{}/{}", zone.id, id),
                    name,
                    attrs: attrs([
                        ("zone_id", Attr::lit(json!(zone.id))),
                        ("name", Attr::from_json(&ruleset["name"])),
                        ("kind", Attr::from_json(&ruleset["kind"])),
                        ("phase", Attr::from_json(&ruleset["phase"])),
                        ("rules", kept(&full["result"]["rules"], RULE_FIELDS)),
                    ]),
                });
            }
        }

        let bots = self
            .optional(
                self.get(&format!("{base}/bot_management")),
                "bot management",
                &zone.name,
                not_imported,
            )
            .await?;
        if let Some(bots) = bots {
            out.push(Pending {
                kind: "cloudflare_bot_management",
                import_id: zone.id.clone(),
                name: "this".to_string(),
                attrs: json_attrs([
                    ("zone_id", json!(zone.id)),
                    ("fight_mode", bots["result"]["fight_mode"].clone()),
                ]),
            });
        }

        Ok(out.finish())
    }

    // -- account-level objects ---------------------------------------------

    /// The objects that hang off the account rather than a zone, all in the
    /// [`ACCOUNT_MODULE`].
    async fn account_level(
        &self,
        account_id: &str,
        account: &mut Account,
    ) -> Result<Vec<Resource>, Error> {
        let mut out = Builder::new(ACCOUNT_MODULE);
        let base = format!("/accounts/{}", encode(account_id));
        let id_var = Attr::expr(format!("var.{ACCOUNT_VAR}"));

        let projects = self.get(&format!("{base}/pages/projects")).await?;
        for project in array(&projects, "result") {
            let Some(name) = field(project, "name") else { continue };
            out.push(Pending {
                kind: "cloudflare_pages_project",
                import_id: format!("{account_id}/{name}"),
                name: slug(&name),
                attrs: attrs([
                    ("account_id", id_var.clone()),
                    ("name", Attr::lit(json!(name))),
                    ("production_branch", Attr::from_json(&project["production_branch"])),
                ]),
            });
            let domains =
                self.get(&format!("{}/pages/projects/{}/domains", base, encode(&name))).await?;
            for domain in array(&domains, "result") {
                let Some(host) = field(domain, "name") else { continue };
                out.push(Pending {
                    kind: "cloudflare_pages_domain",
                    import_id: format!("{account_id}/{name}/{host}"),
                    name: slug(&host),
                    attrs: attrs([
                        ("account_id", id_var.clone()),
                        ("project_name", Attr::lit(json!(name))),
                        ("name", Attr::lit(json!(host))),
                    ]),
                });
            }
        }

        let workers_domains = self.get(&format!("{base}/workers/domains")).await?;
        for domain in array(&workers_domains, "result") {
            let Some(id) = field(domain, "id") else { continue };
            out.push(Pending {
                kind: "cloudflare_workers_custom_domain",
                import_id: format!("{account_id}/{id}"),
                name: slug(&field(domain, "hostname").unwrap_or_else(|| id.clone())),
                attrs: attrs([
                    ("account_id", id_var.clone()),
                    ("hostname", Attr::from_json(&domain["hostname"])),
                    ("service", Attr::from_json(&domain["service"])),
                    ("zone_id", Attr::from_json(&domain["zone_id"])),
                    ("environment", Attr::from_json(&domain["environment"])),
                ]),
            });
        }

        let databases = self.get(&format!("{base}/d1/database")).await?;
        for database in array(&databases, "result") {
            let Some(uuid) = field(database, "uuid") else { continue };
            out.push(Pending {
                kind: "cloudflare_d1_database",
                import_id: format!("{account_id}/{uuid}"),
                name: slug(&field(database, "name").unwrap_or_else(|| uuid.clone())),
                attrs: attrs([
                    ("account_id", id_var.clone()),
                    ("name", Attr::from_json(&database["name"])),
                ]),
            });
        }

        let buckets = self.get(&format!("{base}/r2/buckets")).await?;
        for bucket in array(&buckets["result"], "buckets") {
            let Some(name) = field(bucket, "name") else { continue };
            out.push(Pending {
                kind: "cloudflare_r2_bucket",
                import_id: format!("{account_id}/{name}/default"),
                name: slug(&name),
                attrs: attrs([("account_id", id_var.clone()), ("name", Attr::lit(json!(name)))]),
            });
        }

        for namespace in self.list(&format!("{base}/storage/kv/namespaces"), "").await? {
            let Some(id) = field(&namespace, "id") else { continue };
            out.push(Pending {
                kind: "cloudflare_workers_kv_namespace",
                import_id: format!("{account_id}/{id}"),
                name: slug(field(&namespace, "title").unwrap_or_else(|| id.clone()).as_str()),
                attrs: attrs([
                    ("account_id", id_var.clone()),
                    ("title", Attr::from_json(&namespace["title"])),
                ]),
            });
        }

        // Workers scripts are listed so their absence is on the record, not
        // because this slice can carry one.
        let listed = self.get(&format!("{base}/workers/scripts")).await?;
        let scripts: Vec<String> =
            array(&listed, "result").iter().filter_map(|script| field(script, "id")).collect();
        if !scripts.is_empty() {
            account.not_imported.insert(SCRIPTS_KIND, scripts);
        }

        Ok(out.finish())
    }
}

/// A zone as the listing gave it.
struct Zone {
    id: String,
    name: String,
    slug: String,
    kind: String,
}

impl Zone {
    fn read(value: &Value) -> Option<Zone> {
        Some(Zone {
            id: field(value, "id")?,
            name: field(value, "name")?,
            slug: slug(&field(value, "name")?),
            kind: field(value, "type").unwrap_or_else(|| "full".to_string()),
        })
    }
}

/// A resource before names are deduplicated, collected per module.
struct Pending {
    kind: &'static str,
    import_id: String,
    name: String,
    attrs: BTreeMap<String, Attr>,
}

/// Collects one module's resources and hands them back sorted and named.
///
/// Names are made unique by sorting on (kind, import_id) and suffixing `_2`,
/// `_3`, … on a clash: the suffix a colliding object gets must not depend on the
/// order the API listed them in.
struct Builder {
    module: String,
    pending: Vec<Pending>,
}

impl Builder {
    fn new(module: impl Into<String>) -> Builder {
        Builder { module: module.into(), pending: Vec::new() }
    }

    fn push(&mut self, pending: Pending) {
        self.pending.push(pending);
    }

    fn finish(mut self) -> Vec<Resource> {
        self.pending.sort_by(|a, b| (&a.kind, &a.import_id).cmp(&(&b.kind, &b.import_id)));
        let mut taken: BTreeSet<String> = BTreeSet::new();
        let mut out = Vec::with_capacity(self.pending.len());
        for pending in self.pending {
            let base = pending.name;
            let mut name = base.clone();
            let mut attempt = 2;
            while !taken.insert(name.clone()) {
                name = format!("{base}_{attempt}");
                attempt += 1;
            }
            out.push(Resource {
                module: self.module.clone(),
                kind: pending.kind,
                name,
                import_id: pending.import_id,
                attrs: pending.attrs,
            });
        }
        out
    }
}

// -- small helpers -----------------------------------------------------------

/// Percent-encodes every byte outside RFC 3986's unreserved set, so an id or
/// name the API returned cannot change the shape of the path or query it is
/// interpolated into.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// A readable, identifier-shaped name: lowercase, runs of anything else
/// collapsed to one underscore. Never empty — a resource block needs a name —
/// and never starting with a digit, which HCL identifiers may not (`0rtt`
/// becomes `r_0rtt`).
fn slug(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.starts_with(|ch: char| ch.is_ascii_digit()) {
        return format!("r_{trimmed}");
    }
    if trimmed.is_empty() { "r".to_string() } else { trimmed }
}

/// A record's label relative to its zone: `www` for `www.factoryzero.dev`, and
/// `apex` for the zone name itself.
fn relative(name: &str, zone: &str) -> String {
    let suffix = format!(".{}", zone.to_ascii_lowercase());
    let lowered = name.to_ascii_lowercase();
    if lowered == zone.to_ascii_lowercase() {
        return "apex".to_string();
    }
    let label = lowered.strip_suffix(&suffix).unwrap_or(lowered.as_str());
    let label = slug(label.trim_start_matches('*').trim_start_matches('.'));
    if label.is_empty() { "apex".to_string() } else { label }
}

/// A string field of an API object.
fn field(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_string)
}

/// An array field of an API response, or nothing.
fn array<'a>(body: &'a Value, key: &str) -> &'a [Value] {
    body.get(key).and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// The attributes of a resource block.
fn attrs<const N: usize>(pairs: [(&str, Attr); N]) -> BTreeMap<String, Attr> {
    pairs.into_iter().map(|(key, value)| (key.to_string(), value)).collect()
}

/// The attributes of a resource block, from JSON the API returned, minus the
/// fields it left null: a null argument is not an argument.
fn json_attrs<const N: usize>(pairs: [(&str, Value); N]) -> BTreeMap<String, Attr> {
    pairs
        .into_iter()
        .filter(|(_, value)| !value.is_null())
        .map(|(key, value)| (key.to_string(), Attr::from_json(&value)))
        .collect()
}

/// A JSON object — or a list of them — keeping only `fields` of each.
fn kept(value: &Value, fields: &[&str]) -> Attr {
    if let Some(items) = value.as_array() {
        return Attr::List(items.iter().map(|item| kept(item, fields)).collect());
    }
    Attr::Obj(
        fields
            .iter()
            .filter_map(|key| {
                let field = value.get(*key)?;
                (!field.is_null()).then(|| ((*key).to_string(), Attr::from_json(field)))
            })
            .collect(),
    )
}

/// An email routing rule's actions, with every forward destination replaced by a
/// `var.email_routing_destinations["key"]` reference. The address itself is
/// dropped here, before the model can hold it. An action with no list of values
/// — a `drop`, say — comes across with its type and nothing else.
fn forwards(actions: &Value, name: &str, keys: &mut BTreeSet<String>) -> Attr {
    Attr::List(
        actions
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|action| {
                let kind = field(action, "type")?;
                let Some(addresses) = action.get("value").and_then(Value::as_array) else {
                    return Some(Attr::Obj(vec![("type".to_string(), Attr::lit(json!(kind)))]));
                };
                let rendered: Vec<Attr> = if kind == "forward" {
                    addresses
                        .iter()
                        .map(|_| {
                            Attr::expr(format!(
                                "var.{DESTINATIONS_VAR}[{}]",
                                hcl::quoted(&destination_key(keys, name))
                            ))
                        })
                        .collect()
                } else {
                    addresses.iter().map(Attr::from_json).collect()
                };
                Some(Attr::Obj(vec![
                    ("type".to_string(), Attr::lit(json!(kind))),
                    ("value".to_string(), Attr::List(rendered)),
                ]))
            })
            .collect(),
    )
}

/// The next unused destination key for a rule, recorded so the report can name
/// what the operator has to supply. The address never reaches this function.
fn destination_key(keys: &mut BTreeSet<String>, name: &str) -> String {
    let mut candidate = name.to_string();
    let mut attempt = 2;
    while !keys.insert(candidate.clone()) {
        candidate = format!("{name}_{attempt}");
        attempt += 1;
    }
    candidate
}

/// Parses a response body as the JSON envelope Cloudflare wraps everything in.
fn parse(body: &[u8]) -> Result<Value, Error> {
    serde_json::from_slice(body).map_err(|error| Error::Api {
        message: format!("the response is not the Cloudflare envelope: {error}"),
    })
}

/// What Cloudflare said went wrong: the `errors[].message` values, joined.
fn messages(body: &Value) -> String {
    let joined: Vec<&str> = body
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|error| error.get("message")?.as_str())
        .collect();
    if joined.is_empty() { "no message".to_string() } else { joined.join("; ") }
}
