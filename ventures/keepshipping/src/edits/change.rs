//! The pure half of the edits module: a submitted form in, the change it
//! describes out — file path, HCL, title, summary — or the plain-word
//! validation errors it fails with. Nothing here touches a port, so every
//! generator is unit-testable and deterministic: the same form always
//! renders the same bytes into the pull request.
//!
//! Every edit writes one additive file into the zone's own module
//! directory, the layout `adapters/cloudflare` generates (`modules/<zone>/…`,
//! `var.cloudflare_account_id` in scope). The console never sees a Cloudflare
//! zone id, so the generated resource looks the zone up by name — a
//! `data "cloudflare_zone"` read, which plans as no change — and every kind
//! still adds exactly one `resource` block. The kinds themselves are
//! table-driven ([`FORMS`]): the table drives the HTML form, and each
//! generator turns the same fields into HCL.

use serde_json::Value;
use std::fmt::Write as _;

/// Size ceiling for an Advanced edit's Terraform.
pub(crate) const MAX_RAW: usize = 32 * 1024;

/// Size ceiling for a plain-text variable value entered on the form.
const MAX_VALUE: usize = 1024;

/// How many resource changes one edit stores.
pub(crate) const MAX_CHANGES: usize = 200;

/// One form field. `options` non-empty makes it a dropdown, `flag` a
/// checkbox, `area` a textarea, otherwise a text input.
pub(crate) struct Field {
    pub name: &'static str,
    pub label: &'static str,
    pub ph: &'static str,
    pub default: &'static str,
    pub options: &'static [&'static str],
    pub area: bool,
    pub flag: bool,
}

const fn text(name: &'static str, label: &'static str, ph: &'static str) -> Field {
    Field { name, label, ph, default: "", options: &[], area: false, flag: false }
}

/// A dropdown with a default selection.
const fn opt(
    name: &'static str,
    label: &'static str,
    default: &'static str,
    options: &'static [&'static str],
) -> Field {
    Field { name, label, ph: "", default, options, area: false, flag: false }
}

/// A checkbox, off unless the form carried it on.
const fn flag(name: &'static str, label: &'static str) -> Field {
    Field { name, label, ph: "", default: "", options: &[], area: false, flag: true }
}

const ZONE_FIELD: Field = text("zone", "Zone", "example.com");
const WORKER_FIELD: Field = text("worker", "Worker's name", "my-worker");

/// A kind of change: its slug, plain name, the note under its form, and the
/// fields it asks for.
pub(crate) struct Form {
    pub kind: &'static str,
    pub name: &'static str,
    pub note: &'static str,
    pub fields: &'static [Field],
}

/// The forms on offer, in chooser order. The slug is what `/new?kind=` takes
/// and what the `edits.kind` column stores.
pub(crate) const FORMS: &[Form] = &[
    Form {
        kind: "dns",
        name: "DNS record",
        note: "",
        fields: &[
            ZONE_FIELD,
            text("name", "Record name (@ for the zone itself)", "www"),
            opt("rtype", "Record type", "A", &["A", "AAAA", "CNAME", "TXT"]),
            text("content", "Content", "192.0.2.10"),
            Field { default: "1", ph: "1", ..text("ttl", "TTL seconds (1 is automatic)", "1") },
            flag("proxied", "Send through Cloudflare's proxy"),
        ],
    },
    Form {
        kind: "redirect",
        name: "Redirect",
        note: "A zone has one dynamic-redirect ruleset; this change owns it. More redirects \
               than one fit an Advanced change.",
        fields: &[
            ZONE_FIELD,
            text("from_host", "Redirect from host", "old.example.com"),
            Field {
                default: "/",
                ..text("from_path", "Redirect from path (/ for everything)", "/")
            },
            text("to_url", "Redirect to address", "https://example.com/new"),
            opt("status", "Status", "301", &["301", "302"]),
            Field { default: "on", ..flag("keep_query", "Keep the query string") },
        ],
    },
    Form {
        kind: "domain",
        name: "Worker domain",
        note: "",
        fields: &[ZONE_FIELD, text("hostname", "Hostname", "api.example.com"), WORKER_FIELD],
    },
    Form {
        kind: "route",
        name: "Route",
        note: "",
        fields: &[ZONE_FIELD, text("pattern", "Route pattern", "example.com/api/*"), WORKER_FIELD],
    },
    Form {
        kind: "email",
        name: "Email rule",
        note: "",
        fields: &[
            ZONE_FIELD,
            text("address", "Address to forward", "team@example.com"),
            text("destination", "Deliver to", "you@elsewhere.com"),
        ],
    },
    Form {
        kind: "setting",
        name: "Zone setting",
        note: "Only the settings listed are offered, and each accepts a fixed set of values.",
        fields: &[
            ZONE_FIELD,
            opt("setting", "Setting", "", SETTINGS_NAMES),
            text("value", "Value", "on"),
        ],
    },
    Form {
        kind: "variable",
        name: "Worker variable",
        note: "A secret's value never enters the pull request: leave the value empty and set \
               it out of band (with wrangler secret put, for example). The pull request \
               carries the name only, plus the exact lines to merge into the Worker's \
               bindings.",
        fields: &[
            ZONE_FIELD,
            WORKER_FIELD,
            text("name", "Variable name", "API_KEY"),
            text("value", "Value (leave empty for a secret)", ""),
        ],
    },
    Form {
        kind: "raw",
        name: "Advanced (Terraform)",
        note: "Written as given, under the zone's module directory.",
        fields: &[
            ZONE_FIELD,
            text("file", "File name", "edit-extra.tf"),
            Field { area: true, ..text("text", "Terraform", "") },
        ],
    },
];

/// The settings a `setting` edit may touch, with the values each accepts.
/// Anything outside the list is refused: these are the settings whose
/// wording the console can say something honest about. The names also drive
/// the form's dropdown, so the two can never drift.
pub(crate) const SETTINGS: &[(&str, &[&str])] = &[
    ("always_use_https", &["on", "off"]),
    ("min_tls_version", &["default", "1.0", "1.1", "1.2", "1.3"]),
    ("ssl", &["off", "flexible", "full", "strict"]),
    ("security_level", &["off", "essentially_off", "low", "medium", "high", "under_attack"]),
];

/// Just the setting names, for the dropdown.
const SETTINGS_NAMES: &[&str] = &["always_use_https", "min_tls_version", "ssl", "security_level"];

/// Looks up a kind's form.
pub(crate) fn form(kind: &str) -> Option<&'static Form> {
    FORMS.iter().find(|&spec| spec.kind == kind)
}

/// The change a form describes: what a pull request is opened with.
#[derive(Debug)]
pub(crate) struct Change {
    pub zone: String,
    pub kind: &'static str,
    /// One plain-words line: the page's title and the PR's subject.
    pub title: String,
    /// The same in a few bullets, as the PR body's summary.
    pub summary_md: String,
    /// `(path, content)` pairs, relative to the infra repository root.
    pub files: Vec<(String, String)>,
}

/// Validates the form and builds the change. `Err` carries plain-word
/// messages, one per problem, for the page to show above the form again.
pub(crate) fn parse(
    kind: &str,
    params: &[(String, String)],
    edit_id: &str,
    infra_dir: &str,
) -> Result<Change, Vec<String>> {
    let Some(spec) = form(kind) else {
        return Err(vec![format!("Unknown change kind {kind:?}.")]);
    };
    let ctx = Ctx {
        zone: super::param(params, "zone").unwrap_or_default().trim().to_owned(),
        id: edit_id,
        dir: infra_dir,
        params,
    };
    let mut errors: Vec<String> = Vec::new();
    if !is_hostname(&ctx.zone) {
        errors.push("Enter the zone this change belongs to, like example.com.".to_owned());
    }
    let (title, summary, files) = match spec.kind {
        "dns" => dns(&ctx, &mut errors),
        "redirect" => redirect(&ctx, &mut errors),
        "domain" => domain(&ctx, &mut errors),
        "route" => route(&ctx, &mut errors),
        "email" => email(&ctx, &mut errors),
        "setting" => setting(&ctx, &mut errors),
        "variable" => variable(&ctx, &mut errors),
        _ => raw(&ctx, &mut errors),
    };
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Change { zone: ctx.zone, kind: spec.kind, title, summary_md: summary, files })
}

/// Everything a generator needs: the zone, the edit id, the infra dir, and
/// the submitted fields.
struct Ctx<'a> {
    zone: String,
    id: &'a str,
    dir: &'a str,
    params: &'a [(String, String)],
}

impl Ctx<'_> {
    /// A submitted field, trimmed.
    fn f(&self, name: &str) -> String {
        super::param(self.params, name).unwrap_or_default().trim().to_owned()
    }
    /// A checkbox's state: present and truthy means on.
    fn on(&self, name: &str) -> bool {
        matches!(self.f(name).as_str(), "on" | "true" | "1")
    }
}

/// One generator's output: title, summary, and the files fully formed.
type Build = (String, String, Vec<(String, String)>);

fn done(ctx: &Ctx, title: &str, summary: String, body: String) -> Build {
    let path = file_for(ctx.dir, &ctx.zone, ctx.id);
    let content = format!(
        "# Added by Keep Shipping (edit {}): {title}\n# The zone is looked up by name, so this file carries no ids and no secrets.\n\ndata \"cloudflare_zone\" \"ks_edit_zone\" {{\n  filter = {{ name = {} }}\n}}\n\n{body}",
        ctx.id.to_ascii_lowercase(),
        q(&ctx.zone),
    );
    (title.to_owned(), summary, vec![(path, content)])
}

/// A generator's tail: the one resource this kind adds, wrapped into the
/// one file the pull request carries.
fn one(ctx: &Ctx, resource: &str, title: String, summary: String, attrs: String) -> Build {
    done(ctx, &title, summary, block(resource, &res(ctx.id), &attrs))
}

/// `name = "value"` with `value` quoted.
fn attr(name: &str, value: &str) -> String {
    format!("  {name} = {}\n", q(value))
}

/// `name = expression` verbatim (references, numbers, booleans).
fn expr(name: &str, expression: &str) -> String {
    format!("  {name} = {expression}\n")
}

/// One `resource "type" "label" { … }` block.
fn block(resource: &str, label: &str, attrs: &str) -> String {
    format!("resource \"{resource}\" \"{label}\" {{\n{attrs}}}\n")
}

/// The `data "cloudflare_zone"` reference every generated resource shares.
const ZONE_REF: &str = "data.cloudflare_zone.ks_edit_zone.id";

// -- the one resource each kind writes ------------------------------------

/// `resource "cloudflare_dns_record"`: one record in the zone.
fn dns(ctx: &Ctx, errors: &mut Vec<String>) -> Build {
    let name = record_name(&ctx.f("name"), &ctx.zone, errors);
    let rtype = ctx.f("rtype").to_ascii_uppercase();
    if !matches!(rtype.as_str(), "A" | "AAAA" | "CNAME" | "TXT") {
        errors.push("Record type must be one of A, AAAA, CNAME or TXT.".to_owned());
    }
    let content = ctx.f("content");
    match rtype.as_str() {
        "A" if content.parse::<std::net::Ipv4Addr>().is_err() => {
            errors.push("An A record needs an IPv4 address, like 192.0.2.10.".to_owned());
        }
        "AAAA" if content.parse::<std::net::Ipv6Addr>().is_err() => {
            errors.push("An AAAA record needs an IPv6 address, like 2001:db8::1.".to_owned());
        }
        "CNAME" if !is_hostname(&content) => {
            errors.push("A CNAME record's target must be a hostname.".to_owned());
        }
        "TXT" if content.is_empty() || content.len() > 4096 => {
            errors.push("Enter the TXT record's text (up to 4096 characters).".to_owned());
        }
        _ => {}
    }
    let proxied = ctx.on("proxied");
    if proxied && !matches!(rtype.as_str(), "A" | "AAAA" | "CNAME") {
        errors.push("Only A, AAAA and CNAME records can go through the proxy.".to_owned());
    }
    let ttl = ttl_of(&ctx.f("ttl"), errors);
    if !errors.is_empty() {
        return empty();
    }
    let attrs = expr("zone_id", ZONE_REF)
        + &attr("name", &name)
        + &attr("type", &rtype)
        + &attr("content", &content)
        + &expr("ttl", &ttl.to_string())
        + &expr("proxied", &proxied.to_string());
    one(
        ctx,
        "cloudflare_dns_record",
        format!("DNS record {name} ({rtype})"),
        format!(
            "- Record: `{name}` ({rtype}) → `{content}`\n- Proxied: {}\n- TTL: {ttl}\n",
            yes(proxied),
        ),
        attrs,
    )
}

/// `resource "cloudflare_ruleset"` in phase `http_request_dynamic_redirect`;
/// a zone has one ruleset per phase, so this kind owns the whole file.
fn redirect(ctx: &Ctx, errors: &mut Vec<String>) -> Build {
    let host = ctx.f("from_host");
    if !is_hostname(&host) {
        errors.push("Enter the host to redirect from, like old.example.com.".to_owned());
    }
    let path = ctx.f("from_path");
    if !path.starts_with('/') || path.contains(char::is_whitespace) || path.len() > 512 {
        errors.push(
            "The path to redirect from must start with / (use / for the whole site).".to_owned(),
        );
    }
    let target = ctx.f("to_url");
    if !is_url(&target) {
        errors.push("Enter the address to redirect to, starting with https://.".to_owned());
    }
    let status: u16 = if ctx.f("status") == "302" { 302 } else { 301 };
    let keep = ctx.on("keep_query");
    if !errors.is_empty() {
        return empty();
    }
    let expression =
        format!("(http.host eq {} and http.request.uri.path eq {})", q(&host), q(&path));
    let attrs = expr("zone_id", ZONE_REF)
        + &attr("name", "ks-edit-dynamic-redirect")
        + "  kind    = \"zone\"\n  phase   = \"http_request_dynamic_redirect\"\n  rules = [{\n    action = \"redirect\"\n    action_parameters = {\n      redirect = {\n"
        + &expr("status_code", &status.to_string())
        + &attr("target_url", &target)
        + &expr("preserve_query_string", &keep.to_string())
        + "      }\n    }\n"
        + &attr("expression", &expression)
        + "    enabled    = true\n  }]\n";
    let title = format!("Redirect {host}{path} → {target}");
    let summary = format!(
        "- From: `{host}{path}`\n- To: `{target}`\n- Status: {status} ({})\n- Query string: {}\n",
        if status == 301 { "moved for good" } else { "moved for now" },
        if keep { "kept" } else { "dropped" },
    );
    one(ctx, "cloudflare_ruleset", title, summary, attrs)
}

/// `resource "cloudflare_workers_custom_domain"`: a hostname onto a Worker.
fn domain(ctx: &Ctx, errors: &mut Vec<String>) -> Build {
    let hostname = record_name(&ctx.f("hostname"), &ctx.zone, errors);
    let service = ctx.f("worker");
    if !is_worker_name(&service) {
        errors.push("Enter the Worker's name (lowercase letters, numbers, dashes).".to_owned());
    }
    if !errors.is_empty() {
        return empty();
    }
    let attrs = expr("account_id", "var.cloudflare_account_id")
        + &expr("zone_id", ZONE_REF)
        + &attr("hostname", &hostname)
        + &attr("service", &service)
        + "  environment = \"production\"\n";
    let title = format!("Worker domain {hostname}");
    one(
        ctx,
        "cloudflare_workers_custom_domain",
        title,
        format!("- Hostname: `{hostname}`\n- Worker: `{service}`\n"),
        attrs,
    )
}

/// `resource "cloudflare_workers_route"`: a URL pattern onto a Worker.
fn route(ctx: &Ctx, errors: &mut Vec<String>) -> Build {
    let pattern = ctx.f("pattern");
    let service = ctx.f("worker");
    if pattern.is_empty() || pattern.len() > 256 || pattern.contains(char::is_whitespace) {
        errors.push("Enter the route pattern, like example.com/api/*.".to_owned());
    } else if !pattern.to_ascii_lowercase().contains(&ctx.zone.to_ascii_lowercase()) {
        errors.push(format!("The pattern must be inside the zone ({}).", ctx.zone));
    }
    if !is_worker_name(&service) {
        errors.push("Enter the Worker's name (lowercase letters, numbers, dashes).".to_owned());
    }
    if !errors.is_empty() {
        return empty();
    }
    let attrs = expr("zone_id", ZONE_REF) + &attr("pattern", &pattern) + &attr("script", &service);
    let title = format!("Route {pattern}");
    one(
        ctx,
        "cloudflare_workers_route",
        title,
        format!("- Pattern: `{pattern}`\n- Worker: `{service}`\n"),
        attrs,
    )
}

/// `resource "cloudflare_email_routing_rule"`: one address in, one out.
fn email(ctx: &Ctx, errors: &mut Vec<String>) -> Build {
    let address = ctx.f("address");
    let destination = ctx.f("destination");
    if !is_email(&address) || !address.ends_with(&format!("@{}", ctx.zone)) {
        errors.push(format!("Enter the address to forward, ending in @{}.", ctx.zone));
    }
    if !is_email(&destination) {
        errors.push("Enter the address that receives the mail.".to_owned());
    }
    if !errors.is_empty() {
        return empty();
    }
    let attrs = expr("zone_id", ZONE_REF)
        + &attr("name", &format!("forward {address}"))
        + "  enabled = true\n  matchers = [{ type = \"literal\", field = \"to\", value = "
        + &q(&address)
        + " }]\n  actions  = [{ type = \"forward\", value = ["
        + &q(&destination)
        + "] }]\n";
    let title = format!("Email rule {address}");
    one(
        ctx,
        "cloudflare_email_routing_rule",
        title,
        format!("- Address: `{address}`\n- Forwards to: `{destination}`\n"),
        attrs,
    )
}

/// `resource "cloudflare_zone_setting"`: one of the allow-listed settings.
fn setting(ctx: &Ctx, errors: &mut Vec<String>) -> Build {
    let id = ctx.f("setting");
    let value = ctx.f("value");
    let Some(allowed) = SETTINGS.iter().find(|&&(name, _)| name == id).map(|&(_, values)| values)
    else {
        errors.push(format!("Choose a setting this console knows: {}.", SETTINGS_NAMES.join(", ")));
        return empty();
    };
    if !allowed.contains(&value.as_str()) {
        errors.push(format!("{id} must be one of: {}.", allowed.to_vec().join(", ")));
        return empty();
    }
    let attrs = expr("zone_id", ZONE_REF) + &attr("setting_id", &id) + &attr("value", &value);
    one(
        ctx,
        "cloudflare_zone_setting",
        format!("Zone setting {id}"),
        format!("- Setting: `{id}`\n- Value: `{value}`\n"),
        attrs,
    )
}

/// A Worker environment variable. Bindings live on the Worker's own
/// `cloudflare_workers_script` resource, so no additive file can attach one
/// — this kind is honest about that: it writes the exact `bindings` entry
/// to merge into the Worker's resource and never pretends to apply it. For
/// a secret only the NAME enters the repository; the value is set out of
/// band (`wrangler secret put`, or the harness Secrets port as `TF_VAR_NAME`
/// at plan time).
fn variable(ctx: &Ctx, errors: &mut Vec<String>) -> Build {
    let service = ctx.f("worker");
    let name = ctx.f("name");
    let value = ctx.f("value");
    if !is_worker_name(&service) {
        errors.push("Enter the Worker's name (lowercase letters, numbers, dashes).".to_owned());
    }
    if !is_var_name(&name) {
        errors.push(
            "Enter the variable's name (letters, numbers, underscores, starting with a letter)."
                .to_owned(),
        );
    }
    // A long value does not belong in a reviewable pull request; real
    // secrets go out of band anyway (the empty-value path below).
    if value.len() > MAX_VALUE {
        errors.push(format!(
            "The value is {} bytes; plain-text values are capped at {MAX_VALUE}. For anything \
             longer (or secret), leave the value empty and set it out of band.",
            value.len()
        ));
    }
    // A secret-looking name with a value typed in is refused rather than
    // written into a pull request: the value belongs out of band.
    if !value.is_empty()
        && ["KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD"]
            .iter()
            .any(|suffix| name.to_ascii_uppercase().ends_with(suffix))
    {
        errors.push(format!(
            "{name} looks like a secret. Leave the value empty — the value is set out of band \
             and never enters this repository or the pull request."
        ));
    }
    if !errors.is_empty() {
        return empty();
    }
    let entry = if value.is_empty() {
        format!(
            "#   {{\n#     name = {}\n#     type = \"secret_text\"\n#     text = var.{name}  # set out of band, see below\n#   }},\n\n# The value itself is never in this repository. Set it out of band with\n# `wrangler secret put {name}` on the Worker, or provide it to plan and apply\n# as TF_VAR_{name} through the harness Secrets port (SecretRef `env:{name}`).\nvariable {} {{\n  type        = string\n  sensitive   = true\n  description = \"Set out of band; never committed.\"\n}}\n",
            q(&name),
            q(&name),
        )
    } else {
        format!(
            "#   {{\n#     name = {}\n#     type = \"plain_text\"\n#     text = {}\n#   }},\n",
            q(&name),
            q(&value),
        )
    };
    let body = format!(
        "# Worker bindings live on the Worker's own resource, so this file adds\n# no resource: merge the marked entry below into that Worker's\n# `bindings` list. The pull request is the review; nothing applies it.\n\n# --- merge into resource \"cloudflare_workers_script\" for {service} ---\n# bindings = [\n{entry}# --- end of the entry to merge ---\n",
    );
    let title = format!("Worker variable {name} on {service}");
    let summary_value = if value.is_empty() {
        "a secret — the value is set out of band, never in this repository".to_owned()
    } else {
        format!("plain text (`{value}`)")
    };
    done(
        ctx,
        &title,
        format!("- Worker: `{service}`\n- Variable: `{name}`\n- Value: {summary_value}\n"),
        body,
    )
}

/// The Advanced tab: a file name and Terraform text, written verbatim.
fn raw(ctx: &Ctx, errors: &mut Vec<String>) -> Build {
    let file = ctx.f("file");
    let body = ctx.f("text");
    if !is_file_name(&file) {
        errors.push(
            "File name must end in .tf and use only letters, numbers, dots, dashes and \
             underscores."
                .to_owned(),
        );
    }
    if body.is_empty() {
        errors.push("Write the Terraform to add.".to_owned());
    } else if body.contains('\0') {
        errors.push("The Terraform cannot contain null bytes.".to_owned());
    } else if body.len() > MAX_RAW {
        errors.push(format!("The Terraform is {} bytes; the ceiling is {MAX_RAW}.", body.len()));
    }
    if !errors.is_empty() {
        return empty();
    }
    let path = format!("{}/{}", dir_for(ctx.dir, &ctx.zone), file);
    let title = format!("Advanced Terraform change ({file})");
    let summary = format!("- File: `{path}`\n- {} bytes, written as given.\n", body.len());
    (title, summary, vec![(path, format!("{body}\n"))])
}

fn empty() -> Build {
    (String::new(), String::new(), Vec::new())
}

/// The resource label inside one edit's file: unique per edit, HCL-safe.
fn res(id: &str) -> String {
    format!("ks_edit_{}", id.to_ascii_lowercase())
}

// -- files and their paths -------------------------------------------------

/// The directory one zone's files live in, matching the layout
/// `adapters/cloudflare` generates: `modules/<zone-slug>/`.
pub(crate) fn dir_for(infra_dir: &str, zone: &str) -> String {
    let root = infra_dir.trim_matches('/');
    let root = if root.is_empty() { String::new() } else { format!("{root}/") };
    format!("{root}modules/{}", slug(zone))
}

/// One edit's default file: `modules/<zone>/edit-<id>.tf`.
pub(crate) fn file_for(infra_dir: &str, zone: &str, edit_id: &str) -> String {
    format!("{}/edit-{}.tf", dir_for(infra_dir, zone), edit_id.to_ascii_lowercase())
}

/// The zone's module directory name: lowercase letters and digits, anything
/// else an underscore — the same slug `adapters/cloudflare` names modules by.
pub(crate) fn slug(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
    }
    out.trim_matches('_').to_owned()
}

// -- plans in plain words ---------------------------------------------------

/// What a posted plan said, ready to render: one row per resource change and
/// the three counts, with removals and replacements flagged.
pub(crate) struct PlanView {
    /// `(kind, plain-words sentence)` per resource, plan order.
    pub rows: Vec<(Row, String)>,
    pub add: usize,
    pub change: usize,
    pub destroy: usize,
}

/// A row's colour class: additions green, changes amber, removals and
/// replacements red.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Row {
    Add,
    Change,
    Remove,
    Replace,
}

impl PlanView {
    /// `1 to add · 0 to change · 0 to remove`. A replacement is one add and
    /// one removal — which is what the plan file itself counts.
    pub(crate) fn counts(&self) -> String {
        format!("{} to add · {} to change · {} to remove", self.add, self.change, self.destroy)
    }

    /// Whether the plan removes or replaces anything: the page warns, and
    /// approving then requires the zone typed back.
    pub(crate) fn risky(&self) -> bool {
        self.destroy > 0
    }

    /// Reads back what [`extract`] stored. Unparsable stored JSON renders as
    /// no changes rather than breaking the page.
    pub(crate) fn from_json(stored: &str) -> PlanView {
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(stored) else {
            return PlanView { rows: Vec::new(), add: 0, change: 0, destroy: 0 };
        };
        let mut view = PlanView { rows: Vec::new(), add: 0, change: 0, destroy: 0 };
        for change in parsed.as_array().into_iter().flatten() {
            let Some(address) = change.get("address").and_then(Value::as_str) else {
                continue;
            };
            let actions: Vec<&str> = change
                .get("actions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let (delete, create, update) = (
                actions.contains(&"delete"),
                actions.contains(&"create"),
                actions.contains(&"update"),
            );
            let kind = match (delete, create, update) {
                (true, true, _) => Row::Replace,
                (true, false, _) => Row::Remove,
                (false, true, false) => Row::Add,
                (_, _, true) => Row::Change,
                _ => continue,
            };
            view.add += usize::from(create);
            view.change += usize::from(update);
            view.destroy += usize::from(delete);
            let detail = change.get("after").cloned().unwrap_or(Value::Null);
            view.rows.push((kind, row_text(kind, address, &detail)));
        }
        view
    }
}

/// One row in words: `Add the DNS record: www.example.com → 192.0.2.10` —
/// no Terraform address; a person reads the what, not the HCL path. A
/// removal stops at what went away (there is no "→ where").
fn row_text(kind: Row, address: &str, body: &Value) -> String {
    let verb = match kind {
        Row::Add => "Add",
        Row::Change => "Change",
        Row::Remove => "Remove",
        Row::Replace => "Replace",
    };
    let mut text = format!("{verb}{}", noun_of(address));
    let pick = |key: &str| body.get(key).and_then(Value::as_str).filter(|value| !value.is_empty());
    if kind == Row::Remove {
        if let Some(what) = pick("name")
            .or_else(|| pick("hostname"))
            .or_else(|| pick("pattern"))
            .or_else(|| pick("setting_id"))
            .or_else(|| pick("script"))
            .or_else(|| pick("service"))
        {
            let _ = write!(text, ": {what}");
        }
        return text;
    }
    if let Some(name) = pick("name").or_else(|| pick("hostname")) {
        let _ = write!(text, ": {name}");
        if let Some(content) = pick("content") {
            let _ = write!(text, " → {content}");
        }
        if address.contains("dns_record")
            && let Some(rtype) = pick("type")
        {
            let _ = write!(text, " ({rtype})");
        }
    } else if let Some(pattern) = pick("pattern") {
        let _ = write!(text, ": {pattern}");
    } else if let Some(setting) = pick("setting_id") {
        let _ = write!(text, ": {setting}");
        if let Some(value) = pick("value") {
            let _ = write!(text, " → {value}");
        }
    } else if let Some(script) = pick("script").or_else(|| pick("service")) {
        let _ = write!(text, ": {script}");
    }
    text
}

/// A resource type in words, from the plan address.
fn noun_of(address: &str) -> &'static str {
    for (needle, noun) in [
        ("dns_record", " the DNS record"),
        ("ruleset", " the redirect ruleset"),
        ("workers_custom_domain", " the worker domain"),
        ("workers_route", " the route"),
        ("email_routing_rule", " the email rule"),
        ("zone_setting", " the zone setting"),
        ("workers_script", " the worker"),
        ("worker", " the worker"),
    ] {
        if address.contains(needle) {
            return noun;
        }
    }
    " the resource"
}

/// Narrows a `tofu show -json` plan to what the module stores: per resource
/// change, the address, the actions, and the few fields the detail page
/// quotes (from `after`, falling back to `before`, which is where a removal
/// keeps its values). At most [`MAX_CHANGES`] resources are kept.
pub(crate) fn extract(plan: &Value) -> Value {
    let empty = Vec::new();
    let changes = plan.get("resource_changes").and_then(Value::as_array).unwrap_or(&empty);
    Value::Array(
        changes
            .iter()
            .take(MAX_CHANGES)
            .map(|change| {
                serde_json::json!({
                    "address": change.get("address").cloned().unwrap_or_default(),
                    "actions": change
                        .get("change")
                        .and_then(|c| c.get("actions"))
                        .cloned()
                        .unwrap_or_default(),
                    "after": picked(change),
                })
            })
            .collect(),
    )
}

/// The fields [`row_text`] quotes, `after` first, `before` as fallback.
fn picked(change: &Value) -> Value {
    let change = change.get("change");
    let mut out = serde_json::Map::new();
    for key in [
        "name",
        "content",
        "type",
        "hostname",
        "pattern",
        "script",
        "setting_id",
        "value",
        "service",
    ] {
        if let Some(value) = change
            .and_then(|c| c.get("after"))
            .and_then(|after| after.get(key))
            .filter(|v| !v.is_null())
            .or_else(|| change.and_then(|c| c.get("before")).and_then(|before| before.get(key)))
        {
            out.insert(key.to_owned(), value.clone());
        }
    }
    Value::Object(out)
}

// -- validation and quoting helpers ----------------------------------------

fn yes(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}

/// TTL as stored: `1` is Cloudflare's automatic; otherwise 60..=86400.
fn ttl_of(raw: &str, errors: &mut Vec<String>) -> i64 {
    match raw.parse::<i64>() {
        Ok(1) => 1,
        Ok(ttl) if (60..=86_400).contains(&ttl) => ttl,
        _ => {
            errors.push("TTL must be 1 (automatic) or between 60 and 86400 seconds.".to_owned());
            1
        }
    }
}

/// A record's full name: `@` is the zone itself; a bare label or any name
/// not ending in the zone gets the zone appended.
fn record_name(raw: &str, zone: &str, errors: &mut Vec<String>) -> String {
    let lowered = raw.trim_end_matches('.').to_ascii_lowercase();
    if lowered.is_empty() || lowered == "@" {
        if lowered.is_empty() {
            errors.push("Enter the record's name (use @ for the zone itself).".to_owned());
        }
        return zone.to_owned();
    }
    if !is_hostname(&lowered) {
        errors
            .push("Enter a hostname, like www.example.com (or @ for the zone itself).".to_owned());
        return lowered;
    }
    let suffix = format!(".{zone}");
    if lowered == zone.to_ascii_lowercase() || lowered.ends_with(&suffix) {
        lowered
    } else {
        format!("{lowered}.{zone}")
    }
}

/// A hostname: dot-separated labels of letters, digits and inner hyphens,
/// 253 bytes at most.
pub(crate) fn is_hostname(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 253
        && text.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// A Worker name: lowercase letters, digits, dashes and underscores, led by
/// a letter or digit.
fn is_worker_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 63
        && text.starts_with(|ch: char| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
}

/// A JavaScript-style environment variable name.
fn is_var_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_')
        && text.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// An address to forward: `local@` plus a hostname, nothing fancier.
fn is_email(text: &str) -> bool {
    let Some((local, domain)) = text.rsplit_once('@') else {
        return false;
    };
    !local.is_empty() && local.len() <= 64 && is_hostname(domain)
}

/// An absolute http(s) URL with no whitespace or control characters.
fn is_url(text: &str) -> bool {
    (text.starts_with("https://") || text.starts_with("http://"))
        && text.len() <= 2048
        && !text.contains(char::is_whitespace)
        && !text.chars().any(char::is_control)
}

/// An Advanced edit's file name: one path segment ending in `.tf`.
fn is_file_name(text: &str) -> bool {
    let Some(stem) = text.strip_suffix(".tf") else {
        return false;
    };
    !stem.is_empty()
        && !stem.starts_with('.')
        && text.len() <= 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// Quotes and escapes `text` so no byte of it can end the HCL string or open
/// an interpolation: `"`, `\`, `${` and `%{` are escaped, control characters
/// too — the same rules `adapters/cloudflare`'s emitter applies.
pub(crate) fn q(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '$' if chars.clone().next() == Some('{') => {
                chars.next();
                out.push_str("$${");
            }
            '%' if chars.clone().next() == Some('{') => {
                chars.next();
                out.push_str("%%{");
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if ch.is_control() => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn every_kind_turns_its_form_into_exactly_one_file() {
        let cases: &[(&str, Vec<(&str, &str)>)] = &[
            (
                "redirect",
                vec![
                    ("from_host", "old.example.com"),
                    ("from_path", "/"),
                    ("to_url", "https://example.com/"),
                    ("status", "301"),
                    ("keep_query", "on"),
                ],
            ),
            ("domain", vec![("hostname", "api"), ("worker", "my-worker")]),
            ("route", vec![("pattern", "example.com/api/*"), ("worker", "my-worker")]),
            ("email", vec![("address", "team@example.com"), ("destination", "you@elsewhere.com")]),
            ("setting", vec![("setting", "ssl"), ("value", "strict")]),
            ("variable", vec![("worker", "my-worker"), ("name", "FEATURE"), ("value", "on")]),
            (
                "raw",
                vec![
                    ("file", "edit-extra.tf"),
                    ("text", "resource \"cloudflare_zone_setting\" \"x\" {}"),
                ],
            ),
        ];
        for (kind, fields) in cases {
            let mut params = form(&[("zone", "example.com")]);
            params.extend(form(fields));
            let change = parse(kind, &params, "01hxyz", ".").expect(kind);
            assert_eq!(change.files.len(), 1, "{kind}");
            assert_eq!(change.zone, "example.com");
            let (_, content) = &change.files[0];
            if *kind == "raw" {
                // The Advanced kind writes the Terraform as given — the
                // author supplies their own lookups.
                assert!(content.contains("resource \"cloudflare_zone_setting\""), "{content}");
            } else {
                // The zone is looked up by name (provider v5 takes it under
                // `filter`), which plans as no change.
                assert!(
                    content.contains("data \"cloudflare_zone\" \"ks_edit_zone\"")
                        && content.contains("filter = { name = \"example.com\" }"),
                    "{kind}: {content}"
                );
                assert!(content.contains("resource \"cloudflare_"), "{kind}: {content}");
            }
        }
    }

    #[test]
    fn hcl_quoting_escapes_interpolations_and_quotes() {
        assert_eq!(q("plain"), "\"plain\"");
        assert_eq!(q("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(q("${var.x}"), "\"$${var.x}\"");
        assert_eq!(q("100$ and %"), "\"100$ and %\"");
    }

    #[test]
    fn a_secret_variable_never_reaches_the_hcl() {
        let errors = parse(
            "variable",
            &form(&[
                ("zone", "example.com"),
                ("worker", "api"),
                ("name", "API_KEY"),
                ("value", "sk-super-secret"),
            ]),
            "01hxyz",
            ".",
        )
        .expect_err("a secret-looking value is refused");
        assert!(errors[0].contains("looks like a secret"), "{errors:?}");

        let change = parse(
            "variable",
            &form(&[("zone", "example.com"), ("worker", "api"), ("name", "API_KEY")]),
            "01hxyz",
            ".",
        )
        .expect("an empty value is the secret path");
        let (_, file) = &change.files[0];
        assert!(file.contains("\"API_KEY\""), "{file}");
        assert!(!file.contains("sk-super-secret"), "the secret leaked: {file}");
        assert!(file.contains("sensitive   = true"), "{file}");
        assert!(file.contains("var.API_KEY"), "{file}");
    }

    #[test]
    fn file_paths_follow_the_zone_module_layout() {
        assert_eq!(
            file_for("infra", "Example.COM", "01AB"),
            "infra/modules/example_com/edit-01ab.tf"
        );
        assert_eq!(file_for("", "example.com", "01AB"), "modules/example_com/edit-01ab.tf");
        assert_eq!(dir_for("infra/", "a.b"), "infra/modules/a_b");
    }

    #[test]
    fn plan_rows_and_counts_read_in_words() {
        let plan = serde_json::json!({
            "resource_changes": [
                {"address": "cloudflare_dns_record.a", "change": {"actions": ["create"],
                 "after": {"name": "www.example.com", "content": "192.0.2.10", "type": "A"}}},
                {"address": "cloudflare_workers_route.b", "change": {"actions": ["delete"],
                 "before": {"pattern": "example.com/api/*"}}},
                {"address": "cloudflare_zone_setting.c", "change": {"actions": ["delete", "create"],
                 "before": {"setting_id": "ssl", "value": "flexible"},
                 "after": {"setting_id": "ssl", "value": "strict"}}},
                {"address": "cloudflare_ruleset.d", "change": {"actions": ["update", "create"],
                 "after": {"pattern": "example.com/*"}}},
            ]
        });
        let view = PlanView::from_json(&extract(&plan).to_string());
        assert_eq!(view.counts(), "3 to add · 1 to change · 2 to remove");
        assert!(view.risky());
        // No Terraform address in any row; a removal stops at what went away.
        assert_eq!(view.rows[0].1, "Add the DNS record: www.example.com → 192.0.2.10 (A)");
        assert_eq!(view.rows[1].1, "Remove the route: example.com/api/*");
        assert_eq!(view.rows[2].0, Row::Replace);
        assert_eq!(view.rows[2].1, "Replace the zone setting: ssl → strict");
        assert_eq!(view.rows[3].1, "Change the redirect ruleset: example.com/*");
    }
}
