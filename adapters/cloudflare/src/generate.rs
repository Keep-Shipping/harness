//! [`generate`]: an [`Account`] in, a set of files out — OpenTofu for the
//! `cloudflare` provider v5, `import` blocks for everything it declared, and a
//! report of what a human still has to do.
//!
//! It is a pure function, and it stays one: everything is sorted, nothing reads
//! a clock, and every file ends with a newline, so re-running the import on an
//! unchanged account rewrites the same bytes.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::hcl;
use crate::{
    ACCOUNT_VAR, Account, Attr, DESTINATIONS_VAR, PROVIDER_VERSION, Resource, SCRIPTS_KIND,
};

/// The files a read turns into, keyed by their path relative to the output root.
pub fn generate(account: &Account) -> BTreeMap<String, String> {
    let mut modules: BTreeMap<&str, Vec<&Resource>> = BTreeMap::new();
    for resource in &account.resources {
        modules.entry(resource.module.as_str()).or_default().push(resource);
    }
    for resources in modules.values_mut() {
        resources.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));
    }

    let mut out = BTreeMap::new();
    out.insert("main.tf".to_string(), root_main(&modules, !account.destinations.is_empty()));
    out.insert("variables.tf".to_string(), root_variables(!account.destinations.is_empty()));
    out.insert("imports.tf".to_string(), imports(account));
    out.insert("IMPORT-REPORT.md".to_string(), report(account));
    for (slug, resources) in &modules {
        let dests = uses_destinations(resources);
        out.insert(format!("modules/{slug}/main.tf"), module_main(resources));
        out.insert(format!("modules/{slug}/variables.tf"), module_variables(dests));
    }
    out
}

/// The `terraform`/`provider`/module wiring of the root module.
fn root_main(modules: &BTreeMap<&str, Vec<&Resource>>, destinations: bool) -> String {
    let mut out = providers();
    out.push_str("\nprovider \"cloudflare\" {\n  api_token = var.cloudflare_api_token\n}\n");
    for (slug, resources) in modules {
        let _ = writeln!(out, "\nmodule {} {{", hcl::quoted(slug));
        let _ = writeln!(out, "  source = {}", hcl::quoted(&format!("./modules/{slug}")));
        let _ = writeln!(out, "\n  {ACCOUNT_VAR} = var.{ACCOUNT_VAR}");
        if destinations && uses_destinations(resources) {
            let _ = writeln!(out, "  {DESTINATIONS_VAR} = var.{DESTINATIONS_VAR}");
        }
        out.push_str("}\n");
    }
    out
}

/// The `required_providers` block every root and module carries.
fn providers() -> String {
    format!(
        "terraform {{\n  required_providers {{\n    cloudflare = {{\n      source = \"cloudflare/cloudflare\"\n      version = {}\n    }}\n  }}\n}}\n",
        hcl::quoted(PROVIDER_VERSION)
    )
}

/// The root variables: the token, the account, and the destinations when a rule
/// asked for one.
fn root_variables(destinations: bool) -> String {
    let mut out = String::from(
        "variable \"cloudflare_api_token\" {\n  description = \"Cloudflare API token, supplied through the Secrets port as TF_VAR_cloudflare_api_token.\"\n  type        = string\n  sensitive   = true\n}\n",
    );
    out.push_str(
        "\nvariable \"cloudflare_account_id\" {\n  description = \"The Cloudflare account this was imported from.\"\n  type        = string\n}\n",
    );
    if destinations {
        let _ = write!(
            out,
            "\nvariable \"{DESTINATIONS_VAR}\" {{\n  description = \"Email routing forward destinations, keyed by the rule they belong to. See IMPORT-REPORT.md.\"\n  type        = map(string)\n  sensitive   = true\n}}\n"
        );
    }
    out
}

/// One `import` block per resource. These must live in the root module, because
/// that is where Terraform evaluates them.
fn imports(account: &Account) -> String {
    let mut sorted: Vec<&Resource> = account.resources.iter().collect();
    // In the order the modules are written — module, then kind, then import
    // id — so the order the API listed zones in cannot reach the files.
    sorted.sort_by(|a, b| {
        (&a.module, &a.kind, &a.import_id).cmp(&(&b.module, &b.kind, &b.import_id))
    });
    let mut out = String::new();
    for resource in sorted {
        let _ = write!(
            out,
            "import {{\n  to = module.{}.{}.{}\n  id = {}\n}}\n",
            resource.module,
            resource.kind,
            resource.name,
            hcl::quoted(&resource.import_id)
        );
    }
    out
}

/// One module's resources, sorted by (kind, name).
fn module_main(resources: &[&Resource]) -> String {
    let mut out = providers();
    out.push('\n');
    for resource in resources {
        let _ =
            write!(out, "resource {} {} ", hcl::quoted(resource.kind), hcl::quoted(&resource.name));
        out.push_str(&hcl::object(resource.attrs.iter().map(|(k, v)| (k.as_str(), v)), 1));
        out.push_str("\n\n");
    }
    out
}

/// The variables one module reads. Every module hangs off the account id; a
/// module with a forwarding rule also reads the destinations.
fn module_variables(destinations: bool) -> String {
    let mut out = format!(
        "variable \"{ACCOUNT_VAR}\" {{\n  description = \"The Cloudflare account these objects live in.\"\n  type        = string\n}}\n"
    );
    if destinations {
        out.push_str(&format!(
            "\nvariable \"{DESTINATIONS_VAR}\" {{\n  description = \"Email routing forward destinations, keyed by the rule they belong to.\"\n  type        = map(string)\n  sensitive   = true\n}}\n"
        ));
    }
    out
}

/// What was imported, what a human must supply, and what was left behind.
fn report(account: &Account) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for resource in &account.resources {
        *counts.entry(resource.kind).or_default() += 1;
    }

    let mut out = format!(
        "# Cloudflare import report\n\nAccount `{}`, {}.\n\n## Imported\n\n| resource | count |\n| --- | --- |\n",
        account.account_id,
        plural(account.resources.len(), "resource")
    );
    for (kind, count) in &counts {
        let _ = writeln!(out, "| `{kind}` | {count} |");
    }

    if !account.destinations.is_empty() {
        out.push_str(
            "\n## Secrets to supply\n\nEmail routing destinations are not in these files. Supply them through the Secrets port as `TF_VAR_email_routing_destinations`, a JSON object mapping each key below to the address that rule forwards to:\n",
        );
        for key in &account.destinations {
            let _ = writeln!(out, "\n- `{key}`");
        }
        out.push('\n');
    }

    if !account.not_imported.is_empty() {
        out.push_str("\n## Found but not imported\n");
        for (kind, names) in &account.not_imported {
            // Sorted, so the order the API answered in cannot reach the report.
            let mut sorted = names.clone();
            sorted.sort();
            let _ = writeln!(
                out,
                "\n- {}: {}",
                kind,
                sorted.iter().map(|name| format!("`{name}`")).collect::<Vec<_>>().join(", ")
            );
        }
        if account.not_imported.contains_key(SCRIPTS_KIND) {
            out.push_str(
                "\nWorkers scripts are listed on purpose: their bodies are multipart downloads, and writing a script out of one is its own job.\n",
            );
        }
    }
    out
}

/// Whether any of these resources references a destination variable, anywhere
/// inside it: a reference sits inside a rule's actions, not at the top.
fn uses_destinations(resources: &[&Resource]) -> bool {
    let needle = format!("var.{DESTINATIONS_VAR}[");
    resources.iter().any(|resource| resource.attrs.values().any(|attr| references(attr, &needle)))
}

/// Whether `attr` mentions the expression `needle` at any depth.
fn references(attr: &Attr, needle: &str) -> bool {
    match attr {
        Attr::Expr(text) => text.starts_with(needle),
        Attr::Obj(fields) => fields.iter().any(|(_, attr)| references(attr, needle)),
        Attr::List(items) => items.iter().any(|item| references(item, needle)),
        Attr::Lit(_) => false,
    }
}

/// `1 resource` / `2 resources`.
fn plural(count: usize, noun: &str) -> String {
    if count == 1 { format!("{count} {noun}") } else { format!("{count} {noun}s") }
}
