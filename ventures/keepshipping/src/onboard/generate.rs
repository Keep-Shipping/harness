//! The pure half of onboarding: what a site is, which part of a read account
//! belongs to it, the files that bring it under code, and the plain-words
//! summary a person confirms before anything is written.
//!
//! Everything here is a function of its inputs. No clock, no socket, no
//! token: the test environment is described by names and flags only, and the
//! database's address, port, name, user and password are never values in
//! these files. They are `sensitive` variables the infra repository's
//! workflow supplies from its own secrets. A test that puts a sentinel
//! address in the account proves the sentinel never reaches the output.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use ks_cloudflare::{ACCOUNT_MODULE, Account, Attr, Resource, StateBackend, add_backend, generate};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cloudflare::rollback::{Target, target};
use crate::fleet::Site;
use crate::onboard::wizard;

/// The database engine behind a test environment's Hyperdrive config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbKind {
    /// PostgreSQL, reached through Hyperdrive.
    Postgres,
    /// MySQL, reached through Hyperdrive.
    MySql,
}

impl DbKind {
    /// The origin scheme the Hyperdrive config is written with.
    fn scheme(self) -> &'static str {
        match self {
            DbKind::Postgres => "postgresql",
            DbKind::MySql => "mysql",
        }
    }

    /// The engine's name in plain words.
    fn words(self) -> &'static str {
        match self {
            DbKind::Postgres => "Postgres",
            DbKind::MySql => "MySQL",
        }
    }
}

/// What a site owns on the Cloudflare account, as the scope needs to know it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SiteScope {
    /// The hostnames the site answers on. The zones they sit in are kept whole.
    pub domains: Vec<String>,
    /// A Pages project's name, for a Pages site.
    pub pages_project: Option<String>,
    /// A Worker script's name, for a Worker site.
    pub worker_script: Option<String>,
    /// Names of the D1, KV and R2 objects the site binds, as the account lists them.
    pub bindings: Vec<String>,
}

impl SiteScope {
    /// The scope of a fleet site: its domains, and the Pages project or Worker
    /// script its id names. A preview or a domain-only site names neither.
    pub fn from_site(site: &Site, bindings: Vec<String>) -> SiteScope {
        let (pages_project, worker_script) = match target(site) {
            Some(Target::Pages { project, .. }) => (Some(project), None),
            Some(Target::Worker { script, .. }) => (None, Some(script)),
            None => (None, None),
        };
        SiteScope { domains: site.domains.clone(), pages_project, worker_script, bindings }
    }
}

/// The test environment a site gets next to its imported code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestEnv {
    /// Whether any of it is created at all. When false nothing below is written.
    pub enabled: bool,
    /// The base name for the test objects, e.g. `<site>-test`.
    pub name: String,
    /// The test hostname on the site's Pages project, e.g. `test.<main domain>`.
    pub hostname: Option<String>,
    /// Create a D1 database.
    pub d1: bool,
    /// Create a KV namespace.
    pub kv: bool,
    /// Create an R2 bucket.
    pub r2: bool,
    /// Reach a database through Hyperdrive, with this engine.
    pub hyperdrive: Option<DbKind>,
    /// The Pages project the hostname is attached to.
    pub pages_project: Option<String>,
}

/// The files that bring a scoped account under code and, when asked, a test
/// environment next to it. Keys are paths relative to the infra repository.
///
/// The output is a pure function of its inputs: sorted, clock-free, every file
/// ending in a newline. It contains the generated import, the state backend
/// (`backend.tf`), a README, the CI workflow and — only when `test.enabled` —
/// `modules/test-env/` with its wiring in the root.
pub fn plan_files(
    scoped: &Account,
    test: &TestEnv,
    backend: &StateBackend,
) -> BTreeMap<String, String> {
    let mut files = generate(scoped);
    add_backend(&mut files, backend);
    let db = if test.enabled { test.hyperdrive } else { None };
    if test.enabled {
        add_test_env(&mut files, scoped, test);
    }
    let destinations = !scoped.destinations.is_empty();
    files.insert(
        ".github/workflows/infra.yml".to_string(),
        workflow(db, destinations, &scoped.account_id),
    );
    files.insert("README.md".to_string(), readme(test.enabled, destinations));
    files
}

/// Keeps only what belongs to one site: the zone modules of its domains, the
/// account-level objects it owns, and the destinations and "not imported" notes
/// that refer to it. Everything else on the account is dropped.
pub fn scope(account: &Account, site: &SiteScope) -> Account {
    let zone_names: Vec<&str> = account
        .resources
        .iter()
        .filter(|resource| resource.kind == "cloudflare_zone")
        .filter_map(|resource| text(resource, "name"))
        .filter(|zone| site.domains.iter().any(|domain| is_within(domain, zone)))
        .collect();
    let zone_modules: BTreeSet<&str> = account
        .resources
        .iter()
        .filter(|resource| {
            resource.kind == "cloudflare_zone"
                && text(resource, "name").is_some_and(|name| zone_names.contains(&name))
        })
        .map(|resource| resource.module.as_str())
        .collect();

    let resources: Vec<Resource> = account
        .resources
        .iter()
        .filter(|resource| {
            if resource.module == ACCOUNT_MODULE {
                owned_by_site(resource, site)
            } else {
                zone_modules.contains(resource.module.as_str())
            }
        })
        .cloned()
        .collect();

    let destinations = account
        .destinations
        .iter()
        .filter(|key| {
            resources
                .iter()
                .any(|resource| resource.attrs.values().any(|attr| refers_to(attr, key)))
        })
        .cloned()
        .collect();

    let not_imported = account
        .not_imported
        .iter()
        .filter_map(|(kind, names)| {
            let kept: Vec<String> =
                names.iter().filter(|name| mentions_site(name, site)).cloned().collect();
            (!kept.is_empty()).then_some((*kind, kept))
        })
        .collect();

    Account { account_id: account.account_id.clone(), resources, destinations, not_imported }
}

/// The plain-words summary a person reads before confirming: one sentence per
/// thing the import or the test environment will do.
pub fn summary(scoped: &Account, test: &TestEnv) -> Vec<String> {
    let mut lines = Vec::new();

    let mut zones: Vec<(&str, &str)> = scoped
        .resources
        .iter()
        .filter(|resource| resource.kind == "cloudflare_zone")
        .filter_map(|resource| Some((text(resource, "name")?, resource.module.as_str())))
        .collect();
    zones.sort();
    for (zone, module) in zones {
        let in_zone: Vec<&Resource> =
            scoped.resources.iter().filter(|resource| resource.module == module).collect();
        let dns = in_zone.iter().filter(|r| r.kind == "cloudflare_dns_record").count();
        let other = in_zone
            .iter()
            .filter(|r| r.kind != "cloudflare_dns_record" && r.kind != "cloudflare_zone")
            .count();
        if dns > 0 {
            lines.push(format!("Imports {} in {zone}", plural(dns, "DNS record")));
        }
        if other > 0 {
            lines.push(format!("Imports {} in {zone}", plural(other, "setting, rule or route")));
        }
        if dns == 0 && other == 0 {
            lines.push(format!("Imports the domain {zone}"));
        }
    }

    let account_level: Vec<&Resource> =
        scoped.resources.iter().filter(|resource| resource.module == ACCOUNT_MODULE).collect();
    for resource in &account_level {
        match resource.kind {
            "cloudflare_pages_project" => {
                let name = text(resource, "name").unwrap_or(resource.name.as_str());
                lines.push(format!("Imports the Pages site {name}"));
            }
            "cloudflare_pages_domain" => {
                let project = text(resource, "project_name").unwrap_or("its project");
                let host = text(resource, "name").unwrap_or(resource.name.as_str());
                lines.push(format!("Imports the address {host} on the Pages site {project}"));
            }
            "cloudflare_workers_custom_domain" => {
                let host = text(resource, "hostname").unwrap_or(resource.name.as_str());
                lines.push(format!("Imports the Worker address {host}"));
            }
            "cloudflare_d1_database" => {
                let name = text(resource, "name").unwrap_or(resource.name.as_str());
                lines.push(format!("Imports the database {name} (D1)"));
            }
            "cloudflare_workers_kv_namespace" => {
                let title = text(resource, "title").unwrap_or(resource.name.as_str());
                lines.push(format!("Imports the key-value store {title}"));
            }
            "cloudflare_r2_bucket" => {
                let name = text(resource, "name").unwrap_or(resource.name.as_str());
                lines.push(format!("Imports the file bucket {name}"));
            }
            other => lines.push(format!("Imports the {other} objects in the account")),
        }
    }

    if !scoped.destinations.is_empty() {
        lines.push(format!(
            "Email forwarding addresses are not in the files; they are kept as secrets ({})",
            plural(scoped.destinations.len(), "forward destination")
        ));
    }
    for (kind, names) in &scoped.not_imported {
        lines.push(format!("Does not import {kind}: {}", names.join(", ")));
    }

    if !test.enabled {
        lines.push("No test environment is created.".to_string());
        return lines;
    }
    let mut test_lines = Vec::new();
    if test.d1 {
        test_lines.push(format!("Creates a test database (D1) called {}", test.name));
    }
    if test.kv {
        test_lines.push(format!("Creates a test key-value store called {}", test.name));
    }
    if test.r2 {
        test_lines.push(format!("Creates a test file bucket called {}", test.name));
    }
    if let Some(kind) = test.hyperdrive {
        test_lines.push(format!(
            "{} for the test environment goes through Hyperdrive; the database address is kept as a secret",
            kind.words()
        ));
    }
    if let (Some(host), Some(project)) = (&test.hostname, &test.pages_project) {
        if zone_of(scoped, host).is_some() {
            test_lines.push(format!(
                "Creates the test address {host}, pointed at the test branch of {project}"
            ));
        } else {
            test_lines.push(format!(
                "The test address {host} is not in an imported domain, so no test address is created"
            ));
        }
    }
    if test_lines.is_empty() {
        test_lines.push("The test environment has nothing to create.".to_string());
    }
    lines.extend(test_lines);
    lines
}

// -- the test environment ----------------------------------------------------

/// Writes `modules/test-env/` and wires it into the root. Only called when the
/// environment is enabled, so a disabled one adds no file and no block.
fn add_test_env(files: &mut BTreeMap<String, String>, scoped: &Account, test: &TestEnv) {
    let zone = test.hostname.as_deref().and_then(|host| zone_of(scoped, host));
    let module = module_main(test, zone.as_deref());
    let variables = module_variables(test.hyperdrive.is_some());
    let outputs = module_outputs(test);

    files.insert("modules/test-env/main.tf".to_string(), module);
    files.insert("modules/test-env/variables.tf".to_string(), variables);
    if !outputs.is_empty() {
        files.insert("modules/test-env/outputs.tf".to_string(), outputs);
    }

    let root_main = files.entry("main.tf".to_string()).or_default();
    root_main.push_str("\nmodule \"test_env\" {\n  source = \"./modules/test-env\"\n\n");
    root_main.push_str("  cloudflare_account_id = var.cloudflare_account_id\n");
    if test.hyperdrive.is_some() {
        for (name, ..) in DB_VAR_SPECS {
            let _ = writeln!(root_main, "  {name} = var.{name}");
        }
    }
    root_main.push_str("}\n");

    if test.hyperdrive.is_some() {
        let root_vars = files.entry("variables.tf".to_string()).or_default();
        for (name, description, kind, sensitive) in DB_VAR_SPECS {
            let _ = write!(
                root_vars,
                "\nvariable \"{name}\" {{\n  description = \"{description}\"\n  type        = {kind}\n  sensitive   = {sensitive}\n}}\n"
            );
        }
    }

    let root_outputs = module_outputs_root(test);
    if !root_outputs.is_empty() {
        files.insert("outputs.tf".to_string(), root_outputs);
    }
}

/// Name, description, type and sensitivity of each database variable.
const DB_VAR_SPECS: [(&str, &str, &str, bool); 5] = [
    (
        "test_db_host",
        "Address of the test database, supplied as TF_VAR_test_db_host.",
        "string",
        true,
    ),
    ("test_db_port", "Port of the test database, supplied as TF_VAR_test_db_port.", "number", true),
    (
        "test_db_database",
        "Name of the test database, supplied as TF_VAR_test_db_database.",
        "string",
        true,
    ),
    (
        "test_db_user",
        "User for the test database, supplied as TF_VAR_test_db_user.",
        "string",
        true,
    ),
    (
        "test_db_password",
        "Password for the test database, supplied as TF_VAR_test_db_password.",
        "string",
        true,
    ),
];

/// The test-env module's resources. Every name is a literal the caller chose;
/// every database detail is a `var.test_db_*` reference.
fn module_main(test: &TestEnv, zone: Option<&str>) -> String {
    let mut out = String::from(
        "terraform {\n  required_providers {\n    cloudflare = {\n      source  = \"cloudflare/cloudflare\"\n      version = \"~> 5.0\"\n    }\n  }\n}\n\n",
    );
    out.push_str(
        "# The test environment. Names here are chosen by Keep Shipping; the database\n# details are sensitive variables, never literal values.\n",
    );
    let name = quoted(&test.name);
    if test.d1 {
        let _ = write!(
            out,
            "\nresource \"cloudflare_d1_database\" \"test\" {{\n  account_id = var.cloudflare_account_id\n  name       = {name}\n}}\n"
        );
    }
    if test.kv {
        let _ = write!(
            out,
            "\nresource \"cloudflare_workers_kv_namespace\" \"test\" {{\n  account_id = var.cloudflare_account_id\n  title      = {name}\n}}\n"
        );
    }
    if test.r2 {
        let _ = write!(
            out,
            "\nresource \"cloudflare_r2_bucket\" \"test\" {{\n  account_id = var.cloudflare_account_id\n  name       = {name}\n}}\n"
        );
    }
    if let Some(kind) = test.hyperdrive {
        let _ = write!(
            out,
            "\nresource \"cloudflare_hyperdrive_config\" \"test\" {{\n  account_id = var.cloudflare_account_id\n  name       = {name}\n  origin = {{\n    scheme   = {scheme}\n    host     = var.test_db_host\n    port     = var.test_db_port\n    database = var.test_db_database\n    user     = var.test_db_user\n    password = var.test_db_password\n  }}\n}}\n",
            scheme = quoted(kind.scheme()),
        );
    }
    if let (Some(project), Some(host), Some(zone)) = (&test.pages_project, &test.hostname, zone) {
        let _ = write!(
            out,
            "\ndata \"cloudflare_zone\" \"test\" {{\n  filter = {{ name = {zone} }}\n}}\n\nresource \"cloudflare_pages_domain\" \"test\" {{\n  account_id   = var.cloudflare_account_id\n  project_name = {project}\n  name         = {host}\n}}\n\nresource \"cloudflare_dns_record\" \"test\" {{\n  zone_id = data.cloudflare_zone.test.id\n  name    = {host}\n  type    = \"CNAME\"\n  content = {content}\n  ttl     = 1\n  proxied = true\n}}\n",
            zone = quoted(zone),
            project = quoted(project),
            host = quoted(host),
            content = quoted(&format!("test.{project}.pages.dev")),
        );
    }
    out
}

/// The test-env module's inputs: the account, and the database variables when
/// Hyperdrive is used.
fn module_variables(database: bool) -> String {
    let mut out = String::from(
        "variable \"cloudflare_account_id\" {\n  description = \"The Cloudflare account the test environment lives in.\"\n  type        = string\n}\n",
    );
    if database {
        for (name, description, kind, sensitive) in DB_VAR_SPECS {
            let _ = write!(
                out,
                "\nvariable \"{name}\" {{\n  description = \"{description}\"\n  type        = {kind}\n  sensitive   = {sensitive}\n}}\n"
            );
        }
    }
    out
}

/// The module's outputs: the id or name of each object it created.
fn module_outputs(test: &TestEnv) -> String {
    let mut out = String::new();
    for (name, value) in output_pairs(test) {
        let _ = write!(out, "output \"{name}\" {{\n  value = {value}\n}}\n\n");
    }
    tidy(out)
}

/// The root's outputs: the module's, re-exported under the environment's name.
fn module_outputs_root(test: &TestEnv) -> String {
    let mut out = String::new();
    for (name, _) in output_pairs(test) {
        let _ =
            write!(out, "output \"test_env_{name}\" {{\n  value = module.test_env.{name}\n}}\n\n");
    }
    tidy(out)
}

/// Drops the blank line a run of blocks leaves at the end, keeping one final newline.
fn tidy(text: String) -> String {
    if text.is_empty() { text } else { format!("{}\n", text.trim_end()) }
}

/// `(output name, expression)` for every object the environment creates.
fn output_pairs(test: &TestEnv) -> Vec<(&'static str, &'static str)> {
    let mut pairs = Vec::new();
    if test.d1 {
        pairs.push(("d1_database_id", "cloudflare_d1_database.test.id"));
    }
    if test.kv {
        pairs.push(("kv_namespace_id", "cloudflare_workers_kv_namespace.test.id"));
    }
    if test.r2 {
        pairs.push(("r2_bucket_name", "cloudflare_r2_bucket.test.name"));
    }
    if test.hyperdrive.is_some() {
        pairs.push(("hyperdrive_config_id", "cloudflare_hyperdrive_config.test.id"));
    }
    if test.pages_project.is_some() && test.hostname.is_some() {
        pairs.push(("pages_domain_name", "cloudflare_pages_domain.test.name"));
    }
    pairs
}

// -- the workflow and the README ---------------------------------------------

/// Whether `id` is a Cloudflare account id: 32 hexadecimal characters. The
/// workflow carries the id as a literal, so nothing else may reach the file.
#[must_use]
pub fn is_account_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The CI workflow: plan on each pull request, post the plan back, and keep the
/// saved plan as an artifact; apply exactly that saved plan on
/// `repository_dispatch`. Secrets are named here and their values never appear
/// in the file. The account id and the console's address are not secrets, so
/// the file carries them as quoted literals in `env:`. Event values reach the
/// shell only through `env:`, never inline.
fn workflow(database: Option<DbKind>, destinations: bool, account_id: &str) -> String {
    let mut env = format!(
        "      TF_VAR_cloudflare_api_token: ${{{{ secrets.CLOUDFLARE_API_TOKEN }}}}\n      TF_VAR_cloudflare_account_id: \"{account_id}\"\n      TF_VAR_state_encryption_passphrase: ${{{{ secrets.STATE_ENCRYPTION_PASSPHRASE }}}}\n      AWS_ACCESS_KEY_ID: ${{{{ secrets.AWS_ACCESS_KEY_ID }}}}\n      AWS_SECRET_ACCESS_KEY: ${{{{ secrets.AWS_SECRET_ACCESS_KEY }}}}\n",
    );
    if destinations {
        env.push_str(
            "      TF_VAR_email_routing_destinations: ${{ secrets.EMAIL_ROUTING_DESTINATIONS }}\n",
        );
    }
    if database.is_some() {
        for (name, secret) in [
            ("test_db_host", "TEST_DB_HOST"),
            ("test_db_port", "TEST_DB_PORT"),
            ("test_db_database", "TEST_DB_DATABASE"),
            ("test_db_user", "TEST_DB_USER"),
            ("test_db_password", "TEST_DB_PASSWORD"),
        ] {
            let _ = writeln!(env, "      TF_VAR_{name}: ${{{{ secrets.{secret} }}}}");
        }
    }
    WORKFLOW
        .replace("__TF_ENV__\n", &env)
        .replace("${{ vars.KEEPSHIPPING_CONSOLE_URL }}", &format!("\"{}\"", wizard::CONSOLE_URL))
}

/// The workflow text. `__TF_ENV__` is replaced by the variables both jobs need.
const WORKFLOW: &str = r#"# Written by Keep Shipping. Pull requests are planned and the plan is posted
# back to the console; approval sends a repository_dispatch and this workflow
# applies the saved plan that was checked. Regenerated when the setup is
# re-run, so change the setup rather than this file.
name: infra

on:
  pull_request:
    paths:
      - "**.tf"
      - ".github/workflows/infra.yml"
  repository_dispatch:
    types: [keepshipping-edit-approved]

permissions:
  contents: read

jobs:
  plan:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    env:
__TF_ENV__
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: opentofu/setup-opentofu@a1320f892987e89d278cc92dc5adc984fb93aca4 # v2.0.2
        with:
          tofu_wrapper: false
      - name: Initialise
        run: tofu init -input=false
      - name: Plan
        run: tofu plan -input=false -lock-timeout=5m -out=tfplan
      - name: Render the plan as JSON
        run: tofu show -json tfplan > plan.json
      - name: Fingerprint the saved plan
        id: fingerprint
        run: echo "sha=$(sha256sum tfplan | cut -d' ' -f1)" >> "$GITHUB_OUTPUT"
      - name: Keep the saved plan for the apply
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: tfplan-${{ github.event.pull_request.head.sha }}
          path: tfplan
          retention-days: 7
          if-no-files-found: error
      - name: Post the plan to Keep Shipping
        if: startsWith(github.head_ref, 'ks-edit/')
        env:
          CONSOLE_URL: ${{ vars.KEEPSHIPPING_CONSOLE_URL }}
          RUNNER_TOKEN: ${{ secrets.EDITS_RUNNER_TOKEN }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
          HEAD_REF: ${{ github.head_ref }}
          PLAN_SHA: ${{ steps.fingerprint.outputs.sha }}
        run: |
          set -euo pipefail
          edit_id="${HEAD_REF#ks-edit/}"
          jq -n --arg head "$HEAD_SHA" --arg sha "$PLAN_SHA" --slurpfile plan plan.json \
            '{head_sha: $head, plan_file_sha256: $sha, plan: $plan[0]}' > body.json
          curl --fail-with-body --silent --show-error -X POST \
            -H "Authorization: Bearer ${RUNNER_TOKEN}" \
            -H "Content-Type: application/json" \
            --data-binary @body.json \
            "${CONSOLE_URL}/v1/edits/${edit_id}/plan"

  apply:
    if: github.event_name == 'repository_dispatch'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
    concurrency:
      group: infra-apply
      cancel-in-progress: false
    env:
__TF_ENV__
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ github.event.client_payload.head_sha }}
          persist-credentials: false
      - uses: opentofu/setup-opentofu@a1320f892987e89d278cc92dc5adc984fb93aca4 # v2.0.2
        with:
          tofu_wrapper: false
      - name: Find the plan run for this commit
        id: find
        env:
          HEAD_SHA: ${{ github.event.client_payload.head_sha }}
          GH_TOKEN: ${{ github.token }}
          GH_REPO: ${{ github.repository }}
        run: |
          set -euo pipefail
          run_id="$(gh run list --repo "$GH_REPO" --workflow infra.yml --commit "$HEAD_SHA" \
            --event pull_request --status success --limit 1 --json databaseId \
            --jq '.[0].databaseId')"
          if [ -z "$run_id" ] || [ "$run_id" = "null" ]; then
            echo "No successful plan run for this commit; refusing to apply." >&2
            exit 1
          fi
          echo "run_id=$run_id" >> "$GITHUB_OUTPUT"
      - name: Fetch the saved plan
        uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: tfplan-${{ github.event.client_payload.head_sha }}
          path: approved
          run-id: ${{ steps.find.outputs.run_id }}
          github-token: ${{ github.token }}
      - name: Check this is the approved plan
        env:
          APPROVED: ${{ github.event.client_payload.plan_file_sha256 }}
        run: |
          set -euo pipefail
          if [ -z "$APPROVED" ]; then
            echo "The approval carries no plan digest; refusing to apply." >&2
            exit 1
          fi
          actual="$(sha256sum approved/tfplan | cut -d' ' -f1)"
          if [ "$actual" != "$APPROVED" ]; then
            echo "The saved plan does not match the approved digest; refusing to apply." >&2
            exit 1
          fi
      - name: Initialise
        run: tofu init -input=false
      # tofu refuses a saved plan whose state has moved on since it was made, so a
      # stale plan fails here rather than applying changes nobody checked.
      - name: Apply the approved plan
        run: tofu apply -input=false approved/tfplan
"#;

/// The README for the infra repository, in plain words.
fn readme(test: bool, destinations: bool) -> String {
    let destinations_line = if destinations {
        "- `EMAIL_ROUTING_DESTINATIONS`: the email forwarding addresses, as one JSON object keyed by rule.\n"
    } else {
        ""
    };
    let mut out = format!(
        "# Infrastructure\n\nThis repository describes the Cloudflare setup of the site or sites it was made for, as code.\n\n## What is here\n\n- `imports.tf` and the `modules/` folders describe what already exists on Cloudflare. Nothing here creates it again.\n- `backend.tf` keeps the record of what Terraform manages in Cloudflare R2, encrypted.\n- `IMPORT-REPORT.md` lists what was brought in and what was left alone.\n- `.github/workflows/infra.yml` plans each pull request and applies a change only after it is approved.\n\n## Secrets\n\nSet these in the repository's settings. Their values are never written to a file.\n\n- `CLOUDFLARE_API_TOKEN`: the Cloudflare token the workflow uses.\n- `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`: the R2 keys for the record of changes.\n- `STATE_ENCRYPTION_PASSPHRASE`: encrypts that record.\n- `EDITS_RUNNER_TOKEN`: lets the workflow report each plan back to Keep Shipping.\n{destinations_line}\nThe Cloudflare account id and the console's address are not secrets: the workflow file carries them.\n",
    );
    if test {
        out.push_str(
            "\n## Test environment\n\nThe test environment has its own folder, `modules/test-env/`. If it uses a database, its address, port, name, user and password are secrets named `TEST_DB_HOST`, `TEST_DB_PORT`, `TEST_DB_DATABASE`, `TEST_DB_USER` and `TEST_DB_PASSWORD`.\n",
        );
    }
    out
}

// -- helpers -----------------------------------------------------------------

/// The text of a literal attribute, if it is one.
fn text<'a>(resource: &'a Resource, key: &str) -> Option<&'a str> {
    match resource.attrs.get(key)? {
        Attr::Lit(Value::String(text)) => Some(text.as_str()),
        _ => None,
    }
}

/// Whether `host` is `zone` or a name under it, compared without case.
fn is_within(host: &str, zone: &str) -> bool {
    let (host, zone) = (host.to_ascii_lowercase(), zone.to_ascii_lowercase());
    host == zone || host.ends_with(&format!(".{zone}"))
}

/// The longest imported zone that `host` sits in.
fn zone_of(scoped: &Account, host: &str) -> Option<String> {
    scoped
        .resources
        .iter()
        .filter(|resource| resource.kind == "cloudflare_zone")
        .filter_map(|resource| text(resource, "name"))
        .filter(|zone| is_within(host, zone))
        .max_by_key(|zone| zone.len())
        .map(str::to_string)
}

/// Whether an account-level object belongs to the site.
fn owned_by_site(resource: &Resource, site: &SiteScope) -> bool {
    match resource.kind {
        "cloudflare_pages_project" => site
            .pages_project
            .as_deref()
            .is_some_and(|project| text(resource, "name") == Some(project)),
        "cloudflare_pages_domain" => site
            .pages_project
            .as_deref()
            .is_some_and(|project| text(resource, "project_name") == Some(project)),
        "cloudflare_workers_custom_domain" => site
            .worker_script
            .as_deref()
            .is_some_and(|script| text(resource, "service") == Some(script)),
        "cloudflare_d1_database" | "cloudflare_r2_bucket" | "cloudflare_workers_kv_namespace" => {
            let label = text(resource, "name").or_else(|| text(resource, "title"));
            site.bindings
                .iter()
                .any(|binding| binding == &resource.name || Some(binding.as_str()) == label)
        }
        _ => false,
    }
}

/// Whether a "not imported" name refers to the site: one of its identifiers, or
/// one of its domains.
fn mentions_site(name: &str, site: &SiteScope) -> bool {
    site.worker_script.as_deref() == Some(name)
        || site.pages_project.as_deref() == Some(name)
        || site.bindings.iter().any(|binding| binding == name)
        || site.domains.iter().any(|domain| domain == name)
}

/// Whether an attribute refers to an email forward destination by `key`.
fn refers_to(attr: &Attr, key: &str) -> bool {
    let needle = format!("email_routing_destinations[\"{key}\"]");
    match attr {
        Attr::Expr(text) => text.contains(&needle),
        Attr::Obj(fields) => fields.iter().any(|(_, attr)| refers_to(attr, key)),
        Attr::List(items) => items.iter().any(|item| refers_to(item, key)),
        Attr::Lit(_) => false,
    }
}

/// `1 DNS record` / `2 DNS records`.
fn plural(count: usize, noun: &str) -> String {
    if count == 1 { format!("{count} {noun}") } else { format!("{count} {noun}s") }
}

/// An HCL string literal. `$` and `%` are doubled so nothing in a name can open
/// an interpolation or a template directive.
fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '$' => out.push_str("$$"),
            '%' => out.push_str("%%"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
