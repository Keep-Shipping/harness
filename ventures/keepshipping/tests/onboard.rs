//! The onboarding generator, over one hand-built account with two zones, a
//! Pages project and a Worker on one side and a second project on the other.
//! The properties: a scoped account keeps only one site, the output holds no
//! secret-looking literal, a re-run is byte-identical, and the test environment
//! is wired only when it is enabled.

use std::collections::{BTreeMap, BTreeSet};

use keepshipping_waitlist::onboard::{DbKind, SiteScope, TestEnv, plan_files, scope, summary};
use ks_cloudflare::{ACCOUNT_MODULE, Account, Attr, Resource, StateBackend};
use serde_json::json;

/// The Workers-scripts key the adapter lists unimported scripts under.
const SCRIPTS: &str = "Cloudflare Workers scripts";

fn lit(text: &str) -> Attr {
    Attr::lit(json!(text))
}

fn res(module: &str, kind: &'static str, name: &str, attrs: Vec<(&str, Attr)>) -> Resource {
    Resource {
        module: module.to_string(),
        kind,
        name: name.to_string(),
        import_id: format!("{module}/{name}"),
        attrs: attrs.into_iter().map(|(key, value)| (key.to_string(), value)).collect(),
    }
}

fn zone(module: &str, name: &str) -> Resource {
    res(
        module,
        "cloudflare_zone",
        module,
        vec![
            ("account", Attr::expr("{ id = var.cloudflare_account_id }")),
            ("name", lit(name)),
            ("type", lit("full")),
        ],
    )
}

fn dns(module: &str, name: &str, host: &str) -> Resource {
    res(
        module,
        "cloudflare_dns_record",
        name,
        vec![("name", lit(host)), ("type", lit("CNAME")), ("content", lit("edge.example.net"))],
    )
}

/// Two zones, two Pages projects, one Worker custom domain each, the bindings
/// of each side, two destinations, and two unimported scripts.
fn account() -> Account {
    let mut resources = vec![
        zone("example_com", "example.com"),
        dns("example_com", "www", "www.example.com"),
        dns("example_com", "kaje", "kaje.example.com"),
        res(
            "example_com",
            "cloudflare_zone_setting",
            "ssl",
            vec![("setting_id", lit("ssl")), ("value", lit("strict"))],
        ),
        res(
            "example_com",
            "cloudflare_email_routing_rule",
            "sales",
            vec![(
                "actions",
                Attr::List(vec![Attr::Obj(vec![
                    ("type".to_string(), lit("forward")),
                    (
                        "value".to_string(),
                        Attr::List(vec![Attr::expr(
                            "var.email_routing_destinations[\"kaje_sales\"]",
                        )]),
                    ),
                ])]),
            )],
        ),
        zone("other_net", "other.net"),
        dns("other_net", "www", "www.other.net"),
        res(
            ACCOUNT_MODULE,
            "cloudflare_pages_project",
            "kaje",
            vec![("name", lit("kaje")), ("production_branch", lit("main"))],
        ),
        res(
            ACCOUNT_MODULE,
            "cloudflare_pages_domain",
            "kaje_example_com",
            vec![("project_name", lit("kaje")), ("name", lit("kaje.example.com"))],
        ),
        res(
            ACCOUNT_MODULE,
            "cloudflare_pages_project",
            "other",
            vec![("name", lit("other-site")), ("production_branch", lit("main"))],
        ),
        res(
            ACCOUNT_MODULE,
            "cloudflare_pages_domain",
            "other_net",
            vec![("project_name", lit("other-site")), ("name", lit("other.net"))],
        ),
        res(
            ACCOUNT_MODULE,
            "cloudflare_workers_custom_domain",
            "api_example_com",
            vec![("hostname", lit("api.example.com")), ("service", lit("kaje-api"))],
        ),
        res(
            ACCOUNT_MODULE,
            "cloudflare_workers_custom_domain",
            "x_other_net",
            vec![("hostname", lit("x.other.net")), ("service", lit("other-api"))],
        ),
        res(ACCOUNT_MODULE, "cloudflare_d1_database", "kaje_db", vec![("name", lit("kaje-db"))]),
        res(ACCOUNT_MODULE, "cloudflare_d1_database", "other_db", vec![("name", lit("other-db"))]),
        res(
            ACCOUNT_MODULE,
            "cloudflare_workers_kv_namespace",
            "kaje_cache",
            vec![("title", lit("kaje-cache"))],
        ),
        res(
            ACCOUNT_MODULE,
            "cloudflare_r2_bucket",
            "other_bucket",
            vec![("name", lit("other-bucket"))],
        ),
    ];
    resources.sort_by(|a, b| (&a.module, &a.name).cmp(&(&b.module, &b.name)));
    Account {
        account_id: "acct123".to_string(),
        resources,
        destinations: BTreeSet::from(["kaje_sales".to_string(), "other_forward".to_string()]),
        not_imported: BTreeMap::from([(
            SCRIPTS,
            vec!["kaje-api".to_string(), "other-api".to_string()],
        )]),
    }
}

fn pages_site() -> SiteScope {
    SiteScope {
        domains: vec!["kaje.example.com".to_string(), "api.example.com".to_string()],
        pages_project: Some("kaje".to_string()),
        worker_script: None,
        bindings: vec!["kaje-db".to_string(), "kaje-cache".to_string()],
    }
}

fn worker_site() -> SiteScope {
    SiteScope {
        domains: vec!["api.example.com".to_string()],
        pages_project: None,
        worker_script: Some("kaje-api".to_string()),
        bindings: vec!["kaje-db".to_string()],
    }
}

fn backend() -> StateBackend {
    StateBackend::new("acct123", "ks-state", "kaje").expect("valid backend")
}

fn no_test() -> TestEnv {
    TestEnv {
        enabled: false,
        name: "kaje-test".to_string(),
        hostname: None,
        d1: false,
        kv: false,
        r2: false,
        hyperdrive: None,
        pages_project: None,
    }
}

fn full_test(db: Option<DbKind>) -> TestEnv {
    TestEnv {
        enabled: true,
        name: "kaje-test".to_string(),
        hostname: Some("test.kaje.example.com".to_string()),
        d1: true,
        kv: true,
        r2: true,
        hyperdrive: db,
        pages_project: Some("kaje".to_string()),
    }
}

/// Every file, one after another under its own heading, for one snapshot.
fn render(files: &BTreeMap<String, String>) -> String {
    files.iter().map(|(path, body)| format!("=== {path} ===\n{body}")).collect()
}

/// Output of the scoped Pages site with a test environment; shared by tests.
fn pages_files(test: &TestEnv) -> BTreeMap<String, String> {
    plan_files(&scope(&account(), &pages_site()), test, &backend())
}

#[test]
fn import_only_snapshot_for_a_pages_site() {
    let files = pages_files(&no_test());
    insta::assert_snapshot!("pages_import_only", render(&files));
}

#[test]
fn full_test_environment_with_postgres_snapshot_for_a_pages_site() {
    let files = pages_files(&full_test(Some(DbKind::Postgres)));
    insta::assert_snapshot!("pages_with_postgres_test_env", render(&files));
}

#[test]
fn full_test_environment_with_mysql_snapshot_for_a_worker_site() {
    let scoped = scope(&account(), &worker_site());
    let files = plan_files(&scoped, &full_test(Some(DbKind::MySql)), &backend());
    insta::assert_snapshot!("worker_with_mysql_test_env", render(&files));
}

#[test]
fn scoping_a_pages_site_drops_the_other_zone_and_project() {
    let scoped = scope(&account(), &pages_site());
    let kinds: BTreeSet<(&str, &str)> =
        scoped.resources.iter().map(|r| (r.module.as_str(), r.name.as_str())).collect();
    assert!(!scoped.resources.iter().any(|r| r.module == "other_net"), "{kinds:?}");
    assert!(!scoped.resources.iter().any(|r| r.name == "other-site" || r.name == "other_db"));
    assert!(!scoped.resources.iter().any(|r| r.attrs.get("name") == Some(&lit("other-db"))));
    assert!(
        scoped.resources.iter().any(|r| r.kind == "cloudflare_pages_project" && r.name == "kaje")
    );
    assert!(
        scoped.resources.iter().any(|r| r.kind == "cloudflare_d1_database" && r.name == "kaje_db")
    );
    assert!(!scoped.resources.iter().any(|r| r.kind == "cloudflare_r2_bucket"));
    assert!(!scoped.resources.iter().any(|r| r.kind == "cloudflare_workers_custom_domain"
        && r.attrs.get("service") == Some(&lit("other-api"))));
}

#[test]
fn scoping_keeps_only_the_destinations_and_script_notes_the_site_uses() {
    let scoped = scope(&account(), &pages_site());
    assert_eq!(scoped.destinations, BTreeSet::from(["kaje_sales".to_string()]));
    // A Pages site owns no Worker script, so the script note is dropped.
    assert!(scoped.not_imported.is_empty(), "{:?}", scoped.not_imported);

    let worker = scope(&account(), &worker_site());
    assert!(
        worker
            .not_imported
            .get(SCRIPTS)
            .is_some_and(|names| names == &vec!["kaje-api".to_string()])
    );
    assert!(worker.resources.iter().any(|r| r.kind == "cloudflare_workers_custom_domain"
        && r.attrs.get("service") == Some(&lit("kaje-api"))));
}

#[test]
fn a_worker_site_keeps_its_own_custom_domain_and_drops_the_pages_project() {
    let scoped = scope(&account(), &worker_site());
    assert!(!scoped.resources.iter().any(|r| r.kind == "cloudflare_pages_project"));
    assert!(scoped.resources.iter().any(|r| r.kind == "cloudflare_workers_custom_domain"));
}

#[test]
fn no_secret_looking_literal_is_ever_written() {
    for files in [
        pages_files(&no_test()),
        pages_files(&full_test(Some(DbKind::Postgres))),
        plan_files(&scope(&account(), &worker_site()), &full_test(Some(DbKind::MySql)), &backend()),
    ] {
        for (path, body) in &files {
            assert!(body.ends_with('\n') || body.is_empty(), "{path} has no final newline");
            for line in body.lines() {
                let trimmed = line.trim();
                // A literal assignment to a secret-named key. A reference such as
                // `password = var.test_db_password` is fine; a quoted value is not.
                for shape in ["password", "token", "secret", "api_key"] {
                    if trimmed.contains(&format!("{shape} = \""))
                        || trimmed.contains(&format!("{shape}\": \""))
                    {
                        panic!("{path}: a literal {shape} line: {line}");
                    }
                }
            }
            assert!(!body.contains("private-example"), "{path} carries a destination");
        }
        let db_mentions: Vec<&str> = files
            .values()
            .flat_map(|body| body.lines())
            .filter(|line| line.contains("test_db_"))
            .collect();
        for line in db_mentions {
            let trimmed = line.trim();
            let is_reference = trimmed.contains("var.test_db_")
                || trimmed.contains("variable \"test_db_")
                || trimmed.contains("TF_VAR_test_db_")
                || trimmed.starts_with("test_db_");
            assert!(is_reference, "a database detail is not a variable reference: {line}");
        }
    }
}

#[test]
fn the_hyperdrive_origin_reads_every_detail_from_a_sensitive_variable() {
    let files = pages_files(&full_test(Some(DbKind::Postgres)));
    let module = &files["modules/test-env/main.tf"];
    for field in ["host", "port", "database", "user", "password"] {
        assert!(module.contains(&format!("var.test_db_{field}")), "origin.{field}: {module}");
    }
    assert!(!module.contains("password = \""), "{module}");
    let variables = &files["modules/test-env/variables.tf"];
    assert_eq!(variables.matches("sensitive   = true").count(), 5, "{variables}");
    assert!(files["variables.tf"].contains("variable \"test_db_password\""));
    assert!(module.contains("scheme   = \"postgresql\""), "{module}");
}

#[test]
fn a_disabled_test_environment_adds_no_module_no_block_and_no_secret_variable() {
    let files = pages_files(&no_test());
    assert!(!files.keys().any(|path| path.starts_with("modules/test-env")));
    assert!(!files["main.tf"].contains("module \"test_env\""));
    assert!(!files["variables.tf"].contains("test_db_"));
    assert!(!files.contains_key("outputs.tf"));
    assert!(!files[".github/workflows/infra.yml"].contains("TEST_DB_"));
}

#[test]
fn the_workflow_names_database_secrets_only_when_hyperdrive_is_used() {
    let with_db = pages_files(&full_test(Some(DbKind::Postgres)));
    assert!(with_db[".github/workflows/infra.yml"].contains("secrets.TEST_DB_PASSWORD"));
    let without_db = pages_files(&full_test(None));
    assert!(!without_db[".github/workflows/infra.yml"].contains("TEST_DB_"));
    assert!(without_db[".github/workflows/infra.yml"].contains("secrets.CLOUDFLARE_API_TOKEN"));
}

#[test]
fn the_plan_is_deterministic_and_order_of_the_input_does_not_matter() {
    let first = pages_files(&full_test(Some(DbKind::Postgres)));
    let second = pages_files(&full_test(Some(DbKind::Postgres)));
    assert_eq!(first, second);

    let mut reversed = scope(&account(), &pages_site());
    reversed.resources.reverse();
    assert_eq!(plan_files(&reversed, &full_test(Some(DbKind::Postgres)), &backend()), first);
}

#[test]
fn every_file_ends_with_a_newline() {
    for (path, body) in pages_files(&full_test(Some(DbKind::Postgres))) {
        assert!(body.is_empty() || body.ends_with('\n'), "{path}");
    }
}

#[test]
fn the_summary_says_what_will_happen_in_plain_words() {
    let scoped = scope(&account(), &pages_site());
    let lines = summary(&scoped, &full_test(Some(DbKind::Postgres)));
    let text = lines.join("\n");
    assert!(text.contains("Imports 2 DNS records in example.com"), "{text}");
    assert!(text.contains("Imports the Pages site kaje"), "{text}");
    assert!(text.contains("Creates a test database (D1) called kaje-test"), "{text}");
    assert!(text.contains(
        "Postgres for the test environment goes through Hyperdrive; the database address is kept as a secret"
    ), "{text}");
    assert!(text.contains("Creates the test address test.kaje.example.com"), "{text}");
    assert!(!text.contains("other"), "{text}");
    assert!(!text.contains("IaC") && !text.contains("tofu"), "{text}");
}

#[test]
fn the_summary_of_a_disabled_environment_says_so() {
    let scoped = scope(&account(), &pages_site());
    let lines = summary(&scoped, &no_test());
    assert_eq!(lines.last().map(String::as_str), Some("No test environment is created."));
}

#[test]
fn a_test_hostname_outside_every_imported_zone_is_not_created() {
    let scoped = scope(&account(), &pages_site());
    let mut test = full_test(None);
    test.hostname = Some("test.somewhere-else.org".to_string());
    let text = summary(&scoped, &test).join("\n");
    assert!(text.contains("is not in an imported domain"), "{text}");
    let files = plan_files(&scoped, &test, &backend());
    assert!(!files["modules/test-env/main.tf"].contains("cloudflare_dns_record"));
}

#[test]
fn the_workflow_pins_actions_by_full_sha_and_keeps_event_values_out_of_scripts() {
    let files = pages_files(&full_test(Some(DbKind::Postgres)));
    let workflow = &files[".github/workflows/infra.yml"];
    assert!(
        workflow
            .contains("opentofu/setup-opentofu@a1320f892987e89d278cc92dc5adc984fb93aca4 # v2.0.2")
    );
    assert!(
        workflow
            .contains("actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2")
    );
    assert!(
        workflow.contains(
            "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2"
        )
    );
    assert_eq!(workflow.matches("tofu_wrapper: false").count(), 2);
    assert!(!workflow.contains("TODO"), "{workflow}");
    // Every `${{ }}` that carries a caller-controlled value sits in an env or
    // with value, never in a `run:` script.
    for line in workflow.lines().filter(|line| line.contains("${{")) {
        let controlled = line.contains("client_payload")
            || line.contains("head_ref")
            || line.contains("event.pull_request");
        if controlled {
            let trimmed = line.trim_start();
            let is_value = trimmed.starts_with("ref:")
                || trimmed.starts_with("name:")
                || trimmed.starts_with("run-id:")
                || trimmed.starts_with("github-token:")
                || trimmed.chars().next().is_some_and(|ch| ch.is_ascii_uppercase())
                    && trimmed.contains(": ${{");
            assert!(is_value, "a caller-controlled value outside env/with: {line}");
        }
    }
    // The apply job refuses without a digest and reads the saved plan from the run that made it.
    assert!(workflow.contains("refusing to apply"));
    assert!(workflow.contains("approved/tfplan"));
    assert!(workflow.contains("actions: read"));
}
