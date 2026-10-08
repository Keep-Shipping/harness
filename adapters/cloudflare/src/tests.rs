//! One scripted fake account, and the four properties the import has to hold:
//! no secret in the output, no diff on a re-run, the right import targets, and
//! a listing that is read to its last page.

use std::path::Path;
use std::sync::Arc;

use ks_core::ports::http::{HttpMethod, HttpResponse};
use ks_core::ports::iac::{Backend, ChangeAction, IacTool, PlanJson, ResourceChange};
use ks_core::ports::secrets::SecretValue;
use ks_testing::block_on;
use ks_testing::http::FakeHttpClient;
use ks_testing::iac::FakeIacTool;
use serde_json::{Value, json};

use super::*;

const TOKEN: &str = "cf-token-secret-abc";
const DESTINATION: &str = "owner@private-example.net";
const SECOND_DESTINATION: &str = "admin@private-example.net";
const ACCOUNT: &str = "acct123";

/// A response body: the envelope every Cloudflare answer is wrapped in.
fn page(result: Value, total_pages: u64) -> Value {
    json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": result,
        "result_info": {"page": 1, "per_page": PER_PAGE, "total_pages": total_pages},
    })
}

/// A paginated response, on `page` of `total_pages`.
fn paged(result: Value, page: u64, total_pages: u64) -> Value {
    json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": result,
        "result_info": {"page": page, "per_page": PER_PAGE, "total_pages": total_pages},
    })
}

/// The DNS listing's first page, in the order the API happened to answer.
fn dns_page_one(reverse: bool) -> Value {
    let records = json!([
        {"id": "rec1", "name": "www.factoryzero.dev", "type": "A", "content": "203.0.113.9",
         "ttl": 1, "proxied": true, "comment": null, "priority": null},
        {"id": "rec3", "name": "www.factoryzero.dev", "type": "CNAME", "content": "edge.example.net",
         "ttl": 300, "proxied": false, "comment": "edge", "priority": null},
    ]);
    paged(if reverse { json!([records[1].clone(), records[0].clone()]) } else { records }, 1, 2)
}

/// A small account: two zones — one with DNS, an edited setting (one named
/// `0rtt`), a forward rule with a `drop` after it, a zone ruleset and bot
/// management, the other with two forward rules whose slugs collide — plus a
/// Pages project, a KV namespace and one Workers script. `reverse` permutes the
/// order the zones and listings answer in, and `bot_management` overrides that
/// endpoint's answer — `None` is the usual 200.
fn fake(reverse: bool, bot_management: Option<HttpResponse>) -> Arc<FakeHttpClient> {
    let reply = |url: &str, body: Value| {
        (
            HttpMethod::Get,
            url.to_string(),
            HttpResponse { status: 200, headers: vec![], body: body.to_string().into_bytes() },
        )
    };
    let zones = format!("{API_BASE}/zones?account.id={ACCOUNT}&page=1&per_page={PER_PAGE}");
    let dns = format!("{API_BASE}/zones/zone1/dns_records?page=1&per_page={PER_PAGE}");
    let dns_last = format!("{API_BASE}/zones/zone1/dns_records?page=2&per_page={PER_PAGE}");
    let email = format!("{API_BASE}/zones/zone1/email/routing/rules?page=1&per_page={PER_PAGE}");
    let kv =
        format!("{API_BASE}/accounts/{ACCOUNT}/storage/kv/namespaces?page=1&per_page={PER_PAGE}");
    let rules = json!([{
        "id": "rule1", "name": "forward to owner", "enabled": true, "priority": 0,
        "matchers": [{"type": "all", "field": "to", "value": ["owner@factoryzero.dev"]}],
        "actions": [{"type": "forward", "value": [DESTINATION]}, {"type": "drop"}],
    }]);
    // Two rules whose slugs collide: which one keeps the bare destination key
    // must not depend on the order the API listed them in.
    let admin_rules = json!([
        {"id": "ruleB", "name": "forward to admin", "enabled": true, "priority": 0,
         "matchers": [{"type": "all"}],
         "actions": [{"type": "forward", "value": [SECOND_DESTINATION]}]},
        {"id": "ruleA", "name": "forward to admin", "enabled": true, "priority": 1,
         "matchers": [{"type": "all"}],
         "actions": [{"type": "forward", "value": [SECOND_DESTINATION]}]},
    ]);
    let zone_list = json!([
        {"id": "zone1", "name": "factoryzero.dev", "type": "full"},
        {"id": "zone2", "name": "second-example.net", "type": "full"},
    ]);
    let rulesets = json!([
        {"id": "rs1", "name": "zone waf", "kind": "zone", "phase": "http_request_firewall_custom"},
        {"id": "rs2", "name": "root rules", "kind": "root", "phase": "http_request_firewall_custom"},
    ]);
    let responses = [
        reply(
            &zones,
            page(
                if reverse {
                    json!([zone_list[1].clone(), zone_list[0].clone()])
                } else {
                    zone_list
                },
                1,
            ),
        ),
        reply(
            &format!("{API_BASE}/zones/zone1/settings"),
            page(
                json!([
                    {"id": "always_use_https", "value": "on", "editable": true,
                     "modified_on": "2024-01-01T00:00:00Z"},
                    {"id": "0rtt", "value": "on", "editable": true,
                     "modified_on": "2024-01-01T00:00:00Z"},
                    {"id": "browser_cache_ttl", "value": 14400, "editable": true, "modified_on": null},
                ]),
                1,
            ),
        ),
        reply(&dns, dns_page_one(reverse)),
        reply(
            &dns_last,
            paged(
                json!([{"id": "rec2", "name": "factoryzero.dev", "type": "MX",
                          "content": "mail.private-example.net", "ttl": 3600, "proxied": false,
                          "comment": "primary", "priority": 10}]),
                2,
                2,
            ),
        ),
        reply(
            &format!("{API_BASE}/zones/zone1/workers/routes"),
            page(json!([{"id": "wr1", "pattern": "api.factoryzero.dev/*", "script": "api"}]), 1),
        ),
        reply(&email, page(rules, 1)),
        reply(&format!("{API_BASE}/zones/zone1/rulesets"), page(rulesets, 1)),
        reply(
            &format!("{API_BASE}/zones/zone1/rulesets/rs1"),
            page(
                json!({"id": "rs1", "name": "zone waf", "kind": "zone",
                        "phase": "http_request_firewall_custom",
                        "rules": [{"id": "r1", "version": "1", "last_updated": "2024-01-01T00:00:00Z",
                                   "action": "block", "expression": "http.request.uri.path eq \"/admin\"",
                                   "description": "no admin", "enabled": true,
                                   "action_parameters": {"uri": "shopify.com"}}]}),
                1,
            ),
        ),
        reply(&format!("{API_BASE}/zones/zone2/settings"), page(json!([]), 1)),
        reply(
            &format!("{API_BASE}/zones/zone2/dns_records?page=1&per_page={PER_PAGE}"),
            page(json!([]), 1),
        ),
        reply(&format!("{API_BASE}/zones/zone2/workers/routes"), page(json!([]), 1)),
        reply(
            &format!("{API_BASE}/zones/zone2/email/routing/rules?page=1&per_page={PER_PAGE}"),
            page(
                if reverse {
                    json!([admin_rules[1].clone(), admin_rules[0].clone()])
                } else {
                    admin_rules
                },
                1,
            ),
        ),
        reply(&format!("{API_BASE}/zones/zone2/rulesets"), page(json!([]), 1)),
        reply(
            &format!("{API_BASE}/zones/zone2/bot_management"),
            page(json!({"fight_mode": false}), 1),
        ),
        reply(
            &format!("{API_BASE}/accounts/{ACCOUNT}/pages/projects"),
            page(json!([{"name": "site", "production_branch": "main"}]), 1),
        ),
        reply(
            &format!("{API_BASE}/accounts/{ACCOUNT}/pages/projects/site/domains"),
            page(json!([{"name": "www.factoryzero.dev"}]), 1),
        ),
        reply(
            &format!("{API_BASE}/accounts/{ACCOUNT}/workers/domains"),
            page(
                json!([{"id": "wd1", "hostname": "api.factoryzero.dev", "service": "api",
                         "zone_id": "zone1", "environment": "production"}]),
                1,
            ),
        ),
        reply(
            &format!("{API_BASE}/accounts/{ACCOUNT}/d1/database"),
            page(json!([{"uuid": "1111-2222", "name": "app"}]), 1),
        ),
        reply(
            &format!("{API_BASE}/accounts/{ACCOUNT}/r2/buckets"),
            page(json!({"buckets": [{"name": "media"}]}), 1),
        ),
        reply(&kv, page(json!([{"id": "kv1", "title": "cache"}]), 1)),
        reply(
            &format!("{API_BASE}/accounts/{ACCOUNT}/workers/scripts"),
            page(json!([{"id": "hello-worker"}]), 1),
        ),
    ];
    let mut client = FakeHttpClient::new().with_allowed_host("api.cloudflare.com");
    for (method, url, response) in responses {
        client = client.with_response(method, url, response);
    }
    let bot_management = bot_management.unwrap_or_else(|| HttpResponse {
        status: 200,
        headers: vec![],
        body: page(json!({"fight_mode": true}), 1).to_string().into_bytes(),
    });
    client = client.with_response(
        HttpMethod::Get,
        format!("{API_BASE}/zones/zone1/bot_management"),
        bot_management,
    );
    Arc::new(client)
}

/// Reads the scripted account and generates its files.
fn import(reverse: bool) -> BTreeMap<String, String> {
    let client = fake(reverse, None);
    let reader = Cloudflare::with_base(client.clone(), SecretValue::new(TOKEN.into()), API_BASE);
    generate(&block_on(reader.read(ACCOUNT)).expect("the scripted account reads"))
}

#[test]
fn no_secret_appears_in_generated_code() {
    let client = fake(false, None);
    let reader = Cloudflare::with_base(client.clone(), SecretValue::new(TOKEN.into()), API_BASE);
    let files = generate(&block_on(reader.read(ACCOUNT)).expect("the scripted account reads"));

    for (path, contents) in &files {
        assert!(!contents.contains(TOKEN), "{path} carries the api token");
        assert!(!contents.contains(DESTINATION), "{path} carries a destination address");
        assert!(!contents.contains(SECOND_DESTINATION), "{path} carries a destination address");
    }
    assert!(files.contains_key("IMPORT-REPORT.md"));
    assert!(files["IMPORT-REPORT.md"].contains("`forward_to_owner`"));
    assert!(files["IMPORT-REPORT.md"].contains("`forward_to_admin_2`"));
    // The address left as a reference, and the reference is wired all the way
    // through: the module declares the variable and the root passes it on.
    assert!(
        files["modules/factoryzero_dev/main.tf"]
            .contains("value = [var.email_routing_destinations[\"forward_to_owner\"]]")
    );
    assert!(
        files["modules/factoryzero_dev/variables.tf"]
            .contains("variable \"email_routing_destinations\"")
    );
    assert!(
        files["main.tf"].contains("email_routing_destinations = var.email_routing_destinations")
    );
    // The token was really in play: it went out on the wire, and nowhere else.
    assert!(client.requests().iter().all(|request| {
        request.headers.contains(&("Authorization".to_string(), format!("Bearer {TOKEN}")))
    }));
    assert!(!client.requests().is_empty());
}

#[test]
fn re_running_the_import_changes_nothing() {
    let first = import(false);
    assert_eq!(first, import(false));
    // The order Cloudflare listed results in must not reach the output.
    assert_eq!(first, import(true));
}

#[test]
fn imports_point_at_the_objects_they_name() {
    let files = import(false);
    assert!(files["imports.tf"].contains(
        "import {\n  to = module.factoryzero_dev.cloudflare_dns_record.www_a\n  id = \"zone1/rec1\"\n}\n"
    ));
    assert!(
        files["imports.tf"].contains(
            "to = module.factoryzero_dev.cloudflare_zone.factoryzero_dev\n  id = \"zone1\""
        )
    );
    assert!(
        files["modules/factoryzero_dev/main.tf"].contains(
            "resource \"cloudflare_dns_record\" \"www_a\" {\n  content = \"203.0.113.9\""
        )
    );
    assert!(files["main.tf"].contains("source = \"./modules/factoryzero_dev\""));
    assert!(files["main.tf"].contains("cloudflare = {"));
    // A ruleset's rules come across whole; a dropped one would import as an
    // empty list and then fight every plan.
    assert!(
        files["modules/factoryzero_dev/main.tf"]
            .contains("rules = [\n    {\n      action = \"block\"")
    );
    // A name that would start with a digit is not an HCL identifier: the
    // setting `0rtt` imports as `r_0rtt`.
    assert!(
        files["imports.tf"].contains("module.factoryzero_dev.cloudflare_zone_setting.r_0rtt"),
        "{}",
        files["imports.tf"]
    );
    // An action with no values — a `drop` — comes across with its type.
    assert!(
        files["modules/factoryzero_dev/main.tf"].contains("type = \"drop\""),
        "{}",
        files["modules/factoryzero_dev/main.tf"]
    );
}

#[test]
fn a_two_page_listing_is_read_to_its_last_page() {
    let files = import(false);
    assert!(files["imports.tf"].contains("id = \"zone1/rec2\""), "{}", files["imports.tf"]);
    assert!(
        files["modules/factoryzero_dev/main.tf"]
            .contains("resource \"cloudflare_dns_record\" \"apex_mx\"")
    );
}

#[test]
fn a_failed_read_carries_cloudflares_message_and_not_the_token() {
    let client =
        Arc::new(FakeHttpClient::new().with_allowed_host("api.cloudflare.com").with_response(
            HttpMethod::Get,
            format!("{API_BASE}/zones?account.id={ACCOUNT}&page=1&per_page={PER_PAGE}"),
            HttpResponse {
                status: 403,
                headers: vec![],
                body: br#"{"success":false,"errors":[{"message":"Invalid API Token"}]}"#.to_vec(),
            },
        ));
    let reader = Cloudflare::with_base(client, SecretValue::new(TOKEN.into()), API_BASE);
    let message = block_on(reader.read(ACCOUNT)).expect_err("a 403 is not a read");
    assert!(message.to_string().contains("Invalid API Token"), "{message}");
    assert!(!message.to_string().contains(TOKEN), "{message}");
    assert!(!format!("{message:?}").contains(TOKEN), "{message:?}");
}

#[test]
fn a_200_that_is_not_the_envelope_is_an_error_not_an_empty_account() {
    // An HTML error page that answers 200 must not read as an account with
    // nothing in it — an empty account would pass the empty-plan gate.
    let client =
        Arc::new(FakeHttpClient::new().with_allowed_host("api.cloudflare.com").with_response(
            HttpMethod::Get,
            format!("{API_BASE}/zones?account.id={ACCOUNT}&page=1&per_page={PER_PAGE}"),
            HttpResponse {
                status: 200,
                headers: vec![],
                body: b"<html>bad gateway</html>".to_vec(),
            },
        ));
    let reader = Cloudflare::with_base(client, SecretValue::new(TOKEN.into()), API_BASE);
    let message = block_on(reader.read(ACCOUNT))
        .expect_err("a 200 whose body is not the envelope is not a read");
    assert!(message.to_string().contains("not the Cloudflare envelope"), "{message}");
    assert!(!message.to_string().contains(TOKEN), "{message}");
}

#[test]
fn an_entitlement_refusal_degrades_to_a_note_not_a_failure() {
    // Bot management needs a plan this token does not carry; everything else
    // reads. The import survives, and the report puts the refusal on record.
    let client = fake(
        false,
        Some(HttpResponse {
            status: 403,
            headers: vec![],
            body: br#"{"success":false,"errors":[{"message":"Authentication error"}]}"#.to_vec(),
        }),
    );
    let reader = Cloudflare::with_base(client, SecretValue::new(TOKEN.into()), API_BASE);
    let account =
        block_on(reader.read(ACCOUNT)).expect("a refused optional endpoint is not a failed read");
    let files = generate(&account);

    let report = &files["IMPORT-REPORT.md"];
    assert!(
        report.contains(
            "- Not readable with this token: `zone factoryzero.dev: bot management (403: Authentication error)`"
        ),
        "{report}"
    );
    // The refused object is out of the module; the rest of the zone is in.
    assert!(!files["modules/factoryzero_dev/main.tf"].contains("cloudflare_bot_management"));
    assert!(files["modules/factoryzero_dev/main.tf"].contains("cloudflare_dns_record"));
    for (path, contents) in &files {
        assert!(!contents.contains(TOKEN), "{path} carries the api token");
    }
}

#[test]
fn an_empty_plan_is_proposable() {
    // No entries at all, and entries that are all no-ops — the tool's
    // "untouched" — are both empty to the gate.
    assert!(check_empty_plan(&PlanJson::default()).is_ok());
    let untouched = PlanJson {
        changes: vec![ResourceChange {
            address: "module.factoryzero_dev.cloudflare_zone.factoryzero_dev".to_string(),
            actions: vec![ChangeAction::NoOp],
        }],
    };
    assert!(check_empty_plan(&untouched).is_ok());
}

#[test]
fn a_plan_that_would_change_is_refused_with_the_addresses_named() {
    // Fed the way a caller feeds it: the port's fake plans and shows, the gate
    // reads the PlanJson that comes back.
    let tool = FakeIacTool::new().with_plan(vec![
        ResourceChange {
            address: "module.factoryzero_dev.cloudflare_dns_record.www_a".to_string(),
            actions: vec![ChangeAction::Create],
        },
        ResourceChange {
            address: "module.factoryzero_dev.cloudflare_zone.factoryzero_dev".to_string(),
            actions: vec![ChangeAction::NoOp],
        },
    ]);
    let backend = Backend::new("local");
    let dir = Path::new("/ks-cloudflare/import");
    let saved = block_on(tool.plan(dir, &BTreeMap::new(), &backend)).expect("the fake plans");
    let plan = block_on(tool.show(&saved)).expect("the fake shows");
    let refusal = check_empty_plan(&plan).expect_err("a plan that would change is not proposable");
    let message = refusal.to_string();
    assert!(message.contains("cloudflare_dns_record.www_a"), "{message}");
    // The untouched entry neither blocks nor is named, and the token is in
    // no message.
    assert!(!message.contains("cloudflare_zone"), "{message}");
    assert!(!message.contains(TOKEN), "{message}");
    assert_eq!(refusal.addresses, vec!["module.factoryzero_dev.cloudflare_dns_record.www_a"]);
}
