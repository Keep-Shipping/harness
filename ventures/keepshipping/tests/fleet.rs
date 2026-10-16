//! The console fleet view (issue #169), exercised natively — `fleet/` is
//! pure rendering over the snapshot, so no Workers runtime is involved:
//! the checked-in fixture parses, every site renders with its last deploy
//! and its exact Terraform link, the detail page lists resources and
//! deploys, unknown ids route nowhere, hostile snapshot strings stay
//! escaped, and the auth helpers the worker glue calls behave.

use keepshipping_waitlist::fleet::{self, Route};

const FIXTURE: &str = include_str!("fixtures/fleet.json");

fn fixture() -> fleet::Fleet {
    serde_json::from_str(FIXTURE).expect("fixtures/fleet.json is a valid snapshot")
}

/// The fixture's own `generated_at`: "checked … just now".
const NOW: &str = "2026-10-09T06:00:00Z";

fn index() -> String {
    fleet::render_index(&fixture(), NOW)
}

#[test]
fn the_index_lists_every_site_with_its_last_deploy_and_terraform_link() {
    let html = index();
    // The optional tail of the contract defaults sensibly: the worker
    // snapshot entry carries no deploys, baseline, drift or resources.
    let snapshot = fixture();
    let worker = snapshot.sites.iter().find(|s| s.id == "keepshipping-waitlist").unwrap();
    assert!(worker.deploys.is_empty() && worker.baseline.is_none() && worker.drift.is_none());
    for name in [
        "keepshipping.run",
        "factory0.ventures",
        "factoryzero.dev",
        "keepshipping-site",
        "keepshipping-waitlist",
    ] {
        assert!(html.contains(name), "missing {name}");
    }
    // deploys[0] is the last deploy: the zone's newer commit, not the
    // older one, and the time in plain words. A site never deployed says
    // so rather than leaving an empty cell.
    assert!(html.contains(
        "<time datetime=\"2026-10-08T17:42:00Z\" title=\"8 Oct 2026, 17:42 UTC · ada\">12 hours ago</time>"
    ));
    assert!(html.contains("<code>b7e4a9c</code>"));
    assert!(!html.contains("5a3c1e9"), "older deploy must not be the shown one");
    assert!(html.contains("Never deployed"));
    // The summary line and the count of sites needing attention: one
    // expiring certificate, one failing one, one site changed outside code.
    assert!(html.contains("5 sites in Factory Zero"));
    assert!(html.contains("<span class=\"n\">3</span> Need attention"));
    assert!(html.contains("3 sites need attention"));
    assert!(html.contains(
        "checked <time datetime=\"2026-10-09T06:00:00Z\">9 Oct 2026, 06:00 UTC</time> · just now"
    ));
    // Every site and every resource links to its exact Terraform file and
    // line — the acceptance criterion, checked against the index and each
    // detail page: short link text `main.tf:12`, full path in the title.
    let rev = "9f31c02d8b7a1e55c0aa4e2f6d3b90c17a84e5f1";
    fn expects(page: &str, path: &str, line: u32, rev: &str) {
        let url = format!("https://github.com/Factory-Zero/infra/blob/{rev}/{path}#L{line}");
        assert!(page.contains(&url), "missing {url}");
        assert!(page.contains(&format!("title=\"{path}\"")), "no title for {path}");
        let short = path.rsplit('/').next().unwrap_or_default();
        assert!(page.contains(&format!(">{short}:{line}</a>")), "no short link for {path}");
    }
    for site in &snapshot.sites {
        let detail = fleet::render_site(&snapshot, &site.id, NOW).expect("known id");
        if let Some(at) = &site.defined_at {
            for page in [&html, detail.as_str()] {
                expects(page, &at.path, at.line, rev);
            }
        }
        for resource in &site.resources {
            expects(&detail, &resource.defined_at.path, resource.defined_at.line, rev);
        }
    }
    // Only zones get the Change link to the edit-as-code page.
    assert!(html.contains("/v1/edits/new?kind=dns&amp;zone=keepshipping.run"));
    assert!(!html.contains("zone=keepshipping-site"));
}

#[test]
fn the_detail_page_lists_resources_deploys_and_optional_fields() {
    let html = fleet::render_site(&fixture(), "keepshipping-run", NOW).expect("known id");
    assert!(html.contains("&larr; All sites"));
    assert!(html.contains("DNS record"), "resource kinds in plain words");
    assert!(html.contains("<strong>apex</strong>"));
    assert!(html.contains("dns.tf:40"));
    // The whole deploy history, newest first, not just the last deploy.
    assert!(html.contains("b7e4a9c") && html.contains("5a3c1e9"));
    assert!(html.contains("92/100"));
    assert!(html.contains("DMARC policy is not p=reject on www.keepshipping.run"));
    // Optional fields read as not-checked, never as blank.
    let worker = fleet::render_site(&fixture(), "keepshipping-waitlist", NOW).expect("known id");
    assert!(worker.contains("Not checked yet"));
    assert!(worker.contains("None recorded") && worker.contains("Never deployed"));
}

#[test]
fn an_unknown_id_renders_nothing() {
    assert_eq!(fleet::render_site(&fixture(), "no-such-site", NOW), None);
    assert_eq!(fleet::render_site(&fixture(), "", NOW), None);
    // No prefix matches, either: ids match exactly.
    assert_eq!(fleet::render_site(&fixture(), "keepshipping-ru", NOW), None);
}

#[test]
fn route_parses_the_console_paths_only() {
    assert_eq!(fleet::route("/console/fleet"), Some(Route::Index));
    assert_eq!(fleet::route("/console/fleet/"), Some(Route::Index));
    assert_eq!(fleet::route("/console/fleet//"), Some(Route::Index));
    assert_eq!(
        fleet::route("/console/fleet/keepshipping-run/"),
        Some(Route::Site("keepshipping-run".to_owned()))
    );
    assert_eq!(
        fleet::route("/console/fleet/b7e4a9c%2Brun"),
        Some(Route::Site("b7e4a9c+run".to_owned()))
    );
    // Not the console's: near-misses, deeper paths and other prefixes all
    // fall through to the harness.
    for path in ["/console/fleetfoo", "/console/fleets", "/console/fleet/a/b", "/", "/console"] {
        assert_eq!(fleet::route(path), None, "{path}");
    }
}

#[test]
fn hostile_snapshot_strings_stay_escaped() {
    let hostile: fleet::Fleet = serde_json::from_value(serde_json::json!({
        "account": "Factory Zero",
        "generated_at": "2026-10-09T06:00:00Z",
        "terraform": { "repo": "Factory-Zero/infra\", onmouseover=\"x", "ref": "9f31c02" },
        "sites": [{
            "id": "evil",
            "name": "<script>alert(1)</script>",
            "kind": "zone",
            "venture": "&quot; onclick=\"steal()",
            "defined_at": { "path": "a<b>/../../main.tf", "line": 1 },
            "deploys": [{ "commit": "abc", "at": "not-a-date", "by": "<b>ada" }]
        }]
    }))
    .expect("the hostile snapshot is still valid JSON against the contract");
    let html = fleet::render_index(&hostile, NOW);
    assert!(!html.contains("<script>"), "no raw script tag: {html}");
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    // The entity the attacker planted is shown as text ("&amp;quot;"), the
    // real quote is escaped ("&quot;"): nothing raw survives either way.
    assert!(html.contains("&amp;quot; onclick=&quot;steal()"));
    // Attribute contexts escape too — the repo lands inside an href/title.
    assert!(html.contains("Factory-Zero/infra&quot;, onmouseover=&quot;x"));
    // An unparseable timestamp is shown as-is, never reformatted into a lie.
    assert!(html.contains("not-a-date"));
    // A dot-segment path could normalise the link out of the repo, so it
    // gets no link at all — just plain text.
    assert!(!html.contains("href=\"https://github.com/"));
    assert!(html.contains("<span class=\"unknown\">main.tf:1</span>"));
    let detail = fleet::render_site(&hostile, "evil", NOW).expect("known id");
    assert!(!detail.contains("<script>"));
    // The trigger is in the site page's deploy history, escaped.
    assert!(detail.contains("&lt;b&gt;ada"));
}

#[test]
fn pages_are_static_and_keyboard_friendly() {
    let html = index();
    // The stylesheet is inlined and dark mode is a media query, not JS.
    assert!(html.contains("prefers-color-scheme: dark"));
    assert!(html.contains("display=swap"));
    // Keyboard: a skip link, a visible focus outline, and table semantics.
    assert!(html.contains("class=\"skip\" href=\"#main\""));
    assert!(html.contains(":focus-visible"));
    assert!(html.contains("<th scope=\"col\">") && html.contains("<th scope=\"row\">"));
    assert!(!html.contains("<script"), "no JS anywhere");
    // Signing out is a same-origin POST, never a link.
    assert!(html.contains("<form class=\"signout\" method=\"post\" action=\"/console/logout\">"));
}

#[test]
fn the_auth_helpers_behave() {
    let allowlist = "ada@factory0.ventures, grace@factory0.ventures";
    assert!(fleet::email_allowed("ada@factory0.ventures", allowlist));
    assert!(fleet::email_allowed("  ADA@Factory0.Ventures ", allowlist));
    // Not a substring match: an attacker's address containing an allowed
    // one must not pass, and empty anything allows nothing.
    assert!(!fleet::email_allowed("ada@factory0.ventures.evil.example", allowlist));
    assert!(!fleet::email_allowed("", allowlist));
    assert!(!fleet::email_allowed("ada@factory0.ventures", "  ,  "));

    assert_eq!(fleet::bearer_token(Some("  BEARER  tok  ")), Some("tok".to_owned()));
    assert_eq!(fleet::bearer_token(Some("bearer tok")), Some("tok".to_owned()));
    // Any other scheme, a bare value, or a blank token is no token.
    for header in [None, Some("Basic tok"), Some("Bearer"), Some("Bearer   ")] {
        assert_eq!(fleet::bearer_token(header), None);
    }

    let cookies = "other=1; ks_console=tok.abc; more=2";
    assert_eq!(fleet::cookie_value(Some(cookies), "ks_console"), Some("tok.abc".to_owned()));
    assert_eq!(fleet::cookie_value(Some("a=1; b=2"), "ks_console"), None);
    assert_eq!(fleet::cookie_value(None, "ks_console"), None);
    // A look-alike name is not a match — cookie names are case-sensitive
    // (RFC 6265), and so is a prefix.
    assert_eq!(fleet::cookie_value(Some("xks_console=tok"), "ks_console"), None);
    assert_eq!(fleet::cookie_value(Some("ks_console=tok"), "KS_CONSOLE"), None);
}
