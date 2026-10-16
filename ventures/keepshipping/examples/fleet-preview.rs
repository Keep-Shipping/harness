//! The fleet console as static files: renders the fleet list, every site
//! page, the connect page and the empty state from a snapshot and writes
//! them to `target/fleet-preview/`, so a design change can be looked at in
//! a browser without a Worker, a sign-in or a Cloudflare token:
//!
//! ```text
//! cargo run -p keepshipping-waitlist --example fleet-preview [-- snapshot.json]
//! python3 -m http.server -d target/fleet-preview 8080
//! # then open http://localhost:8080/console/fleet/index.html
//! ```
//!
//! Without an argument it reads the checked-in `tests/fixtures/fleet.json`.
//! Links between pages point at the Worker's routes, so only the files
//! named below open directly.

use keepshipping_waitlist::cloudflare::page::connect_page;
use keepshipping_waitlist::cloudflare::rollback::{self, Candidate, Panel};
use keepshipping_waitlist::fleet::{self, Fleet};
use keepshipping_waitlist::github::app::{AppRow, Installation, Overview};
use keepshipping_waitlist::github::page::{
    State as GitHubState, connect_page as github_page, handoff_page,
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use std::fs;
use std::path::Path;

const FIXTURE: &str = include_str!("../tests/fixtures/fleet.json");

fn main() {
    let snapshot = match std::env::args().nth(1) {
        Some(path) => fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path}: {err}")),
        None => FIXTURE.to_owned(),
    };
    let snapshot: Fleet = serde_json::from_str(&snapshot).expect("a fleet snapshot");
    // An hour after the snapshot, so the relative times read as they would.
    let now = later(&snapshot.generated_at);
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/fleet-preview/console");
    let write = |name: &str, html: String| {
        let path = out.join(name);
        fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        fs::write(&path, html).expect("write");
    };
    write("fleet/index.html", fleet::render_index(&snapshot, &now, &Default::default()));
    for view in ["domains", "attention"] {
        let filter = fleet::Filter::from_query(Some(view), None);
        write(&format!("fleet/{view}.html"), fleet::render_index(&snapshot, &now, &filter));
    }
    let one = fleet::Filter::from_query(None, Some("Factory0"));
    write("fleet/factory0.html", fleet::render_index(&snapshot, &now, &one));
    for site in &snapshot.sites {
        let id = utf8_percent_encode(&site.id, NON_ALPHANUMERIC).to_string();
        write(
            &format!("fleet/{id}.html"),
            fleet::render_site(&snapshot, &site.id, &now).expect("a known id"),
        );
    }
    // A rollback panel and its confirmation page on the first Pages
    // production site, with made-up versions (the real ones are read live).
    if let Some(site) = snapshot.sites.iter().find(|site| rollback::target(site).is_some()) {
        let candidates: Vec<Candidate> = (0..4)
            .map(|n| Candidate {
                id: format!("{n}3f9a1c2b4d5e6f70"),
                at: snapshot.generated_at.clone(),
                commit: Some(format!("{n}a1f9c2e7b3d")),
                branch: Some("main".to_owned()),
                message: Some(format!("Release {}", 20 - n)),
                source: Some("github:push".to_owned()),
                number: None,
                live: n == 0,
            })
            .collect();
        let panel = rollback::panel_html(site, &Panel::Candidates(candidates.clone()), &now);
        write(
            "rollback-site.html",
            fleet::render_site_with(&snapshot, &site.id, &now, "", &panel, None)
                .expect("a known id"),
        );
        write(
            "rollback-confirm.html",
            rollback::confirm_page(site, &candidates[2], Some(&candidates[0]), &now),
        );
    }
    wizard_pages(&snapshot, &out);
    let accounts = vec!["Factory0".to_owned(), "Earth.OS".to_owned()];
    write(
        "connect.html",
        connect_page(
            Some(&snapshot.generated_at),
            &accounts,
            Some(&snapshot.generated_at),
            None,
            Some(1),
            &now,
        ),
    );
    write(
        "connect-error.html",
        connect_page(None, &[], None, Some("Cloudflare did not accept that token."), None, &now),
    );
    github_pages(&snapshot, &now, &write);
    write("empty.html", fleet::empty_snapshot_page(true));
    write(
        "notice.html",
        fleet::notice_page(
            "Not allowed",
            "This account is not on the console's allowlist.",
            Some(("/console/fleet", "Back to sites")),
        ),
    );
    println!("wrote {}", out.display());
}

/// The GitHub connection page in every state the App can be in, with the
/// personal token fallback both connected and not, and the hand-off page the
/// create form shows before GitHub takes over.
fn github_pages(snapshot: &Fleet, now: &str, write: &dyn Fn(&str, String)) {
    let app = AppRow {
        app_id: 4242,
        slug: "keep-shipping-console".to_owned(),
        client_id: "Iv1.preview".to_owned(),
        html_url: "https://github.com/apps/keep-shipping-console".to_owned(),
        owner: "keep-shipping".to_owned(),
        permissions: serde_json::json!({
            "contents": "write", "pull_requests": "write", "workflows": "write",
            "secrets": "write", "administration": "write", "actions": "read", "metadata": "read"
        }),
    };
    let installed = Overview {
        app: Some(app.clone()),
        installations: vec![
            Installation {
                id: 101,
                account: "nick".to_owned(),
                account_type: "User".to_owned(),
                selection: "all".to_owned(),
            },
            Installation {
                id: 202,
                account: "keep-shipping".to_owned(),
                account_type: "Organization".to_owned(),
                selection: "selected".to_owned(),
            },
        ],
    };
    let connected = GitHubState::Connected { login: Some("nick"), saved: &snapshot.generated_at };
    // No app yet: the create form, the token open below it.
    write(
        "github.html",
        github_page(&Overview::default(), None, GitHubState::Disconnected, None, None, now),
    );
    // A refusal from the create form (a bad organisation name).
    write(
        "github-app-error.html",
        github_page(
            &Overview::default(),
            Some("The organisation name can only use letters, numbers and hyphens."),
            GitHubState::Disconnected,
            None,
            None,
            now,
        ),
    );
    // Created on GitHub, not yet installed anywhere.
    write(
        "github-app-created.html",
        github_page(
            &Overview { app: Some(app.clone()), installations: Vec::new() },
            None,
            GitHubState::Disconnected,
            None,
            None,
            now,
        ),
    );
    // Installed on a personal account and an organisation, token connected.
    write("github-installed.html", github_page(&installed, None, connected, None, None, now));
    // The personal token alone, as before the app existed.
    write("github-token.html", github_page(&Overview::default(), None, connected, None, None, now));
    write(
        "github-handoff.html",
        handoff_page(
            "Keep Shipping console (keep-shipping)",
            Some("keep-shipping"),
            &keepshipping_waitlist::github::app::manifest("Keep Shipping console (keep-shipping)")
                .to_string(),
            &keepshipping_waitlist::github::app::create_target(Some("keep-shipping"), "preview"),
        ),
    );
}

/// Every step of the manage-as-code wizard, rendered with made-up findings
/// for the first site that can be managed as code: the connect card, the
/// repository choice, the review (with and without an error) and the status
/// page of a finished setup.
fn wizard_pages(snapshot: &Fleet, out: &Path) {
    use keepshipping_waitlist::github::Repo;
    use keepshipping_waitlist::onboard::detect::{Framework, Need, Runtime, Stack};
    use keepshipping_waitlist::onboard::flow::{Opened, Scan};
    use keepshipping_waitlist::onboard::generate::DbKind;
    use keepshipping_waitlist::onboard::generate::TestEnv;
    use keepshipping_waitlist::onboard::page::{Review, StatusView, View, wizard};
    use keepshipping_waitlist::onboard::store::EditView;
    use keepshipping_waitlist::onboard::wizard::{Step, preselect};
    use std::collections::BTreeSet;

    // The wizard needs a site it can manage: a Pages project. The fixture's
    // first site is re-labelled as one, so every step renders from it.
    let Some(first) = snapshot.sites.first() else {
        return;
    };
    let site = &fleet::Site {
        id: "pages:fixture-account:shop-web".to_owned(),
        name: "shop-web".to_owned(),
        kind: fleet::Kind::Pages,
        ..first.clone()
    };
    let write = |name: &str, html: String| {
        let path = out.join(name);
        fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        fs::write(&path, html).expect("write");
    };
    let here = format!("/console/fleet/{}/code", site.id);
    write("code-github.html", wizard(site, Some(Step::GitHub), View::Connect { next: &here }));

    let repo = |name: &str, private: bool| Repo {
        owner: "nick".to_owned(),
        name: name.to_owned(),
        default_branch: "main".to_owned(),
        private,
    };
    let repos = vec![repo("blog", false), repo("shop-web", true), repo("shop", true)];
    let selected =
        preselect(&site.name, None, &repos).map(|index| format!("nick/{}", repos[index].name));
    write(
        "code-repo.html",
        wizard(
            site,
            Some(Step::Repo),
            View::Repo { repos: &repos, selected: selected.as_deref(), error: None },
        ),
    );

    let mut needs = BTreeSet::new();
    needs.insert(Need::Postgres);
    needs.insert(Need::ObjectStorage);
    let stack = Stack {
        framework: Some(Framework::Next),
        runtime: Some(Runtime::Pages),
        needs,
        env_vars: BTreeSet::from(["DATABASE_URL".to_owned(), "SESSION_SECRET".to_owned()]),
        ..Stack::default()
    };
    let scan = Scan {
        repo: "nick/shop".to_owned(),
        branch: "main".to_owned(),
        truncated: true,
        stack: stack.clone(),
    };
    let plan = vec![
        "Imports 3 DNS records in example.com".to_owned(),
        "Imports the Pages site shop".to_owned(),
        "Imports the address shop.example.com on the Pages site shop".to_owned(),
        "Creates a test database (D1) called shop-test".to_owned(),
        "Postgres for the test environment goes through Hyperdrive; the database address is kept as a secret".to_owned(),
    ];
    fn review_for<'a>(scan: &'a Scan, plan: &'a [String], error: Option<&'a str>) -> Review<'a> {
        Review {
            app_repo: &scan.repo,
            stack_lines: scan.stack.summary(),
            truncated: scan.truncated,
            plan_lines: Some(plan),
            plan_note: None,
            db: Some(DbKind::Postgres),
            infra_default: "nick/infra",
            error,
        }
    }
    write(
        "code-review.html",
        wizard(site, Some(Step::Review), View::Review(review_for(&scan, &plan, None))),
    );
    let failed = "Opening the pull request did not finish. GitHub would not do that. Check the \
         token's permissions against the list on the connection page.";
    write(
        "code-failed.html",
        wizard(site, Some(Step::Review), View::Review(review_for(&scan, &plan, Some(failed)))),
    );

    let edit = EditView {
        status: "planned".to_owned(),
        summary_md: plan.iter().map(|line| format!("- {line}\n")).collect(),
        pr_url: "https://github.com/nick/infra/pull/7".to_owned(),
        pr_number: 7,
        error: String::new(),
    };
    let facts = Opened {
        test_env: TestEnv {
            enabled: true,
            name: "shop-test".to_owned(),
            hostname: Some("test.example.com".to_owned()),
            d1: false,
            kv: false,
            r2: true,
            hyperdrive: Some(DbKind::Postgres),
            pages_project: Some("shop".to_owned()),
        },
        db_given: false,
        destinations: false,
        db_kind: Some(DbKind::Postgres),
    };
    write(
        "code-opened.html",
        wizard(
            site,
            None,
            View::Status(StatusView {
                infra_repo: "nick/infra",
                edit_id: "ks0123456789abcdef0123456789abcdef",
                edit: Some(&edit),
                facts: Some(&facts),
                runner_set: false,
                worker: false,
                error: None,
            }),
        ),
    );
}

/// `generated_at` plus one hour, RFC 3339; the snapshot's own time when it
/// does not parse.
fn later(generated_at: &str) -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::parse(generated_at, &Rfc3339)
        .map(|at| (at + time::Duration::hours(1)).format(&Rfc3339).unwrap_or_default())
        .unwrap_or_else(|_| generated_at.to_owned())
}
