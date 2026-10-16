//! The wizard's HTML: the four steps under one progress header, the status
//! page a finished setup shows, and the callout on a site's page that starts
//! or links to it. Plain words throughout, and every value from the console,
//! the repositories or the stack is escaped.
//!
//! Nothing here takes or echoes a secret. The two secret fields are empty
//! `type="password"` inputs with autocomplete off; the page is rendered from
//! names, kinds and flags only.

use super::flow::Opened;
use super::generate::DbKind;
use super::store::{EditView, Record};
use super::wizard::Step;
use crate::cloudflare::template_url_for;
use crate::fleet::{Site, Tab, esc, notice_page, signed_in_layout, site_path_segment};
use crate::github::Repo;

/// The name the infrastructure token gets on Cloudflare's form.
pub const INFRA_TOKEN_NAME: &str = "Keep Shipping infrastructure";

/// The permission groups the infrastructure token needs, as Cloudflare's
/// template URL takes them: `(key, access)`. The keys follow Cloudflare's
/// permission reference; check them against the template page before a
/// release (the words below are what the page shows).
pub const INFRA_PERMISSIONS: [(&str, &str); 12] = [
    ("zone", "read"),
    ("dns", "edit"),
    ("zone_settings", "edit"),
    ("single_redirect", "edit"),
    ("email_routing_rule", "edit"),
    ("workers_scripts", "edit"),
    ("page", "edit"),
    ("d1", "edit"),
    ("workers_kv_storage", "edit"),
    ("workers_r2", "edit"),
    ("hyperdrive", "edit"),
    ("account_settings", "read"),
];

/// [`INFRA_PERMISSIONS`] in the words the page lists them with.
pub const INFRA_PERMISSION_WORDS: [&str; 12] = [
    "Zone: Read",
    "Zone: DNS edit",
    "Zone: Zone settings edit",
    "Zone: Single redirect edit",
    "Zone: Email routing rules edit",
    "Account: Workers scripts edit",
    "Account: Pages edit",
    "Account: D1 edit",
    "Account: Workers KV edit",
    "Account: Workers R2 storage edit",
    "Account: Hyperdrive edit",
    "Account: Account settings read",
];

/// Where the page's infrastructure token is made, pre-filled with the
/// permissions above.
#[must_use]
pub fn infra_token_url() -> String {
    template_url_for(&INFRA_PERMISSIONS, INFRA_TOKEN_NAME)
}

/// What the review shows: the scan, the plan and the form's defaults.
pub struct Review<'a> {
    /// The app repository as `owner/name`; empty for "Cloudflare only".
    pub app_repo: &'a str,
    /// The stack's findings, one plain line each.
    pub stack_lines: Vec<String>,
    /// GitHub cut the file list short.
    pub truncated: bool,
    /// The plan in words, or `None` when the account could not be read.
    pub plan_lines: Option<&'a [String]>,
    /// Why the plan is missing, in plain words.
    pub plan_note: Option<&'a str>,
    /// The database engine the test environment reaches through Hyperdrive.
    pub db: Option<DbKind>,
    /// The infrastructure repository the form starts with.
    pub infra_default: &'a str,
    /// The last failure, in plain words.
    pub error: Option<&'a str>,
}

/// The status page's facts.
pub struct StatusView<'a> {
    /// The infrastructure repository, `owner/name`.
    pub infra_repo: &'a str,
    /// The edit the setup opened.
    pub edit_id: &'a str,
    /// The edit's current state, when its row exists.
    pub edit: Option<&'a EditView>,
    /// The facts recorded by the setup.
    pub facts: Option<&'a Opened>,
    /// Whether this console has its runner token set.
    pub runner_set: bool,
    /// Whether the site is a Worker (a Pages site has no wrangler config step).
    pub worker: bool,
    /// The last failure recorded for the site, shown above the status.
    pub error: Option<&'a str>,
}

/// The page's body, by step.
pub enum View<'a> {
    /// GitHub is not connected: a card to connect it, returning to `next`.
    Connect {
        /// The wizard's own path, to come back to.
        next: &'a str,
    },
    /// The app repository choice.
    Repo {
        /// The repositories the token can see, most recently pushed first.
        repos: &'a [Repo],
        /// The one to preselect, as `owner/name`.
        selected: Option<&'a str>,
        /// The last failure, in plain words.
        error: Option<&'a str>,
    },
    /// The review and the secret fields.
    Review(Review<'a>),
    /// A finished setup.
    Status(StatusView<'a>),
}

/// The wizard page for a site. `current` is the step the progress header
/// marks; `None` marks them all done (the status page).
#[must_use]
pub fn wizard(site: &Site, current: Option<Step>, view: View<'_>) -> String {
    let name = esc(&site.name);
    let here = format!("/console/fleet/{}/code", site_path_segment(&site.id));
    let card = match view {
        View::Connect { next } => connect_card(next),
        View::Repo { repos, selected, error } => repo_card(repos, selected, error, &here),
        View::Review(review) => review_card(&review, &here),
        View::Status(status) => status_card(&status, &here, site),
    };
    let body = format!(
        "<main id=\"main\" class=\"wrap narrow\">\n\
         <nav class=\"crumbs\" aria-label=\"Breadcrumb\"><a href=\"/console/fleet\">&larr; All sites</a>\
         <span aria-hidden=\"true\">/</span><a href=\"/console/fleet/{segment}\">{name}</a></nav>\n\
         <div class=\"pagehead\"><div>\n<h1>Manage {name} as code</h1>\n\
         <p class=\"sub\">Imports this site into a GitHub repository and sets up a test environment. \
         Nothing changes until you approve a pull request.</p>\n</div></div>\n\
         {progress}\n{card}</main>\n",
        segment = site_path_segment(&site.id),
        progress = progress(current),
    );
    signed_in_layout(&format!("Manage {} as code", site.name), Tab::Sites, &body)
}

/// A plain notice page (for a refusal or an error), in the console's layout.
#[must_use]
pub fn notice(title: &str, message: &str) -> String {
    notice_page(title, message, Some(("/console/fleet", "All sites")))
}

/// The numbered progress header: the four steps, the current one marked, the
/// earlier ones done. `None` marks all four done.
fn progress(current: Option<Step>) -> String {
    let items: String = Step::ALL
        .iter()
        .map(|step| {
            let (class, aria) = match current {
                None => (" class=\"done\"", ""),
                Some(now) if step.number() < now.number() => (" class=\"done\"", ""),
                Some(now) if *step == now => ("", " aria-current=\"step\""),
                Some(_) => ("", ""),
            };
            format!(
                "<li{class}{aria}><span class=\"n\">{number}</span>{words}</li>\n",
                number = step.number(),
                words = step.words(),
            )
        })
        .collect();
    format!("<ol class=\"progress\" aria-label=\"Setup steps\">\n{items}</ol>")
}

fn connect_card(next: &str) -> String {
    let query = form_urlencoded::Serializer::new(String::new()).append_pair("next", next).finish();
    format!(
        "<section class=\"panel\">\n<h2>Connect GitHub first</h2>\n\
         <p>The code for this site lives in a GitHub repository. Connect GitHub, then come back \
         here to continue.</p>\n\
         <p><a class=\"btn primary\" href=\"/console/connect/github?{query}\">Connect GitHub</a></p>\n\
         </section>\n",
        query = esc(&query),
    )
}

fn repo_card(repos: &[Repo], selected: Option<&str>, error: Option<&str>, here: &str) -> String {
    let error = error.map(error_callout).unwrap_or_default();
    let mut options = format!(
        "<option value=\"none\"{}>None — Cloudflare only</option>\n",
        if selected.is_none() { " selected" } else { "" }
    );
    for repo in repos {
        let full = format!("{}/{}", repo.owner, repo.name);
        let chosen = selected == Some(full.as_str());
        options.push_str(&format!(
            "<option value=\"{value}\"{mark}>{label}{private}</option>\n",
            value = esc(&full),
            mark = if chosen { " selected" } else { "" },
            label = esc(&full),
            private = if repo.private { " (private)" } else { "" },
        ));
    }
    format!(
        "<section class=\"panel\">\n<h2>Choose the app repository</h2>\n\
         <p>This is the repository the app's code lives in. We read its files to see what the app \
         needs, and we never change it. Your most recently changed repositories come first.</p>\n\
         {error}\
         <form class=\"connect\" method=\"post\" action=\"{action}\" autocomplete=\"off\">\n\
         <input type=\"hidden\" name=\"step\" value=\"scan\">\n\
         <label for=\"app-repo\">App repository</label>\n\
         <select id=\"app-repo\" name=\"repo\">\n{options}</select>\n\
         <p class=\"hint\">Pick the repository, or <strong>None</strong> if the site has no code \
         in GitHub.</p>\n\
         <button class=\"btn primary\" type=\"submit\">Read this repository</button>\n\
         </form>\n</section>\n",
        action = esc(here),
    )
}

fn review_card(review: &Review<'_>, here: &str) -> String {
    let error = review.error.map(error_callout).unwrap_or_default();
    let found = if review.app_repo.is_empty() {
        "<p>No app repository: only the Cloudflare resources are imported.</p>\n".to_owned()
    } else {
        format!("<p>App repository: <code>{}</code></p>\n", esc(review.app_repo))
    };
    let findings: String =
        review.stack_lines.iter().map(|line| format!("<li>{}</li>\n", esc(line))).collect();
    let truncated = if review.truncated {
        "<div class=\"callout warn\"><p>GitHub cut the list of files short, so some of the app's \
         files were not read. Check the findings above before you approve.</p></div>\n"
    } else {
        ""
    };
    let plan = match (review.plan_lines, review.plan_note) {
        (Some(lines), _) => format!(
            "<ul class=\"findings\">\n{}</ul>\n",
            lines.iter().map(|line| format!("<li>{}</li>\n", esc(line))).collect::<String>()
        ),
        (None, note) => format!(
            "<div class=\"callout warn\"><p>{}</p></div>\n",
            esc(note.unwrap_or("The Cloudflare account could not be read just now."))
        ),
    };
    let database = match review.db {
        Some(kind) => format!(
            "<label for=\"test-db\">Test database address</label>\n\
             <input id=\"test-db\" name=\"test_db_url\" type=\"password\" autocomplete=\"off\" \
             autocapitalize=\"off\" spellcheck=\"false\" placeholder=\"postgres://user:password@host:5432/dbname\">\n\
             <p class=\"hint\">This app uses {engine}. Neon, Supabase or your own server. Leave \
             blank to add it later.</p>\n",
            engine = if kind == DbKind::Postgres { "Postgres" } else { "MySQL" },
        ),
        None => String::new(),
    };
    let permissions: String =
        INFRA_PERMISSION_WORDS.iter().map(|words| format!("<li>{words}</li>\n")).collect();
    let submit = if review.error.is_some() { "Try again" } else { "Open the pull request" };
    format!(
        "<section class=\"panel\">\n<h2>What we found</h2>\n{found}\
         <ul class=\"findings\">\n{findings}</ul>\n{truncated}</section>\n\
         <section class=\"panel\">\n<h2>What the setup will do</h2>\n{plan}\
         <p class=\"hint\">Nothing is created until you approve the plan.</p>\n</section>\n\
         <section class=\"panel\">\n<h2>Finish the setup</h2>\n{error}\
         <form class=\"connect\" method=\"post\" action=\"{action}\" autocomplete=\"off\">\n\
         <input type=\"hidden\" name=\"step\" value=\"open\">\n\
         <div class=\"check\"><input id=\"test-env\" type=\"checkbox\" name=\"test_env\" value=\"on\" checked>\
         <label for=\"test-env\">Create a test environment</label></div>\n\
         <p class=\"hint\">Untick it to bring the site under code without a test copy.</p>\n\
         <label for=\"infra-repo\">Infrastructure repository</label>\n\
         <input id=\"infra-repo\" name=\"infra_repo\" type=\"text\" value=\"{infra}\" \
         placeholder=\"owner/infra\" required autocapitalize=\"off\" spellcheck=\"false\">\n\
         <p class=\"hint\">We'll create it, private, if it doesn't exist.</p>\n\
         <label for=\"infra-token\">Cloudflare token for the infrastructure repository</label>\n\
         <input id=\"infra-token\" name=\"infra_token\" type=\"password\" required \
         autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\">\n\
         <p class=\"hint\"><a href=\"{token_url}\" target=\"_blank\" rel=\"noopener noreferrer\">Create the token on Cloudflare ↗</a> \
         with these permissions:</p>\n\
         <ul class=\"perms-list\">\n{permissions}</ul>\n\
         <p class=\"hint\">It is used once, to store the settings the workflow needs in the \
         repository's secrets. It is never stored here or shown again.</p>\n\
         {database}\
         <button class=\"btn primary\" type=\"submit\">{submit}</button>\n\
         </form>\n</section>\n",
        infra = esc(review.infra_default),
        token_url = esc(&infra_token_url()),
        action = esc(here),
    )
}

fn error_callout(message: &str) -> String {
    format!("<div class=\"callout bad\" role=\"alert\"><p>{}</p></div>\n", esc(message))
}

fn status_card(status: &StatusView<'_>, here: &str, site: &Site) -> String {
    let error = status.error.map(error_callout).unwrap_or_default();
    let pull = match status.edit {
        Some(edit) if !edit.pr_url.is_empty() => format!(
            "<p>Pull request <a href=\"{url}\" target=\"_blank\" rel=\"noopener noreferrer\">#{number} on GitHub ↗</a> \
             in <code>{repo}</code>.</p>\n",
            url = esc(&edit.pr_url),
            number = edit.pr_number,
            repo = esc(status.infra_repo),
        ),
        _ => {
            format!("<p>Infrastructure repository: <code>{}</code>.</p>\n", esc(status.infra_repo))
        }
    };
    let state = esc(&status.edit.map_or(
        "Waiting for the first plan. The workflow reads the code and posts the plan here."
            .to_owned(),
        |edit| match edit.status.as_str() {
            "planned" => {
                "The plan is ready. Read it and approve it on the change's page.".to_owned()
            }
            "approved" => "Approved. The workflow is applying it.".to_owned(),
            "failed" => format!("Failed: {}", edit.error),
            "checking" | "" => {
                "Waiting for the first plan. The workflow reads the code and posts the plan here."
                    .to_owned()
            }
            other => format!("Status: {other}."),
        },
    ));
    let summary: String = status
        .edit
        .map(|edit| {
            edit.summary_md
                .lines()
                .filter_map(|line| line.strip_prefix("- "))
                .map(|line| format!("<li>{}</li>\n", esc(line)))
                .collect::<String>()
        })
        .unwrap_or_default();
    let todo = to_do(status.facts, status.worker, status.runner_set);
    let repo_note = status.infra_repo;
    let todo_html = if todo.is_empty() {
        "<p>Nothing else to do.</p>\n".to_owned()
    } else {
        format!(
            "<ul class=\"findings\">\n{}</ul>\n",
            todo.iter().map(|line| format!("<li>{}</li>\n", esc(line))).collect::<String>()
        )
    };
    let edit_link = if status.edit_id.is_empty() {
        String::new()
    } else {
        format!(
            "<p><a class=\"btn primary\" href=\"/v1/edits/{id}\">Review the plan and approve</a></p>\n",
            id = esc(status.edit_id),
        )
    };
    format!(
        "{error}<section class=\"panel\">\n<h2>Setup status</h2>\n{pull}<p>{state}</p>\n{edit_link}\
         <p class=\"hint\">The infrastructure workflow lives on the default branch of \
         <code>{repo}</code>: that is where the approval runs it. The pull request carries the \
         same copy.</p>\n</section>\n\
         <section class=\"panel\">\n<h2>What the change does</h2>\n<ul class=\"findings\">\n{summary}</ul>\n</section>\n\
         <section class=\"panel\">\n<h2>Still to do</h2>\n{todo_html}</section>\n\
         <p><a class=\"btn\" href=\"{here}?again=1\">Run the setup again</a> \
         <span class=\"muted\">{name}</span></p>\n",
        here = esc(here),
        name = esc(&site.name),
        repo = esc(repo_note),
    )
}

/// What a person still has to do after a setup, in plain words. Pure: the
/// facts are names and flags, never a value.
#[must_use]
pub fn to_do(facts: Option<&Opened>, worker: bool, runner_set: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if !runner_set {
        lines.push(
            "Plans cannot report back yet: this console has no EDITS_RUNNER_TOKEN secret. Set \
             it, then run the setup again."
                .to_owned(),
        );
    }
    let Some(facts) = facts else {
        return lines;
    };
    if facts.test_env.enabled && facts.db_kind.is_some() && !facts.db_given {
        lines.push(
            "Add a test database later: the app needs a database for its test environment and \
             none was given, so the test environment is planned without it. In the \
             infrastructure repository go to Settings → Secrets and variables → Actions, set \
             TEST_DB_HOST, TEST_DB_PORT, TEST_DB_DATABASE, TEST_DB_USER and TEST_DB_PASSWORD, \
             then run the setup again."
                .to_owned(),
        );
    }
    if facts.destinations {
        lines.push(
            "Email forwarding: set the secret EMAIL_ROUTING_DESTINATIONS in the same place. Its \
             value is not in the files."
                .to_owned(),
        );
    }
    if worker && facts.test_env.enabled {
        lines.push(
            "After the first apply, add the test environment to your app's wrangler config. \
             Keep Shipping does not open that pull request yet."
                .to_owned(),
        );
    }
    lines
}

/// The callout on a site's page: not started, started, or managed as code.
/// `site_segment` is the site's id as one path segment.
#[must_use]
pub fn callout(site_segment: &str, record: Option<&Record>) -> String {
    let here = format!("/console/fleet/{site_segment}/code");
    match record {
        Some(record) if record.status == "opened" => format!(
            "<section class=\"callout info\"><p><strong>Managed as code.</strong> The infrastructure \
             for this site is in a pull request on GitHub. <a href=\"{here}\">Setup status →</a></p></section>\n"
        ),
        Some(_) => format!(
            "<section class=\"callout info\"><p><strong>Setup started.</strong> Finish connecting \
             this site to code.</p>\n<p><a class=\"btn primary\" href=\"{here}\">Continue the setup →</a></p></section>\n"
        ),
        None => format!(
            "<section class=\"callout info\"><p><strong>Not managed as code yet.</strong> Imports it \
             into a GitHub repo and sets up a test environment. Baseline scores, code drift and \
             links to the code appear once it is managed as code.</p>\n\
             <p><a class=\"btn primary\" href=\"{here}\">Manage this site as code →</a></p></section>\n"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::{Kind, Site};
    use crate::onboard::generate::TestEnv;

    fn site() -> Site {
        Site {
            id: "pages:acct:shop".into(),
            name: "shop<script>".into(),
            kind: Kind::Pages,
            environment: None,
            venture: String::new(),
            domains: Vec::new(),
            defined_at: None,
            deploys: Vec::new(),
            tls: None,
            dns: None,
            baseline: None,
            drift: None,
            resources: Vec::new(),
        }
    }

    fn repo(owner: &str, name: &str) -> Repo {
        Repo {
            owner: owner.into(),
            name: name.into(),
            default_branch: "main".into(),
            private: false,
        }
    }

    fn facts(enabled: bool, hyper: bool, db_given: bool, destinations: bool) -> Opened {
        Opened {
            test_env: TestEnv {
                enabled,
                name: "shop-test".into(),
                hostname: None,
                d1: false,
                kv: false,
                r2: false,
                hyperdrive: hyper.then_some(DbKind::Postgres),
                pages_project: None,
            },
            db_given,
            destinations,
            db_kind: hyper.then_some(DbKind::Postgres),
        }
    }

    #[test]
    fn the_progress_header_marks_the_current_step() {
        let page = wizard(
            &site(),
            Some(Step::Review),
            View::Repo { repos: &[], selected: None, error: None },
        );
        assert!(page.contains("<li class=\"done\"><span class=\"n\">1</span>GitHub</li>"));
        assert!(page.contains("<li class=\"done\"><span class=\"n\">2</span>App repo</li>"));
        assert!(page.contains("aria-current=\"step\"><span class=\"n\">3</span>Review"));
        assert!(page.contains("<span class=\"n\">4</span>Open pull request"));
    }

    #[test]
    fn names_are_escaped_everywhere_they_appear() {
        let page = wizard(&site(), None, View::Connect { next: "/console/fleet/x/code" });
        assert!(page.contains("shop&lt;script&gt;"));
        assert!(!page.contains("shop<script>"));
    }

    #[test]
    fn the_repo_list_preselects_and_offers_cloudflare_only() {
        let repos = [repo("nick", "a<b>"), repo("nick", "shop")];
        let page = repo_card(&repos, Some("nick/shop"), None, "/console/fleet/x/code");
        assert!(page.contains("<option value=\"none\">None — Cloudflare only</option>"));
        assert!(page.contains("<option value=\"nick/shop\" selected>nick/shop</option>"));
        assert!(page.contains("a&lt;b&gt;"));
        assert!(page.contains("name=\"step\" value=\"scan\""));
    }

    #[test]
    fn the_connect_card_returns_to_the_wizard_through_a_same_origin_next() {
        let page = connect_card("/console/fleet/pages%3Aacct%3Ashop/code");
        assert!(page.contains("/console/connect/github?next="));
        assert!(page.contains("%2Fconsole%2Ffleet%2Fpages%253Aacct%253Ashop%2Fcode"));
    }

    #[test]
    fn the_review_form_never_carries_a_secret_value_and_marks_its_fields() {
        let lines = vec!["Imports the Pages site shop".to_owned()];
        let review = Review {
            app_repo: "nick/shop",
            stack_lines: vec!["Built with Next.js".to_owned()],
            truncated: true,
            plan_lines: Some(&lines),
            plan_note: None,
            db: Some(DbKind::Postgres),
            infra_default: "nick/infra",
            error: Some(
                "Checking the infrastructure token did not finish. Cloudflare did not accept this token.",
            ),
        };
        let page = review_card(&review, "/console/fleet/x/code");
        assert!(
            page.contains("name=\"infra_token\" type=\"password\" required autocomplete=\"off\"")
        );
        assert!(page.contains("name=\"test_db_url\" type=\"password\" autocomplete=\"off\""));
        assert!(page.contains("placeholder=\"postgres://user:password@host:5432/dbname\""));
        assert!(!page.contains("name=\"infra_token\" value"));
        assert!(page.contains("GitHub cut the list of files short"));
        assert!(page.contains("Try again"));
        assert!(page.contains("value=\"nick/infra\""));
        assert!(page.contains("permissions:"));
        assert!(page.contains("Account: Hyperdrive edit"));
        assert!(page.contains(&format!("href=\"{}\"", esc(&infra_token_url()))));
    }

    #[test]
    fn an_error_is_escaped_and_never_turns_into_a_field_value() {
        let review = Review {
            app_repo: "",
            stack_lines: Vec::new(),
            truncated: false,
            plan_lines: None,
            plan_note: Some("Cloudflare did not give the account's details."),
            db: None,
            infra_default: "",
            error: Some("<b>cf_token_sentinel_0123</b>"),
        };
        let page = review_card(&review, "/console/fleet/x/code");
        assert!(page.contains("&lt;b&gt;cf_token_sentinel_0123&lt;/b&gt;"));
        assert!(!page.contains("<b>cf_token_sentinel"));
        assert!(!page.contains("test_db_url"), "no database field without Postgres or MySQL");
    }

    #[test]
    fn the_to_do_list_names_what_is_left_in_plain_words() {
        let lines = to_do(Some(&facts(true, true, false, true)), true, false);
        assert!(lines.iter().any(|line| line.contains("EDITS_RUNNER_TOKEN")));
        assert!(lines.iter().any(|line| line.contains("TEST_DB_PASSWORD")));
        assert!(lines.iter().any(|line| line.contains("EMAIL_ROUTING_DESTINATIONS")));
        assert!(lines.iter().any(|line| line.contains("wrangler config")));
    }

    #[test]
    fn a_complete_setup_has_no_to_do_but_the_runner_when_it_is_set() {
        assert!(to_do(Some(&facts(false, false, false, false)), false, true).is_empty());
        assert!(to_do(Some(&facts(true, true, true, false)), false, true).is_empty());
        assert_eq!(to_do(None, false, true), Vec::<String>::new());
    }

    #[test]
    fn the_site_callout_starts_or_links_by_state() {
        let none = callout("pages%3Aacct%3Ashop", None);
        assert!(none.contains("Manage this site as code →"));
        assert!(none.contains("Imports it into a GitHub repo and sets up a test environment."));
        let opened = Record { status: "opened".into(), ..Record::default() };
        let done = callout("pages%3Aacct%3Ashop", Some(&opened));
        assert!(done.contains("Managed as code."));
        assert!(!done.contains("Manage this site as code"));
        let started = Record { status: "failed".into(), ..Record::default() };
        assert!(callout("x", Some(&started)).contains("Continue the setup"));
    }

    #[test]
    fn the_status_page_links_the_pull_request_and_the_edit() {
        let edit = EditView {
            status: "planned".into(),
            summary_md: "- Imports the DNS records\n".into(),
            pr_url: "https://github.com/nick/infra/pull/7".into(),
            pr_number: 7,
            error: String::new(),
        };
        let facts = facts(true, false, false, false);
        let page = status_card(
            &StatusView {
                infra_repo: "nick/infra",
                edit_id: "ksabc",
                edit: Some(&edit),
                facts: Some(&facts),
                runner_set: true,
                worker: false,
                error: None,
            },
            "/console/fleet/pages%3Aacct%3Ashop/code",
            &site(),
        );
        assert!(page.contains("#7 on GitHub"));
        assert!(page.contains("href=\"/v1/edits/ksabc\""));
        assert!(page.contains("The plan is ready"));
        assert!(page.contains("<li>Imports the DNS records</li>"));
        assert!(page.contains("Run the setup again"));
    }
}
