//! The GitHub connection page's HTML. Two ways in, in this order:
//!
//! * the GitHub App, the recommended one: its state (not created, created but
//!   not installed, installed on which accounts), and the form that starts
//!   its creation through GitHub's manifest flow;
//! * a personal access token, under "Use a personal access token instead":
//!   the permissions in words, the link that opens GitHub's token page, and
//!   the paste form.
//!
//! Nothing here echoes a token or a key. The forms post back to the worker,
//! which checks what they name, and redirects. The pages use the console's
//! two-column layout: the explanation on the left, the action on the right,
//! one column on a phone.

use crate::fleet::{Tab, esc, signed_in_layout, time_html};
use crate::github::app::{self, Installation, Overview};

/// Where the personal token's paste form posts, and where the page is shown.
pub const CONNECT_PATH: &str = "/console/connect/github";
/// Where disconnect posts.
pub const DISCONNECT_PATH: &str = "/console/connect/github/disconnect";
/// GitHub's page for a new fine-grained token. GitHub does not take the
/// permissions as a URL, so the page lists them in words for the person to
/// tick.
pub const TOKEN_PAGE: &str = "https://github.com/settings/personal-access-tokens/new";

/// The permissions the personal token needs, each with what it is for in plain
/// words.
pub const PERMISSIONS: [(&str, &str, &str); 6] = [
    ("Contents", "Read and write", "to read your app's code and to commit the infrastructure code"),
    ("Pull requests", "Read and write", "to open the pull request each change goes through"),
    ("Workflows", "Read and write", "to add the workflow that plans and applies the code"),
    (
        "Secrets",
        "Read and write",
        "to store the settings the workflow needs in the repository's secrets",
    ),
    (
        "Administration",
        "Read and write",
        "to create the infrastructure repository, only when it does not exist yet",
    ),
    ("Metadata", "Read-only", "GitHub requires it for every token"),
];

/// The permissions the GitHub App asks for, in words: the names GitHub shows
/// on its own confirmation page.
const APP_PERMISSIONS: [&str; 7] =
    ["Contents", "Pull requests", "Workflows", "Secrets", "Administration", "Actions", "Metadata"];

/// Where the connection returns a person to after it is saved: a path on this
/// console and nowhere else. Anything else (another origin, a protocol-relative
/// `//host` path, a backslash or a control character) is refused and the page
/// falls back to its own.
#[must_use]
pub fn safe_next(raw: &str) -> Option<&str> {
    let ok = raw.starts_with("/console/")
        && !raw.starts_with("//")
        && !raw.contains('\\')
        && raw.chars().all(|c| !c.is_control());
    ok.then_some(raw)
}

/// A one-line notice shown at the top of the connection page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice<'a> {
    /// Nothing to say.
    None,
    /// The app was removed from the console. `advanced` is GitHub's settings
    /// page for the app, when the link was checked.
    Removed {
        /// The app's advanced settings page on GitHub.
        advanced: Option<&'a str>,
    },
    /// The check's result: the app's installations GitHub lists that the
    /// console does not record yet. Empty when there are none.
    Found {
        /// The installations to offer for adding.
        new: &'a [Installation],
    },
}

/// What the page shows about the personal token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State<'a> {
    /// No token is stored, or the stored one no longer opens.
    Disconnected,
    /// A token is stored: the account it speaks for when GitHub could be
    /// asked, and the RFC 3339 time it was saved.
    Connected {
        /// The signed-in account's login, when GitHub answered.
        login: Option<&'a str>,
        /// When the token was saved.
        saved: &'a str,
    },
}

/// The GitHub connection page: the app's state and create form, the personal
/// token's fallback. `app_error` is a refusal from the app's create form;
/// `token_error` one from the last token paste; `next` is where a successful
/// paste returns the person (already checked by [`safe_next`]); `now` is
/// RFC 3339, for the relative save time.
#[must_use]
pub fn connect_page(
    overview: &Overview,
    app_error: Option<&str>,
    token: State<'_>,
    token_error: Option<&str>,
    next: Option<&str>,
    now: &str,
) -> String {
    connect_page_noticed(overview, app_error, token, token_error, next, Notice::None, now)
}

/// [`connect_page`], with a notice above its content.
#[must_use]
pub fn connect_page_noticed(
    overview: &Overview,
    app_error: Option<&str>,
    token: State<'_>,
    token_error: Option<&str>,
    next: Option<&str>,
    notice: Notice<'_>,
    now: &str,
) -> String {
    let app_card = app_card(overview, app_error);
    let token_open = overview.app.is_none() || matches!(token, State::Connected { .. });
    let body = format!(
        "<main id=\"main\" class=\"wrap\">\n\
         {notice}\
         <div class=\"pagehead\"><div>\n<h1>GitHub connection</h1>\n\
         <p class=\"sub\">The infrastructure code for each site lives in a GitHub repository. \
         Connecting lets the console read your app repositories and open the pull requests \
         that set the infrastructure up. Nothing is changed until you approve a pull request.</p>\n\
         </div></div>\n\
         <div class=\"split\">\n\
         <div class=\"prose\">\n\
         <h2>The GitHub App (recommended)</h2>\n\
         <p>The app is the console's own identity on GitHub. You install it on the accounts or \
         organisations that hold your repositories, and choose which repositories it can see. \
         It works in short sessions and never holds a password.</p>\n\
         <p class=\"hint\">The app can only create repositories under an organisation. On your \
         own account, create the empty repository on GitHub first, or connect a personal token \
         below.</p>\n\
         </div>\n\
         <div>\n{app_card}</div>\n\
         </div>\n\
         <details class=\"token-fallback\"{open}>\n\
         <summary>Use a personal access token instead</summary>\n\
         {token_card}\
         </details>\n\
         </main>\n",
        notice = notice_html(notice),
        open = if token_open { " open" } else { "" },
        token_card = token_card(token, token_error, next, now),
    );
    signed_in_layout("GitHub connection", Tab::GitHub, &body)
}

/// The notice's markup. The GitHub link is escaped like every other value.
fn notice_html(notice: Notice<'_>) -> String {
    match notice {
        Notice::None => String::new(),
        Notice::Removed { advanced } => {
            let link = advanced
                .map(|url| {
                    format!(
                        " <a href=\"{}\" rel=\"noopener noreferrer\">Open the app on GitHub ↗</a>",
                        esc(url)
                    )
                })
                .unwrap_or_default();
            format!(
                "<p class=\"callout ok\" role=\"status\">The app was removed from the console. \
                 Delete it on GitHub too, so its name is free again.{link}</p>\n"
            )
        }
        Notice::Found { new: [] } => {
            "<p class=\"callout ok\" role=\"status\">Every installation of the app is already \
             listed.</p>\n"
                .to_owned()
        }
        Notice::Found { new } => {
            let rows: String = new.iter().map(new_installation_row).collect();
            format!(
                "<section class=\"panel\" aria-labelledby=\"found-title\">\n\
                 <h2 id=\"found-title\">Installations not listed yet</h2>\n\
                 <p class=\"muted\">GitHub has these installations of the app that this console \
                 does not list. Add only the ones that are yours: the app is public, so an \
                 account you do not know can appear here, and adding it lets the console act in \
                 its repositories.</p>\n\
                 <ul class=\"rows installs\">\n{rows}</ul>\n</section>\n"
            )
        }
    }
}

/// The check button, shown in both created states: it asks GitHub for the
/// app's installations and lists the ones this console does not record.
fn check_form() -> String {
    format!(
        "<form class=\"check-installs\" method=\"post\" action=\"{CHECK}\">\n\
         <p class=\"hint\">Use this if you installed the app from an organisation's settings \
         and it is not listed above.</p>\n\
         <button class=\"btn\" type=\"submit\">Check for new installations</button>\n\
         </form>\n",
        CHECK = app::CHECK_PATH,
    )
}

/// One installation the check found, with the button that adds it. GitHub's
/// text is escaped; the id is posted back and checked again on the server.
fn new_installation_row(installation: &Installation) -> String {
    let kind = if installation.is_user() { "Personal" } else { "Organisation" };
    let reach =
        if installation.selection == "all" { "all repositories" } else { "selected repositories" };
    format!(
        "<li><strong>{account}</strong> <span class=\"tag\">{kind}</span>\
         <div class=\"what\">{reach}</div>\
         <form method=\"post\" action=\"{ADOPT}\">\
         <input type=\"hidden\" name=\"installation_id\" value=\"{id}\">\
         <button class=\"btn\" type=\"submit\">Add</button></form></li>\n",
        account = esc(&installation.account),
        ADOPT = app::ADOPT_PATH,
        id = installation.id,
    )
}

/// The remove button, shown in both app states (created, and installed): a
/// secondary form with one line of warning.
fn remove_form() -> String {
    format!(
        "<form class=\"remove-app\" method=\"post\" action=\"{REMOVE}\">\n\
         <p class=\"hint\">Use this if the app was created under the wrong account. Sites \
         already set up keep working only if they use a personal token.</p>\n\
         <button class=\"btn\" type=\"submit\">Remove this app from the console</button>\n\
         </form>\n",
        REMOVE = app::REMOVE_PATH,
    )
}

/// The app's card: the create form, the "Install" step, or the installations.
fn app_card(overview: &Overview, app_error: Option<&str>) -> String {
    let error = app_error
        .map(|message| format!("<p class=\"callout bad\" role=\"alert\">{}</p>\n", esc(message)))
        .unwrap_or_default();
    let Some(app) = &overview.app else {
        return format!(
            "<section class=\"panel app-card\" aria-labelledby=\"app-title\">\n\
             <div class=\"status-head\"><h2 id=\"app-title\">GitHub App \
             <span class=\"tag live\">recommended</span></h2>\
             <p><span class=\"status unknown\">Not created</span></p></div>\n\
             <p class=\"muted\">The console creates the app on GitHub, with the permissions it \
             needs, and keeps its key in the console's secrets store.</p>\n\
             {error}\
             <form class=\"connect\" method=\"post\" action=\"{CREATE_PATH}\" autocomplete=\"off\">\n\
             <label for=\"gh-org\">GitHub organisation</label>\n\
             <input id=\"gh-org\" name=\"org\" type=\"text\" autocapitalize=\"off\" \
             spellcheck=\"false\" placeholder=\"Leave blank for your own account\">\n\
             <p class=\"hint\">The organisation's name as it appears in its GitHub address.</p>\n\
             <label for=\"gh-app-name\">App name</label>\n\
             <input id=\"gh-app-name\" name=\"name\" type=\"text\" maxlength=\"64\" \
             placeholder=\"Keep Shipping console (organisation)\">\n\
             <p class=\"hint\">GitHub app names are unique across all of GitHub. If this one is \
             taken, type another.</p>\n\
             <button class=\"btn primary\" type=\"submit\">Create the GitHub App</button>\n\
             </form>\n</section>\n",
            CREATE_PATH = CREATE_PATH,
        );
    };
    let shortfall = missing_warning(&app.missing_permissions());
    let installs = if overview.installations.is_empty() {
        format!(
            "<p class=\"muted\">The app is created but not installed on any account yet.</p>\n\
             <p><a class=\"btn primary\" href=\"{href}\">Install on GitHub ↗</a></p>\n",
            href = esc(&app::install_url(&app.slug)),
        )
    } else {
        let rows: String = overview.installations.iter().map(installation_row).collect();
        format!(
            "<ul class=\"rows installs\">\n{rows}</ul>\n\
             <p><a class=\"btn\" href=\"{href}\">Add another account ↗</a></p>\n\
             <p class=\"hint\">To install on another organisation, the app must be public: on \
             GitHub open the app's Advanced settings and choose Make public.</p>\n",
            href = esc(&app::install_url(&app.slug)),
        )
    };
    let status = if overview.installations.is_empty() {
        "<span class=\"status warn\">Created, not installed</span>"
    } else {
        "<span class=\"status ok\">Installed</span>"
    };
    format!(
        "<section class=\"panel app-card\" aria-labelledby=\"app-title\">\n\
         <div class=\"status-head\"><h2 id=\"app-title\">GitHub App \
         <span class=\"tag live\">recommended</span></h2><p>{status}</p></div>\n\
         <p class=\"muted\">App <a href=\"{page}\" rel=\"noopener noreferrer\">{slug}</a>, \
         created under {owner}.</p>\n\
         {error}{shortfall}{installs}{check}{remove}</section>\n",
        page = esc(&app.html_url),
        slug = esc(&app.slug),
        owner = esc(&app.owner),
        check = check_form(),
        remove = remove_form(),
    )
}

/// The warning shown when GitHub granted the app less than it needs: each
/// missing permission named, with what to do. Empty when nothing is missing.
fn missing_warning(missing: &[String]) -> String {
    if missing.is_empty() {
        return String::new();
    }
    let names: Vec<String> = missing.iter().map(|name| esc(name)).collect();
    format!(
        "<div class=\"callout warn\" role=\"status\"><p><strong>GitHub did not grant the app \
         everything it needs.</strong> Missing or lower than needed: {}. Open the app's \
         permissions on GitHub, accept the changes, then reload this page.</p></div>\n",
        names.join(", ")
    )
}

/// One installation: the account, its kind, what the app can see, and the
/// link to manage it on GitHub.
fn installation_row(installation: &Installation) -> String {
    let kind = if installation.is_user() { "Personal" } else { "Organisation" };
    let reach =
        if installation.selection == "all" { "all repositories" } else { "selected repositories" };
    format!(
        "<li><strong>{account}</strong> <span class=\"tag\">{kind}</span>\
         <div class=\"what\">{reach} · <a href=\"{manage}\" rel=\"noopener noreferrer\">\
         Manage on GitHub ↗</a></div></li>\n",
        account = esc(&installation.account),
        manage = esc(&app::manage_url(installation)),
    )
}

/// The personal token's section: its state, then the steps and the paste form
/// in the same two columns as the rest of the page.
fn token_card(token: State<'_>, error: Option<&str>, next: Option<&str>, now: &str) -> String {
    let status = match token {
        State::Connected { login, saved } => format!(
            "<section class=\"panel status-card\" aria-labelledby=\"status-title\">\n\
             <div class=\"status-head\"><h2 id=\"status-title\"><span class=\"status ok\">Connected</span></h2>\
             <form class=\"disconnect\" method=\"post\" action=\"{DISCONNECT_PATH}\">\
             <button class=\"btn danger\" type=\"submit\">Disconnect GitHub</button></form></div>\n\
             <p class=\"muted\">{who}Token saved {when}.</p>\n</section>\n",
            who = match login {
                Some(login) => format!("Signed in to GitHub as <strong>{}</strong>. ", esc(login)),
                None => "GitHub could not be asked which account this is just now. ".to_owned(),
            },
            when = time_html(saved, now),
        ),
        State::Disconnected => {
            "<section class=\"panel status-card\" aria-labelledby=\"status-title\">\n\
             <h2 id=\"status-title\"><span class=\"status unknown\">Not connected</span></h2>\n\
             <p class=\"muted\">No GitHub token is connected yet.</p>\n</section>\n"
                .to_owned()
        }
    };
    let error = error
        .map(|message| format!("<p class=\"callout bad\" role=\"alert\">{}</p>\n", esc(message)))
        .unwrap_or_default();
    let permissions = PERMISSIONS
        .iter()
        .map(|(name, access, why)| format!("<li><strong>{name}</strong>, {access}: {why}</li>"))
        .collect::<Vec<_>>()
        .join("\n");
    let (heading, submit) = match token {
        State::Connected { .. } => ("Replace the token", "Replace the GitHub token"),
        State::Disconnected => ("Connect GitHub", "Connect GitHub"),
    };
    let next_field = next
        .map(|next| format!("<input type=\"hidden\" name=\"next\" value=\"{}\">\n", esc(next)))
        .unwrap_or_default();
    format!(
        "{status}\
         <div class=\"split\">\n\
         <div class=\"prose\">\n\
         <ol class=\"steps\">\n\
         <li class=\"panel\">\n<h2>Create a token on GitHub</h2>\n\
         <p>Open GitHub's token page, give the token a name such as <em>Keep Shipping console</em>, \
         and choose the repositories: either <strong>All repositories</strong>, or only your app \
         repositories plus the infrastructure repository.</p>\n\
         <p><a class=\"btn primary\" target=\"_blank\" rel=\"noopener noreferrer\" href=\"{TOKEN_PAGE}\">\
         Create the token on GitHub ↗</a></p>\n\
         <details class=\"perms\" open><summary>Give it these permissions</summary>\n\
         <ul>\n{permissions}\n</ul>\n\
         <p class=\"hint\">Set every other permission to <strong>No access</strong>.</p>\n\
         </details>\n</li>\n</ol>\n\
         </div>\n\
         <div>\n\
         <ol class=\"steps\" style=\"counter-reset: step 1\">\n\
         <li class=\"panel\">\n<h2>{heading}</h2>\n\
         <p>Paste the token below. It is checked with GitHub, encrypted, and stored by this \
         console. It is never shown again.</p>\n\
         {error}\
         <form class=\"connect\" method=\"post\" action=\"{CONNECT_PATH}\" autocomplete=\"off\">\n\
         {next_field}\
         <label for=\"gh-token\">GitHub token</label>\n\
         <input id=\"gh-token\" name=\"token\" type=\"password\" required autocomplete=\"off\" \
         autocapitalize=\"off\" spellcheck=\"false\">\n\
         <button class=\"btn primary\" type=\"submit\">{submit}</button>\n\
         </form>\n</li>\n</ol>\n\
         </div>\n\
         </div>\n",
    )
}

/// Where the create form posts.
const CREATE_PATH: &str = "/console/connect/github/app/new";

/// The hand-off page: the manifest goes to GitHub in a plain form, which the
/// person submits. Nothing is created until they press the button on GitHub.
#[must_use]
pub fn handoff_page(name: &str, org: Option<&str>, manifest: &str, target: &str) -> String {
    let owner =
        org.map_or_else(|| "your own account".to_owned(), |org| format!("the {org} organisation"));
    let permissions = APP_PERMISSIONS.join(", ");
    let body = format!(
        "<main id=\"main\" class=\"wrap\">\n\
         <div class=\"pagehead\"><div>\n<h1>Create the GitHub App</h1>\n\
         <p class=\"sub\">GitHub will show the app's details for you to confirm.</p>\n\
         </div></div>\n\
         <div class=\"split\">\n\
         <div class=\"prose\">\n\
         <p>The app is <strong>{name}</strong>, created under {owner}. It asks for these \
         permissions: {permissions}.</p>\n\
         <p class=\"hint\">Nothing is created until you press the button on GitHub. Its webhook \
         and return links all point at this console.</p>\n\
         </div>\n\
         <div>\n\
         <section class=\"panel\" aria-labelledby=\"handoff-title\">\n\
         <h2 id=\"handoff-title\">Continue to GitHub</h2>\n\
         <form method=\"post\" action=\"{target}\">\n\
         <input type=\"hidden\" name=\"manifest\" value=\"{manifest}\">\n\
         <button class=\"btn primary\" type=\"submit\">Continue to GitHub ↗</button>\n\
         </form>\n\
         <p><a href=\"{back}\">Back to the GitHub connection</a></p>\n\
         </section>\n\
         </div>\n\
         </div>\n\
         </main>\n",
        name = esc(name),
        owner = esc(&owner),
        target = esc(target),
        manifest = esc(manifest),
        back = CONNECT_PATH,
    );
    signed_in_layout("Create the GitHub App", Tab::GitHub, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(slug: &str) -> app::AppRow {
        app::AppRow {
            app_id: 42,
            slug: slug.to_owned(),
            client_id: "Iv1.abc".to_owned(),
            html_url: format!("https://github.com/apps/{slug}"),
            owner: "nick".to_owned(),
            permissions: serde_json::json!({"contents": "write"}),
        }
    }

    fn install(id: i64, account: &str, kind: &str, selection: &str) -> Installation {
        Installation {
            id,
            account: account.to_owned(),
            account_type: kind.to_owned(),
            selection: selection.to_owned(),
        }
    }

    const NOW: &str = "2026-10-16T09:00:00Z";

    #[test]
    fn with_no_app_the_create_form_is_offered_and_the_token_is_open() {
        let page = connect_page(&Overview::default(), None, State::Disconnected, None, None, NOW);
        assert!(page.contains("<span class=\"status unknown\">Not created</span>"));
        assert!(page.contains("method=\"post\" action=\"/console/connect/github/app/new\""));
        assert!(page.contains("name=\"org\""));
        assert!(page.contains("name=\"name\""));
        assert!(page.contains("<details class=\"token-fallback\" open>"));
        assert!(page.contains("Use a personal access token instead"));
        assert!(page.contains("method=\"post\" action=\"/console/connect/github\""));
        assert!(page.contains("type=\"password\""));
        assert!(!page.contains("Install on GitHub"));
    }

    #[test]
    fn created_but_not_installed_offers_the_install_button() {
        let overview = Overview { app: Some(app("keep-shipping-console")), installations: vec![] };
        let page = connect_page(&overview, None, State::Disconnected, None, None, NOW);
        assert!(page.contains("Created, not installed"));
        assert!(
            page.contains(
                "href=\"https://github.com/apps/keep-shipping-console/installations/new\""
            )
        );
        assert!(page.contains("Install on GitHub"));
        assert!(!page.contains("name=\"org\""), "no second create form");
        assert!(
            !page.contains("<details class=\"token-fallback\" open>"),
            "closed once an app exists"
        );
    }

    #[test]
    fn installed_lists_each_account_with_its_reach_and_manage_link() {
        let overview = Overview {
            app: Some(app("keep-shipping-console")),
            installations: vec![
                install(7, "nick", "User", "all"),
                install(9, "keep-shipping", "Organization", "selected"),
            ],
        };
        let page = connect_page(&overview, None, State::Disconnected, None, None, NOW);
        assert!(page.contains("<span class=\"status ok\">Installed</span>"));
        assert!(page.contains("<strong>nick</strong>"));
        assert!(page.contains("all repositories"));
        assert!(page.contains("https://github.com/settings/installations/7"));
        assert!(page.contains("<strong>keep-shipping</strong>"));
        assert!(page.contains("selected repositories"));
        assert!(
            page.contains(
                "https://github.com/organizations/keep-shipping/settings/installations/9"
            )
        );
        assert!(page.contains("Add another account"));
        assert!(page.contains("choose Make public."), "the public-app hint is shown");
    }

    #[test]
    fn a_connected_token_closes_nothing_and_offers_disconnect_never_the_token() {
        let overview = Overview { app: Some(app("x")), installations: vec![] };
        let page = connect_page(
            &overview,
            None,
            State::Connected { login: Some("nick<script>"), saved: "2026-10-15T09:00:00Z" },
            None,
            None,
            NOW,
        );
        assert!(page.contains("Signed in to GitHub as <strong>nick&lt;script&gt;</strong>"));
        assert!(page.contains("action=\"/console/connect/github/disconnect\""));
        assert!(page.contains("Replace the GitHub token"));
        assert!(page.contains("<details class=\"token-fallback\" open>"));
    }

    #[test]
    fn a_connected_page_without_the_login_says_so_plainly() {
        let page = connect_page(
            &Overview::default(),
            None,
            State::Connected { login: None, saved: "2026-10-15T09:00:00Z" },
            None,
            None,
            NOW,
        );
        assert!(page.contains("GitHub could not be asked which account this is"));
    }

    #[test]
    fn errors_are_escaped_and_announced() {
        let page = connect_page(
            &Overview::default(),
            Some("<b>org</b>"),
            State::Disconnected,
            Some("<i>token</i>"),
            None,
            NOW,
        );
        assert_eq!(page.matches("role=\"alert\"").count(), 2);
        assert!(page.contains("&lt;b&gt;org&lt;/b&gt;"));
        assert!(page.contains("&lt;i&gt;token&lt;/i&gt;"));
        assert!(!page.contains("<b>org</b>"));
    }

    #[test]
    fn account_names_and_links_are_escaped() {
        let overview = Overview {
            app: Some(app("x")),
            installations: vec![install(1, "a\"b<c", "Organization", "all")],
        };
        let page = connect_page(&overview, None, State::Disconnected, None, None, NOW);
        assert!(page.contains("<strong>a&quot;b&lt;c</strong>"));
        assert!(!page.contains("a\"b<c"));
    }

    #[test]
    fn a_missing_permission_is_named_on_the_page_and_a_full_grant_is_not() {
        let granted = Overview {
            app: Some(app::AppRow {
                permissions: serde_json::json!({
                    "contents": "write", "pull_requests": "write", "workflows": "write",
                    "secrets": "write", "administration": "write", "actions": "read",
                    "metadata": "read"
                }),
                ..app("x")
            }),
            installations: vec![],
        };
        let page = connect_page(&granted, None, State::Disconnected, None, None, NOW);
        assert!(!page.contains("did not grant"), "nothing missing, no warning");

        let short = Overview {
            app: Some(app::AppRow {
                permissions: serde_json::json!({"contents": "read"}),
                ..app("x")
            }),
            installations: vec![],
        };
        let page = connect_page(&short, None, State::Disconnected, None, None, NOW);
        assert!(page.contains("did not grant the app"));
        assert!(page.contains("contents (write)"), "the missing permission is named");
        assert!(page.contains("administration (write)"));
        assert!(!page.contains("actions variables"), "variables are no longer asked for");
    }

    #[test]
    fn the_personal_account_limitation_is_said_in_one_line() {
        let page = connect_page(&Overview::default(), None, State::Disconnected, None, None, NOW);
        assert!(page.contains("can only create repositories under an organisation"));
    }

    #[test]
    fn the_token_copy_says_encrypted_and_stored() {
        let page = connect_page(&Overview::default(), None, State::Disconnected, None, None, NOW);
        assert!(page.contains("encrypted, and stored by this console"));
        assert!(!page.contains("sealed with a key only this console holds"));
    }

    #[test]
    fn the_handoff_posts_the_manifest_in_a_plain_form_to_github() {
        let target = app::create_target(Some("keep-shipping"), "abc123");
        let page = handoff_page(
            "Keep Shipping console (keep-shipping)",
            Some("keep-shipping"),
            "{\"name\":\"<x>\"}",
            &target,
        );
        assert!(page.contains(
            "method=\"post\" action=\"https://github.com/organizations/keep-shipping/settings/apps/new?state=abc123\""
        ));
        assert!(
            page.contains("name=\"manifest\" value=\"{&quot;name&quot;:&quot;&lt;x&gt;&quot;}\"")
        );
        assert!(!page.contains("<script"), "no script: the hand-off is a plain form");
        assert!(page.contains("Keep Shipping console (keep-shipping)"));
    }

    #[test]
    fn only_console_paths_are_taken_as_the_way_back() {
        assert_eq!(safe_next("/console/fleet/a%3Ab/code"), Some("/console/fleet/a%3Ab/code"));
        assert_eq!(safe_next("https://evil.example/console/x"), None);
        assert_eq!(safe_next("//evil.example/console/x"), None);
        assert_eq!(safe_next("/console/\\evil"), None);
        assert_eq!(safe_next("/console/x\nSet-Cookie: a"), None);
        assert_eq!(safe_next("/elsewhere"), None);
        assert_eq!(safe_next(""), None);
    }

    #[test]
    fn a_next_path_is_carried_in_a_hidden_field_and_escaped() {
        let page = connect_page(
            &Overview::default(),
            None,
            State::Disconnected,
            None,
            Some("/console/x\"y"),
            NOW,
        );
        assert!(page.contains("name=\"next\" value=\"/console/x&quot;y\""));
        let plain = connect_page(&Overview::default(), None, State::Disconnected, None, None, NOW);
        assert!(!plain.contains("name=\"next\""));
    }

    #[test]
    fn the_remove_button_is_offered_when_created_and_when_installed() {
        let created = Overview { app: Some(app("kp")), installations: vec![] };
        let installed = Overview {
            app: Some(app("kp")),
            installations: vec![install(7, "nick", "User", "all")],
        };
        for overview in [created, installed] {
            let page = connect_page(&overview, None, State::Disconnected, None, None, NOW);
            assert!(page.contains("action=\"/console/connect/github/app/remove\""));
            assert!(page.contains("method=\"post\""));
            assert!(page.contains("Remove this app from the console"));
            assert!(page.contains(
                "Use this if the app was created under the wrong account. Sites already set up \
                 keep working only if they use a personal token."
            ));
        }
        // No app, nothing to remove.
        let page = connect_page(&Overview::default(), None, State::Disconnected, None, None, NOW);
        assert!(!page.contains("app/remove"));
    }

    #[test]
    fn the_removal_notice_links_github_and_escapes_the_link() {
        let overview = Overview::default();
        let link = "https://github.com/settings/apps/kp/advanced";
        let page = connect_page_noticed(
            &overview,
            None,
            State::Disconnected,
            None,
            None,
            Notice::Removed { advanced: Some(link) },
            NOW,
        );
        assert!(page.contains(
            "The app was removed from the console. Delete it on GitHub too, so its name is free again."
        ));
        assert!(page.contains(&format!("href=\"{link}\"")));

        let hostile = connect_page_noticed(
            &overview,
            None,
            State::Disconnected,
            None,
            None,
            Notice::Removed { advanced: Some("https://github.com/x\"><script>") },
            NOW,
        );
        assert!(!hostile.contains("<script>"));
        assert!(hostile.contains("&quot;&gt;&lt;script&gt;"));

        let bare = connect_page_noticed(
            &overview,
            None,
            State::Disconnected,
            None,
            None,
            Notice::Removed { advanced: None },
            NOW,
        );
        assert!(bare.contains("so its name is free again.</p>"), "no link, the line still shows");
        assert!(!bare.contains("Open the app on GitHub"));
        let quiet = connect_page(&overview, None, State::Disconnected, None, None, NOW);
        assert!(!quiet.contains("was removed from the console"));
    }

    #[test]
    fn the_page_never_carries_a_secret_shaped_value() {
        let overview = Overview { app: Some(app("x")), installations: vec![] };
        let page = connect_page(&overview, None, State::Disconnected, None, None, NOW);
        assert!(!page.contains("BEGIN"), "no key material in the markup");
        assert!(!page.contains("github_pat_"));
    }

    #[test]
    fn the_check_lists_new_installations_and_escapes_each_login() {
        let hostile = install(3, "<img src=x onerror=alert(1)>", "Organization", "all");
        let fresh = [hostile, install(4, "keep-shipping", "User", "selected")];
        let overview = Overview { app: Some(app("kp")), installations: vec![] };
        let page = connect_page_noticed(
            &overview,
            None,
            State::Disconnected,
            None,
            None,
            Notice::Found { new: &fresh },
            NOW,
        );
        assert!(page.contains("Installations not listed yet"));
        assert!(!page.contains("<img"), "the hostile login is never raw HTML");
        assert!(page.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(page.contains("<strong>keep-shipping</strong>"));
        assert!(page.contains("action=\"/console/connect/github/app/adopt\""));
        assert!(page.contains("name=\"installation_id\" value=\"3\""));
        assert!(page.contains("name=\"installation_id\" value=\"4\""));
        assert!(page.contains("Organisation"));
        assert!(page.contains("all repositories"));
        assert!(page.contains("selected repositories"));
    }

    #[test]
    fn the_check_button_is_offered_in_both_created_states_and_names_the_check() {
        let created = Overview { app: Some(app("kp")), installations: vec![] };
        let installed = Overview {
            app: Some(app("kp")),
            installations: vec![install(7, "nick", "User", "all")],
        };
        for overview in [created, installed] {
            let page = connect_page(&overview, None, State::Disconnected, None, None, NOW);
            assert!(page.contains("action=\"/console/connect/github/app/check\""));
            assert!(page.contains("Check for new installations"));
        }
        let none = connect_page(&Overview::default(), None, State::Disconnected, None, None, NOW);
        assert!(!none.contains("Check for new installations"), "no app, no check");
    }

    #[test]
    fn a_check_with_nothing_new_says_so_in_one_line() {
        let overview = Overview { app: Some(app("kp")), installations: vec![] };
        let page = connect_page_noticed(
            &overview,
            None,
            State::Disconnected,
            None,
            None,
            Notice::Found { new: &[] },
            NOW,
        );
        assert!(page.contains("Every installation of the app is already listed."));
        assert!(!page.contains("Installations not listed yet"));
    }
}
