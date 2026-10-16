//! The GitHub connection page's HTML: plain words, the link that opens
//! GitHub's token page, the permissions in words, and the paste form.
//! Nothing here echoes a token; the form posts back to the worker, which
//! checks the token with GitHub, seals it and redirects.

use crate::fleet::{Tab, esc, signed_in_layout, time_html};

/// Where the paste form posts, and where the page is shown.
pub const CONNECT_PATH: &str = "/console/connect/github";
/// Where disconnect posts.
pub const DISCONNECT_PATH: &str = "/console/connect/github/disconnect";
/// GitHub's page for a new fine-grained token. GitHub does not take the
/// permissions as a URL, so the page lists them in words for the person to
/// tick.
pub const TOKEN_PAGE: &str = "https://github.com/settings/personal-access-tokens/new";

/// The permissions the token needs, each with what it is for in plain words.
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

/// What the page shows about the connection.
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

/// The GitHub connection page. `error` is a plain-words refusal from the
/// last paste, shown above the form; `next` is where a successful paste
/// returns the person (already checked by [`safe_next`]); `now` is RFC 3339,
/// for the relative save time.
#[must_use]
pub fn connect_page(
    state: State<'_>,
    error: Option<&str>,
    next: Option<&str>,
    now: &str,
) -> String {
    let status = match state {
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
    let (heading, submit) = match state {
        State::Connected { .. } => ("Replace the token", "Replace the GitHub token"),
        State::Disconnected => ("Connect GitHub", "Connect GitHub"),
    };
    let next_field = next
        .map(|next| format!("<input type=\"hidden\" name=\"next\" value=\"{}\">\n", esc(next)))
        .unwrap_or_default();
    let body = format!(
        "<main id=\"main\" class=\"wrap narrow\">\n\
         <div class=\"pagehead\"><div>\n<h1>GitHub connection</h1>\n\
         <p class=\"sub\">The infrastructure code for each site lives in a GitHub repository. \
         Connecting lets the console read your app repositories and open the pull requests \
         that set the infrastructure up. Nothing is changed until you approve a pull request.</p>\n\
         </div></div>\n\
         {status}\
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
         </details>\n</li>\n\
         <li class=\"panel\">\n<h2>{heading}</h2>\n\
         <p>Paste the token below. It is checked with GitHub, sealed with a key only this console \
         holds, and stored. It is never shown again.</p>\n\
         {error}\
         <form class=\"connect\" method=\"post\" action=\"{CONNECT_PATH}\" autocomplete=\"off\">\n\
         {next_field}\
         <label for=\"gh-token\">GitHub token</label>\n\
         <input id=\"gh-token\" name=\"token\" type=\"password\" required autocomplete=\"off\" \
         autocapitalize=\"off\" spellcheck=\"false\">\n\
         <button class=\"btn primary\" type=\"submit\">{submit}</button>\n\
         </form>\n</li>\n</ol>\n\
         </main>\n",
    );
    signed_in_layout("GitHub connection", Tab::GitHub, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disconnected_page_lists_every_permission_and_offers_a_paste() {
        let page = connect_page(State::Disconnected, None, None, "2026-10-16T09:00:00Z");
        assert!(page.contains(&format!("href=\"{TOKEN_PAGE}\"")));
        for (name, _, _) in PERMISSIONS {
            assert!(page.contains(&format!("<strong>{name}</strong>")), "{name} listed");
        }
        assert!(page.contains("Read and write"));
        assert!(page.contains("method=\"post\" action=\"/console/connect/github\""));
        assert!(page.contains("type=\"password\""));
        assert!(page.contains("Not connected"));
        assert!(!page.contains("Disconnect GitHub"), "nothing to disconnect");
    }

    #[test]
    fn a_connected_page_names_the_account_and_offers_disconnect_never_the_token() {
        let page = connect_page(
            State::Connected { login: Some("nick<script>"), saved: "2026-10-15T09:00:00Z" },
            None,
            None,
            "2026-10-16T09:00:00Z",
        );
        assert!(page.contains("Signed in to GitHub as <strong>nick&lt;script&gt;</strong>"));
        assert!(page.contains("action=\"/console/connect/github/disconnect\""));
        assert!(page.contains("Replace the GitHub token"));
    }

    #[test]
    fn a_connected_page_without_the_login_says_so_plainly() {
        let page = connect_page(
            State::Connected { login: None, saved: "2026-10-15T09:00:00Z" },
            None,
            None,
            "2026-10-16T09:00:00Z",
        );
        assert!(page.contains("GitHub could not be asked which account this is"));
    }

    #[test]
    fn an_error_is_escaped_and_announced() {
        let page =
            connect_page(State::Disconnected, Some("<b>no</b>"), None, "2026-10-16T09:00:00Z");
        assert!(page.contains("role=\"alert\""));
        assert!(page.contains("&lt;b&gt;no&lt;/b&gt;"));
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
        let page =
            connect_page(State::Disconnected, None, Some("/console/x\"y"), "2026-10-16T09:00:00Z");
        assert!(page.contains("name=\"next\" value=\"/console/x&quot;y\""));
        let plain = connect_page(State::Disconnected, None, None, "2026-10-16T09:00:00Z");
        assert!(!plain.contains("name=\"next\""));
    }
}
