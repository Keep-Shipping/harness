//! The connect page's HTML: plain words, the one button that opens
//! Cloudflare's pre-filled token page, the permissions in words, and the
//! paste form. Nothing here echoes a token; the form posts back to the
//! worker, which seals it and redirects.

use super::{PERMISSION_WORDS, PERMISSIONS, template_url};
use crate::fleet::{Tab, esc, signed_in_layout, time_html};

/// Where the paste form posts.
pub const CONNECT_PATH: &str = "/console/connect/cloudflare";
/// Where disconnect posts.
pub const DISCONNECT_PATH: &str = "/console/connect/cloudflare/disconnect";

/// The connect page. `connected_at` is the RFC 3339 time the stored token was
/// saved (when one is stored and readable), shown relative to `now`, also
/// RFC 3339; `accounts` the account names that token can read, when they
/// could be listed; `error` is a plain-words refusal from the last paste, if
/// the page is shown after one.
#[must_use]
pub fn connect_page(
    connected_at: Option<&str>,
    accounts: &[String],
    error: Option<&str>,
    now: &str,
) -> String {
    let permissions = PERMISSIONS
        .iter()
        .zip(PERMISSION_WORDS)
        .map(|((key, _), words)| format!("<li>{words} <code>{key}</code></li>"))
        .collect::<Vec<_>>()
        .join("\n");
    let status = match connected_at {
        Some(when) => format!(
            "<section class=\"panel status-card\" aria-labelledby=\"status-title\">\n\
             <div class=\"status-head\"><h2 id=\"status-title\"><span class=\"status ok\">Connected</span></h2>\
             <form class=\"disconnect\" method=\"post\" action=\"{DISCONNECT_PATH}\">\
             <button class=\"btn danger\" type=\"submit\">Disconnect Cloudflare</button></form></div>\n\
             <p class=\"muted\">Token saved {when}.</p>\n{reads}\
             <p class=\"hint\">To read more accounts, create a new token with <strong>All accounts</strong> \
             under Account Resources and paste it below. It replaces this one.</p>\n</section>\n",
            when = time_html(when, now),
            reads = if accounts.is_empty() {
                String::new()
            } else {
                format!(
                    "<p>It can read {} account{}:</p>\n<ul class=\"chips\">{}</ul>\n",
                    accounts.len(),
                    if accounts.len() == 1 { "" } else { "s" },
                    accounts
                        .iter()
                        .map(|name| format!("<li>{}</li>", esc(name)))
                        .collect::<String>()
                )
            },
        ),
        None => "<section class=\"panel status-card\" aria-labelledby=\"status-title\">\n\
                 <h2 id=\"status-title\"><span class=\"status unknown\">Not connected</span></h2>\n\
                 <p class=\"muted\">No Cloudflare token is connected yet.</p>\n</section>\n"
            .to_owned(),
    };
    let error = error
        .map(|message| format!("<p class=\"callout bad\" role=\"alert\">{}</p>\n", esc(message)))
        .unwrap_or_default();
    let body = format!(
        "<main id=\"main\" class=\"wrap narrow\">\n\
         <div class=\"pagehead\"><div>\n<h1>Cloudflare connection</h1>\n\
         <p class=\"sub\">The console reads your Cloudflare accounts to list their domains, Pages \
         sites and Workers, when each was last deployed, and whether HTTPS and DNS are healthy. \
         Every permission it asks for is read-only, so it can change nothing.</p>\n</div></div>\n\
         {status}\
         <ol class=\"steps\">\n\
         <li class=\"panel\">\n<h2>Create a read-only token</h2>\n\
         <p>Cloudflare opens its token page with the permissions already chosen. Check them, \
         choose <strong>Continue to summary</strong>, then <strong>Create Token</strong>.</p>\n\
         <p><a class=\"btn primary\" target=\"_blank\" rel=\"noopener noreferrer\" href=\"{href}\">\
         Create the token on Cloudflare ↗</a></p>\n\
         <details class=\"perms\"><summary>The {count} permissions it asks for</summary>\n\
         <ul>\n{permissions}\n</ul>\n</details>\n</li>\n\
         <li class=\"panel\">\n<h2>Paste it here</h2>\n\
         <p>It is checked with Cloudflare, sealed with a key only this console holds, and stored. \
         It is never shown again.</p>\n\
         {error}\
         <form class=\"connect\" method=\"post\" action=\"{CONNECT_PATH}\" autocomplete=\"off\">\n\
         <label for=\"cf-token\">Cloudflare API token</label>\n\
         <input id=\"cf-token\" name=\"token\" type=\"password\" required autocomplete=\"off\" \
         autocapitalize=\"off\" spellcheck=\"false\">\n\
         <button class=\"btn primary\" type=\"submit\">{submit}</button>\n\
         </form>\n</li>\n</ol>\n\
         </main>\n",
        href = esc(&template_url()),
        count = PERMISSIONS.len(),
        submit = if connected_at.is_some() {
            "Replace the token and refresh"
        } else {
            "Connect and read the account"
        },
    );
    signed_in_layout("Cloudflare connection", Tab::Cloudflare, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_links_the_template_and_lists_every_permission_read_only() {
        let page = connect_page(None, &[], None, "2026-10-16T09:00:00Z");
        assert!(page.contains("permissionGroupKeys=%5B%7B%22key%22%3A%22zone%22"));
        for (key, _) in PERMISSIONS {
            assert!(page.contains(&format!("<code>{key}</code>")), "{key} listed");
        }
        assert!(!page.contains("type=\"edit\""), "no write permission is asked for");
        assert!(page.contains("type=\"password\""));
        assert!(page.contains("method=\"post\" action=\"/console/connect/cloudflare\""));
        assert!(!page.contains("Disconnect"), "no disconnect without a token");
    }

    #[test]
    fn a_connected_page_offers_disconnect_and_never_shows_a_token() {
        let page = connect_page(
            Some("2026-10-15T09:00:00.123456Z"),
            &["Factory0".to_owned()],
            None,
            "2026-10-16T09:00:00Z",
        );
        assert!(page.contains("action=\"/console/connect/cloudflare/disconnect\""));
        assert!(page.contains("saved <time datetime=\"2026-10-15T09:00:00.123456Z\">15 Oct 2026, 09:00 UTC</time> · 23 hours ago."));
        assert!(page.contains("It can read 1 account:"));
        assert!(page.contains("<li>Factory0</li>"));
        assert!(page.contains("Replace the token"));
    }

    #[test]
    fn an_error_is_escaped_and_announced() {
        let page = connect_page(None, &[], Some("<b>nope</b>"), "2026-10-16T09:00:00Z");
        assert!(page.contains("role=\"alert\""));
        assert!(page.contains("&lt;b&gt;nope&lt;/b&gt;"));
    }
}
