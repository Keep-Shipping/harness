//! The connect page's HTML: plain words, the one button that opens
//! Cloudflare's pre-filled token page, the permissions in words, and the
//! paste form. Nothing here echoes a token; the form posts back to the
//! worker, which seals it and redirects.

use super::{PERMISSION_WORDS, PERMISSIONS, template_url};
use crate::fleet::{esc, signed_in_layout};

/// Where the paste form posts.
pub const CONNECT_PATH: &str = "/console/connect/cloudflare";
/// Where disconnect posts.
pub const DISCONNECT_PATH: &str = "/console/connect/cloudflare/disconnect";

/// The connect page. `connected_at` is the time the stored token was saved
/// (when one is stored and readable); `accounts` the account names that
/// token can read, when they could be listed; `error` is a plain-words
/// refusal from the last paste, if the page is shown after one.
#[must_use]
pub fn connect_page(
    connected_at: Option<&str>,
    accounts: &[String],
    error: Option<&str>,
) -> String {
    let permissions = PERMISSIONS
        .iter()
        .zip(PERMISSION_WORDS)
        .map(|((key, _), words)| format!("<li>{words} <code>{key}</code></li>"))
        .collect::<Vec<_>>()
        .join("\n");
    let status = match connected_at {
        Some(when) => format!(
            "<p class=\"meta\">A token is connected, saved {when}.{reads}</p>\n\
             <p>To read more accounts, create a new token with <strong>All accounts</strong> under \
             Account Resources and paste it below: it replaces this one.</p>\n\
             <form class=\"disconnect\" method=\"post\" action=\"{DISCONNECT_PATH}\">\
             <button type=\"submit\">Disconnect Cloudflare</button></form>\n",
            when = esc(when),
            reads = if accounts.is_empty() {
                String::new()
            } else {
                format!(
                    " It can read {} account{}: {}.",
                    accounts.len(),
                    if accounts.len() == 1 { "" } else { "s" },
                    accounts.iter().map(|name| esc(name)).collect::<Vec<_>>().join(", ")
                )
            },
        ),
        None => "<p class=\"meta\">No Cloudflare token is connected.</p>\n".to_owned(),
    };
    let error = error
        .map(|message| format!("<p class=\"error\" role=\"alert\">{}</p>\n", esc(message)))
        .unwrap_or_default();
    let body = format!(
        "<main id=\"main\">\n\
         <h1>Connect Cloudflare</h1>\n\
         <p>The fleet view reads your Cloudflare account to list its domains, Pages sites and \
         Workers, when each was last deployed, and whether each domain's HTTPS certificate is \
         active. It only reads. The token below can change nothing: every permission is \
         read-only.</p>\n\
         {status}\
         <h2>1. Create the token</h2>\n\
         <p>Cloudflare opens its token page with the permissions already chosen. Check them, \
         choose Continue to summary, then Create Token.</p>\n\
         <div class=\"actions\"><a class=\"button\" target=\"_blank\" rel=\"noopener noreferrer\" href=\"{href}\">\
         Create a read-only token on Cloudflare</a></div>\n\
         <p>The permissions it asks for:</p>\n\
         <ul class=\"plain\">\n{permissions}\n</ul>\n\
         <h2>2. Paste the token</h2>\n\
         <p>Copy the token once Cloudflare shows it, then paste it here. It is checked with \
         Cloudflare, sealed with a key only this console holds, and stored. It is never shown \
         again.</p>\n\
         {error}\
         <form class=\"connect\" method=\"post\" action=\"{CONNECT_PATH}\" autocomplete=\"off\">\n\
         <label for=\"cf-token\">Cloudflare API token</label>\n\
         <input id=\"cf-token\" name=\"token\" type=\"password\" required autocomplete=\"off\" \
         autocapitalize=\"off\" spellcheck=\"false\">\n\
         <div class=\"actions\"><button type=\"submit\">{submit}</button></div>\n\
         </form>\n\
         </main>\n",
        href = esc(&template_url()),
        submit = if connected_at.is_some() {
            "Replace the token and rebuild the fleet"
        } else {
            "Connect and build the fleet"
        },
    );
    signed_in_layout("Connect Cloudflare", &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_links_the_template_and_lists_every_permission_read_only() {
        let page = connect_page(None, &[], None);
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
        let page = connect_page(Some("2026-10-16 09:00 UTC"), &["Factory0".to_owned()], None);
        assert!(page.contains("action=\"/console/connect/cloudflare/disconnect\""));
        assert!(page.contains("saved 2026-10-16 09:00 UTC"));
        assert!(page.contains("It can read 1 account: Factory0."));
        assert!(page.contains("Replace the token"));
    }

    #[test]
    fn an_error_is_escaped_and_announced() {
        let page = connect_page(None, &[], Some("<b>nope</b>"));
        assert!(page.contains("role=\"alert\""));
        assert!(page.contains("&lt;b&gt;nope&lt;/b&gt;"));
    }
}
