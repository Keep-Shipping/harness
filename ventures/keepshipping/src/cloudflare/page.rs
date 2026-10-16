//! The connect page's HTML: plain words, the one button that opens
//! Cloudflare's pre-filled token page, the permissions in words, and the
//! paste form. Nothing here echoes a token; the form posts back to the
//! worker, which seals it and redirects.

use super::rollback::{DEPLOY_PERMISSION_WORDS, DEPLOY_PERMISSIONS, DEPLOY_TOKEN_NAME};
use super::{PERMISSION_WORDS, PERMISSIONS, template_url, template_url_for};
use crate::fleet::{Tab, esc, signed_in_layout, time_html};

/// Where the paste form posts.
pub const CONNECT_PATH: &str = "/console/connect/cloudflare";
/// Where disconnect posts.
pub const DISCONNECT_PATH: &str = "/console/connect/cloudflare/disconnect";
/// Where the deploy token's paste form posts.
pub const DEPLOY_CONNECT_PATH: &str = "/console/connect/cloudflare/deploy";
/// Where removing the deploy token posts.
pub const DEPLOY_DISCONNECT_PATH: &str = "/console/connect/cloudflare/deploy/disconnect";
/// Where the master key card posts: re-wraps the stored data keys under the
/// current master key version. Tokens are not re-encrypted.
pub const KEYS_REWRAP_PATH: &str = "/console/connect/keys/rewrap";

/// The master key card: the current version as a number, and the one action
/// that moves the stored keys onto it. Only numbers and fixed copy are
/// rendered, so nothing from the key store reaches the page.
#[must_use]
pub fn key_card(version: Option<u32>) -> String {
    let (status, copy, action) = match version {
        Some(version) => (
            format!("Master key version {version}"),
            "Stored data keys are wrapped under this master key version. Re-encrypting moves \
             them onto the current version; the tokens themselves do not change."
                .to_owned(),
            format!(
                "<form class=\"rewrap\" method=\"post\" action=\"{KEYS_REWRAP_PATH}\">\
                 <button class=\"btn\" type=\"submit\">Re-encrypt with the current key</button></form>\n"
            ),
        ),
        None => (
            "No master key".to_owned(),
            "The master key is not set up, so stored tokens cannot be read or saved. See the \
             README, Deploy, for the one-time setup."
                .to_owned(),
            String::new(),
        ),
    };
    format!(
        "<section class=\"panel key-card\" aria-labelledby=\"key-title\">\n\
         <h2 id=\"key-title\">Master key</h2>\n\
         <p class=\"muted\">{status}</p>\n<p>{copy}</p>\n{action}</section>\n"
    )
}

/// The connect page. `connected_at` is the RFC 3339 time the stored token was
/// saved (when one is stored and readable), shown relative to `now`, also
/// RFC 3339; `accounts` the account names that token can read, when they
/// could be listed; `error` is a plain-words refusal from the last paste, if
/// the page is shown after one.
#[must_use]
pub fn connect_page(
    connected_at: Option<&str>,
    accounts: &[String],
    deploy_connected_at: Option<&str>,
    error: Option<&str>,
    key_version: Option<u32>,
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
    let key = key_card(key_version);
    let body = format!(
        "<main id=\"main\" class=\"wrap narrow\">\n\
         <div class=\"pagehead\"><div>\n<h1>Cloudflare connection</h1>\n\
         <p class=\"sub\">The console reads your Cloudflare accounts to list their domains, Pages \
         sites and Workers, when each was last deployed, and whether HTTPS and DNS are healthy. \
         This token is read-only: it can change nothing. Rollbacks use a separate, optional \
         token, below.</p>\n</div></div>\n\
         {status}{key}\
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
         {rollbacks}\
         </main>\n",
        rollbacks = rollbacks_section(deploy_connected_at, now),
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

/// The optional deploy token, for rollbacks: what it allows, its state, and
/// its own create link and paste form.
fn rollbacks_section(connected_at: Option<&str>, now: &str) -> String {
    let permissions = DEPLOY_PERMISSIONS
        .iter()
        .zip(DEPLOY_PERMISSION_WORDS)
        .map(|((key, kind), words)| format!("<li>{words} <code>{key}:{kind}</code></li>"))
        .collect::<Vec<_>>()
        .join("\n");
    let state = match connected_at {
        Some(when) => format!(
            "<div class=\"status-head\"><p><span class=\"status ok\">Rollbacks on</span> \
             <span class=\"muted\">· deploy token saved {when}</span></p>\
             <form class=\"disconnect\" method=\"post\" action=\"{DEPLOY_DISCONNECT_PATH}\">\
             <button class=\"btn danger\" type=\"submit\">Remove the deploy token</button></form></div>\n",
            when = time_html(when, now),
        ),
        None => "<p><span class=\"status unknown\">Rollbacks off</span></p>\n".to_owned(),
    };
    format!(
        "<section class=\"panel\" id=\"rollbacks\" aria-labelledby=\"rollbacks-title\">\n\
         <h2 id=\"rollbacks-title\">Rollbacks <span class=\"tag\">optional</span></h2>\n\
         {state}\
         <p>To roll a Pages site or Worker back to an earlier deployment from its page, add a \
         second token that can deploy. It is kept apart from the read-only one, used only when \
         you confirm a rollback, and can be removed here at any time.</p>\n\
         <p><a class=\"btn\" target=\"_blank\" rel=\"noopener noreferrer\" href=\"{href}\">\
         Create a deploy token on Cloudflare ↗</a></p>\n\
         <details class=\"perms\"><summary>The {count} permissions it asks for</summary>\n\
         <ul>\n{permissions}\n</ul>\n</details>\n\
         <form class=\"connect\" method=\"post\" action=\"{DEPLOY_CONNECT_PATH}\" autocomplete=\"off\">\n\
         <label for=\"cf-deploy-token\">Cloudflare deploy token</label>\n\
         <input id=\"cf-deploy-token\" name=\"token\" type=\"password\" required autocomplete=\"off\" \
         autocapitalize=\"off\" spellcheck=\"false\">\n\
         <button class=\"btn\" type=\"submit\">{submit}</button>\n\
         </form>\n</section>\n",
        href = esc(&template_url_for(&DEPLOY_PERMISSIONS, DEPLOY_TOKEN_NAME)),
        count = DEPLOY_PERMISSIONS.len(),
        submit =
            if connected_at.is_some() { "Replace the deploy token" } else { "Turn on rollbacks" },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_links_the_template_and_lists_every_permission_read_only() {
        let page = connect_page(None, &[], None, None, None, "2026-10-16T09:00:00Z");
        assert!(page.contains("permissionGroupKeys=%5B%7B%22key%22%3A%22zone%22"));
        for (key, _) in PERMISSIONS {
            assert!(page.contains(&format!("<code>{key}</code>")), "{key} listed");
        }
        // The read token's link asks for no write; only the separate deploy
        // token's link does.
        let read_link = template_url();
        assert!(!read_link.contains("%22edit%22"), "the read token asks for no write");
        assert!(page.contains("action=\"/console/connect/cloudflare/deploy\""));
        assert!(page.contains("Rollbacks off"));
        assert!(page.contains("type=\"password\""));
        assert!(page.contains("method=\"post\" action=\"/console/connect/cloudflare\""));
        assert!(!page.contains("Disconnect Cloudflare"), "no disconnect without a token");
        assert!(!page.contains("Remove the deploy token"));
    }

    #[test]
    fn the_key_card_shows_only_the_version_number_and_the_one_action() {
        let card = key_card(Some(2));
        assert!(card.contains("Master key version 2"));
        assert!(card.contains("action=\"/console/connect/keys/rewrap\""));
        assert!(card.contains("Re-encrypt with the current key"));
        let none = key_card(None);
        assert!(none.contains("No master key"));
        assert!(!none.contains("<form"), "nothing to re-encrypt without a key");
        assert!(!card.contains("HARNESS_KEK"), "the key ring's names stay off the page");
    }

    #[test]
    fn a_connected_page_offers_disconnect_and_never_shows_a_token() {
        let page = connect_page(
            Some("2026-10-15T09:00:00.123456Z"),
            &["Factory0".to_owned()],
            None,
            None,
            Some(2),
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
        let page = connect_page(None, &[], None, Some("<b>nope</b>"), None, "2026-10-16T09:00:00Z");
        assert!(page.contains("role=\"alert\""));
        assert!(page.contains("&lt;b&gt;nope&lt;/b&gt;"));
    }
}
