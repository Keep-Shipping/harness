//! The console's pages, hand-rendered HTML in the Keep Shipping theme
//! (the tokens of `src/mail-theme.json`, square corners included): the
//! domain list, one checklist per domain, tiny error pages, and the
//! status JSON the page polls. Everything dynamic goes through
//! [`escape`] — these pages carry domain names and record values a
//! hostile caller typed.

use cratefield_core::axum::http::{HeaderValue, StatusCode, header};
use cratefield_core::axum::response::{IntoResponse, Response};

use super::{Desired, ITEMS};
use crate::setup::checks::ItemStatus;

/// The five characters that can break out of an HTML text node or
/// attribute, and no more. The ampersand goes first, so no escape is
/// itself escaped.
fn escape(text: &str) -> String {
    let five = [('&', "&amp;"), ('<', "&lt;"), ('>', "&gt;"), ('"', "&quot;"), ('\'', "&#39;")];
    five.iter().fold(text.to_owned(), |out, (from, to)| out.replace(*from, to))
}

/// The brand, as CSS custom properties: light by default, dark when the
/// visitor's system asks. Mobile-first; nothing external is loaded.
const CSS: &str = r#"
:root {
  --bg:#eef0f3; --card:#fbfcfd; --border:#ced1d6; --ink:#11161f; --text:#3e434b;
  --muted:#4e535b; --accent:#1950cc; --button:#1950cc; --button-text:#ffffff;
  --code-bg:#e6efff;
  font-family:'Bricolage Grotesque',system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg:#11161f; --card:#1a1f29; --border:#3d434d; --ink:#ffffff; --text:#d5d7db;
    --muted:#a1a5ab; --accent:#9cbeff; --button:#4d81eb; --button-text:#11161f;
    --code-bg:#1e2735;
  }
}
* { border-radius:0; box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-size:16px; line-height:1.5; }
main { max-width:40rem; margin:0 auto; padding:1rem; }
h1 { color:var(--ink); font-size:1.4rem; margin:0 0 .25rem; }
.domain { font-family:'DM Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  color:var(--ink); margin:0 0 .5rem; }
.intro, .footer { color:var(--muted); margin:.25rem 0 1rem; }
.note { background:var(--code-bg); border:1px solid var(--border); color:var(--ink);
  padding:.6rem .75rem; margin:0 0 1rem; }
.note a { color:var(--accent); }
.item { background:var(--card); border:1px solid var(--border); padding:.9rem; margin:.6rem 0; }
.item .head { display:flex; align-items:flex-start; gap:.6rem; }
.item input[type=checkbox] { width:1.25rem; height:1.25rem; flex-shrink:0; margin-top:.15rem;
  accent-color:var(--button); }
.item label { color:var(--ink); font-weight:600; flex:1; line-height:1.35; }
.chip { font-family:'DM Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:.72rem; padding:.1rem .45rem; border:1px solid var(--border); color:var(--muted);
  white-space:nowrap; }
.chip.done { color:var(--ink); background:var(--code-bg); border-color:var(--accent); }
.chip.pending { color:var(--text); }
.chip.needs-you { background:var(--button); border-color:var(--button); color:var(--button-text); }
.explain { margin:.45rem 0 0; }
.detail { margin:.25rem 0 0; color:var(--muted); font-size:.92rem; }
.need { margin:.5rem 0 0; }
.need a { color:var(--accent); }
form.confirm { display:inline; margin-left:.6rem; }
.fields { display:grid; gap:.4rem; margin-top:.5rem; }
.fields label, .details label { display:grid; gap:.15rem; color:var(--muted); font-size:.9rem; }
input[type=text], textarea { border:1px solid var(--border); background:var(--bg);
  color:var(--ink); padding:.5rem; font:inherit; width:100%; }
textarea { min-height:3.5rem; }
details { margin-top:.6rem; }
details summary { cursor:pointer; color:var(--accent); }
.details { display:grid; gap:.6rem; margin-top:.6rem; }
button { background:var(--button); border:1px solid var(--button); color:var(--button-text);
  padding:.65rem 1.05rem; font:inherit; font-weight:600; cursor:pointer; }
form.change { margin:1rem 0 0; }
form.change .footer { margin:.5rem 0 0; }
ul.domains { list-style:none; padding:0; }
ul.domains li { background:var(--card); border:1px solid var(--border); padding:.6rem .75rem;
  margin:.4rem 0; }
ul.domains a { color:var(--ink); }
form.new-domain { display:flex; gap:.5rem; margin-top:1rem; }
form.new-domain input { flex:1; }
p.error { margin:1rem 0; }
@media (min-width: 40rem) {
  main { padding:2rem 1rem; }
  h1 { font-size:1.6rem; }
  .fields { grid-template-columns:1fr 2fr; }
}
"#;

/// The live re-check: poll `body[data-status]` every five seconds while
/// the page is visible, and rewrite chip, detail and needs-you blocks in
/// place. No libraries; a failed poll leaves the page as it was.
const JS: &str = r#"
(function () {
  "use strict";
  var url = document.body.getAttribute("data-status");
  if (!url) { return; }
  var labels = { "done": "Done", "pending": "Turning on", "needs-you": "Needs you", "off": "Off" };
  function paint(items) {
    items.forEach(function (item) {
      var chip = document.querySelector('[data-chip="' + item.key + '"]');
      if (chip) { chip.textContent = labels[item.chip] || item.chip; chip.className = "chip " + item.chip; }
      var detail = document.querySelector('[data-detail="' + item.key + '"]');
      if (detail) { detail.textContent = item.detail; }
      var need = document.querySelector('[data-need="' + item.key + '"]');
      if (need) { need.hidden = item.chip !== "needs-you"; }
    });
  }
  function tick() {
    fetch(url, { headers: { "accept": "application/json" } })
      .then(function (answer) { return answer.ok ? answer.json() : null; })
      .then(function (status) { if (status && status.items) { paint(status.items); } })
      .catch(function () {});
  }
  setInterval(function () { if (!document.hidden) { tick(); } }, 5000);
})();
"#;

/// The page skeleton: everything the console serves is this shape.
fn page(title: &str, status_url: Option<&str>, body: &str) -> String {
    let status =
        status_url.map(|url| format!(" data-status=\"{}\"", escape(url))).unwrap_or_default();
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title><style>{CSS}</style></head>\
         <body{status}><main>{body}</main><script>{JS}</script></body></html>\n",
        title = escape(title),
    )
}

/// An HTML response with the one content type every page here carries.
pub(crate) fn html_response(status: StatusCode, body: String) -> Response {
    let typed = [(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"))];
    (status, typed, body).into_response()
}

/// A small error page, in the theme, for the HTML routes.
pub(crate) fn error_page(status: StatusCode, title: &str, detail: &str) -> Response {
    let body = format!(
        "<h1>{}</h1><p class=\"error\">{}</p><p class=\"footer\"><a href=\"/v1/setup\">Back to \
         standard setup</a></p>",
        escape(title),
        escape(detail)
    );
    html_response(status, page(title, None, &body))
}

/// `GET /v1/setup`: the domains already set up, and the box to name a new
/// one (the handler turns `?domain=` into the checklist's address).
pub fn index_page(domains: &[String]) -> String {
    let listed: String = domains
        .iter()
        .map(|domain| {
            format!(
                "<li><a href=\"/v1/setup/{domain}\">{domain}</a></li>\n",
                domain = escape(domain)
            )
        })
        .collect();
    let empty = if domains.is_empty() {
        "<p class=\"detail\">No domains set up yet. Name one below to begin.</p>"
    } else {
        ""
    };
    let body = format!(
        "<h1>Standard setup</h1>\
         <p class=\"intro\">The basics every domain needs, sent as one change you can review.</p>\
         {empty}<ul class=\"domains\">\n{listed}</ul>\
         <form class=\"new-domain\" method=\"get\" action=\"/v1/setup\">\
         <input type=\"text\" name=\"domain\" placeholder=\"example.com\" aria-label=\"Domain\">\
         <button type=\"submit\">Set up a domain</button></form>",
        listed = listed,
        empty = empty,
    );
    page("Standard setup", None, &body)
}

/// What the redirect back to the page says happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// Saved; the pull request when one opened, `None` when GitHub is not
    /// connected.
    Saved(Option<String>),
    /// GitHub is connected, but the pull request did not open: the change
    /// is kept, and sending it again retries.
    Unfiled,
    /// Nothing material changed, so no change was sent.
    NoChange,
}

impl Note {
    fn html(&self) -> String {
        match self {
            Note::Saved(Some(url)) => format!(
                "<p class=\"note\">Saved. The change is a pull request you can read before it \
                 goes live: <a href=\"{url}\">{url}</a></p>",
                url = escape(url)
            ),
            Note::Saved(None) => "<p class=\"note\">Saved. Connecting this console to GitHub is \
                 needed before the pull request can open.</p>"
                .to_owned(),
            Note::Unfiled => "<p class=\"note\">Saved. The pull request didn't open just now — \
                 the change is kept here, and sending it again will try once more.</p>"
                .to_owned(),
            Note::NoChange => "<p class=\"note\">Saved — that is already what's on file, so no \
                 new change was sent.</p>"
                .to_owned(),
        }
    }
}

/// `GET /v1/setup/{domain}`: the checklist. One form for the whole board
/// (the inputs name it through `form="change"`, so each row can also hold
/// its own little "I did this" form), every value escaped, every input
/// pre-filled from what is stored.
pub fn checklist_page(
    domain: &str,
    desired: &Desired,
    statuses: &[ItemStatus],
    note: Option<Note>,
) -> String {
    let here = format!("/v1/setup/{domain}");
    let rows: String = ITEMS
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let status = &statuses[index];
            let checked = if desired.on[index] { " checked" } else { "" };
            let extra = if item.key == "dkim" {
                format!(
                    "<div class=\"fields\">\
                     <label>selector<input type=\"text\" name=\"dkim_selector\" form=\"change\" \
                     value=\"{selector}\"></label>\
                     <label>key<input type=\"text\" name=\"dkim_key\" form=\"change\" \
                     placeholder=\"paste the key from Google\" value=\"{key}\"></label></div>",
                    selector = escape(&desired.dkim_selector),
                    key = escape(desired.dkim_key.as_deref().unwrap_or_default()),
                )
            } else {
                String::new()
            };
            let need = match (&status.link, status.confirmable) {
                (Some(link), _) => format!(
                    "<div class=\"need\" data-need=\"{key}\"{hidden}><a data-detail=\"{key}\" \
                     href=\"{link}\">{detail}</a>{confirm}</div>",
                    key = escape(item.key),
                    link = escape(link),
                    detail = escape(&status.detail),
                    hidden = if status.chip == crate::setup::checks::Chip::NeedsYou {
                        ""
                    } else {
                        " hidden"
                    },
                    confirm = if status.confirmable {
                        format!(
                            "<form class=\"confirm\" method=\"post\" action=\"{here}/confirmed\">\
                             <input type=\"hidden\" name=\"item\" value=\"{key}\">\
                             <button type=\"submit\">I did this</button></form>",
                            here = escape(&here),
                            key = escape(item.key),
                        )
                    } else {
                        String::new()
                    },
                ),
                (None, _) => format!(
                    "<p class=\"detail\" data-detail=\"{key}\">{detail}</p>",
                    key = escape(item.key),
                    detail = escape(&status.detail),
                ),
            };
            format!(
                "<div class=\"item\">\
                 <div class=\"head\"><input type=\"checkbox\" id=\"on-{key}\" name=\"{key}\" \
                 form=\"change\"{checked}><label for=\"on-{key}\">{label}</label>\
                 <span class=\"chip {chip}\" data-chip=\"{key}\">{chip_label}</span></div>\
                 <p class=\"explain\">{explain}</p>{extra}{need}</div>\n",
                key = escape(item.key),
                label = escape(item.label),
                explain = escape(item.explain),
                chip = status.chip.id(),
                chip_label = status.chip.label(),
                checked = checked,
            )
        })
        .collect();
    let details = format!(
        "<details><summary>The values, if you want to change them</summary>\
         <div class=\"details\">\
         <label>SPF record<textarea name=\"spf_value\" form=\"change\">{spf}</textarea></label>\
         <label>DMARC reports go to<input type=\"text\" name=\"dmarc_rua\" form=\"change\" \
         value=\"{rua}\"></label>\
         <label>Sitemap address<input type=\"text\" name=\"sitemap_url\" form=\"change\" \
         value=\"{sitemap}\"></label></div></details>",
        spf = escape(&desired.spf_value),
        rua = escape(&desired.dmarc_rua),
        sitemap = escape(&desired.sitemap_url),
    );
    let note = note.map(|note| note.html()).unwrap_or_default();
    let body = format!(
        "<h1>Standard setup</h1><p class=\"domain\">{domain}</p>\
         <p class=\"intro\">The basics every domain needs, sent as one change you can review.</p>\
         {note}{rows}{details}\
         <form class=\"change\" id=\"change\" method=\"post\" action=\"{here}\">\
         <button type=\"submit\">Send one change</button>\
         <p class=\"footer\">The change is a pull request you can read before it goes live.</p>\
         </form>",
        domain = escape(domain),
        here = escape(&here),
    );
    page(&format!("Standard setup — {domain}"), Some(&format!("{here}/status")), &body)
}

/// The status answer the page polls: one row per item, in checklist order.
#[must_use]
pub fn status_json(domain: &str, statuses: &[ItemStatus], checked_at: &str) -> serde_json::Value {
    serde_json::json!({
        "domain": domain,
        "items": statuses
            .iter()
            .map(|status| {
                let mut item = serde_json::json!({
                    "key": status.key,
                    "label": status.label,
                    "chip": status.chip.id(),
                    "detail": status.detail,
                    "confirmable": status.confirmable,
                });
                if let Some(link) = &status.link {
                    item["link"] = serde_json::Value::String(link.clone());
                }
                item
            })
            .collect::<Vec<_>>(),
        "checked_at": checked_at,
    })
}
