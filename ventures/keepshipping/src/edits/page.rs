//! The edits console's pages: server-rendered HTML, one shared layout, one
//! stylesheet (the venture's mail theme tokens, inlined), no script. Plain
//! words throughout — a status is a sentence a non-engineer can read, a
//! plan row is a sentence about a resource, and the only destructive
//! confirm is typing the zone's own name.

use crate::edits::change::{self, Field};
use std::fmt::Write as _;

/// One CSS block shared by every page: the mail theme's tokens (light and
/// dark), square corners, system-first type. Chips and plan rows get the
/// four meanings: additions green, changes amber, removals and replacements
/// red.
const CSS: &str = r#":root{--bg:#eef0f3;--card:#fbfcfd;--border:#ced1d6;--ink:#11161f;--text:#3e434b;--muted:#4e535b;--accent:#1950cc;--code:#e6efff;--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#11161f;--card:#1a1f29;--border:#3d434d;--ink:#ffffff;--text:#d5d7db;--muted:#a1a5ab;--accent:#9cbeff;--code:#1e2735;--ok:#3fb950;--warn:#d29922;--bad:#f85149}button{color:#11161f}.danger{color:#11161f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 'Bricolage Grotesque',system-ui,-apple-system,'Segoe UI',sans-serif}
main{max-width:38rem;margin:0 auto;padding:1rem}h1,h2{color:var(--ink);line-height:1.2}h1{font-size:1.5rem}h2{font-size:1.1rem;margin-top:1.5rem}
a{color:var(--accent)}code,.mono{font-family:'DM Mono',ui-monospace,SFMono-Regular,monospace;font-size:.9em}
section,p,ul{overflow-wrap:anywhere}section{background:var(--card);border:1px solid var(--border);padding:1rem;margin:1rem 0}
label{display:block;margin:.75rem 0 .25rem;color:var(--ink)}input,select,textarea{width:100%;padding:.55rem;border:1px solid var(--border);background:var(--bg);color:var(--ink);font:inherit}
textarea{font:15px/1.5 'DM Mono',ui-monospace,SFMono-Regular,monospace}
.check{display:flex;align-items:center;min-height:44px;gap:.6rem;margin:.75rem 0}.check input{width:20px;height:20px;flex:none;accent-color:var(--accent)}
button{margin-top:1rem;padding:.6rem 1.1rem;border:1px solid var(--accent);background:var(--accent);color:#fff;font:inherit;cursor:pointer}
.danger{background:var(--bad);border-color:var(--bad);color:#fff}
.chip{display:inline-block;padding:.15rem .6rem;border:1px solid var(--border);font-size:.85rem;color:var(--ink)}
.chip.ok{border-color:var(--ok);color:var(--ok)}.chip.warn{border-color:var(--warn);color:var(--warn)}
.chip.bad{border-color:var(--bad);color:var(--bad)}.chip.go{border-color:var(--accent);color:var(--accent)}
.muted{color:var(--muted)}small{color:var(--muted)}
.errors{border:1px solid var(--bad);color:var(--bad);padding:.75rem;margin:1rem 0}
.risky{border:1px solid var(--bad);padding:.75rem;margin:1rem 0;color:var(--ink)}
.plan{list-style:none;padding:0;margin:.5rem 0}.plan li{padding:.3rem 0;border-bottom:1px solid var(--border)}.plan li:last-child{border-bottom:0}
.plan .add{color:var(--ok)}.plan .chg{color:var(--warn)}.plan .del{color:var(--bad)}
.ask{margin:.5rem 0;padding-left:1.25rem}
ul.links{list-style:none;padding:0}.links li{margin:.4rem 0}.links a{display:block;padding:.55rem .75rem;border:1px solid var(--border);background:var(--card);text-decoration:none}
table{width:100%;border-collapse:collapse}td{padding:.45rem 0;border-bottom:1px solid var(--border);vertical-align:top}"#;

/// The brand fonts, loaded once per page from Google Fonts.
const FONTS: &str = "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n\
<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n\
<link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@400;600&family=DM+Mono&display=swap\">";

/// The page shell: title, fonts, the stylesheet, one `main`, and — unless
/// `footer` is false — a way back to the list.
fn shell(title: &str, body: &str, footer: bool) -> String {
    let back = if footer { "\n<p><a href=\"/v1/edits\">All changes</a></p>" } else { "" };
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>{}</title>\n{FONTS}\n<style>{CSS}</style></head>\n<body><main>{}{back}</main></body></html>\n",
        escape(title),
        body,
    )
}

/// The shared layout: title, the stylesheet, one `main`, a way back.
pub(crate) fn page(title: &str, body: &str) -> String {
    shell(title, body, true)
}

/// Escapes `text` for safe inclusion in element text and attribute values.
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// The 401 body: signed-out is a normal state, so it is a page, not a
/// stack trace. The link leads to the console sign-in (or the configured
/// `EDITS_SIGN_IN_URL`) and straight back; `None` renders plain words and
/// no dead link. No "all changes" footer — the list would only 401 too.
pub(crate) fn signed_out(sign_in: Option<String>) -> String {
    let link = match sign_in {
        Some(href) => {
            format!(
                "<p><a href=\"{}\">Sign in</a> and you will come straight back here.</p>",
                escape(&href)
            )
        }
        None => {
            "<p class=\"muted\">This deployment has no sign-in page configured yet.</p>".to_owned()
        }
    };
    shell(
        "Sign in to continue",
        &format!(
            "<section><h1>Sign in to continue</h1>\n<p>You need to sign in before you can see or \
             make changes.</p>\n{link}</section>"
        ),
        false,
    )
}

/// The 503 body: the module is not wired to everything it needs yet.
pub(crate) fn not_ready(what: &str) -> String {
    page(
        "Not ready",
        &format!(
            "<section><h1>Not ready</h1><p>This part of the console is not set up yet: {}</p></section>",
            escape(what)
        ),
    )
}

/// A status in words plus its chip colour class.
pub(crate) fn status_chip(status: &str) -> (&'static str, &'static str) {
    match status {
        "opening" => ("Opening the pull request", "warn"),
        "awaiting" => ("Checking the plan", "warn"),
        "planned" => ("Ready for approval", "ok"),
        "approved" => ("Approved — applying", "go"),
        "failed" => ("Failed", "bad"),
        _ => ("In progress", ""),
    }
}

fn chip(status: &str) -> String {
    let (words, class) = status_chip(status);
    format!("<span class=\"chip {class}\">{words}</span>")
}

/// One row of the list page.
pub(crate) struct ListRow {
    pub id: String,
    pub title: String,
    pub zone: String,
    pub status: String,
    pub created_at: String,
}

/// The "Make a change" links, shared by the chooser page and the list.
fn chooser_links() -> String {
    let mut links = String::new();
    for spec in change::FORMS {
        let _ = writeln!(
            links,
            "<li><a href=\"/v1/edits/new?kind={0}\">{1}</a></li>",
            spec.kind, spec.name
        );
    }
    links
}

/// `2026-10-09T12:34:56Z` → `9 Oct 2026`; anything that is not that shape
/// stays as it came, rather than lying.
fn short_date(stamp: &str) -> String {
    const MONTHS: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let (Some(year), Some(month), Some(day)) = (stamp.get(0..4), stamp.get(5..7), stamp.get(8..10))
    else {
        return stamp.to_owned();
    };
    let digit = |text: &str| text.bytes().all(|byte| byte.is_ascii_digit());
    let Ok(month) = month.parse::<usize>() else { return stamp.to_owned() };
    let (Some(name), true) = (MONTHS.get(month.wrapping_sub(1)), digit(year) && digit(day)) else {
        return stamp.to_owned();
    };
    let day = day.trim_start_matches('0');
    let day = if day.is_empty() { "0" } else { day };
    format!("{day} {name} {year}")
}

/// The list page: every edit newest first, plus the "Make a change" chooser.
pub(crate) fn list(rows: &[ListRow]) -> String {
    let mut table = String::new();
    for row in rows {
        let _ = write!(
            table,
            "<tr><td><a href=\"/v1/edits/{}\">{}</a><br><small>{}</small></td><td>{}<br><small>{}</small></td></tr>",
            escape(&row.id),
            escape(&row.title),
            escape(&short_date(&row.created_at)),
            chip(&row.status),
            escape(&row.zone),
        );
    }
    let table = if table.is_empty() {
        "<p class=\"muted\">No changes yet. Pick one below.</p>".to_owned()
    } else {
        format!("<table>{table}</table>")
    };
    // No "all changes" footer: this is the list the footer would return to.
    shell(
        "Changes",
        &format!(
            "<h1>Changes</h1>\n<p>Every change here is a pull request in the infrastructure \
             repository. Nothing applies until its plan has been read and approved.</p>\n{table}\n\
             <section><h2>Make a change</h2><ul class=\"links\">{}</ul></section>",
            chooser_links(),
        ),
        false,
    )
}

// -- the forms ---------------------------------------------------------------

/// The chooser: what the "Make a change" list, and `/new` without a kind,
/// render.
pub(crate) fn chooser() -> String {
    page(
        "Make a change",
        &format!(
            "<section><h1>Make a change</h1><ul class=\"links\">{}</ul></section>",
            chooser_links()
        ),
    )
}

/// A submitted field, as typed (empty when absent).
fn val(params: &[(String, String)], name: &str) -> String {
    super::param(params, name).unwrap_or_default().to_owned()
}

/// One field, rendered: checkbox, textarea, dropdown or text input, with the
/// submitted value (or the field's default) carried back in.
fn render(field: &Field, params: &[(String, String)]) -> String {
    let mut value = val(params, field.name);
    if value.is_empty() && params.is_empty() {
        value = field.default.to_owned();
    }
    if field.flag {
        let on = matches!(value.as_str(), "on" | "true" | "1");
        format!(
            "<label class=\"check\"><input type=\"checkbox\" name=\"{}\"{}><span>{}</span></label>\n",
            field.name,
            if on { " checked" } else { "" },
            escape(field.label),
        )
    } else if field.area {
        format!(
            "<label for=\"{0}\">{1}</label>\n<textarea id=\"{0}\" name=\"{0}\" rows=\"12\">{2}</textarea>\n",
            field.name,
            escape(field.label),
            escape(&value),
        )
    } else if !field.options.is_empty() {
        let mut html = format!(
            "<label for=\"{0}\">{1}</label>\n<select id=\"{0}\" name=\"{0}\">\n",
            field.name,
            escape(field.label),
        );
        for option in field.options {
            let _ = writeln!(
                html,
                "<option value=\"{option}\"{}>{option}</option>",
                if *option == value { " selected" } else { "" },
            );
        }
        html + "</select>\n"
    } else {
        format!(
            "<label for=\"{0}\">{1}</label>\n<input id=\"{0}\" name=\"{0}\" value=\"{2}\" placeholder=\"{3}\">\n",
            field.name,
            escape(field.label),
            escape(&value),
            escape(field.ph),
        )
    }
}

/// The form for one kind, with its errors (if any) and the values typed so
/// far, so a refused submit never loses the visitor's work.
pub(crate) fn form(kind: &str, params: &[(String, String)], errors: &[String]) -> String {
    let Some(spec) = change::form(kind) else {
        return page(
            "Unknown change",
            "<section><h1>Unknown change</h1><p>Pick a change from the list.</p></section>",
        );
    };
    let mut fields = String::new();
    fields.push_str(&format!(
        "<input type=\"hidden\" name=\"kind\" value=\"{}\">\n",
        escape(spec.kind)
    ));
    for field in spec.fields {
        fields.push_str(&render(field, params));
    }
    let mut errors_html = String::new();
    if !errors.is_empty() {
        errors_html.push_str("<div class=\"errors\">");
        for error in errors {
            let _ = write!(errors_html, "<p>{}</p>", escape(error));
        }
        errors_html.push_str("</div>");
    }
    let note = if spec.note.is_empty() {
        String::new()
    } else {
        format!("<p class=\"muted\">{}</p>", escape(spec.note))
    };
    page(
        &format!("{} — make a change", spec.name),
        &format!(
            "{errors_html}<section><h1>{}</h1>\n<form method=\"post\" action=\"/v1/edits\">\n{fields}\n\
             <button>Open a pull request</button>\n</form>\n{note}\
             <p class=\"muted\">Submitting opens a pull request in the infrastructure repository. \
             Nothing is applied until its plan has been read and approved.</p></section>",
            escape(spec.name),
        ),
    )
}

/// Everything the detail page renders, gathered by the caller.
pub(crate) struct Detail {
    pub id: String,
    pub title: String,
    pub zone: String,
    pub status: String,
    pub summary_md: String,
    pub file_path: String,
    pub pr_number: Option<i64>,
    pub pr_url: Option<String>,
    pub plan: Option<change::PlanView>,
    /// The plan digest this page was rendered from: the approve form
    /// carries it back so a newer plan cannot be approved sight-unseen.
    pub plan_sha256: String,
    pub approver: Option<String>,
    pub approved_at: Option<String>,
    pub error: Option<String>,
}

/// The ask as a plain list: markdown bullets become list items and
/// backticks disappear (the pull request keeps its markdown).
fn plain_ask(markdown: &str) -> String {
    let mut items = String::new();
    for line in markdown.lines() {
        let line = line.trim().trim_start_matches("- ");
        if line.is_empty() {
            continue;
        }
        let _ = write!(items, "<li>{}</li>", escape(&line.replace('`', "")));
    }
    if items.is_empty() { String::new() } else { format!("<ul class=\"ask\">{items}</ul>") }
}

/// The detail page: the ask, the pull request, and the plan in words — with
/// the extra typed confirmation whenever the plan removes anything.
pub(crate) fn detail(d: &Detail) -> String {
    let risky = d.plan.as_ref().is_some_and(change::PlanView::risky);
    let chip = if d.status == "planned" && risky {
        "<span class=\"chip bad\">Removes things — check carefully</span>".to_owned()
    } else {
        chip(&d.status)
    };
    let mut html = format!(
        "<h1>{}</h1>\n<p>{chip}</p>\n<section><h2>What was asked</h2>\n{}\n\
         <p>Zone <code>{}</code></p>\n<p><small>File <code>{}</code></small></p>\n",
        escape(&d.title),
        plain_ask(&d.summary_md),
        escape(&d.zone),
        escape(&d.file_path),
    );
    if let (Some(number), Some(url)) = (d.pr_number, d.pr_url.as_deref()) {
        let _ =
            write!(html, "<p><a href=\"{}\">Pull request #{number} on GitHub</a></p>", escape(url));
    } else if d.status == "opening" {
        html.push_str("<p class=\"muted\">Opening the pull request…</p>");
    }
    html.push_str("</section>\n<section><h2>The plan</h2>\n");
    match d.plan.as_ref() {
        None => html.push_str(
            "<p class=\"muted\">Waiting for the plan… the repository's workflow posts it here \
             once the plan has finished.</p>",
        ),
        Some(view) => {
            let _ = write!(html, "<p><strong>{}</strong></p>\n<ul class=\"plan\">", view.counts());
            for (kind, text) in &view.rows {
                let class = match kind {
                    change::Row::Add => "add",
                    change::Row::Change => "chg",
                    change::Row::Remove | change::Row::Replace => "del",
                };
                let _ = write!(html, "<li class=\"{class}\">{}</li>", escape(text));
            }
            html.push_str("</ul>\n");
            if risky {
                html.push_str(
                    "<div class=\"risky\"><strong>This plan removes things.</strong> Approving \
                     applies the removals for real. To confirm, type the zone's name \
                     (<code>",
                );
                html.push_str(&escape(&d.zone));
                html.push_str("</code>) in the approval box below.</div>");
            }
        }
    }
    html.push_str("</section>\n");
    match d.status.as_str() {
        "planned" => {
            html.push_str("<section><h2>Approve</h2>\n<form method=\"post\" action=\"/v1/edits/");
            html.push_str(&escape(&d.id));
            html.push_str("/approve\">\n");
            let _ = writeln!(
                html,
                "<input type=\"hidden\" name=\"saw\" value=\"{}\">",
                escape(&d.plan_sha256)
            );
            if risky {
                html.push_str(
                    "<label for=\"confirm\">Type the zone name to confirm the removals</label>\n<input id=\"confirm\" name=\"confirm\" autocomplete=\"off\">",
                );
            }
            html.push_str(if risky {
                "<button class=\"danger\">Approve and apply</button>\n</form>\n<p class=\"muted\">Approving fires the repository's workflow, which applies the plan that was checked.</p></section>"
            } else {
                "<button>Approve and apply</button>\n</form>\n<p class=\"muted\">Approving fires the repository's workflow, which applies the plan that was checked.</p></section>"
            });
        }
        "approved" => {
            html.push_str("<section><h2>Approved</h2><p>Approved");
            if let Some(approver) = d.approver.as_deref() {
                let _ = write!(html, " by {}", escape(approver));
            }
            if let Some(at) = d.approved_at.as_deref() {
                let _ = write!(html, " at {}", escape(at));
            }
            html.push_str(". The repository's workflow applies the plan.</p></section>");
        }
        "failed" => {
            html.push_str("<section><h2>Failed</h2><p>");
            match d.error.as_deref() {
                Some(error) if !error.is_empty() => html.push_str(&escape(error)),
                _ => html.push_str("Something went wrong; the change can be tried again."),
            }
            html.push_str("</p></section>");
        }
        _ => {}
    }
    page(&d.title, &html)
}
