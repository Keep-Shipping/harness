//! Plain-terms plan rendering for reviewers
//! ([#68](https://github.com/Keep-Shipping/harness/issues/68)).
//!
//! Distils a plan into three counts plus the risky changes (destroys and
//! replacements) and the ordinary ones, rendered as plain chat text, a
//! colourised terminal report, a Markdown comment or the web review's HTML.
//! `ks-core` has no serde and never sees the terminal, so the adapter flattens
//! `tofu show -json` (`before`/`after`/`after_unknown`/`before_sensitive`/
//! `after_sensitive`/`replace_paths`/`action_reason`) into [`PlanChange`]s and
//! passes a [`Target`].
//!
//! # Secrets and control characters cannot leave
//!
//! Masking happens once, in [`summarize`]: an attribute is masked when the
//! tool marks it sensitive *or* its path matches [`SENSITIVE_PATH_MARKERS`],
//! and both halves then render as `(sensitive)` — the path and the
//! forces-replacement note stay. Every text that enters the summary (address,
//! path, value, reason) is also stripped of control characters, so a value
//! cannot forge a diff line or drive a terminal. The [`PlanSummary`] therefore
//! holds no secret and no live escape sequence, and no renderer can leak one.

use crate::ports::iac::{ChangeAction, ResourceChange};

/// Marker text both halves of a masked attribute render as.
const SENSITIVE: &str = "(sensitive)";

/// Path fragments that make an attribute sensitive even when the tool does
/// not say so. Matched case-insensitively as substrings, so `db_password`,
/// `master_user_secret.0.token` and `aws_access_key_id` all match.
/// Over-masking is intended: a missed secret is far worse than a hidden
/// public value.
pub const SENSITIVE_PATH_MARKERS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "private_key",
    "api_key",
    "apikey",
    "access_key",
    "credential",
    "connection_string",
];

/// Hosted bodies are capped at 64 KiB
/// ([#147](https://github.com/Keep-Shipping/harness/issues/147)); pass this
/// as [`Limits::max_bytes`] for a hosted body.
pub const HOSTED_BODY_LIMIT: usize = 64 * 1024;

/// One resource's planned change, flattened from `tofu show -json` by the
/// adapter. Not `Debug`: `attributes` are unmasked, so only the summary is
/// safe to print.
#[derive(Clone, PartialEq, Eq)]
pub struct PlanChange {
    /// The resource address, e.g. `aws_ecs_service.api`.
    pub address: String,
    /// The planned actions, in the tool's order (a replace is two).
    pub actions: Vec<ChangeAction>,
    /// The attribute-level diff the adapter flattened.
    pub attributes: Vec<AttributeChange>,
    /// The plan's `action_reason` code (e.g. `replace_because_tainted`), not
    /// free text; sanitized like every other text, never masked.
    pub reason: Option<String>,
}

/// One attribute's before/after in a [`PlanChange`]. Not `Debug`: unmasked.
#[derive(Clone, PartialEq, Eq)]
pub struct AttributeChange {
    /// The attribute path, e.g. `master_user_secret.0.token`.
    pub path: String,
    /// The value before the change.
    pub before: AttrValue,
    /// The value after the change.
    pub after: AttrValue,
    /// Whether the tool marks the attribute sensitive.
    pub sensitive: bool,
    /// Whether changing the attribute forces a replacement.
    pub forces_replacement: bool,
}

/// A single attribute value. Not `Debug`: [`AttrValue::Known`] is unmasked.
#[derive(Clone, PartialEq, Eq)]
pub enum AttrValue {
    /// Not set: renders `(none)`.
    Absent,
    /// A known value: renders as given.
    Known(String),
    /// Not known until apply: renders `(known after apply)`.
    Unknown,
}

impl From<&ResourceChange> for PlanChange {
    /// A change with no attribute detail and no reason, for callers that only
    /// have the [`ResourceChange`] the port carries.
    fn from(change: &ResourceChange) -> PlanChange {
        PlanChange {
            address: change.address.clone(),
            actions: change.actions.clone(),
            attributes: Vec::new(),
            reason: None,
        }
    }
}

/// What a change does, once classified. [`Kind::Replace`] counts as one add
/// *and* one destroy, the way `tofu` counts a replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A resource is created.
    Add,
    /// A resource is updated in place.
    Change,
    /// A resource is destroyed.
    Destroy,
    /// A resource is destroyed and recreated.
    Replace,
}

impl Kind {
    /// The one- or two-character symbol, as in `tofu plan`.
    pub fn symbol(&self) -> &'static str {
        match self {
            Kind::Add => "+",
            Kind::Change => "~",
            Kind::Destroy => "-",
            Kind::Replace => "-/+",
        }
    }

    /// The stable slug used for HTML classes.
    fn slug(&self) -> &'static str {
        match self {
            Kind::Add => "add",
            Kind::Change => "change",
            Kind::Destroy => "destroy",
            Kind::Replace => "replace",
        }
    }
}

/// One already-masked, already-sanitized attribute line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryAttribute {
    /// The attribute path (never masked).
    pub path: String,
    /// The before text: the value, or `(sensitive)`, `(none)`,
    /// `(known after apply)`.
    pub before: String,
    /// The after text, masked the same way as [`before`](Self::before).
    pub after: String,
    /// Whether this attribute forces a replacement.
    pub forces_replacement: bool,
}

/// One line of the summary: an already-classified, masked, sanitized change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryEntry {
    /// What the change does.
    pub kind: Kind,
    /// The resource address.
    pub address: String,
    /// The masked attribute diff.
    pub attributes: Vec<SummaryAttribute>,
    /// The action reason, shown only for a [`Kind::Replace`].
    pub reason: Option<String>,
}

/// The safe, structured result of [`summarize`]: risky changes, ordinary
/// changes and the whole-plan counts. Holds no secret or escape sequence.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlanSummary {
    /// Destroys and replacements, in plan order.
    pub risky: Vec<SummaryEntry>,
    /// Creates and updates, in plan order.
    pub others: Vec<SummaryEntry>,
    /// How many the plan adds (replacements count here too).
    pub add: usize,
    /// How many the plan updates in place.
    pub change: usize,
    /// How many the plan destroys (replacements count here too).
    pub destroy: usize,
}

/// Classify a change's actions, or `None` for a no-op or pure read.
fn classify(actions: &[ChangeAction]) -> Option<Kind> {
    let has = |action| actions.contains(&action);
    match (has(ChangeAction::Delete), has(ChangeAction::Create)) {
        (true, true) => Some(Kind::Replace),
        (_, true) => Some(Kind::Add),
        _ if has(ChangeAction::Update) => Some(Kind::Change),
        (true, false) => Some(Kind::Destroy),
        _ => None,
    }
}

/// Whether a path is sensitive by name, per [`SENSITIVE_PATH_MARKERS`].
fn path_is_sensitive(path: &str) -> bool {
    let lower = path.to_lowercase();
    SENSITIVE_PATH_MARKERS.iter().any(|marker| lower.contains(marker))
}

/// Escape control characters so a value cannot forge a line or drive a
/// terminal; visible text (`→`, non-ASCII) is untouched.
fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            out.extend(character.escape_debug());
        } else {
            out.push(character);
        }
    }
    out
}

/// The masked, sanitized text of one attribute value.
fn value_text(value: &AttrValue) -> String {
    match value {
        AttrValue::Absent => "(none)".to_string(),
        AttrValue::Known(text) => sanitize(text),
        AttrValue::Unknown => "(known after apply)".to_string(),
    }
}

/// Mask one attribute: sensitive or denylisted paths render `(sensitive)` for
/// both halves, everything else renders its sanitized value.
fn mask(attribute: &AttributeChange) -> SummaryAttribute {
    let masked = attribute.sensitive || path_is_sensitive(&attribute.path);
    let (before, after) = if masked {
        (SENSITIVE.to_string(), SENSITIVE.to_string())
    } else {
        (value_text(&attribute.before), value_text(&attribute.after))
    };
    SummaryAttribute {
        path: sanitize(&attribute.path),
        before,
        after,
        forces_replacement: attribute.forces_replacement,
    }
}

/// Build the safe summary: classify every change, mask and sanitize every
/// attribute, and bucket destroys/replacements apart from the rest. This is
/// the only place values are read, so nothing sensitive or control-bearing
/// can reach a renderer.
#[must_use]
pub fn summarize(changes: &[PlanChange]) -> PlanSummary {
    let mut summary = PlanSummary::default();
    for change in changes {
        let Some(kind) = classify(&change.actions) else {
            continue;
        };
        match kind {
            Kind::Add => summary.add += 1,
            Kind::Change => summary.change += 1,
            Kind::Destroy => summary.destroy += 1,
            // A replace is a destroy and a create of one resource.
            Kind::Replace => {
                summary.add += 1;
                summary.destroy += 1;
            }
        }
        let entry = SummaryEntry {
            kind,
            address: sanitize(&change.address),
            attributes: change.attributes.iter().map(mask).collect(),
            reason: change.reason.as_deref().map(sanitize),
        };
        if matches!(kind, Kind::Destroy | Kind::Replace) {
            summary.risky.push(entry);
        } else {
            summary.others.push(entry);
        }
    }
    summary
}

/// Where a rendering is headed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Plain chat text: no colour, no markup.
    Plain,
    /// A terminal report: the plain text, colourised when `color` is set
    /// (`Terminal { color: false }` equals [`Target::Plain`]).
    Terminal {
        /// Whether to emit ANSI colours.
        color: bool,
    },
    /// A GitHub-flavoured Markdown comment.
    Markdown,
    /// The HTML of the web review.
    Html,
}

/// How much of the plan a rendering may show.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Limits {
    /// Cap on the entries shown; risky entries lead, so ordinary changes are
    /// dropped first.
    pub max_resources: Option<usize>,
    /// Cap on the rendering's length in bytes. The shown count is reduced
    /// until it fits, keeping the summary and the `and N more` note; only if
    /// no form fits is a longer result returned. Use [`HOSTED_BODY_LIMIT`].
    pub max_bytes: Option<usize>,
    /// A link to the full plan, shown beside the truncation note. Ignored
    /// unless it is a plain http(s) URL: any other scheme, whitespace, a
    /// control character or one of ``<>"'` `` drops the link.
    pub full_plan_url: Option<String>,
}

/// The URL to link to, or `None` when it is not a plain http(s) URL. A
/// `javascript:` scheme, whitespace, a control character or any of ``<>"'` ``
/// could break out of a Markdown link or an HTML attribute, so such a URL is
/// dropped and the `and N more` note stands alone.
fn safe_url(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let unsafe_char =
        |c: char| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | '"' | '\'' | '`');
    (!rest.is_empty() && !url.chars().any(unsafe_char)).then_some(url)
}

const RESET: &str = "\x1b[0m";
const RED_BOLD: &str = "\x1b[1;31m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";

/// Append `line` plus a newline; writing to a `String` cannot fail.
fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

/// How a truncation note's link is spelled.
#[derive(Clone, Copy)]
enum LinkStyle {
    Plain,
    Markdown,
    Html,
}

/// The truncation note, `… and N more`, with the full-plan link when the URL
/// is safe. One helper so the three text targets agree.
fn more_text(hidden: usize, limits: &Limits, style: LinkStyle) -> String {
    let mut text = format!("… and {hidden} more");
    if let Some(url) = limits.full_plan_url.as_deref().and_then(safe_url) {
        text.push_str(&match style {
            LinkStyle::Plain => format!(" — full plan: {url}"),
            LinkStyle::Markdown => format!(" — [full plan](<{url}>)"),
            LinkStyle::Html => format!(" — <a href=\"{}\">full plan</a>", html_escape(url)),
        });
    }
    text
}

impl PlanSummary {
    /// An entry's line: symbol, space, address, then the attribute diff and
    /// any reason. The symbol is colourised when `color` is set.
    fn entry_line(entry: &SummaryEntry, color: bool) -> String {
        let code = match entry.kind {
            Kind::Add => GREEN,
            Kind::Change => YELLOW,
            Kind::Destroy | Kind::Replace => RED_BOLD,
        };
        let symbol = if color {
            format!("{code}{}{RESET}", entry.kind.symbol())
        } else {
            entry.kind.symbol().to_string()
        };
        let mut line = format!("{symbol} {}", entry.address);
        if !entry.attributes.is_empty() {
            let attributes = entry
                .attributes
                .iter()
                .map(|attribute| {
                    let forces =
                        if attribute.forces_replacement { " (forces replacement)" } else { "" };
                    format!("{} {} → {}{forces}", attribute.path, attribute.before, attribute.after)
                })
                .collect::<Vec<_>>()
                .join(", ");
            line.push_str("   ");
            line.push_str(&attributes);
        }
        // A reason is only meaningful on a replacement.
        if entry.kind == Kind::Replace
            && let Some(reason) = &entry.reason
        {
            line.push_str(&format!(" ({reason})"));
        }
        line
    }

    /// The summary line, or `No changes.` when the plan is empty.
    fn summary_text(&self) -> String {
        if self.add == 0 && self.change == 0 && self.destroy == 0 {
            "No changes.".to_string()
        } else {
            self.counts()
        }
    }

    /// The whole plan's three counts, as `tofu` prints them, whatever is
    /// shown: `2 to add · 1 to change · 0 to destroy`. Shared with callers
    /// outside this module so one wording says it everywhere.
    #[must_use]
    pub fn counts(&self) -> String {
        format!("{} to add · {} to change · {} to destroy", self.add, self.change, self.destroy)
    }

    /// How `shown` entries split over the buckets (risky, ordinary, hidden);
    /// risky lead, so ordinary changes are dropped first.
    fn shown(&self, shown: usize) -> (usize, usize, usize) {
        let risky = self.risky.len().min(shown);
        (risky, shown - risky, (self.risky.len() + self.others.len()) - shown)
    }

    /// A ```diff block of entry lines, fenced longer than any backtick run in
    /// the body so a value can never break out.
    fn diff_block(entries: &[SummaryEntry]) -> String {
        let mut body = String::new();
        for entry in entries {
            push_line(&mut body, &Self::entry_line(entry, false));
        }
        let fence = "`".repeat(fence_len(&body));
        format!("{fence}diff\n{body}{fence}\n\n")
    }

    /// The plain/terminal rendering at `shown` entries.
    fn text(&self, shown: usize, limits: &Limits, color: bool) -> String {
        let (risky, others, hidden) = self.shown(shown);
        let mut out = String::new();
        if risky > 0 {
            push_line(&mut out, "Destroys and replacements:");
            for entry in &self.risky[..risky] {
                push_line(&mut out, &Self::entry_line(entry, color));
            }
            out.push('\n');
        }
        for entry in &self.others[..others] {
            push_line(&mut out, &Self::entry_line(entry, color));
        }
        if hidden > 0 {
            push_line(&mut out, &more_text(hidden, limits, LinkStyle::Plain));
        }
        push_line(&mut out, &self.summary_text());
        out
    }

    /// The Markdown rendering at `shown` entries.
    fn markdown(&self, shown: usize, limits: &Limits) -> String {
        let (risky, others, hidden) = self.shown(shown);
        let mut out = format!("**{}**\n\n", self.summary_text());
        if risky > 0 {
            push_line(&mut out, "#### ⚠️ Destroys and replacements");
            out.push('\n');
            out.push_str(&Self::diff_block(&self.risky[..risky]));
        }
        if others > 0 {
            out.push_str(&Self::diff_block(&self.others[..others]));
        }
        if hidden > 0 {
            push_line(&mut out, &more_text(hidden, limits, LinkStyle::Markdown));
        }
        out
    }

    /// One `<ul>` of entries, each with a per-kind class.
    fn html_list(entries: &[SummaryEntry]) -> String {
        let mut out = String::from("<ul class=\"ks-plan-list\">\n");
        for entry in entries {
            push_line(
                &mut out,
                &format!(
                    "<li class=\"ks-plan-item ks-plan-{}\"><code>{}</code></li>",
                    entry.kind.slug(),
                    html_escape(&Self::entry_line(entry, false)),
                ),
            );
        }
        out.push_str("</ul>\n");
        out
    }

    /// The HTML rendering at `shown` entries.
    fn html(&self, shown: usize, limits: &Limits) -> String {
        let (risky, others, hidden) = self.shown(shown);
        let mut out = String::from("<section class=\"ks-plan\">\n");
        push_line(
            &mut out,
            &format!("<p class=\"ks-plan-summary\">{}</p>", html_escape(&self.summary_text())),
        );
        if risky > 0 {
            push_line(&mut out, "<h4 class=\"ks-plan-risky\">⚠️ Destroys and replacements</h4>");
            out.push_str(&Self::html_list(&self.risky[..risky]));
        }
        if others > 0 {
            out.push_str(&Self::html_list(&self.others[..others]));
        }
        if hidden > 0 {
            let note = more_text(hidden, limits, LinkStyle::Html);
            push_line(&mut out, &format!("<p class=\"ks-plan-more\">{note}</p>"));
        }
        out.push_str("</section>\n");
        out
    }

    /// The rendering at exactly `shown` entries, for `target`.
    fn render_at(&self, target: Target, shown: usize, limits: &Limits) -> String {
        match target {
            Target::Plain => self.text(shown, limits, false),
            Target::Terminal { color } => self.text(shown, limits, color),
            Target::Markdown => self.markdown(shown, limits),
            Target::Html => self.html(shown, limits),
        }
    }

    /// The largest entry count, at most `max_shown`, whose rendering fits
    /// `max_bytes`. The caller has checked the minimal form fits, and the
    /// rendering grows with the shown count (the full render is checked
    /// first), so "fits" is a prefix and a binary search is exact.
    fn largest_fitting(
        &self,
        target: Target,
        max_shown: usize,
        limits: &Limits,
        max_bytes: usize,
    ) -> usize {
        let fits = |count| self.render_at(target, count, limits).len() <= max_bytes;
        let (mut low, mut high) = (0, max_shown + 1);
        while low < high {
            let mid = low + (high - low) / 2;
            if fits(mid) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low.saturating_sub(1)
    }

    /// Render for `target`, honouring `limits`: cap the entries, then shrink
    /// the shown count until the result fits `max_bytes`, keeping the summary
    /// and the `and N more` note; the link is dropped before a longer minimal
    /// form is returned. The counts always describe the whole plan.
    #[must_use]
    pub fn render(&self, target: Target, limits: &Limits) -> String {
        let total = self.risky.len() + self.others.len();
        let max_shown = limits.max_resources.unwrap_or(total).min(total);
        let full = self.render_at(target, max_shown, limits);
        let Some(max_bytes) = limits.max_bytes else {
            return full;
        };
        if full.len() <= max_bytes {
            return full;
        }
        // Prefer keeping the link; drop it only if even the minimal form is
        // too large.
        let no_url = Limits { full_plan_url: None, ..limits.clone() };
        for candidate in [limits, &no_url] {
            if self.render_at(target, 0, candidate).len() <= max_bytes {
                let shown = self.largest_fitting(target, max_shown, candidate, max_bytes);
                return self.render_at(target, shown, candidate);
            }
        }
        self.render_at(target, 0, &no_url)
    }
}

/// The fence length for `body`: one longer than its longest backtick run, and
/// never shorter than three.
fn fence_len(body: &str) -> usize {
    body.split(|character| character != '`').map(str::len).max().unwrap_or(0).max(2) + 1
}

/// Escape text for HTML: the five characters that end an attribute or open a
/// tag. Applied to hrefs too, so a value cannot break out of an attribute.
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
