//! The views: a repo's runs, one run's story, and the badge that says whether the
//! seal verified — the three things a hosted reader comes for.
//!
//! Every name in a story comes off [`Entry::line`], the line as it was uploaded
//! rather than a re-serialization of it, so what a reader is shown is what the
//! runner wrote. Nothing is invented to fill a gap: a run that does not say who
//! proposed it has no proposed-by, and the page shows nothing where a name would
//! be.
//!
//! Everything interpolated into a page goes through [`escape`]. A step name is
//! whatever a `ship.ks` file said, and a `ship.ks` file is not trusted input.

use crate::chain::{ChainBreak, Entry};
use crate::store::RunIndex;

/// How far a run got, and how much can be said about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The log has entries but the run has not said it finished.
    Unfinished,
    /// A seal over the tip verified under a trusted key.
    Verified,
    /// The run finished but no seal covers it, so truncation and rewrite cannot be
    /// ruled out — the same refusal `crates/cli`'s seal check makes.
    Unsealed,
    /// A seal is recorded over the run but did not verify. Nothing about the log
    /// itself is claimed here — that is [`story`]'s job.
    Broken,
}

impl Status {
    /// The status's one word.
    pub fn label(self) -> &'static str {
        match self {
            Status::Unfinished => "unfinished",
            Status::Verified => "verified",
            Status::Unsealed => "unsealed",
            Status::Broken => "broken",
        }
    }
}

/// One row of the runs-per-repo table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {
    /// The run's id.
    pub run: String,
    /// The repository it happened in.
    pub repo: String,
    /// How many entries the log holds.
    pub entries: usize,
    /// The tip's `hash`.
    pub head: String,
    /// A seal has been accepted.
    pub sealed: bool,
    /// That seal verified.
    pub verified: bool,
    /// The first entry's `at`, in unix millis.
    pub started_at: u64,
    /// The last entry's `at`, when the run finished.
    pub finished_at: Option<u64>,
    /// What can be said about the run.
    pub status: Status,
}

/// What the index alone says about a run — no log, no keys, no store.
pub fn summarize(index: &RunIndex) -> RunSummary {
    let status = match (index.sealed, index.verified, index.finished_at) {
        (true, true, Some(_)) => Status::Verified,
        (true, false, _) => Status::Broken,
        (true, true, None) => Status::Unfinished,
        (false, _, None) => Status::Unfinished,
        (false, _, Some(_)) => Status::Unsealed,
    };
    RunSummary {
        run: index.run.clone(),
        repo: index.repo.clone(),
        entries: index.entries,
        head: index.head.clone(),
        sealed: index.sealed,
        verified: index.verified,
        started_at: index.started_at,
        finished_at: index.finished_at,
        status,
    }
}

/// One answer a run recorded: a decision model, or a human overruling one.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    /// The step the decision was about.
    pub step: String,
    /// The entry's `at`, in unix millis.
    pub at: u64,
    /// What was decided: a `decide.answered` entry's `outcome`, or `overridden`.
    pub verdict: String,
    /// Who decided: the `decide.answered` entry's `model`, or the overruling
    /// entry's `by`. A decision model's own name, not a person — the log does not
    /// say a person agreed with it.
    pub by: String,
    /// The model's `confidence`, when the entry carries one. An override has no
    /// score, so it has none here either.
    pub score: Option<f64>,
}

/// What one run says, in the order a reader asks: who proposed it, who approved
/// each step, what it shipped, and what it decided.
#[derive(Debug, Clone, PartialEq)]
pub struct Story {
    /// The run's id.
    pub run: String,
    /// The repository it happened in.
    pub repo: String,
    /// `run.started`'s `actor`, when the log names one.
    pub proposed_by: Option<String>,
    /// Every `approval.granted`'s `approver`, in log order. An approval that was
    /// denied or expired is not here — the log records those separately and this
    /// does not fold them in.
    pub approved_by: Vec<String>,
    /// `run.finished`'s `shipped`, as digests.
    pub shipped: Vec<String>,
    /// Every decision, in log order.
    pub decisions: Vec<Decision>,
    /// What can be said about the run.
    pub status: Status,
    /// The tip's `hash`.
    pub head: String,
    /// How many entries the log holds.
    pub entries: usize,
}

/// Replays a run's log and derives its story. The field names are the ones
/// `crates/cli`'s run log writes (`crates/cli/src/run_log.rs`'s `event_fields`),
/// so a name here is a name there:
///
/// * `run.started` — `actor` is who proposed the run;
/// * `approval.granted` — `approver` is who approved a step;
/// * `run.finished` — `shipped` is the digests, `status` is how it ended;
/// * `decide.answered` — `outcome` is the verdict, `model` who decided, and
///   `confidence` is the score;
/// * `decision.overridden` — `by` is who overruled, and it carries no score.
///
/// The chain is re-walked as it is read, so a log whose lines do not chain is an
/// error rather than a story assembled from pieces of one, and the walk must
/// land where the index says it lands: every prefix of a good chain is a good
/// chain, so a log spliced or cut short would otherwise render with a "verified"
/// badge off an index describing a different log. This is the check behind the
/// upload checks rather than in front of them — by the time a story is read, the
/// damage it catches has already happened.
pub fn story(text: &str, index: &RunIndex) -> Result<Story, ChainBreak> {
    let mut story = Story {
        run: index.run.clone(),
        repo: index.repo.clone(),
        proposed_by: None,
        approved_by: Vec::new(),
        shipped: Vec::new(),
        decisions: Vec::new(),
        status: summarize(index).status,
        head: index.head.clone(),
        entries: 0,
    };
    let mut prev = crate::chain::GENESIS.to_string();
    for line in text.lines() {
        let entry = Entry::parse(line)?;
        if !entry.continues_from(&prev) {
            return Err(ChainBreak::Broken { found: entry.prev.clone(), expected: prev });
        }
        prev = entry.hash.clone();
        story.entries += 1;
        let text_of = |key: &str| {
            entry
                .value()
                .get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        match entry.kind.as_str() {
            "run.started" => {
                let actor = text_of("actor");
                story.proposed_by = (!actor.is_empty()).then_some(actor);
            }
            "approval.granted" => story.approved_by.push(text_of("approver")),
            "run.finished" => {
                story.shipped = entry
                    .value()
                    .get("shipped")
                    .and_then(serde_json::Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(String::from)
                            .collect()
                    })
                    .unwrap_or_default();
            }
            "decide.answered" => story.decisions.push(Decision {
                step: text_of("step"),
                at: entry.at,
                verdict: text_of("outcome"),
                by: text_of("model"),
                score: entry.value().get("confidence").and_then(serde_json::Value::as_f64),
            }),
            "decision.overridden" => story.decisions.push(Decision {
                step: text_of("step"),
                at: entry.at,
                verdict: "overridden".to_string(),
                by: text_of("by"),
                score: None,
            }),
            _ => {}
        }
    }
    // The walk has to land where the index says it lands; see [`story`].
    if story.entries != index.entries {
        return Err(ChainBreak::Count { found: story.entries, expected: index.entries });
    }
    if prev != index.head {
        return Err(ChainBreak::Head { found: prev, expected: index.head.clone() });
    }
    Ok(story)
}

/// The badge a hosted page shows beside a run. A badge is a claim, so it never
/// has an `Unfinished` shape: a run still going says nothing at all rather than
/// reading as a weaker kind of verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Badge {
    /// A seal over the tip verified under a trusted key.
    Verified,
    /// The run finished with no seal, or is still going.
    Unsealed,
    /// The stored log does not hold.
    Broken,
}

impl Badge {
    /// The badge's one word, as it appears on the page.
    pub fn label(self) -> &'static str {
        match self {
            Badge::Verified => "verified",
            Badge::Unsealed => "unsealed",
            Badge::Broken => "broken",
        }
    }
}

/// The badge for a status: everything that is not verified and not broken reads
/// as unsealed, because an unfinished run and an unasserted one make the same
/// claim — nothing has been vouched for.
pub fn badge(status: Status) -> Badge {
    match status {
        Status::Verified => Badge::Verified,
        Status::Broken => Badge::Broken,
        Status::Unfinished | Status::Unsealed => Badge::Unsealed,
    }
}

/// The runs-per-repo page: a table, one row per run, newest last.
pub fn index_page(repo: &str, runs: &[RunSummary]) -> String {
    let mut page = head(&format!("runs in {}", escape(repo)));
    page.push_str("<table><thead><tr><th>run</th><th>status</th><th>entries</th><th>head</th></tr></thead><tbody>");
    for run in runs {
        page.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            escape(&run.run),
            escape(badge(run.status).label()),
            run.entries,
            escape(&run.head)
        ));
    }
    page.push_str("</tbody></table>");
    page.push_str("</body></html>");
    page
}

/// One run's story, with its badge.
pub fn run_page(story: &Story) -> String {
    let mut page = head(&format!("run {}", escape(&story.run)));
    page.push_str(&format!(
        "<p class=\"badge {}\">{}</p>",
        escape(badge(story.status).label()),
        escape(badge(story.status).label())
    ));
    page.push_str(&format!(
        "<dl><dt>repository</dt><dd>{}</dd><dt>entries</dt><dd>{}</dd><dt>head</dt><dd><code>{}</code></dd>",
        escape(&story.repo),
        story.entries,
        escape(&story.head)
    ));
    if let Some(actor) = &story.proposed_by {
        page.push_str(&format!("<dt>proposed by</dt><dd>{}</dd>", escape(actor)));
    }
    for approver in &story.approved_by {
        page.push_str(&format!("<dt>approved by</dt><dd>{}</dd>", escape(approver)));
    }
    for digest in &story.shipped {
        page.push_str(&format!("<dt>shipped</dt><dd><code>{}</code></dd>", escape(digest)));
    }
    for decision in &story.decisions {
        let score = decision.score.map(|score| format!(" ({score})")).unwrap_or_default();
        page.push_str(&format!(
            "<dt>decided</dt><dd>{} — {} by {}{score}</dd>",
            escape(&decision.step),
            escape(&decision.verdict),
            escape(&decision.by)
        ));
    }
    page.push_str("</dl></body></html>");
    page
}

fn head(title: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title}</title></head><body><h1>{title}</h1>"
    )
}

/// HTML-escapes the five characters that can leave text context. `&` goes first,
/// so the ampersands this introduces are not escaped again.
pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
