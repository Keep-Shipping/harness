//! The Checks API: a check run on a commit, carrying the findings as
//! annotations on the diff ([#129](https://github.com/Keep-Shipping/harness/issues/129)).
//!
//! A PR comment is a wall of prose somebody has to read to find one line that
//! is wrong. A check run is not: each annotation carries a file and a line, so
//! a mistake in a `ship.ks` names the line it is on rather than asking to be
//! hunted for. The trade is that the Checks API documents a narrow shape: it
//! supports `start_column` and `end_column` only when `start_line` and
//! `end_line` are the same line — a multi-line span with columns on it is
//! outside what the API describes — so the conversions here are careful about
//! which fields they send.
//!
//! This is not a port: nothing in the engine talks to GitHub for findings yet,
//! and giving this type a home in `ks-core` would put a GitHub-shaped type in
//! a crate that has deliberately never mentioned GitHub. It speaks the same
//! [`HttpClient`] port as the rest of the crate, so a caller that wants the
//! annotations on a real PR wires it exactly as it wires the approvals channel.

use std::fmt;
use std::sync::Arc;

use ks_core::ports::http::{HttpClient, HttpMethod, HttpRequest, HttpResponse};
use ks_lang::{Diagnostic, Severity};

use crate::{DEFAULT_API_BASE, DEFAULT_USER_AGENT, Token, api_base, authed};

/// The line starts of `src`, so a span's two byte offsets cost a binary search
/// rather than a rescan of the file per diagnostic.
///
/// This mirrors `render::Lines` in the CLI on purpose: the same finding must
/// land on the same line and column whether it was printed, posted as a
/// workflow command, or attached to a PR, and an annotation that disagrees
/// with the console report by a line sends the reader to the wrong place.
struct Lines {
    starts: Vec<u32>,
}

impl Lines {
    fn new(src: &str) -> Lines {
        let mut starts: Vec<u32> = src
            .bytes()
            .enumerate()
            .filter(|&(_, b)| b == b'\n')
            .map(|(i, _)| i as u32 + 1)
            .collect();
        starts.insert(0, 0);
        Lines { starts }
    }

    /// The 1-based line and column of a byte offset. Columns count
    /// characters, not bytes, so a multi-byte character is one column.
    ///
    /// The offsets come from a `Diagnostic`, which is not tied to `src` by
    /// anything the type system can see, so an offset can land inside a
    /// multi-byte character where the string cannot be sliced. The clamp handles
    /// an offset past the end; this handles one in the middle, pulled back to
    /// the start of the character containing it — which is the place the reader
    /// would have looked at anyway.
    fn line_col(&self, src: &str, offset: u32) -> (usize, usize) {
        let offset = (offset as usize).min(src.len());
        let offset = src.floor_char_boundary(offset);
        let line = self.starts.partition_point(|&s| s <= offset as u32) - 1;
        let col = src[self.starts[line] as usize..offset].chars().count() + 1;
        (line + 1, col)
    }
}

/// One finding, pinned to a place in a file.
///
/// Columns are optional because the API supports them only on a span that
/// starts and ends on the same line; see [`Annotation::from_diagnostic`].
///
/// GitHub takes at most 50 annotations per request, and an annotation's
/// `message` is capped at 64 KB. Nothing here enforces either: this type is one
/// finding at a time, and the count belongs to whoever batches them into a
/// [`CheckOutput`], which is expected to hold 50 or fewer and to carry the rest
/// across successive update requests rather than one oversized body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    /// The file the finding is in, as a path from the repository root.
    pub path: String,
    /// The 1-based line the span starts on.
    pub start_line: usize,
    /// The 1-based column the span starts at, when the span is one line long —
    /// the only shape the API gives columns a meaning for.
    pub start_column: Option<usize>,
    /// The 1-based line the span ends on.
    pub end_line: usize,
    /// The 1-based column the span ends at, when the span is one line long.
    pub end_column: Option<usize>,
    /// How loudly GitHub shows it.
    pub level: AnnotationLevel,
    /// A short title for the annotation.
    pub title: Option<String>,
    /// The finding itself, plus any hints that go with it.
    pub message: String,
}

impl Annotation {
    /// `d` as an annotation against `src`, named `path` in the repository.
    ///
    /// The columns are computed but only kept when the span is on one line:
    /// the API supports `start_column` and `end_column` on a single-line span
    /// and tells callers to omit them when `start_line` and `end_line` differ,
    /// so a multi-line finding is reported by its line range alone. The
    /// omission is enforced again on the way out in
    /// [`CheckRuns::create`] rather than trusted to this constructor.
    ///
    /// The title and the message are the same strings the CLI's
    /// `render::github` writes, so a finding reads identically whichever
    /// surface it arrives on. `render::github` spells a hint as `%0Ahint: `
    /// because a workflow command is one line that cannot hold a real one; the
    /// Checks API is JSON, so the newline is a real `\n` here and GitHub
    /// renders it as a second paragraph. Same content, no percent-encoding.
    pub fn from_diagnostic(path: &str, src: &str, d: &Diagnostic) -> Annotation {
        let lines = Lines::new(src);
        let (start_line, start_column) = lines.line_col(src, d.span.start);
        let (end_line, end_column) = lines.line_col(src, d.span.end);
        let single_line = start_line == end_line;
        let message = d.hints.iter().fold(d.message.clone(), |mut message, hint| {
            message.push_str(&format!("\n\nhint: {hint}"));
            message
        });
        Annotation {
            path: path.to_string(),
            start_line,
            start_column: single_line.then_some(start_column),
            end_line,
            end_column: single_line.then_some(end_column),
            // The Checks API has no "error" level: `failure` is the one it
            // renders as a failing annotation, so a checker error becomes a
            // failure and a warning stays a warning.
            level: match d.severity {
                Severity::Error => AnnotationLevel::Failure,
                Severity::Warning => AnnotationLevel::Warning,
            },
            title: Some(match &d.subject {
                Some(subject) => format!("{} {subject}", d.code.as_str()),
                None => d.code.as_str().to_string(),
            }),
            message,
        }
    }
}

/// How loudly GitHub shows an annotation.
///
/// The Checks API has three levels and no `error`: its failure level is the
/// one that reads as a broken build, which is what a checker error is, so
/// [`Severity::Error`] is reported as [`AnnotationLevel::Failure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationLevel {
    /// Something worth reading, not worth failing over.
    Notice,
    /// A warning.
    Warning,
    /// A failure: the thing the check found.
    Failure,
}

impl AnnotationLevel {
    /// The level as the API spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            AnnotationLevel::Notice => "notice",
            AnnotationLevel::Warning => "warning",
            AnnotationLevel::Failure => "failure",
        }
    }
}

/// How a check run ended. Only the two verdicts this crate has something to
/// say about are here: a run that found nothing wrong, and one that did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conclusion {
    /// Nothing the check objects to.
    Success,
    /// At least one failure.
    Failure,
}

impl Conclusion {
    /// The conclusion as the API spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Conclusion::Success => "success",
            Conclusion::Failure => "failure",
        }
    }
}

/// The check run to create: a name, somewhere to read more, and — the point
/// of the exercise — the output to attach.
#[derive(Debug)]
pub struct CheckRun<'a> {
    /// The name shown on the commit and in the checks list.
    pub name: &'a str,
    /// A URL with more detail about the run, for a reader who wants to follow it.
    pub details_url: Option<&'a str>,
    /// The findings, if there are any to report yet.
    pub output: Option<CheckOutput<'a>>,
}

/// The body of a check run: a summary for the checks list and one annotation
/// per finding.
#[derive(Debug)]
pub struct CheckOutput<'a> {
    /// A short title for the check run.
    pub title: &'a str,
    /// A short summary of the check run.
    pub summary: &'a str,
    /// The findings, each pinned to its own place in the source.
    pub annotations: &'a [Annotation],
}

/// Why a check run was not created, or not completed.
///
/// The Checks API is not a port and has no agreed failure vocabulary, so this
/// is the adapter's own: whatever GitHub, or the transport underneath it,
/// would not let us through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckError {
    /// The check run could not be created or completed. The message says what
    /// GitHub answered, or what the transport reported.
    Unavailable {
        /// What went wrong, in prose.
        message: String,
    },
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckError::Unavailable { message } => {
                write!(f, "github check run unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for CheckError {}

/// Check runs over one repository, authenticated with one token.
///
/// The token is held only to set the `Authorization` header, and the client
/// only ever talks to the API base it was configured with, so a run cannot be
/// pointed at a host the caller's [`HttpClient`] policy does not already name.
pub struct CheckRuns {
    http: Arc<dyn HttpClient>,
    token: Token,
    api_base: String,
    owner: String,
    repo: String,
    user_agent: String,
}

impl CheckRuns {
    /// Check runs over `owner`/`repo`, authenticated with `token`.
    pub fn new(
        http: Arc<dyn HttpClient>,
        token: Token,
        owner: impl Into<String>,
        repo: impl Into<String>,
    ) -> CheckRuns {
        CheckRuns {
            http,
            token,
            api_base: DEFAULT_API_BASE.to_string(),
            owner: owner.into(),
            repo: repo.into(),
            user_agent: DEFAULT_USER_AGENT.to_string(),
        }
    }

    /// Overrides the API base (for GHES).
    pub fn with_api_base(mut self, base: impl Into<String>) -> CheckRuns {
        self.api_base = api_base(base);
        self
    }

    /// Overrides the `User-Agent` header.
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> CheckRuns {
        self.user_agent = ua.into();
        self
    }

    fn check_runs_url(&self) -> String {
        format!("{}/repos/{}/{}/check-runs", self.api_base, self.owner, self.repo)
    }

    fn check_run_url(&self, id: i64) -> String {
        format!("{}/repos/{}/{}/check-runs/{id}", self.api_base, self.owner, self.repo)
    }

    /// Creates `run` against `head_sha` and returns the id GitHub gave it.
    ///
    /// The run is created `queued`: the annotations are known now, so they
    /// ride along with the creation rather than waiting for a second write,
    /// and the caller closes the run with [`complete`](Self::complete) once
    /// the rest of the work has an answer.
    ///
    /// GitHub answers a creation with exactly `201`, and takes at most 50
    /// annotations in the body it is sent. This does not split an oversized
    /// output across requests: the caller builds the [`CheckOutput`] and owns
    /// that count, appending anything beyond 50 in later update requests.
    pub async fn create(&self, head_sha: &str, run: &CheckRun<'_>) -> Result<i64, CheckError> {
        let mut body = serde_json::json!({
            "name": run.name,
            "head_sha": head_sha,
            "status": "queued",
        });
        let Some(object) = body.as_object_mut() else {
            return Err(CheckError::Unavailable {
                message: "a check run body would not build".to_string(),
            });
        };
        if let Some(details_url) = run.details_url {
            object.insert("details_url".to_string(), serde_json::json!(details_url));
        }
        // The run is `queued` because its findings are known now and the rest
        // of the work is not, so there is no verdict to record yet. A
        // conclusion is what turns a run into a verdict — GitHub sets the
        // status to completed the moment one is sent — so it is left to
        // `complete`, which the caller calls when it has an answer.
        if let Some(output) = &run.output {
            object.insert(
                "output".to_string(),
                serde_json::json!({
                    "title": output.title,
                    "summary": output.summary,
                    "annotations": output.annotations.iter().map(annotation_json).collect::<Vec<_>>(),
                }),
            );
        }
        let url = self.check_runs_url();
        let mut req = authed(&self.token, &self.user_agent, HttpMethod::Post, &url);
        req.headers.push(("Content-Type".to_string(), "application/json".to_string()));
        req.body = serde_json::to_vec(&body).map_err(|error| CheckError::Unavailable {
            message: format!("check run would not serialize: {error}"),
        })?;
        let response = self.send(req).await?;
        // Creating a check run answers `201` and nothing else, the same
        // strictness the approvals channel applies to a comment it posts.
        if response.status != 201 {
            return Err(CheckError::Unavailable {
                message: format!("GitHub answered {} creating a check run", response.status),
            });
        }
        serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|value| value.get("id").and_then(serde_json::Value::as_i64))
            .ok_or_else(|| CheckError::Unavailable {
                message: "GitHub did not return a check run id".to_string(),
            })
    }

    /// Closes the check run `id` with `conclusion`.
    ///
    /// A run left `queued` is shown on the commit forever, so a PR can sit
    /// waiting on a check that will never answer; concluding it is how the
    /// finding becomes a verdict a branch protection rule can act on.
    pub async fn complete(&self, id: i64, conclusion: Conclusion) -> Result<(), CheckError> {
        let body = serde_json::json!({ "status": "completed", "conclusion": conclusion.as_str() });
        let mut req =
            authed(&self.token, &self.user_agent, HttpMethod::Patch, &self.check_run_url(id));
        req.headers.push(("Content-Type".to_string(), "application/json".to_string()));
        req.body = serde_json::to_vec(&body).map_err(|error| CheckError::Unavailable {
            message: format!("check run completion would not serialize: {error}"),
        })?;
        let response = self.send(req).await?;
        if response.status != 200 {
            return Err(CheckError::Unavailable {
                message: format!("GitHub answered {} completing a check run", response.status),
            });
        }
        Ok(())
    }

    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, CheckError> {
        self.http.send(req).await.map_err(|error| CheckError::Unavailable {
            message: format!("GitHub request failed: {error}"),
        })
    }
}

impl fmt::Debug for CheckRuns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckRuns")
            .field("api_base", &self.api_base)
            .field("owner", &self.owner)
            .field("repo", &self.repo)
            .finish_non_exhaustive()
    }
}

/// `annotation` as the API reads it, with the columns dropped whenever the
/// span crosses a line break.
///
/// The API supports `start_column` and `end_column` only on a span whose
/// `start_line` and `end_line` are the same line, so the omission is enforced
/// again here, on the way out, rather than left to whoever built the
/// [`Annotation`]. A span that reaches into a line past its start is still
/// worth reporting: the line range is the finding, and the column is a
/// refinement the API offers on one line only.
fn annotation_json(annotation: &Annotation) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert("path".to_string(), serde_json::json!(annotation.path));
    object.insert("start_line".to_string(), serde_json::json!(annotation.start_line));
    object.insert("end_line".to_string(), serde_json::json!(annotation.end_line));
    let single_line = annotation.start_line == annotation.end_line;
    if single_line {
        if let Some(column) = annotation.start_column {
            object.insert("start_column".to_string(), serde_json::json!(column));
        }
        if let Some(column) = annotation.end_column {
            object.insert("end_column".to_string(), serde_json::json!(column));
        }
    }
    // The severity field is `annotation_level`; `level` is not a property of
    // the request schema, and the field is required alongside the path and the
    // line range.
    object.insert("annotation_level".to_string(), serde_json::json!(annotation.level.as_str()));
    if let Some(title) = &annotation.title {
        object.insert("title".to_string(), serde_json::json!(title));
    }
    object.insert("message".to_string(), serde_json::json!(annotation.message));
    serde_json::Value::Object(object)
}
