//! The Checks API end to end over the real site fixture: the `build.tag`
//! mistake the CLI's own snapshots use, carried all the way to the bytes
//! GitHub would read.
//!
//! Everything is scripted on a [`FakeHttpClient`], and every assertion is read
//! back out of `fake.requests()` and parsed as JSON — the adapter never hands
//! its own structs to a test, so what is checked here is the exact body GitHub
//! would be sent, field names and all.

use std::sync::Arc;

use ks_core::ports::http::{HttpClient, HttpMethod, HttpRequest, HttpResponse};
use ks_github::{
    Annotation, AnnotationLevel, CheckError, CheckOutput, CheckRun, CheckRuns, Conclusion, Token,
};
use ks_lang::Code;
use ks_testing::block_on;
use ks_testing::http::FakeHttpClient;

const API: &str = "https://api.github.com";
const OWNER: &str = "keep-shipping";
const REPO: &str = "harness";
/// The id GitHub mints for the run.
const RUN_ID: i64 = 4207;
const HEAD_SHA: &str = "9f1c0d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c";

/// The site the CLI snapshots check: `deploy.image` is given `build.tag`,
/// where the deploy wants an immutable digest.
const SITE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../crates/cli/tests/fixtures/site/ship.ks");

fn check_runs_url() -> String {
    format!("{API}/repos/{OWNER}/{REPO}/check-runs")
}

fn check_run_url(id: i64) -> String {
    format!("{API}/repos/{OWNER}/{REPO}/check-runs/{id}")
}

fn response(status: u16, body: &[u8]) -> HttpResponse {
    HttpResponse { status, headers: vec![], body: body.to_vec() }
}

fn created() -> HttpResponse {
    response(201, format!(r#"{{"id":{RUN_ID}}}"#).as_bytes())
}

/// The fake, scripted with a created check run and nothing else.
fn fake() -> Arc<FakeHttpClient> {
    Arc::new(FakeHttpClient::new().with_allowed_host("api.github.com").with_response(
        HttpMethod::Post,
        check_runs_url(),
        created(),
    ))
}

fn check_runs(fake: &Arc<FakeHttpClient>) -> CheckRuns {
    let http: Arc<dyn HttpClient> = Arc::clone(fake) as Arc<dyn HttpClient>;
    CheckRuns::new(http, Token::new("t0ken"), OWNER, REPO)
}

/// The body of the check run the adapter posted, read back off the wire.
fn posted(fake: &FakeHttpClient) -> serde_json::Value {
    let requests = fake.requests();
    let body = requests
        .iter()
        .find(|req| req.method == HttpMethod::Post && req.url == check_runs_url())
        .map(|req: &HttpRequest| req.body.clone())
        .expect("the run is created");
    serde_json::from_slice(&body).expect("the body GitHub would read is JSON")
}

/// The annotation on `path` the wire body carries.
fn annotation_on<'a>(run: &'a serde_json::Value, path: &str) -> &'a serde_json::Value {
    run.pointer("/output/annotations")
        .and_then(|annotations| annotations.as_array())
        .expect("the run carries annotations")
        .iter()
        .find(|annotation| annotation.get("path").and_then(serde_json::Value::as_str) == Some(path))
        .expect("the run annotates the file it checked")
}

#[test]
fn the_build_tag_mistake_shows_as_an_annotation_on_line_21() {
    let src = std::fs::read_to_string(SITE).expect("the site fixture ships with the CLI");
    let catalog = ks_core::Catalog::builtin();
    let checked = ks_core::check_with(&ks_lang::parse(&src), &ks_core::CheckOptions::new(&catalog));
    let found = checked
        .diagnostics
        .iter()
        .find(|d| d.code == Code::TypeMismatch)
        .expect("the fixture still yields the oci.Tag-vs-oci.Digest finding");
    assert_eq!(
        found.code.as_str(),
        "KS0101",
        "the fixture's finding is the type mismatch the snapshots name"
    );
    assert_eq!(
        found.subject.as_deref(),
        Some("deploy.image"),
        "the finding is about the field that names the image"
    );
    assert!(
        found.message.contains("expected oci.Digest") && found.message.contains("got oci.Tag"),
        "the finding says what was wrong: {}",
        found.message
    );

    let annotations: Vec<Annotation> = checked
        .diagnostics
        .iter()
        .map(|d| Annotation::from_diagnostic("ship.ks", &src, d))
        .collect();
    let fake = fake();
    let id = block_on(check_runs(&fake).create(
        HEAD_SHA,
        &CheckRun {
            name: "keepshipping check",
            details_url: None,
            output: Some(CheckOutput {
                title: "ship.ks",
                summary: "keepshipping check on ship.ks",
                annotations: &annotations,
            }),
        },
    ));
    assert_eq!(id, Ok(RUN_ID), "GitHub's id is what the run is completed against");

    let run = posted(&fake);
    assert_eq!(run.get("name").and_then(serde_json::Value::as_str), Some("keepshipping check"));
    assert_eq!(run.get("head_sha").and_then(serde_json::Value::as_str), Some(HEAD_SHA));
    assert_eq!(run.get("status").and_then(serde_json::Value::as_str), Some("queued"));

    let annotation = annotation_on(&run, "ship.ks");
    assert_eq!(
        annotation.get("start_line").and_then(serde_json::Value::as_u64),
        Some(21),
        "the mistake is annotated on the line it is written on, not on the step's first line"
    );
    // The body above is read back off the wire, which proves the adapter sent
    // what it meant to — but the names in it are written out by hand here, and
    // no schema check runs against them. A key GitHub does not know (`level`
    // rather than `annotation_level`) parses as JSON just the same, so only a
    // reader who has the schema in front of them catches that class of bug.
    assert_eq!(
        annotation.get("annotation_level").and_then(serde_json::Value::as_str),
        Some("failure"),
        "the Checks API has no error level, so a checker error is a failure"
    );
    assert_eq!(
        annotation.get("title").and_then(serde_json::Value::as_str),
        Some("KS0101 deploy.image"),
        "the title is the string render::github uses, so both surfaces read alike"
    );
    assert!(
        annotation
            .get("message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|message| message.contains("expected oci.Digest, got oci.Tag")),
        "the message carries the finding itself: {annotation}"
    );
    // The span is inside one line, so it may carry columns — the one shape the
    // API gives columns a meaning for, and what lets a reader see exactly the
    // text the fix would rewrite.
    assert!(
        annotation.get("start_column").and_then(serde_json::Value::as_u64).is_some_and(|c| c > 0),
        "a single-line span keeps its columns: {annotation}"
    );
}

#[test]
fn a_span_across_lines_is_sent_without_columns() {
    // Built by hand, deliberately wrong: the API supports `start_column` and
    // `end_column` only when `start_line` and `end_line` are the same line, and
    // tells callers to omit them when the two differ. The columns therefore
    // have to be dropped on the way out, not trusted to whoever built the
    // annotation.
    let annotations = vec![Annotation {
        path: "ship.ks".to_string(),
        start_line: 21,
        start_column: Some(12),
        end_line: 24,
        end_column: Some(7),
        level: AnnotationLevel::Warning,
        title: Some("KS0101 deploy.image".to_string()),
        message: "a finding that runs past the end of its line".to_string(),
    }];
    let fake = fake();
    block_on(check_runs(&fake).create(
        HEAD_SHA,
        &CheckRun {
            name: "keepshipping check",
            details_url: None,
            output: Some(CheckOutput {
                title: "ship.ks",
                summary: "keepshipping check on ship.ks",
                annotations: &annotations,
            }),
        },
    ))
    .expect("the run is created");

    let run = posted(&fake);
    let annotation = annotation_on(&run, "ship.ks");
    assert_eq!(annotation.get("start_line").and_then(serde_json::Value::as_u64), Some(21));
    assert_eq!(annotation.get("end_line").and_then(serde_json::Value::as_u64), Some(24));
    assert!(
        annotation.get("start_column").is_none(),
        "a multi-line span must not carry a start column: {annotation}"
    );
    assert!(
        annotation.get("end_column").is_none(),
        "a multi-line span must not carry an end column: {annotation}"
    );
    assert_eq!(
        annotation.get("annotation_level").and_then(serde_json::Value::as_str),
        Some("warning"),
        "the finding itself still travels, columns or not"
    );
}

#[test]
fn a_hint_rides_the_message_as_a_real_newline() {
    let src = std::fs::read_to_string(SITE).expect("the site fixture ships with the CLI");
    let mut diagnostic =
        ks_lang::Diagnostic::error(Code::TypeMismatch, ks_lang::Span::point(0), "nope");
    diagnostic.subject = Some("deploy.image".to_string());
    diagnostic.hints.push("deploy the digest, not the tag.".to_string());

    let annotation = Annotation::from_diagnostic("ship.ks", &src, &diagnostic);
    assert_eq!(annotation.title.as_deref(), Some("KS0101 deploy.image"));
    assert!(
        annotation.message.starts_with("nope\n\nhint: deploy the digest, not the tag."),
        "the hint is appended the way render::github writes it, with a newline instead of %0A: {}",
        annotation.message
    );
}

#[test]
fn an_offset_inside_a_multi_byte_character_still_annotates() {
    // `a中文b` puts three bytes per CJK character, so byte offset 2 is inside
    // `中` and is nowhere the source can be sliced. Nothing in the types ties a
    // `Diagnostic` to the string it is measured against — a caller can hand
    // `from_diagnostic` any span — so the annotation has to come out a line
    // and a column rather than a panic.
    let src = "a中文b\nnext\n";
    let diagnostic =
        ks_lang::Diagnostic::error(Code::TypeMismatch, ks_lang::Span::point(2), "nope");

    let annotation = Annotation::from_diagnostic("ship.ks", src, &diagnostic);
    assert_eq!(annotation.start_line, 1, "the offset is inside the first line");
    assert_eq!(
        annotation.start_column,
        Some(2),
        "the offset rounds down onto the character containing it, which is column 2"
    );
    assert_eq!(
        annotation.end_column, annotation.start_column,
        "a point span starts and ends in the same place"
    );
    assert_eq!(annotation.title.as_deref(), Some("KS0101"), "the finding still travels whole");
}

#[test]
fn completing_a_run_patches_it_as_completed() {
    let fake = Arc::new(FakeHttpClient::new().with_allowed_host("api.github.com").with_response(
        HttpMethod::Patch,
        check_run_url(RUN_ID),
        response(200, b"{}"),
    ));
    block_on(check_runs(&fake).complete(RUN_ID, Conclusion::Failure))
        .expect("the run is completed");

    let requests = fake.requests();
    let request = requests
        .iter()
        .find(|req| req.method == HttpMethod::Patch)
        .expect("completing patches the run");
    assert_eq!(request.url, check_run_url(RUN_ID));
    let body: serde_json::Value = serde_json::from_slice(&request.body).expect("the patch is JSON");
    assert_eq!(body.get("status").and_then(serde_json::Value::as_str), Some("completed"));
    assert_eq!(body.get("conclusion").and_then(serde_json::Value::as_str), Some("failure"));
}

#[test]
fn a_refused_check_run_is_an_error_not_a_run() {
    let fake = Arc::new(FakeHttpClient::new().with_allowed_host("api.github.com").with_response(
        HttpMethod::Post,
        check_runs_url(),
        response(403, b"{}"),
    ));
    let error = block_on(check_runs(&fake).create(
        HEAD_SHA,
        &CheckRun { name: "keepshipping check", details_url: None, output: None },
    ))
    .expect_err("a refused run is not a run");
    assert!(
        matches!(&error, CheckError::Unavailable { message } if message.contains("403")),
        "the error says what GitHub answered: {error}"
    );
}

#[test]
fn the_debug_of_a_client_says_nothing_about_the_token() {
    let rendered = format!("{:?}", check_runs(&fake()));
    assert!(rendered.contains("CheckRuns"), "{rendered}");
    assert!(rendered.contains(OWNER) && rendered.contains(REPO), "{rendered}");
    assert!(!rendered.contains("t0ken"), "the token must never be printed: {rendered}");
}
