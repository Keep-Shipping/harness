//! Service-free tests of the Jev adapter: the request it builds, the answers
//! it accepts and refuses, and the retry policy — against a scripted
//! [`FakeHttpClient`], so `cargo test --workspace` never opens a socket. The
//! bodies are the documented shapes, not recordings; the live half is `smoke.rs`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ks_core::ids::StepId;
use ks_core::plan_summary::{Kind, Limits, PlanSummary, SummaryAttribute, SummaryEntry, Target};
use ks_core::ports::decision_model::{
    Answer, ChoiceOption, DecisionError, DecisionModel, ESCALATE, Question, RedactedState,
};
use ks_core::ports::http::{HttpError, HttpMethod, HttpResponse};
use ks_core::ports::secrets::SecretRef;
use ks_jev::{DEFAULT_BASE_URL, Jev, MAX_STATE_BYTES, PINNED_MODEL};
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::http::FakeHttpClient;
use ks_testing::secrets::FakeSecrets;

const SUCCESS: &str = include_str!("fixtures/success.json");
const UNKNOWN_OPTION: &str = include_str!("fixtures/unknown-option.json");
const UNAUTHORIZED: &str = include_str!("fixtures/unauthorized.json");
const UNPROCESSABLE: &str = include_str!("fixtures/unprocessable.json");
const OVERLOADED: &str = include_str!("fixtures/overloaded.json");

/// A key that is not a key. The tests assert it never escapes a message.
const KEY: &str = "sk-typesafe-not-a-real-key";

/// A legal `Retry-After` this adapter cannot read: seconds, not dates.
const DATE: &str = "Wed, 21 Oct 2026 07:28:00 GMT";

/// The adapter over its fakes, still reachable so a test can read back the run.
struct Wired {
    jev: Jev,
    http: Arc<FakeHttpClient>,
    clock: Arc<FakeClock>,
}

/// The adapter that answers `responses` in order; the last one repeats.
fn over(responses: Vec<HttpResponse>) -> Wired {
    let mut http = FakeHttpClient::new().with_allowed_host("api.typesafe.ai");
    for response in responses {
        http = http.with_response(HttpMethod::Post, DEFAULT_BASE_URL, response);
    }
    let http = Arc::new(http);
    let clock = Arc::new(FakeClock::new());
    Wired { jev: wired(&http, &clock), http, clock }
}

/// The adapter over fakes a test has built itself; its key resolves.
fn wired(http: &Arc<FakeHttpClient>, clock: &Arc<FakeClock>) -> Jev {
    let secrets = FakeSecrets::new().with(key(), KEY.as_bytes().to_vec());
    Jev::new(http.clone(), Arc::new(secrets), clock.clone(), key(), StepId::new("decide"))
}

/// The same fakes under a reconfigured adapter.
fn rewired(wire: &Wired, rewire: impl FnOnce(Jev) -> Jev) -> Wired {
    let (http, clock) = (wire.http.clone(), wire.clock.clone());
    Wired { jev: rewire(wired(&http, &clock)), http, clock }
}

/// A response; a `retry_after` of `""` is no `Retry-After` at all.
fn r(status: u16, retry_after: &str, body: &str) -> HttpResponse {
    let retry = vec![("Retry-After".to_string(), retry_after.to_string())];
    let headers = if retry_after.is_empty() { Vec::new() } else { retry };
    HttpResponse { status, headers, body: body.as_bytes().to_vec() }
}

impl Wired {
    fn ask(&self) -> Result<BTreeMap<String, Answer>, DecisionError> {
        block_on(self.jev.ask(state(), questions()))
    }

    /// The failing ask's message, or a panic naming what it was.
    fn failed(&self) -> String {
        message(self.ask())
    }

    /// How many requests and sleeps the run made.
    fn made(&self) -> (usize, usize) {
        (self.http.requests().len(), self.clock.sleeps().len())
    }

    /// The JSON body of the first request the adapter sent.
    fn body(&self) -> serde_json::Value {
        let requests = self.http.requests();
        serde_json::from_slice(&requests.first().expect("a request was sent").body)
            .expect("the body is json")
    }
}

fn key() -> SecretRef {
    SecretRef::new("env", "typesafe")
}

fn questions() -> BTreeMap<String, Question> {
    let risk = vec![
        ChoiceOption::described("low", "nothing can break"),
        ChoiceOption::described("medium", "recoverable damage"),
        ChoiceOption::new("high"),
        ChoiceOption::new(ESCALATE),
    ];
    let ship = vec![ChoiceOption::new("approve"), ChoiceOption::new(ESCALATE)];
    BTreeMap::from([
        ("risk".to_string(), Question::choice("How risky is this plan?", risk)),
        ("deploy".to_string(), Question::choice("Ship it?", ship)),
    ])
}

/// The state every test hands over: one replacement in a summary.
fn state() -> RedactedState {
    let attribute = SummaryAttribute {
        path: "instance_type".to_string(),
        before: "t3.small".to_string(),
        after: "m5.large".to_string(),
        forces_replacement: true,
    };
    let risky = vec![SummaryEntry {
        kind: Kind::Replace,
        address: "aws_instance.web".to_string(),
        attributes: vec![attribute],
        reason: Some("instance type changed".to_string()),
    }];
    let summary = PlanSummary { risky, add: 1, destroy: 1, ..PlanSummary::default() };
    RedactedState::summarise(&summary, Target::Plain, &Limits::default())
}

/// The message of a [`DecisionError::Model`], or a panic naming what it was.
fn message(result: Result<BTreeMap<String, Answer>, DecisionError>) -> String {
    match result {
        Err(DecisionError::Model { message }) => message,
        Err(other) => panic!("expected a model failure, got {other:?}"),
        Ok(answers) => panic!("expected a failure, got {answers:?}"),
    }
}

/// The key must never reach a message, whichever vendor body produced it.
#[track_caller]
fn assert_key_free(message: &str) {
    assert!(!message.contains(KEY), "the key is never in an error: {message}");
}

// -- the five acceptance criteria ------------------------------------------

#[test]
fn a_success_becomes_one_validated_answer_per_question() {
    let harness = over(vec![r(200, "", SUCCESS)]);
    let answers = harness.ask().expect("a scripted 200 is an answer");

    let request = &harness.http.requests()[0];
    assert_eq!((request.method, request.url.as_str()), (HttpMethod::Post, DEFAULT_BASE_URL));
    let header =
        |name: &str| request.headers.iter().find(|(f, _)| f == name).map(|(_, v)| v.as_str());
    assert_eq!(header("Authorization"), Some(format!("Bearer {KEY}").as_str()));
    assert_eq!(header("Content-Type"), Some("application/json"));

    let body = harness.body();
    assert_eq!(body["model"], PINNED_MODEL, "the pinned model is named in the request");
    assert_eq!(body["state"], state().as_str(), "the state is sent verbatim");
    assert_eq!(body["questions"]["risk"]["type"], "choice");
    assert_eq!(body["questions"]["risk"]["instructions"], "How risky is this plan?");
    // No description is a null criterion, not an empty string.
    let none = || serde_json::Value::Null;
    let criteria = serde_json::json!({
        "low": "nothing can break", "medium": "recoverable damage", "high": none(), "escalate": none()
    });
    assert_eq!(body["questions"]["risk"]["criteria"], criteria);

    let risk = &answers["risk"];
    assert_eq!(
        (risk.choice.as_str(), risk.probabilities["low"], risk.confidence),
        ("medium", 0.15, 0.82)
    );
    assert_eq!(risk.problem(&questions()["risk"]), None, "the answer is usable");
    assert_eq!(answers["deploy"].choice, ESCALATE);
    assert_eq!(answers.len(), 2, "one answer per question, no more");
    assert_eq!(harness.made(), (1, 0), "a 200 is neither retried nor waited for");
}

#[test]
fn an_answer_off_the_menu_is_refused_rather_than_used() {
    match over(vec![r(200, "", UNKNOWN_OPTION)]).ask() {
        Err(DecisionError::InvalidAnswer { id, reason }) => {
            assert_eq!(id, "risk");
            assert!(reason.contains("moderate"), "the reason names what it chose: {reason}");
        }
        other => panic!("expected InvalidAnswer, got {other:?}"),
    }
}

#[test]
fn a_rejected_key_fails_closed_at_once_and_never_prints_the_key() {
    let harness = over(vec![r(401, "", UNAUTHORIZED)]);
    let message = harness.failed();
    assert_eq!(harness.made(), (1, 0), "a rejected key will be rejected again");
    assert!(message.contains("env:typesafe"), "the message names the reference: {message}");
    assert!(message.contains("401"), "{message}");
    assert_key_free(&message);
}

#[test]
fn a_rate_limit_waits_for_what_it_asked_and_then_succeeds() {
    let harness = over(vec![r(429, "7", OVERLOADED), r(200, "", SUCCESS)]);
    harness.ask().expect("the second attempt is answered");
    assert_eq!(harness.made(), (2, 1));
    assert_eq!(harness.clock.sleeps(), vec![Duration::from_secs(7)], "the vendor's own wait");
}

#[test]
fn a_timeout_is_retried_then_fails_closed() {
    let host = FakeHttpClient::new().with_allowed_host("api.typesafe.ai");
    let timed_out = HttpError::Timeout { after: Duration::from_secs(30) };
    let http = Arc::new(host.with_error(HttpMethod::Post, DEFAULT_BASE_URL, timed_out));
    let clock = Arc::new(FakeClock::new());
    let harness = Wired { jev: wired(&http, &clock), http, clock };
    let message = harness.failed();
    assert_eq!(harness.made(), (3, 2), "bounded attempts, backoff between them");
    assert_eq!(harness.clock.sleeps(), vec![Duration::from_secs(1), Duration::from_secs(2)]);
    assert!(message.contains("timed out"), "{message}");
    assert_key_free(&message);
}

// -- one scripted reply, one expectation -----------------------------------

/// A scripted reply, the traffic it may cause, and a word the message must carry.
type Case = (&'static str, Vec<HttpResponse>, (usize, usize), &'static str);

/// 503 is here because it is 429's meaning from another vendor, and retried.
#[test]
fn a_reply_it_cannot_use_says_why_and_never_says_the_key() {
    let drifted = SUCCESS.replace(PINNED_MODEL, "jev-1.14.0");
    let partial = SUCCESS.replace("\"deploy\": {", "\"unasked\": {");
    let echoed = format!("{{\"error\":{{\"message\":\"bad key {KEY}\"}}}}");
    let cases: Vec<Case> = vec![
        ("422, quoting the vendor back", vec![r(422, "", UNPROCESSABLE)], (1, 0), "criteria"),
        ("a status nobody documented", vec![r(418, "", "{\"error\":\"teapot\"}")], (1, 0), "418"),
        ("a retry-after over the cap", vec![r(429, "3600", OVERLOADED)], (1, 0), "cap"),
        ("503, retried like a 429", vec![r(503, "", OVERLOADED)], (3, 2), "503"),
        ("a retry-after it cannot read", vec![r(429, DATE, OVERLOADED)], (1, 0), "cannot read"),
        ("a body echoing the key back", vec![r(422, "", &echoed)], (1, 0), "***"),
        ("an answer from another model", vec![r(200, "", &drifted)], (1, 0), "jev-1.14.0"),
        ("a body with an answer missing", vec![r(200, "", &partial)], (1, 0), "deploy"),
    ];
    for (name, responses, made, carries) in cases {
        let harness = over(responses);
        let message = harness.failed();
        assert_eq!(harness.made(), made, "{name}: requests, then sleeps");
        assert!(message.contains(carries), "{name}: {message} must say {carries:?}");
        assert_key_free(&message);
    }
}

/// A `Retry-After` of zero asks for no wait, so our own backoff is used.
#[test]
fn a_retry_after_of_zero_asks_for_no_wait_so_the_backoff_is_used() {
    let harness = over(vec![r(429, "0", OVERLOADED), r(200, "", SUCCESS)]);
    harness.ask().expect("the second attempt is answered");
    assert_eq!(harness.clock.sleeps(), vec![Duration::from_secs(1)], "our own backoff, not zero");
}

#[test]
fn one_attempt_makes_exactly_one_request_and_never_sleeps() {
    let once = |jev: Jev| jev.with_retry(1, Duration::from_secs(30));
    let harness = rewired(&over(vec![r(429, "1", OVERLOADED)]), once);
    let message = harness.failed();
    assert_eq!(harness.made(), (1, 0), "with_retry(1, …) does not retry");
    assert!(message.contains("1 attempt"), "{message}");
}

#[test]
fn the_profile_names_the_pinned_model_and_only_a_pinned_one_is_accepted() {
    let adapter = || over(vec![]).jev;
    let profile = adapter().profile();
    assert_eq!(profile.model_id, "typesafe/jev", "the id the dsl spells");
    assert_eq!((profile.version.as_str(), profile.max_state_bytes), ("1.13.0", MAX_STATE_BYTES));
    assert_eq!(profile.calibration_family, "typesafe/jev-1.13.0");
    for alias in ["jev-latest", "jev-preview", "jev-", "jev-1.x", "latest", "gpt-4o"] {
        let refused = ks_jev::UnpinnedModel { requested: alias.to_string() };
        assert_eq!(adapter().with_model(alias).err(), Some(refused), "{alias} is not pinned");
    }
    let pinned = adapter().with_model("jev-1.14.0").expect("a pinned version is allowed");
    assert_eq!(pinned.profile().calibration_family, "typesafe/jev-1.14.0");
}

#[test]
fn a_state_truncated_to_our_bound_is_recorded_and_sent_short() {
    // A summary far longer than the bound, so the fit really cuts.
    let added = |index: usize| SummaryEntry {
        kind: Kind::Add,
        address: format!("aws_s3_bucket.artefacts-{index:04}"),
        attributes: Vec::new(),
        reason: None,
    };
    let summary = PlanSummary { others: (0..2000).map(added).collect(), ..PlanSummary::default() };
    let long = RedactedState::summarise(&summary, Target::Plain, &Limits::default());
    assert!(long.len() > MAX_STATE_BYTES, "the fixture must exceed the bound: {}", long.len());

    let harness = over(vec![r(200, "", SUCCESS)]);
    block_on(harness.jev.ask(long, questions())).expect("the scripted 200 answers");

    let lines = harness.jev.take_truncations();
    assert_eq!(lines.len(), 1, "a truncation nobody logged is nobody's known: {lines:?}");
    assert!(lines[0].contains("state truncated"), "{lines:?}");
    let sent = harness.body()["state"].as_str().map(str::len);
    assert_eq!(sent, Some(MAX_STATE_BYTES), "only the fitted state is sent");
    assert_eq!(harness.jev.take_truncations(), Vec::<String>::new(), "the read drains");
}

#[test]
fn a_question_set_that_breaks_the_contract_never_reaches_the_vendor() {
    let harness = over(vec![r(200, "", SUCCESS)]);
    let low = ChoiceOption::new("low");
    let broken = BTreeMap::from([("risk".to_string(), Question::choice("How risky?", vec![low]))]);
    match block_on(harness.jev.ask(state(), broken)) {
        Err(DecisionError::InvalidQuestion { id, .. }) => assert_eq!(id, "risk"),
        other => panic!("expected InvalidQuestion, got {other:?}"),
    }
    assert!(harness.http.requests().is_empty());
}

#[test]
fn a_resolver_that_refuses_the_key_stops_the_run_before_any_request() {
    let http = Arc::new(FakeHttpClient::new().with_allowed_host("api.typesafe.ai"));
    let refused = Arc::new(FakeSecrets::new().unavailable(key(), "forbidden for this actor"));
    let jev =
        Jev::new(http.clone(), refused, Arc::new(FakeClock::new()), key(), StepId::new("decide"));
    let message = message(block_on(jev.ask(state(), questions())));
    assert!(message.contains("forbidden"), "the resolver's reason is carried: {message}");
    assert!(http.requests().is_empty(), "no key means no request at all");
}

#[test]
fn an_unallowlisted_host_is_refused_before_any_traffic() {
    let elsewhere = |jev: Jev| jev.with_base_url("https://jev.example.com/v1/systemone");
    let harness = rewired(&over(vec![r(200, "", SUCCESS)]), elsewhere);
    let message = harness.failed();
    assert_eq!(harness.made(), (1, 0), "the fake records the attempt, and it is not retried");
    assert!(message.contains("allowlist"), "{message}");
}

#[test]
fn the_debug_output_names_the_reference_and_never_the_key() {
    let debug = format!("{:?}", over(vec![r(200, "", SUCCESS)]).jev);
    assert!(debug.contains("env:typesafe"), "{debug}");
    assert_key_free(&debug);
}
