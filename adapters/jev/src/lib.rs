//! `Jev`: a [`DecisionModel`] adapter for TypeSafe's Jev
//! ([#105](https://github.com/Keep-Shipping/harness/issues/105)). One JSON
//! request over an [`HttpClient`] and nothing else: the socket, the TLS and the
//! allowlist belong to the client, so this crate holds the *protocol*. The key
//! comes from the [`Secrets`] port.
//!
//! # Invariants
//!
//! - **The model is pinned, or this adapter does not exist.** [`Jev::with_model`]
//!   refuses `jev-latest`, `jev-preview` and anything not `jev-<version>`, and
//!   so does a response naming another model.
//! - **An answer is only ever an option the question offered**: every answer is
//!   checked with [`Answer::problem`] before it leaves this crate.
//! - **Failing closed is an error, not an answer.** A 401, an unreadable body, a
//!   rate limit that outlived the retries — all `Err`. This adapter never
//!   fabricates an `escalate` to dress a provider outage as a judgement.
//! - **The key is read once per call, inside
//!   [`with_bytes`](ks_core::ports::secrets::SecretValue::with_bytes), and
//!   becomes exactly one string**: the `Authorization` header value, for that
//!   call's life. It is in no error, no `Debug` and no log line, and every
//!   message quoting a vendor body is scrubbed through a [`Redactor`] holding it.
//! - **A truncation is recorded.** The port cannot log for this adapter and the
//!   run log has no free-form line, so each `Truncation::log_line` goes to
//!   [`Jev::take_truncations`] for the caller to write.
//! - **A run cannot hang on a rate limit**: attempts and waits are bounded, and
//!   an un-obeyable `Retry-After` ends the retrying, not the run itself.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ks_core::ids::StepId;
use ks_core::ports::BoxFuture;
use ks_core::ports::clock::Clock;
use ks_core::ports::decision_model::{
    Answer, ChoiceOption, DecisionError, DecisionModel, ModelProfile, Question, RedactedState,
    check_questions,
};
use ks_core::ports::http::{HttpClient, HttpError, HttpMethod, HttpRequest, HttpResponse};
use ks_core::ports::secrets::{Redactor, SecretRef, Secrets, SecretsError};
use serde_json::{Map, Value, json};

/// The only model id used unless told otherwise: pinned, so a decision names
/// the model that made it.
pub const PINNED_MODEL: &str = "jev-1.13.0";

/// Where the vendor's API lives.
pub const DEFAULT_BASE_URL: &str = "https://api.typesafe.ai/v1/systemone";

/// The bound [`RedactedState::fit`] cuts to — ours; the vendor documents none.
pub const MAX_STATE_BYTES: usize = 32 * 1024;

/// Attempts in total, the first included: one call plus two retries.
pub const DEFAULT_ATTEMPTS: usize = 3;

/// The longest a single wait may be, whatever `Retry-After` asked for.
pub const DEFAULT_MAX_WAIT: Duration = Duration::from_secs(30);

/// The first backoff wait; each attempt doubles it.
const BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Characters of a vendor error body quoted back in a message.
const ERROR_SNIPPET_CHARS: usize = 200;

/// The model id asked for is not a pinned `jev-<version>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpinnedModel {
    /// The id that was asked for.
    pub requested: String,
}

impl fmt::Display for UnpinnedModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let moving =
            "(`jev-latest`, `jev-preview`) are refused: they make a decision unreproducible";
        let wanted =
            format!("want `jev-<version>` such as {PINNED_MODEL:?}. The moving aliases {moving}");
        write!(f, "{:?} is not a pinned jev model: {wanted}", self.requested)
    }
}

impl std::error::Error for UnpinnedModel {}

/// A [`DecisionModel`] over TypeSafe's Jev API.
pub struct Jev {
    http: Arc<dyn HttpClient>,
    secrets: Arc<dyn Secrets>,
    clock: Arc<dyn Clock>,
    /// The key, as a reference. Never the key itself.
    key: SecretRef,
    /// The step the key resolves *for*: an actor's gate reads against it.
    for_step: StepId,
    base_url: String,
    /// The pinned id, and the profile it names.
    model: String,
    profile: ModelProfile,
    attempts: usize,
    max_wait: Duration,
    /// Truncation lines, drained by `take_truncations`.
    truncations: Mutex<Vec<String>>,
}

/// The answers a [`DecisionModel`] hands back, and the one error it reports.
type Answers = Result<BTreeMap<String, Answer>, DecisionError>;

impl Jev {
    /// An adapter asking for [`PINNED_MODEL`], `key` resolved for `for_step`
    /// every call — a tool credential an actor may reach through
    /// [`ActorGatedSecrets`](ks_core::ports::secrets::ActorGatedSecrets).
    pub fn new(
        http: Arc<dyn HttpClient>,
        secrets: Arc<dyn Secrets>,
        clock: Arc<dyn Clock>,
        key: SecretRef,
        for_step: StepId,
    ) -> Jev {
        let (model, base_url) = (PINNED_MODEL.to_string(), DEFAULT_BASE_URL.to_string());
        Jev {
            http,
            secrets,
            clock,
            key,
            for_step,
            profile: profile_of(&model),
            base_url,
            model,
            attempts: DEFAULT_ATTEMPTS,
            max_wait: DEFAULT_MAX_WAIT,
            truncations: Mutex::new(Vec::new()),
        }
    }

    /// Pins a different `jev-<version>`, or [`UnpinnedModel`] for a moving alias.
    pub fn with_model(mut self, model: impl Into<String>) -> Result<Jev, UnpinnedModel> {
        let model = model.into();
        if !is_pinned(&model) {
            return Err(UnpinnedModel { requested: model });
        }
        self.model = model.clone();
        self.profile = profile_of(&model);
        Ok(self)
    }

    /// Points the adapter at another endpoint — a proxy, or a test.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Jev {
        self.base_url = base_url.into();
        self
    }

    /// Bounded retries: `attempts` in total, no wait over `max_wait`.
    pub fn with_retry(mut self, attempts: usize, max_wait: Duration) -> Jev {
        self.attempts = attempts.max(1);
        self.max_wait = max_wait;
        self
    }

    /// Takes and clears the truncation lines since the last call: a log nobody
    /// drains is a leak.
    pub fn take_truncations(&self) -> Vec<String> {
        let mut lines = self.truncations.lock().unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut *lines)
    }

    /// Every [`DecisionError::Model`] this adapter reports, one shape.
    fn fail(&self, message: impl Into<String>) -> DecisionError {
        DecisionError::Model { message: message.into() }
    }

    /// The JSON body: state, pinned model, each question's options as
    /// `criteria` — a description is the rubric, none is `null`.
    fn body(&self, state: &RedactedState, questions: &BTreeMap<String, Question>) -> String {
        let criteria = |options: &[ChoiceOption]| {
            let entry = |o: &ChoiceOption| (o.id.clone(), o.description.clone().into());
            options.iter().map(entry).collect::<Map<String, Value>>()
        };
        let asked: Map<String, Value> = questions
            .iter()
            .map(|(id, Question::Choice { instructions, options })| {
                let choice = json!({"type": "choice", "instructions": instructions, "criteria": criteria(options)});
                (id.clone(), choice)
            })
            .collect();
        json!({"state": state.as_str(), "model": self.model, "questions": asked}).to_string()
    }

    /// One call, classified retryable or final; anything quoting the vendor
    /// back goes through the [`Redactor`].
    async fn attempt(&self, authorization: &str, body: &str, redactor: &Redactor) -> Attempt {
        let mut req = HttpRequest::new(HttpMethod::Post, &self.base_url);
        let auth = ("Authorization".to_string(), authorization.to_string());
        req.headers.push(("Content-Type".to_string(), "application/json".to_string()));
        req.headers.push(auth);
        req.body = body.as_bytes().to_vec();
        let refused = |m: String| Attempt::Failed(self.fail(m));
        let response = match self.http.send(req).await {
            Ok(response) => response,
            // A refused host or URL will be refused again, and a body over the
            // policy cap is a property of the policy: retrying repeats the refusal.
            Err(HttpError::InvalidUrl | HttpError::HostNotAllowed { .. }) => {
                let why = "the jev endpoint is not allowlisted by this client's http policy";
                return refused(why.into());
            }
            Err(HttpError::ResponseTooLarge { limit }) => {
                return refused(format!("the jev response exceeded the {limit}-byte limit"));
            }
            // A timeout or a dropped connection is worth another go: the vendor
            // had no chance to say when.
            Err(error) => {
                let because = error.to_string();
                return Attempt::Retryable { retry_after: None, because };
            }
        };

        let quoted = || redactor.redact(&snippet(&response.body));
        match response.status {
            200 => Attempt::Answer(response),
            401 => {
                let why = "was rejected (401 unauthorized): check the secret it names";
                refused(format!("the key from {} {why}", self.key))
            }
            422 => refused(format!("jev refused the request body (422): {}", quoted())),
            // Documented as "back off and retry". 503 is the same statement
            // about the same capacity, from every other vendor.
            429 | 503 | 529 => Attempt::Retryable {
                retry_after: header(&response, "retry-after").map(str::to_string),
                because: format!("jev answered {}", response.status),
            },
            status => refused(format!("jev answered an unexpected {status}: {}", quoted())),
        }
    }

    /// The whole call: fit, resolve the key, ask, retry, map.
    async fn ask_all(&self, state: RedactedState, q: &BTreeMap<String, Question>) -> Answers {
        check_questions(q)?;
        let fit = state.fit(self.profile.max_state_bytes);
        if let Some(truncation) = &fit.truncated {
            let mut lines = self.truncations.lock().unwrap_or_else(PoisonError::into_inner);
            lines.push(truncation.log_line());
        }
        let body = self.body(&fit.state, q);
        // One resolution for the whole call, retries included: the key does not
        // rotate between attempts, and re-reading a secret is how one ends up
        // in two places.
        let unresolved = |e: SecretsError| {
            self.fail(format!("the key from {} could not be resolved: {e}", self.key))
        };
        let key = self.secrets.resolve(&self.key, &self.for_step).await.map_err(unresolved)?;
        let mut redactor = Redactor::new();
        redactor.register(&key);
        let authorization =
            key.with_bytes(|b| format!("Bearer {}", String::from_utf8_lossy(b).trim()));
        let mut attempt = 1;
        loop {
            match self.attempt(&authorization, &body, &redactor).await {
                Attempt::Answer(reply) => return self.answers(&reply, q, &redactor),
                Attempt::Failed(error) => return Err(error),
                Attempt::Retryable { retry_after, because } => {
                    let tried = format!(" after {attempt} attempt(s)");
                    if attempt >= self.attempts {
                        let gave_up = format!("jev did not answer{tried}: {because}");
                        return Err(self.fail(gave_up));
                    }
                    let wait = match wait_for(retry_after.as_deref(), self.max_wait) {
                        Ok(Some(after)) => after,
                        // No header, or one asking for no wait at all.
                        Ok(None) => backoff(attempt).min(self.max_wait),
                        Err(refusal) => {
                            let stalled =
                                format!("{refusal}; giving up rather than stalling{tried}");
                            return Err(self.fail(stalled));
                        }
                    };
                    self.clock.sleep(wait).await;
                    attempt += 1;
                }
            }
        }
    }

    /// The 200's answers, each checked against the question it answers.
    fn answers(
        &self,
        reply: &HttpResponse,
        q: &BTreeMap<String, Question>,
        red: &Redactor,
    ) -> Answers {
        let not_json =
            |e: serde_json::Error| self.fail(format!("the jev response is not json: {e}"));
        let document: Value = serde_json::from_slice(&reply.body).map_err(not_json)?;
        // A response naming another model is not this run's answer: the
        // profile, and every decision logged against it, name a version.
        match document.get("model").and_then(Value::as_str) {
            Some(model) if model == self.model => {}
            None => return Err(self.fail("the jev response names no model to attribute it to")),
            Some(other) => {
                let drift = format!("jev answered from model {other:?}, not {:?}", self.model);
                return Err(self.fail(drift));
            }
        }
        let answers = document.get("answers").and_then(Value::as_object);
        let answered = answers.ok_or_else(|| self.fail("the jev response has no `answers`"))?;
        let mut out = BTreeMap::new();
        for (id, question) in q {
            let raw =
                answered.get(id).ok_or_else(|| self.fail(format!("jev did not answer {id:?}")))?;
            let answer = self.answer_of(id, raw, red)?;
            if let Some(reason) = answer.problem(question) {
                return Err(DecisionError::InvalidAnswer { id: id.clone(), reason });
            }
            out.insert(id.clone(), answer);
        }
        // An id nobody asked about means this is not the response to this request.
        if let Some(id) = answered.keys().find(|id| !q.contains_key(*id)) {
            let extra = format!("jev answered a question that was not asked: {id:?}");
            return Err(self.fail(extra));
        }
        Ok(out)
    }

    /// One answer as documented: unreadable is a model failure, misfitting is
    /// [`DecisionError::InvalidAnswer`] at [`Answer::problem`].
    fn answer_of(&self, id: &str, raw: &Value, red: &Redactor) -> Result<Answer, DecisionError> {
        let field = |name: &str| self.fail(format!("the jev answer to {id:?} has no {name}"));
        let text = |name: &str| raw.get(name).and_then(Value::as_str);
        let number = |name: &str| raw.get(name).and_then(Value::as_f64);
        if let Some(kind) = text("type")
            && kind != "choice"
        {
            let other = format!("jev answered {id:?} as {kind:?}, and this reads only `choice`");
            return Err(self.fail(other));
        }
        let choice = text("choice").ok_or_else(|| field("`choice`"))?;
        let confidence = number("confidence").ok_or_else(|| field("`confidence` in 0..=1"))?;
        let spread = raw.get("probabilities").and_then(Value::as_object);
        let spread = spread.ok_or_else(|| field("`probabilities` per option"))?;
        let mut probabilities = BTreeMap::new();
        for (option, probability) in spread {
            let bad = format!("the probability for {option:?} in {id:?} is not a number");
            let number = probability.as_f64().ok_or_else(|| self.fail(red.redact(&bad)))?;
            probabilities.insert(option.clone(), number);
        }
        Ok(Answer::new(choice, probabilities, confidence))
    }
}

impl DecisionModel for Jev {
    fn ask<'a>(
        &'a self,
        state: RedactedState,
        q: BTreeMap<String, Question>,
    ) -> BoxFuture<'a, Answers> {
        Box::pin(async move { self.ask_all(state, &q).await })
    }

    fn profile(&self) -> ModelProfile {
        self.profile.clone()
    }
}

impl fmt::Debug for Jev {
    // `key` is the reference, never the key itself: a reference is not secret,
    // and it is what makes this `Debug` useful in a bug report.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key = self.key.to_string();
        f.debug_struct("Jev")
            .field("base_url", &self.base_url)
            .field("profile", &self.profile)
            .field("key", &key)
            .field("for_step", &self.for_step.as_str())
            .field("attempts", &self.attempts)
            .field("max_wait", &self.max_wait)
            .finish_non_exhaustive()
    }
}

/// The profile a pinned id names; confidence compares only within a family.
fn profile_of(model: &str) -> ModelProfile {
    let version = model.strip_prefix("jev-").unwrap_or(model).to_string();
    let calibration_family = format!("typesafe/jev-{version}");
    ModelProfile {
        model_id: "typesafe/jev".into(),
        calibration_family,
        version,
        max_state_bytes: MAX_STATE_BYTES,
    }
}

/// Whether `model` is a pinned `jev-<version>`.
fn is_pinned(model: &str) -> bool {
    let Some(version) = model.strip_prefix("jev-") else { return false };
    let numeric = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    !version.is_empty() && version.split('.').all(numeric)
}

/// `Some` a wait to take, `None` use the backoff, `Err` a `Retry-After` to
/// refuse: over the cap, or not seconds — an HTTP-date is legal and unreadable
/// here, and refusing beats guessing over it.
fn wait_for(retry_after: Option<&str>, max_wait: Duration) -> Result<Option<Duration>, String> {
    let named = retry_after.map(str::trim).filter(|raw| !raw.is_empty());
    let Some(raw) = named else { return Ok(None) };
    let unreadable =
        || format!("jev sent a retry-after of {raw:?}, which this adapter cannot read");
    let Ok(seconds) = raw.parse::<u64>() else { return Err(unreadable()) };
    // Zero asks for no wait, which is no instruction at all.
    if seconds == 0 {
        return Ok(None);
    }
    let after = Duration::from_secs(seconds);
    let cap = max_wait.as_secs();
    if after > max_wait {
        return Err(format!("jev asked for a wait of {after:?}, over the {cap}-second cap"));
    }
    Ok(Some(after))
}

/// The wait when the vendor named none: a second, then two.
fn backoff(attempt: usize) -> Duration {
    BACKOFF_BASE.saturating_mul(u32::try_from(attempt).unwrap_or(u32::MAX))
}

/// A vendor error body, trimmed to print in a log and a bug report.
fn snippet(body: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(body).chars().take(ERROR_SNIPPET_CHARS).collect();
    let text = text.trim();
    if text.is_empty() { "no body".to_string() } else { text.replace(['\n', '\r'], " ") }
}

/// A response header, case-insensitively: presence is the contract.
fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    let found = response.headers.iter().find(|(field, _)| field.eq_ignore_ascii_case(name));
    found.map(|(_, value)| value.as_str())
}

/// What one attempt concluded.
enum Attempt {
    /// A 200 to be parsed.
    Answer(HttpResponse),
    /// Worth another go. The raw `Retry-After` reaches [`wait_for`] unparsed:
    /// an unreadable one is a refusal, not a backoff.
    Retryable {
        retry_after: Option<String>,
        /// Why, for the final message.
        because: String,
    },
    /// The run stops here.
    Failed(DecisionError),
}
