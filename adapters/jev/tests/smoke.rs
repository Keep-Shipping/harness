//! The live smoke test against TypeSafe's Jev API.
//!
//! `KS_JEV_SMOKE_KEY` unset — the case in `cargo test --workspace` — the test
//! prints that it skipped and returns, so the ordinary run stays service-free
//! (ADR 0002). `.github/workflows/jev-smoke.yml` runs it on demand with the key
//! from a repository secret.
//!
//! [`CurlHttpClient`] is defined here rather than imported: the workspace's
//! only real `HttpClient` is `ks-cli`'s, and an adapter's test must not depend
//! on the CLI to reach the network.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ks_core::ids::StepId;
use ks_core::plan_summary::{Limits, PlanSummary, Target};
use ks_core::ports::BoxFuture;
use ks_core::ports::clock::Clock;
use ks_core::ports::decision_model::{
    ChoiceOption, DecisionModel, ESCALATE, Question, RedactedState,
};
use ks_core::ports::http::{HttpClient, HttpError, HttpPolicy, HttpRequest, HttpResponse};
use ks_core::ports::secrets::SecretRef;
use ks_jev::{Jev, PINNED_MODEL};
use ks_testing::block_on;
use ks_testing::secrets::FakeSecrets;

#[test]
fn the_real_vendor_answers_a_question_and_the_adapter_validates_it() {
    let Ok(key) = std::env::var("KS_JEV_SMOKE_KEY") else {
        println!("skipping the jev smoke test: KS_JEV_SMOKE_KEY is unset");
        return;
    };
    assert!(!key.trim().is_empty(), "KS_JEV_SMOKE_KEY is set but empty");

    let reference = SecretRef::new("env", "typesafe");
    let jev = Jev::new(
        Arc::new(CurlHttpClient::new(HttpPolicy {
            allowed_hosts: ["api.typesafe.ai".to_string()].into_iter().collect(),
            timeout: Duration::from_secs(60),
            max_response_bytes: 1024 * 1024,
        })),
        Arc::new(FakeSecrets::new().with(reference.clone(), key.trim().as_bytes().to_vec())),
        Arc::new(SystemClock),
        reference,
        StepId::new("jev-smoke"),
    );

    let risk = Question::choice(
        "How risky is this infrastructure change?",
        vec![
            ChoiceOption::described("low", "nothing here can break production"),
            ChoiceOption::described("medium", "damage is recoverable"),
            ChoiceOption::described("high", "production is at stake"),
            ChoiceOption::new(ESCALATE),
        ],
    );
    let questions = BTreeMap::from([("risk".to_string(), risk)]);
    let state = RedactedState::summarise(
        &PlanSummary { add: 1, change: 2, destroy: 1, ..PlanSummary::default() },
        Target::Plain,
        &Limits::default(),
    );

    let answers = block_on(jev.ask(state, questions.clone())).expect("the vendor answers");
    let answer = &answers["risk"];
    println!(
        "jev {} chose {:?} with confidence {}",
        jev.profile().version,
        answer.choice,
        answer.confidence
    );
    // The only way a caller learns the state was cut: read and log the lines.
    for line in jev.take_truncations() {
        println!("{line}");
    }
    assert_eq!(answers.len(), 1);
    assert_eq!(
        answer.problem(&questions["risk"]),
        None,
        "a live answer must satisfy the port's contract"
    );
    assert_eq!(jev.profile().version, PINNED_MODEL.trim_start_matches("jev-"));
}

/// The one real [`Clock`] here; `SystemClock` lives in `ks-cli`.
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::now()
    }

    fn sleep<'a>(&'a self, duration: Duration) -> BoxFuture<'a, ()> {
        Box::pin(async move { std::thread::sleep(duration) })
    }
}

/// An [`HttpClient`] that shells out to `curl`, the TLS client this test needs
/// and does not have (`ks-cli`'s is plain HTTP).
///
/// The whole request — url, headers, body — goes out on `curl`'s **stdin**, as
/// a `-K -` config file, so the key never reaches argv, the process table or
/// the filesystem. Two scratch files hold what comes back, which is the
/// vendor's answer and not a secret; `--write-out` puts the status on stdout.
struct CurlHttpClient {
    policy: HttpPolicy,
}

impl CurlHttpClient {
    fn new(policy: HttpPolicy) -> CurlHttpClient {
        CurlHttpClient { policy }
    }

    fn curl(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        // The policy first, as a real client does: nothing runs for a host the
        // policy does not name.
        self.policy.check(&req.url)?;
        // Two scratch files for what comes back. Requests are sequential here,
        // so one name per process is enough; `--output` truncates before curl
        // writes, so a retry never reads the previous attempt's leftovers.
        let tag = format!("jev-smoke-{}", std::process::id());
        let body_file = scratch(&tag, "body");
        let header_file = scratch(&tag, "headers");

        let mut config = format!(
            "url = {}\nrequest = {}\nmax-time = {}\nsilent\nshow-error\noutput = {}\n\
             dump-header = {}\nwrite-out = %{{http_code}}\n",
            quoted(&req.url),
            quoted(req.method.as_str()),
            self.policy.timeout.as_secs(),
            quoted(&body_file),
            quoted(&header_file),
        );
        for (name, value) in &req.headers {
            config.push_str(&format!("header = {}\n", quoted(&format!("{name}: {value}"))));
        }
        if !req.body.is_empty() {
            let body = String::from_utf8_lossy(&req.body).into_owned();
            config.push_str(&format!("data-binary = {}\n", quoted(&body)));
        }

        let mut child = Command::new("curl")
            .arg("--config")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| HttpError::Transport {
                message: format!("curl could not start: {error}"),
            })?;
        let transport = |error: std::io::Error| HttpError::Transport { message: error.to_string() };
        if let Some(mut pipe) = child.stdin.take() {
            // Dropping the pipe closes curl's stdin, which it reads the config to.
            pipe.write_all(config.as_bytes()).map_err(transport)?;
        }
        let output = child.wait_with_output().map_err(transport)?;

        let body = std::fs::read(&body_file).unwrap_or_default();
        let dumped = std::fs::read_to_string(&header_file).unwrap_or_default();
        let _ = std::fs::remove_file(&body_file);
        let _ = std::fs::remove_file(&header_file);

        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            let message = format!("curl: {}", detail.trim());
            return Err(if detail.contains("timed out") {
                HttpError::Timeout { after: self.policy.timeout }
            } else {
                HttpError::Transport { message }
            });
        }
        if body.len() > self.policy.max_response_bytes {
            return Err(HttpError::ResponseTooLarge { limit: self.policy.max_response_bytes });
        }
        let status = String::from_utf8_lossy(&output.stdout).trim().parse();
        let status = status.map_err(|error| HttpError::Transport {
            message: format!("curl reported no status ({error}): {dumped}"),
        })?;
        Ok(HttpResponse { status, headers: parse_headers(&dumped), body })
    }
}

impl HttpClient for CurlHttpClient {
    fn policy(&self) -> &HttpPolicy {
        &self.policy
    }

    fn send<'a>(&'a self, req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse, HttpError>> {
        Box::pin(std::future::ready(self.curl(req)))
    }
}

/// A curl config value: quoted, with `\` and `"` escaped — the only two
/// characters its parser treats specially inside quotes, so a JSON body
/// round-trips as it stands.
fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// One scratch path per request per file kind.
fn scratch(tag: &str, kind: &str) -> String {
    std::env::temp_dir().join(format!("{kind}-{tag}")).display().to_string()
}

/// The header lines from a `--dump-header` block, folded as they arrived.
fn parse_headers(dumped: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in dumped.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with("HTTP/") {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim().to_string(), value.trim().to_string()));
        } else if let Some(last) = out.last_mut() {
            // Continuation: appended to the previous header's value.
            last.1.push(' ');
            last.1.push_str(line.trim());
        }
    }
    out
}
