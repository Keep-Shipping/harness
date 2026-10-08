//! What a step is given to talk to a cloud, and what the run log says about it
//! ([#71](https://github.com/Keep-Shipping/harness/issues/71)).
//!
//! Three properties, and the rest is detail. The plan and the apply federate into
//! **separate** roles, so a token for one cannot act as the other. A `role:` on a
//! CI job that cannot mint a token **fails** rather than falling back to the
//! job's long-lived keys. And the token **never reaches the log** — what reaches
//! it is cloud, role and `via`: enough to say which role a step held, not enough
//! to replay it.

use std::path::Path;
use std::sync::Arc;

use ks_core::ids::RunId;
use ks_core::ports::run_context::{Actor, ActorKind, Establishment};
use ks_core::ports::run_log::{RunEvent, RunLog};
use ks_core::ports::secrets::Redactor;
use ks_engine::credentials::{CloudRole, resolve};
use ks_engine::journal::Journal;
use ks_testing::block_on;
use ks_testing::run_context::FakeRunContext;
use ks_testing::run_log::RecordingRunLog;

/// The read-only role the plan step federates into.
const PLAN_ROLE: &str = "arn:aws:iam::123456789012:role/ks-plan";
/// The write role the apply step federates into.
const APPLY_ROLE: &str = "arn:aws:iam::123456789012:role/ks-apply";
/// The token the fake mints; it must appear in nothing that was recorded.
const TOKEN: &str = "eyJhbGciOi.federated-token-do-not-log";
/// Where an adapter would write the token before spawning the subprocess.
const TOKEN_FILE: &str = "/work/.ks/plan.token";

/// A CI actor, which is the only kind that can federate.
fn ci() -> Actor {
    Actor {
        kind: ActorKind::Ci,
        established: Establishment::CiOidc {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            subject: "repo:Keep-Shipping/harness:environment:prod".to_string(),
        },
        display_name: "github-actions".to_string(),
    }
}

/// An environment snapshot as a lookup closure, the way an adapter passes it.
fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let owned: Vec<(String, String)> =
        pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();
    move |name: &str| owned.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone())
}

/// A journal over a fresh recording fake.
fn journal() -> (Journal, Arc<RecordingRunLog>) {
    let log = Arc::new(RecordingRunLog::new());
    let run = RunId::from_parts(0, 1);
    (Journal::new(Arc::clone(&log) as Arc<dyn RunLog>, Arc::new(Redactor::new()), run), log)
}

/// The errors `ks_core::check` reports for a site file, as text.
fn check_errors(src: &str) -> Vec<String> {
    ks_core::check(&ks_lang::parse(src))
        .diagnostics
        .iter()
        .filter(|d| format!("{} {}", d.severity, d.message).contains("error"))
        .map(ToString::to_string)
        .collect()
}

#[test]
fn plan_and_apply_federate_into_separate_roles_and_the_token_is_never_logged() {
    let context = FakeRunContext::new().with_actor(ci()).with_oidc_token(TOKEN.as_bytes().to_vec());
    let plan_role = CloudRole::parse(PLAN_ROLE).expect("a plan role parses");
    let apply_role = CloudRole::parse(APPLY_ROLE).expect("an apply role parses");
    let (j, log) = journal();

    for (step, role) in [("plan", &plan_role), ("apply", &apply_role)] {
        let credentials =
            block_on(resolve(step, Some(role), Some(&context), &env_of(&[]))).expect("federates");
        block_on(j.credentials_resolved(step, &credentials)).expect("the log takes it");
    }

    let events = log.events();
    assert_eq!(events.len(), 2, "one credentials entry per step");
    let roles: Vec<Option<&str>> = events
        .iter()
        .map(|event| match event {
            RunEvent::CredentialsResolved { role, cloud, via, .. } => {
                assert_eq!((cloud.as_str(), via.as_str()), ("aws", "oidc"));
                role.as_deref()
            }
            other => panic!("not a credentials entry: {other:?}"),
        })
        .collect();
    assert_eq!(roles, vec![Some(PLAN_ROLE), Some(APPLY_ROLE)], "distinct roles, in order");
    // The token is a secret the log cannot hold: nothing Debug-formatted does.
    let shown = format!("{events:?}");
    assert!(!shown.contains(TOKEN), "the federated token reached the run log: {shown}");
}

#[test]
fn a_federated_aws_step_gets_the_role_and_the_token_file_never_the_token() {
    let context = FakeRunContext::new().with_actor(ci()).with_oidc_token(TOKEN.as_bytes().to_vec());
    let role = CloudRole::parse(PLAN_ROLE).expect("a plan role parses");
    let credentials =
        block_on(resolve("plan", Some(&role), Some(&context), &env_of(&[]))).expect("federates");

    let env = credentials.env(Path::new(TOKEN_FILE), "ks-plan");
    let get =
        |name: &str| env.iter().find(|(key, _)| *key == name).map(|(_, value)| value.as_str());
    assert_eq!(get("AWS_ROLE_ARN"), Some(PLAN_ROLE));
    assert_eq!(get("AWS_WEB_IDENTITY_TOKEN_FILE"), Some(TOKEN_FILE));
    assert_eq!(get("AWS_ROLE_SESSION_NAME"), Some("ks-plan"));
    for (name, value) in &env {
        assert!(!value.contains(TOKEN), "{name} carries the token, not just its path: {value}");
    }
    assert!(credentials.token().is_some(), "a federated step holds the token it minted");
}

#[test]
fn a_ci_job_that_cannot_mint_a_token_fails_rather_than_downgrading() {
    // A CI actor, but a context with no OIDC capability: the job's long-lived
    // keys are still there, and using them would be the silent downgrade.
    let context = FakeRunContext::new().with_actor(ci());
    let role = CloudRole::parse(APPLY_ROLE).expect("an apply role parses");

    let error =
        block_on(resolve("apply", Some(&role), Some(&context), &env_of(&[]))).expect_err("refused");
    let message = error.to_string();
    assert!(message.contains("apply"), "the message names the step: {message}");
    assert!(message.contains("id-token"), "the message says what to fix: {message}");
}

#[test]
fn a_local_run_uses_the_users_profile_and_assumes_no_role() {
    let context = FakeRunContext::new(); // human actor, no OIDC
    let role = CloudRole::parse(PLAN_ROLE).expect("a plan role parses");
    let credentials =
        block_on(resolve("plan", Some(&role), Some(&context), &env_of(&[("AWS_PROFILE", "dev")])))
            .expect("a local run does not fail, it just assumes nothing");

    assert_eq!(credentials.via(), "profile:dev");
    assert_eq!(credentials.role(), None, "nothing was assumed, so nothing is claimed");
    assert_eq!(credentials.cloud(), "aws");
    assert!(credentials.token().is_none(), "a local run mints no token");
    assert!(
        credentials.env(Path::new(TOKEN_FILE), "ks-plan").is_empty(),
        "nothing federated, so nothing for the subprocess to inherit"
    );
    // No context at all is a laptop, and says so rather than guessing.
    let none = block_on(resolve("plan", Some(&role), None, &env_of(&[]))).expect("local");
    assert_eq!((none.via(), none.role()), ("ambient", None));
}

#[test]
fn a_role_the_harness_cannot_federate_into_is_refused_by_name() {
    for bad in [
        "not-a-role",
        "arn:aws:iam::12345678901:role/short-account",
        "arn:aws:iam::123456789012:user/someone",
        "arn:aws:zz:iam::123456789012:role/x",
        "arn:aws:iam:us-east-1:123456789012:role/x",
        "12345678-1234-1234-1234",
    ] {
        let message = CloudRole::parse(bad).expect_err("refused").to_string();
        assert!(message.contains("role/<name>"), "{bad}: names the AWS shape");
        assert!(message.contains("GUID"), "{bad}: names the Azure shape");
        assert!(message.contains("GCP"), "{bad}: says GCP is not built yet");
    }
    // A GUID is an Azure client id, and its audience is Azure's, not STS's.
    let azure = CloudRole::parse("00000000-1234-1234-1234-123456789012").expect("a GUID parses");
    assert_eq!((azure.cloud(), azure.audience()), ("azure", "api://AzureADTokenExchange"));
    assert_eq!(CloudRole::parse(PLAN_ROLE).expect("an arn parses").audience(), "sts.amazonaws.com");
}

#[test]
fn a_role_on_the_plan_and_apply_steps_checks_clean() {
    let src = "\
name: infra
steps:
  plan:   tofu.plan
    dir:   ./infra/prod
    role:  arn:aws:iam::123456789012:role/ks-plan
  apply: tofu.apply
    plan:  plan.file
    role:  arn:aws:iam::123456789012:role/ks-apply
";
    assert!(check_errors(src).is_empty(), "`role:` is a declared input of both steps");

    // A typo is still a typo: `role` is the name, not `arn` or `roles`.
    let typo = check_errors(&src.replace("role:  arn", "roles: arn"));
    assert!(!typo.is_empty(), "an undeclared input is an error, not a warning");
}
