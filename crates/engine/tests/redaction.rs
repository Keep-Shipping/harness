//! The engine's redaction contract: every secret resolved for a step is
//! registered with the redactor before the step's output is read, so log
//! lines never carry secret bytes.

use ks_core::ids::StepId;
use ks_core::ports::secrets::{CheckSeverity, Redactor, SecretRef, SecretValue, SecretsError};
use ks_engine::secrets::resolve_step_secrets;
use ks_testing::{block_on, secrets};

fn refs() -> Vec<(String, SecretRef)> {
    vec![
        ("token".to_string(), SecretRef::new("env", "deploy-token")),
        ("password".to_string(), SecretRef::new("env", "db-password")),
    ]
}

#[test]
fn step_output_containing_a_secret_is_redacted() {
    let resolver = secrets::FakeSecrets::new()
        .with(SecretRef::new("env", "deploy-token"), b"s3cr3t-token".to_vec())
        .with(SecretRef::new("env", "db-password"), b"hunter2".to_vec());
    let step = StepId::new("deploy");
    let mut redactor = Redactor::new();

    let bundle = block_on(resolve_step_secrets(&resolver, &refs(), &step, &mut redactor))
        .expect("both secrets are scripted");

    // The step ran and printed a log line with both secrets embedded — the
    // token in the middle of a longer line, as it would be in real output.
    let raw_output = "deployed api:200 using token=s3cr3t-token (db password hunter2) ok";
    let logged = redactor.redact(raw_output);

    assert!(!logged.contains("s3cr3t-token"), "token leaked into the log: {logged}");
    assert!(!logged.contains("hunter2"), "password leaked into the log: {logged}");
    assert!(logged.contains("***"), "redactions should be visible: {logged}");
    assert_eq!(logged, "deployed api:200 using token=*** (db password ***) ok");

    // The bundle still hands the step its values.
    assert_eq!(
        bundle.get("token").expect("token is in the bundle").with_bytes(|bytes| bytes.to_vec()),
        b"s3cr3t-token".to_vec()
    );
    assert_eq!(
        bundle.get("password").expect("password is in the bundle").with_bytes(|bytes| bytes.len()),
        7
    );
    // And the fake saw both resolutions, for this step.
    assert_eq!(
        resolver.calls(),
        vec![
            (SecretRef::new("env", "deploy-token"), step.clone()),
            (SecretRef::new("env", "db-password"), step),
        ]
    );
}

#[test]
fn a_partially_failed_resolution_still_registers_what_resolved() {
    let resolver = secrets::FakeSecrets::new()
        .with(SecretRef::new("env", "deploy-token"), b"s3cr3t-token".to_vec())
        .unavailable(SecretRef::new("env", "db-password"), "wrong branch");
    let mut redactor = Redactor::new();

    let error =
        block_on(resolve_step_secrets(&resolver, &refs(), &StepId::new("deploy"), &mut redactor))
            .expect_err("db-password is scripted unavailable");

    // The failure is reported, not crashed on — and the first secret is
    // already registered, so output from this point on is still scrubbed.
    assert!(matches!(error, SecretsError::NotAvailableInContext { .. }), "{error:?}");
    assert_eq!(redactor.redact("token=s3cr3t-token"), "token=***");
}

#[test]
fn not_available_in_context_is_a_warning_not_a_crash() {
    let reference = SecretRef::new("env", "db-password");
    let resolver = secrets::FakeSecrets::new().unavailable(reference.clone(), "wrong branch");
    let refs = vec![("password".to_string(), reference.clone())];
    let mut redactor = Redactor::new();

    // Checker #34 reports this as a warning: the error carries the severity,
    // and nothing in the resolution path panics.
    let error =
        block_on(resolve_step_secrets(&resolver, &refs, &StepId::new("deploy"), &mut redactor))
            .expect_err("the secret is unavailable");
    assert_eq!(error.check_severity(), CheckSeverity::Warning);
    match &error {
        SecretsError::NotAvailableInContext { reference: reported, reason } => {
            assert_eq!(*reported, reference);
            assert_eq!(reason, "wrong branch");
        }
        other => panic!("expected NotAvailableInContext, got {other:?}"),
    }
}

#[test]
fn debug_output_of_the_bundle_never_shows_values() {
    let resolver = secrets::FakeSecrets::new()
        .with(SecretRef::new("env", "deploy-token"), b"s3cr3t-token".to_vec());
    let refs = vec![("token".to_string(), SecretRef::new("env", "deploy-token"))];
    let mut redactor = Redactor::new();
    let bundle =
        block_on(resolve_step_secrets(&resolver, &refs, &StepId::new("deploy"), &mut redactor))
            .expect("the secret is scripted");
    let debug = format!("{bundle:?}");
    assert!(!debug.contains("s3cr3t-token"), "bundle debug leaked the secret: {debug}");
}

/// A value wrapped here is what the engine registers; this guards the
/// `SecretValue` contract the engine relies on: no `Display`, `Debug` is `***`.
#[test]
fn resolved_values_do_not_print_their_bytes() {
    let value = SecretValue::new(b"s3cr3t-token".to_vec());
    assert_eq!(format!("{value:?}"), "***");
}
