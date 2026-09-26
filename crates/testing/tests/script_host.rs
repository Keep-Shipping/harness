//! Behaviour of the `ScriptHost` fake: the conformance fixtures, typed
//! output errors, secrets passed by name only, and dyn compatibility.

use std::collections::BTreeMap;

use ks_core::ports::script_host::{ScriptHost, ScriptHostError, ScriptRef, Value, ValueType};
use ks_core::ports::secrets::{SecretBundle, SecretValue};
use ks_testing::block_on;
use ks_testing::script_host::{
    FakeScriptHost, conformance as script_host_conformance, fixture_path, fixtures,
};

fn fixture_script(name: &str) -> ScriptRef {
    ScriptRef::new(format!("/fixtures/{name}.ts"))
}

#[test]
fn the_fake_passes_conformance_over_the_whole_fixture_set() {
    let host = FakeScriptHost::new().with_fixtures();
    block_on(script_host_conformance(&host, |fixture| ScriptRef::new(fixture_path(fixture.name))));
}

#[test]
fn a_wrong_typed_output_is_a_typed_error() {
    // Declares `x: String`, returns `x: Number` — the fixture bug, directly.
    let host = FakeScriptHost::new().with_script(
        &fixture_script("wrong-type"),
        fixtures().into_iter().find(|f| f.name == "wrong-type").expect("the fixture").schema,
        BTreeMap::from([("x".to_string(), Value::Number(7.0))]),
    );
    match block_on(host.run(&fixture_script("wrong-type"), &BTreeMap::new(), &SecretBundle::new()))
    {
        Err(ScriptHostError::OutputTypeMismatch { name, expected, found }) => {
            assert_eq!(name, "x");
            assert_eq!((expected, found), (ValueType::String, ValueType::Number));
        }
        other => panic!("expected OutputTypeMismatch, got {other:?}"),
    }
    // The message names the field and both types, so `check` can point at it.
    let message = ScriptHostError::OutputTypeMismatch {
        name: "x".to_string(),
        expected: ValueType::String,
        found: ValueType::Number,
    }
    .to_string();
    assert!(message.contains('x') && message.contains("string") && message.contains("number"));
}

#[test]
fn secrets_reach_the_script_by_name_only() {
    let schema =
        fixtures().into_iter().find(|f| f.name == "echo").expect("the echo fixture").schema;
    let host = FakeScriptHost::new().with_script_fn(&fixture_script("echo"), schema, |inputs| {
        BTreeMap::from([("greeting".to_string(), inputs["name"].clone())])
    });
    let inputs = BTreeMap::from([("name".to_string(), Value::from("app"))]);
    let mut secrets = SecretBundle::new();
    secrets.insert("deploy-token", SecretValue::new(b"hunter2".to_vec()));

    let outputs = block_on(host.run(&fixture_script("echo"), &inputs, &secrets))
        .expect("the echo script runs");
    assert_eq!(outputs["greeting"], Value::from("app"));

    // The fake records which names arrived — and never the values.
    assert_eq!(host.received_secret_names(), vec!["deploy-token".to_string()]);
    let debug = format!("{host:?}");
    assert!(!debug.contains("hunter2"), "{debug}");
}

#[test]
fn a_scripted_failure_comes_back_typed() {
    let host = FakeScriptHost::new().with_failure(
        &fixture_script("broken"),
        Default::default(),
        Some(3),
        "cannot find module",
    );
    let error =
        block_on(host.run(&fixture_script("broken"), &BTreeMap::new(), &SecretBundle::new()))
            .expect_err("the broken script fails");
    assert_eq!(
        error,
        ScriptHostError::ScriptFailed {
            exit_code: Some(3),
            message: "cannot find module".to_string()
        }
    );
}

#[test]
fn the_script_host_trait_is_dyn_compatible() {
    fn assert_send_sync<T: ?Sized + Send + Sync>() {}
    assert_send_sync::<dyn ScriptHost>();

    let host = FakeScriptHost::new().with_fixtures();
    let dynamic: &dyn ScriptHost = &host;
    let echo = ScriptRef::new(fixture_path("echo"));
    let schema = block_on(dynamic.schema(&echo)).expect("the fake knows the echo fixture");
    assert_eq!(schema.inputs.get("name"), Some(&ValueType::String));
    assert!(schema.outputs.contains_key("greeting"));
}
