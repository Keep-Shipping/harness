//! What a signature has to be before anyone believes it
//! ([#61](https://github.com/Keep-Shipping/harness/issues/61)).
//!
//! Three properties, and the rest is detail. A signature **names who signed** —
//! a keyless CI identity or a named key, never an anonymous one. It is
//! **bound to the digest** it was made for, so copying it onto another image
//! verifies for nothing. And it is **reported only after it comes back off the
//! registry and verifies**, so `signed: true` means a third party could check
//! it, not that the push call returned.
//!
//! The refusals are as much the contract as the acceptances: unsigned,
//! unverifiable and signed-by-somebody-else each fail differently, because each
//! calls for a different fix. [`SignedBy::parse`] covers the matcher grammar a
//! workflow file writes by hand.

use std::sync::Arc;

use ks_core::harness::Harness;
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::secrets::Redactor;
use ks_core::ports::supply_chain::{
    ArtifactUpload, Descriptor, Digest, OciLayoutContents, Registry, RegistryError, Signer,
};
use ks_core::step::{CancellationToken, LogRecord, LogSink, Port, Ports, StepLog, TypeDef};
use ks_engine::run::run_step;
use ks_engine::signing::{
    SignedBy, SignedByError, identity_text, is_local, sign_and_attach, simple_signing_payload,
    verify_signed,
};
use ks_testing::clock::FakeClock;
use ks_testing::supply_chain::{FakeRegistry, FakeSigner};
use ks_testing::{block_on, step::step_conformance};

/// The repository every scenario signs into.
const REPOSITORY: &str = "registry.example/team/app";

/// A real image manifest, so the digest under test is a real SHA-256.
const MANIFEST: &[u8] = b"{\"schemaVersion\":2,\"config\":{}}";

/// A digest nothing has ever signed: thirty-two `cd` pairs (a canonical
/// SHA-256 hex string, sixty-four characters).
const STRANGER: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

/// A [`LogSink`] that keeps every record, for the one log-line assertion.
#[derive(Default)]
struct RecordingSink {
    records: std::sync::Mutex<Vec<LogRecord>>,
}

impl LogSink for RecordingSink {
    fn record(&self, record: LogRecord) {
        self.records.lock().expect("recording sink").push(record);
    }
}

/// Pushes the image every scenario verifies, and returns its digest.
fn seeded() -> (Arc<FakeRegistry>, Digest) {
    let registry = Arc::new(FakeRegistry::new());
    let descriptor = block_on(registry.push_layout(
        REPOSITORY,
        &OciLayoutContents {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            manifest: MANIFEST.to_vec(),
            blobs: vec![b"layer".to_vec()],
        },
    ))
    .expect("the image push succeeds");
    (registry, descriptor.digest)
}

/// Copies the signature referrer of `from` onto `to`, exactly as a registry
/// that lost track of its subjects — or somebody copying a referrer by hand —
/// would leave it.
fn copy_signature(registry: &FakeRegistry, from: &Digest, to: &Digest) {
    let referrers = block_on(registry.referrers(REPOSITORY, from)).expect("referrers work");
    let source = referrers.first().expect("the source digest has a signature on it").clone();
    let upload = ArtifactUpload {
        media_type: source.media_type.clone(),
        artifact_type: "application/vnd.dev.cosign.artifact.sig.v1+json".to_string(),
        blobs: vec![simple_signing_payload(REPOSITORY, from)],
        annotations: source.annotations,
        subject: Some(to.clone()),
    };
    block_on(registry.push_artifact(REPOSITORY, &upload)).expect("the copy push succeeds");
}

/// Pushes the one signature referrer a scenario needs, with `signature` as the
/// base64 signature annotation. The identity annotations name `alice-laptop`,
/// so a tampered blob is a referrer that claims alice but does not carry her
/// signature — and the only referrer on the digest, so the valid one a
/// `sign_and_attach` would leave alongside it cannot verify first.
fn push_signature_referrer(registry: &FakeRegistry, digest: &Digest, signature: &str) {
    let mut annotations = std::collections::BTreeMap::new();
    annotations.insert("dev.cosignproject.cosign/signature".to_string(), signature.to_string());
    annotations.insert("dev.keepshipping.signature/identity-kind".to_string(), "key".to_string());
    annotations.insert("dev.keepshipping.signature/key-id".to_string(), "alice-laptop".to_string());
    annotations.insert("dev.keepshipping.signature/local".to_string(), "true".to_string());
    let upload = ArtifactUpload {
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        artifact_type: "application/vnd.dev.cosign.artifact.sig.v1+json".to_string(),
        blobs: vec![simple_signing_payload(REPOSITORY, digest)],
        annotations,
        subject: Some(digest.clone()),
    };
    block_on(registry.push_artifact(REPOSITORY, &upload)).expect("the referrer lands");
}

#[test]
fn the_payload_is_byte_for_byte_deterministic_and_binds_the_digest() {
    let (_, digest) = seeded();
    let payload = simple_signing_payload(REPOSITORY, &digest);
    assert_eq!(
        String::from_utf8(payload.clone()).expect("the payload is text"),
        format!(
            r#"{{"critical":{{"identity":{{"docker-reference":"{REPOSITORY}"}},"image":{{"docker-manifest-digest":"{digest}"}},"type":"cosign container image signature"}},"optional":null}}"#
        ),
        "the payload is the cosign simple-signing document, byte for byte",
    );
    assert_eq!(payload, simple_signing_payload(REPOSITORY, &digest), "and it is deterministic");

    let stranger = Digest::parse(&format!("sha256:{STRANGER}")).expect("canonical digest");
    assert_ne!(
        payload,
        simple_signing_payload(REPOSITORY, &stranger),
        "a different digest is a different payload, so a signature cannot be reused across them"
    );
}

#[test]
fn a_local_key_signature_verifies_against_the_local_public_key() {
    let (registry, digest) = seeded();
    let signer = FakeSigner::with_key("alice-laptop");

    let signed = block_on(sign_and_attach(&signer, &*registry, REPOSITORY, &digest, true))
        .expect("a local signature attaches");
    assert!(signed.signed);
    assert!(signed.local, "a key on a laptop is a local signature");
    assert_eq!(
        signed.identity,
        ks_core::ports::supply_chain::SignerIdentity::Key { key_id: "alice-laptop".to_string() }
    );

    let verified = block_on(verify_signed(
        &signer,
        &*registry,
        REPOSITORY,
        &digest,
        &SignedBy::parse("key:alice-laptop").expect("a key matcher"),
    ))
    .expect("A local signature verifies against the local public key");
    assert_eq!(identity_text(&verified), "key:alice-laptop");
}

#[test]
fn a_ci_keyless_signature_verifies_as_the_workflow_that_made_it() {
    let (registry, digest) = seeded();
    let signer = FakeSigner::keyless(
        "https://token.actions.githubusercontent.com",
        "repo:Keep-Shipping/harness:ref:refs/heads/main",
    );

    let signed = block_on(sign_and_attach(&signer, &*registry, REPOSITORY, &digest, false))
        .expect("a keyless signature attaches");
    assert!(signed.signed);
    assert!(!signed.local, "a CI workflow identity is not a local signature");

    let verified = block_on(verify_signed(
        &signer,
        &*registry,
        REPOSITORY,
        &digest,
        &SignedBy::parse(
            "signed-by repo:Keep-Shipping/harness:ref:refs/heads/main from \
                          https://token.actions.githubusercontent.com",
        )
        .expect("a keyless matcher"),
    ))
    .expect("a keyless signature verifies against its issuer and subject");
    assert!(identity_text(&verified).ends_with("from https://token.actions.githubusercontent.com"));
}

#[test]
fn signing_logs_who_signed_and_whether_it_was_local() {
    let (registry, digest) = seeded();
    let signer = FakeSigner::with_key("alice-laptop");
    let signed = block_on(sign_and_attach(&signer, &*registry, REPOSITORY, &digest, true))
        .expect("the signature attaches");

    let sink = Arc::new(RecordingSink::default());
    ks_engine::signing::log_signature(
        &StepLog::new("build", Arc::new(Redactor::new()), sink.clone() as Arc<dyn LogSink>),
        &signed,
    );
    let records = sink.records.lock().expect("recording sink").clone();
    let record = records.first().expect("the signature logged one line");
    assert!(
        record.message.contains("key:alice-laptop") && record.message.contains("(local signature)"),
        "the line names the signer and marks it local: {}",
        record.message,
    );
}

#[test]
fn an_unsigned_digest_is_refused_as_unsigned() {
    let (registry, digest) = seeded();
    let signer = FakeSigner::with_key("alice-laptop");
    let error = block_on(verify_signed(
        &signer,
        &*registry,
        REPOSITORY,
        &digest,
        &SignedBy::parse("key:alice-laptop").expect("a key matcher"),
    ))
    .expect_err("nothing signed this digest");
    assert_eq!(error.to_string(), format!("step failed: {digest} is unsigned"));
}

#[test]
fn a_signature_by_somebody_else_names_both_identities() {
    let (registry, digest) = seeded();
    let signer = FakeSigner::with_key("alice-laptop");
    block_on(sign_and_attach(&signer, &*registry, REPOSITORY, &digest, true))
        .expect("the signature attaches");

    let error = block_on(verify_signed(
        &signer,
        &*registry,
        REPOSITORY,
        &digest,
        &SignedBy::parse("key:mallory").expect("a key matcher"),
    ))
    .expect_err("alice is not mallory");
    assert_eq!(
        error.to_string(),
        format!("step failed: {digest} is signed by key:alice-laptop, not by key:mallory"),
        "a wrong signer names who signed and who was expected, so the fix is obvious",
    );
}

#[test]
fn a_signature_copied_onto_another_digest_does_not_verify() {
    let (registry, digest) = seeded();
    let signer = FakeSigner::with_key("alice-laptop");
    block_on(sign_and_attach(&signer, &*registry, REPOSITORY, &digest, true))
        .expect("the signature attaches");

    let stranger = Digest::parse(&format!("sha256:{STRANGER}")).expect("canonical digest");
    copy_signature(&registry, &digest, &stranger);

    let error = block_on(verify_signed(
        &signer,
        &*registry,
        REPOSITORY,
        &stranger,
        &SignedBy::parse("key:alice-laptop").expect("a key matcher"),
    ))
    .expect_err("alice signed the other image");
    assert_eq!(
        error.to_string(),
        format!("step failed: the signature on {stranger} does not verify"),
        "the referrer moved, the payload it covers did not",
    );
}

#[test]
fn a_tampered_signature_annotation_is_refused() {
    let (registry, digest) = seeded();
    let signer = FakeSigner::with_key("alice-laptop");

    // A byte flipped in the base64 blob: still decodes, still claims alice,
    // and no longer is her signature. It is the only referrer on the digest,
    // so a valid one left by `sign_and_attach` cannot verify first.
    push_signature_referrer(&registry, &digest, "AAAAAAAA");
    let error = block_on(verify_signed(
        &signer,
        &*registry,
        REPOSITORY,
        &digest,
        &SignedBy::parse("key:alice-laptop").expect("a key matcher"),
    ))
    .expect_err("the rewritten bytes are not alice's signature");
    assert_eq!(
        error.to_string(),
        format!("step failed: the signature on {digest} does not verify"),
    );
}

#[test]
fn a_registry_that_refuses_the_push_is_not_signed() {
    let registry = Arc::new(FakeRegistry::new().unauthorized(REPOSITORY));
    let signer = FakeSigner::with_key("alice-laptop");
    let (_, digest) = seeded();
    let error = block_on(sign_and_attach(&signer, &*registry, REPOSITORY, &digest, true))
        .expect_err("the registry refused the push");
    assert!(
        matches!(error, ks_core::step::StepError::Port { port: Port::Registry, .. }),
        "the refusal is the registry's, not a step failure: {error}",
    );
    assert!(error.to_string().contains("not authorized"), "{error}");
}

#[test]
fn a_registry_that_drops_the_referrer_is_not_signed() {
    // The push succeeds but nothing refers back to the digest, which is what a
    // registry that does not honour referrers looks like from here.
    struct ForgetfulRegistry(Arc<FakeRegistry>);

    impl Registry for ForgetfulRegistry {
        fn resolve<'a>(
            &'a self,
            image: &'a ks_core::ports::supply_chain::ImageRef,
        ) -> ks_core::ports::BoxFuture<'a, Result<Digest, RegistryError>> {
            self.0.resolve(image)
        }
        fn push_layout<'a>(
            &'a self,
            repository: &'a str,
            layout: &'a OciLayoutContents,
        ) -> ks_core::ports::BoxFuture<'a, Result<Descriptor, RegistryError>> {
            self.0.push_layout(repository, layout)
        }
        fn push_artifact<'a>(
            &'a self,
            repository: &'a str,
            upload: &'a ArtifactUpload,
        ) -> ks_core::ports::BoxFuture<'a, Result<Descriptor, RegistryError>> {
            // Deliberately drops the `subject`, so the referrer lands nowhere.
            let mut upload = upload.clone();
            upload.subject = None;
            Box::pin(async move { self.0.push_artifact(repository, &upload).await })
        }
        fn pull<'a>(
            &'a self,
            repository: &'a str,
            digest: &'a Digest,
        ) -> ks_core::ports::BoxFuture<'a, Result<Vec<u8>, RegistryError>> {
            self.0.pull(repository, digest)
        }
        fn referrers<'a>(
            &'a self,
            repository: &'a str,
            digest: &'a Digest,
        ) -> ks_core::ports::BoxFuture<'a, Result<Vec<Descriptor>, RegistryError>> {
            self.0.referrers(repository, digest)
        }
        fn exists<'a>(
            &'a self,
            repository: &'a str,
            digest: &'a Digest,
        ) -> ks_core::ports::BoxFuture<'a, Result<bool, RegistryError>> {
            self.0.exists(repository, digest)
        }
        fn tag<'a>(
            &'a self,
            repository: &'a str,
            tag: &'a str,
            digest: &'a Digest,
        ) -> ks_core::ports::BoxFuture<'a, Result<(), RegistryError>> {
            self.0.tag(repository, tag, digest)
        }
    }

    let (inner, digest) = seeded();
    let registry = Arc::new(ForgetfulRegistry(inner.clone()));
    let signer = FakeSigner::with_key("alice-laptop");
    let error = block_on(sign_and_attach(&signer, &*registry, REPOSITORY, &digest, true))
        .expect_err("the signature never came back");
    assert!(error.to_string().contains("not signed"), "{error}");
}

#[test]
fn a_signed_by_matcher_says_what_it_wants() {
    assert_eq!(
        SignedBy::parse("key:alice-laptop").expect("a key matcher").to_string(),
        "key:alice-laptop",
    );
    assert_eq!(
        SignedBy::parse(" signed-by key:alice-laptop ").expect("a deploy step's value").to_string(),
        "key:alice-laptop",
        "the prefix a deploy step's `verify:` carries is accepted verbatim",
    );
    assert_eq!(
        SignedBy::parse("workflow from https://issuer.example")
            .expect("a keyless matcher")
            .to_string(),
        "workflow from https://issuer.example",
    );
    assert_eq!(
        SignedBy::parse("a from b from c").expect("the last ` from ` splits"),
        SignedBy::parse("a from b from c").unwrap(),
    );
    assert_eq!(SignedBy::parse("  "), Err(SignedByError::Empty), "an empty matcher names nobody",);
    assert_eq!(SignedBy::parse("key:"), Err(SignedByError::MissingKeyId));
    assert_eq!(
        SignedBy::parse("alice"),
        Err(SignedByError::Unrecognised),
        "half a keyless identity is not a matcher",
    );
    assert_eq!(SignedBy::parse(" from https://issuer.example"), Err(SignedByError::MissingSubject));
    assert_eq!(SignedBy::parse("workflow from "), Err(SignedByError::MissingIssuer));
    assert!(
        SignedByError::MissingIssuer.to_string().contains("issuer"),
        "the error says what is missing: {}",
        SignedByError::MissingIssuer,
    );
}

/// The harness the `oci.verify` step runs under.
fn harness_with(registry: &Arc<FakeRegistry>, signer: Arc<dyn Signer>) -> Harness {
    Harness::builder()
        .ports(
            Ports::default()
                .with_clock(Arc::new(FakeClock::new()))
                .with_registry(Arc::clone(registry) as Arc<dyn Registry>)
                .with_signer(signer),
        )
        .type_def(TypeDef {
            name: "digest",
            base: ValueType::String,
            doc: "an OCI digest (`sha256:…`)",
        })
        .step(ks_engine::oci_verify::OciVerify)
        .build()
        .expect("the composition is valid")
}

#[test]
fn the_verify_step_passes_a_correctly_signed_image() {
    let (registry, digest) = seeded();
    block_on(sign_and_attach(
        &FakeSigner::with_key("alice-laptop"),
        &*registry,
        REPOSITORY,
        &digest,
        true,
    ))
    .expect("the signature attaches");
    let harness = harness_with(&registry, Arc::new(FakeSigner::with_key("alice-laptop")));

    let mut inputs = ks_core::step::Inputs::new();
    inputs.insert("image".to_string(), Value::from(format!("{REPOSITORY}@{digest}")));
    inputs.insert("signed_by".to_string(), Value::from("signed-by key:alice-laptop"));
    let outputs = block_on(run_step(
        &harness,
        "oci.verify",
        inputs,
        CancellationToken::new(),
        Arc::new(RecordingSink::default()) as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
    ))
    .expect("the step verifies");

    assert_eq!(outputs.get("digest"), Some(&Value::from(digest.to_string())));
    assert_eq!(outputs.get("identity"), Some(&Value::from("key:alice-laptop")));
}

#[test]
fn the_verify_step_refuses_an_unsigned_image() {
    let (registry, digest) = seeded();
    let harness = harness_with(&registry, Arc::new(FakeSigner::with_key("alice-laptop")));

    let mut inputs = ks_core::step::Inputs::new();
    inputs.insert("image".to_string(), Value::from(format!("{REPOSITORY}@{digest}")));
    inputs.insert("signed_by".to_string(), Value::from("key:alice-laptop"));
    let error = block_on(run_step(
        &harness,
        "oci.verify",
        inputs,
        CancellationToken::new(),
        Arc::new(RecordingSink::default()) as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
    ))
    .expect_err("nothing signed this image");
    assert!(error.to_string().contains("is unsigned"), "{error}");
}

#[test]
fn the_verify_step_refuses_a_tag_rather_than_verifying_whatever_it_points_at() {
    let (registry, digest) = seeded();
    block_on(registry.tag(REPOSITORY, "v1", &digest)).expect("the tag lands");
    let harness = harness_with(&registry, Arc::new(FakeSigner::with_key("alice-laptop")));

    let mut inputs = ks_core::step::Inputs::new();
    inputs.insert("image".to_string(), Value::from(format!("{REPOSITORY}:v1")));
    inputs.insert("signed_by".to_string(), Value::from("key:alice-laptop"));
    let error = block_on(run_step(
        &harness,
        "oci.verify",
        inputs,
        CancellationToken::new(),
        Arc::new(RecordingSink::default()) as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
    ))
    .expect_err("a tag is not something to verify");
    assert!(
        matches!(error, ks_core::step::StepError::InvalidInput { ref field, .. } if field == "image"),
        "the input is what is wrong, not the image: {error}",
    );
}

#[test]
fn the_verify_step_passes_the_step_conformance_kit() {
    let (registry, digest) = seeded();
    block_on(sign_and_attach(
        &FakeSigner::with_key("alice-laptop"),
        &*registry,
        REPOSITORY,
        &digest,
        true,
    ))
    .expect("the signature attaches");
    let harness = harness_with(&registry, Arc::new(FakeSigner::with_key("alice-laptop")));

    let mut inputs = ks_core::step::Inputs::new();
    inputs.insert("image".to_string(), Value::from(format!("{REPOSITORY}@{digest}")));
    inputs.insert("signed_by".to_string(), Value::from("key:alice-laptop"));
    block_on(step_conformance(&harness, ks_testing::step::StepCase::new("oci.verify", inputs)));
}

#[test]
fn locality_comes_from_the_run_context_when_there_is_one() {
    use ks_core::ports::BoxFuture;
    use ks_core::ports::run_context::{
        Actor, ActorKind, Establishment, RunContext, RunContextError, Workspace,
    };
    use ks_core::ports::secrets::SecretValue;
    use ks_core::ports::supply_chain::SignerIdentity;
    use ks_testing::run_context::FakeRunContext;

    let key = SignerIdentity::Key { key_id: "alice-laptop".into() };
    let keyless = SignerIdentity::Keyless {
        issuer: "https://issuer.example".into(),
        subject: "workflow".into(),
    };
    let ci = Actor {
        kind: ActorKind::Ci,
        established: Establishment::CiOidc {
            issuer: "https://issuer.example".into(),
            subject: "workflow".into(),
        },
        display_name: "github-actions".into(),
    };
    let laptop = Actor {
        kind: ActorKind::Human,
        established: Establishment::LocalGitConfig,
        display_name: "alice".into(),
    };
    let context = |actor: Actor| FakeRunContext::new().with_actor(actor);

    // Without the port there is nobody to ask, so the identity answers for itself.
    assert!(is_local(&key, None), "a key is a person's");
    assert!(!is_local(&keyless, None), "a keyless identity exists because CI certified it");
    // With it, CI is CI whatever the signer says, and a laptop is a laptop.
    assert!(!is_local(&key, Some(&context(ci.clone()))), "on CI even a key is the runner's");
    assert!(is_local(&key, Some(&context(laptop.clone()))), "at a laptop a key is local");
    assert!(!is_local(&keyless, Some(&context(ci))));
    assert!(is_local(&keyless, Some(&context(laptop.clone()))), "a laptop run is local");

    // Named so the assertion above is about the port, not about a trait object
    // that happens to satisfy it.
    fn takes_port(_: &dyn RunContext) {}
    takes_port(&context(laptop));
    let _: Option<&dyn RunContext> = None;
    let _: Option<SecretValue> = None;
    let _: Option<BoxFuture<'static, Result<SecretValue, RunContextError>>> = None;
    let _: Option<Workspace> = None;
}
