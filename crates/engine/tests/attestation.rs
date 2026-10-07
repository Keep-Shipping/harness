//! Attestations end to end ([#63](https://github.com/Keep-Shipping/harness/issues/63)): a
//! provenance statement says what built the image and names the run, the `ship.ks`, the commit
//! and the pinned builder; an SBOM statement wraps a document the generator produced; both are
//! signed as DSSE envelopes and pushed against the image digest, so `referrers` lists them.

use std::sync::Arc;

use ks_core::ports::supply_chain::{
    Digest, Registry, SignPayload, Signature, Signer, SignerIdentity,
};
use ks_engine::attestation::{
    AttestError, DSSE_ENVELOPE, DSSE_PAYLOAD_TYPE, OCI_IMAGE_BUILD_TYPE, PREDICATE_TYPE_ANNOTATION,
    Provenance, SLSA_PROVENANCE, SPDX_DOCUMENT, STATEMENT_TYPE, Subject, attach, base64, pae,
    provenance, sbom, sign,
};
use ks_testing::block_on;
use ks_testing::supply_chain::{FakeRegistry, FakeSigner};
use serde_json::Value;

/// Where the image and everything about it lives.
const REPOSITORY: &str = "ghcr.io/acme/api";
/// The image as `oci.image` returned it: an index digest over the platforms built.
const DIGEST_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn image() -> Digest {
    Digest::parse(&format!("sha256:{DIGEST_HEX}")).expect("canonical digest")
}

fn subject() -> Subject {
    Subject::image(REPOSITORY, &image()).expect("a sha256 image digest")
}

fn build() -> Provenance {
    Provenance {
        step: "build".into(),
        run: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        commit: "9fceb02d0ae8f1c1e0b0d2a8b1e2d3c4b5a69788".into(),
        git_ref: "refs/heads/main".into(),
        file_sha256: "cd".repeat(32),
        builder_id: "keepshipping-buildkit-v0.33.1".into(),
    }
}

/// The value of a dotted path, so an assertion names what it is looking at. A numeric segment
/// indexes the array it lands in — `subject.0.name` is the first subject's name.
fn at(value: &Value, path: &str) -> String {
    let mut cursor = value;
    for key in path.split('.') {
        cursor = match cursor {
            Value::Array(items) => &items[key.parse::<usize>().expect("a numeric path segment")],
            other => &other[key],
        };
    }
    cursor.as_str().unwrap_or_else(|| panic!("{path} is not a string in the statement")).to_string()
}

#[test]
fn provenance_names_the_run_the_commit_the_file_and_the_builder() {
    let statement = provenance(subject(), &build());
    let value = serde_json::from_slice::<Value>(&statement.to_bytes()).expect("json");

    assert_eq!(at(&value, "_type"), STATEMENT_TYPE);
    assert_eq!(at(&value, "predicateType"), SLSA_PROVENANCE);
    assert_eq!(at(&value, "subject.0.name"), REPOSITORY);
    assert_eq!(at(&value, "subject.0.digest.sha256"), DIGEST_HEX);
    assert_eq!(at(&value, "predicate.buildDefinition.buildType"), OCI_IMAGE_BUILD_TYPE);
    assert_eq!(at(&value, "predicate.buildDefinition.externalParameters.step"), "build");
    assert_eq!(
        at(&value, "predicate.buildDefinition.externalParameters.shipFile.sha256"),
        "cd".repeat(32)
    );
    assert_eq!(
        at(&value, "predicate.buildDefinition.resolvedDependencies.0.digest.gitCommit"),
        build().commit
    );
    assert_eq!(
        at(&value, "predicate.buildDefinition.resolvedDependencies.0.uri"),
        "git+refs/heads/main"
    );
    assert_eq!(at(&value, "predicate.runDetails.builder.id"), "keepshipping-buildkit-v0.33.1");
    assert_eq!(at(&value, "predicate.runDetails.metadata.invocationId"), build().run);
}

/// The bytes that get signed have their keys sorted, so a signature over them does not depend
/// on the order `serde_json` happened to put them in.
#[test]
fn the_signed_bytes_are_canonical() {
    let bytes = provenance(subject(), &build()).to_canonical();
    let order: Vec<usize> = ["\"_type\"", "\"predicate\"", "\"predicateType\"", "\"subject\""]
        .iter()
        .map(|key| bytes.find(key).unwrap_or_else(|| panic!("{key} is missing")))
        .collect();
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "not sorted: {order:?} in {bytes}");
}

#[test]
fn the_pae_is_the_one_the_dsse_spec_describes() {
    // The worked example from the DSSE specification: type and body both 12 bytes.
    assert_eq!(
        pae("http://example.com/HelloWorld", "hello world"),
        "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    );
    // A statement's PAE is its type and body, never the base64 payload.
    assert_eq!(pae(DSSE_PAYLOAD_TYPE, "hi"), "DSSEv1 28 application/vnd.in-toto+json 2 hi");
}

#[test]
fn an_sbom_statement_wraps_the_document_it_was_given() {
    let document = br#"{"spdxVersion":"SPDX-2.3","name":"acme-api","packages":[]}"#;
    let statement = sbom(subject(), document).expect("a json document");
    let value = serde_json::from_slice::<Value>(&statement.to_bytes()).expect("json");

    assert_eq!(statement.predicate_type, SPDX_DOCUMENT);
    assert_eq!(at(&value, "predicate.name"), "acme-api");
    // The document is parsed into the statement, not smuggled as a string.
    assert_eq!(value["predicate"]["packages"], serde_json::json!([]));
    let refused = sbom(subject(), b"not json").expect_err("a document that is not JSON is refused");
    assert!(matches!(refused, AttestError::Sbom { .. }), "got {refused:?}");
}

#[test]
fn the_signature_verifies_over_the_pae_of_the_statement_bytes() {
    let statement = provenance(subject(), &build());
    let signer = FakeSigner::with_key("cosign-key");
    let envelope = block_on(sign(&signer, &statement)).expect("sign");

    assert_eq!(envelope.payload_type, DSSE_PAYLOAD_TYPE);
    assert_eq!(envelope.signatures[0].keyid, "cosign-key");

    // What the payload carries is the statement's own bytes, and what the signature covers is
    // the PAE of those bytes — which a verifier can rebuild without re-serializing anything.
    let body = statement.to_canonical();
    assert_eq!(envelope.payload, base64(body.as_bytes()));
    let signed = pae(DSSE_PAYLOAD_TYPE, &body);
    let expected =
        block_on(signer.sign(&SignPayload::Bytes(signed.clone().into_bytes()))).expect("sign");
    assert_eq!(envelope.signatures[0].sig, base64(&expected.bytes), "over the PAE: {signed}");

    // And the fake agrees the signature and the payload belong together.
    let verified = block_on(signer.verify(
        &SignPayload::Bytes(signed.into_bytes()),
        &Signature { bytes: expected.bytes, identity: expected.identity },
    ))
    .expect("the envelope verifies");
    assert_eq!(verified, SignerIdentity::Key { key_id: "cosign-key".into() });
}

#[test]
fn a_keyless_identity_names_its_issuer_as_well_as_its_subject() {
    let signer = FakeSigner::keyless("https://token.actions.githubusercontent.com", "workflow");
    let envelope = block_on(sign(&signer, &provenance(subject(), &build()))).expect("sign");
    assert_eq!(
        envelope.signatures[0].keyid,
        "https://token.actions.githubusercontent.com#workflow"
    );
}

/// An image is named under sha256 in an in-toto digest map, so a sha512 digest is refused at
/// the point it would otherwise be filed under the wrong algorithm.
#[test]
fn a_subject_is_only_built_from_a_sha256_digest() {
    let sha512 = Digest::parse(&format!("sha512:{}", "ab".repeat(64))).expect("canonical");
    let refused = Subject::image(REPOSITORY, &sha512).expect_err("sha512 is not a sha256");
    assert!(refused.to_string().contains("sha512"), "{refused}");
}

#[test]
fn attach_pushes_an_envelope_that_referrers_lists_under_the_image() {
    let registry = Arc::new(FakeRegistry::new());
    let signer = FakeSigner::with_key("cosign-key");
    let statement = provenance(subject(), &build());
    let digest =
        block_on(attach(&*registry, REPOSITORY, &signer, &subject(), &statement)).expect("attach");

    let referrers = block_on(registry.referrers(REPOSITORY, &image())).expect("referrers");
    assert_eq!(referrers.len(), 1, "the envelope refers to the image: {referrers:?}");
    assert_eq!(referrers[0].digest, digest);
    assert_eq!(referrers[0].media_type, DSSE_ENVELOPE);
    assert_eq!(
        referrers[0].annotations.get(PREDICATE_TYPE_ANNOTATION).map(String::as_str),
        Some(SLSA_PROVENANCE),
        "the predicate is recorded where a referrers listing can read it"
    );

    // The envelope is the layer the manifest points at, so the pushed manifest names its digest.
    let manifest = String::from_utf8(block_on(registry.pull(REPOSITORY, &digest)).expect("pull"))
        .expect("utf-8");
    let layer = registry.stored_digests(REPOSITORY);
    assert!(
        manifest.contains("artifactType\":\"application/vnd.dsse.envelope.v1+json"),
        "the artifact type is the envelope's: {manifest}"
    );
    assert!(
        layer.iter().any(|stored| manifest.contains(&format!("{stored}"))),
        "the manifest carries the envelope layer's digest: {manifest}"
    );
    assert_eq!(registry.stored_digests(REPOSITORY).len(), 2, "a manifest and one layer");
}

#[test]
fn two_attestations_of_the_same_image_are_two_referrers() {
    let registry = Arc::new(FakeRegistry::new());
    let signer = FakeSigner::with_key("cosign-key");
    for statement in [
        provenance(subject(), &build()),
        sbom(subject(), br#"{"spdxVersion":"SPDX-2.3"}"#).unwrap(),
    ] {
        block_on(attach(&*registry, REPOSITORY, &signer, &subject(), &statement)).expect("attach");
    }
    assert_eq!(
        block_on(registry.referrers(REPOSITORY, &image())).expect("referrers").len(),
        2,
        "provenance and an SBOM sit side by side, neither hiding the other"
    );
}

#[test]
fn a_registry_that_refuses_the_push_is_not_swallowed() {
    let registry = FakeRegistry::new().unauthorized(REPOSITORY);
    let signer = FakeSigner::with_key("cosign-key");
    let outcome = block_on(attach(
        &registry,
        REPOSITORY,
        &signer,
        &subject(),
        &provenance(subject(), &build()),
    ))
    .expect_err("an unauthorized repository fails the attach");
    assert!(matches!(outcome, AttestError::Registry(_)), "got {outcome:?}");
}

#[test]
fn a_subject_that_is_not_a_digest_is_refused_before_anything_is_pushed() {
    let registry = FakeRegistry::new();
    let signer = FakeSigner::with_key("cosign-key");
    let bad = Subject { name: REPOSITORY.into(), sha256: "not-a-digest".into() };
    let outcome =
        block_on(attach(&registry, REPOSITORY, &signer, &bad, &provenance(bad.clone(), &build())))
            .expect_err("a subject with no sha256 cannot address an image");
    assert!(matches!(outcome, AttestError::Digest(_)), "got {outcome:?}");
    assert!(registry.stored_digests(REPOSITORY).is_empty(), "nothing was pushed");
}
