//! Behaviour of the supply-chain fakes: a content-addressed registry, a
//! deterministic builder, a signer that binds signatures to identities — plus
//! the conformance kits, run against the fakes through the `dyn` traits.

use std::collections::BTreeMap;
use std::sync::Arc;

use ks_core::ports::supply_chain::{
    BuildCache, BuildError, BuildOutput, BuildRequest, BuildSecrets, Digest, ImageBuilder,
    ImageRef, OciLayoutContents, Reference, Registry, RegistryError, SignError, SignPayload,
    Signature, Signer, SignerIdentity,
};
use ks_testing::block_on;
use ks_testing::supply_chain::{
    FakeImageBuilder, FakeRegistry, FakeSigner, registry_conformance, signer_conformance,
};

fn build_request(push_to: Option<String>) -> BuildRequest {
    BuildRequest {
        context: "/work/src".into(),
        dockerfile: "/work/src/Dockerfile".into(),
        args: BTreeMap::from([("version".to_string(), "1.2".to_string())]),
        platforms: vec!["linux/amd64".to_string()],
        target: None,
        push_to,
        secrets: BuildSecrets::new(),
        cache: BuildCache::Local,
        sbom: false,
    }
}

fn layout() -> OciLayoutContents {
    OciLayoutContents {
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        manifest: b"{\"schemaVersion\":2}".to_vec(),
        blobs: vec![b"blob".to_vec()],
    }
}

/// Dyn-compatibility: steps hold ports as `&dyn`, so all three work as trait
/// objects.
fn _ports_are_dyn_compatible(
    _builder: &dyn ImageBuilder,
    _registry: &dyn Registry,
    _signer: &dyn Signer,
) {
}

#[test]
fn the_supply_chain_ports_are_send_sync_and_dyn_compatible() {
    fn assert_send_sync<T: ?Sized + Send + Sync>() {}
    assert_send_sync::<dyn ImageBuilder>();
    assert_send_sync::<dyn Registry>();
    assert_send_sync::<dyn Signer>();
    let _ = _ports_are_dyn_compatible as fn(&dyn ImageBuilder, &dyn Registry, &dyn Signer);
}

#[test]
fn the_fakes_pass_their_conformance_kits_through_the_dyn_traits() {
    let registry = FakeRegistry::new();
    let dynamic: &dyn Registry = &registry;
    block_on(registry_conformance(dynamic, "registry.example:5000/conformance/app"));

    let signer = FakeSigner::keyless(
        "https://token.example",
        "https://github.com/Keep-Shipping/harness/.github/workflows/ci.yml@refs/heads/main",
    );
    block_on(signer_conformance(&signer));
}

#[test]
fn the_fake_registry_is_content_addressed_and_scripts_unauthorized_repositories() {
    let registry = FakeRegistry::new().unauthorized("registry.example:5000/private");
    let error = block_on(registry.push_layout("registry.example:5000/private", &layout()))
        .expect_err("the private repository is scripted unauthorized");
    assert_eq!(
        error,
        RegistryError::Unauthorized { repository: "registry.example:5000/private".to_string() },
        "{error}"
    );
    // `exists` must not silently report an unauthorized repository as empty.
    let stray = Digest::parse(&format!("sha256:{}", "ab".repeat(32))).expect("canonical stray");
    assert_eq!(
        block_on(registry.exists("registry.example:5000/private", &stray)),
        Err(RegistryError::Unauthorized {
            repository: "registry.example:5000/private".to_string()
        }),
    );

    // The same bytes are welcome in an authorized repository, under the digest
    // of the exact manifest bytes.
    let pushed = block_on(registry.push_layout("registry.example:5000/team/app", &layout()))
        .expect("pushed");
    let stored = registry.stored_digests("registry.example:5000/team/app");
    assert_eq!(stored.len(), 2, "the manifest and its blob are stored separately");
    assert!(
        stored.contains(&pushed.digest),
        "content-addressed: storage is keyed by the digest of the bytes"
    );
    assert_eq!(
        block_on(registry.pull("registry.example:5000/team/app", &pushed.digest))
            .expect("the manifest pulls back"),
        layout().manifest,
        "pull returns the exact pushed bytes"
    );
    let pinned =
        ImageRef::new("registry.example:5000/team/app", Reference::Digest(pushed.digest.clone()));
    assert_eq!(
        block_on(registry.resolve(&pinned)).expect("a held digest resolves to itself"),
        pushed.digest
    );
}

#[test]
fn the_fake_image_builder_is_deterministic_per_request() {
    let builder = FakeImageBuilder::new();
    let same_args = build_request(None);
    let BuildOutput::OciLayout { manifest: first, path } =
        block_on(builder.build(&same_args)).expect("the fake builder succeeds")
    else {
        panic!("without push_to the output is a local OCI layout");
    };
    let BuildOutput::OciLayout { manifest: second, path: second_path } =
        block_on(builder.build(&same_args)).expect("the fake builder succeeds")
    else {
        panic!("without push_to the output is a local OCI layout");
    };
    assert_eq!(first.digest, second.digest, "same request in, same digest out");
    assert_eq!(path, second_path);

    let mut changed = build_request(None);
    changed.args.insert("build-arg".to_string(), "other".to_string());
    let BuildOutput::OciLayout { manifest: third, .. } =
        block_on(builder.build(&changed)).expect("the fake builder succeeds")
    else {
        panic!("without push_to the output is a local OCI layout");
    };
    assert_ne!(first.digest, third.digest, "changed args, changed digest");
    let recorded = builder.requests();
    assert_eq!(recorded.len(), 3);
    assert_eq!(recorded[0], recorded[1], "same request in, same record out");
    assert_eq!(recorded[0].args, same_args.args, "the record carries the args");
    assert!(recorded[2].args.len() > recorded[0].args.len(), "the changed one differs");
}

#[test]
fn the_fake_image_builder_pushes_into_the_shared_registry_and_can_fail() {
    let registry = Arc::new(FakeRegistry::new());
    let builder = FakeImageBuilder::new().pushing_into(registry.clone());
    let output =
        block_on(builder.build(&build_request(Some("registry.example:5000/team/app".to_string()))))
            .expect("the fake builder succeeds");
    let BuildOutput::PushedImage { repository, digest } = output else {
        panic!("with push_to the output is a pushed image");
    };
    assert_eq!(repository, "registry.example:5000/team/app");
    assert_eq!(
        block_on(registry.exists(&repository, &digest)),
        Ok(true),
        "the pushed image must be in the shared registry"
    );

    let failing = FakeImageBuilder::new().failing("dockerfile syntax error");
    assert_eq!(
        block_on(failing.build(&build_request(None))),
        Err(BuildError::Failed { reason: "dockerfile syntax error".to_string() })
    );
}

#[test]
fn the_fake_signer_binds_signatures_to_an_identity() {
    let signer = FakeSigner::with_key("test-key");
    let payload = SignPayload::Bytes(b"payload".to_vec());
    let signature = block_on(signer.sign(&payload)).expect("signing succeeds");
    assert_eq!(signature.identity, SignerIdentity::Key { key_id: "test-key".to_string() });
    assert_eq!(
        block_on(signer.verify(&payload, &signature)).expect("fresh signatures verify"),
        signature.identity
    );

    // A tampered payload no longer verifies…
    let tampered = SignPayload::Bytes(b"tampered".to_vec());
    assert!(matches!(
        block_on(signer.verify(&tampered, &signature)),
        Err(SignError::Invalid { .. })
    ));
    // …and neither does a signature re-claimed by another identity.
    let stolen = Signature {
        bytes: signature.bytes.clone(),
        identity: SignerIdentity::Key { key_id: "other-key".to_string() },
    };
    assert!(matches!(block_on(signer.verify(&payload, &stolen)), Err(SignError::Invalid { .. })));
}
