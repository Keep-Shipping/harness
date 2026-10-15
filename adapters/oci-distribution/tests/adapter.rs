//! Service-free tests of the OCI distribution adapter: the authentication
//! dance, the digest verification, and the referrers fallback — all against a
//! scripted [`FakeHttpClient`], so `cargo test --workspace` never opens a
//! socket.
//!
//! The same conformance kit runs against real registries in
//! `conformance.rs`.

use std::collections::BTreeMap;
use std::sync::Arc;

use ks_core::ports::http::{HttpClient, HttpMethod, HttpResponse};
use ks_core::ports::supply_chain::{
    ArtifactUpload, Descriptor, Digest, ImageRef, OciLayoutContents, Reference, Registry,
    RegistryError,
};
use ks_oci_distribution::{
    CredentialStore, Credentials, EMPTY_CONFIG, OCI_LAYER, OCI_MANIFEST, OciDistribution,
};
use ks_testing::block_on;
use ks_testing::http::FakeHttpClient;
use sha2::{Digest as _, Sha256};

const REPOSITORY: &str = "registry.example/team/app";

/// SHA-256 of `bytes`, as the adapter computes it.
fn digest_of(bytes: &[u8]) -> Digest {
    Digest::sha256_from_hex(
        &Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    )
    .expect("sha256 hex is canonical")
}

fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> HttpResponse {
    HttpResponse {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect(),
        body: body.to_vec(),
    }
}

fn ok(body: &[u8]) -> HttpResponse {
    response(200, &[], body)
}

/// Credentials for a host, wherever the test needs one.
fn creds() -> Credentials {
    Credentials::new("alice", "s3cr3t")
}

/// A fake that allowlists every host these tests name.
fn scripted() -> FakeHttpClient {
    FakeHttpClient::new().with_allowed_host("registry.example").with_allowed_host("auth.example")
}

/// The adapter over `fake`, speaking plain `http` to it.
fn insecure(fake: &Arc<FakeHttpClient>) -> OciDistribution {
    OciDistribution::new(client(Arc::clone(fake))).with_insecure_hosts(["registry.example"])
}

/// The fake as the trait object the adapter takes.
fn client(fake: Arc<FakeHttpClient>) -> Arc<dyn HttpClient> {
    fake
}

fn manifest_url(reference: &str) -> String {
    format!("http://registry.example/v2/team/app/manifests/{reference}")
}

fn blob_url(digest: &Digest) -> String {
    format!("http://registry.example/v2/team/app/blobs/{digest}")
}

fn referrers_url(digest: &Digest) -> String {
    format!("http://registry.example/v2/team/app/referrers/{digest}")
}

/// The tag schema the distribution spec prescribes when there is no referrers
/// API.
fn fallback_url(digest: &Digest) -> String {
    manifest_url(&format!("sha256-{}", digest.hex()))
}

fn tagged(tag: &str) -> ImageRef {
    ImageRef::new(REPOSITORY, Reference::Tag(tag.to_string()))
}

#[test]
fn a_bearer_challenge_is_answered_with_a_token_and_the_request_retried() {
    let digest = digest_of(b"manifest bytes");
    let challenge = r#"Bearer realm="https://auth.example/token",service="registry.example",scope="repository:team/app:pull""#;
    let fake = Arc::new(
        scripted()
            .with_response(HttpMethod::Head, manifest_url("v1"), response(401, &[("WWW-Authenticate", challenge)], b""))
            // The last entry of a key's queue repeats, so this is the retry.
            .with_response(
                HttpMethod::Head,
                manifest_url("v1"),
                response(200, &[("Docker-Content-Digest", &digest.to_string())], b""),
            )
            .with_response(
                HttpMethod::Get,
                "https://auth.example/token?service=registry.example&scope=repository%3Ateam%2Fapp%3Apull",
                ok(br#"{"token":"t0ken"}"#),
            ),
    );
    let registry = insecure(&fake);
    assert_eq!(block_on(registry.resolve(&tagged("v1"))), Ok(digest));
    let authorizations: Vec<String> = fake
        .requests()
        .iter()
        .filter(|req| req.url == manifest_url("v1"))
        .filter_map(|req| req.headers.iter().find(|(name, _)| name == "Authorization"))
        .map(|(_, value)| value.clone())
        .collect();
    assert_eq!(authorizations, vec!["Bearer t0ken".to_string()], "the retry carries the token");
}

#[test]
fn a_refused_registry_is_unauthorized_rather_than_a_silent_empty_repository() {
    let fake = Arc::new(scripted().with_response(
        HttpMethod::Head,
        manifest_url("v1"),
        response(401, &[], b"no"),
    ));
    let registry = insecure(&fake);
    assert!(matches!(
        block_on(registry.resolve(&tagged("v1"))),
        Err(RegistryError::Unauthorized { .. })
    ));
}

#[test]
fn pulled_bytes_that_do_not_hash_to_the_digest_they_were_served_under_are_a_mismatch() {
    let digest = digest_of(b"the real bytes");
    let fake = Arc::new(
        scripted()
            // Not a manifest...
            .with_response(
                HttpMethod::Get,
                manifest_url(&digest.to_string()),
                response(404, &[], b""),
            )
            // ...so it falls back to the blob endpoint, and the blob lies.
            .with_response(HttpMethod::Get, blob_url(&digest), ok(b"tampered bytes")),
    );
    let registry = insecure(&fake);
    let error = block_on(registry.pull(REPOSITORY, &digest)).expect_err("tampered bytes");
    assert!(
        matches!(&error, RegistryError::DigestMismatch { expected, actual }
            if expected == &digest && actual.hex() != digest.hex()),
        "{error}"
    );
}

#[test]
fn a_manifest_endpoint_that_serves_a_blob_wrapped_as_a_manifest_falls_back_to_the_blob() {
    // distribution 2.8.3 answers the manifest endpoint for a blob digest with a
    // 200 whose bytes are the blob re-wrapped (and so do not hash to the digest).
    // That is not the content: the blob endpoint has it, and it is verified.
    let digest = digest_of(b"layer bytes");
    let fake = Arc::new(
        scripted()
            .with_response(
                HttpMethod::Get,
                manifest_url(&digest.to_string()),
                ok(b"{\"layer bytes\",\"signatures\":[]}"),
            )
            .with_response(HttpMethod::Get, blob_url(&digest), ok(b"layer bytes")),
    );
    let registry = insecure(&fake);
    assert_eq!(block_on(registry.pull(REPOSITORY, &digest)), Ok(b"layer bytes".to_vec()));
}

#[test]
fn pulling_a_blob_that_is_there_returns_its_exact_bytes() {
    let digest = digest_of(b"layer bytes");
    let fake = Arc::new(
        scripted()
            .with_response(
                HttpMethod::Get,
                manifest_url(&digest.to_string()),
                response(404, &[], b""),
            )
            .with_response(HttpMethod::Get, blob_url(&digest), ok(b"layer bytes")),
    );
    let registry = insecure(&fake);
    assert_eq!(block_on(registry.pull(REPOSITORY, &digest)), Ok(b"layer bytes".to_vec()));
}

#[test]
fn referrers_fall_back_to_the_tag_index_when_the_api_is_not_there() {
    let subject = digest_of(b"subject manifest");
    let fake = Arc::new(
        scripted()
            .with_response(HttpMethod::Get, referrers_url(&subject), response(404, &[], b""))
            .with_response(
                HttpMethod::Get,
                fallback_url(&subject),
                ok(format!(
                    r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"{OCI_MANIFEST}","digest":"{}","size":12,"annotations":{{"k":"v"}}}}]}}"#,
                    digest_of(b"artifact")
                )
                .as_bytes()),
            ),
    );
    let registry = insecure(&fake);
    let referrers = block_on(registry.referrers(REPOSITORY, &subject)).expect("the tag answers");
    assert_eq!(
        referrers,
        vec![Descriptor {
            media_type: OCI_MANIFEST.to_string(),
            digest: digest_of(b"artifact"),
            size: 12,
            annotations: BTreeMap::from([("k".to_string(), "v".to_string())]),
        }]
    );
}

#[test]
fn a_digest_nothing_refers_to_is_an_empty_list_not_an_error() {
    let subject = digest_of(b"subject manifest");
    let fake = Arc::new(
        scripted()
            .with_response(HttpMethod::Get, referrers_url(&subject), response(404, &[], b""))
            .with_response(HttpMethod::Get, fallback_url(&subject), response(404, &[], b"")),
    );
    let registry = insecure(&fake);
    assert_eq!(block_on(registry.referrers(REPOSITORY, &subject)), Ok(vec![]));
}

#[test]
fn the_tag_listing_reads_the_tags_and_a_missing_repository_is_an_empty_one() {
    let url = "http://registry.example/v2/team/app/tags/list";
    // `tags: null` is a repository with nothing in it, in the spelling some
    // registries use for exactly that.
    for (body, wanted) in [
        (br#"{"name":"team/app","tags":["1.0.0","2.0.0"]}"#.as_slice(), vec!["1.0.0", "2.0.0"]),
        (br#"{"name":"team/app","tags":null}"#.as_slice(), vec![]),
    ] {
        let fake = Arc::new(scripted().with_response(HttpMethod::Get, url, ok(body)));
        let wanted: Vec<String> = wanted.into_iter().map(String::from).collect();
        assert_eq!(block_on(insecure(&fake).tags(REPOSITORY)), Ok(wanted));
    }

    // A repository nothing was ever pushed to answers 404, which is the empty
    // list and not a failure; a listing that is not json is a registry in
    // trouble, not an empty one.
    let missing = Arc::new(scripted().with_response(HttpMethod::Get, url, response(404, &[], b"")));
    assert_eq!(block_on(insecure(&missing).tags(REPOSITORY)), Ok(vec![]));
    let broken = Arc::new(scripted().with_response(HttpMethod::Get, url, ok(b"<html>nope</html>")));
    assert!(block_on(insecure(&broken).tags(REPOSITORY)).is_err());
}

#[test]
fn a_paginated_tag_listing_is_walked_to_the_end() {
    let next = "/v2/team/app/tags/list?last=2.0.0&n=1";
    let first = format!("<{next}>; rel=\"next\"");
    let fake = Arc::new(
        scripted()
            .with_response(
                HttpMethod::Get,
                "http://registry.example/v2/team/app/tags/list",
                response(200, &[("Link", &first)], br#"{"tags":["1.0.0","2.0.0"]}"#),
            )
            .with_response(
                HttpMethod::Get,
                format!("http://registry.example{next}"),
                response(
                    200,
                    &[("Link", "</v2/other/app/tags/list?n=1>; rel=\"next\"")],
                    br#"{"tags":["3.0.0"]}"#,
                ),
            ),
    );
    // The second page's `Link` names a different repository, so it ends the
    // walk rather than being followed into someone else's listing.
    assert_eq!(
        block_on(insecure(&fake).tags(REPOSITORY)),
        Ok(vec!["1.0.0".to_string(), "2.0.0".to_string(), "3.0.0".to_string()])
    );
}

#[test]
fn existence_is_false_only_on_a_real_404() {
    let present = digest_of(b"present");
    let absent = digest_of(b"absent");
    let fake = Arc::new(
        scripted()
            .with_response(HttpMethod::Head, blob_url(&present), ok(b""))
            .with_response(HttpMethod::Head, blob_url(&absent), response(404, &[], b""))
            .with_response(
                HttpMethod::Head,
                manifest_url(&absent.to_string()),
                response(404, &[], b""),
            ),
    );
    let registry = insecure(&fake);
    assert_eq!(block_on(registry.exists(REPOSITORY, &present)), Ok(true));
    assert_eq!(block_on(registry.exists(REPOSITORY, &absent)), Ok(false));

    // A registry that is broken is not a repository that is empty.
    let broken = Arc::new(scripted().with_response(
        HttpMethod::Head,
        blob_url(&absent),
        response(503, &[], b"unavailable"),
    ));
    let registry = insecure(&broken);
    assert!(matches!(
        block_on(registry.exists(REPOSITORY, &absent)),
        Err(RegistryError::Backend { .. })
    ));
}

#[test]
fn a_push_verifies_the_digest_the_registry_reported_against_the_bytes_sent() {
    let manifest = b"{\"schemaVersion\":2}";
    let blob = b"a layer";
    let manifest_digest = digest_of(manifest);
    let blob_digest = digest_of(blob);
    let lying = digest_of(b"something else entirely");
    let fake = Arc::new(
        scripted()
            .with_response(HttpMethod::Head, blob_url(&blob_digest), response(404, &[], b""))
            .with_response(
                HttpMethod::Post,
                "http://registry.example/v2/team/app/blobs/uploads/",
                response(202, &[("Location", "/v2/team/app/blobs/uploads/1")], b""),
            )
            .with_response(
                HttpMethod::Put,
                format!(
                    "http://registry.example/v2/team/app/blobs/uploads/1?digest={}",
                    blob_digest.to_string().replace(':', "%3A")
                ),
                response(201, &[("Docker-Content-Digest", &blob_digest.to_string())], b""),
            )
            .with_response(
                HttpMethod::Put,
                manifest_url(&manifest_digest.to_string()),
                response(201, &[("Docker-Content-Digest", &lying.to_string())], b""),
            ),
    );
    let registry = insecure(&fake);
    let layout = OciLayoutContents {
        media_type: OCI_MANIFEST.to_string(),
        manifest: manifest.to_vec(),
        blobs: vec![blob.to_vec()],
    };
    let error = block_on(registry.push_layout(REPOSITORY, &layout)).expect_err("a lying registry");
    assert!(matches!(error, RegistryError::DigestMismatch { .. }), "{error}");
}

#[test]
fn a_blob_the_repository_already_has_is_not_uploaded_again() {
    let manifest = b"{}";
    let blob = b"a layer";
    let fake = Arc::new(
        scripted()
            .with_response(HttpMethod::Head, blob_url(&digest_of(blob)), ok(b""))
            .with_response(
                HttpMethod::Put,
                manifest_url(&digest_of(manifest).to_string()),
                response(201, &[("Docker-Content-Digest", &digest_of(manifest).to_string())], b""),
            ),
    );
    let registry = insecure(&fake);
    let layout = OciLayoutContents {
        media_type: OCI_MANIFEST.to_string(),
        manifest: manifest.to_vec(),
        blobs: vec![blob.to_vec()],
    };
    let descriptor = block_on(registry.push_layout(REPOSITORY, &layout)).expect("a push");
    assert_eq!(descriptor.digest, digest_of(manifest));
    let sent: Vec<String> =
        fake.requests().iter().map(|req| format!("{} {}", req.method, req.url)).collect();
    assert!(!sent.iter().any(|line| line.contains("uploads")), "{sent:?}");
}

#[test]
fn a_registry_that_is_not_named_insecure_is_spoken_to_over_https() {
    let digest = digest_of(b"{}");
    let fake = Arc::new(scripted().with_response(
        HttpMethod::Head,
        manifest_url("v1").replace("http://", "https://"),
        response(200, &[("Docker-Content-Digest", &digest.to_string())], b""),
    ));
    let registry = OciDistribution::new(client(fake));
    assert_eq!(block_on(registry.resolve(&tagged("v1"))), Ok(digest));
}

#[test]
fn a_repository_without_a_name_is_refused_with_an_example() {
    let registry = insecure(&Arc::new(scripted()));
    let error = block_on(registry.pull("registry.example", &digest_of(b""))).expect_err("no name");
    assert!(error.to_string().contains("host[:port]/name"), "{error}");
}

/// Compile-time check that the adapter is a `Registry` a step can hold as a
/// trait object, the way the port is meant to be used.
#[test]
fn the_adapter_is_a_registry() {
    fn assert_registry<T: Registry + Send + Sync + 'static>(_: &T) {}
    assert_registry(&insecure(&Arc::new(scripted())));
}

#[test]
fn a_registry_cannot_talk_the_client_into_sending_credentials_to_a_plain_http_realm() {
    let challenge = r#"Bearer realm="http://auth.example/token",service="registry.example",scope="repository:team/app:pull""#;
    let fake = Arc::new(scripted().with_response(
        HttpMethod::Head,
        manifest_url("v1").replace("http://", "https://"),
        response(401, &[("WWW-Authenticate", challenge)], b""),
    ));
    // Not named insecure, so every request is `https`.
    let registry = OciDistribution::new(client(fake.clone()))
        .with_credentials(CredentialStore::new().with("registry.example", creds()));
    let error = block_on(registry.resolve(&tagged("v1"))).expect_err("an http realm is refused");
    assert!(error.to_string().contains("not https"), "{error}");
    let talked_to: Vec<String> = fake
        .requests()
        .iter()
        .filter(|req| req.url.contains("auth.example"))
        .map(|req| req.url.clone())
        .collect();
    assert!(talked_to.is_empty(), "no credentials were offered to {talked_to:?}");
}

#[test]
fn an_insecure_registry_and_an_insecure_realm_are_both_allowed() {
    let challenge = r#"Bearer realm="http://auth.example/token",service="registry.example",scope="repository:team/app:pull""#;
    let digest = digest_of(b"manifest bytes");
    let token_url =
        "http://auth.example/token?service=registry.example&scope=repository%3Ateam%2Fapp%3Apull";
    let fake = Arc::new(
        scripted()
            .with_response(
                HttpMethod::Head,
                manifest_url("v1"),
                response(401, &[("WWW-Authenticate", challenge)], b""),
            )
            .with_response(
                HttpMethod::Head,
                manifest_url("v1"),
                response(200, &[("Docker-Content-Digest", &digest.to_string())], b""),
            )
            .with_response(HttpMethod::Get, token_url, ok(br#"{"token":"t0ken"}"#)),
    );
    let registry = OciDistribution::new(client(Arc::clone(&fake)))
        .with_insecure_hosts(["registry.example", "auth.example"])
        .with_credentials(CredentialStore::new().with("registry.example", creds()));
    assert_eq!(block_on(registry.resolve(&tagged("v1"))), Ok(digest));
}

#[test]
fn a_head_without_a_digest_header_falls_back_to_getting_the_manifest() {
    let manifest = b"{\"schemaVersion\":2}";
    let fake = Arc::new(
        scripted()
            // A HEAD that answered, but named no digest to take at its word.
            .with_response(HttpMethod::Head, manifest_url("v1"), ok(b""))
            .with_response(HttpMethod::Get, manifest_url("v1"), ok(manifest)),
    );
    let registry = insecure(&fake);
    assert_eq!(block_on(registry.resolve(&tagged("v1"))), Ok(digest_of(manifest)));
}

#[test]
fn a_retag_of_bytes_that_do_not_hash_to_the_digest_is_refused() {
    let digest = digest_of(b"the manifest that is really there");
    let fake = Arc::new(
        scripted()
            .with_response(HttpMethod::Get, manifest_url(&digest.to_string()), ok(b"other bytes"))
            .with_response(
                HttpMethod::Put,
                manifest_url("v1"),
                response(201, &[("Docker-Content-Digest", &digest.to_string())], b""),
            ),
    );
    let registry = insecure(&fake);
    let error = block_on(registry.tag(REPOSITORY, "v1", &digest)).expect_err("a lying registry");
    assert!(matches!(error, RegistryError::DigestMismatch { .. }), "{error}");
    assert!(
        !fake.requests().iter().any(|req| req.method == HttpMethod::Put),
        "nothing was re-pushed under the tag"
    );
}

/// The artifact manifest the adapter builds for `upload` with `subject` —
/// mirrored here because the push has to name the manifest's digest to script
/// the registry that answers it.
fn artifact_manifest_bytes(upload: &ArtifactUpload, subject: &Digest) -> Vec<u8> {
    let layers: Vec<serde_json::Value> = upload
        .blobs
        .iter()
        .map(|blob| {
            serde_json::json!({
                "mediaType": OCI_LAYER,
                "digest": digest_of(blob).to_string(),
                "size": blob.len(),
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": upload.media_type,
        "artifactType": upload.artifact_type,
        "config": {
            "mediaType": EMPTY_CONFIG,
            "digest": digest_of(b"{}").to_string(),
            "size": 2,
        },
        "layers": layers,
        "annotations": upload.annotations,
        // The subject HEAD below names no length, so its size is 0.
        "subject": {
            "mediaType": OCI_MANIFEST,
            "digest": subject.to_string(),
            "size": 0,
        },
    }))
    .expect("a manifest serializes")
}

#[test]
fn a_referrers_index_that_cannot_be_read_is_an_error_not_an_emptied_one() {
    let layer = b"a layer";
    let subject = digest_of(b"subject manifest");
    let upload = ArtifactUpload {
        media_type: OCI_MANIFEST.to_string(),
        artifact_type: OCI_MANIFEST.to_string(),
        blobs: vec![layer.to_vec()],
        annotations: BTreeMap::new(),
        subject: Some(subject.clone()),
    };
    let manifest = artifact_manifest_bytes(&upload, &subject);
    let manifest_digest = digest_of(&manifest);
    let fake = Arc::new(
        scripted()
            // Both blobs are already there...
            .with_response(HttpMethod::Head, blob_url(&digest_of(b"{}")), ok(b""))
            .with_response(HttpMethod::Head, blob_url(&digest_of(layer)), ok(b""))
            .with_response(HttpMethod::Head, manifest_url(&subject.to_string()), ok(b""))
            // ...so the push is the manifest and the fallback index.
            .with_response(
                HttpMethod::Put,
                manifest_url(&manifest_digest.to_string()),
                response(201, &[("Docker-Content-Digest", &manifest_digest.to_string())], b""),
            )
            .with_response(HttpMethod::Get, fallback_url(&subject), ok(b"{ not an index"))
            .with_response(HttpMethod::Put, fallback_url(&subject), ok(b"{}")),
    );
    let registry = insecure(&fake);
    let error = block_on(registry.push_artifact(REPOSITORY, &upload)).expect_err("unreadable");
    assert!(error.to_string().contains("could not be read"), "{error}");
    assert!(
        !fake
            .requests()
            .iter()
            .any(|req| req.method == HttpMethod::Put && req.url == fallback_url(&subject)),
        "an index we cannot read is never overwritten"
    );
}

#[test]
fn a_blob_past_the_chunk_threshold_is_uploaded_in_ordered_chunks() {
    let manifest = b"{}";
    // Two chunks of a 2 MiB threshold, plus a tail.
    let blob = vec![b'z'; 2 * 1024 * 1024 + 512 * 1024];
    let blob_digest = digest_of(&blob);
    let manifest_digest = digest_of(manifest);
    let upload = "http://registry.example/v2/team/app/blobs/uploads/";
    let fake = Arc::new(
        scripted()
            .with_response(HttpMethod::Head, blob_url(&blob_digest), response(404, &[], b""))
            // A `Location` with no leading slash hangs off the directory of the
            // URL that answered, not off the registry root.
            .with_response(HttpMethod::Post, upload, response(202, &[("Location", "1")], b""))
            .with_response(
                HttpMethod::Patch,
                format!("{upload}1"),
                response(202, &[("Location", &format!("{upload}2"))], b""),
            )
            .with_response(HttpMethod::Patch, format!("{upload}2"), response(202, &[], b""))
            .with_response(
                HttpMethod::Put,
                format!("{upload}2?digest={}", blob_digest.to_string().replace(':', "%3A")),
                response(201, &[("Docker-Content-Digest", &blob_digest.to_string())], b""),
            )
            .with_response(
                HttpMethod::Put,
                manifest_url(&manifest_digest.to_string()),
                response(201, &[("Docker-Content-Digest", &manifest_digest.to_string())], b""),
            ),
    );
    let registry = insecure(&fake);
    let layout = OciLayoutContents {
        media_type: OCI_MANIFEST.to_string(),
        manifest: manifest.to_vec(),
        blobs: vec![blob.clone()],
    };
    let descriptor = block_on(registry.push_layout(REPOSITORY, &layout)).expect("a push");
    assert_eq!(descriptor.digest, manifest_digest);

    let sent: Vec<(String, String, Vec<u8>)> = fake
        .requests()
        .iter()
        .filter(|req| req.method == HttpMethod::Patch)
        .map(|req| {
            let range = req
                .headers
                .iter()
                .find(|(name, _)| name == "Content-Range")
                .map(|(_, value)| value.clone())
                .expect("a chunked upload ranges every chunk");
            (req.url.clone(), range, req.body.clone())
        })
        .collect();
    assert_eq!(sent.len(), 2, "a 2.5 MiB blob is two 2 MiB chunks and a tail");
    assert_eq!(sent[0].0, format!("{upload}1"));
    assert_eq!(sent[0].1, "0-2097151");
    assert_eq!(sent[1].0, format!("{upload}2"), "the follow-up Location was followed");
    assert_eq!(sent[1].1, "2097152-2621439");
    let chunks: Vec<u8> = sent.iter().flat_map(|(_, _, body)| body.clone()).collect();
    assert_eq!(chunks, blob, "the chunks are the blob, in order, once each");
}
