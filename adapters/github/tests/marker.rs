//! The hidden marker: what `marker_for` writes, what `parse_marker` recovers,
//! and the bodies it refuses to believe.
//!
//! The marker is how a resume job in a different process recovers the request
//! it was asked about, so a round trip that loses a field loses the binding.

use ks_core::ids::RunId;
use ks_core::ports::approval::{ApprovalRequest, Artifact, ArtifactKind, Identity, Team};
use ks_core::ports::supply_chain::Digest;
use ks_github::{marker_for, parse_marker};

fn digest(hex_char: char) -> Digest {
    Digest::sha256_from_hex(&hex_char.to_string().repeat(64)).expect("64 hex digits is a sha256")
}

fn request(artifacts: Vec<Artifact>) -> ApprovalRequest {
    ApprovalRequest {
        run: RunId::from_parts(1_700_000_000_000, 3),
        step: "apply-infra".to_string(),
        summary: "2 to create".to_string(),
        artifacts,
        from: Team::parse("@platform").expect("valid"),
        reason: "production deploy".to_string(),
        proposed_by: Identity::human("ada"),
    }
}

#[test]
fn every_artifact_kind_survives_the_round_trip() {
    let artifacts = vec![
        Artifact::new(ArtifactKind::PlanFile, digest('a')),
        Artifact::new(ArtifactKind::Image, digest('b')),
        // An adapter-named kind carries a label the marker has no alphabet
        // for, so it is base64'd: this label has a colon, a comma and a
        // non-ASCII character, all of which would break a naive encoding.
        Artifact::new(ArtifactKind::Other("sbom:cpe-2.3,é".to_string()), digest('c')),
    ];
    let parsed = parse_marker(&marker_for(&request(artifacts.clone())))
        .expect("a marker this adapter wrote is one it can read back");
    assert_eq!(parsed.artifacts, artifacts, "every kind comes back byte-identical");
    assert_eq!(parsed.from, Team::parse("@platform").expect("valid"));
    assert_eq!(parsed.proposed_by_handle, "ada");
}

#[test]
fn a_request_with_no_artifacts_round_trips_as_no_artifacts() {
    let parsed = parse_marker(&marker_for(&request(vec![]))).expect("an empty marker still parses");
    assert!(
        parsed.artifacts.is_empty(),
        "a request about nothing binds a verdict to nothing, not to a phantom digest"
    );
}

#[test]
fn a_body_carrying_two_markers_is_not_believed() {
    // If an attacker could get a second marker into the comment, parsing the
    // first would let them name their own team and proposer. A body with two
    // markers has no established provenance, so there is no reading of it.
    let request = request(vec![Artifact::new(ArtifactKind::PlanFile, digest('a'))]);
    let doubled = format!(
        "## Approval needed\n\n{}\n\nsomebody else's marker\n\n{}",
        marker_for(&request),
        marker_for(&request)
    );
    assert!(parse_marker(&doubled).is_none(), "a body with two markers must not be believed");
}

#[test]
fn a_body_with_no_marker_is_not_a_request() {
    assert!(parse_marker("/keepshipping approve").is_none());
    assert!(parse_marker("").is_none());
}

#[test]
fn a_truncated_marker_is_refused_rather_than_half_read() {
    let request = request(vec![Artifact::new(ArtifactKind::PlanFile, digest('a'))]);
    let truncated = marker_for(&request).replace("\n-->", "");
    assert!(
        parse_marker(&truncated).is_none(),
        "a marker with no closing delimiter proves nothing"
    );
}
