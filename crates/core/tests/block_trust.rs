//! Block trust: a block runs someone else's pipeline code with your
//! credentials, so it must be signed by someone you name, and it may not
//! ship its own policy (ADR 0011, ADR 0012).

use ks_core::Checked;
use ks_core::block_trust::{Untrusted, policy_sections, verify};
use ks_core::ports::policy::Baseline;
use ks_core::ports::supply_chain::SignerIdentity;
use ks_lang::{Code, Diagnostic, Severity};

type Identity = SignerIdentity;

/// The baseline an organization that has chosen its publishers would have.
fn baseline(publishers: Vec<SignerIdentity>) -> Baseline {
    Baseline { publishers, ..Baseline::conservative() }
}

fn keyless(issuer: &str, subject: &str) -> Identity {
    Identity::Keyless { issuer: issuer.to_string(), subject: subject.to_string() }
}

fn key(key_id: &str) -> Identity {
    Identity::Key { key_id: key_id.to_string() }
}

fn checked(src: &str) -> Checked {
    ks_core::check(&ks_lang::parse(src))
}

fn codes(src: &str) -> Vec<Code> {
    checked(src).diagnostics.iter().map(|d| d.code).collect()
}

fn block_policy_errors(src: &str) -> Vec<Diagnostic> {
    checked(src).diagnostics.into_iter().filter(|d| d.code == Code::BlockPolicy).collect()
}

const BLOCK: &str = "\
block:  web-service
inputs:
  image:    oci.Digest
  domain:   string
";

#[test]
fn an_unsigned_block_is_refused() {
    let err =
        verify(None, &baseline(vec![key("acme")])).expect_err("an unsigned block is untrusted");
    assert_eq!(err, Untrusted::Unsigned);
}

#[test]
fn a_block_signed_by_an_unlisted_publisher_is_refused() {
    let signer = key("someone-else");
    let err =
        verify(Some(&signer), &baseline(vec![key("acme")])).expect_err("not on the allowlist");
    assert_eq!(err, Untrusted::UnknownPublisher(signer));
}

#[test]
fn a_block_signed_by_a_listed_key_publisher_is_accepted() {
    let signer = key("acme");
    assert_eq!(verify(Some(&signer), &baseline(vec![signer.clone()])), Ok(signer));
}

#[test]
fn a_block_signed_by_a_listed_keyless_publisher_is_accepted() {
    let signer = keyless("https://issuer.example", "repo:acme/blocks");
    assert_eq!(verify(Some(&signer), &baseline(vec![signer.clone()])), Ok(signer));
}

#[test]
fn the_conservative_baseline_trusts_no_block_at_all() {
    let baseline = Baseline::conservative();
    assert!(baseline.publishers.is_empty(), "the default must name no publishers");
    assert_eq!(verify(None, &baseline), Err(Untrusted::Unsigned));
    assert_eq!(
        verify(Some(&key("acme")), &baseline),
        Err(Untrusted::UnknownPublisher(key("acme"))),
        "a signed block is still unknown under the default"
    );
}

#[test]
fn a_keyless_identity_from_another_issuer_is_a_different_publisher() {
    // Same subject, different issuer: the subject name alone must not
    // inherit the allowlist, or any issuer could mint the name.
    let listed = keyless("https://issuer.example", "repo:acme/blocks");
    let other = keyless("https://elsewhere.example", "repo:acme/blocks");
    assert_eq!(
        verify(Some(&other), &baseline(vec![listed])),
        Err(Untrusted::UnknownPublisher(other))
    );
}

#[test]
fn a_refusal_names_the_publisher_the_way_a_signed_by_match_does() {
    assert_eq!(
        Untrusted::UnknownPublisher(key("acme")).to_string(),
        "block is signed by an identity this organization does not trust: key:acme",
    );
    assert_eq!(
        Untrusted::UnknownPublisher(keyless("https://issuer.example", "repo:acme/blocks"))
            .to_string(),
        "block is signed by an identity this organization does not trust: \
         repo:acme/blocks from https://issuer.example",
    );
    assert_eq!(
        Untrusted::Unsigned.to_string(),
        "block is unsigned: no publisher can be held to it"
    );
}

#[test]
fn a_block_with_policy_is_an_error_at_check() {
    let src = format!("{BLOCK}policy:\n  agents:\n    never: destroy prod\n");
    let diags = block_policy_errors(&src);
    assert_eq!(diags.len(), 1, "expected one KS0405, got {diags:#?}");
    assert_eq!(diags[0].severity, Severity::Error);
    assert!(
        diags[0].hints.iter().any(|h| h.contains("policy belongs to the repo")),
        "expected the policy hint, got {:?}",
        diags[0].hints
    );
}

#[test]
fn a_workflow_policy_is_not_a_block_policy() {
    let src = "\
name: ship-it
policy:
  agents:
    never: destroy prod
steps:
  deploy: k8s.rollout
    image: build.digest
";
    assert!(
        policy_sections(&ks_lang::parse(src).file()).is_empty(),
        "a workflow's own policy is where policy belongs"
    );
    assert!(!codes(src).contains(&Code::BlockPolicy));
}

#[test]
fn a_block_without_policy_is_clean_of_ks0410() {
    assert!(policy_sections(&ks_lang::parse(BLOCK).file()).is_empty());
    assert!(!codes(BLOCK).contains(&Code::BlockPolicy));
}

#[test]
fn every_policy_entry_in_a_block_is_reported() {
    let src = format!(
        "{BLOCK}policy:\n  agents:\n    never: destroy prod\npolicy:\n  humans:\n    never: read secrets\n"
    );
    assert_eq!(block_policy_errors(&src).len(), 2, "the grammar allows more than one");
}
