//! Using blocks: `@v3`, semver resolution and `ship.lock`
//! ([#81](https://github.com/Keep-Shipping/harness/issues/81)).
//!
//! The issue's acceptance criteria as tests: `@v3` picks the highest 3.x and
//! not a prerelease; two repositories on different majors of one block both
//! work; a pin resolves *once*, so a release published today does not change
//! what an unchanged lock runs; exact and digest pins work; an upgrade is a
//! diff of a version and a digest; and `verify` refuses a mismatched digest, an
//! unsigned block, and a block signed by a publisher the baseline does not
//! list ([#125](https://github.com/Keep-Shipping/harness/issues/125)).
//!
//! Everything runs against [`FakeBlockSource`], so no test opens a socket — the
//! same property the `offline` CI job asserts of `check`.

use ks_core::block_trust::Untrusted;
use ks_core::lock::{BlockRef, Lock};
use ks_core::ports::block_source::{BlockDefinition, BlockPackage};
use ks_core::ports::blocks::{BlockVersion, SignatureStatus};
use ks_core::ports::policy::Baseline;
use ks_core::ports::supply_chain::{Digest, SignerIdentity};
use ks_engine::blocks::{LockUpdateError, VerifyError, update, verify};
use ks_testing::block_on;
use ks_testing::block_source::{BlockSourceCall, FakeBlockSource};

/// Every version the fixture publishes: two majors, a release candidate, and a
/// version this build cannot read (a source listing it must not break a pin).
fn web_service() -> Vec<BlockVersion> {
    [("4.0.0", 'e'), ("3.5.0-rc.1", 'd'), ("3.4.1", 'c'), ("3.0.0", 'b'), ("2.9.0", 'a')]
        .into_iter()
        .map(|(version, byte)| BlockVersion {
            version: version.to_string(),
            digest: digest_of(byte),
            signature: SignatureStatus::Signed,
        })
        .chain(std::iter::once(BlockVersion {
            version: "not-a-version".to_string(),
            digest: digest_of('0'),
            signature: SignatureStatus::Signed,
        }))
        .collect()
}

fn digest_of(byte: char) -> Digest {
    Digest::parse(&format!("sha256:{}", byte.to_string().repeat(64))).expect("a digest")
}

fn source() -> FakeBlockSource {
    FakeBlockSource::new().with_versions(web_service())
}

fn published(version: &str) -> BlockVersion {
    web_service().into_iter().find(|entry| entry.version == version).expect("a published version")
}

fn reference(text: &str) -> BlockRef {
    BlockRef::parse(text).expect("a block reference")
}

fn package(byte: char, signature: SignatureStatus) -> BlockPackage {
    BlockPackage {
        name: "acme/web-service".to_string(),
        version: "as published".to_string(),
        digest: digest_of(byte),
        definition: BlockDefinition::default(),
        signature,
    }
}

/// The publisher the fixture's blocks are signed by, and the baseline that
/// trusts it: an organization that has chosen who may publish its blocks.
fn publisher() -> SignerIdentity {
    SignerIdentity::Keyless {
        issuer: "https://token.acme.example".to_string(),
        subject: "acme/release@v3".to_string(),
    }
}

fn baseline() -> Baseline {
    Baseline { publishers: vec![publisher()], ..Baseline::conservative() }
}

#[test]
fn a_major_pin_picks_the_highest_release_of_that_major_and_not_a_prerelease() {
    let lock = block_on(update(&source(), &[reference("acme/web-service@v3")], &Lock::new()))
        .expect("3.x is published");
    let entry = lock.get(&reference("acme/web-service@v3")).expect("the @v3 entry");

    assert_eq!(entry.version, "3.4.1", "3.5.0-rc.1 is a candidate and 4.0.0 is another major");
    assert_eq!(entry.digest, digest_of('c'));
    assert_eq!(entry.request, "v3", "the request is recorded as the file spells it");
}

#[test]
fn a_pin_matching_nothing_is_an_error_naming_what_it_looked_for() {
    let error = block_on(update(&source(), &[reference("acme/web-service@v9")], &Lock::new()))
        .expect_err("there is no 9.x");
    match &error {
        LockUpdateError::Unresolved { reference, request, published } => {
            assert_eq!((reference.as_str(), request.as_str()), ("acme/web-service@v9", "v9"));
            assert!(published.contains(&"3.4.1".to_string()), "{published:?}");
        }
        other => panic!("a major with nothing published is Unresolved, got {other}"),
    }
    assert!(error.to_string().contains("3.4.1"), "the error says what is on offer");
}

/// The acceptance criterion: two repositories on different majors of one block
/// both work. They share a source, as two repos pulling from `acme/blocks` do,
/// and neither can be served the other's bytes.
#[test]
fn two_repositories_pinned_to_different_majors_both_work_against_one_source() {
    let shared = source();
    let repo_a =
        block_on(update(&shared, &[reference("acme/web-service@v3")], &Lock::new())).expect("A");
    let repo_b =
        block_on(update(&shared, &[reference("acme/web-service@v4")], &Lock::new())).expect("B");

    let three = repo_a.get(&reference("acme/web-service@v3")).expect("A's pin");
    let four = repo_b.get(&reference("acme/web-service@v4")).expect("B's pin");
    assert_eq!((three.version.as_str(), four.version.as_str()), ("3.4.1", "4.0.0"));
    assert_ne!(three.digest, four.digest, "each pin is its own content");

    // Each package passes against its own lock and fails against the other's,
    // which is what makes the digest a pin rather than a record.
    for (own, own_byte, other_byte) in [(three, 'c', 'e'), (four, 'e', 'c')] {
        assert_eq!(
            verify(
                own,
                &package(own_byte, SignatureStatus::Signed),
                Some(&publisher()),
                &baseline()
            ),
            Ok(publisher())
        );
        assert!(matches!(
            verify(
                own,
                &package(other_byte, SignatureStatus::Signed),
                Some(&publisher()),
                &baseline()
            ),
            Err(VerifyError::DigestMismatch { .. })
        ));
    }

    // And one lock *can* hold both, as a monorepo or a migrating repo would.
    let both = block_on(update(
        &shared,
        &[reference("acme/web-service@v3"), reference("acme/web-service@v4")],
        &Lock::new(),
    ))
    .expect("both majors resolve into one lock");
    assert_eq!(both.entries().len(), 2);
    assert_eq!(Lock::parse(&both.render()).expect("round trip"), both);
}

/// "Resolved once", as a test: a 3.5.0 published after the lock was written
/// does not become what the lock runs, and the update makes no call at all.
#[test]
fn a_pin_already_in_the_lock_is_never_re_resolved() {
    let three = reference("acme/web-service@v3");
    let first =
        block_on(update(&source(), std::slice::from_ref(&three), &Lock::new())).expect("first");
    assert_eq!(first.get(&three).expect("the entry").version, "3.4.1");

    // A candidate, then a release, published since the lock was written.
    let newer = FakeBlockSource::new().with_versions(
        [("3.6.0", 'f'), ("3.5.0", 'e'), ("3.4.1", 'c')]
            .into_iter()
            .map(|(version, byte)| BlockVersion {
                version: version.to_string(),
                digest: digest_of(byte),
                signature: SignatureStatus::Signed,
            })
            .collect(),
    );
    let second = block_on(update(&newer, std::slice::from_ref(&three), &first)).expect("second");
    assert_eq!(second, first, "an unchanged reference keeps its pin");
    assert_eq!(
        newer.calls(),
        Vec::<BlockSourceCall>::new(),
        "an already-locked reference is not even looked up: that is what resolved once means"
    );

    // Upgrading is deliberate: the same source against an empty lock takes the
    // new release, and that is a two-line diff.
    let upgraded =
        block_on(update(&newer, std::slice::from_ref(&three), &Lock::new())).expect("the 3.6.0");
    assert_eq!(upgraded.get(&three).expect("the entry").version, "3.6.0");
    let before = first.render();
    let after = upgraded.render();
    let changed: Vec<&str> = before
        .lines()
        .zip(after.lines())
        .filter_map(|(before, after)| (before != after).then_some(after))
        .collect();
    assert_eq!(
        changed,
        vec!["version = \"3.6.0\"", &format!("digest  = \"sha256:{}\"", "f".repeat(64))],
        "only the version and the digest moved"
    );
}

#[test]
fn an_exact_pin_names_one_version_and_a_digest_pin_names_the_content() {
    let source = source();
    let exact = reference("acme/web-service@3.5.0-rc.1");
    let by_digest = reference(&format!("acme/web-service@sha256:{}", "e".to_string().repeat(64)));
    let missing = reference("acme/web-service@3.1.2");

    let lock = block_on(update(&source, &[exact.clone(), by_digest.clone()], &Lock::new()))
        .expect("both pins resolve");
    assert_eq!(lock.get(&exact).expect("the exact pin").version, "3.5.0-rc.1");
    assert_eq!(lock.get(&by_digest).expect("the digest pin").version, "4.0.0");
    assert_eq!(lock.get(&by_digest).expect("the digest pin").digest, digest_of('e'));

    // An exact pin is exact: a version nobody published resolves to nothing
    // rather than sliding to the nearest release.
    assert!(matches!(
        block_on(update(&source, std::slice::from_ref(&missing), &Lock::new())),
        Err(LockUpdateError::Unresolved { .. })
    ));
}

#[test]
fn a_reference_a_repository_stopped_using_is_dropped_from_the_lock() {
    let three = reference("acme/web-service@v3");
    let four = reference("acme/web-service@v4");
    let first = block_on(update(&source(), &[three.clone(), four.clone()], &Lock::new()))
        .expect("both resolve");

    let second =
        block_on(update(&source(), std::slice::from_ref(&three), &first)).expect("@v3 resolves");
    assert_eq!(second.entries().len(), 1, "the lock records what is pinned now, not a history");
    assert_eq!(second.get(&four), None);
}

/// The same reference listed twice in `ship.ks` is one pin with one entry: the
/// update must not emit a duplicate the lock parser would refuse.
#[test]
fn the_same_reference_twice_is_one_entry_and_still_parses() {
    let three = reference("acme/web-service@v3");
    let lock =
        block_on(update(&source(), &[three.clone(), three.clone(), three.clone()], &Lock::new()))
            .expect("a repeated reference resolves once per listing, not to a conflict");

    assert_eq!(lock.entries().len(), 1, "one reference is one entry");
    assert_eq!(
        Lock::parse(&lock.render()).expect("the lock re-parses"),
        lock,
        "a lock the parser refuses is not a lock"
    );
}

/// A source cannot choose what a lock file contains. A version carrying a
/// newline would otherwise be written out as extra entries.
#[test]
fn a_published_version_that_is_not_a_version_never_reaches_the_lock() {
    let injection = "1.0.0-x\n\n[[block]]\nname = \"evil/block\"\nrequest = \"v9\"\n\
                     version = \"9.9.9\"\ndigest = \"sha256:{}\""
        .replace("{}", &"c".repeat(64));
    let hostile = FakeBlockSource::new().with_versions(vec![
        BlockVersion {
            version: injection.clone(),
            digest: digest_of('c'),
            signature: SignatureStatus::Signed,
        },
        published("3.4.1"),
    ]);
    let three = reference("acme/web-service@v3");
    let lock = block_on(update(&hostile, std::slice::from_ref(&three), &Lock::new()))
        .expect("3.4.1 satisfies the major");

    assert_eq!(lock.entries().len(), 1);
    assert_eq!(lock.entries()[0].version, "3.4.1", "the unparsable tag is skipped, not locked");
    let reparsed = Lock::parse(&lock.render()).expect("the lock re-parses");
    assert!(
        reparsed.get(&BlockRef::parse("evil/block@v9").unwrap()).is_none(),
        "no entry was injected"
    );
}

/// Every locked version is a semver, digest pin or not: a block published as
/// `2024-10-01` is not lockable, because the format cannot record it.
#[test]
fn a_digest_pin_does_not_lock_a_version_that_is_not_a_version() {
    let dated = FakeBlockSource::new().with_versions(vec![BlockVersion {
        version: "2024-10-01".to_string(),
        digest: digest_of('e'),
        signature: SignatureStatus::Signed,
    }]);
    let by_digest = reference(&format!("acme/web-service@sha256:{}", "e".to_string().repeat(64)));

    assert!(
        matches!(
            block_on(update(&dated, std::slice::from_ref(&by_digest), &Lock::new())),
            Err(LockUpdateError::Unresolved { .. })
        ),
        "a digest names content, but the version beside it must still be a version"
    );
}

#[test]
fn verify_refuses_content_that_is_not_the_pin_and_content_that_is_unsigned() {
    let lock = block_on(update(&source(), &[reference("acme/web-service@v3")], &Lock::new()))
        .expect("resolved");
    let entry = lock.get(&reference("acme/web-service@v3")).expect("the entry");
    let signer = publisher();

    assert_eq!(
        verify(entry, &package('c', SignatureStatus::Signed), Some(&signer), &baseline()),
        Ok(signer.clone())
    );
    assert_eq!(
        verify(entry, &package('e', SignatureStatus::Signed), Some(&signer), &baseline())
            .expect_err("not what was pinned"),
        VerifyError::DigestMismatch {
            reference: "acme/web-service@v3".to_string(),
            expected: digest_of('c'),
            actual: digest_of('e'),
        }
    );
    let unsigned =
        verify(entry, &package('c', SignatureStatus::Unsigned), Some(&signer), &baseline())
            .expect_err("an unsigned block is not used");
    assert!(matches!(unsigned, VerifyError::Unsigned { .. }), "{unsigned:?}");
    assert!(unsigned.to_string().contains("no verified signature"), "{unsigned}");
}

/// The gap #125 names: a signature from *anybody* used to clear the gate, so a
/// compromised publisher's block reached a run with the digest right and the
/// status `signed`.
#[test]
fn a_block_signed_by_an_unlisted_publisher_is_refused() {
    let lock = block_on(update(&source(), &[reference("acme/web-service@v3")], &Lock::new()))
        .expect("resolved");
    let entry = lock.get(&reference("acme/web-service@v3")).expect("the entry");
    let intruder = SignerIdentity::Keyless {
        issuer: "https://token.evil.example".to_string(),
        subject: "acme/release@v3".to_string(),
    };

    // Same digest, `signed`, and still refused: the allowlist is the only thing
    // that tells an honest publisher from a compromised one.
    let refused =
        verify(entry, &package('c', SignatureStatus::Signed), Some(&intruder), &baseline())
            .expect_err("the baseline does not list that publisher");
    let VerifyError::Untrusted { reference, reason } = &refused else {
        panic!("a signature from an unlisted publisher is Untrusted, got {refused:?}");
    };
    assert_eq!(reference, "acme/web-service@v3");
    assert_eq!(reason, &Untrusted::UnknownPublisher(intruder));
    assert!(refused.to_string().contains("acme/release@v3"), "the message names it: {refused}");
}

#[test]
fn a_block_signed_by_a_listed_publisher_is_accepted_and_named() {
    let lock = block_on(update(&source(), &[reference("acme/web-service@v3")], &Lock::new()))
        .expect("resolved");
    let entry = lock.get(&reference("acme/web-service@v3")).expect("the entry");

    let identity =
        verify(entry, &package('c', SignatureStatus::Signed), Some(&publisher()), &baseline())
            .expect("a listed publisher is trusted");

    assert_eq!(identity, publisher(), "the caller records who published what it runs");
}

/// A package can report `signed` while the signature referrer resolved to nobody
/// — a compromised registry, a referrer that did not verify. The baseline does
/// not rescue it: without an identity there is no publisher to hold to it, so
/// the gate fails closed.
#[test]
fn a_block_with_no_signer_is_refused_even_against_a_permissive_baseline() {
    let lock = block_on(update(&source(), &[reference("acme/web-service@v3")], &Lock::new()))
        .expect("resolved");
    let entry = lock.get(&reference("acme/web-service@v3")).expect("the entry");

    let refused = verify(entry, &package('c', SignatureStatus::Signed), None, &baseline())
        .expect_err("a signed package with no identity behind it names no publisher");

    assert!(
        matches!(refused, VerifyError::Untrusted { reason: Untrusted::Unsigned, .. }),
        "{refused:?}"
    );
    assert!(refused.to_string().contains("unsigned"), "{refused}");
}
