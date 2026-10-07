//! Fake for the [`BlockSource`] port: scripted packages by digest, a record of
//! every call. Never talks to a network.

use std::sync::Mutex;

use ks_core::ports::BoxFuture;
use ks_core::ports::block_source::{
    BlockPackage, BlockSource, BlockSourceError, ResolvedBlock, VersionReq,
};
use ks_core::ports::blocks::BlockVersion;
use ks_core::ports::supply_chain::Digest;

/// The block name no adapter may serve. See [`conformance`].
pub const RESERVED_NAME: &str = "conformance";

/// The hex of a digest no adapter may hold. All `f`, so it cannot collide with
/// a real content digest a test would script. See [`conformance`].
pub const RESERVED_DIGEST_HEX: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// A [`BlockSource`] whose resolutions, packages and version lists you script per
/// test.
///
/// Each of the three methods is scripted separately, so a test can resolve a
/// reference and then fetch what it resolved to, or answer a resolve with an
/// error while `fetch` still works. Every call is recorded, so tests can assert
/// what was asked, not just what came back.
///
/// Unscripted input is a [`BlockSourceError::NotFound`] rather than a panic:
/// a fake that only answers what it was given would let a test pass without
/// ever exercising the path it meant to.
///
/// ```
/// use ks_core::ports::block_source::{
///     BlockDefinition, BlockPackage, BlockSource, VersionReq,
/// };
/// use ks_core::ports::supply_chain::Digest;
/// use ks_testing::{block_on, block_source::FakeBlockSource};
///
/// let digest = Digest::parse("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc").expect("digest");
/// let source = FakeBlockSource::new().with_package(
///     digest.clone(),
///     BlockPackage {
///         name: "acme/web-service".to_string(),
///         version: "3.1.0".to_string(),
///         digest: digest.clone(),
///         definition: BlockDefinition::default(),
///         signature: ks_core::ports::blocks::SignatureStatus::Signed,
///     },
/// );
///
/// let fetched = block_on(source.fetch(&digest)).expect("the scripted package");
/// assert_eq!(fetched.version, "3.1.0");
/// assert_eq!(source.fetches(), vec![digest]);
/// ```
pub struct FakeBlockSource {
    resolved: Mutex<std::collections::BTreeMap<String, Result<ResolvedBlock, BlockSourceError>>>,
    packages: Mutex<std::collections::BTreeMap<Digest, BlockPackage>>,
    versions: Mutex<Result<Vec<BlockVersion>, BlockSourceError>>,
    calls: Mutex<Vec<BlockSourceCall>>,
}

impl FakeBlockSource {
    /// Creates a fake that knows nothing: every resolve and every fetch is
    /// [`BlockSourceError::NotFound`] echoing the reference that was asked for,
    /// and every version list is empty — an empty answer is normal, not a
    /// failure.
    pub fn new() -> FakeBlockSource {
        FakeBlockSource {
            resolved: Mutex::new(Default::default()),
            packages: Mutex::new(Default::default()),
            versions: Mutex::new(Ok(Vec::new())),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Scripts what [`BlockSource::resolve`] answers for the block named `name`.
    ///
    /// The script is keyed by name, because that is what the port is asked: a
    /// block's resolution is a fact about that block, and a fake that answered
    /// every reference from one answer would let a test resolve `a` and `b` to
    /// the same digest and never notice — which is the bug a per-name script
    /// is what makes a test able to catch. It is the same shape as
    /// [`FakePolicyStore`](crate::policy::FakePolicyStore)'s per-repository
    /// baseline script.
    ///
    /// The constraint itself is not part of the key, and that is the fake's one
    /// simplification: a block name answers for whatever constraint is asked
    /// with, so a test that wants two constraints to resolve differently must
    /// use two names. Anything scripted for another name (or for no name at
    /// all) is [`BlockSourceError::NotFound`], not a panic.
    #[must_use]
    pub fn with_resolved(self, name: &str, resolved: ResolvedBlock) -> FakeBlockSource {
        self.resolved
            .lock()
            .expect("fake block source resolve script")
            .insert(name.to_string(), Ok(resolved));
        self
    }

    /// Scripts a failing [`BlockSource::resolve`] for the block named `name`.
    #[must_use]
    pub fn with_resolve_error(self, name: &str, error: BlockSourceError) -> FakeBlockSource {
        self.resolved
            .lock()
            .expect("fake block source resolve script")
            .insert(name.to_string(), Err(error));
        self
    }

    /// Scripts the package [`BlockSource::fetch`] serves for `digest`.
    #[must_use]
    pub fn with_package(self, digest: Digest, package: BlockPackage) -> FakeBlockSource {
        self.packages.lock().expect("fake block source package script").insert(digest, package);
        self
    }

    /// Scripts what [`BlockSource::list_versions`] answers for every name.
    #[must_use]
    pub fn with_versions(self, versions: Vec<BlockVersion>) -> FakeBlockSource {
        *self.versions.lock().expect("fake block source version script") = Ok(versions);
        self
    }

    /// Every call the fake was asked, oldest first.
    pub fn calls(&self) -> Vec<BlockSourceCall> {
        self.calls.lock().expect("fake block source call record").clone()
    }

    /// The digests [`BlockSource::fetch`] was asked for, oldest first.
    pub fn fetches(&self) -> Vec<Digest> {
        self.calls()
            .into_iter()
            .filter_map(|call| match call {
                BlockSourceCall::Fetch { digest } => Some(digest),
                _ => None,
            })
            .collect()
    }
}

impl Default for FakeBlockSource {
    fn default() -> FakeBlockSource {
        FakeBlockSource::new()
    }
}

/// One call a [`FakeBlockSource`] received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockSourceCall {
    /// [`BlockSource::resolve`], with the name and constraint as asked.
    Resolve {
        /// The block name that was asked for.
        name: String,
        /// The version constraint that was asked for.
        version_req: String,
    },
    /// [`BlockSource::fetch`], with the digest as asked.
    Fetch {
        /// The digest that was asked for.
        digest: Digest,
    },
    /// [`BlockSource::list_versions`], with the name as asked.
    ListVersions {
        /// The block name that was asked for.
        name: String,
    },
}

impl BlockSource for FakeBlockSource {
    fn resolve<'a>(
        &'a self,
        name: &'a str,
        version_req: &'a VersionReq,
    ) -> BoxFuture<'a, Result<ResolvedBlock, BlockSourceError>> {
        self.calls.lock().expect("fake block source call record").push(BlockSourceCall::Resolve {
            name: name.to_string(),
            version_req: version_req.as_str().to_string(),
        });
        let scripted =
            self.resolved.lock().expect("fake block source resolve script").get(name).cloned();
        Box::pin(std::future::ready(
            scripted
                .unwrap_or_else(|| Err(BlockSourceError::NotFound { reference: name.to_string() })),
        ))
    }

    fn fetch<'a>(
        &'a self,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<BlockPackage, BlockSourceError>> {
        self.calls
            .lock()
            .expect("fake block source call record")
            .push(BlockSourceCall::Fetch { digest: digest.clone() });
        let found =
            self.packages.lock().expect("fake block source package script").get(digest).cloned();
        Box::pin(std::future::ready(
            found.ok_or_else(|| BlockSourceError::NotFound { reference: digest.to_string() }),
        ))
    }

    fn list_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Vec<BlockVersion>, BlockSourceError>> {
        self.calls
            .lock()
            .expect("fake block source call record")
            .push(BlockSourceCall::ListVersions { name: name.to_string() });
        let scripted = self.versions.lock().expect("fake block source version script").clone();
        Box::pin(std::future::ready(scripted))
    }
}

/// The `BlockSource` conformance kit: every source adapter must pass this.
///
/// It probes a name and a digest reserved for the kit — a source that serves
/// them is not answering the protocol, it is returning the test's own
/// expectation back at it, and every assertion below would then pass
/// vacuously. The reserved name must come back as
/// [`BlockSourceError::NotFound`] and the reserved digest likewise — a fetch
/// that failed for some other reason, or one that succeeded, both fail the
/// kit — and both without a panic. `NotFound` names a *reference*, which is
/// the name for a resolve and the digest for a fetch, and the kit requires the
/// answer to echo the reference it was asked for in both cases.
///
/// It then checks the shape of an answer: an empty version list is a normal
/// answer and must be `Ok`, never an error, because a block nobody has
/// published yet is a fact and not a failure.
pub async fn conformance(source: &dyn BlockSource) {
    let requirement = VersionReq::new("conformance").expect("the reserved constraint is not empty");

    let refused = source.resolve(RESERVED_NAME, &requirement).await;
    match refused {
        Err(BlockSourceError::NotFound { reference }) => {
            assert_eq!(
                reference, RESERVED_NAME,
                "NotFound must echo the reference it was asked for"
            );
        }
        Err(other) => {
            panic!("block_source conformance: `{RESERVED_NAME}` must be NotFound, got {other:?}")
        }
        Ok(resolved) => panic!(
            "block_source conformance: no adapter may serve the reserved `{RESERVED_NAME}` block, \
             got {resolved:?}"
        ),
    }

    let reserved = Digest::parse(&format!("sha256:{RESERVED_DIGEST_HEX}"))
        .expect("the reserved digest is well formed");
    match source.fetch(&reserved).await {
        Err(BlockSourceError::NotFound { reference }) => {
            assert_eq!(
                reference,
                reserved.to_string(),
                "NotFound must echo the digest it was asked for"
            )
        }
        Err(other) => {
            panic!("block_source conformance: `{reserved}` must be NotFound, got {other:?}")
        }
        Ok(package) => panic!(
            "block_source conformance: no adapter may serve the reserved digest {reserved}, got \
             {package:?}"
        ),
    }

    // A name nobody published is an empty list, not an error.
    match source.list_versions(RESERVED_NAME).await {
        Ok(versions) => assert!(
            versions.is_empty(),
            "block_source conformance: an unpublished block must list no versions, got {versions:?}"
        ),
        Err(error) => panic!(
            "block_source conformance: listing versions must never be a failure, got {error:?}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;
    use ks_core::ports::block_source::{BlockDefinition, BlockField};
    use ks_core::ports::blocks::SignatureStatus;

    fn package(name: &str, version: &str, digest: Digest) -> BlockPackage {
        BlockPackage {
            name: name.to_string(),
            version: version.to_string(),
            digest: digest.clone(),
            definition: BlockDefinition {
                summary: "A block.".to_string(),
                inputs: vec![BlockField {
                    name: "in".to_string(),
                    type_name: "string".to_string(),
                    required: true,
                }],
                outputs: Vec::new(),
            },
            signature: SignatureStatus::Unsigned,
        }
    }

    #[test]
    fn unscripted_names_and_digests_are_not_found() {
        let source = FakeBlockSource::new();
        let requirement = VersionReq::new("3.1").expect("constraint");
        assert!(matches!(
            block_on(source.resolve("acme/nope", &requirement)),
            Err(BlockSourceError::NotFound { .. })
        ));
        let hex = "d".repeat(64);
        let digest = Digest::parse(&format!("sha256:{hex}")).expect("digest");
        assert!(matches!(block_on(source.fetch(&digest)), Err(BlockSourceError::NotFound { .. })));
    }

    #[test]
    fn scripted_packages_come_back_by_digest_and_every_call_is_recorded() {
        let hex = "b".repeat(64);
        let digest = Digest::parse(&format!("sha256:{hex}")).expect("digest");
        let other = Digest::parse(&format!("sha256:{}", "e".repeat(64))).expect("digest");
        let source = FakeBlockSource::new()
            .with_package(digest.clone(), package("acme/web-service", "3.1.0", digest.clone()))
            .with_versions(vec![BlockVersion {
                version: "3.1.0".to_string(),
                digest: digest.clone(),
                signature: SignatureStatus::Signed,
            }]);

        let fetched = block_on(source.fetch(&digest)).expect("the scripted package");
        assert_eq!(fetched.version, "3.1.0");
        assert!(block_on(source.fetch(&other)).is_err(), "only the scripted digest is served");

        assert_eq!(block_on(source.list_versions("acme/web-service")).expect("versions").len(), 1);

        let requirement = VersionReq::new("3.1").expect("constraint");
        assert!(block_on(source.resolve("acme/web-service", &requirement)).is_err());

        assert_eq!(
            source.calls(),
            vec![
                BlockSourceCall::Fetch { digest: digest.clone() },
                BlockSourceCall::Fetch { digest: other.clone() },
                BlockSourceCall::ListVersions { name: "acme/web-service".to_string() },
                BlockSourceCall::Resolve {
                    name: "acme/web-service".to_string(),
                    version_req: "3.1".to_string(),
                },
            ]
        );
        assert_eq!(source.fetches(), vec![digest, other]);
    }

    fn resolved_block(name: &str, version: &str, digest: Digest) -> ResolvedBlock {
        ResolvedBlock { name: name.to_string(), version: version.to_string(), digest }
    }

    #[test]
    fn a_scripted_resolve_answers_the_name_it_was_scripted_for() {
        let source = FakeBlockSource::new().with_resolved(
            "acme/web-service",
            resolved_block("acme/web-service", "3.1.0", digest_of("c")),
        );
        let requirement = VersionReq::new("3.1.0").expect("constraint");
        let resolved =
            block_on(source.resolve("acme/web-service", &requirement)).expect("resolved");
        assert_eq!(resolved.version, "3.1.0");

        // A sibling name was never scripted, so it is NotFound rather than the
        // answer meant for `acme/web-service`.
        assert_eq!(
            block_on(source.resolve("acme/other", &requirement)),
            Err(BlockSourceError::NotFound { reference: "acme/other".to_string() })
        );
    }

    /// The reason the resolve script is keyed by name at all: two blocks asked
    /// for separately are answered separately. A single global script would make
    /// both of these resolve to the same digest and the test would still pass.
    #[test]
    fn two_different_names_resolve_to_two_different_scripted_answers() {
        let source = FakeBlockSource::new()
            .with_resolved(
                "acme/web-service",
                resolved_block("acme/web-service", "3.1.0", digest_of("c")),
            )
            .with_resolved("acme/api", resolved_block("acme/api", "1.4.2", digest_of("d")));
        let requirement = VersionReq::new("*").expect("constraint");

        let web = block_on(source.resolve("acme/web-service", &requirement)).expect("scripted");
        let api = block_on(source.resolve("acme/api", &requirement)).expect("scripted");
        assert_eq!(web.version, "3.1.0");
        assert_eq!(api.version, "1.4.2");
        assert_ne!(web.digest, api.digest, "each name resolves to its own pin");
        assert_eq!(web.name, "acme/web-service");
        assert_eq!(api.name, "acme/api");
    }

    /// `with_resolve_error` is how a test stages a source that refuses to
    /// resolve — a registry that is down, or a constraint it will not serve —
    /// and it must fail for that name only, leaving the rest of the fake intact.
    #[test]
    fn a_scripted_resolve_error_fails_that_name_only_and_still_records_the_call() {
        let source = FakeBlockSource::new()
            .with_resolve_error(
                "acme/broken",
                BlockSourceError::Backend { message: "registry unreachable".to_string() },
            )
            .with_resolved(
                "acme/web-service",
                resolved_block("acme/web-service", "3.1.0", digest_of("c")),
            );
        let requirement = VersionReq::new("3.1").expect("constraint");

        assert_eq!(
            block_on(source.resolve("acme/broken", &requirement)),
            Err(BlockSourceError::Backend { message: "registry unreachable".to_string() })
        );
        assert!(block_on(source.resolve("acme/web-service", &requirement)).is_ok());

        // An unscripted name still reads as NotFound, not as the scripted error.
        assert_eq!(
            block_on(source.resolve("acme/never-scripted", &requirement)),
            Err(BlockSourceError::NotFound { reference: "acme/never-scripted".to_string() })
        );

        assert_eq!(
            source.calls(),
            vec![
                BlockSourceCall::Resolve {
                    name: "acme/broken".to_string(),
                    version_req: "3.1".to_string(),
                },
                BlockSourceCall::Resolve {
                    name: "acme/web-service".to_string(),
                    version_req: "3.1".to_string(),
                },
                BlockSourceCall::Resolve {
                    name: "acme/never-scripted".to_string(),
                    version_req: "3.1".to_string(),
                },
            ]
        );
    }

    #[test]
    fn an_empty_version_list_is_a_normal_answer() {
        let source = FakeBlockSource::new();
        assert_eq!(block_on(source.list_versions("acme/unpublished")), Ok(Vec::new()));
    }

    #[test]
    fn the_fake_passes_conformance() {
        block_on(conformance(&FakeBlockSource::new()));
    }

    /// Content that does not hash to the digest it was asked for must fail
    /// closed, and say which two digests disagreed.
    ///
    /// The fake itself cannot produce this — it serves what it was handed and
    /// reports [`BlockSourceError::NotFound`] for anything else — so the case
    /// is pinned against a rigged adapter, which is where it will actually
    /// occur: an OCI or git source whose bytes disagree with the pin.
    #[test]
    fn content_that_is_not_the_digest_asked_for_fails_closed() {
        let expected = digest_of("b");
        let actual = digest_of("c");
        let rigged = ServingWrongBytes { actual: actual.clone() };

        let error = block_on(rigged.fetch(&expected))
            .expect_err("content that is not what was pinned must not be served");
        assert_eq!(
            error,
            BlockSourceError::DigestMismatch { expected: expected.clone(), actual: actual.clone() },
            "the failure must name both digests, so an operator can tell which pin is wrong"
        );
        let message = error.to_string();
        assert!(message.contains(&expected.to_string()), "{message}");
        assert!(message.contains(&actual.to_string()), "{message}");

        // And the fake, which has only ever been handed that digest's package,
        // still refuses everything else rather than serving it.
        let source = FakeBlockSource::new()
            .with_package(expected.clone(), package("acme/x", "1.0.0", expected));
        assert!(
            block_on(source.fetch(&digest_of("d"))).is_err(),
            "only the pinned digest is served"
        );
    }

    fn digest_of(hex_byte: &str) -> Digest {
        Digest::parse(&format!("sha256:{}", hex_byte.repeat(64))).expect("digest")
    }

    /// An adapter that always serves the wrong bytes: the fail-closed case the
    /// fake cannot stage by itself.
    struct ServingWrongBytes {
        actual: Digest,
    }

    impl BlockSource for ServingWrongBytes {
        fn resolve<'a>(
            &'a self,
            _name: &'a str,
            _version_req: &'a VersionReq,
        ) -> BoxFuture<'a, Result<ResolvedBlock, BlockSourceError>> {
            Box::pin(std::future::ready(Err(BlockSourceError::Backend {
                message: "not scripted".to_string(),
            })))
        }

        fn fetch<'a>(
            &'a self,
            digest: &'a Digest,
        ) -> BoxFuture<'a, Result<BlockPackage, BlockSourceError>> {
            Box::pin(std::future::ready(Err(BlockSourceError::DigestMismatch {
                expected: digest.clone(),
                actual: self.actual.clone(),
            })))
        }

        fn list_versions<'a>(
            &'a self,
            _name: &'a str,
        ) -> BoxFuture<'a, Result<Vec<BlockVersion>, BlockSourceError>> {
            Box::pin(std::future::ready(Ok(Vec::new())))
        }
    }

    /// A source rigged to serve the reserved name must abort the kit rather
    /// than sail through it.
    #[test]
    fn conformance_never_passes_vacuously() {
        let rigged = FakeBlockSource::new().with_resolved(
            RESERVED_NAME,
            ResolvedBlock {
                name: RESERVED_NAME.to_string(),
                version: "1.0.0".to_string(),
                digest: Digest::parse(&format!("sha256:{}", "d".repeat(64))).expect("digest"),
            },
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(conformance(&rigged));
        }));
        assert!(result.is_err(), "conformance must refuse a source that serves the reserved name");
    }

    /// A source rigged to serve the reserved *digest* — the other way the kit
    /// could be satisfied vacuously — must abort it too.
    #[test]
    fn conformance_refuses_a_source_that_serves_the_reserved_digest() {
        let reserved =
            Digest::parse(&format!("sha256:{RESERVED_DIGEST_HEX}")).expect("well formed digest");
        let rigged = FakeBlockSource::new()
            .with_package(reserved.clone(), package("acme/served", "1.0.0", reserved));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(conformance(&rigged));
        }));
        assert!(
            result.is_err(),
            "conformance must refuse a source that serves the reserved digest"
        );
    }
}
