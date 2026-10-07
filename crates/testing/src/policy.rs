//! Fake for the [`PolicyStore`] port: a scripted baseline per repository, a
//! record of every repository asked for. Never talks to a network.

use std::sync::Mutex;

use ks_core::ports::BoxFuture;
use ks_core::ports::policy::{Baseline, PolicyStore, PolicyStoreError};

/// The org no store may have configured. See [`conformance`].
pub const RESERVED_ORG: &str = "conformance-org";

/// The first reserved repository, under [`RESERVED_ORG`]. See [`conformance`].
pub const RESERVED_REPO: &str = "conformance-a";

/// A second reserved repository, under [`RESERVED_ORG`]. Two distinct probes,
/// so the kit can tell whether a store distinguishes repositories at all. See
/// [`conformance`].
pub const RESERVED_REPO_B: &str = "conformance-b";

/// A [`PolicyStore`] whose baselines you script per test.
///
/// The script is keyed by `(org, repo)`, because that is what the port is
/// asked: an org's baseline is not a global setting, and a fake that answered
/// every repository from one answer would let a test pass without ever
/// distinguishing an org that configured a baseline from one that did not.
/// Repositories with no scripted answer are `Ok(None)` — "no baseline
/// configured", the first-class state the port documents — not an error.
///
/// ```
/// use ks_core::ports::policy::{
///     Baseline, BaselineSource, Disposition, PolicyStore, Provenance, Rule, Subject,
/// };
/// use ks_core::ports::run_context::ActorKind;
/// use ks_testing::{block_on, policy::FakePolicyStore};
///
/// let source = BaselineSource::RepoFile {
///     org: "acme".to_string(),
///     path: ".keepshipping/policy.ks".to_string(),
///     git_ref: "main".to_string(),
/// };
/// let store = FakePolicyStore::new().with_baseline(
///     "acme",
///     "web",
///     Baseline {
///         rules: vec![Rule {
///             subject: Subject::Actor(ActorKind::Agent),
///             verb: "deploy".to_string(),
///             object: "prod".to_string(),
///             disposition: Disposition::Allow,
///             provenance: Provenance::Baseline { source: source.clone() },
///         }],
///         source: Some(source),
///     },
/// );
///
/// let read = block_on(store.baseline("acme", "web")).expect("scripted").expect("configured");
/// assert_eq!(read.decide(ActorKind::Agent, "deploy", "prod"), Disposition::Allow);
/// assert_eq!(store.asked(), vec![("acme".to_string(), "web".to_string())]);
/// ```
pub struct FakePolicyStore {
    baselines:
        Mutex<std::collections::BTreeMap<(String, String), Result<Baseline, PolicyStoreError>>>,
    asked: Mutex<Vec<(String, String)>>,
}

impl FakePolicyStore {
    /// Creates a store with nothing configured: every repository is
    /// `Ok(None)`, and every ask is recorded.
    pub fn new() -> FakePolicyStore {
        FakePolicyStore { baselines: Mutex::new(Default::default()), asked: Mutex::new(Vec::new()) }
    }

    /// Scripts the baseline `org`/`repo` is configured with.
    #[must_use]
    pub fn with_baseline(self, org: &str, repo: &str, baseline: Baseline) -> FakePolicyStore {
        self.baselines
            .lock()
            .expect("fake policy store baseline script")
            .insert((org.to_string(), repo.to_string()), Ok(baseline));
        self
    }

    /// Scripts a failing read for `org`/`repo`.
    #[must_use]
    pub fn with_error(self, org: &str, repo: &str, error: PolicyStoreError) -> FakePolicyStore {
        self.baselines
            .lock()
            .expect("fake policy store baseline script")
            .insert((org.to_string(), repo.to_string()), Err(error));
        self
    }

    /// Every `(org, repo)` pair the store was asked for, oldest first.
    pub fn asked(&self) -> Vec<(String, String)> {
        self.asked.lock().expect("fake policy store ask record").clone()
    }
}

impl Default for FakePolicyStore {
    fn default() -> FakePolicyStore {
        FakePolicyStore::new()
    }
}

impl PolicyStore for FakePolicyStore {
    fn baseline<'a>(
        &'a self,
        org: &'a str,
        repo: &'a str,
    ) -> BoxFuture<'a, Result<Option<Baseline>, PolicyStoreError>> {
        self.asked
            .lock()
            .expect("fake policy store ask record")
            .push((org.to_string(), repo.to_string()));
        let scripted = self
            .baselines
            .lock()
            .expect("fake policy store baseline script")
            .get(&(org.to_string(), repo.to_string()))
            .cloned();
        Box::pin(std::future::ready(match scripted {
            None => Ok(None),
            Some(Ok(baseline)) => Ok(Some(baseline)),
            Some(Err(error)) => Err(error),
        }))
    }
}

/// The `PolicyStore` conformance kit: every store adapter must pass this.
///
/// It reads two reserved `(org, repo)` pairs, and **both must come back
/// `Ok(None)`** — "no baseline configured", the first-class state ADR 0012
/// decided on. Anything else fails the kit, and there are exactly two ways to
/// fail it:
///
/// - `Err` — a reserved pair is a repository nobody configured, so an error
///   for it is an adapter failing on a state that is every org's day one.
///   Reporting that as a failure would train every caller to treat "unprotected"
///   as a crash, the opposite of what ADR 0012 decided.
/// - `Ok(Some(…))` — a store that has *configured* a reserved pair is answering
///   about a repository the kit invented, so every assertion the kit could make
///   about it would be the test's own expectation reflected back. This is the
///   same rule the block-source kit applies to its reserved name and digest.
///
/// **The panic is the assertion.** There is no counter and no aggregate check:
/// a kit satisfied only by failures proves nothing about the read path, so the
/// way a store that has stopped answering is caught is that this function does
/// not return. The two probes differ only in the repository, which is the
/// point — the port is asked per repository, and a store that cannot be told
/// apart per repository has not implemented it.
///
/// The kit is I/O-free and synchronous in its demands, so it runs against a
/// fake and a real adapter alike without a network.
pub async fn conformance(store: &dyn PolicyStore) {
    for repo in [RESERVED_REPO, RESERVED_REPO_B] {
        match store.baseline(RESERVED_ORG, repo).await {
            Ok(None) => {}
            Ok(Some(baseline)) => panic!(
                "policy_store conformance: no adapter may have configured `{RESERVED_ORG}/{repo}`; \
                 a reserved repository reads `Ok(None)`, got {baseline:?}"
            ),
            Err(error) => panic!(
                "policy_store conformance: no adapter may have configured \
                 `{RESERVED_ORG}/{repo}`; an unconfigured org is `Ok(None)`, got {error:?}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;
    use ks_core::ports::policy::{
        ANY_OBJECT, BaselineSource, Disposition, Provenance, Rule, Subject, effective_baseline,
    };
    use ks_core::ports::run_context::ActorKind;

    fn source() -> BaselineSource {
        BaselineSource::RepoFile {
            org: "acme".to_string(),
            path: ".keepshipping/policy.ks".to_string(),
            git_ref: "main".to_string(),
        }
    }

    fn baseline() -> Baseline {
        Baseline {
            rules: vec![Rule {
                subject: Subject::Any,
                verb: "destroy".to_string(),
                object: "*".to_string(),
                disposition: Disposition::Never,
                provenance: Provenance::Baseline { source: source() },
            }],
            source: Some(source()),
        }
    }

    #[test]
    fn an_unconfigured_repository_is_none_not_an_error() {
        let store = FakePolicyStore::new();
        assert_eq!(block_on(store.baseline("acme", "web")), Ok(None));
        assert_eq!(store.asked(), vec![("acme".to_string(), "web".to_string())]);
    }

    #[test]
    fn each_repository_gets_its_own_scripted_baseline() {
        let store = FakePolicyStore::new().with_baseline("acme", "web", baseline());

        assert!(block_on(store.baseline("acme", "web")).expect("read").is_some());
        assert_eq!(
            block_on(store.baseline("acme", "api")),
            Ok(None),
            "a sibling repository is not configured by acme/web's baseline"
        );
        assert_eq!(store.asked().len(), 2);
    }

    #[test]
    fn scripted_errors_surface_and_still_record_the_ask() {
        let store = FakePolicyStore::new().with_error(
            "acme",
            "web",
            PolicyStoreError::Backend { message: "repository not found".to_string() },
        );
        assert_eq!(
            block_on(store.baseline("acme", "web")),
            Err(PolicyStoreError::Backend { message: "repository not found".to_string() })
        );
        assert_eq!(store.asked(), vec![("acme".to_string(), "web".to_string())]);
    }

    #[test]
    fn an_unconfigured_store_reads_as_the_conservative_baseline() {
        let store = FakePolicyStore::new();
        let read =
            block_on(store.baseline("acme", "web")).expect("an unconfigured org is not an error");
        let effective = effective_baseline(read);
        assert_eq!(effective, Baseline::conservative());
        assert_eq!(effective.decide(ActorKind::Agent, "check", "prod"), Disposition::Allow);
        assert_eq!(effective.decide(ActorKind::Human, "destroy", "prod"), Disposition::Never);
    }

    #[test]
    fn the_fake_passes_conformance() {
        block_on(conformance(&FakePolicyStore::new()));
        // A store configured for real repositories is still a pass; only the
        // reserved pairs are the kit's own.
        block_on(conformance(&FakePolicyStore::new().with_baseline("acme", "web", baseline())));
    }

    /// Configuring a reserved pair fails the kit, exactly as serving the
    /// block-source kit's reserved name or digest does. A kit that let it
    /// through would be reading a repository it invented.
    #[test]
    fn conformance_refuses_a_store_that_has_configured_a_reserved_pair() {
        let store = FakePolicyStore::new().with_baseline(RESERVED_ORG, RESERVED_REPO, baseline());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(conformance(&store));
        }));
        assert!(result.is_err(), "conformance must refuse a configured reserved pair");
    }

    /// A store rigged to fail every read must abort the kit rather than sail
    /// through it: a kit that only ever asserted on failures would be
    /// satisfied by a port that never answers at all.
    #[test]
    fn conformance_never_passes_vacuously() {
        let always_fails = FakePolicyStore::new()
            .with_error(
                RESERVED_ORG,
                RESERVED_REPO,
                PolicyStoreError::Backend { message: "backend down".to_string() },
            )
            .with_error(
                RESERVED_ORG,
                RESERVED_REPO_B,
                PolicyStoreError::Backend { message: "backend down".to_string() },
            );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(conformance(&always_fails));
        }));
        assert!(result.is_err(), "conformance must refuse a store that fails every read");
    }

    /// Provenance is the port's own invariant rather than the kit's: a rule in
    /// a baseline that claims a source must be attributed to that document, and
    /// one claiming [`Provenance::Default`] is the built-in wearing an org's
    /// authority. The kit refuses a *configured* reserved pair outright, so it
    /// never gets far enough to inspect rules; the invariant is pinned here on
    /// the baseline it is about.
    #[test]
    fn a_configured_baseline_may_not_claim_the_default_provenance() {
        let wearing = Baseline {
            rules: vec![Rule {
                subject: Subject::Any,
                verb: "destroy".to_string(),
                object: ANY_OBJECT.to_string(),
                disposition: Disposition::Never,
                provenance: Provenance::Default,
            }],
            source: Some(source()),
        };
        // A baseline that claims a document has been read, yet attributes a
        // rule to nothing anyone wrote. Nothing in the type stops it, which is
        // why `explain` has to be able to tell the two apart.
        assert!(wearing.rules.iter().any(|rule| rule.provenance == Provenance::Default));
        assert!(wearing.source.is_some());
        assert_eq!(baseline().rules[0].provenance, Provenance::Baseline { source: source() });
    }
}
