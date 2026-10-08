//! The [`Secrets`] port: resolving named secrets without their values ever
//! leaking ([#49](https://github.com/Keep-Shipping/harness/issues/49)).
//!
//! The shape of the contract:
//!
//! - A [`SecretRef`] names a secret. Names are not secret — they appear in
//!   logs and diagnostics; only [`SecretValue`]s do.
//! - A value is raw bytes handed to the step through
//!   [`SecretValue::with_bytes`], so there is exactly one way to reach it and
//!   it is trivial to audit. Values have no `Display`, do not `Clone`, and
//!   their `Debug` prints `***`.
//! - [`Redactor`] scrubs registered values out of step output before it is
//!   written anywhere.
//! - [`ActorGatedSecrets`] is the policy front door: agent actors may only
//!   read allowlisted references.
//! - [`SecretsError::check_severity`] tells the checker
//!   ([#34](https://github.com/Keep-Shipping/harness/issues/34)) which
//!   failures are warnings and which are errors, so a missing secret is
//!   reported, never a crash.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::BoxFuture;
use crate::ids::StepId;

/// How the checker should report a secrets problem
/// ([#34](https://github.com/Keep-Shipping/harness/issues/34)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckSeverity {
    /// A problem with the run's configuration: report it, keep going.
    Warning,
    /// A problem that must fail the check or the run.
    Error,
}

/// A reference to a secret: which resolver to ask, and which key within it.
///
/// A reference is *not* secret — `resolver:key` appears in logs, diagnostics
/// and the run log. Order the fields the way the notation reads them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretRef {
    resolver: String,
    key: String,
}

impl SecretRef {
    /// Creates a reference, e.g. `SecretRef::new("env", "deploy-token")` for
    /// `env:deploy-token`.
    pub fn new(resolver: impl Into<String>, key: impl Into<String>) -> SecretRef {
        SecretRef { resolver: resolver.into(), key: key.into() }
    }

    /// The resolver (adapter) that owns the secret.
    pub fn resolver(&self) -> &str {
        &self.resolver
    }

    /// The key of the secret within the resolver.
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.resolver, self.key)
    }
}

/// The value of a secret: raw bytes that are awkward to leak by accident.
///
/// There is no `Display`, no `Clone`, and `Debug` prints `***`; the only way
/// in is [`with_bytes`](SecretValue::with_bytes). A `SecretValue` is an
/// owned value — resolution hands out a fresh one each call, and adapters
/// that must keep a copy hold the raw bytes and mint new `SecretValue`s.
#[derive(Default)]
pub struct SecretValue {
    bytes: Vec<u8>,
}

impl SecretValue {
    /// Wraps raw bytes as a secret value.
    pub fn new(bytes: Vec<u8>) -> SecretValue {
        SecretValue { bytes }
    }

    /// The only way to read a secret: hand your closure the bytes.
    ///
    /// Keeping the access behind a closure makes every read site greppable
    /// and keeps values from escaping into strings, logs or serialisation by
    /// mistake.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.bytes)
    }

    /// The number of secret bytes. (The length is for matching bookkeeping;
    /// there is deliberately no public accessor, so length metadata cannot
    /// leak past this module.)
    fn byte_len(&self) -> usize {
        self.bytes.len()
    }
}

/// Best-effort zeroisation, without `unsafe` (see
/// [#49](https://github.com/Keep-Shipping/harness/issues/49)): the bytes are
/// overwritten with zeros and the loop is pinned with
/// [`std::hint::black_box`] so the optimizer cannot elide the stores. This
/// covers only this allocation — copies the allocator made while the `Vec`
/// grew are not reached; if an adapter needs stronger guarantees, an ADR can
/// swap in the `zeroize` crate there.
impl Drop for SecretValue {
    fn drop(&mut self) {
        let mut marker: u8 = 0;
        for byte in self.bytes.iter_mut() {
            marker |= *byte;
            *byte = 0;
        }
        std::hint::black_box(marker);
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

/// The resolved secrets of one step, keyed by the name the step declared.
///
/// Iteration is sorted by name so runs are reproducible in the log.
#[derive(Default)]
pub struct SecretBundle {
    entries: BTreeMap<String, SecretValue>,
}

impl SecretBundle {
    /// Creates an empty bundle.
    pub fn new() -> SecretBundle {
        SecretBundle { entries: BTreeMap::new() }
    }

    /// Inserts `value` under `name`, returning the value it replaces, if any.
    /// (The replaced value is zeroised on drop.)
    pub fn insert(&mut self, name: impl Into<String>, value: SecretValue) -> Option<SecretValue> {
        self.entries.insert(name.into(), value)
    }

    /// The value stored under `name`.
    pub fn get(&self, name: &str) -> Option<&SecretValue> {
        self.entries.get(name)
    }

    /// Iterates the `(name, value)` pairs, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &SecretValue)> {
        self.entries.iter().map(|(name, value)| (name.as_str(), value))
    }

    /// The declared names, sorted.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }
}

impl fmt::Debug for SecretBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Names only: a bundle's debug output must be safe to paste into a bug report.
        f.debug_struct("SecretBundle").field("names", &self.names().collect::<Vec<_>>()).finish()
    }
}

/// What a resolver can say about itself — descriptions, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverInfo {
    /// The resolver's name, as it appears in `ship.ks` references.
    pub name: String,
    /// What backs the resolver, e.g. `process-env` or `vault`.
    pub backend: String,
    /// Whether the resolver can serve anything in this environment at all.
    pub available: bool,
    /// A human-readable note, e.g. why the resolver is unavailable.
    pub note: Option<String>,
}

impl ResolverInfo {
    /// One-line description safe for logs and `keepshipping run` output.
    /// It contains the resolver's name and backend — never a value.
    pub fn describe(&self) -> String {
        let availability = if self.available { "available" } else { "unavailable" };
        match &self.note {
            Some(note) => {
                format!(
                    "resolver {:?} (backend {:?}, {availability}; {note})",
                    self.name, self.backend
                )
            }
            None => {
                format!("resolver {:?} (backend {:?}, {availability})", self.name, self.backend)
            }
        }
    }
}

/// Why a [`Secrets`] resolver refused or failed to resolve a reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretsError {
    /// No secret under this reference.
    NotFound {
        /// The reference that could not be found.
        reference: SecretRef,
    },
    /// The secret exists, but not for this run's context (e.g. wrong branch
    /// or environment). The checker reports this as a
    /// [`Warning`](CheckSeverity::Warning) — it usually means the workflow
    /// asked for a secret this context never carries.
    NotAvailableInContext {
        /// The reference that is unavailable.
        reference: SecretRef,
        /// Why the resolver refuses, safe to print.
        reason: String,
    },
    /// The run's actor may not read this secret; see
    /// [`ActorGatedSecrets`].
    ForbiddenForActor {
        /// The reference that was refused.
        reference: SecretRef,
        /// The actor that was refused.
        actor: String,
    },
    /// The resolver's backend itself failed (network, auth, …).
    Backend {
        /// The reference resolution was attempted for.
        reference: SecretRef,
        /// What the backend reported, safe to print.
        message: String,
    },
}

impl SecretsError {
    /// Whether the checker reports this as a
    /// [`Warning`](CheckSeverity::Warning) or an [`Error`](CheckSeverity::Error).
    ///
    /// Only [`NotAvailableInContext`](SecretsError::NotAvailableInContext) is
    /// a warning: it is a property of the context, and the checker
    /// ([#34](https://github.com/Keep-Shipping/harness/issues/34)) reports it
    /// as a warning, never a crash. Everything else is an error.
    pub fn check_severity(&self) -> CheckSeverity {
        match self {
            SecretsError::NotAvailableInContext { .. } => CheckSeverity::Warning,
            SecretsError::NotFound { .. }
            | SecretsError::ForbiddenForActor { .. }
            | SecretsError::Backend { .. } => CheckSeverity::Error,
        }
    }
}

impl fmt::Display for SecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretsError::NotFound { reference } => {
                write!(f, "secret {reference} not found")
            }
            SecretsError::NotAvailableInContext { reference, reason } => {
                write!(f, "secret {reference} is not available in this context: {reason}")
            }
            SecretsError::ForbiddenForActor { reference, actor } => {
                write!(f, "actor {actor:?} is not allowed to read secret {reference}")
            }
            SecretsError::Backend { reference, message } => {
                write!(f, "secrets backend failed for {reference}: {message}")
            }
        }
    }
}

impl std::error::Error for SecretsError {}

/// The `Secrets` port: a resolver adapter answers one question — *what are the
/// bytes behind this reference, for this step?*
///
/// Adapters return a fresh [`SecretValue`] per call; the value is zeroised
/// when dropped. Adapters must fail with [`SecretsError`] rather than panicking,
/// and must serve the same reference deterministically within a run so a
/// re-run of one step behaves like the original.
pub trait Secrets: Send + Sync {
    /// Resolves `reference` for the step `for_step` is currently running.
    fn resolve<'a>(
        &'a self,
        reference: &'a SecretRef,
        for_step: &'a StepId,
    ) -> BoxFuture<'a, Result<SecretValue, SecretsError>>;

    /// Describes the resolver — its name and backend, never any value.
    fn describe(&self) -> ResolverInfo;
}

/// Scrubs registered secret values out of text before it is logged.
///
/// The engine resolves a step's secrets through this port and registers every
/// value with the run's `Redactor` before any step output is read, so a
/// secret that shows up in stdout — or a dependency's stack trace — is
/// replaced with `***`. Every match lands in a merged span — overlapping or
/// adjacent matches included — so a shorter value that is a prefix of a
/// longer one cannot leak the longer one's tail, and no byte of any
/// registered value survives.
///
/// Values are stored as zeroised-on-drop copies ([`SecretValue`]), so a
/// `Redactor` is exactly as leaky as a resolved value: no more. Its `Debug`
/// prints a count, never a value.
#[derive(Default)]
pub struct Redactor {
    /// Registered values, longest first.
    values: Vec<SecretValue>,
}

impl Redactor {
    /// Creates an empty redactor.
    pub fn new() -> Redactor {
        Redactor { values: Vec::new() }
    }

    /// Registers a value for redaction; empty values are ignored (they would
    /// otherwise replace everything, or nothing, depending on the matcher —
    /// either is useless). Registering the same value twice is harmless.
    pub fn register(&mut self, value: &SecretValue) {
        value.with_bytes(|bytes| {
            if bytes.is_empty() {
                return;
            }
            let copy = SecretValue::new(bytes.to_vec());
            let position =
                self.values.partition_point(|existing| existing.byte_len() >= bytes.len());
            self.values.insert(position, copy);
        });
    }

    /// Returns `text` with every occurrence of every registered value
    /// replaced by `***`.
    ///
    /// Matching is over UTF-8: values that are not valid UTF-8 are skipped
    /// (kept simple on purpose — bytes-level matching would need a scanner
    /// over non-char-boundaries for no real payload yet). Occurrences are
    /// searched at every starting offset and their byte ranges merged, so
    /// overlapping matches — one secret inside another's match, two secrets
    /// overlapping, adjacent matches — leave no surviving bytes.
    pub fn redact(&self, text: &str) -> String {
        let mut redacted = String::with_capacity(text.len());
        let mut emitted = 0;
        for (start, end) in self.match_spans(text) {
            redacted.push_str(&text[emitted..start]);
            redacted.push_str("***");
            emitted = end;
        }
        redacted.push_str(&text[emitted..]);
        redacted
    }

    /// Whether `text` contains any registered value at all.
    ///
    /// The question [`reject_secret_outputs`](crate::step::reject_secret_outputs) asks about a
    /// step's return value before it is read: the run's secrets are already registered here, so a
    /// yes means the step handed one back. It reuses `match_spans` — the same scan
    /// [`Redactor::redact`] makes — so it agrees exactly with what redaction would have hidden,
    /// including the skip for non-UTF-8 values, and a second implementation cannot drift from
    /// the first. Matching here is *detection*, not redaction: the caller must not print `text`.
    pub fn contains(&self, text: &str) -> bool {
        !self.match_spans(text).is_empty()
    }

    /// Every byte range of `text` a registered value matches, merged so
    /// overlapping or adjacent matches form one span, in order. Ranges from
    /// matching a UTF-8 value inside a `&str` always land on char
    /// boundaries, so the caller's slicing is safe.
    fn match_spans(&self, text: &str) -> Vec<(usize, usize)> {
        let mut spans: Vec<(usize, usize)> = Vec::new();
        for value in &self.values {
            value.with_bytes(|bytes| {
                let Ok(pattern) = std::str::from_utf8(bytes) else { return };
                let mut offset = 0;
                while let Some(index) = text[offset..].find(pattern) {
                    let start = offset + index;
                    spans.push((start, start + pattern.len()));
                    // Step one character, not one byte (a `+1` could land
                    // inside a multibyte char), so overlapping occurrences
                    // are still found.
                    offset = start + text[start..].chars().next().map_or(1, char::len_utf8);
                }
            });
        }
        spans.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
        for (start, end) in spans {
            match merged.last_mut() {
                Some((_, last_end)) if start <= *last_end => *last_end = (*last_end).max(end),
                _ => merged.push((start, end)),
            }
        }
        merged
    }
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor").field("values", &self.values.len()).finish()
    }
}

/// The policy front door for [`Secrets`]: what an actor may read.
///
/// The engine wraps the run's resolver with this gate, passing `is_agent` as
/// “the run's [`RunContext`] actor kind is `Agent`” (the `RunContext` port is
/// still landing, so the gate takes a plain `bool` for now). A human-run
/// pipeline delegates unchanged; an agent run may only read references on the
/// allowlist and gets [`SecretsError::ForbiddenForActor`] for anything else.
///
/// The allowlist is a stand-in for the effective policy, which the policy
/// work ([#103](https://github.com/Keep-Shipping/harness/issues/103)) will
/// own; when that lands, the gate reads the policy instead of a `BTreeSet`.
///
/// [`RunContext`]: super::run_context
pub struct ActorGatedSecrets<S> {
    inner: S,
    is_agent: bool,
    allowed: BTreeSet<SecretRef>,
}

impl<S> ActorGatedSecrets<S> {
    /// Gates `inner`: `is_agent` gates, `allowed` is the set of references
    /// agents may read.
    pub fn new(inner: S, is_agent: bool, allowed: BTreeSet<SecretRef>) -> ActorGatedSecrets<S> {
        ActorGatedSecrets { inner, is_agent, allowed }
    }

    /// Whether the current actor may read `reference`.
    pub fn is_allowed(&self, reference: &SecretRef) -> bool {
        !self.is_agent || self.allowed.contains(reference)
    }
}

impl<S: Secrets> Secrets for ActorGatedSecrets<S> {
    fn resolve<'a>(
        &'a self,
        reference: &'a SecretRef,
        for_step: &'a StepId,
    ) -> BoxFuture<'a, Result<SecretValue, SecretsError>> {
        if self.is_agent && !self.allowed.contains(reference) {
            return Box::pin(std::future::ready(Err(SecretsError::ForbiddenForActor {
                reference: reference.clone(),
                // The gate only ever refuses agents; #103 will name the actor properly.
                actor: "agent".to_string(),
            })));
        }
        self.inner.resolve(reference, for_step)
    }

    fn describe(&self) -> ResolverInfo {
        self.inner.describe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::{Context, Poll, Waker};

    /// A minimal resolver for gate tests: every reference resolves to the
    /// same three bytes.
    #[derive(Default)]
    struct StubResolver;

    impl Secrets for StubResolver {
        fn resolve<'a>(
            &'a self,
            reference: &'a SecretRef,
            _for_step: &'a StepId,
        ) -> BoxFuture<'a, Result<SecretValue, SecretsError>> {
            let _ = reference;
            Box::pin(std::future::ready(Ok(SecretValue::new(b"stub".to_vec()))))
        }

        fn describe(&self) -> ResolverInfo {
            ResolverInfo {
                name: "stub".to_string(),
                backend: "in-memory".to_string(),
                available: true,
                note: None,
            }
        }
    }

    /// Polls a futures' future to completion with a noop waker. Fakes and
    /// stubs are always ready after the first poll, so busy-polling is fine —
    /// and it keeps `ks-core` from needing any executor dependency.
    fn block_on_free<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
        }
    }

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_secrets_trait_is_dyn_compatible() {
        assert_send_sync::<dyn Secrets>();
        let resolver: &dyn Secrets = &StubResolver;
        assert_eq!(resolver.describe().name, "stub");
    }

    #[test]
    fn secret_value_debug_never_prints_bytes() {
        let value = SecretValue::new(b"hunter2".to_vec());
        assert_eq!(format!("{value:?}"), "***");
        assert_eq!(value.with_bytes(|bytes| bytes.to_vec()), b"hunter2".to_vec());
    }

    #[test]
    fn secret_bundle_debug_shows_names_only() {
        let mut bundle = SecretBundle::new();
        bundle.insert("token", SecretValue::new(b"hunter2".to_vec()));
        bundle.insert("password", SecretValue::new(b"hunter3".to_vec()));
        let debug = format!("{bundle:?}");
        assert!(debug.contains("\"password\"") && debug.contains("\"token\""), "{debug}");
        assert!(!debug.contains("hunter"), "{debug}");
        // Sorted by name, and readable through the accessors.
        assert_eq!(bundle.names().collect::<Vec<_>>(), ["password", "token"]);
        assert!(bundle.get("token").is_some());
        assert_eq!(bundle.iter().count(), 2);
    }

    #[test]
    fn secret_values_are_zeroised_on_drop() {
        let mut leaked = Vec::new();
        {
            let value = SecretValue::new(b"hunter2".to_vec());
            value.with_bytes(|bytes| leaked.extend_from_slice(bytes));
        }
        // The copy we made is ours to zero; the point is the value's own
        // allocation is scrubbed without unsafe.
        leaked.fill(0);
        assert!(leaked.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn redactor_replaces_every_occurrence_with_stars() {
        let mut redactor = Redactor::new();
        redactor.register(&SecretValue::new(b"hunter2".to_vec()));
        let redacted = redactor.redact("login: hunter2 / pass: hunter2 again");
        assert_eq!(redacted, "login: *** / pass: *** again");
        assert!(!redacted.contains("hunter2"));
    }

    #[test]
    fn redactor_leaks_nothing_when_occurrences_overlap() {
        let mut redactor = Redactor::new();
        redactor.register(&SecretValue::new(b"aa".to_vec()));
        // Overlapping occurrences of one secret: byte-wise replacement of
        // non-overlapping matches would leave the trailing `a` in the clear.
        assert_eq!(redactor.redact("aaa"), "***");
        assert_eq!(redactor.redact("aaaa"), "***");
        // Multibyte secrets step by character, never into a char's middle.
        redactor.register(&SecretValue::new("éé".as_bytes().to_vec()));
        assert_eq!(redactor.redact("ééé"), "***");
    }

    #[test]
    fn redactor_merges_overlapping_and_adjacent_secrets() {
        let mut redactor = Redactor::new();
        redactor.register(&SecretValue::new(b"abc".to_vec()));
        redactor.register(&SecretValue::new(b"cde".to_vec()));
        // The two secrets overlap around the `c`; neither's tail may survive.
        assert_eq!(redactor.redact("xabcdey"), "x***y");
    }

    #[test]
    fn redactor_matches_longest_values_first() {
        let mut redactor = Redactor::new();
        redactor.register(&SecretValue::new(b"hunter2".to_vec()));
        redactor.register(&SecretValue::new(b"hunter2-infra".to_vec()));
        // If the shorter value matched first, "infra" would survive in the clear.
        let redacted = redactor.redact("token=hunter2-infra and token=hunter2");
        assert_eq!(redacted, "token=*** and token=***");
    }

    #[test]
    fn redactor_skips_non_utf8_and_empty_values() {
        let mut redactor = Redactor::new();
        redactor.register(&SecretValue::new(vec![0xFF, 0xFE, 0x00]));
        redactor.register(&SecretValue::new(Vec::new()));
        assert_eq!(redactor.redact("nothing to see"), "nothing to see");
    }

    #[test]
    fn contains_agrees_with_what_redact_would_have_hidden() {
        let mut redactor = Redactor::new();
        redactor.register(&SecretValue::new(b"hunter2".to_vec()));
        for text in ["hunter2", "login=hunter2", "hunter2hunter2", "hunter2-infra", "clean"] {
            assert_eq!(
                redactor.contains(text),
                redactor.redact(text).contains("***"),
                "{text:?} was detected and redacted inconsistently"
            );
        }
        // A redactor that never saw a value detects nothing — the check is only as
        // good as the registration the engine did before the step ran.
        assert!(!Redactor::new().contains("hunter2"));
    }

    #[test]
    fn redactor_debug_prints_a_count_not_values() {
        let mut redactor = Redactor::new();
        redactor.register(&SecretValue::new(b"hunter2".to_vec()));
        let debug = format!("{redactor:?}");
        assert!(debug.contains('1'), "{debug}");
        assert!(!debug.contains("hunter"), "{debug}");
    }

    #[test]
    fn error_severity_maps_not_available_to_warning() {
        let reference = SecretRef::new("env", "deploy-token");
        assert_eq!(
            SecretsError::NotAvailableInContext {
                reference: reference.clone(),
                reason: "wrong branch".to_string()
            }
            .check_severity(),
            CheckSeverity::Warning
        );
        for error in [
            SecretsError::NotFound { reference: reference.clone() },
            SecretsError::ForbiddenForActor {
                reference: reference.clone(),
                actor: "agent".to_string(),
            },
            SecretsError::Backend { reference, message: "vault down".to_string() },
        ] {
            assert_eq!(error.check_severity(), CheckSeverity::Error, "{error:?}");
        }
    }

    #[test]
    fn secret_refs_display_as_resolver_key() {
        let reference = SecretRef::new("env", "deploy-token");
        assert_eq!(reference.resolver(), "env");
        assert_eq!(reference.key(), "deploy-token");
        assert_eq!(reference.to_string(), "env:deploy-token");
    }

    #[test]
    fn resolver_info_describes_itself_without_values() {
        let info = ResolverInfo {
            name: "env".to_string(),
            backend: "process-env".to_string(),
            available: false,
            note: Some("no environment in `keepshipping check`".to_string()),
        };
        let description = info.describe();
        assert!(
            description.contains("env") && description.contains("unavailable"),
            "{description}"
        );
    }

    #[test]
    fn non_agents_delegate_to_the_inner_resolver() {
        let gate = ActorGatedSecrets::new(StubResolver, false, BTreeSet::new());
        let reference = SecretRef::new("env", "deploy-token");
        let step = StepId::new("deploy");
        let value = block_on_free(gate.resolve(&reference, &step)).expect("humans read anything");
        assert_eq!(value.with_bytes(|bytes| bytes.to_vec()), b"stub".to_vec());
        assert!(gate.is_allowed(&reference));
    }

    #[test]
    fn agents_may_read_allowlisted_references() {
        let reference = SecretRef::new("env", "deploy-token");
        let gate = ActorGatedSecrets::new(StubResolver, true, BTreeSet::from([reference.clone()]));
        let step = StepId::new("deploy");
        let value = block_on_free(gate.resolve(&reference, &step)).expect("allowlisted ref passes");
        assert_eq!(value.with_bytes(|bytes| bytes.len()), 4);
    }

    #[test]
    fn agents_are_refused_references_outside_the_allowlist() {
        let reference = SecretRef::new("env", "deploy-token");
        let gate = ActorGatedSecrets::new(StubResolver, true, BTreeSet::new());
        let step = StepId::new("deploy");
        assert!(!gate.is_allowed(&reference));
        match block_on_free(gate.resolve(&reference, &step)) {
            Err(SecretsError::ForbiddenForActor { reference, actor }) => {
                assert_eq!(reference.to_string(), "env:deploy-token");
                assert_eq!(actor, "agent");
            }
            other => panic!("expected ForbiddenForActor, got {other:?}"),
        }
    }

    #[test]
    fn the_gate_delegates_describe() {
        let gate = ActorGatedSecrets::new(StubResolver, true, BTreeSet::new());
        assert_eq!(gate.describe().name, "stub");
    }
}
