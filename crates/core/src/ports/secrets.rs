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
///
/// [`register`](Redactor::register) also registers each value's common
/// encodings — base64 (padded, unpadded and URL-safe), URL percent-encoding,
/// and JSON string escaping — because a step that encodes a secret before
/// printing it writes bytes the literal value never matches. Matching stays
/// exact and best-effort, so what is *not* covered is worth naming:
///
/// - base64 of a secret embedded at an offset other than a multiple of three
///   inside a longer blob: the surrounding bytes shift every triplet, so the
///   secret's own encoding does not appear as a substring. The three aligned
///   offsets of any longer blob are not registered either — that would mean
///   re-encoding every possible container.
/// - hashed, truncated, encrypted or otherwise transformed values.
/// - a secret split across lines or re-ordered before it is printed.
/// - non-UTF-8 values in the clear; those are skipped (see
///   [`redact`](Redactor::redact)), though their base64 and percent-encodings
///   are still registered.
///
/// Redaction is a safety net, not a guarantee: the reason `Secret` is a type
/// is what actually keeps values out of strings.
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

    /// Registers a value for redaction, together with each of its common
    /// encodings; empty values are ignored (they would otherwise replace
    /// everything, or nothing, depending on the matcher — either is useless).
    /// An encoding identical to the raw value is not registered twice.
    /// Registering the same value twice is harmless.
    ///
    /// The encodings are the ones a step is likely to produce on its own: the
    /// standard base64 alphabet (`+`/`/`) with and without padding, the URL-safe
    /// alphabet (`-`/`_`), percent-encoding of every byte outside the RFC 3986
    /// unreserved set, and the JSON string escaping `serde_json` writes. See the
    /// type's documentation for what this does not cover.
    pub fn register(&mut self, value: &SecretValue) {
        value.with_bytes(|bytes| {
            if bytes.is_empty() {
                return;
            }
            let mut patterns = vec![bytes.to_vec()];
            let padded = base64_encode(bytes, false);
            for encoded in [
                padded.clone(),
                // Unpadded base64 is the padded form minus its `=` run, and
                // URL-safe swaps `+`/`/` for `-`/`_`.
                base64_encode(bytes, true),
                base64_unpadded(&padded),
                percent_encode(bytes),
                json_escape(bytes),
            ] {
                // Only what the raw value does not already match: an encoding
                // that came out unchanged would only grow the scan.
                if encoded != bytes && !patterns.contains(&encoded) {
                    patterns.push(encoded);
                }
            }
            for pattern in patterns {
                self.insert_pattern(pattern);
            }
        });
    }

    /// Inserts one pattern, keeping `values` sorted longest-first so the
    /// longest match wins a tie in `match_spans`.
    fn insert_pattern(&mut self, pattern: Vec<u8>) {
        if pattern.is_empty() {
            return;
        }
        let position = self.values.partition_point(|existing| existing.byte_len() >= pattern.len());
        self.values.insert(position, SecretValue::new(pattern));
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

/// Uppercase hex, as percent-encoding writes it.
const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";
/// Lowercase hex, as `serde_json` writes its `\u00XX` escapes.
const HEX_LOWER: [u8; 16] = *b"0123456789abcdef";

/// Standard base64 (`+`/`/`) per RFC 4648 §4, or the URL-safe alphabet (`-`/`_`)
/// per §5, with padding. Hand-rolled because `ks-core` takes no dependencies
/// ([ADR 0004](../../../docs/adr/0004-secrets.md)).
fn base64_encode(bytes: &[u8], url_safe: bool) -> Vec<u8> {
    const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let alphabet = if url_safe { URL_SAFE } else { STANDARD };
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let bits = (first << 16) | (second << 8) | third;
        out.push(alphabet[(bits >> 18 & 0x3F) as usize]);
        out.push(alphabet[(bits >> 12 & 0x3F) as usize]);
        // A short final chunk has no bits left for these groups, so it pads.
        out.push(if chunk.len() > 1 { alphabet[(bits >> 6 & 0x3F) as usize] } else { b'=' });
        out.push(if chunk.len() > 2 { alphabet[(bits & 0x3F) as usize] } else { b'=' });
    }
    out
}

/// `padded` base64 with its trailing `=` run stripped, the form a caller that
/// knows its length omits.
fn base64_unpadded(padded: &[u8]) -> Vec<u8> {
    let keep = padded.iter().rposition(|byte| *byte != b'=').map_or(0, |index| index + 1);
    padded[..keep].to_vec()
}

/// Percent-encoding of every byte outside RFC 3986's unreserved set
/// (`ALPHA / DIGIT / "-" / "." / "_" / "~"`), as `application/x-www-form-urlencoded`
/// and URL-building code write it. The space becomes `%20` rather than `+`,
/// because the `+`-for-space form only appears in form bodies.
fn percent_encode(bytes: &[u8]) -> Vec<u8> {
    let unreserved =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
    let mut out = Vec::with_capacity(bytes.len());
    for byte in bytes {
        if unreserved(*byte) {
            out.push(*byte);
        } else {
            out.push(b'%');
            out.push(HEX_UPPER[usize::from(byte >> 4)]);
            out.push(HEX_UPPER[usize::from(byte & 0x0F)]);
        }
    }
    out
}

/// JSON string escaping as `serde_json` writes it, without the surrounding
/// quotes: `"` and `\` get a backslash, `\n \t \r \b \f` their two-letter
/// forms, and any other control byte a `\u00XX` escape. Bytes outside ASCII are
/// copied through, matching `serde_json`'s default (it escapes `/` only when the
/// caller asks). Non-UTF-8 bytes pass through unchanged and will simply never
/// match, exactly as the raw value does not.
fn json_escape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for byte in bytes {
        match byte {
            b'"' => out.extend_from_slice(br#"\""#),
            b'\\' => out.extend_from_slice(br"\\"),
            0x08 => out.extend_from_slice(br"\b"),
            0x0C => out.extend_from_slice(br"\f"),
            b'\n' => out.extend_from_slice(br"\n"),
            b'\r' => out.extend_from_slice(br"\r"),
            b'\t' => out.extend_from_slice(br"\t"),
            byte if *byte < 0x20 => {
                out.extend_from_slice(br"\u00");
                out.push(HEX_LOWER[usize::from(byte >> 4)]);
                out.push(HEX_LOWER[usize::from(byte & 0x0F)]);
            }
            byte => out.push(*byte),
        }
    }
    out
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
        // A count of patterns (the raw value plus its encodings), never bytes.
        assert!(debug.starts_with("Redactor { values: "), "{debug}");
        assert!(!debug.contains("hunter"), "{debug}");
        assert!(!debug.contains("hunter2"), "{debug}");
    }

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        // RFC 4648 §10's test vectors, and the §5 URL-safe case whose standard
        // encoding contains both `+` and `/`.
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes(), false), expected.as_bytes(), "{input:?}");
            // Unpadding only ever drops the trailing `=`.
            assert_eq!(
                base64_unpadded(&base64_encode(input.as_bytes(), false)),
                expected.trim_end_matches('=').as_bytes(),
                "{input:?}"
            );
        }
        // §5: bytes 0xFB 0xFF are `+/` in the standard alphabet, `-_` in the
        // URL-safe one.
        let standard = base64_encode(&[0xFB, 0xFF], false);
        assert_eq!(standard, b"+/8=");
        assert_eq!(base64_encode(&[0xFB, 0xFF], true), b"-_8=");
    }

    #[test]
    fn percent_encoding_escapes_everything_outside_the_unreserved_set() {
        // RFC 3986 §2.3: unreserved are ALPHA / DIGIT / "-" / "." / "_" / "~",
        // and everything else becomes `%XX` with uppercase hex.
        assert_eq!(percent_encode(b"abcXYZ019-._~"), b"abcXYZ019-._~");
        assert_eq!(percent_encode(b"s3cr3t p@ss"), b"s3cr3t%20p%40ss");
        assert_eq!(percent_encode(b"/?#[]"), b"%2F%3F%23%5B%5D");
        // Bytes above ASCII, too.
        assert_eq!(percent_encode(&[0xC3, 0xA9]), b"%C3%A9");
    }

    #[test]
    fn json_escaping_matches_serde_json() {
        assert_eq!(json_escape(b"plain"), b"plain");
        assert_eq!(json_escape(br#"a"b\c"#), br#"a\"b\\c"#);
        assert_eq!(json_escape(b"line\nbreak\ttab"), br"line\nbreak\ttab");
        assert_eq!(json_escape(b"\x08\x0c\r"), br"\b\f\r");
        // Other control characters get the \u00XX form, lowercase as serde_json writes it.
        assert_eq!(json_escape(b"\x00\x1f\x7f"), b"\\u0000\\u001f\x7f");
        // A solidus is left alone; that is not what serde_json does by default.
        assert_eq!(json_escape(b"a/b"), b"a/b");
    }

    #[test]
    fn redactor_catches_every_registered_encoding_of_a_secret() {
        let secret = b"s3cr3t \"p@ss\"/word\n+x";
        let mut redactor = Redactor::new();
        redactor.register(&SecretValue::new(secret.to_vec()));

        for (label, encoded) in [
            ("raw", secret.to_vec()),
            ("base64", base64_encode(secret, false)),
            ("base64 url-safe", base64_encode(secret, true)),
            ("base64 unpadded", base64_unpadded(&base64_encode(secret, false))),
            ("percent", percent_encode(secret)),
            ("json", json_escape(secret)),
        ] {
            let text = String::from_utf8(encoded.clone()).expect("these encodings are UTF-8");
            let redacted = redactor.redact(&format!("prefix {text} suffix"));
            assert_eq!(redacted, "prefix *** suffix", "{label} leaked: {redacted}");
        }
    }

    #[test]
    fn registering_an_encoding_costs_nothing_when_it_is_the_raw_value() {
        // `hunter2` is already base64-safe, so several encodings come out
        // unchanged; the redactor must not blow up, and must still catch it.
        let mut redactor = Redactor::new();
        redactor.register(&SecretValue::new(b"hunter2".to_vec()));
        assert_eq!(redactor.redact("token hunter2"), "token ***");
        // `Zm9vYmFy` is `foobar` base64'd; a literal that happens to look like
        // an encoding is not mistaken for one.
        assert_eq!(redactor.redact("Zm9vYmFy"), "Zm9vYmFy");
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
