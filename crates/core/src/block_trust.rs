//! What a block has to prove before it runs, and what a block is not allowed
//! to contain.
//!
//! A block is someone else's pipeline code running with your credentials. It
//! names the steps your run executes, it reads the inputs you hand it, and it
//! runs under your cloud keys. Two questions follow, and this module answers
//! both.
//!
//! **Who published it?** The [`BlockSource`](crate::ports::block_source::BlockSource)
//! adapter fetches content and does *not* decide whether a signature is
//! acceptable ([ADR
//! 0011](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0011-block-distribution.md)):
//! the adapter has no idea what your organization's publishers are. What it
//! reports is a [`SignatureStatus`](crate::ports::blocks::SignatureStatus) —
//! signed or unsigned, and nothing about *who* — so
//! [`BlockPackage`](crate::ports::block_source::BlockPackage) carries no
//! identity either. The identity is what
//! [`Signer::verify`](crate::ports::supply_chain::Signer::verify) returns when
//! it checks the signature referrer, and [`verify`] is what decides whether
//! that identity is one this organization trusts. Failing closed is the whole
//! point: an unverifiable block is refused, never run.
//!
//! **What is in it?** A block that carries `policy:` would be a block shipping
//! its own rules into your run. Policy is the repo's and the org's alone ([ADR
//! 0012](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0012-policy-authority.md)),
//! and a block is nobody's repo. [`policy_sections`] finds those entries, and
//! `check` errors on them today ([`Code::BlockPolicy`](ks_lang::Code::BlockPolicy)).
//! `blocks publish` (ADR
//! 0011) is to call the same function when it lands, so the two agree by
//! construction rather than by two rules that could drift apart.
//!
//! Neither function does I/O: [`verify`] is a pure comparison against the
//! baseline, and [`policy_sections`] reads an already-parsed file.

use std::fmt;

use ks_lang::{File, Span};

use crate::ports::policy::Baseline;
use crate::ports::supply_chain::SignerIdentity;

/// Why a block is refused.
///
/// There is no third case and no "probably fine": the two here are what can go
/// wrong with a block's provenance, and everything else about it is somebody
/// else's problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Untrusted {
    /// The package carries no signature at all.
    Unsigned,
    /// It is signed, but by an identity the baseline does not list.
    UnknownPublisher(SignerIdentity),
}

impl fmt::Display for Untrusted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Untrusted::Unsigned => {
                write!(f, "block is unsigned: no publisher can be held to it")
            }
            Untrusted::UnknownPublisher(id) => write!(
                f,
                "block is signed by an identity this organization does not trust: {}",
                identity_text(id)
            ),
        }
    }
}

impl std::error::Error for Untrusted {}

/// An identity as it reads in a refusal: `key:alice`, or `<subject> from
/// <issuer>`.
///
/// [`SignerIdentity`] has no `Display` of its own — the port type stays free of
/// presentation so an adapter is never forced to have an opinion. This is that
/// opinion, in one place, so a refusal and a log line name the same signer the
/// same way. It matches the `signed_by` spelling `ks_engine::signing` writes.
fn identity_text(identity: &SignerIdentity) -> String {
    match identity {
        SignerIdentity::Key { key_id } => format!("key:{key_id}"),
        SignerIdentity::Keyless { issuer, subject } => format!("{subject} from {issuer}"),
    }
}

/// Whether `signer` may run a block, and under whose name.
///
/// `signer` is the identity a [`Signer::verify`](crate::ports::supply_chain::Signer::verify)
/// returned for the block's signature referrer — `None` when the package is
/// unsigned. The answer is `Ok` only when the block **is** signed **and** that
/// identity is in [`publishers`](Baseline::publishers), compared exactly: a
/// keyless identity matches a keyless identity with the same issuer *and* the
/// same subject, and nothing looser, because an issuer that reuses a subject
/// name across organizations would otherwise inherit the allowlist.
///
/// Pure and offline, so it is callable from the same path as `check`.
///
/// **It has no call site yet.** Nothing resolves a block today, so nothing
/// consults this verdict. It is the decision the block-resolution path (`using`,
/// `ship.lock`) will call when that lands, under this contract: `check`
/// reports an `Err` as a *warning* — a laptop author should see that a block
/// is untrusted without being stopped by it — and `run` refuses outright.
/// Both callers land with block resolution, not here.
pub fn verify(
    signer: Option<&SignerIdentity>,
    baseline: &Baseline,
) -> Result<SignerIdentity, Untrusted> {
    let Some(id) = signer else { return Err(Untrusted::Unsigned) };
    if baseline.publishers.contains(id) {
        Ok(id.clone())
    } else {
        Err(Untrusted::UnknownPublisher(id.clone()))
    }
}

/// The top-level `policy:` entries in a block definition, for the caller to
/// refuse.
///
/// Empty when `file` is a workflow rather than a block — there is no `block:`
/// header, so the `policy:` it carries is the repo's own and is exactly where
/// policy belongs. A block file returns one span per `policy:` entry; the
/// grammar allows more than one, and each is reported on its own.
///
/// `check` calls this today and errors on every span it returns. `blocks
/// publish` (ADR 0011) is to call the same function when it lands and refuse
/// such a block outright — one rule, two callers, rather than two rules that
/// could drift apart.
#[must_use]
pub fn policy_sections(file: &File<'_>) -> Vec<Span> {
    let is_block = file.entries().any(|e| e.key_name() == Some("block"));
    if !is_block {
        return Vec::new();
    }
    file.entries().filter(|e| e.key_name() == Some("policy")).map(|e| e.node().span()).collect()
}
