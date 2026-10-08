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
//! and a block is nobody's repo. [`policy_sections`] finds those entries,
//! `check` errors on them today ([`Code::BlockPolicy`](ks_lang::Code::BlockPolicy)),
//! and `blocks publish` refuses such a block outright (ADR 0011), so the two
//! agree by construction rather than by two rules that could drift apart.
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
/// Pure and offline, so it costs a caller nothing but a comparison.
///
/// `ks_engine::blocks::verify` is a caller, and it fails closed: a package it
/// is handed comes back as `VerifyError::Untrusted` and is not used. A signature
/// from *any* signer satisfies the digest-and-status rules, so without this
/// verdict a compromised publisher's block would clear the gate those rules
/// leave open ([#125](https://github.com/Keep-Shipping/harness/issues/125)).
///
/// **That gate is not yet in front of a run.** Nothing resolves a block at run
/// time today — `using` and `ship.lock` are not on any path a run takes — so
/// no run consults this verdict, and the gate above has no production caller of
/// its own. The rule is enforced wherever it is called and tested as a gate;
/// calling it from `run` lands with block resolution, not here.
///
/// `check` does not consult this function, and is not going to: it reports
/// [`policy_sections`] as an error but has no
/// `ship.lock`-resolved package in hand and so no signature to check. The
/// advisory half of the contract — a laptop author should see that a block is
/// untrusted — is what that remains for; enforcement is the gate's.
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
/// `check` calls this and errors on every span it returns, and `blocks publish`
/// calls the same function and refuses such a block outright (ADR 0011) — one
/// rule, two callers, rather than two rules that could drift apart.
#[must_use]
pub fn policy_sections(file: &File<'_>) -> Vec<Span> {
    let is_block = file.entries().any(|e| e.key_name() == Some("block"));
    if !is_block {
        return Vec::new();
    }
    file.entries().filter(|e| e.key_name() == Some("policy")).map(|e| e.node().span()).collect()
}
