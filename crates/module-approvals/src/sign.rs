//! The decision signature. The run receiving a `repository_dispatch` cannot ask
//! us, so the approval carries its own proof: an HMAC over the fields that give
//! the dispatch meaning. Change the ticket, the repo, the outcome, the
//! approver, the timestamp or one byte of a digest and it no longer verifies.
//!
//! The canonical form is one `key=value` line per field, because a signature
//! over ambiguous bytes proves nothing: a digest list joined with `,` and a step
//! name *containing* a `,` must not be the same message. [`crate::validate`]
//! holds every signed field to a charset in which that holds — no newline, no
//! comma, no `=` — and the scheme line keeps a signature over some other message
//! type from being read as this one.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::store::RequestRow;

/// The domain separator.
const SCHEME: &str = "keepshipping-approval-v1";

/// Test-only: the instant every signature in this file's tests is taken at.
#[cfg(test)]
const AT: &str = "2027-01-15T09:00:00Z";

/// The bytes an approval signs. Digests are sorted, so the same artifact set
/// signs identically whatever order the runner listed it in.
pub(crate) fn canonical(
    request: &RequestRow,
    decision: &str,
    approver: &str,
    decided_at: &str,
) -> String {
    let mut digests: Vec<&str> = request.artifacts.iter().map(|a| a.sha256.as_str()).collect();
    digests.sort_unstable();
    format!(
        "{SCHEME}\nticket={}\nrun={}\nrepo={}\nstep={}\ndecision={decision}\napprover={approver}\n\
         decided_at={decided_at}\nartifacts={}",
        request.ticket,
        request.run_id,
        request.repo,
        request.step,
        digests.join(","),
    )
}

/// The signature as lower-case hex, the form every HMAC in this workspace
/// travels in, so it survives JSON and a shell argument unchanged.
pub(crate) fn sign(secret: &[u8], canonical: &str) -> String {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(canonical.as_bytes());
    mac.finalize().into_bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Artifact;

    fn request() -> RequestRow {
        RequestRow {
            ticket: "01JQ".into(),
            run_id: "42".into(),
            repo: "Keep-Shipping/harness".into(),
            step: "apply".into(),
            summary: "1 to create".into(),
            artifacts: vec![
                Artifact { name: "plan.tfplan".into(), sha256: "bb".repeat(32) },
                Artifact { name: "main.tf".into(), sha256: "aa".repeat(32) },
            ],
            team_org: "keep-shipping".into(),
            team_slug: "platform".into(),
            proposed_by: "ada".into(),
            reason: "conformance".into(),
            created_at: "2027-01-15T08:00:00Z".into(),
            expires_at: "2027-01-16T08:00:00Z".into(),
        }
    }

    fn signature(secret: &[u8], request: &RequestRow, decision: &str, approver: &str) -> String {
        sign(secret, &canonical(request, decision, approver, AT))
    }

    #[test]
    fn only_the_order_of_the_artifacts_is_forgettable() {
        let mut shuffled = request();
        shuffled.artifacts.reverse();
        let base = signature(b"secret", &request(), "approve", "grace");
        assert_eq!(base, signature(b"secret", &shuffled, "approve", "grace"));

        // Every bound field, and the secret, change the signature.
        let mut moved = request();
        moved.step = "destroy".into();
        let mut digested = request();
        digested.artifacts[0].sha256 = "cc".repeat(32);
        for other in [
            signature(b"secret", &moved, "approve", "grace"),
            signature(b"secret", &digested, "approve", "grace"),
            signature(b"secret", &request(), "deny", "grace"),
            signature(b"secret", &request(), "approve", "alan"),
            signature(b"other", &request(), "approve", "grace"),
            sign(b"secret", &canonical(&request(), "approve", "grace", "2027-01-15T09:00:01Z")),
        ] {
            assert_ne!(base, other);
        }
    }
}
