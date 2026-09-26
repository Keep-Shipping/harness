//! Resolving a step's secrets through the [`Secrets`] port, and registering
//! every value with the run's [`Redactor`].
//!
//! The engine resolves a step's secrets **before any step output is read**, so
//! a secret that reaches stdout, stderr or a dependency's stack trace is
//! already registered and every log line goes out through
//! [`Redactor::redact`]. This module is the one funnel through which that
//! happens; steps never resolve secrets themselves.

use ks_core::ids::StepId;
use ks_core::ports::secrets::{Redactor, SecretBundle, SecretRef, Secrets, SecretsError};

/// Resolves every `(name, reference)` pair for one step and returns the
/// resulting [`SecretBundle`].
///
/// Each value is registered with `redactor` the moment it is resolved —
/// before the bundle is returned, and before any later resolution in the same
/// call fails — so a partial failure still leaves the redactor able to scrub
/// the values that did resolve. The first resolution error aborts with that
/// error; the caller decides (via [`SecretsError::check_severity`]) whether it
/// is a warning or a failure.
pub async fn resolve_step_secrets(
    secrets: &dyn Secrets,
    refs: &[(String, SecretRef)],
    step: &StepId,
    redactor: &mut Redactor,
) -> Result<SecretBundle, SecretsError> {
    let mut bundle = SecretBundle::new();
    for (name, reference) in refs {
        let value = secrets.resolve(reference, step).await?;
        redactor.register(&value);
        bundle.insert(name.clone(), value);
    }
    Ok(bundle)
}
