//! Fake for the [`Secrets`] port: scripted in-memory values, scripted
//! unavailability, and a record of every resolution attempt.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use ks_core::ids::StepId;
use ks_core::ports::BoxFuture;
use ks_core::ports::secrets::{ResolverInfo, SecretRef, SecretValue, Secrets, SecretsError};

/// A [`Secrets`] resolver you script per test.
///
/// ```
/// use ks_core::ids::StepId;
/// use ks_core::ports::secrets::{SecretRef, Secrets};
/// use ks_testing::{block_on, secrets::FakeSecrets};
///
/// let fake = FakeSecrets::new()
///     .with(SecretRef::new("env", "deploy-token"), b"hunter2".to_vec());
/// let reference = SecretRef::new("env", "deploy-token");
/// let value = block_on(fake.resolve(&reference, &StepId::new("deploy")))
///     .expect("scripted references resolve");
/// assert_eq!(value.with_bytes(|bytes| bytes.to_vec()), b"hunter2".to_vec());
/// ```
///
/// Unscripted references fail with
/// [`NotFound`](SecretsError::NotFound); references scripted with
/// [`unavailable`](FakeSecrets::unavailable) fail with
/// [`NotAvailableInContext`](SecretsError::NotAvailableInContext), which is
/// how the engine's warning path is exercised. Values are zeroised when the
/// fake is dropped, and its `Debug` prints counts, never bytes.
#[derive(Default)]
pub struct FakeSecrets {
    values: BTreeMap<SecretRef, Vec<u8>>,
    unavailable: BTreeMap<SecretRef, String>,
    calls: Mutex<Vec<(SecretRef, StepId)>>,
}

impl FakeSecrets {
    /// Creates an empty fake.
    pub fn new() -> FakeSecrets {
        FakeSecrets::default()
    }

    /// Scripts `bytes` as the value of `reference`.
    pub fn with(mut self, reference: SecretRef, bytes: impl Into<Vec<u8>>) -> FakeSecrets {
        self.values.insert(reference, bytes.into());
        self
    }

    /// Scripts `reference` to fail with `NotAvailableInContext` and `reason`.
    pub fn unavailable(mut self, reference: SecretRef, reason: impl Into<String>) -> FakeSecrets {
        self.unavailable.insert(reference, reason.into());
        self
    }

    /// Every `(reference, step)` resolution attempt so far, oldest first.
    pub fn calls(&self) -> Vec<(SecretRef, StepId)> {
        self.calls.lock().expect("fake secrets call record").clone()
    }
}

/// The fake's stored values are zeroised on drop, best-effort and without
/// `unsafe` — same guarantees and caveats as [`SecretValue`]'s own drop.
impl Drop for FakeSecrets {
    fn drop(&mut self) {
        let mut marker: u8 = 0;
        for bytes in self.values.values_mut() {
            for byte in bytes.iter_mut() {
                marker |= *byte;
                *byte = 0;
            }
        }
        std::hint::black_box(marker);
    }
}

impl fmt::Debug for FakeSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeSecrets")
            .field("values", &self.values.len())
            .field("unavailable", &self.unavailable.len())
            .field("calls", &self.calls.lock().expect("fake secrets call record").len())
            .finish()
    }
}

impl Secrets for FakeSecrets {
    fn resolve<'a>(
        &'a self,
        reference: &'a SecretRef,
        for_step: &'a StepId,
    ) -> BoxFuture<'a, Result<SecretValue, SecretsError>> {
        self.calls
            .lock()
            .expect("fake secrets call record")
            .push((reference.clone(), for_step.clone()));
        let result = if let Some(reason) = self.unavailable.get(reference) {
            Err(SecretsError::NotAvailableInContext {
                reference: reference.clone(),
                reason: reason.clone(),
            })
        } else if let Some(bytes) = self.values.get(reference) {
            Ok(SecretValue::new(bytes.clone()))
        } else {
            Err(SecretsError::NotFound { reference: reference.clone() })
        };
        Box::pin(std::future::ready(result))
    }

    fn describe(&self) -> ResolverInfo {
        ResolverInfo {
            name: "fake".to_string(),
            backend: "ks-testing in-memory".to_string(),
            available: true,
            note: Some("scripted per test".to_string()),
        }
    }
}

/// The `Secrets` conformance kit: every resolver adapter must pass this.
///
/// Run it against the adapter as a trusted principal (before any actor gate).
/// It checks that `describe` names a real resolver and that a reference under
/// the reserved `conformance` resolver — which no adapter serves — comes back
/// as `NotFound`, never a panic or a value.
pub async fn conformance(secrets: &dyn Secrets) {
    let info = secrets.describe();
    assert!(!info.name.is_empty(), "Secrets::describe must report a resolver name");
    assert!(!info.backend.is_empty(), "Secrets::describe must report a backend");

    let reference = SecretRef::new("conformance", "missing");
    let step = StepId::new("conformance");
    match secrets.resolve(&reference, &step).await {
        Err(SecretsError::NotFound { reference: reported }) => {
            assert_eq!(reported, reference, "NotFound must echo the reference it was asked for");
        }
        Err(other) => {
            panic!("secrets conformance: {reference} must be NotFound, got {other:?}")
        }
        Ok(_) => {
            panic!("secrets conformance: no adapter may serve the reserved `conformance` resolver")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    #[test]
    fn fake_debug_never_prints_bytes() {
        let fake = FakeSecrets::new().with(SecretRef::new("env", "token"), b"hunter2".to_vec());
        let debug = format!("{fake:?}");
        assert!(!debug.contains("hunter"), "{debug}");
    }

    #[test]
    fn unscripted_references_are_not_found() {
        let fake = FakeSecrets::new();
        let reference = SecretRef::new("env", "nope");
        let step = StepId::new("deploy");
        assert!(matches!(
            block_on(fake.resolve(&reference, &step)),
            Err(SecretsError::NotFound { .. })
        ));
    }

    #[test]
    fn every_attempt_is_recorded() {
        let reference = SecretRef::new("env", "token");
        let fake = FakeSecrets::new().with(reference.clone(), b"x".to_vec());
        let step = StepId::new("deploy");
        for _ in 0..2 {
            assert!(block_on(fake.resolve(&reference, &step)).is_ok());
        }
        assert_eq!(fake.calls(), vec![(reference.clone(), step.clone()), (reference, step)]);
    }

    #[test]
    fn the_fake_passes_conformance() {
        let fake = FakeSecrets::new().with(SecretRef::new("env", "token"), b"x".to_vec());
        block_on(conformance(&fake));
    }
}
