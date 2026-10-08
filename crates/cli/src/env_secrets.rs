//! Environment-backed [`Secrets`] resolvers: `env` and `github-actions`.
//!
//! Both read environment variables — GitHub Actions already hands its secrets
//! to a job as variables ([ADR 0004](../../docs/adr/0004-secrets.md)) — and
//! they differ only in two ways: the naming convention a key is read under, and
//! when each is allowed to read anything at all.
//!
//! - `env:NAME` reads `NAME` verbatim. It is **opt-in outside CI**: an
//!   operator opts a laptop in explicitly (or runs under `CI=true`), so a
//!   machine that merely has the variable set cannot silently serve a
//!   workflow's secrets. This is the gate `ci-only` environments rely on, so
//!   it fails closed with [`SecretsError::NotAvailableInContext`] — a check
//!   *warning*, not a crash.
//! - `github-actions:key` reads GitHub's own secrets, whose names are
//!   upper-case `[A-Z0-9_]`: `deploy-token` becomes `DEPLOY_TOKEN`. Keys in
//!   GitHub's reserved `GITHUB_` namespace are refused, because the runner
//!   sets those itself and they are not workflow secrets. It answers only
//!   inside a job (`GITHUB_ACTIONS=true`); there is no local opt-in.
//!
//! The environment is reached through an injectable [`EnvLookup`], so tests
//! script a snapshot instead of mutating the process environment. Values are
//! read into a [`SecretValue`], which zeroises on drop; the adapter keeps no
//! copy of its own and never puts a value in an error or in `Debug`.

use std::fmt;
use std::sync::Arc;

use ks_core::ids::StepId;
use ks_core::ports::BoxFuture;
use ks_core::ports::secrets::{ResolverInfo, SecretRef, SecretValue, Secrets, SecretsError};

/// The `env` resolver's name, as references spell it: `env:NAME`.
pub const ENV: &str = "env";
/// The `github-actions` resolver's name: `github-actions:deploy-token`.
pub const GITHUB_ACTIONS: &str = "github-actions";

/// Reads one variable by name, or `None` when it is not set.
///
/// A closure rather than a snapshot map on purpose: a `BTreeMap` the adapter
/// holds would be a second, un-zeroised copy of every secret in the process
/// environment, alive for the whole run.
pub type EnvLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// A lookup over the real process environment.
pub fn process_env() -> EnvLookup {
    Arc::new(|name| std::env::var(name).ok())
}

/// Why `env` is off locally, and how to turn it on.
const LOCAL_OPT_IN: &str = "the `env` resolver is opt-in outside CI; run the pipeline in CI, or opt the laptop in explicitly";
/// Why `github-actions` is off, and how to turn it on.
const NOT_A_JOB: &str =
    "the `github-actions` resolver only answers inside a GitHub Actions job (GITHUB_ACTIONS=true)";
/// GitHub's own namespace, which holds runner variables, not workflow secrets.
const RESERVED_PREFIX: &str = "GITHUB_";

/// How a key names a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Convention {
    /// `env:NAME` — the variable is spelled exactly as the key.
    Verbatim,
    /// `github-actions:key` — GitHub's `[A-Z0-9_]` convention.
    GithubActions,
}

/// A [`Secrets`] resolver over the process environment.
///
/// Construct one with [`env`](EnvSecrets::env) or
/// [`github_actions`](EnvSecrets::github_actions); [`describe`](Secrets::describe)
/// reports which one it is and whether it is available here. A resolver holds
/// no secret bytes at all — only the lookup — so its `Debug` is safe to print.
pub struct EnvSecrets {
    name: &'static str,
    backend: &'static str,
    convention: Convention,
    available: bool,
    unavailable_note: &'static str,
    lookup: EnvLookup,
}

impl EnvSecrets {
    /// The `env` resolver, available when the run is in CI (`CI=true`) or when
    /// `opted_in` says the operator meant it.
    pub fn env(lookup: EnvLookup, opted_in: bool) -> EnvSecrets {
        let in_ci = lookup("CI").is_some_and(|value| is_true(&value));
        EnvSecrets {
            name: ENV,
            backend: "process-env",
            convention: Convention::Verbatim,
            available: in_ci || opted_in,
            unavailable_note: LOCAL_OPT_IN,
            lookup,
        }
    }

    /// The `github-actions` resolver, available only inside a job.
    pub fn github_actions(lookup: EnvLookup) -> EnvSecrets {
        let in_job = lookup("GITHUB_ACTIONS").is_some_and(|value| is_true(&value));
        EnvSecrets {
            name: GITHUB_ACTIONS,
            backend: "github-actions-env",
            convention: Convention::GithubActions,
            available: in_job,
            unavailable_note: NOT_A_JOB,
            lookup,
        }
    }

    /// The variable `reference` names, or the error that says why it names
    /// none.
    fn variable_name(&self, reference: &SecretRef) -> Result<String, SecretsError> {
        match self.convention {
            Convention::Verbatim => Ok(reference.key().to_string()),
            Convention::GithubActions => github_variable(reference),
        }
    }
}

impl Secrets for EnvSecrets {
    fn resolve<'a>(
        &'a self,
        reference: &'a SecretRef,
        _for_step: &'a StepId,
    ) -> BoxFuture<'a, Result<SecretValue, SecretsError>> {
        Box::pin(async move {
            if reference.resolver() != self.name {
                return Err(SecretsError::NotFound { reference: reference.clone() });
            }
            if !self.available {
                return Err(SecretsError::NotAvailableInContext {
                    reference: reference.clone(),
                    reason: self.unavailable_note.to_string(),
                });
            }
            let variable = self.variable_name(reference)?;
            // `into_bytes` hands over the variable's own allocation, so the
            // bytes are moved into the value rather than copied — the one
            // heap buffer that holds them is the one `SecretValue` zeroises.
            match (self.lookup)(&variable) {
                Some(value) => Ok(SecretValue::new(value.into_bytes())),
                None => Err(SecretsError::NotFound { reference: reference.clone() }),
            }
        })
    }

    fn describe(&self) -> ResolverInfo {
        ResolverInfo {
            name: self.name.to_string(),
            backend: self.backend.to_string(),
            available: self.available,
            note: (!self.available).then(|| self.unavailable_note.to_string()),
        }
    }
}

impl fmt::Debug for EnvSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvSecrets")
            .field("name", &self.name)
            .field("backend", &self.backend)
            .field("available", &self.available)
            .finish_non_exhaustive()
    }
}

/// GitHub's convention for a workflow secret name: upper-case `[A-Z0-9_]`,
/// with `-` and `.` folded to `_`. A key GitHub could not name as a secret is
/// reported as [`SecretsError::Backend`] — the malformed reference rather than
/// a store that failed — which is an error, never a warning.
fn github_variable(reference: &SecretRef) -> Result<String, SecretsError> {
    let key = reference.key();
    let mut name = String::with_capacity(key.len());
    for character in key.chars() {
        match character {
            '-' | '.' => name.push('_'),
            alphanumeric if alphanumeric.is_ascii_alphanumeric() => {
                name.push(alphanumeric.to_ascii_uppercase());
            }
            other => {
                return Err(malformed(
                    reference,
                    format!("{other:?} is not valid in a secret name"),
                ));
            }
        }
    }
    if name.is_empty() {
        return Err(malformed(reference, "the secret name is empty".to_string()));
    }
    if name.starts_with(RESERVED_PREFIX) {
        return Err(malformed(
            reference,
            format!("{RESERVED_PREFIX} is reserved by the runner, not a workflow secret"),
        ));
    }
    Ok(name)
}

/// A key this resolver cannot name, as an error safe to print: it names the
/// key, never a value.
fn malformed(reference: &SecretRef, reason: String) -> SecretsError {
    SecretsError::Backend { reference: reference.clone(), message: reason }
}

/// CI systems spell the flag several ways; GitHub and most others use `true`.
fn is_true(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_testing::block_on;

    const VALUE: &str = "s3cr3t-value";

    /// A lookup over a scripted snapshot, standing in for the process
    /// environment — setting a variable in a test is `unsafe` in edition 2024.
    fn scripted(pairs: &[(&str, &str)]) -> EnvLookup {
        let map: std::collections::BTreeMap<String, String> =
            pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();
        Arc::new(move |name: &str| map.get(name).cloned())
    }

    fn resolve(resolver: &EnvSecrets, reference: &SecretRef) -> Result<SecretValue, SecretsError> {
        block_on(resolver.resolve(reference, &StepId::new("deploy")))
    }

    #[test]
    fn env_reads_the_named_variable() {
        let resolver = EnvSecrets::env(scripted(&[("DEPLOY_TOKEN", VALUE)]), true);
        let reference = SecretRef::new(ENV, "DEPLOY_TOKEN");
        let value = resolve(&resolver, &reference).expect("a set variable resolves");
        assert_eq!(value.with_bytes(|bytes| bytes.to_vec()), VALUE.as_bytes().to_vec());
    }

    #[test]
    fn env_reports_a_missing_variable_as_not_found() {
        let resolver = EnvSecrets::env(scripted(&[]), true);
        let error = resolve(&resolver, &SecretRef::new(ENV, "DEPLOY_TOKEN"))
            .expect_err("an unset variable is not a secret");
        assert_eq!(
            error,
            SecretsError::NotFound { reference: SecretRef::new(ENV, "DEPLOY_TOKEN") }
        );
        assert_eq!(error.check_severity(), ks_core::ports::secrets::CheckSeverity::Error);
    }

    #[test]
    fn env_is_off_locally_and_says_how_to_opt_in() {
        // The variable is set, but nothing opted in: it must still not resolve.
        let resolver = EnvSecrets::env(scripted(&[("DEPLOY_TOKEN", VALUE)]), false);
        let error =
            resolve(&resolver, &SecretRef::new(ENV, "DEPLOY_TOKEN")).expect_err("not opted in");
        assert_eq!(
            error.check_severity(),
            ks_core::ports::secrets::CheckSeverity::Warning,
            "an unavailable context is a check warning, never a crash"
        );
        let rendered = error.to_string();
        assert!(rendered.contains("opt-in"), "the diagnostic says how to opt in: {rendered}");
        assert!(!rendered.contains(VALUE), "the diagnostic never carries the value");
    }

    #[test]
    fn env_resolves_in_ci_without_an_explicit_opt_in() {
        let resolver = EnvSecrets::env(scripted(&[("CI", "true"), ("DEPLOY_TOKEN", VALUE)]), false);
        resolve(&resolver, &SecretRef::new(ENV, "DEPLOY_TOKEN")).expect("CI is an opt-in");
        assert!(resolver.describe().available);
    }

    #[test]
    fn env_resolves_when_the_operator_opts_in() {
        let resolver = EnvSecrets::env(scripted(&[("DEPLOY_TOKEN", VALUE)]), true);
        resolve(&resolver, &SecretRef::new(ENV, "DEPLOY_TOKEN")).expect("explicitly opted in");
    }

    #[test]
    fn github_actions_reads_the_key_in_ghs_convention() {
        let resolver = EnvSecrets::github_actions(scripted(&[
            ("GITHUB_ACTIONS", "true"),
            ("DEPLOY_TOKEN", VALUE),
            ("DB_URL", VALUE),
        ]));
        resolve(&resolver, &SecretRef::new(GITHUB_ACTIONS, "deploy-token"))
            .expect("a hyphenated key reads its upper-case variable");
        let value = resolve(&resolver, &SecretRef::new(GITHUB_ACTIONS, "Db.Url"))
            .expect("dots fold to underscores too");
        assert_eq!(value.with_bytes(|bytes| bytes.to_vec()), VALUE.as_bytes().to_vec());
    }

    #[test]
    fn github_actions_only_answers_inside_a_job() {
        let resolver = EnvSecrets::github_actions(scripted(&[("DEPLOY_TOKEN", VALUE)]));
        let error = resolve(&resolver, &SecretRef::new(GITHUB_ACTIONS, "deploy-token"))
            .expect_err("not a job");
        assert!(matches!(error, SecretsError::NotAvailableInContext { .. }));
        assert!(error.to_string().contains("GITHUB_ACTIONS=true"), "{error}");
        assert!(!resolver.describe().available);
    }

    #[test]
    fn github_actions_refuses_ghs_own_namespace() {
        let resolver = EnvSecrets::github_actions(scripted(&[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_TOKEN", VALUE),
        ]));
        let error = resolve(&resolver, &SecretRef::new(GITHUB_ACTIONS, "GITHUB_TOKEN"))
            .expect_err("GITHUB_ is the runner's own");
        assert!(error.to_string().contains("GITHUB_"), "{error}");
        assert_eq!(error.check_severity(), ks_core::ports::secrets::CheckSeverity::Error);
    }

    #[test]
    fn github_actions_refuses_a_name_github_could_not_hold() {
        let resolver = EnvSecrets::github_actions(scripted(&[("GITHUB_ACTIONS", "true")]));
        let error = resolve(&resolver, &SecretRef::new(GITHUB_ACTIONS, "db url"))
            .expect_err("a space cannot be in a secret name");
        assert!(error.to_string().contains("not valid in a secret name"), "{error}");
    }

    #[test]
    fn a_reference_for_another_resolver_is_not_found() {
        let resolver = EnvSecrets::env(scripted(&[("CI", "true")]), false);
        let error = resolve(&resolver, &SecretRef::new("vault", "db-url"))
            .expect_err("this resolver owns no vault keys");
        assert_eq!(error, SecretsError::NotFound { reference: SecretRef::new("vault", "db-url") });
    }

    #[test]
    fn neither_errors_nor_debug_carry_a_value() {
        let resolver = EnvSecrets::env(scripted(&[("DEPLOY_TOKEN", VALUE)]), true);
        let reference = SecretRef::new(ENV, "DEPLOY_TOKEN");
        // The resolved value: `SecretValue`'s `Debug` is `***` by construction.
        let value = resolve(&resolver, &reference).expect("resolves");
        assert_eq!(format!("{value:?}"), "***");
        for rendered in [
            format!("{resolver:?}"),
            resolver.describe().describe(),
            resolve(&resolver, &SecretRef::new(ENV, "OTHER")).unwrap_err().to_string(),
        ] {
            assert!(!rendered.contains(VALUE), "leaked a value: {rendered}");
        }
    }
}
