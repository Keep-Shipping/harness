//! Which cloud credentials a step runs with
//! ([#71](https://github.com/Keep-Shipping/harness/issues/71)).
//!
//! The model is **one role per step**, and plan and apply are separate steps. A
//! `role:` on `tofu.plan` and a different one on `tofu.apply` are two separate
//! assumptions, so an agent handed only the plan step's credentials cannot
//! apply with them: it would have to reach a role it was never given a token
//! for. The least-privilege shape is structural, not advisory, and the run log
//! names which role each step assumed.
//!
//! Two rules keep the token safe. It lives in a [`SecretValue`], never a
//! `String`, so it is redacted and zeroised like any other secret; and
//! [`StepCredentials::env`] hands a subprocess the *path* it was written to,
//! never the token, because an environment vector shows up in `/proc`. What
//! reaches the log is cloud, role and `via` — the shape of the assumption, and
//! nothing that replays it.
//!
//! Resolution is deliberately honest: a `role:` on CI federates into it, a
//! `role:` on a laptop does not, and a `role:` on a CI job that cannot mint one
//! is an error, never a silent downgrade.
//!
//! Not yet wired: nothing calls this from the run loop — `keepshipping run`
//! does not execute steps ([#45](https://github.com/Keep-Shipping/harness/issues/45)) —
//! and the checker does not parse a `role:` yet.

use std::fmt;
use std::path::Path;

use ks_core::ports::run_context::{ActorKind, RunContext, RunContextError};
use ks_core::ports::secrets::SecretValue;

/// The `via` for a federated step, and for one that inherited the shell's own.
const VIA_OIDC: &str = "oidc";
const VIA_AMBIENT: &str = "ambient";

/// The AWS partitions whose IAM ARNs [`CloudRole::parse`] accepts.
const AWS_PARTITIONS: &[&str] = &["aws", "aws-us-gov", "aws-cn"];

/// Why a step could not be given credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// A `role:` naming no role this harness knows how to federate into;
    /// `given` is the value verbatim, so the message can say what it was.
    UnrecognisedRole { given: String },
    /// A CI job asked for a role it has no token for. An ambient fallback here
    /// would apply with the job's own long-lived keys, so it fails.
    NoFederation {
        /// The step that asked.
        step: String,
        /// The role it asked for.
        role: String,
    },
    /// The run context could not mint the token it promised.
    Mint {
        /// The step that asked.
        step: String,
        /// What the run context said, safe to print.
        message: String,
    },
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialError::UnrecognisedRole { given } => write!(
                f,
                "{given:?} is not a role keepshipping can federate into: an AWS IAM role ARN \
                 (arn:<partition>:iam::<12 digits>:role/<name>, partition aws, aws-us-gov or \
                 aws-cn) or an Azure application (client) id (a GUID, 8-4-4-4-12 hex). Per-step \
                 federation on GCP is not built yet; use ADC"
            ),
            CredentialError::NoFederation { step, role } => write!(
                f,
                "step `{step}` asks for {role:?} but this CI job cannot federate into it: the \
                 run context has no OIDC token. Grant the job `permissions: id-token: write`"
            ),
            CredentialError::Mint { step, message } => {
                write!(f, "step `{step}` could not get an OIDC token: {message}")
            }
        }
    }
}

impl std::error::Error for CredentialError {}

/// The role a step federates into: an AWS IAM role ARN or an Azure application
/// (client) id. A `role:` is parsed into this, so a typo is refused before
/// anything runs rather than becoming an opaque failure from the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudRole {
    /// An AWS IAM role, by ARN.
    Aws {
        /// The role ARN, `arn:<partition>:iam::<account>:role/<name>`.
        arn: String,
    },
    /// An Azure application (client) id, for `az login --federated-token`.
    Azure {
        /// The client id, a GUID.
        client_id: String,
    },
}

impl CloudRole {
    /// Parses a `role:` value: an AWS IAM role ARN, or an Azure client id.
    ///
    /// AWS needs a real partition (`aws`, `aws-us-gov`, `aws-cn`) — separate
    /// partitions with their own ARNs, and pretending otherwise would produce a
    /// token the provider rejects. Azure wants a bare client id: that is how a
    /// service principal is identified when a federated credential is made.
    pub fn parse(given: &str) -> Result<CloudRole, CredentialError> {
        let trimmed = given.trim();
        if trimmed.starts_with("arn:") {
            // arn:<partition>:iam::<account>:role/<name> — the empty field between `iam` and the
            // account is the region, which an IAM ARN never has, and nothing may follow the name.
            let mut parts = trimmed.split(':');
            let fields: Vec<&str> = parts.by_ref().take(6).collect();
            let valid = fields.len() == 6
                && fields[0] == "arn"
                && AWS_PARTITIONS.contains(&fields[1])
                && fields[2] == "iam"
                && fields[3].is_empty()
                && is_account(fields[4])
                && fields[5].starts_with("role/")
                && fields[5].len() > "role/".len()
                && parts.next().is_none();
            return valid
                .then(|| CloudRole::Aws { arn: trimmed.to_string() })
                .ok_or_else(|| CredentialError::UnrecognisedRole { given: given.to_string() });
        }
        if is_guid(trimmed) {
            return Ok(CloudRole::Azure { client_id: trimmed.to_string() });
        }
        Err(CredentialError::UnrecognisedRole { given: given.to_string() })
    }

    /// The cloud this role lives in, as the run log spells it.
    #[must_use]
    pub fn cloud(&self) -> &'static str {
        match self {
            CloudRole::Aws { .. } => "aws",
            CloudRole::Azure { .. } => "azure",
        }
    }

    /// The audience the token must be minted for — fixed per cloud, because a
    /// token minted for anyone else is one the provider will not accept.
    #[must_use]
    pub fn audience(&self) -> &'static str {
        match self {
            CloudRole::Aws { .. } => "sts.amazonaws.com",
            CloudRole::Azure { .. } => "api://AzureADTokenExchange",
        }
    }
}

impl fmt::Display for CloudRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudRole::Aws { arn } => f.write_str(arn),
            CloudRole::Azure { client_id } => f.write_str(client_id),
        }
    }
}

/// Twelve digits: an AWS account id.
fn is_account(account: &str) -> bool {
    account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit())
}

/// A GUID: 8-4-4-4-12 lowercase-or-uppercase hex, and nothing else.
fn is_guid(text: &str) -> bool {
    let mut parts = text.split('-');
    for width in [8usize, 4, 4, 4, 12] {
        let Some(part) = parts.next() else { return false };
        if part.len() != width || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
    }
    parts.next().is_none()
}

/// The credentials one step runs with: what was assumed, and the token when one
/// was minted. The record fields (`cloud`, `role`, `via`) are what the run log
/// says; the token is not among them and has no accessor yielding a `String`,
/// so wanting it means going through [`SecretValue::with_bytes`] deliberately.
#[derive(Debug)]
pub struct StepCredentials {
    cloud: String,
    role: Option<String>,
    via: String,
    token: Option<SecretValue>,
}

impl StepCredentials {
    /// `"aws"`, `"azure"`, or `"unknown"` when nothing said — see [`resolve`].
    #[must_use]
    pub fn cloud(&self) -> &str {
        &self.cloud
    }

    /// The role federated into, `None` when nothing was assumed.
    #[must_use]
    pub fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }

    /// `"oidc"`, `"profile:<name>"` or `"ambient"`.
    #[must_use]
    pub fn via(&self) -> &str {
        &self.via
    }

    /// The OIDC token, when one was minted; `None` otherwise.
    #[must_use]
    pub fn token(&self) -> Option<&SecretValue> {
        self.token.as_ref()
    }

    /// The environment a step's subprocess needs, as `(name, value)` pairs: the
    /// role, the *path* of the token file and a session name for AWS, the ARM
    /// spellings for Azure. Everything else gets nothing and inherits the user's
    /// own environment — a laptop run must not be handed an identity it did not
    /// ask for.
    #[must_use]
    pub fn env(&self, token_file: &Path, session: &str) -> Vec<(&'static str, String)> {
        let Some(role) = self.role.as_deref().filter(|_| self.via == VIA_OIDC) else {
            return Vec::new();
        };
        let path = || token_file.display().to_string();
        match self.cloud.as_str() {
            "aws" => vec![
                ("AWS_ROLE_ARN", role.to_string()),
                ("AWS_WEB_IDENTITY_TOKEN_FILE", path()),
                ("AWS_ROLE_SESSION_NAME", session.to_string()),
            ],
            // Azure, and any future cloud: the ARM spellings.
            _ => vec![
                ("ARM_USE_OIDC", "true".to_string()),
                ("ARM_CLIENT_ID", role.to_string()),
                ("ARM_OIDC_TOKEN_FILE_PATH", path()),
            ],
        }
    }
}

/// Works out the credentials step `step` runs with.
///
/// * **A `role:` on CI that can mint tokens** — federate, token minted for
///   [`CloudRole::audience`], `via` `"oidc"`, role recorded.
/// * **A `role:` on CI that cannot** — [`CredentialError::NoFederation`], never
///   a fallback to ambient credentials: a step that cannot prove *which* role
///   it holds does not get to act.
/// * **A `role:` on a laptop** — assume nothing. There is no token to federate,
///   and standing in a role with the user's long-lived keys is the confusion
///   the separate roles exist to prevent. `via` is `profile:<AWS_PROFILE>` when
///   the user set one (else `"ambient"`), `role` is `None`: the `role:` line
///   documents CI, and a laptop cannot honour it.
/// * **No `role:`** — whatever the environment already has. `cloud` is `"aws"`
///   when `AWS_PROFILE` names a profile and `"unknown"` otherwise: without a
///   role there is nothing to say which provider is in play, and guessing would
///   put a claim in the log the run cannot back.
///
/// `run_context` and `env` are supplied rather than read, so this stays pure —
/// no `std::env`, no clock, no I/O. A `run_context` of `None` means a laptop.
pub async fn resolve(
    step: &str,
    role: Option<&CloudRole>,
    run_context: Option<&dyn RunContext>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<StepCredentials, CredentialError> {
    let cloud = match role {
        Some(role) => role.cloud(),
        None if env("AWS_PROFILE").is_some() => "aws",
        None => "unknown",
    };
    let context = run_context.filter(|c| c.capabilities().oidc);
    let federate = match (role, context) {
        (None, _) => None,
        (Some(_), None) if run_context.is_some_and(|c| c.actor().kind == ActorKind::Ci) => {
            let role = role.map(ToString::to_string).unwrap_or_default();
            return Err(CredentialError::NoFederation { step: step.to_string(), role });
        }
        (Some(role), Some(context)) => Some((role, context)),
        (Some(_), None) => None, // local: assume nothing, see the module docs
    };
    let Some((role, context)) = federate else {
        return Ok(StepCredentials {
            cloud: cloud.to_string(),
            role: None,
            via: via_local(cloud, env),
            token: None,
        });
    };
    let token =
        context.oidc_token(role.audience()).await.map_err(|error| mint_failure(step, error))?;
    Ok(StepCredentials {
        cloud: role.cloud().to_string(),
        role: Some(role.to_string()),
        via: VIA_OIDC.to_string(),
        token: Some(token),
    })
}

/// The run context's own failure, carrying the step it happened for.
fn mint_failure(step: &str, error: RunContextError) -> CredentialError {
    let message = match error {
        RunContextError::OidcUnavailable { audience } => format!(
            "no OIDC token provider for audience {audience:?}; grant the job \
             `permissions: id-token: write`"
        ),
        RunContextError::Backend { message } => message,
    };
    CredentialError::Mint { step: step.to_string(), message }
}

/// What a local step's `via` says: `profile:<name>` where a profile names one,
/// `"ambient"` otherwise — `az login` has no name the harness knows.
fn via_local(cloud: &str, env: &dyn Fn(&str) -> Option<String>) -> String {
    let named =
        if cloud == "aws" { env("AWS_PROFILE").filter(|name| !name.is_empty()) } else { None };
    match named {
        Some(name) => format!("profile:{name}"),
        None => VIA_AMBIENT.to_string(),
    }
}
