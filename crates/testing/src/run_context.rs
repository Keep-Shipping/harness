//! Fake for the [`RunContext`] port: a scriptable laptop-or-CI run, plus the
//! conformance kit every adapter must pass
//! ([#48](https://github.com/Keep-Shipping/harness/issues/48)).

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use ks_core::ports::BoxFuture;
use ks_core::ports::run_context::{
    Actor, ActorKind, Capabilities, Establishment, Event, GitInfo, IdentityStrength, NetworkScope,
    RunContext, RunContextError, Trigger, Workspace,
};
use ks_core::ports::secrets::SecretValue;

/// The fake's default commit: a fixed 40-char lowercase-hex SHA.
pub const FAKE_SHA: &str = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b";

/// A [`RunContext`] you script per test, defaulting to a boring local run: a
/// human actor established by [`Establishment::LocalGitConfig`], a `Push` of
/// [`FAKE_SHA`] on `refs/heads/main`, interactive, no OIDC, and a `/work`
/// workspace with `/work/.ks/scratch` beside it.
///
/// ```
/// use ks_core::ports::run_context::{ActorKind, RunContext};
/// use ks_testing::{block_on, run_context::FakeRunContext};
///
/// let fake = FakeRunContext::new().with_oidc_token(b"token".to_vec());
/// assert_eq!(fake.actor().kind, ActorKind::Human);
/// assert!(fake.capabilities().oidc, "scripting a token turns the capability on");
/// let token = block_on(fake.oidc_token("any-audience")).expect("scripted tokens resolve");
/// assert_eq!(token.with_bytes(|bytes| bytes.len()), 5);
/// ```
///
/// Its `Debug` prints the token's length, never its bytes.
pub struct FakeRunContext {
    actor: Actor,
    event: Event,
    capabilities: Capabilities,
    workspace: Workspace,
    oidc_token: Option<Vec<u8>>,
}

impl Default for FakeRunContext {
    fn default() -> FakeRunContext {
        FakeRunContext::new()
    }
}

impl FakeRunContext {
    /// Creates a fake modelling a plain local run.
    pub fn new() -> FakeRunContext {
        FakeRunContext {
            actor: Actor {
                kind: ActorKind::Human,
                established: Establishment::LocalGitConfig,
                display_name: "local-user".to_string(),
            },
            event: Event {
                git: GitInfo { sha: FAKE_SHA.to_string(), git_ref: "refs/heads/main".to_string() },
                trigger: Trigger::Push,
            },
            capabilities: Capabilities {
                oidc: false,
                interactive: true,
                ci_cache: false,
                network: NetworkScope::None,
                secret_resolvers: BTreeSet::new(),
            },
            workspace: Workspace {
                root: PathBuf::from("/work"),
                scratch: PathBuf::from("/work/.ks/scratch"),
            },
            oidc_token: None,
        }
    }

    /// Scripts the run's actor.
    pub fn with_actor(mut self, actor: Actor) -> FakeRunContext {
        self.actor = actor;
        self
    }

    /// Scripts the run's event.
    pub fn with_event(mut self, event: Event) -> FakeRunContext {
        self.event = event;
        self
    }

    /// Scripts the run's capabilities wholesale.
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> FakeRunContext {
        self.capabilities = capabilities;
        self
    }

    /// Scripts the run's workspace.
    pub fn with_workspace(mut self, workspace: Workspace) -> FakeRunContext {
        self.workspace = workspace;
        self
    }

    /// Scripts an OIDC token — served for every audience — and turns on the
    /// [`oidc`](Capabilities::oidc) capability: a fake that mints tokens must
    /// advertise it. Call before [`with_capabilities`](Self::with_capabilities),
    /// which overwrites capabilities wholesale.
    pub fn with_oidc_token(mut self, bytes: impl Into<Vec<u8>>) -> FakeRunContext {
        self.oidc_token = Some(bytes.into());
        self.capabilities.oidc = true;
        self
    }
}

impl fmt::Debug for FakeRunContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeRunContext")
            .field("actor", &self.actor)
            .field("event", &self.event)
            .field("capabilities", &self.capabilities)
            .field("workspace", &self.workspace)
            .field("oidc_token", &self.oidc_token.as_ref().map(Vec::len))
            .finish()
    }
}

impl RunContext for FakeRunContext {
    fn actor(&self) -> &Actor {
        &self.actor
    }

    fn event(&self) -> &Event {
        &self.event
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn workspace(&self) -> &Workspace {
        &self.workspace
    }

    fn oidc_token<'a>(
        &'a self,
        audience: &'a str,
    ) -> BoxFuture<'a, Result<SecretValue, RunContextError>> {
        let result = match &self.oidc_token {
            Some(bytes) => Ok(SecretValue::new(bytes.clone())),
            None => Err(RunContextError::OidcUnavailable { audience: audience.to_string() }),
        };
        Box::pin(std::future::ready(result))
    }
}

fn is_lower_hex_of(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The `RunContext` conformance kit: every adapter — the local one and the
/// GitHub Actions one — must pass it, so both report the same shape.
///
/// Panics with a `run context conformance:` message when the adapter breaks
/// an invariant: a 40- or 64-char lowercase-hex SHA; a `git_ref` under
/// `refs/`; a `Tag` trigger naming `refs/tags/<name>`; `oidc_token` answering
/// `Ok` if and only if `capabilities().oidc`; a `Ci` actor established
/// strongly; a scratch directory distinct from the workspace root; and a
/// non-empty actor display name.
pub async fn conformance(ctx: &dyn RunContext) {
    let actor = ctx.actor();
    assert!(
        !actor.display_name.is_empty(),
        "run context conformance: display name must not be empty"
    );
    if actor.kind == ActorKind::Ci {
        assert_eq!(
            actor.established.strength(),
            IdentityStrength::Strong,
            "run context conformance: a Ci actor must be established via CiOidc, got {actor:?}"
        );
    }

    let event = ctx.event();
    let sha = &event.git.sha;
    assert!(
        is_lower_hex_of(sha, 40) || is_lower_hex_of(sha, 64),
        "run context conformance: sha must be 40 or 64 lowercase hex chars, got {sha:?}"
    );
    let git_ref = &event.git.git_ref;
    assert!(
        git_ref.starts_with("refs/"),
        "run context conformance: git_ref must start with `refs/`, got {git_ref:?}"
    );
    if let Trigger::Tag { name } = &event.trigger {
        assert_eq!(
            git_ref,
            &format!("refs/tags/{name}"),
            "run context conformance: a Tag trigger must carry refs/tags/<name>"
        );
    }

    let oidc_capable = ctx.capabilities().oidc;
    match ctx.oidc_token("conformance-audience").await {
        Ok(_) => assert!(
            oidc_capable,
            "run context conformance: oidc_token resolved although capabilities().oidc is false"
        ),
        Err(RunContextError::OidcUnavailable { .. }) => assert!(
            !oidc_capable,
            "run context conformance: capabilities().oidc is true although oidc_token is unavailable"
        ),
        Err(other) => panic!(
            "run context conformance: oidc_token must be Ok or OidcUnavailable, got {other:?}"
        ),
    }

    let workspace = ctx.workspace();
    assert_ne!(
        workspace.scratch, workspace.root,
        "run context conformance: scratch must differ from the workspace root"
    );
}
