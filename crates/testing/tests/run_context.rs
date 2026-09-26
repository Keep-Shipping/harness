//! Behaviour of the `RunContext` port pieces: the fake, the conformance kit
//! and the pure local-actor detector
//! ([#48](https://github.com/Keep-Shipping/harness/issues/48)).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use ks_core::ports::run_context::{
    Actor, ActorKind, Capabilities, Establishment, Event, GitInfo, IdentityStrength, LocalRunFacts,
    NetworkScope, RunContext, RunContextError, Trigger, UnknownRunPolicy, Workspace,
    agent_typical_evidence, detect_local_actor,
};
use ks_testing::block_on;
use ks_testing::run_context::{FakeRunContext, conformance};

/// Compile-time check that `RunContext` is dyn-compatible.
fn _assert(_: &dyn RunContext) {}

const SHA40: &str = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b";

fn facts(env: &[(&str, &str)], stdin_is_tty: bool) -> LocalRunFacts {
    LocalRunFacts {
        declared: None,
        env: env.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect(),
        stdin_is_tty,
        git_user_name: None,
    }
}

fn ci_capabilities() -> Capabilities {
    Capabilities {
        oidc: true,
        interactive: false,
        ci_cache: true,
        network: NetworkScope::Hosts(BTreeSet::from(["api.github.com".to_string()])),
        secret_resolvers: BTreeSet::from(["env".to_string()]),
    }
}

#[test]
fn the_default_fake_passes_conformance_and_models_a_local_run() {
    let fake = FakeRunContext::new();
    block_on(conformance(&fake));

    let actor = fake.actor();
    assert_eq!(actor.kind, ActorKind::Human);
    assert_eq!(actor.established, Establishment::LocalGitConfig);

    let event = fake.event();
    assert_eq!(event.git.sha.len(), 40);
    assert_eq!(event.git.git_ref, "refs/heads/main");
    assert_eq!(event.trigger, Trigger::Push);
    assert_eq!(event.pr_number(), None);

    let capabilities = fake.capabilities();
    assert!(!capabilities.oidc);
    assert!(capabilities.interactive);
    assert_eq!(capabilities.network, NetworkScope::None);
    assert_eq!(
        fake.workspace(),
        &Workspace { root: PathBuf::from("/work"), scratch: PathBuf::from("/work/.ks/scratch") }
    );
}

#[test]
fn an_oidc_enabled_ci_fake_passes_conformance_and_serves_tokens() {
    let fake = FakeRunContext::new()
        .with_actor(Actor {
            kind: ActorKind::Ci,
            established: Establishment::CiOidc {
                issuer: "https://token.actions.githubusercontent.com".to_string(),
                subject: "repo:Keep-Shipping/harness:pull_request".to_string(),
            },
            display_name: "github-actions".to_string(),
        })
        .with_event(Event {
            git: GitInfo { sha: "b".repeat(64), git_ref: "refs/pull/48/merge".to_string() },
            trigger: Trigger::PullRequest { number: 48 },
        })
        .with_capabilities(ci_capabilities())
        .with_oidc_token(b"oidc-token-bytes".to_vec());

    block_on(conformance(&fake));
    assert_eq!(fake.actor().established.strength(), IdentityStrength::Strong);
    assert_eq!(fake.event().pr_number(), Some(48));
    let token = block_on(fake.oidc_token("fake-audience")).expect("the token is scripted");
    assert_eq!(token.with_bytes(|bytes| bytes.to_vec()), b"oidc-token-bytes".to_vec());
    assert!(!format!("{fake:?}").contains("oidc-token-bytes"), "no token bytes in debug");
}

#[test]
fn a_tag_event_names_its_ref_and_passes_conformance() {
    let fake = FakeRunContext::new().with_event(Event {
        git: GitInfo { sha: SHA40.to_string(), git_ref: "refs/tags/v1.2.3".to_string() },
        trigger: Trigger::Tag { name: "v1.2.3".to_string() },
    });
    block_on(conformance(&fake));
}

#[test]
#[should_panic(expected = "run context conformance")]
fn conformance_rejects_a_git_ref_that_is_not_a_ref() {
    let fake = FakeRunContext::new().with_event(Event {
        git: GitInfo { sha: SHA40.to_string(), git_ref: "main".to_string() },
        trigger: Trigger::Push,
    });
    block_on(conformance(&fake));
}

#[test]
#[should_panic(expected = "run context conformance")]
fn conformance_rejects_a_tag_trigger_whose_ref_disagrees() {
    let fake = FakeRunContext::new().with_event(Event {
        git: GitInfo { sha: SHA40.to_string(), git_ref: "refs/heads/main".to_string() },
        trigger: Trigger::Tag { name: "v1.2.3".to_string() },
    });
    block_on(conformance(&fake));
}

#[test]
#[should_panic(expected = "run context conformance")]
fn conformance_rejects_a_capability_that_mints_no_token() {
    let fake = FakeRunContext::new().with_capabilities(Capabilities {
        oidc: true,
        interactive: true,
        ci_cache: false,
        network: NetworkScope::None,
        secret_resolvers: BTreeSet::new(),
    });
    block_on(conformance(&fake));
}

#[test]
fn a_known_marker_beats_a_declared_human() {
    let mut input = facts(&[("CLAUDECODE", "1")], true);
    input.declared = Some(ActorKind::Human);
    let actor = detect_local_actor(&input, UnknownRunPolicy::TreatAsHuman);
    assert_eq!(actor.kind, ActorKind::Agent);
    assert_eq!(actor.established, Establishment::Detected { marker: "CLAUDECODE".to_string() });
    assert_eq!(actor.established.strength(), IdentityStrength::Weak);
}

#[test]
fn an_empty_marker_is_no_marker() {
    let actor =
        detect_local_actor(&facts(&[("CLAUDECODE", "")], true), UnknownRunPolicy::TreatAsHuman);
    assert_eq!(actor.kind, ActorKind::Human);
}

#[test]
fn a_declared_agent_is_self_declared() {
    let mut input = facts(&[], true);
    input.declared = Some(ActorKind::Agent);
    let actor = detect_local_actor(&input, UnknownRunPolicy::TreatAsHuman);
    assert_eq!(actor.kind, ActorKind::Agent);
    assert_eq!(actor.established, Establishment::SelfDeclared);
}

#[test]
fn a_non_tty_run_with_agent_typical_vars_is_a_detected_agent() {
    let input = facts(&[("NO_COLOR", "1"), ("PAGER", "cat")], false);
    for baseline in [UnknownRunPolicy::TreatAsAgent, UnknownRunPolicy::TreatAsHuman] {
        let actor = detect_local_actor(&input, baseline);
        assert_eq!(actor.kind, ActorKind::Agent, "{actor:?}");
        assert_eq!(
            actor.established,
            Establishment::Detected { marker: "no-tty+NO_COLOR+PAGER=cat".to_string() }
        );
    }
    assert_eq!(agent_typical_evidence(&input.env), vec!["NO_COLOR", "PAGER"]);
}

#[test]
fn a_set_but_empty_variable_is_not_agent_typical_evidence() {
    // `NO_COLOR=""` is set but says nothing: the entry expects any
    // *non-empty* value, so this run stays unknown, not detected.
    let input = facts(&[("NO_COLOR", "")], false);
    assert!(agent_typical_evidence(&input.env).is_empty());
    assert_eq!(detect_local_actor(&input, UnknownRunPolicy::TreatAsHuman).kind, ActorKind::Human);
    // Any non-empty value still matches, as before.
    assert_eq!(agent_typical_evidence(&facts(&[("NO_COLOR", "1")], false).env), vec!["NO_COLOR"]);
}

#[test]
fn a_bare_non_tty_run_is_also_unknown() {
    let input = facts(&[], false);
    let agent = detect_local_actor(&input, UnknownRunPolicy::TreatAsAgent);
    assert_eq!(agent.kind, ActorKind::Agent);
    assert_eq!(agent.established, Establishment::AssumedByBaseline);
    assert_eq!(detect_local_actor(&input, UnknownRunPolicy::TreatAsHuman).kind, ActorKind::Human);
    assert!(agent_typical_evidence(&input.env).is_empty());
}

#[test]
fn an_interactive_human_is_taken_from_git_config() {
    let mut input = facts(&[], true);
    input.git_user_name = Some("Ada Lovelace".to_string());
    let actor = detect_local_actor(&input, UnknownRunPolicy::TreatAsHuman);
    assert_eq!(actor.kind, ActorKind::Human);
    assert_eq!(actor.established, Establishment::LocalGitConfig);
    assert_eq!(actor.display_name, "Ada Lovelace");

    let unnamed = detect_local_actor(&facts(&[], true), UnknownRunPolicy::TreatAsHuman);
    assert_eq!(unnamed.display_name, "unknown");
}

#[test]
fn ci_true_in_a_local_env_never_makes_the_run_ci() {
    let spoofed = facts(&[("CI", "true")], false);
    for actor in [
        detect_local_actor(&spoofed, UnknownRunPolicy::TreatAsAgent),
        detect_local_actor(&spoofed, UnknownRunPolicy::TreatAsHuman),
    ] {
        assert_ne!(actor.kind, ActorKind::Ci, "{actor:?}");
    }

    // Even a `--as ci` declaration with a marker stays Agent: only a CI
    // adapter with a verified OIDC subject may claim Ci.
    let mut input = facts(&[("CI", "true"), ("CLAUDECODE", "1")], false);
    input.declared = Some(ActorKind::Ci);
    let actor = detect_local_actor(&input, UnknownRunPolicy::TreatAsAgent);
    assert_eq!(actor.kind, ActorKind::Agent);
}

#[test]
fn oidc_without_the_capability_is_oidc_unavailable() {
    let error =
        block_on(FakeRunContext::new().oidc_token("deploy")).expect_err("no oidc by default");
    match error {
        RunContextError::OidcUnavailable { audience } => assert_eq!(audience, "deploy"),
        other => panic!("expected OidcUnavailable, got {other:?}"),
    }
}

#[test]
fn detector_facts_default_to_an_anonymous_interactive_run() {
    let input = LocalRunFacts::default();
    assert_eq!(input.declared, None);
    assert_eq!(input.env, BTreeMap::new());
    assert!(!input.stdin_is_tty);
    assert_eq!(input.git_user_name, None);
    assert_eq!(
        detect_local_actor(&input, UnknownRunPolicy::TreatAsAgent).established,
        Establishment::AssumedByBaseline
    );
}
