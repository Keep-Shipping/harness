//! The Keep Shipping core: shared types, the checker, the diagnostics
//! registry, the `StepKind` trait, the port traits and the `Harness` builder.
//!
//! Pure computation: no I/O of any kind, so the crate compiles unchanged for
//! `wasm32-unknown-unknown`.
//!
//! # Example
//!
//! ```
//! let src = "\
//! steps:
//!   build: oci.image
//!     from: ./Dockerfile
//!   deploy: k8s.rollout
//!     image: build.digest
//! ";
//! let parse = ks_lang::parse(src);
//! let checked = ks_core::check(&parse);
//! assert!(checked.diagnostics.is_empty(), "{:?}", checked.diagnostics);
//! assert_eq!(checked.workflow.step("deploy").map(|s| s.kind.as_deref()), Some(Some("k8s.rollout")));
//! // `deploy` reads `build.digest`, so `build` must run first.
//! assert_eq!(checked.workflow.edges(), [("build".to_string(), "deploy".to_string())]);
//! assert!(checked.workflow.topo_order().is_some());
//! ```
//!
//! The meaning of a file — references, types, triggers, environments,
//! policy — is defined here; the concrete syntax lives in `ks-lang`.

#![forbid(unsafe_code)]

pub mod auto_rule;
pub mod block;
pub mod block_diff;
pub mod block_trust;
mod catalog;
mod check;
pub mod context;
mod env;
pub mod format;
pub mod harness;
pub mod ids;
pub mod k8s;
pub mod lock;
pub mod plan_summary;
pub mod policy;
pub mod ports;
pub mod registry;
pub mod repro;
pub mod script;
pub mod script_step;
pub mod step;
pub mod tf;
mod types;
pub mod version;
mod workflow;

pub use auto_rule::{
    AUTO_VERB, Answered, Decision, DecisionSource, Facts, POLICY_AUTO, Resolution, Why,
    auto_approves, baseline_allows_auto, guards_destroys, resolve,
};
pub use catalog::{Catalog, CatalogError, StepTypes, action_kind};
pub use check::{
    CheckOptions, Checked, EnvSecrets, SecretRequirement, SecretUse, check, check_with,
    secret_requirements,
};
pub use context::{CheckContext, ContextName, UnmetStep, run_order, unmet_steps};
pub use env::{EnvChoice, select_env};
pub use format::{BUILTIN as BUILTIN_FORMATS, Formats};
pub use k8s::{Auth, Cluster, ExecPlugin, Target};
pub use policy::{
    BLOCKS, Decision as PolicyDecision, SCRIPTS, SECRETS, Source as PolicySource, action_of,
    decide as decide_policy,
};
pub use registry::{Explanation, explain};
pub use script::{ScriptOutputs, Tag};
pub use types::{LiteralFit, Type, coerce, literal, literal_type};
pub use version::{FORMAT_VERSION, SCRIPT_PROTOCOL, STEP_API};
pub use workflow::{
    AskHandle, Condition, ContextTest, Env, Policy, PolicyRule, Step, Trigger, TriggerKind,
    Workflow,
};
