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

mod catalog;
mod check;
mod env;
pub mod harness;
pub mod ids;
pub mod ports;
pub mod step;
mod types;
mod workflow;

pub use check::{Checked, check};
pub use env::{EnvChoice, select_env};
pub use types::Type;
pub use workflow::{Env, Step, Trigger, TriggerKind, Workflow};
