//! The Keep Shipping core: shared types, the checker, the diagnostics
//! registry, the `StepKind` trait, the port traits and the `Harness` builder.
//!
//! Pure computation: no I/O of any kind, so the crate compiles unchanged for
//! `wasm32-unknown-unknown`.

#![forbid(unsafe_code)]

pub mod harness;
pub mod ids;
pub mod ports;
pub mod step;
