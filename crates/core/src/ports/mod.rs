//! Ports: the traits through which steps and the engine touch the world.
//!
//! A step never opens a socket, reads a CI environment variable or talks to a
//! vendor SDK directly: it calls a port, and an adapter (in `adapters/*`,
//! outside this crate) answers. That is what lets the same workflow run on a
//! laptop and in CI — only the adapters change. The ports defined here:
//!
//! - [`approval`] — asking a team, and the two rules that bind the answer to the artifacts ([#53](https://github.com/Keep-Shipping/harness/issues/53));
//! - [`run_context`] — who and where a run is (actor, repo, environment);
//! - [`secrets`] — resolving named secrets and redacting their values ([#49](https://github.com/Keep-Shipping/harness/issues/49));
//! - [`supply_chain`] — signing, attestations and digests ([#50](https://github.com/Keep-Shipping/harness/issues/50));
//! - [`iac`] — planning and applying infrastructure ([#51](https://github.com/Keep-Shipping/harness/issues/51));
//! - [`cluster`] — applying manifests and watching rollouts ([#52](https://github.com/Keep-Shipping/harness/issues/52));
//! - [`remote_shell`] — running commands on a host the harness does not own ([#52](https://github.com/Keep-Shipping/harness/issues/52));
//! - [`function_host`] — publishing a version and shifting traffic to it ([#52](https://github.com/Keep-Shipping/harness/issues/52));
//! - [`health`] — the shared vocabulary every port reports health in ([#78](https://github.com/Keep-Shipping/harness/issues/78));
//! - [`http`] — bounded, policy-checked HTTP ([#57](https://github.com/Keep-Shipping/harness/issues/57));
//! - [`blocks`] — the metadata-only blocks index ([#149](https://github.com/Keep-Shipping/harness/issues/149));
//! - [`block_source`] — block content, resolved and fetched by digest ([#56](https://github.com/Keep-Shipping/harness/issues/56));
//! - [`policy`] — the org baseline policy, read from outside the repository ([#56](https://github.com/Keep-Shipping/harness/issues/56));
//! - [`clock`] — time and sleeping, as a dependency rather than ambient;
//! - [`id_gen`] — minting fresh run ids;
//! - [`run_log`] — the append-only record of what a run did ([#46](https://github.com/Keep-Shipping/harness/issues/46));
//! - [`script_host`] — running the TypeScript escape-hatch steps;
//! - [`decision_model`] — asking a model a judgement it cannot be handed ([#54](https://github.com/Keep-Shipping/harness/issues/54));
//! - [`state_store`] — a parked run's state and its saved plans
//!   ([#42](https://github.com/Keep-Shipping/harness/issues/42)).
//!
//! [`run_log`], [`block_source`] and [`policy`] are the ports a step never sees
//! — the engine and the CLI hold them, not a step — so none of the three is in
//! the `Port` enum or in `define_ports!`, and `STEP_API` does not move when
//! they change. `check` in particular stays pure and I/O-free: it reads a
//! block's *digest* and a baseline's rules, and never resolves a version or
//! fetches a document. The remaining ports from the crate map (image building,
//! registry, cluster, approvals, …) land here with their issues.
//!
//! # Async without dependencies
//!
//! Async port methods return [`BoxFuture`] rather than `impl Future`. Boxing
//! keeps every trait dyn-compatible — steps hold ports as `&dyn Traits` so
//! adapters can be swapped at `Harness::build()` time — and hand-rolling the
//! alias keeps `ks-core` dependency-free and wasm-buildable. If the workspace
//! later adopts `async-trait`, the swap is mechanical: same signatures, the
//! macro owns the boxing.

use core::pin::Pin;

/// The future type used by async port methods.
///
/// A boxed, `Send`, explicitly-lifetimed future. See the [module
/// documentation](self) for why the ports box instead of using `async-trait`.
pub type BoxFuture<'a, T> = Pin<Box<dyn core::future::Future<Output = T> + Send + 'a>>;

pub mod approval;
pub mod block_source;
pub mod blocks;
pub mod clock;
pub mod cluster;
pub mod decision_model;
pub mod function_host;
pub mod health;
pub mod http;
pub mod iac;
pub mod id_gen;
pub mod policy;
pub mod remote_shell;
pub mod run_context;
pub mod run_log;
pub mod script_host;
pub mod secrets;
pub mod state_store;
pub mod supply_chain;
