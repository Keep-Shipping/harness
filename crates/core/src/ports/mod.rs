//! Ports: the traits through which steps and the engine touch the world.
//!
//! A step never opens a socket, reads a CI environment variable or talks to a
//! vendor SDK directly: it calls a port, and an adapter (in `adapters/*`,
//! outside this crate) answers. That is what lets the same workflow run on a
//! laptop and in CI — only the adapters change. The ports defined here:
//!
//! - [`run_context`] — who and where a run is (actor, repo, environment);
//! - [`secrets`] — resolving named secrets and redacting their values ([#49](https://github.com/Keep-Shipping/harness/issues/49));
//! - [`supply_chain`] — signing, attestations and digests ([#50](https://github.com/Keep-Shipping/harness/issues/50));
//! - [`iac`] — planning and applying infrastructure ([#51](https://github.com/Keep-Shipping/harness/issues/51));
//! - [`http`] — bounded, policy-checked HTTP ([#57](https://github.com/Keep-Shipping/harness/issues/57));
//! - [`blocks`] — the metadata-only blocks index ([#149](https://github.com/Keep-Shipping/harness/issues/149));
//! - [`clock`] — time and sleeping, as a dependency rather than ambient;
//! - [`id_gen`] — minting fresh run ids;
//! - [`script_host`] — running the TypeScript escape-hatch steps.
//!
//! The remaining ports from the crate map (image building, registry, cluster,
//! approvals, run log, …) land here with their issues.
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

pub mod blocks;
pub mod clock;
pub mod http;
pub mod iac;
pub mod id_gen;
pub mod run_context;
pub mod script_host;
pub mod secrets;
pub mod supply_chain;
