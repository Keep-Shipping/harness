//! Test support for the Keep Shipping workspace: fakes for every port plus
//! conformance kits that adapters must pass.
//!
//! Each module mirrors a port from [`ks_core::ports`] and holds the fake(s)
//! for it plus, where relevant, a `conformance` function that panics with a
//! clear message when a port contract is violated. Everything here is
//! dependency-free and deterministic: no sockets, no real time, no randomness.
//!
//! Run futures with [`block_on`] — no executor dependency needed, because
//! fakes are always ready.

#![forbid(unsafe_code)]

use std::future::Future;
use std::task::Poll;

pub mod approval;
pub mod block_source;
pub mod blocks;
pub mod clock;
pub mod cluster;
pub mod decision_model;
pub mod function_host;
pub mod http;
pub mod iac;
pub mod id_gen;
pub mod policy;
pub mod remote_shell;
pub mod run_context;
pub mod run_lock;
pub mod run_log;
pub mod script_host;
pub mod secrets;
pub mod state_store;
pub mod step;
pub mod supply_chain;

/// The worked example in `docs/STEP-AUTHORING.md`, compiled and run as this
/// crate's doctests ([#142](https://github.com/Keep-Shipping/harness/issues/142)).
///
/// `cfg(doctest)` keeps the item out of an ordinary build and out of the
/// rendered docs; rustdoc sets it when it collects doctests, and then every
/// Rust code block in the guide becomes one. The guide's example runs
/// [`step::step_conformance`] against the fakes in this crate, so a step that
/// drifts out of the kit's contract breaks `cargo test` rather than the review.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/STEP-AUTHORING.md")]
pub struct StepAuthoringGuide;

/// Runs a future to completion on the current thread.
///
/// A busy-poll loop over a [`std::task::Waker::noop`] waker: the fakes in
/// this crate are always ready after the first poll, so a future here never
/// actually suspends. Do not use this on futures that do real I/O — it would
/// spin at 100% CPU; that is what a real executor is for.
pub fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    loop {
        match f.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => {}
        }
    }
}
