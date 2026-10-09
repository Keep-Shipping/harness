//! The shared conformance suite (issue #147) plus the wasm dependency
//! boundary (ADR 0001) for `ks-module-approvals`.

use cratefield_testing::{assert_wasm_safe_deps, conformance};
use ks_module_approvals::Approvals;

#[test]
fn approvals_conforms() {
    conformance(Box::new(Approvals::new()));
}

#[test]
fn approvals_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
