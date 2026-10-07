//! Library pieces of the `keepshipping` CLI.
//!
//! The binary lives in `main.rs`; this target exists so the OCI distribution
//! adapter's conformance job can drive the real
//! [`http_client::TcpHttpClient`] against live registries.

#![forbid(unsafe_code)]

pub mod http_client;
// Test-only scaffolding, but it has to be reachable from the binary's test
// harness too — `github_actions_run_context` drives a real socket through it —
// and a `#[cfg(test)]` module of the library is not compiled into the library
// as the binary's dependency. One copy, always compiled.
pub mod test_server;
