//! The "manage as code" wizard's building blocks: what an app repository is
//! built with and what it needs, worked out from its files ([`detect`]); the
//! files that put one site and its test environment under code, plus the
//! summary a person confirms ([`generate`]); and the one `worker::Fetch`
//! socket the Cloudflare read goes through ([`fetch`]).
//!
//! Nothing here writes to Cloudflare or to a repository. The wizard that
//! drives it (the page, the state and the pull request) is a later slice;
//! this module is what that slice calls.

pub mod detect;
pub mod fetch;
pub mod generate;

pub use fetch::WorkersHttp;
pub use generate::{DbKind, SiteScope, TestEnv, plan_files, scope, summary};
