//! The "manage as code" wizard's building blocks: what an app repository is
//! built with and what it needs, worked out from its files ([`detect`]); the
//! files that put one site and its test environment under code, plus the
//! summary a person confirms ([`generate`]); and the one `worker::Fetch`
//! socket the Cloudflare read goes through ([`fetch`]).
//!
//! The wizard on top of them is split by what each part touches: [`wizard`]
//! holds the pure rules (steps, names, the R2 secret, repository choice),
//! [`database`] parses a test database address, [`store`] keeps one row per
//! site in D1, [`page`] renders the steps, and [`flow`] runs them against
//! GitHub and Cloudflare. Each step is re-runnable; the pull request is the
//! only change the console makes to a repository, and approval is a person's.

pub mod database;
pub mod detect;
pub mod fetch;
pub mod flow;
pub mod generate;
pub mod page;
pub mod store;
pub mod wizard;

pub use fetch::WorkersHttp;
pub use generate::{DbKind, SiteScope, TestEnv, plan_files, scope, summary};
