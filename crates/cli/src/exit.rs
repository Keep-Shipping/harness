//! The exit codes the CLI returns, by name.
//!
//! An agent driving `keepshipping` should not have to memorise numbers: each
//! code here names an outcome, and the JSON a run prints carries the same
//! words in its `status`. 0–3 are the codes the CLI has always returned; 10–12
//! are the run's own states, kept apart from them so a new outcome can be
//! added without renumbering. The codes are pinned in `docs/CLI.md`.
//!
//! `130` is not here: a cancelled run is the engine's
//! ([`ks_engine::exec::EXIT_CANCELLED`](ks_engine::exec::EXIT_CANCELLED)), the
//! shell's own report of `SIGINT`, and no branch here can reach it.

/// Everything selected ran, and it succeeded. For `check`, the file is clean.
pub const SHIPPED: u8 = 0;
/// A step failed, or `check` found errors (warnings with
/// `--warnings-as-errors`).
pub const FAILED: u8 = 1;
/// A bug in keepshipping: an unexpected I/O error or a panic.
pub const INTERNAL: u8 = 3;
/// The run stopped at an approval nobody could answer: a state, not a verdict,
/// and one an agent should report and stop on. See `docs/CLI.md`.
pub const WAITING: u8 = 10;
/// A human was asked and said no. Unlike [`WAITING`] this is a verdict, and
/// re-running asks the same person again.
pub const DENIED: u8 = 11;
/// Policy refused the run — the engine's
/// [`EXIT_POLICY_REFUSED`](ks_engine::exec::EXIT_POLICY_REFUSED), named here so
/// the two cannot drift apart.
#[allow(dead_code)]
pub const REFUSED: u8 = 12;

#[cfg(test)]
mod tests {
    use super::*;

    /// The codes an agent branches on are the ones the engine's run status
    /// spells the same way, so `docs/CLI.md` has one row for each.
    #[test]
    fn the_run_states_match_the_engines() {
        assert_eq!(WAITING, ks_engine::exec::EXIT_WAITING_FOR_APPROVAL);
        assert_eq!(REFUSED, ks_engine::exec::EXIT_POLICY_REFUSED);
        assert_eq!(FAILED, ks_engine::exec::EXIT_FAILED);
        assert_eq!(INTERNAL, 3, "the panic hook in main");
    }
}
