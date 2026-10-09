//! The empty-plan gate: an import is proposed as a PR only when the plan over
//! the files it generated is empty
//! ([#167](https://github.com/Keep-Shipping/harness/issues/167)).
//!
//! The gate is a pure function over the port's own [`PlanJson`] — what
//! [`IacTool::plan`](ks_core::ports::iac::IacTool::plan) plus
//! [`IacTool::show`](ks_core::ports::iac::IacTool::show) answer for the
//! generated directory — so it invents no abstraction of its own and reads the
//! same shapes the engine's plan guard does.

use std::fmt;

use ks_core::ports::iac::{ChangeAction, PlanJson};

/// Why an import is not proposable: the plan over the generated files is not
/// empty. It carries the addresses that would change, so the caller can say
/// what the import disagrees with instead of opening a PR whose first apply
/// would move a live account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChanges {
    /// The resource addresses the plan would change, sorted.
    pub addresses: Vec<String>,
}

impl fmt::Display for PlannedChanges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the plan after import is not empty: {} would change; propose nothing until it is empty",
            self.addresses.join(", ")
        )
    }
}

impl std::error::Error for PlannedChanges {}

/// The gate: an empty plan is proposable; anything that would change is a
/// refusal naming the addresses, so the caller does not open a PR that is
/// known to disagree with the account. The plan must already have succeeded:
/// [`PlanJson`] is what `show` answers for a saved plan and has no way to say
/// "the plan errored" — an [`IacError`](ks_core::ports::iac::IacError) reaches
/// the caller before this runs.
pub fn check_empty_plan(plan: &PlanJson) -> Result<(), PlannedChanges> {
    // An entry whose actions are exactly `[NoOp]` is an untouched resource —
    // the entry the plan guard drops too. Everything else listed would change.
    let mut addresses: Vec<String> = plan
        .changes
        .iter()
        .filter(|change| change.actions != [ChangeAction::NoOp])
        .map(|change| change.address.clone())
        .collect();
    if addresses.is_empty() {
        return Ok(());
    }
    // Sorted, so the refusal does not depend on the order the tool listed
    // the changes in.
    addresses.sort();
    Err(PlannedChanges { addresses })
}
