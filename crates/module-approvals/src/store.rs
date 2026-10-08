//! The two tables, read and written through the [`Database`] port. Plain
//! parameterised SQL rather than a query builder: two inserts and two reads,
//! each one checkable against the migration beside it.

use cratefield_core::{Database, DbError, Row, Statement};
use serde::{Deserialize, Serialize};

/// One artifact the request binds. Digests are compared as strings: this module
/// never re-derives one, and a decision that changed the list would not verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Artifact {
    pub name: String,
    pub sha256: String,
}

/// A parked step asking for a decision.
#[derive(Debug, Clone)]
pub(crate) struct RequestRow {
    pub ticket: String,
    pub run_id: String,
    pub repo: String,
    pub step: String,
    pub summary: String,
    pub artifacts: Vec<Artifact>,
    pub team_org: String,
    pub team_slug: String,
    pub proposed_by: String,
    pub reason: String,
    pub created_at: String,
    pub expires_at: String,
}

/// The answer, if one was given.
#[derive(Debug, Clone)]
pub(crate) struct DecisionRow {
    pub ticket: String,
    pub approver: String,
    pub decision: String,
    pub comment: Option<String>,
    pub decided_at: String,
    pub signature: String,
}

const REQUEST_COLUMNS: &str = "ticket, run_id, repo, step, summary, artifacts, team_org, \
                              team_slug, proposed_by, reason, created_at, expires_at";

fn text(row: &Row, column: &str) -> String {
    row.get::<String>(column).unwrap_or_default()
}

fn request_from(row: &Row) -> RequestRow {
    RequestRow {
        artifacts: serde_json::from_str(&text(row, "artifacts")).unwrap_or_default(),
        ticket: text(row, "ticket"),
        run_id: text(row, "run_id"),
        repo: text(row, "repo"),
        step: text(row, "step"),
        summary: text(row, "summary"),
        team_org: text(row, "team_org"),
        team_slug: text(row, "team_slug"),
        proposed_by: text(row, "proposed_by"),
        reason: text(row, "reason"),
        created_at: text(row, "created_at"),
        expires_at: text(row, "expires_at"),
    }
}

fn decision_from(row: &Row) -> DecisionRow {
    DecisionRow {
        ticket: text(row, "ticket"),
        approver: text(row, "approver"),
        decision: text(row, "decision"),
        comment: row.get::<Option<String>>("comment").flatten(),
        decided_at: text(row, "decided_at"),
        signature: text(row, "signature"),
    }
}

/// The request behind `ticket`, or `None` for a ticket this module never minted.
pub(crate) async fn find_request(
    db: &dyn Database,
    ticket: &str,
) -> Result<Option<RequestRow>, DbError> {
    let sql = format!("SELECT {REQUEST_COLUMNS} FROM approval_requests WHERE ticket = ?");
    Ok(db
        .query(&Statement::with_values(&sql, vec![ticket.into()]))
        .await?
        .first()
        .map(request_from))
}

/// The decision on `ticket`, or `None` while it is still pending.
pub(crate) async fn find_decision(
    db: &dyn Database,
    ticket: &str,
) -> Result<Option<DecisionRow>, DbError> {
    let sql = "SELECT ticket, approver, decision, comment, decided_at, signature \
         FROM approval_decisions WHERE ticket = ?";
    Ok(db
        .query(&Statement::with_values(sql, vec![ticket.into()]))
        .await?
        .first()
        .map(decision_from))
}

/// Parks the request. A ticket is a fresh ULID, so a collision is not a case
/// this module handles.
pub(crate) async fn insert_request(db: &dyn Database, row: &RequestRow) -> Result<(), DbError> {
    let artifacts = serde_json::to_string(&row.artifacts)
        .map_err(|error| DbError::Execute(error.to_string()))?;
    let sql = format!(
        "INSERT INTO approval_requests ({REQUEST_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    );
    let ordered = [
        row.ticket.as_str(),
        row.run_id.as_str(),
        row.repo.as_str(),
        row.step.as_str(),
        row.summary.as_str(),
        artifacts.as_str(),
        row.team_org.as_str(),
        row.team_slug.as_str(),
        row.proposed_by.as_str(),
        row.reason.as_str(),
        row.created_at.as_str(),
        row.expires_at.as_str(),
    ];
    db.execute(&Statement::with_values(sql, ordered.into_iter().map(Into::into).collect())).await?;
    Ok(())
}

/// The decision insert and the outbox enqueue, as one batch for the caller to
/// hand to [`Database::batch_atomic`]: the decision is what the run waits for
/// and the dispatch is what tells it the wait is over.
pub(crate) fn decision_batch(row: &DecisionRow, dispatch: Statement) -> Vec<Statement> {
    let sql = "INSERT INTO approval_decisions (ticket, approver, decision, comment, decided_at, \
               signature) VALUES (?, ?, ?, ?, ?, ?)";
    let decision = Statement::with_values(
        sql,
        vec![
            row.ticket.clone().into(),
            row.approver.clone().into(),
            row.decision.clone().into(),
            row.comment.clone().into(),
            row.decided_at.clone().into(),
            row.signature.clone().into(),
        ],
    );
    vec![decision, dispatch]
}
