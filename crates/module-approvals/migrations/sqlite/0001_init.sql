-- One parked step asking for a human decision. `artifacts` is the runner's
-- digest list as JSON, and `expires_at` the instant after which nobody may
-- decide: the server compares it against the Clock rather than trusting a
-- deadline the runner restated for itself.
CREATE TABLE IF NOT EXISTS approval_requests (
    ticket TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    repo TEXT NOT NULL,
    step TEXT NOT NULL,
    summary TEXT NOT NULL,
    artifacts TEXT NOT NULL,
    team_org TEXT NOT NULL,
    team_slug TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- One decision per request. The primary key is the ticket, so a second answer
-- cannot land even when two approvers click in the same instant: one insert
-- wins and the other is refused by the constraint rather than by a check that
-- raced. `signature` is what the repository_dispatch event carries back to the
-- run, so it is written with the decision and never recomputed on read.
CREATE TABLE IF NOT EXISTS approval_decisions (
    ticket TEXT PRIMARY KEY REFERENCES approval_requests (ticket),
    approver TEXT NOT NULL,
    decision TEXT NOT NULL,
    comment TEXT,
    decided_at TEXT NOT NULL,
    signature TEXT NOT NULL
);

-- The durable half of "tell the run": the decision and the dispatch that
-- announces it commit together, so a decision can never be recorded without
-- its dispatch or delivered without its decision. DDL from
-- `cratefield_core::Outbox::create_table_sql`, shipped here as a migration.
CREATE TABLE IF NOT EXISTS approvals_outbox (
    id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    payload TEXT NOT NULL,
    subject TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    locked_until TEXT,
    created_at TEXT NOT NULL
);