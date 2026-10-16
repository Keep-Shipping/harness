-- The edits module (issue #170): console forms that write Terraform pull
-- requests. One row per requested change, plus the module's own outbox —
-- cratefield-core's portable DDL, under this module's table name — so opening
-- the pull request and firing the approval dispatch survive a crash between
-- the click and GitHub. Kept inside src/edits/ because the tables belong to
-- this module, not to the venture's shared schema directory. The venture's
-- production migration is migrations/0013_edits.sql; keep the two in step.

CREATE TABLE IF NOT EXISTS edits (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    zone TEXT NOT NULL,
    title TEXT NOT NULL,
    summary_md TEXT NOT NULL,
    file_path TEXT NOT NULL DEFAULT '',
    author TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'opening',
    repo TEXT NOT NULL DEFAULT '',
    pr_number INTEGER,
    pr_url TEXT NOT NULL DEFAULT '',
    pr_head_sha TEXT NOT NULL DEFAULT '',
    changes_json TEXT,
    plan_sha256 TEXT NOT NULL DEFAULT '',
    plan_file_sha256 TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    approver TEXT,
    approved_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_edits_created_at ON edits (created_at DESC);

CREATE TABLE IF NOT EXISTS edits_outbox (
    id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    payload TEXT NOT NULL,
    subject TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    locked_until TEXT,
    created_at TEXT NOT NULL
);
