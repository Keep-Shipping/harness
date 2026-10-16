-- The edit-as-code module's tables (issue #170): console forms whose submit is
-- a Terraform pull request (`src/edits/`). Mirrors the module's own migration
-- `src/edits/migrations/0001_init.sql`, which the native tests run; this file is
-- what production applies, so the two stay in step (a test checks every column).
-- `repo` is the repository the edit's pull request lives in; empty means the
-- configured EDITS_REPO. CREATE ... IF NOT EXISTS so a database that already has
-- the tables is left as it is.

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
