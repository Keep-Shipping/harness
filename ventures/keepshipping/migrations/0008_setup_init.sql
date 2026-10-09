-- Standard setup console (issue #273): one checklist per domain, one change
-- per send. The waitlist and billing modules own wrangler numbering
-- 0001-0007; this file is that numbering's `0008` AND, embedded in
-- `src/setup/mod.rs`, the setup module's own `0001`. Nothing here deletes:
-- a sent change keeps its row (and its pull request) even after the domain
-- moves on, and a confirmation is a fact about a person, not about state.

-- The desired state the checklist edits; one row per domain, created on
-- first view. The eight `*_on` columns follow the checklist's order; a
-- write must match `version` (optimistic concurrency, as billing does).
CREATE TABLE IF NOT EXISTS setup_domains (
    domain             TEXT PRIMARY KEY,
    search_console_on  INTEGER NOT NULL DEFAULT 1,
    postmaster_on      INTEGER NOT NULL DEFAULT 1,
    bing_on            INTEGER NOT NULL DEFAULT 1,
    spf_on             INTEGER NOT NULL DEFAULT 1,
    dkim_on            INTEGER NOT NULL DEFAULT 1,
    dmarc_on           INTEGER NOT NULL DEFAULT 1,
    mta_sts_on         INTEGER NOT NULL DEFAULT 1,
    tls_rpt_on         INTEGER NOT NULL DEFAULT 1,
    spf_value          TEXT NOT NULL,
    dkim_selector      TEXT NOT NULL,
    dkim_key           TEXT,  -- NULL until the operator pastes Google's key
    dmarc_rua          TEXT NOT NULL,
    sitemap_url        TEXT NOT NULL,
    version            INTEGER NOT NULL,  -- a write must match it
    updated_at         TEXT NOT NULL
);

-- Every send, opened or not: what was asked, as the exact files and summary
-- the pull request carries, so a later send can tell "already asked" from
-- "never asked". `pr_url` stays NULL while GitHub is not connected — the
-- change is saved, the pull request is not (and the page says so).
CREATE TABLE IF NOT EXISTS setup_changes (
    id         TEXT PRIMARY KEY,  -- ULID; its first 8 chars name the branch
    domain     TEXT NOT NULL,
    branch     TEXT NOT NULL,
    title      TEXT NOT NULL,
    summary_md TEXT NOT NULL,
    files      TEXT NOT NULL,  -- JSON object: path → content
    pr_url     TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS setup_changes_domain ON setup_changes (domain, created_at);

-- The clicks a pull request cannot make: "I did this" for the outside
-- services (Search Console, Postmaster Tools, Bing). One row per item.
CREATE TABLE IF NOT EXISTS setup_confirmations (
    domain       TEXT NOT NULL,
    item         TEXT NOT NULL,
    confirmed_at TEXT NOT NULL,
    confirmed_by TEXT NOT NULL,
    PRIMARY KEY (domain, item)
);
