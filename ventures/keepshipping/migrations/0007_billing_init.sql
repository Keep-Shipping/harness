-- Billing (issue #177, ADR 0202), through Polar as Merchant of Record.
-- The waitlist module owns wrangler numbering 0001-0006; this file is that
-- numbering's `0007` AND, embedded in `src/billing/mod.rs`, the billing
-- module's own `0001`. A row is NEVER deleted for non-payment: lapsed,
-- unpaid, refunded, revoked or dispute-lost subscriptions read as the free
-- plan through `status`/`access_until`/`revoked`, and the row survives.
-- Subscription events move the plan; an `order.paid` keeps only identity.

CREATE TABLE IF NOT EXISTS billing_accounts (
    account_id      TEXT PRIMARY KEY,  -- venture account id (= Polar external_customer_id)
    subscription_id TEXT,
    last_order_id   TEXT,  -- last `order.paid`: disputes without a customer id resolve through it
    product_id      TEXT,
    status          TEXT NOT NULL,  -- cratefield-core `Status`: 'active', 'expired', 'revoked', ...
    period_type     TEXT NOT NULL DEFAULT 'normal',
    renews          INTEGER NOT NULL DEFAULT 0,
    access_until    TEXT,  -- RFC 3339; paid access lapses here
    last_event_at   TEXT NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0,
    disputed        INTEGER NOT NULL DEFAULT 0,
    version         INTEGER NOT NULL DEFAULT 0,  -- optimistic-concurrency token: a write must match it
    last_event_id   TEXT,  -- dedup key of the event that won the row last
    updated_at      TEXT NOT NULL
);

-- Append-only: one row per applied event; `id` is the dedup key.
CREATE TABLE IF NOT EXISTS billing_audit (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL,
    source      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    plan_before TEXT NOT NULL,
    plan_after  TEXT NOT NULL,
    at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS billing_audit_account ON billing_audit (account_id, at);

-- The dedup ledger the harness `Inbox` expects (`Inbox::create_table_sql`).
CREATE TABLE IF NOT EXISTS billing_inbox (
    event_key TEXT PRIMARY KEY,
    seen_at   TEXT NOT NULL
);
