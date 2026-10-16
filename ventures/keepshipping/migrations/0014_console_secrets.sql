-- The secrets store's schema for the console's own credentials (the
-- Cloudflare read token, the Cloudflare deploy token and the GitHub token,
-- `src/secrets.rs`).
--
-- Copied verbatim from cratefield-secrets 0.4.0: the four SQLite migrations
-- its `migrations()` returns, `0001_init` through `0004_store_attribution`,
-- in that order, with nothing changed. This venture's test
-- (`src/secrets.rs`, `the_schema_is_the_crate_s_verbatim`) fails if this file
-- ever drifts from the crate's SQL. Upgrading cratefield-secrets means
-- re-copying from its new migrations and adding a new numbered file, never
-- editing this one once it has run anywhere.
--
-- The store's tables live in this venture's own database (the tenant tier of
-- the crate). `harness_secret_keys` holds the wrapped data key, wrapped under
-- the master key (the KEK) that never leaves the Worker's secret store;
-- `harness_secrets` holds the tokens, encrypted under that data key.
-- ---- cratefield-secrets 0.4.0: sqlite/0001_init.sql ----
-- The secrets store's own tables (issue #39, docs/SECRETS-DESIGN.md §3).
-- The same two tables exist in every store: once in the control database
-- as the global store, once in each tenant database as that tenant's.
-- No table mixes tiers and no database holds both.
--
-- The wrapped DEK lives here, not in the KMS: a dump of this database is
-- ciphertext plus a blob that cannot be unwrapped anywhere but the KMS,
-- and a backup, a tenant move and an offboarding shred are all local.
CREATE TABLE IF NOT EXISTS harness_secret_keys (
    key_id       TEXT PRIMARY KEY,
    kms_provider TEXT NOT NULL,
    kms_key_ref  TEXT NOT NULL,
    wrapped_dek  BLOB NOT NULL,
    cipher       TEXT NOT NULL,
    state        TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS harness_secrets (
    name       TEXT NOT NULL,
    version    INTEGER NOT NULL,
    key_id     TEXT NOT NULL REFERENCES harness_secret_keys (key_id),
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    deleted_at TEXT,
    PRIMARY KEY (name, version)
);

-- ---- cratefield-secrets 0.4.0: sqlite/0002_audit.sql ----
-- The secret-access audit chain (issue #41). One per store: the global
-- store's chain in the control database, each tenant's in its own, so a
-- tenant's auditor sees only that tenant's chain and the log lives and
-- dies with the data it describes.
--
-- Every row's hash covers the previous row's hash, so altering or
-- removing any row breaks every link after it.
CREATE TABLE IF NOT EXISTS harness_secret_audit (
    seq        INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    INTEGER,
    action     TEXT NOT NULL,
    allowed    INTEGER NOT NULL,
    request_id TEXT,
    prev_hash  BLOB NOT NULL,
    hash       BLOB NOT NULL
);

-- Append-only, enforced by the database rather than by convention. The
-- role grants that stop an application role even trying are deployment
-- configuration; these triggers stop everything that reaches the table,
-- including the migration role.
CREATE TRIGGER IF NOT EXISTS harness_secret_audit_no_update
BEFORE UPDATE ON harness_secret_audit
BEGIN
    SELECT RAISE(ABORT, 'harness_secret_audit is append-only');
END;

CREATE TRIGGER IF NOT EXISTS harness_secret_audit_no_delete
BEFORE DELETE ON harness_secret_audit
BEGIN
    SELECT RAISE(ABORT, 'harness_secret_audit is append-only');
END;

-- ---- cratefield-secrets 0.4.0: sqlite/0003_audit_store.sql ----
-- Store attribution on the audit chain (issue #142). A chain lives in
-- its store's own database and the hash of every row written from here
-- on covers the store it belongs to, so a chain copied verbatim from
-- another database cannot verify as this store's history. Rows written
-- before this migration carry the empty default and keep their
-- original (v1) hash bytes, so existing chains stay valid — an
-- append-only table's past is not rewritten.
ALTER TABLE harness_secret_audit ADD COLUMN store TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS harness_secret_audit_store_seq
    ON harness_secret_audit (store, seq);

-- ---- cratefield-secrets 0.4.0: sqlite/0004_store_attribution.sql ----
-- Store attribution on the secrets and key tables (the row-level twin
-- of the audit chain's #142): one physical database may host several
-- stores' rows -- the control database holds the global store and every
-- tenant store the platform runs, side by side -- and until this
-- migration those rows were indistinguishable at the SQL layer. The AAD
-- kept them separate under encryption (a row never decrypts in the
-- wrong store), but every query was store-blind: `active_key` served
-- whichever key row was newest regardless of store, `delete` soft-deleted
-- every store's rows of that name, `rotate_dek` tried to re-encrypt the
-- other stores' rows and failed closed on their AAD, and the primary
-- key (name, version) made the same name in two stores of one database
-- impossible outright.
--
-- `harness_secrets` is rebuilt rather than altered because its primary
-- key must grow the store column, and neither engine alters a primary
-- key. The copy rewrites nothing but the table's shape, which in a table
-- holding ciphertext is the entire point.
--
-- A row written before this migration would carry the empty store, and
-- an empty store is nobody's: every query here scopes to `store = ?`
-- exactly, so such a row is invisible rather than visible to all. The
-- audit chain's #142 chose the opposite (`OR store = ''`) because it is
-- append-only -- its past cannot be rewritten, so the clause can only
-- let an old row be read. These tables are deleted, re-encrypted and
-- re-keyed from, where the same clause would instead hand every store a
-- write over every other store's unstamped rows. Nothing is lost by the
-- stricter rule: no composition ever applied this schema before
-- attribution, so no such row exists to be rescued.
CREATE TABLE harness_secrets_attributed (
    name       TEXT NOT NULL,
    version    INTEGER NOT NULL,
    key_id     TEXT NOT NULL REFERENCES harness_secret_keys (key_id),
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    deleted_at TEXT,
    store      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (store, name, version)
);

INSERT INTO harness_secrets_attributed
    (name, version, key_id, nonce, ciphertext, created_at, created_by, deleted_at, store)
    SELECT name, version, key_id, nonce, ciphertext, created_at, created_by, deleted_at, ''
    FROM harness_secrets;

DROP TABLE harness_secrets;

ALTER TABLE harness_secrets_attributed RENAME TO harness_secrets;

ALTER TABLE harness_secret_keys ADD COLUMN store TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS harness_secrets_store_name
    ON harness_secrets (store, name);

CREATE INDEX IF NOT EXISTS harness_secret_keys_store_state
    ON harness_secret_keys (store, state);

