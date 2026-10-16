-- The optional Cloudflare deploy token the console rolls deployments back
-- with (`src/cloudflare/rollback.rs`): Pages Edit and Workers Scripts Edit
-- only. Kept apart from the read-only token in 0009 so the fleet view never
-- holds write access unless the operator adds it, and removing it leaves
-- the fleet view untouched. Sealed the same way, under its own key
-- (HKDF info "ks-console/cloudflare-deploy-token/v1").
CREATE TABLE IF NOT EXISTS console_cloudflare_deploy_token (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    nonce       TEXT NOT NULL,
    ciphertext  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
