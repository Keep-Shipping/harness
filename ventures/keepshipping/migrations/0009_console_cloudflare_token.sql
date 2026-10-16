-- The Cloudflare read-only token the console reads the account with (the
-- fleet view's collector, `src/cloudflare/`). One row, written by the
-- connect page, deleted by disconnect. The token is never stored in clear:
-- `ciphertext` is AES-256-GCM output (tag included) under a key derived from
-- HARNESS_SECRET, and `nonce` is the 96-bit nonce it was sealed with, both
-- base64. Rotating HARNESS_SECRET makes the stored token unreadable; the
-- connect page then asks for it again.
CREATE TABLE IF NOT EXISTS console_cloudflare_token (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    nonce       TEXT NOT NULL,
    ciphertext  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
