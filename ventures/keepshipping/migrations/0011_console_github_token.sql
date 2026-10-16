-- The GitHub token the console talks to GitHub with (`src/github/`): a
-- fine-grained personal access token, pasted on the GitHub connection page.
-- One row, written by that page, deleted by disconnect. The token is never
-- stored in clear: `ciphertext` is AES-256-GCM output (tag included) under a
-- key derived from HARNESS_SECRET with its own info string
-- ("ks-console/github-token/v1"), and `nonce` is the 96-bit nonce it was
-- sealed with, both base64. Rotating HARNESS_SECRET makes the stored token
-- unreadable; the connect page then asks for it again.
CREATE TABLE IF NOT EXISTS console_github_token (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    nonce       TEXT NOT NULL,
    ciphertext  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
