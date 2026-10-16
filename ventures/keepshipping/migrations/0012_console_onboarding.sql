-- The "manage as code" wizard's state for one site (src/onboard/): which app
-- repository it was matched to, what the scan found, the test environment
-- and the edit (pull request) the setup opened. One row per site, written by
-- each wizard step and kept after the pull request is open so the site page
-- can show where it stands.
--
-- Never a token and never a database address: the Cloudflare infrastructure
-- token and the test database password are used once, in memory, to set the
-- infrastructure repository's secrets, and are not stored here. `stack_json`
-- holds names and kinds only (the scan keeps no environment values), and
-- `test_env_json` holds the test environment's names and flags.
CREATE TABLE IF NOT EXISTS console_onboarding (
    site_id       TEXT PRIMARY KEY,
    app_repo      TEXT NOT NULL DEFAULT '',
    infra_repo    TEXT NOT NULL DEFAULT '',
    stack_json    TEXT NOT NULL DEFAULT '',
    test_env_json TEXT NOT NULL DEFAULT '',
    edit_id       TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'draft',
    error         TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
