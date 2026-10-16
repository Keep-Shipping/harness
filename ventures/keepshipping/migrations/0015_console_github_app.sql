-- The console's GitHub App (`src/github/app.rs`): the app the console was
-- created as, its installations, and the one-time `state` values the
-- manifest flow checks on return. Non-secret columns only. The app's private
-- key, webhook secret and client secret live in the secrets store
-- (`github-app/private-key`, `github-app/webhook-secret`,
-- `github-app/client-secret`), never in these tables.

-- One row: the console creates one app. `id` is pinned to 1.
CREATE TABLE IF NOT EXISTS console_github_app (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    app_id INTEGER NOT NULL,
    slug TEXT NOT NULL,
    client_id TEXT NOT NULL,
    html_url TEXT NOT NULL,
    owner_login TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- One row per installation of the app on an account (a user or an
-- organisation). Kept in step by the installed callback and the webhook.
CREATE TABLE IF NOT EXISTS console_github_installation (
    installation_id INTEGER PRIMARY KEY,
    account_login TEXT NOT NULL,
    account_type TEXT NOT NULL,
    repository_selection TEXT NOT NULL DEFAULT 'selected',
    updated_at TEXT NOT NULL
);

-- The manifest flow's `state`: random, single use, ten minutes. `expires_at`
-- is unix seconds.
CREATE TABLE IF NOT EXISTS console_github_app_state (
    state TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
