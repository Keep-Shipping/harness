-- The repository an edit's pull request lives in, when it is not the module's
-- configured EDITS_REPO. Onboarding (src/onboard/) opens each site's pull
-- request in that site's own infrastructure repository, so its approval has
-- to dispatch there. Empty means the configured repository, as before.
ALTER TABLE edits ADD COLUMN repo TEXT NOT NULL DEFAULT '';
