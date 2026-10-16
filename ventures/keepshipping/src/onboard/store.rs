//! The wizard's D1 rows: one `console_onboarding` row per site, and the
//! `edits` row the setup's pull request is tracked by. The reads are plain
//! `SELECT`s and the writes are upserts; nothing here carries a token or a
//! database address, and the callers never pass one in.

use serde::Deserialize;
use worker::Env;
use worker::wasm_bindgen::JsValue;

/// The table one site's wizard state lives in.
pub const TABLE: &str = "console_onboarding";

/// One site's wizard state, as D1 returns it. Every column is text; the JSON
/// columns are read by [`super::flow`] and [`super::page`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Record {
    /// The app repository the scan read, as `owner/name`; empty for none.
    pub app_repo: String,
    /// The infrastructure repository, as `owner/name`, once chosen.
    pub infra_repo: String,
    /// The scan's findings ([`super::flow::Scan`]), as JSON.
    pub stack_json: String,
    /// The facts the status page needs ([`super::flow::Opened`]), as JSON.
    pub test_env_json: String,
    /// The edit the setup opened; empty until the pull request is.
    pub edit_id: String,
    /// `draft`, `scanned`, `opening`, `failed` or `opened`.
    pub status: String,
    /// The last failure, in plain words, naming the step that failed.
    pub error: String,
    /// When the row was first written, RFC 3339.
    pub created_at: String,
    /// When it last changed, RFC 3339.
    pub updated_at: String,
}

/// The state of a site's wizard, or `None` when it has never been started.
pub async fn get(env: &Env, site_id: &str) -> worker::Result<Option<Record>> {
    let db = env.d1("DB")?;
    db.prepare(format!(
        "SELECT app_repo, infra_repo, stack_json, test_env_json, edit_id, status, error, \
         created_at, updated_at FROM {TABLE} WHERE site_id = ?"
    ))
    .bind(&[JsValue::from_str(site_id)])?
    .first::<Record>(None)
    .await
}

/// Writes a site's wizard state, creating the row on first use. `created_at`
/// is kept from the first write.
pub async fn put(env: &Env, site_id: &str, record: &Record, now: &str) -> worker::Result<()> {
    let db = env.d1("DB")?;
    let created = if record.created_at.is_empty() { now } else { record.created_at.as_str() };
    let values = [
        JsValue::from_str(site_id),
        JsValue::from_str(&record.app_repo),
        JsValue::from_str(&record.infra_repo),
        JsValue::from_str(&record.stack_json),
        JsValue::from_str(&record.test_env_json),
        JsValue::from_str(&record.edit_id),
        JsValue::from_str(&record.status),
        JsValue::from_str(&record.error),
        JsValue::from_str(created),
        JsValue::from_str(now),
    ];
    db.prepare(format!(
        "INSERT INTO {TABLE} (site_id, app_repo, infra_repo, stack_json, test_env_json, edit_id, \
         status, error, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(site_id) DO UPDATE SET app_repo = excluded.app_repo, \
         infra_repo = excluded.infra_repo, stack_json = excluded.stack_json, \
         test_env_json = excluded.test_env_json, edit_id = excluded.edit_id, \
         status = excluded.status, error = excluded.error, updated_at = excluded.updated_at"
    ))
    .bind(&values)?
    .run()
    .await?;
    Ok(())
}

/// What the wizard and the site page show about an edit: its state, the
/// summary the person confirmed and the pull request it went out as.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct EditView {
    /// The edit's status: `checking`, `planned`, `approved`, `failed`, …
    pub status: String,
    /// The summary the edit was created with, as Markdown.
    pub summary_md: String,
    /// The pull request's page, empty until it is open.
    pub pr_url: String,
    /// The pull request's number, 0 until it is open.
    pub pr_number: i64,
    /// Why the edit failed, empty otherwise.
    pub error: String,
}

/// The edit's view, or `None` when no such edit exists.
pub async fn edit(env: &Env, edit_id: &str) -> worker::Result<Option<EditView>> {
    if edit_id.is_empty() {
        return Ok(None);
    }
    let db = env.d1("DB")?;
    db.prepare(
        "SELECT status, summary_md, pr_url, COALESCE(pr_number, 0) AS pr_number, error \
         FROM edits WHERE id = ?",
    )
    .bind(&[JsValue::from_str(edit_id)])?
    .first::<EditView>(None)
    .await
}

/// Whether an edit row already exists: the marker that the pull request was
/// opened, so a repeated setup does not open a second one.
pub async fn edit_exists(env: &Env, edit_id: &str) -> worker::Result<bool> {
    if edit_id.is_empty() {
        return Ok(false);
    }
    let db = env.d1("DB")?;
    let row = db
        .prepare("SELECT id FROM edits WHERE id = ?")
        .bind(&[JsValue::from_str(edit_id)])?
        .first::<serde_json::Value>(None)
        .await?;
    Ok(row.is_some())
}

/// Records the edit a setup opened. `INSERT OR IGNORE`: a repeated setup keeps
/// the row it already made, with whatever status it has reached.
#[allow(clippy::too_many_arguments)]
pub async fn insert_edit(
    env: &Env,
    edit_id: &str,
    repo: &str,
    zone: &str,
    title: &str,
    summary_md: &str,
    file_path: &str,
    author: &str,
    pull: &crate::github::Pull,
    now: &str,
) -> worker::Result<()> {
    let db = env.d1("DB")?;
    let number = pull.number.to_string();
    let values = [
        JsValue::from_str(edit_id),
        JsValue::from_str(zone),
        JsValue::from_str(title),
        JsValue::from_str(summary_md),
        JsValue::from_str(file_path),
        JsValue::from_str(author),
        JsValue::from_str(repo),
        JsValue::from_str(&number),
        JsValue::from_str(&pull.url),
        JsValue::from_str(&pull.head_sha),
        JsValue::from_str(now),
        JsValue::from_str(now),
    ];
    db.prepare(
        "INSERT OR IGNORE INTO edits (id, kind, zone, title, summary_md, file_path, author, \
         status, repo, pr_number, pr_url, pr_head_sha, created_at, updated_at) \
         VALUES (?, 'onboard', ?, ?, ?, ?, ?, 'checking', ?, ?, ?, ?, ?, ?)",
    )
    .bind(&values)?
    .run()
    .await?;
    Ok(())
}

/// Whether another site's setup already uses this infrastructure repository.
/// One repository holds one state per site, named by the site, so two sites
/// cannot share one.
pub async fn repo_taken(env: &Env, repo: &str, site_id: &str) -> worker::Result<bool> {
    let db = env.d1("DB")?;
    let row = db
        .prepare(format!(
            "SELECT site_id FROM {TABLE} WHERE infra_repo = ? AND site_id != ? LIMIT 1"
        ))
        .bind(&[JsValue::from_str(repo), JsValue::from_str(site_id)])?
        .first::<serde_json::Value>(None)
        .await?;
    Ok(row.is_some())
}
