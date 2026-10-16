//! The wizard's Worker wiring: each step of "manage as code" as a request
//! handler. A GET shows the step the site is on; a POST runs one step and
//! answers with a redirect back to the page, so a refresh never repeats a
//! write. Every step is re-runnable: a failure is stored in the site's
//! `console_onboarding` row, naming the step that failed, and the page offers
//! "Try again", which runs the same steps over.
//!
//! Two secrets pass through this module and are never stored: the infra
//! Cloudflare token and the test database address. They go straight into the
//! infrastructure repository's Actions secrets, and every error message is a
//! fixed phrase, so neither can reach a page or a log.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use cratefield_core::Clock;
use cratefield_runtime_cloudflare::WorkersClock;
use ks_cloudflare::{Account as CfAccount, Attr, Cloudflare, StateBackend};
use ks_core::ports::secrets::SecretValue;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use worker::Env;

use super::WorkersHttp;
use super::database::{self, DbAddress};
use super::detect::{self, BindingKind, Stack};
use super::generate::DbKind;
use super::generate::{self, SiteScope, TestEnv};
use super::page::{self, Review, StatusView, View};
use super::store::{self, Record};
use super::wizard::{self, Step};
use crate::cloudflare::api;
use crate::cloudflare::rollback::{self, Target};
use crate::fleet::{self, Kind, Site};
use crate::github::{self, Client, NewPull, Repo};

const STEP_TOKEN: &str = "Checking the infrastructure token";
const STEP_BUCKET: &str = "Creating the state bucket";
const STEP_REPO: &str = "Finding the infrastructure repository";
const STEP_READ: &str = "Reading the Cloudflare account";
const STEP_NAME: &str = "Naming the state";
const STEP_SECRETS: &str = "Storing the setup secrets";
const STEP_PULL: &str = "Opening the pull request";
const STEP_RECORD: &str = "Recording the change";
const STEP_CHECK: &str = "Checking the earlier pull request";
const STEP_BRANCH: &str = "Putting the workflow on the default branch";

const NOT_CONNECTED: &str = "GitHub is not connected. Connect it first.";
const NO_READ_TOKEN: &str = "No Cloudflare read token is connected. Connect one first.";
const READ_FAILED: &str = "Cloudflare did not give the account's details. Check the read token's \
     permissions on the Cloudflare connection page.";
const UNAVAILABLE: &str = "This kind of site cannot be managed as code yet. Pages projects and \
     Workers can.";
const NO_SCAN: &str = "Scan the app repository first.";
const NO_RANDOM: &str = "The server has no random source right now. Try again.";

/// The scan of the app repository, stored as the row's `stack_json`. Names and
/// kinds only: the scan keeps no environment values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scan {
    /// The app repository as `owner/name`; empty for "Cloudflare only".
    pub repo: String,
    /// The branch the files were read from.
    pub branch: String,
    /// GitHub cut the file list short, so some files were not read.
    pub truncated: bool,
    /// What the files said.
    pub stack: Stack,
}

/// The facts the status page reads after a setup, stored as the row's
/// `test_env_json`. Says whether a database address was given and whether
/// email forwarding needs its secret set by hand; never the address itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opened {
    /// The test environment the setup generated.
    pub test_env: TestEnv,
    /// Whether a test database address was supplied.
    pub db_given: bool,
    /// Whether the account has email forwarding destinations, whose secret
    /// is set by hand.
    pub destinations: bool,
    /// The database engine the app needs for its test environment, when it
    /// needs one. Set even when no address was given yet.
    pub db_kind: Option<DbKind>,
}

/// What a wizard request answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A page, with its HTTP status.
    Html(u16, String),
    /// A 303 to a path on this console.
    Redirect(String),
}

/// A failed step: its name, and what to tell the person, in plain words.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stop {
    step: &'static str,
    message: String,
}

impl Stop {
    fn new(step: &'static str, message: impl Into<String>) -> Stop {
        Stop { step, message: message.into() }
    }
}

/// The wizard's page path for a site.
#[must_use]
pub fn page_path(site: &Site) -> String {
    format!("/console/fleet/{}/code", fleet::site_path_segment(&site.id))
}

/// `GET /console/fleet/<id>/code`: the step the site is on. `again` shows the
/// review of a finished setup, to run it again.
pub async fn view(env: &Env, secret: Option<&str>, site: &Site, again: bool) -> Reply {
    let here = page_path(site);
    let Some(target) = rollback::target(site) else {
        return Reply::Html(200, page::notice("Not available", UNAVAILABLE));
    };
    let record = match load(env, &site.id).await {
        Ok(record) => record,
        Err(reply) => return reply,
    };
    match github::client_for(env, None, secret).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Reply::Html(
                200,
                page::wizard(site, Some(Step::GitHub), View::Connect { next: &here }),
            );
        }
        Err(failed) => {
            return Reply::Html(
                failed.status,
                page::notice("Could not check GitHub", failed.message),
            );
        }
    }
    match record.status.as_str() {
        "opened" if !again => status(env, site, &record).await,
        "" | "draft" => repo_step(env, secret, site, &target, &record).await,
        _ => review(env, secret, site, &target, &record, None).await,
    }
}

/// `POST /console/fleet/<id>/code`: runs the step named by the `step` field.
pub async fn post(
    env: &Env,
    secret: Option<&str>,
    site: &Site,
    email: &str,
    form: &[(String, String)],
) -> Reply {
    let Some(target) = rollback::target(site) else {
        return Reply::Html(409, page::notice("Not available", UNAVAILABLE));
    };
    match field(form, "step") {
        "scan" => scan(env, secret, site, form).await,
        "open" => open(env, secret, site, &target, email, form).await,
        _ => Reply::Redirect(page_path(site)),
    }
}

/// The site's wizard row, read for the site page. `None` when the setup was
/// never started, or the row cannot be read (the page then offers to start).
pub async fn site_record(env: &Env, site_id: &str) -> Option<Record> {
    match store::get(env, site_id).await {
        Ok(record) => record,
        Err(error) => {
            tracing::warn!(%error, "console: reading the setup state for a site page failed");
            None
        }
    }
}

fn field<'a>(form: &'a [(String, String)], name: &str) -> &'a str {
    form.iter().find(|(key, _)| key == name).map_or("", |(_, value)| value.as_str())
}

fn account_of(target: &Target) -> &str {
    match target {
        Target::Pages { account, .. } | Target::Worker { account, .. } => account,
    }
}

fn name_of(target: &Target) -> &str {
    match target {
        Target::Pages { project, .. } => project,
        Target::Worker { script, .. } => script,
    }
}

fn non_empty(text: &str) -> Option<&str> {
    Some(text).filter(|text| !text.trim().is_empty())
}

fn to_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// The site's row, or the page that says it could not be read: a POST must
/// never write over a row it failed to read.
async fn load(env: &Env, site_id: &str) -> Result<Record, Reply> {
    store::get(env, site_id).await.map(Option::unwrap_or_default).map_err(|error| {
        tracing::warn!(%error, "console: reading the setup state failed");
        Reply::Html(
            503,
            page::notice(
                "Could not read the setup",
                "The setup state could not be read. Try again in a moment.",
            ),
        )
    })
}

/// Saves the row. A failed write is logged, not shown: every step can be run
/// again, so the next run catches up.
async fn save(env: &Env, site: &Site, record: &Record, now: &str) {
    if let Err(error) = store::put(env, &site.id, record, now).await {
        tracing::warn!(%error, "console: saving the setup state failed");
    }
}

/// The site's test environment, from what its stack needs.
fn test_env_of(site: &Site, target: &Target, stack: &Stack, enabled: bool) -> TestEnv {
    let main = fleet::main_domain(&site.domains).map(String::as_str);
    let pages = match target {
        Target::Pages { project, .. } => Some(project.as_str()),
        Target::Worker { .. } => None,
    };
    let mut test = wizard::test_env_for(stack, &wizard::slug(name_of(target)), main, pages);
    test.enabled = enabled;
    test
}

/// The scope of one site on its account: its domains and its own objects.
fn scope_of(site: &Site, stack: &Stack) -> SiteScope {
    let bindings = stack
        .existing_bindings
        .iter()
        .filter(|binding| {
            matches!(binding.kind, BindingKind::D1 | BindingKind::Kv | BindingKind::R2)
        })
        .map(|binding| binding.name.clone())
        .collect();
    SiteScope::from_site(site, bindings)
}

/// The account, read with the stored read token.
async fn read_account(env: &Env, secret: Option<&str>, target: &Target) -> Result<CfAccount, Stop> {
    let token = api::load_token(env, secret)
        .await
        .map_err(|failed| Stop::new(STEP_READ, failed.message))?
        .ok_or(Stop::new(STEP_READ, NO_READ_TOKEN))?;
    let reader =
        Cloudflare::new(Arc::new(WorkersHttp::cloudflare()), SecretValue::new(token.into_bytes()));
    reader.read(account_of(target)).await.map_err(|_| Stop::new(STEP_READ, READ_FAILED))
}

/// The first step: a repository choice, preselected from the Pages source or
/// the closest name.
async fn repo_step(
    env: &Env,
    secret: Option<&str>,
    site: &Site,
    target: &Target,
    record: &Record,
) -> Reply {
    let repos = match github::list_repos(env, secret).await {
        Ok(repos) => repos,
        Err(failed) => {
            return Reply::Html(
                failed.status,
                page::notice("Could not list your repositories", failed.message),
            );
        }
    };
    let source = match target {
        Target::Pages { account, project } => match api::load_token(env, secret).await {
            Ok(Some(token)) => api::pages_source(&token, account, project).await,
            _ => None,
        },
        Target::Worker { .. } => None,
    };
    let source = source.as_ref().map(|(owner, name)| (owner.as_str(), name.as_str()));
    let selected = wizard::preselect(name_of(target), source, &repos)
        .map(|index| format!("{}/{}", repos[index].owner, repos[index].name));
    Reply::Html(
        200,
        page::wizard(
            site,
            Some(Step::Repo),
            View::Repo {
                repos: &repos,
                selected: selected.as_deref(),
                error: non_empty(&record.error),
            },
        ),
    )
}

/// The review: what the scan found, what the setup will create, and the
/// fields for the two secrets.
async fn review(
    env: &Env,
    secret: Option<&str>,
    site: &Site,
    target: &Target,
    record: &Record,
    error: Option<&str>,
) -> Reply {
    let scan: Scan = serde_json::from_str(&record.stack_json).unwrap_or_default();
    let test = test_env_of(site, target, &scan.stack, true);
    let (plan_lines, plan_note) = match read_account(env, secret, target).await {
        Ok(account) => {
            let scoped = generate::scope(&account, &scope_of(site, &scan.stack));
            (Some(generate::summary(&scoped, &test)), None)
        }
        Err(stop) => (None, Some(stop.message)),
    };
    let infra_default = if record.infra_repo.is_empty() {
        wizard::infra_repo_default(&scan.repo, &wizard::slug(name_of(target)))
    } else {
        record.infra_repo.clone()
    };
    Reply::Html(
        200,
        page::wizard(
            site,
            Some(Step::Review),
            View::Review(Review {
                app_repo: &scan.repo,
                stack_lines: if scan.repo.is_empty() { Vec::new() } else { scan.stack.summary() },
                truncated: scan.truncated,
                plan_lines: plan_lines.as_deref(),
                plan_note: plan_note.as_deref(),
                db: test.hyperdrive,
                infra_default: &infra_default,
                error: error.or_else(|| non_empty(&record.error)),
            }),
        ),
    )
}

/// The status page of a finished setup: the pull request, the edit's state
/// and what is left for a person to do.
async fn status(env: &Env, site: &Site, record: &Record) -> Reply {
    let edit = store::edit(env, &record.edit_id).await.ok().flatten();
    let facts: Option<Opened> = serde_json::from_str(&record.test_env_json).ok();
    let runner_set = env
        .secret("EDITS_RUNNER_TOKEN")
        .map(|secret| !secret.to_string().trim().is_empty())
        .unwrap_or(false);
    Reply::Html(
        200,
        page::wizard(
            site,
            None,
            View::Status(StatusView {
                infra_repo: &record.infra_repo,
                edit_id: &record.edit_id,
                edit: edit.as_ref(),
                facts: facts.as_ref(),
                runner_set,
                worker: site.kind == Kind::Worker,
                error: non_empty(&record.error),
            }),
        ),
    )
}

/// Scans the app repository (or records "Cloudflare only") and moves the
/// wizard on to the review. A failure is stored as the row's error.
async fn scan(env: &Env, secret: Option<&str>, site: &Site, form: &[(String, String)]) -> Reply {
    let mut record = match load(env, &site.id).await {
        Ok(record) => record,
        Err(reply) => return reply,
    };
    if record.status == "opened" {
        return Reply::Redirect(page_path(site));
    }
    let now = api::now();
    let choice = field(form, "repo").trim();
    if choice == "none" {
        record.app_repo = String::new();
        record.infra_repo = String::new();
        record.stack_json = to_json(&Scan::default());
        return finish_scan(env, site, record, &now).await;
    }
    let Some((owner, name)) = wizard::parse_repo(choice) else {
        return refuse_scan(env, site, record, "Choose a repository from the list.", &now).await;
    };
    if !matches!(github::client_for(env, None, secret).await, Ok(Some(_))) {
        return refuse_scan(env, site, record, NOT_CONNECTED, &now).await;
    }
    let repos = match github::list_repos(env, secret).await {
        Ok(repos) => repos,
        Err(failed) => return refuse_scan(env, site, record, failed.message, &now).await,
    };
    let Some(repo) = repos.into_iter().find(|repo| {
        repo.owner.eq_ignore_ascii_case(owner) && repo.name.eq_ignore_ascii_case(name)
    }) else {
        return refuse_scan(
            env,
            site,
            record,
            "That repository is not one the GitHub token can see. Pick one from the list.",
            &now,
        )
        .await;
    };
    let client = match github::client_for(env, Some((owner, name)), secret).await {
        Ok(Some(client)) => client,
        _ => return refuse_scan(env, site, record, NOT_CONNECTED, &now).await,
    };
    match read_scan(&client, &repo).await {
        Ok(scan) => {
            record.app_repo = scan.repo.clone();
            record.infra_repo = String::new();
            record.stack_json = to_json(&scan);
            finish_scan(env, site, record, &now).await
        }
        Err(message) => refuse_scan(env, site, record, message, &now).await,
    }
}

/// The client that works on the infrastructure repository, and the repository
/// itself. An existing repository is reached through a connection that covers
/// it. One that does not exist yet is created through the owner's connection
/// (the app's installation on that account, else the personal token).
async fn repo_client(
    env: &Env,
    secret: Option<&str>,
    owner: &str,
    name: &str,
) -> Result<(Client, Repo), Stop> {
    let existing = github::client_for(env, Some((owner, name)), secret)
        .await
        .map_err(|failed| Stop::new(STEP_REPO, failed.message))?;
    if let Some(client) = existing
        && let Some(repo) =
            client.repo(owner, name).await.map_err(|failed| Stop::new(STEP_REPO, failed.message))?
    {
        return Ok((client, repo));
    }
    let creator = github::client_for_owner(env, owner, secret)
        .await
        .map_err(|failed| Stop::new(STEP_REPO, failed.message))?
        .ok_or(Stop::new(STEP_REPO, NOT_CONNECTED))?;
    let repo = creator
        .create_repo(owner, name)
        .await
        .map_err(|failed| Stop::new(STEP_REPO, failed.message))?;
    Ok((creator, repo))
}

/// Lists the repository's files, reads the ones [`detect::pick`] chooses and
/// works out the stack from them.
async fn read_scan(client: &Client, repo: &Repo) -> Result<Scan, &'static str> {
    let tree = client
        .tree(&repo.owner, &repo.name, &repo.default_branch)
        .await
        .map_err(|failed| failed.message)?;
    let mut files = BTreeMap::new();
    for path in detect::pick(&tree.paths) {
        let text =
            client.file(&repo.owner, &repo.name, &path).await.map_err(|failed| failed.message)?;
        if let Some(text) = text {
            files.insert(path, text);
        }
    }
    Ok(Scan {
        repo: format!("{}/{}", repo.owner, repo.name),
        branch: repo.default_branch.clone(),
        truncated: tree.truncated,
        stack: detect::detect(&files),
    })
}

async fn finish_scan(env: &Env, site: &Site, mut record: Record, now: &str) -> Reply {
    record.status = "scanned".to_owned();
    record.error = String::new();
    save(env, site, &record, now).await;
    Reply::Redirect(page_path(site))
}

async fn refuse_scan(
    env: &Env,
    site: &Site,
    mut record: Record,
    message: &str,
    now: &str,
) -> Reply {
    record.error = message.to_owned();
    save(env, site, &record, now).await;
    Reply::Redirect(page_path(site))
}

/// The path of the workflow every infrastructure repository carries on its
/// default branch: `repository_dispatch` runs only workflows that are there.
const WORKFLOW_PATH: &str = ".github/workflows/infra.yml";
/// The state backend file: its presence on a default branch means the
/// repository already holds a site's state.
const STATE_FILE: &str = "backend.tf";
/// How long a running setup holds the site before a second one may start.
const LOCK: Duration = Duration::minutes(2);

const ALREADY_RUNNING: &str =
    "A setup for this site is already running. Wait a minute, then reload this page.";
const APPROVED_CHANGED: &str = "This change is already approved and is being applied, so its \
     pull request cannot take the new files. Open a new change for them.";
const DB_READ: &str = "The database could not be read.";

/// Whether a setup started at `updated_at` still holds the site at `now`.
fn holds(updated_at: &str, now: OffsetDateTime) -> bool {
    OffsetDateTime::parse(updated_at, &Rfc3339).is_ok_and(|at| now - at < LOCK)
}

/// The open step: check the form, then run the setup. A problem with the form
/// is shown on the review; a failure in the setup is stored with its step.
async fn open(
    env: &Env,
    secret: Option<&str>,
    site: &Site,
    target: &Target,
    email: &str,
    form: &[(String, String)],
) -> Reply {
    let mut record = match load(env, &site.id).await {
        Ok(record) => record,
        Err(reply) => return reply,
    };
    let now = api::now();
    if record.status == "opening" && holds(&record.updated_at, WorkersClock.now()) {
        return refuse_form(env, site, record, ALREADY_RUNNING, &now).await;
    }
    let scan: Scan = match serde_json::from_str(&record.stack_json) {
        Ok(scan) if !record.stack_json.is_empty() => scan,
        _ => return refuse_form(env, site, record, NO_SCAN, &now).await,
    };
    let test_on = field(form, "test_env") == "on";
    let infra_text = field(form, "infra_repo").trim().to_owned();
    let Some((infra_owner, infra_name)) = wizard::parse_repo(&infra_text) else {
        return refuse_form(
            env,
            site,
            record,
            "Enter the infrastructure repository as owner/name, like you/infra-shop.",
            &now,
        )
        .await;
    };
    let token = field(form, "infra_token").trim().to_owned();
    if token.is_empty() {
        return refuse_form(
            env,
            site,
            record,
            "Paste the Cloudflare token for the infrastructure repository.",
            &now,
        )
        .await;
    }
    let db_kind = test_env_of(site, target, &scan.stack, test_on).hyperdrive;
    let db_text = field(form, "test_db_url").trim().to_owned();
    let database = if test_on && db_kind.is_some() && !db_text.is_empty() {
        match database::parse(&db_text) {
            Ok(address) => Some(address),
            Err(error) => {
                return refuse_form(env, site, record, error.message(), &now).await;
            }
        }
    } else {
        None
    };

    let infra_full = format!("{infra_owner}/{infra_name}");
    let own_repo = record.infra_repo == infra_full;
    record.status = "opening".to_owned();
    record.error = String::new();
    record.infra_repo = infra_full;
    save(env, site, &record, &now).await;

    let input = OpenInput {
        site,
        target,
        scan: &scan,
        test_on,
        email,
        infra: (infra_owner, infra_name),
        token: &token,
        database,
        own_repo,
    };
    match run_open(env, secret, &input, &mut record, &now).await {
        Ok(()) => {
            record.status = "opened".to_owned();
            record.error = String::new();
        }
        Err(stop) => {
            record.status = "failed".to_owned();
            record.error = format!("{} did not finish. {}", stop.step, stop.message);
        }
    }
    save(env, site, &record, &now).await;
    Reply::Redirect(page_path(site))
}

async fn refuse_form(
    env: &Env,
    site: &Site,
    mut record: Record,
    message: &str,
    now: &str,
) -> Reply {
    record.error = message.to_owned();
    save(env, site, &record, now).await;
    Reply::Redirect(page_path(site))
}

/// What the open step was given, once the form is checked.
struct OpenInput<'a> {
    site: &'a Site,
    target: &'a Target,
    scan: &'a Scan,
    test_on: bool,
    email: &'a str,
    infra: (&'a str, &'a str),
    token: &'a str,
    database: Option<DbAddress>,
    /// The site's row already named this repository: a repeat, not a clash.
    own_repo: bool,
}

/// The open step's work, in an order that makes a repeat safe.
///
/// The repository must be the site's own: no other site's row names it, and
/// (unless it is this site's repository already) its default branch holds no
/// state file. The workflow goes on the default branch before anything else,
/// since a repository_dispatch can only run a workflow found there. Secrets
/// are set on every run. The state passphrase is generated only
/// when the repository has no `STATE_ENCRYPTION_PASSPHRASE` yet, so a repeat
/// never rotates a key the state may be encrypted under. The plan is read on
/// every run, and the pull request's files follow it: a new branch when there
/// is no edit yet, the existing branch brought up to date when there is one.
async fn run_open(
    env: &Env,
    secret: Option<&str>,
    input: &OpenInput<'_>,
    record: &mut Record,
    now: &str,
) -> Result<(), Stop> {
    let site = input.site;
    let account = account_of(input.target);
    let (owner, name) = input.infra;
    let infra_full = format!("{owner}/{name}");

    let token_id = api::verify_account_token(input.token, account)
        .await
        .map_err(|failed| Stop::new(STEP_TOKEN, failed.message))?;
    api::create_bucket(input.token, account, wizard::STATE_BUCKET)
        .await
        .map_err(|failed| Stop::new(STEP_BUCKET, failed.message))?;

    let (client, repo) = repo_client(env, secret, owner, name).await?;
    let slug = wizard::slug(name_of(input.target));
    let shared = Stop::new(
        STEP_REPO,
        format!(
            "That repository already belongs to another site, or already holds its state. Use \
             {owner}/infra-{slug} instead, or another repository name."
        ),
    );
    if store::repo_taken(env, &infra_full, &site.id)
        .await
        .map_err(|_| Stop::new(STEP_REPO, DB_READ))?
    {
        return Err(shared);
    }
    if !input.own_repo
        && client
            .file_at(owner, name, STATE_FILE, &repo.default_branch)
            .await
            .map_err(|failed| Stop::new(STEP_REPO, failed.message))?
            .is_some()
    {
        return Err(shared);
    }

    // Whether the test database exists: an address given now, or one an
    // earlier run stored. Without one the test environment waits for it.
    let mut test = test_env_of(site, input.target, &input.scan.stack, input.test_on);
    let db_kind = test.hyperdrive;
    let has_db = match &input.database {
        Some(_) => true,
        None => client
            .actions_secret_exists(owner, name, "TEST_DB_HOST")
            .await
            .map_err(|failed| Stop::new(STEP_SECRETS, failed.message))?,
    };
    if !has_db {
        test.hyperdrive = None;
    }

    if record.edit_id.is_empty() {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| Stop::new(STEP_PULL, NO_RANDOM))?;
        record.edit_id = wizard::new_edit_id(random);
    }
    let edit =
        store::edit(env, &record.edit_id).await.map_err(|_| Stop::new(STEP_CHECK, DB_READ))?;

    let account_read = read_account(env, secret, input.target).await?;
    let scoped = generate::scope(&account_read, &scope_of(site, &input.scan.stack));
    if !generate::is_account_id(&scoped.account_id) {
        return Err(Stop::new(
            STEP_READ,
            "Cloudflare did not give the account's id in the form this setup can use.",
        ));
    }
    let backend = StateBackend::new(account, wizard::STATE_BUCKET, &slug)
        .map_err(|_| Stop::new(STEP_NAME, "The site's name cannot be used to name its state."))?;
    let files: BTreeMap<String, String> = generate::plan_files(&scoped, &test, &backend);
    let lines = generate::summary(&scoped, &test);

    let facts = Opened {
        test_env: test.clone(),
        db_given: has_db,
        destinations: !scoped.destinations.is_empty(),
        db_kind,
    };
    record.test_env_json = to_json(&facts);
    record.infra_repo = infra_full.clone();
    save(env, site, record, now).await;

    let mut secrets: Vec<(&str, String)> = vec![
        ("CLOUDFLARE_API_TOKEN", input.token.to_owned()),
        ("AWS_ACCESS_KEY_ID", token_id),
        ("AWS_SECRET_ACCESS_KEY", wizard::r2_secret_access_key(input.token)),
    ];
    if !client
        .actions_secret_exists(owner, name, "STATE_ENCRYPTION_PASSPHRASE")
        .await
        .map_err(|failed| Stop::new(STEP_SECRETS, failed.message))?
    {
        secrets.push(("STATE_ENCRYPTION_PASSPHRASE", state_passphrase()?));
    }
    if let Ok(key) = env.secret("EDITS_RUNNER_TOKEN") {
        let key = key.to_string();
        if !key.trim().is_empty() {
            // Each repository's workflow gets its own runner token, so a leaked
            // one opens only that repository's edits.
            let per_repo = crate::edits::runner_token_for(key.trim(), &infra_full);
            secrets.push(("EDITS_RUNNER_TOKEN", per_repo));
        }
    }
    if test.hyperdrive.is_some()
        && let Some(address) = &input.database
    {
        secrets.extend(database::secrets(address));
    }
    for (secret_name, value) in &secrets {
        client
            .set_actions_secret(owner, name, secret_name, value)
            .await
            .map_err(|failed| Stop::new(STEP_SECRETS, failed.message))?;
    }

    // The workflow on the default branch, the copy the pull request carries too.
    if let Some(workflow) = files.get(WORKFLOW_PATH) {
        client
            .put_if_changed(
                owner,
                name,
                WORKFLOW_PATH,
                &repo.default_branch,
                workflow,
                "Keep the infrastructure workflow current (Keep Shipping).",
            )
            .await
            .map_err(|failed| Stop::new(STEP_BRANCH, failed.message))?;
    }

    match edit {
        None => {
            let pull_input = PullInput {
                site,
                repo: &repo,
                edit_id: &record.edit_id,
                files,
                lines: &lines,
                zone: zone_for(&scoped, site),
                email: input.email,
                now,
            };
            open_pull_request(env, &client, &pull_input).await?;
        }
        Some(edit) => {
            update_branch(&client, &repo, &record.edit_id, &files, edit.status == "approved")
                .await?;
        }
    }
    Ok(())
}

/// Brings the edit's branch up to the planned files, committing only what
/// changed, so the workflow plans the new files. An approved edit cannot take
/// new files: when they differ, that is said rather than silently dropped.
async fn update_branch(
    client: &Client,
    repo: &Repo,
    edit_id: &str,
    files: &BTreeMap<String, String>,
    approved: bool,
) -> Result<(), Stop> {
    let branch = wizard::edit_branch(edit_id);
    for (path, content) in files {
        if approved {
            let current = client
                .file_at(&repo.owner, &repo.name, path, &branch)
                .await
                .map_err(|failed| Stop::new(STEP_PULL, failed.message))?;
            if current.as_ref().map(|(_, text)| text.as_str()) != Some(content.as_str()) {
                return Err(Stop::new(STEP_PULL, APPROVED_CHANGED));
            }
        } else {
            client
                .put_if_changed(
                    &repo.owner,
                    &repo.name,
                    path,
                    &branch,
                    content,
                    "Update the planned change (Keep Shipping).",
                )
                .await
                .map_err(|failed| Stop::new(STEP_PULL, failed.message))?;
        }
    }
    Ok(())
}

/// What opening the pull request needs.
struct PullInput<'a> {
    site: &'a Site,
    repo: &'a Repo,
    edit_id: &'a str,
    files: BTreeMap<String, String>,
    lines: &'a [String],
    zone: String,
    email: &'a str,
    now: &'a str,
}

/// Opens the pull request with the planned files, then records the edit the
/// plan callback and the approval page work from. The edit row is written
/// straight after the pull request, so a plan that arrives first finds it.
async fn open_pull_request(env: &Env, client: &Client, input: &PullInput<'_>) -> Result<(), Stop> {
    let title = wizard::pr_title(&input.site.name);
    let summary_md: String = input.lines.iter().map(|line| format!("- {line}\n")).collect();
    let edit_url = format!("{}/v1/edits/{}", wizard::CONSOLE_URL, input.edit_id);
    let body = wizard::pr_body(input.lines, &edit_url);
    let files: Vec<(String, String)> =
        input.files.iter().map(|(path, text)| (path.clone(), text.clone())).collect();
    let first_path = files.first().map_or_else(String::new, |(path, _)| path.clone());
    let pull = client
        .commit_pull_request(
            &input.repo.owner,
            &input.repo.name,
            &NewPull {
                base: &input.repo.default_branch,
                branch: &wizard::edit_branch(input.edit_id),
                title: &title,
                body: &body,
                files: &files,
            },
        )
        .await
        .map_err(|failed| Stop::new(STEP_PULL, failed.message))?;
    let repo = format!("{}/{}", input.repo.owner, input.repo.name);
    store::insert_edit(
        env,
        input.edit_id,
        &repo,
        &input.zone,
        &title,
        &summary_md,
        &first_path,
        input.email,
        &pull,
        input.now,
    )
    .await
    .map_err(|_| Stop::new(STEP_RECORD, "The database could not record the change."))
}

/// The zone the change is about: the first zone the site's domains sit in,
/// named as the approval page asks for it. The site's domain when no zone is
/// in the scope.
fn zone_for(account: &CfAccount, site: &Site) -> String {
    account
        .resources
        .iter()
        .filter(|resource| resource.kind == "cloudflare_zone")
        .find_map(|resource| match resource.attrs.get("name") {
            Some(Attr::Lit(Value::String(name))) => Some(name.clone()),
            _ => None,
        })
        .or_else(|| fleet::main_domain(&site.domains).cloned())
        .unwrap_or_else(|| site.name.clone())
}

/// A random 32-byte passphrase for the state, base64, shown nowhere.
fn state_passphrase() -> Result<String, Stop> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Stop::new(STEP_SECRETS, NO_RANDOM))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}
