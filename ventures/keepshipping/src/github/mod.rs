//! The console's GitHub connection: a fine-grained token the console keeps
//! in its secrets vault (`src/secrets.rs`, envelope-encrypted), and the
//! GitHub REST calls the setup wizard makes with it.
//!
//! The pure parts — URL building, reading GitHub's JSON, sealing a secret
//! for GitHub's Actions endpoint — are plain functions, tested natively
//! below. What is left is the Workers wiring: `worker::Fetch` for the calls
//! and the vault for the token. The token is only ever in memory, in a
//! request header, or in the vault. It is never logged, never put in a URL
//! and never returned.

pub mod page;

use std::sync::Arc;

use base64::Engine as _;
use cratefield_core::Database;
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit};

use crate::cloudflare::seal::GITHUB_INFO;
use crate::secrets::{self, Legacy, Stored, Vault};

/// The public REST root.
pub const API: &str = "https://api.github.com";
/// The REST API version every call pins, so a GitHub-side default change
/// cannot change what the console reads.
const API_VERSION: &str = "2022-11-28";
const USER_AGENT: &str = "keepshipping-console";
/// The old D1 table the token was sealed in before the vault (`id = 1`).
/// Read only to move the row across; see `src/secrets.rs`.
const LEGACY_TABLE: &str = "console_github_token";

/// A failure the connection and wizard pages can show: an HTTP status to
/// answer with, and what to tell the person, in plain words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failed {
    /// The HTTP status the console answers with.
    pub status: u16,
    /// The plain-words reason, shown to the person.
    pub message: &'static str,
}

const NETWORK: Failed =
    Failed { status: 502, message: "Could not reach GitHub. Try again in a moment." };
const NOT_ACCEPTED: Failed = Failed {
    status: 400,
    message: "GitHub did not accept this token. Check that you copied the whole token and that \
              it has not expired.",
};
const REFUSED: Failed = Failed {
    status: 502,
    message: "GitHub refused a request this token should be able to make. Check the token's \
              permissions against the list on the connection page.",
};
const SHAPE: Failed = Failed {
    status: 502,
    message: "GitHub answered in a shape this console does not read. Try again later.",
};
const STORE: Failed = Failed { status: 503, message: "The token could not be saved. Try again." };
const NO_MASTER_KEY: Failed = Failed { status: 503, message: secrets::NO_MASTER_KEY_COPY };
const REPO_REFUSED: Failed = Failed {
    status: 502,
    message: "GitHub would not create that repository. The name may already be taken, or the \
              token may lack Administration on this account.",
};
/// A repository the token can see, as far as the wizard needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    /// The account or organisation that owns it.
    pub owner: String,
    /// The repository's name, without the owner.
    pub name: String,
    /// The branch new work starts from.
    pub default_branch: String,
    /// Whether only the repository's members can see it.
    pub private: bool,
}

/// A repository's file paths on one branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    /// Every file path, relative to the repository root.
    pub paths: Vec<String>,
    /// GitHub cut the listing short: `paths` is not the whole tree.
    pub truncated: bool,
}

/// The public key a repository's Actions secrets are sealed under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionsKey {
    /// The key's id, sent back with the sealed value.
    pub key_id: String,
    /// The key itself, base64 of 32 bytes.
    pub key: String,
}

/// A pull request to open: the branch it comes from, the branch it targets,
/// its text, and the files each committed on the branch.
#[derive(Debug, Clone, Copy)]
pub struct NewPull<'a> {
    /// The branch the pull request merges into.
    pub base: &'a str,
    /// The branch the commits go on; created off `base`.
    pub branch: &'a str,
    /// The pull request's title, also the first line of each commit.
    pub title: &'a str,
    /// The pull request's body, Markdown.
    pub body: &'a str,
    /// Each file's path and full text.
    pub files: &'a [(String, String)],
}

/// A pull request the console opened, or found already open for its branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pull {
    /// The pull request's number in its repository.
    pub number: u64,
    /// The page on GitHub a person opens to read it.
    pub url: String,
    /// The commit the branch's head is at.
    pub head_sha: String,
}

// ---------------------------------------------------------------------------
// Pure: URLs.
// ---------------------------------------------------------------------------

/// Percent-encodes one path segment: unreserved characters pass, everything
/// else is `%XX`. Owners, repository names and file names never carry a `/`
/// in a segment, so each is encoded whole.
#[must_use]
pub fn segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// [`segment`] for a path that may contain `/`: each part is encoded, the
/// slashes kept. Branch names like `feature/x` and file paths use this.
#[must_use]
pub fn path(text: &str) -> String {
    text.split('/').map(segment).collect::<Vec<_>>().join("/")
}

/// `GET /user`: the signed-in account.
#[must_use]
pub fn user_url() -> String {
    format!("{API}/user")
}

/// `GET /user/repos`: every repository the token can see, most recently
/// pushed first, one page of 100.
#[must_use]
pub fn repos_url() -> String {
    format!("{API}/user/repos?sort=pushed&per_page=100")
}

/// `GET /repos/{owner}/{name}`.
#[must_use]
pub fn repo_url(owner: &str, name: &str) -> String {
    format!("{API}/repos/{}/{}", segment(owner), segment(name))
}

/// `GET /repos/{owner}/{name}/git/trees/{branch}?recursive=1`.
#[must_use]
pub fn tree_url(owner: &str, name: &str, branch: &str) -> String {
    format!("{}/git/trees/{}?recursive=1", repo_url(owner, name), path(branch))
}

/// `GET /repos/{owner}/{name}/contents/{path}`: the default branch's file.
#[must_use]
pub fn contents_url(owner: &str, name: &str, file: &str) -> String {
    format!("{}/contents/{}", repo_url(owner, name), path(file))
}

/// Where a new repository is created: `POST /user/repos` for the token's own
/// account, `POST /orgs/{org}/repos` for an organisation.
#[must_use]
pub fn create_repo_url(owner: &str, login: &str) -> String {
    if owner.eq_ignore_ascii_case(login) {
        format!("{API}/user/repos")
    } else {
        format!("{API}/orgs/{}/repos", segment(owner))
    }
}

/// `GET /repos/{owner}/{name}/actions/secrets/public-key`.
#[must_use]
pub fn actions_key_url(owner: &str, name: &str) -> String {
    format!("{}/actions/secrets/public-key", repo_url(owner, name))
}

/// `PUT /repos/{owner}/{name}/actions/secrets/{secret}`.
#[must_use]
pub fn actions_secret_url(owner: &str, name: &str, secret: &str) -> String {
    format!("{}/actions/secrets/{}", repo_url(owner, name), segment(secret))
}

/// `GET /repos/{owner}/{name}/git/ref/heads/{branch}`: a branch's head.
#[must_use]
pub fn branch_ref_url(owner: &str, name: &str, branch: &str) -> String {
    format!("{}/git/ref/heads/{}", repo_url(owner, name), path(branch))
}

/// `POST /repos/{owner}/{name}/git/refs`: creates a branch.
#[must_use]
pub fn refs_url(owner: &str, name: &str) -> String {
    format!("{}/git/refs", repo_url(owner, name))
}

/// `GET` or `PUT /repos/{owner}/{name}/contents/{path}` on one branch.
#[must_use]
pub fn contents_on_url(owner: &str, name: &str, file: &str, branch: &str) -> String {
    format!("{}?ref={}", contents_url(owner, name, file), segment(branch))
}

/// `POST /repos/{owner}/{name}/pulls`.
#[must_use]
pub fn pulls_url(owner: &str, name: &str) -> String {
    format!("{}/pulls", repo_url(owner, name))
}

/// `GET /repos/{owner}/{name}/pulls` for the open pull request from `branch`
/// (the head is `owner:branch`).
#[must_use]
pub fn open_pulls_url(owner: &str, name: &str, branch: &str) -> String {
    format!("{}?head={}&state=open", pulls_url(owner, name), segment(&format!("{owner}:{branch}")))
}

/// `POST /repos/{owner}/{name}/actions/variables`.
#[must_use]
pub fn variables_url(owner: &str, name: &str) -> String {
    format!("{}/actions/variables", repo_url(owner, name))
}

/// `PATCH /repos/{owner}/{name}/actions/variables/{variable}`.
#[must_use]
pub fn variable_url(owner: &str, name: &str, variable: &str) -> String {
    format!("{}/{}", variables_url(owner, name), segment(variable))
}

// ---------------------------------------------------------------------------
// Pure: reading GitHub's answers.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct UserBody {
    login: String,
}

#[derive(Deserialize)]
struct OwnerBody {
    login: String,
}

#[derive(Deserialize)]
struct RepoBody {
    name: String,
    default_branch: String,
    private: bool,
    owner: OwnerBody,
}

#[derive(Deserialize)]
struct TreeBody {
    tree: Vec<TreeEntry>,
    #[serde(default)]
    truncated: bool,
}

#[derive(Deserialize)]
struct TreeEntry {
    path: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct FileBody {
    content: Option<String>,
    encoding: Option<String>,
}

#[derive(Deserialize)]
struct KeyBody {
    key_id: String,
    key: String,
}

fn shape<T>(parsed: Result<T, serde_json::Error>) -> Result<T, Failed> {
    parsed.map_err(|_| SHAPE)
}

/// The login of an account answer (`GET /user`).
pub fn read_login(body: &str) -> Result<String, Failed> {
    shape(serde_json::from_str::<UserBody>(body)).map(|user| user.login)
}

/// The repositories of a listing (`GET /user/repos`).
pub fn read_repos(body: &str) -> Result<Vec<Repo>, Failed> {
    let listed: Vec<RepoBody> = shape(serde_json::from_str(body))?;
    Ok(listed.into_iter().map(repo_from).collect())
}

/// One repository (`GET /repos/{owner}/{name}`, or a created one).
pub fn read_repo(body: &str) -> Result<Repo, Failed> {
    shape(serde_json::from_str::<RepoBody>(body)).map(repo_from)
}

fn repo_from(body: RepoBody) -> Repo {
    Repo {
        owner: body.owner.login,
        name: body.name,
        default_branch: body.default_branch,
        private: body.private,
    }
}

/// The file paths of a tree answer: blobs only, directories dropped.
pub fn read_tree(body: &str) -> Result<Tree, Failed> {
    let parsed: TreeBody = shape(serde_json::from_str(body))?;
    let paths = parsed
        .tree
        .into_iter()
        .filter(|entry| entry.kind == "blob")
        .map(|entry| entry.path)
        .collect();
    Ok(Tree { paths, truncated: parsed.truncated })
}

/// A file's text from a contents answer: GitHub's base64, decoded. A file
/// too large for the contents API has no `content`, and reads as a shape
/// problem rather than an empty file.
pub fn read_file(body: &str) -> Result<String, Failed> {
    let parsed: FileBody = shape(serde_json::from_str(body))?;
    if parsed.encoding.as_deref().is_some_and(|encoding| encoding != "base64") {
        return Err(SHAPE);
    }
    let encoded = parsed.content.ok_or(SHAPE)?;
    // GitHub wraps its base64 at 60 columns; the decoder wants none of it.
    let compact: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD.decode(compact).map_err(|_| SHAPE)?;
    String::from_utf8(bytes).map_err(|_| SHAPE)
}

/// The Actions public key (`GET .../actions/secrets/public-key`).
pub fn read_actions_key(body: &str) -> Result<ActionsKey, Failed> {
    shape(serde_json::from_str::<KeyBody>(body))
        .map(|parsed| ActionsKey { key_id: parsed.key_id, key: parsed.key })
}

#[derive(Deserialize)]
struct ShaBody {
    sha: String,
}

#[derive(Deserialize)]
struct RefBody {
    object: ShaBody,
}

#[derive(Deserialize)]
struct PullBody {
    number: u64,
    html_url: String,
    head: PullHead,
}

#[derive(Deserialize)]
struct PullHead {
    sha: String,
}

/// A branch's head commit (`GET .../git/ref/heads/...`).
pub fn read_ref_sha(body: &str) -> Result<String, Failed> {
    shape(serde_json::from_str::<RefBody>(body)).map(|parsed| parsed.object.sha)
}

/// A file's blob sha (`GET .../contents/...`): what an overwrite must name.
pub fn read_blob_sha(body: &str) -> Result<String, Failed> {
    shape(serde_json::from_str::<ShaBody>(body)).map(|parsed| parsed.sha)
}

/// One pull request (`POST .../pulls`).
pub fn read_pull(body: &str) -> Result<Pull, Failed> {
    shape(serde_json::from_str::<PullBody>(body)).map(|parsed| Pull {
        number: parsed.number,
        url: parsed.html_url,
        head_sha: parsed.head.sha,
    })
}

/// The first pull request of a listing, if any.
pub fn read_first_pull(body: &str) -> Result<Option<Pull>, Failed> {
    let listed: Vec<PullBody> = shape(serde_json::from_str(body))?;
    Ok(listed.into_iter().next().map(|parsed| Pull {
        number: parsed.number,
        url: parsed.html_url,
        head_sha: parsed.head.sha,
    }))
}

// ---------------------------------------------------------------------------
// Pure: sealing a value for GitHub's Actions secrets.
// ---------------------------------------------------------------------------

/// Seals `value` for a repository's Actions secrets: libsodium's sealed box
/// (`crypto_box`'s `seal`) under the repository's public key, base64 — the
/// `encrypted_value` GitHub's `PUT` expects. Each call draws a fresh
/// ephemeral key, so the same value seals differently every time.
pub fn seal_secret(public_key: &str, value: &str) -> Result<String, Failed> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(public_key).map_err(|_| SHAPE)?;
    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| SHAPE)?;
    let recipient = crypto_box::PublicKey::from(key);
    let sealed =
        recipient.seal(&mut crypto_box::aead::OsRng, value.as_bytes()).map_err(|_| STORE)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(sealed))
}

// ---------------------------------------------------------------------------
// The GitHub client: one token, worker `Fetch`.
// ---------------------------------------------------------------------------

/// A GitHub client over one token. The token lives in memory only.
pub struct Client {
    token: String,
}

impl Client {
    /// A client that speaks as `token`.
    #[must_use]
    pub fn new(token: String) -> Self {
        Self { token }
    }

    /// The signed-in account's login (`GET /user`): the check that a token
    /// works at all.
    pub async fn whoami(&self) -> Result<String, Failed> {
        let (status, body) = self.get(&user_url()).await?;
        ok(status, "the account")?;
        read_login(&body)
    }

    /// Every repository the token can see.
    pub async fn list_repos(&self) -> Result<Vec<Repo>, Failed> {
        let (status, body) = self.get(&repos_url()).await?;
        ok(status, "the repository list")?;
        read_repos(&body)
    }

    /// One repository, or `None` when GitHub says it is not there (or the
    /// token cannot see it).
    pub async fn repo(&self, owner: &str, name: &str) -> Result<Option<Repo>, Failed> {
        let (status, body) = self.get(&repo_url(owner, name)).await?;
        if status == 404 {
            return Ok(None);
        }
        ok(status, "the repository")?;
        read_repo(&body).map(Some)
    }

    /// The file paths of `branch`, in one recursive listing.
    pub async fn tree(&self, owner: &str, name: &str, branch: &str) -> Result<Tree, Failed> {
        let (status, body) = self.get(&tree_url(owner, name, branch)).await?;
        ok(status, "the file list")?;
        read_tree(&body)
    }

    /// One file's text on the default branch, or `None` when it is not there.
    pub async fn file(
        &self,
        owner: &str,
        name: &str,
        file: &str,
    ) -> Result<Option<String>, Failed> {
        let (status, body) = self.get(&contents_url(owner, name, file)).await?;
        if status == 404 {
            return Ok(None);
        }
        ok(status, "the file")?;
        read_file(&body).map(Some)
    }

    /// Creates a private repository with an initial commit (`auto_init`) so
    /// it has a default branch. An organisation's repository is created under
    /// the organisation, the token's own under its account.
    pub async fn create_repo(&self, owner: &str, name: &str) -> Result<Repo, Failed> {
        let login = self.whoami().await?;
        let payload = serde_json::json!({ "name": name, "private": true, "auto_init": true });
        let (status, body) = self
            .send(Method::Post, &create_repo_url(owner, &login), Some(payload.to_string()))
            .await?;
        if status == 422 {
            return Err(REPO_REFUSED);
        }
        if !(200..300).contains(&status) {
            tracing::warn!(status, "console: github refused to create a repository");
            return Err(REPO_REFUSED);
        }
        read_repo(&body)
    }

    /// Stores one Actions secret on a repository: the repository's public
    /// key, the value sealed under it, then the `PUT`.
    pub async fn set_actions_secret(
        &self,
        owner: &str,
        name: &str,
        secret: &str,
        value: &str,
    ) -> Result<(), Failed> {
        let (status, body) = self.get(&actions_key_url(owner, name)).await?;
        ok(status, "the secrets key")?;
        let key = read_actions_key(&body)?;
        let encrypted = seal_secret(&key.key, value)?;
        let payload = serde_json::json!({ "encrypted_value": encrypted, "key_id": key.key_id });
        let (status, _) = self
            .send(Method::Put, &actions_secret_url(owner, name, secret), Some(payload.to_string()))
            .await?;
        // 201 creates it, 204 updates it.
        if status == 201 || status == 204 {
            Ok(())
        } else {
            tracing::warn!(status, "console: github refused to store an actions secret");
            Err(REFUSED)
        }
    }

    /// A branch's head commit.
    pub async fn branch_head(
        &self,
        owner: &str,
        name: &str,
        branch: &str,
    ) -> Result<String, Failed> {
        let (status, body) = self.get(&branch_ref_url(owner, name, branch)).await?;
        ok(status, "the branch")?;
        read_ref_sha(&body)
    }

    /// Creates `branch` at `sha`. A branch that already exists (`422`) counts
    /// as made: a setup that is run again replays this step.
    pub async fn create_branch(
        &self,
        owner: &str,
        name: &str,
        branch: &str,
        sha: &str,
    ) -> Result<(), Failed> {
        let payload = serde_json::json!({ "ref": format!("refs/heads/{branch}"), "sha": sha });
        let (status, _) =
            self.send(Method::Post, &refs_url(owner, name), Some(payload.to_string())).await?;
        if status == 201 || status == 422 {
            return Ok(());
        }
        tracing::warn!(status, "console: github refused to create a branch");
        Err(REFUSED)
    }

    /// The blob sha of a file on `branch`, or `None` when the file is not
    /// there. An overwrite must name it.
    pub async fn file_sha(
        &self,
        owner: &str,
        name: &str,
        file: &str,
        branch: &str,
    ) -> Result<Option<String>, Failed> {
        let (status, body) = self.get(&contents_on_url(owner, name, file, branch)).await?;
        if status == 404 {
            return Ok(None);
        }
        ok(status, "the file")?;
        read_blob_sha(&body).map(Some)
    }

    /// Commits one file on `branch`, creating or overwriting it. `sha` is the
    /// file's current blob sha, when it exists.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_file(
        &self,
        owner: &str,
        name: &str,
        file: &str,
        branch: &str,
        content: &str,
        sha: Option<&str>,
        message: &str,
    ) -> Result<(), Failed> {
        let mut payload = serde_json::json!({
            "message": message,
            "content": base64::engine::general_purpose::STANDARD.encode(content.as_bytes()),
            "branch": branch,
        });
        if let Some(sha) = sha {
            payload["sha"] = serde_json::Value::from(sha);
        }
        let (status, _) = self
            .send(Method::Put, &contents_url(owner, name, file), Some(payload.to_string()))
            .await?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        tracing::warn!(status, "console: github refused to commit a file");
        Err(REFUSED)
    }

    /// Opens a pull request from `head` into `base`. A pull request the head
    /// already has (`422`) is adopted, so a repeated setup finds it.
    pub async fn open_pull(
        &self,
        owner: &str,
        name: &str,
        head: &str,
        base: &str,
        title: &str,
        body_text: &str,
    ) -> Result<Pull, Failed> {
        let payload =
            serde_json::json!({ "title": title, "body": body_text, "head": head, "base": base });
        let (status, body) =
            self.send(Method::Post, &pulls_url(owner, name), Some(payload.to_string())).await?;
        if status == 201 || status == 200 {
            return read_pull(&body);
        }
        if status == 422 {
            let (listed_status, listed) = self.get(&open_pulls_url(owner, name, head)).await?;
            ok(listed_status, "the pull request")?;
            if let Some(pull) = read_first_pull(&listed)? {
                return Ok(pull);
            }
        }
        tracing::warn!(status, "console: github refused to open a pull request");
        Err(REFUSED)
    }

    /// A file on `branch` with its blob sha and text, or `None` when the file
    /// is not there.
    pub async fn file_at(
        &self,
        owner: &str,
        name: &str,
        file: &str,
        branch: &str,
    ) -> Result<Option<(String, String)>, Failed> {
        let (status, body) = self.get(&contents_on_url(owner, name, file, branch)).await?;
        if status == 404 {
            return Ok(None);
        }
        ok(status, "the file")?;
        Ok(Some((read_blob_sha(&body)?, read_file(&body)?)))
    }

    /// Makes `file` on `branch` read `content`, committing only when it does
    /// not already. Returns whether a commit was made.
    pub async fn put_if_changed(
        &self,
        owner: &str,
        name: &str,
        file: &str,
        branch: &str,
        content: &str,
        message: &str,
    ) -> Result<bool, Failed> {
        let current = self.file_at(owner, name, file, branch).await?;
        let sha = match &current {
            Some((_, text)) if text == content => return Ok(false),
            Some((sha, _)) => Some(sha.as_str()),
            None => None,
        };
        self.put_file(owner, name, file, branch, content, sha, message).await?;
        Ok(true)
    }

    /// Whether a repository Actions secret exists. Values are write-only, so
    /// this is how a setup learns that a secret was stored by an earlier run.
    pub async fn actions_secret_exists(
        &self,
        owner: &str,
        name: &str,
        secret: &str,
    ) -> Result<bool, Failed> {
        let (status, _) = self.get(&actions_secret_url(owner, name, secret)).await?;
        if status == 404 {
            return Ok(false);
        }
        ok(status, "the secrets")?;
        Ok(true)
    }

    /// Creates a repository variable, or updates it when it exists.
    pub async fn put_variable(
        &self,
        owner: &str,
        name: &str,
        variable: &str,
        value: &str,
    ) -> Result<(), Failed> {
        let payload = serde_json::json!({ "name": variable, "value": value }).to_string();
        let (status, _) =
            self.send(Method::Post, &variables_url(owner, name), Some(payload.clone())).await?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        if status == 409 {
            let (status, _) = self
                .send(Method::Patch, &variable_url(owner, name, variable), Some(payload))
                .await?;
            if (200..300).contains(&status) {
                return Ok(());
            }
        }
        tracing::warn!(status, "console: github refused to store a variable");
        Err(REFUSED)
    }

    /// Puts `pr.files` on a new branch off `pr.base`, one commit per file, and
    /// opens the pull request. Every step tolerates a repeat, so a setup that
    /// failed half-way can be run again.
    pub async fn commit_pull_request(
        &self,
        owner: &str,
        name: &str,
        pr: &NewPull<'_>,
    ) -> Result<Pull, Failed> {
        let head = self.branch_head(owner, name, pr.base).await?;
        self.create_branch(owner, name, pr.branch, &head).await?;
        let message = format!("{}\n\nAdded by Keep Shipping; see the pull request.", pr.title);
        for (file, content) in pr.files {
            let sha = self.file_sha(owner, name, file, pr.branch).await?;
            self.put_file(owner, name, file, pr.branch, content, sha.as_deref(), &message).await?;
        }
        self.open_pull(owner, name, pr.branch, pr.base, pr.title, pr.body).await
    }

    async fn get(&self, url: &str) -> Result<(u16, String), Failed> {
        self.send(Method::Get, url, None).await
    }

    /// One call: the status and body, with the token only in the header.
    async fn send(
        &self,
        method: Method,
        url: &str,
        body: Option<String>,
    ) -> Result<(u16, String), Failed> {
        let headers = Headers::new();
        headers.set("authorization", &format!("Bearer {}", self.token)).map_err(|_| NETWORK)?;
        headers.set("accept", "application/vnd.github+json").map_err(|_| NETWORK)?;
        headers.set("x-github-api-version", API_VERSION).map_err(|_| NETWORK)?;
        headers.set("user-agent", USER_AGENT).map_err(|_| NETWORK)?;
        if body.is_some() {
            headers.set("content-type", "application/json").map_err(|_| NETWORK)?;
        }
        let mut init = RequestInit::new();
        init.with_method(method).with_headers(headers);
        if let Some(body) = body {
            init.with_body(Some(JsValue::from_str(&body)));
        }
        let request = Request::new_with_init(url, &init).map_err(|_| NETWORK)?;
        let mut response = Fetch::Request(request).send().await.map_err(|error| {
            tracing::warn!(%error, "console: github request did not complete");
            NETWORK
        })?;
        let status = response.status_code();
        let text = response.text().await.map_err(|_| NETWORK)?;
        Ok((status, text))
    }
}

/// A read's status as a result: 2xx passes; a 5xx is GitHub's trouble, any
/// other refusal means the token cannot do this. The status is logged, never
/// the body or the token.
fn ok(status: u16, what: &str) -> Result<(), Failed> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    tracing::warn!(status, what, "console: github refused a read");
    Err(if status >= 500 { NETWORK } else { REFUSED })
}

// ---------------------------------------------------------------------------
// The stored token.
// ---------------------------------------------------------------------------

/// The GitHub token's name in the vault.
const NAME: &str = secrets::GITHUB;

fn legacy(secret: Option<&str>) -> Legacy<'_> {
    Legacy { table: LEGACY_TABLE, info: GITHUB_INFO, secret }
}

fn vault_failed(error: secrets::Error) -> Failed {
    match error {
        secrets::Error::NoMasterKey => NO_MASTER_KEY,
        secrets::Error::Storage => STORE,
    }
}

/// The stored token and its save time, opened; `None` when there is none or
/// it does not open.
async fn load(env: &Env, legacy_secret: Option<&str>) -> Result<Option<Stored>, Failed> {
    secrets::read(env, NAME, &legacy(legacy_secret)).await.map_err(vault_failed)
}

/// The stored token, read from inside the edits module. That module holds the
/// database port and the config but not the Worker `Env`, so it reads the
/// vault with the master key this isolate already loaded (see
/// `secrets::read_cached`). Without one, the legacy row is read in place,
/// read-only, so deliveries keep working until the key exists. `None` when
/// nothing is stored or it does not open.
pub async fn stored_token(db: Arc<dyn Database>, legacy_secret: Option<&str>) -> Option<String> {
    match secrets::read_cached(db, secrets::GITHUB, &legacy(legacy_secret)).await {
        Ok(stored) => stored.map(Stored::into_token),
        Err(error) => {
            tracing::warn!(?error, "console: the stored github token could not be read");
            None
        }
    }
}

/// When the GitHub token was saved, when one is stored and opens. A token
/// that no longer opens (a rotated master key) reads as not connected.
pub async fn connected_at(
    env: &Env,
    legacy_secret: Option<&str>,
) -> Result<Option<String>, Failed> {
    Ok(load(env, legacy_secret).await?.map(|stored| stored.saved_at().to_owned()))
}

/// A client for the stored token, when one is stored and opens.
pub async fn client(env: &Env, legacy_secret: Option<&str>) -> Result<Option<Client>, Failed> {
    Ok(load(env, legacy_secret).await?.map(|stored| Client::new(stored.into_token())))
}

/// The paste: the token is checked with GitHub (`GET /user`), stored in the
/// vault and the legacy row (if any) dropped. Returns the account it speaks
/// for, so the page can say who is connected. A network failure is said as
/// one; any other refusal of the token reads as "not accepted".
pub async fn connect(env: &Env, token: &str) -> Result<String, Failed> {
    let login = Client::new(token.to_owned())
        .whoami()
        .await
        .map_err(|failed| if failed == NETWORK { NETWORK } else { NOT_ACCEPTED })?;
    let vault = Vault::open(env).await.map_err(vault_failed)?;
    vault.write(NAME, token, &legacy(None)).await.map_err(vault_failed)?;
    Ok(login)
}

/// Forgets the GitHub token. Nothing else is touched.
pub async fn disconnect(env: &Env) -> Result<(), Failed> {
    secrets::forget(env, NAME, &legacy(None)).await.map_err(vault_failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::aead::OsRng;

    #[test]
    fn segments_encode_everything_but_unreserved_characters() {
        assert_eq!(segment("keep-shipping_app.v1~x"), "keep-shipping_app.v1~x");
        assert_eq!(segment("a b/c?d#e"), "a%20b%2Fc%3Fd%23e");
        assert_eq!(segment("ü"), "%C3%BC");
    }

    #[test]
    fn paths_keep_their_slashes_and_encode_each_part() {
        assert_eq!(path("feature/x y/z.tf"), "feature/x%20y/z.tf");
        assert_eq!(path("main"), "main");
    }

    #[test]
    fn the_rest_urls_are_built_from_encoded_parts() {
        assert_eq!(user_url(), "https://api.github.com/user");
        assert_eq!(repos_url(), "https://api.github.com/user/repos?sort=pushed&per_page=100");
        assert_eq!(
            repo_url("Keep-Shipping", "app repo"),
            "https://api.github.com/repos/Keep-Shipping/app%20repo"
        );
        assert_eq!(
            tree_url("o", "r", "release/1.0"),
            "https://api.github.com/repos/o/r/git/trees/release/1.0?recursive=1"
        );
        assert_eq!(
            contents_url("o", "r", "infra/main.tf"),
            "https://api.github.com/repos/o/r/contents/infra/main.tf"
        );
        assert_eq!(
            actions_key_url("o", "r"),
            "https://api.github.com/repos/o/r/actions/secrets/public-key"
        );
        assert_eq!(
            actions_secret_url("o", "r", "TF_VAR_DB"),
            "https://api.github.com/repos/o/r/actions/secrets/TF_VAR_DB"
        );
    }

    #[test]
    fn a_repo_is_created_under_the_account_or_the_organisation() {
        assert_eq!(create_repo_url("Nick", "nick"), "https://api.github.com/user/repos");
        assert_eq!(
            create_repo_url("keep-shipping", "nick"),
            "https://api.github.com/orgs/keep-shipping/repos"
        );
    }

    #[test]
    fn the_login_is_read_from_the_account_answer() {
        assert_eq!(read_login(r#"{"login":"nick","id":1}"#), Ok("nick".to_owned()));
        assert_eq!(read_login(r#"{"id":1}"#), Err(SHAPE));
        assert_eq!(read_login("not json"), Err(SHAPE));
    }

    #[test]
    fn the_repo_list_keeps_the_fields_the_wizard_needs() {
        let body = r#"[
            {"name":"app","default_branch":"main","private":true,
             "owner":{"login":"nick","id":1},"full_name":"nick/app"},
            {"name":"site","default_branch":"trunk","private":false,
             "owner":{"login":"keep-shipping"}}
        ]"#;
        let repos = read_repos(body).expect("a listing");
        assert_eq!(repos.len(), 2);
        assert_eq!(
            repos[0],
            Repo {
                owner: "nick".into(),
                name: "app".into(),
                default_branch: "main".into(),
                private: true,
            }
        );
        assert_eq!(repos[1].owner, "keep-shipping");
        assert!(!repos[1].private);
    }

    #[test]
    fn a_tree_keeps_blobs_and_reports_truncation() {
        let body = r#"{"truncated":true,"tree":[
            {"path":"src","type":"tree","sha":"a"},
            {"path":"src/main.rs","type":"blob","sha":"b"},
            {"path":"wrangler.toml","type":"blob","sha":"c"}
        ]}"#;
        let tree = read_tree(body).expect("a tree");
        assert_eq!(tree.paths, ["src/main.rs", "wrangler.toml"]);
        assert!(tree.truncated);
        let whole = read_tree(r#"{"tree":[]}"#).expect("a tree");
        assert!(whole.paths.is_empty());
        assert!(!whole.truncated);
    }

    #[test]
    fn a_file_is_decoded_from_githubs_wrapped_base64() {
        // "hello\nworld\n" with GitHub's line wrapping.
        let body = r#"{"type":"file","encoding":"base64","content":"aGVsbG8K\nd29ybGQK\n"}"#;
        assert_eq!(read_file(body), Ok("hello\nworld\n".to_owned()));
    }

    #[test]
    fn a_file_without_content_or_in_another_encoding_is_a_shape_problem() {
        assert_eq!(read_file(r#"{"type":"file","encoding":"none"}"#), Err(SHAPE));
        assert_eq!(read_file(r#"{"encoding":"utf-8","content":"x"}"#), Err(SHAPE));
        assert_eq!(read_file(r#"{"encoding":"base64","content":"%%%"}"#), Err(SHAPE));
    }

    #[test]
    fn the_actions_key_is_read() {
        let key =
            read_actions_key(r#"{"key_id":"568250167242549743","key":"abc="}"#).expect("a key");
        assert_eq!(key, ActionsKey { key_id: "568250167242549743".into(), key: "abc=".into() });
    }

    #[test]
    fn a_secret_seals_and_opens_only_with_the_repository_key() {
        let recipient = crypto_box::SecretKey::generate(&mut OsRng);
        let public =
            base64::engine::general_purpose::STANDARD.encode(recipient.public_key().as_bytes());
        let sealed = seal_secret(&public, "postgres://user:pw@host/db").expect("seals");
        let bytes = base64::engine::general_purpose::STANDARD.decode(&sealed).expect("base64");
        let opened = recipient.unseal(&bytes).expect("opens with the repository key");
        assert_eq!(opened, b"postgres://user:pw@host/db");

        let stranger = crypto_box::SecretKey::generate(&mut OsRng);
        assert!(stranger.unseal(&bytes).is_err(), "another key does not open it");
    }

    #[test]
    fn a_malformed_public_key_seals_nothing() {
        assert_eq!(seal_secret("not base64!", "x"), Err(SHAPE));
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        assert_eq!(seal_secret(&short, "x"), Err(SHAPE));
    }

    #[test]
    fn the_branch_pull_request_and_variable_urls_are_built_from_encoded_parts() {
        assert_eq!(
            branch_ref_url("o", "r", "main"),
            "https://api.github.com/repos/o/r/git/ref/heads/main"
        );
        assert_eq!(refs_url("o", "r"), "https://api.github.com/repos/o/r/git/refs");
        assert_eq!(
            contents_on_url("o", "r", "modules/test-env/main.tf", "ks-edit/ks1"),
            "https://api.github.com/repos/o/r/contents/modules/test-env/main.tf?ref=ks-edit%2Fks1"
        );
        assert_eq!(pulls_url("o", "r"), "https://api.github.com/repos/o/r/pulls");
        assert_eq!(
            open_pulls_url("nick", "infra", "ks-edit/ks1"),
            "https://api.github.com/repos/nick/infra/pulls?head=nick%3Aks-edit%2Fks1&state=open"
        );
        assert_eq!(variables_url("o", "r"), "https://api.github.com/repos/o/r/actions/variables");
        assert_eq!(
            variable_url("o", "r", "KEEPSHIPPING_CONSOLE_URL"),
            "https://api.github.com/repos/o/r/actions/variables/KEEPSHIPPING_CONSOLE_URL"
        );
    }

    #[test]
    fn a_pull_request_and_its_listing_are_read() {
        let body = r#"{"number":7,"html_url":"https://github.com/o/r/pull/7",
            "head":{"sha":"abc"},"state":"open"}"#;
        assert_eq!(
            read_pull(body),
            Ok(Pull {
                number: 7,
                url: "https://github.com/o/r/pull/7".into(),
                head_sha: "abc".into(),
            })
        );
        assert_eq!(read_first_pull("[]"), Ok(None));
        assert_eq!(
            read_first_pull(&format!("[{body}]")).map(|pull| pull.map(|p| p.number)),
            Ok(Some(7))
        );
        assert_eq!(read_ref_sha(r#"{"object":{"sha":"deadbeef"}}"#), Ok("deadbeef".into()));
        assert_eq!(read_blob_sha(r#"{"sha":"blob1","path":"x"}"#), Ok("blob1".into()));
        assert_eq!(read_ref_sha("{}"), Err(SHAPE));
    }
}
