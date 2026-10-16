//! The console's GitHub connection: a fine-grained token the console seals
//! in D1 (the same scheme as the Cloudflare read token, under its own key),
//! and the GitHub REST calls the setup wizard makes with it.
//!
//! The pure parts — URL building, reading GitHub's JSON, sealing a secret
//! for GitHub's Actions endpoint — are plain functions, tested natively
//! below. What is left is the Workers wiring: `worker::Fetch` for the calls
//! and the D1 row for the token. The token is only ever in memory, in a
//! request header, or in the sealed row. It is never logged, never put in a
//! URL and never returned.

pub mod page;

use base64::Engine as _;
use cratefield_core::Clock;
use cratefield_runtime_cloudflare::WorkersClock;
use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use worker::wasm_bindgen::JsValue;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit};

use crate::cloudflare::seal::{self, GITHUB_INFO, Sealed};

/// The public REST root.
pub const API: &str = "https://api.github.com";
/// The REST API version every call pins, so a GitHub-side default change
/// cannot change what the console reads.
const API_VERSION: &str = "2022-11-28";
const USER_AGENT: &str = "keepshipping-console";
/// The D1 table holding the sealed token: one row, `id = 1`.
const TABLE: &str = "console_github_token";

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

#[derive(Deserialize)]
struct StoredRow {
    nonce: String,
    ciphertext: String,
    updated_at: String,
}

async fn stored(env: &Env) -> Result<Option<StoredRow>, Failed> {
    let db = env.d1("DB").map_err(|_| STORE)?;
    db.prepare(format!("SELECT nonce, ciphertext, updated_at FROM {TABLE} WHERE id = 1"))
        .first::<StoredRow>(None)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "console: reading the stored github token failed");
            STORE
        })
}

/// When the GitHub token was saved, when one is stored and opens. A token
/// that no longer opens (a rotated `HARNESS_SECRET`) reads as not connected.
pub async fn connected_at(env: &Env, secret: &str) -> Result<Option<String>, Failed> {
    Ok(load(env, secret).await?.map(|(_, updated_at)| updated_at))
}

/// A client for the stored token, when one is stored and opens.
pub async fn client(env: &Env, secret: &str) -> Result<Option<Client>, Failed> {
    Ok(load(env, secret).await?.map(|(token, _)| Client::new(token)))
}

/// The stored token and its save time, opened; `None` when there is none or
/// it does not open.
async fn load(env: &Env, secret: &str) -> Result<Option<(String, String)>, Failed> {
    let Some(row) = stored(env).await? else {
        return Ok(None);
    };
    let sealed = Sealed { nonce: row.nonce, ciphertext: row.ciphertext };
    match seal::open_for(GITHUB_INFO, secret, &sealed) {
        Ok(token) => Ok(Some((token, row.updated_at))),
        Err(error) => {
            tracing::warn!(?error, "console: stored github token does not open");
            Ok(None)
        }
    }
}

/// The paste: the token is checked with GitHub (`GET /user`), sealed under
/// its own key and stored. Returns the account it speaks for, so the page
/// can say who is connected. A network failure is said as one; any other
/// refusal of the token reads as "not accepted".
pub async fn connect(env: &Env, secret: &str, token: &str) -> Result<String, Failed> {
    let login = Client::new(token.to_owned())
        .whoami()
        .await
        .map_err(|failed| if failed == NETWORK { NETWORK } else { NOT_ACCEPTED })?;
    let sealed = seal::seal_for(GITHUB_INFO, secret, token).map_err(|_| STORE)?;
    let now = WorkersClock.now().format(&Rfc3339).map_err(|_| STORE)?;
    let db = env.d1("DB").map_err(|_| STORE)?;
    let values = [
        JsValue::from_str(&sealed.nonce),
        JsValue::from_str(&sealed.ciphertext),
        JsValue::from_str(&now),
    ];
    db.prepare(format!(
        "INSERT INTO {TABLE} (id, nonce, ciphertext, updated_at) \
         VALUES (1, ?, ?, ?) \
         ON CONFLICT(id) DO UPDATE SET nonce = excluded.nonce, \
         ciphertext = excluded.ciphertext, updated_at = excluded.updated_at"
    ))
    .bind(&values)
    .map_err(|_| STORE)?
    .run()
    .await
    .map_err(|error| {
        tracing::warn!(%error, "console: writing the stored github token failed");
        STORE
    })?;
    Ok(login)
}

/// Forgets the GitHub token. Nothing else is touched.
pub async fn disconnect(env: &Env) -> Result<(), Failed> {
    let db = env.d1("DB").map_err(|_| STORE)?;
    db.prepare(format!("DELETE FROM {TABLE} WHERE id = 1")).run().await.map_err(|_| STORE)?;
    Ok(())
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
}
