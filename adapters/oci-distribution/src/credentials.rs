//! Registry credentials: a username and password, and the docker
//! `config.json` they are usually written down in.
//!
//! Only the static forms are handled — an `auth` string, or an explicit
//! `username`/`password` pair. Credential *helpers* (`credHelpers`,
//! `credsStore`) shell out to another program; this adapter says so plainly
//! rather than silently trying to push without credentials.
//!
//! Base64 is implemented here rather than pulled in: the standard alphabet is
//! twenty lines, and the workspace's dependency budget is part of its design
//! ([ADR 0002](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0002-ports-and-adapters.md)).

use std::collections::BTreeMap;
use std::path::PathBuf;

use ks_core::ports::supply_chain::RegistryError;

/// One registry's credentials.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    /// Credentials for `username`, whatever the password is.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Credentials {
        Credentials { username: username.into(), password: password.into() }
    }

    /// The user name.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The password or token, never printed.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// The `Authorization` value for an HTTP Basic challenge.
    pub fn basic(&self) -> String {
        let raw = format!("{}:{}", self.username, self.password);
        format!("Basic {}", base64_encode(raw.as_bytes()))
    }
}

/// Credentials for several registries, keyed by host.
#[derive(Clone, Debug, Default)]
pub struct CredentialStore {
    entries: BTreeMap<String, Credentials>,
    /// Hosts a helper stands in for, and the helper's name.
    helper_hosts: BTreeMap<String, String>,
    /// The global `credsStore`, if the config names one: it covers every host
    /// it has nothing explicit for.
    creds_store: Option<String>,
}

impl CredentialStore {
    /// An empty store: every registry is anonymous.
    pub fn new() -> CredentialStore {
        CredentialStore::default()
    }

    /// Adds credentials for `host` (as it appears in a repository string,
    /// port included). Later entries win.
    pub fn with(mut self, host: impl Into<String>, credentials: Credentials) -> CredentialStore {
        self.entries.insert(normalize_host(&host.into()), credentials);
        self
    }

    /// Parses a docker `config.json` — the `auths` entries are read, and so is
    /// the fact that a host is served by a credential helper.
    ///
    /// Unparseable JSON is not fatal: a config file we cannot read is the same
    /// as one with nothing for this host in it, and the push fails later with a
    /// message about authorization rather than a parse error.
    pub fn from_config_json(contents: &str) -> CredentialStore {
        let mut store = CredentialStore::new();
        let Ok(config) = serde_json::from_str::<serde_json::Value>(contents) else {
            return store;
        };
        if let Some(helpers) = config.get("credHelpers").and_then(serde_json::Value::as_object) {
            store.helper_hosts.extend(helpers.iter().filter_map(|(host, helper)| {
                Some((normalize_host(host), helper.as_str()?.to_string()))
            }));
        }
        if let Some(global) = config.get("credsStore").and_then(serde_json::Value::as_str) {
            store.creds_store = Some(global.to_string());
        }
        let Some(auths) = config.get("auths").and_then(serde_json::Value::as_object) else {
            return store;
        };
        for (host, entry) in auths {
            let key = normalize_host(host);
            if let Some(credentials) = entry_credentials(entry) {
                store.entries.insert(key, credentials);
                continue;
            }
            // An empty `auths` entry is how Docker Desktop records a host it
            // is logged in to: the credentials are in the helper, not in this
            // file. An entry with an `auth` in it we cannot decode is simply
            // nothing we can read.
            if entry.as_object().is_none_or(serde_json::Map::is_empty) {
                let helper = store.creds_store.clone().unwrap_or_else(|| key.clone());
                store.helper_hosts.entry(key).or_insert(helper);
            }
        }
        store
    }

    /// Reads the docker config the environment points at: `$DOCKER_CONFIG/config.json`,
    /// else `~/.docker/config.json`. A missing file is an empty store.
    pub fn load() -> CredentialStore {
        let Some(path) = config_path() else {
            return CredentialStore::new();
        };
        let Ok(contents) = std::fs::read_to_string(path) else {
            return CredentialStore::new();
        };
        CredentialStore::from_config_json(&contents)
    }

    /// The hosts this store holds credentials for — for `Debug` and for
    /// telling a user which hosts are already covered. Never the credentials.
    pub fn hosts(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// The credentials for `host`, or [`None`] when there are none.
    ///
    /// [`RegistryError::Backend`] when the host is served by a credential
    /// helper: this adapter does not run other programs, and guessing would
    /// mean pushing anonymously into a registry that expects a login. A
    /// global `credsStore` covers every host it has no explicit entry for, so
    /// a config with one has no anonymously-pushable host at all.
    pub fn for_host(&self, host: &str) -> Result<Option<&Credentials>, RegistryError> {
        let key = normalize_host(host);
        if let Some(credentials) = self.entries.get(&key) {
            return Ok(Some(credentials));
        }
        let helper = self.helper_hosts.get(&key).cloned().or_else(|| self.creds_store.clone());
        if let Some(helper) = helper {
            return Err(RegistryError::Backend {
                message: format!(
                    "{key} is served by credential helper {helper:?}, which this \
                                  adapter does not run; log in with `docker login` or pass \
                                  credentials explicitly"
                ),
            });
        }
        Ok(None)
    }
}

/// The `config.json` path the environment selects, if any.
fn config_path() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("DOCKER_CONFIG")
        && !dir.is_empty()
    {
        return Some(PathBuf::from(dir).join("config.json"));
    }
    let home = std::env::var_os("HOME")?;
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home).join(".docker").join("config.json"))
}

/// The credentials in one `auths` entry: `auth` (base64 `user:password`) or an
/// explicit `username`/`password` pair.
fn entry_credentials(entry: &serde_json::Value) -> Option<Credentials> {
    if let (Some(username), Some(password)) = (
        entry.get("username").and_then(serde_json::Value::as_str),
        entry.get("password").and_then(serde_json::Value::as_str),
    ) {
        return Some(Credentials::new(username, password));
    }
    let encoded = entry.get("auth").and_then(serde_json::Value::as_str)?;
    let decoded = base64_decode(encoded)?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some(Credentials::new(username, password))
}

/// `https://Index.Docker.io/v1/` and `index.docker.io:443` both name one
/// registry: the scheme, any path, and the case are not part of the key.
fn normalize_host(host: &str) -> String {
    let host = host
        .trim()
        .strip_prefix("https://")
        .or_else(|| host.trim().strip_prefix("http://"))
        .unwrap_or(host.trim())
        .trim_end_matches('/');
    let host = host.strip_suffix("/v1").unwrap_or(host);
    host.to_ascii_lowercase()
}

/// The standard base64 alphabet, with padding.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes bytes as standard base64.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(B64[(n >> 18 & 0x3f) as usize] as char);
        out.push(B64[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6 & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 0x3f) as usize] as char } else { '=' });
    }
    out
}

/// Decodes standard base64, or [`None`] for anything malformed — a config file
/// with a broken `auth` entry is a host we have no credentials for, not a
/// reason to stop reading the rest of the file.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut bits = 0u32;
    let mut held = 0u32;
    for character in text.trim().chars() {
        if character == '=' {
            break;
        }
        let value = B64.iter().position(|c| *c as char == character)? as u32;
        held = held << 6 | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((held >> bits & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"{
      "auths": {
        "registry.example:5000": {"auth": "YWxpY2U6czNjcjN0"},
        "https://index.docker.io/v1/": {"username": "hub", "password": "token"},
        "broken.example": {"auth": "not base64!"}
      },
      "credHelpers": {"helper.example": "pass"}
    }"#;

    #[test]
    fn base64_round_trips_at_every_padding_length() {
        for text in ["", "a", "ab", "abc", "abcd", "alice:s3cr3t"] {
            let encoded = base64_encode(text.as_bytes());
            assert_eq!(base64_decode(&encoded).as_deref(), Some(text.as_bytes()), "{text:?}");
        }
        assert_eq!(base64_encode(b"alice:s3cr3t"), "YWxpY2U6czNjcjN0");
        assert_eq!(base64_decode("!!!"), None);
    }

    #[test]
    fn parses_docker_config_auths_by_host_with_port_and_scheme() {
        let store = CredentialStore::from_config_json(CONFIG);
        let credentials = store.for_host("registry.example:5000").expect("no helper").unwrap();
        assert_eq!((credentials.username(), credentials.password()), ("alice", "s3cr3t"));
        // Docker Hub is written with a scheme and a `/v1` path in the file.
        let hub = store.for_host("index.docker.io").expect("no helper").unwrap();
        assert_eq!((hub.username(), hub.password()), ("hub", "token"));
        // Broken entries are hosts we simply have nothing for.
        assert_eq!(store.for_host("broken.example").expect("no helper"), None);
        assert_eq!(store.for_host("unknown.example").expect("no helper"), None);
    }

    #[test]
    fn basic_headers_are_the_standard_encoding() {
        let credentials = Credentials::new("alice", "s3cr3t");
        assert_eq!(credentials.basic(), "Basic YWxpY2U6czNjcjN0");
    }

    #[test]
    fn credential_helpers_are_an_explicit_error_not_an_anonymous_push() {
        let store = CredentialStore::from_config_json(CONFIG);
        let error = store.for_host("helper.example").expect_err("helpers are not run");
        assert!(error.to_string().contains("credential helper"), "{error}");
    }

    #[test]
    fn a_config_that_is_not_json_yields_no_credentials() {
        let store = CredentialStore::from_config_json("{ not json");
        assert_eq!(store.for_host("registry.example:5000").expect("no helper"), None);
    }

    #[test]
    fn explicit_entries_win_and_need_no_file() {
        let store = CredentialStore::new()
            .with("registry.example:5000", Credentials::new("alice", "s3cr3t"));
        assert!(store.for_host("registry.example:5000").expect("no helper").is_some());
    }

    const DESKTOP: &str = r#"{
      "credsStore": "desktop",
      "auths": {"registry.example:5000": {}}
    }"#;

    #[test]
    fn a_global_creds_store_is_an_error_for_every_host_it_covers() {
        let store = CredentialStore::from_config_json(DESKTOP);
        // Docker Desktop logs a host in by writing an empty `auths` entry and
        // keeping the credentials in the helper.
        let empty = store.for_host("registry.example:5000").expect_err("the helper stands in");
        assert!(empty.to_string().contains("credential helper \"desktop\""), "{empty}");
        // ...and a host it has never heard of is not an anonymous push either.
        let unknown = store.for_host("unknown.example").expect_err("the store covers it");
        assert!(unknown.to_string().contains("credential helper"), "{unknown}");
    }

    #[test]
    fn an_explicit_auth_wins_over_a_global_creds_store() {
        let config = r#"{"credsStore": "desktop", "auths": {"registry.example:5000": {"auth": "YWxpY2U6czNjcjN0"}}}"#;
        let store = CredentialStore::from_config_json(config);
        let credentials = store.for_host("registry.example:5000").expect("no helper").unwrap();
        assert_eq!((credentials.username(), credentials.password()), ("alice", "s3cr3t"));
    }

    #[test]
    fn a_config_with_no_helpers_leaves_unknown_hosts_anonymous() {
        let store = CredentialStore::from_config_json(CONFIG);
        assert_eq!(store.for_host("unknown.example").expect("no helper"), None);
    }
}
