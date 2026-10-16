//! The pure rules of the "manage as code" wizard: its four steps, how a
//! site's name becomes the test environment's and the state's names, which
//! repository a site most likely lives in, and the small derivations the
//! pull request and the repository secrets need (the R2 secret, the edit's
//! id and branch). Everything here is a function of its inputs; the Worker
//! wiring that calls it is in [`super::flow`].

use sha2::{Digest, Sha256};

use super::detect::{BindingKind, Need, Stack};
use super::generate::{DbKind, TestEnv};
use crate::github::Repo;

/// The R2 bucket the infrastructure state lives in, created with the infra
/// token on the first run.
pub const STATE_BUCKET: &str = "ks-tofu-state";
/// The console's public address. The generated workflow carries it, so the
/// plan callback can find the console.
pub const CONSOLE_URL: &str = "https://console.keepshipping.run";
/// The branch prefix an edit's pull request uses: `ks-edit/<id>`, the shape
/// the infra workflow and the edits module both read.
pub const BRANCH_PREFIX: &str = "ks-edit/";

/// One step of the wizard, in the order a person passes through them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Connect GitHub.
    GitHub,
    /// Choose the app repository and scan it.
    Repo,
    /// Read what was found and the plan, and enter the secrets.
    Review,
    /// Open the pull request; the status comes after.
    Open,
}

impl Step {
    /// The four steps, in order, for the progress header.
    pub const ALL: [Step; 4] = [Step::GitHub, Step::Repo, Step::Review, Step::Open];

    /// The step's number as the header shows it (1 to 4).
    #[must_use]
    pub const fn number(self) -> usize {
        match self {
            Self::GitHub => 1,
            Self::Repo => 2,
            Self::Review => 3,
            Self::Open => 4,
        }
    }

    /// The step's name in plain words.
    #[must_use]
    pub const fn words(self) -> &'static str {
        match self {
            Self::GitHub => "GitHub",
            Self::Repo => "App repo",
            Self::Review => "Review",
            Self::Open => "Open pull request",
        }
    }
}

/// The R2 S3 secret access key for a Cloudflare API token: lowercase hex of
/// the SHA-256 of the token's value, which is how R2 documents deriving the
/// S3 secret from a token. The access key id is the token's id.
#[must_use]
pub fn r2_secret_access_key(token_value: &str) -> String {
    let digest = Sha256::digest(token_value.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    hex
}

/// A site's name as a state and resource name: lowercase letters, digits and
/// single dashes; `site` when nothing usable is left.
#[must_use]
pub fn slug(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_end_matches('-');
    if trimmed.is_empty() { "site".to_owned() } else { trimmed.to_owned() }
}

/// The test environment a stack asks for. A D1 database when the app needs
/// SQLite or already binds one; KV, R2 when it needs them; Hyperdrive for
/// Postgres (or MySQL, when no Postgres is needed). The name is
/// `<slug>-test`, the hostname `test.<main domain>` and the Pages project,
/// when the site is one. Enabled by default; the caller decides.
#[must_use]
pub fn test_env_for(
    stack: &Stack,
    slug: &str,
    main_domain: Option<&str>,
    pages_project: Option<&str>,
) -> TestEnv {
    let has = |need: Need| stack.needs.contains(&need);
    let binds = |kind: BindingKind| stack.existing_bindings.iter().any(|b| b.kind == kind);
    let hyperdrive = if has(Need::Postgres) {
        Some(DbKind::Postgres)
    } else if has(Need::MySql) {
        Some(DbKind::MySql)
    } else {
        None
    };
    TestEnv {
        enabled: true,
        name: format!("{slug}-test"),
        hostname: main_domain.map(|domain| format!("test.{domain}")),
        d1: has(Need::Sqlite) || binds(BindingKind::D1),
        kv: has(Need::KeyValue),
        r2: has(Need::ObjectStorage),
        hyperdrive,
        pages_project: pages_project.map(str::to_owned),
    }
}

/// A repository name as `owner/name`, both parts GitHub-legal (letters,
/// digits, `-`, `_`, `.`), and nothing else. `None` otherwise.
#[must_use]
pub fn parse_repo(text: &str) -> Option<(&str, &str)> {
    let (owner, name) = text.trim().split_once('/')?;
    let ok = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    (ok(owner) && ok(name) && !name.contains('/')).then_some((owner, name))
}

/// The infrastructure repository a person is offered: `<app owner>/infra-<site
/// slug>`, one per site, since a repository holds one state per site.
#[must_use]
pub fn infra_repo_default(app_repo: &str, site_slug: &str) -> String {
    match parse_repo(app_repo) {
        Some((owner, _)) => format!("{owner}/infra-{site_slug}"),
        None => String::new(),
    }
}

/// The words a name is compared by: its lowercase alphanumeric runs.
fn words_of(name: &str) -> Vec<String> {
    name.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// How alike two names are: 100 for the same words in any spelling, 10 per
/// shared word, 5 more when one name contains the other. Zero when they share
/// nothing.
#[must_use]
pub fn name_score(site: &str, repo: &str) -> u32 {
    let (a, b) = (words_of(site), words_of(repo));
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    if a.concat() == b.concat() {
        return 100;
    }
    let shared = a.iter().filter(|word| b.contains(word)).count() as u32;
    let contained = a.concat().contains(&b.concat()) || b.concat().contains(&a.concat());
    shared * 10 + if contained { 5 } else { 0 }
}

/// Which repository to preselect: the Pages project's source when it is one
/// the token can see, else the repository whose name is most like the site's
/// (ties to the earlier, more recently pushed one). `None` when nothing is
/// alike at all.
#[must_use]
pub fn preselect(site_name: &str, source: Option<(&str, &str)>, repos: &[Repo]) -> Option<usize> {
    if let Some((owner, name)) = source
        && let Some(index) = repos.iter().position(|repo| {
            repo.owner.eq_ignore_ascii_case(owner) && repo.name.eq_ignore_ascii_case(name)
        })
    {
        return Some(index);
    }
    let mut best: Option<(u32, usize)> = None;
    for (index, repo) in repos.iter().enumerate() {
        let score = name_score(site_name, &repo.name);
        if score == 0 {
            continue;
        }
        if best.is_none_or(|(top, _)| score > top) {
            best = Some((score, index));
        }
    }
    best.map(|(_, index)| index)
}

/// A new edit id: `ks` and 32 lowercase hex digits from the given random
/// bytes. Lowercase because the branch name is the id, and the edits module
/// lower-cases the branch it reads back.
#[must_use]
pub fn new_edit_id(random: [u8; 16]) -> String {
    let mut id = String::from("ks");
    for byte in random {
        id.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        id.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    id
}

/// The branch an edit's pull request is opened from.
#[must_use]
pub fn edit_branch(edit_id: &str) -> String {
    format!("{BRANCH_PREFIX}{edit_id}")
}

/// The pull request's title for a site.
#[must_use]
pub fn pr_title(site_name: &str) -> String {
    format!("Manage {site_name} as code")
}

/// The pull request's body: what it does and what happens next, in words.
#[must_use]
pub fn pr_body(summary: &[String], console_edit_url: &str) -> String {
    let mut body = String::from("## What this brings under code\n\n");
    for line in summary {
        body.push_str("- ");
        body.push_str(line);
        body.push('\n');
    }
    body.push_str(&format!(
        "\nOpened from the Keep Shipping console: {console_edit_url}\n\n\
         Nothing changes until someone approves the plan on that page. The workflow plans \
         this change, posts the plan to the console, and applies it only after approval.\n"
    ));
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onboard::detect::{Binding, Stack};
    use std::collections::BTreeSet;

    fn repo(owner: &str, name: &str) -> Repo {
        Repo {
            owner: owner.into(),
            name: name.into(),
            default_branch: "main".into(),
            private: true,
        }
    }

    #[test]
    fn the_r2_secret_is_the_lowercase_hex_sha256_of_the_token() {
        // The standard SHA-256 test vector for "abc".
        assert_eq!(
            r2_secret_access_key("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(r2_secret_access_key("abc").len(), 64);
    }

    #[test]
    fn slugs_keep_letters_and_digits_and_single_dashes() {
        assert_eq!(slug("KAJE Guest_List!"), "kaje-guest-list");
        assert_eq!(slug("--a  b--"), "a-b");
        assert_eq!(slug("***"), "site");
    }

    #[test]
    fn a_stack_maps_to_the_test_resources_it_needs() {
        let mut needs = BTreeSet::new();
        needs.insert(Need::Postgres);
        needs.insert(Need::ObjectStorage);
        let stack = Stack {
            needs,
            existing_bindings: vec![Binding { kind: BindingKind::D1, name: "CACHE".into() }],
            ..Stack::default()
        };
        let env = test_env_for(&stack, "shop", Some("example.com"), Some("shop"));
        assert!(env.enabled);
        assert_eq!(env.name, "shop-test");
        assert_eq!(env.hostname.as_deref(), Some("test.example.com"));
        assert!(env.d1, "an existing D1 binding keeps a D1 test database");
        assert!(!env.kv);
        assert!(env.r2);
        assert_eq!(env.hyperdrive, Some(DbKind::Postgres));
        assert_eq!(env.pages_project.as_deref(), Some("shop"));
    }

    #[test]
    fn mysql_and_sqlite_map_to_their_resources_and_nothing_extra() {
        let mut needs = BTreeSet::new();
        needs.insert(Need::MySql);
        let stack = Stack { needs, ..Stack::default() };
        let env = test_env_for(&stack, "a", None, None);
        assert_eq!(env.hyperdrive, Some(DbKind::MySql));
        assert!(env.hostname.is_none());
        let mut lite = BTreeSet::new();
        lite.insert(Need::Sqlite);
        let env = test_env_for(&Stack { needs: lite, ..Stack::default() }, "a", None, None);
        assert!(env.d1);
        assert_eq!(env.hyperdrive, None);
    }

    #[test]
    fn repository_names_are_checked_before_use() {
        assert_eq!(parse_repo("keep-shipping/app.v1"), Some(("keep-shipping", "app.v1")));
        assert_eq!(parse_repo("owner"), None);
        assert_eq!(parse_repo("a/b/c"), None);
        assert_eq!(parse_repo("a/../b"), None);
        assert_eq!(parse_repo("a/b c"), None);
        assert_eq!(parse_repo("/b"), None);
        assert_eq!(infra_repo_default("nick/shop", "shop"), "nick/infra-shop");
        assert_eq!(infra_repo_default("", "shop"), "");
    }

    #[test]
    fn the_pages_source_wins_when_the_token_can_see_it() {
        let repos = [repo("nick", "shop-web"), repo("nick", "shop")];
        assert_eq!(preselect("shop", Some(("nick", "shop-web")), &repos), Some(0));
        // Case does not matter for a GitHub owner or name.
        assert_eq!(preselect("shop", Some(("NICK", "SHOP")), &repos), Some(1));
    }

    #[test]
    fn without_a_source_the_most_alike_name_is_preselected() {
        let repos = [repo("nick", "blog"), repo("nick", "kaje-guest-list"), repo("nick", "kaje")];
        assert_eq!(preselect("kaje_guest_list", None, &repos), Some(1));
        assert_eq!(preselect("kaje", None, &repos), Some(2));
        // A source the token cannot see falls back to the name.
        assert_eq!(preselect("blog", Some(("other", "gone")), &repos), Some(0));
        assert_eq!(preselect("zzz", None, &repos), None);
        assert_eq!(preselect("anything", None, &[]), None);
    }

    #[test]
    fn an_edit_id_is_lowercase_and_names_its_branch() {
        let id = new_edit_id([0xab; 16]);
        assert_eq!(id, format!("ks{}", "ab".repeat(16)));
        assert_eq!(edit_branch(&id), format!("ks-edit/{id}"));
        assert_eq!(id, id.to_ascii_lowercase());
    }

    #[test]
    fn the_pull_request_body_lists_the_summary() {
        let body = pr_body(&["Imports 2 DNS records in a.com".to_owned()], "https://x/v1/edits/1");
        assert!(body.contains("- Imports 2 DNS records in a.com"));
        assert!(body.contains("https://x/v1/edits/1"));
        assert_eq!(pr_title("shop"), "Manage shop as code");
    }

    #[test]
    fn the_steps_number_one_to_four() {
        let numbers: Vec<usize> = Step::ALL.iter().map(|step| step.number()).collect();
        assert_eq!(numbers, [1, 2, 3, 4]);
        assert_eq!(Step::Open.words(), "Open pull request");
    }
}
