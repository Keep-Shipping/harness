//! The default branch's own `policy:` block, read out of git, so a branch's
//! copy is a proposal rather than an authority
//! ([#118](https://github.com/Keep-Shipping/harness/issues/118), [ADR
//! 0012](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0012-policy-authority.md)).
//!
//! One read, at the start of a run and of an `explain`: the file as the
//! default branch has it. Every decision then folds the working file's policy
//! against it, and a branch can only narrow — a widening in the branch takes
//! effect when it merges, which is the one moment a human reviewed it.
//!
//! Fails closed throughout. A ref that does not resolve, a file that is not on
//! it, a file that does not parse: each is an *empty* base, which says nothing
//! may be widened. The one error is a ref the caller named and git cannot
//! find, because that is a question about the command line rather than about
//! the repository.

use std::path::Path;
use std::process::Command;

use ks_core::Policy;

/// The environment variable naming the base ref when `--base` is absent.
pub const BASE_ENV: &str = "KEEPSHIPPING_BASE";

/// The environment variable a pull-request build sets to the branch the change
/// is proposed against. It is a branch *name*, so the remote's copy is tried
/// first.
pub const BASE_REF_ENV: &str = "GITHUB_BASE_REF";

/// The default-branch policy, and the ref it was read at.
pub struct Base {
    /// The ref as resolved, exactly as git names it — what `explain` prints
    /// and what `--base` would take next time.
    pub git_ref: String,
    /// The default branch's `policy:` block. Empty when the ref carries no
    /// such file, or one that does not parse: a branch whose policy nobody
    /// reviewed narrows nothing.
    pub policy: Policy,
    /// Whether the ref carries a copy of this file at all. An empty `policy`
    /// is not the same answer as "the default branch has nothing to say about
    /// this": one is a file whose rules were read, the other is a file that
    /// was never there, and `explain` says which rather than letting a missing
    /// copy read like a permissive one.
    pub has_file: bool,
}

/// The refs auto-detection tries, in order, before giving up: the remote's own
/// idea of its default branch, then the two names it has under every host.
const AUTO_REFS: &[&str] = &["origin/HEAD", "origin/main", "main", "master"];

/// Reads the default branch's policy for the site file at `path`.
///
/// `asked` is `--base`: a ref the caller named. It must resolve, or the caller
/// gets [`Err`] and decides what to do about it — a base that was asked for
/// and is not there is a question about the command line, not a repository to
/// guess at. With no `--base` the ref is detected, and detection failing is a
/// [`None`]: no git, no repository, no default branch — the file's own policy
/// stands alone, as it did before this read existed.
pub fn read(path: &Path, asked: Option<&str>) -> Result<Option<Base>, String> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let requested = asked
        .map(str::to_string)
        .or_else(|| std::env::var(BASE_ENV).ok().filter(|v| !v.is_empty()));
    match requested {
        // The caller named it, so a ref that is not there is answered rather
        // than guessed around.
        Some(name) if !usable(&name) => Err(format!("`{name}` is not a ref")),
        Some(name) if !resolves(dir, &name) => Err(format!("`{name}` does not name a commit here")),
        Some(name) => Ok(Some(at(dir, &name, path))),
        None => Ok(auto_ref(dir).map(|git_ref| at(dir, &git_ref, path))),
    }
}

/// The default branch's copy of the file at `path`, and whether it had one.
fn at(dir: &Path, git_ref: &str, path: &Path) -> Base {
    let Some(src) = show(dir, git_ref, path) else {
        return Base { git_ref: git_ref.to_string(), policy: Policy::default(), has_file: false };
    };
    // Read the way `check` reads: the parse is the whole of it, and a block
    // the checker would reject is a block with no rules in it.
    let policy = ks_core::check(&ks_lang::parse(&src)).workflow.policy().clone();
    Base { git_ref: git_ref.to_string(), policy, has_file: true }
}

/// Whether a ref is shaped like a ref. A leading `-` is git's own option
/// prefix, so a base that starts with one would be read as a flag rather than
/// as a revision; that is a question about the command line, and answering it
/// beats passing the string along to git to interpret.
fn usable(git_ref: &str) -> bool {
    !git_ref.is_empty() && !git_ref.starts_with('-')
}

/// The first ref this repository resolves, if any: what a pull-request build
/// is told it is proposed against, then the usual default-branch names.
///
/// `GITHUB_BASE_REF` comes first because a pull-request build knows its base
/// and `main` may not be it. It is detection, not a request, so a ref that
/// does not resolve falls through to the guesses.
fn auto_ref(dir: &Path) -> Option<String> {
    let from_env = std::env::var(BASE_REF_ENV)
        .ok()
        .filter(|branch| !branch.is_empty())
        .map(|branch| format!("origin/{branch}"));
    from_env
        .into_iter()
        .chain(AUTO_REFS.iter().map(|r| (*r).to_string()))
        .filter(|candidate| usable(candidate))
        .find(|candidate| resolves(dir, candidate))
}

/// The file as `git_ref` has it, or `None` when the ref carries no such file.
/// A ref that resolves but has no copy of this path is a real answer, not a
/// failure to read one.
fn show(dir: &Path, git_ref: &str, path: &Path) -> Option<String> {
    // `./` is what makes the path relative to the directory the command ran
    // in rather than to the repository root, which is where a site file given
    // as `services/api/ship.ks` actually lives.
    let spec = format!("{git_ref}:./{}", file_name(path));
    git(dir, &["show", "--end-of-options", &spec]).ok()
}

/// The last path element, which is all `git show <ref>:./<name>` wants.
fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Whether `git_ref` names a commit here. `rev-parse` writes nothing, so this
/// is a question, not an edit.
fn resolves(dir: &Path, git_ref: &str) -> bool {
    let spec = format!("{git_ref}^{{commit}}");
    git(dir, &["rev-parse", "--verify", "--quiet", "--end-of-options", &spec]).is_ok()
}

/// `git` with the environment this process was given stripped of the
/// repository it happens to be running in: `GIT_DIR` and its kin make a child
/// git address *this* checkout rather than the directory it was pointed at,
/// and a test that ran `git init` would write into the repository it is
/// standing in. Absence of git, and anything that goes wrong, is `Err` — every
/// caller treats it as "no base", never as "an empty base at a ref".
fn git(dir: &Path, args: &[&str]) -> Result<String, ()> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .output()
        .map_err(|_| ())?;
    if !out.status.success() {
        return Err(());
    }
    String::from_utf8(out.stdout).map_err(|_| ())
}
