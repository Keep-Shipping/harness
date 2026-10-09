//! The charset every signed field is held to, checked once at request time.
//!
//! Two jobs. It keeps [`crate::sign`]'s canonical form unambiguous: no signed
//! field can carry a newline, a comma that would split a digest list, or an `=`
//! that would move a value onto another key. And it keeps runner free text out
//! of the URLs [`crate::github`] builds, where a `?`, a `/` or a `#` would aim
//! the deployment's token at a repository the runner did not name.

use cratefield_core::Problem;

/// A run id or a step name. Wide enough for the ULID `RunId` mints, for a bare
/// numeric GitHub run number, and for the dotted names a plan step may carry.
const RUN: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-";

/// A repository or team name: GitHub's alphabet plus `.` and `_`.
const SEGMENT: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";

/// A GitHub login: the alphabet plus `-`, and nothing else — no dot, no
/// underscore, which is what makes `ada.l` a refusal rather than a login.
const LOGIN: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-";

const HEX: &str = "0123456789abcdef";

/// Every byte in `chars`, and no longer than `max`.
fn only(value: &str, chars: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| chars.as_bytes().contains(&byte))
}

/// A run id or a step name: `[A-Za-z0-9._:-]{1,128}`.
pub(crate) fn run_field(value: &str) -> bool {
    only(value, RUN, 128)
}

/// A GitHub login: `[A-Za-z0-9-]{1,39}`.
pub(crate) fn login(value: &str) -> bool {
    only(value, LOGIN, 39)
}

/// Exactly 64 lower-case hex digits, the one spelling of a SHA-256 a digest
/// check can compare byte for byte.
pub(crate) fn sha256(value: &str) -> bool {
    value.len() == 64 && only(value, HEX, 64)
}

/// An artifact name is a label, not a path: anything that could break the HTML
/// or the review page's own framing is out, but it is otherwise free.
pub(crate) fn artifact_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && !value.chars().any(|character| character.is_control() || character == '<')
}

/// `owner/name` or `org/team`: exactly two segments, each a GitHub name. A
/// handle with a second slash in it is a handle GitHub never issues, and one
/// with a `?` in it is a query, not a team.
pub(crate) fn pair(value: &str, field: &str) -> Result<(String, String), Problem> {
    let bad = |why: &str| {
        Problem::validation_failed(format!(
            "{field} must be `owner/name` with GitHub names on each side ({why}), got {value:?}"
        ))
    };
    let trimmed = value.trim();
    let Some((owner, name)) = trimmed.split_once('/') else {
        return Err(bad("no slash"));
    };
    if trimmed.matches('/').count() != 1 {
        return Err(bad("more than one slash"));
    }
    if owner.is_empty() || !only(owner, SEGMENT, 100) {
        return Err(bad("the owner is not a GitHub name"));
    }
    if name.is_empty() || !only(name, SEGMENT, 100) {
        return Err(bad("the name is not a GitHub name"));
    }
    Ok((owner.to_owned(), name.to_owned()))
}

/// One repository and one team, both inside the orgs this deployment says it
/// hosts. Without this the token is a confused deputy: any runner that can
/// reach the API could name a repository this installation was never given.
pub(crate) fn hosted(orgs: &[String], repo_owner: &str, team_org: &str) -> Result<(), Problem> {
    for (owner, what) in [(repo_owner, "repo"), (team_org, "team")] {
        if !orgs.iter().any(|org| org.eq_ignore_ascii_case(owner)) {
            return Err(Problem::validation_failed(format!(
                "the {what} organisation {owner:?} is not one this deployment hosts ({})",
                orgs.join(", ")
            )));
        }
    }
    Ok(())
}

/// The configured org allow-list, trimmed and non-empty.
pub(crate) fn orgs(raw: &str) -> Vec<String> {
    raw.split(',').map(str::trim).filter(|org| !org.is_empty()).map(str::to_owned).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pair_is_two_github_names_and_nothing_else() {
        assert_eq!(
            pair("Keep-Shipping/harness", "repo").expect("a pair"),
            ("Keep-Shipping".into(), "harness".into())
        );
        for bad in ["nope", "a/b/c", "org?x=1/slug", "/slug", "own er/slug", "org/slu g", ""] {
            assert!(pair(bad, "repo").is_err(), "{bad:?} was accepted");
        }
        assert!(login("ada") && login("Ada-1") && !login("ada.l") && !login(&"a".repeat(40)));
        assert!(sha256(&"a".repeat(64)) && !sha256("a,b") && !sha256(&"A".repeat(64)));
        assert!(run_field("apply") && run_field("1700000000001") && !run_field("a\nb"));
        assert!(!artifact_name("main\n.tfplan") && artifact_name("main.tfplan"));
    }
}
