//! The connect-time least-privilege check
//! ([#168](https://github.com/Keep-Shipping/harness/issues/168)): what the
//! generated modules manage, what the token grants, and the difference. All
//! `GET`s; the token goes out in the `Authorization` header and nowhere else.

use std::collections::BTreeSet;
use std::fmt;

use ks_core::ports::BoxFuture;
use serde_json::Value;

use crate::{Account, Cloudflare, Error};

/// The one permission beyond the managed set the check accepts: a read-only
/// permission over the account's API tokens, the only way a token can read its
/// own policies — which is how this check runs at all. Any other extra is named
/// in the refusal.
const ALLOWED_EXTRA: &[&str] = &["Account API Tokens Read"];

/// The permission groups one resource type needs — read and write, since a
/// plan reads the account and an apply changes it. An unknown kind (not emitted
/// by [`generate`](crate::generate)) needs nothing here.
fn groups_for(kind: &str) -> &'static [&'static str] {
    match kind {
        "cloudflare_zone" => &["Zone Read", "Zone Write"],
        "cloudflare_zone_setting" => &["Zone Settings Read", "Zone Settings Write"],
        "cloudflare_dns_record" => &["DNS Read", "DNS Write"],
        "cloudflare_workers_route" => &["Workers Routes Read", "Workers Routes Write"],
        "cloudflare_email_routing_rule" => {
            &["Email Routing Rules Read", "Email Routing Rules Write"]
        }
        // Zone-scoped rulesets; the account-level ones are not this slice's.
        "cloudflare_ruleset" => &["Zone WAF Read", "Zone WAF Write"],
        "cloudflare_bot_management" => &["Bot Management Read", "Bot Management Write"],
        "cloudflare_pages_project" | "cloudflare_pages_domain" => {
            &["Cloudflare Pages Read", "Cloudflare Pages Write"]
        }
        // Custom domains hang off the Workers scripts permission.
        "cloudflare_workers_custom_domain" => &["Workers Scripts Read", "Workers Scripts Write"],
        "cloudflare_d1_database" => &["D1 Read", "D1 Write"],
        "cloudflare_r2_bucket" => &["Workers R2 Storage Read", "Workers R2 Storage Write"],
        "cloudflare_workers_kv_namespace" => {
            &["Workers KV Storage Read", "Workers KV Storage Write"]
        }
        _ => &[],
    }
}

/// The permission groups `account`'s resource types need: the yardstick
/// [`Cloudflare::check_scope`] holds the token's policies against.
pub fn required_groups(account: &Account) -> BTreeSet<String> {
    account
        .resources
        .iter()
        .flat_map(|resource| groups_for(resource.kind))
        .map(|name| canon(name))
        .collect()
}

/// Folds a permission group name across Cloudflare's `Edit` → `Write` rename.
fn canon(name: &str) -> String {
    name.strip_suffix("Edit").map(|stem| format!("{stem}Write")).unwrap_or_else(|| name.to_string())
}

/// Why a token's scope does not fit. Both fields are permission group names —
/// the token itself is never in here, nor in the [`Display`](fmt::Display).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeError {
    /// Granted beyond the managed set and beyond [`ALLOWED_EXTRA`].
    pub extra: Vec<String>,
    /// Needed by the managed resource types and not granted.
    pub missing: Vec<String>,
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.extra.is_empty() {
            write!(f, "granted beyond what this slice manages: {}", self.extra.join(", "))?;
            if !self.missing.is_empty() {
                write!(f, "; ")?;
            }
        }
        if !self.missing.is_empty() {
            write!(f, "missing: {}", self.missing.join(", "))?;
        }
        Ok(())
    }
}

impl std::error::Error for ScopeError {}

/// The scope gate: `granted` must cover every group `required` names (already
/// [`canon`]ical, as [`required_groups`] builds it) and carry nothing beyond
/// them but [`ALLOWED_EXTRA`] — either way, a refusal naming the difference.
pub fn check_scope(
    granted: &BTreeSet<String>,
    required: &BTreeSet<String>,
) -> Result<(), ScopeError> {
    let granted: BTreeSet<String> = granted.iter().map(|name| canon(name)).collect();
    let extra: Vec<String> = granted
        .iter()
        .filter(|name| !required.contains(*name) && !ALLOWED_EXTRA.contains(&name.as_str()))
        .cloned()
        .collect();
    let missing: Vec<String> = required.difference(&granted).cloned().collect();
    if extra.is_empty() && missing.is_empty() {
        return Ok(());
    }
    Err(ScopeError { extra, missing })
}

impl Cloudflare {
    /// The connect-time check: verify the token, read its own policies, and
    /// hold them against `required`. The token is an account-owned one and
    /// verifies at `GET /accounts/{id}/tokens/verify`.
    pub fn check_scope<'a>(
        &'a self,
        account_id: &'a str,
        required: &'a BTreeSet<String>,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            let (id, tokens) = self.verify_token(account_id).await?;
            let body = self.get(&format!("{tokens}/{id}")).await?;
            let granted = granted(&body, account_id)?;
            check_scope(&granted, required)
                .map_err(|error| Error::Scope { message: error.to_string() })
        })
    }

    /// `GET /accounts/{id}/tokens/verify` — the account-owned token endpoints,
    /// and nothing else. A 403 or 404 means this is not an account-owned token;
    /// the error says so in plain words and never carries the token. Answers the
    /// token's id and the token endpoints that worked.
    async fn verify_token(&self, account_id: &str) -> Result<(String, String), Error> {
        let account = format!("/accounts/{}/tokens", crate::encode(account_id));
        match self.get(&format!("{account}/verify")).await {
            Ok(body) => Ok((verified(&body)?, account)),
            Err(Error::Status { status: status @ (403 | 404), .. }) => Err(Error::Scope {
                message: format!(
                    "the account's token verify endpoint refused it ({status}); \
                     an account-owned API token — one created inside this \
                     account — is needed, not a user token"
                ),
            }),
            Err(error) => Err(error),
        }
    }
}

/// The token id out of a verify response; a named status other than `active`
/// is refused in plain words.
fn verified(body: &Value) -> Result<String, Error> {
    let result = &body["result"];
    let id = crate::field(result, "id")
        .ok_or(Error::Api { message: "the token verify response carries no id".to_string() })?;
    if let Some(status) = crate::field(result, "status")
        && status != "active"
    {
        return Err(Error::Scope {
            message: format!("the token is not active: Cloudflare reports it {status}"),
        });
    }
    Ok(id)
}

/// The groups the token's policies grant: an `allow` policy inside this account
/// grants, a `deny` takes back (deny wins), and any policy reaching beyond this
/// account — another account or a wildcard — is refused: a dedicated token
/// names exactly one account.
fn granted(body: &Value, account_id: &str) -> Result<BTreeSet<String>, Error> {
    let mut granted = BTreeSet::new();
    for policy in body["result"]["policies"].as_array().into_iter().flatten() {
        if !policy_resources(policy).iter().all(|resource| in_account(resource, account_id)) {
            return Err(Error::Scope {
                message:
                    "a policy reaches beyond this account; a dedicated token names exactly one"
                        .to_string(),
            });
        }
        let groups: Vec<String> = policy["permission_groups"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|group| crate::field(group, "name"))
            .map(|name| canon(&name))
            .collect();
        if policy.get("effect").and_then(Value::as_str) == Some("deny") {
            for group in groups {
                granted.remove(&group);
            }
        } else {
            granted.extend(groups);
        }
    }
    Ok(granted)
}

/// The resources one policy covers: the keys of Cloudflare's resource map, or
/// its items when the API answered with a list.
fn policy_resources(policy: &Value) -> Vec<String> {
    match policy.get("resources") {
        Some(Value::Object(map)) => map.keys().cloned().collect(),
        Some(Value::Array(items)) => {
            items.iter().filter_map(|item| item.as_str()).map(str::to_string).collect()
        }
        _ => Vec::new(),
    }
}

/// Whether `resource` sits inside the account: the account itself or one of
/// its zones. Anything else — another account, a wildcard over all of them —
/// is outside.
fn in_account(resource: &str, account_id: &str) -> bool {
    let prefix = format!("com.cloudflare.api.account.{account_id}");
    resource == prefix || resource.strip_prefix(&prefix).is_some_and(|rest| rest.starts_with('.'))
}
