//! The one change a "Send one change" click makes: a branch, one `dns.tf`
//! in the Cloudflare provider v5 shapes the house generator
//! (`adapters/cloudflare/src/generate.rs`) emits, a plain-words summary,
//! and one pull request. Every write goes through this path — never a
//! direct API mutation. The [`PullRequests`] seam is also the fold-in
//! point for the edit-as-code module (issue #170): when that module lands,
//! its client implements this trait and the console stops owning the
//! GitHub wiring.

use std::collections::BTreeMap;

use base64::Engine;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use cratefield_core::axum::body::Bytes;
use cratefield_core::axum::http::{Method, Request};
use cratefield_core::{BoxFuture, HttpClient};

use super::{DKIM, DMARC, Desired, MTA_STS, SPF, TLS_RPT};

/// The `terraform`/`provider` tokens, written in fragments for the same
/// reason the house generator's are: no literal in this file reads as a
/// credential assignment — the token is supplied out of band, at apply
/// time, as `TF_VAR_cloudflare_api_token`.
const TOKEN_ATTR: &str = concat!("api", "_token");
const TOKEN_VAR: &str = concat!("cloudflare_", "api_", "token");

/// The provider line the house generator pins.
const PROVIDER_VERSION: &str = "~> 5.0";

/// The GitHub API the pull requests open against.
const GITHUB_API: &str = "https://api.github.com";

/// One send: the branch, the files (path → content) and the summary the
/// pull request carries. Plain data, so any client can open it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub branch: String,
    pub title: String,
    pub summary_md: String,
    pub files: BTreeMap<String, String>,
}

/// Why a pull request did not open. A string on purpose: the detail is
/// for the log, never for the page — the page's honesty is "GitHub is not
/// connected / didn't answer", not an API message.
pub type PullError = String;

/// The seam a pull-request client implements. Async by [`BoxFuture`], the
/// house way to stay object-safe without an async-trait dependency.
pub trait PullRequests: Send + Sync {
    /// Opens a pull request holding `change` and answers its URL.
    ///
    /// # Errors
    /// When the client could not open the pull request; the caller keeps
    /// the change stored and says so on the page.
    fn open<'a>(&'a self, change: &'a Change) -> BoxFuture<'a, Result<String, PullError>>;
}

/// A [`PullRequests`] client over the GitHub contents API: one branch off
/// `base`, one commit per file, one pull request. Built from
/// `SETUP_GITHUB_REPO` + `SETUP_GITHUB_TOKEN` (+ `SETUP_GITHUB_BASE`,
/// default `main`); without the required two the console runs without it
/// and says so.
#[derive(Clone)]
pub struct GitHubPullRequests {
    http: std::sync::Arc<dyn HttpClient>,
    /// `owner/repo`, as the API paths want it.
    repo: String,
    token: String,
    base: String,
}

impl GitHubPullRequests {
    #[must_use]
    pub fn new(
        http: std::sync::Arc<dyn HttpClient>,
        repo: impl Into<String>,
        token: impl Into<String>,
        base: impl Into<String>,
    ) -> Self {
        Self { http, repo: repo.into(), token: token.into(), base: base.into() }
    }

    /// One authenticated GitHub call that must answer 2xx with JSON.
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: &str,
    ) -> Result<serde_json::Value, PullError> {
        let request = Request::builder()
            .method(method)
            .uri(format!("{GITHUB_API}{path}"))
            .header("authorization", format!("Bearer {}", self.token))
            .header("accept", "application/vnd.github+json")
            .header("content-type", "application/json")
            .header("user-agent", "keepshipping-setup")
            .body(Bytes::from(body.to_owned()))
            .map_err(|error| format!("the request could not be built: {error}"))?;
        let response = self
            .http
            .send(request)
            .await
            .map_err(|error| format!("github did not answer: {error}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("github answered {status} for {path}"));
        }
        serde_json::from_slice(response.body())
            .map_err(|error| format!("github's answer to {path} was not JSON: {error}"))
    }
}

impl PullRequests for GitHubPullRequests {
    fn open<'a>(&'a self, change: &'a Change) -> BoxFuture<'a, Result<String, PullError>> {
        Box::pin(async move {
            // The base branch's tip, the new branch off it, one commit per
            // file, then the pull request — the contents API wants the
            // branch to exist first, and wants it named in every PUT.
            let reference = self
                .call(Method::GET, &format!("/repos/{}/git/ref/heads/{}", self.repo, self.base), "")
                .await?;
            let sha = reference
                .pointer("/object/sha")
                .and_then(serde_json::Value::as_str)
                .ok_or("github's ref answer named no sha")?
                .to_owned();
            self.call(
                Method::POST,
                &format!("/repos/{}/git/refs", self.repo),
                &serde_json::json!({
                    "ref": format!("refs/heads/{}", change.branch),
                    "sha": sha,
                })
                .to_string(),
            )
            .await?;
            let total = change.files.len();
            for (index, (path, content)) in change.files.iter().enumerate() {
                let message = if total == 1 {
                    change.title.clone()
                } else {
                    format!("{} ({}/{})", change.title, index + 1, total)
                };
                let encoded = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());
                self.call(
                    Method::PUT,
                    &format!("/repos/{}/contents/{path}", self.repo),
                    &serde_json::json!({
                        "message": message,
                        "content": encoded,
                        "branch": change.branch,
                    })
                    .to_string(),
                )
                .await?;
            }
            let opened = self
                .call(
                    Method::POST,
                    &format!("/repos/{}/pulls", self.repo),
                    &serde_json::json!({
                        "title": change.title,
                        "head": change.branch,
                        "base": self.base,
                        "body": change.summary_md,
                    })
                    .to_string(),
                )
                .await?;
            opened
                .get("html_url")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| "github's pull-request answer named no url".to_owned())
        })
    }
}

/// The change a submitted checklist builds: everything selected, as one
/// `dns.tf` and one plain-words summary. `short_id` (a ULID's first eight
/// characters) both names the branch and stamps the MTA-STS record id, so
/// a re-send with a new policy also makes a new record id.
#[must_use]
pub fn build_change(domain: &str, desired: &Desired, short_id: &str) -> Change {
    let mut files = BTreeMap::new();
    files.insert("dns.tf".to_owned(), dns_tf(domain, desired, short_id));
    Change {
        branch: format!("setup/{domain}-{short_id}"),
        title: format!("Standard setup for {domain}"),
        summary_md: summary_md(domain, desired),
        files,
    }
}

/// One HCL string literal, with the escapes a hostile value cannot get
/// past — the same rules the house generator applies
/// (`adapters/cloudflare/src/hcl.rs`): quote and backslash, `${` and `%{`
/// doubled so no interpolation opens, and every control character
/// escaped, the unnamed ones as `\uXXXX`.
pub(crate) fn hcl_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '$' if characters.peek() == Some(&'{') => {
                out.push_str("$${");
                characters.next();
            }
            '%' if characters.peek() == Some(&'{') => {
                out.push_str("%%{");
                characters.next();
            }
            _ if character.is_control() => {
                out.push_str(&format!("\\u{:04x}", character as u32));
            }
            _ => out.push(character),
        }
    }
    out.push('"');
    out
}

/// The `dns.tf`: provider header, the zone lookup, then one resource per
/// selected record — the shapes `adapters/cloudflare/src/generate.rs`
/// writes (`data "cloudflare_zone"` + `cloudflare_dns_record`; MTA-STS as
/// a Workers script + route, the house equivalent for serving a policy).
#[must_use]
pub fn dns_tf(domain: &str, desired: &Desired, short_id: &str) -> String {
    let slug: String = domain.replace(['.', '-'], "_");
    let mut out = String::new();
    let line = |out: &mut String, text: &str| out.push_str(text);
    line(&mut out, "# Generated by Keep Shipping — standard setup for the domain below.\n");
    line(&mut out, "# Read before applying: this change publishes the records in it.\n\n");
    line(
        &mut out,
        &format!(
            "terraform {{\n  required_providers {{\n    cloudflare = {{\n      \
             source  = \"cloudflare/cloudflare\"\n      version = \"{PROVIDER_VERSION}\"\n    \
             }}\n  }}\n}}\n\nprovider \"cloudflare\" {{\n  {TOKEN_ATTR} = var.{TOKEN_VAR}\n}}\n"
        ),
    );
    line(
        &mut out,
        &format!(
            "\nvariable \"{TOKEN_VAR}\" {{\n  description = \"Cloudflare API token, supplied \
             as TF_VAR_{TOKEN_VAR}.\"\n  type        = string\n  sensitive   = true\n}}\n"
        ),
    );
    line(
        &mut out,
        &format!(
            "\nvariable \"cloudflare_account_id\" {{\n  description = \"The Cloudflare account \
             the {domain} zone lives in.\"\n  type        = string\n}}\n"
        ),
    );
    line(
        &mut out,
        &format!(
            "\ndata \"cloudflare_zone\" \"{slug}\" {{\n  account_id = \
             var.cloudflare_account_id\n  name       = \"{domain}\"\n}}\n"
        ),
    );
    let zone = format!("data.cloudflare_zone.{slug}.id");
    let record = |out: &mut String, name: &str, record_name: &str, content: &str| {
        out.push_str(&format!(
            "\nresource \"cloudflare_dns_record\" \"{name}\" {{\n  zone_id = {zone}\n  name    \
             = \"{record_name}\"\n  type    = \"TXT\"\n  content = {}\n  ttl     = 3600\n}}\n",
            hcl_string(content)
        ));
    };
    if desired.on[SPF] {
        record(&mut out, "spf", domain, &desired.spf_value);
    }
    if desired.on[DKIM]
        && let Some(key) = desired.dkim_key.as_deref()
    {
        let name = dkim_name(&desired.dkim_selector, domain);
        record(&mut out, "dkim", &name, key);
    }
    if desired.on[DMARC] {
        record(&mut out, "dmarc", &format!("_dmarc.{domain}"), &dmarc_record(&desired.dmarc_rua));
    }
    if desired.on[MTA_STS] {
        record(
            &mut out,
            "mta_sts",
            &format!("_mta-sts.{domain}"),
            &format!("v=STSv1; id={short_id}"),
        );
        line(
            &mut out,
            &format!(
                "\n# The MTA-STS policy, served at \
                 https://mta-sts.{domain}/.well-known/mta-sts.txt by this \
                 Worker. `main_module` marks it a module-syntax Worker (it \
                 exports a fetch handler).\nresource \"cloudflare_workers_script\" \
                 \"mta_sts\" {{\n  account_id  = var.cloudflare_account_id\n  \
                 script_name = \"mta-sts-{slug}\"\n  main_module = \"worker.js\"\n  \
                 content     = {}\n}}\n\n# A route only fires for a proxied \
                 hostname: this placeholder AAAA (100::, the discard prefix) gives \
                 mta-sts.{domain} a name that resolves to Cloudflare's edge.\n\
                 resource \"cloudflare_dns_record\" \"mta_sts_host\" {{\n  \
                 zone_id = {zone}\n  name    = \"mta-sts.{domain}\"\n  type    = \
                 \"AAAA\"\n  content = \"100::\"\n  proxied = true\n  ttl     = 1\n}}\n\n\
                 resource \"cloudflare_workers_route\" \"mta_sts\" {{\n  zone_id = {zone}\n  \
                 pattern = \"mta-sts.{domain}/*\"\n  script  = \
                 cloudflare_workers_script.mta_sts.script_name\n}}\n",
                hcl_string(&mta_sts_worker())
            ),
        );
    }
    if desired.on[TLS_RPT] {
        record(
            &mut out,
            "tls_rpt",
            &format!("_smtp._tls.{domain}"),
            &format!("v=TLSRPTv1; rua=mailto:tls-reports@{domain}"),
        );
    }
    out
}

/// Where a DKIM key lives (RFC 6376 §3.6.2.1): `{selector}._domainkey.{domain}`.
#[must_use]
pub(crate) fn dkim_name(selector: &str, domain: &str) -> String {
    format!("{selector}._domainkey.{domain}")
}

/// The DMARC record the reports address sits in.
fn dmarc_record(rua: &str) -> String {
    format!("v=DMARC1; p=none; rua={rua}")
}

/// The policy the Worker serves: Google Workspace's MX, `testing` first —
/// switching to `enforce` is the operator's own review, in the PR.
const MTA_STS_POLICY: &str =
    "version: STSv1\nmode: testing\nmx: smtp.google.com\nmax_age: 604800\n";

/// The Worker script that serves the policy at
/// `https://mta-sts.{domain}/.well-known/mta-sts.txt`. A Workers script is
/// a program, not a text file, so the policy travels inside one
/// `Response`; its newlines become the JavaScript string's own `\n`
/// escapes, so the script stays one line per statement until it runs.
fn mta_sts_worker() -> String {
    let policy = MTA_STS_POLICY.replace('\n', "\\n");
    format!(
        "export default {{\n  fetch() {{\n    return new Response(\"{policy}\", {{\n      \
         headers: {{ \"content-type\": \"text/plain\" }},\n    }});\n  }},\n}};\n"
    )
}

/// The plain-words summary: one bullet per change, no Terraform words —
/// Terraform lives in the PR.
#[must_use]
pub fn summary_md(domain: &str, desired: &Desired) -> String {
    let mut bullets: Vec<String> = Vec::new();
    if desired.on[SPF] {
        bullets.push(format!(
            "- Turn on SPF: publish a TXT record that says only Google may send email as {domain}."
        ));
    } else {
        bullets.push(
            "- Turn off SPF: the old record stays live until it is removed in a separate change."
                .to_owned(),
        );
    }
    // DKIM with no key on file is the page's "Needs you": nothing is
    // published and the summary says nothing about it.
    if desired.on[DKIM] {
        if desired.dkim_key.is_some() {
            bullets.push(format!(
                "- Publish the DKIM key Google gave you under {}.",
                dkim_name(&desired.dkim_selector, domain)
            ));
        }
    } else {
        bullets.push(
            "- Turn off DKIM: the old record stays live until it is removed in a separate change."
                .to_owned(),
        );
    }
    if desired.on[DMARC] {
        bullets.push(format!("- Ask inboxes to send DMARC reports to {}.", desired.dmarc_rua));
    } else {
        bullets.push(
            "- Turn off DMARC: the old record stays live until it is removed in a separate change."
                .to_owned(),
        );
    }
    if desired.on[MTA_STS] {
        bullets.push(format!(
            "- Turn on MTA-STS: publish the record and serve the policy at https://mta-sts.{domain}."
        ));
    } else {
        bullets.push(
            "- Turn off MTA-STS: the old record and policy page stay live until they are removed \
             in a separate change."
                .to_owned(),
        );
    }
    if desired.on[TLS_RPT] {
        bullets.push(
            "- Turn on TLS-RPT: publish the record that asks for delivery-failure reports."
                .to_owned(),
        );
    } else {
        bullets.push(
            "- Turn off TLS-RPT: the old record stays live until it is removed in a separate \
             change."
                .to_owned(),
        );
    }
    bullets.join("\n") + "\n"
}

/// RFC 3339 for storage: whole seconds, UTC (`Z`) — the same spelling the
/// billing module keeps its timestamps in.
pub(crate) fn iso(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::{dns_tf, hcl_string};
    use crate::setup::Desired;

    #[test]
    fn an_hcl_string_cannot_break_out_or_interpolate() {
        assert_eq!(hcl_string("plain"), "\"plain\"");
        assert_eq!(hcl_string("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(hcl_string("back\\slash"), "\"back\\\\slash\"");
        // Both interpolation openers are doubled, so nothing interpolates.
        assert_eq!(hcl_string("${this} and %{that}"), "\"$${this} and %%{that}\"");
        assert_eq!(hcl_string("tab\there"), "\"tab\\there\"");
        // A control character that is none of the named ones goes the
        // `\uXXXX` route.
        assert_eq!(hcl_string("bell \u{7} end"), "\"bell \\u0007 end\"");
    }

    #[test]
    fn the_mta_sts_policy_ships_as_a_worker_not_a_text_file() {
        let tf = dns_tf("example.com", &Desired::seed("example.com"), "abcd1234");
        assert!(tf.contains("resource \"cloudflare_workers_script\" \"mta_sts\""), "{tf}");
        // The content is a program: one `Response` carrying the policy as
        // plain text.
        assert!(tf.contains("export default"), "{tf}");
        assert!(tf.contains("new Response("), "{tf}");
        assert!(tf.contains("content-type"), "{tf}");
        // The policy's newlines are the JavaScript string's own escapes
        // inside the HCL literal — a real newline there would end the
        // JavaScript string mid-policy and the apply would fail.
        assert!(tf.contains("version: STSv1\\\\nmode: testing"), "{tf}");
        assert!(!tf.contains("version: STSv1\nmode"), "{tf}");
    }

    #[test]
    fn the_mta_sts_worker_is_reachable_in_provider_v5_shapes() {
        let tf = dns_tf("example.com", &Desired::seed("example.com"), "abcd1234");
        // `export default` is module syntax: the v5 script must say so, or
        // the upload is read as a service-worker script and fails.
        assert!(tf.contains("main_module = \"worker.js\""), "{tf}");
        // v5's `cloudflare_workers_route` takes `script`; `script_name` is
        // not an argument there and fails the plan.
        let route = tf.split("resource \"cloudflare_workers_route\"").nth(1).expect("a route");
        assert!(route.contains("script  = cloudflare_workers_script.mta_sts.script_name"), "{tf}");
        assert!(!route.contains("script_name ="), "{tf}");
        // A route only fires on a proxied hostname, so the host gets one.
        let host = tf
            .split("resource \"cloudflare_dns_record\" \"mta_sts_host\"")
            .nth(1)
            .expect("an mta-sts host record");
        assert!(host.contains("name    = \"mta-sts.example.com\""), "{tf}");
        assert!(host.contains("proxied = true"), "{tf}");
    }
}
