//! Rollbacks: putting an earlier deployment of a site back live. This is the
//! pure half: which sites can be rolled back and how they are addressed on
//! Cloudflare, the response shapes of the version listings, the candidate
//! list, and the HTML of the site page's "Roll back" panel and the
//! confirmation page. The calls themselves are in [`super::api`].
//!
//! Only two kinds of site roll back, the two Cloudflare has an API for: a
//! Pages project's production (its rollback endpoint, to an earlier
//! successful production deployment) and a Worker (a new deployment sending
//! all traffic to an earlier version). A Pages preview is whatever its branch
//! last built; a domain has no deployments.
//!
//! Rolling back needs the optional deploy token (Pages Edit, Workers Scripts
//! Edit), stored apart from the read-only one. Every rollback is a POST from
//! a confirmation page, and the target is checked against a fresh listing
//! before it is sent, so a stale or hand-made form cannot put an arbitrary
//! id live.

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::Deserialize;

use crate::fleet::{
    Site, Tab, esc, main_domain, message_line, signed_in_layout, time_html, trigger_words,
};

/// The deploy token's permission groups, as `(key, type)` pairs for
/// Cloudflare's template URL: write on Pages and Workers scripts, which is
/// what the two rollback calls need, and read on the account list so the
/// token can be checked when it is pasted.
pub const DEPLOY_PERMISSIONS: [(&str, &str); 3] =
    [("page", "edit"), ("workers_scripts", "edit"), ("account_settings", "read")];

/// The plain-words names of [`DEPLOY_PERMISSIONS`], in the same order.
pub const DEPLOY_PERMISSION_WORDS: [&str; 3] =
    ["Pages Edit", "Workers Scripts Edit", "Account Settings Read"];

/// The deploy token's name on Cloudflare's form.
pub const DEPLOY_TOKEN_NAME: &str = "Keep Shipping console (rollbacks)";

/// How many earlier versions the panel offers.
pub const CANDIDATES: usize = 10;

/// A path segment from a snapshot or Cloudflare string: anything a URL path
/// cannot carry raw, plus `/`, `?` and `#`.
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'\\')
    .add(b'^')
    .add(b'|');

/// What a rollback addresses on Cloudflare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A Pages project's production.
    Pages { account: String, project: String },
    /// A Worker script.
    Worker { account: String, script: String },
}

/// The rollback target of a site, from the id the collector gave it
/// (`pages:<account>:<project>`, `worker:<account>:<script>`). `None` for a
/// domain, a Pages preview (`pages:<account>:<project>:<branch>`), or an id
/// of any other shape.
#[must_use]
pub fn target(site: &Site) -> Option<Target> {
    let mut parts = site.id.splitn(3, ':');
    let (kind, account, rest) = (parts.next()?, parts.next()?, parts.next()?);
    if account.is_empty() || rest.is_empty() {
        return None;
    }
    match kind {
        "pages" if !rest.contains(':') => {
            Some(Target::Pages { account: account.to_owned(), project: rest.to_owned() })
        }
        "worker" => Some(Target::Worker { account: account.to_owned(), script: rest.to_owned() }),
        _ => None,
    }
}

impl Target {
    /// The API path (after `/client/v4`) listing what can be rolled back to.
    #[must_use]
    pub fn versions_path(&self) -> String {
        match self {
            Target::Pages { account, project } => format!(
                "/accounts/{}/pages/projects/{}/deployments?env=production&per_page=25",
                seg(account),
                seg(project)
            ),
            Target::Worker { account, script } => {
                format!("/accounts/{}/workers/scripts/{}/versions", seg(account), seg(script))
            }
        }
    }

    /// The API path that says which deployment is live now: the Pages
    /// project (its `canonical_deployment`), or the Worker's newest
    /// deployment.
    #[must_use]
    pub fn live_path(&self) -> String {
        match self {
            Target::Pages { account, project } => {
                format!("/accounts/{}/pages/projects/{}", seg(account), seg(project))
            }
            Target::Worker { account, script } => format!(
                "/accounts/{}/workers/scripts/{}/deployments?per_page=1",
                seg(account),
                seg(script)
            ),
        }
    }

    /// The POST that rolls back to `to`, and its JSON body (`None` for the
    /// Pages rollback endpoint, which takes none).
    #[must_use]
    pub fn rollback_request(&self, to: &str) -> (String, Option<String>) {
        match self {
            Target::Pages { account, project } => (
                format!(
                    "/accounts/{}/pages/projects/{}/deployments/{}/rollback",
                    seg(account),
                    seg(project),
                    seg(to)
                ),
                None,
            ),
            Target::Worker { account, script } => (
                format!("/accounts/{}/workers/scripts/{}/deployments", seg(account), seg(script)),
                Some(
                    serde_json::json!({
                        "strategy": "percentage",
                        "versions": [{ "percentage": 100, "version_id": to }],
                        "annotations": { "workers/message": "Rolled back from the Keep Shipping console" },
                    })
                    .to_string(),
                ),
            ),
        }
    }
}

fn seg(value: &str) -> String {
    utf8_percent_encode(value, SEGMENT).to_string()
}

/// One deployment a site can be rolled back to (or the live one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The Pages deployment id or the Worker version id: what the rollback
    /// call names.
    pub id: String,
    /// RFC 3339, as Cloudflare gave it.
    pub at: String,
    /// The git commit, for a Pages deployment built from one.
    pub commit: Option<String>,
    pub branch: Option<String>,
    pub message: Option<String>,
    /// How it was made, as Cloudflare says it (`ad_hoc`, `github:push`,
    /// `wrangler`): shown through [`trigger_words`].
    pub source: Option<String>,
    /// A Worker version's number (`v42`).
    pub number: Option<u64>,
    pub live: bool,
}

/// A Pages deployment as the production listing returns it.
#[derive(Debug, Clone, Deserialize)]
pub struct PagesDeployment {
    pub id: String,
    #[serde(default)]
    pub created_on: String,
    #[serde(default)]
    pub latest_stage: Option<Stage>,
    #[serde(default)]
    pub deployment_trigger: Option<super::Trigger>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Stage {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
}

/// `GET …/pages/projects/{project}`: only the deployment it serves matters.
#[derive(Debug, Clone, Deserialize)]
pub struct PagesProjectLive {
    #[serde(default)]
    pub canonical_deployment: Option<IdOnly>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdOnly {
    pub id: String,
}

/// `GET …/workers/scripts/{script}/versions`: `{"items": [...]}`, newest
/// first; read as a bare list too, in case the envelope is flat.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum WorkerVersions {
    Items { items: Vec<WorkerVersionItem> },
    List(Vec<WorkerVersionItem>),
}

impl WorkerVersions {
    fn into_items(self) -> Vec<WorkerVersionItem> {
        match self {
            WorkerVersions::Items { items } | WorkerVersions::List(items) => items,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerVersionItem {
    pub id: String,
    #[serde(default)]
    pub number: Option<u64>,
    #[serde(default)]
    pub metadata: Option<WorkerVersionMetadata>,
    #[serde(default)]
    pub annotations: Option<super::WorkerAnnotations>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerVersionMetadata {
    #[serde(default)]
    pub created_on: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

/// The successful production deployments, newest first, at most
/// [`CANDIDATES`] plus the live one, with the live one marked. A deployment
/// that failed or is still building cannot be rolled back to.
#[must_use]
pub fn pages_candidates(deployments: Vec<PagesDeployment>, live: Option<&str>) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = deployments
        .into_iter()
        .filter(|deployment| {
            deployment.latest_stage.as_ref().is_some_and(|stage| {
                stage.status == "success" && (stage.name.is_empty() || stage.name == "deploy")
            })
        })
        .map(|deployment| {
            let trigger = deployment.deployment_trigger;
            let metadata = trigger.as_ref().and_then(|trigger| trigger.metadata.clone());
            Candidate {
                live: live == Some(deployment.id.as_str()),
                id: deployment.id,
                at: deployment.created_on,
                commit: metadata.as_ref().and_then(|m| m.commit_hash.clone()),
                branch: metadata.as_ref().and_then(|m| m.branch.clone()),
                message: metadata.and_then(|m| m.commit_message),
                source: trigger.and_then(|trigger| trigger.kind),
                number: None,
            }
        })
        .collect();
    keep(&mut out);
    out
}

/// The Worker's versions, newest first, at most [`CANDIDATES`] plus the live
/// one, with the live one marked.
#[must_use]
pub fn worker_candidates(versions: WorkerVersions, live: Option<&str>) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = versions
        .into_items()
        .into_iter()
        .map(|version| {
            let metadata = version
                .metadata
                .unwrap_or(WorkerVersionMetadata { created_on: None, source: None });
            Candidate {
                live: live == Some(version.id.as_str()),
                id: version.id,
                at: metadata.created_on.unwrap_or_default(),
                commit: None,
                branch: None,
                message: version.annotations.and_then(|annotations| annotations.message),
                source: metadata.source,
                number: version.number,
            }
        })
        .collect();
    keep(&mut out);
    out
}

/// Trims to the live one plus [`CANDIDATES`] others, in listed order.
fn keep(candidates: &mut Vec<Candidate>) {
    let mut others = 0;
    candidates.retain(|candidate| {
        if candidate.live {
            return true;
        }
        others += 1;
        others <= CANDIDATES
    });
}

/// Whether `to` may be rolled back to: listed, and not already live.
#[must_use]
pub fn allowed<'a>(candidates: &'a [Candidate], to: &str) -> Option<&'a Candidate> {
    candidates.iter().find(|candidate| candidate.id == to && !candidate.live)
}

/// What the site page's rollback panel can show.
#[derive(Debug, Clone)]
pub enum Panel {
    /// The site has no rollback (a domain or a Pages preview): no panel.
    NotSupported,
    /// No deploy token is stored: say how to add one.
    NoDeployToken,
    /// The listing failed; the words say why.
    Unavailable(&'static str),
    Candidates(Vec<Candidate>),
}

/// The URL of a site's rollback page (GET: confirm, POST: do it).
#[must_use]
pub fn rollback_path(site_id: &str) -> String {
    format!("/console/fleet/{}/rollback", seg(site_id))
}

/// The site page's "Roll back" panel.
#[must_use]
pub fn panel_html(site: &Site, panel: &Panel, now: &str) -> String {
    let body = match panel {
        Panel::NotSupported => return String::new(),
        Panel::NoDeployToken => "<p class=\"muted\">Rolling back needs a deploy token, separate \
             from the read-only one. Add it on the <a href=\"/console/connect/cloudflare#rollbacks\">\
             Cloudflare connection</a> page.</p>\n"
            .to_owned(),
        Panel::Unavailable(message) => {
            format!("<p class=\"callout warn\">{}</p>\n", esc(message))
        }
        Panel::Candidates(candidates) if candidates.iter().all(|c| c.live) => {
            "<p class=\"muted\">There is no earlier deployment to roll back to.</p>\n".to_owned()
        }
        Panel::Candidates(candidates) => {
            let action = rollback_path(&site.id);
            let rows = candidates
                .iter()
                .map(|candidate| {
                    let button = if candidate.live {
                        "<span class=\"tag live\">live</span>".to_owned()
                    } else {
                        format!(
                            "<form method=\"get\" action=\"{action}\"><input type=\"hidden\" \
                             name=\"to\" value=\"{id}\"><button class=\"btn\" type=\"submit\">\
                             Roll back to this</button></form>",
                            action = esc(&action),
                            id = esc(&candidate.id),
                        )
                    };
                    format!(
                        "<li><div class=\"when\">{when}</div><div class=\"what\">{what}</div>\
                         <div class=\"do\">{button}</div></li>\n",
                        when = time_html(&candidate.at, now),
                        what = candidate_words(candidate),
                    )
                })
                .collect::<String>();
            format!("<ol class=\"rows versions\">\n{rows}</ol>\n")
        }
    };
    format!(
        "<section class=\"panel\" id=\"rollback\" aria-labelledby=\"rollback-title\">\n\
         <h2 id=\"rollback-title\">Roll back</h2>\n{body}</section>\n"
    )
}

/// A candidate in words, `·`-separated: version number or commit, branch,
/// message, how it was made.
#[must_use]
pub fn candidate_words(candidate: &Candidate) -> String {
    let mut parts = Vec::new();
    if let Some(number) = candidate.number {
        parts.push(format!("version {number}"));
    }
    match candidate.commit.as_deref().map(str::trim).filter(|commit| !commit.is_empty()) {
        Some(commit) => parts.push(format!("<code>{}</code>", esc(short(commit, 7)))),
        None if candidate.number.is_none() => {
            parts.push(format!("<code>{}</code>", esc(short(&candidate.id, 8))));
        }
        None => {}
    }
    if let Some(branch) = candidate.branch.as_deref().filter(|branch| !branch.trim().is_empty()) {
        parts.push(esc(branch.trim()));
    }
    if let Some(message) =
        candidate.message.as_deref().map(message_line).filter(|message| !message.is_empty())
    {
        parts.push(format!("<span class=\"msg\">{}</span>", esc(&message)));
    }
    if let Some(source) = candidate.source.as_deref().filter(|source| !source.trim().is_empty()) {
        parts.push(esc(&trigger_words(source)));
    }
    parts.join(" · ")
}

fn short(id: &str, len: usize) -> &str {
    id.get(..len).unwrap_or(id)
}

/// The confirmation page: what goes live, what it replaces, where, and one
/// POST button.
#[must_use]
pub fn confirm_page(site: &Site, to: &Candidate, live: Option<&Candidate>, now: &str) -> String {
    let site_path = format!("/console/fleet/{}", seg(&site.id));
    let place = main_domain(&site.domains)
        .map(|domain| format!(" on <strong>{}</strong>", esc(domain)))
        .unwrap_or_default();
    let replaces = live
        .map(|live| {
            format!(
                "<dt>Replaces</dt><dd>{what}<br><span class=\"muted\">{when}</span></dd>\n",
                what = candidate_words(live),
                when = time_html(&live.at, now),
            )
        })
        .unwrap_or_default();
    let body = format!(
        "<main id=\"main\" class=\"wrap narrow\">\n\
         <nav class=\"crumbs\" aria-label=\"Breadcrumb\"><a href=\"{site_path}\">&larr; {name}</a></nav>\n\
         <div class=\"pagehead\"><div>\n<h1>Roll back {name}?</h1>\n\
         <p class=\"sub\">This puts an earlier deployment live{place} straight away. Nothing is \
         deleted: you can roll forward again from the same list.</p>\n</div></div>\n\
         <section class=\"panel\">\n<dl class=\"facts\">\n\
         <dt>Goes live</dt><dd>{what}<br><span class=\"muted\">{when}</span></dd>\n\
         {replaces}</dl>\n\
         <form method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" name=\"to\" value=\"{id}\">\
         <div class=\"actions\"><button class=\"btn primary danger-fill\" type=\"submit\">Roll back now</button>\
         <a class=\"btn\" href=\"{site_path}\">Cancel</a></div></form>\n\
         </section>\n</main>\n",
        name = esc(&site.name),
        what = candidate_words(to),
        when = time_html(&to.at, now),
        action = esc(&rollback_path(&site.id)),
        id = esc(&to.id),
    );
    signed_in_layout(&format!("Roll back {}", site.name), Tab::Sites, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(id: &str) -> Site {
        serde_json::from_value(serde_json::json!({
            "id": id, "name": "kaje", "kind": "pages",
        }))
        .unwrap()
    }

    #[test]
    fn only_pages_production_and_workers_have_a_target() {
        assert_eq!(
            target(&site("pages:acct:kaje")),
            Some(Target::Pages { account: "acct".into(), project: "kaje".into() })
        );
        assert_eq!(
            target(&site("worker:acct:api-staging")),
            Some(Target::Worker { account: "acct".into(), script: "api-staging".into() })
        );
        assert_eq!(target(&site("pages:acct:kaje:feature/x")), None, "a preview");
        assert_eq!(target(&site("zone:abc")), None);
        assert_eq!(target(&site("pages::kaje")), None);
        assert_eq!(target(&site("worker:acct:")), None);
    }

    #[test]
    fn the_rollback_calls_are_the_documented_ones_with_segments_encoded() {
        let pages = Target::Pages { account: "a1".into(), project: "kaje".into() };
        assert_eq!(
            pages.rollback_request("d/../x"),
            ("/accounts/a1/pages/projects/kaje/deployments/d%2F..%2Fx/rollback".to_owned(), None)
        );
        let worker = Target::Worker { account: "a1".into(), script: "api".into() };
        let (path, body) = worker.rollback_request("v-1");
        assert_eq!(path, "/accounts/a1/workers/scripts/api/deployments");
        let body: serde_json::Value = serde_json::from_str(&body.unwrap()).unwrap();
        assert_eq!(body["strategy"], "percentage");
        assert_eq!(body["versions"][0]["version_id"], "v-1");
        assert_eq!(body["versions"][0]["percentage"], 100);
    }

    #[test]
    fn pages_candidates_are_the_successful_ones_with_the_live_one_marked() {
        let deployments: Vec<PagesDeployment> = serde_json::from_value(serde_json::json!([
            { "id": "d3", "created_on": "2026-10-15T10:00:00Z",
              "latest_stage": { "name": "deploy", "status": "failure" } },
            { "id": "d2", "created_on": "2026-10-14T10:00:00Z",
              "latest_stage": { "name": "deploy", "status": "success" },
              "deployment_trigger": { "type": "github:push", "metadata": {
                  "commit_hash": "4a1f9c2e7b", "branch": "main", "commit_message": "fix" } } },
            { "id": "d1", "created_on": "2026-10-13T10:00:00Z",
              "latest_stage": { "name": "deploy", "status": "success" } }
        ]))
        .unwrap();
        let candidates = pages_candidates(deployments, Some("d2"));
        let ids: Vec<&str> = candidates.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["d2", "d1"]);
        assert!(candidates[0].live && !candidates[1].live);
        assert_eq!(allowed(&candidates, "d1").map(|c| c.id.as_str()), Some("d1"));
        assert!(allowed(&candidates, "d2").is_none(), "the live one is not a rollback");
        assert!(allowed(&candidates, "d3").is_none(), "a failed build is not offered");
        assert!(allowed(&candidates, "anything").is_none());
        assert_eq!(
            candidate_words(&candidates[0]),
            "<code>4a1f9c2</code> · main · <span class=\"msg\">fix</span> · git push"
        );
    }

    #[test]
    fn worker_versions_read_either_shape_and_keep_ten_plus_the_live_one() {
        let items: Vec<serde_json::Value> = (0..15)
            .map(|n| {
                serde_json::json!({ "id": format!("v{n}"), "number": 100 - n,
                "metadata": { "created_on": "2026-10-15T10:00:00Z", "source": "wrangler" } })
            })
            .collect();
        let wrapped: WorkerVersions =
            serde_json::from_value(serde_json::json!({ "items": items.clone() })).unwrap();
        let flat: WorkerVersions = serde_json::from_value(serde_json::json!(items)).unwrap();
        for versions in [wrapped, flat] {
            let candidates = worker_candidates(versions, Some("v12"));
            assert_eq!(candidates.len(), CANDIDATES + 1);
            assert!(candidates.iter().any(|c| c.id == "v12" && c.live));
            assert!(candidates.iter().all(|c| c.id != "v13"));
        }
    }

    #[test]
    fn the_panel_and_confirm_page_escape_and_post_to_the_site() {
        let mut kaje = site("pages:acct:kaje");
        kaje.domains = vec!["kaje.example".into()];
        let candidates = vec![
            Candidate {
                id: "live".into(),
                at: "2026-10-15T10:00:00Z".into(),
                commit: None,
                branch: None,
                message: None,
                source: None,
                number: None,
                live: true,
            },
            Candidate {
                id: "old\"><script>".into(),
                at: "2026-10-14T10:00:00Z".into(),
                commit: Some("abcdef0123".into()),
                branch: None,
                message: Some("<b>msg</b>".into()),
                source: None,
                number: None,
                live: false,
            },
        ];
        let html =
            panel_html(&kaje, &Panel::Candidates(candidates.clone()), "2026-10-16T10:00:00Z");
        assert!(html.contains("action=\"/console/fleet/pages:acct:kaje/rollback\""), "{html}");
        assert!(!html.contains("<script>") && html.contains("&lt;b&gt;msg"));
        assert_eq!(html.matches("Roll back to this").count(), 1, "not for the live one");
        let page =
            confirm_page(&kaje, &candidates[1], Some(&candidates[0]), "2026-10-16T10:00:00Z");
        assert!(page.contains("method=\"post\""));
        assert!(page.contains("<strong>kaje.example</strong>"));
        assert!(page.contains("value=\"old&quot;&gt;&lt;script&gt;\""));
        assert!(panel_html(&kaje, &Panel::NotSupported, "t").is_empty());
        assert!(panel_html(&kaje, &Panel::NoDeployToken, "t").contains("#rollbacks"));
    }
}
