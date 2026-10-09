//! The four routes of `/v1/approvals`. The runner's two carry the deployment's
//! runner token; the approver's two need a signed-in caller whose subject id is
//! a GitHub login, checked against team membership at the click.

use cratefield_core::axum;
use cratefield_core::axum::extract::{Path, State};
use cratefield_core::axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use cratefield_core::axum::response::{IntoResponse, Response};
use cratefield_core::axum::routing::{get, post};
use cratefield_core::{
    Auth, AuthError, Caller, Database, HttpClient, IdGen, Json, ModuleConfig, ModuleContext,
    Outbox, Problem, ProblemDef, RequestStream, SLUGS, UlidIdGen, bearer_token, constant_time_eq,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::store::{self, Artifact, DecisionRow, RequestRow};
use crate::{
    DEFAULT_TTL_SECS, EVENT_TYPE, MAX_TTL_SECS, OUTBOX_TABLE, SUMMARY_LIMIT_BYTES, TOPIC_DISPATCH,
    github, sign, validate,
};
use github::Membership;

const fn def(
    slug: &'static str,
    status: StatusCode,
    title: &'static str,
    description: &'static str,
) -> ProblemDef {
    ProblemDef { slug, status, title, description }
}

/// The runner's fix is on the runner's side, and it is a specific constant.
pub(crate) const SUMMARY_TOO_LARGE: ProblemDef = def(
    "summary-too-large",
    StatusCode::PAYLOAD_TOO_LARGE,
    "Plan summary too large",
    "Over the hosted 64 KiB ceiling; render the plan with \
     `plan_summary::Limits { max_bytes: HOSTED_BODY_LIMIT }` and resend.",
);
const ALREADY_DECIDED: ProblemDef =
    def("already-decided", StatusCode::CONFLICT, "Already decided", "The first answer stands.");
/// 410 rather than 409: the request is still there, and nobody may decide it now.
const APPROVAL_EXPIRED: ProblemDef = def(
    "approval-expired",
    StatusCode::GONE,
    "Approval request expired",
    "This request passed its expiry; park a new one.",
);
const PROPOSER_CANNOT_APPROVE: ProblemDef = def(
    "proposer-cannot-approve",
    StatusCode::FORBIDDEN,
    "The proposer cannot approve their own request",
    "The login that parked this step is not allowed to decide it.",
);
const NOT_A_TEAM_MEMBER: ProblemDef = def(
    "not-a-team-member",
    StatusCode::FORBIDDEN,
    "Not a member of the reviewing team",
    "The signed-in login is not an active member of the team this request asked.",
);
/// 503, not 403: the membership was never established. A reviewer whose team
/// rejected them and a reviewer GitHub would not answer about must not be told
/// the same thing.
const MEMBERSHIP_UNCHECKED: ProblemDef = def(
    "membership-unchecked",
    StatusCode::SERVICE_UNAVAILABLE,
    "Team membership could not be checked",
    "GitHub did not answer the membership lookup; the decision was not evaluated. Try again.",
);
const CROSS_SITE: ProblemDef = def(
    "cross-site-decision",
    StatusCode::FORBIDDEN,
    "Cross-site decision refused",
    "A decision must be posted from this deployment's own origin.",
);
const UNSUPPORTED_MEDIA: ProblemDef = def(
    "unsupported-media-type",
    StatusCode::UNSUPPORTED_MEDIA_TYPE,
    "Unsupported decision body",
    "Post a decision as `application/json`, or as the review form's \
     `application/x-www-form-urlencoded`.",
);
const NOT_A_LOGIN: ProblemDef = def(
    "approver-not-a-login",
    StatusCode::FORBIDDEN,
    "The signed-in identity is not a GitHub login",
    "This module signs decisions with the login; an identity that is not one \
     cannot be looked up on a team.",
);

/// Generous for a run id, step, repo or handle, and short enough that none can
/// push the summary's ceiling out by a field.
const MAX_FIELD: usize = 256;
const MAX_COMMENT: usize = 4 * 1024;
const MAX_ARTIFACTS: usize = 64;

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
}

pub(crate) fn router(ctx: ModuleContext) -> axum::Router {
    let state = Arc::new(ModuleState { ctx: Arc::new(ctx) });
    axum::Router::new()
        .route("/requests", post(create_request))
        .route("/requests/{ticket}", get(read_request))
        .route("/requests/{ticket}/review", get(review_page))
        .route("/requests/{ticket}/decision", post(decide))
        .with_state(state)
}

/// `POST /requests`: park a step. The body arrives as a [`RequestStream`] rather
/// than through [`Json`] because the harness's buffered ceiling is 64 KiB —
/// see [`crate::STREAMED`].
async fn create_request(
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    mut body: RequestStream,
) -> Result<Response, Problem> {
    require_runner(&state.ctx, &headers)?;
    let db = state.db()?;
    let mut raw = Vec::new();
    while let Some(chunk) = body.next_chunk().await {
        let chunk = chunk.map_err(|err| {
            Problem::request_too_large()
                .with_detail(format!("the request body stopped reading: {err}"))
        })?;
        raw.extend_from_slice(&chunk);
    }
    let body: CreateRequest = serde_json::from_slice(&raw)
        .map_err(|err| validation(format!("not a valid approval request: {err}")))?;

    let size = body.summary.len();
    if size > SUMMARY_LIMIT_BYTES {
        return Err(Problem::new(&SUMMARY_TOO_LARGE)
            .with_detail(format!(
                "the plan summary is {size} bytes; a hosted summary may be at most \
                 {SUMMARY_LIMIT_BYTES} bytes (64 KiB). Render the plan with \
                 `plan_summary::Limits {{ max_bytes: HOSTED_BODY_LIMIT }}` and resend."
            ))
            .with_extension("limit", SUMMARY_LIMIT_BYTES)
            .with_extension("size", size));
    }

    let step = check_fields(&body)?;
    let (repo_owner, repo_name) = validate::pair(&body.repo, "repo")?;
    let (team_org, team_slug) = validate::pair(&body.team, "team")?;
    let settings = config(&state.ctx);
    let orgs = validate::orgs(&settings.get_str("GITHUB_ORGS", ""));
    validate::hosted(&orgs, &repo_owner, &team_org)?;

    let now = crate::clock(&state.ctx).now();
    let ceiling = settings
        .get_opt("MAX_TTL_SECS")
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(MAX_TTL_SECS);
    let ttl = body.ttl_secs.unwrap_or(DEFAULT_TTL_SECS).clamp(1, ceiling.max(1));
    let row = RequestRow {
        ticket: state.mint_id(),
        run_id: body.run_id.trim().to_owned(),
        repo: format!("{repo_owner}/{repo_name}"),
        step,
        summary: body.summary,
        artifacts: body.artifacts,
        team_org,
        team_slug,
        proposed_by: body.proposed_by.trim().to_owned(),
        reason: body.reason,
        created_at: rfc3339(now),
        expires_at: rfc3339(now + time::Duration::seconds(i64::try_from(ttl).unwrap_or(i64::MAX))),
    };
    store::insert_request(&*db, &row).await?;

    let base = settings.get_str("PUBLIC_BASE_URL", "");
    let review =
        format!("{}/v1/approvals/requests/{}/review", base.trim_end_matches('/'), row.ticket);
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "ticket": row.ticket, "review_url": review, "expires_at": row.expires_at
        })),
    )
        .into_response())
}

/// `GET /requests/{ticket}`: what the runner polls.
async fn read_request(
    State(state): State<Arc<ModuleState>>,
    Path(ticket): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    require_runner(&state.ctx, &headers)?;
    let db = state.db()?;
    let row = require_request(&*db, &ticket).await?;
    let decision = store::find_decision(&*db, &ticket).await?;
    Ok(Json(request_json(&row, decision.as_ref(), crate::clock(&state.ctx).now())).into_response())
}

/// `GET /requests/{ticket}/review`: the page a person reads.
async fn review_page(
    State(state): State<Arc<ModuleState>>,
    Path(ticket): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    let caller = require_caller(&state.ctx, &headers).await?;
    let db = state.db()?;
    let row = require_request(&*db, &ticket).await?;
    let decision = store::find_decision(&*db, &ticket).await?;
    let base = config(&state.ctx).get_str("PUBLIC_BASE_URL", "");
    let action =
        format!("{}/v1/approvals/requests/{}/decision", base.trim_end_matches('/'), row.ticket);
    let html =
        review_html(&row, decision.as_ref(), crate::clock(&state.ctx).now(), &caller, &action);
    let type_ = (header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    Ok((StatusCode::OK, [type_], html).into_response())
}

/// `POST /requests/{ticket}/decision`: the click. The checks run in the order a
/// reader would apply them, so a refusal names the first thing wrong rather than
/// a consequence of it.
async fn decide(
    State(state): State<Arc<ModuleState>>,
    Path(ticket): Path<String>,
    headers: HeaderMap,
    mut stream: RequestStream,
) -> Result<Response, Problem> {
    let body = decision_body(&state.ctx, &headers, &mut stream).await?;
    let caller = require_caller(&state.ctx, &headers).await?;
    let db = state.db()?;
    let row = require_request(&*db, &ticket).await?;

    let decision = match body.decision.as_str() {
        "approve" => "approved",
        "deny" => "denied",
        other => return Err(validation(format!("{other:?} is not `approve` or `deny`"))),
    };
    if body.comment.len() > MAX_COMMENT {
        let got = body.comment.len();
        return Err(validation(format!("a comment may be at most {MAX_COMMENT} bytes, got {got}")));
    }
    if store::find_decision(&*db, &ticket).await?.is_some() {
        return Err(Problem::new(&ALREADY_DECIDED));
    }
    let now = crate::clock(&state.ctx).now();
    if now > parse_rfc3339(&row.expires_at) {
        let at = row.expires_at.clone();
        return Err(Problem::new(&APPROVAL_EXPIRED).with_detail(format!("it expired at {at}")));
    }
    // GitHub logins are case-insensitive: "Ada" parked this step is "ada".
    let approver = caller.subject().map_or_else(String::new, |subject| subject.id.clone());
    // The login goes into a GitHub URL, so it is held to a charset before it is
    // interpolated anywhere. A subject like `ada/../x` is not a login this
    // deployment could look up, whatever the identity provider minted.
    if !validate::login(&approver) {
        return Err(
            Problem::new(&NOT_A_LOGIN).with_detail(format!("{approver:?} is not a GitHub login"))
        );
    }
    if approver.eq_ignore_ascii_case(&row.proposed_by) {
        return Err(Problem::new(&PROPOSER_CANNOT_APPROVE)
            .with_detail(format!("{approver} parked this step and cannot decide it")));
    }

    // Membership is read at the click, never carried over from the request.
    let config = config(&state.ctx);
    let api = github::GitHub::new(
        state.http()?,
        config.get_str("GITHUB_TOKEN", ""),
        config.get_str("GITHUB_API_BASE", github::API_BASE),
    );
    match api.membership(&row.team_org, &row.team_slug, &approver).await {
        Membership::Active => {}
        Membership::NotMember => {
            let team = format!("{}/{}", row.team_org, row.team_slug);
            return Err(Problem::new(&NOT_A_TEAM_MEMBER)
                .with_detail(format!("{approver} is not an active member of {team}")));
        }
        Membership::Unknown(why) => {
            return Err(Problem::new(&MEMBERSHIP_UNCHECKED)
                .with_detail(format!("membership of {approver} could not be checked: {why}")));
        }
    }

    // Fail closed, exactly as the runner token does: an HMAC keyed with the
    // empty string is a signature anybody can reproduce, so there is none.
    let secret = config.get_str("SIGNING_SECRET", "");
    if secret.is_empty() {
        return Err(Problem::not_ready("SIGNING_SECRET is empty; nothing can be signed"));
    }
    let decided_at = rfc3339(now);
    let canonical = sign::canonical(&row, decision, &approver, &decided_at);
    let signature = sign::sign(secret.as_bytes(), &canonical);
    let comment = body.comment.trim();
    let decided = DecisionRow {
        ticket: row.ticket.clone(),
        approver: approver.clone(),
        decision: decision.to_owned(),
        comment: (!comment.is_empty()).then(|| comment.to_owned()),
        decided_at: decided_at.clone(),
        signature,
    };

    // One commit: the decision and the dispatch announcing it. Split across two,
    // a run can be released by a dispatch for a rolled-back decision, or parked
    // for ever behind one whose dispatch never shipped.
    let dispatch = Outbox::new(OUTBOX_TABLE).enqueue_statement(
        &state.mint_id(),
        TOPIC_DISPATCH,
        &dispatch_payload(&row, &decided),
        Some(&decided.approver),
        &decided_at,
    );
    if let Err(error) = db.batch_atomic(&store::decision_batch(&decided, dispatch)).await {
        // A second click can commit between the pre-check above and this write.
        // The constraint refusing us is then the whole answer, not a 500.
        if store::find_decision(&*db, &ticket).await?.is_some() {
            return Err(Problem::new(&ALREADY_DECIDED));
        }
        return Err(error.into());
    }

    // Best effort: the decision is durable, and this only shortens how long an
    // open review page takes to notice.
    if let Some(realtime) = state.ctx.ports.realtime.clone() {
        let room = format!("approvals/{}", row.ticket);
        let announced = request_json(&row, Some(&decided), now).to_string();
        if let Err(error) = realtime.broadcast(&room, announced.as_bytes()).await {
            tracing::warn!(error = %error, ticket = %row.ticket, "the announcement did not reach the room");
        }
    }

    Ok(Json(request_json(&row, Some(&decided), now)).into_response())
}

impl ModuleState {
    fn db(&self) -> Result<Arc<dyn Database>, Problem> {
        self.ctx
            .ports
            .db
            .clone()
            .ok_or_else(|| Problem::not_ready("this deployment wired no database"))
    }

    fn http(&self) -> Result<Arc<dyn HttpClient>, Problem> {
        self.ctx
            .ports
            .http
            .clone()
            .ok_or_else(|| Problem::not_ready("this deployment wired no http client"))
    }

    fn mint_id(&self) -> String {
        self.ctx.ports.id_gen.as_deref().map_or_else(|| UlidIdGen.ulid(), IdGen::ulid)
    }
}

fn config(ctx: &ModuleContext) -> ModuleConfig<'_> {
    ModuleConfig::new("approvals", &*ctx.config)
}

/// The runner's proof: the deployment's runner token, in constant time. Absent
/// configuration refuses, so a deployment that forgot the key has no open route.
fn require_runner(ctx: &ModuleContext, headers: &HeaderMap) -> Result<(), Problem> {
    let expected = config(ctx).get_opt("RUNNER_TOKEN").unwrap_or_default();
    let presented = bearer_token(headers).unwrap_or_default();
    if expected.is_empty() || !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        let detail = "present the deployment's runner token as a bearer";
        return Err(Problem::new(&SLUGS.api_key_unauthorized).with_detail(detail));
    }
    Ok(())
}

/// The approver's proof: a signed-in caller. `Caller` is `#[non_exhaustive]`, so
/// a caller kind this build does not know is nobody this module treats as an
/// approver — and a caller who cannot sign in is told so.
async fn require_caller(ctx: &ModuleContext, headers: &HeaderMap) -> Result<Caller, Problem> {
    let auth = ctx
        .ports
        .auth
        .clone()
        .ok_or_else(|| Problem::not_ready("this deployment wired no identity provider"))?;
    match auth.identify(headers).await {
        Ok(caller @ Caller::Subject(_)) => Ok(caller),
        Ok(_) | Err(AuthError::NotVerified) => Err(Problem::new(&SLUGS.unauthenticated)
            .with_detail("sign in to review; the approver is the signed-in GitHub login")),
        Err(other) => {
            tracing::warn!(error = %other, "the auth port could not identify the caller");
            Err(Problem::new(&SLUGS.not_ready).with_detail("the identity provider did not answer"))
        }
    }
}

async fn require_request(db: &dyn Database, ticket: &str) -> Result<RequestRow, Problem> {
    let found = store::find_request(db, ticket).await?;
    found.ok_or_else(|| Problem::not_found().with_detail("no approval request carries that ticket"))
}

/// The request as the runner reads it. The polling route, the decision response
/// and the room announcement all answer from here, so none can drift.
fn request_json(row: &RequestRow, decision: Option<&DecisionRow>, now: OffsetDateTime) -> Value {
    let state = state_of(row, decision, now);
    let mut body = json!({
        "ticket": row.ticket, "state": state, "run_id": row.run_id, "repo": row.repo,
        "step": row.step, "team": format!("{}/{}", row.team_org, row.team_slug),
        "proposed_by": row.proposed_by, "reason": row.reason, "artifacts": row.artifacts,
        "created_at": row.created_at, "expires_at": row.expires_at,
    });
    if let Some(decision) = decision.filter(|_| state != "expired") {
        let canonical =
            sign::canonical(row, &decision.decision, &decision.approver, &decision.decided_at);
        body["decision"] = json!({
            "approver": decision.approver, "decision": decision.decision,
            "comment": decision.comment, "decided_at": decision.decided_at,
            "signature": decision.signature, "artifacts": row.artifacts, "canonical": canonical,
        });
    }
    body
}

/// `pending`, `approved`, `denied` or `expired`, against the server's clock — a
/// runner cannot hold a request open by restating its own deadline.
fn state_of(row: &RequestRow, decision: Option<&DecisionRow>, now: OffsetDateTime) -> &'static str {
    match decision {
        Some(decided) if decided.decision == "approved" => "approved",
        Some(_) => "denied",
        None if now > parse_rfc3339(&row.expires_at) => "expired",
        None => "pending",
    }
}

/// The outbox record: the destination, and the body GitHub will receive.
/// `repo` stays beside the body rather than inside it — GitHub's
/// `repository_dispatch` documents only `event_type` and `client_payload`, and
/// an undocumented top-level key risks a permanent 422 on every dispatch.
fn dispatch_payload(row: &RequestRow, decision: &DecisionRow) -> String {
    // `client_payload` allows at most ten top-level properties; nine below.
    let client_payload = json!({
        "ticket": row.ticket, "run": row.run_id, "repo": row.repo, "step": row.step,
        "decision": decision.decision, "approver": decision.approver,
        "decided_at": decision.decided_at, "signature": decision.signature,
        "artifacts": row.artifacts,
    });
    json!({
        "repo": row.repo,
        "body": {"event_type": EVENT_TYPE, "client_payload": client_payload},
    })
    .to_string()
}

fn validation(detail: impl Into<String>) -> Problem {
    Problem::validation_failed(detail)
}

/// Every field that reaches a signature, a URL or the decision table is checked
/// by [`validate`] first; this only reports the ones a caller most often gets
/// wrong, and returns the trimmed step.
fn check_fields(body: &CreateRequest) -> Result<String, Problem> {
    for (name, value) in [("run_id", &body.run_id), ("step", &body.step)] {
        if !validate::run_field(value) {
            return Err(validation(format!("{name} must be 1-128 characters of [A-Za-z0-9._:-]")));
        }
    }
    if !validate::login(&body.proposed_by) {
        return Err(validation("proposed_by must be a GitHub login: [A-Za-z0-9-]{1,39}"));
    }
    if body.reason.len() > MAX_FIELD {
        return Err(validation(format!("reason may be at most {MAX_FIELD} bytes")));
    }
    if body.artifacts.len() > MAX_ARTIFACTS {
        let got = body.artifacts.len();
        return Err(validation(format!("at most {MAX_ARTIFACTS} artifacts, got {got}")));
    }
    for artifact in &body.artifacts {
        if !validate::artifact_name(&artifact.name) {
            return Err(validation(
                "an artifact name must be 1-256 bytes with no control characters",
            ));
        }
        if !validate::sha256(&artifact.sha256) {
            return Err(validation(format!(
                "the digest of {} must be 64 lower-case hex digits",
                artifact.name
            )));
        }
    }
    Ok(body.step.trim().to_owned())
}

/// RFC 3339 to the second in UTC, the spelling both tables store: lexicographic
/// order on it is chronological, which is what the expiry compare relies on.
fn rfc3339(at: OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    at.replace_nanosecond(0).unwrap_or(at).format(&Rfc3339).unwrap_or_default()
}

/// An unreadable stored timestamp reads as "long expired", never as "never".
fn parse_rfc3339(stamp: &str) -> OffsetDateTime {
    time::OffsetDateTime::parse(stamp, &Rfc3339).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

/// The review page. Everything the run controls — the summary above all — is
/// escaped: this is a page with an approve button beside attacker prose.
fn review_html(
    row: &RequestRow,
    decision: Option<&DecisionRow>,
    now: OffsetDateTime,
    caller: &Caller,
    action: &str,
) -> String {
    let artifacts: String = row
        .artifacts
        .iter()
        .map(|a| {
            format!(
                "<li><code>{name}</code> <code>{sha}</code></li>\n",
                name = escape(&a.name),
                sha = escape(&a.sha256)
            )
        })
        .collect();
    let banner = match decision {
        Some(decided) => format!(
            "<p class=\"decided\">{} by <code>{}</code> at <code>{}</code>.</p>",
            escape(&decided.decision),
            escape(&decided.approver),
            escape(&decided.decided_at)
        ),
        None if now > parse_rfc3339(&row.expires_at) => {
            "<p class=\"expired\">This request expired and can no longer be decided.</p>".to_owned()
        }
        // The action is the absolute URL the review link was built under, so the
        // `Origin` the browser sends back matches the one we compare against.
        None => format!(
            "<form method=\"post\" action=\"{action}\">\
             <textarea name=\"comment\" rows=\"4\"></textarea>\
             <button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button> \
             <button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form>\n",
            action = escape(action)
        ),
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>Approve {step} on {run}</title></head><body>\n\
<h1>Approve <code>{step}</code> on <code>{run}</code> in <code>{repo}</code></h1>\n\
<p>Proposed by <code>{proposer}</code>, reason: {reason}. Any active member of <code>{team}</code> \
may decide; signed in as <code>{viewer}</code>. Expires <code>{expiry}</code>.</p>\n\
{banner}\
<h2>What you are approving</h2><pre class=\"summary\">{summary}</pre>\n\
<h2>Artifacts</h2><ul class=\"artifacts\">\n{artifacts}</ul>\n</body></html>\n",
        step = escape(&row.step),
        run = escape(&row.run_id),
        repo = escape(&row.repo),
        reason = escape(&row.reason),
        proposer = escape(&row.proposed_by),
        team = escape(&format!("{}/{}", row.team_org, row.team_slug)),
        viewer = escape(caller.subject().map_or("nobody", |subject| subject.id.as_str())),
        expiry = escape(&row.expires_at),
        summary = escape(&row.summary),
    )
}

/// The five characters that can break out of an HTML text node or attribute, and
/// no more. The ampersand goes first, so no escape is itself escaped.
fn escape(text: &str) -> String {
    let five = [('&', "&amp;"), ('<', "&lt;"), ('>', "&gt;"), ('"', "&quot;"), ('\'', "&#39;")];
    five.iter().fold(text.to_owned(), |out, (from, to)| out.replace(*from, to))
}

/// What a runner sends to park a step. The approver is never a field here: it is
/// the signed-in caller.
#[derive(Debug, Deserialize)]
struct CreateRequest {
    run_id: String,
    repo: String,
    step: String,
    summary: String,
    #[serde(default)]
    artifacts: Vec<Artifact>,
    team: String,
    proposed_by: String,
    #[serde(default)]
    reason: String,
    ttl_secs: Option<u64>,
}

/// What an approver sends: the outcome and, optionally, why.
#[derive(Debug, Default, Deserialize)]
struct DecisionBody {
    decision: String,
    #[serde(default)]
    comment: String,
}

/// The decision body, whichever way it was sent: the review page's form posts
/// `application/x-www-form-urlencoded`, an API client posts JSON. Anything else
/// is a 415 — accepting an arbitrary content type is what let a
/// `fetch(..., {mode: "no-cors", headers: {"Content-Type": "text/plain"}})`
/// reach the JSON branch with no preflight at all.
///
/// The CSRF guard is separate and applies to both: a browser attaches `Origin`
/// to every cross-site POST, so if one is present it must be ours. The form
/// branch also *requires* it, because a form post is the path a page takes
/// without asking the approver anything. JSON without an `Origin` is an API
/// client, which a browser cannot be.
async fn decision_body(
    ctx: &ModuleContext,
    headers: &HeaderMap,
    stream: &mut RequestStream,
) -> Result<DecisionBody, Problem> {
    let mut raw = Vec::new();
    while let Some(chunk) = stream.next_chunk().await {
        let chunk = chunk.map_err(|err| {
            Problem::request_too_large()
                .with_detail(format!("the request body stopped reading: {err}"))
        })?;
        raw.extend_from_slice(&chunk);
    }
    let ours = origin_of(&config(ctx).get_str("PUBLIC_BASE_URL", ""));
    let offered = headers.get(header::ORIGIN).and_then(|value| value.to_str().ok());
    if offered.is_some_and(|origin| origin != ours) {
        return Err(Problem::new(&CROSS_SITE)
            .with_detail(format!("a decision must come from {ours}, got {offered:?}")));
    }
    let content_type =
        headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).unwrap_or_default();
    let essence = content_type.split(';').next().unwrap_or_default().trim();
    if essence == "application/x-www-form-urlencoded" {
        if offered.is_none() {
            return Err(Problem::new(&CROSS_SITE).with_detail(format!(
                "a form decision must carry an Origin, and it must be {ours}"
            )));
        }
        let form = String::from_utf8(raw)
            .map_err(|err| validation(format!("the form body is not UTF-8: {err}")))?;
        return Ok(form_decision(&form));
    }
    if essence != "application/json" {
        return Err(Problem::new(&UNSUPPORTED_MEDIA)
            .with_detail(format!("this route reads `application/json`, got {content_type:?}")));
    }
    serde_json::from_slice(&raw).map_err(|err| validation(format!("not a valid decision: {err}")))
}

/// `scheme://authority`, the origin a browser puts in the header and the prefix
/// the review link is built under.
fn origin_of(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    format!("{scheme}://{}", rest.split('/').next().unwrap_or_default())
}

/// `decision=approve&comment=looks+right`, percent-decoded. Two keys, so this is
/// a fold rather than a parser.
fn form_decision(form: &str) -> DecisionBody {
    let mut body = DecisionBody::default();
    for pair in form.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "decision" => body.decision = percent_decode(value),
            "comment" => body.comment = percent_decode(value),
            _ => {}
        }
    }
    body
}

/// `+` is a space and `%XX` is a byte, which is all a browser sends.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let decoded = (byte == b'%' && index + 2 < bytes.len())
            .then(|| std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or_default())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match decoded {
            Some(byte) => {
                out.push(char::from(byte));
                index += 3;
            }
            None if byte == b'+' => {
                out.push(' ');
                index += 1;
            }
            None => {
                out.push(char::from(byte));
                index += 1;
            }
        }
    }
    out
}
