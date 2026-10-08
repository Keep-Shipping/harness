//! Service-free tests of the hosted approval adapters — all in memory, so
//! `cargo test --workspace` never opens a socket. The engine has no `approval`
//! step yet, so these play its part: request, decide, `accepts`, `is_member`, and
//! `journal.approval_granted` with the channel the adapter recorded.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use hmac::Mac;
use ks_core::ids::RunId;
use ks_core::ports::approval::{
    ApprovalChannel, ApprovalError, ApprovalRequest, Artifact, ArtifactKind, Directory, Identity,
    Outcome, Team, Ticket, Verdict,
};
use ks_core::ports::run_log::{RunEvent, RunLog};
use ks_core::ports::secrets::Redactor;
use ks_core::ports::supply_chain::Digest;
use ks_engine::journal::Journal;
use ks_hosted_approvals::{
    Channel, Decision, GitHubSession, HostedApprovals, ReviewForm, SlackError, SlackIdentities,
    WebError, handle_interaction, message, review_page, submit,
};
use ks_testing::approval::FakeDirectory;
use ks_testing::block_on;
use ks_testing::run_log::RecordingRunLog;

const TEAM: &str = "@acme-deployers";
/// Short enough that an unanswered wait is a fast failure, not a slow one.
const PATIENCE: Duration = Duration::from_millis(50);
const GRACE: &str = "grace";
const MALLORY: &str = "mallory";
/// The host's secret for CSRF tokens, and Slack's for signing.
const KEY: &[u8] = b"form-key";
const SECRET: &[u8] = b"signing-secret";
/// The clock and the timestamp both tests read at, a second of Slack's own past.
const NOW: i64 = 1_700_000_000;
const AT: &str = "1700000000";

fn team() -> Team {
    Team::parse(TEAM).expect("a well-formed team handle")
}

/// A plan artifact with `hex` repeated into a sha256 digest.
fn plan(hex: char) -> Artifact {
    Artifact::new(
        ArtifactKind::PlanFile,
        Digest::sha256_from_hex(&hex.to_string().repeat(64)).expect("64 hex digits"),
    )
}

/// Proposed by someone other than the approvers, so "a run never approves
/// itself" does not fire before the interesting checks.
fn request() -> ApprovalRequest {
    ApprovalRequest {
        run: RunId::from_parts(1_700_000_000_000, 7),
        step: "apply-infra".to_string(),
        summary: "3 to create, 1 to destroy".to_string(),
        artifacts: vec![plan('a'), plan('b')],
        from: team(),
        reason: "production deploy".to_string(),
        proposed_by: Identity::human("ada"),
    }
}

/// The roster of the test organisation.
fn directory() -> FakeDirectory {
    FakeDirectory::new()
        .with_member(&team(), Identity::human(GRACE))
        .with_member(&team(), Identity::human("heidi"))
}

/// Asks the channel and hands back the request and its ticket.
fn ask(store: &HostedApprovals) -> (ApprovalRequest, Ticket) {
    let request = request();
    let ticket = block_on(store.request(&request)).expect("the channel accepts a request");
    (request, ticket)
}

/// The review page as the host renders it for `login`.
fn page(request: &ApprovalRequest, ticket: &Ticket) -> String {
    review_page(request, ticket, &GitHubSession::new(GRACE), KEY).expect("the host has a form key")
}

/// What the page rendered, parsed back into a form: a field the page forgets to
/// render would be a decision bound to nothing.
fn form_from(page: &str, outcome: &str) -> ReviewForm {
    let values = |marker: &str| -> Vec<String> {
        page.match_indices(marker)
            .map(|(at, marker)| {
                let rest = &page[at + marker.len()..];
                let value = &rest[..rest.find('"').expect("the field is closed")];
                value
                    .replace("&quot;", "\"")
                    .replace("&#39;", "'")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&amp;", "&")
            })
            .collect()
    };
    let one = |marker: &str| {
        values(marker).into_iter().next().expect("the page carries the field it must")
    };
    ReviewForm {
        ticket: one("name=\"ticket\" value=\""),
        outcome: outcome.to_string(),
        comment: "looks right".to_string(),
        shown: values("name=\"artifact\" value=\""),
        token: one("name=\"token\" value=\""),
    }
}

/// Journals `store`'s answer as the engine's approval step will.
fn journal_answer(
    store: &HostedApprovals,
    ticket: &Ticket,
    request: &ApprovalRequest,
) -> (Verdict, Arc<RecordingRunLog>) {
    let log = Arc::new(RecordingRunLog::new());
    let journal = Journal::new(
        Arc::clone(&log) as Arc<dyn RunLog>,
        Arc::new(Redactor::new()),
        request.run.clone(),
    );
    let channel = store.channel_of(ticket).expect("an answered ticket names its channel");

    let verdict = block_on(store.wait(ticket, PATIENCE)).expect("the approval arrives");
    request.accepts(&verdict).expect("the verdict binds the artifacts asked about");
    assert!(
        block_on(directory().is_member(&verdict.approver, &request.from)).expect("answered"),
        "{} must be on {TEAM}",
        verdict.approver
    );

    let digests: Vec<String> =
        verdict.bound_artifacts.iter().map(|a| a.digest.to_string()).collect();
    let (step, approver) = (&request.step, &verdict.approver.handle);
    if verdict.is_approved() {
        block_on(journal.approval_granted(step, approver, channel.as_str(), digests))
    } else {
        block_on(journal.approval_denied(
            step,
            approver,
            channel.as_str(),
            digests,
            verdict.comment.as_deref().unwrap_or("denied"),
        ))
    }
    .expect("the log takes the entry");
    (verdict, log)
}

/// The `(channel, approver)` a journaled decision recorded.
fn recorded(log: &RecordingRunLog) -> (String, String) {
    let events = log.events();
    assert_eq!(events.len(), 1, "one decision, one event: {events:?}");
    match &events[0] {
        RunEvent::ApprovalGranted { channel, approver, .. }
        | RunEvent::ApprovalDenied { channel, approver, .. } => (channel.clone(), approver.clone()),
        other => panic!("a decision must be journaled as an approval event, got {other:?}"),
    }
}

/// The field a plan that moved after the page went out would send back.
fn moved_field() -> String {
    format!("plan-file|sha256:{}", "c".repeat(64))
}

/// Slack's signature over `body` stamped at `at`, computed here independently of
/// the adapter so that verifying it is not a self-check.
fn signed(at: &str, body: &str) -> String {
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(SECRET)
        .expect("HMAC takes a key of any length");
    mac.update(format!("v0:{at}:").as_bytes());
    mac.update(body.as_bytes());
    let hex: String =
        mac.finalize().into_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
    format!("v0={hex}")
}

/// Posts `payload` to the Slack webhook the way Slack would sign it.
fn from_slack(
    store: &HostedApprovals,
    identities: &SlackIdentities,
    payload: &str,
) -> Result<Verdict, SlackError> {
    handle_interaction(store, identities, SECRET, AT, &signed(AT, payload), payload.as_bytes(), NOW)
}

/// The value the Approve button carries: the ticket and the artifact hash.
fn button_value(posted: &serde_json::Value) -> String {
    posted["blocks"]
        .as_array()
        .and_then(|blocks| {
            blocks
                .iter()
                .find(|block| block["block_id"].is_string())
                .and_then(|block| block["elements"][0]["value"].as_str().map(str::to_string))
        })
        .expect("the message carries buttons that carry a value")
}

/// A `block_actions` payload, with the display names a rename attack would use.
fn interaction(
    store_team: &str,
    user: &str,
    action_id: &str,
    ticket: &Ticket,
    name: &str,
) -> String {
    let value = button_value(&message(&request(), ticket));
    serde_json::json!({
        "type": "block_actions",
        "team": { "id": store_team, "name": "acme" },
        "user": { "id": user, "name": name, "username": name, "real_name": name },
        "actions": [{ "action_id": action_id, "value": value }],
    })
    .to_string()
}

/// Answers on another thread as soon as anything is outstanding, as a request
/// handler or a Slack webhook does.
fn answer_off_thread(store: Arc<HostedApprovals>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for _ in 0..4_000 {
            if let Some(ticket) = store.outstanding().into_iter().next()
                && let Some(request) = store.pending(&ticket)
            {
                // Bound to exactly what the request asked about, as a channel
                // that showed them would.
                let approving = Decision::new(
                    Identity::human(GRACE),
                    Outcome::Approved,
                    request.artifacts,
                    Channel::Web,
                );
                if store.decide(&ticket, approving).is_ok() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("the other thread never answered the ticket");
    })
}

/// The first acceptance criterion: a web decision round trips through the
/// rendered page and reaches the run log with its channel.
#[test]
fn a_web_decision_round_trips_binds_the_digests_and_reaches_the_run_log_as_web() {
    for (outcome, is_approved, comment) in
        [("approve", true, "looks right"), ("deny", false, "not during the freeze")]
    {
        let store = HostedApprovals::new();
        let (request, ticket) = ask(&store);
        let page = page(&request, &ticket);
        let mut form = form_from(&page, outcome);
        form.comment = comment.to_string();

        submit(&store, &GitHubSession::new(GRACE), &form, KEY).expect("the review is recorded");

        let (verdict, log) = journal_answer(&store, &ticket, &request);
        assert_eq!(verdict.is_approved(), is_approved, "{outcome} went the wrong way");
        assert_eq!(verdict.approver, Identity::human(GRACE));
        assert_eq!(verdict.comment.as_deref(), Some(comment));
        assert_eq!(recorded(&log), ("web".to_string(), GRACE.to_string()));
        // Structurally: the page submits exactly these five names, and none of
        // them says who decided — only the session does.
        let fields: BTreeSet<&str> = page
            .match_indices("name=\"")
            .map(|(at, marker)| {
                let rest = &page[at + marker.len()..];
                &rest[..rest.find('"').expect("a closed field")]
            })
            .collect();
        assert_eq!(fields, BTreeSet::from(["ticket", "token", "artifact", "comment", "outcome"]));
    }

    // A plan that changed after the page was rendered releases nothing: the
    // answer binds the digests that were on screen.
    let store = HostedApprovals::new();
    let (request, ticket) = ask(&store);
    let mut moved = form_from(&page(&request, &ticket), "approve");
    moved.shown[1] = moved_field();
    submit(&store, &GitHubSession::new(GRACE), &moved, KEY).expect("the store records it");
    let verdict = block_on(store.wait(&ticket, PATIENCE)).expect("the approval arrives");
    assert!(
        matches!(request.accepts(&verdict), Err(ApprovalError::ArtifactsChanged { .. })),
        "a verdict for different digests must not be accepted: {verdict:?}"
    );

    // A field that is not an artifact at all is refused rather than dropped, so
    // nothing can be approved against an unparsed digest.
    let store = HostedApprovals::new();
    let (request, ticket) = ask(&store);
    let mut broken = form_from(&page(&request, &ticket), "approve");
    broken.shown[1] = "plan-file".to_string();
    let refused = submit(&store, &GitHubSession::new(GRACE), &broken, KEY);
    assert!(matches!(refused, Err(WebError::Malformed(_))), "{refused:?}");
    assert_eq!(block_on(store.poll(&ticket)), Ok(None));
}

/// A form is a token that says "this session was shown this page". One fetched
/// elsewhere, replayed under another session, or signed with any other key must
/// decide nothing.
#[test]
fn a_form_is_only_good_for_the_session_it_was_rendered_for() {
    let store = HostedApprovals::new();
    let (request, ticket) = ask(&store);
    let form = form_from(&page(&request, &ticket), "approve");

    // The token was minted for Grace; Heidi's session does not match it.
    let refused = submit(&store, &GitHubSession::new("heidi"), &form, KEY);
    assert!(
        matches!(refused, Err(WebError::Malformed(_))),
        "another session's form must not decide, got {refused:?}"
    );
    assert_eq!(block_on(store.poll(&ticket)), Ok(None), "and nothing was recorded");

    // Nor does one minted with another key, nor an invented or empty token.
    let other = form_from(
        &review_page(&request, &ticket, &GitHubSession::new(GRACE), b"another-key")
            .expect("that host has a key of its own"),
        "approve",
    );
    for candidate in [other, ReviewForm { token: String::new(), ..form.clone() }] {
        assert!(submit(&store, &GitHubSession::new(GRACE), &candidate, KEY).is_err());
    }
    assert!(submit(&store, &GitHubSession::new(GRACE), &form, b"").is_err(), "no key, no form");
    assert!(review_page(&request, &ticket, &GitHubSession::new(GRACE), b"").is_err());
    assert_eq!(block_on(store.poll(&ticket)), Ok(None), "still nothing recorded");

    // Grace's own form, unchanged, does decide.
    submit(&store, &GitHubSession::new(GRACE), &form, KEY).expect("her own form is hers");
}

/// Everything the run writes reaches a page and a Slack message as text, so
/// both have to escape it — HTML five characters, Slack three — and the escaping
/// has to hold in an attribute as well as in prose.
#[test]
fn everything_the_run_controls_is_escaped_for_html_and_for_mrkdwn() {
    let mut request = request();
    request.summary = "<script>alert('x')</script>".to_string();
    request.reason = "\"><img src=x onerror=alert(1)>".to_string();
    request.step = "apply<script>".to_string();
    request.proposed_by = Identity::human("ada<@here>");
    request.artifacts[1] =
        Artifact::new(ArtifactKind::Other("\"'&<>".to_string()), plan('b').digest);

    let page = page(&request, &Ticket::new("ha-1"));
    assert!(
        !page.contains("<script>") && !page.contains("<img"),
        "markup reached the page:\n{page}"
    );
    for entity in ["&lt;", "&gt;", "&quot;", "&#39;", "&amp;"] {
        assert!(page.contains(entity), "{entity} is missing from the page:\n{page}");
    }
    // The kind name lands in a hidden `value="…"` as well as in prose.
    assert!(
        page.contains("value=\"other: &quot;&#39;&amp;&lt;&gt;|sha256:"),
        "an attribute context must be escaped too:\n{page}"
    );
    assert!(
        !page.contains("&amp;lt;") && !page.contains("&amp;amp;"),
        "an ampersand must be escaped once, not twice:\n{page}"
    );

    let posted = serde_json::to_string(&message(&request, &Ticket::new("ha-1")))
        .expect("the message serialises");
    for raw in ["<script>", "<@here>", "<img", "\u{22}'&<>"] {
        assert!(!posted.contains(raw), "mrkdwn did not escape {raw:?}:\n{posted}");
    }
    assert!(posted.contains("&lt;script&gt;"), "the summary should read as text");
    assert!(
        !posted.contains("&amp;lt;") && !posted.contains("&amp;amp;"),
        "an ampersand must be escaped once, not twice:\n{posted}"
    );
}

/// The second acceptance criterion: a renamed account and an impostor name both
/// decide nothing, and neither leaves a verdict behind.
#[test]
fn a_slack_identity_is_its_immutable_ids_not_its_display_names() {
    let store = HostedApprovals::new();
    let identities = SlackIdentities::default().with("T1", "U1", GRACE);

    // Grace renames her account to look like a colleague, and presses Approve.
    let (_request, ticket) = ask(&store);
    let renamed = interaction("T1", "U1", "approve", &ticket, MALLORY);
    let verdict = from_slack(&store, &identities, &renamed).expect("mapped and allowed");
    assert_eq!(
        verdict.approver,
        Identity::human(GRACE),
        "a renamed account is still the id it was mapped under"
    );

    // A different account that calls itself `grace`, and the same Slack user id
    // arriving from another workspace: neither is mapped, so neither decides.
    for (team_id, user_id, name) in [("T1", "U2", GRACE), ("T2", "U1", GRACE)] {
        let (_request, ticket) = ask(&store);
        let spoofed = interaction(team_id, user_id, "approve", &ticket, name);
        assert_eq!(
            from_slack(&store, &identities, &spoofed),
            Err(SlackError::UnmappedUser {
                team_id: team_id.to_string(),
                user_id: user_id.to_string()
            }),
            "{user_id} in {team_id} must not be able to answer"
        );
        assert_eq!(block_on(store.poll(&ticket)), Ok(None), "no verdict may be recorded");
    }
    assert_eq!(store.outstanding().len(), 2, "both refused tickets are still waiting");
}

/// A Slack decision takes the same run-log path under its own channel id, and a
/// button whose hash no longer describes the request binds nothing.
#[test]
fn a_slack_decision_is_journaled_as_the_slack_channel_and_binds_the_shown_digests() {
    let store = HostedApprovals::new();
    let identities = SlackIdentities::default().with("T1", "U1", GRACE);
    let (request, ticket) = ask(&store);

    let payload = interaction("T1", "U1", "deny", &ticket, GRACE);
    from_slack(&store, &identities, &payload).expect("grace denies in Slack");
    let (verdict, log) = journal_answer(&store, &ticket, &request);
    assert_eq!(verdict.outcome, Outcome::Refused);
    assert_eq!(recorded(&log), ("slack".to_string(), GRACE.to_string()));

    // The button carries a hash of the digests as shown. A message posted for a
    // different artifact list is a hash of the wrong list, so the answer binds
    // nothing and releases nothing.
    let store = HostedApprovals::new();
    let (request, ticket) = ask(&store);
    let mut elsewhere = request.clone();
    elsewhere.artifacts = vec![plan('a'), plan('c')];
    let moved = serde_json::json!({
        "team": { "id": "T1" }, "user": { "id": "U1" },
        "actions": [{
            "action_id": "approve",
            "value": button_value(&message(&elsewhere, &ticket)),
        }],
    })
    .to_string();
    from_slack(&store, &identities, &moved).expect("still a mapped, signed press");
    let verdict = block_on(store.wait(&ticket, PATIENCE)).expect("the approval arrives");
    assert!(
        matches!(request.accepts(&verdict), Err(ApprovalError::ArtifactsChanged { .. })),
        "a button for other digests must not release the run: {verdict:?}"
    );
}

/// The signature scheme, end to end on the real store: the raw request is the
/// only way in, so everything that fails it leaves nothing behind.
#[test]
fn a_slack_interaction_is_only_honoured_over_a_verified_signature() {
    let store = HostedApprovals::new();
    let identities = SlackIdentities::default().with("T1", "U1", GRACE);
    let (request, ticket) = ask(&store);
    let payload = interaction("T1", "U1", "approve", &ticket, GRACE);
    let honest = signed(AT, &payload);
    let sends = |at: &str, sig: &str, body: &str| {
        handle_interaction(&store, &identities, SECRET, at, sig, body.as_bytes(), NOW)
    };

    // Signed and fresh verifies. A body edited after signing, a replay from
    // either direction in time, another scheme, a timestamp that is not a
    // number, one chosen to overflow the skew, and an empty secret are all
    // refused.
    for (at, sig, body, expected) in [
        (AT, &honest, &format!("{payload} "), SlackError::BadSignature),
        ("1700000301", &honest, &payload, SlackError::Stale { skew_seconds: 301 }),
        ("1699999699", &honest, &payload, SlackError::Stale { skew_seconds: 301 }),
        (AT, &"v1=deadbeef".to_string(), &payload, SlackError::BadSignature),
        (&i64::MIN.to_string(), &honest, &payload, SlackError::Stale { skew_seconds: i64::MAX }),
        (
            "later",
            &honest,
            &payload,
            SlackError::Malformed("\"later\" is not a Unix timestamp".into()),
        ),
    ] {
        assert_eq!(sends(at, sig, body), Err(expected.clone()), "{at} {sig}");
    }
    assert_eq!(
        handle_interaction(&store, &identities, b"", AT, &honest, payload.as_bytes(), NOW),
        Err(SlackError::NoSigningSecret),
        "an unconfigured host must not accept what anybody signs"
    );
    assert_eq!(block_on(store.poll(&ticket)), Ok(None), "none of that recorded anything");

    // Neither is a payload that is not an approval, however well signed.
    let not_an_approval = serde_json::json!({
        "team": { "id": "T1" }, "user": { "id": "U1" },
        "actions": [{ "action_id": "delete_everything", "value": "{}" }],
    })
    .to_string();
    assert!(matches!(
        from_slack(&store, &identities, &not_an_approval),
        Err(SlackError::UnknownAction(_))
    ));
    for malformed in ["{ not json", r#"{"user":{"id":"U1"},"actions":[]}"#] {
        assert!(
            matches!(from_slack(&store, &identities, malformed), Err(SlackError::Malformed(_))),
            "{malformed} must be refused"
        );
    }
    assert_eq!(block_on(store.poll(&ticket)), Ok(None), "still nothing recorded");

    // The honest request: sign what Slack would sign and it applies.
    let verdict = sends(AT, &honest, &payload).expect("then it applies");
    assert_eq!(verdict.approver, Identity::human(GRACE));
    request.accepts(&verdict).expect("and it binds the digests shown");
}

/// First decision wins, a ticket this store never minted is never answered, and
/// nobody answering is not an approval.
#[test]
fn a_second_decision_is_refused_and_an_unanswered_ticket_approves_nothing() {
    let store = HostedApprovals::new();
    let (request, ticket) = ask(&store);
    let page = page(&request, &ticket);

    submit(&store, &GitHubSession::new(GRACE), &form_from(&page, "approve"), KEY).expect("first");
    // Heidi renders a legitimate page of her own and finds it already answered:
    // that is what the first answer standing means.
    let heidi = review_page(&request, &ticket, &GitHubSession::new("heidi"), KEY)
        .expect("the host has a form key");
    let second = submit(&store, &GitHubSession::new("heidi"), &form_from(&heidi, "deny"), KEY);
    assert!(
        matches!(second, Err(WebError::Refused(ApprovalError::Unavailable { .. }))),
        "a second decision must be refused, got {second:?}"
    );
    let verdict = block_on(store.wait(&ticket, PATIENCE)).expect("the approval arrives");
    assert_eq!(verdict.approver, Identity::human(GRACE), "the first answer stands");
    assert!(verdict.is_approved());

    // An open ticket, and one this store never minted.
    let (_open, waiting) = ask(&store);
    assert_eq!(block_on(store.poll(&waiting)), Ok(None), "nobody answered yet");
    assert!(matches!(
        block_on(store.wait(&waiting, PATIENCE)),
        Err(ApprovalError::Undecided { .. })
    ));
    assert_eq!(store.outstanding(), vec![waiting.clone()]);
    assert_eq!(store.pending(&waiting).as_ref(), Some(&request));
    let made_up = Ticket::new("ha-9999");
    assert_eq!(
        block_on(store.poll(&made_up)),
        Err(ApprovalError::UnknownTicket { ticket: made_up.as_str().to_string() })
    );
    // Waiting tickets come back oldest first, not in the order their ids sort in:
    // past ten, `ha-10` sorts before `ha-2`.
    let mut in_order = vec![waiting.clone()];
    while in_order.len() < 12 {
        in_order.push(ask(&store).1);
    }
    assert_eq!(store.outstanding(), in_order);
}

/// The shared conformance kit: the same `request`/`wait`/`accepts` walk every
/// approval adapter must pass, answered from a second thread so a `wait` a
/// decision arrives on must survive the blocking call.
#[test]
fn the_approval_conformance_kit_passes() {
    let store = Arc::new(HostedApprovals::new());
    let directory = directory();
    let decider = answer_off_thread(Arc::clone(&store));

    block_on(ks_testing::approval::conformance(
        &*store,
        &directory,
        &team(),
        &Identity::human(GRACE),
    ));
    decider.join().expect("the deciding thread finished");
    assert!(
        !block_on(directory.is_member(&Identity::human(MALLORY), &team())).expect("answered"),
        "the roster still says what it said"
    );
}
