//! The webhook's native tests: the signature (accepted, wrong, missing,
//! malformed), the judging order, and the effect each event asks for.

use super::*;

const SECRET: &[u8] = b"whsec_test_value";

/// `sha256=<hex>` of `body` under `secret`, as GitHub sends it.
fn sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("a key");
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256={hex}")
}

const INSTALL: &[u8] = br#"{"action":"created","installation":{"id":7,
    "account":{"login":"nick","type":"User"},"repository_selection":"all"}}"#;

#[test]
fn a_correct_signature_is_accepted() {
    let header = sign(SECRET, INSTALL);
    assert!(signature_is_valid(SECRET, INSTALL, Some(&header)));
    // Upper-case hex is the same digest.
    assert!(signature_is_valid(
        SECRET,
        INSTALL,
        Some(&header.to_uppercase().replace("SHA256=", "sha256="))
    ));
}

#[test]
fn a_wrong_signature_is_refused() {
    let wrong_secret = sign(b"another secret", INSTALL);
    assert!(!signature_is_valid(SECRET, INSTALL, Some(&wrong_secret)));
    let other_body = sign(SECRET, b"{}");
    assert!(!signature_is_valid(SECRET, INSTALL, Some(&other_body)));
    let mut tampered = sign(SECRET, INSTALL);
    let last = tampered.pop().expect("a digit");
    tampered.push(if last == '0' { '1' } else { '0' });
    assert!(!signature_is_valid(SECRET, INSTALL, Some(&tampered)));
}

#[test]
fn a_missing_or_malformed_signature_is_refused() {
    assert!(!signature_is_valid(SECRET, INSTALL, None));
    assert!(!signature_is_valid(SECRET, INSTALL, Some("")));
    let bare = sign(SECRET, INSTALL).replace("sha256=", "");
    assert!(!signature_is_valid(SECRET, INSTALL, Some(&bare)), "the prefix is required");
    assert!(!signature_is_valid(SECRET, INSTALL, Some("sha256=zz")));
    assert!(!signature_is_valid(SECRET, INSTALL, Some("sha256=abc")), "odd length");
    assert!(!signature_is_valid(SECRET, INSTALL, Some("sha256=")), "empty digest");
    assert!(!signature_is_valid(SECRET, INSTALL, Some("sha1=00")));
}

#[test]
fn a_signature_over_an_empty_body_is_checked_too() {
    let header = sign(SECRET, b"");
    assert!(signature_is_valid(SECRET, b"", Some(&header)));
    assert!(!signature_is_valid(SECRET, b"x", Some(&header)));
}

#[test]
fn an_oversized_body_is_refused_before_anything_else() {
    let big = vec![b' '; MAX_BODY + 1];
    assert_eq!(judge(Some(SECRET), Some("ping"), None, &big), Err(413));
    // Even with no event and no secret, size is the first answer.
    assert_eq!(judge(None, None, None, &big), Err(413));
    // A body at the ceiling is not refused for its size.
    let at_limit = vec![b' '; MAX_BODY];
    assert_ne!(judge(Some(SECRET), Some("ping"), None, &at_limit), Err(413));
}

#[test]
fn the_judging_order_is_event_then_secret_then_signature_then_body() {
    assert_eq!(judge(Some(SECRET), None, None, INSTALL), Err(400), "no event");
    assert_eq!(judge(None, Some("installation"), None, INSTALL), Err(503), "no secret");
    assert_eq!(
        judge(Some(SECRET), Some("installation"), None, INSTALL),
        Err(401),
        "missing signature"
    );
    let header = sign(SECRET, b"{not json");
    assert_eq!(
        judge(Some(SECRET), Some("installation"), Some(&header), b"{not json"),
        Err(400),
        "a verified body that does not parse"
    );
    let header = sign(SECRET, INSTALL);
    assert!(matches!(
        judge(Some(SECRET), Some("installation"), Some(&header), INSTALL),
        Ok(Effect::Save(_))
    ));
}

#[test]
fn a_created_installation_is_saved_with_its_account_and_selection() {
    assert_eq!(
        effect_of("installation", INSTALL),
        Some(Effect::Save(Installation {
            id: 7,
            account: "nick".into(),
            account_type: "User".into(),
            selection: "all".into(),
        }))
    );
}

#[test]
fn deleted_and_suspended_installations_are_removed_and_resumed_ones_saved() {
    let deleted = br#"{"action":"deleted","installation":{"id":9,
        "account":{"login":"x","type":"Organization"}}}"#;
    assert_eq!(effect_of("installation", deleted), Some(Effect::Remove(9)));
    let suspended = br#"{"action":"suspend","installation":{"id":9,
        "account":{"login":"x","type":"Organization"}}}"#;
    assert_eq!(effect_of("installation", suspended), Some(Effect::Remove(9)));
    let resumed = br#"{"action":"unsuspend","installation":{"id":9,
        "account":{"login":"x","type":"Organization"},"repository_selection":"selected"}}"#;
    assert!(
        matches!(effect_of("installation", resumed), Some(Effect::Save(row)) if row.selection == "selected")
    );
    let unknown = br#"{"action":"something_new","installation":{"id":9,
        "account":{"login":"x","type":"Organization"}}}"#;
    assert_eq!(effect_of("installation", unknown), Some(Effect::Nothing));
}

#[test]
fn a_changed_repository_selection_is_recorded_for_its_installation() {
    let changed = br#"{"action":"added","installation":{"id":7,
        "account":{"login":"nick","type":"User"},"repository_selection":"selected"}}"#;
    assert_eq!(
        effect_of("installation_repositories", changed),
        Some(Effect::Selection(7, "selected".into()))
    );
    let without = br#"{"action":"added","installation":{"id":7,
        "account":{"login":"nick","type":"User"}}}"#;
    assert_eq!(effect_of("installation_repositories", without), Some(Effect::Nothing));
}

#[test]
fn a_ping_and_the_events_not_acted_on_change_nothing() {
    assert_eq!(effect_of("ping", b"{\"zen\":\"x\"}"), Some(Effect::Nothing));
    assert_eq!(effect_of("pull_request", b"{\"action\":\"opened\"}"), Some(Effect::Nothing));
    assert_eq!(effect_of("workflow_run", b"{}"), Some(Effect::Nothing));
}

#[test]
fn an_installation_event_without_an_installation_is_malformed() {
    assert_eq!(effect_of("installation", br#"{"action":"created"}"#), None);
    assert_eq!(effect_of("installation", b"not json"), None);
}

#[test]
fn an_effect_does_not_print_the_account_of_a_secret_it_never_carries() {
    // The effect carries the installation's facts only; there is no token or
    // key in it to print.
    let shown = format!("{:?}", effect_of("installation", INSTALL));
    assert!(shown.contains("nick"));
    assert!(!shown.contains("whsec"));
}
