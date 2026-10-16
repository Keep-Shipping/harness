//! The app's native tests: the manifest, the key formats, the JWT, the state
//! rules (against a migrated SQLite database), the installation choice and
//! the token's freshness.

use std::sync::Arc;

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{Database, SqlMigration};
use crypto_box::aead::OsRng;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rsa::{RsaPrivateKey, RsaPublicKey};

use super::*;

const NOW: i64 = 1_800_000_000;
const ME: &str = "Nick@CHI.app ";

fn test_key() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut OsRng, 1024).expect("a test key")
}

/// A database with the console's app tables, from the venture's own migration.
fn database() -> Arc<dyn Database> {
    let db = SqliteDatabase::in_memory().expect("in-memory sqlite");
    db.apply_migrations(
        "console-github-app",
        &[SqlMigration::new(
            "0015",
            "console_github_app",
            include_str!("../../../migrations/0015_console_github_app.sql"),
        )],
    )
    .expect("the app's schema applies");
    Arc::new(db)
}

fn block<T>(future: impl std::future::Future<Output = T>) -> T {
    pollster::block_on(future)
}

#[test]
fn a_coverage_answer_is_used_only_when_it_is_this_apps_and_is_not_stored() {
    let body = r#"{"id":7,"app_id":42,"account":{"login":"Nick","type":"User"},
        "repository_selection":"selected"}"#;
    let found = covering_installation(body, 42).expect("parses").expect("this app's");
    assert_eq!(found.id, 7);
    assert_eq!(covering_installation(body, 99).expect("parses"), None, "another app's");
    assert!(covering_installation("not json", 42).is_err());
    // Nothing is recorded by the lookup itself: the table stays empty.
    let db = database();
    assert!(block(installations(db)).expect("list").is_empty());
}

#[test]
fn the_manifest_names_the_console_its_webhook_and_its_permissions() {
    let manifest = manifest("Keep Shipping console (keep-shipping)");
    assert_eq!(manifest["name"], "Keep Shipping console (keep-shipping)");
    assert_eq!(manifest["url"], "https://console.keepshipping.run");
    assert_eq!(
        manifest["hook_attributes"],
        serde_json::json!({
            "url": "https://console.keepshipping.run/console/github/webhook",
            "active": true
        })
    );
    assert_eq!(
        manifest["redirect_url"],
        "https://console.keepshipping.run/console/connect/github/app/created"
    );
    assert_eq!(
        manifest["setup_url"],
        "https://console.keepshipping.run/console/connect/github/app/installed"
    );
    assert_eq!(manifest["setup_on_update"], true);
    assert_eq!(manifest["public"], true, "installable on any account, not only the creator's");
    assert_eq!(manifest["default_events"], serde_json::json!(["pull_request", "workflow_run"]));
    let permissions = manifest["default_permissions"].as_object().expect("an object");
    let mut keys: Vec<(&str, &str)> = permissions
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str().expect("a string")))
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            ("actions", "read"),
            ("administration", "write"),
            ("contents", "write"),
            ("metadata", "read"),
            ("pull_requests", "write"),
            ("secrets", "write"),
            ("workflows", "write"),
        ]
    );
}

#[test]
fn the_create_target_is_the_organisation_or_the_own_account() {
    assert_eq!(
        create_target(Some("keep-shipping"), "abc"),
        "https://github.com/organizations/keep-shipping/settings/apps/new?state=abc"
    );
    assert_eq!(create_target(None, "abc"), "https://github.com/settings/apps/new?state=abc");
}

#[test]
fn an_organisation_name_is_checked_before_it_is_used() {
    assert_eq!(owner_of("  "), Ok(None));
    assert_eq!(owner_of(" keep-shipping "), Ok(Some("keep-shipping".to_owned())));
    assert!(owner_of("-bad").is_err());
    assert!(owner_of("bad-").is_err());
    assert!(owner_of("has space").is_err());
    assert!(owner_of("a/b").is_err());
    assert!(owner_of(&"a".repeat(40)).is_err());
}

#[test]
fn the_app_name_defaults_and_is_bounded() {
    assert_eq!(name_of(Some("acme"), "").expect("default"), "Keep Shipping console (acme)");
    assert_eq!(name_of(None, "").expect("default"), "Keep Shipping console (personal account)");
    assert_eq!(name_of(None, " Mine ").expect("typed"), "Mine");
    assert!(name_of(None, &"x".repeat(65)).is_err());
    assert!(name_of(None, "two\nlines").is_err());
}

#[test]
fn a_pkcs1_key_and_a_pkcs8_key_both_parse_to_the_same_key() {
    let key = test_key();
    let pkcs1 = key.to_pkcs1_pem(LineEnding::LF).expect("pkcs1 pem");
    let pkcs8 = key.to_pkcs8_pem(LineEnding::LF).expect("pkcs8 pem");
    assert!(pkcs1.contains("BEGIN RSA PRIVATE KEY"));
    assert!(pkcs8.contains("BEGIN PRIVATE KEY"));
    assert_eq!(parse_private_key(&pkcs1).expect("pkcs1 parses"), key);
    assert_eq!(parse_private_key(&pkcs8).expect("pkcs8 parses"), key);
    assert!(parse_private_key("not a key").is_err());
    assert!(parse_private_key("").is_err());
}

#[test]
fn the_app_jwt_is_rs256_with_the_client_id_and_the_clock_claims() {
    let key = test_key();
    let jwt = app_jwt(&key, "Iv1.client", NOW).expect("a jwt");
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "three segments");
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header: serde_json::Value =
        serde_json::from_slice(&engine.decode(parts[0]).expect("base64url")).expect("json");
    assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT"}));
    let claims: serde_json::Value =
        serde_json::from_slice(&engine.decode(parts[1]).expect("base64url")).expect("json");
    assert_eq!(claims["iss"], "Iv1.client");
    assert_eq!(claims["iat"], NOW - 60, "backdated a minute");
    assert_eq!(claims["exp"], NOW + 9 * 60, "nine minutes");

    let signature = Signature::try_from(engine.decode(parts[2]).expect("base64url").as_slice())
        .expect("a signature");
    let public = RsaPublicKey::from(&key);
    VerifyingKey::<Sha256>::new(public)
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .expect("the signature verifies with the public key");

    // A different key does not verify it.
    let other = RsaPublicKey::from(&test_key());
    assert!(
        VerifyingKey::<Sha256>::new(other)
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .is_err()
    );
}

#[test]
fn a_conversion_is_read_and_its_secrets_are_kept_out_of_the_app_row() {
    let body = r#"{"id":42,"slug":"ks","client_id":"Iv1.x","html_url":"https://github.com/apps/ks",
        "owner":{"login":"keep-shipping"},"pem":"-----BEGIN RSA PRIVATE KEY-----",
        "webhook_secret":"whs","client_secret":"cs"}"#;
    let conversion = read_conversion(body).expect("a conversion");
    assert_eq!(conversion.app.app_id, 42);
    assert_eq!(conversion.app.owner, "keep-shipping");
    assert_eq!(conversion.webhook_secret, "whs");
    assert!(!format!("{:?}", conversion.app).contains("whs"));
    assert_eq!(read_conversion("{}").err(), Some(SHAPE));
}

#[test]
fn an_installation_is_read_with_its_app_and_selection() {
    let body = r#"{"id":7,"app_id":42,"account":{"login":"Nick","type":"User"},
        "repository_selection":"selected"}"#;
    let (app_id, installation) = read_installation(body).expect("an installation");
    assert_eq!(app_id, 42);
    assert_eq!(
        installation,
        Installation {
            id: 7,
            account: "Nick".into(),
            account_type: "User".into(),
            selection: "selected".into(),
        }
    );
    assert!(installation.is_user());
    assert!(read_installation(r#"{"id":7}"#).is_err());
}

#[test]
fn a_token_answer_gives_the_token_and_its_expiry() {
    let (token, expires) =
        read_token(r#"{"token":"ghs_x","expires_at":"2026-10-16T10:00:00Z"}"#, NOW).expect("ok");
    assert_eq!(token, "ghs_x");
    let expected = OffsetDateTime::parse("2026-10-16T10:00:00Z", &Rfc3339).expect("a time");
    assert_eq!(expires, expected.unix_timestamp());
    // An expiry that does not parse is trusted for the fallback lifetime.
    let (_, fallback) = read_token(r#"{"token":"t","expires_at":"soon"}"#, NOW).expect("ok");
    assert_eq!(fallback, NOW + FALLBACK_TOKEN_SECS);
    assert!(read_token(r#"{"expires_at":"x"}"#, NOW).is_err());
}

#[test]
fn a_cached_token_is_used_until_five_minutes_before_it_expires() {
    assert!(token_is_fresh(NOW + 3600, NOW));
    assert!(token_is_fresh(NOW + 301, NOW));
    assert!(!token_is_fresh(NOW + 300, NOW), "inside the margin, it is replaced");
    assert!(!token_is_fresh(NOW - 1, NOW));
}

#[test]
fn the_installation_for_an_owner_is_the_matching_account_ignoring_case() {
    let rows = vec![
        Installation {
            id: 1,
            account: "nick".into(),
            account_type: "User".into(),
            selection: "all".into(),
        },
        Installation {
            id: 2,
            account: "Keep-Shipping".into(),
            account_type: "Organization".into(),
            selection: "selected".into(),
        },
    ];
    assert_eq!(pick_installation(&rows, "keep-shipping").map(|row| row.id), Some(2));
    assert_eq!(pick_installation(&rows, "NICK").map(|row| row.id), Some(1));
    assert_eq!(pick_installation(&rows, "someone-else"), None);
    assert_eq!(pick_installation(&[], "nick"), None);
}

#[test]
fn an_installation_links_to_its_own_settings_page() {
    let user = Installation {
        id: 7,
        account: "nick".into(),
        account_type: "User".into(),
        selection: "all".into(),
    };
    assert_eq!(manage_url(&user), "https://github.com/settings/installations/7");
    let org = Installation {
        id: 9,
        account: "keep-shipping".into(),
        account_type: "Organization".into(),
        selection: "selected".into(),
    };
    assert_eq!(
        manage_url(&org),
        "https://github.com/organizations/keep-shipping/settings/installations/9"
    );
    assert_eq!(install_url("ks"), "https://github.com/apps/ks/installations/new");
}

#[test]
fn only_a_plausible_code_is_exchanged() {
    assert!(code_is_plausible("abc123-_"));
    assert!(!code_is_plausible(""));
    assert!(!code_is_plausible("a/b"));
    assert!(!code_is_plausible("a b"));
    assert!(!code_is_plausible(&"a".repeat(129)));
}

#[test]
fn the_app_token_debug_never_shows_the_token() {
    let token = AppToken { token: "ghs_secret_value".into(), user_account: true };
    let shown = format!("{token:?}");
    assert!(!shown.contains("ghs_secret_value"), "{shown}");
    assert!(shown.contains("redacted"));
}

#[test]
fn a_state_is_taken_once_and_only_in_time() {
    let db = database();
    let state = block(issue_state(Arc::clone(&db), NOW, &subject_of(ME))).expect("a state");
    assert_eq!(state.len(), 64, "32 random bytes in hex");
    assert!(state.chars().all(|c| c.is_ascii_hexdigit()));

    assert!(
        block(take_state(Arc::clone(&db), &state, NOW + 60, &subject_of(ME))).expect("take"),
        "first use"
    );
    assert!(
        !block(take_state(Arc::clone(&db), &state, NOW + 61, &subject_of(ME))).expect("take"),
        "second use"
    );
    assert!(!block(take_state(Arc::clone(&db), "not-issued", NOW, &subject_of(ME))).expect("take"));
}

#[test]
fn a_state_expires_after_ten_minutes() {
    let db = database();
    let state = block(issue_state(Arc::clone(&db), NOW, &subject_of(ME))).expect("a state");
    assert!(
        !block(take_state(Arc::clone(&db), &state, NOW + 600, &subject_of(ME))).expect("take"),
        "at ten minutes it is already expired"
    );

    let late = block(issue_state(Arc::clone(&db), NOW, &subject_of(ME))).expect("a state");
    assert!(
        block(take_state(Arc::clone(&db), &late, NOW + 599, &subject_of(ME))).expect("take"),
        "just inside the window it is good"
    );
}

#[test]
fn issuing_a_state_sweeps_the_expired_ones() {
    let db = database();
    let old = block(issue_state(Arc::clone(&db), NOW, &subject_of(ME))).expect("a state");
    block(issue_state(Arc::clone(&db), NOW + 1000, &subject_of(ME))).expect("a later state");
    assert!(
        !block(take_state(Arc::clone(&db), &old, NOW + 1000, &subject_of(ME))).expect("take"),
        "swept"
    );
}

#[test]
fn installations_are_saved_refreshed_selected_and_removed() {
    let db = database();
    let mut row = Installation {
        id: 7,
        account: "nick".into(),
        account_type: "User".into(),
        selection: "selected".into(),
    };
    block(save_installation(Arc::clone(&db), &row, "2026-10-16T09:00:00Z")).expect("save");
    row.selection = "all".into();
    block(save_installation(Arc::clone(&db), &row, "2026-10-16T09:01:00Z")).expect("refresh");
    let listed = block(installations(Arc::clone(&db))).expect("list");
    assert_eq!(listed, vec![row.clone()], "one row, refreshed in place");

    block(set_selection(Arc::clone(&db), 7, "selected")).expect("selection");
    assert_eq!(block(installations(Arc::clone(&db))).expect("list")[0].selection, "selected");

    block(remove_installation(Arc::clone(&db), 7)).expect("remove");
    assert!(block(installations(db)).expect("list").is_empty());
}

#[test]
fn the_app_row_reads_back_and_is_absent_before_it_is_created() {
    let db = database();
    assert_eq!(block(app_row(Arc::clone(&db))).expect("read"), None);
    assert!(block(claim_app(Arc::clone(&db), NOW)).expect("claim"), "the first claim is taken");
    assert!(
        block(app_row(Arc::clone(&db))).expect("read").is_none(),
        "a claim is not an app until it is finished"
    );
    let app = AppRow {
        app_id: 42,
        slug: "ks".into(),
        client_id: "Iv1.x".into(),
        html_url: "https://github.com/apps/ks".into(),
        owner: "keep-shipping".into(),
        permissions: serde_json::json!({"contents": "write"}),
    };
    block(finish_app(Arc::clone(&db), &app)).expect("finish");
    assert_eq!(block(app_row(Arc::clone(&db))).expect("read"), Some(app.clone()));
    let overview = block(overview(db)).expect("overview");
    assert_eq!(overview.app, Some(app));
    assert!(overview.installations.is_empty());
}

#[test]
fn the_stamp_is_rfc_3339_in_utc() {
    assert_eq!(stamp(NOW), "2027-01-15T08:00:00Z");
}

#[test]
fn a_second_claim_on_the_app_row_is_refused_until_the_first_is_released() {
    let db = database();
    assert!(block(claim_app(Arc::clone(&db), NOW)).expect("claim"));
    assert!(!block(claim_app(Arc::clone(&db), NOW + 1)).expect("claim"), "one row, one claim");
    block(release_claim(Arc::clone(&db))).expect("release");
    assert!(block(claim_app(Arc::clone(&db), NOW + 2)).expect("claim"), "free again");
}

#[test]
fn a_stale_claim_from_an_unfinished_create_is_cleared_by_the_next_one() {
    let db = database();
    assert!(block(claim_app(Arc::clone(&db), NOW)).expect("claim"));
    assert!(
        !block(claim_app(Arc::clone(&db), NOW + 599)).expect("claim"),
        "a claim inside the window still holds the row"
    );
    assert!(
        block(claim_app(Arc::clone(&db), NOW + 600)).expect("claim"),
        "one left past the window is cleared and taken"
    );
}

#[test]
fn a_state_is_bound_to_the_person_it_was_issued_to() {
    let db = database();
    let state = block(issue_state(Arc::clone(&db), NOW, &subject_of(ME))).expect("a state");
    assert!(
        !block(take_state(Arc::clone(&db), &state, NOW + 1, &subject_of("someone@else.app")))
            .expect("take"),
        "another person cannot return it"
    );
    assert!(
        block(take_state(Arc::clone(&db), &state, NOW + 2, &subject_of("nick@chi.app")))
            .expect("take"),
        "the same person, in any letter case, can"
    );
}

#[test]
fn the_subject_hash_is_a_sha256_of_the_normalised_email() {
    let hash = subject_of(" Nick@CHI.app ");
    assert_eq!(hash.len(), 64);
    assert_eq!(hash, subject_of("nick@chi.app"));
    assert_ne!(hash, subject_of("nick@chi.apps"));
    assert!(!hash.contains("nick"), "the email itself is not in the hash");
}

#[test]
fn a_grant_short_of_a_required_permission_is_named_and_a_full_grant_is_not() {
    let full = serde_json::json!({
        "contents": "write", "pull_requests": "write", "workflows": "write",
        "secrets": "write", "administration": "write", "actions": "read", "metadata": "read"
    });
    assert!(missing_permissions(&full).is_empty());
    // More than needed is fine.
    let more = serde_json::json!({
        "contents": "write", "pull_requests": "write", "workflows": "write",
        "secrets": "write", "administration": "write", "actions": "write", "metadata": "read"
    });
    assert!(missing_permissions(&more).is_empty());
    // Lower than needed, and absent, are both named with the level needed.
    let short = serde_json::json!({"contents": "read", "metadata": "read", "actions": "read"});
    assert_eq!(
        missing_permissions(&short),
        [
            "contents (write)",
            "pull requests (write)",
            "workflows (write)",
            "secrets (write)",
            "administration (write)"
        ]
    );
    assert_eq!(missing_permissions(&serde_json::Value::Null).len(), 7);
}

#[test]
fn the_advanced_link_is_built_only_from_a_checked_app_page() {
    assert_eq!(
        advanced_url("https://github.com/settings/apps/kp-console").as_deref(),
        Some("https://github.com/settings/apps/kp-console/advanced")
    );
    assert_eq!(
        advanced_url("https://github.com/organizations/keep-shipping/settings/apps/kp-console")
            .as_deref(),
        Some("https://github.com/organizations/keep-shipping/settings/apps/kp-console/advanced")
    );
    // Other hosts, schemes, paths and characters never reach the page.
    for hostile in [
        "http://github.com/settings/apps/kp",
        "https://evil.example/settings/apps/kp",
        "https://github.com.evil.example/settings/apps/kp",
        "https://github.com/apps/kp",
        "https://github.com/settings/apps/kp/advanced",
        "https://github.com/settings/apps/",
        "https://github.com/settings/apps/kp?x=1",
        "https://github.com/settings/apps/kp#frag",
        "https://github.com/settings/apps/k%20p",
        "https://github.com/settings/apps/kp\"><script>",
        "https://github.com/organizations//settings/apps/kp",
        "https://github.com/organizations/a.b/settings/apps/kp",
        "https://github.com/organizations/keep-shipping/settings/apps/",
        "//github.com/settings/apps/kp",
        "",
    ] {
        assert_eq!(advanced_url(hostile), None, "{hostile} is refused");
    }
    let long = "a".repeat(APP_SLUG_MAX + 1);
    assert_eq!(advanced_url(&format!("https://github.com/settings/apps/{long}")), None);
}

#[test]
fn a_redirected_advanced_link_is_accepted_only_when_it_is_the_built_one() {
    let built = advanced_url("https://github.com/settings/apps/kp").expect("built");
    assert_eq!(checked_advanced_url(&built).as_deref(), Some(built.as_str()));
    assert_eq!(checked_advanced_url("https://github.com/settings/apps/kp/advanced/x"), None);
    assert_eq!(checked_advanced_url("https://evil.example/settings/apps/kp/advanced"), None);
    assert_eq!(checked_advanced_url("https://github.com/settings/apps/kp"), None);
    assert_eq!(checked_advanced_url(""), None);
}

#[test]
fn removing_the_app_forgets_its_installations_and_its_row_and_a_claim_too() {
    let db = database();
    let installation = Installation {
        id: 7,
        account: "keep-shipping".to_owned(),
        account_type: "Organization".to_owned(),
        selection: "all".to_owned(),
    };
    block(save_installation(Arc::clone(&db), &installation, "2026-10-16T09:00:00Z")).expect("save");
    block(finish_app(Arc::clone(&db), &app_row_for_tests())).expect("finish");
    block(remove_app(Arc::clone(&db))).expect("remove");
    assert!(block(installations(Arc::clone(&db))).expect("list").is_empty());
    assert!(block(app_row(Arc::clone(&db))).expect("row").is_none());
    // The row is gone, so a fresh claim is taken (a placeholder would refuse it).
    assert!(block(claim_app(Arc::clone(&db), NOW)).expect("claim"));

    // A placeholder claim, left by a create that never finished, goes too.
    block(remove_app(Arc::clone(&db))).expect("remove the claim");
    assert!(block(claim_app(db, NOW)).expect("claim"), "the claim is gone");
}

fn app_row_for_tests() -> AppRow {
    AppRow {
        app_id: 42,
        slug: "kp-console".to_owned(),
        client_id: "Iv1.abc".to_owned(),
        html_url: "https://github.com/organizations/keep-shipping/settings/apps/kp-console"
            .to_owned(),
        owner: "keep-shipping".to_owned(),
        permissions: serde_json::json!({"contents": "write"}),
    }
}

#[test]
fn the_delete_link_is_built_from_the_slug_and_owner_not_the_public_page() {
    assert_eq!(
        advanced_url_for("keep-shipping-console", "Keep-Shipping", true).as_deref(),
        Some(
            "https://github.com/organizations/Keep-Shipping/settings/apps/keep-shipping-console/advanced"
        )
    );
    assert_eq!(
        advanced_url_for("keep-shipping-console", "ParallelEntrepreneur", false).as_deref(),
        Some("https://github.com/settings/apps/keep-shipping-console/advanced")
    );
    assert_eq!(advanced_url("https://github.com/apps/keep-shipping-console"), None);
    assert_eq!(advanced_url_for("bad/slug", "owner", false), None);
    assert_eq!(advanced_url_for("slug", "own?er", true), None);
    for built in [
        advanced_url_for("a-1", "Org", true).unwrap(),
        advanced_url_for("a-1", "me", false).unwrap(),
    ] {
        assert_eq!(checked_advanced_url(&built).as_deref(), Some(built.as_str()));
    }
}

#[test]
fn only_a_recorded_installation_is_acted_through() {
    let one = |id| Installation {
        id,
        account: "Someone".into(),
        account_type: "Organization".into(),
        selection: "all".into(),
    };
    assert_eq!(recorded_only(one(7), &[one(7), one(8)]), Some(one(7)));
    assert_eq!(recorded_only(one(9), &[one(7), one(8)]), None, "a stranger's installation");
    assert_eq!(recorded_only(one(7), &[]), None);
}
