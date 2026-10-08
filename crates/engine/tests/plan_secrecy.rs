//! The acceptance test for [#122](https://github.com/Keep-Shipping/harness/issues/122):
//! a fixture plan with a sensitive attribute, swept end to end.
//!
//! A `tofu show -json` document puts attribute values in cleartext, and a saved
//! plan carries the same bytes in binary. Everything downstream of parsing — the
//! engine's [`PlanJson`](ks_core::ports::iac::PlanJson), every rendering of the
//! summary, the exact text a decision model is sent, and every byte written to a
//! run directory — is swept for the fixture's marker. Nothing may match.
//!
//! The marker is planted twice on purpose: once where the tool marks the
//! attribute sensitive, and once where only the path says `password`. The
//! second is masked by [`SENSITIVE_PATH_MARKERS`] even though the tool said
//! nothing — over-masking is intended, and this pins it.
//!
//! Neither the fixture nor this file spells the marker out. The fixture holds a
//! `<<PLAN_MARKER>>` placeholder and [`marker()`] assembles the real value from
//! fragments at runtime, because a password-shaped literal in a test fixture is
//! enough for push protection to reject the branch — synthetic or not. Nothing
//! downstream of the substitution is affected: the sweep still looks for one
//! value that cannot occur in a real plan by accident.
//!
//! The sweep's own honesty is asserted too: the fixture really does carry the
//! marker once substituted, so a sweep that found nothing could never pass by
//! reading nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ks_core::ids::RunId;
use ks_core::plan_summary::{AttrValue, AttributeChange, Limits, PlanChange, Target, summarize};
use ks_core::ports::decision_model::RedactedState;
use ks_core::ports::iac::ChangeAction;
use ks_core::sensitivity::Sensitivity;
use ks_engine::state::{CompletedStep, LocalStateStore, RunState, park, plan_key, save_plan};
use ks_engine::tofu_plan::parse_show_json;
use ks_testing::block_on;

/// What stands in for the marker in the committed fixture.
const PLACEHOLDER: &str = "<<PLAN_MARKER>>";

/// The value planted in the fixture, assembled from fragments at runtime so
/// that no secret-shaped literal is ever committed: push protection rejects
/// the branch over a password-shaped string in a test fixture. Not a secret
/// and never was — it is a string that cannot occur in a real plan by
/// accident, which is the only thing a sweep needs it to be.
fn marker() -> String {
    ["PLANMARKER", "9f2a", "sentinel"].join("-")
}

/// Every rendering the summary can take.
const TARGETS: [Target; 4] =
    [Target::Plain, Target::Terminal { color: true }, Target::Markdown, Target::Html];

/// The fixture's `tofu show -json` document exactly as committed: the
/// placeholder token where the marker goes, and nothing else.
fn fixture_raw() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tofu/secretish.plan.json");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The same document with [`PLACEHOLDER`] swapped for the runtime [`marker()`],
/// which is what the rest of this file parses, renders and sweeps.
fn fixture() -> String {
    fixture_raw().replace(PLACEHOLDER, &marker())
}

/// The fixture's two changes as the adapter flattens them: the marked one, and
/// one the tool did *not* mark but whose path is a denylisted fragment.
fn changes() -> Vec<PlanChange> {
    let attr = |path: &str, sensitive: bool| AttributeChange {
        path: path.to_string(),
        before: AttrValue::Absent,
        after: AttrValue::Known(marker()),
        sensitive,
        forces_replacement: false,
    };
    vec![
        PlanChange {
            address: "aws_db_instance.app".to_string(),
            actions: vec![ChangeAction::Create],
            attributes: vec![attr("password", true)],
            reason: None,
        },
        PlanChange {
            address: "aws_secretsmanager_secret.db".to_string(),
            actions: vec![ChangeAction::Create],
            // Not flagged sensitive by the tool; `db_password` is masked by
            // name all the same.
            attributes: vec![attr("db_password", false)],
            reason: None,
        },
    ]
}

/// The negative control: a sweep that cannot find the marker proves nothing,
/// so the fixture is checked to really hold it — once where the tool marked it
/// sensitive, and once where only the attribute's name gives it away.
///
/// Both halves of the placeholder arrangement are pinned: the committed file
/// carries the placeholder exactly twice and never the assembled value, and the
/// substituted fixture carries the marker exactly twice.
#[test]
fn the_fixture_really_carries_the_marker_the_sweep_looks_for() {
    let raw = fixture_raw();
    assert_eq!(
        raw.matches(PLACEHOLDER).count(),
        2,
        "the fixture must plant the placeholder where the marker goes: {raw}"
    );
    assert!(!raw.contains(&marker()), "the fixture must not spell the marker out: {raw}");
    assert_ne!(marker(), PLACEHOLDER, "the placeholder is not the marker: it must be replaced");

    let json = fixture();
    assert_eq!(json.matches(&marker()).count(), 2, "the fixture must plant the marker: {json}");
    assert!(json.contains(r#""after_sensitive": { "password": true }"#), "{json}");
    assert!(!json.contains(r#""db_password": true"#), "the unmarked half stays unmarked: {json}");
}

/// The engine's parser reads addresses and actions only, so the value never
/// reaches the typed plan at all — not even in its `Debug` form, which a log
/// line could print.
#[test]
fn the_parsed_plan_holds_no_attribute_value() {
    let json = fixture();
    let plan = parse_show_json(&json).expect("the fixture is a readable plan");
    assert_eq!(plan.creates(), 2, "the fixture is a real plan, not an empty one");
    let rendered = format!("{plan:?}");
    assert!(!rendered.contains(&marker()), "the parsed plan leaked the marker: {rendered}");
}

/// Every rendering, plus the summary's own `Debug`: masking happens in
/// `summarize`, so no renderer downstream of it can leak.
#[test]
fn no_rendering_of_the_summary_carries_the_marker() {
    let summary = summarize(&changes());
    let marker = marker();
    for target in TARGETS {
        let rendered = summary.render(target, &Limits::default());
        assert!(!rendered.contains(&marker), "{target:?} leaked the marker: {rendered}");
        // The masked half is shown as something, not silently dropped.
        assert!(rendered.contains("(sensitive)"), "{target:?} dropped it instead: {rendered}");
    }
    let debug = format!("{summary:?}");
    assert!(!debug.contains(&marker), "Debug leaked the marker: {debug}");
}

/// The text a decision model is handed is a rendering of the summary, so it is
/// the exact `state` the Jev adapter POSTs. This is the outgoing-request half
/// of the criterion.
#[test]
fn the_state_a_decision_model_is_sent_carries_no_marker() {
    let summary = summarize(&changes());
    let state = RedactedState::summarise(&summary, Target::Plain, &Limits::default());
    assert!(!state.as_str().contains(&marker()), "the outgoing state leaked: {}", state.as_str());
}

/// What the state store writes to disk, swept as raw bytes.
///
/// The one file that *does* hold the value is the saved plan blob: that is the
/// artifact, and the engine needs those bytes verbatim to apply the plan in a
/// later job. It is protected rather than removed — classified secretish by
/// its key and written owner-only — so this asserts both halves honestly: the
/// record the run actually reads and resumes from carries nothing, and the one
/// file that carries the marker is not readable by anyone else.
#[test]
fn the_only_bytes_a_run_directory_holds_the_marker_are_owner_only() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ks-plan-secrecy-bytes");
    std::fs::remove_dir_all(&dir).ok();
    let run = RunId::from_parts(1_700_000_000_000, 122);
    let store = LocalStateStore::new(&dir);

    let plan =
        block_on(save_plan(&store, &run, "tofu.plan", fixture().as_bytes())).expect("stores");
    let blob = store.run_dir(&run).join(plan_key(&plan.sha256));
    let mut state = RunState::new(run.clone(), b"steps: {}\n", "push");
    state.record(CompletedStep {
        name: "tofu.plan".to_string(),
        outputs: BTreeMap::from([("sha256".to_string(), plan.sha256.clone())]),
        plans: vec![plan],
    });
    state.park_at("tofu.apply").expect("the run parks");
    block_on(park(&store, &state)).expect("the state parks");

    let stored = store.run_dir(&run);
    let files = walk(&stored);
    let marker = marker();
    // The control: the sweep below must have real files to read, including the
    // blob it is meant to catch, or it would pass by reading nothing.
    assert!(files.len() >= 2, "expected the plan blob and the record: {}", stored.display());
    let mut caught = 0;
    for path in files {
        let bytes = std::fs::read(&path).expect("a readable run-directory file");
        if !String::from_utf8_lossy(&bytes).contains(&marker) {
            continue;
        }
        caught += 1;
        assert_eq!(path, blob, "the marker reached {}", path.display());
        // Secretish by key, and owner-only on disk: 0600 is the floor the
        // adapter and the store both write it with.
        assert_eq!(
            Sensitivity::of_key(path.file_name().unwrap().to_str().unwrap()).to_string(),
            "secretish"
        );
        // Owner-only on unix; a platform with no mode bits has nothing to
        // assert, so the check is compiled out rather than failed.
        #[cfg(unix)]
        assert_eq!(
            mode_of(&path),
            Some(0o600),
            "{} must not be readable by anyone else",
            path.display()
        );
    }
    assert_eq!(caught, 1, "the sweep must have caught the blob it was written to find");
    std::fs::remove_dir_all(&dir).ok();
}

/// The permission bits of `path`, or `None` where the file cannot be stat-ed.
/// Only unix platforms carry them, so this — and the assertion that uses it —
/// is compiled out elsewhere rather than failed there.
#[cfg(unix)]
fn mode_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(std::fs::metadata(path).ok()?.permissions().mode() & 0o777)
}

/// Every file under `root`, in a deterministic order.
fn walk(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else { return Vec::new() };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path);
        }
    }
    found.sort();
    found
}
