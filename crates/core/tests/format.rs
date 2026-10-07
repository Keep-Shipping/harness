//! The file format: the `keepshipping:` header, the versions a build reads,
//! and the upgrade path between them.
//!
//! Two guards run over the built-in tables on every test run, both of them
//! about a future bump rather than today's behaviour: a version with no
//! migration out of it must not ship, and a migration without a fixture pair
//! must not ship either. Everything after that exercises the machinery
//! through a synthetic format table (`current: 2`, one migration), because
//! the built-in table is format 1 with nothing to migrate.

use std::path::{Path, PathBuf};

use ks_core::Catalog;
use ks_core::format::{self, BUILTIN, Edit, Formats, Migration, Rewrites, Unrewritten, upgrade};
use ks_core::ports::run_context::ActorKind;
use ks_core::{CheckOptions, FORMAT_VERSION, check_with};
use ks_lang::{Code, Parse, Severity, Span};

#[expect(
    clippy::disallowed_methods,
    reason = "the fixtures live on disk; the library itself stays I/O-free"
)]
fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The fixtures for one migration, as `(before, after)` pairs.
#[expect(
    clippy::disallowed_methods,
    reason = "the fixture pairs live on disk; the library itself stays I/O-free"
)]
fn pairs(dir: &Path) -> Vec<(PathBuf, PathBuf)> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .filter_map(|entry| {
            let stem = entry.file_stem()?.to_string_lossy().into_owned();
            let before = stem.strip_suffix(".before")?;
            let dir = entry.parent().expect("an entry has a parent");
            Some((dir.join(format!("{before}.before.ks")), dir.join(format!("{before}.after.ks"))))
        })
        .collect()
}

fn fixture(name: &str) -> String {
    read(&Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/upgrade/{name}")))
}

fn with_formats(src: &str, formats: &Formats<'_>) -> ks_core::Checked {
    check_with(&ks_lang::parse(src), &CheckOptions::new(&Catalog::builtin()).formats(formats))
}

fn check(src: &str, options: &CheckOptions<'_>) -> ks_core::Checked {
    check_with(&ks_lang::parse(src), options)
}

// --- guards over the built-in tables ---------------------------------------

#[test]
fn a_bumped_format_carries_an_upgrade_path_out_of_the_one_before_it() {
    if FORMAT_VERSION > 1 {
        assert!(
            BUILTIN.migrations.iter().any(|m| m.from == FORMAT_VERSION - 1),
            "format {FORMAT_VERSION} has no migration from format {}: bump the constant \
             and append the migration that gets here from it",
            FORMAT_VERSION - 1
        );
    }
}

#[test]
fn every_built_in_migration_has_a_fixture_pair_that_upgrades_and_then_re_upgrades() {
    for migration in BUILTIN.migrations {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/fixtures/upgrade/0.{}", migration.from));
        let pairs = pairs(&dir);
        assert!(!pairs.is_empty(), "no fixture pair under {}", dir.display());

        for (before, after) in pairs {
            let from = read(&before);
            let expected = read(&after);
            let got =
                upgrade(&from, &BUILTIN).unwrap_or_else(|e| panic!("{}: {e}", before.display()));
            assert_eq!(
                got.src,
                expected,
                "{}: migration from {}",
                before.display(),
                migration.from
            );
            assert!(
                got.unrewritten.is_empty(),
                "{}: a built-in migration fixture leaves nothing to hand a human",
                before.display()
            );

            // Idempotent: a second run writes the same bytes again.
            let again = upgrade(&expected, &BUILTIN).expect("an upgraded file upgrades again");
            assert_eq!(again.src, expected, "{}: upgrade is not idempotent", after.display());

            let upgraded = with_formats(&expected, &BUILTIN);
            assert!(
                upgraded.diagnostics.iter().all(|d| d.severity != Severity::Error),
                "{}: an upgraded file must check clean, got {:#?}",
                after.display(),
                upgraded.diagnostics
            );
            assert!(
                !upgraded.diagnostics.iter().any(|d| d.code == Code::FormatDeprecated),
                "{}: an upgraded file declares the current format",
                after.display()
            );
        }
    }
}

// --- the synthetic format table --------------------------------------------

/// Format 1 -> 2, test-only: the top-level `name:` became `title:`, and a
/// `name:` the migration cannot place is left for a human. The nested case
/// is real, not decorative — a third-party step kind can declare an input
/// called `name`, and a migration rewriting every `name:` key in the file
/// would silently rename it.
fn rename_name_to_title(parse: &Parse) -> Rewrites {
    let mut rewrites = Rewrites::default();
    for entry in parse.file().entries() {
        if entry.key_name() == Some("name") {
            rewrites.edits.push(Edit::new(entry.key_span(), "title"));
        }
        nested_names(entry, &mut rewrites);
    }
    rewrites
}

/// Every `name:` below `entry`, which the migration leaves alone: nested
/// that deep it is a step's own input.
fn nested_names(entry: ks_lang::Entry<'_>, rewrites: &mut Rewrites) {
    for child in entry.children() {
        if child.key_name() == Some("name") {
            rewrites.unrewritten.push(Unrewritten {
                span: child.key_span(),
                message: "`name:` inside another entry may be a step's own input, \
                          not the pipeline's name; rename it by hand if it was"
                    .to_string(),
            });
        }
        nested_names(child, rewrites);
    }
}

const SYNTHETIC: Formats<'static> = Formats {
    current: 2,
    migrations: &[Migration {
        from: 1,
        summary: "the top-level `name:` key became `title:`",
        rewrite: rename_name_to_title,
    }],
};

const BEFORE: &str = "synthetic/renamed-key.before.ks";
const AFTER: &str = "synthetic/renamed-key.after.ks";

// --- the header, read -------------------------------------------------------

#[test]
fn spellings_round_trip_and_nothing_else_is_a_version() {
    assert_eq!(format::spelling(1), "0.1");
    for v in [0, 1, 2, 12] {
        assert_eq!(format::parse_spelling(&format::spelling(v)), Some(v), "version {v}");
    }
    for text in ["", "1", "1.0", "0.", "0.01", "0.1.1", "banana", "0.1 ", " 0.1"] {
        assert_eq!(format::parse_spelling(text), None, "{text:?} is not a format version");
    }
}

#[test]
fn a_header_is_the_first_entry_through_the_comments_above_it() {
    let src = "# the pipeline\n\nkeepshipping: 0.2\nname: api\n";
    assert_eq!(
        format::header(ks_lang::parse(src).file()),
        format::Header::Declared { version: 2, span: Span::new(30, 33) }
    );
    assert_eq!(format::header(ks_lang::parse("steps:\n  a: b\n").file()), format::Header::Absent);
    for src in ["keepshipping: banana\n", "keepshipping:\n"] {
        assert!(
            matches!(format::header(ks_lang::parse(src).file()), format::Header::Malformed { .. }),
            "{src:?} must not read as a version"
        );
    }
}

// --- the checker on the header ---------------------------------------------

#[test]
fn a_file_on_the_current_format_is_not_mentioned() {
    let src = "keepshipping: 0.1\nsteps:\n  build: oci.image\n    from: ./x\n";
    assert!(with_formats(src, &BUILTIN).diagnostics.is_empty(), "{src:?}");
}

#[test]
fn a_file_on_the_previous_format_warns_and_names_the_upgrade() {
    let checked = with_formats(&fixture(BEFORE), &SYNTHETIC);
    assert!(
        checked.diagnostics.iter().all(|d| d.severity != Severity::Error),
        "a file one format behind still checks: {:#?}",
        checked.diagnostics
    );
    let deprecated: Vec<_> =
        checked.diagnostics.iter().filter(|d| d.code == Code::FormatDeprecated).collect();
    assert_eq!(deprecated.len(), 1, "{:#?}", checked.diagnostics);
    assert_eq!(deprecated[0].severity, Severity::Warning);
    assert!(
        deprecated[0].message.contains("0.1") && deprecated[0].message.contains("0.2"),
        "the warning names both formats: {}",
        deprecated[0].message
    );
    assert!(
        deprecated[0].hints.iter().any(|h| h.contains("fmt --upgrade")),
        "the warning points at the upgrade: {:?}",
        deprecated[0].hints
    );
}

#[test]
fn a_format_this_build_does_not_read_is_refused() {
    let step = "steps:\n  build: oci.image\n    from: ./x\n";
    for src in [
        format!("keepshipping: 0.9\n{step}"),
        format!("keepshipping: banana\n{step}"),
        // Not the first entry.
        format!("name: api\nkeepshipping: 0.1\n{step}"),
        // And not merely misplaced: a header under `steps:` is not a header.
        format!("{step}keepshipping: 0.1\n"),
    ] {
        let diags = with_formats(&src, &BUILTIN).diagnostics;
        let hit = diags
            .iter()
            .find(|d| d.code == Code::FormatUnsupported)
            .unwrap_or_else(|| panic!("{src:?} must be refused"));
        assert_eq!(hit.severity, Severity::Error, "{src:?}");
        let at = hit.span.slice(&src);
        assert!(!at.is_empty(), "{src:?}: the span points at the header, not past it");
    }
}

/// KS0611 fires in CI and nowhere else: a pipeline owner wants to hear that
/// nobody pinned the format, a local run would only nag. CI is either an
/// actor bound to `ci` or a caller that says so — and saying so is advisory
/// only, so spoofing it earns a warning nobody reads rather than a run.
#[test]
fn only_ci_is_told_a_file_declares_no_format() {
    let src = "steps:\n  build: oci.image\n    from: ./Dockerfile\n";
    let catalog = Catalog::builtin();
    let undeclared = |options: CheckOptions<'_>| {
        check(src, &options).diagnostics.into_iter().find(|d| d.code == Code::FormatUndeclared)
    };

    for options in [
        CheckOptions::new(&catalog),
        CheckOptions::new(&catalog).actor(ActorKind::Human),
        CheckOptions::new(&catalog).actor(ActorKind::Agent),
        CheckOptions::new(&catalog).ci(false),
    ] {
        assert!(
            undeclared(options).is_none(),
            "neither an ordinary actor nor an off `ci` option is asked to pin a format"
        );
    }

    for hit in [
        undeclared(CheckOptions::new(&catalog).actor(ActorKind::Ci)),
        undeclared(CheckOptions::new(&catalog).ci(true)),
    ]
    .into_iter()
    .flatten()
    {
        assert_eq!(hit.severity, Severity::Warning, "advisory, never an error");
        assert!(hit.hints.iter().any(|h| h.contains("keepshipping: 0.1")));
    }
}

/// Policy binds the actor, and only the actor: a run CI told apart from a run
/// the checker believes is CI must reach the same verdict.
#[test]
fn the_ci_option_does_not_replace_the_actor_in_policy() {
    let src = "\
name: gated
steps:
  migrate: db.migrate
    url: secrets.db_url
policy:
  agents:
    never: read secrets
";
    let catalog = Catalog::builtin();
    let refused = |actor| {
        check(src, &CheckOptions::new(&catalog).actor(actor).ci(true))
            .diagnostics
            .iter()
            .any(|d| d.code == Code::PolicyForbidden)
    };
    assert!(refused(ActorKind::Agent), "an agent is refused the secret, CI or not");
    assert!(!refused(ActorKind::Human), "`CI` must never stand in for the actor policy binds");
}

// --- the upgrade ------------------------------------------------------------

/// A headerless file gets the current format pinned above its first entry,
/// and keeps what was already at its start: a byte-order mark stays the
/// file's first bytes, a CRLF file stays CRLF throughout. A header that
/// reordered either would make a different file of the one it was asked to
/// upgrade.
#[test]
fn pinning_a_file_keeps_its_byte_order_mark_and_its_line_endings() {
    let key = format!("keepshipping: {}", format::spelling(BUILTIN.current));
    for (src, want) in [
        (
            "# a comment first\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n",
            format!(
                "{key}\n# a comment first\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n"
            ),
        ),
        ("\u{FEFF}steps:\r\n  a: b\r\n", format!("\u{FEFF}{key}\r\nsteps:\r\n  a: b\r\n")),
        ("steps:\n  a: b\n", format!("{key}\nsteps:\n  a: b\n")),
    ] {
        let got = upgrade(src, &BUILTIN).expect("a headerless file upgrades");
        assert_eq!(got.src, want);
        assert_eq!(
            upgrade(&got.src, &BUILTIN).expect("re-pins").src,
            got.src,
            "pinning is idempotent"
        );
    }

    // A pinned file stops the CI warning.
    let src = format!("{key}\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n");
    let got = upgrade(&src, &BUILTIN).expect("a pinned file upgrades");
    assert!(got.unrewritten.is_empty());
    assert!(
        !with_formats(&got.src, &BUILTIN)
            .diagnostics
            .iter()
            .any(|d| d.code == Code::FormatUndeclared),
        "a pinned file stops CI warning"
    );
}

#[test]
fn upgrading_rewrites_the_fixture_keeping_every_comment() {
    let got = upgrade(&fixture(BEFORE), &SYNTHETIC).expect("the fixture upgrades");
    assert_eq!(got.src, fixture(AFTER), "byte for byte");
    assert_eq!(got.from, 1);

    // The one thing the migration could not place is named, not guessed at,
    // and its span indexes the source it was handed, not the pre-edit one.
    assert_eq!(got.unrewritten.len(), 1, "{:#?}", got.unrewritten);
    assert_eq!(got.unrewritten[0].span.slice(&got.src), "name");

    // And it is idempotent.
    let again = upgrade(&got.src, &SYNTHETIC).expect("an upgraded file upgrades again");
    assert_eq!(again.src, got.src, "a second run writes the same bytes again");
    assert_eq!(again.from, SYNTHETIC.current);
    assert!(again.unrewritten.is_empty(), "nothing is left to do on a current file");
}

#[test]
fn upgrading_refuses_a_file_it_cannot_read() {
    for src in [
        "keepshipping: 0.9\nsteps:\n  build: oci.image\n    from: ./x\n",
        "keepshipping: banana\n",
        "steps:\n  build: oci.image\n    from: ./x\nkeepshipping: 0.1\n",
    ] {
        let err = upgrade(src, &BUILTIN).expect_err("an unreadable file is refused");
        assert!(!err.message.is_empty(), "{src:?} must say why");
    }
}

/// The table says which formats it reads, and reads no other: a version
/// with no migration out of it is refused however old it is.
#[test]
fn a_table_names_the_formats_it_reads_and_no_others() {
    assert_eq!(SYNTHETIC.reads(), "0.2 and 0.1");
    assert!(SYNTHETIC.supports(2) && SYNTHETIC.supports(1));
    assert!(!SYNTHETIC.supports(0), "format 0 has no migration out of it");

    assert!(BUILTIN.supports(BUILTIN.current));
    assert_eq!(
        BUILTIN.reads(),
        format::spelling(BUILTIN.current),
        "the built-in table is format 1 with nothing behind it"
    );
}
