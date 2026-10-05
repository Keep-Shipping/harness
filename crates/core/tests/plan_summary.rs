//! Golden renderings of a plan summary, plus the safety invariants: no secret
//! and no control character ever reaches a rendering.
//!
//! The site example is pinned byte for byte; the mixed scenario (destroy,
//! replace, sensitive values, truncation) is pinned with all four targets in
//! one file per scenario. Re-run with
//! `UPDATE_GOLDEN=1 cargo test -p ks-core --test plan_summary` after reviewing
//! the diff.

use std::fs;
use std::path::Path;

use ks_core::plan_summary::{
    AttrValue, AttributeChange, Kind, Limits, PlanChange, PlanSummary, SummaryEntry, Target,
    summarize,
};
use ks_core::ports::iac::ChangeAction;

/// Every target, for the invariant tests that must hold in all of them.
const TARGETS: [Target; 5] = [
    Target::Plain,
    Target::Terminal { color: false },
    Target::Terminal { color: true },
    Target::Markdown,
    Target::Html,
];

fn change(address: &str, actions: &[ChangeAction]) -> PlanChange {
    PlanChange {
        address: address.to_string(),
        actions: actions.to_vec(),
        attributes: Vec::new(),
        reason: None,
    }
}

fn attribute(
    path: &str,
    before: AttrValue,
    after: AttrValue,
    sensitive: bool,
    forces_replacement: bool,
) -> AttributeChange {
    AttributeChange { path: path.to_string(), before, after, sensitive, forces_replacement }
}

fn text(value: &str) -> AttrValue {
    AttrValue::Known(value.to_string())
}

/// Every target in one dump, separated by headers, so one golden file covers
/// them all. Plain is first; terminal uses colour on.
fn all_renderings(summary: &PlanSummary, limits: &Limits) -> String {
    let mut out = String::new();
    for (header, target) in [
        ("=== plain ===\n", Target::Plain),
        ("=== terminal ===\n", Target::Terminal { color: true }),
        ("=== markdown ===\n", Target::Markdown),
        ("=== html ===\n", Target::Html),
    ] {
        out.push_str(header);
        out.push_str(&summary.render(target, limits));
    }
    out
}

#[expect(
    clippy::disallowed_methods,
    reason = "the golden update path is test-only; the library itself stays I/O-free"
)]
fn assert_golden(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::write(&path, actual).expect("write golden");
    } else {
        let expected = fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(actual, expected, "golden mismatch; re-run with UPDATE_GOLDEN=1");
    }
}

/// The site example: two adds and one update, exactly as the issue pins it.
fn site() -> PlanSummary {
    summarize(&[
        change("aws_lb.api", &[ChangeAction::Create]),
        PlanChange {
            attributes: vec![attribute("count", text("2"), text("4"), false, false)],
            ..change("aws_ecs_service.api", &[ChangeAction::Update])
        },
        change("aws_route53_record.api", &[ChangeAction::Create]),
    ])
}

#[test]
fn the_site_example_renders_and_matches_its_golden() {
    let plain = site().render(Target::Plain, &Limits::default());
    assert_eq!(
        plain,
        "+ aws_lb.api\n\
         ~ aws_ecs_service.api   count 2 → 4\n\
         + aws_route53_record.api\n\
         2 to add · 1 to change · 0 to destroy\n"
    );
    // Terminal without colour is the plain text; with colour only the symbols'
    // ANSI escapes differ.
    assert_eq!(site().render(Target::Terminal { color: false }, &Limits::default()), plain);
    assert!(site().render(Target::Terminal { color: true }, &Limits::default()).contains("\x1b["));
    assert_golden("plan-summary-site.snap", &all_renderings(&site(), &Limits::default()));
}

/// A plan with a destroy, a replace that forces it, a sensitive update, and
/// unknown/absent values; rendered full, then truncated with a URL.
fn mixed() -> PlanSummary {
    let attr = |path: &str, before: &str, after: &str, sensitive, forces| {
        attribute(path, text(before), text(after), sensitive, forces)
    };
    summarize(&[
        PlanChange {
            attributes: vec![attribute("identifier", text("old"), AttrValue::Absent, false, false)],
            ..change("aws_db_instance.old", &[ChangeAction::Delete])
        },
        PlanChange {
            attributes: vec![attribute("ami", text("ami-1"), text("ami-2"), false, true)],
            reason: Some("replace_because_tainted".to_string()),
            ..change("aws_instance.web", &[ChangeAction::Delete, ChangeAction::Create])
        },
        PlanChange {
            attributes: vec![
                attr("master_password", "S3CR3T-MASTER-OLD", "S3CR3T-MASTER-NEW", true, false),
                attr("db_password", "S3CR3T-DENY-OLD", "S3CR3T-DENY-NEW", false, false),
                attribute("count", text("2"), AttrValue::Unknown, false, false),
            ],
            ..change("aws_rds_cluster.app", &[ChangeAction::Update])
        },
    ])
}

#[test]
fn the_mixed_scenario_matches_its_golden() {
    let truncated = Limits {
        max_resources: Some(2),
        full_plan_url: Some("https://ci.example/plans/42".to_string()),
        ..Limits::default()
    };
    let mut dump = all_renderings(&mixed(), &Limits::default());
    for (header, target) in
        [("=== truncated ===\n", Target::Plain), ("=== truncated markdown ===\n", Target::Markdown)]
    {
        dump.push_str(header);
        dump.push_str(&mixed().render(target, &truncated));
    }
    dump.push_str("=== empty ===\n");
    dump.push_str(&summarize(&[]).render(Target::Plain, &Limits::default()));
    assert_golden("plan-summary-mixed.snap", &dump);
}

#[test]
fn classification_counts_a_replace_twice_and_ignores_noop_and_read() {
    let summary = summarize(&[
        change("a", &[ChangeAction::Create]),
        change("b", &[ChangeAction::Update]),
        change("c", &[ChangeAction::Delete]),
        change("d", &[ChangeAction::Delete, ChangeAction::Create]),
        change("d2", &[ChangeAction::Create, ChangeAction::Delete]),
        change("e", &[ChangeAction::NoOp]),
        change("f", &[ChangeAction::Read]),
    ]);
    assert_eq!((summary.add, summary.change, summary.destroy), (3, 1, 3));
    let kinds =
        |entries: &[SummaryEntry]| entries.iter().map(|entry| entry.kind).collect::<Vec<_>>();
    // Both replace orders classify as Replace; NoOp and Read are dropped.
    assert_eq!(kinds(&summary.risky), [Kind::Destroy, Kind::Replace, Kind::Replace]);
    assert_eq!(kinds(&summary.others), [Kind::Add, Kind::Change]);
    // A no-op-only plan is empty: no counts, and the empty renderings.
    let empty = summarize(&[change("data.x.y", &[ChangeAction::NoOp])]);
    assert_eq!(empty.add, 0);
    assert_eq!(empty.render(Target::Plain, &Limits::default()), "No changes.\n");
    assert_eq!(empty.render(Target::Markdown, &Limits::default()), "**No changes.**\n\n");
}

#[test]
fn markdown_and_html_escape_their_delimiters() {
    let html = summarize(&[PlanChange {
        attributes: vec![attribute("v", text("<&>\"'"), text("x"), false, false)],
        ..change("aws_x.<y>", &[ChangeAction::Create])
    }])
    .render(Target::Html, &Limits::default());
    assert!(!html.contains("<y>"), "{html}");
    assert!(html.contains("&lt;y&gt;"), "{html}");
    assert!(html.contains("&lt;&amp;&gt;&quot;&#39;"), "{html}");
    let markdown = summarize(&[PlanChange {
        attributes: vec![attribute("v", text("```"), text("```"), false, false)],
        ..change("aws_x.y", &[ChangeAction::Create])
    }])
    .render(Target::Markdown, &Limits::default());
    // Four backticks, not the three the value would close.
    assert!(markdown.contains("````diff\n"), "{markdown}");
    assert!(markdown.contains("\n````\n"), "{markdown}");
}

#[test]
fn control_characters_cannot_forge_a_line_or_drive_a_terminal() {
    let summary = summarize(&[PlanChange {
        attributes: vec![attribute(
            "count",
            text("1\n+ fake.resource"),
            text("\u{1b}[31mred"),
            false,
            false,
        )],
        ..change("aws_x.y", &[ChangeAction::Update])
    }]);
    for target in TARGETS {
        let rendered = summary.render(target, &Limits::default());
        // The value is escaped, never a live newline or ESC.
        assert!(rendered.contains("\\n+ fake.resource"), "{target:?}: {rendered}");
        assert!(rendered.contains("\\u{1b}[31mred"), "{target:?}: {rendered}");
        assert!(!rendered.contains("\n+ fake.resource"), "{target:?}: a forged line");
        if target != (Target::Terminal { color: true }) {
            assert!(!rendered.contains('\u{1b}'), "{target:?}: a raw ESC");
        }
    }
    // A reason and an address are escaped the same way.
    let summary = summarize(&[PlanChange {
        address: "aws_z.\nq".to_string(),
        actions: vec![ChangeAction::Delete, ChangeAction::Create],
        attributes: Vec::new(),
        reason: Some("bad\nreason".to_string()),
    }]);
    let rendered = summary.render(Target::Plain, &Limits::default());
    assert!(rendered.contains("aws_z.\\nq"), "{rendered}");
    assert!(rendered.contains("bad\\nreason"), "{rendered}");
    assert!(!rendered.contains("bad\nreason"), "{rendered}");
}

#[test]
fn unsafe_urls_are_not_emitted_but_a_safe_one_is_linked() {
    let summary = site();
    let mut limits = Limits {
        max_resources: Some(1),
        full_plan_url: Some("javascript:alert(1)".to_string()),
        ..Limits::default()
    };
    for target in [Target::Plain, Target::Markdown, Target::Html] {
        let rendered = summary.render(target, &limits);
        assert!(rendered.contains("more"), "{target:?}: {rendered}");
        assert!(!rendered.contains("full plan"), "{target:?}: {rendered}");
        assert!(!rendered.contains("javascript"), "{target:?}: {rendered}");
    }
    // A `)` cannot break out: the Markdown link uses the angle-bracket form.
    limits.full_plan_url = Some("https://ci.example/a)b".to_string());
    let markdown = summary.render(Target::Markdown, &limits);
    assert!(markdown.contains("[full plan](<https://ci.example/a)b>)"), "{markdown}");
    assert!(!markdown.contains("[full plan](https://ci.example/a)b)"), "{markdown}");
    // A safe URL is linked in every target.
    limits.full_plan_url = Some("https://ci.example/plans/7".to_string());
    assert!(
        summary.render(Target::Plain, &limits).contains("full plan: https://ci.example/plans/7")
    );
    assert!(summary.render(Target::Html, &limits).contains("href=\"https://ci.example/plans/7\""));
}

#[test]
fn max_bytes_is_honoured_whenever_a_form_fits() {
    let summary = summarize(
        &(0..6)
            .map(|i| change(&format!("aws_r.x{i}"), &[ChangeAction::Create]))
            .collect::<Vec<_>>(),
    );
    assert_eq!(summary.add, 6);
    let full = summary.render(Target::Plain, &Limits::default());
    let minimal =
        summary.render(Target::Plain, &Limits { max_resources: Some(0), ..Limits::default() });
    for budget in 0..=full.len() {
        let rendered =
            summary.render(Target::Plain, &Limits { max_bytes: Some(budget), ..Limits::default() });
        if minimal.len() <= budget {
            assert!(rendered.len() <= budget, "budget {budget}: {rendered:?}");
        }
        // The counts always describe the whole plan.
        assert!(rendered.contains("6 to add"), "budget {budget}: {rendered:?}");
        assert!(rendered.ends_with("\n"), "budget {budget}: {rendered:?}");
    }
    // The link is dropped before the summary when it would overrun the budget.
    let limits = Limits {
        max_resources: Some(0),
        max_bytes: Some(minimal.len()),
        full_plan_url: Some("https://ci.example/plans/very-long-identifier-0123456789".to_string()),
    };
    let rendered = summary.render(Target::Plain, &limits);
    assert!(rendered.len() <= minimal.len(), "{rendered:?}");
    assert!(!rendered.contains("full plan"), "{rendered:?}");
    assert!(rendered.contains("6 to add") && rendered.contains("and 6 more"), "{rendered:?}");
}

/// Markers that must never surface: planted in a sensitive attribute and in a
/// denylisted path, one of them forcing a replacement.
const MARKERS: &[&str] = &["S3CR3T-MARK-A", "S3CR3T-MARK-B", "S3CR3T-MARK-C"];

fn secretive() -> PlanSummary {
    let attr = |path: &str, value: &str, sensitive, forces| {
        attribute(path, text(value), text(value), sensitive, forces)
    };
    summarize(&[PlanChange {
        attributes: vec![
            attr("value", "S3CR3T-MARK-A", true, true),
            // Not flagged sensitive, but `master_user_secret.0.token` matches
            // the denylist.
            attr("master_user_secret.0.token", "S3CR3T-MARK-B", false, false),
            attr("db_password", "S3CR3T-MARK-C", false, true),
        ],
        ..change("aws_db_instance.secret", &[ChangeAction::Delete])
    }])
}

#[test]
fn a_sensitive_attribute_never_appears_in_any_rendering() {
    let summary = secretive();
    let limits = [
        Limits::default(),
        Limits { max_resources: Some(0), ..Limits::default() },
        Limits { max_resources: Some(1), ..Limits::default() },
        Limits { max_bytes: Some(0), ..Limits::default() },
        Limits {
            full_plan_url: Some("https://ci.example/plans/9".to_string()),
            ..Limits::default()
        },
    ];
    for target in TARGETS {
        for limit in &limits {
            let rendered = summary.render(target, limit);
            for marker in MARKERS {
                assert!(!rendered.contains(marker), "{target:?} leaked {marker}: {rendered}");
            }
        }
    }
    // The summary itself is the safe artifact: even its Debug repr has no
    // secret, because masking happened during `summarize`.
    let debug = format!("{summary:?}");
    for marker in MARKERS {
        assert!(!debug.contains(marker), "Debug leaked {marker}: {debug}");
    }
}
