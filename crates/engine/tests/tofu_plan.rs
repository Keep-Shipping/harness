//! What a plan has to say before anything is applied
//! ([#65](https://github.com/Keep-Shipping/harness/issues/65)).
//!
//! The counts are the contract: `+2 ~1 -0` and three resource lines, with the
//! no-ops and the data-source read the tool reports alongside them filtered out
//! — a plan that counted its own noise would be a plan nobody could read. And
//! the plan's contents stay inside the step: the digest reaches the log, the
//! `show -json` document never does.

use std::collections::BTreeMap;
use std::sync::Arc;

use ks_core::harness::Harness;
use ks_core::ports::iac::{IacTool, PlanJson, SavedPlan};
use ks_core::ports::script_host::Value;
use ks_core::ports::secrets::Redactor;
use ks_core::step::{
    CancellationToken, Inputs, LogSink, Port, Ports, StepCtx, StepError, StepKind, StepLog,
};
use ks_engine::run::run_step;
use ks_engine::tofu_plan::{ShowError, TofuPlan, address_parts, parse_show_json};
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::iac::{FakeIacTool, IacCall};
use ks_testing::step::RecordingSink;

/// The directory every scenario plans: a path the fake never touches.
const DIR: &str = "/ws/site/infra";

/// The site plan's summary, exactly as the renderer produces it: the two adds
/// and the one update in plan order, then the totals. No header, because
/// nothing in this plan is destroyed.
const SITE_SUMMARY: &str = "\
+ aws_lb.api
~ aws_ecs_service.api
+ aws_route53_record.api
2 to add · 1 to change · 0 to destroy
";

/// A `tofu show -json` document from the fixtures directory, parsed the way the
/// adapters parse it.
fn parsed(name: &str) -> PlanJson {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tofu").join(name);
    let json = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    parse_show_json(&json).unwrap_or_else(|error| panic!("{name}: {error}"))
}

/// Inputs with only `dir` set, so every other input takes its declared default.
fn site_inputs() -> Inputs {
    let mut inputs = Inputs::new();
    inputs.insert("dir".to_string(), Value::from(DIR));
    inputs
}

/// Runs `tofu.plan` under a harness whose `IacTool` is `tool`.
fn run_with(
    tool: &Arc<FakeIacTool>,
    inputs: Inputs,
    sink: &Arc<RecordingSink>,
) -> Result<Inputs, StepError> {
    let harness = Harness::builder()
        .ports(
            Ports::default()
                .with_clock(Arc::new(FakeClock::new()))
                .with_iac_tool(Arc::clone(tool) as Arc<dyn IacTool>),
        )
        .step(TofuPlan)
        .build()
        .expect("the composition is valid");
    block_on(run_step(
        &harness,
        "tofu.plan",
        inputs,
        CancellationToken::new(),
        Arc::clone(sink) as Arc<dyn LogSink>,
        Arc::new(Redactor::new()),
    ))
}

/// The `changes` output's resources, one `address/action/type/module` row each.
fn rows(outputs: &Inputs) -> Vec<String> {
    let Some(Value::Map(changes)) = outputs.get("changes") else {
        panic!("`changes` is not a map: {outputs:?}");
    };
    let Some(Value::List(resources)) = changes.get("resources") else {
        panic!("`changes` carries no resources: {changes:?}");
    };
    resources
        .iter()
        .map(|resource| match resource {
            Value::Map(fields) => ["address", "action", "type", "module"]
                .iter()
                .map(|field| match fields.get(*field) {
                    Some(Value::String(text)) => text.as_str(),
                    other => panic!("a resource has no {field}: {other:?}"),
                })
                .collect::<Vec<_>>()
                .join("/"),
            other => panic!("a resource is not a map: {other:?}"),
        })
        .collect()
}

/// One field of the `file` output — the saved plan, as `tofu.apply` will read it.
fn file(outputs: &Inputs, field: &str) -> String {
    let Some(Value::Map(file)) = outputs.get("file") else {
        panic!("`file` is not a map: {outputs:?}");
    };
    match file.get(field) {
        Some(Value::String(text)) => text.clone(),
        other => panic!("`file` carries no {field}: {other:?}"),
    }
}

/// An output read back as text; a run that returned anything else has broken its
/// schema, which `run_step` would already have refused.
fn summary(outputs: &Inputs) -> &str {
    match outputs.get("summary") {
        Some(Value::String(text)) => text,
        other => panic!("`summary` is not text: {other:?}"),
    }
}

#[test]
fn the_site_plan_is_two_adds_one_change_and_nothing_destroyed() {
    let tool = Arc::new(FakeIacTool::new().with_plan(parsed("site.plan.json").changes));
    let outputs = run_with(&tool, site_inputs(), &Arc::new(RecordingSink::new()))
        .expect("the plan is scripted");

    assert_eq!(outputs.get("adds"), Some(&Value::from(2.0)));
    assert_eq!(outputs.get("changes_count"), Some(&Value::from(1.0)));
    assert_eq!(outputs.get("destroys"), Some(&Value::from(0.0)));
    assert_eq!(outputs.get("empty"), Some(&Value::from(false)));
    // Exactly four lines: the three resources the plan changes, in plan order,
    // and the totals. The tool's no-op resource is not part of it.
    assert_eq!(summary(&outputs), SITE_SUMMARY);
    assert_eq!(
        rows(&outputs),
        vec![
            "aws_lb.api/create/aws_lb/",
            "aws_ecs_service.api/update/aws_ecs_service/",
            "aws_route53_record.api/create/aws_route53_record/",
            // The read is listed — it is part of the plan — but in no count.
            "data.aws_vpc.main/read/aws_vpc/",
        ],
        "the no-op resource is dropped; the read is kept as a read"
    );
}

#[test]
fn the_counts_hold_when_the_plan_replaces_and_reaches_into_a_module() {
    let tool = Arc::new(FakeIacTool::new().with_plan(parsed("replace.plan.json").changes));
    let outputs = run_with(&tool, site_inputs(), &Arc::new(RecordingSink::new()))
        .expect("the plan is scripted");

    // A replace is one add and one destroy, the way `tofu plan` counts it.
    assert_eq!(outputs.get("adds"), Some(&Value::from(2.0)));
    assert_eq!(outputs.get("changes_count"), Some(&Value::from(0.0)));
    assert_eq!(outputs.get("destroys"), Some(&Value::from(1.0)));
    assert_eq!(outputs.get("empty"), Some(&Value::from(false)));

    assert_eq!(
        rows(&outputs),
        vec![
            "aws_security_group.legacy_api/replace/aws_security_group/",
            "module.net.aws_subnet.a[\"eu-west-1a\"]/create/aws_subnet/module.net",
        ]
    );

    let summary = summary(&outputs);
    assert!(summary.starts_with("Destroys and replacements:"), "{summary}");
    assert!(summary.contains("-/+ aws_security_group.legacy_api"), "{summary}");
    assert!(summary.ends_with("2 to add · 0 to change · 1 to destroy\n"), "{summary}");
}

#[test]
fn an_empty_plan_says_so_and_counts_nothing() {
    let tool = Arc::new(FakeIacTool::new());
    let outputs = run_with(&tool, site_inputs(), &Arc::new(RecordingSink::new()))
        .expect("an empty plan is a plan");

    assert_eq!(outputs.get("adds"), Some(&Value::from(0.0)));
    assert_eq!(outputs.get("changes_count"), Some(&Value::from(0.0)));
    assert_eq!(outputs.get("destroys"), Some(&Value::from(0.0)));
    assert_eq!(outputs.get("empty"), Some(&Value::from(true)));
    assert_eq!(summary(&outputs), "No changes.\n");
}

#[test]
fn the_log_carries_the_digest_and_the_counts_and_nothing_else() {
    let tool = Arc::new(FakeIacTool::new().with_plan(parsed("site.plan.json").changes));
    let sink = Arc::new(RecordingSink::new());
    let outputs = run_with(&tool, site_inputs(), &sink).expect("the plan is scripted");

    // The `file` output is the plan `tofu.apply` will be handed, digest and all:
    // a real sha256, which is what makes apply's tamper check work.
    assert_eq!(file(&outputs, "path"), "/ks-testing/fake-iac/plan-1.tfplan");
    assert!(SavedPlan::new(file(&outputs, "path"), file(&outputs, "sha256")).is_ok());
    // One plan, then that very plan shown.
    let calls = tool.calls();
    assert_eq!(calls.len(), 2, "one plan, one show: {calls:?}");
    assert_eq!(calls[0], IacCall::Plan);
    let IacCall::Show { sha256 } = &calls[1] else {
        panic!("the plan was shown, not something else: {calls:?}");
    };
    assert_eq!(*sha256, file(&outputs, "sha256"));

    let logged: Vec<String> = sink
        .records()
        .iter()
        .flat_map(|record| {
            std::iter::once(record.message.clone())
                .chain(record.fields.iter().map(|(name, value)| format!("{name}={value}")))
        })
        .collect();
    assert!(
        logged.iter().any(|line| line == "plan +2 ~1 -0"),
        "the counts are one line: {logged:?}"
    );
    let digest = file(&outputs, "sha256");
    assert!(logged.iter().any(|line| line.contains(&digest)), "the digest is logged: {logged:?}");

    // Nothing from the document the tool produced: no attribute value, no
    // resource body, no JSON punctuation.
    for secret in ["site-assets", "203.0.113.10", "vpc-0abc123def456", "resource_changes", "{"] {
        assert!(
            !logged.iter().any(|line| line.contains(secret)),
            "{secret:?} reached the log: {logged:?}"
        );
    }
}

#[test]
fn the_backend_and_vars_reach_the_port_as_strings() {
    let tool = Arc::new(FakeIacTool::new().with_plan(parsed("site.plan.json").changes));
    let mut inputs = site_inputs();
    inputs.insert("backend".to_string(), Value::from("s3"));
    inputs.insert(
        "backend_config".to_string(),
        Value::Map(BTreeMap::from([("bucket".to_string(), Value::from("site-tfstate"))])),
    );
    inputs.insert(
        "vars".to_string(),
        Value::Map(BTreeMap::from([("region".to_string(), Value::from("eu-west-1"))])),
    );

    // The fake honours none of it, so what is checked is that a run naming them
    // plans the same directory and reaches the same counts.
    let outputs = run_with(&tool, inputs, &Arc::new(RecordingSink::new()))
        .expect("the backend and vars are accepted");
    assert_eq!(outputs.get("adds"), Some(&Value::from(2.0)));

    let mut inputs = site_inputs();
    inputs.insert(
        "vars".to_string(),
        Value::Map(BTreeMap::from([("replicas".to_string(), Value::from(4.0))])),
    );
    // A silently stringified number is a plan nobody reviewed.
    assert_eq!(
        run_with(&tool, inputs, &Arc::new(RecordingSink::new()))
            .expect_err("a number is not a variable value"),
        StepError::InvalidInput {
            field: "vars".to_string(),
            reason: "`replicas` is a number, not a string".to_string()
        }
    );
}

#[test]
fn a_plan_without_a_tool_port_is_refused() {
    // The harness refuses to build at all: `tofu.plan` requires IacTool. What
    // the step does when one is somehow absent is the port error.
    let ctx = StepCtx::new(
        Ports::default(),
        Arc::new(FakeClock::new()),
        CancellationToken::new(),
        StepLog::new("tofu.plan", Arc::new(Redactor::new()), Arc::new(RecordingSink::new())),
    );
    let error =
        block_on(TofuPlan.run(ctx, site_inputs())).expect_err("there is no tool to plan with");
    assert_eq!(
        error,
        StepError::Port { port: Port::IacTool, message: "no iac tool was provided".to_string() }
    );
}

#[test]
fn the_show_parser_reads_a_document_and_refuses_one_it_cannot() {
    let parsed = parsed("site.plan.json");
    assert_eq!(parsed.changes.len(), 5);
    assert_eq!((parsed.creates(), parsed.updates(), parsed.destroys()), (2, 1, 0));

    // No `resource_changes` at all is an empty plan, not an error.
    let empty = parse_show_json(r#"{"format_version":"1.2"}"#).expect("an empty document");
    assert!(empty.is_empty());

    // Anything that is not a plan document is refused rather than read as an
    // empty one — a plan nobody could see would be a plan nobody reviewed.
    for bad in [
        "{not json",
        r#"{"resource_changes":"nope"}"#,
        r#"{"resource_changes":[{"address":"a.b","change":{"actions":"create"}}]}"#,
        r#"{"resource_changes":[{"address":"a.b","change":{"actions":[7]}}]}"#,
        r#"{"resource_changes":[{"change":{"actions":["create"]}}]}"#,
    ] {
        assert!(matches!(parse_show_json(bad), Err(ShowError::Malformed(_))), "refused: {bad}");
    }
    assert_eq!(
        parse_show_json(
            r#"{"resource_changes":[{"address":"a.b","change":{"actions":["frobnicate"]}}]}"#,
        ),
        Err(ShowError::UnknownAction { action: "frobnicate".to_string() }),
        "an action this parser does not know would otherwise read as no change"
    );
}

#[test]
fn an_address_splits_into_its_module_and_type() {
    for (address, module, kind) in [
        ("aws_lb.api", "", "aws_lb"),
        ("data.aws_vpc.main", "", "aws_vpc"),
        ("module.net.aws_subnet.a[\"eu-west-1a\"]", "module.net", "aws_subnet"),
        ("module.a.module.b[\"x\"].aws_iam_role.r", "module.a.module.b[\"x\"]", "aws_iam_role"),
        // A dot inside an index key belongs to the key, not to the address.
        ("aws_subnet.a[\"eu.west-1a\"]", "", "aws_subnet"),
        ("module.net.data.aws_ami.base", "module.net", "aws_ami"),
    ] {
        assert_eq!(address_parts(address), (module.to_string(), kind.to_string()), "{address}");
    }
}

/// The acceptance case for [#101]: an apply whose plan contains a *replace* is
/// a destroy, so the site's policy asks `@platform` for it.
///
/// The count comes from the plan the adapter read, through
/// [`PlanJson::destroys`] — the same count `tofu.plan` reports in its
/// `destroys` output, so there is no second, disagreeing definition of "this
/// plan destroys something" anywhere in the tree.
#[test]
fn an_apply_whose_plan_replaces_is_classified_as_a_destroy() {
    use ks_core::policy::{Source, decide};
    use ks_core::ports::policy::Disposition;
    use ks_core::ports::run_context::ActorKind;
    use ks_core::step::{ActionClass, ActionKind};
    use ks_core::{Catalog, CheckOptions, check_with};

    let replaces = parsed("replace.plan.json").destroys();
    let creates = parsed("site.plan.json").destroys();
    assert_eq!(replaces, 1, "a replace is a delete plus a create");
    assert_eq!(creates, 0);

    let apply = ActionClass::new(ActionKind::Apply);
    assert_eq!(apply.clone().with_plan_destroys(replaces).kind, ActionKind::Destroy);
    assert_eq!(apply.clone().with_plan_destroys(creates).kind, ActionKind::Apply);

    // The site's policy block, over a file whose only consequential step is
    // the apply: `apply` sits under `before:`, `can:` does not mention it.
    let site = include_str!("../../lang/tests/fixtures/site-policy.ks");
    let src = format!(
        "\
envs:
  staging:
    ci-only: true
  prod:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
  plan: tofu.plan
    dir: ./infra
  apply: tofu.apply
    plan: plan.file
  deploy: k8s.rollout
    image: build.digest
{site}"
    );
    let checked = check_with(&ks_lang::parse(&src), &CheckOptions::new(&Catalog::builtin()));
    assert!(
        !checked.diagnostics.iter().any(|d| d.severity == ks_lang::Severity::Error),
        "{:#?}",
        checked.diagnostics
    );

    let decision = decide(
        checked.workflow.policy(),
        None,
        ActorKind::Agent,
        &apply.with_plan_destroys(replaces),
    )
    .expect("destroy is governed");
    assert_eq!(decision.disposition, Disposition::Ask, "not `can:`");
    assert_eq!(decision.ask, ["platform"], "the file names who is asked");
    assert_eq!(decision.source, Source::File);
}
