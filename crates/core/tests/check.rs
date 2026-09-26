//! Checker acceptance tests, run against the site fixtures and inline files.

use ks_core::{EnvChoice, Trigger, TriggerKind, check, select_env};

const HERO: &str = include_str!("../../lang/tests/fixtures/site-hero.ks");
const POLICY: &str = include_str!("../../lang/tests/fixtures/site-policy.ks");

fn messages(src: &str) -> Vec<String> {
    ks_core::check(&ks_lang::parse(src))
        .diagnostics
        .iter()
        .map(std::string::ToString::to_string)
        .collect()
}

fn errors(src: &str) -> Vec<String> {
    ks_core::check(&ks_lang::parse(src))
        .diagnostics
        .iter()
        .filter(|d| format!("{} {}", d.severity, d.message).contains("error"))
        .map(std::string::ToString::to_string)
        .collect()
}

#[test]
fn hero_checks_clean_and_builds_the_expected_graph() {
    let checked = check(&ks_lang::parse(HERO));
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);

    let mut edges: Vec<_> = checked.workflow.edges().to_vec();
    edges.sort();
    let mut expected: Vec<_> = vec![
        ("build", "deploy"),
        ("plan", "review"),
        ("review", "apply"), // review gates apply, the other consumer of plan
        ("plan", "apply"),
        ("apply", "deploy"),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_string(), b.to_string()))
    .collect();
    expected.sort();
    assert_eq!(edges, expected);

    let order = checked.workflow.topo_order().expect("acyclic");
    let pos = |n: &str| order.iter().position(|s| s == n).expect("step in order");
    assert!(pos("build") < pos("deploy"));
    assert!(pos("plan") < pos("review"));
    assert!(pos("review") < pos("apply"));
    assert!(pos("apply") < pos("deploy"));
    assert_eq!(checked.workflow.name(), Some("api"));
    assert_eq!(checked.workflow.triggers()[0].kind, ks_core::TriggerKind::Push);
}

const DECIDE: &str = "\
name: decide-demo
steps:
  plan: tofu.plan
    dir: ./infra
  risk: decide
    model: typesafe/jev
    ask: \"How risky is this plan?\"
    input: plan.changes
    returns: low | medium | high
  review: approval
    auto: risk is low \u{2265} 0.95
             and plan.destroys == 0
    else: ask @platform, show risk.reason
";

#[test]
fn auto_types_against_the_declared_answers() {
    let checked = check(&ks_lang::parse(DECIDE));
    assert!(
        !checked.diagnostics.iter().any(|d| format!("{:?}", d.severity) == "Error"),
        "{:#?}",
        checked.diagnostics
    );
}

#[test]
fn misspelled_answer_gets_did_you_mean() {
    let src = DECIDE.replace("risk is low", "risk is mediumn");
    let all = messages(&src);
    assert!(
        all.iter().any(|m| m.contains("unknown answer `mediumn`") && m.contains("`medium`")),
        "{all:?}"
    );
}

#[test]
fn forward_references_are_fine_but_cycles_are_reported_with_their_path() {
    let src = "\
name: loop
steps:
  a: decide
    model: m
    ask: \"q?\"
    input: b.out.x
    returns: low | high
  b: decide
    model: m
    ask: \"q?\"
    input: a.answer
    returns: low | high
";
    let diags = check(&ks_lang::parse(src)).diagnostics;
    assert!(
        diags.iter().any(|d| d.message == "cycle: a → b → a"),
        "expected the exact two-step path, got {:#?}",
        diags
    );

    let src = "steps:\n  c: decide\n    model: m\n    ask: \"q?\"\n    input: c.out.x\n";
    let diags = check(&ks_lang::parse(src)).diagnostics;
    assert!(
        diags.iter().any(|d| d.message == "cycle: c → c"),
        "a self-cycle names itself once, got {:#?}",
        diags
    );

    // Forward references alone are fine: the order comes from the data.
    let src = "\
steps:
  deploy: k8s.rollout
    image: build.digest
  build: oci.image
    from: ./Dockerfile
";
    assert!(errors(src).is_empty(), "{:?}", errors(src));
}

#[test]
fn interpolating_a_secret_fails_with_a_hint() {
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
    push: ghcr.io/acme/api:{secrets.token}
";
    let all = messages(src);
    assert!(
        all.iter().any(|m| m.contains("secret `secrets.token` cannot be interpolated")
            && m.contains("secrets never go into strings or logs")),
        "{all:?}"
    );
}

#[test]
fn misspelled_step_gets_did_you_mean() {
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: biuld.digest
";
    let all = messages(src);
    assert!(
        all.iter()
            .any(|m| m.contains("unknown step or context value `biuld`") && m.contains("`build`")),
        "{all:?}"
    );
}

#[test]
fn type_mismatch_hints_the_output_with_the_wanted_type() {
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.tag
";
    let all = messages(src);
    assert!(
        all.iter()
            .any(|m| m.contains("expected `oci.Digest`, got `String`")
                && m.contains("`build.digest`")),
        "{all:?}"
    );
}

#[test]
fn runtime_outputs_live_under_out() {
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
  plan: tofu.plan
    dir: ./infra
  apply: tofu.apply
    plan: plan.file
  deploy: k8s.rollout
    image: build.digest
    to: apply.digest
";
    let all = messages(src);
    assert!(all.iter().any(|m| m.contains("apply.out.")), "{all:?}");
    // The `out.` form itself is accepted without verification.
    let src = src.replace("apply.digest", "apply.out.cluster");
    assert!(errors(&src).is_empty(), "{:?}", errors(&src));
}

#[test]
fn optional_context_values_warn() {
    let src = "\
steps:
  review: approval
    show: pr.number
    from: @platform
";
    let checked = check(&ks_lang::parse(src));
    assert!(
        checked
            .diagnostics
            .iter()
            .any(|d| format!("{:?}", d.severity) == "Warning" && d.message.contains("`pr.number`")),
        "{:#?}",
        checked.diagnostics
    );
}

#[test]
fn when_tests_the_declared_environments() {
    let with_envs = "\
envs:
  prod:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    when: env is prod
    image: build.digest
";
    assert!(errors(with_envs).is_empty(), "{:?}", errors(with_envs));

    let without = with_envs.replace("envs:\n  prod:\n    ci-only: true\n", "");
    let all = messages(&without);
    assert!(all.iter().any(|m| m.contains("unknown environment `prod`")), "{all:?}");
}

const POLICY_FILE: &str = "\
name: policy-demo
envs:
  staging:
    ci-only: true
  prod:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
";

#[test]
fn policy_type_checks_against_declared_environments() {
    let src = format!("{POLICY_FILE}{POLICY}");
    assert!(errors(&src).is_empty(), "{:?}", errors(&src));

    // Without `envs:` the policy's `deploy prod` names nothing.
    let src = format!("steps:\n  build: oci.image\n    from: ./Dockerfile\n{POLICY}");
    let all = messages(&src);
    assert!(all.iter().any(|m| m.contains("undeclared environment `prod`")), "{all:?}");

    let src = format!("{POLICY_FILE}policy:\n  robots:\n    can: apply\n");
    let all = messages(&src);
    assert!(all.iter().any(|m| m.contains("unknown policy subject `robots`")), "{all:?}");
    assert!(
        !all.iter().any(|m| m.contains("expected an action")),
        "`can: apply` is a well-formed action: {all:?}"
    );
}

#[test]
fn environments_and_the_implicit_default() {
    let checked = check(&ks_lang::parse(HERO));
    let names: Vec<_> = checked.workflow.envs().iter().map(|e| e.name.clone()).collect();
    assert_eq!(names, ["default"]);

    let src = format!("{POLICY_FILE}policy:\n  agents:\n    can: read secrets\n");
    let checked = check(&ks_lang::parse(&src));
    let names: Vec<_> = checked.workflow.envs().iter().map(|e| e.name.clone()).collect();
    assert_eq!(names, ["staging", "prod"]);
}

#[test]
fn triggers_are_checked() {
    let src = "on: schedule 5m\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n";
    let all = messages(src);
    assert!(all.iter().any(|m| m.contains("`schedule` triggers are not supported yet")), "{all:?}");

    let src = "on: psh main\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n";
    let all = messages(src);
    assert!(
        all.iter().any(|m| m.contains("unknown trigger `psh`") && m.contains("`push`")),
        "{all:?}"
    );
}

#[test]
fn tuple_items_and_single_words_are_seen_as_atoms() {
    // Normalization happens at every level, so tuple items and one-atom
    // values arrive as plain atoms — the checker must not lose them.

    // `show:` with two items: both are references, no false
    // "expected a reference".
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
  review: approval
    from: @platform
    show: build.digest, build.tag
";
    assert!(errors(src).is_empty(), "{:?}", errors(src));

    // The approval shows `build`'s output, so it still gates `build`'s
    // other consumer.
    let src = format!("{src}  deploy: k8s.rollout\n    image: build.digest\n");
    let checked = check(&ks_lang::parse(&src));
    assert!(errors(&src).is_empty(), "{:?}", errors(&src));
    assert!(
        checked.workflow.edges().contains(&("review".to_string(), "deploy".to_string())),
        "{:?}",
        checked.workflow.edges()
    );

    // `on: pr`, `on: manual`, `on: push main`: triggers, not
    // "expected a trigger".
    for on in ["pr", "manual", "push main"] {
        let src = format!("on: {on}\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n");
        let checked = check(&ks_lang::parse(&src));
        assert!(errors(&src).is_empty(), "{on}: {:?}", errors(&src));
        assert_eq!(checked.workflow.triggers().len(), 1, "{on}");
    }
    let src = "on: push main, tag v*\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n";
    assert_eq!(check(&ks_lang::parse(src)).workflow.triggers().len(), 2);

    // `can: apply` is one action, not "expected an action".
    let src = format!("{POLICY_FILE}policy:\n  agents:\n    can: apply\n");
    assert!(errors(&src).is_empty(), "{:?}", errors(&src));

    // `approvers:` items are handles; a non-handle item is diagnosed.
    let src = "\
envs:
  prod:
    approvers: notahandle, @platform
steps:
  build: oci.image
    from: ./Dockerfile
";
    let all = messages(src);
    assert!(all.iter().any(|m| m.contains("expected `Handle`, got `notahandle`")), "{all:?}");

    // Same for a policy `ask:` tuple.
    let src = format!("{POLICY_FILE}policy:\n  humans:\n    ask: notahandle, @platform\n");
    let all = messages(&src);
    assert!(all.iter().any(|m| m.contains("expected `Handle`, got `notahandle`")), "{all:?}");
}

#[test]
fn glob_matching_stays_linear_with_many_stars() {
    // Every `*` used to retry every suffix: 30 stars meant an exponential
    // search. The greedy matcher answers instantly even without a match.
    let pattern = format!("{}b", "*a".repeat(30));
    let src = format!(
        "envs:\n  prod:\n    on: push {pattern}\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n"
    );
    let wf = check(&ks_lang::parse(&src)).workflow;
    let event =
        Trigger { kind: TriggerKind::Push, glob: Some("a".repeat(30)), span: Default::default() };
    let started = std::time::Instant::now();
    let choice = select_env(&wf, None, Some(&event));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "glob matching exploded on many stars"
    );
    // No environment's `on:` matches, so the single declared one is used.
    assert_eq!(choice, Ok(EnvChoice::Selected("prod".into())));
}

#[test]
fn optional_context_values_compare_against_bare_types() {
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
    when: git.tag != \"\"
";
    let checked = check(&ks_lang::parse(src));
    assert!(errors(src).is_empty(), "{:?}", errors(src));
    // The use-site warning for optional values stays.
    assert!(
        checked
            .diagnostics
            .iter()
            .any(|d| format!("{:?}", d.severity) == "Warning" && d.message.contains("`git.tag`")),
        "{:#?}",
        checked.diagnostics
    );
}

#[test]
fn secrets_cannot_be_shown() {
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
  review: approval
    from: @platform
    show: secrets.api_key
    else: show secrets.token
";
    let all = messages(src);
    assert!(
        all.iter().any(|m| m.contains("secret `secrets.api_key` cannot be shown")
            && m.contains("secrets never go into strings or logs")),
        "{all:?}"
    );
    assert!(all.iter().any(|m| m.contains("secret `secrets.token` cannot be shown")), "{all:?}");
}

#[test]
fn interpolation_in_a_path_is_reported_once() {
    // The value walk and the string check used to each report it.
    let src = "\
steps:
  build: oci.image
    from: \"{secrets.t}\"
";
    let all = messages(src);
    assert_eq!(
        all.iter().filter(|m| m.contains("interpolation is not allowed")).count(),
        1,
        "{all:?}"
    );
}

#[test]
fn checked_diagnostics_are_in_source_order() {
    // The parser's missing-value error sits after the checker's unknown
    // reference in the file; the report must still be in source order.
    let src = "\
steps:
  deploy: k8s.rollout
    image: nope.digest
  build:
";
    let diags = check(&ks_lang::parse(src)).diagnostics;
    let starts: Vec<_> = diags.iter().map(|d| d.span.start).collect();
    assert!(starts.windows(2).all(|w| w[0] <= w[1]), "{:#?}", diags);
    assert!(diags.iter().any(|d| d.message.contains("unknown step or context value `nope`")));
    assert!(diags.iter().any(|d| d.message.contains("missing value for `build`")));
}

#[test]
fn deeply_nested_input_still_checks() {
    // The parser caps nesting on adversarial input; the checker must handle
    // the capped tree (and select an environment) without blowing up.
    let checked = check(&ks_lang::parse(&format!("a: {}\n", "(".repeat(20_000))));
    assert!(checked.workflow.steps().is_empty());
    assert!(ks_core::select_env(&checked.workflow, None, None).is_ok());
}

#[test]
fn a_wide_graph_checks_fast_and_orders_every_step() {
    // 600 steps, each plan gated by an approval that shows it: building the
    // graph used to scan edges linearly per lookup, which made checking time
    // explode on wide files.
    let mut src = String::new();
    for i in 0..200 {
        src.push_str(&format!(
            "steps:\n  plan{i}: tofu.plan\n    dir: ./{i}\n  gate{i}: approval\n    show: \
             plan{i}.file\n  apply{i}: tofu.apply\n    plan: plan{i}.file\n"
        ));
    }
    let checked = check(&ks_lang::parse(&src));
    assert!(
        checked.diagnostics.is_empty(),
        "{:#?}",
        checked.diagnostics.iter().take(3).collect::<Vec<_>>()
    );
    assert_eq!(checked.workflow.steps().len(), 600);
    assert_eq!(checked.workflow.edges().len(), 600); // plan→gate, plan→apply, gate→apply
    let order = checked.workflow.topo_order().expect("acyclic");
    assert_eq!(order.len(), 600);
    let pos = |n: &str| order.iter().position(|s| s == n).expect("step in order");
    for i in 0..200 {
        assert!(pos(&format!("plan{i}")) < pos(&format!("gate{i}")));
        assert!(pos(&format!("gate{i}")) < pos(&format!("apply{i}")));
    }
}

// --- select_env ------------------------------------------------------------

fn hero_workflow() -> ks_core::Workflow {
    check(&ks_lang::parse(HERO)).workflow
}

fn two_env_workflow() -> ks_core::Workflow {
    let src = format!("{POLICY_FILE}policy:\n  agents:\n    can: read secrets\n");
    check(&ks_lang::parse(&src)).workflow
}

#[test]
fn select_env_prefers_the_request_then_the_event_then_uniqueness() {
    // A file without `envs:` has exactly one implicit environment.
    assert_eq!(select_env(&hero_workflow(), None, None), Ok(EnvChoice::Selected("default".into())));

    let wf = two_env_workflow();
    assert_eq!(select_env(&wf, Some("prod"), None), Ok(EnvChoice::Selected("prod".into())));
    assert_eq!(
        select_env(&wf, None, None),
        Ok(EnvChoice::Ambiguous(vec!["staging".into(), "prod".into()]))
    );
    let err = select_env(&wf, Some("prodd"), None).expect_err("unknown env");
    assert!(err.to_string().contains("did you mean `prod`?"), "{err}");

    // An event picks the one environment whose `on:` matches.
    let src = "\
envs:
  staging:
    on: push main
  prod:
    on: tag v*
steps:
  build: oci.image
    from: ./Dockerfile
";
    let wf = check(&ks_lang::parse(src)).workflow;
    let push_main =
        Trigger { kind: TriggerKind::Push, glob: Some("main".into()), span: Default::default() };
    let tag_v1 =
        Trigger { kind: TriggerKind::Tag, glob: Some("v1".into()), span: Default::default() };
    assert_eq!(select_env(&wf, None, Some(&push_main)), Ok(EnvChoice::Selected("staging".into())));
    assert_eq!(select_env(&wf, None, Some(&tag_v1)), Ok(EnvChoice::Selected("prod".into())));
    assert_eq!(
        select_env(&wf, Some("prod"), Some(&push_main)),
        Ok(EnvChoice::Selected("prod".into())),
        "an explicit request wins over the event"
    );
}
