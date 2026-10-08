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
        all.iter().any(|m| m.contains("expected oci.Digest, got oci.Tag")
            && m.contains("use build.digest so prod runs exactly the image you built")),
        "{all:?}"
    );
}

#[test]
fn a_rationale_less_type_hint_says_what_the_output_is() {
    let src = "\
steps:
  plan: tofu.plan
    dir: ./infra
  apply: tofu.apply
    plan: plan.changes
";
    let all = messages(src);
    assert!(
        all.iter().any(|m| m.contains("expected tofu.PlanFile, got tofu.Changes")
            && m.contains("use plan.file, which is a tofu.PlanFile")),
        "{all:?}"
    );
}

#[test]
fn a_tofu_plan_file_cannot_be_applied_by_terraform() {
    let src = "\
steps:
  plan: tofu.plan
    dir: ./infra
  apply: terraform.apply
    plan: plan.file
";
    let all = messages(src);
    assert!(
        all.iter().any(|m| m.contains("expected terraform.PlanFile, got tofu.PlanFile")),
        "{all:?}"
    );
}

#[test]
fn a_terraform_plan_applies_through_terraform() {
    let src = "\
steps:
  plan: terraform.plan
    dir: ./infra
  apply: terraform.apply
    plan: plan.file
";
    assert!(errors(src).is_empty(), "{:?}", errors(src));
}

#[test]
fn a_pasted_digest_literal_warns_and_names_the_reference() {
    let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let src = format!(
        "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: \"sha256:{digest}\"
"
    );
    let checked = check(&ks_lang::parse(&src));
    let warns: Vec<_> = checked
        .diagnostics
        .iter()
        .filter(|d| matches!(d.severity, ks_lang::Severity::Warning))
        .collect();
    assert_eq!(warns.len(), 1, "{:#?}", checked.diagnostics);
    assert_eq!(warns[0].message, "digest literal pinned by value");
    assert_eq!(
        warns[0].hints.as_slice(),
        ["pin by reference, not by pasted digest: use build.digest"]
    );
}

#[test]
fn an_unquoted_digest_literal_is_one_word_and_warns_too() {
    let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let src = format!(
        "\
steps:
  deploy: k8s.rollout
    image: sha256:{digest}
  build: oci.image
    from: ./Dockerfile
"
    );
    let all = messages(&src);
    assert!(
        all.iter().any(|m| m.contains("digest literal pinned by value")
            && m.contains("pin by reference, not by pasted digest")),
        "{all:?}"
    );
}

#[test]
fn a_digest_literal_must_actually_be_a_digest() {
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: \"sha256:not-hex\"
";
    let all = messages(src);
    assert!(all.iter().any(|m| m.contains("expected oci.Digest, got string")), "{all:?}");
}

#[test]
fn a_rollout_pins_what_it_deploys_by_reference_and_by_container_name() {
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
    manifests: ./k8s
    namespace: prod
    rollback: none
    images:
      sidecar: build.digest
";
    assert!(errors(src).is_empty(), "{:?}", errors(src));

    // A tag typed in where a digest belongs is the same mistake as a pasted
    // digest: the checker reads both as a string where it wanted a digest.
    let tagged = src.replace("image: build.digest", "image: \"ghcr.io/acme/api:1.2\"");
    let all = messages(&tagged);
    assert!(all.iter().any(|m| m.contains("expected oci.Digest, got string")), "{all:?}");
}

#[test]
fn a_string_is_never_another_familys_type() {
    let src = "\
steps:
  apply: tofu.apply
    plan: \"./infra/tfplan\"
";
    let all = messages(src);
    assert!(all.iter().any(|m| m.contains("expected tofu.PlanFile, got string")), "{all:?}");
}

/// `oci.artifact` is in the builtin catalog, so its inputs are typed: a
/// `files` that is not a list is rejected rather than passing unchecked.
#[test]
fn an_artifact_step_is_typed_by_the_builtin_catalog() {
    let src = "\
steps:
  chart: oci.artifact
    files: ./chart.tgz
    type: helm
    push: registry.example/charts/app:1.0.0
";
    let all = messages(src);
    assert!(all.iter().any(|m| m.contains("expected list[any], got path")), "{all:?}");
}

#[test]
fn a_well_formed_artifact_step_checks_clean() {
    let src = "\
steps:
  chart: oci.artifact
    files:
      - ./chart.tgz
    type: helm
    push: registry.example/charts/app:1.0.0
    subject: \"sha256:\
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"
";
    let all = errors(src);
    assert!(all.is_empty(), "{all:?}");
}

#[test]
fn a_custom_catalog_types_its_own_steps() {
    use ks_core::step::{Field, StepSchema, TypeRef};
    let mut catalog = ks_core::Catalog::builtin();
    catalog
        .add_schema(
            "web.deploy",
            &StepSchema {
                doc: "deploy the web service",
                inputs: vec![
                    Field::new("replicas", TypeRef::Named("int"), "how many"),
                    Field::new("image", TypeRef::Named("oci.Digest"), "what"),
                    Field::new("tags", TypeRef::Named("list[string]"), "labels"),
                    Field::new("size", TypeRef::Named("s | m | l"), "which size"),
                    Field::new("endpoint", TypeRef::Named("url"), "where"),
                ],
                outputs: vec![],
            },
        )
        .expect("the schema joins");
    let options = ks_core::CheckOptions::new(&catalog);
    let check = |src: &str| ks_core::check_with(&ks_lang::parse(src), &options);

    let src = "\
steps:
  deploy: web.deploy
    replicas: int = 2
    image: build.digest
    tags: api, edge
    size: m
    endpoint: https://api.acme.dev
  build: oci.image
    from: ./Dockerfile
";
    assert!(check(src).diagnostics.is_empty(), "{:#?}", check(src).diagnostics);

    // A default that is no literal of its annotation, an enum word that
    // names no variant, a host that is no url.
    let bad = src.replace("replicas: int = 2", "replicas: int = two");
    assert!(check(&bad).diagnostics.iter().any(|d| d.message == "expected int, got string"));
    let bad = src.replace("size: m", "size: xxl");
    assert!(check(&bad).diagnostics.iter().any(|d| d.message == "expected s | m | l, got string"));
    let bad = src.replace("endpoint: https://api.acme.dev", "endpoint: \"api.acme.dev\"");
    assert!(check(&bad).diagnostics.iter().any(|d| d.message == "expected url, got string"));
}

#[test]
fn a_record_input_checks_positionally_and_a_list_element_wise() {
    use ks_core::step::{Field, StepSchema, TypeRef};
    let mut catalog = ks_core::Catalog::builtin();
    catalog
        .add_schema(
            "web.rollout",
            &StepSchema {
                doc: "roll out",
                inputs: vec![
                    Field::new(
                        "wait",
                        TypeRef::Named("{healthy: bool, grace: duration, port: int}"),
                        "when ready",
                    ),
                    Field::new("hosts", TypeRef::Named("list[int]"), "which hosts"),
                ],
                outputs: vec![],
            },
        )
        .expect("the schema joins");
    let options = ks_core::CheckOptions::new(&catalog);
    let check = |src: &str| ks_core::check_with(&ks_lang::parse(src), &options);

    let src = "steps:\n  d: web.rollout\n    wait: true, 5m, 8080\n    hosts: 1, 2\n";
    assert!(check(src).diagnostics.is_empty(), "{:#?}", check(src).diagnostics);

    let bad = "steps:\n  d: web.rollout\n    wait: 5m, true, 8080\n    hosts: 1, 2\n";
    assert!(check(bad).diagnostics.iter().any(|d| d.message == "expected bool, got duration"));
    let bad = "steps:\n  d: web.rollout\n    wait: true, 5m\n    hosts: 1, 2\n";
    assert!(check(bad).diagnostics.iter().any(|d| {
        d.message == "expected {healthy: bool, grace: duration, port: int}, got 2 items"
    }));
    let bad = "steps:\n  d: web.rollout\n    wait: true, 5m\n    hosts: 1, x\n";
    assert!(check(bad).diagnostics.iter().any(|d| d.message == "expected int, got string"));
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

const AFTER: &str = "\
steps:
  build: oci.image
    from: ./Dockerfile
  plan: tofu.plan
    dir: ./infra
  apply: tofu.apply
    after: plan
    plan: plan.file
  deploy: k8s.rollout
    after: build, apply
    image: build.digest
";

#[test]
fn after_orders_without_data() {
    let checked = check(&ks_lang::parse(AFTER));
    assert!(errors(AFTER).is_empty(), "{:?}", checked.diagnostics);
    let mut edges: Vec<_> = checked.workflow.edges().to_vec();
    edges.sort();
    assert_eq!(
        edges,
        [
            ("apply".to_string(), "deploy".to_string()),
            ("build".to_string(), "deploy".to_string()),
            ("plan".to_string(), "apply".to_string()),
        ]
    );
    let order = checked.workflow.topo_order().expect("acyclic");
    assert_eq!(order, ["build", "plan", "apply", "deploy"]);
}

#[test]
fn after_names_an_unknown_step_like_a_reference_and_a_loop_is_a_cycle() {
    let misspelt = AFTER.replace("after: build, apply", "after: bild, apply");
    let all = messages(&misspelt);
    assert!(all.iter().any(|m| m.contains("`after:` names no step `bild`")), "{all:?}");
    assert!(all.iter().any(|m| m.contains("did you mean `build`?")), "{all:?}");

    let loop_ = AFTER.replace("after: plan", "after: apply");
    let all = messages(&loop_);
    assert!(all.iter().any(|m| m.contains("cycle: apply → apply")), "{all:?}");
}

#[test]
fn after_takes_quoted_names_and_says_so_about_anything_else() {
    let quoted = AFTER.replace("after: plan", "after: \"plan\"");
    let checked = check(&ks_lang::parse(&quoted));
    assert!(errors(&quoted).is_empty(), "{:#?}", checked.diagnostics);
    assert!(checked.workflow.edges().contains(&("plan".to_string(), "apply".to_string())));
    // A quoted name is a name, not a string value: an unknown one is still
    // the unknown-reference diagnostic.
    let unknown = quoted.replace("after: \"plan\"", "after: \"plann\"");
    assert!(messages(&unknown).iter().any(|m| m.contains("names no step `plann`")));

    // A value that is not a name cannot order anything, and says so rather
    // than being ignored.
    for bad in ["after: 3", "after: plan == 3", "after: [plan]"] {
        let src = AFTER.replace("after: plan", bad);
        let all = messages(&src);
        assert!(all.iter().any(|m| m.contains("`after:` takes step names")), "{bad}: {all:?}");
    }
}

#[test]
fn an_after_edge_orders_without_making_the_follower_a_consumer() {
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
  review: approval
    show: build.digest
    from: @platform
  apply: oci.image
    after: build
    from: ./Dockerfile
";
    let checked = check(&ks_lang::parse(src));
    assert!(errors(src).is_empty(), "{:#?}", checked.diagnostics);
    // `apply` follows `build` without reading anything of it, so the approval
    // that shows `build` has no consumer to gate: no `review → apply`.
    let mut edges: Vec<_> = checked.workflow.edges().to_vec();
    edges.sort();
    assert_eq!(
        edges,
        [("build".to_string(), "apply".to_string()), ("build".to_string(), "review".to_string()),],
        "{:#?}",
        checked.diagnostics
    );
}

#[test]
fn a_data_edge_alongside_an_after_one_still_makes_the_follower_a_consumer() {
    // `image:` before `after:`, and the other way round: the same file either
    // way. Reading `build` is what makes `deploy` a consumer of it, so the
    // approval that shows `build` gates it — whichever edge the file mentions
    // first.
    let build = "\
steps:
  build: oci.image
    from: ./Dockerfile
  review: approval
    show: build.digest
    from: @platform
  deploy: k8s.rollout
";
    let want = [
        ("build".to_string(), "deploy".to_string()),
        ("build".to_string(), "review".to_string()),
        ("review".to_string(), "deploy".to_string()),
    ];
    for deploy in [
        "    image: build.digest\n    after: build\n",
        "    after: build\n    image: build.digest\n",
    ] {
        let src = format!("{build}{deploy}");
        let checked = check(&ks_lang::parse(&src));
        assert!(errors(&src).is_empty(), "{deploy}: {:#?}", checked.diagnostics);
        let mut edges: Vec<_> = checked.workflow.edges().to_vec();
        edges.sort();
        assert_eq!(edges, want, "{deploy}: the approval stopped gating the follower");
    }
}

#[test]
fn a_when_names_the_steps_it_reads_and_is_evaluable_only_without_them() {
    let checked = check(&ks_lang::parse(AFTER));
    assert!(checked.workflow.step("deploy").expect("deploy").when.is_none());

    let src = "\
envs:
  prod:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
  one: oci.image
    when: env is prod
    from: ./Dockerfile
  two: oci.image
    when: not env is prod
    from: ./Dockerfile
  three: k8s.rollout
    when: build.signed
    image: build.digest
";
    let checked = check(&ks_lang::parse(src));
    assert!(errors(src).is_empty(), "{:#?}", checked.diagnostics);
    let when =
        |name: &str| checked.workflow.step(name).and_then(|s| s.when.as_ref()).expect("a when");
    assert_eq!(when("one").test, Some(ks_core::ContextTest::EnvIs { env: "prod".into() }));
    assert_eq!(when("one").steps, Vec::<String>::new());
    assert_eq!(
        when("two").test,
        Some(ks_core::ContextTest::Not(Box::new(ks_core::ContextTest::EnvIs {
            env: "prod".into()
        })))
    );
    // Reading a step output keeps the condition for the run, and makes the
    // step it reads run first.
    assert_eq!(when("three").steps, ["build"]);
    assert_eq!(when("three").test, None);
    assert!(checked.workflow.edges().contains(&("build".to_string(), "three".to_string())));
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

// --- secrets are typed (#27 AC1) -------------------------------------------

#[test]
fn a_secret_into_a_string_or_tag_input_errors_with_the_secret_hint() {
    // `model` is a `string`; `push` is an `oci.Tag`. Neither takes a secret.
    let src = "\
steps:
  judge: decide
    model: secrets.db_url
  build: oci.image
    from: ./Dockerfile
    push: secrets.token
";
    let all = messages(src);
    assert!(
        all.iter().any(|m| m.contains("expected string, got Secret")
            && m.contains("secrets flow only into inputs typed Secret")),
        "{all:?}"
    );
    assert!(
        all.iter().any(|m| m.contains("expected oci.Tag, got Secret")
            && m.contains("secrets flow only into inputs typed Secret")),
        "{all:?}"
    );
}

#[test]
fn a_secret_interpolates_nowhere_in_a_word_or_a_string() {
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
    push: ghcr.io/acme/api:{secrets.token}
  judge: decide
    model: \"token is {secrets.token}\"
";
    let all = messages(src);
    let seen = all.iter().filter(|m| {
        m.contains("secret `secrets.token` cannot be interpolated into a string")
            && m.contains("secrets never go into strings or logs")
    });
    assert_eq!(seen.count(), 2, "once per spelling, word and quoted string: {all:?}");
}

#[test]
fn a_step_output_typed_secret_is_refused_before_any_file_is_checked() {
    use ks_core::step::{
        ActionClass, ActionKind, Field, Inputs, Outputs, Port, Ports, StepCtx, StepError, StepKind,
        StepSchema, TypeRef, Version,
    };

    struct LeakyStep;

    impl StepKind for LeakyStep {
        fn name(&self) -> &'static str {
            "leaky.step"
        }

        fn version(&self) -> Version {
            Version::new(1, 0, 0)
        }

        fn schema(&self) -> StepSchema {
            StepSchema {
                doc: "would emit a secret as an output",
                inputs: vec![],
                outputs: vec![Field::new("token", TypeRef::Named("Secret"), "the token")],
            }
        }

        fn requires(&self) -> &'static [Port] {
            &[]
        }

        fn action(&self, _inputs: &Inputs) -> ActionClass {
            ActionClass::new(ActionKind::Other)
        }

        fn run(
            &self,
            _ctx: StepCtx,
            _inputs: Inputs,
        ) -> ks_core::ports::BoxFuture<'_, Result<Outputs, StepError>> {
            Box::pin(std::future::ready(Ok(Outputs::new())))
        }
    }

    // `add_schema` refuses, so `check_with` can never see a Secret output.
    let mut catalog = ks_core::Catalog::builtin();
    let err = catalog
        .add_schema(
            "leaky.step",
            &StepSchema {
                doc: "would emit a secret as an output",
                inputs: vec![],
                outputs: vec![Field::new("token", TypeRef::Named("Secret"), "the token")],
            },
        )
        .expect_err("secret output refused");
    assert_eq!(err.to_string(), "step outputs cannot be Secret in v1");
    // The refused schema joined nothing: the name is still free.
    catalog
        .add_schema("leaky.step", &StepSchema { doc: "harmless", inputs: vec![], outputs: vec![] })
        .expect("the refused name stayed free");

    // The harness route is closed too, so `Catalog::from_harness` cannot
    // carry one in behind the checker's back.
    struct ZeroClock;
    impl ks_core::ports::clock::Clock for ZeroClock {
        fn now(&self) -> std::time::SystemTime {
            std::time::SystemTime::UNIX_EPOCH
        }

        fn sleep<'a>(
            &'a self,
            _duration: std::time::Duration,
        ) -> ks_core::ports::BoxFuture<'a, ()> {
            Box::pin(std::future::ready(()))
        }
    }
    let built = ks_core::harness::HarnessBuilder::new()
        .ports(Ports::default().with_clock(std::sync::Arc::new(ZeroClock)))
        .step(LeakyStep)
        .build()
        .expect_err("a harness refuses a Secret output");
    assert!(
        matches!(
            built.errors(),
            [ks_core::harness::CompositionError::SecretOutput { step, output }]
                if step == "leaky.step" && output == "token"
        ),
        "{built}"
    );
}

#[test]
fn a_secret_flows_into_an_input_typed_secret() {
    use ks_core::step::{Field, StepSchema, TypeRef};
    let mut catalog = ks_core::Catalog::builtin();
    catalog
        .add_schema(
            "vault.read",
            &StepSchema {
                doc: "uses a secret in the adapter",
                inputs: vec![Field::new("token", TypeRef::Named("Secret"), "the token")],
                outputs: vec![],
            },
        )
        .expect("the schema joins");
    let options = ks_core::CheckOptions::new(&catalog);
    let src = "\
steps:
  read: vault.read
    token: secrets.db_password
";
    let checked = ks_core::check_with(&ks_lang::parse(src), &options);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
    // The run carries the requirement even though nothing leaks.
    assert_eq!(checked.secret_uses.len(), 1);
    assert_eq!(checked.secret_uses[0].key, "db_password");
    assert_eq!(checked.secret_uses[0].step, "read");
}

// --- policy binds the actor (#27 AC3) --------------------------------------

const SECRET_NEED: &str = "\
envs:
  prod:
    ci-only: true
steps:
  migrate: db.migrate
    url: secrets.db_url
";

#[test]
fn an_agent_needing_secrets_the_policy_forbids_is_refused() {
    let src = format!("{SECRET_NEED}policy:\n  agents:\n    never: read secrets\n");

    // The agent run is refused, at the reference and at the rule.
    let catalog = ks_core::Catalog::builtin();
    let options =
        ks_core::CheckOptions::new(&catalog).actor(ks_core::ports::run_context::ActorKind::Agent);
    let checked = ks_core::check_with(&ks_lang::parse(&src), &options);
    assert!(
        checked.diagnostics.iter().any(|d| d.message
            == "policy forbids agents from reading secrets, but this run needs secrets.db_url"
            && d.hints.as_slice() == ["the rule is `policy: agents: never: read secrets`"]),
        "{:#?}",
        checked.diagnostics
    );
    assert!(
        checked
            .diagnostics
            .iter()
            .any(|d| d.message == "the `never: read secrets` rule applies to this run"),
        "{:#?}",
        checked.diagnostics
    );

    // The same file checks clean for a human.
    let options =
        ks_core::CheckOptions::new(&catalog).actor(ks_core::ports::run_context::ActorKind::Human);
    let checked = ks_core::check_with(&ks_lang::parse(&src), &options);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);

    // And a check with no actor at all stays policy-silent.
    let checked = check(&ks_lang::parse(&src));
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);

    // Two references to the same key are refused once, at the first.
    let src = format!(
        "{SECRET_NEED}  report: db.report\n    url: secrets.db_url\npolicy:\n  agents:\n    \
         never: read secrets\n"
    );
    let options =
        ks_core::CheckOptions::new(&catalog).actor(ks_core::ports::run_context::ActorKind::Agent);
    let checked = ks_core::check_with(&ks_lang::parse(&src), &options);
    let refusals: Vec<_> = checked
        .diagnostics
        .iter()
        .filter(|d| d.message.starts_with("policy forbids agents"))
        .collect();
    assert_eq!(refusals.len(), 1, "one per distinct key, not per reference: {:#?}", refusals);
    assert_eq!(checked.diagnostics.len(), 2, "the refusal plus the one on the rule");
}

#[test]
fn an_agent_runs_when_the_file_needs_no_secrets_or_the_policy_stays_silent() {
    // No secrets, policy or not: nothing to refuse.
    let no_secrets = format!("{SECRET_NEED}policy:\n  agents:\n    never: read secrets\n");
    let no_secrets = no_secrets.replace("    url: secrets.db_url\n", "");
    let catalog = ks_core::Catalog::builtin();
    let options =
        ks_core::CheckOptions::new(&catalog).actor(ks_core::ports::run_context::ActorKind::Agent);
    let checked = ks_core::check_with(&ks_lang::parse(&no_secrets), &options);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);

    // Secrets without the never-rule: the agent may read them.
    let allowed = format!("{SECRET_NEED}policy:\n  agents:\n    can: read secrets\n");
    let checked = ks_core::check_with(&ks_lang::parse(&allowed), &options);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);

    // A rule binding humans does not bind the agent.
    let humans_only = format!("{SECRET_NEED}policy:\n  humans:\n    never: read secrets\n");
    let checked = ks_core::check_with(&ks_lang::parse(&humans_only), &options);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
}

// --- suggested fixes -------------------------------------------------------

/// Splice every fix into `src`, back to front, the way `--fix` does.
fn apply_fixes(src: &str, fixes: &[ks_lang::Fix]) -> String {
    let mut out = src.to_string();
    for f in fixes.iter().rev() {
        out.replace_range(f.span.start as usize..f.span.end as usize, &f.replacement);
    }
    out
}

fn fixes_of(src: &str) -> Vec<ks_lang::Fix> {
    check(&ks_lang::parse(src)).diagnostics.iter().flat_map(|d| d.fixes.iter()).cloned().collect()
}

/// Each case is one diagnostic: the code it carries, the fix it proposes
/// and the bytes that fix names. Applying the fix must leave a file the
/// checker is happy with.
#[test]
fn every_suggestion_rewrites_its_own_span_and_the_file_then_checks_clean() {
    let base = "\
steps:
  build: oci.image
    from: ./Dockerfile
  plan: tofu.plan
    dir: ./infra
  deploy: k8s.rollout
    image: build.digest
";
    // (the misspelling, the code, the replacement, the bytes rewritten)
    let cases = [
        ("image: build.digest", "image: build.tag", "digest", "tag"),
        ("from: ./Dockerfile", "frome: ./Dockerfile", "from", "frome"),
        ("dir: ./infra", "dirr: ./infra", "dir", "dirr"),
    ];
    for (good, bad, replacement, rewritten) in cases {
        let src = base.replace(good, bad);
        let fixes = fixes_of(&src);
        assert_eq!(fixes.len(), 1, "{bad}: {:#?}", fixes_of(&src));
        let fix = &fixes[0];
        assert_eq!(fix.replacement, replacement, "{bad}");
        assert!(fix.machine_applicable, "{bad}: nothing ties it");
        assert_eq!(fix.span.slice(&src), rewritten, "{bad}");
        let fixed = apply_fixes(&src, &fixes);
        assert_eq!(fixed, base, "{bad}: {fixed}");
        let rechecked = check(&ks_lang::parse(&fixed));
        assert!(rechecked.diagnostics.is_empty(), "{bad}: {:#?}", rechecked.diagnostics);
    }
}

#[test]
fn a_misspelled_output_is_fixed_by_rewriting_the_output_segment() {
    let src = "\
steps:
  build: oci.image
    from: ./Dockerfile
  plan: tofu.plan
    dir: ./infra
  review: approval
    show: plan.change
";
    let fixes = fixes_of(src);
    assert_eq!(fixes.len(), 1, "{:#?}", fixes_of(src));
    assert_eq!((fixes[0].replacement.as_str(), fixes[0].machine_applicable), ("changes", true));
    assert_eq!(fixes[0].span.slice(src), "change", "not the whole reference");
    let fixed = apply_fixes(src, &fixes);
    assert!(fixed.contains("show: plan.changes"), "{fixed}");
    assert!(check(&ks_lang::parse(&fixed)).diagnostics.is_empty());
}

#[test]
fn a_tie_is_hinted_but_never_applied() {
    use ks_core::step::{Field, StepSchema, TypeRef};
    let mut catalog = ks_core::Catalog::builtin();
    catalog
        .add_schema(
            "web.deploy",
            &StepSchema {
                doc: "deploy the web service",
                inputs: vec![
                    Field::new("cat", TypeRef::Named("string"), "what"),
                    Field::new("car", TypeRef::Named("string"), "what"),
                ],
                outputs: vec![],
            },
        )
        .expect("the schema joins");
    let options = ks_core::CheckOptions::new(&catalog);
    // `cap` is one edit from both declared inputs: a person is told, a
    // machine is not told what to choose.
    let src = "steps:\n  d: web.deploy\n    cap: sofa\n";
    let checked = ks_core::check_with(&ks_lang::parse(src), &options);
    let d = &checked.diagnostics[0];
    assert!(d.hints.iter().any(|h| h.starts_with("did you mean")), "{:#?}", d.hints);
    let fix = &d.fixes[0];
    assert_eq!(fix.replacement, "cat", "the first candidate, as the hint names it");
    assert!(!fix.machine_applicable, "two names tie; --fix must not pick one");
}

// --- IaC outputs: `apply.out.<name>` typed from the .tf files ------------

/// A site whose `apply.out.<name>` is checked against what the IaC behind
/// its plan declares: `./infra/prod` exports a `cluster`.
const IAC: &str = "\
steps:
  build:  oci.image
    from:  ./Dockerfile
  plan:   tofu.plan
    dir:   ./infra/prod
  apply:  tofu.apply
    plan:  plan.file
  deploy: k8s.rollout
    image: build.digest
    to:    apply.out.cluster
";

/// Checks `src` with `./infra/prod` declaring the outputs in `outputs`.
fn check_iac(src: &str, outputs: &[(&str, ks_core::Type)]) -> ks_core::Checked {
    let catalog = ks_core::Catalog::builtin();
    let mut declared = std::collections::BTreeMap::new();
    declared.insert(
        "./infra/prod".to_string(),
        outputs.iter().map(|(n, t)| (n.to_string(), t.clone())).collect(),
    );
    let options = ks_core::CheckOptions::new(&catalog).iac_outputs(&declared);
    ks_core::check_with(&ks_lang::parse(src), &options)
}

fn iac_errors(src: &str, outputs: &[(&str, ks_core::Type)]) -> Vec<String> {
    check_iac(src, outputs).diagnostics.iter().map(std::string::ToString::to_string).collect()
}

#[test]
fn a_declared_output_is_typed_from_its_directory() {
    let cluster = ks_core::Type::Named("k8s.Cluster".to_string());
    // The .tf says `cluster` is a cluster, and `k8s.rollout` wants one.
    let all = iac_errors(IAC, &[("cluster", cluster)]);
    assert!(all.iter().all(|m| !m.contains("error")), "{all:?}");
    // A string from the same directory is not a cluster.
    let all = iac_errors(IAC, &[("cluster", ks_core::Type::String)]);
    assert!(all.iter().any(|m| m.contains("expected k8s.Cluster, got string")), "{all:?}");
}

#[test]
fn an_output_the_iac_does_not_declare_is_an_unknown_output() {
    let all = iac_errors(IAC, &[("region", ks_core::Type::String)]);
    assert!(all.iter().any(|m| m.contains("produces no output `cluster`")), "{all:?}");
    assert!(all.iter().any(|m| m.contains("`./infra/prod` declares `region`")), "{all:?}");
}

#[test]
fn a_directory_the_caller_could_not_read_says_nothing() {
    // The same file, checked with no `.tf` files at all: the name is
    // unchecked, exactly as it was before this rule.
    assert!(errors(IAC).is_empty(), "{:?}", errors(IAC));
}

#[test]
fn the_step_may_map_output_names_to_types_itself() {
    let mapping = IAC.replace(
        "    plan:  plan.file\n",
        "    plan:  plan.file\n    outputs:\n      cluster: k8s.Cluster\n",
    );
    // The mapping wins over the directory, which declares something else.
    let all = iac_errors(&mapping, &[("cluster", ks_core::Type::String)]);
    assert!(all.iter().all(|m| !m.contains("error")), "{all:?}");
    // A type that is not a type is a type error, where it is spelled — and
    // names nothing, so the read of it falls back to the directory.
    let bad = mapping.replace("cluster: k8s.Cluster", "cluster: 3");
    let all = iac_errors(&bad, &[("cluster", ks_core::Type::String)]);
    assert!(all.iter().any(|m| m.contains("`3` is not a type")), "{all:?}");
    // Names nothing, so the read falls back to what the directory declares.
    assert!(all.iter().any(|m| m.contains("expected k8s.Cluster, got string")), "{all:?}");
}

#[test]
fn outputs_is_not_an_input_of_any_kind_but_an_apply() {
    let step = |src: &str| errors(src);
    // Written as a mapping and as a value, on a kind that declares neither.
    for src in [
        "steps:\n  build: oci.image\n    from: ./Dockerfile\n    outputs: string\n",
        "steps:\n  build: oci.image\n    from: ./Dockerfile\n    outputs:\n      digest: string\n",
    ] {
        let all = step(src);
        assert!(all.iter().any(|m| m.contains("unknown input `outputs`")), "{all:?}");
    }
}

#[test]
fn every_outputs_mapping_is_checked_where_it_is_written() {
    // Two `outputs:` blocks: the second is read as itself, not as the first
    // again, so a bad type in it is reported on its own line.
    let src = "\
steps:
  build:  oci.image
    from:  ./Dockerfile
  plan:   tofu.plan
    dir:   ./infra/prod
  apply:  tofu.apply
    plan:  plan.file
    outputs:
      cluster: k8s.Cluster
    outputs:
      cluster: 3
  deploy: k8s.rollout
    image: build.digest
    to:    apply.out.cluster
";
    let cluster = ks_core::Type::Named("k8s.Cluster".to_string());
    let all = iac_errors(src, &[("cluster", cluster)]);
    assert!(all.iter().any(|m| m.contains("`3` is not a type")), "{all:?}");
    // The second block names nothing usable, so the first still types the
    // read and the file keeps one error rather than two.
    assert!(!all.iter().any(|m| m.contains("expected k8s.Cluster")), "{all:?}");
}

#[test]
fn a_field_of_an_output_keeps_the_types_it_knows() {
    // A record's fields are known, so a field that is not a cluster fails
    // as itself rather than as `any`.
    let record = ks_core::Type::Record(vec![("endpoint".to_string(), ks_core::Type::Url)]);
    let src = IAC.replace("apply.out.cluster", "apply.out.thing.endpoint");
    let all = iac_errors(&src, &[("thing", record)]);
    assert!(all.iter().any(|m| m.contains("expected k8s.Cluster, got url")), "{all:?}");
    // A field nothing declares stays unchecked, as an unknown output's do.
    let src = IAC.replace("apply.out.cluster", "apply.out.thing.nope");
    assert!(errors(&src).is_empty(), "{:?}", errors(&src));
}

// --- script steps: `<step>.<name>` typed from the module -----------------

/// A site whose `migrate.applied` is checked against what the module its
/// kind names declares for it. The read is interpolated into a tag, so a
/// site that cannot read the module at all still checks clean.
const SCRIPT: &str = "\
steps:
  migrate: ./ship/migrate.ts
  build:   oci.image
    from:   ./Dockerfile
    push:   ghcr.io/acme/api:v{migrate.applied}
";

/// The same site, reading `migrate.applied` in a position that needs an
/// `int`. Used only where the module was read, so an unchecked `any` — which
/// no comparison accepts — cannot be mistaken for a typed one.
const COMPARED: &str = "\
steps:
  migrate: ./ship/migrate.ts
  build:   oci.image
    from:   ./Dockerfile
    when:   migrate.applied > 0
";

/// Checks `src` with `./ship/migrate.ts` declaring `outputs`.
fn check_script(src: &str, outputs: &[(&str, ks_core::Tag)]) -> ks_core::Checked {
    let catalog = ks_core::Catalog::builtin();
    let tags: std::collections::BTreeMap<String, ks_core::Tag> =
        outputs.iter().map(|(n, t)| (n.to_string(), t.clone())).collect();
    let declared = std::collections::BTreeMap::from([(
        "./ship/migrate.ts".to_string(),
        ks_core::script::outputs(&tags),
    )]);
    let options = ks_core::CheckOptions::new(&catalog).script_outputs(&declared);
    ks_core::check_with(&ks_lang::parse(src), &options)
}

fn script_errors(src: &str, outputs: &[(&str, ks_core::Tag)]) -> Vec<String> {
    check_script(src, outputs).diagnostics.iter().map(std::string::ToString::to_string).collect()
}

#[test]
fn a_declared_output_is_typed_from_its_module() {
    // `applied` is an int, and `> 0` needs one.
    assert!(script_errors(COMPARED, &[("applied", ks_core::Tag::Int)]).is_empty());
    // A string is not an int, so the comparison fails on the declaration.
    let all = script_errors(COMPARED, &[("applied", ks_core::Tag::Str)]);
    assert!(all.iter().any(|m| m.contains("cannot compare `string` and `int`")), "{all:?}");
}

#[test]
fn a_declared_output_is_the_type_hover_shows() {
    let at = SCRIPT.find("migrate.applied").expect("the read") + "migrate.applied".len();
    let checked = check_script(SCRIPT, &[("applied", ks_core::Tag::Int)]);
    assert_eq!(checked.type_at(at as u32).map(|(_, ty)| ty.clone()), Some(ks_core::Type::Int));
}

#[test]
fn an_output_the_module_does_not_declare_is_an_unknown_output() {
    let all = script_errors(SCRIPT, &[("rows", ks_core::Tag::Int), ("apllied", ks_core::Tag::Int)]);
    // The hint lists what the module really declares, and the misspelling
    // in the file is one edit from one of them.
    assert!(
        all.iter().any(|m| m.contains("`./ship/migrate.ts` declares `apllied`, `rows`")),
        "{all:?}"
    );
    assert!(all.iter().any(|m| m.contains("did you mean `apllied`?")), "{all:?}");
    let all = script_errors(SCRIPT, &[("rows", ks_core::Tag::Int)]);
    assert!(all.iter().any(|m| m.contains("produces no output `applied`")), "{all:?}");
}

#[test]
fn an_output_that_is_not_a_ks_type_is_an_error_saying_how_to_be_one() {
    let all = script_errors(SCRIPT, &[("applied", ks_core::Tag::Number)]);
    assert!(
        all.iter().any(|m| m.contains("`applied` of step `migrate` is not a ks type")),
        "{all:?}"
    );
    assert!(all.iter().any(|m| m.contains("ambiguous in ks")), "{all:?}");
    assert!(all.iter().any(|m| m.contains("`int()` or `float()`")), "{all:?}");
}

#[test]
fn a_module_nobody_read_says_nothing() {
    // No caller to read it at all, and a module that declares nothing, are
    // the same silence as a kind the catalog answers for itself.
    assert!(errors(SCRIPT).is_empty(), "{:?}", errors(SCRIPT));
    assert!(script_errors(SCRIPT, &[]).is_empty());
    let src = "steps:\n  build: oci.image\n    from: ./Dockerfile\n    push: ghcr.io/acme/api:{git.sha}\n";
    assert!(script_errors(src, &[("digest", ks_core::Tag::Int)]).is_empty());
    // A kind whose declaration nobody read stays unchecked, where another
    // kind would say it has no such output.
    let src = SCRIPT.replace("oci.image", "oci.verify");
    assert!(!check_script(&src, &[("rows", ks_core::Tag::Int)]).diagnostics.is_empty());
}

#[test]
fn an_artifact_a_gated_step_uses_must_be_in_the_approval_that_gates_it() {
    // The approval shows the plan and nothing else, yet `deploy` runs after it
    // and acts on an image digest the approver never saw: the thing being
    // rolled out is not the thing that was approved (KS0702).
    let ungated = "\
steps:
  plan: tofu.plan
    dir: ./infra
  build: oci.image
    from: ./Dockerfile
  review: approval
    show: plan.changes
    from: @platform
  deploy: k8s.rollout
    image: build.digest
    after: review
";
    let checked = check(&ks_lang::parse(ungated));
    assert!(
        checked.diagnostics.iter().any(|d| d.code == ks_lang::Code::UncoveredArtifact),
        "KS0702 fires: {:#?}",
        checked.diagnostics
    );
    let reported = errors(ungated);
    assert!(
        reported.iter().any(|e| e.contains("`deploy` uses `build.digest`")
            && e.contains("`review`")
            && e.contains("add `build.digest` to `review`'s `show:`")),
        "{reported:?}"
    );

    // The same workflow with the digest in `show:` covers it, and nothing is
    // reported.
    let covered = ungated.replace("show: plan.changes", "show: plan.changes, build.digest");
    assert!(errors(&covered).is_empty(), "{:?}", errors(&covered));

    // Showing *any* output of `build` covers the step, so `build.tag` would
    // do — coverage is per step, not per output.
    let by_other_output = ungated.replace("show: plan.changes", "show: plan.changes, build.tag");
    assert!(errors(&by_other_output).is_empty(), "{:?}", errors(&by_other_output));
}

// --- `require-verified:` --------------------------------------------------
// A deploy that says nothing verifies what it ships is refused in an
// environment that demands it (#113). The tests below are about which steps
// that covers, not about parsing the property.

/// A workflow whose only deploy is an unverified `k8s.rollout`, with the
/// property spelling swapped in by the caller.
const UNVERIFIED: &str = "\
envs:
  dev:
    require-verified: false
  prod:
    require-verified: true
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
";

#[test]
fn an_unverified_deploy_is_refused_in_an_environment_that_demands_verification() {
    let reported = errors(UNVERIFIED);
    let about_step = reported
        .iter()
        .filter(|e| e.contains("`prod` requires verified deploys") && e.contains("`deploy`"))
        .count();
    assert_eq!(about_step, 1, "one finding names both the environment and the step: {reported:?}");
    assert!(
        reported
            .iter()
            .any(|e| e.contains("signed-by key:release-key") && e.contains("`when: env is <env>`")),
        "the hint shows the fix and the exemption: {reported:?}"
    );
}

#[test]
fn a_verify_input_is_what_the_environment_asked_for() {
    let verified = UNVERIFIED.replace(
        "    image: build.digest\n",
        "    image: build.digest\n    verify: \"signed-by key:k\"\n",
    );
    assert!(errors(&verified).is_empty(), "{:?}", errors(&verified));
}

#[test]
fn an_empty_verify_is_not_a_request_for_verification() {
    // `verify: ""` is what a rollout that verifies nothing spells. Reading it
    // as a request would let a step claim verification by writing nothing.
    let empty = UNVERIFIED
        .replace("    image: build.digest\n", "    image: build.digest\n    verify: \"\"\n");
    let reported = errors(&empty);
    assert!(
        reported.iter().any(|e| e.contains("`prod` requires verified deploys")),
        "{reported:?}"
    );
    assert!(
        !reported.iter().any(|e| e.contains("verify") && e.contains("KS") && e.contains("signed")),
        "the empty value is not a type error here, it is simply not a request: {reported:?}"
    );
}

#[test]
fn a_deploy_gated_to_another_environment_is_out_of_scope() {
    let dev_only = "\
envs:
  dev:
    require-verified: false
  prod:
    require-verified: true
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
    when: env is dev
";
    assert!(errors(dev_only).is_empty(), "{:?}", errors(dev_only));

    // Gated to `prod` it is in scope, and so is a deploy that names no
    // environment at all: `when: env is prod` is a declaration of scope, and
    // its absence is not an exemption.
    let to_prod = dev_only.replace("when: env is dev", "when: env is prod");
    assert!(errors(&to_prod).iter().any(|e| e.contains("requires verified deploys")));
    let ungated = dev_only.replace("    when: env is dev\n", "");
    assert!(
        errors(&ungated).iter().any(|e| e.contains("requires verified deploys")),
        "an ungated deploy runs in whichever environment was selected, prod included: {:?}",
        errors(&ungated)
    );
}

#[test]
fn a_require_verified_value_is_a_boolean_and_says_which_one() {
    let src = UNVERIFIED.replace("require-verified: true", "require-verified: maybe");
    let reported = errors(&src);
    assert!(
        reported.iter().any(|e| e.contains("`require-verified` takes `true` or `false`")
            && e.contains("`require-verified: true`")),
        "{reported:?}"
    );
    // The property is not a deploy finding: the step it named is fine, the
    // value was not read as asking for anything.
    assert!(!reported.iter().any(|e| e.contains("requires verified deploys")), "{reported:?}");

    // And it is a did-you-mean away from being missed, like every other
    // environment property.
    let misspelt = UNVERIFIED.replace("require-verified: true", "require-verifiedd: true");
    let all = messages(&misspelt);
    assert!(
        all.iter().any(|m| m.contains("unknown environment property `require-verifiedd`")
            && m.contains("did you mean `require-verified`?")),
        "{all:?}"
    );
}

#[test]
fn require_verified_covers_vm_deploy_too_and_is_silent_with_nothing_to_refuse() {
    // Both deploy kinds are `ActionKind::Deploy`, so both are covered: the
    // rule is about what a run does, not which step kind spells it.
    let vm = "\
envs:
  prod:
    require-verified: true
steps:
  deploy: vm.deploy
    hosts: [\"web-1\", \"web-2\"]
";
    let reported = errors(vm);
    assert!(
        reported
            .iter()
            .any(|e| e.contains("`prod` requires verified deploys") && e.contains("`deploy`")),
        "{reported:?}"
    );
    let verified = vm.replace("    hosts: [\"web-1\", \"web-2\"]\n",
        "    hosts: [\"web-1\", \"web-2\"]\n    image: ghcr.io/acme/api@sha256:0000\n    verify: \"signed-by key:k\"\n");
    assert!(errors(&verified).is_empty(), "{:?}", errors(&verified));

    // Nothing deploys: the property binds nothing and says nothing.
    let no_deploys = UNVERIFIED.replace("  deploy: k8s.rollout\n    image: build.digest\n", "");
    assert!(errors(&no_deploys).is_empty(), "{:?}", errors(&no_deploys));

    // And a file that never asks for verification is untouched by any of this.
    let plain = "\
steps:
  build: oci.image
    from: ./Dockerfile
  deploy: k8s.rollout
    image: build.digest
";
    assert!(errors(plain).is_empty(), "{:?}", errors(plain));
}
