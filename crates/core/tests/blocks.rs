//! Blocks: what a `block:` file declares, what a use is checked against,
//! and what policy can see through one
//! ([#80](https://github.com/Keep-Shipping/harness/issues/80)).

use std::collections::BTreeMap;

use ks_core::block::{self, BlockSignature, MAX_BLOCK_DEPTH};
use ks_core::ports::run_context::ActorKind;
use ks_core::{Catalog, CheckOptions, Checked, check_with};
use ks_lang::{Code, Diagnostic, Severity};

/// The site's block, exactly as `crates/lang/tests/fixtures/site-block.ks`
/// spells it. The use that file shows under it is [`USE`].
const BLOCK: &str = "\
# acme/blocks · web-service@v3
block:  web-service
inputs:
  image:    oci.Digest
  domain:   string
  replicas: int = 2
";

/// The site's use of that block, as the `steps:` child it is. Spelled with
/// explicit newlines: a `\` line continuation eats the indentation of the
/// line after it, and this text is all indentation.
const USE: &str = "  deploy:   acme/web-service@v3\n    image:  build.digest\n    \
                   domain: api.acme.dev\n";

/// A block with internal steps and declared outputs: what the site's block
/// grows into once it ships something. The rollouts name their environment
/// with `when: env is …`, which is how an action reaches policy.
const SHIPPING_BLOCK: &str = "\
block: web-service
envs:
  prod:
    ci-only: true
  staging:
    ci-only: true
inputs:
  image: oci.Digest
  replicas: int = 2
outputs:
  ref: oci.Ref = pack.ref
steps:
  pack: oci.image
    from: ./Dockerfile
  ship: k8s.rollout
    image: inputs.image
    when: env is prod
  probe: k8s.rollout
    image: inputs.image
    when: env is staging
";

/// The site's use of [`SHIPPING_BLOCK`], which declares no `domain`.
const SHIPPING_USE: &str = "  deploy:   acme/web-service@v3\n    image:  build.digest\n";

/// The signatures a use of `acme/web-service@v3` is checked against, keyed
/// by the kind exactly as the file spells it.
fn blocks(src: &str) -> BTreeMap<String, BlockSignature> {
    let catalog = Catalog::builtin();
    let sig =
        block::signature(&ks_lang::parse(src), &catalog, &BTreeMap::new()).expect("a block file");
    BTreeMap::from([("acme/web-service@v3".to_string(), sig)])
}

/// The site's use under a build it reads the image from.
fn use_file(use_body: &str) -> String {
    format!("steps:\n  build: oci.image\n    from: ./Dockerfile\n{use_body}")
}

fn check_src(src: &str) -> Checked {
    check_with(&ks_lang::parse(src), &CheckOptions::new(&Catalog::builtin()))
}

fn checked_use(src: &str, block_src: &str) -> Checked {
    let blocks = blocks(block_src);
    check_with(&ks_lang::parse(src), &CheckOptions::new(&Catalog::builtin()).blocks(&blocks))
}

fn codes(src: &str, block_src: &str) -> Vec<Code> {
    checked_use(src, block_src).diagnostics.iter().map(|d| d.code).collect()
}

fn messages(src: &str, block_src: &str) -> Vec<String> {
    checked_use(src, block_src).diagnostics.iter().map(ToString::to_string).collect()
}

#[test]
fn the_site_block_checks_clean_on_its_own() {
    let checked = check_src(BLOCK);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
}

#[test]
fn the_site_use_checks_clean_against_the_signature() {
    let checked = checked_use(&use_file(USE), BLOCK);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
    let deploy = checked.workflow.step("deploy").expect("the use is a step");
    assert_eq!(deploy.kind.as_deref(), Some("acme/web-service@v3"));
    // It reads the build, so the build runs first.
    assert!(checked.workflow.edges().contains(&("build".to_string(), "deploy".to_string())));
}

#[test]
fn a_use_leaving_out_a_required_input_is_an_error() {
    let src = use_file("  deploy:   acme/web-service@v3\n    image:  build.digest\n");
    let got = codes(&src, BLOCK);
    assert!(got.contains(&Code::MissingInput), "{:?}", messages(&src, BLOCK));
    let missing = messages(&src, BLOCK)
        .into_iter()
        .find(|m| m.contains("requires input `domain`"))
        .expect("the missing input is named");
    assert!(missing.contains("block `web-service`"), "{missing}");
}

#[test]
fn a_default_is_filled_in_where_the_file_left_it_out() {
    let checked = checked_use(
        &use_file(
            "  deploy:   acme/web-service@v3\n    image:  build.digest\n    domain: api.acme.dev\n",
        ),
        BLOCK,
    );
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
    let inputs = &checked.workflow.step("deploy").expect("the use is a step").block_inputs;
    assert_eq!(inputs["replicas"], "2", "the default the file did not spell");
    assert_eq!(inputs["domain"], "api.acme.dev");
    assert_eq!(inputs["image"], "build.digest");
}

#[test]
fn an_input_the_block_does_not_declare_is_an_error() {
    let src = use_file(&format!("{USE}    zone: eu\n"));
    let got = codes(&src, BLOCK);
    assert!(got.contains(&Code::UnknownInput), "{:?}", messages(&src, BLOCK));
    assert!(messages(&src, BLOCK).iter().any(|m| m.contains("unknown input `zone`")));
}

#[test]
fn a_value_of_the_wrong_type_is_a_type_mismatch() {
    let src = use_file(
        "  deploy:   acme/web-service@v3\n    image:  build.tag\n    domain: api.acme.dev\n",
    );
    let got = codes(&src, BLOCK);
    assert!(got.contains(&Code::TypeMismatch), "{:?}", messages(&src, BLOCK));
}

#[test]
fn a_block_file_reads_its_own_inputs_and_says_so_when_it_does_not() {
    let checked = check_src(SHIPPING_BLOCK);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);

    let typo = check_src(&SHIPPING_BLOCK.replace("inputs.image", "inputs.imag"));
    let hit = typo
        .diagnostics
        .iter()
        .find(|d| d.code == Code::UnknownRef)
        .unwrap_or_else(|| panic!("an unknown input is reported, got {:#?}", typo.diagnostics));
    assert!(hit.message.contains("unknown context value `inputs.imag`"), "{}", hit.message);
    assert!(
        hit.hints.iter().any(|h| h.contains("did you mean `inputs.image`?")),
        "{:#?}",
        hit.hints
    );
}

#[test]
fn a_blocks_declared_outputs_are_checked_against_its_own_steps() {
    let checked = check_src(SHIPPING_BLOCK);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
    let typo = check_src(&SHIPPING_BLOCK.replace("pack.ref", "pack.rafe"));
    let hit =
        typo.diagnostics.iter().find(|d| d.code == Code::UnknownOutput).unwrap_or_else(|| {
            panic!("an output no step produces is reported, got {:#?}", typo.diagnostics)
        });
    assert!(hit.message.contains("has no output `rafe`"), "{}", hit.message);
}

#[test]
fn a_use_reads_the_output_the_block_declares() {
    let src = use_file(&format!(
        "{SHIPPING_USE}  ok: approval\n    show: deploy.out.ref\n    from: @platform\n"
    ));
    let checked = checked_use(&src, SHIPPING_BLOCK);
    assert!(
        checked.diagnostics.iter().all(|d| d.code != Code::UnknownOutput),
        "{:#?}",
        checked.diagnostics
    );

    let unknown = use_file(&format!(
        "{SHIPPING_USE}  ok: approval\n    show: deploy.out.reff\n    from: @platform\n"
    ));
    let all = messages(&unknown, SHIPPING_BLOCK);
    assert!(
        all.iter().any(|m| m.contains("has no output `reff`") && m.contains("did you mean `ref`?")),
        "{all:?}"
    );
}

const AGENT_POLICY: &str = "\
envs:
  prod:
    ci-only: true
policy:
  agents:
    never: deploy prod
";

/// The block as a use of it is checked: the same rule, the same answer.
fn under_agent_policy(steps: &str) -> Checked {
    let catalog = Catalog::builtin();
    let blocks = blocks(SHIPPING_BLOCK);
    let options = CheckOptions::new(&catalog).actor(ActorKind::Agent).blocks(&blocks);
    check_with(&ks_lang::parse(&format!("{AGENT_POLICY}{steps}")), &options)
}

#[test]
fn policy_sees_the_apply_inside_a_block_use() {
    let checked = under_agent_policy(&use_file(USE));
    let deploy = checked.workflow.step("deploy").expect("the use is a step");
    let actions: Vec<String> = deploy.actions.iter().map(ToString::to_string).collect();
    assert!(
        actions.iter().any(|a| a == "deploy prod"),
        "the block's rollout to prod is the use's action: {actions:?}"
    );
    let forbidden: Vec<&Diagnostic> =
        checked.diagnostics.iter().filter(|d| d.code == Code::PolicyForbidden).collect();
    assert_eq!(
        forbidden.len(),
        1,
        "prod is rolled out once, so refused once: {:#?}",
        checked.diagnostics
    );
    let message = &forbidden[0].message;
    assert!(message.contains("block `web-service`"), "{message}");
    assert!(message.contains("k8s.rollout"), "{message}");
    assert!(message.contains("runs `deploy prod`"), "{message}");
    assert!(message.contains("policy forbids agents from running `deploy prod`"), "{message}");
    assert_eq!(forbidden[0].severity, Severity::Error);
}

#[test]
fn a_step_policy_cannot_see_behind_behaves_the_same() {
    let src = "\
envs:
  prod:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
  ship: k8s.rollout
    image: build.digest
    when: env is prod
";
    let catalog = Catalog::builtin();
    let checked = check_with(
        &ks_lang::parse(&format!("{AGENT_POLICY}{src}")),
        &CheckOptions::new(&catalog).actor(ActorKind::Agent),
    );
    let ship = checked.workflow.step("ship").expect("the step");
    assert_eq!(ship.actions.iter().map(ToString::to_string).collect::<Vec<_>>(), ["deploy prod"]);
    let hit =
        checked.diagnostics.iter().find(|d| d.code == Code::PolicyForbidden).unwrap_or_else(|| {
            panic!("a direct rollout to prod is refused: {:#?}", checked.diagnostics)
        });
    assert!(hit.message.contains("step `ship` runs `deploy prod`"), "{}", hit.message);
}

#[test]
fn a_human_run_is_not_bound_by_the_agents_rule() {
    let catalog = Catalog::builtin();
    let blocks = blocks(SHIPPING_BLOCK);
    let options = CheckOptions::new(&catalog).actor(ActorKind::Human).blocks(&blocks);
    let checked =
        check_with(&ks_lang::parse(&format!("{AGENT_POLICY}{}", use_file(USE))), &options);
    assert!(
        checked.diagnostics.iter().all(|d| d.code != Code::PolicyForbidden),
        "{:#?}",
        checked.diagnostics
    );
}

/// The signatures of `srcs`, one block file per entry.
fn signatures(srcs: &[&str]) -> (BTreeMap<String, BlockSignature>, Vec<block::BlockProblem>) {
    let parses: Vec<ks_lang::Parse> = srcs.iter().map(|s| ks_lang::parse(s)).collect();
    let files: BTreeMap<String, &ks_lang::Parse> =
        parses.iter().enumerate().map(|(i, p)| (format!("block{i}.ks"), p)).collect();
    block::block_signatures(&files, &Catalog::builtin())
}

#[test]
fn blocks_that_use_each_other_in_a_circle_are_reported() {
    let (sigs, problems) =
        signatures(&["block: a\nsteps:\n  use: b\n", "block: b\nsteps:\n  use: a\n"]);
    assert!(
        sigs.contains_key("a"),
        "each block is still readable: {:?}",
        sigs.keys().collect::<Vec<_>>()
    );
    let cycle: Vec<&block::BlockProblem> =
        problems.iter().filter(|p| p.code == Code::Cycle).collect();
    assert!(!cycle.is_empty(), "{:#?}", problems);
    assert!(
        cycle[0].message.contains("a → b → a") || cycle[0].message.contains("b → a → b"),
        "{}",
        cycle[0].message
    );
    assert!(problems.iter().all(|p| p.file.ends_with(".ks")), "each names its file");
}

#[test]
fn a_nest_deeper_than_the_limit_is_refused() {
    // One block more than the limit, chained.
    let mut chain = Vec::new();
    for i in 0..=MAX_BLOCK_DEPTH {
        chain.push(format!("block: b{i}\nsteps:\n  use: b{}\n", i + 1));
    }
    chain.push(format!(
        "block: b{}\nsteps:\n  build: oci.image\n    from: ./Dockerfile\n",
        MAX_BLOCK_DEPTH + 1
    ));
    let refs: Vec<&str> = chain.iter().map(String::as_str).collect();
    let (_, problems) = signatures(&refs);
    let deep: Vec<&block::BlockProblem> =
        problems.iter().filter(|p| p.code == Code::BlockDepth).collect();
    assert!(!deep.is_empty(), "{:#?}", problems);
    assert!(deep[0].message.contains(&MAX_BLOCK_DEPTH.to_string()), "{}", deep[0].message);
    // Each file over the limit reports at its own use, and no file twice.
    let files: Vec<&str> = deep.iter().map(|p| p.file.as_str()).collect();
    let mut sorted = files.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(files.len(), sorted.len(), "one report per offending use: {files:?}");

    // One block fewer checks clean.
    let refs: Vec<&str> = chain[..MAX_BLOCK_DEPTH].iter().map(String::as_str).collect();
    let (_, problems) = signatures(&refs);
    assert!(problems.is_empty(), "{:#?}", problems);
}

#[test]
fn a_block_actions_flatten_through_a_nest() {
    let (sigs, _) = signatures(&[
        "block: leaf\nenvs:\n  prod:\n    ci-only: true\nsteps:\n  ship: k8s.rollout\n    \
         image: inputs.image\n    when: env is prod\n",
        "block: mid\nsteps:\n  go: leaf\n    image: build.digest\n",
    ]);
    let mid = sigs.get("mid").expect("mid resolves");
    assert_eq!(
        mid.actions.iter().map(|(a, _)| a.to_string()).collect::<Vec<_>>(),
        ["deploy prod"],
        "what is inside the block it uses is the block's own action"
    );
    let leaf = sigs.get("leaf").expect("leaf resolves");
    assert_eq!(
        leaf.actions.iter().map(|(a, _)| a.to_string()).collect::<Vec<_>>(),
        ["deploy prod"]
    );
}

/// A dotted name that is only a near miss of a step is a misspelled
/// reference, even where the input takes `string`: `api.acme.dev` is a domain
/// and stays text, `biuld.digest` is `build.digest` with the letters moved.
#[test]
fn a_near_miss_in_a_string_input_is_still_a_misspelled_reference() {
    let typo =
        "  deploy:   acme/web-service@v3\n    image:  build.digest\n    domain: biuld.digest\n";
    let got = codes(&use_file(typo), BLOCK);
    assert!(got.contains(&Code::UnknownRef), "{:?}", messages(&use_file(typo), BLOCK));
    let named = messages(&use_file(typo), BLOCK)
        .into_iter()
        .find(|m| m.contains("unknown step or context value `biuld`"))
        .expect("the misspelled head is named");
    assert!(named.contains("did you mean `build`?"), "{named}");

    // A domain that is no near miss of anything is text, as it always was.
    let checked = checked_use(&use_file(USE), BLOCK);
    assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
    assert_eq!(
        checked.workflow.step("deploy").expect("the use is a step").block_inputs["domain"],
        "api.acme.dev"
    );
}

/// A block cannot hide a secret behind its name: the steps inside it read
/// `secrets.<key>`, and `agents: never: read secrets` refuses the use.
#[test]
fn secrets_inside_a_block_are_refused_at_the_use() {
    let secret_block = "\
block: web-service
inputs:
  image: oci.Digest
steps:
  ship: k8s.rollout
    image: inputs.image
    token: secrets.registry_token
";
    let src = "\
policy:
  agents:
    never: read secrets
steps:
  build: oci.image
    from: ./Dockerfile
  deploy:   acme/web-service@v3
    image:  build.digest
";
    let catalog = Catalog::builtin();
    let blocks = blocks(secret_block);
    let options = CheckOptions::new(&catalog).actor(ActorKind::Agent).blocks(&blocks);
    let checked = check_with(&ks_lang::parse(src), &options);
    let refused = checked
        .diagnostics
        .iter()
        .find(|d| d.message.contains("secrets.registry_token"))
        .unwrap_or_else(|| panic!("{:#?}", checked.diagnostics));
    assert!(
        refused.message
            == "policy forbids agents from reading secrets, but this run needs \
                            secrets.registry_token"
            && refused.hints.as_slice() == ["the rule is `policy: agents: never: read secrets`"],
        "{refused:?}"
    );
    // It is reported at the use, which is the only place the file spells it.
    let use_start = src.find("acme/web-service@v3").expect("the use");
    assert_eq!(refused.span.start, use_start as u32, "at the use's own kind");
}

/// An input may not be named after a property a step already has: the use
/// would spell `when:` as the step's own, and the input could never be set.
#[test]
fn an_input_named_after_a_step_property_is_refused() {
    for name in ["when", "after", "outputs"] {
        let src = format!("block: web-service\ninputs:\n  {name}: string\n");
        let checked = check_src(&src);
        let d = checked
            .diagnostics
            .iter()
            .find(|d| d.code == Code::ReservedStepName)
            .unwrap_or_else(|| panic!("`{name}`: {:#?}", checked.diagnostics));
        assert!(d.message.contains("is a step property, not an input name"), "{d:?}");
    }
}
