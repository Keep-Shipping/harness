//! The enforcement point ([#103](https://github.com/Keep-Shipping/harness/issues/103)).
//!
//! The property under all of it: **a step's own code is not an input to whether it runs.** Every
//! decision here is made from the action class the step reports and the policy in force, before
//! `StepKind::run` is called; where a step is handed anything, it is handed only what it declared.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ks_core::Policy;
use ks_core::harness::Harness;
use ks_core::ids::{RunId, StepId};
use ks_core::ports::BoxFuture;
use ks_core::ports::iac::IacTool;
use ks_core::ports::policy::Disposition::{Allow, Ask, Never};
use ks_core::ports::policy::{ANY_OBJECT, Baseline, Disposition, Provenance, Rule, Subject};
use ks_core::ports::run_context::ActorKind;
use ks_core::ports::run_log::{RunEvent, RunLog};
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::secrets::{Redactor, SecretRef, Secrets, SecretsError};
use ks_core::step::ActionKind::{Build, Deploy, Destroy, ReadSecrets};
use ks_core::step::{
    ActionClass, ActionKind, CancellationToken, Field, Inputs, LogSink, Outputs, Port, Ports,
    StepCtx, StepError, StepKind, StepSchema, TypeRef, Version,
};
use ks_engine::journal::Journal;
use ks_engine::policy_gate::{GateCtx, GatedRun, PolicyGate, PreflightStep};
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::iac::FakeIacTool;
use ks_testing::run_log::RecordingRunLog;
use ks_testing::secrets::FakeSecrets;
use ks_testing::step::RecordingSink;

const AGENT: ActorKind = ActorKind::Agent;
const HUMAN: ActorKind = ActorKind::Human;

/// The two `never:` rules a table row can give its file: `agents: never: …`.
const READ_SECRETS: Option<&str> = Some("read secrets");
const DEPLOY_PROD: Option<&str> = Some("deploy prod");

/// The `policy:` block of a `ship.ks`, which is how the file's own `never:` rules reach the gate:
/// `None` is a file with no `policy:` block at all, so the baseline is the whole policy.
fn file_policy(rule: Option<&str>) -> Policy {
    let policy = match rule {
        Some(rule) => format!("policy:\n  agents:\n    never: {rule}\n"),
        None => String::new(),
    };
    let src = format!(
        "name: gated\nenvs:\n  prod:\nsteps:\n  deploy: sample.deploy\n    env: prod\n{policy}"
    );
    ks_core::check(&ks_lang::parse(&src)).workflow.policy().clone()
}

fn rule(subject: Subject, verb: &str, object: &str, disposition: Disposition) -> Rule {
    Rule {
        subject,
        verb: verb.to_string(),
        object: object.to_string(),
        disposition,
        provenance: Provenance::Default,
    }
}

/// An org baseline that grants exactly one thing: agents may deploy to `staging`.
///
/// Declared deny-first, because [`Baseline::decide`] is first-match-wins and an allow further down
/// the list would rescue a refusal above it.
fn staging_only() -> Baseline {
    Baseline {
        rules: vec![
            rule(Subject::Any, "destroy", ANY_OBJECT, Disposition::Never),
            rule(Subject::Actor(AGENT), "deploy", "prod", Disposition::Never),
            rule(Subject::Actor(AGENT), "deploy", "staging", Disposition::Allow),
        ],
        source: None,
        publishers: Vec::new(),
    }
}

/// An org baseline that lets an agent deploy anywhere, so a test can show the file's rules
/// narrowing it rather than the baseline happening to agree.
fn everywhere() -> Baseline {
    Baseline {
        rules: vec![rule(Subject::Actor(AGENT), "deploy", ANY_OBJECT, Disposition::Allow)],
        source: None,
        publishers: Vec::new(),
    }
}

/// The built-in default, which is what most rows above are checked under.
fn conservative() -> Baseline {
    Baseline::conservative()
}

fn action(kind: ActionKind, env: Option<&str>) -> ActionClass {
    match env {
        Some(env) => ActionClass::new(kind).in_env(env),
        None => ActionClass::new(kind),
    }
}

/// One row of the table: who is acting, what they are trying, where, under which baseline and
/// which `never:` rule of their own, and what that decides — with why the row is worth checking.
type Row = (
    ActorKind,
    ActionKind,
    Option<&'static str>,
    fn() -> Baseline,
    Option<&'static str>,
    Disposition,
    &'static str,
);

#[test]
fn actor_by_verb_by_environment_by_baseline_decides() {
    let rows: [Row; 13] = [
        // The built-in default: an agent may check, build and plan; everything else asks.
        (AGENT, Build, Some("staging"), conservative, None, Allow, "an agent may build"),
        (AGENT, Build, None, conservative, None, Allow, "no environment named is any object"),
        (AGENT, Deploy, Some("prod"), conservative, None, Ask, "the default grants no deploy"),
        (HUMAN, Build, Some("prod"), conservative, None, Ask, "an agent allow is not a human one"),
        (HUMAN, Destroy, Some("dev"), conservative, None, Never, "the default never destroys"),
        (AGENT, ReadSecrets, None, conservative, None, Never, "the default refuses secrets"),
        (
            HUMAN,
            ReadSecrets,
            None,
            conservative,
            READ_SECRETS,
            Never,
            "a rule for agents binds no human",
        ),
        (AGENT, Build, Some("staging"), conservative, READ_SECRETS, Allow, "it binds no build"),
        // An org baseline that grants a narrow deploy and refuses another.
        (AGENT, Deploy, Some("staging"), staging_only, None, Allow, "the baseline allows staging"),
        (AGENT, Deploy, Some("prod"), staging_only, None, Never, "the baseline refuses prod"),
        // The file narrows a baseline that would have allowed it...
        (AGENT, Deploy, Some("prod"), everywhere, DEPLOY_PROD, Never, "the file narrows an allow"),
        (AGENT, Deploy, Some("prod"), everywhere, None, Allow, "without it, the baseline allows"),
        // ...and binds only the principal it names.
        (
            HUMAN,
            Deploy,
            Some("prod"),
            conservative,
            DEPLOY_PROD,
            Ask,
            "an agent rule leaves human asking",
        ),
    ];

    for (actor, kind, env, baseline_fn, rule, expected, why) in rows {
        let baseline = baseline_fn();
        let file = file_policy(rule);
        let decision = PolicyGate::new(actor, &baseline, &file).decide(&action(kind, env));
        assert_eq!(decision.disposition, expected, "{why}");
        // The refusal names itself, so a run log carries an answer an operator can act on.
        assert!(!decision.rule.is_empty(), "a decision without a rule reads as {why}");
    }
}

/// The preflight refuses the run — not one step of it — when a step is certain to hit a refusal,
/// and otherwise says which steps will ask.
#[test]
fn preflight_refuses_a_run_that_would_certainly_hit_a_never() {
    let baseline = Baseline::conservative();
    let file = file_policy(None);
    let gate = PolicyGate::new(AGENT, &baseline, &file);
    let build = || PreflightStep::new("build", action(ActionKind::Build, Some("staging")));

    let refused = gate
        .preflight(&[
            build(),
            PreflightStep::new("rollout", action(ActionKind::Destroy, Some("prod"))),
        ])
        .expect_err("a destroy is refused under the default");
    assert_eq!(refused.step, "rollout");
    assert!(refused.rule.contains("destroy"), "{}", refused.rule);

    // A step that needs secrets is refused by the rule about secrets, and named as the step that
    // needs them — not as whichever step happened to come first.
    let refused = gate
        .preflight(&[PreflightStep {
            needs_secrets: true,
            ..PreflightStep::new("migrate", action(ActionKind::Apply, Some("prod")))
        }])
        .expect_err("the default refuses an agent reading secrets");
    assert_eq!(refused.step, "migrate");
    assert!(refused.rule.contains("secrets"), "{}", refused.rule);

    // A run that may start, with the questions it will ask reported in order.
    let asks = gate
        .preflight(&[
            build(),
            PreflightStep::new("rollout", action(ActionKind::Deploy, Some("prod"))),
        ])
        .expect("nothing in this plan is certainly refused");
    let asking: Vec<&str> = asks.iter().map(|need| need.step.as_str()).collect();
    assert_eq!(asking, vec!["rollout"], "the build asks for nothing");
}

/// The boundary is where the check has to be re-run: the action class comes from the prepared
/// inputs, after the steps before it have produced their outputs, so an apply whose plan came back
/// carrying a destroy is refused as the destroy it is.
#[test]
fn a_plan_that_turns_out_to_destroy_is_refused_at_the_boundary() {
    let f = fixture();
    let gate = f.gate();

    let inputs = Inputs::from_iter([("changes".to_string(), Value::from("destroy"))]);
    let refused = f.drive(&gate, "sample.apply", inputs, true);
    assert!(matches!(&refused, GatedRun::Refused(rule) if rule.contains("destroy")), "{refused:?}");
    assert_eq!(f.ran("sample.apply"), 0, "a refused step never runs");

    // The decision is in the run log, with the rule and the step.
    assert!(f.events().iter().any(|event| matches!(
        event,
        RunEvent::PolicyRefused { step: Some(step), rule }
            if step == "sample.apply" && rule.contains("destroy")
    )));
}

/// A question that has not been answered stops the step at the boundary; the same question
/// answered does not — and an approval answers a question and never a refusal.
#[test]
fn a_step_that_needs_an_approval_waits_for_one() {
    let f = fixture();
    let gate = f.gate();
    let inputs = || Inputs::from_iter([("env".to_string(), Value::from("prod"))]);

    // The conservative default grants no deploy to anyone, so deploying is a question.
    let outcome = f.drive(&gate, "sample.rollout", inputs(), false);
    assert_eq!(outcome, GatedRun::WaitingForApproval);
    assert_eq!(f.ran("sample.rollout"), 0, "an unapproved step never runs");
    assert!(f.events().iter().any(|event| matches!(
        event,
        RunEvent::ApprovalRequested { step, .. } if step == "sample.rollout"
    )));

    let outcome = f.drive(&gate, "sample.rollout", inputs(), true);
    assert!(matches!(outcome, GatedRun::Ran(Ok(_))), "{outcome:?}");
    assert_eq!(f.ran("sample.rollout"), 1, "the approved step ran");

    // The approval changes nothing for a refusal: `true` here, and the step still does not run.
    let inputs = Inputs::from_iter([("changes".to_string(), Value::from("destroy"))]);
    assert!(matches!(f.drive(&gate, "sample.apply", inputs, true), GatedRun::Refused(_)));
}

/// A step is never handed a port it did not declare. This one declares only the clock, and its
/// `run` reaches for the apply-capable IaC tool and the secret store anyway: the composition
/// provides both, and the step's context holds neither, so it cannot apply or read a secret. The
/// thing that stops a *declared* apply is the gate, above, not the step's own restraint.
#[test]
fn a_step_is_never_handed_a_port_it_did_not_declare() {
    let f = fixture();
    let outcome = f.drive(&f.gate(), "sample.sneaky", Inputs::new(), true);
    assert!(matches!(outcome, GatedRun::Ran(Ok(_))), "{outcome:?}");
    assert_eq!(f.ran("sample.sneaky"), 1, "the approved step ran");

    let observed = f.spy.saw_ports();
    assert!(!observed.iac, "the IaC port is provided but not handed over");
    assert!(!observed.secrets, "the secret store is provided but not handed over");
}

/// The port a run resolves secrets through refuses what policy refuses for the run's actor, even
/// when the step holds it legitimately — the boundary check is not the only thing standing in the
/// way, and it does not depend on which kind of actor is running.
#[test]
fn the_port_refuses_what_policy_refuses_for_the_running_actor() {
    let reference = SecretRef::new("env", "db_url");
    let secrets = Arc::new(FakeSecrets::new().with(reference.clone(), "postgres://db"));
    let resolve = |actor: ActorKind, gate: PolicyGate<'_>| {
        let gated = gate.secrets_port(Arc::clone(&secrets) as Arc<dyn Secrets>);
        let value = block_on(gated.resolve(&reference, &StepId::new("sample.migrate")));
        (actor, value)
    };

    // A baseline that would allow it, so the refusal below is the file's rule and not the default's.
    let permissive = Baseline {
        rules: vec![rule(Subject::Any, "read", "secrets", Disposition::Allow)],
        source: None,
        publishers: Vec::new(),
    };
    let bare = file_policy(None);
    let refusing = file_policy(Some("read secrets"));

    // The file's rule refuses, and it refuses before the run's resolver is asked for anything.
    let gate = PolicyGate::new(AGENT, &permissive, &refusing);
    match resolve(AGENT, gate).1 {
        Err(SecretsError::ForbiddenForActor { reference: refused, actor }) => {
            assert_eq!(refused, reference, "the refusal names the secret, not its value");
            assert!(actor.contains("agent"), "the refusal names who it is for: {actor}");
        }
        other => panic!("an agent under a policy that refuses secrets gets none: {other:?}"),
    }
    assert!(secrets.calls().is_empty(), "the refusal happens before the resolver is asked");

    // Without the file's rule nothing refuses, so the file is what refused it.
    let gate = PolicyGate::new(AGENT, &permissive, &bare);
    assert!(resolve(AGENT, gate).1.is_ok(), "without the rule, nothing refuses");

    // A human is refused under exactly the rule the preflight refuses the run for, and the refusal
    // names the human rather than an agent: the same gate, whatever is acting. The default's
    // `read secrets` refusal binds every principal, so this is the rule that binds a human.
    let conservative = Baseline::conservative();
    let gate = PolicyGate::new(HUMAN, &conservative, &bare);
    match resolve(HUMAN, gate).1 {
        Err(SecretsError::ForbiddenForActor { actor, .. }) => {
            assert!(actor.contains("human"), "the refusal names who it is for: {actor}");
        }
        other => panic!("a human under a policy that refuses secrets gets none: {other:?}"),
    }

    // Where policy allows the read, the port passes through for whoever is acting: a refusal here
    // would be one the policy never wrote.
    for (actor, baseline) in [(HUMAN, &permissive), (AGENT, &permissive)] {
        let gate = PolicyGate::new(actor, baseline, &bare);
        let (_, value) = resolve(actor, gate);
        let value = value.unwrap_or_else(|error| panic!("{actor:?} must resolve: {error:?}"));
        assert!(value.with_bytes(|bytes| bytes == b"postgres://db"));
    }
}

// ---- the steps and the composition the tests above run against ----

/// One run's worth of composition: a harness that *provides* an IaC tool, a secrets resolver and a
/// clock, three steps, and the log the decisions are written to.
struct Fixture {
    harness: Harness,
    /// The policy every boundary test above runs under: an agent, the conservative default, and a
    /// file with no rules of its own, so the decision comes from the baseline alone.
    baseline: Baseline,
    file: Policy,
    spy: Spy,
    log: Arc<RecordingRunLog>,
    sink: Arc<RecordingSink>,
    journal: Journal,
}

impl Fixture {
    /// How many times `name`'s `run` was called: the evidence that a refused or unapproved step
    /// never reached its own code.
    fn ran(&self, name: &str) -> u32 {
        self.spy.ran(name)
    }

    fn events(&self) -> Vec<RunEvent> {
        self.log.events()
    }

    fn gate(&self) -> PolicyGate<'_> {
        PolicyGate::new(AGENT, &self.baseline, &self.file)
    }

    /// Runs `name` through `gate` — the only path into `StepKind::run`.
    fn drive(&self, gate: &PolicyGate<'_>, name: &str, inputs: Inputs, approved: bool) -> GatedRun {
        block_on(gate.run_gated(
            &GateCtx {
                harness: &self.harness,
                journal: &self.journal,
                cancel: CancellationToken::new(),
                log: Arc::clone(&self.sink) as Arc<dyn LogSink>,
                redactor: Arc::new(Redactor::new()),
            },
            name,
            inputs,
            approved,
        ))
        .expect("the step resolves before it runs")
    }
}

fn fixture() -> Fixture {
    let spy = Spy::default();
    let ports = Ports::default()
        .with_clock(Arc::new(FakeClock::new()))
        .with_iac_tool(Arc::new(FakeIacTool::new()) as Arc<dyn IacTool>)
        .with_secrets(Arc::new(FakeSecrets::new()));
    let harness = Harness::builder()
        .ports(ports)
        // A deploy, whose action class is the environment it is aimed at.
        .step_arc(Arc::new(FakeStep {
            name: "sample.rollout",
            doc: "Deploys to an environment.",
            input: Some("env"),
            requires: &[],
            action: |inputs| match inputs.get("env") {
                Some(Value::String(env)) => ActionClass::new(ActionKind::Deploy).in_env(env),
                _ => ActionClass::new(ActionKind::Deploy),
            },
            spy: spy.clone(),
        }))
        // An apply whose action class is what the plan turned out to contain, and which *does*
        // declare the apply-capable port — so the boundary check, not the port restriction, is
        // what stands between it and the cluster.
        .step_arc(Arc::new(FakeStep {
            name: "sample.apply",
            doc: "Applies a plan.",
            input: Some("changes"),
            requires: &[Port::IacTool],
            action: |inputs| {
                let destroying =
                    matches!(inputs.get("changes"), Some(Value::String(t)) if t.contains("destroy"));
                let kind = if destroying { ActionKind::Destroy } else { ActionKind::Apply };
                ActionClass::new(kind).in_env("prod")
            },
            spy: spy.clone(),
        }))
        // A step that wants the apply-capable port and the secret store, declares neither, and
        // tries anyway from inside `run`.
        .step_arc(Arc::new(FakeStep {
            name: "sample.sneaky",
            doc: "Reaches for ports it never declared.",
            input: None,
            requires: &[Port::Clock],
            action: |_| ActionClass::new(ActionKind::Other),
            spy: spy.clone(),
        }))
        .build()
        .expect("the fixture composition is valid");
    let log = Arc::new(RecordingRunLog::new());
    let journal = Journal::new(
        Arc::clone(&log) as Arc<dyn RunLog>,
        Arc::new(Redactor::new()),
        RunId::from_parts(0, 1),
    );
    Fixture {
        harness,
        baseline: Baseline::conservative(),
        file: file_policy(None),
        spy,
        log,
        sink: Arc::new(RecordingSink::default()),
        journal,
    }
}

/// One parameterised fake step: the one input it takes, the ports it declares, and how it
/// classifies itself.
struct FakeStep {
    name: &'static str,
    doc: &'static str,
    input: Option<&'static str>,
    requires: &'static [Port],
    action: fn(&Inputs) -> ActionClass,
    spy: Spy,
}

impl StepKind for FakeStep {
    fn name(&self) -> &'static str {
        self.name
    }
    fn version(&self) -> Version {
        Version::new(0, 1, 0)
    }
    fn schema(&self) -> StepSchema {
        let inputs = self
            .input
            .map(|name| Field::new(name, TypeRef::Builtin(ValueType::String), "a string"))
            .into_iter()
            .collect();
        StepSchema { doc: self.doc, inputs, outputs: vec![] }
    }
    fn requires(&self) -> &'static [Port] {
        self.requires
    }
    fn action(&self, inputs: &Inputs) -> ActionClass {
        (self.action)(inputs)
    }
    fn run(&self, ctx: StepCtx, _inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        self.spy.record_run(self.name);
        // Every step looks at its own context; with the IaC port `None` there is no apply to make
        // at all, so a step cannot do the thing it was written to do, whatever it decides here.
        self.spy.record_ports(ctx.ports().iac_tool().is_some(), ctx.ports().secrets().is_some());
        Box::pin(std::future::ready(Ok(Outputs::new())))
    }
}

/// What the steps saw: how often each ran, and what the last of them found in its context.
#[derive(Clone, Default)]
struct Spy {
    runs: Arc<Mutex<BTreeMap<String, u32>>>,
    ports: Arc<Mutex<Observed>>,
}

/// What a step found in its context: was it handed the ports it did not declare?
#[derive(Clone, Copy, Default)]
struct Observed {
    iac: bool,
    secrets: bool,
}

impl Spy {
    fn record_run(&self, name: &str) {
        *self.runs.lock().expect("run counts").entry(name.to_string()).or_default() += 1;
    }

    fn record_ports(&self, iac: bool, secrets: bool) {
        *self.ports.lock().expect("the spy") = Observed { iac, secrets };
    }

    fn ran(&self, name: &str) -> u32 {
        self.runs.lock().expect("run counts").get(name).copied().unwrap_or(0)
    }

    /// What the last step to run found in its context.
    fn saw_ports(&self) -> Observed {
        *self.ports.lock().expect("the spy")
    }
}
