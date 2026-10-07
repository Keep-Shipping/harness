//! The order of a run is a function of the file, never of timing
//! ([#40](https://github.com/Keep-Shipping/harness/issues/40)).
//!
//! The property at the centre of it: however the independent steps of a plan
//! happen to finish — one at a time, eight at a time, in whatever order the
//! scheduler happens to be free — the log reads in sequence order, every step
//! appears exactly once, and the outputs are the ones the plan says they
//! should be. Hundreds of seeded random workflows check exactly that, against
//! what a plain forward pass over the plan says without any scheduler at all.

use std::collections::{BTreeMap, BTreeSet};

use ks_core::{Condition, ContextTest, TriggerKind};
use ks_engine::plan::{Gate, Plan, PlanCtx};
use ks_engine::sched::{Emitted, Outcome, Scheduler};

const HERO: &str = include_str!("../../lang/tests/fixtures/site-hero.ks");

/// Workflows in the sweep, and shuffles of each.
const SWEEP: u64 = 300;
const SHUFFLES: u64 = 4;

fn plan(src: &str, env: &str) -> Plan {
    let checked = ks_core::check(&ks_lang::parse(src));
    assert!(
        checked.diagnostics.is_empty(),
        "the fixture must check clean: {:#?}",
        checked.diagnostics
    );
    Plan::new(&checked.workflow, &PlanCtx { env: env.to_string(), event: None })
}

/// xorshift64*, so a failing seed replays exactly.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// What a step produced, as the log reads it: its records, or nothing at all
/// because it never ran. Whether it ran well or badly is not here — a failure
/// keeps its records — but the run's shape is.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Result {
    Ran(String),
    Skipped,
}

impl Result {
    fn of(emitted: &Emitted<String>) -> Result {
        match emitted {
            Emitted::Skipped(_) => Result::Skipped,
            Emitted::Ran(records) | Emitted::Failed(records) => {
                Result::Ran(records.first().cloned().unwrap_or_default())
            }
        }
    }
}

/// A step's one record: its own name and what it was built from, so that a
/// record which arrived early, or never, cannot pass for the right one.
fn record_of(plan: &Plan, seq: usize, outputs: &BTreeMap<usize, String>) -> String {
    let step = plan.step(seq).expect("a step in the plan");
    let body: Vec<String> = step
        .deps
        .iter()
        .map(|d| {
            outputs
                .get(d)
                .unwrap_or_else(|| panic!("{seq} started without the output of {d}"))
                .clone()
        })
        .collect();
    format!("{}={}", step.name, body.join("+"))
}

/// What each step does when the run reaches it, decided from the plan's own
/// seed — it is the content of the run, not its timing, so every shuffle of
/// one plan has to agree on it.
fn fates(plan: &Plan, seed: u64) -> Vec<Outcome> {
    let mut rng = Rng::new(seed ^ 0x5DEE_CE6E_D1AB_1E55);
    plan.steps
        .iter()
        .map(|_| match rng.below(8) {
            0 => Outcome::Failed,
            1 => Outcome::Skipped,
            _ => Outcome::Done,
        })
        .collect()
}

/// What the run must produce, from the plan alone: one forward pass, no
/// scheduler in it. A step runs when the plan did not rule it out and nothing
/// it waits on fell out; everything else is skipped, and a step that runs
/// produces `name=` its dependencies' outputs whatever the timing was.
fn expected(plan: &Plan, fates: &[Outcome]) -> Vec<(usize, Result)> {
    let mut outputs: BTreeMap<usize, String> = BTreeMap::new();
    let mut log = Vec::new();
    for step in &plan.steps {
        let ran = !step.gate.is_skipped()
            && !step
                .deps
                .iter()
                .any(|d| !outputs.contains_key(d) || fates[*d - 1] != Outcome::Done);
        // A step that runs and fails keeps its record, like one that succeeds.
        if !ran || matches!(fates[step.seq - 1], Outcome::Skipped) {
            log.push((step.seq, Result::Skipped));
            continue;
        }
        let record = record_of(plan, step.seq, &outputs);
        outputs.insert(step.seq, record.clone());
        log.push((step.seq, Result::Ran(record)));
    }
    log
}

/// One simulated run: the log as the scheduler released it, and the order the
/// steps finished in.
struct Sim {
    log: Vec<(usize, Emitted<String>)>,
    completed: Vec<usize>,
}

impl Sim {
    /// The log as results, which is what the plan says it should be.
    fn results(&self) -> Vec<(usize, Result)> {
        self.log.iter().map(|(seq, e)| (*seq, Result::of(e))).collect()
    }
}

/// Run `plan` with `jobs` steps at a time, completing a running step chosen
/// at random each turn. `runs` is a cap on the turns: a scheduler that stops
/// making progress fails the test rather than hanging it.
fn simulate(plan: &Plan, fates: &[Outcome], jobs: usize, seed: u64) -> Sim {
    let mut rng = Rng::new(seed);
    let mut sched: Scheduler<String> = Scheduler::new(plan, jobs);
    let mut running: Vec<usize> = Vec::new();
    let mut log: Vec<(usize, Emitted<String>)> = Vec::new();
    let mut completed: Vec<usize> = Vec::new();
    let mut outputs: BTreeMap<usize, String> = BTreeMap::new();
    let mut turns = 0usize;
    loop {
        turns += 1;
        assert!(turns < 10_000, "the scheduler stopped making progress");
        running.extend(sched.start());
        if running.is_empty() {
            // Nothing left to run: the steps a skip ruled out settle
            // themselves, and the log reads them in sequence order here.
            log.extend(sched.release());
            if sched.done() {
                break;
            }
            continue;
        }
        let picked = running.remove(rng.below(running.len()));
        let outcome = fates[picked - 1];
        let record = (outcome != Outcome::Skipped).then(|| record_of(plan, picked, &outputs));
        if let Some(record) = &record {
            outputs.insert(picked, record.clone());
        }
        completed.push(picked);
        log.extend(sched.finish(picked, outcome, record.into_iter().collect()));
    }
    Sim { log, completed }
}

#[test]
fn the_hero_plans_build_plan_review_apply_deploy() {
    let plan = plan(HERO, "default");
    let names: Vec<&str> = plan.steps.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["build", "plan", "review", "apply", "deploy"]);
    let seqs: Vec<usize> = plan.steps.iter().map(|s| s.seq).collect();
    assert_eq!(seqs, [1, 2, 3, 4, 5]);
    assert_eq!(plan.triggers, [TriggerKind::Push]);
    assert_eq!(plan.step(3).expect("review").kind.as_deref(), Some("approval"));
    // `apply` reads `plan` and waits for the approval that shows it; the
    // approval edge is in the plan like any other.
    assert_eq!(plan.step(4).expect("apply").deps, [2, 3]);
    assert!(plan.steps.iter().all(|s| s.gate == Gate::Always), "{:?}", plan.steps);
}

/// A random workflow, written as source and planned by the real planner: `n`
/// steps declared in a random order, joined by `after:` edges that always run
/// forward in the plan, and a `when:` on some. The sweep goes through the same
/// path a file does, so the plan it shuffles is the plan `graph` prints.
fn random_plan(rng: &mut Rng) -> Plan {
    let n = 2 + rng.below(8);
    let mut order: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rng.below(i + 1);
        order.swap(i, j);
    }
    let mut src =
        String::from("envs:\n  prod:\n    ci-only: true\n  staging:\n    ci-only: true\nsteps:\n");
    for (pos, name) in order.iter().enumerate() {
        let earlier: Vec<String> =
            (0..pos).filter(|_| rng.below(3) == 0).map(|q| format!("s{}", order[q])).collect();
        src.push_str(&format!("  s{name}: oci.image\n    from: ./Dockerfile\n"));
        if !earlier.is_empty() {
            // One name in four is quoted: a quoted name is still a name.
            let quoted = if earlier.len() == 1 && rng.below(4) == 0 {
                format!("\"{}\"", earlier[0])
            } else {
                earlier.join(", ")
            };
            src.push_str(&format!("    after: {quoted}\n"));
        }
        match rng.below(4) {
            // False for this environment, both of them: the plan-time skip and
            // the cascade behind it have something to work on.
            0 => src.push_str("    when: env is staging\n"),
            1 => src.push_str("    when: false\n"),
            _ => {}
        }
    }
    plan(&src, "prod")
}

#[test]
fn completion_order_never_changes_the_log_or_the_outputs() {
    let hero = plan(HERO, "default");
    let mut with_independence = 0;
    let mut reordered = 0;
    for seed in 0..SWEEP {
        let plan = if seed == 0 { hero.clone() } else { random_plan(&mut Rng::new(seed)) };
        let fates = fates(&plan, seed);
        let expected = expected(&plan, &fates);
        if plan.steps.iter().filter(|s| s.deps.is_empty()).count() >= 2 {
            with_independence += 1;
        }
        let mut orders: BTreeSet<Vec<usize>> = BTreeSet::new();
        for shuffle in 0..SHUFFLES {
            let jobs = 1 + (shuffle as usize % 8);
            let run = simulate(&plan, &fates, jobs, seed.wrapping_mul(0x9E37) + shuffle);
            // Every step, exactly once, in sequence order — and the outputs
            // the plan says they should have.
            assert_eq!(
                run.log.len(),
                plan.steps.len(),
                "seed={seed} shuffle={shuffle}: log length"
            );
            assert_eq!(
                run.results(),
                expected,
                "seed={seed} shuffle={shuffle} jobs={jobs}: the log or the outputs moved"
            );
            for ((seq, emitted), (_, want)) in run.log.iter().zip(&expected) {
                // A step that fell out reads as out; one that was to fail
                // reads as failed, and keeps what it logged.
                match want {
                    Result::Skipped => assert!(
                        matches!(emitted, Emitted::Skipped(_)),
                        "seed={seed} seq={seq}: {emitted:?} for a step that never ran"
                    ),
                    Result::Ran(_) => assert_eq!(
                        matches!(emitted, Emitted::Failed(_)),
                        fates[*seq - 1] == Outcome::Failed,
                        "seed={seed} seq={seq}: {emitted:?} for a step whose fate is {:?}",
                        fates[*seq - 1]
                    ),
                }
            }
            orders.insert(run.completed.clone());
        }
        if orders.len() > 1 {
            reordered += 1;
        }
    }
    // The sweep is only worth anything if it actually produced parallelism.
    assert!(with_independence >= 10, "only {with_independence} plans had independent steps");
    assert!(reordered >= 10, "only {reordered} plans ran in more than one order");
}

#[test]
fn a_plan_with_nothing_to_run_still_reads_as_a_whole_log() {
    let src = "\
envs:
  prod:
    ci-only: true
steps:
  one: oci.image
    when: false
    from: ./Dockerfile
  two: oci.image
    after: one
    from: ./Dockerfile
";
    let plan = plan(src, "prod");
    let mut sched: Scheduler<String> = Scheduler::new(&plan, 4);
    assert!(sched.done(), "the plan ruled out every step");
    assert_eq!(
        sched.release(),
        vec![
            (1, Emitted::Skipped("`when: false` is false in prod".to_string())),
            (2, Emitted::Skipped("one is skipped".to_string())),
        ]
    );
}

#[test]
fn start_takes_exactly_what_the_job_slots_leave() {
    // Four independent steps, so nothing but `jobs` decides how many start.
    let src = "\
steps:
  a: oci.image
    from: ./Dockerfile
  b: oci.image
    from: ./Dockerfile
  c: oci.image
    from: ./Dockerfile
  d: oci.image
    from: ./Dockerfile
";
    let plan = plan(src, "default");
    for jobs in 1..=5 {
        let mut sched: Scheduler<String> = Scheduler::new(&plan, jobs);
        let started = sched.start();
        assert_eq!(started.len(), jobs.min(4), "jobs={jobs}: started {started:?}");
        assert_eq!(started, (1..=started.len()).collect::<Vec<_>>());
        // What is already running counts against the next slots.
        let rest = sched.start();
        assert!(rest.is_empty(), "jobs={jobs}: started {rest:?} on top of {started:?}");
    }
    // Zero is read as one rather than as "run nothing at all".
    let mut sched: Scheduler<String> = Scheduler::new(&plan, 0);
    assert_eq!(sched.start(), [1]);
}

#[test]
fn finish_ignores_a_step_that_is_not_running() {
    let plan = plan(HERO, "default");
    let mut sched: Scheduler<String> = Scheduler::new(&plan, 2);
    assert_eq!(sched.start(), [1, 2]);
    // Nothing is running at these sequence numbers, and neither of them is in
    // the plan: nothing panics, nothing is overwritten, nothing is lost.
    for seq in [0, 99] {
        assert_eq!(sched.finish(seq, Outcome::Done, vec!["ghost".to_string()]), Vec::new());
    }
    // A double finish keeps the first outcome's records.
    assert_eq!(
        sched.finish(1, Outcome::Done, vec!["built".to_string()]),
        vec![(1, Emitted::Ran(vec!["built".to_string()]))]
    );
    assert_eq!(sched.finish(1, Outcome::Done, vec!["again".to_string()]), Vec::new());
    assert_eq!(
        sched.finish(2, Outcome::Failed, vec!["broke".to_string()]),
        vec![
            (2, Emitted::Failed(vec!["broke".to_string()])),
            // `review` and `apply` waited on the failure and never started.
            (3, Emitted::Skipped("plan failed".to_string())),
            (4, Emitted::Skipped("plan failed".to_string())),
            (5, Emitted::Skipped("apply failed".to_string())),
        ]
    );
    // A finish for a step the cascade settled cannot take that reason away.
    assert!(sched.is_settled(3) && sched.is_settled(4) && sched.is_settled(5));
    assert_eq!(sched.finish(4, Outcome::Done, vec!["applied".to_string()]), Vec::new());
}

/// A step that did not run reads as out, whatever it was handed as it settled.
#[test]
fn a_skip_is_never_reported_as_a_run() {
    let plan = plan(HERO, "default");
    let mut sched: Scheduler<String> = Scheduler::new(&plan, 8);
    assert_eq!(sched.start(), [1, 2]);
    assert!(
        sched.finish(2, Outcome::Skipped, vec!["nearly ran".to_string()]).is_empty(),
        "`build` has not settled, so nothing is due yet"
    );
    assert_eq!(
        sched.finish(1, Outcome::Done, vec!["built".to_string()]),
        vec![
            (1, Emitted::Ran(vec!["built".to_string()])),
            // The records go with the skip that says why, not into a log
            // entry that reads as `plan` having run.
            (2, Emitted::Skipped("its `when:` was false at run time".to_string())),
            (3, Emitted::Skipped("plan was skipped".to_string())),
            (4, Emitted::Skipped("plan was skipped".to_string())),
            (5, Emitted::Skipped("apply was skipped".to_string())),
        ]
    );
}

#[test]
fn a_failure_keeps_its_records() {
    let plan = plan(HERO, "default");
    let mut sched: Scheduler<String> = Scheduler::new(&plan, 8);
    assert_eq!(sched.start(), [1, 2]);
    assert!(sched.finish(2, Outcome::Failed, vec!["plan blew up".to_string()]).is_empty());
    assert_eq!(
        sched.finish(1, Outcome::Done, vec!["built".to_string()]),
        vec![
            (1, Emitted::Ran(vec!["built".to_string()])),
            (2, Emitted::Failed(vec!["plan blew up".to_string()])),
            (3, Emitted::Skipped("plan failed".to_string())),
            (4, Emitted::Skipped("plan failed".to_string())),
            (5, Emitted::Skipped("apply failed".to_string())),
        ]
    );
}

/// `when:` that reads only context is settled before the run starts; one that
/// reads a step's output is not, and says so in the plan.
#[test]
fn a_context_when_is_settled_before_the_run_and_the_rest_is_not() {
    let src = "\
envs:
  prod:
    ci-only: true
  staging:
    ci-only: true
steps:
  build: oci.image
    from: ./Dockerfile
  inprod: oci.image
    when: env is prod
    from: ./Dockerfile
  elsewhere: oci.image
    when: env is staging
    from: ./Dockerfile
  downstream: oci.image
    after: elsewhere
    from: ./Dockerfile
  gated: oci.image
    when: build.signed
    from: ./Dockerfile
";
    let plan = plan(src, "prod");
    let gate = |name: &str| {
        plan.steps.iter().find(|s| s.name == name).expect("a planned step").gate.clone()
    };
    // Every step is planned — a skip is a gate, not a missing step.
    assert_eq!(plan.steps.len(), 5);
    assert!(matches!(gate("inprod"), Gate::Always));
    let Gate::Skip { reason } = gate("elsewhere") else {
        panic!("a `when:` false for the environment skips the step at plan time")
    };
    assert!(reason.contains("env is staging"), "{reason}");
    // The skip cascades, naming the step it follows.
    let Gate::Skip { reason } = gate("downstream") else {
        panic!("a step that waits on a skipped step is skipped too")
    };
    assert_eq!(reason, "elsewhere is skipped");
    assert!(matches!(
        gate("gated"),
        Gate::Runtime { condition: Condition { ref steps, .. } } if *steps == ["build"]
    ));
}

#[test]
fn a_runtime_skip_takes_its_dependents_with_it() {
    let plan = plan(HERO, "default");
    let mut sched: Scheduler<String> = Scheduler::new(&plan, 4);
    assert_eq!(sched.start(), [1, 2]);
    // `plan` skips at run time. Nothing is logged yet — `build` has not
    // settled, and the log reads in sequence order — but what waited on
    // `plan` is out without running.
    assert!(sched.finish(2, Outcome::Skipped, vec![]).is_empty());
    assert!(sched.is_settled(3) && sched.is_settled(4));
    // `build` finishes and the log catches up in one go.
    assert_eq!(
        sched.finish(1, Outcome::Done, vec!["built".to_string()]),
        vec![
            (1, Emitted::Ran(vec!["built".to_string()])),
            (2, Emitted::Skipped("its `when:` was false at run time".to_string())),
            (3, Emitted::Skipped("plan was skipped".to_string())),
            (4, Emitted::Skipped("plan was skipped".to_string())),
            (5, Emitted::Skipped("apply was skipped".to_string())),
        ]
    );
    // Nothing is left to start: the skip reached `deploy` through `apply`.
    assert!(sched.done());
    assert_eq!(sched.start(), Vec::<usize>::new());
}

/// A `not` over the environment test, and a boolean literal, are context
/// tests too.
#[test]
fn negations_and_literals_are_context_tests() {
    let src = "\
envs:
  prod:
    ci-only: true
steps:
  a: oci.image
    when: not env is prod
    from: ./Dockerfile
  b: oci.image
    when: false
    from: ./Dockerfile
";
    let plan = plan(src, "prod");
    assert!(plan.steps.iter().all(|s| s.gate.is_skipped()), "{:?}", plan.steps);
    assert!(!ContextTest::Bool(false).eval("prod"));
}
