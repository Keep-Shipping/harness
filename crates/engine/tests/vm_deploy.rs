//! The built-in `vm.deploy` step over the `ks-testing` fakes: a rolling deploy across a fleet,
//! the batch that stops and rolls back, the batch a percent groups, and the two things a deploy
//! must never do — connect to a host whose key is not pinned, and accept a key it did not expect.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ks_core::Catalog;
use ks_core::harness::{Harness, HarnessBuilder};
use ks_core::ports::clock::Clock;
use ks_core::ports::health::Health;
use ks_core::ports::remote_shell::{Host, HostKey, RemoteShell, ShellError};
use ks_core::ports::script_host::Value;
use ks_core::ports::secrets::Redactor;
use ks_core::step::{CancellationToken, Inputs, LogSink, Outputs, Ports, StepError, StepKind};
use ks_engine::run::run_step;
use ks_engine::vm_deploy::{NAME, VmDeploy};
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::remote_shell::{FakeRemoteShell, ShellCall};
use ks_testing::step::{RecordingSink, StepCase, step_conformance};

/// The probe every host in the fleet answers.
const PROBE: &str = "curl -fsS localhost:8080/healthz";
/// The command a deploy runs on a host.
const DEPLOY: &str = "/opt/app/bin/release.sh";
/// The command that puts a host back the way it was.
const ROLLBACK: &str = "/opt/app/bin/rollback.sh";
/// A second rollback command, so a test can tell "every restore command ran" from "the first one
/// did and the step stopped there".
const ROLLBACK_TWO: &str = "/opt/app/bin/restart.sh";
/// How often the health gate polls, and therefore what it waits between two probes. The step's
/// own constant; a test that asserts on the waits has to name the same number.
const POLL: Duration = Duration::from_secs(5);

/// The composition `vm.deploy` needs: the built-in types its siblings' schemas name, and the
/// step itself.
fn harness_for(ports: Ports) -> HarnessBuilder {
    ks_engine::steps::builtin_types()
        .into_iter()
        .fold(Harness::builder().ports(ports), |builder, def| builder.type_def(def))
        .step_arc(Arc::new(VmDeploy))
}

/// A pinned host, as an operator names one.
fn host(address: &str, fingerprint: &str) -> Host {
    Host::new(
        address,
        22,
        "deploy",
        HostKey::new("ssh-ed25519", fingerprint).expect("a well-formed host key"),
    )
    .expect("a well-formed host")
}

/// A host as the `hosts` input spells it: an address and the fingerprint it must present.
fn host_input(address: &str, fingerprint: &str) -> Value {
    Value::Map(BTreeMap::from([
        ("address".to_string(), Value::from(address)),
        ("host_key".to_string(), Value::from(fingerprint)),
    ]))
}

/// The three-host fleet the tests deploy to, each its own fake so a test can see what happened
/// on that host alone.
struct Fleet {
    harness: Harness,
    gateway: Arc<FakeRemoteShell>,
    a: Arc<FakeRemoteShell>,
    b: Arc<FakeRemoteShell>,
    c: Arc<FakeRemoteShell>,
    sink: Arc<RecordingSink>,
    /// The run's clock, kept so a test can read back what the health gate waited on. Its
    /// `sleep` advances instantly and records, so asserting on it proves the gate waits
    /// without a test waiting with it.
    clock: Arc<FakeClock>,
}

/// A gateway over three peers that all come up healthy.
fn fleet() -> Fleet {
    fleet_with([Health::Healthy, Health::Healthy, Health::Healthy])
}

/// As [`fleet`], with what each peer's probe answers on its own first call. A script that runs
/// out holds at its last entry, so a host that answers `Healthy` keeps answering it.
fn fleet_with(states: [Health; 3]) -> Fleet {
    fleet_scripted([vec![states[0]], vec![states[1]], vec![states[2]]])
}

/// As [`fleet`], with a full probe script for each peer rather than a single answer, so a test can
/// watch a host walk out of `Progressing` and into `Healthy`. A script that runs out holds at its
/// last entry, so a host that reaches `Healthy` keeps answering it.
fn fleet_scripted(scripts: [Vec<Health>; 3]) -> Fleet {
    let peer = |address: &str, fingerprint: &str, script: &[Health]| {
        Arc::new(
            FakeRemoteShell::new()
                .with_host(host(address, fingerprint))
                .with_probe_script(PROBE, script.to_vec()),
        )
    };
    let a = peer("a.example", "SHA256:a", &scripts[0]);
    let b = peer("b.example", "SHA256:b", &scripts[1]);
    let c = peer("c.example", "SHA256:c", &scripts[2]);
    let gateway = Arc::new(
        FakeRemoteShell::new()
            .with_peer(Arc::clone(&a))
            .with_peer(Arc::clone(&b))
            .with_peer(Arc::clone(&c)),
    );
    let clock = Arc::new(FakeClock::new());
    let ports = Ports::default()
        .with_clock(Arc::clone(&clock) as Arc<dyn Clock>)
        .with_remote_shell(Arc::clone(&gateway) as Arc<dyn RemoteShell>);
    Fleet {
        harness: harness_for(ports).build().expect("the composition is valid"),
        gateway,
        a,
        b,
        c,
        sink: Arc::new(RecordingSink::new()),
        clock,
    }
}

/// `hosts` as the three-host fleet, with the deploy command and the health gate on each host.
fn fleet_inputs() -> Inputs {
    let mut inputs = Inputs::new();
    inputs.insert(
        "hosts".to_string(),
        Value::List(vec![
            host_input("a.example", "SHA256:a"),
            host_input("b.example", "SHA256:b"),
            host_input("c.example", "SHA256:c"),
        ]),
    );
    inputs.insert("run".to_string(), Value::List(vec![command(DEPLOY)]));
    inputs.insert("health".to_string(), Value::from(PROBE));
    inputs
}

/// One `{ program, args, timeout }` command, as the input spells it.
fn command(program: &str) -> Value {
    Value::Map(BTreeMap::from([
        ("program".to_string(), Value::from(program)),
        ("args".to_string(), Value::List(vec![Value::from("--quiet")])),
        ("timeout".to_string(), Value::from(30.0)),
    ]))
}

/// The `&str` under `name`.
fn text<'a>(outputs: &'a Outputs, name: &str) -> &'a str {
    match outputs.get(name) {
        Some(Value::String(text)) => text,
        other => panic!("the step returns a {name}, got {other:?}"),
    }
}

/// The whole number under `name`.
fn number(outputs: &Outputs, name: &str) -> f64 {
    match outputs.get(name) {
        Some(Value::Number(number)) => *number,
        other => panic!("the step returns a number {name}, got {other:?}"),
    }
}

/// Runs the step, keeping whatever it said.
fn drive(harness: &Harness, inputs: Inputs, sink: Arc<dyn LogSink>) -> Result<Outputs, StepError> {
    block_on(run_step(
        harness,
        NAME,
        inputs,
        CancellationToken::new(),
        sink,
        Arc::new(Redactor::new()),
    ))
}

/// Runs the step against `fleet`, keeping whatever it said.
fn run(fleet: &Fleet, inputs: Inputs) -> Result<Outputs, StepError> {
    drive(&fleet.harness, inputs, Arc::clone(&fleet.sink) as Arc<dyn LogSink>)
}

/// As [`run`], panicking on a failure.
fn deploy(fleet: &Fleet, inputs: Inputs) -> Outputs {
    run(fleet, inputs).unwrap_or_else(|error| panic!("the step runs: {error}"))
}

/// Every message the fleet's sink kept.
fn logged(fleet: &Fleet) -> Vec<String> {
    fleet.sink.records().into_iter().map(|record| record.message).collect()
}

/// The addresses `gateway` was asked to connect to, in order. `Connect` is only ever recorded
/// against the gateway a step asked for a host through — a peer never sees one — so this is the
/// only place the fleet's connect order is visible.
fn connected(gateway: &FakeRemoteShell) -> Vec<String> {
    gateway
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            ShellCall::Connect { address } => Some(address),
            _ => None,
        })
        .collect()
}

/// The programs a peer was asked to run, in order.
fn programs(peer: &FakeRemoteShell) -> Vec<String> {
    peer.calls()
        .into_iter()
        .filter_map(|call| match call {
            ShellCall::Run { program } => Some(program),
            _ => None,
        })
        .collect()
}

#[test]
fn a_rolling_deploy_walks_the_fleet_one_host_at_a_time() {
    let fleet = fleet();
    let mut inputs = fleet_inputs();
    inputs.insert("batch".to_string(), Value::from("1"));

    let outputs = deploy(&fleet, inputs);

    assert_eq!(text(&outputs, "summary"), "3/3 hosts healthy");
    assert_eq!(number(&outputs, "healthy"), 3.0);
    assert_eq!(number(&outputs, "total"), 3.0);
    assert!(
        logged(&fleet).iter().any(|line| line == "3/3 hosts healthy"),
        "the summary is in the run log too: {:?}",
        logged(&fleet)
    );

    // One host per batch, in fleet order, each reached through the gateway to its own pin.
    assert_eq!(connected(&fleet.gateway), ["a.example", "b.example", "c.example"]);
    for peer in [&fleet.a, &fleet.b, &fleet.c] {
        assert_eq!(programs(peer), [DEPLOY], "each host ran its deploy command exactly once");
        assert!(
            peer.calls()
                .iter()
                .any(|call| matches!(call, ShellCall::Probe { command } if command == PROBE)),
            "each host was health-gated: {:?}",
            peer.calls()
        );
    }
}

#[test]
fn a_failure_in_batch_two_stops_the_deploy_and_rolls_back_only_that_batch() {
    // A comes up, B settles failed, C is never asked.
    let fleet = fleet_with([Health::Healthy, Health::Failed, Health::Healthy]);
    let mut inputs = fleet_inputs();
    inputs.insert("batch".to_string(), Value::from("1"));
    inputs.insert("rollback".to_string(), Value::List(vec![command(ROLLBACK)]));

    let error = run(&fleet, inputs).expect_err("a failed host stops the deploy");

    // The message names the batch and the host, so a reader knows what to look at.
    let message = error.to_string();
    assert!(message.contains("batch 2"), "{message}");
    assert!(message.contains("b.example"), "{message}");
    assert!(matches!(error, StepError::Failed(_)), "{error:?}");

    // C is in a later batch, and a later batch is never touched.
    assert_eq!(fleet.c.calls(), [], "the host after the failure was never reached");
    assert!(
        !connected(&fleet.gateway).contains(&"c.example".to_string()),
        "the gateway was never even asked for c: {:?}",
        connected(&fleet.gateway)
    );

    // B was rolled back, because it is what failed.
    assert!(
        programs(&fleet.b).contains(&ROLLBACK.to_string()),
        "b was rolled back: {:?}",
        programs(&fleet.b)
    );
    // A deployed cleanly and is not undone: rolling back a whole fleet because one host failed is
    // a longer outage than the one being repaired.
    assert_eq!(programs(&fleet.a), [DEPLOY], "a was left deployed");
}

#[test]
fn a_batch_of_no_rollback_commands_says_so_in_the_message() {
    let fleet = fleet_with([Health::Healthy, Health::Failed, Health::Healthy]);
    let mut inputs = fleet_inputs();
    inputs.insert("batch".to_string(), Value::from("1"));
    // No `rollback` input at all.

    let error = run(&fleet, inputs).expect_err("a failed host stops the deploy");
    assert!(error.to_string().contains("no rollback commands"), "{error}");
}

/// The step's real subject here is the rounding, not the deployment: 50% of a three-host fleet is
/// 1.5 hosts, and rounding that down would put a batch of zero hosts in a run that reports a
/// deploy. The grouping itself is what the batch log lines pin down.
#[test]
fn a_percent_batch_rounds_up_and_groups_the_fleet() {
    let fleet = fleet();
    let mut inputs = fleet_inputs();
    // 50% of three hosts rounds up to two: a batch of zero would deploy nothing and look like a
    // deploy that ran.
    inputs.insert("batch".to_string(), Value::from("50%"));

    let outputs = deploy(&fleet, inputs);
    assert_eq!(text(&outputs, "summary"), "3/3 hosts healthy");

    // Two batches, of two hosts and then of one. `batch 1, batch 1, batch 2` would be three
    // batches — the rounding down this test exists to rule out — and `batch 1, batch 2` is only
    // reachable with the batch of two the step logs as carrying two hosts.
    let batches: Vec<String> =
        logged(&fleet).into_iter().filter(|line| line.starts_with("batch ")).collect();
    assert_eq!(batches, ["batch 1", "batch 2"], "two batches: {:?}", logged(&fleet));

    // Every host was reached: a batch the step rounds up but never fills would leave a host
    // untouched while still reporting the fleet healthy.
    assert_eq!(connected(&fleet.gateway), ["a.example", "b.example", "c.example"]);
    for peer in [&fleet.a, &fleet.b, &fleet.c] {
        assert_eq!(programs(peer), [DEPLOY], "every host in the fleet was deployed to");
    }
}

#[test]
fn a_host_with_no_pinned_key_is_refused_before_anything_is_reached() {
    let fleet = fleet();
    let mut inputs = Inputs::new();
    inputs.insert(
        "hosts".to_string(),
        Value::List(vec![
            host_input("a.example", "SHA256:a"),
            // The last entry names no `host_key`: there is no "accept once", and no TOFU prompt
            // the run could answer on the operator's behalf.
            Value::Map(BTreeMap::from([("address".to_string(), Value::from("b.example"))])),
        ]),
    );
    inputs.insert("health".to_string(), Value::from(PROBE));

    let error = run(&fleet, inputs).expect_err("an unpinned host key is refused");
    match &error {
        StepError::InvalidInput { field, reason } => {
            assert_eq!(field, "hosts");
            assert!(reason.contains("host_key"), "{reason}");
        }
        other => panic!("an input error, not a port failure: {other:?}"),
    }

    // The refusal happened before a single connection: the whole fleet is read before any of it
    // is touched, so a bad pin at the end never leaves the first host half-deployed.
    assert_eq!(fleet.gateway.calls(), [], "nothing was reached");
}

#[test]
fn an_empty_fleet_is_refused_rather_than_deployed_to_nothing() {
    let fleet = fleet();
    let mut inputs = Inputs::new();
    inputs.insert("hosts".to_string(), Value::List(Vec::new()));

    let error = run(&fleet, inputs).expect_err("a deploy to no hosts is not a deploy");
    assert!(matches!(error, StepError::InvalidInput { .. }), "{error:?}");
    assert_eq!(fleet.gateway.calls(), []);
}

/// What this pins is the path a real SSH adapter takes: the ADAPTER refuses a host whose
/// presented key is not the one it was pinned to, and that refusal has to surface as a step
/// failure rather than a host quietly reported healthy. The step's own [`pinned_for`] comparison
/// is equal by construction here — the peer's `Host` carries the same fingerprint the workflow
/// pins — so this test does NOT cover that check;
/// `a_rebuilt_host_is_refused_before_anything_is_run_on_it` does.
#[test]
fn an_adapters_pin_rejection_surfaces_as_a_step_failure_and_is_never_retried() {
    // The gateway itself reaches the fleet; the peer standing in for `b` has its own adapter
    // refuse the key its `Host` claims to pin.
    let rebuilt = Arc::new(
        FakeRemoteShell::new()
            .with_host(host("b.example", "SHA256:b"))
            .with_rejected_host_key("SHA256:b")
            .with_probe_script(PROBE, [Health::Healthy]),
    );
    let gateway = Arc::new(
        FakeRemoteShell::new()
            .with_peer(Arc::new(
                FakeRemoteShell::new()
                    .with_host(host("a.example", "SHA256:a"))
                    .with_probe_script(PROBE, [Health::Healthy]),
            ))
            .with_peer(Arc::clone(&rebuilt)),
    );
    let harness = harness_for(
        Ports::default()
            .with_clock(Arc::new(FakeClock::new()))
            .with_remote_shell(Arc::clone(&gateway) as Arc<dyn RemoteShell>),
    )
    .build()
    .expect("the composition is valid");

    let mut inputs = Inputs::new();
    inputs.insert(
        "hosts".to_string(),
        Value::List(vec![host_input("a.example", "SHA256:a"), host_input("b.example", "SHA256:b")]),
    );
    inputs.insert("health".to_string(), Value::from(PROBE));

    let error = drive(&harness, inputs, Arc::new(RecordingSink::new()) as Arc<dyn LogSink>)
        .expect_err("a host the adapter refuses is refused");
    assert!(matches!(error, StepError::Failed(_)), "{error:?}");
    assert!(error.to_string().contains("host key mismatch"), "{error}");

    // Not retried: exactly one probe was fired at the refused host, and its probe script answers
    // `Healthy` every time. A second attempt — a retry loop, or a second health gate after a
    // failure — would be a second probe and would fail this count. The refusal is terminal.
    assert_eq!(
        rebuilt.calls(),
        [ShellCall::Probe { command: PROBE.to_string() }],
        "one probe on the refused host, and no retry: {:?}",
        rebuilt.calls()
    );

    // The gateway was asked for `b` twice and `a` once: the deploy's own reach, and the rollback
    // the failed batch earns. Both are accounted for, so a retry loop that reconnected would
    // lengthen this list rather than leave it as it is.
    assert_eq!(
        connected(&gateway),
        ["a.example", "b.example", "b.example"],
        "a, then b for the deploy and once more for the rollback attempt"
    );
}

#[test]
fn max_failures_lets_a_deploy_carry_on_and_then_stops_it() {
    // B fails and C comes up: with a budget of one failure the deploy runs to the end, and the
    // fleet reports the shortfall rather than hiding it.
    let fleet = fleet_with([Health::Healthy, Health::Failed, Health::Healthy]);
    let mut inputs = fleet_inputs();
    inputs.insert("batch".to_string(), Value::from("1"));
    inputs.insert("max_failures".to_string(), Value::from(1.0));

    let outputs = deploy(&fleet, inputs);
    assert_eq!(number(&outputs, "healthy"), 2.0);
    assert_eq!(number(&outputs, "total"), 3.0);
    assert_eq!(text(&outputs, "summary"), "2/3 hosts healthy");
    assert_eq!(
        connected(&fleet.gateway),
        ["a.example", "b.example", "c.example"],
        "the deploy did not stop at b"
    );

    // The default budget is zero: one failure stops it. A fresh fleet, same script.
    let strict = fleet_with([Health::Healthy, Health::Failed, Health::Healthy]);
    let mut inputs = fleet_inputs();
    inputs.insert("batch".to_string(), Value::from("1"));
    let error = run(&strict, inputs).expect_err("one failure over a zero budget stops the deploy");
    assert!(error.to_string().contains("b.example"), "{error}");
    assert_eq!(strict.c.calls(), [], "the host after the stop was never reached");
}

/// The programs a step would record instead of `systemctl` if it did not pass a typed argv:
/// a shell it handed the line to, or the line itself as one program name. Each is scripted to
/// fail on the peer, so a step reaching for one fails the deploy instead of quietly reaching the
/// same summary.
const NOT_A_TYPED_ARGV: [&str; 8] = [
    "sh",
    "bash",
    "/bin/sh",
    "/usr/bin/env",
    "zsh",
    "dash",
    "systemctl restart two words' --and-more",
    "systemctl restart \"two words' --and-more\"",
];

/// What [`NOT_A_TYPED_ARGV`] names cannot be told apart by this fake, which records a `run` by
/// program only — so this test pins the program sequence and asserts the program is the bare
/// name the input gave. It does NOT observe argument boundaries: [`ks_testing::remote_shell::ShellCall::Run`]
/// carries no arguments, so "one argument, or two?" is invisible here. The fake offers no way to
/// see them either — [`with_command_result`] and
/// [`with_command_error`](ks_testing::remote_shell::FakeRemoteShell::with_command_error) key on
/// the program alone. What the program being `systemctl` does rule out is handing the whole line
/// to a shell, and that is what this asserts.
#[test]
fn the_deploy_runs_each_typed_command_by_its_program_name() {
    let a = Arc::new(
        NOT_A_TYPED_ARGV.iter().fold(
            FakeRemoteShell::new()
                .with_host(host("a.example", "SHA256:a"))
                .with_probe_script(PROBE, [Health::Healthy]),
            |shell, program| {
                shell.with_command_error(
                    *program,
                    ShellError::Command {
                        command: (*program).to_string(),
                        status: 126,
                        stderr: "a shell string must never run a deploy command".to_string(),
                    },
                )
            },
        ),
    );
    let gateway = Arc::new(FakeRemoteShell::new().with_peer(Arc::clone(&a)));
    let harness = harness_for(
        Ports::default()
            .with_clock(Arc::new(FakeClock::new()))
            .with_remote_shell(Arc::clone(&gateway) as Arc<dyn RemoteShell>),
    )
    .build()
    .expect("the composition is valid");

    let mut inputs = Inputs::new();
    inputs.insert("hosts".to_string(), Value::List(vec![host_input("a.example", "SHA256:a")]));
    inputs.insert(
        "run".to_string(),
        Value::List(vec![Value::Map(BTreeMap::from([
            ("program".to_string(), Value::from("systemctl")),
            (
                "args".to_string(),
                Value::List(vec![
                    Value::from("restart"),
                    // A value with a space and a quote in it. The step hands it to the adapter
                    // as one argument of a typed argv, so the quote starts no new command.
                    Value::from("two words' --and-more"),
                ]),
            ),
            ("timeout".to_string(), Value::from(30.0)),
        ]))]),
    );
    inputs.insert("health".to_string(), Value::from(PROBE));

    let outputs = drive(&harness, inputs, Arc::new(RecordingSink::new()) as Arc<dyn LogSink>)
        .unwrap_or_else(|error| panic!("the deploy runs: {error}"));

    // The bare program name, exactly once. Every program that would mean "the line went through a
    // shell" is scripted to fail above, so this record is only reachable if the step named
    // `systemctl` and nothing else.
    assert_eq!(
        programs(&a),
        ["systemctl"],
        "the program the adapter was asked for, not a shell and not a joined line"
    );
    assert_eq!(
        number(&outputs, "healthy"),
        1.0,
        "the deploy ran: the unquoted value did not break it"
    );
}

#[test]
fn without_a_health_probe_there_is_no_gate_and_the_deploy_still_runs() {
    let fleet = fleet();
    let mut inputs = Inputs::new();
    inputs.insert("hosts".to_string(), Value::List(vec![host_input("a.example", "SHA256:a")]));
    inputs.insert("run".to_string(), Value::List(vec![command(DEPLOY)]));

    let outputs = deploy(&fleet, inputs);
    assert_eq!(text(&outputs, "summary"), "1/1 hosts healthy");
    assert!(
        !fleet.a.calls().iter().any(|call| matches!(call, ShellCall::Probe { .. })),
        "nothing was probed, because nothing was asked to probe"
    );
    // Healthy here means the host was reached to its pinned key and ran its command — not that
    // nothing was checked. Without a `run` list and without a probe there is nothing else to
    // check, which is exactly why the pin has to be verified on its own.
    assert_eq!(programs(&fleet.a), [DEPLOY], "the host was reached, to its pin");
    assert!(fleet.clock.sleeps().is_empty(), "no probe, so no waiting");
}

/// A fleet whose single host presents a key the input does not pin is refused even with no `run`
/// and no `health` — the case the pin exists for, with nothing else on the path to catch it.
#[test]
fn a_rebuilt_host_is_refused_before_anything_is_run_on_it() {
    let rebuilt = Arc::new(
        FakeRemoteShell::new()
            .with_host(host("a.example", "SHA256:rebuilt"))
            .with_probe_script(PROBE, [Health::Healthy]),
    );
    let gateway = Arc::new(FakeRemoteShell::new().with_peer(Arc::clone(&rebuilt)));
    let harness = harness_for(
        Ports::default()
            .with_clock(Arc::new(FakeClock::new()) as Arc<dyn Clock>)
            .with_remote_shell(Arc::clone(&gateway) as Arc<dyn RemoteShell>),
    )
    .build()
    .expect("the composition is valid");

    let mut inputs = Inputs::new();
    inputs.insert("hosts".to_string(), Value::List(vec![host_input("a.example", "SHA256:a")]));
    inputs.insert("run".to_string(), Value::List(vec![command(DEPLOY)]));

    let error = drive(&harness, inputs, Arc::new(RecordingSink::new()) as Arc<dyn LogSink>)
        .expect_err("a host presenting another key is refused");
    let message = error.to_string();
    assert!(message.contains("a.example"), "the host is named: {message}");
    assert!(message.contains("SHA256:a"), "the pinned fingerprint is named: {message}");
    assert!(
        message.contains("SHA256:rebuilt"),
        "the fingerprint it actually presented is named: {message}"
    );

    // Nothing ran on it: the pin is checked before the deploy commands, not after.
    assert_eq!(rebuilt.calls(), [], "the rebuilt host was reached but never changed");
}

/// The gate waits between probes rather than firing them back to back, so a host that needs a
/// moment to boot is still healthy when the gate opens. The [`FakeClock`] records the waits
/// without spending them, which is what makes this provable in a fast test.
#[test]
fn the_health_gate_waits_between_probes_and_a_slow_host_still_comes_up() {
    let slow = vec![Health::Progressing, Health::Progressing, Health::Healthy];
    let fleet = fleet_scripted([slow.clone(), slow.clone(), slow]);
    let mut inputs = fleet_inputs();
    inputs.insert("batch".to_string(), Value::from("1"));
    // 30s of budget over a 5s poll interval is six probes; the host answers on the third.
    inputs.insert("health_timeout".to_string(), Value::from(30.0));

    let outputs = deploy(&fleet, inputs);
    assert_eq!(text(&outputs, "summary"), "3/3 hosts healthy");

    // Each host was probed three times and waited a poll interval twice: the loop spans the
    // declared duration rather than exhausting a probe count in milliseconds.
    let sleeps = fleet.clock.sleeps();
    assert_eq!(sleeps, vec![POLL; 6], "two waits per host, three hosts: {sleeps:?}");
    assert_eq!(fleet.clock.elapsed_since_start(), POLL * 6, "the run spent the waits it recorded");
}

/// A gate that never sees health fails a host once its timeout is spent, and the message says
/// how many probes that was — a host that never comes up is a failure, not a hang.
#[test]
fn a_host_that_never_reports_healthy_is_failed_after_the_declared_timeout() {
    // Every host answers `Progressing` forever: the script holds at its last entry.
    let fleet = fleet_with([Health::Progressing; 3]);
    let mut inputs = fleet_inputs();
    inputs.insert("batch".to_string(), Value::from("1"));
    // 15s over a 5s interval is three probes, so three probes and two waits.
    inputs.insert("health_timeout".to_string(), Value::from(15.0));

    let error = run(&fleet, inputs).expect_err("a host that never comes up fails the deploy");
    let message = error.to_string();
    assert!(message.contains("after 3 tries"), "the message counts the probes: {message}");
    assert_eq!(fleet.clock.sleeps(), vec![POLL; 2], "one wait fewer than the probe count");

    // The first host exhausted the budget and stopped the deploy: later batches are untouched.
    assert_eq!(fleet.b.calls(), [], "the deploy stopped at the first host that never came up");
}

/// `health_timeout` is a duration, so a negative one is a mistake in the workflow rather than a
/// very short wait — the same refusal `max_failures` gets.
#[test]
fn a_negative_health_timeout_is_refused_rather_than_clamped_into_one_probe() {
    let fleet = fleet();
    let mut inputs = fleet_inputs();
    inputs.insert("health_timeout".to_string(), Value::from(-1.0));

    let error = run(&fleet, inputs).expect_err("a negative timeout is a bad input");
    match &error {
        StepError::InvalidInput { field, reason } => {
            assert_eq!(field, "health_timeout");
            assert!(reason.contains("negative"), "{reason}");
        }
        other => panic!("an input error, not a gate failure: {other:?}"),
    }
    assert_eq!(fleet.gateway.calls(), [], "nothing was reached");
}

/// A rollback command that fails must not abandon the rest: a later restore step may be the one
/// that puts the host back, and stopping at the first error leaves it half undone with nothing
/// said about why.
#[test]
fn a_failing_rollback_command_does_not_skip_the_rest_and_says_why() {
    // B comes up failed, and its first rollback command exits nonzero: the step must still
    // attempt the second one.
    let b = Arc::new(
        FakeRemoteShell::new()
            .with_host(host("b.example", "SHA256:b"))
            .with_probe_script(PROBE, [Health::Failed])
            .with_command_error(
                ROLLBACK,
                ShellError::Command {
                    command: ROLLBACK.to_string(),
                    status: 1,
                    stderr: "the previous artifact is gone".to_string(),
                },
            ),
    );
    let gateway = Arc::new(FakeRemoteShell::new().with_peer(Arc::clone(&b)));
    let harness = harness_for(
        Ports::default()
            .with_clock(Arc::new(FakeClock::new()) as Arc<dyn Clock>)
            .with_remote_shell(Arc::clone(&gateway) as Arc<dyn RemoteShell>),
    )
    .build()
    .expect("the composition is valid");

    let mut inputs = Inputs::new();
    inputs.insert("hosts".to_string(), Value::List(vec![host_input("b.example", "SHA256:b")]));
    inputs.insert("run".to_string(), Value::List(vec![command(DEPLOY)]));
    inputs.insert("health".to_string(), Value::from(PROBE));
    inputs.insert(
        "rollback".to_string(),
        Value::List(vec![command(ROLLBACK), command(ROLLBACK_TWO)]),
    );

    let error = drive(&harness, inputs, Arc::new(RecordingSink::new()) as Arc<dyn LogSink>)
        .expect_err("a failed host stops the deploy");
    let message = error.to_string();
    assert!(
        message.contains("rolled back 0 of 1 host(s)"),
        "the batch is reported as not restored: {message}"
    );
    assert!(
        message.contains("not fully rolled back") && message.contains(ROLLBACK),
        "the reason the restore failed is in the message: {message}"
    );
    assert!(
        message.contains("the previous artifact is gone"),
        "the host's own stderr is in the message: {message}"
    );

    // Both rollback commands were attempted: the failure did not skip the second.
    assert_eq!(
        programs(&b),
        [DEPLOY, ROLLBACK, ROLLBACK_TWO],
        "the remaining rollback command still ran"
    );
}

/// A host the rollback cannot even reach is named in the message rather than dropped: a batch
/// silently left half restored is the failure this step exists to avoid.
#[test]
fn a_host_the_rollback_cannot_reach_is_named_in_the_message() {
    // A comes up and is restored; B is in the same batch but nothing can reach it, so its
    // rollback attempt has no shell to run on.
    let a = Arc::new(
        FakeRemoteShell::new()
            .with_host(host("a.example", "SHA256:a"))
            .with_probe_script(PROBE, [Health::Healthy]),
    );
    let gateway = Arc::new(FakeRemoteShell::new().with_peer(Arc::clone(&a)));
    let harness = harness_for(
        Ports::default()
            .with_clock(Arc::new(FakeClock::new()) as Arc<dyn Clock>)
            .with_remote_shell(Arc::clone(&gateway) as Arc<dyn RemoteShell>),
    )
    .build()
    .expect("the composition is valid");

    let mut inputs = Inputs::new();
    inputs.insert(
        "hosts".to_string(),
        Value::List(vec![host_input("a.example", "SHA256:a"), host_input("b.example", "SHA256:b")]),
    );
    inputs.insert("health".to_string(), Value::from(PROBE));
    inputs.insert("batch".to_string(), Value::from("2"));
    inputs.insert("rollback".to_string(), Value::List(vec![command(ROLLBACK)]));

    let error = drive(&harness, inputs, Arc::new(RecordingSink::new()) as Arc<dyn LogSink>)
        .expect_err("an unreachable host stops the deploy");
    let message = error.to_string();
    assert!(
        message.contains("rolled back 1 of 2 host(s)"),
        "the reachable host was restored: {message}"
    );
    assert!(
        message.contains("not fully rolled back") && message.contains("b.example"),
        "the host that could not be restored is named, and why: {message}"
    );
}

#[test]
fn a_zero_or_nonsense_batch_is_refused_rather_than_deploying_nothing() {
    // A count of zero, a percent of zero, a negative, and two things that are neither.
    for asked in ["0", "0%", "-1", "half", "50 percent"] {
        let fleet = fleet();
        let mut inputs = fleet_inputs();
        inputs.insert("batch".to_string(), Value::from(asked));
        let error = run(&fleet, inputs).expect_err("a batch that deploys nothing is a bad input");
        match &error {
            StepError::InvalidInput { field, .. } => assert_eq!(field, "batch", "for {asked:?}"),
            other => panic!("an input error for {asked:?}, got {other:?}"),
        }
        assert_eq!(fleet.gateway.calls(), [], "nothing was reached for {asked:?}");
    }
}

#[test]
fn the_step_passes_the_conformance_kit() {
    let fleet = fleet();
    block_on(step_conformance(&fleet.harness, StepCase::new(NAME, fleet_inputs())));
}

/// The parity check, the same one `oci_image` runs: the checker and the executable must agree,
/// or a workflow the checker blesses may not run. The comparison runs against what
/// `Catalog::from_harness` derives from the [`StepKind`] itself — the mapping the harness applies
/// when a composition is built.
#[test]
fn the_catalog_entry_and_the_step_schema_are_the_same_contract() {
    let harness = fleet().harness;
    let from_harness = Catalog::from_harness(&harness).expect("the catalog builds");
    let step = from_harness.step(NAME).expect("built in");
    let catalog = Catalog::builtin();
    let builtin = catalog.step(NAME).expect("built in");
    assert_eq!(step.inputs, builtin.inputs, "the inputs drifted");
    assert_eq!(step.outputs, builtin.outputs, "the outputs drifted");
}

/// Every declared output is returned, and nothing else is — the engine refuses both directions,
/// so this asserts the names directly as well as through the run.
#[test]
fn the_outputs_are_exactly_what_the_schema_declares() {
    let fleet = fleet();
    let outputs = deploy(&fleet, fleet_inputs());
    // `Outputs` iterates sorted, so the comparison is on the names themselves rather than on the
    // order the step happened to insert them in.
    let mut declared: Vec<&str> =
        VmDeploy.schema().outputs.iter().map(|field| field.name).collect();
    declared.sort_unstable();
    let mut returned: Vec<&str> = outputs.keys().map(String::as_str).collect();
    returned.sort_unstable();
    assert_eq!(returned, declared);
    assert_eq!(returned, ["healthy", "summary", "total"]);
}
