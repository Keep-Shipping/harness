//! The built-in `vm.deploy` step: a rolling deploy across a fleet of hosts the harness does not
//! own ([#76](https://github.com/Keep-Shipping/harness/issues/76)).
//!
//! Three rules shape it:
//!
//! - **The fleet is validated before the network is touched.** Every host's address, port, user
//!   and — above all — its pinned host key is read and checked while nothing has been reached
//!   yet. A fleet with a bad pin in its last entry fails without having opened a connection to
//!   its first, which is the difference between a rejected workflow and a half-applied one.
//! - **A batch is the unit that is stopped or kept.** One host failing its health gate stops the
//!   deploy where it stands: later batches are never touched, and the failed batch is rolled back
//!   so the fleet is not left half-deployed. `max_failures` is the budget that says how far a
//!   deploy may carry on before that happens. A rollback that could not restore every host says so
//!   in the failure message, because a partial rollback nobody was told about is the same as none.
//! - **A health gate waits.** `health_timeout` is a duration the host has to come up in, spent
//!   waiting on the run's clock between probes — not a number of probes to fire back to back. A
//!   host that needs a minute to boot gets a minute.
//! - **A host key is pinned, never learned.** A [`Host`] with no `host_key` is an
//!   [`StepError::InvalidInput`], not a prompt: there is no "accept once", because the second
//!   connect is exactly the one an attacker would win. See the [`RemoteShell`] port's own
//!   documentation.
//! - **An artifact is shipped only behind the identity the workflow named.** When `verify:` names
//!   one, the digest under `image` is checked against it before any host is reached
//!   ([#113](https://github.com/Keep-Shipping/harness/issues/113)). A run that names no identity
//!   verifies nothing and behaves exactly as before; a run that asks and cannot be satisfied fails
//!   rather than skipping the check.
//!
//! The step reaches the fleet through [`RemoteShell`]: the configured host itself when the input
//! names it, and [`connect`](RemoteShell::connect) — each to its own pin — for the rest.

use std::sync::Arc;
use std::time::Duration;

use ks_core::ports::BoxFuture;
use ks_core::ports::clock::Clock;
use ks_core::ports::health::{Health, HealthReport};
use ks_core::ports::remote_shell::{Command, Host, HostKey, Probe, RemoteShell, ShellError};
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::step::{
    ActionClass, ActionKind, Field, Inputs, Outputs, Port, StepCtx, StepError, StepKind,
    StepSchema, TypeRef, Version,
};

use crate::deploy_verify;

/// The step's registered name; what a workflow writes as `deploy: vm.deploy`.
pub const NAME: &str = "vm.deploy";

/// The port a host is reached on when a host entry does not name one.
const DEFAULT_PORT: u16 = 22;
/// The host-key algorithm a host entry gets when it does not name one.
const DEFAULT_ALGORITHM: &str = "ssh-ed25519";
/// The user a host is deployed as when neither the entry nor `ssh_user` names one.
const DEFAULT_USER: &str = "deploy";
/// How long a `run` or `rollback` command may take when its entry does not say.
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a health gate waits by default.
const DEFAULT_HEALTH_TIMEOUT: Duration = Duration::from_secs(60);
/// How often a health gate polls. Fixed, so the poll count follows from the timeout.
const HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// The most probes one host gets however long a timeout asks for — five hours, which is a
/// mistake long before it is a deploy.
const MAX_PROBES: usize = 3_600;

/// Deploys to a fleet of hosts over the [`RemoteShell`] port, one batch at a time.
#[derive(Debug, Default)]
pub struct VmDeploy;

impl StepKind for VmDeploy {
    fn name(&self) -> &'static str {
        NAME
    }

    fn version(&self) -> Version {
        Version::new(1, 1, 0)
    }

    fn schema(&self) -> StepSchema {
        let list = TypeRef::Builtin(ValueType::List);
        let text = TypeRef::Builtin(ValueType::String);
        let int = TypeRef::Named("int");
        StepSchema {
            doc: "Deploys to a fleet of hosts over SSH, one batch at a time, and reports how \
                  many came up.",
            inputs: vec![
                // `host_key` is required on every entry and the step refuses a host without one.
                // That is the whole point of the port: a key that is learned on first use is a
                // key that was never checked, and the connect after that is the one an attacker
                // wins. The doc says so where an operator reads it.
                Field::new(
                    "hosts",
                    list,
                    "the fleet: `address` and `host_key` are required on every entry, and a host \
                     with no pinned `host_key` is refused rather than trusted on first use. Each \
                     entry also takes `port` (22), `user` (`ssh_user`), and `host_key_algorithm` \
                     (`ssh-ed25519`)",
                ),
                // One type, two spellings: a count (`\"2\"`) or a percent of the fleet
                // (`\"50%\"`). The engine types an input, so both are strings and `run` parses
                // either.
                Field::new(
                    "batch",
                    text,
                    "how many hosts per batch: a count, or a percent of the fleet such as \
                     `\"25%\"`. A percent rounds up and is never zero",
                )
                .with_default(Value::from("1")),
                Field::new(
                    "run",
                    list,
                    "commands to run on each host as it is deployed, in order, as \
                     `{ program, args, timeout }`. The argv is typed, never a shell string",
                )
                .optional(),
                Field::new(
                    "health",
                    text,
                    "a probe command to run on each host after its commands; the deploy waits for \
                     it to report healthy. Without one there is no health gate",
                )
                .optional(),
                Field::new(
                    "health_timeout",
                    int,
                    "how long the health gate polls a host before calling it failed",
                )
                .with_default(Value::from(DEFAULT_HEALTH_TIMEOUT.as_secs() as f64)),
                Field::new(
                    "max_failures",
                    int,
                    "how many hosts may fail health before the deploy stops and rolls back",
                )
                .with_default(Value::from(0.0)),
                Field::new(
                    "rollback",
                    list,
                    "commands that restore a host's previous artifact, in the same `{ program, \
                     args, timeout }` shape as `run`, run on every host of a failed batch",
                )
                .optional(),
                Field::new(
                    "ssh_user",
                    text,
                    "the user to deploy as, for the hosts that do not name one",
                )
                .with_default(Value::from(DEFAULT_USER)),
                Field::new(
                    "image",
                    text,
                    "the digest-pinned artifact the deploy ships, as `repository@sha256:…`; \
                     verification checks the signature on this digest",
                )
                .optional(),
                Field::new(
                    "verify",
                    text,
                    "the identity `image` must be signed by, as `signed-by <identity>`: `signed-by \
                     key:release-key`, or `signed-by \
                     https://token.actions.githubusercontent.com from \
                     https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main`. \
                     An empty value verifies nothing",
                )
                .with_default(Value::from("")),
            ],
            outputs: vec![
                Field::new("healthy", int, "the hosts that reached health"),
                Field::new("total", int, "the hosts in the fleet"),
                Field::new(
                    "summary",
                    text,
                    "the fleet in one line, as `{healthy}/{total} hosts \
                                             healthy`",
                ),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::RemoteShell]
    }

    /// Optional, because `optional()` is static and `verify:` is not: the
    /// registry and the signer are only ever *used* when a run names an
    /// identity in `verify:`, and `HarnessBuilder::build` never checks this
    /// list. Listing them here says "a composition that has neither still
    /// builds", which is what keeps a deploy with no `verify:` working exactly
    /// as before. A run that asks for verification and has neither port fails
    /// loudly instead of skipping the check — see [`crate::deploy_verify`].
    fn optional(&self) -> &'static [Port] {
        &[Port::Registry, Port::Signer]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Deploy)
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let shell = ctx.ports().remote_shell().cloned().ok_or_else(|| StepError::Port {
                port: Port::RemoteShell,
                message: "no remote shell was provided".to_string(),
            })?;

            // The whole fleet is read, pinned and refused here, before a single connection is
            // opened: a bad pin at the end of the list must not be found after the first host has
            // already been changed.
            let fleet = fleet_of(&inputs, &default_user(&inputs))?;
            let batch_size = batch_of(&inputs, fleet.len())?;
            let deploy = commands_of(&inputs, "run")?;
            let restore = commands_of(&inputs, "rollback")?;
            let probe = probe_of(&inputs)?;
            let budget = probe_budget(&inputs)?;
            let max_failures = whole(&inputs, "max_failures")?;

            // Before a single host is reached, on the same footing as the fleet's pins: an
            // artifact nobody signed as the identity the workflow named must stop the deploy
            // while every host is still exactly as it was.
            deploy_verify::verify_deploy(
                &ctx,
                &inputs,
                &deploy_verify::images_of(&inputs, "image"),
            )
            .await?;

            let batches = fleet.len().div_ceil(batch_size);
            let fleet_text = fleet.len().to_string();
            let batch_text = batch_size.to_string();
            // Host addresses and counts, never command output: a log line is somewhere a value
            // the step was handed ends up.
            ctx.log().info(
                &format!("deploying to {fleet_text} hosts"),
                &[("hosts", &fleet_text), ("batch", &batch_text)],
            );

            let mut healthy = 0usize;
            let mut failures = 0usize;
            for (at, batch) in fleet.chunks(batch_size).enumerate() {
                // A fleet deploy is long; the run's own cancellation is checked between batches
                // and again between hosts, or a cancelled run keeps changing hosts.
                if ctx.cancel().is_cancelled() {
                    return Err(StepError::Cancelled);
                }
                let batch_number = at + 1;
                let number = batch_number.to_string();
                let count = batch.len().to_string();
                ctx.log()
                    .info(&format!("batch {number}"), &[("batch", &number), ("hosts", &count)]);

                let mut failed: Vec<(&Host, String)> = Vec::new();
                for host in batch {
                    if ctx.cancel().is_cancelled() {
                        return Err(StepError::Cancelled);
                    }
                    match deploy_host(
                        ctx.clock().as_ref(),
                        &shell,
                        host,
                        &deploy,
                        probe.as_ref(),
                        budget,
                    )
                    .await
                    {
                        Ok(()) => {
                            healthy += 1;
                            ctx.log().info(
                                &format!("deployed {}", host.address()),
                                &[("host", host.address()), ("health", Health::Healthy.as_str())],
                            );
                        }
                        Err(reason) => {
                            failures += 1;
                            failed.push((host, reason.clone()));
                            ctx.log().info(
                                &format!("{} did not come up", host.address()),
                                &[("host", host.address()), ("reason", &reason)],
                            );
                        }
                    }
                }

                // The budget is the rule; `max_failures: 0` is the "any failure stops" case.
                if failures > max_failures {
                    let stop =
                        Stoppage { batch: batch_number, batches, failures, budget: max_failures };
                    return Err(stopped(&shell, batch, &failed, &restore, stop).await);
                }
            }

            let total = fleet.len();
            let summary = format!("{healthy}/{total} hosts healthy");
            // The step has no summary channel of its own, so the one it declares is also logged:
            // a run log that could not say what the deploy did is a run log nobody reads.
            ctx.log().info(&summary, &[]);
            let mut outputs = Outputs::new();
            outputs.insert("healthy".to_string(), Value::from(healthy as f64));
            outputs.insert("total".to_string(), Value::from(total as f64));
            outputs.insert("summary".to_string(), Value::from(summary));
            Ok(outputs)
        })
    }
}

/// A shell for `host`, opened to the pin the fleet named: the configured one when the input names
/// the host it was configured for, and [`RemoteShell::connect`] for the rest — then checked
/// against that pin before anything is run on it.
///
/// The check is here rather than left to the adapter because the pin has to be load-bearing on
/// every path, not only the ones that happen to run a command: a deploy with no `run` list and no
/// probe still reaches its host, and a host that was never verified is not a host that was
/// deployed to. The `Err` is the mismatch, naming the expected and the presented fingerprint.
async fn pinned_for(
    shell: &Arc<dyn RemoteShell>,
    host: &Host,
) -> Result<Arc<dyn RemoteShell>, String> {
    let target = match shell_for(shell, host).await {
        Ok(target) => target,
        Err(error) => return Err(error.to_string()),
    };
    let pinned = host.host_key();
    let presented = target.host().host_key();
    if presented != pinned {
        return Err(format!(
            "host key mismatch: the step pins {} ({}), the host presented {} ({}); verify the \
             host before re-pinning",
            pinned.fingerprint(),
            pinned.algorithm(),
            presented.fingerprint(),
            presented.algorithm()
        ));
    }
    Ok(target)
}

/// A shell for `host`: the configured one when the input names the host it was configured for,
/// and [`RemoteShell::connect`] for the rest of the fleet — each to its own pinned key.
async fn shell_for(
    shell: &Arc<dyn RemoteShell>,
    host: &Host,
) -> Result<Arc<dyn RemoteShell>, ShellError> {
    if shell.host() == host {
        return Ok(Arc::clone(shell));
    }
    shell.connect(host).await
}

/// Runs one host's commands, then waits for it to be healthy. The `Err` is the reason a human
/// reads: what the host said, or what it never said.
async fn deploy_host(
    clock: &dyn Clock,
    shell: &Arc<dyn RemoteShell>,
    host: &Host,
    deploy: &[Command],
    probe: Option<&Probe>,
    budget: usize,
) -> Result<(), String> {
    let target = pinned_for(shell, host).await?;
    for command in deploy {
        target.run(command).await.map_err(|error| format!("{}: {error}", command.program()))?;
    }
    // Without a probe there is nothing to wait for, and a host that ran its commands to the pin
    // it was named with is as healthy as this step is able to tell.
    let Some(probe) = probe else { return Ok(()) };
    wait_healthy(clock, target.as_ref(), probe, budget).await
}

/// Polls `probe` until it reports healthy, it settles failed, or the budget runs out.
///
/// The wait is real: between two probes the run's clock sleeps
/// [`HEALTH_POLL_INTERVAL`], so `health_timeout` bounds the *duration* a host has to come up
/// rather than the number of times it was asked. A host that genuinely needs a minute to boot is
/// given a minute; one that spins 720 probes in a millisecond is not a health gate at all. The
/// budget still bounds the loop, so an adapter that never settles fails the host rather than
/// hanging the run.
async fn wait_healthy(
    clock: &dyn Clock,
    shell: &dyn RemoteShell,
    probe: &Probe,
    budget: usize,
) -> Result<(), String> {
    for attempt in 0..budget {
        let report = shell.probe(probe).await.map_err(|error| error.to_string())?;
        if report.satisfies(Health::Healthy) {
            return Ok(());
        }
        // Settled failed is an answer, not a wait: the host will not come up on its own.
        if matches!(report.state(), Health::Failed) {
            return Err(describe(&report));
        }
        // Nothing left to wait for between this probe and the answer the budget already spent.
        if attempt + 1 < budget {
            clock.sleep(HEALTH_POLL_INTERVAL).await;
        }
    }
    Err(format!("the probe did not report healthy after {budget} tries"))
}

/// A failed health report in one line, with the adapter's own reason when it gave one.
fn describe(report: &HealthReport) -> String {
    match report.reason() {
        Some(reason) => format!("the probe reported {}: {reason}", report.state()),
        None => format!("the probe reported {}", report.state()),
    }
}

/// Where a deploy stopped: which batch, of how many, and how the tally stood when it did. One
/// struct rather than four numbers, so a reader of [`stopped`] sees the tally as a tally.
struct Stoppage {
    /// The one-based index of the batch that stopped the deploy.
    batch: usize,
    /// How many batches the fleet was split into.
    batches: usize,
    /// How many hosts had failed by then.
    failures: usize,
    /// The `max_failures` budget.
    budget: usize,
}

/// Stops the deploy, rolls the failed batch back, and says why in one message.
///
/// Every host in the failed batch is rolled back, not only the ones that failed: a batch is what
/// was applied together, and a fleet left with half a batch on the new artifact and half on the
/// old one is a fleet nobody planned. The step returns `Err`, so the rollback is reported in the
/// message and in the run log rather than in an output.
async fn stopped(
    shell: &Arc<dyn RemoteShell>,
    batch: &[Host],
    failed: &[(&Host, String)],
    restore: &[Command],
    stop: Stoppage,
) -> StepError {
    // The host's own words, not ours: "the probe reported failed: exit 1" tells an operator more
    // than "b.example did not come up", and the shell errors the port raises carry what an
    // adapter already scrubbed.
    let reasons = failed
        .iter()
        .map(|(host, reason)| format!("{}: {reason}", host.address()))
        .collect::<Vec<_>>()
        .join(", ");
    let (rolled_back, problems) = rollback(shell, batch, restore).await;
    let mut detail = if restore.is_empty() {
        // Saying this is the difference between "we undid it" and "there was nothing to undo".
        "no rollback commands were given, so the batch is left as deployed".to_string()
    } else {
        format!("rolled back {rolled_back} of {} host(s) in the batch", batch.len())
    };
    // A partial rollback is only visible if it is said out loud: the count alone says a host was
    // left as deployed without saying which one, or why.
    if !problems.is_empty() {
        detail.push_str(&format!("; not fully rolled back: {}", problems.join(", ")));
    }
    let addresses =
        batch.iter().map(|host| host.address().to_string()).collect::<Vec<_>>().join(", ");
    StepError::Failed(format!(
        "batch {} of {} stopped the deploy: {reasons}; {} host(s) failed in that batch, {} \
         across the fleet, over the max_failures budget of {}; {detail}; hosts: {addresses}",
        stop.batch,
        stop.batches,
        failed.len(),
        stop.failures,
        stop.budget
    ))
}

/// Runs the rollback commands on every host of the failed batch, and reports how many hosts took
/// all of them — plus what stopped the rest.
///
/// A host that cannot be reached, or whose key does not match the pin, is a reason rather than a
/// silent skip: the operator is told the batch was left as deployed and why. So is a host whose
/// commands failed — and that host still receives its remaining commands, because a later restore
/// step may be the one that matters and abandoning the rest leaves it half undone.
async fn rollback(
    shell: &Arc<dyn RemoteShell>,
    batch: &[Host],
    restore: &[Command],
) -> (usize, Vec<String>) {
    let mut rolled = 0;
    let mut problems: Vec<String> = Vec::new();
    for host in batch {
        let target = match pinned_for(shell, host).await {
            Ok(target) => target,
            Err(reason) => {
                problems.push(reason);
                continue;
            }
        };
        // The first failure is the one reported; the rest are still attempted, because a later
        // restore step may still put this host back and one failure must not abandon it.
        let mut first_failure: Option<String> = None;
        for command in restore {
            if let Err(error) = target.run(command).await {
                let reason = format!("{}: {error}", command.program());
                if first_failure.is_none() {
                    first_failure = Some(reason);
                }
            }
        }
        match first_failure {
            Some(reason) => problems.push(format!("{}: {reason}", host.address())),
            None => rolled += 1,
        }
    }
    (rolled, problems)
}

/// The fleet the input names, as pinned [`Host`]s. Every entry is checked here, so nothing below
/// this point has to wonder whether a host was well formed.
fn fleet_of(inputs: &Inputs, default_user: &str) -> Result<Vec<Host>, StepError> {
    let entries = match inputs.get("hosts") {
        Some(Value::List(entries)) => entries,
        _ => {
            return Err(StepError::InvalidInput {
                field: "hosts".to_string(),
                reason: "it must be a list of hosts".to_string(),
            });
        }
    };
    if entries.is_empty() {
        return Err(StepError::InvalidInput {
            field: "hosts".to_string(),
            reason: "a deploy with no hosts deploys nothing; name at least one".to_string(),
        });
    }
    entries.iter().enumerate().map(|(at, entry)| host_of(entry, default_user, at)).collect()
}

/// One host entry, as a pinned [`Host`]. The pin is required: an entry that names no `host_key`
/// would send the adapter to connect and believe whatever answered.
fn host_of(entry: &Value, default_user: &str, at: usize) -> Result<Host, StepError> {
    let fields = match entry {
        Value::Map(fields) => fields,
        other => {
            return Err(StepError::InvalidInput {
                field: "hosts".to_string(),
                reason: format!("host {at} is a {}, not a host map", other.value_type()),
            });
        }
    };
    let where_ = |problem: &str| StepError::InvalidInput {
        field: "hosts".to_string(),
        reason: format!("host {at}: {problem}"),
    };
    let address = string_of(fields, "address");
    if address.trim().is_empty() {
        return Err(where_("it names no `address`"));
    }
    let where_ = |problem: &str| StepError::InvalidInput {
        field: "hosts".to_string(),
        reason: format!("{address}: {problem}"),
    };
    let fingerprint = string_of(fields, "host_key");
    if fingerprint.trim().is_empty() {
        return Err(where_(
            "it pins no `host_key`. A host key is never accepted on first use and there is no \
             `accept once`: pin the fingerprint the host presents, and re-pin deliberately if \
             the host was rebuilt",
        ));
    }
    let algorithm = match string_of(fields, "host_key_algorithm") {
        "" => DEFAULT_ALGORITHM.to_string(),
        named => named.to_string(),
    };
    let key = HostKey::new(algorithm, fingerprint).map_err(|error| where_(&error.to_string()))?;
    let port = match fields.get("port") {
        None | Some(Value::Null) => DEFAULT_PORT,
        Some(Value::Number(port)) => u16::try_from(*port as u32)
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| where_(&format!("`port` is not a port: {port}")))?,
        Some(other) => return Err(where_(&format!("`port` is a {}", other.value_type()))),
    };
    let user = match string_of(fields, "user") {
        "" => default_user.to_string(),
        named => named.to_string(),
    };
    Host::new(address, port, user, key).map_err(|error| where_(&error.to_string()))
}

/// How many hosts go in one batch: a count, or a percent of the fleet that rounds up.
///
/// A percent never rounds to zero — a batch of no hosts deploys nothing while looking like a
/// deploy — and a count of zero is a mistake worth naming rather than a no-op worth hiding.
fn batch_of(inputs: &Inputs, total: usize) -> Result<usize, StepError> {
    let asked = text(inputs, "batch").trim();
    if asked.is_empty() {
        return Ok(1);
    }
    let invalid = |reason: String| StepError::InvalidInput { field: "batch".to_string(), reason };
    if let Some(percent) = asked.strip_suffix('%') {
        let percent: f64 = percent
            .trim()
            .parse()
            .map_err(|_| invalid(format!("`{asked}` is not a percent of the fleet")))?;
        if !(percent.is_finite() && percent > 0.0) {
            return Err(invalid(format!("`{asked}` is not a positive percent")));
        }
        let hosts = (total as f64 * percent / 100.0).ceil().max(1.0);
        return Ok((hosts as usize).clamp(1, total));
    }
    let hosts: usize = asked
        .parse()
        .map_err(|_| invalid(format!("`{asked}` is neither a host count nor a percent")))?;
    if hosts == 0 {
        return Err(invalid(
            "a batch of zero hosts deploys nothing; give it at least one".to_string(),
        ));
    }
    Ok(hosts.min(total))
}

/// The probe the input names, if any. An empty `health` is no probe rather than an empty command:
/// [`Probe::new`] refuses one, and a waiter polling a question nobody asked is the bug the port
/// guards against.
fn probe_of(inputs: &Inputs) -> Result<Option<Probe>, StepError> {
    match text(inputs, "health").trim() {
        "" => Ok(None),
        command => Probe::new(command).map(Some).map_err(|error| StepError::InvalidInput {
            field: "health".to_string(),
            reason: error.to_string(),
        }),
    }
}

/// How many times the health gate probes a host: `health_timeout` over the poll interval, at
/// least once, so a probe is never declared impossible before it has run.
///
/// A negative timeout is refused rather than clamped, the same way `max_failures` is: a negative
/// budget is a mistake in the workflow, and quietly turning one into a single probe would report
/// a timeout the operator never asked for.
fn probe_budget(inputs: &Inputs) -> Result<usize, StepError> {
    let seconds = seconds_of(inputs, "health_timeout");
    if seconds < 0.0 {
        return Err(StepError::InvalidInput {
            field: "health_timeout".to_string(),
            reason: "it must not be negative".to_string(),
        });
    }
    let polls = (seconds / HEALTH_POLL_INTERVAL.as_secs() as f64).ceil();
    // Clamped rather than merely converted: a timeout of a million seconds is a typo, and
    // turning it into a million probes would turn the typo into a run nobody can stop.
    Ok(polls.clamp(1.0, MAX_PROBES as f64) as usize)
}

/// The commands under `name`, each as a typed argv with its own deadline.
fn commands_of(inputs: &Inputs, name: &'static str) -> Result<Vec<Command>, StepError> {
    match inputs.get(name) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::List(entries)) => {
            entries.iter().enumerate().map(|(at, entry)| command_of(entry, name, at)).collect()
        }
        Some(other) => Err(StepError::InvalidInput {
            field: name.to_string(),
            reason: format!("it must be a list of commands, found a {}", other.value_type()),
        }),
    }
}

/// One `{ program, args, timeout }` entry. The arguments stay separate from the program, so a
/// value that happens to contain a space or a quote is one argument and never a second command.
fn command_of(entry: &Value, name: &'static str, at: usize) -> Result<Command, StepError> {
    let invalid = |reason: String| StepError::InvalidInput {
        field: name.to_string(),
        reason: format!("command {at}: {reason}"),
    };
    let fields = match entry {
        Value::Map(fields) => fields,
        other => return Err(invalid(format!("it is a {}, not a command map", other.value_type()))),
    };
    let program = string_of(fields, "program");
    if program.trim().is_empty() {
        return Err(invalid("it names no `program`".to_string()));
    }
    let args = match fields.get("args") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::List(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => Ok(text.clone()),
                other => {
                    Err(invalid(format!("`args` holds a {}, not a string", other.value_type())))
                }
            })
            .collect::<Result<Vec<String>, StepError>>()?,
        Some(other) => {
            return Err(invalid(format!("`args` is a {}, not a list", other.value_type())));
        }
    };
    let timeout = match fields.get("timeout") {
        None | Some(Value::Null) => DEFAULT_COMMAND_TIMEOUT,
        Some(Value::Number(seconds)) if *seconds > 0.0 => Duration::from_secs(*seconds as u64),
        Some(_) => return Err(invalid("`timeout` must be a positive number of seconds".into())),
    };
    Command::new(program, args, timeout).map_err(|error| invalid(error.to_string()))
}

/// The user a host that names none is deployed as.
fn default_user(inputs: &Inputs) -> String {
    let named = text(inputs, "ssh_user").trim();
    if named.is_empty() { DEFAULT_USER.to_string() } else { named.to_string() }
}

/// The whole number under `name`, or `0`.
fn whole(inputs: &Inputs, name: &str) -> Result<usize, StepError> {
    let seconds = seconds_of(inputs, name);
    if seconds < 0.0 {
        return Err(StepError::InvalidInput {
            field: name.to_string(),
            reason: "it must not be negative".to_string(),
        });
    }
    Ok(seconds as usize)
}

/// The number under `name`, or `0`.
fn seconds_of(inputs: &Inputs, name: &str) -> f64 {
    match inputs.get(name) {
        Some(Value::Number(number)) => *number,
        _ => 0.0,
    }
}

/// The `&str` input under `name`; inputs arrive prepared, so a wrong type never reaches a step.
fn text<'a>(inputs: &'a Inputs, name: &str) -> &'a str {
    match inputs.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

/// The string under `name` in a host or command map; absent and wrongly typed read alike, and
/// what is missing is a bad input the caller names rather than a value guessed at.
fn string_of<'a>(fields: &'a std::collections::BTreeMap<String, Value>, name: &str) -> &'a str {
    match fields.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}
