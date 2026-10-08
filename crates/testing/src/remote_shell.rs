//! Fake for the [`RemoteShell`] port: scripted command results and errors, a
//! probe script that walks a host through a health transition, and an enforced
//! pinned-host-key rule. Never opens a socket.
//!
//! The single filesystem access in this module is the one existence check
//! [`RemoteShell::copy`] makes on its local source path; it writes nothing and
//! reads no other path.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ks_core::ports::BoxFuture;
use ks_core::ports::health::{Health, HealthReport};
use ks_core::ports::remote_shell::{
    Command, CommandResult, Copied, Host, HostKey, Probe, RemoteShell, ShellError,
};

/// The address a fresh [`FakeRemoteShell`] reports.
pub const DEFAULT_ADDRESS: &str = "appliance.fake.invalid";
/// The port a fresh [`FakeRemoteShell`] reports.
pub const DEFAULT_PORT: u16 = 2222;
/// The user a fresh [`FakeRemoteShell`] reports.
pub const DEFAULT_USER: &str = "deploy";
/// The host-key algorithm a fresh [`FakeRemoteShell`] pins.
pub const DEFAULT_ALGORITHM: &str = "ssh-ed25519";
/// The fingerprint a fresh [`FakeRemoteShell`] pins.
pub const DEFAULT_FINGERPRINT: &str = "SHA256:fake0000000000000000000000000000000000";

/// The program the fake ships as succeeding: the conformance kit runs it, and
/// a probe of it is [`Health::Healthy`], because it exits zero.
pub const OK_PROGRAM: &str = "true";
/// The program the fake ships as failing: the conformance kit runs it, and it
/// is [`ShellError::Command`] with a nonzero status, never an `Ok`.
pub const FAILING_PROGRAM: &str = "false";
/// The probe command no host can answer: the conformance kit probes it to
/// check that an adapter says it does not know rather than guessing healthy.
pub const UNANSWERABLE_PROBE: &str = "ks-conformance-nothing-answers-this";
/// The bytes a fresh [`FakeRemoteShell`] reports for every copy.
pub const DEFAULT_COPY_BYTES: u64 = 4096;
/// The address the conformance kit asks [`RemoteShell::connect`] for: in the
/// `.invalid` TLD, which [RFC 2606] reserves and which therefore never
/// resolves, so no adapter can reach it.
///
/// [RFC 2606]: https://www.rfc-editor.org/rfc/rfc2606
const UNREACHABLE_ADDRESS: &str = "ks-conformance-unreachable.invalid";
/// The fingerprint a rejected host is reported as having presented: the fake
/// stands in for a host that was rebuilt, or for a MITM.
pub const REBUILT_HOST_KEY: &str = "SHA256:0000000000000000000000000000000000";

/// The status the fake gives [`FAILING_PROGRAM`]: nonzero, as the port
/// requires for a failed command.
const FAILING_STATUS: i32 = 1;

/// Why the fake reports [`Health::NoData`] for a probe it has nothing scripted
/// for: it cannot tell healthy from unknown, and must say so.
const NO_ANSWER: &str = "the probe ran but produced nothing this port can interpret";

/// One call a test can observe on the [`FakeRemoteShell`], oldest first via
/// [`FakeRemoteShell::calls`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellCall {
    /// [`RemoteShell::run`] was asked to run this program.
    Run {
        /// The program that was run.
        program: String,
    },
    /// [`RemoteShell::copy`] was asked to fetch this destination.
    Copy {
        /// The remote destination path.
        to: String,
    },
    /// [`RemoteShell::probe`] ran this probe command line.
    Probe {
        /// The probe command line.
        command: String,
    },
    /// [`RemoteShell::connect`] was asked for this address.
    Connect {
        /// The address of the host that was asked for.
        address: String,
    },
}

/// The fake's mutable state; every accessor goes through one mutex, so the
/// fake is `Send + Sync`.
#[derive(Default)]
struct State {
    /// Program -> what running it produces.
    results: BTreeMap<String, CommandResult>,
    /// Program -> the error running it produces.
    errors: BTreeMap<String, ShellError>,
    /// Probe command -> its health script; the last entry repeats.
    probe_scripts: BTreeMap<String, VecDeque<HealthReport>>,
    /// Probe command -> how far through its script the fake has walked.
    cursors: BTreeMap<String, usize>,
    /// Fingerprints the fake refuses to connect to.
    rejected: Vec<String>,
    /// The hosts [`connect`](RemoteShell::connect) can reach, each its own
    /// fake so a test can inspect what was done on that host.
    peers: Vec<Arc<FakeRemoteShell>>,
    /// Every call, oldest first.
    calls: Vec<ShellCall>,
}

/// A [`RemoteShell`] you script per test — the stand-in for real SSH
/// adapters ([#52](https://github.com/Keep-Shipping/harness/issues/52)).
///
/// Nothing is installed on the remote host and nothing is forwarded: the fake
/// answers from tables it was handed, so a test can prove the port's two
/// load-bearing rules without a machine anywhere.
///
/// - **Pinned host keys.** Every `run`, `copy` and `probe` checks
///   [`RemoteShell::host`]'s [`HostKey`] first. If the fake was told to reject
///   that fingerprint — [`with_rejected_host_key`](FakeRemoteShell::with_rejected_host_key),
///   standing in for a host that was rebuilt or a MITM — the call fails with
///   [`ShellError::HostKeyMismatch`] and nothing else runs.
/// - **Scripted health transitions.** [`with_probe_script`](FakeRemoteShell::with_probe_script)
///   queues the reports [`RemoteShell::probe`] answers with, one per call,
///   holding at the last, so a `wait` can be watched polling out of
///   [`Health::Progressing`] into [`Health::Healthy`]. A probe with no script
///   answers [`Health::NoData`]: the probe produced nothing the port can
///   interpret, and silence is not health.
/// - **A fleet.** [`with_host`](FakeRemoteShell::with_host) makes a fake stand
///   for a named host with its own pin, and
///   [`with_peer`](FakeRemoteShell::with_peer) registers it as somewhere
///   [`RemoteShell::connect`] can reach. An address with no peer is
///   [`ShellError::Unreachable`], so a step that walks past the fleet it was
///   given fails instead of reaching a host nobody described.
///
/// ```
/// use std::time::Duration;
/// use ks_core::ports::health::Health;
/// use ks_core::ports::remote_shell::{Command, Probe, RemoteShell};
/// use ks_testing::{block_on, remote_shell::FakeRemoteShell};
///
/// let healthz = "curl -fsS localhost:8080/healthz";
/// let shell = FakeRemoteShell::new().with_probe_script(healthz, [Health::Progressing, Health::Healthy]);
///
/// // A probe the fake knows nothing about is silence, not health.
/// let unknown = Probe::new("whatever-nothing-answers").expect("non-empty probe");
/// let quiet = block_on(shell.probe(&unknown)).expect("a report, not an error");
/// assert_eq!(quiet.state(), Health::NoData);
/// assert!(!quiet.satisfies(Health::Healthy));
///
/// // A scripted probe walks its transition, then holds.
/// let probe = Probe::new(healthz).expect("non-empty probe");
/// let first = block_on(shell.probe(&probe)).expect("a report");
/// assert_eq!(first.state(), Health::Progressing);
/// let second = block_on(shell.probe(&probe)).expect("a report");
/// assert_eq!(second.state(), Health::Healthy);
/// assert!(second.satisfies(Health::Healthy));
/// assert_eq!(second.reason(), None);
///
/// // And a command the fake knows exits zero succeeds.
/// let command = Command::new("true", vec![], Duration::from_secs(5)).expect("a deadline");
/// block_on(shell.run(&command)).expect("the command is scripted");
/// ```
///
/// # What the fake touches, and what it records
///
/// The only filesystem access anywhere in this fake is the **one existence
/// check** [`RemoteShell::copy`] makes: a local path that is not there never
/// reaches the host, so a copy of it fails rather than reporting a short
/// [`Copied`]. That check reads the filesystem and writes nothing. Everything
/// else is answered from tables, so no socket is opened, no process is
/// spawned, and no other path is read.
///
/// [`calls`](FakeRemoteShell::calls) records every call **made against the
/// host** — `run`, `copy` and `probe`. [`RemoteShell::host`] is not in the
/// record: it reads the adapter's own configured identity, not the target, so
/// no call was made anywhere. [`connect`](RemoteShell::connect) is: it names a
/// host somewhere else, so the address a step asked for is worth showing. The
/// [`FakeCluster`] fake applies the same rule to
/// [`Cluster::handle`], while the [`FakeFunctionHost`] records its own sync
/// read, [`FunctionHost::pin_is_detectable`], because that read decides whether
/// a smoke check may be believed at all.
///
/// [`FakeCluster`]: crate::cluster::FakeCluster
/// [`Cluster::handle`]: ks_core::ports::cluster::Cluster::handle
/// [`FakeFunctionHost`]: crate::function_host::FakeFunctionHost
/// [`FunctionHost::pin_is_detectable`]: ks_core::ports::function_host::FunctionHost::pin_is_detectable
///
/// All mutable state sits behind one mutex, so the fake is `Send + Sync`.
pub struct FakeRemoteShell {
    host: Host,
    copy_bytes: u64,
    state: Mutex<State>,
}

impl Default for FakeRemoteShell {
    /// The default fake connects to [`DEFAULT_ADDRESS`]:[`DEFAULT_PORT`] as
    /// [`DEFAULT_USER`], pins [`DEFAULT_FINGERPRINT`], runs [`OK_PROGRAM`]
    /// successfully and [`FAILING_PROGRAM`] with a nonzero status, answers any
    /// other command with empty output, copies
    /// [`DEFAULT_COPY_BYTES`] bytes, and reports [`Health::NoData`] for every
    /// probe.
    fn default() -> FakeRemoteShell {
        let host_key = HostKey::new(DEFAULT_ALGORITHM, DEFAULT_FINGERPRINT)
            .expect("the default host key is well formed");
        let host = Host::new(DEFAULT_ADDRESS, DEFAULT_PORT, DEFAULT_USER, host_key)
            .expect("the default host is well formed");
        FakeRemoteShell {
            host,
            copy_bytes: DEFAULT_COPY_BYTES,
            state: Mutex::new(State {
                results: BTreeMap::from([(
                    OK_PROGRAM.to_string(),
                    CommandResult::new(format!("{OK_PROGRAM}\n"), ""),
                )]),
                errors: BTreeMap::from([(
                    FAILING_PROGRAM.to_string(),
                    ShellError::Command {
                        command: FAILING_PROGRAM.to_string(),
                        status: FAILING_STATUS,
                        stderr: String::new(),
                    },
                )]),
                // A probe of the program that exits zero is healthy: that is
                // the port's definition, and the one the conformance kit
                // relies on.
                probe_scripts: BTreeMap::from([(
                    OK_PROGRAM.to_string(),
                    VecDeque::from([HealthReport::new(Health::Healthy)]),
                )]),
                ..State::default()
            }),
        }
    }
}

impl FakeRemoteShell {
    /// Creates a fake with the default host, commands and probe answers.
    pub fn new() -> FakeRemoteShell {
        FakeRemoteShell::default()
    }

    /// Runs `program` by producing `result`, replacing any scripted error.
    pub fn with_command_result(
        self,
        program: impl Into<String>,
        result: CommandResult,
    ) -> FakeRemoteShell {
        let program = program.into();
        {
            let mut state = self.state.lock().expect("fake remote shell state");
            state.results.insert(program.clone(), result);
            state.errors.remove(&program);
        }
        self
    }

    /// Runs `program` by failing with `error`, replacing any scripted result.
    pub fn with_command_error(
        self,
        program: impl Into<String>,
        error: ShellError,
    ) -> FakeRemoteShell {
        let program = program.into();
        {
            let mut state = self.state.lock().expect("fake remote shell state");
            state.results.remove(&program);
            state.errors.insert(program, error);
        }
        self
    }

    /// Queues the states [`RemoteShell::probe`] answers with for `probe`, one
    /// per call; the last repeats, so a `wait` that polls past the script holds
    /// rather than falling off the end. Installing a script rewinds `probe`'s
    /// cursor, so a fresh transition replays from its first state.
    pub fn with_probe_script(
        self,
        probe: &str,
        states: impl IntoIterator<Item = Health>,
    ) -> FakeRemoteShell {
        let states: VecDeque<HealthReport> = states.into_iter().map(HealthReport::new).collect();
        {
            let mut state = self.state.lock().expect("fake remote shell state");
            state.probe_scripts.insert(probe.to_string(), states);
            state.cursors.remove(probe);
        }
        self
    }

    /// Every [`RemoteShell::copy`] reports `bytes` moved.
    pub fn with_copy_bytes(mut self, bytes: u64) -> FakeRemoteShell {
        self.copy_bytes = bytes;
        self
    }

    /// Refuses to connect to a host pinning `fingerprint`, so every `run`,
    /// `copy` and `probe` fails with [`ShellError::HostKeyMismatch`] naming
    /// the pinned fingerprint it was expecting and
    /// [`REBUILT_HOST_KEY`] as what the host actually presented.
    pub fn with_rejected_host_key(self, fingerprint: impl Into<String>) -> FakeRemoteShell {
        self.state.lock().expect("fake remote shell state").rejected.push(fingerprint.into());
        self
    }

    /// Makes this fake stand in for `host` instead of
    /// [`DEFAULT_ADDRESS`]:[`DEFAULT_PORT`]. A fleet fake uses it to give
    /// every host its own address, port and pin, which is what
    /// [`connect`](RemoteShell::connect) matches on.
    pub fn with_host(mut self, host: Host) -> FakeRemoteShell {
        self.host = host;
        self
    }

    /// Registers `peer` as one host this fake can be [`connect`](RemoteShell::connect)ed
    /// to. The peer is matched on its address and port, so a fleet fake is a
    /// gateway plus one peer per host — each of which a test can inspect
    /// afterwards with [`calls`](FakeRemoteShell::calls). An address with no
    /// peer is [`ShellError::Unreachable`]: the fake never invents a host it
    /// was not handed.
    pub fn with_peer(self, peer: Arc<FakeRemoteShell>) -> FakeRemoteShell {
        self.state.lock().expect("fake remote shell state").peers.push(peer);
        self
    }

    /// Every call made against the fake, oldest first.
    #[must_use]
    pub fn calls(&self) -> Vec<ShellCall> {
        self.state.lock().expect("fake remote shell state").calls.clone()
    }
}

impl fmt::Debug for FakeRemoteShell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().expect("fake remote shell state");
        f.debug_struct("FakeRemoteShell")
            .field("commands", &state.results.len())
            .field("failures", &state.errors.len())
            .field("probe_scripts", &state.probe_scripts.len())
            .field("rejected_host_keys", &state.rejected.len())
            .field("peers", &state.peers.len())
            .field("copy_bytes", &self.copy_bytes)
            .field("calls", &state.calls.len())
            .finish()
    }
}

impl FakeRemoteShell {
    /// The pin rule, checked before anything else: a host whose pinned
    /// fingerprint this fake rejects never gets a connection, so `run`, `copy`
    /// and `probe` all fail the same way. Returns the error rather than
    /// reporting a bool, so the three methods cannot answer the mismatch
    /// differently.
    fn pin_mismatch(&self) -> Option<ShellError> {
        let fingerprint = self.host.host_key().fingerprint();
        let rejected = self
            .state
            .lock()
            .expect("fake remote shell state")
            .rejected
            .iter()
            .any(|key| key == fingerprint);
        rejected.then(|| ShellError::HostKeyMismatch {
            expected: fingerprint.to_string(),
            got: REBUILT_HOST_KEY.to_string(),
        })
    }

    /// Records one call. Separate from the methods below so each of them
    /// releases the mutex before deciding its answer: the pin check and the
    /// scripted tables are read under their own locks, never while the call
    /// record is held.
    fn record(&self, call: ShellCall) {
        self.state.lock().expect("fake remote shell state").calls.push(call);
    }

    /// What running `program` produces: the scripted error first, then the
    /// scripted result, then empty output for a program nobody scripted — the
    /// fake stands in for a host that ran something and said nothing.
    fn outcome(&self, program: &str) -> Result<CommandResult, ShellError> {
        let state = self.state.lock().expect("fake remote shell state");
        if let Some(error) = state.errors.get(program) {
            return Err(error.clone());
        }
        Ok(state.results.get(program).cloned().unwrap_or_else(|| CommandResult::new("", "")))
    }

    /// The next entry in a probe's script: advancing one step, holding at the
    /// last. A probe with nothing scripted — or a script with nothing in it —
    /// is [`Health::NoData`], because the fake cannot tell healthy from
    /// unknown there.
    fn next_probe(state: &mut State, command: &str) -> HealthReport {
        let Some(script) = state.probe_scripts.get(command) else {
            return HealthReport::with_reason(Health::NoData, NO_ANSWER);
        };
        let cursor = state.cursors.entry(command.to_string()).or_insert(0);
        if *cursor < script.len() {
            let report = script.get(*cursor).cloned();
            *cursor += 1;
            if let Some(report) = report {
                return report;
            }
        }
        script
            .back()
            .cloned()
            .unwrap_or_else(|| HealthReport::with_reason(Health::NoData, NO_ANSWER))
    }
}

impl RemoteShell for FakeRemoteShell {
    fn run<'a>(&'a self, command: &'a Command) -> BoxFuture<'a, Result<CommandResult, ShellError>> {
        let result = self.pin_mismatch().map_or_else(|| self.outcome(command.program()), Err);
        self.record(ShellCall::Run { program: command.program().to_string() });
        Box::pin(std::future::ready(result))
    }

    fn copy<'a>(
        &'a self,
        from: &'a Path,
        to: &'a str,
    ) -> BoxFuture<'a, Result<Copied, ShellError>> {
        let result = match self.pin_mismatch() {
            Some(error) => Err(error),
            // The one place this fake reads the filesystem: a local file that
            // is not there never reaches the host, so the copy fails rather
            // than reporting a short transfer. A test that wants a successful
            // copy must hand it a path that exists.
            None if !from.exists() => Err(ShellError::Command {
                command: "copy".to_string(),
                status: FAILING_STATUS,
                stderr: format!("no such local file: {}", from.display()),
            }),
            None => Ok(Copied::new(self.copy_bytes)),
        };
        self.record(ShellCall::Copy { to: to.to_string() });
        Box::pin(std::future::ready(result))
    }

    fn probe<'a>(&'a self, probe: &'a Probe) -> BoxFuture<'a, Result<HealthReport, ShellError>> {
        let result = match self.pin_mismatch() {
            Some(error) => Err(error),
            None => {
                let mut state = self.state.lock().expect("fake remote shell state");
                Ok(FakeRemoteShell::next_probe(&mut state, probe.command()))
            }
        };
        self.record(ShellCall::Probe { command: probe.command().to_string() });
        Box::pin(std::future::ready(result))
    }

    fn host(&self) -> &Host {
        &self.host
    }

    /// Hands back the registered peer for `host`, or
    /// [`ShellError::Unreachable`] when there is none. The peer keeps its own
    /// pin rule, so a fleet fake still refuses a host that was rebuilt: the
    /// refusal lands on the peer the call was made against, which is where a
    /// test can see it.
    fn connect<'a>(
        &'a self,
        host: &'a Host,
    ) -> BoxFuture<'a, Result<Arc<dyn RemoteShell>, ShellError>> {
        self.record(ShellCall::Connect { address: host.address().to_string() });
        let result = self
            .state
            .lock()
            .expect("fake remote shell state")
            .peers
            .iter()
            .find(|peer| peer.host.address() == host.address() && peer.host.port() == host.port())
            .map(|peer| Arc::clone(peer) as Arc<dyn RemoteShell>)
            .ok_or_else(|| ShellError::Unreachable {
                host: format!("{}:{}", host.address(), host.port()),
                message: "no peer is registered for this host".to_string(),
            });
        Box::pin(std::future::ready(result))
    }
}

/// How many times a conformance kit polls a probe while waiting for the host
/// to settle — a waiter with no clock, bounded so a broken adapter fails the
/// kit instead of hanging it.
const SETTLE_POLLS: usize = 64;

/// The `RemoteShell` conformance kit: every adapter — the fake here, real SSH
/// adapters in the adapter job
/// ([#52](https://github.com/Keep-Shipping/harness/issues/52)) — must pass
/// this.
///
/// The kit walks the port's contract:
///
/// - [`RemoteShell::host`] names an address, a nonzero port and a user, and
///   pins a **public** key fingerprint — never anything that looks like a
///   private key;
/// - a probe that cannot answer is never [`Health::Healthy`]: it is either
///   [`Health::NoData`] or an error, because an adapter that cannot tell
///   healthy from unknown must say so;
/// - the documented happy path — running [`OK_PROGRAM`] — succeeds, and
///   probing it settles on [`Health::Healthy`]. A zero exit is the port's
///   definition of healthy;
/// - running [`FAILING_PROGRAM`] is [`ShellError::Command`] with a nonzero
///   status, never an `Ok` carrying one;
/// - running the same command twice is idempotent: connects are per command
///   and leave nothing behind;
/// - copying a local path that does not exist fails rather than reporting a
///   short [`Copied`];
/// - [`RemoteShell::connect`] to a host nothing can reach is an error, never
///   a shell.
pub async fn conformance(shell: &dyn RemoteShell) {
    let host = shell.host();
    assert!(!host.address().is_empty(), "remote_shell conformance: the host must name an address");
    assert!(host.port() != 0, "remote_shell conformance: the host's port must be configured");
    assert!(!host.user().is_empty(), "remote_shell conformance: the host must name a user");
    let key = host.host_key();
    assert!(
        !key.algorithm().is_empty() && !key.fingerprint().is_empty(),
        "remote_shell conformance: the host must pin an algorithm and a fingerprint"
    );
    assert!(
        !key.fingerprint().contains("PRIVATE"),
        "remote_shell conformance: the pinned key must be a public fingerprint, never a private key"
    );

    let unanswerable =
        Probe::new(UNANSWERABLE_PROBE).expect("the conformance probe is well formed");
    let quiet = shell.probe(&unanswerable).await;
    assert!(
        !matches!(&quiet, Ok(report) if report.satisfies(Health::Healthy)),
        "remote_shell conformance: a probe that cannot answer must never be Healthy, got {quiet:?}"
    );
    if let Ok(report) = &quiet {
        assert_eq!(
            report.state(),
            Health::NoData,
            "remote_shell conformance: a probe that ran but said nothing must report NoData"
        );
        assert!(!report.state().is_settled(), "remote_shell conformance: NoData is not settled");
    }

    let ok = Command::new(OK_PROGRAM, Vec::new(), Duration::from_secs(30))
        .expect("the conformance command is well formed");
    let result = shell.run(&ok).await.unwrap_or_else(|error| {
        panic!("remote_shell conformance: a command that exits zero must succeed: {error}")
    });
    assert_eq!(
        result.stdout(),
        shell.run(&ok).await.expect("the same command runs again").stdout(),
        "remote_shell conformance: connects are per command — running the same command twice is idempotent"
    );

    let ready = Probe::new(OK_PROGRAM).expect("the conformance probe is well formed");
    let mut report = HealthReport::new(Health::Progressing);
    for _ in 0..SETTLE_POLLS {
        report = shell.probe(&ready).await.unwrap_or_else(|error| {
            panic!("remote_shell conformance: probing a healthy host must be a report: {error}")
        });
        if report.satisfies(Health::Healthy) {
            break;
        }
        if matches!(report.state(), Health::Failed) {
            panic!(
                "remote_shell conformance: the host settled Failed instead of Healthy: {report:?}"
            );
        }
    }
    assert!(
        report.satisfies(Health::Healthy),
        "remote_shell conformance: a zero exit must be Healthy, got {report:?}"
    );

    let failing = Command::new(FAILING_PROGRAM, Vec::new(), Duration::from_secs(30))
        .expect("the conformance command is well formed");
    let failed = shell.run(&failing).await;
    assert!(
        matches!(&failed, Err(ShellError::Command { status, .. }) if *status != 0),
        "remote_shell conformance: a nonzero exit must be ShellError::Command, not an Ok, got {failed:?}"
    );

    let missing = Path::new("/ks-testing/conformance/definitely-not-here");
    let copied = shell.copy(missing, "/tmp/definitely-not-here").await;
    assert!(
        copied.is_err(),
        "remote_shell conformance: a truncated transfer is an error, not a shorter Copied, got {copied:?}"
    );

    // `connect` reaches the rest of a fleet, and only the rest of a fleet:
    // `.invalid` never resolves (RFC 2606), so no adapter can reach it and
    // one that answers `Ok` there is handing back a connection to something
    // nobody named.
    let unknown_key = HostKey::new("ssh-ed25519", "SHA256:conformance")
        .expect("the conformance host key is well formed");
    let unknown = Host::new(UNREACHABLE_ADDRESS, 22, "deploy", unknown_key)
        .expect("the conformance host is well formed");
    let reached = shell.connect(&unknown).await;
    assert!(
        reached.is_err(),
        "remote_shell conformance: a host nothing can reach must not connect, got {:?}",
        reached.err()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;
    use std::path::PathBuf;

    fn command(program: &str) -> Command {
        Command::new(program, vec!["--flag".to_string()], Duration::from_secs(30))
            .expect("the test command is well formed")
    }

    fn probe(command_line: &str) -> Probe {
        Probe::new(command_line).expect("the test probe is well formed")
    }

    /// A local file the test itself creates, so the fake's one existence check
    /// never depends on a path that exists only on some machines — `/etc/*` is
    /// absent from a distroless image. The path is returned alongside a guard
    /// that removes it.
    fn a_local_file(name: &str) -> (PathBuf, impl Drop) {
        let path = std::env::temp_dir().join(format!("ks-testing-{}-{name}", std::process::id()));
        std::fs::write(&path, b"payload the fake never reads\n").expect("the temp dir is writable");
        let cleanup = path.clone();
        (path, TempFile(cleanup))
    }

    /// Removes the file a [`a_local_file`] call created.
    struct TempFile(PathBuf);

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn an_unscripted_probe_is_silence_and_a_scripted_one_walks_its_transition() {
        let shell = FakeRemoteShell::new().with_probe_script(
            "curl healthz",
            [Health::Progressing, Health::Degraded, Health::Healthy],
        );
        let unknown =
            block_on(shell.probe(&probe("curl healthz-other"))).expect("a report, not an error");
        assert_eq!(unknown.state(), Health::NoData);
        assert!(!unknown.satisfies(Health::Healthy));

        let states: Vec<Health> = (0..4)
            .map(|_| block_on(shell.probe(&probe("curl healthz"))).expect("a report").state())
            .collect();
        assert_eq!(
            states,
            vec![Health::Progressing, Health::Degraded, Health::Healthy, Health::Healthy]
        );
        assert_eq!(block_on(shell.probe(&probe("curl healthz"))).expect("a report").reason(), None);
    }

    #[test]
    fn commands_answer_with_their_scripted_output_or_error() {
        let shell =
            FakeRemoteShell::new().with_command_result("uname", CommandResult::new("Linux\n", ""));
        let result = block_on(shell.run(&command("uname"))).expect("the command is scripted");
        assert_eq!(result.stdout(), "Linux\n");
        assert_eq!(result.stderr(), "");

        let failing = FakeRemoteShell::new().with_command_error(
            "systemctl",
            ShellError::TimedOut {
                command: "systemctl".to_string(),
                timeout: Duration::from_secs(30),
            },
        );
        assert_eq!(
            block_on(failing.run(&command("systemctl"))),
            Err(ShellError::TimedOut {
                command: "systemctl".to_string(),
                timeout: Duration::from_secs(30)
            })
        );
    }

    #[test]
    fn a_rejected_pinned_host_key_stops_every_call() {
        let shell = FakeRemoteShell::new()
            .with_rejected_host_key(DEFAULT_FINGERPRINT)
            .with_probe_script("true", [Health::Healthy]);
        let expected = ShellError::HostKeyMismatch {
            expected: DEFAULT_FINGERPRINT.to_string(),
            got: REBUILT_HOST_KEY.to_string(),
        };
        let (local, _cleanup) = a_local_file("rejected-copy");
        assert_eq!(block_on(shell.run(&command(OK_PROGRAM))), Err(expected.clone()));
        assert_eq!(block_on(shell.copy(&local, "/tmp/hostname")), Err(expected.clone()));
        assert_eq!(block_on(shell.probe(&probe("true"))), Err(expected));

        // The calls were still recorded, and the connection never opened.
        assert_eq!(
            shell.calls(),
            vec![
                ShellCall::Run { program: OK_PROGRAM.to_string() },
                ShellCall::Copy { to: "/tmp/hostname".to_string() },
                ShellCall::Probe { command: "true".to_string() },
            ]
        );

        // A host pinning something else is unaffected.
        let other = FakeRemoteShell::new().with_rejected_host_key("SHA256:someone-else");
        assert!(block_on(other.run(&command(OK_PROGRAM))).is_ok());
    }

    #[test]
    fn a_copy_reports_its_bytes_and_fails_on_a_missing_local_file() {
        let shell = FakeRemoteShell::new().with_copy_bytes(12_288);
        // The source is a file this test created, so the fake's one existence
        // check never depends on a path this machine happens to have.
        let (local, _cleanup) = a_local_file("copy-source");
        let copied = block_on(shell.copy(&local, "/tmp/hostname"))
            .expect("the local file this test created exists");
        assert_eq!(copied.bytes(), 12_288);
        assert!(matches!(
            block_on(shell.copy(&local.with_extension("absent"), "/tmp/nope")),
            Err(ShellError::Command { status, .. }) if status != 0
        ));
    }

    #[test]
    fn a_fresh_probe_script_replays_the_transition_from_the_start() {
        let mut shell = FakeRemoteShell::new()
            .with_probe_script("curl healthz", [Health::Progressing, Health::Healthy]);
        let states: Vec<Health> = (0..4)
            .map(|_| block_on(shell.probe(&probe("curl healthz"))).expect("a report").state())
            .collect();
        assert_eq!(
            states,
            vec![Health::Progressing, Health::Healthy, Health::Healthy, Health::Healthy]
        );

        shell = shell.with_probe_script("curl healthz", [Health::Progressing, Health::Healthy]);
        assert_eq!(
            block_on(shell.probe(&probe("curl healthz"))).expect("a report").state(),
            Health::Progressing,
            "installing a script must rewind the cursor, or the new transition starts settled"
        );
        // Another probe's script is untouched by a re-script of this one.
        assert_eq!(
            block_on(shell.probe(&probe("curl other"))).expect("a report").state(),
            Health::NoData
        );
    }

    #[test]
    fn connect_hands_back_the_peer_for_a_host_and_refuses_one_it_was_not_given() {
        let key = |fingerprint: &str| {
            HostKey::new("ssh-ed25519", fingerprint).expect("a well-formed host key")
        };
        let a = Host::new("a.example", 22, "deploy", key("SHA256:a")).expect("a named host");
        let b = Host::new("b.example", 2222, "deploy", key("SHA256:b")).expect("a named host");
        let peer_a = Arc::new(FakeRemoteShell::new().with_host(a.clone()));
        let peer_b = Arc::new(FakeRemoteShell::new().with_host(b.clone()));
        let gateway =
            FakeRemoteShell::new().with_peer(Arc::clone(&peer_a)).with_peer(Arc::clone(&peer_b));

        // The peer is the one the host names, and the call is recorded against
        // the gateway — that is where the address was asked for.
        let reached = block_on(gateway.connect(&a)).expect("a registered host connects");
        assert_eq!(reached.host(), &a);
        assert_eq!(reached.host().host_key().fingerprint(), "SHA256:a");

        // The port, not the port number alone, is what matches: another port
        // on the same address is a host this fake was not given.
        let other_port =
            Host::new("a.example", 2222, "deploy", key("SHA256:a")).expect("a named host");
        assert!(matches!(
            block_on(gateway.connect(&other_port)),
            Err(ShellError::Unreachable { .. })
        ));

        let elsewhere =
            Host::new("nowhere.example", 22, "deploy", key("SHA256:c")).expect("a named host");
        assert!(matches!(
            block_on(gateway.connect(&elsewhere)),
            Err(ShellError::Unreachable { host, .. })
                if host == "nowhere.example:22"
        ));

        assert_eq!(
            gateway.calls(),
            vec![
                ShellCall::Connect { address: "a.example".to_string() },
                ShellCall::Connect { address: "a.example".to_string() },
                ShellCall::Connect { address: "nowhere.example".to_string() },
            ]
        );

        // The peer's own pin rule still holds: connecting to it is not a way
        // around the host key it pins.
        let rebuilt = Arc::new(
            FakeRemoteShell::new().with_host(a.clone()).with_rejected_host_key("SHA256:a"),
        );
        let gateway = FakeRemoteShell::new().with_peer(rebuilt);
        let reached = block_on(gateway.connect(&a)).expect("the host is registered");
        assert_eq!(
            block_on(reached.run(&command(OK_PROGRAM))),
            Err(ShellError::HostKeyMismatch {
                expected: "SHA256:a".to_string(),
                got: REBUILT_HOST_KEY.to_string()
            })
        );
    }

    #[test]
    fn the_debug_output_carries_counts_and_never_command_output() {
        let shell =
            FakeRemoteShell::new().with_command_result("cat", CommandResult::new("hunter2\n", ""));
        let debug = format!("{shell:?}");
        assert!(debug.contains("commands: 2"), "{debug}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(!debug.contains(DEFAULT_ADDRESS), "{debug}");
    }

    #[test]
    fn the_fake_passes_conformance() {
        block_on(conformance(&FakeRemoteShell::new()));
    }
}
