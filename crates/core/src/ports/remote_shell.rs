//! The [`RemoteShell`] port: running commands and moving files on a host the
//! harness does not own
//! ([#52](https://github.com/Keep-Shipping/harness/issues/52)).
//!
//! Some deploy targets are a box, not an API: an appliance, a bastion, a
//! vendor's appliance VM. This port runs one command at a time on it, copies
//! a file across, and turns a probe's exit code into the shared
//! [`HealthReport`] so a `wait` step means the same thing here as on a
//! cluster.
//!
//! # No agent, no side effects
//!
//! There is deliberately no agent-forwarding method and nothing to install on
//! the remote host. An adapter connects per command, runs it, and disconnects;
//! it must not leave a daemon, a package, a key or a cache behind. A deploy
//! that quietly made the host non-reproducible — or that could not be undone
//! because the harness no longer had access — would make every later run on
//! that host untrustworthy.
//!
//! # The host key is pinned
//!
//! Every [`Host`] carries a [`HostKey`], compared on **every** connect. A
//! mismatch is [`ShellError::HostKeyMismatch`] and the connection does not
//! open; there is no "accept once" path, because the second connect is
//! exactly the one an attacker would win. The key is a public fingerprint —
//! never a private key, which must stay on the harness side.
//!
//! [`RemoteShell::host`] names the one host an adapter was configured for.
//! [`RemoteShell::connect`] opens the rest of a fleet over the same
//! transport and credentials, each to the host — and therefore the pin — the
//! caller named.
//!
//! # Every command has a deadline
//!
//! [`Command::new`] rejects a zero timeout: a command that can hang forever
//! holds the run's step slot forever and stops the run from ever reporting. An
//! adapter that exceeds the timeout reports
//! [`ShellError::TimedOut`] rather than waiting for a process that may never
//! exit.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::BoxFuture;
use super::health::HealthReport;

/// A pinned host key: an algorithm and the fingerprint it must present.
///
/// This is a **public** key fingerprint (e.g. `"SHA256:abc123…"`), never a
/// private key — the private half stays on the harness side and never crosses
/// this port. How and when it is checked is in the [module
/// documentation](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    algorithm: String,
    fingerprint: String,
}

impl HostKey {
    /// Pins the key presented by an algorithm, e.g. `("ssh-ed25519",
    /// "SHA256:abc123")`. The fingerprint is opaque to this port: the adapter
    /// parses and compares it. Fails with [`ShellError::Empty`] if either half
    /// is empty — a pin with no algorithm or no fingerprint to compare cannot
    /// reject a wrong host, which is the only job it has.
    pub fn new(
        algorithm: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Result<Self, ShellError> {
        let algorithm = algorithm.into();
        let fingerprint = fingerprint.into();
        if algorithm.trim().is_empty() {
            return Err(ShellError::Empty { field: "host key algorithm" });
        }
        if fingerprint.trim().is_empty() {
            return Err(ShellError::Empty { field: "host key fingerprint" });
        }
        Ok(HostKey { algorithm, fingerprint })
    }

    /// The key's algorithm, e.g. `"ssh-ed25519"`.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The pinned fingerprint, e.g. `"SHA256:abc123"`. Public, and safe to
    /// print — this is what an operator checks against the host's own key.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// A remote host to connect to, and the key it must present.
///
/// Obtained only from [`RemoteShell::host`]; the fields are private so a host
/// cannot be assembled with an empty address and sent at a random target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    address: String,
    port: u16,
    user: String,
    host_key: HostKey,
}

impl Host {
    /// The host at `address`:`port` as `user`, which must present
    /// `host_key`. Fails with [`ShellError::Empty`] if the address or user is
    /// empty — a connection with neither is never what the caller meant — or
    /// if `port` is zero, the "not configured yet" sentinel that would send
    /// the adapter somewhere the caller never named.
    pub fn new(
        address: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        host_key: HostKey,
    ) -> Result<Self, ShellError> {
        let address = address.into();
        let user = user.into();
        if address.trim().is_empty() {
            return Err(ShellError::Empty { field: "address" });
        }
        if port == 0 {
            return Err(ShellError::Empty { field: "port" });
        }
        if user.trim().is_empty() {
            return Err(ShellError::Empty { field: "user" });
        }
        Ok(Host { address, port, user, host_key })
    }

    /// The host's address, e.g. `"appliance.internal"`.
    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    /// The key the host must present (see the [module
    /// documentation](self)).
    pub fn host_key(&self) -> &HostKey {
        &self.host_key
    }
}

/// One command to run, with its own deadline.
///
/// The program and arguments are separate — never a single shell string — so
/// a value that happens to contain a space or a quote is one argument, not a
/// new command. Adapters pass `program` and `args` through without a shell
/// unless the step explicitly asked for one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    program: String,
    args: Vec<String>,
    timeout: Duration,
}

impl Command {
    /// Runs `program` with `args` for at most `timeout`. Fails with
    /// [`ShellError::Empty`] if the program is empty and with
    /// [`ShellError::TimedOut`] if the timeout is zero — an unbounded command
    /// would hold the run's step slot forever.
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = String>,
        timeout: Duration,
    ) -> Result<Self, ShellError> {
        let program = program.into();
        if program.trim().is_empty() {
            return Err(ShellError::Empty { field: "program" });
        }
        if timeout.is_zero() {
            return Err(ShellError::TimedOut { command: program, timeout });
        }
        Ok(Command { program, args: args.into_iter().collect(), timeout })
    }

    pub fn program(&self) -> &str {
        &self.program
    }

    /// The program's arguments, in order and unquoted — a value that contains
    /// a space or a quote is still one argument.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// How long the command may run before it is
    /// [`ShellError::TimedOut`].
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// What one command produced.
///
/// This type exists only on success: a nonzero exit is a
/// [`ShellError::Command`], not an `Ok` carrying a nonzero status. A failing
/// command is a failure, and an adapter must not hand a caller a success it has
/// to re-derive — so there is nothing here to ask whether the command
/// succeeded, because reaching it means it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    stdout: String,
    stderr: String,
}

impl CommandResult {
    /// The output of a command that exited zero.
    pub fn new(stdout: impl Into<String>, stderr: impl Into<String>) -> Self {
        CommandResult { stdout: stdout.into(), stderr: stderr.into() }
    }

    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    /// What the command wrote to stderr; the adapter lets the run's redactor
    /// scrub it before it reaches a log, because remote output can echo
    /// secrets the step passed in.
    pub fn stderr(&self) -> &str {
        &self.stderr
    }
}

/// How much a [`RemoteShell::copy`] moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Copied {
    bytes: u64,
}

impl Copied {
    /// A transfer of `bytes` bytes.
    pub fn new(bytes: u64) -> Copied {
        Copied { bytes }
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// A periodic command whose result becomes a [`HealthReport`].
///
/// Run it on an interval while a `wait` step waits: a zero exit is
/// [`Health::Healthy`](super::health::Health), a nonzero exit the adapter
/// recognises is [`Health::Failed`](super::health::Health) or
/// [`Health::Degraded`](super::health::Health), and *no usable answer at all*
/// is [`Health::NoData`](super::health::Health) — which no healthy gate
/// accepts. A probe that cannot tell healthy from unknown must say so rather
/// than defaulting to success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    command: String,
}

impl Probe {
    /// The command line to run periodically. It is a single string because a
    /// probe is a shell snippet the operator writes (e.g. `"curl -fsS
    /// localhost:8080/healthz"`), unlike a [`Command`], which is an argv.
    /// Fails with [`ShellError::Empty`] if it is empty — the same rule as
    /// [`Command::new`], and load-bearing here, because an empty probe cannot
    /// report anything and a `wait` step would then poll an answer that was
    /// never asked for.
    pub fn new(command: impl Into<String>) -> Result<Self, ShellError> {
        let command = command.into();
        if command.trim().is_empty() {
            return Err(ShellError::Empty { field: "probe command" });
        }
        Ok(Probe { command })
    }

    pub fn command(&self) -> &str {
        &self.command
    }
}

/// Why a [`RemoteShell`] operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellError {
    /// The host presented a key that is not the pinned
    /// [`HostKey`]. The connection was not opened. This is the
    /// MITM-warning case: either the host was rebuilt or the connection is not
    /// the one the pin describes — re-pin deliberately, do not retry.
    HostKeyMismatch {
        /// The pinned fingerprint.
        expected: String,
        /// The fingerprint the host actually presented.
        got: String,
    },
    /// The host could not be reached, or the connection dropped. `message` is
    /// the transport's own wording, safe to print.
    Unreachable {
        /// The host that could not be reached, e.g. `"appliance.internal:22"`.
        host: String,
        /// What the transport reported.
        message: String,
    },
    /// The command ran past its deadline. The adapter must stop waiting on the
    /// remote process; a command that timed out may still be running there.
    TimedOut {
        /// The program that timed out.
        command: String,
        /// The deadline it exceeded.
        timeout: Duration,
    },
    /// The command ran and exited nonzero. `stderr` is the remote's own
    /// output; adapters must let the run's redactor scrub it first.
    Command {
        /// The program that failed.
        command: String,
        /// Its exit status.
        status: i32,
        /// Its stderr, already scrubbed by the adapter.
        stderr: String,
    },
    /// A required field was empty. Raised by [`HostKey::new`], [`Host::new`],
    /// [`Command::new`] and [`Probe::new`] before any connection is attempted.
    Empty {
        /// The empty field's name.
        field: &'static str,
    },
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShellError::HostKeyMismatch { expected, got } => {
                write!(
                    f,
                    "host key mismatch: expected {expected}, host presented {got}; \
                     verify the host before re-pinning"
                )
            }
            ShellError::Unreachable { host, message } => {
                write!(
                    f,
                    "cannot reach {host}: {message}; check the address, port and network route"
                )
            }
            ShellError::TimedOut { command, timeout } => {
                write!(
                    f,
                    "{command:?} timed out after {timeout:?}; raise the timeout or shorten the command"
                )
            }
            ShellError::Command { command, status, stderr } => {
                write!(f, "{command:?} failed with status {status}: {stderr}")?;
                if stderr.trim().is_empty() {
                    write!(f, " (no stderr; run the command on the host to see why)")?;
                }
                Ok(())
            }
            ShellError::Empty { field } => {
                write!(f, "{field} must not be empty; set it in the shell target")
            }
        }
    }
}

impl std::error::Error for ShellError {}

/// The `RemoteShell` port: an adapter connects to a host it does not own,
/// runs one command at a time, and reports back.
///
/// Two of this trait's rules are stated in full in the [module
/// documentation](self) and hold for every method below: an adapter installs
/// nothing on the remote host and forwards no agent, and every connect checks
/// [`Host::host_key`]. In short — connects are per command, a pin mismatch is
/// [`ShellError::HostKeyMismatch`] and the connection does not open.
///
/// Adapters must fail with [`ShellError`] rather than panicking, and must
/// scrub remote output through the run's redactor before it becomes an error
/// message — it can echo whatever the step passed in.
pub trait RemoteShell: Send + Sync {
    /// Runs `command` on the host and returns what it produced. A nonzero
    /// exit is [`ShellError::Command`], never an `Ok` carrying a nonzero
    /// status; exceeding the deadline is [`ShellError::TimedOut`].
    fn run<'a>(&'a self, command: &'a Command) -> BoxFuture<'a, Result<CommandResult, ShellError>>;

    /// Copies the local file `from` to `to` on the host and reports how many
    /// bytes arrived. `to` is the destination *path* as the remote sees it.
    /// A truncated transfer is an error, not a shorter [`Copied`].
    fn copy<'a>(&'a self, from: &'a Path, to: &'a str)
    -> BoxFuture<'a, Result<Copied, ShellError>>;

    /// Runs `probe` once and reports its result as a [`HealthReport`].
    ///
    /// This is the one call a `wait` step polls. An adapter that cannot tell
    /// healthy from unknown — the probe did not run, the host did not answer,
    /// the exit code means nothing here — must report
    /// [`Health::NoData`](super::health::Health), which no healthy gate
    /// accepts, rather than optimistically reporting
    /// [`Health::Healthy`](super::health::Health).
    fn probe<'a>(&'a self, probe: &'a Probe) -> BoxFuture<'a, Result<HealthReport, ShellError>>;

    /// The host this adapter connects to, and the key it pins.
    fn host(&self) -> &Host;

    /// Opens a second shell to `host`: the same transport and the same
    /// credentials, aimed at another host.
    ///
    /// [`host`](RemoteShell::host) names one host, but a deploy has rarely
    /// only one — a rolling deploy walks a fleet, and each host in it pins
    /// its **own** [`HostKey`]. This method is how a step reaches the rest of
    /// the fleet without a second configured adapter per box: the transport
    /// and the credentials are the adapter's, the destination and the pin are
    /// the caller's.
    ///
    /// Everything in the [module documentation](self) still holds for the
    /// host returned here, with one exception worth stating: the pin checked
    /// is `host`'s own, not the configured [`host`](RemoteShell::host)'s, so a
    /// mismatch surfaces as [`ShellError::HostKeyMismatch`] on use, exactly as
    /// it does on the host the adapter was configured for. There is no
    /// default implementation and no "accept once": an adapter that cannot
    /// reach a second host says so with [`ShellError::Unreachable`] rather
    /// than opening the connection unchecked.
    fn connect<'a>(
        &'a self,
        host: &'a Host,
    ) -> BoxFuture<'a, Result<Arc<dyn RemoteShell>, ShellError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::health::Health;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_remote_shell_trait_is_dyn_compatible() {
        assert_send_sync::<dyn RemoteShell>();
    }

    #[test]
    fn a_host_key_is_a_public_fingerprint_checked_every_connect() {
        let key = HostKey::new("ssh-ed25519", "SHA256:abc123").expect("named key");
        assert_eq!(key.algorithm(), "ssh-ed25519");
        assert_eq!(key.fingerprint(), "SHA256:abc123");
        assert!(!format!("{key:?}").contains("PRIVATE"));
    }

    #[test]
    fn host_keys_reject_an_empty_algorithm_or_fingerprint() {
        assert_eq!(
            HostKey::new("", "SHA256:abc123"),
            Err(ShellError::Empty { field: "host key algorithm" })
        );
        assert_eq!(
            HostKey::new("ssh-ed25519", "  "),
            Err(ShellError::Empty { field: "host key fingerprint" })
        );
    }

    #[test]
    fn hosts_reject_an_empty_address_or_user() {
        let key = HostKey::new("ssh-ed25519", "SHA256:abc123").expect("named key");
        assert_eq!(
            Host::new("", 22, "deploy", key.clone()),
            Err(ShellError::Empty { field: "address" })
        );
        assert_eq!(
            Host::new("  ", 22, "deploy", key.clone()),
            Err(ShellError::Empty { field: "address" })
        );
        assert_eq!(
            Host::new("appliance.internal", 22, "", key.clone()),
            Err(ShellError::Empty { field: "user" })
        );
        // Port 0 is the "never configured" sentinel, not a destination.
        assert_eq!(
            Host::new("appliance.internal", 0, "deploy", key.clone()),
            Err(ShellError::Empty { field: "port" })
        );
        let host = Host::new("appliance.internal", 2222, "deploy", key).expect("named host");
        assert_eq!(host.address(), "appliance.internal");
        assert_eq!(host.port(), 2222);
        assert_eq!(host.user(), "deploy");
        assert_eq!(host.host_key().fingerprint(), "SHA256:abc123");
    }

    #[test]
    fn commands_reject_an_empty_program_or_a_zero_timeout() {
        assert_eq!(
            Command::new("", vec!["--version".to_string()], Duration::from_secs(5)),
            Err(ShellError::Empty { field: "program" })
        );
        assert!(matches!(
            Command::new("systemctl", vec![], Duration::ZERO),
            Err(ShellError::TimedOut { command, timeout })
                if command == "systemctl" && timeout.is_zero()
        ));
    }

    #[test]
    fn a_command_keeps_its_arguments_separate_and_unquoted() {
        let command = Command::new(
            "grep",
            vec!["-c".to_string(), "two words".to_string()],
            Duration::from_secs(30),
        )
        .expect("argv form");
        assert_eq!(command.program(), "grep");
        // One argument containing a space, not two arguments: a value must
        // never be able to become a second command.
        assert_eq!(command.args(), ["-c", "two words"]);
        assert_eq!(command.timeout(), Duration::from_secs(30));
    }

    #[test]
    fn a_command_result_exists_only_when_the_command_succeeded() {
        let ok = CommandResult::new("ok\n", "");
        assert_eq!(ok.stdout(), "ok\n");
        assert_eq!(ok.stderr(), "");

        // A failing command is an error, not an Ok with a nonzero status.
        let failed: Result<CommandResult, ShellError> = Err(ShellError::Command {
            command: "false".to_string(),
            status: 1,
            stderr: String::new(),
        });
        assert!(matches!(
            failed,
            Err(ShellError::Command { status, .. }) if status != 0
        ));
    }

    #[test]
    fn a_copy_reports_how_many_bytes_moved() {
        assert_eq!(Copied::new(0).bytes(), 0);
        assert_eq!(Copied::new(4096).bytes(), 4096);
    }

    #[test]
    fn a_probe_is_a_single_command_line_for_the_wait_loop() {
        assert_eq!(Probe::new(""), Err(ShellError::Empty { field: "probe command" }));
        let probe = Probe::new("curl -fsS localhost:8080/healthz").expect("non-empty probe");
        assert_eq!(probe.command(), "curl -fsS localhost:8080/healthz");
        // The same probe, answered two ways, yields two health reports — and
        // silence is not one of the healthy ones.
        let quiet = HealthReport::with_reason(Health::NoData, "probe produced no output");
        assert!(!quiet.satisfies(Health::Healthy));
        let ready = HealthReport::new(Health::Healthy);
        assert!(ready.satisfies(Health::Healthy));
    }

    #[test]
    fn shell_errors_display_actionably() {
        let mismatch = ShellError::HostKeyMismatch {
            expected: "SHA256:abc".to_string(),
            got: "SHA256:xyz".to_string(),
        }
        .to_string();
        assert!(mismatch.contains("SHA256:xyz") && mismatch.contains("re-pin"), "{mismatch}");

        let unreachable = ShellError::Unreachable {
            host: "appliance.internal:22".to_string(),
            message: "connection refused".to_string(),
        }
        .to_string();
        assert!(
            unreachable.contains("appliance.internal:22")
                && unreachable.contains("connection refused"),
            "{unreachable}"
        );

        let timed_out = ShellError::TimedOut {
            command: "apt-get upgrade".to_string(),
            timeout: Duration::from_secs(60),
        }
        .to_string();
        assert!(timed_out.contains("apt-get upgrade") && timed_out.contains("60s"), "{timed_out}");

        let failed =
            ShellError::Command { command: "true".to_string(), status: 2, stderr: String::new() }
                .to_string();
        assert!(failed.contains("no stderr"), "{failed}");
        let failed = ShellError::Command {
            command: "true".to_string(),
            status: 2,
            stderr: "boom".to_string(),
        }
        .to_string();
        assert!(failed.contains("boom") && failed.contains("status 2"), "{failed}");

        let empty = ShellError::Empty { field: "program" }.to_string();
        assert!(empty.contains("program") && empty.contains("must not be empty"), "{empty}");
    }
}
