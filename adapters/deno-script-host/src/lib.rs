//! `DenoScriptHost`: a [`ScriptHost`] that runs TypeScript escape-hatch steps
//! in a pinned Deno, behind the JSON-stdio protocol
//! ([ADR 0009](../../../docs/adr/0009-typescript-escape-hatch-runtime.md)).
//!
//! One `keepshipping` version means one Deno: [`DENO_VERSION`] and the
//! SHA-256 of its release archive are compiled in, verified before the binary
//! is written to the per-user cache, and any Deno already on the machine is
//! ignored. The issue asked for a `ship.lock` to pin in; this repository has
//! none, so the pin lives here.
//!
//! # The sandbox
//!
//! Deny by default, and every grant is an argument this adapter builds — never
//! anything a step asks for directly:
//!
//! - **Read**: the workspace, the embedded bootstrap next to the pinned Deno,
//!   and the one FIFO this run's secrets arrive on. No write, no env, no net,
//!   no subprocesses, no FFI, no sys. A step reading `$HOME/.ssh/id_ed25519`
//!   or `Deno.env.get("HOME")` gets `NotCapable`.
//! - **Read, by way of a link**: Deno checks that grant against the path a step
//!   *names*, not against the file behind it, so a symlink inside the
//!   workspace pointing out of it is a hole — measured on 2.9.7:
//!   `readTextFileSync("keys/id_ed25519")` returns the key, while
//!   `readTextFileSync("/home/…/id_ed25519")` is `NotCapable`. The adapter
//!   walks the workspace before it spawns anything and hands every link that
//!   escapes to `--deny-read`, which Deno applies over `--allow-read` — so the
//!   path is refused and the step still runs, which is the only way a stock
//!   `.venv`, a pnpm-linked `node_modules` or a half-finished `npm install`
//   (all of which have such links, and are all denied nothing useful) can work
//!   at all. The walk is `DenoScriptHost::escaping_links`, private to this
//!   adapter: it is a policy decision this crate makes about the workspace it
//!   was handed, not part of the `ScriptHost` port, so it is documented on the
//!   method rather than exported for a caller to lean on.
//!
//!   What that actually buys, precisely: a step cannot read *through* a link
//!   that existed when the walk finished. It is not a claim about the whole
//!   machine — the walk sees symlinks only, so a hardlink to `/etc/shadow` or a
//!   bind mount under the workspace is outside it — and it is not atomic with
//!   the spawn, so a link created after the walk is not in the deny list. A
//!   workspace an attacker can write to while a step runs is not a sandbox this
//!   flag makes sound; the walk is a closure of the ordinary hole, not of every
//!   way a path can be made to lie.
//! - **Net**: `--allow-net` with exactly the hosts the step *declared* in its
//!   default export, and nothing at all when it declared none.
//! - **Dependencies**: a `deno.json`/`package.json` beside a step requires a
//!   `deno.lock` beside it and runs `--frozen-lockfile`; with no manifest the
//!   step runs `--no-config --no-lock --no-remote --no-npm`, so an un-locked
//!   script cannot pull remote code.
//!
//! Two argv details are load-bearing and are asserted in `tests/adapter.rs`:
//! the seed, and the absence of every other `--allow-*` flag.
//!
//! # Declared types
//!
//! A field may be declared as a plain type name (`"string"`, `"number"`,
//! `"bool"`, `"list"`, `"map"`) or as the runtime tag a future
//! `@keepshipping/sdk` `step()` hands over (`int()`, `path()`, `db: secret()`,
//! …). `describe` normalises both: `int`/`float` are numbers,
//! `string`/`path`/`url`/`duration` are strings, `list(of)` is a list,
//! `optional(of)` is the type inside it, and a `secret` *input* is not a
//! schema input at all — secrets arrive through `ctx.secrets`, never on
//! stdin. A kind the port has no type for is an [`ScriptHostError::InvalidSchema`],
//! never a silent `any`.
//!
//! # The protocol
//!
//! `describe` prints one `{"describe":{...}}` line — the step's declared
//! inputs, outputs and net hosts — and runs nothing. `run` reads one JSON
//! object of inputs on stdin, reads the secrets from the FIFO, calls
//! `run(inputs, ctx)`, and writes any number of `{"log":{...}}` lines and
//! exactly one `{"output":{...}}`. Anything else on stdout is a
//! [`ScriptHostError::Protocol`]; a nonzero exit is
//! [`ScriptHostError::ScriptFailed`], with the stderr tail through the run's
//! [`Redactor`].
//!
//! # What is deferred
//!
//! - **The secret descriptor.** ADR 0009 planned `dup2` onto fd 3 and a reopen
//!   of `/proc/self/fd/3`. Deno 2.9.7 escalates any grant naming a
//!   `/proc/self/fd/N` to *all* access, so that route needs `--allow-all` and
//!   no sandbox at all. The wire is the same length-prefixed frames over a
//!   private FIFO instead; see [`channel`].
//! - **The npm grant shape**: `--allow-npm` and how a step declares its
//!   dependencies is
//!   [#57](https://github.com/Keep-Shipping/harness/issues/57). Until then a
//!   step with no manifest cannot import anything at all.
//! - **Non-Linux**: `/proc/self/fd` and the FIFO route are Linux. Any other
//!   platform is a clear error naming it, not a silent fallback.
//! - **Log plumbing through the port**: `ctx.log` lines go to
//!   [`DenoScriptHost::with_log_sink`], since `ScriptHost` has no log channel
//!   yet — also [#57](https://github.com/Keep-Shipping/harness/issues/57).
//!
//! ```
//! # fn main() -> Result<(), ks_core::ports::script_host::ScriptHostError> {
//! use ks_deno_script_host::DenoScriptHost;
//!
//! // The adapter never downloads in this example; it reports the pinned
//! // version and where it would install it.
//! let host = DenoScriptHost::new(".").expect("a workspace root");
//! println!("runs Deno {} on {}", ks_deno_script_host::DENO_VERSION, host.platform());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use ks_core::ports::BoxFuture;
use ks_core::ports::script_host::{
    ScriptHost, ScriptHostError, ScriptRef, StepSchema, ValueType, Values,
};
use ks_core::ports::secrets::{Redactor, SecretBundle};

pub mod channel;
mod install;
mod json;

pub use install::{CurlFetcher, DENO_TARGET, DENO_VERSION, Fetcher};

/// The embedded bootstrap, written next to the pinned Deno rather than inside
/// the workspace: a step cannot see it, let alone change it.
const BOOTSTRAP: &str = include_str!("bootstrap.ts");

/// V8's PRNG seed. Not `0`: V8 reads a zero seed as *unseeded*, so `--seed=0`
/// leaves `Math.random()` different on every run, which is the opposite of what
/// this argument is here for. The value itself is arbitrary and fixed — the
/// point is that it is the same number on every machine, so the same step and
/// the same Deno produce the same bytes locally and in CI.
const SEED: u32 = 1;

/// How much of a failed step's stderr becomes the error message. A stack trace
/// is worth having; a megabyte of it is not.
const STDERR_TAIL: usize = 4 * 1024;

/// Distinguishes concurrent temp files within one process.
static NEXT_TEMP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Which of the two modes a child process runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Print the step's declared schema and run nothing.
    Describe,
    /// Run the step against the given inputs.
    Run,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Describe => "describe",
            Mode::Run => "run",
        }
    }
}

/// How a step's dependencies are pinned. A step beside a manifest may not run
/// unlocked; a step without one may not reach out at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Manifest {
    /// No `deno.json`/`deno.jsonc`/`package.json` beside the step.
    None,
    /// One is there, so its `deno.lock` is required and used.
    Locked {
        /// The `deno.json`/`deno.jsonc` to pass with `--config`, if any.
        config: Option<PathBuf>,
        /// The `deno.lock` to pass with `--lock`, checked `--frozen-lockfile`.
        lock: PathBuf,
    },
}

/// Everything one child process needs, as data — so the argv can be built and
/// asserted without spawning anything, which is what keeps the sandbox from
/// drifting into a test-only shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// The embedded bootstrap, the module Deno runs.
    pub bootstrap: PathBuf,
    /// The step's own module, inside the workspace.
    pub script: PathBuf,
    /// `describe` or `run`.
    pub mode: Mode,
    /// Exactly what the child may read: the workspace, the bootstrap, and (in
    /// `run`) the secret FIFO.
    pub read_grants: Vec<PathBuf>,
    /// Paths the child may not read whatever `--allow-read` says, and Deno
    /// applies these over it: the links inside the workspace whose targets are
    /// outside it. Empty means no `--deny-read` at all.
    pub deny_read: Vec<PathBuf>,
    /// The hosts the step declared. Empty means no `--allow-net` at all.
    pub net_grants: Vec<String>,
    /// How dependencies are pinned.
    pub manifest: Manifest,
    /// The secret FIFO, in `run` only.
    pub secrets: Option<PathBuf>,
}

impl Invocation {
    /// The child's argv, built here and nowhere else.
    pub fn argv(&self) -> Vec<OsString> {
        let mut argv = vec![
            OsString::from("run"),
            // No update check, no banners, no TTY escapes: stdout is a wire.
            OsString::from("--quiet"),
            // A missing permission is an error, never a prompt on a pipe.
            OsString::from("--no-prompt"),
            OsString::from(format!("--seed={SEED}")),
        ];
        match &self.manifest {
            Manifest::None => {
                argv.push(OsString::from("--no-config"));
                argv.push(OsString::from("--no-lock"));
                argv.push(OsString::from("--no-remote"));
                argv.push(OsString::from("--no-npm"));
            }
            Manifest::Locked { config, lock } => {
                if let Some(config) = config {
                    argv.push(OsString::from("--config"));
                    argv.push(config.into());
                }
                argv.push(OsString::from(format!("--lock={}", lock.display())));
                argv.push(OsString::from("--frozen-lockfile"));
            }
        }
        // `--allow-read` is variadic, so it is passed as one `=` argument:
        // a separate value would let it swallow the module path after it.
        let mut read_grant = OsString::from("--allow-read=");
        for (index, path) in self.read_grants.iter().enumerate() {
            if index > 0 {
                read_grant.push(",");
            }
            read_grant.push(path);
        }
        argv.push(read_grant);
        // One `=` argument for the same reason, and because Deno keeps only
        // the last of a repeated flag rather than adding to it: the deny list
        // has to be a single argument or the first entries would be dropped.
        if !self.deny_read.is_empty() {
            let mut deny = OsString::from("--deny-read=");
            for (index, path) in self.deny_read.iter().enumerate() {
                if index > 0 {
                    deny.push(",");
                }
                deny.push(path);
            }
            argv.push(deny);
        }
        if !self.net_grants.is_empty() {
            argv.push(OsString::from(format!("--allow-net={}", self.net_grants.join(","))));
        }
        argv.push(self.bootstrap.clone().into());
        argv.push(OsString::from(self.mode.as_str()));
        argv.push(self.script.clone().into());
        if let Some(secrets) = &self.secrets {
            argv.push(secrets.clone().into());
        }
        argv
    }
}

/// Where a step's `ctx.log(level, message)` lines go, already redacted.
type LogSink = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// A [`ScriptHost`] running steps in the pinned Deno.
pub struct DenoScriptHost {
    workspace: PathBuf,
    cache_root: Option<PathBuf>,
    deno: Option<PathBuf>,
    fetch: Arc<dyn Fetcher>,
    log_sink: Option<LogSink>,
}

impl DenoScriptHost {
    /// A host for scripts under `workspace`, installing the pinned Deno into
    /// `$XDG_CACHE_HOME/keepshipping/deno`, the first time it needs it.
    ///
    /// # Errors
    ///
    /// If `workspace` does not exist or is not a directory, and if the
    /// platform is not linux-x86_64.
    pub fn new(workspace: impl Into<PathBuf>) -> Result<DenoScriptHost, ScriptHostError> {
        install::check_platform()?;
        let workspace = workspace.into();
        let workspace = workspace.canonicalize().map_err(|error| ScriptHostError::Protocol {
            message: format!(
                "the workspace root {} cannot be resolved: {error}",
                workspace.display()
            ),
        })?;
        if !workspace.is_dir() {
            return Err(ScriptHostError::Protocol {
                message: format!("the workspace root {} is not a directory", workspace.display()),
            });
        }
        Ok(DenoScriptHost {
            workspace,
            cache_root: install::default_cache_root(),
            deno: None,
            fetch: Arc::new(CurlFetcher),
            log_sink: None,
        })
    }

    /// Uses `root` as the cache, instead of the default one.
    pub fn with_cache_root(mut self, root: impl Into<PathBuf>) -> DenoScriptHost {
        self.cache_root = Some(root.into());
        self
    }

    /// Runs `deno` instead of installing the pinned one. For a machine that
    /// already has it, and for tests.
    pub fn with_deno_path(mut self, path: impl Into<PathBuf>) -> DenoScriptHost {
        self.deno = Some(path.into());
        self
    }

    /// Fetches the release archive with `fetch` instead of `curl`.
    pub fn with_fetcher(mut self, fetch: Arc<dyn Fetcher>) -> DenoScriptHost {
        self.fetch = fetch;
        self
    }

    /// Hands every `ctx.log(level, msg)` line to `sink`, already redacted.
    /// Without one, log lines are discarded: they are the step's words, and
    /// the port has nowhere to put them yet.
    pub fn with_log_sink(
        mut self,
        sink: impl Fn(&str, &str) + Send + Sync + 'static,
    ) -> DenoScriptHost {
        self.log_sink = Some(Arc::new(sink));
        self
    }

    /// The platform this adapter reports.
    pub fn platform(&self) -> &'static str {
        install::platform()
    }

    /// The workspace root, canonicalised.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// The cache directory this host installs into.
    fn cache_root(&self) -> Result<&Path, ScriptHostError> {
        self.cache_root.as_deref().ok_or_else(|| ScriptHostError::Protocol {
            message: "no cache directory: set $XDG_CACHE_HOME or $HOME, or call with_cache_root"
                .to_string(),
        })
    }

    /// The Deno to run, installing the pinned one if needed.
    fn deno(&self) -> Result<PathBuf, ScriptHostError> {
        if let Some(deno) = &self.deno {
            return Ok(deno.clone());
        }
        let root = self.cache_root()?;
        install::ensure(root, self.fetch.as_ref())
    }

    /// Writes the embedded bootstrap next to the Deno, if it is not already
    /// there byte for byte.
    fn bootstrap(&self) -> Result<PathBuf, ScriptHostError> {
        let root = self.cache_root()?;
        let directory = install::host_dir(root);
        let path = directory.join("bootstrap.ts");
        let current = std::fs::read(&path).ok();
        if current.as_deref() == Some(BOOTSTRAP.as_bytes()) {
            return Ok(path);
        }
        std::fs::create_dir_all(&directory)
            .map_err(install::io_error("could not create the Deno host directory", &directory))?;
        // Unique per call, not just per process: two hosts in one process — a
        // test binary, a server with two workspaces — would otherwise race for
        // the same temporary and one would rename it out from under the other.
        let temporary = directory.join(format!(
            "bootstrap.{}.{}.tmp",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&temporary, BOOTSTRAP)
            .and_then(|()| std::fs::rename(&temporary, &path))
            .map_err(|error| {
                let _ = std::fs::remove_file(&temporary);
                ScriptHostError::Protocol {
                    message: format!(
                        "could not install the script bootstrap at {}: {error}",
                        path.display()
                    ),
                }
            })?;
        Ok(path)
    }

    /// The step's module, which has to be inside the workspace: a step is
    /// something a repository ships, and `--allow-read` covers nothing else.
    fn script_path(&self, script: &ScriptRef) -> Result<PathBuf, ScriptHostError> {
        let path = self.workspace.join(script.path());
        let resolved = path.canonicalize().map_err(|error| ScriptHostError::Protocol {
            message: format!("the script {} cannot be resolved: {error}", path.display()),
        })?;
        if !resolved.starts_with(&self.workspace) {
            return Err(ScriptHostError::Protocol {
                message: format!(
                    "the script {} resolves to {}, outside the workspace {}",
                    script,
                    resolved.display(),
                    self.workspace.display()
                ),
            });
        }
        Ok(resolved)
    }

    /// What a step beside `script` is allowed to depend on, and which file
    /// pins it.
    fn manifest(script: &Path) -> Result<Manifest, ScriptHostError> {
        let beside = script.parent().unwrap_or(Path::new("."));
        let config = ["deno.json", "deno.jsonc"]
            .iter()
            .map(|name| beside.join(name))
            .find(|candidate| candidate.is_file());
        let has_manifest = config.is_some() || beside.join("package.json").is_file();
        if !has_manifest {
            return Ok(Manifest::None);
        }
        let lock = beside.join("deno.lock");
        if !lock.is_file() {
            return Err(ScriptHostError::Protocol {
                message: format!(
                    "{} is beside a deno.json/package.json, so it must have a deno.lock beside it \
                     too — an unlocked step may not resolve anything",
                    script.display()
                ),
            });
        }
        Ok(Manifest::Locked { config, lock })
    }

    /// The step's declared schema *and* the net hosts it declared: `run` needs
    /// both, and the schema alone is what `check` sees.
    fn describe(&self, script: &ScriptRef) -> Result<(StepSchema, Vec<String>), ScriptHostError> {
        let invocation = self.invocation(script, Mode::Describe, None, &[])?;
        let frames = self.spawn(&invocation, None, &Redactor::new())?;
        let described = frames.describe.ok_or_else(|| ScriptHostError::Protocol {
            message: "the script described nothing: expected one {\"describe\":{...}} line"
                .to_string(),
        })?;
        let mut schema = StepSchema::default();
        for (side, into) in [("inputs", &mut schema.inputs), ("outputs", &mut schema.outputs)] {
            let declared = described.get(side).ok_or_else(|| ScriptHostError::Protocol {
                message: format!("the script's description has no {side:?}"),
            })?;
            let fields = declared.as_object().ok_or_else(|| ScriptHostError::Protocol {
                message: format!("the script's declared {side} is not an object"),
            })?;
            for (name, kind) in fields {
                let kind = kind.as_str().ok_or_else(|| ScriptHostError::Protocol {
                    message: format!("the declared type of {side} field {name:?} is not a string"),
                })?;
                // An unknown type name is a schema nobody can satisfy, and
                // `InvalidSchema` is the port's way of saying exactly that.
                let value_type = value_type(kind)
                    .ok_or_else(|| ScriptHostError::InvalidSchema { name: name.clone() })?;
                into.insert(name.clone(), value_type);
            }
        }
        let net = match described.get("net") {
            None => Vec::new(),
            Some(list) => {
                let list = list.as_array().ok_or_else(|| ScriptHostError::Protocol {
                    message: "the script's declared net is not a list".to_string(),
                })?;
                list.iter()
                    .map(|host| {
                        host.as_str().map(str::to_string).ok_or_else(|| ScriptHostError::Protocol {
                            message: "a declared net host is not a string".to_string(),
                        })
                    })
                    .collect::<Result<Vec<String>, ScriptHostError>>()?
            }
        };
        Ok((schema, net))
    }

    /// The full description of one child process.
    ///
    /// Public because it is the whole sandbox: `argv` is where every grant a
    /// step gets is decided, and a test that could read an `Invocation` off a
    /// host would not have to spawn Deno to check what that sandbox says.
    pub fn invocation(
        &self,
        script: &ScriptRef,
        mode: Mode,
        secrets: Option<&Path>,
        net: &[String],
    ) -> Result<Invocation, ScriptHostError> {
        let bootstrap = self.bootstrap()?;
        let mut read_grants = vec![self.workspace.clone(), bootstrap.clone()];
        if let Some(secrets) = secrets {
            read_grants.push(secrets.to_path_buf());
        }
        // Here rather than in `spawn`, because that is the only place the scan
        // cannot be forgotten: the deny list is part of the argv, so a child
        // spawned without one was never described.
        let deny_read = self.escaping_links()?;
        let script = self.script_path(script)?;
        let manifest = Self::manifest(&script)?;
        Ok(Invocation {
            bootstrap,
            script,
            mode,
            read_grants,
            deny_read,
            net_grants: net.to_vec(),
            manifest,
            secrets: secrets.map(Path::to_path_buf),
        })
    }

    /// The workspace paths a step may not read, because a symlink there leaves
    /// the workspace.
    ///
    /// `--allow-read=<workspace>` is checked by Deno against the path the step
    /// *names*, not against the file behind it (measured on 2.9.7:
    /// `readTextFileSync("keys/id_ed25519")` reads the key, while the key's own
    /// path is `NotCapable`). So these are returned as `--deny-read` grants,
    /// which Deno applies *over* `--allow-read`, and the step runs with the
    /// link refused. Refusing the run instead would have been simpler and wrong:
    /// `.venv/bin/python3 -> /usr/bin/python3`, a pnpm store behind
    /// `node_modules/.bin`, and the `.bin` entries a half-finished `npm install`
    /// leaves dangling are all links that leave, and all of them are what an
    /// ordinary repository looks like.
    ///
    /// What is returned is the link *as named inside the workspace*, not the
    /// target behind it: that is the path Deno checks, and the target is already
    /// unreachable through the workspace grant itself.
    ///
    /// Conservative where it cannot tell. A link that does not resolve — a
    /// dangling target, a loop — is returned too: denying a path that leads
    /// nowhere costs nothing, and the alternative is guessing what a target
    /// that cannot be read now might become later. A directory that cannot be
    /// enumerated is returned for the same reason: refusing the whole step over
    /// one unreadable directory would be a denial of service, and denying it
    /// denies exactly what nobody could vouch for.
    ///
    /// What this is not: it walks symlinks, so a hardlink to `/etc/shadow` or a
    /// bind mount under the workspace is not in this list; and it runs before
    /// the child, not atomically with it, so a link swapped in afterwards is
    /// not either. It closes the ordinary hole; it does not make a workspace
    /// that an attacker is writing to concurrently into a sandbox.
    ///
    /// The walk is not bounded. It costs one `read_dir` per directory and one
    /// `canonicalize` per link, which is cheap next to the Deno process it
    /// guards, and a workspace big enough to hurt is also a workspace whose
    /// escape the run should not be making on the strength of a limit.
    fn escaping_links(&self) -> Result<Vec<PathBuf>, ScriptHostError> {
        let mut denied: BTreeSet<PathBuf> = BTreeSet::new();
        let mut directories = vec![self.workspace.clone()];
        while let Some(directory) = directories.pop() {
            // A directory the adapter cannot read is one it cannot enumerate, so
            // it cannot say what is inside it. Skipping it would let the very
            // escape it is looking for through the one hole nobody looked into;
            // refusing the step over it would let anyone with one unreadable
            // directory stop every run in the repository. Denying it is what is
            // left, and it is exactly the set nobody could vouch for.
            let entries = match std::fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(_) => {
                    denied.insert(self.deniable(&directory)?);
                    continue;
                }
            };
            for entry in entries {
                let Ok(entry) = entry else {
                    denied.insert(self.deniable(&directory)?);
                    break;
                };
                // `file_type` reads the entry itself: a symlink is a leaf here,
                // never a directory to descend into, so the walk cannot loop
                // even though a link could point back up the tree. An entry
                // that will not say is an un-enumerated directory again.
                let Ok(kind) = entry.file_type() else {
                    denied.insert(self.deniable(&directory)?);
                    break;
                };
                if kind.is_dir() {
                    directories.push(entry.path());
                    continue;
                }
                if !kind.is_symlink() {
                    continue;
                }
                let path = entry.path();
                // `canonicalize` resolves every component, link by link, so a
                // chain that leaves the workspace cannot stop halfway looking
                // innocent. It fails on a dangling target and on a loop; either
                // way the link is denied rather than trusted.
                match path.canonicalize() {
                    Ok(target) if target.starts_with(&self.workspace) => {}
                    // It escapes, or it does not resolve at all. Both are the
                    // same answer: deny the link.
                    _ => {
                        denied.insert(self.deniable(&path)?);
                    }
                }
            }
        }
        Ok(denied.into_iter().collect())
    }

    /// `path` as a `--deny-read` grant, or the refusal for one that has no
    /// spelling.
    ///
    /// Deno's grant list is comma-separated and has no escaping, takes no globs,
    /// and repeating the flag keeps only the last occurrence — all three
    /// measured on 2.9.7, and all three fatal to any way of spelling a path
    /// with a comma in it. Denying an ancestor instead does not help: the comma
    /// is in the ancestor too, so it is in the descendant's whole path either
    /// way. Nor does denying the workspace root, which would take the step's own
    /// module down with the link.
    ///
    /// That leaves refusing, which is the one thing here that still stops a
    /// step, and it should: there is no grant to hand over, and a silently
    /// dropped path would be a hole wearing the shape of a fix.
    fn deniable(&self, path: &Path) -> Result<PathBuf, ScriptHostError> {
        if !path.to_string_lossy().contains(',') {
            return Ok(path.to_path_buf());
        }
        Err(ScriptHostError::Protocol {
            message: format!(
                "the workspace link {} cannot be denied: --deny-read takes a comma-separated \
                 list with no escaping, and this path has a comma in it. Nothing was run",
                path.display()
            ),
        })
    }

    /// Runs one child and reads its frames back. `inputs` goes to stdin, and
    /// everything the step wrote — its stderr tail included — is scrubbed by
    /// `redactor` before it leaves this function.
    fn spawn(
        &self,
        invocation: &Invocation,
        inputs: Option<&str>,
        redactor: &Redactor,
    ) -> Result<Frames, ScriptHostError> {
        // Every child this adapter starts was described by `invocation` first,
        // which is where the workspace was walked and the escaping links turned
        // into `--deny-read`. Nothing is left to check here: the argv *is* the
        // check, and it is the argv that gets spawned.
        let deno = self.deno()?;
        let mut command = std::process::Command::new(deno);
        command.args(invocation.argv());
        command.current_dir(&self.workspace);
        // The step's whole world: no inherited environment, no colour, a fixed
        // clock and locale, and a module cache of our own. Nothing here tells
        // Deno about a permission.
        command.env_clear();
        command.env("DENO_DIR", install::deno_dir(self.cache_root()?));
        command.env("DENO_NO_UPDATE_CHECK", "1");
        command.env("NO_COLOR", "1");
        command.env("TZ", "UTC");
        command.env("LANG", "C.UTF-8");
        command.stdin(if inputs.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        });
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());

        let mut child = command.spawn().map_err(|error| ScriptHostError::Protocol {
            message: format!("could not start the Deno runtime: {error}"),
        })?;
        if let Some(inputs) = inputs {
            use std::io::Write as _;
            let mut stdin = child.stdin.take().ok_or_else(|| ScriptHostError::Protocol {
                message: "the Deno process has no stdin".to_string(),
            })?;
            // A step that dies before reading gets EPIPE here; that is the
            // step's failure, not ours, so it is left for the exit status.
            let _ = stdin.write_all(inputs.as_bytes());
        }
        let output = child.wait_with_output().map_err(|error| ScriptHostError::Protocol {
            message: format!("the Deno process could not be waited on: {error}"),
        })?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            let bytes = stderr.as_bytes();
            let start = bytes.len().saturating_sub(STDERR_TAIL);
            let tail = String::from_utf8_lossy(&bytes[start..]).into_owned();
            return Err(ScriptHostError::ScriptFailed {
                exit_code: output.status.code(),
                message: redactor.redact(&tail),
            });
        }
        let mut frames = Frames::default();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.trim().is_empty() {
                continue;
            }
            frames.push(line)?;
        }
        Ok(frames)
    }
}

impl std::fmt::Debug for DenoScriptHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DenoScriptHost")
            .field("workspace", &self.workspace)
            .field("cache_root", &self.cache_root)
            .field("deno", &self.deno)
            .finish()
    }
}

impl ScriptHost for DenoScriptHost {
    fn schema<'a>(
        &'a self,
        script: &'a ScriptRef,
    ) -> BoxFuture<'a, Result<StepSchema, ScriptHostError>> {
        let result = self.describe(script).map(|(schema, _)| schema);
        Box::pin(std::future::ready(result))
    }

    fn run<'a>(
        &'a self,
        script: &'a ScriptRef,
        inputs: &'a Values,
        secrets: &'a SecretBundle,
    ) -> BoxFuture<'a, Result<Values, ScriptHostError>> {
        let result = self.run_step(script, inputs, secrets);
        Box::pin(std::future::ready(result))
    }
}

impl DenoScriptHost {
    /// `run`, synchronously: describe, validate, then spawn.
    fn run_step(
        &self,
        script: &ScriptRef,
        inputs: &Values,
        secrets: &SecretBundle,
    ) -> Result<Values, ScriptHostError> {
        let (schema, net) = self.describe(script)?;
        // Before the process starts: a script that was never legally invoked
        // cannot have failed, and the conformance kit says so.
        schema.validate_inputs(inputs)?;

        let mut redactor = Redactor::new();
        for (_, value) in secrets.iter() {
            redactor.register(value);
        }
        let channel = if secrets.names().next().is_some() {
            Some(channel::SecretChannel::open(secrets)?)
        } else {
            None
        };
        let fifo = channel.as_ref().map(channel::SecretChannel::path);
        let invocation = self.invocation(script, Mode::Run, fifo, &net)?;
        let wire = serde_json::to_string(&json::values_to_json(inputs)).map_err(|error| {
            ScriptHostError::Protocol {
                message: format!("the inputs could not be encoded as JSON: {error}"),
            }
        })?;
        let frames = self.spawn(&invocation, Some(&wire), &redactor)?;

        if let Some(sink) = &self.log_sink {
            for line in frames.logs {
                sink(&redactor.redact(&line.0), &redactor.redact(&line.1));
            }
        }
        let Some(output) = frames.output else {
            return Err(ScriptHostError::Protocol {
                message: "the script wrote no {\"output\":{...}} line".to_string(),
            });
        };
        let outputs = json::values_from_json(&output).ok_or_else(|| ScriptHostError::Protocol {
            message: "the script's output frame does not hold an object".to_string(),
        })?;
        schema.validate_outputs(&outputs)?;
        Ok(outputs)
    }
}

/// Every frame a step wrote, parsed.
#[derive(Debug, Default)]
struct Frames {
    describe: Option<serde_json::Value>,
    logs: Vec<(String, String)>,
    output: Option<serde_json::Value>,
}

impl Frames {
    /// Takes one stdout line. Anything that is not a log or output frame is a
    /// protocol violation: a step's stray `console.log` must not look like
    /// data.
    fn push(&mut self, line: &str) -> Result<(), ScriptHostError> {
        let frame: serde_json::Value =
            serde_json::from_str(line).map_err(|error| ScriptHostError::Protocol {
                message: format!("the script wrote a line that is not JSON: {error}"),
            })?;
        let Some(object) = frame.as_object() else {
            return Err(ScriptHostError::Protocol {
                message: format!("the script wrote a JSON {line}, which is not a frame object"),
            });
        };
        if object.len() != 1 {
            return Err(ScriptHostError::Protocol {
                message: format!(
                    "the script wrote a frame with {} keys, expected one",
                    object.len()
                ),
            });
        }
        let (kind, body) = object.iter().next().expect("one key");
        match kind.as_str() {
            "describe" => self.describe = Some(body.clone()),
            "output" => {
                if self.output.is_some() {
                    return Err(ScriptHostError::Protocol {
                        message: "the script wrote more than one output frame".to_string(),
                    });
                }
                self.output = Some(body.clone());
            }
            "log" => {
                let level = body.get("level").and_then(|level| level.as_str()).unwrap_or("info");
                let message =
                    body.get("msg").and_then(|msg| msg.as_str()).unwrap_or_default().to_string();
                self.logs.push((level.to_string(), message));
            }
            other => {
                return Err(ScriptHostError::Protocol {
                    message: format!("the script wrote an unknown {other:?} frame"),
                });
            }
        }
        Ok(())
    }
}

/// The declared type names a step may use. `null` is deliberately absent: a
/// null satisfies no contract, and the port's validators already say so.
fn value_type(declared: &str) -> Option<ValueType> {
    match declared {
        "string" => Some(ValueType::String),
        "number" => Some(ValueType::Number),
        "bool" => Some(ValueType::Bool),
        "list" => Some(ValueType::List),
        "map" => Some(ValueType::Map),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// A frame a step may write, and nothing else may.
    fn frames_from(lines: &[&str]) -> Result<Frames, ScriptHostError> {
        let mut frames = Frames::default();
        for line in lines {
            frames.push(line)?;
        }
        Ok(frames)
    }

    #[test]
    fn logs_and_outputs_are_read_out_of_a_clean_run() {
        let frames =
            frames_from(&[r#"{"log":{"level":"info","msg":"hello"}}"#, r#"{"output":{"x":"ok"}}"#])
                .expect("a well-formed run");
        assert_eq!(frames.logs, vec![("info".to_string(), "hello".to_string())]);
        assert!(frames.output.is_some());
    }

    #[test]
    fn a_stray_line_is_a_protocol_violation() {
        for line in [
            "hello from console.log",
            "[1,2,3]",
            r#"{"log":{"level":"info","msg":"hi"},"output":{}}"#,
            r#"{"nope":1}"#,
        ] {
            let error = frames_from(&[line]).expect_err("only log and output frames are legal");
            assert!(matches!(error, ScriptHostError::Protocol { .. }), "{line}: {error}");
        }
    }

    #[test]
    fn two_output_frames_are_a_protocol_violation() {
        let error = frames_from(&[r#"{"output":{}}"#, r#"{"output":{}}"#])
            .expect_err("exactly one output frame");
        assert!(error.to_string().contains("more than one"), "{error}");
    }

    /// The gate on every test below that builds a `DenoScriptHost`:
    /// `DenoScriptHost::new` refuses anything but linux-x86_64 as its first
    /// statement, so off that platform such a test asserts the platform check,
    /// or panics on an `expect` — and the two that use `expect_err` would pass
    /// on it without ever reaching the code they are named for. It is
    /// *gating*, not `#[ignore]`: `cargo test --workspace` on Linux still runs
    /// every one of them.
    ///
    /// The helper carries the same gate: off that platform nothing names it,
    /// and an unused function is a warning, and warnings are errors here.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("ks-deno-lib-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the scratch workspace is writable");
        std::fs::write(path.join("step.ts"), "export default {};").expect("the step is writable");
        path.canonicalize().expect("the scratch workspace resolves")
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn a_workspace_of_ordinary_files_denies_nothing() {
        let workspace = scratch("clean");
        std::fs::create_dir_all(workspace.join("scripts/deep/deeper")).expect("writable");
        std::fs::write(workspace.join("scripts/deep/deeper/deno.lock"), "{}\n").expect("writable");
        let host = DenoScriptHost::new(&workspace).expect("a workspace root");
        assert!(host.escaping_links().expect("the workspace is readable").is_empty());
        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn a_link_that_stays_inside_the_workspace_is_allowed() {
        let workspace = scratch("inward");
        let target = workspace.join("real.ts");
        std::fs::write(&target, "export default {};").expect("writable");
        std::os::unix::fs::symlink(&target, workspace.join("step-link.ts"))
            .expect("the link is writable");
        let host = DenoScriptHost::new(&workspace).expect("a workspace root");
        assert!(
            host.escaping_links().expect("a link within the workspace is not an escape").is_empty(),
            "nothing to deny, so no --deny-read at all"
        );
        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn a_link_out_of_the_workspace_is_denied_rather_than_refused() {
        // The regression: a stock `.venv` has `.venv/bin/python3 -> /usr/bin/python3`,
        // a pnpm store has `node_modules/.bin/*` pointing out of the tree, and a
        // half-finished `npm install` leaves `.bin` entries dangling. Refusing the
        // run over any of those is refusing to run the repository.
        let workspace = scratch("outward");
        let outside =
            std::env::temp_dir().join(format!("ks-deno-lib-outside-{}", std::process::id()));
        std::fs::write(&outside, "PRIVATE KEY").expect("the outside file is writable");
        let link = workspace.join("sh.ts");
        std::os::unix::fs::symlink(&outside, &link).expect("the link is writable");

        let host = DenoScriptHost::new(&workspace).expect("a workspace root");
        let denied = host.escaping_links().expect("the workspace is readable");
        assert_eq!(denied, vec![link], "the link is returned by the path Deno checks");
        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_file(&outside);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn a_link_that_cannot_be_resolved_is_denied_too() {
        // A dangling target and a loop: neither resolves inside the workspace,
        // and neither is something to guess about. Denying a path that leads
        // nowhere costs nothing, so they come back like any other escape.
        let workspace = scratch("unresolvable");
        let dangling = workspace.join("dangling.ts");
        std::os::unix::fs::symlink(workspace.join("nowhere.ts"), &dangling)
            .expect("the link is writable");
        let host = DenoScriptHost::new(&workspace).expect("a workspace root");
        assert_eq!(
            host.escaping_links().expect("the workspace is readable"),
            vec![dangling],
            "a dangling link is denied: the target it might become later is not this one's to guess"
        );

        let looped = scratch("looped");
        std::os::unix::fs::symlink(looped.join("b"), looped.join("a"))
            .expect("the link is writable");
        std::os::unix::fs::symlink(looped.join("a"), looped.join("b"))
            .expect("the link is writable");
        let host = DenoScriptHost::new(&looped).expect("a workspace root");
        assert_eq!(
            host.escaping_links().expect("the workspace is readable"),
            vec![looped.join("a"), looped.join("b")],
            "a link loop does not resolve either, and neither member of it is trusted"
        );

        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&looped);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn a_link_with_no_spelling_as_a_deny_grant_is_the_one_thing_refused() {
        // `--deny-read` is a comma-separated list with no escaping, so a path
        // with a comma in it cannot be named at all — not by an ancestor, which
        // has the same comma, and not by the workspace root, which would take
        // the step's own module down with it. That leaves refusing, and quietly
        // dropping the path would be a hole rather than a fix.
        let workspace = scratch("comma");
        let awkward = workspace.join("odd,name");
        std::fs::create_dir_all(&awkward).expect("writable");
        let outside = std::env::temp_dir().join(format!("ks-deno-comma-{}", std::process::id()));
        std::fs::write(&outside, "PRIVATE KEY").expect("the outside file is writable");
        std::os::unix::fs::symlink(&outside, awkward.join("key")).expect("the link is writable");

        let host = DenoScriptHost::new(&workspace).expect("a workspace root");
        let error = host.escaping_links().expect_err("there is no grant that names this path");
        assert!(error.to_string().contains("cannot be denied"), "{error}");
        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_file(&outside);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn a_link_back_up_the_tree_does_not_send_the_walk_round_in_circles() {
        // The walk treats a symlink as a leaf, so a link pointing at an
        // ancestor is checked once and never descended into.
        let workspace = scratch("upward");
        let nested = workspace.join("a/b");
        std::fs::create_dir_all(&nested).expect("writable");
        std::os::unix::fs::symlink(&workspace, nested.join("loop")).expect("the link is writable");
        let host = DenoScriptHost::new(&workspace).expect("a workspace root");
        assert!(
            host.escaping_links().expect("the link resolves inside the workspace").is_empty(),
            "it resolves to the workspace root, which is inside it"
        );
        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[test]
    fn only_the_port_value_types_are_declarable() {
        for (declared, expected) in [
            ("string", ValueType::String),
            ("number", ValueType::Number),
            ("bool", ValueType::Bool),
            ("list", ValueType::List),
            ("map", ValueType::Map),
        ] {
            assert_eq!(value_type(declared), Some(expected));
        }
        for unknown in ["null", "any", "", "String"] {
            assert_eq!(value_type(unknown), None, "{unknown} is not a contract");
        }
    }
}
