//! An [`IacTool`] adapter for the user's own OpenTofu and Terraform binaries
//! ([#69](https://github.com/Keep-Shipping/harness/issues/69)). One adapter
//! drives both: [`IacCli`] is built for an [`IacKind`], so `tofu.*` steps run
//! `tofu` and `terraform.*` steps run `terraform`. **We never download,
//! bundle or redistribute Terraform** (BUSL-1.1) — the harness invokes the
//! binary the user already has, which is why its path is a constructor
//! argument rather than a constant.
//!
//! The port's rules are enforced here: `plan` writes a saved plan under
//! `<dir>/.ks/` and returns its sha256, and `show` and `apply` both re-hash
//! that file before reading it. A saved plan is secretish — it carries the
//! passwords an apply is about to materialise — so it is written owner-only
//! into an owner-only directory, and it is deleted once the apply it was made
//! for has succeeded. **Variables travel only as `TF_VAR_*`
//! environment entries**, never as `-var` arguments: a value must never
//! appear in `argv`, where every process can read it. Every command runs
//! non-interactively — nobody is there to answer a prompt.
//!
//! The port is async but the work is a subprocess: each method blocks its
//! thread inside the returned future, acceptable because the engine drives
//! one step per worker and the tool is the bottleneck anyway.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ks_core::ports::BoxFuture;
use ks_core::ports::iac::{
    ApplyResult, Backend, ChangeAction, IacError, IacKind, IacTool, OutputValue, Outputs, PlanJson,
    ResourceChange, SavedPlan, ToolInfo,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Where saved plans live inside the configured directory. `apply` is handed
/// only a plan, so this directory's *parent* is the working directory the
/// plan belongs to — the way back to its workspace and backend.
const PLAN_DIR: &str = ".ks";

/// Owner-only, read and write. A saved plan carries the generated passwords an
/// apply is about to materialise, in cleartext.
const PLAN_FILE_MODE: u32 = 0o600;

/// Owner-only, so the plan names inside are not enumerable either.
const PLAN_DIR_MODE: u32 = 0o700;

/// How many plans this process has written; part of the plan file's name.
static PLANS_WRITTEN: AtomicU64 = AtomicU64::new(0);

/// Both tools' text for a saved plan that no longer matches the state.
const STALE_PLAN: &str = "Saved plan is stale";

/// Both tools' text for losing the race for the state lock.
const LOCKED: &str = "Error acquiring the state lock";

/// No variables to pass: the commands that take none.
const NO_ENV: BTreeMap<String, String> = BTreeMap::new();

/// An [`IacTool`] that shells out to the `tofu` or `terraform` binary.
///
/// ```no_run
/// use ks_core::ports::iac::{IacKind, IacTool};
/// use ks_tofu_cli::IacCli;
///
/// // `for_kind` probes `tofu version -json` on `PATH`, so this needs the
/// // binary installed — the conformance tests take the path from an env var.
/// let tool = IacCli::for_kind(IacKind::OpenTofu)?;
/// assert_eq!(tool.tool().kind, IacKind::OpenTofu);
/// # Ok::<(), ks_core::ports::iac::IacError>(())
/// ```
#[derive(Debug, Clone)]
pub struct IacCli {
    kind: IacKind,
    bin: PathBuf,
    version: String,
    workspace: Option<String>,
    var_files: Vec<PathBuf>,
}

impl IacCli {
    /// Probes `bin` with `version -json` and records its version.
    pub fn new(kind: IacKind, bin: impl Into<PathBuf>) -> Result<IacCli, IacError> {
        let bin = bin.into();
        let version = version_of(&bin)?;
        Ok(IacCli { kind, bin, version, workspace: None, var_files: Vec::new() })
    }

    /// The default binary for `kind` (`tofu` / `terraform`) on `PATH`.
    pub fn for_kind(kind: IacKind) -> Result<IacCli, IacError> {
        let bin = match kind {
            IacKind::OpenTofu => "tofu",
            IacKind::Terraform => "terraform",
        };
        IacCli::new(kind, bin)
    }

    /// Plans and applies in `name`, creating it if absent. The selection
    /// lives in the directory's own state, so a later `apply` lands there.
    pub fn workspace(mut self, name: impl Into<String>) -> IacCli {
        self.workspace = Some(name.into());
        self
    }

    /// Adds a `-var-file` to every `plan`. Repeatable; the tool reads the
    /// file, not us, so nothing lands in `argv` but the path.
    pub fn var_file(mut self, path: impl Into<PathBuf>) -> IacCli {
        self.var_files.push(path.into());
        self
    }

    /// Where a saved plan lives, as the tool must be told: the `.ks`
    /// directory's parent, and the plan named relative to it. That directory
    /// alone is how `show` and `apply`, handed nothing but a [`SavedPlan`],
    /// recover the working directory. The name is rebuilt rather than reusing
    /// the caller's path — a relative `dir` would resolve twice, wrongly.
    fn locate(plan: &SavedPlan) -> Result<(&Path, String), IacError> {
        let parent = plan.path().parent();
        let dir = parent
            .filter(|parent| parent.file_name().is_some_and(|name| name == PLAN_DIR))
            .and_then(Path::parent)
            .ok_or_else(|| IacError::Tool {
                message: format!(
                    "plan file {} is not in a `{PLAN_DIR}/` directory, so the directory it \
                     belongs to cannot be recovered",
                    plan.path().display()
                ),
                exit_code: None,
            })?;
        let arg = match plan.path().file_name() {
            Some(name) => format!("{PLAN_DIR}/{}", name.to_string_lossy()),
            None => plan.path().display().to_string(),
        };
        Ok((dir, arg))
    }

    /// Runs the tool in `dir` and returns its stdout.
    fn run(
        &self,
        dir: &Path,
        args: &[String],
        env: &BTreeMap<String, String>,
    ) -> Result<String, IacError> {
        let outcome = self.spawn(dir, args, env)?;
        if outcome.status.success() {
            return Ok(String::from_utf8_lossy(&outcome.stdout).into_owned());
        }
        Err(tool_error(&outcome))
    }

    /// Runs the tool and reports everything it produced, failing runs
    /// included: `apply -json` narrates on stdout, not stderr.
    fn spawn(
        &self,
        dir: &Path,
        args: &[String],
        env: &BTreeMap<String, String>,
    ) -> Result<Output, IacError> {
        let mut command = Command::new(&self.bin);
        command.args(args).current_dir(dir);
        command.env("TF_IN_AUTOMATION", "1").envs(env);
        command.output().map_err(|error| IacError::Tool {
            message: format!("could not run {}: {error}", self.bin.display()),
            exit_code: None,
        })
    }

    /// `init` against `backend`, then select the workspace, then `plan -out`
    /// and hash what it wrote — the tool's order, since a workspace exists
    /// only after `init` and the plan must be made where it will apply.
    fn init_and_plan(
        &self,
        dir: &Path,
        vars: &BTreeMap<String, String>,
        backend: &Backend,
    ) -> Result<SavedPlan, IacError> {
        // `local` is the default backend and takes no configuration; any
        // other is configured on the command line, in sorted key order.
        let mut init = argv(&["init", "-no-color", "-input=false"]);
        if backend.kind != "local" {
            for (key, value) in &backend.config {
                init.push(format!("-backend-config={key}={value}"));
            }
        }
        self.run(dir, &init, &NO_ENV)?;

        if let Some(workspace) = &self.workspace {
            self.run(
                dir,
                &argv(&["workspace", "select", "-no-color", "-or-create", workspace]),
                &NO_ENV,
            )?;
        }

        // Environment only: `-var` would put a value in `argv`, where every
        // process on the machine can read it.
        let plan_env: BTreeMap<String, String> =
            vars.iter().map(|(name, value)| (format!("TF_VAR_{name}"), value.clone())).collect();

        let file = plan_file(dir)?;
        let mut plan =
            argv(&["plan", "-no-color", "-input=false", &format!("-out={}", file.display())]);
        plan.extend(self.var_files.iter().map(|path| format!("-var-file={}", path.display())));
        self.run(dir, &plan, &plan_env)?;

        // The tool has written it and nobody else has read it: tighten before
        // hashing, so the digest covers exactly the bytes that were secured.
        restrict(&file, PLAN_FILE_MODE);

        let digest = sha256_of(&file)?;
        SavedPlan::new(file, digest)
    }
}

/// The tool's argument list. Both tools are strict about the order: the
/// subcommand first, then its own flags, because `-no-color` and
/// `-input=false` are not global options — and `-input=false` is accepted
/// only by `init`, `plan` and `apply`, so each caller spells out its own.
fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_string()).collect()
}

/// A fresh absolute plan path under `<dir>/.ks/`, whose parent directory this
/// creates, owner-only before the tool is spawned into it. The clock plus a
/// counter keep two plans in the same second — or two runs at once — from
/// overwriting each other.
///
/// The file itself is **not** created here: the tool writes it, and we must not
/// pre-create or truncate the tool's output. `init_and_plan` tightens it once
/// the tool has written it.
fn plan_file(dir: &Path) -> Result<PathBuf, IacError> {
    let plans = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf()).join(PLAN_DIR);
    std::fs::create_dir_all(&plans).map_err(|error| IacError::Tool {
        message: format!("could not create {}: {error}", plans.display()),
        exit_code: None,
    })?;
    // Tightened here, not after the write: the tool has to be able to create a
    // file inside this directory, and a directory another local user can list
    // is a window even for a file whose own mode is owner-only.
    restrict(&plans, PLAN_DIR_MODE);
    let nanos =
        SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_nanos()).unwrap_or(0);
    let count = PLANS_WRITTEN.fetch_add(1, Ordering::Relaxed);
    Ok(plans.join(format!("plan-{nanos}-{count}.tfplan")))
}

/// Tightens `path` to `mode`, leaving its bytes alone: the digest must cover
/// exactly what the tool wrote, so the file is never reopened for this.
///
/// A failure is not fatal — the plan is still the tool's to write, and a
/// filesystem that cannot carry a mode bit has its own answer to the
/// customer's umask. On a platform with no unix modes this does nothing, so a
/// Windows build still compiles.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) {}

/// Removes a saved plan whose apply has succeeded. A file that is already gone
/// is not a failure: somebody may have cleaned up first, and the outcome we
/// wanted is the one we have.
///
/// Only ever the file. `<dir>/.ks/` is the customer's directory and may hold
/// their own plans.
fn discard(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// The file's sha256, 64 lowercase hex digits — what [`SavedPlan::new`] wants.
fn sha256_of(path: &Path) -> Result<String, IacError> {
    let bytes = std::fs::read(path).map_err(|error| IacError::Tool {
        message: format!("could not read plan file {}: {error}", path.display()),
        exit_code: None,
    })?;
    Ok(Sha256::digest(&bytes).iter().map(|byte| format!("{byte:02x}")).collect())
}

/// `version -json` for the tool at `bin`. A non-zero exit is a failure even
/// when stdout parses: that is not the tool we asked about.
fn version_of(bin: &Path) -> Result<String, IacError> {
    let probe =
        Command::new(bin).args(["version", "-json"]).output().map_err(|error| IacError::Tool {
            message: format!("could not run {} version -json: {error}", bin.display()),
            exit_code: None,
        })?;
    if !probe.status.success() {
        return Err(tool_error(&probe));
    }
    let stdout = String::from_utf8_lossy(&probe.stdout);
    let version = serde_json::from_str::<serde_json::Value>(&stdout)
        .ok()
        .and_then(|parsed| parsed.get("terraform_version")?.as_str().map(str::to_string));
    version.ok_or_else(|| IacError::Tool {
        message: format!("{} reported no terraform_version", bin.display()),
        exit_code: probe.status.code(),
    })
}

/// What the tool said, from whichever stream it used: `apply -json` puts
/// every diagnostic on stdout, so stderr alone would leave a failed apply
/// with no message at all.
fn diagnostics(outcome: &Output) -> String {
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    let text =
        if stderr.trim().is_empty() { String::from_utf8_lossy(&outcome.stdout) } else { stderr };
    text.trim().to_string()
}

/// Maps a failed run onto the port's errors: a lost state-lock race gets its
/// own message, everything else is the tool's trimmed text and exit code.
/// Nothing is dropped — an unexplained failure is worse than a wordy one.
/// What lands here is only what the tool printed; values we pass by
/// environment are never echoed by us.
fn tool_error(outcome: &Output) -> IacError {
    let text = diagnostics(outcome);
    let message = if text.is_empty() {
        "the tool failed without saying why".to_string()
    } else if text.contains(LOCKED) {
        format!("state is locked by another run: {text}")
    } else {
        text
    };
    IacError::Tool { message, exit_code: outcome.status.code() }
}

/// A JSON object field read as a bool, `false` when absent or not one.
fn field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// The port's "the tool's output made no sense" error.
fn unreadable(error: serde_json::Error) -> IacError {
    IacError::Tool {
        message: format!("could not read the tool's JSON output: {error}"),
        exit_code: None,
    }
}

/// Fails with [`IacError::PlanTampered`] unless the file still digests to
/// the value the plan was saved with.
fn verify_digest(plan: &SavedPlan) -> Result<(), IacError> {
    let actual = sha256_of(plan.path())?;
    if actual == plan.sha256() {
        return Ok(());
    }
    Err(IacError::PlanTampered { expected: plan.sha256().to_string(), actual })
}

/// One action name from the tool's JSON. Anything unrecognised counts as a
/// no-op, the honest reading of a plan that touches nothing.
fn action_of(name: &str) -> ChangeAction {
    match name {
        "create" => ChangeAction::Create,
        "read" => ChangeAction::Read,
        "update" => ChangeAction::Update,
        "delete" => ChangeAction::Delete,
        _ => ChangeAction::NoOp,
    }
}

impl IacTool for IacCli {
    fn plan<'a>(
        &'a self,
        dir: &'a Path,
        vars: &'a BTreeMap<String, String>,
        backend: &'a Backend,
    ) -> BoxFuture<'a, Result<SavedPlan, IacError>> {
        Box::pin(std::future::ready(self.init_and_plan(dir, vars, backend)))
    }

    fn show<'a>(&'a self, plan: &'a SavedPlan) -> BoxFuture<'a, Result<PlanJson, IacError>> {
        let result = (|| {
            verify_digest(plan)?;
            let (dir, file) = IacCli::locate(plan)?;
            let stdout = self.run(dir, &argv(&["show", "-no-color", "-json", &file]), &NO_ENV)?;
            parse_plan_json(&stdout)
        })();
        Box::pin(std::future::ready(result))
    }

    fn apply<'a>(&'a self, plan: &'a SavedPlan) -> BoxFuture<'a, Result<ApplyResult, IacError>> {
        let result = (|| {
            verify_digest(plan)?;
            let (dir, file) = IacCli::locate(plan)?;
            let outcome = self.spawn(
                dir,
                &argv(&["apply", "-no-color", "-input=false", "-json", &file]),
                &NO_ENV,
            )?;
            if !outcome.status.success() && diagnostics(&outcome).contains(STALE_PLAN) {
                return Err(IacError::StalePlan);
            }
            if !outcome.status.success() {
                return Err(tool_error(&outcome));
            }
            // Only once the apply has succeeded, and only once the summary has
            // been read: on a stale plan or a failed apply the file must
            // survive, because that is where the human looks before applying
            // anything else. A plan that already applied is a plan nobody needs.
            let summary = parse_change_summary(&String::from_utf8_lossy(&outcome.stdout))?;
            discard(plan.path());
            Ok(summary)
        })();
        Box::pin(std::future::ready(result))
    }

    fn outputs<'a>(&'a self, dir: &'a Path) -> BoxFuture<'a, Result<Outputs, IacError>> {
        let result = (|| {
            let stdout = self.run(dir, &argv(&["output", "-no-color", "-json"]), &NO_ENV)?;
            let parsed: serde_json::Value = serde_json::from_str(&stdout).map_err(unreadable)?;
            let mut outputs = Outputs::new();
            for (name, entry) in parsed.as_object().into_iter().flatten() {
                outputs.insert(
                    name.clone(),
                    OutputValue {
                        value: entry.get("value").map_or_else(String::new, Value::to_string),
                        sensitive: field(entry, "sensitive"),
                    },
                );
            }
            Ok(outputs)
        })();
        Box::pin(std::future::ready(result))
    }

    fn tool(&self) -> ToolInfo {
        ToolInfo { kind: self.kind, version: self.version.clone() }
    }
}

/// `resource_changes[].{address, change.actions}` into the port's typed shape.
/// A plan with nothing to do carries no `resource_changes` key at all, which
/// is an empty plan rather than a parse failure.
fn parse_plan_json(stdout: &str) -> Result<PlanJson, IacError> {
    let parsed: serde_json::Value = serde_json::from_str(stdout).map_err(unreadable)?;
    let empty = Vec::new();
    let entries = parsed.get("resource_changes").and_then(Value::as_array).unwrap_or(&empty);
    let changes = entries
        .iter()
        .filter_map(|entry| {
            let address = entry.get("address")?.as_str()?;
            let actions = entry.get("change")?.get("actions")?.as_array()?;
            let actions = actions.iter().filter_map(Value::as_str).map(action_of).collect();
            Some(ResourceChange { address: address.to_string(), actions })
        })
        .collect();
    Ok(PlanJson { changes })
}

/// The last `change_summary` in `apply -json`'s stream: one JSON object per
/// line, and only the last is the totals. An apply with no summary is a
/// failure to read, not an apply of nothing.
fn parse_change_summary(stdout: &str) -> Result<ApplyResult, IacError> {
    let mut summary = None;
    for line in stdout.lines() {
        let Ok(entry) = serde_json::from_str::<Value>(line) else { continue };
        if entry.get("type").and_then(serde_json::Value::as_str) != Some("change_summary") {
            continue;
        }
        let changes = entry.get("changes").unwrap_or(&Value::Null);
        let count = |key: &str| changes.get(key).and_then(Value::as_u64).unwrap_or(0) as usize;
        summary = Some(ApplyResult {
            added: count("add"),
            changed: count("change"),
            destroyed: count("remove"),
        });
    }
    summary.ok_or_else(|| IacError::Tool {
        message: "the tool applied without reporting a change summary".to_string(),
        exit_code: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    /// A run as the tool produced it: narrated on `stdout` under `-json`, on
    /// `stderr` otherwise, exiting with `code`.
    fn failure(stdout: &[u8], stderr: &[u8], code: i32) -> Output {
        Output {
            status: Command::new("sh")
                .args(["-c", &format!("exit {code}")])
                .status()
                .expect("a shell to exit with"),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn a_plan_names_every_touched_resource() {
        let two = serde_json::json!({
            "resource_changes": [
                {"address": "terraform_data.a", "change": {"actions": ["create"]}},
                {"address": "terraform_data.b", "change": {"actions": ["delete", "create"]}}
            ]
        });
        let plan = parse_plan_json(&two.to_string()).expect("valid plan json");
        assert_eq!((plan.creates(), plan.updates(), plan.destroys()), (2, 0, 1));
        // A plan with nothing to do carries no `resource_changes` key at all.
        assert!(parse_plan_json("{}").expect("no resource_changes").is_empty());
        // Unreadable output is an error, never a silently empty plan.
        assert!(parse_plan_json("not json").is_err());
    }

    #[test]
    fn the_last_change_summary_is_the_totals() {
        let stream = concat!(
            "{\"type\":\"version\",\"tofu\":\"1.13.1\"}\n",
            "{\"type\":\"change_summary\",\"changes\":{\"add\":1,\"change\":2,\"remove\":3}}\n",
            "{\"type\":\"change_summary\",\"changes\":{\"add\":9,\"change\":0,\"remove\":0}}\n"
        );
        let result = parse_change_summary(stream).expect("a summary is present");
        assert_eq!((result.added, result.changed, result.destroyed), (9, 0, 0));
        assert!(parse_change_summary("{\"type\":\"version\"}").is_err());
    }

    /// A failed run keeps the tool's own message whichever stream it used —
    /// `apply -json` puts everything on stdout — and never reports nothing.
    #[test]
    fn a_failed_run_never_loses_the_tools_own_message() {
        let on_stdout = failure(br#"{"@message":"Error: Failed to read plan"}"#, b"", 1);
        assert!(
            matches!(&tool_error(&on_stdout), IacError::Tool { message, exit_code: Some(1) }
                if message.contains("Failed to read plan")),
            "stdout diagnostics must survive"
        );
        let locked = failure(b"", b"  Error acquiring the state lock  ", 1);
        assert!(
            matches!(&tool_error(&locked), IacError::Tool { message, exit_code: Some(1) }
                if message.starts_with("state is locked by another run")),
            "a lost lock race gets its own message"
        );
        assert_eq!(
            tool_error(&failure(b"", b"  something else  ", 2)),
            IacError::Tool { message: "something else".to_string(), exit_code: Some(2) }
        );
        assert!(
            matches!(tool_error(&failure(b"", b"", 9)), IacError::Tool { message, .. }
                if message.contains("without saying why")),
            "silence is still a failure, and says so"
        );
    }

    /// A plan is located by its own `.ks` directory and by name only, so a
    /// relative `dir` is never resolved against the wrong directory.
    #[test]
    fn a_plan_recovers_its_directory_and_is_named_relative_to_it() {
        let plan = SavedPlan::new("/ws/infra/.ks/plan-1.tfplan", "a".repeat(64)).unwrap();
        let (dir, file) = IacCli::locate(&plan).expect("a plan under `.ks`");
        assert_eq!((dir, file.as_str()), (Path::new("/ws/infra"), ".ks/plan-1.tfplan"));
        let elsewhere = SavedPlan::new("/tmp/plan.tfplan", "a".repeat(64)).unwrap();
        assert!(matches!(IacCli::locate(&elsewhere), Err(IacError::Tool { .. })));
    }

    /// A plan path is absolute even for a relative `dir`, which is what keeps
    /// the plan findable from any later working directory.
    #[test]
    fn plan_files_are_absolute_and_unique() {
        let dir = std::env::temp_dir().join("ks-tofu-cli-plan-file");
        let one = plan_file(&dir).expect("the plans directory");
        assert!(one.is_absolute() && one.starts_with(&dir), "{}", one.display());
        assert_eq!(one.parent().unwrap().file_name(), Some(OsStr::new(PLAN_DIR)));
        assert_ne!(one, plan_file(&dir).expect("the plans directory"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A directory under the system temp dir, named for this process and this
    /// test so two tests never collide, and cleaned before and after use.
    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ks-tofu-cli-{}-{label}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("the scratch directory can be created");
        dir
    }

    /// The file's own permission bits, or `None` where there are none.
    #[cfg(unix)]
    fn mode_of(path: &Path) -> Option<u32> {
        use std::os::unix::fs::PermissionsExt;
        Some(std::fs::metadata(path).ok()?.permissions().mode() & 0o777)
    }

    #[cfg(not(unix))]
    fn mode_of(_path: &Path) -> Option<u32> {
        None
    }

    /// The plans directory is owner-only before the tool writes anything into
    /// it, and the plan itself is not created here — the tool owns that file,
    /// and pre-creating it would truncate what the tool is about to write.
    #[test]
    fn the_plans_directory_is_owner_only_before_the_tool_writes() {
        let dir = scratch("dir-mode");
        let file = plan_file(&dir).expect("the plans directory");
        assert_eq!(mode_of(file.parent().unwrap()), Some(PLAN_DIR_MODE), "{}", file.display());
        assert!(!file.exists(), "we must not create the tool's output: {}", file.display());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Tightening is a mode change, never a rewrite: the digest must still be
    /// the digest of exactly the bytes the tool wrote.
    #[test]
    fn tightening_a_plan_leaves_its_bytes_exactly_as_written() {
        let dir = scratch("file-mode");
        let file = plan_file(&dir).expect("the plans directory");
        let bytes = b"a saved plan, which the tool wrote\n";
        std::fs::write(&file, bytes).expect("the plan is written");
        let before = sha256_of(&file).expect("a digest before");
        restrict(&file, PLAN_FILE_MODE);
        assert_eq!(mode_of(&file), Some(PLAN_FILE_MODE), "{}", file.display());
        assert_eq!(sha256_of(&file).expect("a digest after"), before, "the bytes moved");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A plan that has applied is a plan nobody needs, so `discard` removes
    /// that one file and leaves the customer's directory — and any other plan
    /// in it — alone. Removing it twice is not an error.
    #[test]
    fn discarding_an_applied_plan_removes_that_file_and_nothing_else() {
        let dir = scratch("discard");
        let applied = plan_file(&dir).expect("the plans directory");
        let other = plan_file(&dir).expect("the plans directory");
        std::fs::write(&applied, b"applied").expect("the plan is written");
        std::fs::write(&other, b"the customer's own plan").expect("the other plan is written");
        let plans = applied.parent().unwrap().to_path_buf();

        discard(&applied);
        assert!(!applied.exists(), "{} survived its apply", applied.display());
        assert!(other.exists(), "another plan in the same directory is not ours to delete");
        assert!(plans.is_dir(), "the customer's `.ks` directory is not ours to delete");
        // Somebody cleaning up first, or a rerun, is the outcome we wanted.
        discard(&applied);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An exit code we ignore is a tool we have not identified, and a binary
    /// that cannot be run at all is a `Tool` error rather than a panic.
    #[test]
    fn only_a_successful_version_probe_counts_as_the_tool() {
        let missing =
            IacCli::new(IacKind::OpenTofu, "/nonexistent/tofu").expect_err("no tofu there");
        assert!(matches!(missing, IacError::Tool { .. }), "{missing:?}");

        let probe = std::env::temp_dir().join("ks-tofu-cli-lying-version");
        std::fs::write(&probe, "#!/bin/sh\necho '{\"terraform_version\":\"9.9.9\"}'\nexit 3\n")
            .expect("the script");
        let mut permissions = std::fs::metadata(&probe).expect("the script").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&probe, permissions).expect("the script");
        let error =
            IacCli::new(IacKind::OpenTofu, &probe).expect_err("a failing exit is no version");
        std::fs::remove_file(&probe).ok();
        assert!(matches!(error, IacError::Tool { exit_code: Some(3), .. }), "{error:?}");
    }
}
