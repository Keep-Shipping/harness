//! The [`IacTool`] conformance kit against real OpenTofu and Terraform
//! binaries ([#69](https://github.com/Keep-Shipping/harness/issues/69)).
//!
//! These run real changes against a `local` backend, so they are **not**
//! what plain `cargo test` runs ([ADR 0002](../../docs/adr/0002-ports-and-adapters.md)).
//! Each skips unless its binary is named:
//!
//! ```sh
//! KS_TOFU_BIN=/path/to/tofu cargo test -p ks-tofu-cli
//! KS_TERRAFORM_BIN=/path/to/terraform cargo test -p ks-tofu-cli
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ks_core::ports::iac::{Backend, IacError, IacKind, IacTool};
use ks_testing::block_on;
use ks_testing::iac::conformance;
use ks_tofu_cli::IacCli;

/// A provider-free configuration: the built-in `terraform` provider only, so
/// `init` needs no registry and the whole test runs offline once the binary
/// is there.
const CONFIG: &str = "\
variable \"name\" {
  type    = string
  default = \"anonymous\"
}

resource \"terraform_data\" \"conformance\" {
  input = var.name
}

output \"name\" {
  value = terraform_data.conformance.output
}
";

/// A configuration that is slow to apply: `terraform_data` with a
/// `local-exec` provisioner that sleeps, so the state lock is held for whole
/// seconds and a concurrent apply has time to queue behind it.
const SLOW_CONFIG: &str = "\
resource \"terraform_data\" \"slow\" {
  provisioner \"local-exec\" {
    command = \"sleep 3\"
  }
}
";

/// A fresh directory under the system temp dir, unique per call.
fn temp_dir(label: &str, config: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("ks-tofu-cli-{label}-{nanos}"));
    fs::create_dir_all(&dir).expect("a temp directory");
    fs::write(dir.join("main.tf"), config).expect("the configuration");
    dir
}

/// The adapter for `kind`, or a printed skip note: plain `cargo test` has no
/// binaries and must still pass offline.
fn adapter(kind: IacKind, env: &str) -> Option<IacCli> {
    match std::env::var(env) {
        Ok(bin) if !bin.is_empty() => {
            Some(IacCli::new(kind, bin).expect("the binary answers `version -json`"))
        }
        _ => {
            eprintln!("skipping the {kind:?} conformance test: {env} is not set");
            None
        }
    }
}

/// The port's own kit, for both tools: which binary is a choice, the
/// behaviour is not.
#[test]
fn opentofu_passes_the_conformance_kit() {
    let Some(tool) = adapter(IacKind::OpenTofu, "KS_TOFU_BIN") else { return };
    block_on(conformance(&tool, &temp_dir("tofu", CONFIG)));
}

#[test]
fn terraform_passes_the_conformance_kit() {
    let Some(tool) = adapter(IacKind::Terraform, "KS_TERRAFORM_BIN") else { return };
    block_on(conformance(&tool, &temp_dir("terraform", CONFIG)));
}

/// Variables reach the plan as `TF_VAR_*` environment entries, never as `-var`
/// arguments, and land in the outputs; a `-var-file` mixes with them.
fn vars_travel_by_env_and_by_file(kind: IacKind, env: &str) {
    let Some(tool) = adapter(kind, env) else { return };
    let dir = temp_dir("vars", CONFIG);
    let from_file = dir.join("extra.tfvars");
    fs::write(&from_file, "name = \"from-a-file\"\n").expect("the var file");

    // Overridden by the later `-var-file`, which proves both paths are read.
    let vars = BTreeMap::from([("name".to_string(), "from-the-env".to_string())]);
    let tool = tool.var_file(&from_file);
    let saved = block_on(tool.plan(&dir, &vars, &Backend::new("local")))
        .unwrap_or_else(|error| panic!("{kind:?}: plan with vars failed: {error}"));
    let applied = block_on(tool.apply(&saved))
        .unwrap_or_else(|error| panic!("{kind:?}: apply with vars failed: {error}"));
    assert_eq!(applied.added, 1, "{kind:?}: the one resource is created");

    let outputs = block_on(tool.outputs(&dir))
        .unwrap_or_else(|error| panic!("{kind:?}: outputs failed: {error}"));
    let value = outputs.get("name").unwrap_or_else(|| panic!("{kind:?}: name output"));
    assert!(!value.sensitive, "{kind:?}");
    assert_eq!(value.value, "\"from-a-file\"", "{kind:?}: the var file wins");
}

#[test]
fn opentofu_reads_vars_from_the_environment_and_a_var_file() {
    vars_travel_by_env_and_by_file(IacKind::OpenTofu, "KS_TOFU_BIN");
}

#[test]
fn terraform_reads_vars_from_the_environment_and_a_var_file() {
    vars_travel_by_env_and_by_file(IacKind::Terraform, "KS_TERRAFORM_BIN");
}

/// A named workspace is created by `plan` and still selected when the saved
/// plan is applied: the plan file alone does not say which workspace to use,
/// so the directory's own state has to carry the choice.
#[test]
fn a_named_workspace_survives_into_apply() {
    let Some(tool) = adapter(IacKind::OpenTofu, "KS_TOFU_BIN") else { return };
    let dir = temp_dir("workspace", CONFIG);
    let tool = tool.workspace("ks-conformance");
    let saved = block_on(tool.plan(&dir, &BTreeMap::new(), &Backend::new("local")))
        .expect("plan in a named workspace");
    block_on(tool.apply(&saved)).expect("apply in the same workspace");
    let outputs = block_on(tool.outputs(&dir)).expect("outputs");
    assert_eq!(outputs.get("name").map(|value| value.value.as_str()), Some("\"anonymous\""));
}

/// Two concurrent applies on one module: one waits for the state lock
/// ([#168](https://github.com/Keep-Shipping/harness/issues/168)). Neither
/// fails *with* the lock, and the one that finished last ran no earlier than
/// the other's provisioner sleep — it queued, it did not lose. Its plan was
/// made against the same empty state the winner moved, so once it holds the
/// lock it either applies or is told the plan went stale.
fn a_concurrent_apply_queues_behind_the_state_lock(kind: IacKind, env: &str) {
    let Some(tool) = adapter(kind, env) else { return };
    let dir = temp_dir("lock-queue", SLOW_CONFIG);
    let backend = Backend::new("local");
    let plans = [
        block_on(tool.plan(&dir, &BTreeMap::new(), &backend))
            .unwrap_or_else(|error| panic!("{kind:?}: the first plan failed: {error}")),
        block_on(tool.plan(&dir, &BTreeMap::new(), &backend))
            .unwrap_or_else(|error| panic!("{kind:?}: the second plan failed: {error}")),
    ];

    let tool = &tool;
    let mut finished = std::thread::scope(|scoped| {
        let handles: Vec<_> = plans
            .iter()
            .map(|plan| {
                scoped.spawn(move || {
                    let began = Instant::now();
                    let result = block_on(tool.apply(plan));
                    (began.elapsed(), result)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("the apply thread"))
            .collect::<Vec<_>>()
    });

    for (elapsed, result) in &finished {
        assert!(
            !matches!(result, Err(IacError::Tool { message, .. }) if message.contains("locked")),
            "{kind:?}: an apply failed on the lock after {elapsed:?}: {result:?}"
        );
    }
    finished.sort_by_key(|(elapsed, _)| *elapsed);
    let (elapsed, queued) = finished.pop().expect("two applies");
    assert!(
        elapsed >= Duration::from_secs(3),
        "{kind:?}: the last apply waited only {elapsed:?}, so it did not queue"
    );
    match queued {
        Ok(applied) => assert_eq!(applied.added, 1, "{kind:?}: the queued apply went through"),
        Err(IacError::StalePlan) => {} // the state moved under it: plan again
        Err(error) => panic!("{kind:?}: the queued apply failed otherwise: {error}"),
    }
}

#[test]
fn opentofu_queues_a_concurrent_apply_behind_the_state_lock() {
    a_concurrent_apply_queues_behind_the_state_lock(IacKind::OpenTofu, "KS_TOFU_BIN");
}

#[test]
fn terraform_queues_a_concurrent_apply_behind_the_state_lock() {
    a_concurrent_apply_queues_behind_the_state_lock(IacKind::Terraform, "KS_TERRAFORM_BIN");
}

/// A lock wait that runs out is reported, after the wait: with a one-second
/// `-lock-timeout` against a three-second apply the queued run fails late and
/// by name — not on arrival, and not with the tool's raw text.
fn a_lock_wait_that_runs_out_reports_after_waiting(kind: IacKind, env: &str) {
    let Some(tool) = adapter(kind, env) else { return };
    let dir = temp_dir("lock-timeout", SLOW_CONFIG);
    let backend = Backend::new("local");
    let first = block_on(tool.plan(&dir, &BTreeMap::new(), &backend)).expect("the first plan");
    let second = block_on(tool.plan(&dir, &BTreeMap::new(), &backend)).expect("the second plan");

    let impatient = tool.clone().lock_timeout(Duration::from_secs(1));
    std::thread::scope(|scoped| {
        let patient = scoped.spawn(|| block_on(tool.apply(&first)).expect("the patient apply"));
        // The queued run starts only once the lock file on disk says the first
        // apply holds the lock, so the one-second wait is spent against a
        // three-second sleep it cannot outwait.
        let lock = dir.join(".terraform.tfstate.lock.info");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !lock.exists() {
            assert!(Instant::now() < deadline, "{kind:?}: the first apply never took the lock");
            std::thread::sleep(Duration::from_millis(10));
        }
        let queued = scoped.spawn(|| {
            let began = Instant::now();
            let result = block_on(impatient.apply(&second));
            (began.elapsed(), result)
        });
        patient.join().expect("the patient apply thread");
        let (elapsed, result) = queued.join().expect("the queued apply thread");
        assert!(elapsed >= Duration::from_secs(1), "{kind:?}: gave up after {elapsed:?}");
        match result {
            Err(IacError::Tool { message, .. }) => assert!(
                message.starts_with("state is still locked by another run after waiting 1s"),
                "{kind:?}: the failure does not name the wait: {message}"
            ),
            other => panic!("{kind:?}: the short lock wait did not run out: {other:?}"),
        }
    });
}

#[test]
fn opentofu_reports_a_state_lock_after_its_wait_runs_out() {
    a_lock_wait_that_runs_out_reports_after_waiting(IacKind::OpenTofu, "KS_TOFU_BIN");
}

#[test]
fn terraform_reports_a_state_lock_after_its_wait_runs_out() {
    a_lock_wait_that_runs_out_reports_after_waiting(IacKind::Terraform, "KS_TERRAFORM_BIN");
}
