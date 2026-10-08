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

use ks_core::ports::iac::{Backend, IacKind, IacTool};
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

/// A fresh directory under the system temp dir, unique per call.
fn temp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("ks-tofu-cli-{label}-{nanos}"));
    fs::create_dir_all(&dir).expect("a temp directory");
    fs::write(dir.join("main.tf"), CONFIG).expect("the configuration");
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
    block_on(conformance(&tool, &temp_dir("tofu")));
}

#[test]
fn terraform_passes_the_conformance_kit() {
    let Some(tool) = adapter(IacKind::Terraform, "KS_TERRAFORM_BIN") else { return };
    block_on(conformance(&tool, &temp_dir("terraform")));
}

/// Variables reach the plan as `TF_VAR_*` environment entries, never as `-var`
/// arguments, and land in the outputs; a `-var-file` mixes with them.
fn vars_travel_by_env_and_by_file(kind: IacKind, env: &str) {
    let Some(tool) = adapter(kind, env) else { return };
    let dir = temp_dir("vars");
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
    let dir = temp_dir("workspace");
    let tool = tool.workspace("ks-conformance");
    let saved = block_on(tool.plan(&dir, &BTreeMap::new(), &Backend::new("local")))
        .expect("plan in a named workspace");
    block_on(tool.apply(&saved)).expect("apply in the same workspace");
    let outputs = block_on(tool.outputs(&dir)).expect("outputs");
    assert_eq!(outputs.get("name").map(|value| value.value.as_str()), Some("\"anonymous\""));
}
