//! The OpenTofu state backend: Cloudflare R2, one state per account and module,
//! native-lockfile locking and encryption at rest
//! ([#168](https://github.com/Keep-Shipping/harness/issues/168)).
//!
//! [`add_backend`] writes the generated **root**'s `backend.tf`: OpenTofu
//! ignores a `backend` in a child module with a warning and silently ignores an
//! `encryption` block there (checked against tofu 1.10.10). No credential is in
//! the file — R2's S3 keys are `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` in
//! the run environment, the passphrase a `sensitive` `TF_VAR_*` through the
//! Secrets port — and R2 has no object versioning (`PutBucketVersioning` is
//! unimplemented over its S3 API), a gap recorded in docs/CREDENTIALS.md.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

use crate::hcl;

/// The file the root's backend and encryption blocks are written to.
pub const BACKEND_FILE: &str = "backend.tf";

/// The variable carrying the state encryption passphrase; OpenTofu's early
/// evaluation (≥ 1.8) is what lets an encryption block read a variable at all.
const PASSPHRASE_VAR: &str = concat!("state_encryption_", "passphrase");

/// The R2 state backend for one deployable unit: the bucket, the account id
/// the key is namespaced by, and the module name — one lease per (account,
/// module).
#[derive(Clone, Debug, PartialEq)]
pub struct StateBackend {
    account_id: String,
    bucket: String,
    module: String,
}

impl StateBackend {
    /// The backend for `module` under `account_id`, keeping its state in
    /// `bucket`. Every name is validated, so nothing that could change the
    /// meaning of the HCL it is rendered into gets through.
    pub fn new(account_id: &str, bucket: &str, module: &str) -> Result<StateBackend, StateError> {
        for (field, value, valid) in [
            ("account id", account_id, is_slug(account_id, false)),
            ("bucket", bucket, is_bucket(bucket)),
            ("module name", module, is_slug(module, true)),
        ] {
            if !valid {
                return Err(StateError::new(field, value));
            }
        }
        Ok(StateBackend {
            account_id: account_id.to_string(),
            bucket: bucket.to_string(),
            module: module.to_string(),
        })
    }

    /// The state object's key: `<account_id>/<module>/terraform.tfstate`.
    pub fn key(&self) -> String {
        format!("{}/{}/terraform.tfstate", self.account_id, self.module)
    }

    /// The root's `backend.tf`: the `s3` backend pointed at R2 with the native
    /// lockfile (`use_lockfile`, OpenTofu ≥ 1.10: S3 conditional writes, which
    /// R2 answers — no lock table), the `skip_*` flags an S3-compatible store
    /// needs, and the encryption blocks: an AES-GCM key derived from the
    /// passphrase variable, `enforced` so an unencrypted write is a hard error.
    pub fn backend_tf(&self) -> String {
        let mut out = String::from("terraform {\n  backend \"s3\" {\n");
        let _ = writeln!(out, "    key = {}", hcl::quoted(&self.key()));
        let _ = writeln!(out, "    region = \"auto\"");
        let _ = write!(
            out,
            "    endpoints = {{\n      s3 = {}\n    }}\n",
            hcl::quoted(&format!("https://{}.r2.cloudflarestorage.com", self.account_id))
        );
        out.push_str(
            "    use_lockfile = true\n    skip_credentials_validation = true\n    \
             skip_region_validation = true\n    skip_requesting_account_id = true\n    \
             skip_metadata_api_check = true\n    skip_s3_checksum = true\n    \
             use_path_style = true\n  }\n",
        );
        // Encryption at rest: a passphrase-derived AES-GCM key wrapping state
        // and plan, `enforced` so an unencrypted write is a hard error.
        out.push_str(&format!(
            "  encryption {{\n    key_provider \"pbkdf2\" \"state\" {{\n      \
             passphrase = var.{PASSPHRASE_VAR}\n    }}\n    \
             method \"aes_gcm\" \"state\" {{\n      keys = key_provider.pbkdf2.state\n    }}\n    \
             state {{\n      method = method.aes_gcm.state\n      enforced = true\n    }}\n    \
             plan {{\n      method = method.aes_gcm.state\n      enforced = true\n    }}\n  }}\n}}\n",
        ));
        let _ = write!(
            out,
            "\nvariable \"{PASSPHRASE_VAR}\" {{\n  description = \"Passphrase for the OpenTofu \
             state encryption, supplied through the Secrets port as TF_VAR_{PASSPHRASE_VAR}.\"\n  \
             type        = string\n  sensitive   = true\n}}"
        );
        let _ = writeln!(out);
        out
    }
}

/// Writes the root's [`BACKEND_FILE`] into `files` — [`generate`](crate::generate)'s
/// output — giving the whole deployable unit one state.
pub fn add_backend(files: &mut BTreeMap<String, String>, backend: &StateBackend) {
    files.insert(BACKEND_FILE.to_string(), backend.backend_tf());
}

/// Why a state backend could not be built: one name was rejected. The inputs
/// are ids and names, never credentials, so the error may quote them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateError {
    field: &'static str,
    value: String,
}

impl StateError {
    fn new(field: &'static str, value: &str) -> StateError {
        StateError { field, value: value.to_string() }
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the state backend's {} {:?} is not usable: names are ASCII letters and digits, \
             and a bucket name also takes '.', '-' and '_'",
            self.field, self.value
        )
    }
}

impl std::error::Error for StateError {}

/// An account id or a module slug: ASCII alphanumerics — a slug also takes
/// `_` — non-empty.
fn is_slug(text: &str, underscore: bool) -> bool {
    !text.is_empty()
        && text.chars().all(|ch| ch.is_ascii_alphanumeric() || (underscore && ch == '_'))
}

/// An S3 bucket name, as R2 follows AWS's rules: 3-63 lowercase letters,
/// digits, `.`, `-` and `_`, starting and ending with a letter or digit.
fn is_bucket(text: &str) -> bool {
    (3..=63).contains(&text.len())
        && text.starts_with(|ch: char| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && text.ends_with(|ch: char| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && text.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '-' | '_')
        })
}
