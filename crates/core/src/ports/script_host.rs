//! The [`ScriptHost`] port: running the TypeScript escape-hatch steps
//! ([#57](https://github.com/Keep-Shipping/harness/issues/57), protocol in
//! [#10](https://github.com/Keep-Shipping/harness/issues/10) — the runtime is
//! [ADR 0009](../../../../docs/adr/0009-typescript-escape-hatch-runtime.md)).
//!
//! Escape-hatch steps are scripts a repository ships next to its `ship.ks`.
//! They speak the JSON-stdio protocol from #10: a script declares its inputs
//! and outputs (a [`StepSchema`], which is what `check` inspects), then reads
//! one JSON object on stdin and writes JSON lines on stdout — any number of
//! log frames and exactly one output frame. The adapter owns the
//! process and the wire; the port owns the typed shapes — and the secrets:
//! [`ScriptHost::run`] hands the adapter a [`SecretBundle`], and the adapter
//! must pass those values to the script over a dedicated file descriptor,
//! *never* argv, the environment, or stdio (they end up in `ps` output and
//! logs). Validation itself is pure and lives here, so `check` and every
//! adapter share one [`StepSchema::validate_inputs`] /
//! [`StepSchema::validate_outputs`].
//!
//! A script's own logging is the same story from the other end
//! ([#91](https://github.com/Keep-Shipping/harness/issues/91)): its log frames
//! go to the [`StepLog`] [`ScriptHost::run`] is handed, so they pass through
//! the run's [`Redactor`] exactly as a built-in step's do — a script that
//! logs a revealed secret prints `***`. And a secret coming back *out* is not
//! merely redacted, it is refused:
//! [`reject_secret_outputs`](crate::step::reject_secret_outputs) fails the
//! step, because an output feeds wiring and the run log, where masking a
//! value would help nobody.
//!
//! [`Redactor`]: crate::ports::secrets::Redactor
//! [`SecretBundle`]: crate::ports::secrets::SecretBundle

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use super::BoxFuture;
use crate::ports::secrets::SecretBundle;
use crate::step::StepLog;

/// Which script to run: a path, relative to the run's workspace root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptRef {
    path: PathBuf,
}

impl ScriptRef {
    /// References the script at `path`, e.g. `scripts/deploy.ts`.
    pub fn new(path: impl Into<PathBuf>) -> ScriptRef {
        ScriptRef { path: path.into() }
    }

    /// The script's path, relative to the workspace root.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Display for ScriptRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

/// A JSON-ish value crossing the script boundary, in both directions.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// JSON `null`. Never schema-valid: see [`ValueType::Null`].
    Null,
    /// A boolean.
    Bool(bool),
    /// A number (`f64`, like JSON).
    Number(f64),
    /// A string.
    String(String),
    /// A list of values.
    List(Vec<Value>),
    /// An object; keys iterate sorted.
    Map(BTreeMap<String, Value>),
}

impl Value {
    /// The value's type, for schema checks and mismatch diagnostics.
    pub fn value_type(&self) -> ValueType {
        match self {
            Value::Null => ValueType::Null,
            Value::Bool(_) => ValueType::Bool,
            Value::Number(_) => ValueType::Number,
            Value::String(_) => ValueType::String,
            Value::List(_) => ValueType::List,
            Value::Map(_) => ValueType::Map,
        }
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Value {
        Value::String(value.to_string())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Value {
        Value::String(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Value {
        Value::Bool(value)
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Value {
        Value::Number(value)
    }
}

/// The type a [`StepSchema`] requires of a field, and the type a [`Value`]
/// actually has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    /// The type of [`Value::Null`]. Never declare it in a schema: a null
    /// satisfies no contract, and both validators reject a schema that does
    /// (with [`ScriptHostError::InvalidSchema`]). There is deliberately no
    /// optionality yet — a field is required, or it is not declared.
    Null,
    /// [`Value::Bool`].
    Bool,
    /// [`Value::Number`].
    Number,
    /// [`Value::String`].
    String,
    /// [`Value::List`].
    List,
    /// [`Value::Map`].
    Map,
}

impl ValueType {
    /// The type's name, as it appears in diagnostics, e.g. `"string"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ValueType::Null => "null",
            ValueType::Bool => "bool",
            ValueType::Number => "number",
            ValueType::String => "string",
            ValueType::List => "list",
            ValueType::Map => "map",
        }
    }
}

impl fmt::Display for ValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for Value {
    /// The value as JSON — the form it crossed the port in, and the form a run
    /// log shows. A string is quoted, as JSON writes it, so a run log never
    /// reads as though a value ended early.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => f.write_str("null"),
            Value::Bool(true) => f.write_str("true"),
            Value::Bool(false) => f.write_str("false"),
            Value::Number(n) => write!(f, "{n}"),
            Value::String(s) => write!(f, "{s:?}"),
            Value::List(items) => {
                f.write_str("[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{item}")?;
                }
                f.write_str("]")
            }
            Value::Map(entries) => {
                f.write_str("{")?;
                for (i, (key, value)) in entries.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{key:?}: {value}")?;
                }
                f.write_str("}")
            }
        }
    }
}

/// The values handed to or returned by a script, keyed by field name
/// (iterates sorted, so runs are reproducible in the log).
pub type Values = BTreeMap<String, Value>;

/// A script's declared input and output contract — what `check` inspects and
/// `run` enforces, via the pure [`StepSchema::validate_inputs`] and
/// [`StepSchema::validate_outputs`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StepSchema {
    /// Required inputs, by name and type. Nothing here is optional: a script
    /// that can run without a field must not declare it.
    pub inputs: BTreeMap<String, ValueType>,
    /// Promised outputs, by name and type; `run` rejects anything more.
    pub outputs: BTreeMap<String, ValueType>,
}

impl StepSchema {
    /// Checks `values` against the input contract: every declared input must
    /// be present with the declared type. Extra keys are ignored — callers
    /// may pipe their whole context at a script. A field declared as
    /// [`ValueType::Null`] is an [`ScriptHostError::InvalidSchema`]: a null
    /// satisfies no contract. Pure: no I/O, shared by `check` and every
    /// adapter.
    pub fn validate_inputs(&self, values: &Values) -> Result<(), ScriptHostError> {
        for (name, expected) in &self.inputs {
            if *expected == ValueType::Null {
                return Err(ScriptHostError::InvalidSchema { name: name.clone() });
            }
            let Some(found) = values.get(name) else {
                return Err(ScriptHostError::MissingInput { name: name.clone() });
            };
            if found.value_type() != *expected {
                return Err(ScriptHostError::InputTypeMismatch {
                    name: name.clone(),
                    expected: *expected,
                    found: found.value_type(),
                });
            }
        }
        Ok(())
    }

    /// Checks `values` against the output contract: every declared output
    /// present with the declared type, and *nothing else*. A script may not
    /// invent outputs — dependents are wired to the schema, not to whatever
    /// the script happened to return. A field declared as
    /// [`ValueType::Null`] is an [`ScriptHostError::InvalidSchema`]. Pure.
    pub fn validate_outputs(&self, values: &Values) -> Result<(), ScriptHostError> {
        for (name, expected) in &self.outputs {
            if *expected == ValueType::Null {
                return Err(ScriptHostError::InvalidSchema { name: name.clone() });
            }
            let Some(found) = values.get(name) else {
                return Err(ScriptHostError::MissingOutput { name: name.clone() });
            };
            if found.value_type() != *expected {
                return Err(ScriptHostError::OutputTypeMismatch {
                    name: name.clone(),
                    expected: *expected,
                    found: found.value_type(),
                });
            }
        }
        for name in values.keys() {
            if !self.outputs.contains_key(name) {
                return Err(ScriptHostError::UnexpectedOutput { name: name.clone() });
            }
        }
        Ok(())
    }
}

/// Why a [`ScriptHost`] refused to run a script, or a script failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptHostError {
    /// A declared output came back with the wrong type. Raised by
    /// [`StepSchema::validate_outputs`] — the same error from `check` and
    /// every adapter.
    OutputTypeMismatch {
        /// The output's name.
        name: String,
        /// The type the script declared.
        expected: ValueType,
        /// The type the script actually returned.
        found: ValueType,
    },
    /// A declared output was never returned.
    MissingOutput {
        /// The output's name.
        name: String,
    },
    /// The script returned an output it never declared.
    UnexpectedOutput {
        /// The undeclared output's name.
        name: String,
    },
    /// A required input was handed over with the wrong type. Raised by
    /// [`StepSchema::validate_inputs`].
    InputTypeMismatch {
        /// The input's name.
        name: String,
        /// The type the script declared.
        expected: ValueType,
        /// The type the caller provided.
        found: ValueType,
    },
    /// A required input was not provided at all.
    MissingInput {
        /// The input's name.
        name: String,
    },
    /// A schema declared a field as [`ValueType::Null`], which no contract
    /// can satisfy. Raised by [`StepSchema::validate_inputs`] and
    /// [`StepSchema::validate_outputs`] before any value is looked at.
    InvalidSchema {
        /// The field declared as null.
        name: String,
    },
    /// The script broke the JSON-stdio protocol from #10 (malformed JSON on
    /// stdout, no object, …), or the script does not exist.
    Protocol {
        /// What was violated, safe to print.
        message: String,
    },
    /// The script ran and exited nonzero (or never exited).
    ScriptFailed {
        /// The exit code, if it exited at all.
        exit_code: Option<i32>,
        /// The script's own stderr tail. Scrubbed by the adapter with
        /// [`StepLog::redact`](crate::step::StepLog::redact) before it goes
        /// in: those bytes come from the process, and whatever a failed
        /// script printed is exactly what a revealed secret looks like.
        message: String,
    },
}

impl fmt::Display for ScriptHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptHostError::OutputTypeMismatch { name, expected, found } => {
                write!(f, "output {name:?} must be a {expected}, found {found}")
            }
            ScriptHostError::MissingOutput { name } => {
                write!(f, "output {name:?} is declared but the script never returned it")
            }
            ScriptHostError::UnexpectedOutput { name } => {
                write!(f, "script returned undeclared output {name:?}")
            }
            ScriptHostError::InputTypeMismatch { name, expected, found } => {
                write!(f, "input {name:?} must be a {expected}, found {found}")
            }
            ScriptHostError::MissingInput { name } => {
                write!(f, "input {name:?} is required but missing")
            }
            ScriptHostError::InvalidSchema { name } => {
                write!(f, "schema declares {name:?} as null, but a null satisfies no contract")
            }
            ScriptHostError::Protocol { message } => {
                write!(f, "script protocol violation: {message}")
            }
            ScriptHostError::ScriptFailed { exit_code, message } => {
                write!(f, "script failed")?;
                match exit_code {
                    Some(code) => write!(f, " with exit code {code}")?,
                    None => write!(f, " before exiting")?,
                }
                write!(f, ": {message}")
            }
        }
    }
}

impl std::error::Error for ScriptHostError {}

/// The `ScriptHost` port: an adapter runs escape-hatch scripts as processes
/// over the JSON-stdio protocol from #10. `schema` backs `check` (no
/// execution), `run` backs execution — both async, both dyn-compatible, so
/// the engine holds the host as `&dyn ScriptHost` and the Deno adapter
/// (ADR 0009) lands later without a rewrite.
///
/// Adapters must fail with [`ScriptHostError`] rather than panicking.
pub trait ScriptHost: Send + Sync {
    /// The script's declared schema, without running it.
    fn schema<'a>(
        &'a self,
        script: &'a ScriptRef,
    ) -> BoxFuture<'a, Result<StepSchema, ScriptHostError>>;

    /// Runs `script` with `inputs`, handing the values of `secrets` to the
    /// script over a dedicated file descriptor — never argv, the environment
    /// or stdio. Adapters validate `inputs` against the script's schema before
    /// starting the process, and the returned values against it after; a
    /// nonzero exit is [`ScriptFailed`](ScriptHostError::ScriptFailed), a wire
    /// violation is [`Protocol`](ScriptHostError::Protocol) — and a failed
    /// script's stderr tail goes through [`log.redact(..)`](StepLog::redact)
    /// on the way into the error, since a revealed secret is exactly what a
    /// crashing script tends to print.
    ///
    /// The script's log frames go to `log` — the step's own
    /// [`StepLog`], which redacts every message and
    /// field through the run's [`Redactor`](crate::ports::secrets::Redactor)
    /// before the sink sees them. That
    /// is the same channel a built-in step logs on, so `log(db.reveal())`
    /// prints `***` and never the value, and the adapter has no redaction
    /// of its own to get wrong. It must not write log frames anywhere else
    /// either: stdout and stderr belong to the protocol and to errors.
    ///
    /// What the script *returns* is a separate matter: the engine runs every
    /// step's outputs through
    /// [`reject_secret_outputs`](crate::step::reject_secret_outputs) against
    /// the same redactor, so a returned secret — or a string with one
    /// embedded — fails the step rather than propagating.
    fn run<'a>(
        &'a self,
        script: &'a ScriptRef,
        inputs: &'a Values,
        secrets: &'a SecretBundle,
        log: &'a StepLog,
    ) -> BoxFuture<'a, Result<Values, ScriptHostError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_script_host_trait_is_dyn_compatible() {
        assert_send_sync::<dyn ScriptHost>();
    }

    #[test]
    fn values_report_their_type() {
        assert_eq!(Value::Null.value_type(), ValueType::Null);
        assert_eq!(Value::from(true).value_type(), ValueType::Bool);
        assert_eq!(Value::from(1.5).value_type(), ValueType::Number);
        assert_eq!(Value::from("x").value_type(), ValueType::String);
        assert_eq!(Value::List(vec![]).value_type(), ValueType::List);
        assert_eq!(Value::Map(BTreeMap::new()).value_type(), ValueType::Map);
    }

    #[test]
    fn input_validation_requires_declared_inputs_with_declared_types() {
        let schema = StepSchema {
            inputs: BTreeMap::from([
                ("name".to_string(), ValueType::String),
                ("count".to_string(), ValueType::Number),
            ]),
            outputs: BTreeMap::new(),
        };
        // Extra keys are ignored; declared keys must be present and typed.
        let mut values: Values = BTreeMap::new();
        values.insert("extra".to_string(), Value::from("ignored"));
        assert!(matches!(
            schema.validate_inputs(&values),
            Err(ScriptHostError::MissingInput { .. })
        ));
        values.insert("name".to_string(), Value::from("app"));
        values.insert("count".to_string(), Value::from("two"));
        assert!(matches!(
            schema.validate_inputs(&values),
            Err(ScriptHostError::InputTypeMismatch { name, expected, found })
                if name == "count" && expected == ValueType::Number && found == ValueType::String
        ));
        values.insert("count".to_string(), Value::from(2.0));
        assert_eq!(schema.validate_inputs(&values), Ok(()));
    }

    #[test]
    fn a_schema_declaring_null_is_invalid_in_either_direction() {
        let schema = StepSchema {
            inputs: BTreeMap::from([("flag".to_string(), ValueType::Null)]),
            outputs: BTreeMap::new(),
        };
        assert!(matches!(
            schema.validate_inputs(&BTreeMap::new()),
            Err(ScriptHostError::InvalidSchema { name }) if name == "flag"
        ));

        let schema = StepSchema {
            inputs: BTreeMap::new(),
            outputs: BTreeMap::from([("flag".to_string(), ValueType::Null)]),
        };
        let mut values: Values = BTreeMap::new();
        values.insert("flag".to_string(), Value::Null);
        assert!(matches!(
            schema.validate_outputs(&values),
            Err(ScriptHostError::InvalidSchema { name }) if name == "flag"
        ));
    }

    #[test]
    fn output_validation_is_strict_in_both_directions() {
        let schema = StepSchema {
            inputs: BTreeMap::new(),
            outputs: BTreeMap::from([("greeting".to_string(), ValueType::String)]),
        };
        assert!(matches!(
            schema.validate_outputs(&BTreeMap::new()),
            Err(ScriptHostError::MissingOutput { .. })
        ));
        let mut values: Values = BTreeMap::new();
        values.insert("greeting".to_string(), Value::from(1.0));
        assert!(matches!(
            schema.validate_outputs(&values),
            Err(ScriptHostError::OutputTypeMismatch { .. })
        ));
        values.insert("greeting".to_string(), Value::from("hi"));
        values.insert("surprise".to_string(), Value::Null);
        assert!(matches!(
            schema.validate_outputs(&values),
            Err(ScriptHostError::UnexpectedOutput { name }) if name == "surprise"
        ));
        values.remove("surprise");
        assert_eq!(schema.validate_outputs(&values), Ok(()));
    }

    #[test]
    fn values_display_as_the_json_they_crossed_the_port_as() {
        assert_eq!(Value::Null.to_string(), "null");
        assert_eq!(Value::from(true).to_string(), "true");
        assert_eq!(Value::from(3.0).to_string(), "3");
        assert_eq!(Value::from(1.5).to_string(), "1.5");
        assert_eq!(Value::from("hi").to_string(), "\"hi\"");
        assert_eq!(Value::List(vec![Value::from(1.0), Value::from("a")]).to_string(), "[1, \"a\"]");
        assert_eq!(
            Value::Map(BTreeMap::from([
                ("applied".to_string(), Value::from(3.0)),
                ("db".to_string(), Value::from("local")),
            ]))
            .to_string(),
            "{\"applied\": 3, \"db\": \"local\"}"
        );
        assert_eq!(Value::List(vec![]).to_string(), "[]");
    }

    #[test]
    fn script_host_errors_display_actionably() {
        let error = ScriptHostError::OutputTypeMismatch {
            name: "greeting".to_string(),
            expected: ValueType::String,
            found: ValueType::Number,
        }
        .to_string();
        assert!(
            error.contains("greeting") && error.contains("string") && error.contains("number"),
            "{error}"
        );
        let failed =
            ScriptHostError::ScriptFailed { exit_code: Some(3), message: "boom".to_string() }
                .to_string();
        assert!(failed.contains('3') && failed.contains("boom"), "{failed}");
        let killed = ScriptHostError::ScriptFailed { exit_code: None, message: "oom".to_string() }
            .to_string();
        assert!(killed.contains("oom"), "{killed}");
        assert!(
            ScriptHostError::MissingInput { name: "url".to_string() }.to_string().contains("url")
        );
    }
}
