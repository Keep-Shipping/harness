//! The [`Harness`]: composing ports and step kinds, and refusing bad compositions completely
//! ([#39](https://github.com/Keep-Shipping/harness/issues/39)).
//!
//! [`Harness::builder`] collects ports, step kinds and named [`TypeDef`]s; `build` checks all
//! of it at once and returns *every* problem in a deterministic order — harness-level first,
//! then steps in registration order — never just the first. A built harness answers what the
//! engine asks per run: which steps exist, what a named type resolves to, and whether a run's
//! inputs and outputs honor the step's schema.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use crate::ports::clock::Clock;
use crate::ports::script_host::ValueType;
use crate::step::{Inputs, Outputs, Port, Ports, STEP_API, StepError, StepKind, TypeDef, TypeRef};

/// Why a composition was refused.
#[derive(Debug, Clone, PartialEq)]
pub enum CompositionError {
    /// No [`Clock`] was provided, but every step context carries one.
    MissingClock,
    /// A step requires a port nobody provided.
    MissingPort { step: String, port: Port },
    /// A step listed the same port in `requires` and `optional`.
    PortInBothLists { step: String, port: Port },
    /// Several steps registered the same name; one error per duplicated name, with the total
    /// count.
    DuplicateStepName { name: String, count: usize },
    /// A step was built against a different [`STEP_API`] than the harness speaks.
    StepApiMismatch { step: String, found: u32 },
    /// A schema field references a named type that was never registered.
    UnknownType { step: String, field: String, type_name: String },
    /// A field's resolved type is `null` — a builtin `null`, or a [`TypeDef`] with a `null`
    /// base. No value satisfies it, matching the script host's schema rule.
    NullType { step: String, field: String },
    /// A field's default does not match the field's (resolved) type.
    DefaultTypeMismatch { step: String, field: String },
    /// A `type_def` tried to redefine one of the built-in named types.
    ReservedTypeName { name: String },
    /// A step's schema declares an output of type `Secret`; secrets flow into steps, never out.
    SecretOutput { step: String, output: String },
}

impl fmt::Display for CompositionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompositionError::MissingClock => {
                f.write_str("the harness requires port Clock, but no Clock was provided")
            }
            CompositionError::MissingPort { step, port } => {
                write!(f, "step {step:?} requires port {port}, but no {port} was provided")
            }
            CompositionError::PortInBothLists { step, port } => {
                write!(f, "step {step:?} lists port {port} in both requires and optional")
            }
            CompositionError::DuplicateStepName { name, count } => {
                write!(f, "step name {name:?} is registered {count} times")
            }
            CompositionError::StepApiMismatch { step, found } => {
                write!(
                    f,
                    "step {step:?} was built against step API {found}, but this harness speaks step API {STEP_API}"
                )
            }
            CompositionError::UnknownType { step, field, type_name } => {
                write!(f, "step {step:?} field {field:?} references unknown type {type_name:?}")
            }
            CompositionError::NullType { step, field } => {
                write!(
                    f,
                    "step {step:?} field {field:?} declares type null, which no value satisfies"
                )
            }
            CompositionError::DefaultTypeMismatch { step, field } => {
                write!(
                    f,
                    "step {step:?} field {field:?} has a default that does not match its type"
                )
            }
            CompositionError::ReservedTypeName { name } => {
                write!(f, "type {name:?} is built in and cannot be redefined")
            }
            CompositionError::SecretOutput { step, output } => {
                write!(
                    f,
                    "step {step:?} output {output:?} declares type Secret, but outputs cannot be secrets"
                )
            }
        }
    }
}

/// Every problem `Harness::build` found, in its deterministic order.
#[derive(Debug, Clone, PartialEq)]
pub struct BuildErrors(Vec<CompositionError>);

impl BuildErrors {
    /// The problems, in check order.
    pub fn errors(&self) -> &[CompositionError] {
        &self.0
    }
}

impl fmt::Display for BuildErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "harness composition failed with {} error(s):", self.0.len())?;
        for error in &self.0 {
            write!(f, "\n  - {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for BuildErrors {}

/// Collects ports, step kinds and named types, then checks the composition. Assembled through
/// [`Harness::builder`] — no ambient state, no defaults snuck in behind the caller's back.
pub struct HarnessBuilder {
    ports: Ports,
    steps: Vec<Arc<dyn StepKind>>,
    types: BTreeMap<&'static str, TypeDef>,
}

impl HarnessBuilder {
    /// Starts an empty builder.
    #[must_use]
    pub fn new() -> HarnessBuilder {
        HarnessBuilder { ports: Ports::default(), steps: Vec::new(), types: BTreeMap::new() }
    }

    /// Provides the composition's ports.
    #[must_use]
    pub fn ports(mut self, ports: Ports) -> HarnessBuilder {
        self.ports = ports;
        self
    }

    /// Registers a step kind.
    #[must_use]
    pub fn step(mut self, step: impl StepKind) -> HarnessBuilder {
        self.steps.push(Arc::new(step));
        self
    }

    /// Registers a step kind already behind an [`Arc`].
    #[must_use]
    pub fn step_arc(mut self, step: Arc<dyn StepKind>) -> HarnessBuilder {
        self.steps.push(step);
        self
    }

    /// Registers a named type schemas can reference.
    #[must_use]
    pub fn type_def(mut self, def: TypeDef) -> HarnessBuilder {
        self.types.insert(def.name, def);
        self
    }

    /// Checks the whole composition and builds the harness, collecting every error: the clock
    /// check and reserved type names first, then per step in registration order — duplicate
    /// names, port lists, step API, secret outputs, and each schema field's type, null rule
    /// and default.
    pub fn build(self) -> Result<Harness, BuildErrors> {
        let HarnessBuilder { ports, steps, types } = self;
        let mut errors = Vec::new();

        if ports.clock().is_none() {
            errors.push(CompositionError::MissingClock);
        }

        // The built-in names belong to the language; a `type_def` may not shadow them.
        for def in types.values() {
            if built_in(def.name).is_some() {
                errors.push(CompositionError::ReservedTypeName { name: def.name.to_string() });
            }
        }

        let mut name_counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for step in &steps {
            *name_counts.entry(step.name()).or_default() += 1;
        }
        let mut reported: BTreeSet<&'static str> = BTreeSet::new();

        let provided = ports.provided();
        for step in &steps {
            let name = step.name();
            // One error per duplicated name, reported at its first registration.
            if name_counts[name] > 1 && reported.insert(name) {
                errors.push(CompositionError::DuplicateStepName {
                    name: name.to_string(),
                    count: name_counts[name],
                });
            }
            // One report per distinct port, even if a step lists it twice.
            let mut seen = BTreeSet::new();
            for port in step.requires().iter().filter(|port| seen.insert(**port)) {
                if step.optional().contains(port) {
                    errors.push(CompositionError::PortInBothLists {
                        step: name.to_string(),
                        port: *port,
                    });
                }
                if !provided.contains(port) {
                    errors.push(CompositionError::MissingPort {
                        step: name.to_string(),
                        port: *port,
                    });
                }
            }
            if step.step_api() != STEP_API {
                errors.push(CompositionError::StepApiMismatch {
                    step: name.to_string(),
                    found: step.step_api(),
                });
            }
            // In v1 secrets flow into steps, never out of them.
            let schema = step.schema();
            for field in &schema.outputs {
                if field.ty == TypeRef::Named("Secret") {
                    errors.push(CompositionError::SecretOutput {
                        step: name.to_string(),
                        output: field.name.to_string(),
                    });
                }
            }
            for field in schema.inputs.iter().chain(&schema.outputs) {
                let resolved = resolve_in(&types, &field.ty);
                if resolved == Some(ValueType::Null) {
                    errors.push(CompositionError::NullType {
                        step: name.to_string(),
                        field: field.name.to_string(),
                    });
                    continue;
                }
                let Some(resolved) = resolved else {
                    let TypeRef::Named(type_name) = field.ty else { continue };
                    errors.push(CompositionError::UnknownType {
                        step: name.to_string(),
                        field: field.name.to_string(),
                        type_name: type_name.to_string(),
                    });
                    continue;
                };
                if let Some(default) = &field.default
                    && default.value_type() != resolved
                {
                    errors.push(CompositionError::DefaultTypeMismatch {
                        step: name.to_string(),
                        field: field.name.to_string(),
                    });
                }
            }
        }

        if errors.is_empty() {
            let by_name: BTreeMap<&'static str, Arc<dyn StepKind>> =
                steps.iter().map(|step| (step.name(), Arc::clone(step))).collect();
            Ok(Harness { ports, steps, by_name, types })
        } else {
            Err(BuildErrors(errors))
        }
    }
}

impl Default for HarnessBuilder {
    fn default() -> HarnessBuilder {
        HarnessBuilder::new()
    }
}

/// A checked composition of ports and step kinds. Pure: it only *knows* things. Execution goes
/// through `ks_engine::run::run_step`, which uses this type's checks
/// ([`prepare_inputs`](Harness::prepare_inputs), [`check_outputs`](Harness::check_outputs))
/// around a step's `run`.
pub struct Harness {
    ports: Ports,
    steps: Vec<Arc<dyn StepKind>>,
    by_name: BTreeMap<&'static str, Arc<dyn StepKind>>,
    types: BTreeMap<&'static str, TypeDef>,
}

impl Harness {
    /// Starts a builder.
    #[must_use]
    pub fn builder() -> HarnessBuilder {
        HarnessBuilder::new()
    }

    /// The registered step with this name.
    pub fn step(&self, name: &str) -> Option<&Arc<dyn StepKind>> {
        self.by_name.get(name)
    }

    /// Every registered step, in registration order.
    pub fn steps(&self) -> impl Iterator<Item = &Arc<dyn StepKind>> {
        self.steps.iter()
    }

    /// The composition's ports.
    pub fn ports(&self) -> &Ports {
        &self.ports
    }

    /// The composition's clock — present on every built harness.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        self.ports.clock().expect("build() refuses a harness without a Clock")
    }

    /// Resolves a type reference against the registered type definitions and the built-in
    /// named types.
    pub fn resolve(&self, ty: &TypeRef) -> Option<ValueType> {
        resolve_in(&self.types, ty)
    }

    /// Prepares a run's inputs against `step`'s schema: applies defaults, then requires every
    /// present value to be a declared input of the declared type.
    pub fn prepare_inputs(
        &self,
        step: &dyn StepKind,
        mut inputs: Inputs,
    ) -> Result<Inputs, StepError> {
        let schema = step.schema();
        for field in &schema.inputs {
            if inputs.contains_key(field.name) {
                continue;
            }
            match &field.default {
                Some(default) => {
                    inputs.insert(field.name.to_string(), default.clone());
                }
                None if field.optional => {}
                None => {
                    return Err(StepError::InvalidInput {
                        field: field.name.to_string(),
                        reason: "it is required but missing".to_string(),
                    });
                }
            }
        }
        for (name, value) in &inputs {
            let Some(field) = schema.inputs.iter().find(|field| field.name == name.as_str()) else {
                return Err(StepError::InvalidInput {
                    field: name.clone(),
                    reason: "no input with this name is declared".to_string(),
                });
            };
            let Some(expected) = self.resolve(&field.ty) else {
                return Err(StepError::InvalidInput {
                    field: name.clone(),
                    reason: "it references an unknown type".to_string(),
                });
            };
            if value.value_type() != expected {
                return Err(StepError::InvalidInput {
                    field: name.clone(),
                    reason: format!("expected a {expected}, found a {}", value.value_type()),
                });
            }
        }
        Ok(inputs)
    }

    /// Checks a step's returned outputs against its schema: every declared output present and
    /// of the declared type, and nothing else — a step may not invent outputs, matching the
    /// script host's strict validation.
    pub fn check_outputs(&self, step: &dyn StepKind, outputs: &Outputs) -> Result<(), StepError> {
        let schema = step.schema();
        for field in &schema.outputs {
            let Some(value) = outputs.get(field.name) else {
                return Err(StepError::InvalidOutput {
                    field: field.name.to_string(),
                    reason: "it is declared but the step never returned it".to_string(),
                });
            };
            let Some(expected) = self.resolve(&field.ty) else {
                return Err(StepError::InvalidOutput {
                    field: field.name.to_string(),
                    reason: "references an unknown type".to_string(),
                });
            };
            if value.value_type() != expected {
                return Err(StepError::InvalidOutput {
                    field: field.name.to_string(),
                    reason: format!("expected a {expected}, found a {}", value.value_type()),
                });
            }
        }
        for name in outputs.keys() {
            if !schema.outputs.iter().any(|field| field.name == name.as_str()) {
                return Err(StepError::InvalidOutput {
                    field: name.clone(),
                    reason: "it is returned but the step never declared it".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// The language's built-in named types, resolvable without an explicit `type_def` so TS steps
/// and third-party steps can declare them. Registering a `type_def` with one of these names is
/// refused ([`CompositionError::ReservedTypeName`]).
const BUILT_IN_TYPES: &[TypeDef] = &[
    TypeDef {
        name: "Secret",
        base: ValueType::String,
        doc: "a secret reference, resolved per environment; never materialised at check time",
    },
    TypeDef { name: "duration", base: ValueType::String, doc: "a duration, e.g. `30s` or `1m`" },
    TypeDef { name: "path", base: ValueType::String, doc: "a filesystem path" },
    TypeDef { name: "url", base: ValueType::String, doc: "an absolute URL" },
    TypeDef { name: "int", base: ValueType::Number, doc: "a whole number" },
];

/// The built-in named type with this name, if any.
fn built_in(name: &str) -> Option<TypeDef> {
    BUILT_IN_TYPES.iter().copied().find(|def| def.name == name)
}

/// Resolves a [`TypeRef`] against the registered definitions and the built-in named types.
fn resolve_in(types: &BTreeMap<&'static str, TypeDef>, ty: &TypeRef) -> Option<ValueType> {
    match ty {
        TypeRef::Builtin(base) => Some(*base),
        TypeRef::Named(name) => {
            types.get(name).map(|def| def.base).or_else(|| built_in(name).map(|def| def.base))
        }
    }
}

impl fmt::Debug for Harness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Harness")
            .field("ports", &self.ports.provided())
            .field("steps", &self.by_name.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::BoxFuture;
    use crate::ports::script_host::Value;
    use crate::step::test_support::FixedClock;
    use crate::step::{ActionClass, ActionKind, Field, StepCtx, StepSchema};
    use std::time::SystemTime;

    /// A step kind shaped by its fields, for composition tests.
    struct TestStep {
        name: &'static str,
        requires: &'static [Port],
        optional: &'static [Port],
        api: u32,
        schema: StepSchema,
    }

    /// A default-shaped [`TestStep`], for struct-update literals:
    /// `TestStep { api: STEP_API + 1, ..step("x") }`.
    fn step(name: &'static str) -> TestStep {
        TestStep {
            name,
            requires: &[],
            optional: &[],
            api: STEP_API,
            schema: StepSchema { doc: "a step for tests", inputs: Vec::new(), outputs: Vec::new() },
        }
    }

    /// A step with these inputs and no outputs.
    fn schema(inputs: Vec<Field>) -> StepSchema {
        StepSchema { doc: "a step for tests", inputs, outputs: Vec::new() }
    }

    impl StepKind for TestStep {
        fn name(&self) -> &'static str {
            self.name
        }

        fn version(&self) -> crate::step::Version {
            crate::step::Version::new(0, 1, 0)
        }

        fn step_api(&self) -> u32 {
            self.api
        }

        fn schema(&self) -> StepSchema {
            self.schema.clone()
        }

        fn requires(&self) -> &'static [Port] {
            self.requires
        }

        fn optional(&self) -> &'static [Port] {
            self.optional
        }

        fn action(&self, _inputs: &Inputs) -> ActionClass {
            ActionClass::new(ActionKind::Other)
        }

        fn run(&self, _ctx: StepCtx, _inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
            Box::pin(std::future::ready(Ok(Outputs::new())))
        }
    }

    /// A schema exercising named types and defaults.
    fn typed_schema() -> StepSchema {
        StepSchema {
            doc: "a typed step for tests",
            inputs: vec![
                Field::new("image", TypeRef::Builtin(ValueType::String), "the image"),
                Field::new("tag", TypeRef::Builtin(ValueType::String), "the tag")
                    .with_default(Value::from("latest")),
            ],
            outputs: vec![Field::new("digest", TypeRef::Named("digest"), "the digest")],
        }
    }

    /// A builder with a clock and one typed step, ready to `build`.
    fn valid_builder() -> HarnessBuilder {
        Harness::builder()
            .ports(Ports::default().with_clock(Arc::new(FixedClock)))
            .type_def(TypeDef { name: "digest", base: ValueType::String, doc: "an OCI digest" })
            .step(TestStep { schema: typed_schema(), ..step("sample.step") })
    }

    fn clocked_builder() -> HarnessBuilder {
        Harness::builder().ports(Ports::default().with_clock(Arc::new(FixedClock)))
    }

    /// Every `build()` failure mode, refused with exactly these messages.
    #[test]
    fn build_reports_each_fault_with_its_exact_message() {
        // The stale step's message names both numbers, so it cannot be a
        // literal: `STEP_API + 1` keeps this case firing after every bump. The
        // one formatted case owns a leaked `&'static [&'static str]` so it can
        // sit in the same table as the literals.
        let stale_api_message: &str = Box::leak(
            format!(
                r#"step "oci.image" was built against step API {}, but this harness speaks step API {STEP_API}"#,
                STEP_API + 1
            )
            .into_boxed_str(),
        );
        let stale_api: &[&str] = std::slice::from_ref(&stale_api_message);
        let cases: Vec<(&str, HarnessBuilder, &[&str])> = vec![
            (
                "a missing clock",
                Harness::builder(),
                &["the harness requires port Clock, but no Clock was provided"],
            ),
            (
                "a missing port",
                clocked_builder()
                    .step(TestStep { requires: &[Port::Registry], ..step("oci.image") }),
                &[r#"step "oci.image" requires port Registry, but no Registry was provided"#],
            ),
            (
                "a port in both lists",
                clocked_builder().step(TestStep {
                    requires: &[Port::Signer],
                    optional: &[Port::Signer],
                    ..step("oci.image")
                }),
                &[
                    r#"step "oci.image" lists port Signer in both requires and optional"#,
                    r#"step "oci.image" requires port Signer, but no Signer was provided"#,
                ],
            ),
            (
                "a duplicated name",
                clocked_builder()
                    .step(step("oci.image"))
                    .step(step("other.step"))
                    .step(step("oci.image")),
                &[r#"step name "oci.image" is registered 2 times"#],
            ),
            (
                "a step api mismatch",
                // `STEP_API + 1`, not a literal: a bump to `STEP_API` must not
                // quietly turn this case into a composition that now succeeds.
                clocked_builder().step(TestStep { api: STEP_API + 1, ..step("oci.image") }),
                stale_api,
            ),
            (
                "an unknown named type",
                clocked_builder().step(TestStep { schema: typed_schema(), ..step("oci.image") }),
                &[r#"step "oci.image" field "digest" references unknown type "digest""#],
            ),
            (
                "a builtin null type",
                clocked_builder().step(TestStep {
                    schema: schema(vec![Field::new(
                        "ghost",
                        TypeRef::Builtin(ValueType::Null),
                        "nothing",
                    )]),
                    ..step("oci.image")
                }),
                &[r#"step "oci.image" field "ghost" declares type null, which no value satisfies"#],
            ),
            (
                "a named null type",
                clocked_builder()
                    .type_def(TypeDef {
                        name: "nothing",
                        base: ValueType::Null,
                        doc: "no value has this type",
                    })
                    .step(TestStep {
                        schema: schema(vec![Field::new("who", TypeRef::Named("nothing"), "none")]),
                        ..step("oci.image")
                    }),
                &[r#"step "oci.image" field "who" declares type null, which no value satisfies"#],
            ),
            (
                "a mistyped default",
                clocked_builder().step(TestStep {
                    schema: schema(vec![
                        Field::new("replicas", TypeRef::Builtin(ValueType::Number), "how many")
                            .with_default(Value::from("three")),
                    ]),
                    ..step("scale.app")
                }),
                &[
                    r#"step "scale.app" field "replicas" has a default that does not match its type"#,
                ],
            ),
            (
                "an output typed Secret",
                clocked_builder().step(TestStep {
                    schema: StepSchema {
                        doc: "a step for tests",
                        inputs: vec![Field::new(
                            "token",
                            TypeRef::Named("Secret"),
                            "the registry token",
                        )],
                        outputs: vec![Field::new(
                            "token",
                            TypeRef::Named("Secret"),
                            "the registry token",
                        )],
                    },
                    ..step("registry.login")
                }),
                &[
                    r#"step "registry.login" output "token" declares type Secret, but outputs cannot be secrets"#,
                ],
            ),
            (
                "a redefined built-in type",
                clocked_builder().type_def(TypeDef {
                    name: "Secret",
                    base: ValueType::Number,
                    doc: "not the language's Secret",
                }),
                &[r#"type "Secret" is built in and cannot be redefined"#],
            ),
        ];
        for (case, builder, expected) in cases {
            let errors = builder.build().expect_err(case);
            assert_eq!(errors.errors().len(), expected.len(), "{case}: {errors}");
            for (error, message) in errors.errors().iter().zip(expected) {
                assert_eq!(error.to_string(), *message, "{case}");
            }
        }
    }

    #[test]
    fn every_fault_is_reported_together_in_order() {
        let errors = Harness::builder() // no Clock, no Registry, no "digest" type
            .step(TestStep {
                api: STEP_API + 1,
                requires: &[Port::Registry],
                schema: typed_schema(),
                ..step("oci.image")
            })
            .step(step("other.step"))
            .step(step("oci.image"))
            .build()
            .expect_err("the composition should be refused");
        assert_eq!(
            errors.errors(),
            &[
                CompositionError::MissingClock,
                CompositionError::DuplicateStepName { name: "oci.image".to_string(), count: 2 },
                CompositionError::MissingPort {
                    step: "oci.image".to_string(),
                    port: Port::Registry
                },
                CompositionError::StepApiMismatch {
                    step: "oci.image".to_string(),
                    found: STEP_API + 1,
                },
                CompositionError::UnknownType {
                    step: "oci.image".to_string(),
                    field: "digest".to_string(),
                    type_name: "digest".to_string(),
                },
            ]
        );
    }

    #[test]
    fn a_valid_composition_builds_and_answers_lookups() {
        let harness = valid_builder().build().expect("the composition is valid");
        assert_eq!(harness.steps().count(), 1);
        assert!(harness.step("sample.step").is_some());
        assert!(harness.step("nope.step").is_none());
        assert_eq!(harness.ports().provided(), BTreeSet::from([Port::Clock]));
        assert_eq!(harness.clock().now(), SystemTime::UNIX_EPOCH);
        assert_eq!(harness.resolve(&TypeRef::Named("digest")), Some(ValueType::String));
        assert_eq!(harness.resolve(&TypeRef::Builtin(ValueType::Number)), Some(ValueType::Number));
        assert_eq!(harness.resolve(&TypeRef::Named("ghost")), None);
    }

    #[test]
    fn prepare_inputs_applies_defaults_and_rejects_bad_values() {
        let harness = valid_builder().build().expect("the composition is valid");
        let step = harness.step("sample.step").expect("registered");

        let mut inputs = Inputs::new();
        inputs.insert("image".to_string(), Value::from("app:1.0"));
        let prepared = harness.prepare_inputs(step.as_ref(), inputs).expect("valid inputs");
        assert_eq!(prepared.get("tag"), Some(&Value::from("latest")), "the default is applied");

        let missing = harness.prepare_inputs(step.as_ref(), Inputs::new()).expect_err("required");
        assert_eq!(
            missing,
            StepError::InvalidInput {
                field: "image".to_string(),
                reason: "it is required but missing".to_string()
            }
        );

        let mut mistyped = Inputs::new();
        mistyped.insert("image".to_string(), Value::from(42.0));
        assert!(matches!(
            harness.prepare_inputs(step.as_ref(), mistyped),
            Err(StepError::InvalidInput { field, reason })
                if field == "image" && reason.contains("expected a string, found a number")
        ));

        let mut unknown = Inputs::new();
        unknown.insert("image".to_string(), Value::from("app:1.0"));
        unknown.insert("bogus".to_string(), Value::from("x"));
        assert!(matches!(
            harness.prepare_inputs(step.as_ref(), unknown),
            Err(StepError::InvalidInput { field, .. }) if field == "bogus"
        ));
    }

    #[test]
    fn check_outputs_is_strict_in_both_directions() {
        let harness = valid_builder().build().expect("the composition is valid");
        let step = harness.step("sample.step").expect("registered");

        assert!(matches!(
            harness.check_outputs(step.as_ref(), &Outputs::new()),
            Err(StepError::InvalidOutput { field, .. }) if field == "digest"
        ));
        let mut outputs = Outputs::new();
        outputs.insert("digest".to_string(), Value::from(7.0));
        assert!(matches!(
            harness.check_outputs(step.as_ref(), &outputs),
            Err(StepError::InvalidOutput { field, reason })
                if field == "digest" && reason.contains("expected a string, found a number")
        ));
        outputs.insert("digest".to_string(), Value::from("sha256:00"));
        outputs.insert("surprise".to_string(), Value::from("x"));
        assert!(matches!(
            harness.check_outputs(step.as_ref(), &outputs),
            Err(StepError::InvalidOutput { field, reason })
                if field == "surprise" && reason.contains("never declared")
        ));
        outputs.remove("surprise");
        assert_eq!(harness.check_outputs(step.as_ref(), &outputs), Ok(()));
    }

    /// The built-in named types resolve without an explicit `type_def`; unregistered names
    /// stay unknown.
    #[test]
    fn built_in_types_resolve_without_a_type_def() {
        let harness = clocked_builder().build().expect("nothing needs registering");
        for (name, base) in [
            ("Secret", ValueType::String),
            ("duration", ValueType::String),
            ("path", ValueType::String),
            ("url", ValueType::String),
            ("int", ValueType::Number),
        ] {
            assert_eq!(harness.resolve(&TypeRef::Named(name)), Some(base), "{name}");
        }
        assert_eq!(harness.resolve(&TypeRef::Named("digest")), None);
    }

    /// A `Secret` input is welcome — the built-in name resolves without a
    /// `type_def` — while a `Secret` output is refused at build time. The
    /// run-time halves live in the `prepare_inputs`/`check_outputs` tests.
    #[test]
    fn secret_inputs_are_typed_like_strings_but_secret_outputs_are_refused() {
        let builder = clocked_builder().step(TestStep {
            schema: StepSchema {
                doc: "a step for tests",
                inputs: vec![
                    Field::new("token", TypeRef::Named("Secret"), "the registry token")
                        .with_default(Value::from("env:REGISTRY_TOKEN")),
                ],
                outputs: vec![Field::new("image", TypeRef::Named("Secret"), "the pushed image")],
            },
            ..step("registry.push")
        });
        assert!(matches!(
            builder.build(),
            Err(BuildErrors(errors))
                if errors == vec![CompositionError::SecretOutput {
                    step: "registry.push".to_string(),
                    output: "image".to_string(),
                }]
        ));

        let harness = clocked_builder()
            .step(TestStep {
                schema: StepSchema {
                    doc: "a step for tests",
                    inputs: vec![
                        Field::new("token", TypeRef::Named("Secret"), "the registry token")
                            .with_default(Value::from("env:REGISTRY_TOKEN")),
                    ],
                    outputs: vec![Field::new("image", TypeRef::Named("path"), "the pushed image")],
                },
                ..step("registry.push")
            })
            .build()
            .expect("a Secret input is fine");
        assert!(harness.step("registry.push").is_some(), "built-in `Secret` resolves");
    }
}
