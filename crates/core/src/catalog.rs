//! The step catalog: the step kinds a check knows, with the input and
//! output types each declares, plus the nominal type vocabulary those
//! schemas share ([#24](https://github.com/Keep-Shipping/harness/issues/24)).

use std::collections::HashMap;
use std::fmt;

use crate::harness::Harness;
use crate::ports::script_host::{Value, ValueType};
use crate::step::{ActionClass, ActionKind, StepCapabilities, StepSchema, TypeRef};
use crate::types::{self, Type};

/// One step kind's contract as the checker reads it: the input types values
/// are checked against, and the output types references resolve to.
#[derive(Clone, Debug)]
pub struct StepTypes {
    /// The kind's stable name (`oci.image`).
    pub name: String,
    /// Inputs by name, in declaration order.
    pub inputs: Vec<(String, Type)>,
    /// Outputs by name, in declaration order.
    pub outputs: Vec<(String, Type)>,
    /// Outputs known only at run time; read as `<step>.out.<name>`.
    pub runtime_outputs: bool,
    /// `decide`: the bare step name and its `answer` output type as the
    /// declared `returns:` variants.
    pub decision: bool,
    /// What the kind needs from its environment, as its
    /// [`StepKind::capabilities`](crate::step::StepKind::capabilities) declares
    /// it — checked against the context a run would have.
    pub capabilities: StepCapabilities,
}

/// `when:` is a reserved input on every step: a boolean expression.
pub(crate) const WHEN: &str = "when";

/// `after:` is reserved too: the step(s) a step runs after, ordering without
/// data ([#40](https://github.com/Keep-Shipping/harness/issues/40)).
pub(crate) const AFTER: &str = "after";

impl StepTypes {
    /// The declared type of input `name` (`when:` is always a bool).
    pub(crate) fn input(&self, name: &str) -> Option<Type> {
        if name == WHEN {
            return Some(Type::Bool);
        }
        self.inputs.iter().find(|(n, _)| n == name).map(|(_, ty)| ty.clone())
    }

    /// The declared type of output `name`.
    pub(crate) fn output(&self, name: &str) -> Option<&Type> {
        self.outputs.iter().find(|(n, _)| n == name).map(|(_, ty)| ty)
    }

    /// What a run of this step kind is, for policy
    /// ([#101](https://github.com/Keep-Shipping/harness/issues/101)): the
    /// kind's name through [`action_kind`], with no environment — the
    /// catalog does not know which environment a run selected.
    #[must_use]
    pub fn action(&self) -> ActionClass {
        ActionClass::new(action_kind(&self.name))
    }

    /// The input names a value could be meant for, the reserved ones
    /// included.
    pub fn input_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.inputs.iter().map(|(n, _)| n.clone()).collect();
        v.push(WHEN.to_string());
        v.push(AFTER.to_string());
        v
    }
}

/// Why a schema could not join a [`Catalog`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogError {
    message: String,
}

impl CatalogError {
    fn new(message: impl Into<String>) -> CatalogError {
        CatalogError { message: message.into() }
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CatalogError {}

/// The step kinds a check knows, and the nominal types their schemas name.
/// [`Catalog::builtin`] carries the built-in families; schemas for custom
/// steps join with [`Catalog::add_schema`].
#[derive(Default)]
pub struct Catalog {
    steps: HashMap<String, StepTypes>,
    /// The declared nominal types with, when known, why they exist — type
    /// mismatch hints quote the rationale.
    types: Vec<(&'static str, Option<&'static str>)>,
}

impl Catalog {
    /// The built-in catalog: the built-in step kinds plus the domain
    /// families' nominal types.
    #[must_use]
    pub fn builtin() -> Catalog {
        let mut catalog = Catalog { types: FAMILIES.to_vec(), ..Catalog::default() };
        let mut add = |name: &str,
                       inputs: &[(&str, Type)],
                       outputs: &[(&str, Type)],
                       runtime_outputs: bool,
                       decision: bool| {
            catalog.steps.insert(
                name.to_string(),
                StepTypes {
                    name: name.to_string(),
                    inputs: owned(inputs),
                    outputs: owned(outputs),
                    runtime_outputs,
                    decision,
                    capabilities: StepCapabilities::default(),
                },
            );
        };
        add(
            "oci.image",
            &[
                ("from", Type::Path),
                ("context", Type::Optional(Box::new(Type::Path))),
                ("args", Type::Optional(Box::new(Type::Map(Box::new(Type::Any))))),
                ("secrets", Type::Optional(Box::new(Type::Map(Box::new(Type::Any))))),
                ("platforms", Type::Optional(Box::new(Type::List(Box::new(Type::Any))))),
                ("target", Type::Optional(Box::new(Type::String))),
                ("push", named("oci.Tag")),
                ("sign", Type::Optional(Box::new(Type::Bool))),
                ("sbom", Type::Optional(Box::new(Type::Bool))),
                ("cache", Type::Optional(Box::new(Type::String))),
            ],
            &[
                ("digest", named("oci.Digest")),
                ("ref", named("oci.Ref")),
                ("tag", named("oci.Tag")),
                ("signed", Type::Bool),
                ("sbom", named("oci.Artifact")),
                ("provenance", named("oci.Artifact")),
                ("platforms", Type::List(Box::new(Type::Any))),
            ],
            false,
            false,
        );
        add(
            "oci.verify",
            &[("image", named("oci.Digest")), ("signed_by", Type::String)],
            &[("digest", named("oci.Digest")), ("identity", Type::String)],
            false,
            false,
        );
        // `subject` and `sign` carry defaults in the step schema, so the
        // catalog types them as optional — what `insert_schema` would produce.
        add(
            "oci.artifact",
            &[
                ("files", Type::List(Box::new(Type::Any))),
                ("type", Type::String),
                ("push", named("oci.Tag")),
                ("subject", Type::Optional(Box::new(named("oci.Digest")))),
                ("sign", Type::Optional(Box::new(Type::Bool))),
            ],
            &[("digest", named("oci.Digest")), ("ref", named("oci.Ref"))],
            false,
            false,
        );
        add(
            "tofu.plan",
            &[
                ("dir", Type::Path),
                ("backend", Type::Optional(Box::new(Type::String))),
                ("backend_config", Type::Optional(Box::new(Type::Map(Box::new(Type::String))))),
                ("vars", Type::Optional(Box::new(Type::Map(Box::new(Type::String))))),
                ("role", Type::Optional(Box::new(Type::String))),
            ],
            &[
                ("file", named("tofu.PlanFile")),
                ("changes", named("tofu.Changes")),
                ("adds", Type::Int),
                ("changes_count", Type::Int),
                ("destroys", Type::Int),
                ("empty", Type::Bool),
                ("summary", Type::String),
            ],
            false,
            false,
        );
        // `hosts`, `run` and `rollback` are lists of maps, which a `TypeRef` cannot spell more
        // precisely than a list: the step schema declares them as lists, so the catalog says the
        // same and the two cannot drift.
        add(
            "vm.deploy",
            &[
                ("hosts", Type::List(Box::new(Type::Any))),
                ("batch", Type::Optional(Box::new(Type::String))),
                ("run", Type::Optional(Box::new(Type::List(Box::new(Type::Any))))),
                ("health", Type::Optional(Box::new(Type::String))),
                ("health_timeout", Type::Optional(Box::new(Type::Int))),
                ("max_failures", Type::Optional(Box::new(Type::Int))),
                ("rollback", Type::Optional(Box::new(Type::List(Box::new(Type::Any))))),
                ("ssh_user", Type::Optional(Box::new(Type::String))),
                // What the deploy ships, and the identity it must be signed by. Both optional:
                // a deploy that names no artifact has nothing to verify, and a deploy that names
                // no identity verifies nothing.
                ("image", Type::Optional(Box::new(Type::String))),
                ("verify", Type::Optional(Box::new(Type::String))),
            ],
            &[("healthy", Type::Int), ("total", Type::Int), ("summary", Type::String)],
            false,
            false,
        );
        // `quorum` and `expires` carry defaults in the step schema, so the
        // catalog types them as optional, as it does for `oci.artifact`.
        add(
            "approval",
            &[
                ("show", Type::Any),
                ("from", Type::Handle),
                ("quorum", Type::Optional(Box::new(Type::Int))),
                ("expires", Type::Optional(Box::new(Type::Duration))),
                ("auto", Type::Bool),
                ("else", Type::Any),
            ],
            &[
                ("approved_by", Type::List(Box::new(named("Identity")))),
                ("at", Type::String),
                ("comment", Type::String),
            ],
            false,
            false,
        );
        add(
            "tofu.apply",
            &[("plan", named("tofu.PlanFile")), ("role", Type::Optional(Box::new(Type::String)))],
            &[("out", named("tofu.Outputs")), ("applied", Type::Int)],
            true,
            false,
        );
        // The same two steps under the Terraform names. The shapes are identical on purpose —
        // field for field with `tofu.plan` / `tofu.apply` above — and only the nominal types
        // differ. That is what stops a plan made by OpenTofu from being applied by `terraform`:
        // the plan file formats are not interchangeable, and the type system says so.
        add(
            "terraform.plan",
            &[
                ("dir", Type::Path),
                ("backend", Type::Optional(Box::new(Type::String))),
                ("backend_config", Type::Optional(Box::new(Type::Map(Box::new(Type::String))))),
                ("vars", Type::Optional(Box::new(Type::Map(Box::new(Type::String))))),
                ("role", Type::Optional(Box::new(Type::String))),
            ],
            &[
                ("file", named("terraform.PlanFile")),
                ("changes", named("terraform.Changes")),
                ("adds", Type::Int),
                ("changes_count", Type::Int),
                ("destroys", Type::Int),
                ("empty", Type::Bool),
                ("summary", Type::String),
            ],
            false,
            false,
        );
        add(
            "terraform.apply",
            &[
                ("plan", named("terraform.PlanFile")),
                ("role", Type::Optional(Box::new(Type::String))),
            ],
            &[("out", named("terraform.Outputs")), ("applied", Type::Int)],
            true,
            false,
        );
        add(
            "k8s.rollout",
            &[
                ("image", named("oci.Digest")),
                ("to", named("k8s.Cluster")),
                ("wait", Type::Any),
                // Optional because the step schema gives `verify` an empty default: a rollout
                // that names no identity verifies nothing, exactly as it does today.
                ("verify", Type::Optional(Box::new(Type::String))),
                // What is deployed, and where it goes. Optional, because a
                // rollout may pin each image by container name instead, and
                // because a workflow may declare its own defaults.
                ("manifests", Type::Optional(Box::new(Type::Path))),
                ("images", Type::Optional(Box::new(Type::Map(Box::new(named("oci.Digest")))))),
                ("namespace", Type::Optional(Box::new(Type::String))),
                ("rollback", Type::Optional(Box::new(Type::String))),
            ],
            &[],
            true,
            false,
        );
        // `answer` is resolved per step from its `returns:` variants.
        add(
            "decide",
            &[
                ("model", Type::String),
                ("ask", Type::String),
                ("input", Type::Any),
                ("returns", Type::Any),
            ],
            &[
                ("answer", Type::Any),
                ("confidence", Type::Float),
                ("probabilities", Type::Map(Box::new(Type::Float))),
                ("reason", Type::String),
            ],
            false,
            true,
        );
        catalog
    }

    /// Adds a custom step kind from its schema. Field defaults make an input
    /// optional and are checked against the field's declared type. Fails
    /// when `name` is already in the catalog, or when the schema declares an
    /// output of type `Secret`: a secret output would invite exactly the
    /// leaks the type system exists to prevent.
    ///
    /// A schema registered this way declares no capabilities, so its steps
    /// need nothing beyond a laptop. Only [`Catalog::from_harness`], which has
    /// the [`StepKind`](crate::step::StepKind) that owns the schema, records
    /// what they really need.
    pub fn add_schema(&mut self, name: &str, schema: &StepSchema) -> Result<(), CatalogError> {
        if self.steps.contains_key(name) {
            return Err(CatalogError::new(format!("step `{name}` is already in the catalog")));
        }
        self.insert_schema(name, schema, StepCapabilities::default())
    }

    /// Builds a catalog from a harness: the built-in step kinds plus every
    /// custom step registered there, the harness's schema winning on a name
    /// clash. Fails when a schema breaks the [`Catalog`] rules.
    pub fn from_harness(harness: &Harness) -> Result<Catalog, CatalogError> {
        let mut catalog = Catalog::builtin();
        for step in harness.steps() {
            let name = step.name();
            catalog.steps.remove(name);
            catalog.insert_schema(name, &step.schema(), step.capabilities())?;
        }
        Ok(catalog)
    }

    fn insert_schema(
        &mut self,
        name: &str,
        schema: &StepSchema,
        capabilities: StepCapabilities,
    ) -> Result<(), CatalogError> {
        let mut inputs = Vec::new();
        for field in &schema.inputs {
            let ty = ty_of_ref(field.ty);
            match &field.default {
                Some(default) => {
                    if !default_fits(&ty, default) {
                        return Err(CatalogError::new(format!(
                            "default for input `{}` does not fit its declared type {ty}",
                            field.name
                        )));
                    }
                    inputs.push((field.name.to_string(), Type::Optional(Box::new(ty))));
                }
                None if field.optional => {
                    inputs.push((field.name.to_string(), Type::Optional(Box::new(ty))));
                }
                None => inputs.push((field.name.to_string(), ty)),
            }
        }
        let mut outputs = Vec::new();
        for field in &schema.outputs {
            let ty = ty_of_ref(field.ty);
            if ty == Type::Secret {
                return Err(CatalogError::new("step outputs cannot be Secret in v1"));
            }
            outputs.push((field.name.to_string(), ty));
        }
        self.steps.insert(
            name.to_string(),
            StepTypes {
                name: name.to_string(),
                inputs,
                outputs,
                runtime_outputs: false,
                decision: false,
                capabilities,
            },
        );
        Ok(())
    }

    /// The step kind registered under `name`.
    pub fn step(&self, name: &str) -> Option<&StepTypes> {
        self.steps.get(name)
    }

    /// Every registered step kind, in name order. Editors list these when a
    /// step header is being written.
    pub fn kinds(&self) -> impl Iterator<Item = &StepTypes> {
        let mut kinds: Vec<&StepTypes> = self.steps.values().collect();
        kinds.sort_by(|a, b| a.name.cmp(&b.name));
        kinds.into_iter()
    }

    /// Why the nominal type `want` exists, when the catalog declares one.
    pub(crate) fn rationale(&self, want: &Type) -> Option<&'static str> {
        let Type::Named(name) = want else { return None };
        self.types.iter().find(|(n, _)| *n == name.as_str()).and_then(|(_, r)| *r)
    }
}

/// The action class a catalog step kind name stands for
/// ([#101](https://github.com/Keep-Shipping/harness/issues/101)).
///
/// One table, in one place, so the checker, the docs renderer and any caller
/// asking "what does this step *do* under policy?" cannot disagree: a step kind
/// whose classification exists in two places is a policy that answers two
/// different questions.
///
/// Everything not named is [`ActionKind::Other`], which is the safe answer:
/// `Other` is not policy-governed, so a step kind nobody has classified is
/// never refused on a guess. `approval` and `decide` are deliberately in it —
/// an approval step *is* the ask, and gating it on itself would be circular.
#[must_use]
pub fn action_kind(kind: &str) -> ActionKind {
    match kind {
        "oci.image" | "oci.artifact" => ActionKind::Build,
        "tofu.plan" | "terraform.plan" => ActionKind::Plan,
        "tofu.apply" | "terraform.apply" => ActionKind::Apply,
        "k8s.rollout" | "vm.deploy" => ActionKind::Deploy,
        _ => ActionKind::Other,
    }
}

/// The domain families' nominal types, declared so schemas and hints share
/// one vocabulary. The rationale, when present, is why the type exists;
/// mismatch hints quote it as written.
const FAMILIES: &[(&str, Option<&str>)] = &[
    ("oci.Digest", Some("so prod runs exactly the image you built")),
    ("oci.Ref", None),
    ("oci.Tag", None),
    ("oci.Artifact", None),
    ("tofu.PlanFile", None),
    ("tofu.Changes", None),
    ("tofu.Outputs", None),
    ("terraform.PlanFile", None),
    ("terraform.Changes", None),
    ("terraform.Outputs", None),
    ("k8s.Cluster", None),
    ("k8s.Namespace", None),
    ("vm.Hosts", None),
    ("fn.Version", None),
    ("Secret", None),
    ("Team", None),
    ("Identity", None),
    ("Env", None),
];

fn named(n: &str) -> Type {
    Type::Named(n.to_string())
}

fn owned(fields: &[(&str, Type)]) -> Vec<(String, Type)> {
    fields.iter().map(|(n, ty)| (n.to_string(), ty.clone())).collect()
}

/// Maps a schema type reference onto a checker type: builtins map onto
/// their primitives, names through [`Type::parse`] (`Secret`, `duration`,
/// `int`, `oci.Digest`); an unknown name is nominal.
fn ty_of_ref(ty: TypeRef) -> Type {
    match ty {
        TypeRef::Builtin(ValueType::Bool) => Type::Bool,
        TypeRef::Builtin(ValueType::Number) => Type::Float,
        TypeRef::Builtin(ValueType::String) => Type::String,
        TypeRef::Builtin(ValueType::List) => Type::List(Box::new(Type::Any)),
        TypeRef::Builtin(ValueType::Map) => Type::Map(Box::new(Type::Any)),
        TypeRef::Builtin(ValueType::Null) => Type::Any,
        TypeRef::Named(n) => Type::parse(n).unwrap_or_else(|| Type::Named(n.to_string())),
    }
}

/// Whether a field's default value fits its declared type.
fn default_fits(ty: &Type, value: &Value) -> bool {
    match (ty, value) {
        (Type::Any, _) => true,
        (Type::Bool, Value::Bool(_)) => true,
        (Type::Int, Value::Number(n)) => n.fract() == 0.0,
        (Type::Float, Value::Number(_)) => true,
        (Type::String, Value::String(_)) => true,
        (Type::Optional(inner), v) => default_fits(inner, v),
        (Type::List(inner), Value::List(items)) => items.iter().all(|i| default_fits(inner, i)),
        (Type::Map(inner), Value::Map(entries)) => entries.values().all(|v| default_fits(inner, v)),
        // Durations, paths and nominal types are spelled as strings.
        (_, Value::String(text)) => matches!(types::literal(ty, text, None), types::LiteralFit::Ok),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step::Field;

    fn schema(inputs: Vec<Field>, outputs: Vec<Field>) -> StepSchema {
        StepSchema { doc: "a test step", inputs, outputs }
    }

    fn field(name: &'static str, ty: TypeRef) -> Field {
        Field::new(name, ty, "")
    }

    #[test]
    fn builtin_carries_the_built_in_steps() {
        let catalog = Catalog::builtin();
        let image = catalog.step("oci.image").expect("oci.image");
        assert_eq!(image.output("digest"), Some(&named("oci.Digest")));
        assert_eq!(image.input("push"), Some(named("oci.Tag")));
        assert_eq!(image.input("when"), Some(Type::Bool), "when is reserved");
        let decide = catalog.step("decide").expect("decide");
        assert!(decide.decision);
    }

    /// `oci.artifact` carries the same types its step schema declares, so a
    /// `.ks` file using it is checked rather than passing with no spec.
    #[test]
    fn builtin_carries_the_artifact_step() {
        let catalog = Catalog::builtin();
        let artifact = catalog.step("oci.artifact").expect("oci.artifact");
        assert_eq!(artifact.input("files"), Some(Type::List(Box::new(Type::Any))));
        assert_eq!(artifact.input("type"), Some(Type::String));
        assert_eq!(artifact.input("push"), Some(named("oci.Tag")));
        assert_eq!(
            artifact.input("subject"),
            Some(Type::Optional(Box::new(named("oci.Digest")))),
            "subject defaults, so it is optional in a plan"
        );
        assert_eq!(artifact.input("sign"), Some(Type::Optional(Box::new(Type::Bool))));
        assert_eq!(artifact.output("digest"), Some(&named("oci.Digest")));
        assert_eq!(artifact.output("ref"), Some(&named("oci.Ref")));
    }

    #[test]
    fn the_digest_rationale_is_what_hints_quote() {
        let catalog = Catalog::builtin();
        assert_eq!(
            catalog.rationale(&named("oci.Digest")),
            Some("so prod runs exactly the image you built")
        );
        assert_eq!(catalog.rationale(&named("oci.Tag")), None);
        assert_eq!(catalog.rationale(&Type::String), None);
    }

    #[test]
    fn a_schema_joins_with_names_parsed_and_defaults_optional() {
        let mut catalog = Catalog::builtin();
        catalog
            .add_schema(
                "web.deploy",
                &schema(
                    vec![
                        field("replicas", TypeRef::Named("int")).with_default(Value::Number(2.0)),
                        field("image", TypeRef::Named("oci.Digest")),
                        field("weight", TypeRef::Builtin(ValueType::Number)),
                        field("tags", TypeRef::Named("list[string]")),
                    ],
                    vec![],
                ),
            )
            .expect("schema joins");
        let deploy = catalog.step("web.deploy").expect("web.deploy");
        assert_eq!(deploy.input("replicas"), Some(Type::Optional(Box::new(Type::Int))));
        assert_eq!(deploy.input("image"), Some(named("oci.Digest")));
        assert_eq!(deploy.input("weight"), Some(Type::Float), "schema numbers are floats");
        assert_eq!(deploy.input("tags"), Some(Type::List(Box::new(Type::String))));
    }

    #[test]
    fn a_duplicate_step_name_is_refused() {
        let mut catalog = Catalog::builtin();
        let err = catalog
            .add_schema("oci.image", &schema(vec![], vec![]))
            .expect_err("duplicate refused");
        assert_eq!(err.to_string(), "step `oci.image` is already in the catalog");
    }

    #[test]
    fn a_secret_output_is_refused_in_v1() {
        let mut catalog = Catalog::builtin();
        let err = catalog
            .add_schema(
                "leaky.step",
                &schema(vec![], vec![field("token", TypeRef::Named("Secret"))]),
            )
            .expect_err("secret output refused");
        assert_eq!(err.to_string(), "step outputs cannot be Secret in v1");
        assert!(catalog.step("leaky.step").is_none(), "a refused schema joins nothing");
    }

    #[test]
    fn a_default_that_fits_no_type_is_refused() {
        let mut catalog = Catalog::builtin();
        let err = catalog
            .add_schema(
                "web.deploy",
                &schema(
                    vec![field("replicas", TypeRef::Named("int")).with_default("two".into())],
                    vec![],
                ),
            )
            .expect_err("default refused");
        assert_eq!(
            err.to_string(),
            "default for input `replicas` does not fit its declared type int"
        );
    }

    /// A custom step needing no ports, so a harness builds without wiring.
    struct CustomStep;

    impl crate::step::StepKind for CustomStep {
        fn name(&self) -> &'static str {
            "test.custom"
        }

        fn version(&self) -> crate::step::Version {
            crate::step::Version::new(1, 0, 0)
        }

        fn schema(&self) -> StepSchema {
            schema(vec![field("name", TypeRef::Builtin(ValueType::String))], vec![])
        }

        fn requires(&self) -> &'static [crate::step::Port] {
            &[]
        }

        fn action(&self, _inputs: &crate::step::Inputs) -> crate::step::ActionClass {
            crate::step::ActionClass::new(crate::step::ActionKind::Other)
        }

        fn run(
            &self,
            _ctx: crate::step::StepCtx,
            _inputs: crate::step::Inputs,
        ) -> crate::ports::BoxFuture<'_, Result<crate::step::Outputs, crate::step::StepError>>
        {
            Box::pin(std::future::ready(Ok(crate::step::Outputs::new())))
        }
    }

    #[test]
    fn a_harness_lends_its_custom_steps_to_the_catalog() {
        let harness = crate::harness::HarnessBuilder::new()
            .ports(
                crate::step::Ports::default()
                    .with_clock(std::sync::Arc::new(crate::step::test_support::FixedClock)),
            )
            .step(CustomStep)
            .build()
            .expect("only the clock, which every harness needs");
        let catalog = Catalog::from_harness(&harness).expect("schemas are legal");
        assert!(catalog.step("oci.image").is_some(), "built-ins survive");
        let custom = catalog.step("test.custom").expect("custom step");
        assert_eq!(custom.input("name"), Some(Type::String));
    }
}
