//! The checker: turns a parsed file into a [`Workflow`], reporting every
//! reference, type and declaration problem it finds — never just the first.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet};

use ks_lang::{Atom, Code, Diagnostic, Entry, Expr, Fix, Span, StrPart, Word};

use crate::auto_rule::{self, MISSING_GUARD_HINT, MISSING_GUARD_MESSAGE};
use crate::block::{self, BLOCK_KEY, BlockInput, BlockSignature};
use crate::catalog::{AFTER, Catalog, StepTypes, WHEN};
use crate::context::{CheckContext, unmet_steps};
use crate::format::{self, Formats, Header};
use crate::policy::{self, BLOCKS, SCRIPTS, SECRETS};
use crate::ports::policy::{ANY_OBJECT, Disposition};
use crate::ports::run_context::ActorKind;
use crate::ports::secrets::SecretRef;
use crate::step::{ActionClass, ActionKind};
use crate::types::{self, LiteralFit, Type};
use crate::workflow::{
    AskHandle, Condition, ContextTest, Env, Policy, PolicyRule, Step, Trigger, TriggerKind,
    Workflow, implicit_default,
};

/// A checked file: the workflow it declares plus every diagnostic, parser
/// and checker findings alike, sorted into source order.
pub struct Checked {
    pub workflow: Workflow,
    pub diagnostics: Vec<Diagnostic>,
    /// The type of every expression the checker typed: input values,
    /// references, interpolations, sub-expressions.
    /// [`Checked::type_at`] finds the entry to show at an offset.
    pub types: Vec<(Span, Type)>,
    /// Every `secrets.<name>` reference, in source order.
    /// [`secret_requirements`] turns these into per-environment listings.
    pub secret_uses: Vec<SecretUse>,
    /// Every `policy:` entry the file declares — one per block, since the
    /// grammar allows more than one. `check --fix` refuses every edit
    /// overlapping any of them: policy changes need a human ([ADR
    /// 0012](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0012-policy-authority.md)).
    pub policy_spans: Vec<Span>,
}

impl Checked {
    /// The innermost typed expression covering `offset`: its span and the
    /// type the checker gave it. Ties go to the later record — the more
    /// specific demand.
    pub fn type_at(&self, offset: u32) -> Option<(Span, &Type)> {
        self.types
            .iter()
            .filter(|(s, _)| s.contains(offset) || offset == s.end)
            .max_by_key(|(s, _)| std::cmp::Reverse(s.len()))
            .map(|(s, t)| (*s, t))
    }
}

/// One `secrets.<name>` reference: the key, where it appears and the step
/// that consumes it. Names and spans only — never a value.
#[derive(Clone, Debug)]
pub struct SecretUse {
    /// The name under `secrets.` (`db_url` for `secrets.db_url`).
    pub key: String,
    /// Where the reference appears.
    pub span: Span,
    /// The step whose input consumes the secret.
    pub step: String,
}

/// What one environment must provide for a run: the secrets the workflow
/// names, as the environment's resolver serves them, with the steps that
/// need each ([#27](https://github.com/Keep-Shipping/harness/issues/27)).
#[derive(Clone, Debug)]
pub struct EnvSecrets {
    /// The environment's name.
    pub env: String,
    /// The `secrets:` resolver the environment reads from, when it declares
    /// one.
    pub resolver: Option<String>,
    /// The secrets the run needs here, deduplicated, in first-use order.
    pub requirements: Vec<SecretRequirement>,
}

/// One secret an environment must provide.
#[derive(Clone, Debug)]
pub struct SecretRequirement {
    /// The key the workflow names: `db_url` for `secrets.db_url`.
    pub key: String,
    /// The `resolver:key` reference for this environment; `None` when the
    /// environment declares no `secrets:` resolver. A reference — never a
    /// value.
    pub reference: Option<SecretRef>,
    /// The steps that consume the secret, in declaration order.
    pub steps: Vec<String>,
}

/// What each environment must provide for `checked` to run: per declared
/// environment (or the implicit `default` when the file has no `envs:`),
/// every `secrets.<name>` the workflow references, spelled as the
/// environment's [`SecretRef`]s plus the steps that need them. Pure: it
/// reads the checked file only, so no caller can reach a secret store
/// through it — nothing is resolved, and no value exists here.
#[must_use]
pub fn secret_requirements(checked: &Checked) -> Vec<EnvSecrets> {
    let uses = &checked.secret_uses;
    let mut keys: Vec<&str> = Vec::new();
    for u in uses {
        if !keys.contains(&u.key.as_str()) {
            keys.push(&u.key);
        }
    }
    checked
        .workflow
        .envs()
        .iter()
        .map(|env| EnvSecrets {
            env: env.name.clone(),
            resolver: env.secrets.clone(),
            requirements: keys
                .iter()
                .map(|key| {
                    let mut steps: Vec<String> = Vec::new();
                    for u in uses.iter().filter(|u| u.key == *key) {
                        if !steps.contains(&u.step) {
                            steps.push(u.step.clone());
                        }
                    }
                    SecretRequirement {
                        key: (*key).to_string(),
                        reference: env.secrets.as_ref().map(|r| SecretRef::new(r, *key)),
                        steps,
                    }
                })
                .collect(),
        })
        .collect()
}

/// Type-check `parse` and build its [`Workflow`], against the built-in
/// [`Catalog`].
pub fn check(parse: &ks_lang::Parse) -> Checked {
    let builtin = Catalog::builtin();
    check_with(parse, &CheckOptions::new(&builtin))
}

/// Options for [`check_with`]: the catalog to check against, the file
/// formats this build reads, and — when the caller knows it — the actor the
/// run would start under, so policy rules that bind that actor are enforced.
pub struct CheckOptions<'a> {
    pub(crate) catalog: &'a Catalog,
    pub(crate) formats: &'a Formats<'a>,
    pub(crate) actor: Option<ActorKind>,
    pub(crate) context: Option<CheckContext>,
    /// Whether this check is in CI, which the caller knows and the file
    /// cannot. Advisory only: it widens the warnings, never what is
    /// enforced.
    pub(crate) in_ci: bool,
    /// What the IaC behind each `dir:` declares, read from its `.tf` files
    /// by the caller — keyed by the `dir:` text as the file spells it, then
    /// by output name. Without it every run-time output stays unchecked.
    pub(crate) iac_outputs: Option<&'a BTreeMap<String, BTreeMap<String, Type>>>,
    /// The blocks this check may use, resolved by the caller
    /// ([`block_signatures`](crate::block::block_signatures)) — keyed by the
    /// use's kind exactly as the file spells it (`acme/web-service@v3`). A
    /// use is checked against its signature and nothing else.
    pub(crate) blocks: Option<&'a BTreeMap<String, BlockSignature>>,
}

impl<'a> CheckOptions<'a> {
    /// Checks against `catalog` instead of the built-in one.
    pub fn new(catalog: &'a Catalog) -> CheckOptions<'a> {
        CheckOptions {
            catalog,
            formats: &format::BUILTIN,
            actor: None,
            context: None,
            in_ci: false,
            iac_outputs: None,
            blocks: None,
        }
    }

    /// Checks the file as `actor` running it: a policy rule that binds the
    /// actor is enforced, so an agent run needing secrets an
    /// `agents: never: read secrets` rule forbids is refused here, before
    /// anything starts.
    #[must_use]
    pub fn actor(mut self, actor: ActorKind) -> CheckOptions<'a> {
        self.actor = Some(actor);
        self
    }

    /// Checks the file as a run in `context` would: a step needing more than
    /// the context has — CI, an OIDC token, network — warns, so nothing that
    /// cannot work here goes unnoticed. Without a context nothing is said
    /// about what a step needs.
    #[must_use]
    pub fn context(mut self, context: CheckContext) -> CheckOptions<'a> {
        self.context = Some(context);
        self
    }

    /// Checks against a different set of file formats, so a build with a
    /// migration can be tested against a file written for the format before
    /// it.
    #[must_use]
    pub fn formats(mut self, formats: &'a Formats<'a>) -> CheckOptions<'a> {
        self.formats = formats;
        self
    }

    /// Checks as a CI run would: an undeclared file format fires here too.
    ///
    /// The caller decides this, never the environment — `CI` is as
    /// spoofable as any other variable, and the actor, which policy binds,
    /// is never inferred from it.
    #[must_use]
    pub fn ci(mut self, in_ci: bool) -> CheckOptions<'a> {
        self.in_ci = in_ci;
        self
    }

    /// Checks against what the `.tf` files behind each `dir:` declare, as
    /// read by the caller ([`tf`](crate::tf)). `outputs` is keyed by the
    /// `dir:` text exactly as the file spells it (`./infra/prod`), then by
    /// output name. A `tofu.apply` step's run-time outputs are then typed,
    /// and one that is not declared is an error here rather than at run
    /// time; a `dir:` absent from the map says nothing, and its outputs stay
    /// unchecked.
    #[must_use]
    pub fn iac_outputs(
        mut self,
        outputs: &'a BTreeMap<String, BTreeMap<String, Type>>,
    ) -> CheckOptions<'a> {
        self.iac_outputs = Some(outputs);
        self
    }

    /// Checks against the blocks this run may use, as resolved by the
    /// caller ([`block::block_signatures`](crate::block::block_signatures)).
    /// `blocks` is keyed by the use's kind exactly as the file spells it
    /// (`acme/web-service@v3`); a use of a kind it does not name checks no
    /// inputs, as an unknown step kind always has.
    #[must_use]
    pub fn blocks(mut self, blocks: &'a BTreeMap<String, BlockSignature>) -> CheckOptions<'a> {
        self.blocks = Some(blocks);
        self
    }
}

/// Type-check `parse` and build its [`Workflow`], against `options`.
pub fn check_with(parse: &ks_lang::Parse, options: &CheckOptions<'_>) -> Checked {
    let mut c = Ctx::new(
        options.catalog,
        options.formats,
        options.actor,
        options.context.clone(),
        options.in_ci,
        options.iac_outputs,
        options.blocks,
        parse.diagnostics().to_vec(),
    );
    c.file(parse.file());
    c.finish_all()
}

/// Context namespaces a reference's first segment may name. `env` is also
/// the `is` subject of `when: env is prod`.
const NAMESPACES: [&str; 6] = ["git", "pr", "run", "env", "ci", "secrets"];

/// The namespace a block file's declared inputs answer to. It is a
/// namespace in block files only, so no workflow has to give the name up.
const INPUTS: &str = "inputs";

const POLICY_VERBS: [&str; 10] =
    ["check", "build", "test", "plan", "apply", "deploy", "destroy", "publish", "read", "run"];

/// The verbs some step kind can actually produce, and so the only ones the
/// unused-verb warning is about: the rest of [`POLICY_VERBS`] is vocabulary
/// ahead of the step kinds, and a file naming one of those binds nothing for a
/// reason that is not this file's business.
const PRODUCIBLE_VERBS: [&str; 6] = ["build", "plan", "apply", "deploy", "destroy", "read"];

/// The verbs whose object is fixed rather than an environment: `read secrets`,
/// `run scripts`, `publish blocks`. Writing `read` with anything else is a
/// mistake, not an environment the rule names.
fn fixed_object(verb: &str) -> Option<&'static str> {
    match verb {
        "read" => Some(SECRETS),
        "run" => Some(SCRIPTS),
        _ => None,
    }
}

const TRIGGER_KINDS: [&str; 5] = ["push", "pr", "tag", "manual", "schedule"];

const ENV_PROPERTIES: [&str; 5] = ["secrets", "ci-only", "approvers", "on", "vars"];

/// The reserved keys under a step: read with the declaration, never checked
/// as inputs.
const STEP_PROPERTIES: [&str; 1] = ["ci-only"];

/// The kinds that apply a plan and produce its run-time outputs, and so are
/// the ones whose `out.` names the IaC behind their plan can answer.
const APPLY_KINDS: [&str; 2] = ["tofu.apply", "terraform.apply"];

struct Ctx<'a> {
    catalog: &'a Catalog,
    /// The file formats this build reads, and what each is called.
    formats: &'a Formats<'a>,
    /// The actor the run would start under, when the caller knows it; policy
    /// rules that bind it are enforced.
    actor: Option<ActorKind>,
    /// The context the run would have, when the caller knows it; steps
    /// needing more than it has warn.
    context: Option<CheckContext>,
    /// That the caller is running in CI, which widens advisory warnings
    /// only and never what is enforced.
    in_ci: bool,
    /// What the IaC behind each `dir:` declares, when the caller read it.
    iac_outputs: Option<&'a BTreeMap<String, BTreeMap<String, Type>>>,
    /// The blocks a use may be checked against, when the caller resolved
    /// them: keyed by the use's kind exactly as the file spells it.
    blocks: Option<&'a BTreeMap<String, BlockSignature>>,
    /// The `block:` this file declares, when it is a block file: the inputs
    /// its internal steps read as `inputs.<name>`. `None` in every other
    /// file, so `inputs.` names nothing a workflow could have spelled.
    block: Option<BlockScope>,
    diags: Vec<Diagnostic>,
    /// The dotted path of the entry being checked (`deploy.image`), attached
    /// to every diagnostic raised while it is checked.
    subject: Option<String>,
    env_names: Vec<String>,
    env_vars: Vec<String>,
    steps: Vec<StepInfo<'a>>,
    /// `steps` names to indices, so a reference resolves in O(1); a linear
    /// scan made checking quadratic on files with many steps.
    index: HashMap<String, usize>,
    edges: Vec<Edge>,
    /// The `policy:` entries' spans, so `--fix` can refuse to edit them.
    policy_spans: Vec<Span>,
    /// `(from, to)` pairs an `after:` ordered: an order, not a read.
    after: HashSet<(String, String)>,
    /// `(from, to)` pairs something reads across, whether or not an `after:`
    /// orders them too.
    read: HashSet<(String, String)>,
    shown: Vec<(usize, usize)>, // (approval step, step it shows)
    name: Option<String>,
    triggers: Vec<Trigger>,
    envs: Vec<Env>,
    /// The `never:` rules the file declares.
    policy: Policy,
    /// Every `secrets.<name>` reference, in source order.
    secret_uses: Vec<SecretUse>,
    /// The type of every expression typed so far, for editor hover.
    types: Vec<(Span, Type)>,
}

/// The `block:` a block file declares: its name and the inputs in scope for
/// its internal steps.
struct BlockScope {
    name: String,
    inputs: BTreeMap<String, Type>,
}

struct StepInfo<'a> {
    name: String,
    span: Span,
    kind_name: Option<String>,
    kind_span: Span,
    spec: Option<&'a StepTypes>,
    /// `ci-only: true`: the step refuses to run off CI.
    ci_only: bool,
    /// `decide` only: the answers declared under `returns:`.
    variants: Vec<String>,
    /// The literal `dir:` a `tofu.plan` step reads, as the file spells it.
    dir: Option<String>,
    /// An apply step's `plan:`: the step whose `.file` it applies.
    plan: Option<String>,
    /// An apply step's `outputs:`: each run-time output and the type the
    /// file says it holds, or `None` when the spelling is not a type at
    /// all (reported in the second pass).
    outputs: Vec<(String, Option<Type>)>,
    /// The block this step uses, when its kind names one. Its signature is
    /// the step's `spec`, its actions the step's, and its outputs answer
    /// for `<step>.out.<name>`.
    block: Option<&'a BlockSignature>,
    /// What the step does, for policy, with the kind that performs it.
    actions: Vec<(ActionClass, String)>,
    /// A block use's inputs, with the signature's defaults filled in — what
    /// the run will get whether the file spelled it or the block declared
    /// it.
    block_inputs: BTreeMap<String, String>,
    /// The `when:` condition, for the planner.
    when: Option<Condition>,
}

/// `from` must run before `to`; `span` is the reference that asked for it.
#[derive(Clone)]
struct Edge {
    from: String,
    to: String,
    span: Span,
}

impl<'a> Ctx<'a> {
    #[allow(clippy::too_many_arguments)] // the check options, one field for one
    fn new(
        catalog: &'a Catalog,
        formats: &'a Formats<'a>,
        actor: Option<ActorKind>,
        context: Option<CheckContext>,
        in_ci: bool,
        iac_outputs: Option<&'a BTreeMap<String, BTreeMap<String, Type>>>,
        blocks: Option<&'a BTreeMap<String, BlockSignature>>,
        diags: Vec<Diagnostic>,
    ) -> Ctx<'a> {
        Ctx {
            catalog,
            formats,
            actor,
            context,
            in_ci,
            iac_outputs,
            diags,
            blocks,
            block: None,
            subject: None,
            env_names: Vec::new(),
            env_vars: Vec::new(),
            steps: Vec::new(),
            index: HashMap::new(),
            edges: Vec::new(),
            policy_spans: Vec::new(),
            after: HashSet::new(),
            read: HashSet::new(),
            shown: Vec::new(),
            name: None,
            triggers: Vec::new(),
            envs: Vec::new(),
            policy: Policy::default(),
            secret_uses: Vec::new(),
            types: Vec::new(),
        }
    }

    /// Push an error, stamped with the entry path under check, if any.
    fn push(&mut self, d: Diagnostic) {
        self.diags.push(match self.subject.clone() {
            Some(s) => d.with_subject(s),
            None => d,
        });
    }

    fn err(&mut self, code: Code, span: Span, message: impl Into<String>) {
        self.push(Diagnostic::error(code, span, message));
    }

    fn err_hint(
        &mut self,
        code: Code,
        span: Span,
        message: impl Into<String>,
        hint: impl Into<String>,
    ) {
        self.push(Diagnostic::error(code, span, message).with_hint(hint));
    }

    /// [`err_hint`], plus the edit that would resolve the finding.
    fn err_hint_fix(
        &mut self,
        code: Code,
        span: Span,
        message: impl Into<String>,
        hint: impl Into<String>,
        fix: Fix,
    ) {
        self.push(Diagnostic::error(code, span, message).with_hint(hint).with_fix(fix));
    }

    fn record(&mut self, span: Span, ty: Type) {
        self.types.push((span, ty));
    }

    fn file(&mut self, file: ks_lang::File<'_>) {
        // The format header, read first: it gates nothing else, but a file
        // declaring a format this build cannot read should say so before it
        // says anything else.
        self.check_format(file);
        let entries: Vec<Entry<'_>> = file.entries().collect();
        // A block's inputs are in scope for its internal steps, so they are
        // declared before the first pass reads any reference.
        if let Some(block) = entries.iter().find(|e| e.key_name() == Some(BLOCK_KEY)) {
            self.declare_block(&entries, *block);
        }
        // First pass: declare the steps and environments, so a reference
        // resolves no matter where in the file its target sits.
        for e in &entries {
            match e.key_name() {
                Some("steps") => self.declare_steps(*e),
                Some("envs") => self.declare_envs(*e),
                _ => {}
            }
        }
        // Second pass: check everything.
        let mut saw_envs = false;
        for e in entries {
            match e.key_name() {
                Some("name") => self.name = self.scalar_text(e),
                Some(format::HEADER_KEY) => {} // read by `check_format`
                Some("on") => {
                    self.subject = Some("on".to_string());
                    self.triggers = self.triggers_of(e);
                    self.subject = None;
                }
                Some("steps") => self.check_steps(e),
                Some("envs") => {
                    self.envs = self.check_envs(e);
                    saw_envs = true;
                }
                Some("policy") => {
                    self.policy_spans.push(e.node().span());
                    self.check_policy(e);
                }
                Some(BLOCK_KEY | "inputs" | "outputs") if self.block.is_some() => {
                    self.check_block_entry(e);
                }
                _ => {} // other top-level keys carry no meaning here yet
            }
        }
        if !saw_envs {
            self.envs.push(implicit_default());
        }
    }

    /// The `keepshipping:` header: which file format the file is written in,
    /// and whether this build reads it. The format before the current one
    /// still checks, with a warning naming the upgrade; anything this build
    /// has no migration out of, or a header that is not a version or not the
    /// first entry, is refused. No header is the current format — silent
    /// except under CI, where the pipeline's owner should hear that nobody
    /// has pinned it.
    fn check_format(&mut self, file: ks_lang::File<'_>) {
        match format::header(file) {
            Header::Absent => {
                if self.actor != Some(ActorKind::Ci) && !self.in_ci {
                    return;
                }
                // A file with entries points at its first; an empty one at
                // the start of the file.
                let span = file.entries().next().map_or_else(|| Span::point(0), |e| e.key_span());
                self.push(
                    Diagnostic::warning(
                        Code::FormatUndeclared,
                        span,
                        "this file declares no format version",
                    )
                    .with_hint(format!(
                        "add `{}: {}` as the first line, or run `keepshipping fmt --upgrade`",
                        format::HEADER_KEY,
                        format::spelling(self.formats.current)
                    )),
                );
            }
            Header::Declared { version, span } if !self.formats.supports(version) => {
                self.err_hint(
                    Code::FormatUnsupported,
                    span,
                    format!("this keepshipping does not read format {}", format::spelling(version)),
                    format!("it reads {}", self.formats.reads()),
                );
            }
            Header::Declared { version, .. } if version == self.formats.current => {}
            Header::Declared { version, span } => {
                self.push(
                    Diagnostic::warning(
                        Code::FormatDeprecated,
                        span,
                        format!(
                            "written for format {}; this keepshipping reads {}",
                            format::spelling(version),
                            format::spelling(self.formats.current)
                        ),
                    )
                    .with_hint(format!(
                        "run `keepshipping fmt --upgrade` to rewrite it for {}",
                        format::spelling(self.formats.current)
                    )),
                );
            }
            Header::Malformed { span } => self.err_hint(
                Code::FormatUnsupported,
                span,
                format!("the `{}:` value is not a format version", format::HEADER_KEY),
                format!(
                    "a format version is spelled `0.N`, e.g. `{}: {}`",
                    format::HEADER_KEY,
                    format::spelling(self.formats.current)
                ),
            ),
            Header::NotFirst { span } => self.err_hint(
                Code::FormatUnsupported,
                span,
                format!("`{}:` is not the file's first entry", format::HEADER_KEY),
                "the header must come before every other entry, so it is the first thing read",
            ),
        }
    }

    fn scalar_text(&self, e: Entry<'_>) -> Option<String> {
        match e.expr() {
            Some(Expr::Atom { atom: Atom::Word(w), .. }) => Some(w.text().to_string()),
            Some(Expr::Atom { atom: Atom::Str(s), .. }) => Some(s.value()),
            _ => None,
        }
    }

    // --- declarations -----------------------------------------------------

    fn declare_steps(&mut self, steps: Entry<'_>) {
        for s in steps.children() {
            let Some(name) = s.key_name() else { continue };
            let span = s.key_span();
            if NAMESPACES.contains(&name) {
                self.err_hint(
                    Code::ReservedStepName,
                    span,
                    format!("step `{name}` is named like a context namespace"),
                    format!("rename the step; `{name}` is a reserved context name"),
                );
                continue;
            }
            if let Some(first) = self.step_index(name).map(|i| self.steps[i].span) {
                self.push(
                    Diagnostic::error(
                        Code::DuplicateStep,
                        span,
                        format!("duplicate step `{name}`"),
                    )
                    .with_subject(name)
                    .with_label(first, "first defined here"),
                );
                continue;
            }
            let (kind_name, kind_span) = match s.expr() {
                Some(Expr::Atom { atom: Atom::Word(w), .. }) => {
                    (Some(w.text().to_string()), w.node.span())
                }
                _ => (None, span),
            };
            let block = kind_name.as_deref().and_then(|n| self.blocks.and_then(|b| b.get(n)));
            // A block the caller resolved answers as a step kind, so a use
            // flows through the same `spec` path every catalog step takes.
            let spec = kind_name
                .as_deref()
                .and_then(|n| self.catalog.step(n).or_else(|| block.map(|b| b.as_step_types())));
            let ci_only = self.step_ci_only(s);
            let variants = match spec.filter(|sp| sp.decision) {
                Some(_) => s
                    .children()
                    .find(|c| c.key_name() == Some("returns"))
                    .and_then(|r| r.expr())
                    .map(|e| union_words(&e))
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            // What the step does, for policy: a block contributes the
            // actions of every step inside it, so a use cannot hide an
            // apply from the rules.
            let actions = match block {
                Some(b) => b.actions.clone(),
                None => match kind_name.as_deref() {
                    Some(k) if self.catalog.step(k).is_some() => {
                        let class = match env_gate(s) {
                            Some(env) => ActionClass::new(ActionKind::of_kind(k)).in_env(env),
                            None => ActionClass::new(ActionKind::of_kind(k)),
                        };
                        vec![(class, k.to_string())]
                    }
                    _ => Vec::new(),
                },
            };
            self.steps.push(StepInfo {
                name: name.into(),
                span,
                kind_name,
                kind_span,
                spec,
                ci_only,
                variants,
                dir: literal_input(s, "dir"),
                plan: plan_step(s),
                outputs: outputs_mapping(s, spec),
                block,
                actions,
                block_inputs: block.map(|b| block_input_values(s, b)).unwrap_or_default(),
                when: None,
            });
            self.index.insert(name.to_string(), self.steps.len() - 1);
        }
    }

    fn declare_envs(&mut self, envs: Entry<'_>) {
        for e in envs.children() {
            let Some(name) = e.key_name() else { continue };
            self.env_names.push(name.into());
            if let Some(vars) = e.children().find(|c| c.key_name() == Some("vars")) {
                self.env_vars
                    .extend(vars.children().filter_map(|v| v.key_name()).map(String::from));
            }
        }
    }

    // --- steps ------------------------------------------------------------

    fn check_steps(&mut self, steps: Entry<'_>) {
        for s in steps.children() {
            let Some(idx) = s.key_name().and_then(|n| self.step_index(n)) else { continue };
            for input in s.children() {
                let Some(iname) = input.key_name() else { continue };
                // Reserved properties are read with the declaration, not as
                // an input the step kind would have to declare.
                if STEP_PROPERTIES.contains(&iname) {
                    continue;
                }
                self.subject = Some(format!("{}.{}", self.steps[idx].name, iname));
                self.check_input(idx, iname, input);
                self.subject = None;
            }
            self.check_block_use(idx, s);
        }
    }

    /// A block use that leaves out a required input: named at the step's
    /// kind, with the block's own inputs offered as the near misses. An
    /// input with a default may be left out, which is the point of one.
    fn check_block_use(&mut self, idx: usize, step: Entry<'_>) {
        let Some(block) = self.steps[idx].block else { return };
        let given: Vec<String> =
            step.children().filter_map(|c| c.key_name().map(String::from)).collect();
        let names: Vec<String> = block.inputs.iter().map(|i| i.name.clone()).collect();
        for BlockInput { name, ty: _, default } in &block.inputs {
            if default.is_some() {
                continue;
            }
            if given.iter().any(|g| g == name) {
                continue;
            }
            let msg = format!("block `{}` requires input `{name}`", block.name);
            // The name itself is no use as a suggestion for what it is.
            let others: Vec<&str> =
                names.iter().map(String::as_str).filter(|n| *n != name).collect();
            match suggest(name, &others) {
                Some(s) => self.err_hint(
                    Code::MissingInput,
                    self.steps[idx].kind_span,
                    msg,
                    format!("did you mean `{s}`?"),
                ),
                None => self.err(Code::MissingInput, self.steps[idx].kind_span, msg),
            }
        }
    }

    /// A step's reserved `ci-only` property, `false` when it declares none.
    /// It is not an input: the step kind need not declare it.
    fn step_ci_only(&mut self, step: Entry<'_>) -> bool {
        let Some(p) = step.children().find(|c| c.key_name() == Some("ci-only")) else {
            return false;
        };
        self.subject = step.key_name().map(|n| format!("{n}.ci-only"));
        let value = self.ci_only(p, Code::TypeMismatch);
        self.subject = None;
        value
    }

    /// The `true`/`false` under a `ci-only` property; a value that is
    /// neither is `code`'s error, worded the same way for an environment and
    /// for a step.
    fn ci_only(&mut self, p: Entry<'_>, code: Code) -> bool {
        match p.expr().as_ref().and_then(value_word).as_deref() {
            Some("true") => true,
            Some("false") => false,
            _ => {
                self.err_hint(
                    code,
                    p.key_span(),
                    "`ci-only` takes `true` or `false`",
                    "`ci-only: true`",
                );
                false
            }
        }
    }

    fn check_input(&mut self, idx: usize, iname: &str, input: Entry<'_>) {
        // `outputs:` maps an apply step's run-time outputs to types; it is a
        // mapping, so it has children and no value of its own.
        if iname == "outputs"
            && self.steps[idx].spec.is_some_and(|sp| APPLY_KINDS.contains(&sp.name.as_str()))
        {
            return self.check_outputs(input);
        }
        // A kind that is not an apply step has no `outputs:` whatever shape
        // it is written in: a mapping with children is an unknown input like
        // any other. (An unknown kind checks no inputs at all, as everywhere
        // else, so it says nothing about `outputs:` either way.)
        if iname == "outputs" && self.steps[idx].spec.is_some() && input.expr().is_none() {
            return self.unknown_input(idx, iname, input);
        }
        let Some(e) = input.expr() else { return }; // missing values: parse error
        // The reserved inputs mean the same for every kind, checked or not.
        match iname {
            AFTER => return self.check_after(idx, &e),
            WHEN => self.record_when(idx, &e),
            _ => {}
        }
        let Some(spec) = self.steps[idx].spec else {
            self.ty_of(idx, &e); // unknown kind: inputs unchecked, refs resolve
            return;
        };
        let Some(ty) = spec.input(iname) else {
            self.unknown_input(idx, iname, input);
            return;
        };
        match iname {
            "show" => self.check_refs(idx, &e),
            "else" => self.check_actions(idx, &e),
            "auto" => {
                // Only `approval` gates on `auto:`; the destroys guard is its
                // rule, not a convention every `auto:` input follows.
                if spec.name == "approval" {
                    self.check_auto_rule(&e);
                }
                self.demand_input(idx, ty, &e);
            }
            "returns" => {} // variants were collected with the declarations
            _ => self.demand_input(idx, ty, &e),
        }
    }

    /// An `approval` step's `auto:` may approve without a human only if it
    /// says so: the destroys guard must be a top-level conjunct reading a
    /// step that produces a `destroys` count. The engine adds the guard
    /// either way (ADR 0012), so this warns about the file, not the run.
    fn check_auto_rule(&mut self, e: &Expr<'_>) {
        let plans: Vec<String> = self
            .steps
            .iter()
            .filter(|s| s.spec.is_some_and(|sp| sp.output("destroys").is_some()))
            .map(|s| s.name.clone())
            .collect();
        let is_plan_step = |name: &str| plans.iter().any(|n| n == name);
        if !auto_rule::guards_destroys(e, &is_plan_step) {
            self.warn_hint(
                Code::AutoDestroys,
                e.span(),
                MISSING_GUARD_MESSAGE.to_string(),
                MISSING_GUARD_HINT.to_string(),
            );
        }
    }

    /// `after: build`, `after: "build"` or `after: build, review`: ordering
    /// without data. Each name adds the same edge a reference would, so a name
    /// that does not exist, this step itself, or a loop all reach the
    /// diagnostics they reach for a reference. A value that is not a name is
    /// reported rather than ignored: an ordering edge that quietly orders
    /// nothing is the one mistake here nobody would notice.
    /// An apply step's `outputs:` mapping, checked here in the second pass: a
    /// value that is not a type is a type error like any other, named
    /// against the line that spells it.
    fn check_outputs(&mut self, entry: Entry<'_>) {
        for (out, (_, ty)) in entry.children().zip(parse_outputs(entry)) {
            if ty.is_some() {
                continue;
            }
            let hint = "spell it as `k8s.Cluster`, `string` or `{name: type}`";
            let msg = match out.expr().as_ref().and_then(value_word) {
                Some(spelled) => format!("`{spelled}` is not a type"),
                None => "an output's type is a single name".to_string(),
            };
            self.err_hint(Code::TypeMismatch, out.key_span(), msg, hint.to_string());
        }
    }

    /// The input the kind's contract does not declare, named where it is
    /// written, with the kind's own inputs offered as the near misses.
    fn unknown_input(&mut self, idx: usize, iname: &str, input: Entry<'_>) {
        let Some(spec) = self.steps[idx].spec else { return };
        let span = input.key_span();
        let msg = format!("unknown input `{iname}` for step kind `{}`", spec.name);
        let names = spec.input_names();
        match suggestion(iname, &names) {
            Some((s, unique)) => self.err_hint_fix(
                Code::UnknownInput,
                span,
                msg,
                format!("did you mean `{s}`?"),
                Fix::new(span, s, unique),
            ),
            None => self.err(Code::UnknownInput, span, msg),
        }
    }

    fn check_after(&mut self, idx: usize, e: &Expr<'_>) {
        for item in after_names(e) {
            let (name, span) = match item {
                AfterItem::Name(name, span) => (name, span),
                AfterItem::NotAName(span) => {
                    self.err(Code::TypeMismatch, span, "`after:` takes step names, bare or quoted");
                    continue;
                }
            };
            match self.step_index(&name) {
                Some(from) => self.edge(idx, from, span, false),
                None => {
                    let cands: Vec<&str> = self.steps.iter().map(|s| s.name.as_str()).collect();
                    let msg = format!("`after:` names no step `{name}`");
                    match suggest(&name, &cands) {
                        Some(s) => self.err_hint(
                            Code::UnknownRef,
                            span,
                            msg,
                            format!("did you mean `{s}`?"),
                        ),
                        None => self.err(Code::UnknownRef, span, msg),
                    }
                }
            }
        }
    }

    /// Keep the `when:` condition on the step, in the shape the planner
    /// reads: the steps it names, and an evaluable form when the expression
    /// is one of the context-only shapes.
    fn record_when(&mut self, idx: usize, e: &Expr<'_>) {
        let steps: Vec<String> = e
            .refs()
            .into_iter()
            .filter(|r| r.kind == ks_lang::NameKind::Dotted)
            .filter_map(|r| {
                self.step_index(split_first(r.text).0).map(|i| self.steps[i].name.clone())
            })
            .collect();
        let source = e.span().slice(expr_src(e)).to_string();
        self.steps[idx].when = Some(Condition { source, steps, test: context_test(e) });
    }

    /// Check a value expression against the input's declared type.
    fn demand_input(&mut self, idx: usize, want: Type, e: &Expr<'_>) {
        // A typed default (`replicas: int = 2`): the annotation types the
        // value, and the default must be a literal of it.
        if let Some((word, ann, rhs)) = annotation_default(e) {
            self.demand(word.node.span(), want, ann.clone(), None, None);
            self.demand_input(idx, ann.clone(), rhs);
            self.record(e.span(), ann);
            return;
        }
        // Strings report their own interpolations once (`str_typed`); for
        // every other shape this reference walk is the only check.
        if !interp_allowed(&want) && !matches!(e, Expr::Atom { atom: Atom::Str(_), .. }) {
            for r in e.refs() {
                if r.kind == ks_lang::NameKind::Interp {
                    self.err_hint(
                        Code::TypeMismatch,
                        r.span,
                        format!("interpolation is not allowed in a `{want}` value"),
                        "interpolate only into string values",
                    );
                }
            }
        }
        match e {
            Expr::Atom { atom: Atom::Word(w), .. } => self.word_typed(idx, w, want),
            Expr::Atom { atom: Atom::Str(s), .. } => {
                let got = self.str_typed(idx, s, &want);
                self.demand_literal(e.span(), want, got, Some(&s.value()));
            }
            Expr::Atom { atom: Atom::Paren { inner: Some(inner), .. }, .. } => {
                self.demand_input(idx, want, inner)
            }
            Expr::Tuple { items, .. } => self.tuple_input(idx, items, want, e.span()),
            other => {
                let got = self.ty_of(idx, other);
                self.demand(other.span(), want, got, None, None);
            }
        }
    }

    /// A tuple value: element-wise into a list or a record (positionally),
    /// else a list of whatever its items spell.
    fn tuple_input(&mut self, idx: usize, items: &[Expr<'_>], want: Type, span: Span) {
        match &want {
            Type::List(inner) => {
                let inner = (**inner).clone();
                for item in items {
                    self.demand_input(idx, inner.clone(), item);
                }
            }
            Type::Record(fields) => {
                if items.len() != fields.len() {
                    for item in items {
                        self.ty_of(idx, item);
                    }
                    self.err(
                        Code::TypeMismatch,
                        span,
                        format!("expected {want}, got {} items", items.len()),
                    );
                    return;
                }
                for (item, (_, ty)) in items.iter().zip(fields) {
                    self.demand_input(idx, ty.clone(), item);
                }
            }
            _ => {
                let mut same: Option<Type> = None;
                for item in items {
                    let t = self.ty_of(idx, item);
                    same = match same {
                        None => Some(t),
                        Some(u) if u == t => Some(u),
                        _ => Some(Type::Any),
                    };
                }
                let got = Type::List(Box::new(same.unwrap_or(Type::Any)));
                self.demand(span, want, got, None, None);
            }
        }
    }

    /// Check a literal — a bare word or a quoted string — against `want`.
    /// Literals are spelled into the type the input declares (`./x` is a
    /// path, a member names its enum variant, a pasted digest warns);
    /// anything else is the type mismatch it looks like.
    fn demand_literal(&mut self, span: Span, want: Type, got: Type, text: Option<&str>) {
        // A word the reference walk could not type is judged as the literal
        // it spells, not as `any`.
        let untyped = got == Type::Any && !matches!(want, Type::Any);
        // The one `literal_fit` verdict, when a literal text can and must be
        // judged: an untyped word always, a typed one only when the coercion
        // below would fail.
        let fit = text.and_then(|text| {
            (untyped || !types::coerce(&want, &got)).then(|| (text, self.literal_fit(&want, text)))
        });
        match fit {
            Some((_, LiteralFit::Ok)) => self.record(span, want),
            Some((_, LiteralFit::Warn { message, hint })) => {
                self.warn_hint(Code::PastedDigest, span, message, hint);
                self.record(span, want);
            }
            // The word spells no literal of `want`: name what it does spell.
            Some((text, LiteralFit::Err)) if untyped => {
                self.demand(span, want, types::literal_type(text), None, None);
            }
            _ => {
                if types::coerce(&want, &got) {
                    self.record(span, if got == Type::Any { want } else { got });
                } else {
                    self.demand(span, want, got, None, None);
                }
            }
        }
    }

    fn warn_hint(&mut self, code: Code, span: Span, message: String, hint: String) {
        self.push(Diagnostic::warning(code, span, message).with_hint(hint));
    }

    /// [`types::literal`], with the catalog's answer for where a pasted
    /// digest should have come from.
    fn literal_fit(&self, want: &Type, text: &str) -> LiteralFit {
        types::literal(want, text, self.digest_alt(want).as_deref())
    }

    /// A bare word in a typed input position.
    fn word_typed(&mut self, idx: usize, w: &Word<'_>, want: Type) {
        let span = w.node.span();
        // A `string` input takes text, and text has dots in it: `domain:
        // api.acme.dev` is a value, not a reference. A dotted name that
        // does name a step or a context value still is one — `model:
        // secrets.db_url` is a secret, and errors as one — and so does one
        // a keystroke or two from such a name: `type: biuld.digest` is a
        // misspelled reference, not text.
        if w.scalar() == ks_lang::Scalar::DottedName && matches!(want, Type::String) {
            let text = w.text();
            match self.soft_ref(idx, text, span) {
                Some(got) => self.demand(span, want, got, None, None),
                None if self.near_miss(text) => self.unknown_ref(text, span),
                None => self.demand_literal(span, want, Type::String, Some(text)),
            }
        } else if w.scalar() == ks_lang::Scalar::DottedName {
            let Some((target, got)) = self.resolve_ref(Some(idx), w.text(), span) else { return };
            // The output of the wanted type, when the step has exactly one:
            // rewriting just that segment makes the value fit.
            let mut fix = None;
            let hint = if types::coerce(&want, &got) {
                None
            } else {
                target.and_then(|t| {
                    let (hint, out, unique) = self.mismatch_hint(t, &want)?;
                    fix = Some(Fix::new(segment_span(w.text(), span.start, 1), out, unique));
                    Some(hint)
                })
            };
            self.demand(span, want, got, hint, fix);
        } else {
            let text = w.text();
            let got = self.word_untyped(idx, w);
            // A word in a `push:` position is itself the tag literal.
            let got = if got == Type::String && want.is_named("oci.Tag") {
                Type::Named("oci.Tag".to_string())
            } else {
                got
            };
            self.demand_literal(span, want, got, Some(text));
        }
    }

    /// A bare word with nothing specific to satisfy. Dotted names resolve
    /// only when their first segment names a step or a context namespace,
    /// else they are literal text (`domain: api.acme.dev`).
    fn word_untyped(&mut self, idx: usize, w: &Word<'_>) -> Type {
        let text = w.text();
        let span = w.node.span();
        match w.scalar() {
            ks_lang::Scalar::Bool => Type::Bool,
            ks_lang::Scalar::Number if text.contains('.') => Type::Float,
            ks_lang::Scalar::Number => Type::Int,
            ks_lang::Scalar::Duration => Type::Duration,
            ks_lang::Scalar::Handle => Type::Handle,
            ks_lang::Scalar::Path => Type::Path,
            ks_lang::Scalar::DottedName => self.soft_ref(idx, text, span).unwrap_or(Type::String),
            ks_lang::Scalar::Ident => match self.step_index(text) {
                Some(i) => {
                    self.edge(idx, i, span, true);
                    self.bare_step_type(i)
                }
                None => Type::Any, // an enum answer literal, or a plain word
            },
            ks_lang::Scalar::Str | ks_lang::Scalar::Text => {
                for part in w.parts() {
                    if let ks_lang::WordPart::Interp(i) = part
                        && let Some(name) = i.name()
                    {
                        self.interp(idx, name, i.name_span().unwrap_or_else(|| i.node.span()));
                    }
                }
                Type::String
            }
        }
    }

    /// A `{name}` interpolation: always a reference; never a secret.
    fn interp(&mut self, idx: usize, name: &str, span: Span) {
        if let Some((_, ty)) = self.resolve_ref(Some(idx), name, span) {
            if ty == Type::Secret {
                self.err_hint(
                    Code::SecretInString,
                    span,
                    format!("secret `{name}` cannot be interpolated into a string"),
                    "pass it to an input that takes a secret; secrets never go into strings or logs",
                );
            } else {
                self.record(span, ty);
            }
        }
    }

    /// A quoted string; interpolations resolve as everywhere else.
    fn str_typed(&mut self, idx: usize, s: &ks_lang::Str<'_>, want: &Type) -> Type {
        for part in s.parts() {
            if let StrPart::Interp(i) = part
                && let Some(name) = i.name()
            {
                let span = i.name_span().unwrap_or_else(|| i.node.span());
                if !interp_allowed(want) {
                    self.err_hint(
                        Code::TypeMismatch,
                        span,
                        format!("interpolation is not allowed in a `{want}` value"),
                        "interpolate only into string values",
                    );
                } else {
                    self.interp(idx, name, span);
                }
            }
        }
        if want.is_named("oci.Tag") { Type::Named("oci.Tag".to_string()) } else { Type::String }
    }

    /// A value against the type its input declares. `fix`, when the checker
    /// has one, is the edit that would make it fit.
    fn demand(
        &mut self,
        span: Span,
        want: Type,
        got: Type,
        hint: Option<String>,
        fix: Option<Fix>,
    ) {
        if types::coerce(&want, &got) {
            self.record(span, if got == Type::Any { want } else { got });
            return;
        }
        let message = format!("expected {want}, got {got}");
        let hint = hint.or_else(|| secret_hint(&want, &got));
        let d = match hint {
            Some(h) => Diagnostic::error(Code::TypeMismatch, span, message).with_hint(h),
            None => Diagnostic::error(Code::TypeMismatch, span, message),
        };
        self.push(match fix {
            Some(fix) => d.with_fix(fix),
            None => d,
        });
    }

    /// The did-you-mean for a type mismatch: another output of the same
    /// step that has the wanted type. Yields the hint, the output it names
    /// and whether that output is the step's only one of the wanted type.
    /// The hint quotes the wanted type's rationale when the catalog declares
    /// one (`use build.digest so prod runs exactly the image you built`).
    fn mismatch_hint(&self, target: usize, want: &Type) -> Option<(String, String, bool)> {
        let spec = self.steps[target].spec?;
        let (out, unique) = self.alt_output(spec, want)?;
        let name = &self.steps[target].name;
        let hint = match self.catalog.rationale(want) {
            Some(r) => format!("use {name}.{out} {r}"),
            None => format!("use {name}.{out}, which is {} {want}", article(&want.to_string())),
        };
        Some((hint, out, unique))
    }

    /// Another output of `spec` with the wanted type, with whether it is the
    /// only one; for a `decide`, the `answer` output for one of its declared
    /// answers.
    fn alt_output(&self, spec: &StepTypes, want: &Type) -> Option<(String, bool)> {
        let mut fits = spec
            .outputs
            .iter()
            .filter(|(_, ty)| !matches!(ty, Type::Any) && types::coerce(want, ty));
        match fits.next() {
            Some((n, _)) => Some((n.clone(), fits.next().is_none())),
            // A `decide` types its `answer` output from the declared returns:.
            None if spec.decision && matches!(want, Type::Decision(_)) => {
                Some(("answer".to_string(), true))
            }
            None => None,
        }
    }

    /// A same-workflow output of the wanted nominal type — where a pasted
    /// digest should have come from instead (`build.digest`). With several
    /// producers, the first in declaration order is suggested.
    fn digest_alt(&self, want: &Type) -> Option<String> {
        if !matches!(want, Type::Named(_)) {
            return None;
        }
        self.steps.iter().find_map(|s| {
            let spec = s.spec?;
            spec.outputs.iter().find(|(_, ty)| ty == want).map(|(n, _)| format!("{}.{}", s.name, n))
        })
    }

    // --- references -------------------------------------------------------

    fn step_index(&self, name: &str) -> Option<usize> {
        self.index.get(name).copied()
    }

    /// Record that `cur` waits for `target`. `data` says whether anything is
    /// read as well as ordered: an `after:` edge orders without reading, and
    /// is remembered as such, because approval gating asks what a step reads
    /// and following a step reads nothing. Both are remembered rather than
    /// one folded into the other, so the answer does not depend on which of
    /// the two the file mentions first.
    fn edge(&mut self, cur: usize, target: usize, span: Span, data: bool) {
        let pair = (self.steps[target].name.clone(), self.steps[cur].name.clone());
        if data {
            self.read.insert(pair.clone());
        } else {
            self.after.insert(pair.clone());
        }
        self.edges.push(Edge { from: pair.0, to: pair.1, span });
    }

    fn bare_step_type(&self, idx: usize) -> Type {
        match self.steps[idx].spec.filter(|sp| sp.decision) {
            Some(_) => Type::Decision(self.steps[idx].variants.clone()),
            None => Type::Any,
        }
    }

    /// Resolve a dotted or interpolated name that must be a reference.
    /// Returns the step it names (when not a context value) and its type.
    /// `cur` is the step reading it, or `None` where no step is being
    /// checked — a block's `outputs:` mapping, which types against the
    /// block's own steps and orders nothing.
    fn resolve_ref(
        &mut self,
        cur: Option<usize>,
        text: &str,
        span: Span,
    ) -> Option<(Option<usize>, Type)> {
        let (first, rest) = split_first(text);
        if let Some(i) = self.step_index(first) {
            if let Some(cur) = cur {
                self.edge(cur, i, span, true);
            }
            return Some((Some(i), self.step_ref(i, rest, span)));
        }
        if let Some(t) = self.context(first, rest, span) {
            // A secret reference is a requirement the run carries, wherever
            // it appears — record it for the per-environment listing and the
            // policy check.
            if first == "secrets"
                && let Some(name) = rest
            {
                let step = match cur {
                    Some(cur) => self.steps[cur].name.clone(),
                    None => self.block.as_ref().map_or_else(String::new, |b| b.name.clone()),
                };
                self.secret_uses.push(SecretUse { key: name.to_string(), span, step });
            }
            return Some((None, t));
        }
        self.unknown_ref(text, span);
        None
    }

    /// The names a reference's first segment may be: the file's own steps,
    /// the context namespaces, and — in a block file — its inputs.
    fn ref_candidates(&self) -> Vec<&str> {
        let mut cands: Vec<&str> = self.steps.iter().map(|s| s.name.as_str()).collect();
        cands.extend_from_slice(&NAMESPACES);
        if self.block.is_some() {
            cands.push(INPUTS);
        }
        cands
    }

    /// `unknown step or context value`, with the near miss when the head
    /// segment is a keystroke or two from one of the names it could have
    /// been.
    fn unknown_ref(&mut self, text: &str, span: Span) {
        let (first, _) = split_first(text);
        let cands = self.ref_candidates();
        let msg = format!("unknown step or context value `{first}`");
        match suggestion(first, &cands) {
            Some((s, unique)) => self.err_hint_fix(
                Code::UnknownRef,
                span,
                msg,
                format!("did you mean `{s}`?"),
                Fix::new(segment_span(text, span.start, 0), s, unique),
            ),
            None => self.err(Code::UnknownRef, span, msg),
        }
    }

    /// A dotted name in a String/untyped position: a reference only when its
    /// first segment names a step or a context namespace.
    fn soft_ref(&mut self, cur: usize, text: &str, span: Span) -> Option<Type> {
        let (first, _) = split_first(text);
        if self.step_index(first).is_some()
            || NAMESPACES.contains(&first)
            || (first == INPUTS && self.block.is_some())
        {
            return self.resolve_ref(Some(cur), text, span).map(|(_, t)| t);
        }
        None
    }

    /// Whether a dotted name's first segment is close enough to one of the
    /// names it could have been that it reads as a misspelled reference.
    fn near_miss(&self, text: &str) -> bool {
        let (first, _) = split_first(text);
        suggestion(first, &self.ref_candidates()).is_some()
    }

    fn step_ref(&mut self, i: usize, rest: Option<&str>, span: Span) -> Type {
        let Some(rest) = rest else { return self.bare_step_type(i) };
        let (out, more) = split_first(rest);
        if out == "out" {
            return self.run_output(i, rest, more, span);
        }
        let spec = self.steps[i].spec;
        // A `decide` answer types as its declared `returns:` variants.
        if spec.is_some_and(|sp| sp.decision) && out == "answer" && more.is_none() {
            return Type::Decision(self.steps[i].variants.clone());
        }
        match spec.and_then(|sp| sp.output(out)) {
            Some(ty) if more.is_none() => ty.clone(),
            Some(_) => Type::Any, // a field of a declared output, unchecked
            None => {
                let name = self.steps[i].name.clone();
                let msg = format!("step `{name}` has no output `{out}`");
                if spec.is_some_and(|sp| sp.runtime_outputs) {
                    self.err_hint(
                        Code::UnknownOutput,
                        span,
                        msg,
                        format!(
                            "`{name}` outputs are known only at run time: read them as `{name}.out.<name>`"
                        ),
                    );
                } else {
                    let outs: Vec<String> = spec
                        .map(|sp| sp.outputs.iter().map(|(n, _)| n.to_string()).collect())
                        .unwrap_or_default();
                    match suggestion(out, &outs) {
                        Some((s, unique)) => {
                            let hint = format!("did you mean `{s}`?");
                            let at = segment_span(rest, span.end - rest.len() as u32, 0);
                            let fix = Fix::new(at, s, unique);
                            self.err_hint_fix(Code::UnknownOutput, span, msg, hint, fix)
                        }
                        None => self.err(Code::UnknownOutput, span, msg),
                    }
                }
                Type::Any
            }
        }
    }

    /// `<apply step>.out.<name>`: a run-time output, typed by what the IaC
    /// declares. `outputs:` on the step wins, then the `.tf` files behind
    /// its plan's `dir:` when the caller read them; with neither, the name
    /// is unchecked and the type is `any`, as it always was.
    fn run_output(&mut self, i: usize, rest: &str, more: Option<&str>, span: Span) -> Type {
        // `rest` is `<out>.<name>[.<field>…]`; the name is its second
        // segment, and anything after it names a field of the output.
        let Some(after_out) = more else { return Type::Any }; // a bare `.out`
        let (name, deeper) = split_first(after_out);
        let mapped =
            self.steps[i].outputs.iter().find(|(n, _)| n == name).and_then(|(_, ty)| ty.clone());
        if let Some(ty) = mapped {
            return Self::field_of(ty, deeper);
        }
        // A block use: its `outputs:` mapping answers, and a name it does
        // not declare is the same unknown output it is anywhere else.
        if let Some(block) = self.steps[i].block {
            let Some(ty) = block.outputs.iter().find(|(n, _)| n == name).map(|(_, ty)| ty.clone())
            else {
                let step = self.steps[i].name.clone();
                let names: Vec<String> = block.outputs.iter().map(|(n, _)| n.clone()).collect();
                let msg = format!("block `{}` has no output `{name}`", block.name);
                match suggestion(name, &names) {
                    Some((s, unique)) => {
                        let at = segment_span(rest, span.end - rest.len() as u32, 1);
                        let fix = Fix::new(at, s.clone(), unique);
                        self.err_hint_fix(
                            Code::UnknownOutput,
                            span,
                            msg,
                            format!("step `{step}` could read `{step}.{s}`; did you mean `{s}`?"),
                            fix,
                        );
                    }
                    None => self.err(Code::UnknownOutput, span, msg),
                }
                return Type::Any;
            };
            return Self::field_of(ty, deeper);
        }
        let (Some(dir), Some(declared)) = (self.iac_dir(i), self.iac_outputs) else {
            return Type::Any;
        };
        // An empty declaration says as little as no directory at all.
        let Some(outputs) = declared.get(dir).filter(|o| !o.is_empty()) else { return Type::Any };
        let Some(ty) = outputs.get(name).cloned() else {
            let step = self.steps[i].name.clone();
            let names: Vec<String> = outputs.keys().cloned().collect();
            let declared: String =
                names.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(", ");
            let hint = format!("`{dir}` declares {declared}");
            let msg = format!("step `{step}` produces no output `{name}`");
            let at = segment_span(rest, span.end - rest.len() as u32, 1);
            match suggestion(name, &names) {
                Some((s, unique)) => {
                    let fix = Fix::new(at, s.clone(), unique);
                    self.err_hint_fix(
                        Code::UnknownOutput,
                        span,
                        msg,
                        format!("{hint}; did you mean `{s}`?"),
                        fix,
                    );
                }
                None => self.err_hint(Code::UnknownOutput, span, msg, hint),
            }
            return Type::Any;
        };
        Self::field_of(ty, deeper)
    }

    /// The `dir:` whose `.tf` files answer for step `i`: the plan it
    /// applies. `None` for anything that is not an apply step, so nothing
    /// else in the file is checked against Terraform's outputs.
    fn iac_dir(&self, i: usize) -> Option<&str> {
        let step = &self.steps[i];
        if !step.spec.is_some_and(|sp| APPLY_KINDS.contains(&sp.name.as_str())) {
            return None;
        }
        let plan = self.step_index(step.plan.as_deref()?)?;
        self.steps[plan].dir.as_deref()
    }

    /// The type a field of `ty` has, where `rest` is the `.field…` tail. A
    /// record knows its fields; anything else is unchecked.
    fn field_of(ty: Type, rest: Option<&str>) -> Type {
        let (Some(rest), Type::Record(fields)) = (rest, &ty) else { return ty };
        let (name, deeper) = split_first(rest);
        fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, t)| Self::field_of(t.clone(), deeper))
            .unwrap_or(Type::Any)
    }

    fn context(&mut self, ns: &str, rest: Option<&str>, span: Span) -> Option<Type> {
        let Some(rest) = rest else { return Some(Type::Any) }; // a bare namespace
        let (name, _more) = split_first(rest);
        // `inputs.<name>` names a block's own input, and only inside the
        // block file that declares it — in a workflow `inputs` is no
        // namespace at all, so the step below says it is unknown.
        if ns == INPUTS && self.block.is_some() {
            let Some(ty) = self.block.as_ref().and_then(|b| b.inputs.get(name)).cloned() else {
                let names: Vec<String> = self
                    .block
                    .as_ref()
                    .map(|b| b.inputs.keys().cloned().collect())
                    .unwrap_or_default();
                let names: Vec<&str> = names.iter().map(String::as_str).collect();
                member_error(self, INPUTS, name, &names, span);
                return None;
            };
            return Some(ty);
        }
        let ty = match (ns, name) {
            ("git", "sha" | "ref" | "branch") => Type::String,
            ("git", "tag") => Type::Optional(Box::new(Type::String)),
            ("pr", "number") => Type::Optional(Box::new(Type::Int)),
            ("pr", "base") => Type::Optional(Box::new(Type::String)),
            ("run", "id" | "actor") => Type::String,
            ("run", "is_agent") => Type::Bool,
            ("ci", "provider") => Type::Optional(Box::new(Type::String)),
            ("env", "name") => Type::String,
            ("env", var) if self.env_vars.iter().any(|v| v == var) => Type::Any,
            ("secrets", _) => Type::Secret,
            ("git" | "pr" | "run" | "ci" | "env", name) => {
                let msg = format!("unknown context value `{ns}.{name}`");
                match suggest(name, &self.env_vars) {
                    Some(s) => self.err_hint(
                        Code::UnknownRef,
                        span,
                        msg,
                        format!("did you mean `env.{s}`?"),
                    ),
                    None => match (ns, name) {
                        ("git", n) => {
                            member_error(self, "git", n, &["branch", "ref", "sha", "tag"], span)
                        }
                        ("pr", n) => member_error(self, "pr", n, &["base", "number"], span),
                        ("run", n) => {
                            member_error(self, "run", n, &["actor", "id", "is_agent"], span)
                        }
                        ("ci", n) => member_error(self, "ci", n, &["provider"], span),
                        _ => self.err(Code::UnknownRef, span, msg),
                    },
                }
                return None;
            }
            _ => return None, // not a namespace: the caller reports it
        };
        if matches!(ty, Type::Optional(_)) {
            self.warn_hint(
                Code::OptionalAbsent,
                span,
                format!("optional value `{ns}.{name}` may be absent"),
                "it has no value on a laptop or outside a pull request".to_string(),
            );
        }
        Some(ty)
    }

    // --- expressions ------------------------------------------------------

    fn ty_of(&mut self, cur: usize, e: &Expr<'_>) -> Type {
        let t = match e {
            Expr::Default { rhs, .. } => self.ty_of(cur, rhs),
            Expr::Tuple { items, .. } => {
                for i in items {
                    self.ty_of(cur, i);
                }
                Type::Any
            }
            Expr::Or { args, .. } | Expr::And { args, .. } => {
                for a in args {
                    self.demand_bool(cur, a);
                }
                Type::Bool
            }
            Expr::Not { arg, .. } => {
                self.demand_bool(cur, arg);
                Type::Bool
            }
            Expr::Compare { lhs, op, rhs, .. } => self.compare(cur, lhs, *op, rhs.as_deref()),
            Expr::IsTest { subject, answer, threshold, .. } => {
                self.is_test(cur, subject, answer, threshold.as_ref().map(|(_, _, e)| e.as_ref()))
            }
            Expr::Union { alts, .. } => {
                let mut joined = Type::Any;
                for (n, a) in alts.iter().enumerate() {
                    let t = self.ty_of(cur, a);
                    if n == 0 {
                        joined = t;
                    } else if joined != t {
                        joined = Type::Any;
                    }
                }
                joined
            }
            Expr::Phrase { atoms, .. } => {
                for a in atoms {
                    self.atom(cur, a);
                }
                Type::Any
            }
            Expr::Atom { atom, .. } => self.atom(cur, atom),
        };
        self.record(e.span(), t.clone());
        t
    }

    fn demand_bool(&mut self, cur: usize, e: &Expr<'_>) {
        let t = self.ty_of(cur, e);
        if !types::coerce(&Type::Bool, &t) {
            self.err(Code::TypeMismatch, e.span(), format!("expected bool, got {t}"));
        }
    }

    fn atom(&mut self, cur: usize, a: &Atom<'_>) -> Type {
        match a {
            Atom::Word(w) => self.word_untyped(cur, w),
            Atom::Str(s) => {
                for part in s.parts() {
                    if let StrPart::Interp(i) = part
                        && let Some(name) = i.name()
                    {
                        self.interp(cur, name, i.name_span().unwrap_or_else(|| i.node.span()));
                    }
                }
                Type::String
            }
            Atom::Paren { inner: Some(e), .. } => self.ty_of(cur, e),
            Atom::Paren { inner: None, .. } => Type::Any,
        }
    }

    fn compare(
        &mut self,
        cur: usize,
        lhs: &Expr<'_>,
        op: ks_lang::CmpOp,
        rhs: Option<&Expr<'_>>,
    ) -> Type {
        let Some(rhs) = rhs else { return Type::Any }; // the parser reported it
        let lt = self.ty_of(cur, lhs);
        let rt = self.ty_of(cur, rhs);
        // An enum answer literal beside a decision: `risk.answer == low`.
        if let Some(word) = answer_word(rhs)
            && let Type::Decision(vs) = &lt
        {
            self.answer(vs, &word);
            return Type::Bool;
        }
        if let Some(word) = answer_word(lhs)
            && let Type::Decision(vs) = &rt
        {
            self.answer(vs, &word);
            return Type::Bool;
        }
        let ordered = matches!(op, ks_lang::CmpOp::Eq | ks_lang::CmpOp::Ne)
            || (lt.is_numeric() && rt.is_numeric())
            || (lt == Type::String && rt == Type::String);
        // An optional value compares against the bare type: `git.tag != ""`
        // asks whether the tag is set. (The use-site warning for optional
        // values stays.)
        let compatible = lt == rt
            || bare_optional(&lt) == bare_optional(&rt)
            || (lt.is_numeric() && rt.is_numeric())
            || matches!(&lt, Type::Any | Type::Decision(_))
            || matches!(&rt, Type::Any | Type::Decision(_));
        if ordered && compatible {
            return Type::Bool;
        }
        let span = Span::new(lhs.span().start.min(rhs.span().start), rhs.span().end);
        self.err(Code::TypeMismatch, span, format!("cannot compare `{lt}` and `{rt}`"));
        Type::Bool
    }

    fn answer(&mut self, variants: &[String], word: &Word<'_>) {
        let text = word.text();
        if variants.iter().any(|v| v == text) {
            return;
        }
        let span = word.node.span();
        match suggest(text, variants) {
            Some(s) => self.err_hint(
                Code::UnknownAnswer,
                span,
                format!("unknown answer `{text}`"),
                format!("did you mean `{s}`?"),
            ),
            None if variants.is_empty() => self.err_hint(
                Code::UnknownAnswer,
                span,
                format!("unknown answer `{text}`"),
                "declare the answers under `returns:`",
            ),
            None => self.err(
                Code::UnknownAnswer,
                span,
                format!("unknown answer `{text}` (expected one of {})", variants.join(", ")),
            ),
        }
    }

    fn is_test(
        &mut self,
        cur: usize,
        subject: &Expr<'_>,
        answer: &Expr<'_>,
        threshold: Option<&Expr<'_>>,
    ) -> Type {
        // `env is prod`: the subject is the context namespace, the answer a
        // declared environment — the only non-decision `is` subject.
        if let Some(w) = subject_word(subject)
            && w.scalar() == ks_lang::Scalar::Ident
            && w.text() == "env"
        {
            if let Some(name) = subject_word(answer) {
                let text = name.text();
                if !self.env_names.iter().any(|e| e == text) {
                    let msg = format!("unknown environment `{text}`");
                    match suggest(text, &self.env_names) {
                        Some(s) => self.err_hint(
                            Code::EnvProblem,
                            name.node.span(),
                            msg,
                            format!("did you mean `{s}`?"),
                        ),
                        None => self.err(Code::EnvProblem, name.node.span(), msg),
                    }
                }
            } else {
                self.err(Code::EnvProblem, answer.span(), "expected an environment name");
            }
            if threshold.is_some() {
                self.err(
                    Code::EnvProblem,
                    subject.span(),
                    "environment tests take no confidence threshold",
                );
            }
            return Type::Bool;
        }
        match self.ty_of(cur, subject) {
            Type::Decision(vs) => {
                if let Some(w) = subject_word(answer) {
                    self.answer(&vs, &w);
                } else {
                    self.err(Code::UnknownAnswer, answer.span(), "expected an answer word");
                }
                if let Some(bound) = threshold {
                    self.confidence(bound);
                }
            }
            Type::Any => {}
            other => self.err(
                Code::TypeMismatch,
                subject.span(),
                format!("expected a decision, got `{other}`"),
            ),
        }
        Type::Bool
    }

    fn confidence(&mut self, bound: &Expr<'_>) {
        let Expr::Atom { atom: Atom::Word(w), .. } = bound else {
            self.err(
                Code::TypeMismatch,
                bound.span(),
                "confidence must be a number between 0 and 1",
            );
            return;
        };
        let ok = w.scalar() == ks_lang::Scalar::Number
            && w.text().parse::<f64>().is_ok_and(|n| (0.0..=1.0).contains(&n));
        if !ok {
            self.err(
                Code::TypeMismatch,
                w.node.span(),
                "confidence must be a number between 0 and 1",
            );
        }
    }

    // --- structured inputs ------------------------------------------------

    /// `show:` items: references of any type — except secrets, which never
    /// reach a string or a log.
    fn check_refs(&mut self, idx: usize, e: &Expr<'_>) {
        for item in tuple_items(e.clone()) {
            match &item {
                Expr::Atom { atom: Atom::Word(w), .. }
                    if w.scalar() == ks_lang::Scalar::DottedName
                        || w.scalar() == ks_lang::Scalar::Ident =>
                {
                    let span = w.node.span();
                    if let Some((target, ty)) = self.resolve_ref(Some(idx), w.text(), span) {
                        self.record(span, ty.clone());
                        if ty == Type::Secret {
                            self.cannot_show_secret(span, w.text());
                        }
                        if let Some(target) = target {
                            self.shown.push((idx, target));
                        }
                    }
                }
                _ => self.err_hint(
                    Code::UnknownRef,
                    item.span(),
                    "expected a reference (`step.output`)",
                    "show takes step outputs and context values",
                ),
            }
        }
    }

    /// Secrets must never be displayed; same rule as interpolation.
    fn cannot_show_secret(&mut self, span: Span, name: &str) {
        self.err_hint(
            Code::SecretShown,
            span,
            format!("secret `{name}` cannot be shown"),
            "secrets never go into strings or logs",
        );
    }

    /// `else:` actions: `ask @handle[, …]`, `show ref[, …]`.
    fn check_actions(&mut self, idx: usize, e: &Expr<'_>) {
        for item in tuple_items(e.clone()) {
            let Some(Atom::Word(verb)) = item.atoms().first() else {
                self.err_hint(
                    Code::UnknownAction,
                    item.span(),
                    "expected an action",
                    "`ask @platform` or `show risk.reason`",
                );
                continue;
            };
            let rest = &item.atoms()[1..];
            match verb.text() {
                "ask" => {
                    if rest.is_empty() {
                        self.err_hint(
                            Code::UnknownAction,
                            item.span(),
                            "`ask` takes a handle",
                            "`ask @platform`",
                        );
                    }
                    for a in rest {
                        if let Atom::Word(w) = a {
                            let got = self.word_untyped(idx, w);
                            if got != Type::Handle {
                                self.err(
                                    Code::TypeMismatch,
                                    w.node.span(),
                                    format!("expected `Handle`, got `{got}`"),
                                );
                            }
                        }
                    }
                }
                "show" => {
                    if rest.is_empty() {
                        self.err_hint(
                            Code::UnknownAction,
                            item.span(),
                            "`show` takes a reference",
                            "`show risk.reason`",
                        );
                    }
                    for a in rest {
                        if let Atom::Word(w) = a {
                            let span = w.node.span();
                            if let Some(ty) = self.soft_ref(idx, w.text(), span) {
                                if ty == Type::Secret {
                                    self.cannot_show_secret(span, w.text());
                                }
                            } else if w.scalar() != ks_lang::Scalar::Handle {
                                self.err_hint(
                                    Code::UnknownRef,
                                    span,
                                    format!("expected a reference, got `{}`", w.text()),
                                    "show takes step outputs and context values",
                                );
                            }
                        } else {
                            self.err(Code::UnknownRef, a.span(), "expected a reference");
                        }
                    }
                }
                other => {
                    let msg = format!("unknown action `{other}`");
                    match suggest(other, &["ask", "show"]) {
                        Some(s) => self.err_hint(
                            Code::UnknownAction,
                            verb.node.span(),
                            msg,
                            format!("did you mean `{s}`?"),
                        ),
                        None => self.err(Code::UnknownAction, verb.node.span(), msg),
                    }
                }
            }
        }
    }

    // --- triggers, environments, policy -----------------------------------

    fn triggers_of(&mut self, entry: Entry<'_>) -> Vec<Trigger> {
        match entry.expr() {
            Some(e) => tuple_items(e).iter().filter_map(|item| self.trigger(item)).collect(),
            None => Vec::new(),
        }
    }

    fn trigger(&mut self, e: &Expr<'_>) -> Option<Trigger> {
        let hint = "`push main`, `pr`, `tag v*`, `manual`";
        let atoms = e.atoms();
        let Some(Atom::Word(kind)) = atoms.first() else {
            self.err_hint(Code::BadTrigger, e.span(), "expected a trigger", hint);
            return None;
        };
        let text = kind.text();
        let span = kind.node.span();
        let known = match text {
            "push" => TriggerKind::Push,
            "pr" => TriggerKind::Pr,
            "tag" => TriggerKind::Tag,
            "manual" => TriggerKind::Manual,
            "schedule" => {
                self.err(Code::BadTrigger, span, "`schedule` triggers are not supported yet");
                return None;
            }
            other => {
                let msg = format!("unknown trigger `{other}`");
                match suggest(other, &TRIGGER_KINDS) {
                    Some(s) => {
                        self.err_hint(Code::BadTrigger, span, msg, format!("did you mean `{s}`?"))
                    }
                    None => self.err(Code::BadTrigger, span, msg),
                }
                return None;
            }
        };
        let glob = match atoms.get(1) {
            Some(Atom::Word(w)) => Some(w.text().to_string()),
            _ => None,
        };
        Some(Trigger { kind: known, glob, span: e.span() })
    }

    fn check_envs(&mut self, envs: Entry<'_>) -> Vec<Env> {
        let mut out = Vec::new();
        for e in envs.children() {
            let Some(name) = e.key_name() else { continue };
            let mut env = implicit_default();
            env.name = name.into();
            env.span = e.key_span();
            for p in e.children() {
                let Some(prop) = p.key_name() else { continue };
                self.subject = Some(format!("{name}.{prop}"));
                match prop {
                    "on" => env.triggers = self.triggers_of(p),
                    "ci-only" => env.ci_only = self.ci_only(p, Code::EnvProblem),
                    "secrets" => env.secrets = self.scalar_text(p),
                    "approvers" => {
                        if let Some(v) = p.expr() {
                            for item in tuple_items(v) {
                                match &item {
                                    Expr::Atom { atom: Atom::Word(w), .. } => {
                                        env.approvers.push(w.text().into());
                                        if w.scalar() != ks_lang::Scalar::Handle {
                                            self.err_hint(
                                                Code::TypeMismatch,
                                                w.node.span(),
                                                format!("expected `Handle`, got `{}`", w.text()),
                                                "approvers are handles, like `@platform`",
                                            );
                                        }
                                    }
                                    _ => self.err_hint(
                                        Code::TypeMismatch,
                                        item.span(),
                                        "expected a handle",
                                        "approvers are handles, like `@platform`",
                                    ),
                                }
                            }
                        }
                    }
                    "vars" => {
                        env.vars =
                            p.children().filter_map(|c| c.key_name()).map(String::from).collect();
                    }
                    other => {
                        let msg = format!("unknown environment property `{other}`");
                        match suggest(other, &ENV_PROPERTIES) {
                            Some(s) => self.err_hint(
                                Code::EnvProblem,
                                p.key_span(),
                                msg,
                                format!("did you mean `{s}`?"),
                            ),
                            None => self.err(Code::EnvProblem, p.key_span(), msg),
                        }
                    }
                }
                self.subject = None;
            }
            out.push(env);
        }
        out
    }

    // --- blocks ------------------------------------------------------------

    /// The `block:` this file declares, with the inputs its internal steps
    /// read as `inputs.<name>`. Declared before the steps, so a step may
    /// name any input whatever its order in the file.
    fn declare_block(&mut self, entries: &[Entry<'_>], block: Entry<'_>) {
        let Some(name) = block.expr().as_ref().and_then(value_text) else { return };
        let inputs = entries
            .iter()
            .find(|e| e.key_name() == Some("inputs"))
            .map(|declared| {
                declared
                    .children()
                    .filter_map(|i| {
                        let name = i.key_name()?.to_string();
                        let expr = i.expr()?;
                        // `domain: string`, or the annotation of `replicas:
                        // int = 2`: either way the declared type is the
                        // annotation.
                        let ty = match annotation_default(&expr) {
                            Some((_, ty, _)) => ty,
                            None => Type::parse(&value_text(&expr)?)?,
                        };
                        Some((name, ty))
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.block = Some(BlockScope { name, inputs });
    }

    /// A block file's `block:`, `inputs:` and `outputs:`, each checked
    /// against what the language spells. A block file is a file like any
    /// other: what it declares is checked where it is declared, so the
    /// block alone says whether it is sound.
    fn check_block_entry(&mut self, e: Entry<'_>) {
        match e.key_name() {
            Some("inputs") => self.check_block_inputs(e),
            Some("outputs") => self.check_block_outputs(e),
            _ => {}
        }
    }

    /// `inputs:`: `name: <type>`, or `name: <type> = <literal>` for a
    /// default. The type must parse, and a default must be a literal of it
    /// — a default that fits nothing is a lie about what a use may leave
    /// out.
    fn check_block_inputs(&mut self, inputs: Entry<'_>) {
        for i in inputs.children() {
            let (Some(name), Some(expr)) = (i.key_name(), i.expr()) else { continue };
            self.subject = Some(format!("inputs.{name}"));
            // `when:`, `after:` and `outputs:` are read off a use whatever
            // its kind, so an input of that name would be shadowed by the
            // step property rather than reach the block.
            if !block::input_allowed(name) {
                self.err_hint(
                    Code::ReservedStepName,
                    i.key_span(),
                    format!("`{name}` is a step property, not an input name"),
                    format!("rename the input; a use spells `{name}` as the step's own"),
                );
                self.subject = None;
                continue;
            }
            match annotation_default(&expr) {
                Some((_, ty, rhs)) => {
                    let span = rhs.span();
                    let Some(text) = value_text(rhs) else {
                        self.err_hint(
                            Code::TypeMismatch,
                            span,
                            "a default is a single literal",
                            "`replicas: int = 2`",
                        );
                        continue;
                    };
                    if let LiteralFit::Err = self.literal_fit(&ty, &text) {
                        self.err_hint(
                            Code::TypeMismatch,
                            span,
                            format!("expected {ty}, got `{text}`"),
                            "the default must be a literal of the type it declares",
                        );
                    }
                }
                None => {
                    let Some(text) = value_text(&expr) else {
                        self.err_hint(
                            Code::TypeMismatch,
                            expr.span(),
                            "an input declares a type",
                            "`domain: string`",
                        );
                        continue;
                    };
                    if Type::parse(&text).is_none() {
                        let hint = "spell it as `k8s.Cluster`, `string` or `{name: type}`";
                        self.err_hint(
                            Code::TypeMismatch,
                            expr.span(),
                            format!("`{text}` is not a type"),
                            hint,
                        );
                    }
                }
            }
            self.subject = None;
        }
    }

    /// `outputs:`: `name: <type> = <an internal step's output>`. The right
    /// side is a reference like any other, so it types against the steps
    /// the block declares and must fit the type written beside it — the
    /// output a use reads back is exactly what this says it is.
    fn check_block_outputs(&mut self, outputs: Entry<'_>) {
        for o in outputs.children() {
            let (Some(name), Some(expr)) = (o.key_name(), o.expr()) else { continue };
            self.subject = Some(format!("outputs.{name}"));
            let hint = "spell it as `url: string = ship.url`";
            let Some((_, ty, rhs)) = annotation_default(&expr) else {
                let spelled = value_text(&expr).unwrap_or_default();
                self.err_hint(
                    Code::TypeMismatch,
                    expr.span(),
                    format!("`{spelled}` is not a `name: type = step.output` mapping"),
                    hint,
                );
                self.subject = None;
                continue;
            };
            let span = rhs.span();
            match subject_word(rhs) {
                Some(w) if w.scalar() == ks_lang::Scalar::DottedName => {
                    if let Some((_, got)) = self.resolve_ref(None, w.text(), w.node.span()) {
                        self.demand(w.node.span(), ty, got, None, None);
                    }
                }
                Some(w) => {
                    let text = w.text();
                    self.demand_literal(w.node.span(), ty, types::literal_type(text), Some(text));
                }
                None => self.err_hint(
                    Code::TypeMismatch,
                    span,
                    "an output maps one of the block's own step outputs",
                    hint,
                ),
            }
            self.subject = None;
        }
    }

    fn check_policy(&mut self, policy: Entry<'_>) {
        for actor in policy.children() {
            let kind = match actor.key_name() {
                Some("agents") => ActorKind::Agent,
                Some("humans") => ActorKind::Human,
                Some(other) => {
                    let msg = format!("unknown policy subject `{other}`");
                    match suggest(other, &["agents", "humans"]) {
                        Some(s) => self.err_hint(
                            Code::PolicyDecl,
                            actor.key_span(),
                            msg,
                            format!("did you mean `{s}`?"),
                        ),
                        None => self.err(Code::PolicyDecl, actor.key_span(), msg),
                    }
                    continue;
                }
                None => continue,
            };
            for p in actor.children() {
                let Some(prop) = p.key_name() else { continue };
                self.subject = Some(format!("{}.{prop}", actor.key_name().unwrap_or_default()));
                match prop {
                    // Every declaration is retained: `can:` allows, `before:`
                    // asks, `never:` refuses, and a decision weighs all three
                    // ([#101](https://github.com/Keep-Shipping/harness/issues/101)).
                    "can" | "before" | "never" => {
                        let disposition = match prop {
                            "can" => Disposition::Allow,
                            "before" => Disposition::Ask,
                            _ => Disposition::Never,
                        };
                        self.actions(p, kind, disposition);
                    }
                    "ask" => {
                        if let Some(v) = p.expr() {
                            for item in tuple_items(v) {
                                match &item {
                                    Expr::Atom { atom: Atom::Word(w), .. }
                                        if w.scalar() != ks_lang::Scalar::Handle =>
                                    {
                                        self.err_hint(
                                            Code::TypeMismatch,
                                            w.node.span(),
                                            format!("expected `Handle`, got `{}`", w.text()),
                                            "`ask` takes handles, like `@platform`",
                                        );
                                    }
                                    Expr::Atom { atom: Atom::Word(w), .. } => {
                                        // The handles a subject asks are part
                                        // of what its `before:` rules mean, so
                                        // they are kept: "ask" with nobody
                                        // named is still an ask.
                                        let handle = w.text().trim_start_matches('@').to_string();
                                        self.policy.ask(AskHandle {
                                            subject: kind,
                                            handle,
                                            span: item.span(),
                                        });
                                    }
                                    Expr::Atom { .. } => {}
                                    _ => self.err_hint(
                                        Code::TypeMismatch,
                                        item.span(),
                                        "expected a handle",
                                        "`ask` takes handles, like `@platform`",
                                    ),
                                }
                            }
                        }
                    }
                    other => {
                        let msg = format!("unknown policy property `{other}`");
                        match suggest(other, &["ask", "can", "before", "never"]) {
                            Some(s) => self.err_hint(
                                Code::PolicyDecl,
                                p.key_span(),
                                msg,
                                format!("did you mean `{s}`?"),
                            ),
                            None => self.err(Code::PolicyDecl, p.key_span(), msg),
                        }
                    }
                }
                self.subject = None;
            }
        }
    }

    /// `can`/`before`/`never`: tuples of `<verb> [<object>]`
    /// (`read secrets`, `deploy prod`, bare `apply`). Every rule is retained
    /// on the workflow with its disposition, because a decision weighs them
    /// together ([#101](https://github.com/Keep-Shipping/harness/issues/101)).
    fn actions(&mut self, entry: Entry<'_>, subject: ActorKind, disposition: Disposition) {
        let Some(e) = entry.expr() else { return };
        for item in tuple_items(e.clone()) {
            let atoms = item.atoms();
            if atoms.is_empty() {
                self.err_hint(
                    Code::PolicyAction,
                    item.span(),
                    "expected an action",
                    "`apply`, `deploy prod`, `read secrets`",
                );
                continue;
            }
            let Some(Atom::Word(verb)) = atoms.first() else { continue };
            let text = verb.text();
            if !POLICY_VERBS.contains(&text) {
                let msg = format!("unknown action `{text}`");
                let span = verb.node.span();
                let d = Diagnostic::error(Code::PolicyAction, span, msg);
                // `policy:` fixes are real edits, and `--fix` refuses them
                // by span: the edit is right, the decision is a human's.
                self.push(match suggestion(text, &POLICY_VERBS) {
                    Some((s, unique)) => d
                        .with_hint(format!("did you mean `{s}`?"))
                        .with_fix(Fix::new(span, s, unique)),
                    None => d,
                });
                continue;
            }
            if text == "publish"
                && matches!(atoms.get(1), Some(Atom::Word(o)) if o.text() == BLOCKS)
            {
                // `publish blocks` names what is published, not where. A
                // `publish <env>` also parses: publishing somewhere is a real
                // action, and the two objects are distinguishable by name.
                self.rule(subject, disposition, text, BLOCKS, item.span());
                continue;
            }
            if let Some(object) = fixed_object(text) {
                match atoms.get(1) {
                    Some(Atom::Word(obj)) if obj.text() == object => {
                        self.rule(subject, disposition, text, object, item.span());
                    }
                    Some(a) => {
                        self.err(Code::PolicyAction, a.span(), format!("`{text}` takes `{object}`"))
                    }
                    None => self.err_hint(
                        Code::PolicyAction,
                        verb.node.span(),
                        format!("`{text}` takes `{object}`"),
                        format!("`{text} {object}`"),
                    ),
                }
                continue;
            }
            // A verb with no object names one action whatever the
            // environment, so the rule is kept against `*` — a `can: apply`
            // is a real grant, and dropping it would make the file's policy
            // answer a question nobody asked.
            let Some(Atom::Word(env)) = atoms.get(1) else {
                self.rule(subject, disposition, text, ANY_OBJECT, item.span());
                continue;
            };
            let name = env.text();
            self.rule(subject, disposition, text, name, item.span());
            if self.env_names.iter().any(|e| e == name) {
                continue;
            }
            let msg = format!("undeclared environment `{name}`");
            match suggest(name, &self.env_names) {
                Some(s) => self.err_hint(
                    Code::EnvProblem,
                    env.node.span(),
                    msg,
                    format!("did you mean `{s}`? or declare it under `envs:`"),
                ),
                None => self.err_hint(
                    Code::EnvProblem,
                    env.node.span(),
                    msg,
                    "declare it under `envs:`",
                ),
            }
        }
    }

    // --- graph ------------------------------------------------------------

    /// Retains one `policy:` rule on the workflow.
    fn rule(
        &mut self,
        subject: ActorKind,
        disposition: Disposition,
        verb: &str,
        object: &str,
        span: Span,
    ) {
        self.policy.forbid(PolicyRule {
            subject,
            verb: verb.to_string(),
            object: object.to_string(),
            disposition,
            span,
        });
    }

    /// A policy check that binds the run's actor: when an agent runs a file
    /// whose policy forbids agents to read secrets, every distinct secret
    /// the run needs is refused once, at its first reference, so the run
    /// stops before it starts.
    fn enforce_actor_policy(&mut self) {
        if self.actor != Some(ActorKind::Agent) {
            return;
        }
        self.forbid_agent_secrets();
        self.forbid_agent_actions();
    }

    /// `agents: never: read secrets` over the secrets this run needs: every
    /// distinct one is refused once, at its first reference, so the run
    /// stops before it starts. A block use is judged by the secrets the
    /// steps inside it read, so a block cannot hide one behind its name.
    fn forbid_agent_secrets(&mut self) {
        if !self.policy.forbids(ActorKind::Agent, "read", "secrets") {
            return;
        }
        // One refusal per distinct key, at its first reference span. Both
        // sources are collected owned so the loop below can borrow `self`
        // mutably without cloning either.
        let mut seen: HashSet<&str> = HashSet::new();
        let mut firsts: Vec<(String, Span)> = Vec::new();
        let mut seen_keys: HashSet<String> = HashSet::new();
        for u in &self.secret_uses {
            if seen.insert(u.key.as_str()) {
                firsts.push((u.key.clone(), u.span));
            }
        }
        for (key, span) in self.block_secrets() {
            if seen_keys.insert(key.clone()) {
                firsts.push((key, span));
            }
        }
        if firsts.is_empty() {
            return; // the rule binds, but this run needs no secrets
        }
        for (key, span) in &firsts {
            self.err_hint(
                Code::PolicyForbidden,
                *span,
                format!(
                    "policy forbids agents from reading secrets, but this run needs secrets.{key}"
                ),
                "the rule is `policy: agents: never: read secrets`",
            );
        }
        // The rule's own location, so the report shows the line to change.
        if let Some(span) = self.policy.rule_span(ActorKind::Agent, "read", "secrets") {
            self.err(
                Code::PolicyForbidden,
                span,
                "the `never: read secrets` rule applies to this run",
            );
        }
    }

    /// A `never:` rule refuses the run at the step that would break it. Keyed
    /// off the actor being checked, not off `Agent`: `humans: never: apply`
    /// refuses a human run just as `agents: never: apply` refuses an agent's.
    ///
    /// The refusal is the step's, not the run's, so the author sees which line
    /// to change. An `Ask` is deliberately *not* an error — an approval is a
    /// thing the run does.
    fn enforce_step_policy(&mut self) {
        let Some(actor) = self.actor else { return };
        let section = policy::section_name(actor);
        for index in 0..self.steps.len() {
            let Some(spec) = self.steps[index].spec else { continue };
            let class = spec.action();
            let Some(decision) = policy::decide(&self.policy, None, actor, &class) else {
                continue;
            };
            if decision.disposition != Disposition::Never {
                continue;
            }
            let (name, span) = {
                let step = &self.steps[index];
                (step.name.clone(), step.span)
            };
            let (verb, object) = policy::action_of(&class).expect("a class that decided");
            let written =
                if object == ANY_OBJECT { verb.to_string() } else { format!("{verb} {object}") };
            self.push(
                Diagnostic::error(
                    Code::PolicyForbidden,
                    span,
                    format!(
                        "policy forbids {section} from {class}, but this run has a `{}` step",
                        spec.name
                    ),
                )
                .with_subject(name)
                .with_hint(format!("the rule is `policy: {section}: never: {written}`")),
            );
            // The rule's own location, so the report shows the line to change.
            if let Some(rule_span) = decision.rule_span {
                self.err(
                    Code::PolicyForbidden,
                    rule_span,
                    format!("the rule forbidding `{class}` applies to this run"),
                );
            }
        }
    }

    /// A verb under `can:` or `before:` that no step in this file can produce
    /// binds nothing: the rule is a claim about a workflow this file does not
    /// describe. A warning, not an error — the step that makes it real may
    /// arrive from a plugin or a later change.
    ///
    /// `never:` is never warned about (forbidding what the file does not do is
    /// defensive policy), nor is a verb no step kind can produce *yet* (`test`,
    /// `run scripts`, `publish blocks`) — that is vocabulary ahead of the step
    /// kinds, not a claim about this file.
    fn warn_unused_policy_verbs(&mut self) {
        // Verbs are tracked apart from objects because an environment is not a
        // property of a step: any deploy produces `deploy staging`.
        let mut verbs: HashSet<&str> = HashSet::new();
        let mut has_apply = false;
        for step in &self.steps {
            let Some(spec) = step.spec else { continue };
            let kind = spec.action().kind;
            if kind == ActionKind::Apply {
                has_apply = true;
            }
            if let Some((verb, _)) = policy::action_of(&ActionClass::new(kind)) {
                verbs.insert(verb);
            }
        }
        // An apply whose plan destroys anything *is* a destroy
        // ([`ActionClass::with_plan_destroys`]), so any apply produces it.
        if has_apply {
            verbs.insert("destroy");
        }
        // A secret reference produces `read secrets`, which no step kind does.
        let mut objects: HashSet<String> = HashSet::new();
        if !self.secret_uses.is_empty() {
            objects.insert(format!("read {SECRETS}"));
        }
        let unused: Vec<PolicyRule> = self
            .policy
            .rules()
            .iter()
            .filter(|rule| {
                rule.disposition != Disposition::Never
                    && PRODUCIBLE_VERBS.contains(&rule.verb.as_str())
                    && !produced_by(rule, &verbs, &objects)
            })
            .cloned()
            .collect();
        for rule in unused {
            self.warn_hint(
                Code::PolicyUnused,
                rule.span,
                format!("no step in this file can `{}`", written_action(&rule)),
                "a `can:` or `before:` rule binds the action it names; \
                 drop it, or add the step it is about"
                    .to_string(),
            );
        }
    }

    /// The `secrets.<name>` keys every block use needs, at the use's own
    /// kind — the file being checked never spells them, so the use is where
    /// they can be pointed at.
    fn block_secrets(&self) -> Vec<(String, Span)> {
        let mut out = Vec::new();
        for s in &self.steps {
            let Some(block) = s.block else { continue };
            for key in &block.secrets {
                out.push((key.clone(), s.kind_span));
            }
        }
        out
    }

    /// Every step's actions against the agents' `never:` rules. A block
    /// use is judged by what the steps inside it do, so a use cannot hide
    /// an apply behind a name the policy does not know. A plain step that
    /// [`Self::enforce_step_policy`] already refuses is not reported twice.
    fn forbid_agent_actions(&mut self) {
        for i in 0..self.steps.len() {
            let what = match self.block_name(&self.steps[i]) {
                Some(block) => format!("block `{block}`"),
                None => {
                    if let Some(spec) = self.steps[i].spec {
                        let refused =
                            policy::decide(&self.policy, None, ActorKind::Agent, &spec.action())
                                .is_some_and(|d| d.disposition == Disposition::Never);
                        if refused {
                            continue;
                        }
                    }
                    format!("step `{}`", self.steps[i].name)
                }
            };
            self.forbid_actions_of(i, &what);
        }
    }

    /// The actions of step `i` against the agents' rules, named `what`: a
    /// plain step by its own name, a block use by the block's, since the use
    /// only says which block it wants.
    fn forbid_actions_of(&mut self, i: usize, what: &str) {
        for (action, origin) in self.steps[i].actions.clone() {
            let Some(env) = action.env.clone() else { continue };
            let verb = action.kind.as_str();
            if !self.policy.forbids(ActorKind::Agent, verb, &env) {
                continue;
            }
            let span = self.steps[i].kind_span;
            // The kind that does the work, so a refusal names the step
            // inside the block rather than the name the use spells.
            let d = Diagnostic::error(
                Code::PolicyForbidden,
                span,
                format!(
                    "{what} runs `{action}` ({origin}); policy forbids agents from \
                         running `{action}`"
                ),
            );
            self.push(d.with_hint(format!("the rule is `policy: agents: never: {verb} {env}`")));
        }
    }

    /// The block a step uses, when it uses one.
    fn block_name(&self, step: &StepInfo<'_>) -> Option<String> {
        step.block.map(|b| b.name.clone())
    }

    fn finish_all(mut self) -> Checked {
        self.enforce_actor_policy();
        self.enforce_step_policy();
        self.warn_unused_policy_verbs();
        // Approval gating: an approval that shows S runs before every other
        // consumer of S, except steps the approval (transitively) depends on.
        let base: Vec<Edge> = std::mem::take(&mut self.edges);
        // Consumers of each step, so an approval finds them without scanning
        // every edge (that scan made checking cubic on approval-heavy files).
        // An `after:` edge is not one: following a step reads nothing of it,
        // so an approval that shows it does not gate the follower — unless
        // something else in the file does read across the same pair.
        let read: HashSet<(&str, &str)> =
            self.read.iter().map(|(from, to)| (from.as_str(), to.as_str())).collect();
        let after_only: HashSet<(&str, &str)> = self
            .after
            .iter()
            .map(|(from, to)| (from.as_str(), to.as_str()))
            .filter(|pair| !read.contains(pair))
            .collect();
        let mut consumers: HashMap<&str, Vec<&Edge>> = HashMap::new();
        for e in &base {
            if after_only.contains(&(e.from.as_str(), e.to.as_str())) {
                continue;
            }
            consumers.entry(e.from.as_str()).or_default().push(e);
        }
        // Ancestors of each step, for `dependents_of`.
        let mut parents: HashMap<&str, Vec<&str>> = HashMap::new();
        for e in &base {
            parents.entry(e.to.as_str()).or_default().push(e.from.as_str());
        }
        let mut edges = base.clone();
        let approvals: Vec<usize> = (0..self.steps.len())
            .filter(|&i| self.steps[i].spec.is_some_and(|sp| sp.name == "approval"))
            .collect();
        for a in approvals {
            let shown: Vec<usize> =
                self.shown.iter().filter(|(x, _)| *x == a).map(|(_, t)| *t).collect();
            if shown.is_empty() {
                continue;
            }
            let gates = dependents_of(&parents, self.steps[a].name.as_str());
            let from = self.steps[a].name.clone();
            for s in shown {
                for e in consumers.get(self.steps[s].name.as_str()).into_iter().flatten() {
                    if e.to != from && !gates.contains(e.to.as_str()) {
                        edges.push(Edge { from: from.clone(), to: e.to.clone(), span: e.span });
                    }
                }
            }
        }
        // Deduplicate, keeping the first (declaration-order) span.
        let mut seen: HashSet<(String, String)> = HashSet::with_capacity(edges.len());
        edges.retain(|e| seen.insert((e.from.clone(), e.to.clone())));

        let order = match find_cycle(&self.steps, &edges) {
            Some((path, span)) => {
                self.err(Code::Cycle, span, format!("cycle: {}", path.join(" → ")));
                None
            }
            None => topo(&self.steps, &edges),
        };

        let steps = self
            .steps
            .iter()
            .map(|s| Step {
                name: s.name.clone(),
                kind: s.kind_name.clone(),
                span: s.span,
                kind_span: s.kind_span,
                ci_only: s.ci_only,
                actions: s.actions.iter().map(|(a, _)| a.clone()).collect(),
                block_inputs: s.block_inputs.clone(),
                when: s.when.clone(),
            })
            .collect();
        let edges = edges.into_iter().map(|e| (e.from, e.to)).collect();
        let workflow =
            Workflow::new(self.name, self.triggers, self.envs, steps, edges, order, self.policy);
        // Context warnings, once the workflow exists: what a step needs
        // against what a run in this context has. Collected into `diags`
        // rather than pushed, as `self` has been drained into `workflow`.
        let context_warnings: Vec<Diagnostic> = self
            .context
            .iter()
            .flat_map(|ctx| {
                unmet_steps(&workflow, self.catalog, ctx).into_iter().map(|step| {
                    Diagnostic::warning(Code::NeedsContext, step.span, step.message(ctx))
                        .with_subject(step.name.clone())
                        .with_hint(step.hint())
                })
            })
            .collect();
        // One file, one order: parser and checker findings interleaved in
        // source order, so CLI and editor output line up.
        let mut diagnostics = self.diags;
        diagnostics.extend(context_warnings);
        diagnostics.sort_by_key(|d| (d.span.start, d.span.end));
        self.secret_uses.sort_by_key(|u| u.span.start);
        Checked {
            workflow,
            diagnostics,
            types: self.types,
            secret_uses: self.secret_uses,
            policy_spans: self.policy_spans,
        }
    }
}

// --- helpers ---------------------------------------------------------------

/// Whether this file can perform `rule`'s action at all. A rule naming an
/// environment or `*` is answered by the verb — the run picks the environment,
/// not the file. A rule naming a fixed object must match whole, since only one
/// thing produces it.
fn produced_by(rule: &PolicyRule, verbs: &HashSet<&str>, objects: &HashSet<String>) -> bool {
    let fixed = matches!(rule.object.as_str(), SECRETS | SCRIPTS | BLOCKS);
    if fixed { objects.contains(&written_action(rule)) } else { verbs.contains(rule.verb.as_str()) }
}

/// A rule as the file spells it: `deploy prod`, or a bare `apply` when the
/// rule names no object.
fn written_action(rule: &PolicyRule) -> String {
    if rule.object == ANY_OBJECT {
        rule.verb.clone()
    } else {
        format!("{} {}", rule.verb, rule.object)
    }
}

fn member_error(c: &mut Ctx<'_>, ns: &str, name: &str, members: &[&str], span: Span) {
    match suggest(name, members) {
        Some(s) => c.err_hint(
            Code::UnknownRef,
            span,
            format!("unknown context value `{ns}.{name}`"),
            format!("did you mean `{ns}.{s}`?"),
        ),
        None => c.err(Code::UnknownRef, span, format!("unknown context value `{ns}.{name}`")),
    }
}

fn split_first(text: &str) -> (&str, Option<&str>) {
    match text.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (text, None),
    }
}

/// The span of the `n`th dot-separated segment of `text`, which starts at
/// `start`. Fixes rewrite the one misspelled segment — `tag` in
/// `build.tag`, not the whole reference.
fn segment_span(text: &str, start: u32, n: usize) -> Span {
    let mut at = start;
    for (i, seg) in text.split('.').enumerate() {
        if i == n {
            return Span::new(at, at + seg.len() as u32);
        }
        at += seg.len() as u32 + 1;
    }
    Span::new(start, start) // a name without that segment: nothing to rewrite
}

/// A type without its `Optional` wrapper, so `git.tag?` compares against
/// `String`.
fn bare_optional(t: &Type) -> &Type {
    match t {
        Type::Optional(inner) => inner,
        other => other,
    }
}

/// Interpolation composes strings; only string-valued inputs take it.
fn interp_allowed(want: &Type) -> bool {
    match want {
        Type::String | Type::Any => true,
        Type::Named(n) => n == "oci.Tag",
        Type::Optional(inner) => interp_allowed(inner),
        _ => false,
    }
}

/// Why a `Secret` cannot flow where `want` is declared: only an input typed
/// `Secret` takes one ([#27](https://github.com/Keep-Shipping/harness/issues/27)).
fn secret_hint(want: &Type, got: &Type) -> Option<String> {
    (matches!(got, Type::Secret) && !matches!(want, Type::Secret | Type::Any))
        .then(|| "secrets flow only into inputs typed Secret".to_string())
}

/// The environment a step's `when: env is <name>` binds it to: the one
/// environment the step runs in, which is what an action acts on for policy.
/// `None` for every other `when:`, and for a step that names no environment.
pub(crate) fn env_gate(step: Entry<'_>) -> Option<String> {
    let e = step.children().find(|c| c.key_name() == Some("when"))?.expr()?;
    match context_test(&e)? {
        ContextTest::EnvIs { env } => Some(env),
        _ => None,
    }
}

/// The `secrets.<name>` keys one step's own children read, sorted and
/// distinct — what a block's signature carries so a use is judged against
/// what the block needs.
pub(crate) fn secret_keys(step: Entry<'_>) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let exprs = step.expr().into_iter().chain(step.children().filter_map(|c| c.expr()));
    for e in exprs {
        for e in e.refs() {
            if e.kind == ks_lang::NameKind::Dotted
                && let Some(name) = e.text.strip_prefix("secrets.")
            {
                keys.insert(name.to_string());
            }
        }
    }
    keys
}

/// `key: annotation = literal`: an inline type annotation with a default.
/// Yields the annotation word (for its span), the type it spells and the
/// default; `None` when the left side is no word that spells a type.
pub(crate) fn annotation_default<'a>(
    e: &'a Expr<'a>,
) -> Option<(&'a Word<'a>, Type, &'a Expr<'a>)> {
    let Expr::Default { lhs, rhs, .. } = e else { return None };
    let Expr::Atom { atom: Atom::Word(w), .. } = lhs.as_ref() else { return None };
    Type::parse(w.text()).map(|ty| (w, ty, rhs.as_ref()))
}

/// `an oci.Digest`, `a tofu.PlanFile`.
fn article(name: &str) -> &'static str {
    match name.as_bytes().first() {
        Some(b'a' | b'e' | b'i' | b'o' | b'u') => "an",
        _ => "a",
    }
}

/// The answer words of a `returns:` value: `low | medium | high` or one word.
fn union_words(e: &Expr<'_>) -> Vec<String> {
    match e {
        Expr::Union { alts, .. } => alts.iter().filter_map(value_word).collect(),
        other => value_word(other).into_iter().collect(),
    }
}

fn value_word(e: &Expr<'_>) -> Option<String> {
    match e {
        Expr::Atom { atom: Atom::Word(w), .. } => Some(w.text().to_string()),
        _ => None,
    }
}

/// The text a value spells: a bare word, or a quoted string unquoted. Every
/// other shape spells no single value, so it has no text.
pub(crate) fn value_text(e: &Expr<'_>) -> Option<String> {
    match e {
        Expr::Atom { atom: Atom::Word(w), .. } => Some(w.text().to_string()),
        Expr::Atom { atom: Atom::Str(s), .. } => Some(s.value()),
        _ => None,
    }
}

/// What a use passes a block, with the signature's defaults filled in: what
/// the run will get, whether the file spelled it or the block declared it.
/// Only declared inputs appear, so a use's typo is not an input.
fn block_input_values(step: Entry<'_>, sig: &BlockSignature) -> BTreeMap<String, String> {
    let given: BTreeMap<&str, String> = step
        .children()
        .filter(|c| !STEP_PROPERTIES.contains(&c.key_name().unwrap_or_default()))
        .filter_map(|c| {
            let name = c.key_name()?;
            let expr = c.expr()?;
            Some((name, value_text(&expr)?))
        })
        .collect();
    sig.inputs
        .iter()
        .filter_map(|i| {
            let value = given.get(i.name.as_str()).or(i.default.as_ref())?;
            Some((i.name.clone(), value.clone()))
        })
        .collect()
}

/// A step's literal input value, when it has one: `dir: ./infra/prod`.
fn literal_input(step: Entry<'_>, name: &str) -> Option<String> {
    step.children()
        .find(|c| c.key_name() == Some(name))
        .and_then(|c| c.expr())
        .as_ref()
        .and_then(value_word)
}

/// The step an apply step's `plan:` applies: `plan: plan.file` names `plan`.
fn plan_step(step: Entry<'_>) -> Option<String> {
    let ref_ = literal_input(step, "plan")?;
    let (name, output) = split_first(&ref_);
    (output == Some("file") && name != ref_).then(|| name.to_string())
}

/// An apply step's `outputs:` mapping, name to type. Any other kind has none:
/// `outputs` there means what the catalog says it means.
fn outputs_mapping(step: Entry<'_>, spec: Option<&StepTypes>) -> Vec<(String, Option<Type>)> {
    if !spec.is_some_and(|sp| APPLY_KINDS.contains(&sp.name.as_str())) {
        return Vec::new();
    }
    step.children().find(|c| c.key_name() == Some("outputs")).map(parse_outputs).unwrap_or_default()
}

/// One `outputs:` mapping, read the way it was written. A type that does not
/// parse is kept as `None` and reported in the second pass, so a mapping is
/// never silently ignored.
fn parse_outputs(entry: Entry<'_>) -> Vec<(String, Option<Type>)> {
    entry
        .children()
        .filter_map(|c| {
            let name = c.key_name()?.to_string();
            let ty = c.expr().as_ref().and_then(value_word).and_then(|t| Type::parse(&t));
            Some((name, ty))
        })
        .collect()
}

fn subject_word<'a>(e: &'a Expr<'a>) -> Option<Word<'a>> {
    match e {
        Expr::Atom { atom: Atom::Word(w), .. } => Some(*w),
        _ => None,
    }
}

fn answer_word<'a>(e: &'a Expr<'a>) -> Option<Word<'a>> {
    subject_word(e).filter(|w| w.scalar() == ks_lang::Scalar::Ident)
}

/// The file an expression was written in; every expression carries it.
fn expr_src<'a>(e: &'a Expr<'a>) -> &'a str {
    match e {
        Expr::Atom { src, .. } => src,
        Expr::Default { src, .. }
        | Expr::Tuple { src, .. }
        | Expr::Or { src, .. }
        | Expr::And { src, .. }
        | Expr::Not { src, .. }
        | Expr::Compare { src, .. }
        | Expr::IsTest { src, .. }
        | Expr::Union { src, .. }
        | Expr::Phrase { src, .. } => src,
    }
}

/// One element of an `after:` value.
enum AfterItem {
    /// A step name, and where it was written.
    Name(String, Span),
    /// Something that is not a step name, and where it was written.
    NotAName(Span),
}

/// The step names an `after:` value lists: one name, or a comma-separated
/// tuple of them, written bare or quoted. Anything else is reported.
fn after_names(e: &Expr<'_>) -> Vec<AfterItem> {
    let name = |e: &Expr<'_>| match e {
        Expr::Atom { atom: Atom::Word(w), .. } if w.scalar() == ks_lang::Scalar::Ident => {
            AfterItem::Name(w.text().to_string(), w.node.span())
        }
        Expr::Atom { atom: Atom::Str(s), .. } => AfterItem::Name(s.value(), s.node.span()),
        _ => AfterItem::NotAName(e.span()),
    };
    match e {
        Expr::Atom { .. } => vec![name(e)],
        Expr::Tuple { items, .. } => items.iter().map(name).collect(),
        other => vec![AfterItem::NotAName(other.span())],
    }
}

/// A context-only `when:` in a form the planner can settle before the run
/// starts: a boolean literal, or the environment test the language spells
/// (`env is prod`), under `not` as often as not. Anything else — a `when:`
/// reading step outputs above all — is left to the run, never guessed.
fn context_test(e: &Expr<'_>) -> Option<ContextTest> {
    if let Some(w) = subject_word(e) {
        return match w.text() {
            "true" => Some(ContextTest::Bool(true)),
            "false" => Some(ContextTest::Bool(false)),
            _ => None,
        };
    }
    match e {
        Expr::Not { arg, .. } => context_test(arg).map(|t| ContextTest::Not(Box::new(t))),
        Expr::IsTest { subject, answer, threshold: None, .. } => {
            let env = subject_word(subject)?;
            if env.scalar() != ks_lang::Scalar::Ident || env.text() != "env" {
                return None;
            }
            Some(ContextTest::EnvIs { env: answer_word(answer)?.text().to_string() })
        }
        _ => None,
    }
}

fn tuple_items(e: Expr<'_>) -> Vec<Expr<'_>> {
    match e {
        Expr::Tuple { items, .. } => items,
        other => vec![other],
    }
}

/// A did-you-mean is only worth so much: on a machine-generated file with
/// thousands of steps, scanning every name for every unknown reference costs
/// O(steps × references). Past this pool size, errors go out without a hint.
const MAX_SUGGEST_CANDIDATES: usize = 512;

/// The closest candidate within a small threshold, if any.
pub(crate) fn suggest<S: AsRef<str>>(name: &str, candidates: &[S]) -> Option<String> {
    suggestion(name, candidates).map(|(best, _)| best)
}

/// [`suggest`]'s name together with whether it is unambiguous — nothing else
/// ties it. One pass, so the hint a person reads and the fix `--fix` applies
/// can never name different candidates: a tie is shown but not applied.
pub(crate) fn suggestion<S: AsRef<str>>(name: &str, candidates: &[S]) -> Option<(String, bool)> {
    let (best, second) = closest(name, candidates)?;
    Some((best.1.to_string(), second.is_none_or(|(sd, _)| sd > best.0)))
}

/// A candidate within the threshold, with its distance: `(distance, name)`.
type Ranked<'c> = (usize, &'c str);

/// The nearest candidate within the threshold and the runner-up, if any.
/// Ties keep the earlier candidate, exactly as `min_by_key` did.
fn closest<'c, S: AsRef<str>>(
    name: &str,
    candidates: &'c [S],
) -> Option<(Ranked<'c>, Option<Ranked<'c>>)> {
    if candidates.len() > MAX_SUGGEST_CANDIDATES {
        return None;
    }
    let limit = if name.len() < 4 { 1 } else { 2 };
    let mut best: Option<(usize, &str)> = None;
    let mut second: Option<(usize, &str)> = None;
    for c in candidates {
        // A length difference alone already exceeds the threshold.
        if c.as_ref().len().abs_diff(name.len()) > limit {
            continue;
        }
        let d = bounded_levenshtein(name, c.as_ref(), limit);
        if d > limit {
            continue;
        }
        let c = c.as_ref();
        match best {
            // No nearer than what we hold, so it can only be the runner-up.
            Some((bd, _)) if bd <= d => {
                if second.is_none_or(|(sd, _)| d < sd) {
                    second = Some((d, c));
                }
            }
            _ => {
                second = best;
                best = Some((d, c));
            }
        }
    }
    best.map(|b| (b, second))
}

/// Edit distance on bytes, two-row DP, abandoned as soon as a row proves the
/// distance exceeds `limit` (returns `limit + 1`). Bytes, not chars: names
/// reaching a suggestion are idents, and idents are ASCII.
fn bounded_levenshtein(a: &str, b: &str, limit: usize) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        let mut row_min = cur[0];
        for (j, cb) in b.iter().enumerate() {
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + usize::from(ca != cb));
            row_min = row_min.min(cur[j + 1]);
        }
        if row_min > limit {
            return limit + 1;
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Everything that can reach `start` following edges forward: the steps an
/// approval at `start` (transitively) depends on. `parents` maps each step
/// to the names of the steps with an edge into it.
fn dependents_of<'a>(parents: &HashMap<&'a str, Vec<&'a str>>, start: &'a str) -> HashSet<&'a str> {
    let mut seen: HashSet<&'a str> = HashSet::new();
    let mut queue: Vec<&'a str> = vec![start];
    while let Some(n) = queue.pop() {
        for &from in parents.get(n).into_iter().flatten() {
            if seen.insert(from) {
                queue.push(from);
            }
        }
    }
    seen
}

/// A cycle in the edge order, reported as the path (`a → b → a`) and the
/// span of the reference that closes it.
fn find_cycle(steps: &[StepInfo<'_>], edges: &[Edge]) -> Option<(Vec<String>, Span)> {
    let index: HashMap<&str, usize> =
        steps.iter().enumerate().map(|(i, s)| (s.name.as_str(), i)).collect();
    let n = steps.len();
    let mut adj: Vec<Vec<(usize, Span)>> = vec![Vec::new(); n];
    for e in edges {
        // Edges arrive deduplicated, so no (from, to) pair repeats here.
        if let (Some(&a), Some(&b)) = (index.get(e.from.as_str()), index.get(e.to.as_str())) {
            adj[a].push((b, e.span));
        }
    }
    let mut state = vec![0u8; n]; // 0 new, 1 on the stack, 2 done
    let mut stack: Vec<usize> = Vec::new();
    for root in 0..n {
        if state[root] != 0 {
            continue;
        }
        stack.push(root);
        let Some(span) = dfs(&adj, &mut state, &mut stack) else { continue };
        let repeat = *stack.last().expect("the closing node was pushed");
        let start = stack.iter().position(|&i| i == repeat).expect("repeat is on the stack");
        // The stack ends with the back edge's target again; the cycle is
        // everything from its first occurrence, closed by naming it once
        // (`c → c`, not `c → c → c`).
        let mut path: Vec<String> =
            stack[start..stack.len() - 1].iter().map(|&i| steps[i].name.clone()).collect();
        path.push(steps[repeat].name.clone());
        return Some((path, span));
    }
    None
}

/// Iterative DFS from the node already on top of `stack`; returns the span
/// of the back edge when it closes a cycle (the full path left on `stack`).
fn dfs(adj: &[Vec<(usize, Span)>], state: &mut [u8], stack: &mut Vec<usize>) -> Option<Span> {
    while let Some(&node) = stack.last() {
        if state[node] == 0 {
            state[node] = 1;
        }
        let mut descended = false;
        for &(next, span) in &adj[node] {
            match state[next] {
                1 => {
                    stack.push(next);
                    return Some(span);
                }
                0 => {
                    stack.push(next);
                    descended = true;
                    break;
                }
                _ => {}
            }
        }
        if !descended {
            stack.pop();
            state[node] = 2;
        }
    }
    None
}

fn topo(steps: &[StepInfo<'_>], edges: &[Edge]) -> Option<Vec<String>> {
    let index: HashMap<&str, usize> =
        steps.iter().enumerate().map(|(i, s)| (s.name.as_str(), i)).collect();
    let n = steps.len();
    let mut indeg = vec![0usize; n];
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    for e in edges {
        // Edges arrive deduplicated, so no (from, to) pair repeats here.
        if let (Some(&a), Some(&b)) = (index.get(e.from.as_str()), index.get(e.to.as_str())) {
            adj[a].push(b);
            indeg[b] += 1;
        }
    }
    // A min-heap of declaration indices: always the earliest declared ready
    // step next, without resorting the whole ready list each round.
    let mut order = Vec::with_capacity(n);
    let mut ready: BinaryHeap<Reverse<usize>> =
        (0..n).filter(|&i| indeg[i] == 0).map(Reverse).collect();
    while let Some(Reverse(i)) = ready.pop() {
        order.push(i);
        for &next in &adj[i] {
            indeg[next] -= 1;
            if indeg[next] == 0 {
                ready.push(Reverse(next));
            }
        }
    }
    (order.len() == n).then(|| order.into_iter().map(|i| steps[i].name.clone()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_src(src: &str) -> Checked {
        check(&ks_lang::parse(src))
    }

    const TWO_ENVS: &str = "\
envs:
  staging:
    secrets: vault
  prod:
    secrets: env
    ci-only: true
steps:
  migrate: db.migrate
    url: secrets.db_url
  report: db.report
    url: secrets.db_url
    key: secrets.api_key
";

    /// The listing is pure: it reads the checked file only, so this helper's
    /// whole path — parse, check, project — never constructs a resolver or
    /// reads a store.
    #[test]
    fn secret_requirements_list_each_environments_references() {
        let checked = check_src(TWO_ENVS);
        assert!(checked.diagnostics.is_empty(), "{:#?}", checked.diagnostics);
        let listing = secret_requirements(&checked);
        assert_eq!(listing.len(), 2, "one entry per declared environment");
        assert_eq!(listing[0].env, "staging");
        assert_eq!(listing[0].resolver.as_deref(), Some("vault"));
        assert_eq!(listing[1].env, "prod");
        assert_eq!(listing[1].resolver.as_deref(), Some("env"));

        let staging = &listing[0].requirements;
        assert_eq!(staging.len(), 2, "deduplicated: db_url is named twice");
        assert_eq!(staging[0].key, "db_url");
        assert_eq!(
            staging[0].reference.as_ref().map(ToString::to_string).as_deref(),
            Some("vault:db_url")
        );
        assert_eq!(staging[0].steps, ["migrate", "report"]);
        assert_eq!(staging[1].key, "api_key", "keys stay in first-use order");
        assert_eq!(staging[1].steps, ["report"]);

        // The same keys, resolved against the other environment's resolver.
        let prod = &listing[1].requirements;
        assert_eq!(
            prod[0].reference.as_ref().map(ToString::to_string).as_deref(),
            Some("env:db_url")
        );
    }

    #[test]
    fn an_environment_without_a_resolver_needs_one_explicitly() {
        let checked = check_src(&TWO_ENVS.replace("    secrets: vault\n", ""));
        let listing = secret_requirements(&checked);
        assert_eq!(listing[0].resolver, None);
        assert_eq!(listing[0].requirements[0].reference, None, "no resolver, no reference");
        assert_eq!(listing[0].requirements[0].key, "db_url");
    }

    #[test]
    fn a_file_without_envs_or_secrets_lists_the_default_as_none() {
        let checked = check_src("steps:\n  build: oci.image\n    from: ./Dockerfile\n");
        let listing = secret_requirements(&checked);
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].env, "default");
        assert!(listing[0].requirements.is_empty());
    }

    #[test]
    fn secret_uses_carry_the_span_and_the_consuming_step() {
        let checked = check_src(TWO_ENVS);
        assert_eq!(
            checked.secret_uses.len(),
            3,
            "every reference, deduplication is the listing's job"
        );
        let first = &checked.secret_uses[0];
        assert_eq!(first.key, "db_url");
        assert_eq!(first.step, "migrate");
        assert!(first.span.start < checked.secret_uses[1].span.start, "source order");
    }
}
