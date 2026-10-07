//! The checker: turns a parsed file into a [`Workflow`], reporting every
//! reference, type and declaration problem it finds — never just the first.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use ks_lang::{Atom, Code, Diagnostic, Entry, Expr, Fix, Span, StrPart, Word};

use crate::catalog::{Catalog, StepTypes};
use crate::format::{self, Formats, Header};
use crate::ports::run_context::ActorKind;
use crate::ports::secrets::SecretRef;
use crate::types::{self, LiteralFit, Type};
use crate::workflow::{
    Env, NeverRule, Policy, Step, Trigger, TriggerKind, Workflow, implicit_default,
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
    /// Whether this check is in CI, which the caller knows and the file
    /// cannot. Advisory only: it widens the warnings, never what is
    /// enforced.
    pub(crate) in_ci: bool,
}

impl<'a> CheckOptions<'a> {
    /// Checks against `catalog` instead of the built-in one.
    pub fn new(catalog: &'a Catalog) -> CheckOptions<'a> {
        CheckOptions { catalog, formats: &format::BUILTIN, actor: None, in_ci: false }
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
}

/// Type-check `parse` and build its [`Workflow`], against `options`.
pub fn check_with(parse: &ks_lang::Parse, options: &CheckOptions<'_>) -> Checked {
    let mut c = Ctx::new(
        options.catalog,
        options.formats,
        options.actor,
        options.in_ci,
        parse.diagnostics().to_vec(),
    );
    c.file(parse.file());
    c.finish_all()
}

/// Context namespaces a reference's first segment may name. `env` is also
/// the `is` subject of `when: env is prod`.
const NAMESPACES: [&str; 6] = ["git", "pr", "run", "env", "ci", "secrets"];

const POLICY_VERBS: [&str; 9] =
    ["check", "build", "test", "plan", "apply", "deploy", "destroy", "publish", "read"];

const TRIGGER_KINDS: [&str; 5] = ["push", "pr", "tag", "manual", "schedule"];

const ENV_PROPERTIES: [&str; 5] = ["secrets", "ci-only", "approvers", "on", "vars"];

struct Ctx<'a> {
    catalog: &'a Catalog,
    /// The file formats this build reads, and what each is called.
    formats: &'a Formats<'a>,
    /// The actor the run would start under, when the caller knows it; policy
    /// rules that bind it are enforced.
    actor: Option<ActorKind>,
    /// That the caller is running in CI, which widens advisory warnings
    /// only and never what is enforced.
    in_ci: bool,
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

struct StepInfo<'a> {
    name: String,
    span: Span,
    kind_name: Option<String>,
    kind_span: Span,
    spec: Option<&'a StepTypes>,
    /// `decide` only: the answers declared under `returns:`.
    variants: Vec<String>,
}

/// `from` must run before `to`; `span` is the reference that asked for it.
#[derive(Clone)]
struct Edge {
    from: String,
    to: String,
    span: Span,
}

impl<'a> Ctx<'a> {
    fn new(
        catalog: &'a Catalog,
        formats: &'a Formats<'a>,
        actor: Option<ActorKind>,
        in_ci: bool,
        diags: Vec<Diagnostic>,
    ) -> Ctx<'a> {
        Ctx {
            catalog,
            formats,
            actor,
            in_ci,
            diags,
            subject: None,
            env_names: Vec::new(),
            env_vars: Vec::new(),
            steps: Vec::new(),
            index: HashMap::new(),
            edges: Vec::new(),
            policy_spans: Vec::new(),
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
        // First pass: declare the steps and environments, so a reference
        // resolves no matter where in the file its target sits.
        for e in file.entries() {
            match e.key_name() {
                Some("steps") => self.declare_steps(e),
                Some("envs") => self.declare_envs(e),
                _ => {}
            }
        }
        // Second pass: check everything.
        let mut saw_envs = false;
        for e in file.entries() {
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
            let spec = kind_name.as_deref().and_then(|n| self.catalog.step(n));
            let variants = match spec.filter(|sp| sp.decision) {
                Some(_) => s
                    .children()
                    .find(|c| c.key_name() == Some("returns"))
                    .and_then(|r| r.expr())
                    .map(|e| union_words(&e))
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            self.steps.push(StepInfo {
                name: name.into(),
                span,
                kind_name,
                kind_span,
                spec,
                variants,
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
                self.subject = Some(format!("{}.{}", self.steps[idx].name, iname));
                self.check_input(idx, iname, input);
                self.subject = None;
            }
        }
    }

    fn check_input(&mut self, idx: usize, iname: &str, input: Entry<'_>) {
        let Some(e) = input.expr() else { return }; // missing values: parse error
        let Some(spec) = self.steps[idx].spec else {
            self.ty_of(idx, &e); // unknown kind: inputs unchecked, refs resolve
            return;
        };
        let Some(ty) = spec.input(iname) else {
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
            return;
        };
        match iname {
            "show" => self.check_refs(idx, &e),
            "else" => self.check_actions(idx, &e),
            "returns" => {} // variants were collected with the declarations
            _ => self.demand_input(idx, ty, &e),
        }
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
        if w.scalar() == ks_lang::Scalar::DottedName {
            let Some((target, got)) = self.resolve_ref(idx, w.text(), span) else { return };
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
                    self.edge(idx, i, span);
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
        if let Some((_, ty)) = self.resolve_ref(idx, name, span) {
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

    /// The referenced step must run before the referencing one.
    fn edge(&mut self, cur: usize, target: usize, span: Span) {
        self.edges.push(Edge {
            from: self.steps[target].name.clone(),
            to: self.steps[cur].name.clone(),
            span,
        });
    }

    fn bare_step_type(&self, idx: usize) -> Type {
        match self.steps[idx].spec.filter(|sp| sp.decision) {
            Some(_) => Type::Decision(self.steps[idx].variants.clone()),
            None => Type::Any,
        }
    }

    /// Resolve a dotted or interpolated name that must be a reference.
    /// Returns the step it names (when not a context value) and its type.
    fn resolve_ref(&mut self, cur: usize, text: &str, span: Span) -> Option<(Option<usize>, Type)> {
        let (first, rest) = split_first(text);
        if let Some(i) = self.step_index(first) {
            self.edge(cur, i, span);
            return Some((Some(i), self.step_ref(i, rest, span)));
        }
        if let Some(t) = self.context(first, rest, span) {
            // A secret reference is a requirement the run carries, wherever
            // it appears — record it for the per-environment listing and the
            // policy check.
            if first == "secrets"
                && let Some(name) = rest
            {
                self.secret_uses.push(SecretUse {
                    key: name.to_string(),
                    span,
                    step: self.steps[cur].name.clone(),
                });
            }
            return Some((None, t));
        }
        let mut cands: Vec<&str> = self.steps.iter().map(|s| s.name.as_str()).collect();
        cands.extend_from_slice(&NAMESPACES);
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
        None
    }

    /// A dotted name in a String/untyped position: a reference only when its
    /// first segment names a step or a context namespace.
    fn soft_ref(&mut self, cur: usize, text: &str, span: Span) -> Option<Type> {
        let (first, _) = split_first(text);
        if self.step_index(first).is_some() || NAMESPACES.contains(&first) {
            return self.resolve_ref(cur, text, span).map(|(_, t)| t);
        }
        None
    }

    fn step_ref(&mut self, i: usize, rest: Option<&str>, span: Span) -> Type {
        let Some(rest) = rest else { return self.bare_step_type(i) };
        let (out, more) = split_first(rest);
        if out == "out" {
            return Type::Any; // run-time output: the name is not verified
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

    fn context(&mut self, ns: &str, rest: Option<&str>, span: Span) -> Option<Type> {
        let Some(rest) = rest else { return Some(Type::Any) }; // a bare namespace
        let (name, _more) = split_first(rest);
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
                    if let Some((target, ty)) = self.resolve_ref(idx, w.text(), span) {
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
                    "ci-only" => match p.expr().as_ref().and_then(value_word).as_deref() {
                        Some("true") => env.ci_only = true,
                        Some("false") => {}
                        _ => self.err_hint(
                            Code::EnvProblem,
                            p.key_span(),
                            "`ci-only` takes `true` or `false`",
                            "`ci-only: true`",
                        ),
                    },
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

    fn check_policy(&mut self, policy: Entry<'_>) {
        for actor in policy.children() {
            let kind = match actor.key_name() {
                Some("agents") => Some(ActorKind::Agent),
                Some("humans") => Some(ActorKind::Human),
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
                    // `never:` rules are retained on the workflow; `can:`
                    // and `before:` grant and gate, they never forbid.
                    "never" => self.actions(p, kind),
                    "can" | "before" => self.actions(p, None),
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

    /// `can`/`before`/`never`: tuples of `<verb> [<env>]` (`read secrets`).
    /// `subject` is the actor the rule binds — `Some` only for `never:`,
    /// whose rules are retained on the workflow for enforcement.
    fn actions(&mut self, entry: Entry<'_>, subject: Option<ActorKind>) {
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
            if text == "read" {
                match atoms.get(1) {
                    Some(Atom::Word(obj)) if obj.text() == "secrets" => {
                        self.forbid(subject, text, "secrets", item.span());
                    }
                    Some(a) => self.err(Code::PolicyAction, a.span(), "`read` takes `secrets`"),
                    None => self.err_hint(
                        Code::PolicyAction,
                        verb.node.span(),
                        "`read` takes `secrets`",
                        "`read secrets`",
                    ),
                }
                continue;
            }
            let Some(Atom::Word(env)) = atoms.get(1) else { continue };
            let name = env.text();
            self.forbid(subject, text, name, item.span());
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

    /// Retains a `never:` rule when the entry declares one for a subject.
    fn forbid(&mut self, subject: Option<ActorKind>, verb: &str, object: &str, span: Span) {
        if let Some(subject) = subject {
            self.policy.forbid(NeverRule {
                subject,
                verb: verb.to_string(),
                object: object.to_string(),
                span,
            });
        }
    }

    /// A policy check that binds the run's actor: when an agent runs a file
    /// whose policy forbids agents to read secrets, every distinct secret
    /// the run needs is refused once, at its first reference, so the run
    /// stops before it starts.
    fn enforce_actor_policy(&mut self) {
        if self.actor != Some(ActorKind::Agent)
            || !self.policy.forbids(ActorKind::Agent, "read", "secrets")
        {
            return;
        }
        // One refusal per distinct key, at its first reference span. The
        // keys are collected owned so the loop below can borrow `self`
        // mutably without cloning `secret_uses`.
        let mut seen: HashSet<&str> = HashSet::new();
        let firsts: Vec<(String, Span)> = self
            .secret_uses
            .iter()
            .filter(|u| seen.insert(u.key.as_str()))
            .map(|u| (u.key.clone(), u.span))
            .collect();
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

    fn finish_all(mut self) -> Checked {
        self.enforce_actor_policy();
        // Approval gating: an approval that shows S runs before every other
        // consumer of S, except steps the approval (transitively) depends on.
        let base: Vec<Edge> = std::mem::take(&mut self.edges);
        // Consumers of each step, so an approval finds them without scanning
        // every edge (that scan made checking cubic on approval-heavy files).
        let mut consumers: HashMap<&str, Vec<&Edge>> = HashMap::new();
        for e in &base {
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
            })
            .collect();
        let edges = edges.into_iter().map(|e| (e.from, e.to)).collect();
        let workflow =
            Workflow::new(self.name, self.triggers, self.envs, steps, edges, order, self.policy);
        // One file, one order: parser and checker findings interleaved in
        // source order, so CLI and editor output line up.
        let mut diagnostics = self.diags;
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

/// `key: annotation = literal`: an inline type annotation with a default.
/// Yields the annotation word (for its span), the type it spells and the
/// default; `None` when the left side is no word that spells a type.
fn annotation_default<'a>(e: &'a Expr<'a>) -> Option<(&'a Word<'a>, Type, &'a Expr<'a>)> {
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

fn subject_word<'a>(e: &'a Expr<'a>) -> Option<Word<'a>> {
    match e {
        Expr::Atom { atom: Atom::Word(w), .. } => Some(*w),
        _ => None,
    }
}

fn answer_word<'a>(e: &'a Expr<'a>) -> Option<Word<'a>> {
    subject_word(e).filter(|w| w.scalar() == ks_lang::Scalar::Ident)
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
