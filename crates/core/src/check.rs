//! The checker: turns a parsed file into a [`Workflow`], reporting every
//! reference, type and declaration problem it finds — never just the first.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use ks_lang::{Atom, Diagnostic, Entry, Expr, Span, StrPart, Word};

use crate::catalog::{self, StepSpec, Ty};
use crate::types::Type;
use crate::workflow::{Env, Step, Trigger, TriggerKind, Workflow, implicit_default};

/// A checked file: the workflow it declares plus every diagnostic, parser
/// and checker findings alike, sorted into source order.
pub struct Checked {
    pub workflow: Workflow,
    pub diagnostics: Vec<Diagnostic>,
}

/// Type-check `parse` and build its [`Workflow`].
pub fn check(parse: &ks_lang::Parse) -> Checked {
    let mut c = Ctx { diags: parse.diagnostics().to_vec(), ..Ctx::default() };
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

#[derive(Default)]
struct Ctx {
    diags: Vec<Diagnostic>,
    env_names: Vec<String>,
    env_vars: Vec<String>,
    steps: Vec<StepInfo>,
    /// `steps` names to indices, so a reference resolves in O(1); a linear
    /// scan made checking quadratic on files with many steps.
    index: HashMap<String, usize>,
    edges: Vec<Edge>,
    shown: Vec<(usize, usize)>, // (approval step, step it shows)
    name: Option<String>,
    triggers: Vec<Trigger>,
    envs: Vec<Env>,
}

struct StepInfo {
    name: String,
    span: Span,
    kind_name: Option<String>,
    kind_span: Span,
    spec: Option<&'static StepSpec>,
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

impl Ctx {
    fn err(&mut self, span: Span, message: impl Into<String>) {
        self.diags.push(Diagnostic::error(span, message));
    }

    fn err_hint(&mut self, span: Span, message: impl Into<String>, hint: impl Into<String>) {
        self.diags.push(Diagnostic::error(span, message).with_hint(hint));
    }

    fn file(&mut self, file: ks_lang::File<'_>) {
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
                Some("on") => self.triggers = self.triggers_of(e),
                Some("steps") => self.check_steps(e),
                Some("envs") => {
                    self.envs = self.check_envs(e);
                    saw_envs = true;
                }
                Some("policy") => self.check_policy(e),
                _ => {} // other top-level keys carry no meaning here yet
            }
        }
        if !saw_envs {
            self.envs.push(implicit_default());
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
                    span,
                    format!("step `{name}` is named like a context namespace"),
                    format!("rename the step; `{name}` is a reserved context name"),
                );
                continue;
            }
            if self.step_index(name).is_some() {
                self.err(span, format!("duplicate step `{name}`"));
                continue;
            }
            let (kind_name, kind_span) = match s.expr() {
                Some(Expr::Atom { atom: Atom::Word(w), .. }) => {
                    (Some(w.text().to_string()), w.node.span())
                }
                _ => (None, span),
            };
            let spec = kind_name.as_deref().and_then(catalog::find);
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
            let Some(name) = s.key_name().and_then(|n| self.step_index(n)) else { continue };
            for input in s.children() {
                let Some(iname) = input.key_name() else { continue };
                self.check_input(name, iname, input);
            }
        }
    }

    fn check_input(&mut self, idx: usize, iname: &str, input: Entry<'_>) {
        let Some(e) = input.expr() else { return }; // missing values: parse error
        let Some(spec) = self.steps[idx].spec else {
            self.ty_of(idx, &e); // unknown kind: inputs unchecked, refs resolve
            return;
        };
        let Some(ty) = catalog::input(spec, iname) else {
            let span = input.key_span();
            let msg = format!("unknown input `{iname}` for step kind `{}`", spec.name);
            match suggest(iname, &catalog::input_names(spec)) {
                Some(s) => self.err_hint(span, msg, format!("did you mean `{s}`?")),
                None => self.err(span, msg),
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
    fn demand_input(&mut self, idx: usize, ty: Ty, e: &Expr<'_>) {
        // Strings report their own interpolations once (`str_typed`); for
        // every other shape this reference walk is the only check.
        if !interp_allowed(ty) && !matches!(e, Expr::Atom { atom: Atom::Str(_), .. }) {
            for r in e.refs() {
                if r.kind == ks_lang::NameKind::Interp {
                    self.err_hint(
                        r.span,
                        format!("interpolation is not allowed in a `{}` value", ty.to_type()),
                        "interpolate only into string values",
                    );
                }
            }
        }
        match e {
            Expr::Atom { atom: Atom::Word(w), .. } => self.word_typed(idx, w, ty),
            Expr::Atom { atom: Atom::Str(s), .. } => {
                let got = self.str_typed(idx, s, ty);
                self.demand(e.span(), ty, got, None);
            }
            Expr::Atom { atom: Atom::Paren { inner: Some(inner), .. }, .. } => {
                self.demand_input(idx, ty, inner)
            }
            other => {
                let got = self.ty_of(idx, other);
                self.demand(other.span(), ty, got, None);
            }
        }
    }

    /// A bare word in a typed input position.
    fn word_typed(&mut self, idx: usize, w: &Word<'_>, ty: Ty) {
        let span = w.node.span();
        if w.scalar() == ks_lang::Scalar::DottedName {
            let Some((target, got)) = self.resolve_ref(idx, w.text(), span) else { return };
            let want = ty.to_type();
            let hint = match target {
                Some(t) if !accepts(&want, &got) => self.steps[t]
                    .spec
                    .and_then(|sp| catalog::alt_output(sp, &want))
                    .map(|alt| format!("did you mean `{}.{alt}`?", self.steps[t].name)),
                _ => None,
            };
            self.demand(span, ty, got, hint);
        } else {
            let got = self.word_untyped(idx, w);
            // A word in a `push:` position is itself the tag literal.
            let got = if ty == Ty::Named("oci.Tag") && got == Type::String {
                Type::Named("oci.Tag")
            } else {
                got
            };
            self.demand(span, ty, got, None);
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
        if let Some((_, ty)) = self.resolve_ref(idx, name, span)
            && ty == Type::Secret
        {
            self.err_hint(
                span,
                format!("secret `{name}` cannot be interpolated into a string"),
                "pass it to an input that takes a secret; secrets never go into strings or logs",
            );
        }
    }

    /// A quoted string; interpolations resolve as everywhere else.
    fn str_typed(&mut self, idx: usize, s: &ks_lang::Str<'_>, ty: Ty) -> Type {
        for part in s.parts() {
            if let StrPart::Interp(i) = part
                && let Some(name) = i.name()
            {
                let span = i.name_span().unwrap_or_else(|| i.node.span());
                if !interp_allowed(ty) {
                    self.err_hint(
                        span,
                        format!("interpolation is not allowed in a `{}` value", ty.to_type()),
                        "interpolate only into string values",
                    );
                } else {
                    self.interp(idx, name, span);
                }
            }
        }
        if ty == Ty::Named("oci.Tag") { Type::Named("oci.Tag") } else { Type::String }
    }

    fn demand(&mut self, span: Span, ty: Ty, got: Type, hint: Option<String>) {
        let want = ty.to_type();
        if accepts(&want, &got) {
            return;
        }
        match hint {
            Some(h) => self.err_hint(span, format!("expected `{want}`, got `{got}`"), h),
            None => self.err(span, format!("expected `{want}`, got `{got}`")),
        }
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
            return Some((None, t));
        }
        let mut cands: Vec<&str> = self.steps.iter().map(|s| s.name.as_str()).collect();
        cands.extend_from_slice(&NAMESPACES);
        let msg = format!("unknown step or context value `{first}`");
        match suggest(first, &cands) {
            Some(s) => self.err_hint(span, msg, format!("did you mean `{s}`?")),
            None => self.err(span, msg),
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
        match spec.and_then(|sp| catalog::output(sp, out)) {
            Some(Ty::Answer) => Type::Decision(self.steps[i].variants.clone()),
            Some(ty) if more.is_none() => ty.to_type(),
            Some(_) => Type::Any, // a field of a declared output, unchecked
            None => {
                let name = self.steps[i].name.clone();
                let msg = format!("step `{name}` has no output `{out}`");
                if spec.is_some_and(|sp| sp.runtime_outputs) {
                    self.err_hint(
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
                    match suggest(out, &outs) {
                        Some(s) => self.err_hint(span, msg, format!("did you mean `{s}`?")),
                        None => self.err(span, msg),
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
                    Some(s) => self.err_hint(span, msg, format!("did you mean `env.{s}`?")),
                    None => match (ns, name) {
                        ("git", n) => {
                            member_error(self, "git", n, &["branch", "ref", "sha", "tag"], span)
                        }
                        ("pr", n) => member_error(self, "pr", n, &["base", "number"], span),
                        ("run", n) => {
                            member_error(self, "run", n, &["actor", "id", "is_agent"], span)
                        }
                        ("ci", n) => member_error(self, "ci", n, &["provider"], span),
                        _ => self.err(span, msg),
                    },
                }
                return None;
            }
            _ => return None, // not a namespace: the caller reports it
        };
        if matches!(ty, Type::Optional(_)) {
            self.diags.push(
                Diagnostic::warning(span, format!("optional value `{ns}.{name}` may be absent"))
                    .with_hint("it has no value on a laptop or outside a pull request"),
            );
        }
        Some(ty)
    }

    // --- expressions ------------------------------------------------------

    fn ty_of(&mut self, cur: usize, e: &Expr<'_>) -> Type {
        match e {
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
        }
    }

    fn demand_bool(&mut self, cur: usize, e: &Expr<'_>) {
        let t = self.ty_of(cur, e);
        if !accepts(&Type::Bool, &t) {
            self.err(e.span(), format!("expected `Bool`, got `{t}`"));
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
        self.err(span, format!("cannot compare `{lt}` and `{rt}`"));
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
                span,
                format!("unknown answer `{text}`"),
                format!("did you mean `{s}`?"),
            ),
            None if variants.is_empty() => self.err_hint(
                span,
                format!("unknown answer `{text}`"),
                "declare the answers under `returns:`",
            ),
            None => self.err(
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
                        Some(s) => {
                            self.err_hint(name.node.span(), msg, format!("did you mean `{s}`?"))
                        }
                        None => self.err(name.node.span(), msg),
                    }
                }
            } else {
                self.err(answer.span(), "expected an environment name");
            }
            if threshold.is_some() {
                self.err(subject.span(), "environment tests take no confidence threshold");
            }
            return Type::Bool;
        }
        match self.ty_of(cur, subject) {
            Type::Decision(vs) => {
                if let Some(w) = subject_word(answer) {
                    self.answer(&vs, &w);
                } else {
                    self.err(answer.span(), "expected an answer word");
                }
                if let Some(bound) = threshold {
                    self.confidence(bound);
                }
            }
            Type::Any => {}
            other => self.err(subject.span(), format!("expected a decision, got `{other}`")),
        }
        Type::Bool
    }

    fn confidence(&mut self, bound: &Expr<'_>) {
        let Expr::Atom { atom: Atom::Word(w), .. } = bound else {
            self.err(bound.span(), "confidence must be a number between 0 and 1");
            return;
        };
        let ok = w.scalar() == ks_lang::Scalar::Number
            && w.text().parse::<f64>().is_ok_and(|n| (0.0..=1.0).contains(&n));
        if !ok {
            self.err(w.node.span(), "confidence must be a number between 0 and 1");
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
                        if ty == Type::Secret {
                            self.cannot_show_secret(span, w.text());
                        }
                        if let Some(target) = target {
                            self.shown.push((idx, target));
                        }
                    }
                }
                _ => self.err_hint(
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
                        self.err_hint(item.span(), "`ask` takes a handle", "`ask @platform`");
                    }
                    for a in rest {
                        if let Atom::Word(w) = a {
                            let got = self.word_untyped(idx, w);
                            if got != Type::Handle {
                                self.err(w.node.span(), format!("expected `Handle`, got `{got}`"));
                            }
                        }
                    }
                }
                "show" => {
                    if rest.is_empty() {
                        self.err_hint(
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
                                    span,
                                    format!("expected a reference, got `{}`", w.text()),
                                    "show takes step outputs and context values",
                                );
                            }
                        } else {
                            self.err(a.span(), "expected a reference");
                        }
                    }
                }
                other => {
                    let msg = format!("unknown action `{other}`");
                    match suggest(other, &["ask", "show"]) {
                        Some(s) => {
                            self.err_hint(verb.node.span(), msg, format!("did you mean `{s}`?"))
                        }
                        None => self.err(verb.node.span(), msg),
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
            self.err_hint(e.span(), "expected a trigger", hint);
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
                self.err(span, "`schedule` triggers are not supported yet");
                return None;
            }
            other => {
                let msg = format!("unknown trigger `{other}`");
                match suggest(other, &TRIGGER_KINDS) {
                    Some(s) => self.err_hint(span, msg, format!("did you mean `{s}`?")),
                    None => self.err(span, msg),
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
                match p.key_name() {
                    Some("on") => env.triggers = self.triggers_of(p),
                    Some("ci-only") => match p.expr().as_ref().and_then(value_word).as_deref() {
                        Some("true") => env.ci_only = true,
                        Some("false") => {}
                        _ => self.err_hint(
                            p.key_span(),
                            "`ci-only` takes `true` or `false`",
                            "`ci-only: true`",
                        ),
                    },
                    Some("secrets") => env.secrets = self.scalar_text(p),
                    Some("approvers") => {
                        if let Some(v) = p.expr() {
                            for item in tuple_items(v) {
                                match &item {
                                    Expr::Atom { atom: Atom::Word(w), .. } => {
                                        env.approvers.push(w.text().into());
                                        if w.scalar() != ks_lang::Scalar::Handle {
                                            self.err_hint(
                                                w.node.span(),
                                                format!("expected `Handle`, got `{}`", w.text()),
                                                "approvers are handles, like `@platform`",
                                            );
                                        }
                                    }
                                    _ => self.err_hint(
                                        item.span(),
                                        "expected a handle",
                                        "approvers are handles, like `@platform`",
                                    ),
                                }
                            }
                        }
                    }
                    Some("vars") => {
                        env.vars =
                            p.children().filter_map(|c| c.key_name()).map(String::from).collect();
                    }
                    Some(other) => {
                        let msg = format!("unknown environment property `{other}`");
                        match suggest(other, &ENV_PROPERTIES) {
                            Some(s) => {
                                self.err_hint(p.key_span(), msg, format!("did you mean `{s}`?"))
                            }
                            None => self.err(p.key_span(), msg),
                        }
                    }
                    None => {}
                }
            }
            out.push(env);
        }
        out
    }

    fn check_policy(&mut self, policy: Entry<'_>) {
        for subject in policy.children() {
            match subject.key_name() {
                Some("agents" | "humans") => {}
                Some(other) => {
                    let msg = format!("unknown policy subject `{other}`");
                    match suggest(other, &["agents", "humans"]) {
                        Some(s) => {
                            self.err_hint(subject.key_span(), msg, format!("did you mean `{s}`?"))
                        }
                        None => self.err(subject.key_span(), msg),
                    }
                    continue;
                }
                None => continue,
            }
            for p in subject.children() {
                match p.key_name() {
                    Some("can" | "before" | "never") => self.actions(p),
                    Some("ask") => {
                        if let Some(v) = p.expr() {
                            for item in tuple_items(v) {
                                match &item {
                                    Expr::Atom { atom: Atom::Word(w), .. }
                                        if w.scalar() != ks_lang::Scalar::Handle =>
                                    {
                                        self.err_hint(
                                            w.node.span(),
                                            format!("expected `Handle`, got `{}`", w.text()),
                                            "`ask` takes handles, like `@platform`",
                                        );
                                    }
                                    Expr::Atom { .. } => {}
                                    _ => self.err_hint(
                                        item.span(),
                                        "expected a handle",
                                        "`ask` takes handles, like `@platform`",
                                    ),
                                }
                            }
                        }
                    }
                    Some(other) => {
                        let msg = format!("unknown policy property `{other}`");
                        match suggest(other, &["ask", "can", "before", "never"]) {
                            Some(s) => {
                                self.err_hint(p.key_span(), msg, format!("did you mean `{s}`?"))
                            }
                            None => self.err(p.key_span(), msg),
                        }
                    }
                    None => {}
                }
            }
        }
    }

    /// `can`/`before`/`never`: tuples of `<verb> [<env>]` (`read secrets`).
    fn actions(&mut self, entry: Entry<'_>) {
        let Some(e) = entry.expr() else { return };
        for item in tuple_items(e.clone()) {
            let atoms = item.atoms();
            if atoms.is_empty() {
                self.err_hint(
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
                match suggest(text, &POLICY_VERBS) {
                    Some(s) => self.err_hint(verb.node.span(), msg, format!("did you mean `{s}`?")),
                    None => self.err(verb.node.span(), msg),
                }
                continue;
            }
            if text == "read" {
                match atoms.get(1) {
                    Some(Atom::Word(obj)) if obj.text() == "secrets" => {}
                    Some(a) => self.err(a.span(), "`read` takes `secrets`"),
                    None => {
                        self.err_hint(verb.node.span(), "`read` takes `secrets`", "`read secrets`")
                    }
                }
                continue;
            }
            let Some(Atom::Word(env)) = atoms.get(1) else { continue };
            let name = env.text();
            if self.env_names.iter().any(|e| e == name) {
                continue;
            }
            let msg = format!("undeclared environment `{name}`");
            match suggest(name, &self.env_names) {
                Some(s) => self.err_hint(
                    env.node.span(),
                    msg,
                    format!("did you mean `{s}`? or declare it under `envs:`"),
                ),
                None => self.err_hint(env.node.span(), msg, "declare it under `envs:`"),
            }
        }
    }

    // --- graph ------------------------------------------------------------

    fn finish_all(mut self) -> Checked {
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
                self.err(span, format!("cycle: {}", path.join(" → ")));
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
        let workflow = Workflow::new(self.name, self.triggers, self.envs, steps, edges, order);
        // One file, one order: parser and checker findings interleaved in
        // source order, so CLI and editor output line up.
        let mut diagnostics = self.diags;
        diagnostics.sort_by_key(|d| (d.span.start, d.span.end));
        Checked { workflow, diagnostics }
    }
}

// --- helpers ---------------------------------------------------------------

fn member_error(c: &mut Ctx, ns: &str, name: &str, members: &[&str], span: Span) {
    match suggest(name, members) {
        Some(s) => c.err_hint(
            span,
            format!("unknown context value `{ns}.{name}`"),
            format!("did you mean `{ns}.{s}`?"),
        ),
        None => c.err(span, format!("unknown context value `{ns}.{name}`")),
    }
}

fn split_first(text: &str) -> (&str, Option<&str>) {
    match text.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (text, None),
    }
}

fn accepts(want: &Type, got: &Type) -> bool {
    want == got
        || matches!(want, Type::Any)
        || matches!(got, Type::Any)
        || (want == &Type::Float && got == &Type::Int)
        || matches!(got, Type::Optional(inner) if accepts(want, inner))
}

/// A type without its `Optional` wrapper, so `git.tag?` compares against
/// `String`.
fn bare_optional(t: &Type) -> &Type {
    match t {
        Type::Optional(inner) => inner,
        other => other,
    }
}

fn interp_allowed(ty: Ty) -> bool {
    matches!(ty, Ty::String | Ty::Any | Ty::Named("oci.Tag"))
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
    if candidates.len() > MAX_SUGGEST_CANDIDATES {
        return None;
    }
    let limit = if name.len() < 4 { 1 } else { 2 };
    candidates
        .iter()
        // A length difference alone already exceeds the threshold.
        .filter(|c| c.as_ref().len().abs_diff(name.len()) <= limit)
        .map(|c| (bounded_levenshtein(name, c.as_ref(), limit), c))
        .filter(|(d, _)| *d <= limit)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c.as_ref().to_string())
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
fn find_cycle(steps: &[StepInfo], edges: &[Edge]) -> Option<(Vec<String>, Span)> {
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

fn topo(steps: &[StepInfo], edges: &[Edge]) -> Option<Vec<String>> {
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
