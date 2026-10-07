//! Diagnostics shared with the checker: the same `Diagnostic` type that
//! `ks-core` emits, so editor and CLI output can treat parser and checker
//! errors uniformly. Every diagnostic carries a stable [`Code`], so tools
//! and agents can react to a problem without matching on message text.

use std::fmt;

/// A half-open byte range into the source file. Always falls on UTF-8
/// character boundaries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// A zero-length span pointing just before `at`.
    pub fn point(at: u32) -> Self {
        Self { start: at, end: at }
    }

    pub fn len(&self) -> u32 {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// The text this span covers. The span is only ever produced by slicing
    /// the same source at character boundaries, so this cannot panic.
    pub fn slice<'src>(&self, src: &'src str) -> &'src str {
        let start = (self.start as usize).min(src.len());
        let end = (self.end as usize).clamp(start, src.len());
        src.get(start..end).unwrap_or_default()
    }

    pub fn contains(&self, offset: u32) -> bool {
        self.start <= offset && offset < self.end
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Severity {
    Error,
    Warning,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The kind of problem a [`Diagnostic`] reports, as a stable code agents and
/// tools can match on. Codes are grouped by block — `KS00xx` syntax,
/// `KS01xx` types, `KS02xx` names and references, `KS03xx` workflow
/// structure, `KS04xx` policy, `KS05xx` secrets, `KS06xx` environment, file
/// format and CI warnings, `KS07xx` approval safety, `KS08xx` build
/// reproducibility — and are never renumbered: gaps stay free for new codes.
///
/// The meaning, a bad and a good example of every code are documented in
/// `docs/ERRORS.md`, generated from the registry in `ks-core`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    /// The grammar could not place a token or a value.
    Syntax,
    /// A string or `{` interpolation was never closed.
    Unclosed,
    /// The name inside `{...}` is empty or not a dotted name.
    BadInterp,
    /// A tab sits in a line's indentation.
    TabIndent,
    /// A value does not have the type its input declares.
    TypeMismatch,
    /// A literal is well-formed but wrong for its type (a pasted digest).
    PastedDigest,
    /// A step or context name does not resolve.
    UnknownRef,
    /// An input name the step kind does not declare.
    UnknownInput,
    /// An output a step does not produce.
    UnknownOutput,
    /// An answer a `decide` step does not declare.
    UnknownAnswer,
    /// An `else:` action other than `ask` or `show`.
    UnknownAction,
    /// A step name declared twice.
    DuplicateStep,
    /// A step named like a context namespace (`git`, `secrets`, ...).
    ReservedStepName,
    /// A trigger the language does not know.
    BadTrigger,
    /// An environment is undeclared, misspelled or misconfigured.
    EnvProblem,
    /// Steps depend on each other in a circle.
    Cycle,
    /// A `policy:` subject or property the language does not know.
    PolicyDecl,
    /// A `policy:` action the language does not know.
    PolicyAction,
    /// A `never:` rule refuses this run before it starts.
    PolicyForbidden,
    /// A secret interpolated into a string, where it could leak.
    SecretInString,
    /// A secret passed to `show:`, which displays it.
    SecretShown,
    /// An optional context value used where it may be absent.
    OptionalAbsent,
    /// A step needs more than the context it would run in has.
    NeedsContext,
    /// An `auto:` approval rule that could approve a destructive plan.
    AutoDestroys,
    /// The file declares a format this keepshipping does not read.
    FormatUnsupported,
    /// The file declares the format before the current one.
    FormatDeprecated,
    /// The file declares no format at all, where CI wants one pinned.
    FormatUndeclared,
    /// An image build input that can move between two builds.
    NonReproducible,
}

impl Code {
    /// The code's stable spelling (`"KS0101"`), as printed in output and
    /// documented in `docs/ERRORS.md`.
    pub fn as_str(self) -> &'static str {
        match self {
            Code::Syntax => "KS0001",
            Code::Unclosed => "KS0002",
            Code::BadInterp => "KS0003",
            Code::TabIndent => "KS0004",
            Code::TypeMismatch => "KS0101",
            Code::PastedDigest => "KS0102",
            Code::UnknownRef => "KS0201",
            Code::UnknownInput => "KS0202",
            Code::UnknownOutput => "KS0203",
            Code::UnknownAnswer => "KS0204",
            Code::UnknownAction => "KS0205",
            Code::DuplicateStep => "KS0301",
            Code::ReservedStepName => "KS0302",
            Code::BadTrigger => "KS0303",
            Code::EnvProblem => "KS0304",
            Code::Cycle => "KS0305",
            Code::PolicyDecl => "KS0401",
            Code::PolicyAction => "KS0402",
            Code::PolicyForbidden => "KS0403",
            Code::SecretInString => "KS0501",
            Code::SecretShown => "KS0502",
            Code::OptionalAbsent => "KS0601",
            Code::NeedsContext => "KS0602",
            Code::AutoDestroys => "KS0701",
            Code::FormatUnsupported => "KS0005",
            Code::FormatDeprecated => "KS0610",
            Code::FormatUndeclared => "KS0611",
            Code::NonReproducible => "KS0801",
        }
    }

    /// Every code, in numeric order. Exhaustive documentation for each lives
    /// in `ks_core::registry`.
    pub const ALL: &'static [Code] = &[
        Code::Syntax,
        Code::Unclosed,
        Code::BadInterp,
        Code::TabIndent,
        Code::FormatUnsupported,
        Code::TypeMismatch,
        Code::PastedDigest,
        Code::UnknownRef,
        Code::UnknownInput,
        Code::UnknownOutput,
        Code::UnknownAnswer,
        Code::UnknownAction,
        Code::DuplicateStep,
        Code::ReservedStepName,
        Code::BadTrigger,
        Code::EnvProblem,
        Code::Cycle,
        Code::PolicyDecl,
        Code::PolicyAction,
        Code::PolicyForbidden,
        Code::SecretInString,
        Code::SecretShown,
        Code::OptionalAbsent,
        Code::NeedsContext,
        Code::FormatDeprecated,
        Code::FormatUndeclared,
        Code::AutoDestroys,
        Code::NonReproducible,
    ];
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A secondary span on a [`Diagnostic`]: another place in the source that
/// helps explain the problem ("first defined here").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label {
    pub span: Span,
    pub message: String,
}

/// A suggested edit: the bytes at `span` replaced by `replacement`.
///
/// `machine_applicable` marks an edit a tool may apply on its own —
/// `keepshipping check --fix` takes exactly those. A suggestion the checker
/// cannot prove unambiguous carries `false`: it is advice for a person, not
/// an instruction for a machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fix {
    /// The bytes to replace.
    pub span: Span,
    /// What to put in their place.
    pub replacement: String,
    /// Whether the edit is unambiguous enough to apply without a human.
    pub machine_applicable: bool,
}

impl Fix {
    pub fn new(span: Span, replacement: impl Into<String>, machine_applicable: bool) -> Self {
        Self { span, replacement: replacement.into(), machine_applicable }
    }
}

/// A parse or check finding. `ks-lang` produces errors only; `ks-core` emits
/// the same type, including warnings. `code` names the kind of problem,
/// `subject` — when the checker knows it — the dotted thing the finding is
/// about (`deploy.image`), `labels` point at other places in the source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: Code,
    pub span: Span,
    pub message: String,
    pub subject: Option<String>,
    pub labels: Vec<Label>,
    pub hints: Vec<String>,
    /// Edits that would resolve the finding, in the order they apply.
    pub fixes: Vec<Fix>,
}

impl Diagnostic {
    pub fn error(code: Code, span: Span, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code,
            span,
            message: message.into(),
            subject: None,
            labels: Vec::new(),
            hints: Vec::new(),
            fixes: Vec::new(),
        }
    }

    pub fn warning(code: Code, span: Span, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code,
            span,
            message: message.into(),
            subject: None,
            labels: Vec::new(),
            hints: Vec::new(),
            fixes: Vec::new(),
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hints.push(hint.into());
        self
    }

    /// Names the dotted thing this finding is about (`deploy.image`), so
    /// tools can act on it without parsing the message.
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Adds a secondary span with a one-line explanation.
    pub fn with_label(mut self, span: Span, message: impl Into<String>) -> Self {
        self.labels.push(Label { span, message: message.into() });
        self
    }

    /// Attaches a suggested edit — a did-you-mean rewrite, or the type-
    /// directed output that would satisfy this value.
    pub fn with_fix(mut self, fix: Fix) -> Self {
        self.fixes.push(fix);
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.severity, self.span, self.message)?;
        for hint in &self.hints {
            write!(f, "\n  hint: {hint}")?;
        }
        Ok(())
    }
}
