//! Diagnostics shared with the checker: the same `Diagnostic` type that
//! `ks-core` emits, so editor and CLI output can treat parser and checker
//! errors uniformly.

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

/// A parse or check finding. `ks-lang` produces errors only; `ks-core` emits
/// the same type, including warnings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub span: Span,
    pub message: String,
    pub hint: Option<String>,
}

impl Diagnostic {
    pub fn error(span: Span, message: impl Into<String>) -> Self {
        Self { severity: Severity::Error, span, message: message.into(), hint: None }
    }

    pub fn warning(span: Span, message: impl Into<String>) -> Self {
        Self { severity: Severity::Warning, span, message: message.into(), hint: None }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.severity, self.span, self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, "\n  hint: {hint}")?;
        }
        Ok(())
    }
}
