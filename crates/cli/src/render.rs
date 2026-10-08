//! Rendering diagnostics in the three `--format` styles: the human report
//! with source snippets, JSON Lines for tools, and GitHub Actions workflow
//! commands for pull-request annotations. The formats are pinned byte for
//! byte in `docs/DIAGNOSTICS.md` and by the golden tests.

use std::io::{self, IsTerminal, Write};
use std::ops::Range;

use ks_lang::{Diagnostic, Severity, Span};

/// The `--format` styles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// The default: snippets, carets and hints, for people at a terminal.
    Human,
    /// JSON Lines, one diagnostic per line, schema v1.
    Json,
    /// GitHub Actions workflow commands, one annotation per diagnostic.
    Github,
}

impl Format {
    pub fn parse(text: &str) -> Option<Format> {
        match text {
            "human" => Some(Format::Human),
            "json" => Some(Format::Json),
            "github" => Some(Format::Github),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Human => "human",
            Format::Json => "json",
            Format::Github => "github",
        }
    }
}

/// The 1-based line a byte offset falls on, for a command that prints a
/// position without printing the file around it.
pub fn line_at(src: &str, offset: u32) -> usize {
    Lines::new(src).line_col(src, offset).0
}

/// Colour is for terminals: on when stdout is one and `NO_COLOR` is unset or
/// empty — any non-empty value disables it, per no-color.org.
pub fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
}

const RESET: &str = "\x1b[0m";
const RED_BOLD: &str = "\x1b[1;31m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const BLUE: &str = "\x1b[34m";
const CYAN: &str = "\x1b[36m";

/// `text` wrapped in `code` when colour is on, verbatim when not.
fn paint(color: bool, code: &str, text: &str) -> String {
    if color { format!("{code}{text}{RESET}") } else { text.to_string() }
}

/// How far a hint line may reach, the `  hint: ` prefix included: the
/// report has to stay readable in a half-width pane.
const HINT_WIDTH: usize = 40;
const HINT_PREFIX: &str = "  hint: ";
/// Continuation lines align under the hint text.
const HINT_INDENT: &str = "        ";

/// The line starts of a source file, built once: each diagnostic's position
/// is then a binary search plus one short char count, instead of a rescan of
/// the whole file per diagnostic.
pub struct Lines {
    starts: Vec<u32>,
}

impl Lines {
    pub fn new(src: &str) -> Self {
        let mut starts: Vec<u32> = src
            .bytes()
            .enumerate()
            .filter(|&(_, b)| b == b'\n')
            .map(|(i, _)| i as u32 + 1)
            .collect();
        starts.insert(0, 0);
        Self { starts }
    }

    /// The 1-based line and column of a byte offset. Columns count
    /// characters, not bytes, so a multi-byte character is one column.
    pub fn line_col(&self, src: &str, offset: u32) -> (usize, usize) {
        let offset = (offset as usize).min(src.len()) as u32;
        let line = self.starts.partition_point(|&s| s <= offset) - 1;
        let col = src[self.starts[line] as usize..offset as usize].chars().count() + 1;
        (line + 1, col)
    }

    /// The byte range of a 1-based line's text, without the newline.
    fn line_range(&self, src: &str, line: usize) -> Range<usize> {
        let start = self.starts[line - 1] as usize;
        let end = match self.starts.get(line) {
            Some(&next) => next as usize - 1,
            None => src.len(),
        };
        start..end
    }

    fn line_text<'a>(&self, src: &'a str, line: usize) -> &'a str {
        let range = self.line_range(src, line);
        src[range].trim_end_matches('\r')
    }
}

/// How many carets `span` gets on `line`: its length there, at least one —
/// a multi-line span underlines only its first line.
fn mark_width(src: &str, lines: &Lines, span: Span, line: usize) -> usize {
    let line_end = lines.line_range(src, line).end;
    let start = (span.start as usize).min(line_end);
    let end = (span.end as usize).clamp(start, line_end);
    src[start..end].chars().count().max(1)
}

/// The human report: one block per diagnostic — header, snippet, carets,
/// secondary labels, hints — plus the all-clear line and the footer.
pub fn human(
    w: &mut impl Write,
    path: &str,
    src: &str,
    diags: &[Diagnostic],
    color: bool,
) -> io::Result<()> {
    let lines = Lines::new(src);
    for d in diags {
        let (line, col) = lines.line_col(src, d.span.start);
        let (glyph, code) = match d.severity {
            Severity::Error => ("✗", RED_BOLD),
            Severity::Warning => ("⚠", YELLOW),
        };
        write!(w, "{} {path}:{line}", paint(color, code, glyph))?;
        if let Some(subject) = &d.subject {
            write!(w, "  {subject}")?;
        }
        writeln!(w, "  {}", d.message)?;

        let text = lines.line_text(src, line);
        let pad = " ".repeat(line.ilog10() as usize + 1);
        let gutter = paint(color, BLUE, "│");
        writeln!(w, "{pad}{gutter}")?;
        writeln!(w, "{} {gutter} {text}", paint(color, BLUE, &line.to_string()))?;
        let marks = paint(color, code, &"^".repeat(mark_width(src, &lines, d.span, line)));
        writeln!(w, "{pad}{gutter} {}{marks}", " ".repeat(col - 1))?;

        for label in &d.labels {
            let (at, lcol) = lines.line_col(src, label.span.start);
            let lpad = " ".repeat(at.ilog10() as usize + 1);
            writeln!(
                w,
                "{} {gutter} {}",
                paint(color, BLUE, &at.to_string()),
                lines.line_text(src, at)
            )?;
            let dash = paint(color, BLUE, &"-".repeat(mark_width(src, &lines, label.span, at)));
            writeln!(w, "{lpad}{gutter} {}{dash} {}", " ".repeat(lcol - 1), label.message)?;
        }

        for hint in &d.hints {
            write_hint(w, color, hint)?;
        }
    }
    Ok(())
}

/// One hint, word-wrapped so no printed line exceeds [`HINT_WIDTH`] columns
/// — the prefix and the continuation indent count towards the budget alike.
fn write_hint(w: &mut impl Write, color: bool, hint: &str) -> io::Result<()> {
    let mut lines: Vec<String> = vec![String::new()];
    for word in hint.split_whitespace() {
        let last = lines.last().expect("at least one line");
        let budget = HINT_WIDTH - HINT_PREFIX.len();
        if !last.is_empty() && last.chars().count() + 1 + word.chars().count() > budget {
            lines.push(String::new());
        }
        let last = lines.last_mut().expect("just pushed");
        if !last.is_empty() {
            last.push(' ');
        }
        last.push_str(word);
    }
    for (n, line) in lines.iter().enumerate() {
        match n {
            0 => writeln!(w, "  {} {line}", paint(color, CYAN, "hint:"))?,
            _ => writeln!(w, "{HINT_INDENT}{line}")?,
        }
    }
    Ok(())
}

/// The per-file all-clear line.
pub fn ok_line(w: &mut impl Write, path: &str, color: bool) -> io::Result<()> {
    writeln!(w, "{} {path}", paint(color, GREEN, "✓"))
}

/// The promise every human report ends with: checking never runs anything.
pub fn footer(w: &mut impl Write) -> io::Result<()> {
    writeln!(w, "0 steps ran. Nothing was touched.")
}

/// JSON Lines, schema v1: one self-contained object per diagnostic, stable
/// key order, and nothing else on stdout — no footer, no listing. Positions
/// follow the source: `start`/`end` are byte offsets; `line`/`column` are
/// 1-based and count characters; `end_line`/`end_column` are exclusive, the
/// first position past the span.
pub fn json(w: &mut impl Write, path: &str, src: &str, diags: &[Diagnostic]) -> io::Result<()> {
    let lines = Lines::new(src);
    for d in diags {
        write!(
            w,
            "{{\"version\":1,\"code\":{},\"severity\":{},\"file\":{},",
            json_str(d.code.as_str()),
            json_str(d.severity.as_str()),
            json_str(path)
        )?;
        match &d.subject {
            Some(subject) => write!(w, "\"subject\":{},", json_str(subject))?,
            None => write!(w, "\"subject\":null,")?,
        }
        write!(w, "\"message\":{},\"span\":", json_str(&d.message))?;
        json_span(w, &lines, src, d.span)?;
        write!(w, ",\"labels\":[")?;
        for (n, label) in d.labels.iter().enumerate() {
            if n > 0 {
                write!(w, ",")?;
            }
            write!(w, "{{\"message\":{},\"span\":", json_str(&label.message))?;
            json_span(w, &lines, src, label.span)?;
            write!(w, "}}")?;
        }
        write!(w, "],\"hints\":[")?;
        for (n, hint) in d.hints.iter().enumerate() {
            if n > 0 {
                write!(w, ",")?;
            }
            write!(w, "{}", json_str(hint))?;
        }
        // A suggested edit, in the same span encoding as the diagnostic's own.
        write!(w, "],\"fixes\":[")?;
        for (n, fix) in d.fixes.iter().enumerate() {
            if n > 0 {
                write!(w, ",")?;
            }
            write!(w, "{{\"span\":")?;
            json_span(w, &lines, src, fix.span)?;
            write!(
                w,
                ",\"replacement\":{},\"machine_applicable\":{}}}",
                json_str(&fix.replacement),
                fix.machine_applicable
            )?;
        }
        writeln!(w, "]}}")?;
    }
    Ok(())
}
fn json_span(w: &mut impl Write, lines: &Lines, src: &str, span: Span) -> io::Result<()> {
    let (line, column) = lines.line_col(src, span.start);
    let (end_line, end_column) = lines.line_col(src, span.end);
    write!(
        w,
        "{{\"start\":{},\"end\":{},\"line\":{line},\"column\":{column},\
         \"end_line\":{end_line},\"end_column\":{end_column}}}",
        span.start, span.end
    )
}

/// A JSON string literal, escaped per RFC 8259: quote, backslash and the C0
/// controls; everything else rides through as UTF-8.
pub(crate) fn json_str(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// GitHub Actions workflow commands, one annotation per diagnostic, so the
/// findings show up on the pull request. Positions follow the JSON rules;
/// warnings are `::warning`; hints ride in the message as `%0Ahint: …`.
pub fn github(w: &mut impl Write, path: &str, src: &str, diags: &[Diagnostic]) -> io::Result<()> {
    let lines = Lines::new(src);
    for d in diags {
        let (line, col) = lines.line_col(src, d.span.start);
        let (end_line, end_column) = lines.line_col(src, d.span.end);
        let level = match d.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(
            w,
            "::{level} file={},line={line},col={col},endLine={end_line},endColumn={end_column},\
             title={}",
            github_prop(path),
            github_prop(&match &d.subject {
                Some(subject) => format!("{} {subject}", d.code.as_str()),
                None => d.code.as_str().to_string(),
            })
        )?;
        write!(w, "::{}", github_data(&d.message))?;
        for hint in &d.hints {
            write!(w, "%0Ahint: {}", github_data(hint))?;
        }
        writeln!(w)?;
    }
    Ok(())
}

/// GitHub's property escaping: the message trio plus `:` and `,`, the
/// property separators.
fn github_prop(text: &str) -> String {
    let prop = github_data(text).replace(':', "%3A");
    prop.replace(',', "%2C")
}

/// GitHub's message-data escaping: `%`, `\r`, `\n`.
fn github_data(text: &str) -> String {
    text.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}
