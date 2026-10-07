//! The `keepshipping fmt` core: canonical `.ks` source out of the lossless tree.
//!
//! Every line is rebuilt from tokens, so a value keeps its bytes — a string is
//! never rewritten — and only the whitespace *between* tokens is. Anything the
//! parser could not place is refused rather than guessed at; the one exception
//! is [`Code::TabIndent`], whose whole purpose is to be fixed here.

use std::error::Error;
use std::fmt;
use std::iter::once;
use std::ops::Range;

use crate::diagnostic::{Code, Diagnostic, Severity, Span};
use crate::syntax::{SyntaxElement, SyntaxKind, SyntaxNode, SyntaxToken};

/// The least room a trailing comment gets between itself and the code before
/// it. One space is the smallest a comment can be read at, and it is what a
/// well-spaced file already uses.
const MIN_COMMENT_GAP: usize = 1;

/// One top-level entry: the source bytes it covers and the output bytes it
/// covers, so the two can be paired by index.
type Chunk = (Range<usize>, Range<usize>);
type Chunks = Vec<Chunk>;

/// A file `fmt` refused to rewrite, with the diagnostics that stopped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatError {
    diagnostics: Vec<Diagnostic>,
}

impl FormatError {
    /// The error-severity diagnostics that made the file unformattable.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, d) in self.diagnostics.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{d}")?;
        }
        Ok(())
    }
}

impl Error for FormatError {}

/// Format a whole file.
///
/// Returns `Err` when the parse carries error-severity diagnostics other than
/// [`Code::TabIndent`]: `fmt` never reformats a file it cannot fully
/// understand. Tabs are exempt because replacing them is this module's job.
pub fn format(src: &str) -> Result<String, FormatError> {
    Ok(Formatter::new(src).run()?.0)
}

/// Format only the top-level entries (steps) that intersect `range`, as one
/// replacement edit, for an LSP formatting request.
///
/// Returns `None` when the range touches no entry, or when every entry it
/// touches is already canonically spelled. Original and formatted entries are
/// paired by index, so an edit never moves a comment into another step.
///
/// A narrow edit is only returned once it has been checked: the spliced file
/// has to format back to the same canonical whole. The bytes outside the range
/// are left as they were, and that can move a step across a neighbour's
/// indentation and change what the file is, so an edit that fails the check
/// widens to the whole file rather than hand back text that does not parse.
pub fn format_range(
    src: &str,
    range: Range<usize>,
) -> Result<Option<(Range<usize>, String)>, FormatError> {
    let (text, chunks) = Formatter::new(src).run()?;
    let hit = |c: &Chunk| c.0.start < range.end && range.start < c.0.end;
    let (Some(first), Some(last)) = (chunks.iter().position(hit), chunks.iter().rposition(hit))
    else {
        return Ok(None);
    };
    let edit = chunks[first].0.start..chunks[last].0.end;
    let out = chunks[first].1.start..chunks[last].1.end;
    let narrow = edit_span(src, &text, edit, out);
    // Splicing an edit into a file can leave a result `fmt` itself would
    // refuse — an entry dedented past a sibling the edit never touched is one
    // shape of it. Widening cannot: it hands back exactly the canonical text.
    if let Some((at, with)) = &narrow {
        let spliced = format!("{}{with}{}", &src[..at.start], &src[at.end..]);
        if crate::format(&spliced).ok().as_deref() != Some(text.as_str()) {
            return Ok(edit_span(src, &text, 0..src.len(), 0..text.len()));
        }
    }
    Ok(narrow)
}

/// `None` when the region already spells itself canonically, so a caller has
/// nothing to do.
///
/// Columns come from the whole file on every call, so the canonical text of a
/// region is exactly that region's share of the canonical whole: the edit is a
/// fixed point, and a caller can apply it and ask again about the lines it
/// wrote to be told there is nothing left to do.
fn edit_span(
    src: &str,
    text: &str,
    src_range: Range<usize>,
    out_range: Range<usize>,
) -> Option<(Range<usize>, String)> {
    let replacement = text.get(out_range)?;
    (src.get(src_range.clone())? != replacement).then(|| (src_range, replacement.to_string()))
}

/// One output line: the code, and the comment trailing it if it has one.
///
/// An empty `code` means the line is blank or holds a full-line comment, and
/// in both cases it ends a run of trailing comments.
struct Line {
    code: String,
    comment: Option<Comment>,
}

/// A comment and the gap the author put in front of it. The gap is what a run
/// is aligned on, not the gap each comment ends up with.
struct Comment {
    text: String,
    gap: usize,
}

impl Comment {
    /// A comment token's text, without the carriage returns the lexer folded
    /// into it. `#` followed by a bare `\r` is one token; `#` followed by
    /// `\r\n` is a comment and a newline. `fmt` writes its own `\n`, so a `\r`
    /// left in the text would read back as a newline the second time round.
    fn of(token: &SyntaxToken) -> Self {
        Comment { text: token.text().trim_end_matches('\r').to_string(), gap: 0 }
    }
}

impl Line {
    fn of(code: String) -> Self {
        Line { code, comment: None }
    }

    /// A line holding nothing: a blank, or a full-line comment's own line.
    fn blank() -> Self {
        Line::of(String::new())
    }

    /// Where this line's trailing comment wants to sit: the end of the code
    /// plus the gap the author gave it. `None` on a line with no comment of
    /// its own, and on a full-line comment, which ends a run instead of
    /// joining one.
    fn wants(&self) -> Option<usize> {
        if self.code.is_empty() {
            return None;
        }
        Some(self.code.chars().count() + self.comment.as_ref()?.gap)
    }
}

struct Formatter<'a> {
    src: &'a str,
    lines: Vec<Line>,
    /// Where each top-level entry starts: its source offset and its output
    /// line, which `finish` turns into byte ranges.
    chunks: Vec<(usize, usize)>,
    /// The indentation of the file's leftmost entry: a fragment indented for a
    /// surrounding block keeps its shape.
    base: usize,
    /// Blank lines seen since the last line was written. The parser attaches
    /// them to the *end* of the entry above, so this has to outlive a nested
    /// block's return to reach the entry they actually precede.
    blanks: usize,
    /// The last line written was a comment's own line, so the newline ending
    /// it is spent.
    after_comment: bool,
    /// A token the formatter has no rule for: refuse rather than drop it.
    broken: Option<Span>,
}

impl<'a> Formatter<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            lines: Vec::new(),
            chunks: Vec::new(),
            base: 0,
            blanks: 0,
            after_comment: false,
            broken: None,
        }
    }

    fn run(mut self) -> Result<(String, Chunks), FormatError> {
        let parse = crate::parse(self.src);
        let errors = |parse: &crate::Parse| -> Vec<Diagnostic> {
            parse
                .diagnostics()
                .iter()
                .filter(|d| d.severity == Severity::Error && d.code != Code::TabIndent)
                .cloned()
                .collect()
        };
        let diagnostics = errors(&parse);
        if !diagnostics.is_empty() {
            return Err(FormatError { diagnostics });
        }
        if let Some(span) = tab_in_block_string(&parse) {
            return Err(FormatError {
                diagnostics: vec![
                    Diagnostic::error(
                        Code::Syntax,
                        span,
                        "cannot format: a tab inside a block string",
                    )
                    .with_hint(
                        "a block string's text is the author's and `fmt` keeps it byte for byte, \
                            so the tab has to go before the file can be formatted",
                    ),
                ],
            });
        }
        if let Some(span) = bare_carriage_return(&parse) {
            return Err(FormatError {
                diagnostics: vec![
                    Diagnostic::error(
                        Code::Syntax,
                        span,
                        "cannot format: a bare carriage return outside a string",
                    )
                    .with_hint(
                        "end lines with `\\n` or `\\r\\n`; a lone `\\r` is not a line ending here",
                    ),
                ],
            });
        }
        let file = parse.syntax();
        self.base = indent_of(self.src, file.child_nodes_of_kind(SyntaxKind::Entry).next());
        let (root, deep) = self.columns(file);
        self.block(file, 0, root, deep);
        if let Some(span) = self.broken {
            return Err(FormatError {
                diagnostics: vec![Diagnostic::error(
                    Code::Syntax,
                    span,
                    "cannot format: a token the parser could not place",
                )],
            });
        }
        let src = self.src;
        let out = self.finish();
        // Belt and braces: the file `fmt` produces has to be one the parser
        // still accepts, and it has to carry the same tokens it started with.
        // The input carried no errors — that is checked above — so anything
        // wrong here is one formatting introduced, and the output is refused
        // rather than returned: a formatter that drops a token is worse than
        // one that declines to answer.
        let reparsed = crate::parse(&out.0);
        let diagnostics = errors(&reparsed);
        if !diagnostics.is_empty() {
            return Err(FormatError { diagnostics });
        }
        if significant(src) != significant(&out.0) {
            return Err(FormatError {
                diagnostics: vec![Diagnostic::error(
                    Code::Syntax,
                    Span::new(0, src.len() as u32),
                    "cannot format: formatting changed the file's tokens",
                )],
            });
        }
        Ok(out)
    }

    /// Align the comments, join the lines, and pair each entry's source bytes
    /// with the output bytes it became. The file ends in exactly one newline
    /// and no trailing blank lines.
    fn finish(mut self) -> (String, Chunks) {
        while self.lines.last().is_some_and(|l| l.code.is_empty() && l.comment.is_none()) {
            self.lines.pop();
        }
        let cols = run_columns(&self.lines);
        let mut out = String::with_capacity(self.src.len() + self.src.len() / 8);
        let mut starts = Vec::with_capacity(self.lines.len() + 1);
        for (i, line) in self.lines.iter().enumerate() {
            starts.push(out.len());
            out.push_str(&line.code);
            if let Some(c) = &line.comment {
                let end = line.code.chars().count();
                if !line.code.is_empty() {
                    let target = cols[i].unwrap_or(end + c.gap);
                    out.push_str(&" ".repeat(target - end));
                }
                out.push_str(&c.text);
            }
            out.push('\n');
        }
        starts.push(out.len());

        // An entry runs from where it begins to where the next one begins, and
        // the last runs to the end of both. Trivia before the first entry
        // belongs to no entry, so it starts no chunk.
        let srcs: Vec<usize> =
            self.chunks.iter().map(|c| c.0).chain(once(self.src.len())).collect();
        let ends: Vec<usize> =
            self.chunks.iter().map(|c| c.1).chain(once(self.lines.len())).collect();
        let chunks = (0..self.chunks.len())
            .map(|i| (srcs[i]..srcs[i + 1], starts[ends[i]]..starts[ends[i + 1]]))
            .collect();
        (out, chunks)
    }

    /// The two value columns a file uses: one for the top-level entries, one
    /// shared by every entry below them, each the widest `key:` at its own
    /// depth measured from the left margin, plus one space.
    fn columns(&self, file: &SyntaxNode) -> (usize, usize) {
        let (mut root, mut deep) = (0, 0);
        let mut stack = vec![(file, 0usize)];
        while let Some((node, depth)) = stack.pop() {
            for entry in node.child_nodes_of_kind(SyntaxKind::Entry) {
                let width = key_width(entry, depth, self.base);
                if depth == 0 {
                    root = root.max(width);
                } else {
                    deep = deep.max(width);
                }
                stack.push((entry, depth + 1));
            }
        }
        (root, deep)
    }

    /// Walk a `FILE` or `ENTRY` node: the key line it opens, then the value,
    /// then the trivia and child entries that follow. `depth` is this node's
    /// own nesting depth (a `FILE`'s is unused, since it holds no keys).
    fn block(&mut self, node: &SyntaxNode, depth: usize, root: usize, deep: usize) {
        let col = if depth == 0 { root } else { deep };
        let child_depth = if node.kind() == SyntaxKind::Entry { depth + 1 } else { depth };
        let mut line = String::new();
        let mut open = false;
        let mut colon_end = 0usize;
        for el in node.children() {
            match el {
                SyntaxElement::Node(n) => match n.kind() {
                    SyntaxKind::Entry => {
                        self.blank_line();
                        // Only top-level entries are chunks: `format_range`
                        // edits whole steps, not the inputs inside one.
                        if node.kind() == SyntaxKind::File {
                            self.chunk_start(n.span().start as usize);
                        }
                        self.block(n, child_depth, root, deep);
                        open = false;
                    }
                    SyntaxKind::Value => {
                        let (lines, comments) = self.value(n, col, self.base + depth * 2);
                        // A value written hard against its colon stays hard
                        // against it. The padding `fmt` would otherwise add can
                        // change how the token behind it reads back: `a:#` is
                        // the word `#`, while `a: #` is a comment on a key with
                        // no value, which does not parse.
                        if !lines[0].is_empty() {
                            let glued = first_token(n)
                                .is_some_and(|t| t.span().start as usize == colon_end);
                            if !glued {
                                pad(&mut line, col);
                            }
                            line.push_str(&lines[0]);
                        }
                        let first = self.lines.len();
                        self.line_out(std::mem::take(&mut line));
                        for extra in &lines[1..] {
                            self.line_out(extra.clone());
                        }
                        // The comments are hung here rather than written inline
                        // so `run_columns` can see the lines around them.
                        for (at, c) in comments {
                            if let Some(l) = self.lines.get_mut(first + at) {
                                l.comment = Some(c);
                            }
                        }
                        open = false;
                    }
                    _ => self.broken = Some(n.span()),
                },
                SyntaxElement::Token(t) => match t.kind() {
                    SyntaxKind::Key => {
                        line = " ".repeat(self.base + depth * 2);
                        line.push_str(t.text());
                        colon_end = 0;
                        open = true;
                    }
                    SyntaxKind::Colon => {
                        line.push(':');
                        colon_end = t.span().end as usize;
                    }
                    SyntaxKind::Newline => {
                        if open {
                            self.line_out(std::mem::take(&mut line));
                            open = false;
                        } else if self.after_comment {
                            // The newline that ends a comment's own line.
                            self.after_comment = false;
                        } else {
                            self.blanks += 1;
                        }
                    }
                    SyntaxKind::Comment => {
                        if open {
                            // A comment trailing a key with no value of its
                            // own belongs to that key's line. On a line of its
                            // own it would read as a comment about the step
                            // above it.
                            self.line_out(std::mem::take(&mut line));
                            let gap = gap(self.src, colon_end, t.span().start);
                            if let Some(l) = self.lines.last_mut() {
                                l.comment = Some(Comment {
                                    gap: gap.max(MIN_COMMENT_GAP),
                                    ..Comment::of(t)
                                });
                            }
                            open = false;
                            // The newline that ends the key's line is spent.
                            self.after_comment = true;
                        } else {
                            self.blank_line();
                            // A comment on a line of its own keeps that line's
                            // indentation: dedenting it can take it out of the
                            // block it was written in.
                            let indent = indent_at(self.src, t.span().start as usize);
                            self.lines.push(Line {
                                code: String::new(),
                                comment: Some(Comment {
                                    text: format!("{indent}{}", Comment::of(t).text),
                                    gap: 0,
                                }),
                            });
                            self.blanks = 0;
                            self.after_comment = true;
                        }
                    }
                    SyntaxKind::Whitespace | SyntaxKind::Indent => {}
                    _ => self.broken = Some(t.span()),
                },
            }
        }
        if open {
            self.line_out(line);
        }
    }

    fn line_out(&mut self, code: String) {
        self.lines.push(Line::of(code));
        self.blanks = 0;
        self.after_comment = false;
    }

    /// Emit at most one blank line, and never one before the first line.
    fn blank_line(&mut self) {
        if self.blanks > 0 && !self.lines.is_empty() {
            self.lines.push(Line::blank());
        }
        self.blanks = 0;
    }

    /// Open a chunk for the top-level entry starting at `entry_start`. Chunks
    /// tile the file from byte zero, so each one's source range describes the
    /// same text as its formatted counterpart. Trivia since the last entry
    /// belongs to the entry that follows it, so a comment line never migrates
    /// up into another step.
    fn chunk_start(&mut self, entry_start: usize) {
        self.chunks.push((entry_start, self.lines.len()));
    }

    /// Render one value region. Line 0 has no leading padding — the caller
    /// aligns it against the `key:` — and any later line is a continuation,
    /// indented to the value column. The comments come back separately, each
    /// with the line index it belongs to, for the caller to hang off. A
    /// comment ends its own line, so a value may hold several.
    fn value(
        &self,
        value: &SyntaxNode,
        col: usize,
        key_indent: usize,
    ) -> (Vec<String>, Vec<(usize, Comment)>) {
        let block = value.first_child_node_of_kind(SyntaxKind::BlockString);
        let mut tokens = Vec::new();
        match block {
            // A block's own lines are shifted as a unit below; its first line is
            // just the `|` and anything trailing it.
            Some(block) => {
                tokens.extend(block.tokens().filter(|t| t.kind() != SyntaxKind::BlockLine))
            }
            None => collect(value, &mut tokens),
        }
        let mut lines = vec![String::new()];
        let mut comments = Vec::new();
        let mut fresh = true;
        let mut space = false;
        let mut prev_end = None;
        for (i, t) in tokens.iter().enumerate() {
            let n = lines.len() - 1;
            match t.kind() {
                SyntaxKind::Whitespace | SyntaxKind::Indent => space = true,
                SyntaxKind::Newline => {
                    if i + 1 == tokens.len() {
                        break;
                    }
                    lines.push(String::new());
                    fresh = true;
                    space = false;
                    prev_end = None;
                }
                SyntaxKind::Comment => {
                    // A comment with nothing written on its line yet is a
                    // full-line comment: it keeps the indentation it was
                    // written at, or a dedent takes it out of its block.
                    // Line 0 is the exception — the caller has already written
                    // the key on it, and the comment trails that.
                    let c = if n > 0 && lines[n].is_empty() {
                        let indent = indent_at(self.src, t.span().start as usize);
                        Comment { text: format!("{indent}{}", Comment::of(t).text), gap: 0 }
                    } else {
                        let gap = prev_end
                            .map_or(MIN_COMMENT_GAP, |end| gap(self.src, end, t.span().start));
                        Comment { gap: gap.max(MIN_COMMENT_GAP), ..Comment::of(t) }
                    };
                    comments.push((n, c));
                    // A comment runs to the end of its line, so whatever
                    // follows it starts the next one.
                    fresh = false;
                    space = false;
                }
                _ => {
                    if space && !fresh {
                        lines[n].push(' ');
                    }
                    if fresh && n > 0 {
                        pad(&mut lines[n], col);
                    }
                    fresh = false;
                    space = false;
                    lines[n].push_str(canonical(t));
                    prev_end = Some(t.span().end as usize);
                }
            }
        }
        if let Some(block) = block {
            lines.extend(block_lines(block, key_indent + 2));
        }
        (lines, comments)
    }
}

/// The column every trailing comment in a run shares, per line.
///
/// A run is a stretch of consecutive lines that each carry a trailing comment:
/// a blank line, a full-line comment, or a line of code without one ends it.
/// Taking the maximum of `code end + the author's gap` over the run is gofmt's
/// rule — no comment moves left, and a ragged run comes out aligned.
fn run_columns(lines: &[Line]) -> Vec<Option<usize>> {
    let mut cols = vec![None; lines.len()];
    let mut start = 0;
    while start < lines.len() {
        if lines[start].wants().is_none() {
            start += 1;
            continue;
        }
        let mut end = start;
        while lines.get(end).is_some_and(|l| l.wants().is_some()) {
            end += 1;
        }
        let col = (start..end).filter_map(|i| lines[i].wants()).max().unwrap_or_default();
        cols[start..end].fill(Some(col));
        start = end;
    }
    cols
}

/// A token's canonical text: `≥` and `≤` become their ASCII spellings, and
/// nothing else changes.
fn canonical(token: &SyntaxToken) -> &str {
    if token.kind() == SyntaxKind::Op {
        match token.text() {
            "\u{2265}" => ">=",
            "\u{2264}" => "<=",
            other => other,
        }
    } else {
        token.text()
    }
}

/// Every token that carries meaning, in order: the file's content with the
/// whitespace between tokens taken out, and operators in canonical spelling so
/// two spellings of the same file compare equal.
///
/// Comments are trivia but not nothing: the same sequence of comment texts has
/// to come out, or a comment has moved to a different step. A comment's
/// trailing `\r` is a line ending the lexer folded into the token, so it is not
/// part of what the author wrote.
///
/// A block line's text carries its own indentation, which is the formatter's
/// to re-base, so only the text after it is compared — trailing spaces included,
/// since the block's text is the author's.
fn significant(src: &str) -> Vec<(SyntaxKind, String)> {
    fn walk(node: &SyntaxNode, out: &mut Vec<(SyntaxKind, String)>) {
        for el in node.children() {
            match el {
                SyntaxElement::Node(n) => walk(n, out),
                SyntaxElement::Token(t) => {
                    let kind = t.kind();
                    let text = match kind {
                        SyntaxKind::Comment => t.text().trim_end_matches('\r').to_string(),
                        SyntaxKind::BlockLine => t
                            .text()
                            .trim_start_matches([' ', '\t'])
                            .trim_end_matches(['\n', '\r'])
                            .to_string(),
                        _ if kind.is_trivia() => continue,
                        _ => canonical(t).to_string(),
                    };
                    out.push((kind, text));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(crate::parse(src).syntax(), &mut out);
    out
}

/// The span of a tab in a block string's text, if there is one.
///
/// The lexer reads a block string's body as ordinary content, so a tab there
/// is a `TAB_INDENT` diagnostic like any other and `fmt` looks past it — but a
/// block line's text after its indentation is the author's and is copied out
/// byte for byte, and the lexer calls the tab a misplaced one whatever it sits
/// behind. There is no rewriting that keeps the bytes and drops the tab, so the
/// file is refused rather than formatted into one that still trips the
/// diagnostic. Indentation is not that: it is re-based anyway, tab and all.
fn tab_in_block_string(parse: &crate::Parse) -> Option<Span> {
    fn walk(node: &SyntaxNode) -> Option<Span> {
        node.children().iter().find_map(|el| match el {
            SyntaxElement::Node(n) => walk(n),
            SyntaxElement::Token(t)
                if t.kind() == SyntaxKind::BlockLine
                    && t.text().trim_start_matches([' ', '\t']).contains('\t') =>
            {
                Some(t.span())
            }
            SyntaxElement::Token(_) => None,
        })
    }
    walk(parse.syntax())
}

/// The span of a bare `\r` in the file's trivia, if there is one.
///
/// A `\r` only ends a line where a `\n` follows it, so on its own the lexer
/// reads it as whitespace and no rule in this module covers it: it is not an
/// indent, not a gap, and not a line ending. `\r\n` still is a line ending and
/// formats as one; a `\r` inside a string or a block line is the author's
/// bytes and is left alone. Everything else is refused rather than guessed at.
fn bare_carriage_return(parse: &crate::Parse) -> Option<Span> {
    fn walk(node: &SyntaxNode) -> Option<Span> {
        node.children().iter().find_map(|el| match el {
            SyntaxElement::Node(n) => walk(n),
            SyntaxElement::Token(t)
                if matches!(t.kind(), SyntaxKind::Whitespace | SyntaxKind::Indent)
                    && t.text().contains('\r') =>
            {
                Some(t.span())
            }
            SyntaxElement::Token(_) => None,
        })
    }
    walk(parse.syntax())
}

/// Every descendant token of `node`, in source order.
fn collect<'n>(node: &'n SyntaxNode, out: &mut Vec<&'n SyntaxToken>) {
    for el in node.children() {
        match el {
            SyntaxElement::Token(t) => out.push(t),
            SyntaxElement::Node(n) => collect(n, out),
        }
    }
}

/// The first token of `node` or anything below it that is not trivia.
fn first_token(node: &SyntaxNode) -> Option<&SyntaxToken> {
    let mut tokens = Vec::new();
    collect(node, &mut tokens);
    tokens.into_iter().find(|t| !t.kind().is_trivia())
}

/// Block-string lines, shifted so the block hangs two spaces under its key
/// while keeping its own internal shape.
///
/// Only the indentation is re-based: a line's text is the author's, trailing
/// spaces included, and `BlockString::raw` promises it back verbatim.
fn block_lines(block: &SyntaxNode, base_indent: usize) -> Vec<String> {
    let lines: Vec<&str> = block
        .tokens()
        .filter(|t| t.kind() == SyntaxKind::BlockLine)
        .map(|t| t.text().trim_end_matches(['\n', '\r']))
        .collect();
    let lead = |line: &str| line.chars().take_while(|c| *c == ' ' || *c == '\t').count();
    let base = lines.iter().filter(|l| !l.trim().is_empty()).map(|l| lead(l)).min().unwrap_or(0);
    lines
        .iter()
        .map(|line| {
            let n = lead(line);
            let body = &line[n..];
            if body.trim().is_empty() {
                String::new()
            } else {
                format!("{}{}", " ".repeat(base_indent + n - base), body)
            }
        })
        .collect()
}

/// The file's base indentation, in columns: the indentation of the first line
/// that starts a top-level entry.
///
/// Not the first line of the file, which may be blank or a comment, and not an
/// `INDENT` token in the tree: the first entry is usually the whole file's, so
/// its first `INDENT` may belong to a nested entry or a comment. Leading spaces
/// only, for the same reason as [`indent_at`]: a tab is the error this module
/// exists to fix, so it cannot be counted as the one column it occupies.
fn indent_of(src: &str, entry: Option<&SyntaxNode>) -> usize {
    let start = entry
        .and_then(|e| e.first_token_of_kind(SyntaxKind::Key))
        .map_or(0, |t| t.span().start as usize);
    let line_start = src[..start].rfind('\n').map_or(0, |n| n + 1);
    src.get(line_start..start).unwrap_or_default().chars().take_while(|&c| c == ' ').count()
}

/// The column a value starts at if it were written with a single space after
/// its key: the entry's indentation, its key, the colon, and one space.
fn key_width(entry: &SyntaxNode, depth: usize, base: usize) -> usize {
    let key = entry.first_token_of_kind(SyntaxKind::Key).map_or(0, |t| t.text().chars().count());
    base + depth * 2 + key + 2
}

/// The source gap between two offsets, in characters.
fn gap(src: &str, from: usize, to: u32) -> usize {
    let to = (to as usize).min(src.len());
    src.get(from..to).unwrap_or_default().chars().count()
}

/// The indentation of the line `offset` sits on.
///
/// Leading spaces only, for the same reason as [`indent_of`]: a tab is the
/// error this module exists to fix, so it cannot be counted as the one column
/// it occupies.
fn indent_at(src: &str, offset: usize) -> String {
    let line_start = src[..offset].rfind('\n').map_or(0, |n| n + 1);
    src.get(line_start..offset).unwrap_or_default().chars().take_while(|&c| c == ' ').collect()
}

/// Pad `line` out to `col`, unless it is already past it.
fn pad(line: &mut String, col: usize) {
    let len = line.chars().count();
    if len < col {
        line.push_str(&" ".repeat(col - len));
    }
}
