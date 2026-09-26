//! Parser: groups the token stream into entries and value expressions.
//!
//! Recovers from any malformed input with a diagnostic and keeps going; on
//! arbitrary input it always terminates and never panics, and the tree it
//! builds always prints back the exact source.

use crate::diagnostic::{Diagnostic, Span};
use crate::lexer::{Tok, lex};
use crate::syntax::{SyntaxElement, SyntaxKind, SyntaxNode, SyntaxToken};

pub(crate) struct Parsed {
    pub root: SyntaxNode,
    pub diags: Vec<Diagnostic>,
}

pub(crate) fn parse(src: &str) -> Parsed {
    let lexed = lex(src);
    let mut parser = Parser { src, toks: lexed.tokens.as_slice(), i: 0, diags: lexed.errors };
    let (root, diags) = parser.file();
    Parsed { root, diags }
}

fn token_elem(src: &str, t: &Tok) -> SyntaxElement {
    let span = Span::new(t.start, t.end);
    SyntaxElement::Token(SyntaxToken::new(t.kind, span, span.slice(src).into()))
}

fn node(kind: SyntaxKind, children: Vec<SyntaxElement>) -> SyntaxElement {
    SyntaxElement::Node(SyntaxNode::new(kind, children))
}

/// Operators that form a comparison.
const CMP_OPS: [&str; 8] = ["==", "!=", ">=", "<=", "\u{2265}", "\u{2264}", "<", ">"];
/// Operators accepted as the confidence threshold of an `is` test.
const THRESHOLD_OPS: [&str; 2] = ["\u{2265}", ">="];

/// Cap on block and expression nesting depth. Deeper input is recovered from
/// with a diagnostic and still round-trips; without a cap, adversarially
/// nested input (thousands of `(`, or indentation levels) recurses until the
/// stack overflows. Real files nest a handful of levels deep.
const MAX_DEPTH: u32 = 100;

struct Parser<'src> {
    src: &'src str,
    toks: &'src [Tok],
    i: usize,
    diags: Vec<Diagnostic>,
}

impl<'src> Parser<'src> {
    fn file(&mut self) -> (SyntaxNode, Vec<Diagnostic>) {
        let mut children = Vec::new();
        self.entries(None, &mut children, 0);
        // Safety net: anything the block logic did not claim stays in the
        // tree, so printing never loses bytes.
        while self.i < self.toks.len() {
            children.push(token_elem(self.src, &self.toks[self.i]));
            self.i += 1;
        }
        (SyntaxNode::new(SyntaxKind::File, children), std::mem::take(&mut self.diags))
    }

    /// A run of entries at one indentation. `bind` is fixed by the first
    /// entry; `None` binds to it. Returns on a dedent below `bind`, leaving
    /// the caller to decide where the line belongs. `depth` counts block
    /// nesting and stops the recursion at [`MAX_DEPTH`].
    fn entries(&mut self, mut bind: Option<u32>, out: &mut Vec<SyntaxElement>, depth: u32) {
        loop {
            while self.trivia_line(out) {}
            let Some(idx) = self.next_content() else { return };
            let width = self.indent_width(idx);
            match bind {
                None => bind = Some(width),
                Some(b) if width == b => {}
                Some(b) if width > b => {
                    // Dedented out of a deeper block to a column matching no
                    // open level; keep the line as an entry of this block.
                    let span = self.indent_span(idx);
                    self.diags.push(
                        Diagnostic::error(span, "indentation doesn't match any outer level")
                            .with_hint("align with an outer block or with its siblings"),
                    );
                }
                Some(_) => return,
            }
            if self.toks[idx].kind != SyntaxKind::Key {
                let span = self.indent_span(idx);
                self.diags.push(
                    Diagnostic::error(span, "expected `key:`")
                        .with_hint("a line inside a block must start with `key:`"),
                );
                self.valueless_lines(out, false);
                continue;
            }
            self.entry(out, depth);
        }
    }

    fn entry(&mut self, out: &mut Vec<SyntaxElement>, depth: u32) {
        let key_idx = self.next_content().expect("caller checked for a Key token");
        let key_indent = self.indent_width(key_idx);
        let key_tok = self.toks[key_idx];
        let key_text = Span::new(key_tok.start, key_tok.end).slice(self.src).to_string();
        let colon_idx = key_idx + 1;

        let mut children = Vec::new();
        while self.i <= colon_idx {
            children.push(token_elem(self.src, &self.toks[self.i]));
            self.i += 1;
        }
        let nl = self.line_end(self.i);

        let value_tokens: Vec<usize> =
            (self.i..nl.min(self.toks.len())).filter(|j| !self.toks[*j].kind.is_trivia()).collect();
        let is_block_string =
            value_tokens.len() == 1 && self.toks[value_tokens[0]].kind == SyntaxKind::Pipe;

        let mut had_value = false;
        if is_block_string {
            let mut block = (self.i..nl.min(self.toks.len()))
                .map(|j| token_elem(self.src, &self.toks[j]))
                .collect::<Vec<_>>();
            if nl < self.toks.len() {
                block.push(token_elem(self.src, &self.toks[nl]));
                self.i = nl + 1;
            } else {
                self.i = nl;
            }
            self.block_lines(key_indent, &mut block);
            children.push(node(SyntaxKind::Value, vec![node(SyntaxKind::BlockString, block)]));
            had_value = true;
        } else {
            let region_end = self.continuation_end(key_indent, nl);
            if (self.i..region_end).any(|j| !self.toks[j].kind.is_trivia()) {
                let mut value = Vec::new();
                self.parse_value_region(self.i..region_end, &mut value, false);
                children.push(node(SyntaxKind::Value, value));
                had_value = true;
                self.i = region_end;
            } else {
                let stop = if nl < self.toks.len() { nl + 1 } else { nl };
                while self.i < stop {
                    children.push(token_elem(self.src, &self.toks[self.i]));
                    self.i += 1;
                }
                // A deeper line that is not `key:` cannot open a block.
                if self.deeper_non_key(key_indent) {
                    let idx = self.next_content().expect("checked above");
                    let span = self.indent_span(idx);
                    self.diags.push(
                        Diagnostic::error(span, "expected `key:`").with_hint(format!(
                            "continue the value of `{key_text}` on this line, or dedent to close the block"
                        )),
                    );
                    let mut value = Vec::new();
                    self.valueless_lines(&mut value, true);
                    children.push(node(SyntaxKind::Value, value));
                }
            }
        }

        // Deeper `key:` lines open a block — unless the nesting cap is hit,
        // in which case the enclosing run of entries claims those lines (with
        // a diagnostic each) instead of recursing further.
        if depth < MAX_DEPTH && self.deeper_key(key_indent) {
            let idx = self.next_content().expect("checked above");
            self.entries(Some(self.indent_width(idx)), &mut children, depth + 1);
        }

        if !had_value && !children.iter().any(|c| c.kind() == SyntaxKind::Entry) {
            let key_span = Span::new(key_tok.start, key_tok.end);
            self.diags.push(
                Diagnostic::error(key_span, format!("missing value for `{key_text}`")).with_hint(
                    format!("add a value after `{key_text}:`, or indent entries below it"),
                ),
            );
        }
        out.push(node(SyntaxKind::Entry, children));
    }

    /// Raw lines of a `|` block string: blank lines and lines indented deeper
    /// than the key, each kept as one `BLOCK_LINE` token.
    fn block_lines(&mut self, key_indent: u32, out: &mut Vec<SyntaxElement>) {
        loop {
            if self.i >= self.toks.len() {
                return;
            }
            let start = self.i;
            let nl = self.line_end(start);
            let end = (nl + 1).min(self.toks.len());
            let blank = (start..nl)
                .all(|j| matches!(self.toks[j].kind, SyntaxKind::Whitespace | SyntaxKind::Indent));
            // A non-blank line starts with its INDENT token.
            let indent = match self.toks[start].kind {
                SyntaxKind::Indent => Span::new(self.toks[start].start, self.toks[start].end)
                    .slice(self.src)
                    .chars()
                    .count() as u32,
                _ => 0,
            };
            if !blank && indent <= key_indent {
                return;
            }
            let span = Span::new(self.toks[start].start, self.toks[end - 1].end);
            out.push(SyntaxElement::Token(SyntaxToken::new(
                SyntaxKind::BlockLine,
                span,
                span.slice(self.src).into(),
            )));
            self.i = end;
        }
    }

    /// The exclusive end of a value region: the header line plus every
    /// following line indented deeper than the key that does not start with
    /// `key:`. Blank lines in between only join the region when a
    /// continuation actually follows.
    fn continuation_end(&self, key_indent: u32, header_nl: usize) -> usize {
        let mut end = (header_nl + 1).min(self.toks.len());
        loop {
            // Skip to the next content token, stepping over blank and
            // comment-only lines (they join the region only if a continuation
            // actually follows).
            let mut j = end;
            while j < self.toks.len()
                && self.toks[j].kind.is_trivia()
                && self.toks[j].kind != SyntaxKind::Newline
            {
                j += 1;
            }
            if j < self.toks.len() && self.toks[j].kind == SyntaxKind::Newline {
                j += 1;
                while j < self.toks.len()
                    && self.toks[j].kind.is_trivia()
                    && self.toks[j].kind != SyntaxKind::Newline
                {
                    j += 1;
                }
            }
            if j >= self.toks.len()
                || self.indent_width(j) <= key_indent
                || self.toks[j].kind == SyntaxKind::Key
            {
                return end;
            }
            end = (self.line_end(j) + 1).min(self.toks.len());
        }
    }

    /// Consume the current line and any deeper non-`key:` lines as a raw
    /// value region (used after `expected `key:``).
    fn valueless_lines(&mut self, out: &mut Vec<SyntaxElement>, suppress: bool) {
        let Some(idx) = self.next_content() else { return };
        // The line's leading trivia (its INDENT) sits before `idx` but after
        // `self.i`: consume it too, or printing the tree would lose those
        // bytes.
        while self.i < idx {
            out.push(token_elem(self.src, &self.toks[self.i]));
            self.i += 1;
        }
        let key_indent = self.indent_width(idx);
        let mut end = (self.line_end(idx) + 1).min(self.toks.len());
        while let Some(j) = self.next_content_from(end) {
            if self.indent_width(j) <= key_indent || self.toks[j].kind == SyntaxKind::Key {
                break;
            }
            end = (self.line_end(j) + 1).min(self.toks.len());
        }
        self.parse_value_region(idx..end, out, suppress);
        self.i = end;
    }

    fn parse_value_region(
        &mut self,
        range: std::ops::Range<usize>,
        out: &mut Vec<SyntaxElement>,
        suppress: bool,
    ) {
        let mut vp = ValueParser {
            src: self.src,
            toks: self.toks,
            start: range.start,
            end: range.end,
            i: range.start,
            pending: Vec::new(),
            diags: &mut self.diags,
            suppress,
            depth: 0,
        };
        // Leading trivia (line breaks and indents of continuation lines)
        // belongs to the VALUE node, so expression nodes start at their
        // first token.
        while vp.i < vp.end && vp.toks[vp.i].kind.is_trivia() {
            out.push(token_elem(self.src, &vp.toks[vp.i]));
            vp.i += 1;
        }
        vp.value(out);
        vp.finish(out);
    }

    // --- line helpers -----------------------------------------------------

    fn next_content(&self) -> Option<usize> {
        self.next_content_from(self.i)
    }

    fn next_content_from(&self, from: usize) -> Option<usize> {
        (from..self.toks.len()).find(|j| !self.toks[*j].kind.is_trivia())
    }

    /// Consume a blank or comment-only line into `out`. Lines with content
    /// are left alone, indentation included.
    fn trivia_line(&mut self, out: &mut Vec<SyntaxElement>) -> bool {
        if self.i >= self.toks.len() || !self.toks[self.i].kind.is_trivia() {
            return false;
        }
        let mut j = self.i;
        loop {
            if j >= self.toks.len() {
                break;
            }
            let kind = self.toks[j].kind;
            if kind == SyntaxKind::Newline {
                j += 1;
                break;
            }
            if !kind.is_trivia() {
                return false;
            }
            j += 1;
        }
        while self.i < j {
            out.push(token_elem(self.src, &self.toks[self.i]));
            self.i += 1;
        }
        true
    }

    fn line_end(&self, from: usize) -> usize {
        (from..self.toks.len())
            .find(|j| self.toks[*j].kind == SyntaxKind::Newline)
            .unwrap_or(self.toks.len())
    }

    /// Indent width (in characters) of the line containing token `idx`.
    fn indent_width(&self, idx: usize) -> u32 {
        let mut j = idx;
        while j > 0 && self.toks[j - 1].kind.is_trivia() {
            j -= 1;
            if self.toks[j].kind == SyntaxKind::Indent {
                let t = &self.toks[j];
                return Span::new(t.start, t.end).slice(self.src).chars().count() as u32;
            }
            if self.toks[j].kind == SyntaxKind::Newline {
                break;
            }
        }
        0
    }

    fn indent_span(&self, idx: usize) -> Span {
        let mut j = idx;
        while j > 0 && self.toks[j - 1].kind.is_trivia() {
            j -= 1;
            if self.toks[j].kind == SyntaxKind::Indent || self.toks[j].kind == SyntaxKind::Newline {
                let t = &self.toks[j];
                return Span::new(t.start, t.end);
            }
        }
        Span::point(self.toks[idx].start)
    }

    fn deeper_non_key(&self, key_indent: u32) -> bool {
        match self.next_content() {
            Some(idx) => {
                self.indent_width(idx) > key_indent && self.toks[idx].kind != SyntaxKind::Key
            }
            None => false,
        }
    }

    fn deeper_key(&self, key_indent: u32) -> bool {
        match self.next_content() {
            Some(idx) => {
                self.indent_width(idx) > key_indent && self.toks[idx].kind == SyntaxKind::Key
            }
            None => false,
        }
    }
}

/// Recursive-descent parser for one value region. Trivia between tokens is
/// kept in place inside whichever node is being built.
struct ValueParser<'src, 'diag> {
    src: &'src str,
    toks: &'src [Tok],
    start: usize,
    end: usize,
    i: usize,
    pending: Vec<SyntaxElement>,
    diags: &'diag mut Vec<Diagnostic>,
    suppress: bool,
    /// Current expression nesting (`(` groups and `not`s), capped at
    /// [`MAX_DEPTH`].
    depth: u32,
}

impl<'src> ValueParser<'src, '_> {
    /// The whole value: `tuple ["=" tuple]`.
    fn value(&mut self, out: &mut Vec<SyntaxElement>) {
        let mut lhs = Vec::new();
        self.tuple(&mut lhs);
        if self.at_op("=") {
            let mut n = lhs;
            self.flush(&mut n);
            n.push(self.bump());
            self.drain_trivia(&mut n);
            let mut rhs = Vec::new();
            self.tuple(&mut rhs);
            self.missing_after(&rhs, "=");
            n.extend(rhs);
            out.push(node(SyntaxKind::Default, n));
        } else {
            out.extend(lhs);
        }
    }

    /// `expr {"," expr}`
    fn tuple(&mut self, out: &mut Vec<SyntaxElement>) {
        let mut n = Vec::new();
        self.expr(&mut n);
        let mut commas = 0;
        while self.peek().is_some_and(|t| t.kind == SyntaxKind::Comma) {
            self.flush(&mut n);
            n.push(self.bump());
            commas += 1;
            self.drain_trivia(&mut n);
            let before = n.len();
            self.expr(&mut n);
            if n.len() == before {
                self.missing_operand(",");
            }
        }
        if commas > 0 || !n.is_empty() {
            out.push(node(SyntaxKind::Tuple, n));
        } else {
            out.extend(n);
        }
    }

    /// `and { "or" and }`
    fn expr(&mut self, out: &mut Vec<SyntaxElement>) {
        let mut n = Vec::new();
        self.and(&mut n);
        let mut seps = 0;
        while self.at_keyword("or") {
            self.flush(&mut n);
            n.push(self.bump());
            seps += 1;
            self.drain_trivia(&mut n);
            let before = n.len();
            self.and(&mut n);
            if n.len() == before {
                self.missing_operand("or");
            }
        }
        if seps > 0 {
            out.push(node(SyntaxKind::OrExpr, n));
        } else {
            out.extend(n);
        }
    }

    /// `not { "and" not }`
    fn and(&mut self, out: &mut Vec<SyntaxElement>) {
        let mut n = Vec::new();
        self.not(&mut n);
        let mut seps = 0;
        while self.at_keyword("and") {
            self.flush(&mut n);
            n.push(self.bump());
            seps += 1;
            self.drain_trivia(&mut n);
            let before = n.len();
            self.not(&mut n);
            if n.len() == before {
                self.missing_operand("and");
            }
        }
        if seps > 0 {
            out.push(node(SyntaxKind::AndExpr, n));
        } else {
            out.extend(n);
        }
    }

    /// `"not" not | compare`
    fn not(&mut self, out: &mut Vec<SyntaxElement>) {
        if self.at_keyword("not") {
            if self.depth >= MAX_DEPTH {
                // Nesting cap: keep the tokens (round-trip preserved) and let
                // `finish` mop up the run of `not`s instead of recursing.
                let end = self.peek().map_or(0, |t| t.end);
                self.diag(Span::point(end), "expression nests too deep");
                self.compare(out);
                return;
            }
            self.depth += 1;
            let mut n = Vec::new();
            self.flush(&mut n);
            n.push(self.bump());
            self.drain_trivia(&mut n);
            let before = n.len();
            self.not(&mut n);
            self.depth -= 1;
            if n.len() == before {
                self.missing_operand("not");
            }
            out.push(node(SyntaxKind::NotExpr, n));
        } else {
            self.compare(out);
        }
    }

    /// `union [cmp_op union]` or `union "is" union [("≥"|">=") union]`
    fn compare(&mut self, out: &mut Vec<SyntaxElement>) {
        let mut n = Vec::new();
        self.union(&mut n);
        let op = self.peek().filter(|t| t.kind == SyntaxKind::Op);
        if let Some(op) = op {
            let text = self.text(op).to_string();
            if CMP_OPS.contains(&text.as_str()) {
                self.flush(&mut n);
                n.push(self.bump());
                self.drain_trivia(&mut n);
                let mut rhs = Vec::new();
                self.union(&mut rhs);
                self.missing_after(&rhs, &text);
                n.extend(rhs);
                out.push(node(SyntaxKind::Compare, n));
                return;
            }
        }
        if self.at_keyword("is") {
            self.flush(&mut n);
            n.push(self.bump());
            self.drain_trivia(&mut n);
            let mut answer = Vec::new();
            self.union(&mut answer);
            self.missing_after(&answer, "is");
            n.extend(answer);
            if self
                .peek()
                .is_some_and(|t| t.kind == SyntaxKind::Op && THRESHOLD_OPS.contains(&self.text(t)))
            {
                let op = self.peek().expect("checked above");
                let text = self.text(op).to_string();
                self.flush(&mut n);
                n.push(self.bump());
                self.drain_trivia(&mut n);
                let mut threshold = Vec::new();
                self.union(&mut threshold);
                self.missing_after(&threshold, &text);
                n.extend(threshold);
            }
            out.push(node(SyntaxKind::IsTest, n));
            return;
        }
        out.extend(n);
    }

    /// `phrase { "|" phrase }`
    fn union(&mut self, out: &mut Vec<SyntaxElement>) {
        let mut n = Vec::new();
        self.phrase(&mut n);
        let mut seps = 0;
        while self.peek().is_some_and(|t| t.kind == SyntaxKind::Pipe) {
            self.flush(&mut n);
            n.push(self.bump());
            seps += 1;
            self.drain_trivia(&mut n);
            let before = n.len();
            self.phrase(&mut n);
            if n.len() == before {
                self.missing_operand("|");
            }
        }
        if seps > 0 {
            out.push(node(SyntaxKind::Union, n));
        } else {
            out.extend(n);
        }
    }

    /// `atom { atom }` — juxtaposition.
    fn phrase(&mut self, out: &mut Vec<SyntaxElement>) {
        let mut n = Vec::new();
        loop {
            match self.peek() {
                Some(t)
                    if matches!(
                        t.kind,
                        SyntaxKind::WordText
                            | SyntaxKind::LBrace
                            | SyntaxKind::Quote
                            | SyntaxKind::LParen
                    ) =>
                {
                    self.atom(&mut n);
                }
                _ => break,
            }
        }
        if n.is_empty() {
            out.extend(n);
        } else {
            out.push(node(SyntaxKind::Phrase, n));
        }
    }

    fn atom(&mut self, out: &mut Vec<SyntaxElement>) {
        // Trivia before the atom belongs to the enclosing phrase, not to the
        // atom's own node (a word's span must start at its text).
        self.flush(out);
        match self.peek_kind() {
            SyntaxKind::Quote => {
                let mut n = Vec::new();
                n.push(self.bump());
                // A string never spans lines (the lexer recovers at the
                // newline), so its parts are contiguous: read the stream
                // directly, since `peek()` would park skipped trivia in
                // `pending` and flush it after this node, reordering bytes.
                loop {
                    if self.i >= self.end {
                        break;
                    }
                    match self.toks.get(self.i).map(|t| t.kind) {
                        Some(SyntaxKind::Quote) => {
                            n.push(self.bump());
                            break;
                        }
                        Some(SyntaxKind::StringText) => n.push(self.bump()),
                        Some(SyntaxKind::LBrace) => self.interp(&mut n, SyntaxKind::StringText),
                        Some(SyntaxKind::RBrace) => n.push(self.bump()),
                        _ => break, // unclosed: the lexer already reported it
                    }
                }
                out.push(node(SyntaxKind::String, n));
            }
            SyntaxKind::LParen => {
                if self.depth >= MAX_DEPTH {
                    // Nesting cap: keep the `(` as an empty group (round-trip
                    // preserved) and let `finish` mop up what follows instead
                    // of recursing.
                    self.flush(out);
                    let end = self.peek().map_or(0, |t| t.end);
                    self.diag(Span::point(end), "expression nests too deep");
                    let paren = self.bump();
                    out.push(node(SyntaxKind::Paren, vec![paren]));
                    return;
                }
                let open = self.peek();
                let (open_start, open_end) = open.map_or((0, 0), |t| (t.start, t.end));
                let mut n = Vec::new();
                n.push(self.bump());
                self.drain_trivia(&mut n);
                let before = n.len();
                self.depth += 1;
                self.value(&mut n);
                self.depth -= 1;
                let had_value = n.len() > before;
                if self.peek().is_some_and(|t| t.kind == SyntaxKind::RParen) {
                    self.flush(&mut n);
                    n.push(self.bump());
                } else if had_value {
                    self.diag(Span::point(open_end), "missing `)`");
                }
                if !had_value {
                    // `()` — closed or not — holds no value; the span covers
                    // the parens (or the lone `(` when unclosed).
                    self.diag_hint(
                        Span::new(open_start, self.last_end()),
                        "empty `()`",
                        "put a value inside, like `(a or b)`",
                    );
                }
                out.push(node(SyntaxKind::Paren, n));
            }
            _ => {
                // A bare scalar, possibly with interpolations. Word parts
                // are contiguous tokens, so inspect the stream directly:
                // `peek()` would skip trivia and glue `push main` together.
                let mut n = Vec::new();
                loop {
                    match self.toks.get(self.i).map(|t| t.kind) {
                        // The stream is read directly (peek() would skip the
                        // trivia that glues word parts together), so the
                        // region bound has to be checked by hand.
                        Some(SyntaxKind::WordText) if self.i < self.end => n.push(self.bump()),
                        Some(SyntaxKind::LBrace) if self.i < self.end => {
                            self.interp(&mut n, SyntaxKind::WordText)
                        }
                        _ => break,
                    }
                }
                out.push(node(SyntaxKind::Word, n));
            }
        }
    }

    /// An interpolation group: `LBRACE` name `RBRACE`.
    fn interp(&mut self, out: &mut Vec<SyntaxElement>, text_kind: SyntaxKind) {
        let mut n = Vec::new();
        n.push(self.bump()); // LBRACE
        // The lexer emits the name text and `}` contiguously with the brace:
        // read the stream directly, since `peek()` would park any trivia it
        // skips in `pending` and flush it after this node, reordering bytes
        // when the `{` is unclosed and stray text follows.
        while self.i < self.end && self.toks.get(self.i).is_some_and(|t| t.kind == text_kind) {
            n.push(self.bump());
        }
        if self.i < self.end && self.toks.get(self.i).is_some_and(|t| t.kind == SyntaxKind::RBrace)
        {
            n.push(self.bump());
        }
        out.push(node(SyntaxKind::Interp, n));
    }

    /// The kind of the next non-trivia token, without consuming trivia.
    fn peek_kind(&mut self) -> SyntaxKind {
        self.peek().map_or(SyntaxKind::Whitespace, |t| t.kind)
    }

    // --- plumbing ---------------------------------------------------------

    fn peek(&mut self) -> Option<Tok> {
        while self.i < self.end && self.toks[self.i].kind.is_trivia() {
            self.pending.push(token_elem(self.src, &self.toks[self.i]));
            self.i += 1;
        }
        if self.i < self.end { Some(self.toks[self.i]) } else { None }
    }

    fn bump(&mut self) -> SyntaxElement {
        let el = token_elem(self.src, &self.toks[self.i]);
        self.i += 1;
        el
    }

    fn flush(&mut self, into: &mut Vec<SyntaxElement>) {
        into.append(&mut self.pending);
    }

    /// Trivia directly after a separator belongs to the enclosing node, not
    /// to whatever atom follows.
    fn drain_trivia(&mut self, into: &mut Vec<SyntaxElement>) {
        while self.i < self.end && self.toks[self.i].kind.is_trivia() {
            into.push(token_elem(self.src, &self.toks[self.i]));
            self.i += 1;
        }
    }

    fn text(&self, t: Tok) -> &str {
        Span::new(t.start, t.end).slice(self.src)
    }

    fn at_op(&mut self, op: &str) -> bool {
        self.peek().is_some_and(|t| t.kind == SyntaxKind::Op && self.text(t) == op)
    }

    fn at_keyword(&mut self, kw: &str) -> bool {
        self.peek().is_some_and(|t| t.kind == SyntaxKind::Keyword && self.text(t) == kw)
    }

    fn diag(&mut self, span: Span, message: impl Into<String>) {
        if !self.suppress {
            self.diags.push(Diagnostic::error(span, message));
        }
    }

    fn diag_hint(&mut self, span: Span, message: impl Into<String>, hint: impl Into<String>) {
        if !self.suppress {
            self.diags.push(Diagnostic::error(span, message).with_hint(hint));
        }
    }

    /// After an operator, flag an empty right-hand side.
    fn missing_after(&mut self, produced: &[SyntaxElement], op: &str) {
        if produced.is_empty() {
            self.diag(Span::point(self.last_end()), format!("missing value after `{op}`"));
        }
    }

    fn missing_operand(&mut self, op: &str) {
        self.diag(Span::point(self.last_end()), format!("missing operand after `{op}`"));
    }

    /// End offset of the last token consumed, or the region start.
    fn last_end(&self) -> u32 {
        if self.i > self.start {
            self.toks[self.i - 1].end
        } else {
            self.toks.first().map_or(0, |t| t.start)
        }
    }

    /// Leftover tokens the grammar could not place: one diagnostic, then the
    /// rest are kept silently (they are still in the tree).
    fn finish(&mut self, out: &mut Vec<SyntaxElement>) {
        let mut first = true;
        while let Some(t) = self.peek() {
            if first && !self.suppress {
                let text = self.text(t).to_string();
                let span = Span::new(t.start, t.end);
                self.diags.push(
                    Diagnostic::error(span, format!("unexpected `{text}`"))
                        .with_hint("check the value grammar in docs/LANGUAGE.md"),
                );
                first = false;
            }
            self.flush(out);
            out.push(self.bump());
        }
        self.flush(out);
    }
}
