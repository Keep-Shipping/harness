//! Lexer: turns source into a flat token list covering every byte.
//!
//! Line-oriented. A line is an optional `INDENT`, content tokens, optional
//! trivia (whitespace, comment) and a `NEWLINE`. Value-level tokens are
//! recognised only here; the parser groups them into nodes.

use crate::diagnostic::{Code, Diagnostic, Span};
use crate::syntax::SyntaxKind;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Tok {
    pub kind: SyntaxKind,
    pub start: u32,
    pub end: u32,
}

pub(crate) struct Lexed {
    pub tokens: Vec<Tok>,
    pub errors: Vec<Diagnostic>,
}

pub(crate) fn lex(src: &str) -> Lexed {
    Lexer { src, pos: 0, tokens: Vec::new(), errors: Vec::new() }.run()
}

struct Lexer<'src> {
    src: &'src str,
    pos: usize,
    tokens: Vec<Tok>,
    errors: Vec<Diagnostic>,
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

impl<'src> Lexer<'src> {
    fn run(mut self) -> Lexed {
        loop {
            // A byte-order mark is pure trivia: kept in the tree (the CST is
            // lossless) but kept out of keys and words.
            while self.cur() == Some('\u{FEFF}') {
                let start = self.pos;
                self.pos += '\u{FEFF}'.len_utf8();
                self.push(SyntaxKind::Whitespace, start, self.pos);
            }
            // Indentation.
            let ind_start = self.pos;
            while matches!(self.cur(), Some(' ') | Some('\t')) {
                self.pos += 1;
            }
            if self.pos > ind_start {
                if self.at_line_end() {
                    // Trailing whitespace on a blank line is plain trivia.
                    self.push(SyntaxKind::Whitespace, ind_start, self.pos);
                } else {
                    let has_tab = self.src[ind_start..self.pos].contains('\t');
                    self.push(SyntaxKind::Indent, ind_start, self.pos);
                    if has_tab {
                        self.errors.push(
                            Diagnostic::error(
                                Code::TabIndent,
                                Span::new(ind_start as u32, self.pos as u32),
                                "tab in indentation",
                            )
                            .with_hint("indent with spaces; `keepshipping fmt` converts tabs"),
                        );
                    }
                }
            }
            if self.cur().is_none() {
                break;
            }
            if self.at_line_end() {
                self.newline();
                continue;
            }

            // Content.
            let mut prev: Option<SyntaxKind> =
                if self.pos > ind_start { Some(SyntaxKind::Indent) } else { None };
            if matches!(prev, None | Some(SyntaxKind::Indent))
                && let Some(colon) = self.try_key()
            {
                self.push(SyntaxKind::Key, self.pos, colon);
                self.pos = colon + 1; // the colon, known to exist
                self.push(SyntaxKind::Colon, colon, self.pos);
                prev = Some(SyntaxKind::Colon);
            }
            loop {
                match self.cur() {
                    None => return self.finish(),
                    Some('\n') | Some('\r') if self.at_line_end() => {
                        self.newline();
                        break;
                    }
                    Some(' ') | Some('\r') | Some('\t') => prev = self.whitespace(),
                    Some('#')
                        if matches!(
                            prev,
                            None | Some(SyntaxKind::Whitespace | SyntaxKind::Indent)
                        ) =>
                    {
                        prev = Some(SyntaxKind::Comment);
                        self.comment();
                    }
                    Some(',') => {
                        prev = Some(SyntaxKind::Comma);
                        self.single(SyntaxKind::Comma);
                    }
                    Some('|') => {
                        prev = Some(SyntaxKind::Pipe);
                        self.single(SyntaxKind::Pipe);
                    }
                    Some('(') => {
                        prev = Some(SyntaxKind::LParen);
                        self.single(SyntaxKind::LParen);
                    }
                    Some(')') => {
                        prev = Some(SyntaxKind::RParen);
                        self.single(SyntaxKind::RParen);
                    }
                    Some('"') => {
                        prev = self.string();
                    }
                    _ => {
                        prev = self.op_or_word(prev);
                    }
                }
            }
        }
        self.finish()
    }

    fn finish(self) -> Lexed {
        Lexed { tokens: self.tokens, errors: self.errors }
    }

    fn cur(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn at_line_end(&self) -> bool {
        match self.cur() {
            None => true,
            Some('\n') => true,
            Some('\r') => self.src[self.pos..].starts_with("\r\n"),
            _ => false,
        }
    }

    fn newline(&mut self) {
        let start = self.pos;
        self.pos += if self.src[self.pos..].starts_with("\r\n") { 2 } else { 1 };
        self.push(SyntaxKind::Newline, start, self.pos);
    }

    fn push(&mut self, kind: SyntaxKind, start: usize, end: usize) {
        self.tokens.push(Tok { kind, start: start as u32, end: end as u32 });
    }

    fn single(&mut self, kind: SyntaxKind) {
        let start = self.pos;
        self.pos += 1;
        self.push(kind, start, self.pos);
    }

    fn whitespace(&mut self) -> Option<SyntaxKind> {
        let start = self.pos;
        let mut tab = false;
        while let Some(c) = self.cur() {
            if c == '\t' {
                tab = true;
                self.pos += 1;
            } else if c == ' ' || (c == '\r' && !self.at_line_end()) {
                self.pos += 1;
            } else {
                break;
            }
        }
        if tab {
            self.errors.push(
                Diagnostic::error(
                    Code::TabIndent,
                    Span::new(start as u32, self.pos as u32),
                    "tab outside a string",
                )
                .with_hint("use spaces; `keepshipping fmt` converts tabs"),
            );
        }
        self.push(SyntaxKind::Whitespace, start, self.pos);
        Some(SyntaxKind::Whitespace)
    }

    fn comment(&mut self) {
        let start = self.pos;
        while !self.at_line_end() {
            self.pos += self.cur().map_or(1, char::len_utf8);
        }
        self.push(SyntaxKind::Comment, start, self.pos);
    }

    /// `key:` where the colon is followed by whitespace, a comment or the end
    /// of the line. Returns the offset of the colon.
    fn try_key(&self) -> Option<usize> {
        let bytes = self.src.as_bytes();
        let mut i = self.pos;
        let first = self.src[i..].chars().next()?;
        if !is_ident_start(first) {
            return None;
        }
        i += first.len_utf8();
        while let Some(&b) = bytes.get(i) {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                i += 1;
            } else {
                break;
            }
        }
        if bytes.get(i) != Some(&b':') {
            return None;
        }
        match bytes.get(i + 1) {
            None => Some(i),
            Some(&b) if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == b'#' => Some(i),
            _ => None,
        }
    }

    fn string(&mut self) -> Option<SyntaxKind> {
        let open = self.pos;
        self.single(SyntaxKind::Quote);
        let mut text_start = self.pos;
        loop {
            match self.cur() {
                None => {
                    self.flush_text(SyntaxKind::StringText, text_start);
                    self.errors.push(
                        Diagnostic::error(
                            Code::Unclosed,
                            Span::new(open as u32, self.pos as u32),
                            "unclosed string",
                        )
                        .with_hint("add a closing `\"` before the end of the line"),
                    );
                    return Some(SyntaxKind::String);
                }
                Some(_) if self.at_line_end() => {
                    self.flush_text(SyntaxKind::StringText, text_start);
                    self.errors.push(
                        Diagnostic::error(
                            Code::Unclosed,
                            Span::new(open as u32, self.pos as u32),
                            "unclosed string",
                        )
                        .with_hint("add a closing `\"` before the end of the line"),
                    );
                    return Some(SyntaxKind::String);
                }
                Some('"') => {
                    self.flush_text(SyntaxKind::StringText, text_start);
                    self.single(SyntaxKind::Quote);
                    return Some(SyntaxKind::String);
                }
                Some('\\') => {
                    match self.src[self.pos + 1..].chars().next() {
                        Some(c) if !matches!(c, '\n' | '\r') => self.pos += 1 + c.len_utf8(),
                        _ => self.pos += 1, // a trailing `\` is literal text
                    }
                }
                Some('{') => {
                    self.flush_text(SyntaxKind::StringText, text_start);
                    self.interp(false);
                    text_start = self.pos;
                }
                _ => self.pos += self.cur().map_or(1, char::len_utf8),
            }
        }
    }

    /// An interpolation `{name}`: `LBRACE`, the raw name text, `RBRACE`.
    /// Unclosed braces recover at the end of the line; the raw text is kept
    /// either way.
    fn interp(&mut self, word: bool) {
        let kind = if word { SyntaxKind::WordText } else { SyntaxKind::StringText };
        let brace = self.pos;
        self.single(SyntaxKind::LBrace);
        let mid_start = self.pos;
        let mut mid_end = mid_start;
        loop {
            match self.cur() {
                None | Some('\n') | Some('\r') => break,
                Some('}') => break,
                _ => {
                    self.pos += self.cur().map_or(1, char::len_utf8);
                    mid_end = self.pos;
                }
            }
        }
        let closed = self.cur() == Some('}');
        if mid_end > mid_start {
            let text = &self.src[mid_start..mid_end];
            self.push(kind, mid_start, mid_end);
            if !is_dotted_name(text) {
                self.errors.push(
                    Diagnostic::error(
                        Code::BadInterp,
                        Span::new(mid_start as u32, mid_end as u32),
                        format!("invalid interpolation name `{text}`"),
                    )
                    .with_hint("use a dotted name like {git.sha}, without spaces"),
                );
            }
        } else if closed {
            self.errors.push(
                Diagnostic::error(
                    Code::BadInterp,
                    Span::new(brace as u32, mid_end as u32),
                    "empty interpolation",
                )
                .with_hint("put a dotted name inside, like {git.sha}"),
            );
        }
        if closed {
            self.single(SyntaxKind::RBrace);
        } else {
            self.errors.push(
                Diagnostic::error(
                    Code::Unclosed,
                    Span::new(brace as u32, self.pos as u32),
                    "unclosed `{`",
                )
                .with_hint("add a closing `}`"),
            );
        }
    }

    /// An operator only counts when it stands alone as a whitespace-delimited
    /// word; otherwise its characters are part of a bare scalar.
    fn op_or_word(&mut self, prev: Option<SyntaxKind>) -> Option<SyntaxKind> {
        let left_boundary = matches!(
            prev,
            None | Some(
                SyntaxKind::Whitespace
                    | SyntaxKind::Indent
                    | SyntaxKind::LParen
                    | SyntaxKind::Comma
                    | SyntaxKind::Pipe
            )
        );
        if left_boundary && let Some(len) = self.op_at(self.pos) {
            let after = self.pos + len;
            let boundary = match self.src[after..].chars().next() {
                None => true,
                Some(c) => matches!(c, ' ' | '\t' | '\n' | '\r' | ',' | '|' | '(' | ')'),
            };
            if boundary {
                self.push(SyntaxKind::Op, self.pos, after);
                self.pos = after;
                return Some(SyntaxKind::Op);
            }
        }
        self.word()
    }

    /// Longest operator match at `at`: two-character forms first.
    fn op_at(&self, at: usize) -> Option<usize> {
        let rest = &self.src[at..];
        for op in ["==", "!=", ">=", "<=", "\u{2265}", "\u{2264}"] {
            if rest.starts_with(op) {
                return Some(op.len());
            }
        }
        for op in ["<", ">", "="] {
            if rest.starts_with(op) {
                return Some(op.len());
            }
        }
        None
    }

    /// A bare scalar: a maximal run of non-terminator characters, possibly
    /// containing `{name}` interpolations. `and`, `or`, `not` and `is` are
    /// reserved and come back as `Keyword`.
    fn word(&mut self) -> Option<SyntaxKind> {
        let start = self.pos;
        let mut text_start = self.pos;
        loop {
            match self.cur() {
                None | Some(' ') | Some('\t') | Some('\n') | Some('\r') | Some(',') | Some('|')
                | Some('(') | Some(')') | Some('"') => break,
                // A `#` inside a word is part of it; only the caller decides
                // whether a token-initial `#` starts a comment.
                Some('#') => self.pos += 1,
                Some('{') => {
                    self.flush_text(SyntaxKind::WordText, text_start);
                    self.interp(true);
                    text_start = self.pos;
                }
                _ => self.pos += self.cur().map_or(1, char::len_utf8),
            }
        }
        self.flush_text(SyntaxKind::WordText, text_start);
        let text = &self.src[start..self.pos];
        if self
            .tokens
            .last()
            .is_some_and(|t| t.kind == SyntaxKind::WordText && t.start as usize == start)
            && matches!(text, "and" | "or" | "not" | "is")
        {
            let last = self.tokens.last_mut().expect("checked above");
            last.kind = SyntaxKind::Keyword;
            return Some(SyntaxKind::Keyword);
        }
        Some(SyntaxKind::Word)
    }

    fn flush_text(&mut self, kind: SyntaxKind, start: usize) {
        if self.pos > start {
            self.push(kind, start, self.pos);
        }
    }
}

/// A dotted name: `ident` or `ident(.ident)+` with the same ident rules as
/// keys. Also the shape accepted inside `{…}` interpolations.
pub(crate) fn is_dotted_name(text: &str) -> bool {
    let mut segs = text.split('.');
    match segs.next() {
        Some(first) if is_ident(first) => {}
        _ => return false,
    }
    segs.all(is_ident)
}

pub(crate) fn is_ident(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(c) if is_ident_start(c) => {}
        _ => return false,
    }
    chars.all(is_ident_char)
}
