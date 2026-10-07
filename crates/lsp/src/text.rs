//! Byte offsets to LSP positions. Spans are byte offsets into the source
//! ([`ks_lang::Span`]); LSP positions are line/character pairs counted in
//! UTF-16 code units unless the client negotiated UTF-8, so the conversion
//! needs a line index and a character width.

/// How a client counts the characters in a line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Encoding {
    /// The LSP default: one unit per UTF-16 code unit.
    #[default]
    Utf16,
    /// One unit per byte.
    Utf8,
}

/// An LSP position, before it is serialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub line: u32,
    pub character: u32,
}

impl Position {
    /// The JSON shape clients read.
    pub fn to_json(self) -> serde_json::Value {
        serde_json::json!({ "line": self.line, "character": self.character })
    }
}

/// A half-open [`ks_lang::Span`] as an LSP range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

impl Range {
    pub fn to_json(self) -> serde_json::Value {
        serde_json::json!({ "start": self.start.to_json(), "end": self.end.to_json() })
    }
}

/// The byte offset of every line start in a file, plus the encoding the
/// client speaks. Built once per document version.
pub struct LineIndex {
    starts: Vec<u32>,
    encoding: Encoding,
}

impl LineIndex {
    pub fn new(src: &str, encoding: Encoding) -> LineIndex {
        let mut starts = vec![0u32];
        starts.extend(src.match_indices('\n').map(|(i, _)| (i + 1) as u32));
        LineIndex { starts, encoding }
    }

    /// The position of a byte offset. An offset past the end (or inside a
    /// multi-byte character) clamps to the nearest position rather than
    /// failing: a client is allowed to send either.
    pub fn position(&self, src: &str, offset: u32) -> Position {
        let offset = clamp(src, offset);
        let line = self.line_of(offset);
        let start = self.starts[line] as usize;
        let end = (offset as usize).min(self.line_end(src, line));
        let slice = &src[start..end];
        Position { line: line as u32, character: self.width(slice) }
    }

    /// The byte offset of a position. A character index past the end of its
    /// line stops at the line's end (before the newline).
    pub fn offset(&self, src: &str, position: Position) -> u32 {
        let line = (position.line as usize).min(self.starts.len() - 1);
        let start = self.starts[line] as usize;
        let end = self.line_end(src, line);
        let mut seen = 0u32;
        for (i, c) in src[start..end].char_indices() {
            if seen >= position.character {
                return (start + i) as u32;
            }
            seen += self.char_width(c);
        }
        end as u32
    }

    /// The text of the line containing `offset`, without its line
    /// terminator.
    pub fn line_text<'src>(&self, src: &'src str, offset: u32) -> &'src str {
        let line = self.line_of(clamp(src, offset));
        &src[self.starts[line] as usize..self.line_end(src, line)]
    }

    /// The byte offset where the line containing `offset` begins.
    pub fn line_start(&self, offset: u32) -> u32 {
        self.starts[self.line_of(offset)]
    }

    /// The comment lines directly above the one containing `offset`, as
    /// written, newest last. Empty when the line above is not a comment.
    pub fn comments_above<'src>(&self, src: &'src str, offset: u32) -> Vec<&'src str> {
        let mut line = self.line_of(clamp(src, offset));
        let mut out = Vec::new();
        while line > 0 {
            line -= 1;
            let text = self.line_text(src, self.starts[line]).trim();
            let Some(rest) = text.strip_prefix('#') else { break };
            out.push(rest.trim());
        }
        out.reverse();
        out
    }

    fn line_of(&self, offset: u32) -> usize {
        match self.starts.binary_search(&offset) {
            Ok(line) => line,
            Err(next) => next - 1,
        }
    }

    /// Where the content of line `line` ends, before its line terminator.
    /// LSP reads `\r\n` as one terminator, so the `\r` is not part of the
    /// line's text and no position lands on it.
    fn line_end(&self, src: &str, line: usize) -> usize {
        let start = self.starts[line] as usize;
        let end = src[start..].find('\n').map_or(src.len(), |i| start + i);
        if src[..end].ends_with('\r') { end - 1 } else { end }
    }

    fn width(&self, text: &str) -> u32 {
        match self.encoding {
            Encoding::Utf16 => text.chars().map(|c| c.len_utf16() as u32).sum(),
            Encoding::Utf8 => text.len() as u32,
        }
    }

    fn char_width(&self, c: char) -> u32 {
        match self.encoding {
            Encoding::Utf16 => c.len_utf16() as u32,
            Encoding::Utf8 => c.len_utf8() as u32,
        }
    }
}

/// The largest offset `<= offset` that starts a character (`src.len()` past
/// the end), so a client offset in the middle of a character still resolves.
pub fn clamp(src: &str, offset: u32) -> u32 {
    let mut offset = (offset as usize).min(src.len());
    while !src.is_char_boundary(offset) {
        offset -= 1;
    }
    offset as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const UTF8: &str = "héllo\n  ✓: true\n";

    #[test]
    fn positions_count_utf16_code_units_by_default() {
        let index = LineIndex::new(UTF8, Encoding::Utf16);
        let at = UTF8.find("ll").expect("the word") as u32;
        assert_eq!(index.position(UTF8, at), Position { line: 0, character: 2 });
        assert_eq!(index.position(UTF8, at + 1), Position { line: 0, character: 3 });
        // `é` is one UTF-16 unit but two bytes.
        assert_eq!(
            index.position(UTF8, UTF8.find('l').expect("l") as u32),
            Position { line: 0, character: 2 }
        );
    }

    #[test]
    fn positions_count_bytes_when_the_client_says_utf8() {
        let index = LineIndex::new(UTF8, Encoding::Utf8);
        let at = UTF8.find("ll").expect("the word") as u32;
        assert_eq!(index.position(UTF8, at), Position { line: 0, character: 3 });
    }

    #[test]
    fn offsets_round_trip_through_both_encodings() {
        for encoding in [Encoding::Utf16, Encoding::Utf8] {
            let index = LineIndex::new(UTF8, encoding);
            for offset in 0..=UTF8.len() as u32 {
                let at = clamp(UTF8, offset);
                assert_eq!(index.offset(UTF8, index.position(UTF8, at)), at, "{encoding:?}");
            }
        }
    }

    #[test]
    fn offsets_past_a_line_end_stop_before_the_newline() {
        let index = LineIndex::new(UTF8, Encoding::Utf16);
        let end = index.offset(UTF8, Position { line: 0, character: 99 });
        assert_eq!(&UTF8[end as usize..end as usize + 1], "\n");
        // A line past the end of the file clamps to the file's length.
        assert_eq!(index.offset(UTF8, Position { line: 99, character: 0 }), UTF8.len() as u32);
    }

    #[test]
    fn an_offset_inside_a_character_clamps_back_to_its_start() {
        let index = LineIndex::new(UTF8, Encoding::Utf16);
        let start = UTF8.find('é').expect("e-acute") as u32;
        assert_eq!(index.position(UTF8, start + 1), Position { line: 0, character: 1 });
    }

    #[test]
    fn comments_above_a_line_are_collected_bottom_up() {
        let src = "# the api image\n# pushed to ghcr\n  build: oci.image\n    from: ./Dockerfile\n";
        let index = LineIndex::new(src, Encoding::Utf16);
        let at = src.find("oci.image").expect("the header") as u32;
        assert_eq!(index.comments_above(src, at), ["the api image", "pushed to ghcr"]);
    }

    #[test]
    fn comments_stop_at_the_first_non_comment_line() {
        let src = "steps:\n  build: oci.image\n";
        let index = LineIndex::new(src, Encoding::Utf16);
        assert!(index.comments_above(src, src.find("oci.image").expect("kind") as u32).is_empty());
    }

    #[test]
    fn a_crlf_terminator_is_not_part_of_its_line() {
        let src = "  build: oci.image\r\n    from: ./Dockerfile\r\n";
        let index = LineIndex::new(src, Encoding::Utf16);
        assert_eq!(index.line_text(src, 0), "  build: oci.image");
        // A column past the text stops before the `\r`.
        let end = index.offset(src, Position { line: 0, character: 99 });
        assert_eq!(&src[end as usize..end as usize + 2], "\r\n");
        assert_eq!(index.position(src, end), Position { line: 0, character: 18 });
        // Every byte that is not a terminator round trips.
        for offset in 0..=src.len() as u32 {
            let at = clamp(src, offset);
            if src.as_bytes().get(at as usize) == Some(&b'\n') {
                continue;
            }
            assert_eq!(index.offset(src, index.position(src, at)), at);
        }
    }
}
