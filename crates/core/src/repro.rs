//! Reproducibility scan for Dockerfiles: the inputs that decide whether two
//! builds of the same file produce the same image. Everything here is pure —
//! the text in, [`Diagnostic`]s out — so `ks-core` stays I/O-free and the CLI
//! decides which files to scan ([ADR
//! 0010](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0010-image-build-backend.md)).
//!
//! The rules, all [`Code::NonReproducible`] warnings:
//!
//! - `FROM <image>` names an image without a `@sha256:` digest. `FROM
//!   scratch` has no input, and `FROM <stage>` names an earlier build stage,
//!   whose bytes the first `FROM` already fixed. An `ARG`-interpolated image
//!   (`FROM ${BASE}`) cannot be read here and is treated as unpinned: the
//!   value only exists at build time, and an unpinned tag there is the same
//!   defect, one step removed.
//! - `RUN … apt-get update` (or `apt update`) reads a package index that is
//!   rewritten in place. It counts as pinned when the instruction, or any
//!   other instruction in the same file, mentions `snapshot.debian.org`,
//!   `snapshot.ubuntu.com` or a `--snapshot` option — an earlier `RUN` may
//!   have pointed `sources.list` at a snapshot. A comment naming a snapshot
//!   is a comment: it changes nothing.
//! - `ADD https://…` fetches bytes over a URL the author does not control.
//!   `ADD --checksum=sha256:…` pins them and is left alone.
//!
//! Parsing is deliberately shallow: instructions are joined across `\`
//! continuations, heredoc bodies are read as the data they are, comments and
//! parser directives are skipped, and keywords match case-insensitively, as
//! Dockerfile specifies. Anything subtler is Docker's business, not the
//! checker's.

use ks_lang::{Code, Diagnostic, Span};

/// The snapshot hosts and options that count as pinning an `apt` index.
const SNAPSHOT_MARKERS: [&str; 3] = ["snapshot.debian.org", "snapshot.ubuntu.com", "--snapshot"];

/// Every reproducibility warning `src` earns, in source order.
#[must_use]
pub fn scan_dockerfile(src: &str) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let mut stages: Vec<String> = Vec::new();
    let insts = instructions(src);
    // A snapshot named by any instruction in the file may be set up by an
    // earlier `RUN`; from then on every index the file updates is pinned. A
    // comment is not an instruction and pins nothing.
    let snapshot_file = insts.iter().any(|i| i.args.mentions_snapshot());
    for inst in &insts {
        match inst.keyword.as_str() {
            "from" => from(inst, &mut stages, &mut out),
            "run" if !snapshot_file && !inst.args.mentions_snapshot() => apt(inst, &mut out),
            "add" => add(inst, &mut out),
            _ => {}
        }
    }
    out
}

/// `FROM`: the image must be pinned to a digest. `scratch` has no input, and
/// an image that names an earlier stage inherits that stage's bytes.
fn from(inst: &Instruction, stages: &mut Vec<String>, out: &mut Vec<Diagnostic>) {
    let tokens = inst.args.tokens();
    let Some(first) = tokens.iter().position(|(_, t)| !t.starts_with("--")) else { return };
    let (at, image) = tokens[first];
    let alias = tokens
        .get(first + 1)
        .filter(|(_, t)| t.eq_ignore_ascii_case("as"))
        .and_then(|_| tokens.get(first + 2).map(|(_, name)| name.to_string()));
    let inherited = image.eq_ignore_ascii_case("scratch")
        || stages.iter().any(|s| s.eq_ignore_ascii_case(image));
    if let Some(name) = alias {
        stages.push(name);
    }
    if inherited || image.contains("@sha256:") {
        return;
    }
    let span = inst.args.span_of(at, image.len());
    out.push(
        Diagnostic::warning(
            Code::NonReproducible,
            span,
            format!("`FROM {image}` is not pinned to a digest"),
        )
        .with_hint(format!(
            "pin it: `FROM {image}@sha256:…`; a tag can move \
             between two builds"
        )),
    );
}

/// `RUN … apt-get update`: an index rewritten in place is a moving input.
fn apt(inst: &Instruction, out: &mut Vec<Diagnostic>) {
    // `apt-get` first: `apt update` is a different command, and neither is a
    // substring of the other.
    for cmd in ["apt-get", "apt"] {
        for at in inst.args.find_commands(cmd) {
            // Options may sit between the command and its subcommand
            // (`apt-get -y update`), so the subcommand is the first bare word
            // after it, not the next thing on the line.
            let rest = &inst.args.text[at + cmd.len()..];
            let Some(sub) = rest.split_whitespace().find(|w| !w.starts_with('-')) else {
                continue;
            };
            if sub != "update" {
                continue;
            }
            let sub_at = rest.find(sub).expect("split out of the same text");
            let span = inst.args.span_of(at, cmd.len() + sub_at + sub.len());
            out.push(
                Diagnostic::warning(
                    Code::NonReproducible,
                    span,
                    format!("`{cmd} update` is not pinned to a snapshot"),
                )
                .with_hint(
                    "read the index from snapshot.debian.org (or snapshot.ubuntu.com), \
                     or pass `--snapshot=`; the packages it names change between builds",
                ),
            );
            return;
        }
    }
}

/// `ADD <url>`: the bytes behind a URL can change; `--checksum=` fixes them.
fn add(inst: &Instruction, out: &mut Vec<Diagnostic>) {
    let tokens = inst.args.tokens();
    if tokens.iter().any(|(_, t)| t.starts_with("--checksum=")) {
        return;
    }
    let Some(&(at, url)) =
        tokens.iter().find(|(_, t)| t.starts_with("http://") || t.starts_with("https://"))
    else {
        return;
    };
    out.push(
        Diagnostic::warning(
            Code::NonReproducible,
            inst.args.span_of(at, url.len()),
            format!("`ADD {url}` has no checksum"),
        )
        .with_hint("add `--checksum=sha256:…`; the URL can serve different bytes tomorrow"),
    );
}

/// One logical instruction: its keyword, and its arguments with `\`
/// continuations joined back into one line.
struct Instruction {
    keyword: String,
    args: Joined,
}

/// An instruction's arguments, continuations joined, keeping a map from every
/// byte of the joined text back to its offset in the Dockerfile — so a
/// finding can be reported at the place it was written, not at the join.
struct Joined {
    text: String,
    offsets: Vec<u32>,
}

impl Joined {
    /// Whitespace, a continuation `\` and the newline after it all collapse to
    /// one space, exactly as the builder reads them; so do runs of spaces.
    fn new(src: &str, from: usize, to: usize) -> Self {
        let bytes = src.as_bytes();
        let mut text: Vec<u8> = Vec::new();
        let mut offsets: Vec<u32> = Vec::new();
        let mut i = from;
        while i < to {
            if bytes[i].is_ascii_whitespace() || bytes[i] == b'\\' {
                let at = i;
                i += 1;
                while i < to && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                text.push(b' ');
                offsets.push(at as u32);
                continue;
            }
            text.push(bytes[i]);
            offsets.push(i as u32);
            i += 1;
        }
        // `to` never splits a character and the bytes came from a `&str`, so
        // this cannot fail; the lossy arm is here rather than a panic.
        let text = String::from_utf8(text)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
        Self { text, offsets }
    }

    /// The instruction's arguments split on spaces, with each token's start
    /// offset in the joined text.
    fn tokens(&self) -> Vec<(usize, &str)> {
        let mut out = Vec::new();
        let mut start = 0;
        for at in self.text.bytes().enumerate().filter(|(_, b)| *b == b' ').map(|(i, _)| i) {
            if at > start {
                out.push((start, &self.text[start..at]));
            }
            start = at + 1;
        }
        if start < self.text.len() {
            out.push((start, &self.text[start..]));
        }
        out
    }

    /// The source span of `len` bytes of the joined text, from `at`.
    fn span_of(&self, at: usize, len: usize) -> Span {
        let start = self.offsets[at];
        // Every needle ends where a word ends, so its last byte is a
        // character's last byte and the byte after it starts one.
        let end = self.offsets[at + len - 1] + 1;
        Span::new(start, end)
    }

    /// Every place `cmd` appears as a command — preceded by nothing but the
    /// start of the instruction, a space or a shell separator, so
    /// `xapt-get update` inside an `echo` is not a match.
    fn find_commands(&self, cmd: &str) -> Vec<usize> {
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(at) = self.text[from..].find(cmd) {
            let at = from + at;
            let before = self.text[..at].chars().next_back();
            if before.is_none_or(|c| c == ' ' || ";&|(".contains(c)) {
                out.push(at);
            }
            from = at + 1;
        }
        out
    }

    /// The word that closes a heredoc the instruction opens (`RUN <<EOF`).
    /// Docker's marker is `<<`, an optional `-`, an optional quote and the
    /// word; a bare `<<`, as in `echo "a << b"`, opens nothing.
    fn heredoc(&self) -> Option<&str> {
        let (_, marker) = self.tokens().into_iter().find(|(_, t)| t.starts_with("<<"))?;
        let word = marker[2..].trim_start_matches('-').trim_matches(['"', '\'']);
        (!word.is_empty() && word.chars().all(|c| c.is_alphanumeric() || c == '_')).then_some(word)
    }

    fn mentions_snapshot(&self) -> bool {
        SNAPSHOT_MARKERS.iter().any(|m| self.text.contains(m))
    }
}

/// Every instruction in `src`, comments and directives skipped, in order.
fn instructions(src: &str) -> Vec<Instruction> {
    let mut lines = Vec::new();
    let mut at = 0;
    for line in src.split_inclusive('\n') {
        let end = at + line.trim_end_matches(['\n', '\r']).len();
        lines.push((at as u32, end as u32));
        at += line.len();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let (start, end) = (lines[i].0 as usize, lines[i].1 as usize);
        let line = &src[start..end];
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        let head = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
        let args = start + (line.len() - trimmed.len()) + head;
        // A trailing `\` continues the instruction onto the lines below.
        let mut last = i;
        while last + 1 < lines.len() && continued(src, lines[last]) {
            last += 1;
        }
        let inst = Instruction {
            keyword: trimmed[..head].to_ascii_lowercase(),
            args: Joined::new(src, args, lines[last].1 as usize),
        };
        // The body of a heredoc is data the builder hands to a shell, not
        // instructions of its own: a `FROM` or an `apt-get update` in it
        // builds nothing.
        let heredoc = if matches!(inst.keyword.as_str(), "run" | "copy" | "add") {
            inst.args.heredoc().map(str::to_owned)
        } else {
            None
        };
        out.push(inst);
        i = last + 1;
        if let Some(word) = heredoc {
            while i < lines.len() && src[lines[i].0 as usize..lines[i].1 as usize].trim() != word {
                i += 1;
            }
            i += 1;
        }
    }
    out
}

/// Whether the line at `(start, end)` ends in a continuation.
fn continued(src: &str, (start, end): (u32, u32)) -> bool {
    src[start as usize..end as usize].trim_end().ends_with('\\')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(src: &str) -> Vec<Code> {
        scan_dockerfile(src).into_iter().map(|d| d.code).collect()
    }

    /// The text a diagnostic's span covers, so a test asserts on the place
    /// the finding points rather than on its byte numbers.
    fn marked(src: &str) -> Vec<String> {
        scan_dockerfile(src).into_iter().map(|d| d.span.slice(src).to_string()).collect()
    }

    #[test]
    fn an_unpinned_from_warns_about_the_image() {
        assert_eq!(codes("FROM node:20\n"), [Code::NonReproducible]);
        assert_eq!(marked("FROM node:20\n"), ["node:20"]);
    }

    #[test]
    fn a_digest_pin_is_pinned() {
        assert!(codes("FROM node:20@sha256:abc123\n").is_empty());
    }

    #[test]
    fn a_platform_flag_does_not_hide_the_image() {
        let src = "FROM --platform=linux/amd64 node:20 AS build\n";
        assert_eq!(marked(src), ["node:20"]);
    }

    #[test]
    fn scratch_and_stage_aliases_have_no_input_of_their_own() {
        assert!(codes("FROM scratch\n").is_empty());
        let multi = "FROM alpine@sha256:abc AS base\nFROM base\nRUN true\n";
        assert!(codes(multi).is_empty(), "a stage alias inherits pinned bytes");
    }

    #[test]
    fn an_arg_interpolated_image_is_treated_as_unpinned() {
        // The value only exists at build time; we cannot read it, and a
        // tag there is the same defect one step removed.
        assert_eq!(marked("FROM ${BASE}\n"), ["${BASE}"]);
    }

    #[test]
    fn apt_without_a_snapshot_moves() {
        let src = "FROM alpine@sha256:abc\nRUN apt-get update\n";
        assert_eq!(codes(src), [Code::NonReproducible]);
        assert_eq!(marked("RUN apt update && apt install -y curl\n"), ["apt update"]);
    }

    #[test]
    fn a_snapshot_host_pins_the_index() {
        let pinned = concat!(
            "RUN apt-get update \\\n",
            " && sed -i s/deb.debian.org/snapshot.debian.org/ \\\n",
            " /etc/apt/sources.list \\\n",
            " && apt-get install -y curl\n",
        );
        assert!(codes(pinned).is_empty(), "the file names a snapshot host");
        let opt = "RUN apt-get --snapshot=20240101T0000Z update && apt install -y curl\n";
        assert!(codes(opt).is_empty(), "`--snapshot=` pins it");
    }

    #[test]
    fn a_comment_naming_a_snapshot_pins_nothing() {
        let src = "# we used snapshot.debian.org until we dropped it\nRUN apt-get update\n";
        assert_eq!(marked(src), ["apt-get update"], "a comment is not an instruction");
    }

    #[test]
    fn a_continuation_is_one_instruction() {
        let src = "RUN apt-get update \\\n    && apt-get install -y curl\n";
        assert_eq!(codes(src), [Code::NonReproducible], "one RUN, one warning");
    }

    #[test]
    fn options_may_sit_between_the_command_and_its_subcommand() {
        let src = "RUN apt-get -y update && apt install -y curl\n";
        assert_eq!(marked(src), ["apt-get -y update"]);
    }

    #[test]
    fn a_heredoc_body_is_data_not_instructions() {
        let src = concat!(
            "RUN <<EOF\n",
            "FROM node:20\n",
            "apt-get update\n",
            "EOF\n",
            "RUN echo \"a << b\"\n",
            "FROM alpine@sha256:abc\n",
        );
        assert!(
            codes(src).is_empty(),
            "a body builds nothing, and `<<` outside a heredoc opens nothing"
        );
    }

    #[test]
    fn an_add_of_a_url_needs_a_checksum() {
        let src = "ADD https://example.com/tool.tar.gz /usr/local/bin/tool\n";
        assert_eq!(marked(src), ["https://example.com/tool.tar.gz"]);
        let pinned = "ADD --checksum=sha256:abc123 https://example.com/t.tar.gz /t\n";
        assert!(codes(pinned).is_empty());
        assert!(
            codes("ADD ./tool.tar.gz /usr/local/bin/tool\n").is_empty(),
            "a local file is pinned"
        );
    }

    #[test]
    fn comments_and_directives_are_not_instructions() {
        let src = "# syntax=docker/dockerfile:1\n\
                   # FROM node:20 is what we used to write\n\
                   run echo \"apt-get update\"\n";
        assert!(codes(src).is_empty(), "comments and quoted mentions do not count");
    }

    #[test]
    fn keywords_are_case_insensitive() {
        assert_eq!(
            codes("from node:20\nRun apt-get update\n"),
            [Code::NonReproducible, Code::NonReproducible]
        );
    }

    #[test]
    fn every_warning_carries_a_hint_and_no_fix() {
        let diags = scan_dockerfile("FROM node:20\nRUN apt-get update\nADD https://x/y /y\n");
        assert_eq!(diags.len(), 3);
        for d in &diags {
            assert_eq!(d.severity, ks_lang::Severity::Warning);
            assert!(!d.hints.is_empty(), "{}: a warning must say what to do", d.code);
            assert!(d.fixes.is_empty(), "a digest cannot be written for you");
        }
    }
}
