//! The `fmt` subcommand: rewrite `.ks` files into their canonical form, or
//! say what would change. Like `check` it runs no step; unlike `check` it
//! may write, and only when the file parses and the rewrite is the
//! formatter's own — a string value's bytes are never touched.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::args::{Command, Options, USAGE, parse_args};
use crate::check;
use crate::render;

/// What became of one source. The exit code follows from it: `Refused` is a
/// parse failure the user must fix (1), `Usage` a problem with the command
/// line or a file that cannot be read (2), `Internal` a bug here (3).
enum Outcome {
    Unchanged,
    Changed,
    Refused,
    Usage,
    Internal,
}

pub fn fmt(args: &[String]) -> ExitCode {
    let Some(o) = parse_args(args, Command::Fmt) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    // `-` is a filter: source in, formatted source out, nothing touched.
    if o.stdin {
        let mut src = String::new();
        if let Err(e) = io::stdin().lock().read_to_string(&mut src) {
            eprintln!("error: stdin cannot be read: {}", why(&e));
            return ExitCode::from(2);
        }
        return exit(report(None, "<stdin>", &src, &o), o.check);
    }
    let files = match collect(&o) {
        Ok(files) => files,
        Err(code) => return code,
    };
    let (mut changed, mut refused) = (false, false);
    for (path, shown) in &files {
        let src = match read(path, shown) {
            Ok(src) => src,
            Err(()) => return ExitCode::from(2),
        };
        match report(Some(path), shown, &src, &o) {
            Outcome::Changed => changed = true,
            Outcome::Refused => refused = true,
            Outcome::Usage => return ExitCode::from(2),
            Outcome::Internal => return ExitCode::from(3),
            Outcome::Unchanged => {}
        }
    }
    let worst = if refused {
        Outcome::Refused
    } else if changed {
        Outcome::Changed
    } else {
        Outcome::Unchanged
    };
    exit(worst, o.check)
}

/// The process exit code for what became of a run. `check` is what turns "the
/// source was not canonical" into a failure: a rewrite is the job asked for
/// and succeeds, the same rewrite found by `--check` is a finding.
fn exit(outcome: Outcome, check: bool) -> ExitCode {
    match outcome {
        Outcome::Changed if check => ExitCode::from(1),
        Outcome::Unchanged | Outcome::Changed => ExitCode::SUCCESS,
        Outcome::Refused => ExitCode::from(1),
        Outcome::Usage => ExitCode::from(2),
        Outcome::Internal => ExitCode::from(3),
    }
}

/// Format one source and do what the mode asks with the result: rewrite it,
/// report the difference, or write it to stdout. `path` is `None` for stdin,
/// which is never rewritten in place but is always echoed to stdout. A file
/// that is already canonical is not written at all — it keeps its mtime.
fn report(path: Option<&Path>, shown: &str, src: &str, o: &Options) -> Outcome {
    let formatted = match ks_lang::format(src) {
        Ok(formatted) => formatted,
        // A file `fmt` cannot fully understand is left exactly as it was and
        // reported the way `check` reports: the parse has to be fixed before
        // the whitespace matters.
        Err(e) => {
            let mut err = io::stderr().lock();
            let _ = render::human(&mut err, shown, src, e.diagnostics(), render::use_color());
            return Outcome::Refused;
        }
    };
    if o.check {
        let mut out = io::stdout().lock();
        if formatted == src {
            let _ = render::ok_line(&mut out, shown, render::use_color());
            return Outcome::Unchanged;
        }
        let _ = write!(out, "{}", diff(shown, src, &formatted));
        return Outcome::Changed;
    }
    // Stdin is a filter: source in, formatted source out. The write is not
    // short-circuited when the text is already canonical — an early return
    // here would print nothing at all and swallow a perfectly good source,
    // so `fmt - | fmt -` and `fmt - > ship.ks` would empty the file.
    let Some(path) = path else {
        let mut out = io::stdout().lock();
        return match out.write_all(formatted.as_bytes()).and_then(|()| out.flush()) {
            Ok(()) if formatted == src => Outcome::Unchanged,
            Ok(()) => Outcome::Changed,
            Err(e) => {
                eprintln!("internal error: stdout: {e}");
                Outcome::Internal
            }
        };
    };
    // A file that is already canonical keeps its mtime: it is not written.
    if formatted == src {
        return Outcome::Unchanged;
    }
    match write_atomic(path, &formatted) {
        Ok(()) => Outcome::Changed,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("error: {shown} cannot be written: {e}");
            Outcome::Usage
        }
        Err(e) => {
            eprintln!("internal error: {shown}: {e}");
            Outcome::Internal
        }
    }
}

/// The files to format, each with the path to print. With no path this is the
/// file `check` defaults to; a directory is walked for `ship.ks` files the
/// way `check --all` walks, so both commands find the same files.
fn collect(o: &Options) -> Result<Vec<(PathBuf, String)>, ExitCode> {
    let paths: Vec<&str> = if o.paths.is_empty() {
        vec!["ship.ks"]
    } else {
        o.paths.iter().map(String::as_str).collect()
    };
    let mut files = Vec::new();
    for given in paths {
        let path = Path::new(given);
        let meta = match std::fs::metadata(path) {
            Ok(meta) => meta,
            Err(e) => {
                eprintln!("error: {given} {}", why(&e));
                return Err(ExitCode::from(2));
            }
        };
        if !meta.is_dir() {
            files.push((path.to_path_buf(), given.to_string()));
            continue;
        }
        let mut found = Vec::new();
        if let Err(e) = check::walk(path, &mut found) {
            if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) {
                eprintln!("error: {given}: no such directory");
                return Err(ExitCode::from(2));
            }
            eprintln!("internal error: {given}: {e}");
            return Err(ExitCode::from(3));
        }
        found.sort();
        if found.is_empty() {
            eprintln!("error: no ship.ks under {given}");
            return Err(ExitCode::from(2));
        }
        for file in found {
            let shown = file.strip_prefix(path).unwrap_or(&file).to_string_lossy().into_owned();
            files.push((file, shown));
        }
    }
    Ok(files)
}

fn read(path: &Path, shown: &str) -> Result<String, ()> {
    std::fs::read_to_string(path).map_err(|e| eprintln!("error: {shown} {}", why(&e)))
}

/// How a file that cannot be read is described — the same wording `check`
/// uses, so one bad file reads the same under either command.
fn why(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => "no such file".into(),
        io::ErrorKind::IsADirectory => "is a directory".into(),
        io::ErrorKind::InvalidData => "is not valid UTF-8".into(),
        _ => format!("cannot be read: {e}"),
    }
}

/// Rewrite `path` in place through a sibling temporary file and a rename, so
/// a failure part-way through leaves the original whole. The temporary file
/// carries the original's permissions, which survive the rename with it.
fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    // A temporary left by a crashed run must never be reused blindly.
    let (mut tmp, mut n) = (dir.join(format!(".{name}.fmt.tmp")), 0);
    while tmp.exists() {
        n += 1;
        tmp = dir.join(format!(".{name}.fmt{n}.tmp"));
    }
    let written = std::fs::write(&tmp, text).and_then(|()| {
        if let Ok(meta) = std::fs::metadata(path) {
            let _ = std::fs::set_permissions(&tmp, meta.permissions());
        }
        std::fs::rename(&tmp, path)
    });
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// One source line, and whether a newline ended it. A file whose last line
/// has none has to say so in the diff, so the fact travels with the line.
struct Line<'a> {
    text: &'a str,
    nl: bool,
}

/// `str` split into lines, each tagged with whether its newline is there.
fn split_lines(s: &str) -> Vec<Line<'_>> {
    let mut out = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        match rest.find('\n') {
            Some(i) => {
                out.push(Line { text: &rest[..i], nl: true });
                rest = &rest[i + 1..];
            }
            None => {
                out.push(Line { text: rest, nl: false });
                rest = "";
            }
        }
    }
    out
}

/// A unified diff of the two texts: `--- path` / `+++ path`, then one hunk
/// per run of changes with `@@ -l,s +l,s @@` headers. `patch` and
/// `git apply` both read it.
fn diff(path: &str, old: &str, new: &str) -> String {
    let before = split_lines(old);
    let after = split_lines(new);
    let ops = diff_ops(&before, &after);
    let mut out = format!("--- {path}\n+++ {path}\n");
    // Where each op sits in each file, so a hunk header can name its lines.
    let mut at = Vec::with_capacity(ops.len() + 1);
    let (mut i, mut j) = (0, 0);
    for op in &ops {
        at.push((i, j));
        match op.mark {
            ' ' => {
                i += 1;
                j += 1;
            }
            '-' => i += 1,
            _ => j += 1,
        }
    }
    at.push((i, j));

    // The next changed op at or after each one, so a hunk's extent is one
    // scan rather than a rescan per change.
    let mut next_change = vec![ops.len(); ops.len() + 1];
    for k in (0..ops.len()).rev() {
        next_change[k] = if ops[k].changed() { k } else { next_change[k + 1] };
    }
    let mut k = next_change[0];
    while k < ops.len() {
        // Two changes belong to one hunk only when they are near enough that
        // their context would overlap; further apart they get a hunk each.
        let (mut last, mut scan) = (k, k + 1);
        while scan < ops.len() {
            if ops[scan].changed() {
                if scan - last > CONTEXT {
                    break;
                }
                last = scan;
            }
            scan += 1;
        }
        let (from, to) = (k.saturating_sub(CONTEXT), (last + CONTEXT + 1).min(ops.len()));
        let hunk = &ops[from..to];
        let old_count = hunk.iter().filter(|op| op.mark != '+').count();
        let new_count = hunk.iter().filter(|op| op.mark != '-').count();
        // A side with no lines in a hunk names the line it follows, which is
        // the unified diff's way of pointing at an insertion point.
        let old_start = if old_count == 0 { at[from].0 } else { at[from].0 + 1 };
        let new_start = if new_count == 0 { at[from].1 } else { at[from].1 + 1 };
        out.push_str(&format!("@@ -{old_start},{old_count} +{new_start},{new_count} @@\n"));
        for op in hunk {
            push(&mut out, op);
        }
        k = next_change[to.min(ops.len())];
    }
    out
}

/// How many unchanged lines surround each run of changes.
const CONTEXT: usize = 3;

/// One diff line, plus the marker that says it has no newline after it.
fn push(out: &mut String, op: &Op<'_>) {
    out.push(op.mark);
    out.push_str(op.text);
    out.push('\n');
    if !op.nl {
        out.push_str("\\ No newline at end of file\n");
    }
}

/// One line of a diff: its mark, its text, and whether a newline ended it.
struct Op<'a> {
    mark: char,
    text: &'a str,
    nl: bool,
}

impl<'a> Op<'a> {
    fn new(mark: char, line: &'a Line<'_>) -> Op<'a> {
        Op { mark, text: line.text, nl: line.nl }
    }

    fn changed(&self) -> bool {
        self.mark != ' '
    }
}

/// The two line sequences as `Op`s.
///
/// The lines the two files share at the front and the back are kept without
/// any matching, which is what makes the common case — a formatter nudging a
/// few lines in a long file — cost nothing. Only what is left in the middle
/// is matched against itself, and only while the table stays small; past
/// that the middle is reported as one replacement rather than risking a
/// table big enough to matter.
fn diff_ops<'s>(before: &'s [Line<'_>], after: &'s [Line<'_>]) -> Vec<Op<'s>> {
    let same = |a: &Line<'_>, b: &Line<'_>| a.text == b.text && a.nl == b.nl;
    let mut head = 0;
    while head < before.len() && head < after.len() && same(&before[head], &after[head]) {
        head += 1;
    }
    let mut tail = 0;
    while tail < before.len() - head
        && tail < after.len() - head
        && same(&before[before.len() - 1 - tail], &after[after.len() - 1 - tail])
    {
        tail += 1;
    }
    let (mid_old, mid_new) = (&before[head..before.len() - tail], &after[head..after.len() - tail]);

    let mut ops: Vec<Op<'_>> = before[..head].iter().map(|l| Op::new(' ', l)).collect();
    if mid_old.len().saturating_mul(mid_new.len() + 1) <= MAX_CELLS {
        ops.extend(longest_common(mid_old, mid_new));
    } else {
        // Too big to match line by line. The middle is a rewrite either way,
        // so say so in one hunk instead of building a table to find out.
        ops.extend(mid_old.iter().map(|l| Op::new('-', l)));
        ops.extend(mid_new.iter().map(|l| Op::new('+', l)));
    }
    ops.extend(before[before.len() - tail..].iter().map(|l| Op::new(' ', l)));
    ops
}

/// The most cells the matching table may hold. Four million `u32`s is 16 MB,
/// which any machine has and no source file's edit should need.
const MAX_CELLS: usize = 4_000_000;

/// Match `before` against `after` by their longest common subsequence.
fn longest_common<'s>(before: &'s [Line<'_>], after: &'s [Line<'_>]) -> Vec<Op<'s>> {
    let (n, m) = (before.len(), after.len());
    let stride = m + 1;
    // lcs[i * stride + j] = the longest common subsequence of `before[i..]`
    // and `after[j..]`.
    let mut lcs = vec![0u32; (n + 1) * stride];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i * stride + j] = if before[i].text == after[j].text {
                lcs[(i + 1) * stride + j + 1] + 1
            } else {
                lcs[(i + 1) * stride + j].max(lcs[i * stride + j + 1])
            };
        }
    }
    let mut ops = Vec::with_capacity(n + m);
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if before[i].text == after[j].text {
            ops.push(Op::new(' ', &before[i]));
            i += 1;
            j += 1;
        } else if lcs[(i + 1) * stride + j] >= lcs[i * stride + j + 1] {
            ops.push(Op::new('-', &before[i]));
            i += 1;
        } else {
            ops.push(Op::new('+', &after[j]));
            j += 1;
        }
    }
    ops.extend(before[i..].iter().map(|l| Op::new('-', l)));
    ops.extend(after[j..].iter().map(|l| Op::new('+', l)));
    ops
}
