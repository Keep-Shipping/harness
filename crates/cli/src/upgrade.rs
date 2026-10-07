//! `keepshipping fmt --upgrade <paths...>`: brings each file to the format
//! this build writes, using the migrations in `ks_core::format`, and writes
//! the result back only when the bytes actually changed.
//!
//! What a migration cannot rewrite is never guessed at: it is printed for a
//! person, and the run exits 1. So is a file this build refuses to migrate
//! from, which is left byte-for-byte untouched rather than half-upgraded.
//! Plain `fmt` (no `--upgrade`) is the layout formatter in `fmt.rs`; `main`
//! routes a `fmt` command line here only when it carries `--upgrade`.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ks_core::format;

use crate::args::{Command, Options, USAGE, parse_args};
use crate::render;

/// The exit code when something was left for a person: a file refused, or a
/// migration that could not rewrite part of one.
const INCOMPLETE: u8 = 1;

/// `keepshipping fmt --upgrade <paths...>`.
pub fn fmt(args: &[String]) -> ExitCode {
    let Some(o) = parse_args(args, Command::Fmt) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    // `--check` and `-` belong to the layout formatter; an upgrade always
    // rewrites files in place.
    if !o.upgrade || o.check || o.stdin {
        eprintln!("error: fmt --upgrade rewrites files in place; it takes neither --check nor -");
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }

    let paths = match collect(&o) {
        Ok(paths) => paths,
        Err(code) => return code,
    };
    let mut out = io::stdout().lock();
    let mut incomplete = false;
    for path in &paths {
        let shown = path.display().to_string();
        let src = match std::fs::read_to_string(path) {
            Ok(src) => src,
            // A file that cannot be read is the caller's to fix, as in
            // `check`: exit 2, and stop rather than half-rewrite a run.
            Err(e) => {
                let _ = writeln!(io::stderr().lock(), "error: {shown} {}", why(&e));
                return ExitCode::from(2);
            }
        };
        let pinned = format::header(ks_lang::parse(&src).file()) == format::Header::Absent;
        let upgraded = match format::upgrade(&src, &format::BUILTIN) {
            Ok(upgraded) => upgraded,
            Err(refusal) => {
                incomplete = true;
                let line = render::line_at(&src, refusal.span.start);
                let _ = writeln!(io::stderr().lock(), "error: {shown}:{line}: {}", refusal.message);
                continue;
            }
        };
        for left in &upgraded.unrewritten {
            incomplete = true;
            let line = render::line_at(&upgraded.src, left.span.start);
            let _ = writeln!(out, "⚠ {shown}:{line}: {}", left.message);
        }
        if upgraded.src == src {
            let _ = writeln!(out, "unchanged {shown}: {}", format::spelling(upgraded.from));
            continue;
        }
        if let Err(e) = std::fs::write(path, &upgraded.src) {
            let _ = writeln!(io::stderr().lock(), "error: {shown} {}", why(&e));
            return ExitCode::from(2);
        }
        let to = format::spelling(format::BUILTIN.current);
        let _ = if pinned {
            writeln!(out, "pinned {shown}: {} {to}", format::HEADER_KEY)
        } else {
            writeln!(out, "upgraded {shown}: {} → {to}", format::spelling(upgraded.from))
        };
    }
    if incomplete { ExitCode::from(INCOMPLETE) } else { ExitCode::SUCCESS }
}

/// The files to rewrite: the ones named, each a file or a tree to walk for
/// `ship.ks`. No paths means `ship.ks` in the working directory, the default
/// `check` has. A path named twice is rewritten once.
fn collect(o: &Options) -> Result<Vec<PathBuf>, ExitCode> {
    let given = if o.paths.is_empty() { vec!["ship.ks".to_string()] } else { o.paths.clone() };
    let mut found: Vec<PathBuf> = Vec::new();
    for path in &given {
        let path = PathBuf::from(path);
        if !path.is_dir() {
            push(&mut found, path);
            continue;
        }
        let before = found.len();
        walk(&path, &mut found);
        found[before..].sort();
        if found.len() == before {
            eprintln!("error: no ship.ks under {}", path.display());
            return Err(ExitCode::from(2));
        }
    }
    Ok(found)
}

/// Add `path` unless it is already queued, so naming a file and the tree
/// holding it rewrites it once rather than twice.
fn push(found: &mut Vec<PathBuf>, path: PathBuf) {
    if !found.contains(&path) {
        found.push(path);
    }
}

/// Every `ship.ks` under `dir`, recursively, on the terms `check --all`
/// walks: hidden, `target` and `node_modules` trees never hold one.
fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            if name.starts_with('.') || name == "target" || name == "node_modules" {
                continue;
            }
            walk(&entry.path(), found);
        } else if name == "ship.ks" {
            push(found, entry.path());
        }
    }
}

/// Why a file could not be read or written, in `check`'s wording.
fn why(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => "no such file".into(),
        io::ErrorKind::IsADirectory => "is a directory".into(),
        io::ErrorKind::InvalidData => "is not valid UTF-8".into(),
        io::ErrorKind::PermissionDenied => "permission denied".into(),
        _ => format!("cannot be read: {e}"),
    }
}
