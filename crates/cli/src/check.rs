//! The `check` subcommand: parse and type-check the site file — or, with
//! `--all`, every `ship.ks` under a directory — print what it finds, and
//! exit by the documented code. Checking reads files and nothing else: it
//! never runs a step, touches a store or opens a socket.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ks_core::ports::run_context::ActorKind;
use ks_lang::{Diagnostic, Severity};

use crate::args::{Command, Options, USAGE, parse_args};
use crate::render::{self, Format};

/// One checked file: what was read and what the checker said about it.
pub struct Site {
    /// The path as printed: as given on the command line, or relative to
    /// the `--all` walk root.
    pub path: String,
    pub src: String,
    pub checked: ks_core::Checked,
}

pub fn check(args: &[String]) -> ExitCode {
    let Some(o) = parse_args(args, Command::Check) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    // The secrets listing is written for people; inside a machine format it
    // would corrupt the stream.
    if o.secrets && o.format != Format::Human {
        eprintln!(
            "error: --secrets prints a listing for people; it does not combine with --format {}",
            o.format.as_str()
        );
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let sites = match collect(&o) {
        Ok(sites) => sites,
        Err(code) => return code,
    };

    let color = render::use_color();
    let mut out = io::stdout().lock();
    let mut failed = false;
    for site in &sites {
        let diags = &site.checked.diagnostics;
        match o.format {
            Format::Human => {
                let _ = render::human(&mut out, &site.path, &site.src, diags, color);
                if !fails(&o, diags) {
                    let _ = render::ok_line(&mut out, &site.path, color);
                    if o.secrets {
                        let _ = print_secrets(&mut out, &site.checked);
                    }
                }
            }
            Format::Json => {
                let _ = render::json(&mut out, &site.path, &site.src, diags);
            }
            Format::Github => {
                let _ = render::github(&mut out, &site.path, &site.src, diags);
            }
        }
        failed |= fails(&o, diags);
    }
    // The listing comes after the diagnostics and does not soften the exit
    // code: a file with errors is still a failed check.
    if o.format == Format::Human {
        let _ = render::footer(&mut out);
    }
    if failed { ExitCode::from(1) } else { ExitCode::SUCCESS }
}

/// A file fails the check when it carries an error, or — with
/// `--warnings-as-errors` — any warning at all.
pub fn fails(o: &Options, diags: &[Diagnostic]) -> bool {
    diags.iter().any(|d| match d.severity {
        Severity::Error => true,
        Severity::Warning => o.warnings_as_errors,
    })
}

/// The files to check: the one named on the command line, or every
/// `ship.ks` in the tree. An empty `--all` walk is a usage error — a
/// monorepo with no site file is a mistake the caller wants to hear about.
fn collect(o: &Options) -> Result<Vec<Site>, ExitCode> {
    if !o.all {
        let given = o.path.as_deref().unwrap_or("ship.ks");
        return Ok(vec![load(Path::new(given), given, o.actor, o.path.is_none())?]);
    }
    let root = PathBuf::from(o.path.as_deref().unwrap_or("."));
    let mut found = Vec::new();
    if let Err(e) = walk(&root, &mut found) {
        if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) {
            eprintln!("error: {}: no such directory", root.display());
            return Err(ExitCode::from(2));
        }
        eprintln!("internal error: {}: {e}", root.display());
        return Err(ExitCode::from(3));
    }
    found.sort();
    if found.is_empty() {
        eprintln!("error: no ship.ks under {}", root.display());
        return Err(ExitCode::from(2));
    }
    let sites: Result<Vec<Site>, ExitCode> = found
        .iter()
        .map(|path| {
            let shown = path.strip_prefix(&root).unwrap_or(path);
            load(path, &shown.to_string_lossy(), o.actor, false)
        })
        .collect();
    sites
}

/// Every `ship.ks` under `dir`, recursively. Hidden (`.git`), build
/// (`target`) and package-manager (`node_modules`) trees never hold one.
fn walk(dir: &Path, found: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.file_type()?.is_dir() {
            if name.starts_with('.') || name == "target" || name == "node_modules" {
                continue;
            }
            walk(&entry.path(), found)?;
        } else if name == "ship.ks" {
            found.push(entry.path());
        }
    }
    Ok(())
}

/// Read and check one file. Missing, unreadable or non-UTF-8 files are
/// usage errors the caller can fix — the default `ship.ks` may simply not
/// exist yet; anything else is internal: the checker only ever reads, so it
/// cannot recover.
pub fn load(path: &Path, shown: &str, actor: ActorKind, default: bool) -> Result<Site, ExitCode> {
    let src = match std::fs::read_to_string(path) {
        Ok(src) => src,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if default {
                eprintln!("error: no ship.ks in the current directory; pass the file to check");
            } else {
                eprintln!("error: {shown}: no such file");
            }
            return Err(ExitCode::from(2));
        }
        Err(e) if e.kind() != io::ErrorKind::Other => {
            // A problem with this file or its permissions, not with
            // keepshipping: name it and let the caller fix it.
            let why = match e.kind() {
                io::ErrorKind::IsADirectory => "is a directory".into(),
                io::ErrorKind::InvalidData => "is not valid UTF-8".into(),
                _ => format!("cannot be read: {e}"),
            };
            eprintln!("error: {shown} {why}");
            return Err(ExitCode::from(2));
        }
        Err(e) => {
            eprintln!("internal error: {shown}: {e}");
            return Err(ExitCode::from(3));
        }
    };
    let catalog = ks_core::Catalog::builtin();
    let options = ks_core::CheckOptions::new(&catalog).actor(actor).ci(in_ci_env());
    let checked = ks_core::check_with(&ks_lang::parse(&src), &options);
    Ok(Site { path: shown.to_string(), src, checked })
}

/// Whether the environment says this is a CI run, the way most pipelines
/// say it. Set to anything but empty counts; an empty `CI=` says nothing.
///
/// This only widens advisory warnings — the actor, which policy binds, is
/// never inferred from the environment. A spoofed warning costs the
/// spoofer nothing, a spoofed actor would cost them the run.
fn in_ci_env() -> bool {
    std::env::var_os("CI").is_some_and(|v| !v.is_empty())
}

/// The `--secrets` listing: per environment, the secret references its
/// resolver must serve and the steps that need them. Purely a projection of
/// the checked file — no resolver is ever constructed and no store, env var
/// or backend is read, so the listing is safe to run anywhere.
fn print_secrets(out: &mut impl Write, checked: &ks_core::Checked) -> io::Result<()> {
    for env in ks_core::secret_requirements(checked) {
        if env.requirements.is_empty() {
            writeln!(out, "{}: (none)", env.env)?;
            continue;
        }
        for r in &env.requirements {
            let steps = r.steps.join(", ");
            match &r.reference {
                Some(reference) => writeln!(out, "{}: {reference} ({steps})", env.env)?,
                None => writeln!(out, "{}: {} ({steps}) [no `secrets:` resolver]", env.env, r.key)?,
            }
        }
    }
    Ok(())
}
