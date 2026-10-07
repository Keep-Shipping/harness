//! The `check` subcommand: parse and type-check the site file — or, with
//! `--all`, every `ship.ks` under a directory — print what it finds, and
//! exit by the documented code. Checking reads files and nothing else: it
//! never runs a step, touches a store or opens a socket. With `--fix` it
//! additionally rewrites the machine-applicable fixes it proposes.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ks_core::ContextName;
use ks_core::ports::run_context::ActorKind;
use ks_lang::{Diagnostic, Fix, Severity, Span};

use crate::args::{Command, Options, USAGE, context_of, parse_args};
use crate::render::{self, Format};

/// One checked file: what was read and what the checker said about it.
pub struct Site {
    /// The path as printed: as given on the command line, or relative to
    /// the `--all` walk root.
    pub path: String,
    /// The file to write back to — `--fix` edits the file on disk, and the
    /// printed path need not be one you can open.
    pub file: PathBuf,
    pub src: String,
    pub checked: ks_core::Checked,
    /// The steps this context cannot run, as the warnings above named them.
    pub unmet: Vec<ks_core::UnmetStep>,
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
    // Fix, then report what the fixed files check like: the exit code is
    // the re-check's, never the pre-fix one's.
    let sites = if o.fix {
        match fix(sites, &o) {
            Ok(sites) => sites,
            Err(code) => return code,
        }
    } else {
        sites
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

/// `--fix`: apply the machine-applicable edits the checker proposed, then
/// re-check each file it rewrote. Two things are never applied — an edit
/// that overlaps another (the second would land on bytes the first moved),
/// and any edit inside `policy:`, where widening or narrowing what a run
/// may do is a human's decision ([ADR
/// 0012](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0012-policy-authority.md)).
/// Both stay as diagnostics in the re-check output, and are named on
/// stderr: `--fix` writes files, so it says which ones and what it left.
fn fix(sites: Vec<Site>, o: &Options) -> Result<Vec<Site>, ExitCode> {
    let mut fixed = Vec::with_capacity(sites.len());
    for site in sites {
        let plan = plan(&site);
        if !plan.apply.is_empty() {
            let src = apply(&site.src, &plan.apply);
            match std::fs::write(&site.file, &src) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("error: {}: cannot be written: {e}", site.path);
                    return Err(ExitCode::from(2));
                }
            }
            eprintln!(
                "{}: applied {} fix{}",
                site.path,
                plan.apply.len(),
                plural(plan.apply.len())
            );
        }
        if !plan.policy.is_empty() {
            eprintln!(
                "{}: {} fix{} inside `policy:` need{} a human and {} not applied",
                site.path,
                plan.policy.len(),
                plural(plan.policy.len()),
                if plan.policy.len() == 1 { "s" } else { "" },
                if plan.policy.len() == 1 { "was" } else { "were" },
            );
        }
        if plan.overlapping > 0 {
            eprintln!(
                "{}: {} fix{} overlapped an edit already applied and {} not applied",
                site.path,
                plan.overlapping,
                plural(plan.overlapping),
                if plan.overlapping == 1 { "was" } else { "were" },
            );
        }
        if plan.apply.is_empty() {
            fixed.push(site);
            continue;
        }
        // Re-check the bytes we just wrote, so the report and the exit code
        // describe the file as it now stands.
        let shown = site.path.clone();
        fixed.push(load(&site.file, &shown, o.actor, false, context_of(o))?);
    }
    Ok(fixed)
}

/// What `--fix` will do to one file: the edits to splice in, those inside
/// `policy:` a human has to decide on, and the count of edits that lost a
/// race with an overlapping one.
#[derive(Default)]
struct Plan {
    apply: Vec<Fix>,
    policy: Vec<Fix>,
    overlapping: usize,
}

fn plan(site: &Site) -> Plan {
    let mut fixes: Vec<Fix> = site
        .checked
        .diagnostics
        .iter()
        .flat_map(|d| d.fixes.iter())
        .filter(|f| f.machine_applicable)
        .cloned()
        .collect();
    // A fix only ever names bytes inside its own diagnostic's span, so
    // source order of the diagnostics is not span order of the fixes:
    // sort before deciding what overlaps what, and the splices below can
    // rely on ascending spans.
    fixes.sort_by_key(|f| (f.span.start, f.span.end));
    let mut plan = Plan::default();
    for fix in fixes {
        if site.checked.policy_spans.iter().any(|p| overlaps(fix.span, *p)) {
            plan.policy.push(fix);
        } else if plan.apply.iter().any(|a| overlaps(a.span, fix.span)) {
            plan.overlapping += 1;
        } else {
            plan.apply.push(fix);
        }
    }
    plan
}

/// Half-open ranges that share a byte cannot both be rewritten: applying
/// one moves the bytes the other names.
fn overlaps(a: Span, b: Span) -> bool {
    a.start < b.end && b.start < a.end
}

/// `src` with every fix spliced in. The fixes arrive in source order, and
/// are applied back to front so each span still names the same bytes.
fn apply(src: &str, fixes: &[Fix]) -> String {
    let mut out = src.to_string();
    for f in fixes.iter().rev() {
        let start = (f.span.start as usize).min(out.len());
        let end = (f.span.end as usize).clamp(start, out.len());
        out.replace_range(start..end, &f.replacement);
    }
    out
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "es" }
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
        return Ok(vec![load(Path::new(given), given, o.actor, o.path.is_none(), context_of(o))?]);
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
            load(path, &shown.to_string_lossy(), o.actor, false, context_of(o))
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
pub fn load(
    path: &Path,
    shown: &str,
    actor: ActorKind,
    default: bool,
    context: ContextName,
) -> Result<Site, ExitCode> {
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
    let ctx = context.context();
    let options = ks_core::CheckOptions::new(&catalog).actor(actor).context(ctx.clone());
    let checked = ks_core::check_with(&ks_lang::parse(&src), &options);
    // From the same catalog and context the warnings came from, so `run`
    // gates on exactly what `check` said rather than a second opinion.
    let unmet = ks_core::unmet_steps(&checked.workflow, &catalog, &ctx);
    Ok(Site { path: shown.to_string(), file: path.to_path_buf(), src, checked, unmet })
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
