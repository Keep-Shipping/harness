//! Docs-site gate: drives the real `tools/site.py` over the real `docs/`.
//!
//! The point is rot, not rendering. A doc that drifts — a cross-link to a page
//! that no longer exists, a fence left open — passes every other test in this
//! workspace, because nothing else reads `docs/`. This one does, and it fails.
//!
//! The generator itself is stdlib-only Python, so the test shells out rather
//! than reimplementing it: a second implementation would agree with itself
//! about a bug the site actually has.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

/// The exit code `site.py` uses for "the markdown has warnings", as opposed to
/// the 2 it uses for a usage or IO error. Reading the code rather than assuming
/// it keeps `deploy.sh` and this gate telling the same story: calling a crashed
/// generator a markdown problem sends the reader to the wrong file.
const EXIT_WARNINGS: i32 = 1;

/// Markers that must never appear in the chrome `site.py` writes itself. The
/// build is deterministic so the served bytes for a given `docs/` are the same
/// on every machine; a timestamp or a git sha would make every deploy a diff
/// nobody can read.
///
/// Checked only against the bytes the generator authors: the chrome of each
/// page, and the files that are entirely its own. `llms.txt` and
/// `llms-full.txt` are excluded because they are the docs' own words — `docs/`
/// is full of legitimate prose about build reproducibility (`SOURCE_DATE_EPOCH`
/// is a documented knob), and grepping those would fail on the docs rather
/// than on the generator. The list is literal rather than a date-shaped regex
/// on purpose: a regex would also fire on a date a doc legitimately quotes, and
/// the test would go quiet the moment someone widened it.
const FORBIDDEN: &[&str] =
    &["Generated at", "built at", "Build date", "git sha", "git rev", "SOURCE_DATE_EPOCH="];

/// Files whose every byte is the generator's, so the whole file is fair game.
const GENERATOR_OWNED: &[&str] = &["styles.css", "robots.txt", "sitemap.xml"];

/// The parts of a page the generator writes itself: everything outside
/// `<main>`. Borrowed when the page has no body, which never happens for a
/// real page, and owned when it does.
fn chrome(page: &str) -> Cow<'_, str> {
    // `<main` with or without attributes (`<main id="main">`, the skip link's target).
    match (page.find("<main"), page.rsplit_once("</main>")) {
        (Some(at), Some((_, after))) => Cow::Owned(format!("{}{after}", &page[..at])),
        _ => Cow::Borrowed(page),
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `Some(())` when python3 can run, `None` when it cannot.
///
/// A skip with a printed reason, not a silent pass and not a hard failure. CI
/// runs `ubuntu-latest` and `macos-latest` (`cargo test` runs in both, and
/// neither workflow installs python3 — it is preinstalled on both runner
/// images). So this is not expected to fire there. But "expected to be there"
/// is a claim about an image that can change under us, and a gate that deletes
/// itself the moment its tool goes missing is the same silence-as-green the
/// harness exists to catch. A printed reason is the honest outcome.
fn python3_available() -> Option<()> {
    let probe = Command::new("python3").arg("--version").output();
    if matches!(&probe, Ok(output) if output.status.success()) {
        return Some(());
    }
    println!(
        "skipping the docs-site gate: python3 is not on PATH, so tools/site.py cannot run. \
         CI runs ubuntu-latest and macos-latest, which ship python3 preinstalled; this is \
         informational, not a failure."
    );
    None
}

/// A fresh directory under `target/`, removed when the guard drops.
///
/// The workspace has no `tempfile` dependency, so this is the whole of it: a
/// unique name, and a `Drop` that takes the tree with it. On failure the
/// messages name the path instead, and `python3 tools/site.py --out <path>`
/// reproduces exactly what was inspected.
struct TempSite(PathBuf);

impl TempSite {
    fn new(tag: &str) -> TempSite {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = repo_root().join("target").join(format!(
            "docs-site-{}-{tag}-{next}",
            std::process::id(),
            next = NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("a temp directory under target/");
        TempSite(path)
    }

    fn join(&self, relative: &str) -> PathBuf {
        self.0.join(relative)
    }
}

impl Drop for TempSite {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Run `tools/site.py` out of the repo root, which is where its default `--docs`
/// resolves and where the paths in its warnings are repo-relative.
fn run_site(args: &[&str]) -> Output {
    Command::new("python3")
        .arg("tools/site.py")
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("tools/site.py should run")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Build the real `docs/` into a temp dir, asserting the build itself was
/// clean. Returns the guard so the caller can inspect the output.
fn build_real_docs(tag: &str) -> TempSite {
    if python3_available().is_none() {
        return TempSite::new("skipped");
    }
    let out = TempSite::new(tag);
    let output = run_site(&["--out", &out.0.to_string_lossy(), "--check"]);
    assert!(
        output.status.success(),
        "site.py --check on docs/ should be clean; it exited {}\n{}\nFix the docs, or the \
         generator: {}",
        output.status,
        stderr(&output),
        out.0.display()
    );
    out
}

/// Every file under a built site, keyed by its site-relative path, sorted.
fn tree(dir: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current).expect("a built site should be readable") {
            let path = entry.expect("readable entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path
                .strip_prefix(dir)
                .expect("under the site")
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(name, fs::read_to_string(&path).unwrap_or_default());
        }
    }
    out
}

/// A doc opening with a `> **Internal.**` callout is left off the site
/// (`is_internal` in `tools/site.py`).
fn is_internal(path: &Path) -> bool {
    fs::read_to_string(path).expect("a doc should be readable").lines().take(20).any(|line| {
        line.strip_prefix('>').is_some_and(|rest| rest.trim_start().starts_with("**Internal.**"))
    })
}

/// Every published `.md` under `docs/`, as docs-relative `/`-separated paths, sorted.
/// Recursive because `docs/adr/` is published too, its README index included.
fn source_docs(docs: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .expect("a docs/ directory should be readable")
            .map(|e| e.expect("readable entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(root, &path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("md") && !is_internal(&path)
            {
                out.push(
                    path.strip_prefix(root)
                        .expect("under docs/")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    let mut out = Vec::new();
    walk(docs, docs, &mut out);
    out.sort();
    out
}

/// The page URL `site.py` writes for a docs-relative path: the lowercased
/// filename, `.md` -> `.html`, and a README becoming `index.html`.
fn url_for(rel: &str) -> String {
    let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
    let stem = name.trim_end_matches(".md").to_lowercase();
    let out = if stem == "readme" { "index.html".to_string() } else { format!("{stem}.html") };
    if dir.is_empty() { format!("/{out}") } else { format!("/{dir}/{out}") }
}

/// The test runs the generator in this repository, not one found elsewhere on
/// the machine. Without this a stale `site.py` left on PATH — or a stale build
/// left in `target/` — would let every assertion below pass against something
/// that is not the code in the repo.
#[test]
fn runs_the_generator_in_this_repository() {
    if python3_available().is_none() {
        return;
    }
    let out = run_site(&["--help"]);
    let help = stdout(&out);
    assert!(help.contains("--check"), "--help should document --check: {help}");
    assert!(help.contains("--docs"), "--help should document --docs: {help}");

    // A sentinel only this copy of the generator emits. The old generator, and
    // any other site.py on the box, would not.
    let tree = TempSite::new("sentinel");
    let docs = tree.join("docs");
    fs::create_dir_all(&docs).expect("a docs dir");
    fs::write(docs.join("PAGE.md"), "# Page\n\nA page.\n").expect("write a doc");
    let built = run_site(&[
        "--docs",
        &docs.to_string_lossy(),
        "--out",
        &tree.join("out").to_string_lossy(),
    ]);
    assert!(built.status.success(), "the sentinel build should succeed: {}", stderr(&built));
    let page = fs::read_to_string(tree.join("out/page.html")).expect("out/page.html should exist");
    assert!(
        page.contains("A page."),
        "the generator in the repo should have rendered the page: {page}"
    );
}

#[test]
fn docs_build_without_warnings() {
    let out = build_real_docs("clean");
    assert!(
        out.join("index.html").exists(),
        "the build should have written index.html: {}",
        out.0.display()
    );
}

#[test]
fn every_doc_becomes_a_page_and_appears_in_both_llms_files() {
    let out = build_real_docs("coverage");
    let docs = repo_root().join("docs");
    let llms = fs::read_to_string(out.join("llms.txt")).expect("llms.txt should be written");
    let full =
        fs::read_to_string(out.join("llms-full.txt")).expect("llms-full.txt should be written");

    let sources = source_docs(&docs);
    assert!(sources.len() > 10, "docs/ should hold a real corpus; found {}", sources.len());
    for rel in sources {
        let url = url_for(&rel);
        assert!(
            out.join(url.trim_start_matches('/')).exists(),
            "docs/{rel} produced no page at {url}"
        );
        assert!(llms.contains(&url), "llms.txt does not mention {url}, the page for docs/{rel}");
        assert!(
            full.contains(&format!("<!-- source: docs/{rel} -->")),
            "llms-full.txt does not carry the source path of docs/{rel}"
        );
    }
}

#[test]
fn llms_full_carries_a_code_block_verbatim() {
    let out = build_real_docs("verbatim");
    let full =
        fs::read_to_string(out.join("llms-full.txt")).expect("llms-full.txt should be written");

    // A fence as it appears in a source line: `lines()` has no newlines, so
    // the opening marker is the line's own text.
    let block = "```rust";

    // Take a fence out of a real doc and require it, byte for byte, in the file.
    let source = fs::read_to_string(repo_root().join("docs/CLUSTERS.md"))
        .expect("docs/CLUSTERS.md should be readable");
    let body: String = source
        .lines()
        .skip_while(|line| !line.starts_with(block))
        .skip(1)
        .take_while(|l| !l.starts_with("```"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!body.is_empty(), "docs/CLUSTERS.md should hold a rust fence to compare against");
    assert!(
        full.contains(&body),
        "llms-full.txt should reproduce the rust example byte for byte, so an agent copying \
         it copies tested code; it does not contain:\n{body}"
    );
}

#[test]
fn two_builds_are_byte_identical_and_carry_no_build_stamp() {
    let first = build_real_docs("determinism-a");
    let second = build_real_docs("determinism-b");

    // Separate directories, so the second build cannot pass by reading the
    // first: this compares the generator's output and nothing else.
    let a = tree(&first.0);
    let b = tree(&second.0);
    assert_eq!(
        a.keys().collect::<Vec<_>>(),
        b.keys().collect::<Vec<_>>(),
        "two builds wrote different files"
    );
    for (name, content) in &a {
        assert_eq!(
            b.get(name),
            Some(content),
            "two builds of the same docs/ differ in {name}; the output must be deterministic"
        );
        for marker in FORBIDDEN {
            // llms.txt and llms-full.txt are the docs' own words; grepping them
            // would test the docs, not the generator.
            let generated = if GENERATOR_OWNED.contains(&name.as_str()) {
                Cow::Borrowed(content.as_str())
            } else if name.ends_with(".html") {
                chrome(content)
            } else {
                continue;
            };
            assert!(
                !generated.contains(marker),
                "{name} carries {marker:?} in the generator's own output, so it would differ \
                 between two machines holding the same docs/"
            );
        }
    }
}

/// A docs tree built to be hostile, so the generator's refusals are proven
/// rather than assumed. Written into a temp directory, never into `docs/`.
#[test]
fn hostile_docs_warn_and_never_emit_the_scheme() {
    if python3_available().is_none() {
        return;
    }
    let tree = TempSite::new("hostile");
    let docs = tree.join("docs");
    fs::create_dir_all(docs.join("adr")).expect("a docs dir");
    fs::write(
        docs.join("BAD.md"),
        "# Bad\n\nA [scheme](javascript:alert) and a [ghost](NOPE.md).\n\n```rust\nfn main() {}\n",
    )
    .expect("write the hostile doc");
    fs::write(docs.join("adr/README.md"), "# Decisions\n\nAn index that links [up](../BAD.md).\n")
        .expect("write the hostile index");

    let out = tree.join("out");
    let built = run_site(&["--docs", &docs.to_string_lossy(), "--out", &out.to_string_lossy()]);
    assert!(
        built.status.success(),
        "a hostile doc must still build, not crash: {}\n{}",
        built.status,
        stderr(&built)
    );

    let checked =
        run_site(&["--docs", &docs.to_string_lossy(), "--out", &out.to_string_lossy(), "--check"]);
    assert_eq!(
        checked.status.code(),
        Some(EXIT_WARNINGS),
        "--check should exit {EXIT_WARNINGS} when the docs warn; it exited {:?}\n{}",
        checked.status.code(),
        stderr(&checked)
    );

    // Every one of the three problems named. A gate that checks only the exit
    // code would pass a generator that warned about the wrong things.
    let warnings = stderr(&checked);
    for expected in [
        "unsafe URL scheme",
        "javascript:alert",
        "does not resolve to a doc",
        "NOPE.md",
        "unclosed code fence",
    ] {
        assert!(warnings.contains(expected), "no warning named {expected:?}:\n{warnings}");
    }

    let page = fs::read_to_string(out.join("bad.html")).expect("bad.html should exist");
    assert!(
        !page.contains("javascript:"),
        "a javascript: scheme reached the output; it must be escaped as text, never emitted as an href:\n{page}"
    );
    assert!(page.contains("fn main() {}"), "the fenced block should still render:\n{page}");
}
