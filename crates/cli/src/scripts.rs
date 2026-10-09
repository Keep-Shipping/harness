//! `script` steps: what a TypeScript step module declares, read out of the
//! module without ever calling `run`.
//!
//! A bundled extractor (`EXTRACTOR`) imports the module with
//! `@keepshipping/sdk` resolved to a stub, takes the `step()` descriptor off
//! the default export and prints its `outputs` as tags. The mapping from tags
//! to ks types is [`ks_core::script`]'s; this module is the half that needs a
//! filesystem and a process.
//!
//! Every failure here — no `node`, a module that will not import, a
//! descriptor nobody can read — leaves the step's outputs unchecked, exactly
//! as they were before. A `check` never fails for a file it did not see.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ks_core::script::{ScriptOutputs, Tag};

/// The extractor, inlined so a site needs nothing installed to be checked.
const EXTRACTOR: &str = include_str!("scripts_extract.mjs");

/// Where a site's extracted signatures live, under the site file's directory.
const CACHE: &str = ".keepshipping/cache/scripts";

/// How long one extraction may take. A module's body runs at import time —
/// that is what reaching the descriptor costs — so without a bound one that
/// loops would hang `check` for ever.
const TIMEOUT: Duration = Duration::from_secs(10);

/// What every script step in `src` declares, keyed by the kind path as the
/// file spells it — the key
/// [`CheckOptions::script_outputs`](ks_core::CheckOptions::script_outputs) reads under.
///
/// `site` is the site file (`ship.ks`) or the directory holding it: a
/// module is beside the site file, not beside wherever `check` ran.
pub fn script_outputs(site: &Path, src: &str) -> BTreeMap<String, ScriptOutputs> {
    let dir = site.parent().unwrap_or(Path::new("."));
    script_files(src)
        .into_iter()
        .filter_map(|file| {
            let declared = extract(&dir.join(&file), dir);
            (!declared.is_empty()).then_some((file, declared))
        })
        .collect()
}

/// Every kind of `src` that names a module, as the file spells it.
fn script_files(src: &str) -> Vec<String> {
    let parse = ks_lang::parse(src);
    let mut out = Vec::new();
    for entry in parse.file().entries().filter(|e| e.key_name() == Some("steps")) {
        for step in entry.children() {
            let Some(expr) = step.expr() else { continue };
            let Some(kind) = word(&expr) else { continue };
            // A kind that is not a module's path names a step kind, and the
            // catalog answers for that, not this.
            if ks_core::script::is_script_kind(kind) {
                out.push(kind.to_string());
            }
        }
    }
    out
}

/// The step's `expr` word, when it is a plain word and not a reference.
fn word<'a>(expr: &'a ks_lang::Expr<'a>) -> Option<&'a str> {
    match expr {
        ks_lang::Expr::Atom { atom: ks_lang::Atom::Word(w), .. } => Some(w.text()),
        _ => None,
    }
}

/// What `module` declares, from the cache when the extractor's own source
/// and the module have not changed since it last ran.
fn extract(module: &Path, site: &Path) -> ScriptOutputs {
    let Ok(source) = std::fs::read(module) else { return ScriptOutputs::default() };
    let cache = site.join(CACHE).join(format!("{}.json", cache_key(&source)));
    // A cache file that is not what the extractor prints is a miss, not a
    // failed check: the extractor runs again and writes over it.
    if let Some(declared) = std::fs::read_to_string(&cache).ok().as_deref().and_then(declared) {
        return declared;
    }
    let Some(json) = run_extractor(module) else { return ScriptOutputs::default() };
    // A cache nobody can write is not a failed check: the warm path simply
    // does not exist next time.
    let _ = write_cache(&cache, &json);
    declared(&json).unwrap_or_default()
}

/// The extractor as it is bundled here plus the module as it is on disk: a
/// check reads what the two bytes say, never a stale answer to either.
fn cache_key(source: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(EXTRACTOR.as_bytes());
    hasher.update(source);
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Write beside the cache and rename over it, so a run that dies mid-write
/// leaves no half a file for the next one to read as a signature.
fn write_cache(path: &Path, json: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
}

/// The extractor's one line of JSON, or `None` when it could not be had.
fn run_extractor(module: &Path) -> Option<String> {
    let mut child = Command::new("node")
        .args(["--input-type=module", "-e", EXTRACTOR])
        .arg(module)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // Read on another thread: a module that prints at import time can fill
    // the pipe and never exit, and this waits for it to.
    let mut pipe = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    let deadline = Instant::now() + TIMEOUT;
    let read = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => {}
            Err(_) => break false,
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break false;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if !read {
        return None;
    }
    let stdout = String::from_utf8(rx.recv_timeout(TIMEOUT).ok()?).ok()?;
    let _ = reader.join();
    // One line of JSON, or nothing: a descriptor the extractor could not read
    // is not a signature. `{"error": …}` is how it reports a module that
    // would not import, which says nothing about the step.
    let line = stdout.lines().find(|l| l.trim_start().starts_with('{'))?;
    (!serde_json::from_str::<serde_json::Value>(line).ok()?.get("error").is_some())
        .then(|| line.to_string())
}

/// The tags an extractor line declares, mapped to what a checker checks
/// against. `None` for anything that is not the shape the extractor prints,
/// a corrupt cache file included.
fn declared(json: &str) -> Option<ScriptOutputs> {
    let outputs =
        serde_json::from_str::<serde_json::Value>(json).ok()?.get("outputs")?.as_object()?.clone();
    let tags: BTreeMap<String, Tag> = outputs.iter().map(|(n, t)| (n.clone(), tag(t))).collect();
    Some(ks_core::script::outputs(&tags))
}

/// The tag for one value of a descriptor: a constructor the stub made, a
/// plain JavaScript constructor, or anything at all.
fn tag(value: &serde_json::Value) -> Tag {
    let of = value.get("of").map(tag);
    match value.get("kind").and_then(serde_json::Value::as_str) {
        // What it actually was is more use than the word `unknown`.
        Some("unknown") => Tag::new(
            value.get("got").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
            None,
        ),
        Some(kind) => Tag::new(kind, of),
        None => Tag::new("unknown", None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SITE: &str = "\
steps:
  migrate: ./ship/migrate.ts
  build:   oci.image
    from:   ./Dockerfile
";

    #[test]
    fn only_a_kind_that_names_a_module_contributes_its_kind_as_spelled() {
        assert_eq!(script_files(SITE), ["./ship/migrate.ts"]);
        // Another step kind is none of this module's business, and a kind
        // that is not a module's path is not a script step.
        let site = SITE.replace("oci.image", "tofu.plan");
        assert_eq!(script_files(&site), ["./ship/migrate.ts"]);
        let site = SITE.replace("migrate: ./ship/migrate.ts", "migrate: @platform");
        assert!(script_files(&site).is_empty());
    }

    #[test]
    fn the_cache_key_covers_the_extractor_and_the_module() {
        let key = cache_key(b"export default { outputs: { applied: int() } };");
        assert_eq!(key.len(), 64);
        assert_eq!(key, cache_key(b"export default { outputs: { applied: int() } };"));
        assert_ne!(key, cache_key(b"export default { outputs: {} };"));
    }

    #[test]
    fn an_extractor_line_maps_to_what_it_declares() {
        let line = r#"{"inputs":{},"outputs":{"applied":{"kind":"int"},"rows":{"kind":"list","of":{"kind":"string"}}}}"#;
        let declared = declared(line).expect("the extractor's own shape");
        assert_eq!(declared.get("applied"), Some(&Ok(ks_core::Type::Int)));
        assert_eq!(
            declared.get("rows"),
            Some(&Ok(ks_core::Type::List(Box::new(ks_core::Type::String))))
        );
    }

    #[test]
    fn a_line_that_is_not_the_shape_the_extractor_prints_declares_nothing() {
        // A cache file that is not the extractor's shape is a miss, not an
        // answer: it must read as `None` so the module is extracted again.
        for line in ["", "not json", r#"{"outputs":"nope"}"#] {
            assert!(declared(line).is_none(), "{line}");
        }
        // A name the bridge cannot type is said out loud, not dropped: the
        // module named an output and check has to say what it could not read.
        let declared = declared(r#"{"outputs":{"applied":null}}"#).expect("a named output");
        assert!(declared.get("applied").expect("applied").is_err());
    }

    #[test]
    fn a_module_that_does_not_exist_leaves_nothing_checked() {
        let dir = std::env::temp_dir().join(format!("keepshipping-scripts-{}", std::process::id()));
        assert!(extract(&dir.join("nope.ts"), &dir).is_empty());
    }
}
