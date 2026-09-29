//! The `blocks search` command: asks the configured blocks index for
//! metadata about blocks matching a query, and prints it as human text or
//! JSON lines. It never touches block contents — the index is metadata only
//! by contract.
//!
//! Exit codes follow the house rules: 0 when the search ran (even with no
//! results), 1 when the index could not be queried, 2 for usage and
//! configuration problems — including "no index configured", which must not
//! masquerade as an empty result set.

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

use ks_core::ports::blocks::{BlockEntry, BlockQuery, BlocksIndex, BlocksIndexError};
use ks_core::ports::http::HttpPolicy;
use ks_core::ports::supply_chain::SignerIdentity;

use crate::args::{Command, INDEX_ENV, USAGE, parse_args};
use crate::blocks_index::HostedBlocksIndex;
use crate::http_client::TcpHttpClient;
use crate::render::Format;

/// The entry point for `keepshipping blocks <subcommand>`; today only
/// `search` exists.
pub fn blocks(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("search") => search(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn search(args: &[String]) -> ExitCode {
    let Some(o) = parse_args(args, Command::BlocksSearch) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(text) = query_text(o.query.as_deref()) else {
        eprintln!("error: blocks search needs what to look for");
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(base) = resolve_index(o.index.as_deref(), std::env::var(INDEX_ENV).ok().as_deref())
    else {
        eprintln!(
            "error: no blocks index configured; pass --index <url> or set {INDEX_ENV} to the index base url"
        );
        return ExitCode::from(2);
    };
    if base.starts_with("https://") {
        eprintln!(
            "error: {base} uses https, which the command-line client cannot speak yet; point --index at the plain-http address of the index"
        );
        return ExitCode::from(2);
    }
    if !base.starts_with("http://") {
        eprintln!("error: {base} is not an absolute http url");
        return ExitCode::from(2);
    }
    let policy = HttpPolicy {
        allowed_hosts: [host_of(&base)].into_iter().collect(),
        ..HttpPolicy::default()
    };
    let index = match HostedBlocksIndex::new(base, Arc::new(TcpHttpClient::new(policy))) {
        Ok(index) => index,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let query = BlockQuery { text: text.to_string(), limit: o.limit };
    let found = match wait(index.search(&query)) {
        Ok(found) => found,
        Err(error) => {
            eprintln!("error: {}", index_error_text(&error));
            return ExitCode::from(1);
        }
    };
    let mut out = std::io::stdout().lock();
    let rendered = match o.format {
        Format::Json => {
            for entry in &found {
                let _ = writeln!(out, "{}", json_line(entry));
            }
            Ok(())
        }
        _ if found.is_empty() => {
            writeln!(out, "no blocks match {text:?}").map_err(|e| e.to_string())
        }
        _ => human(&mut out, &found).map_err(|e| e.to_string()),
    };
    if let Err(message) = rendered {
        eprintln!("error: writing the results failed ({message})");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// The search text: one non-empty positional, trimmed of its surrounding
/// whitespace. An empty or whitespace-only query is a usage error, not a
/// "list everything" request.
fn query_text(raw: Option<&str>) -> Option<&str> {
    let text = raw?.trim();
    (!text.is_empty()).then_some(text)
}

/// Which index to ask: `--index` when given, else `INDEX_ENV`. Both are
/// trimmed; a blank value counts as unset. Pure, so tests need no
/// environment mutation.
fn resolve_index(flag: Option<&str>, env: Option<&str>) -> Option<String> {
    let from = flag.map(|v| v.trim()).filter(|v| !v.is_empty());
    from.or_else(|| env.map(|v| v.trim()).filter(|v| !v.is_empty())).map(String::from)
}

/// The index host, for the policy allowlist: the only host this command may
/// ever talk to. Pulled through the same URL rules the policy check applies
/// (host only, no port, no userinfo, brackets stripped) so the allowlist
/// entry matches exactly; `resolve_index` and `HostedBlocksIndex::new` have
/// already pinned the base to an absolute http url.
fn host_of(base: &str) -> String {
    let (host, _port) = crate::http_client::url_host_port(base).expect("an absolute http base url");
    host.to_ascii_lowercase()
}

/// The port's errors, worded for a terminal.
fn index_error_text(error: &BlocksIndexError) -> String {
    match error {
        BlocksIndexError::Backend { message } => {
            format!("the blocks index could not be queried ({message})")
        }
        BlocksIndexError::InvalidResponse { reason } => {
            format!("the blocks index answered something unusable: {reason}")
        }
    }
}

/// Runs a search future to completion. The command's futures are all ready
/// on their first poll — the HTTP client does blocking I/O inside `send` —
/// so a busy poll with a noop waker terminates; this is the same shape
/// `ks_testing::block_on` uses, inlined because ks-testing is a
/// dev-dependency and must not ship in the binary.
fn wait<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    loop {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}

/// Human output: one stanza per block — name, publisher, versions with
/// signature status, then the first meaningful readme line — with a blank
/// line between stanzas.
fn human(w: &mut impl Write, found: &[BlockEntry]) -> std::io::Result<()> {
    for (n, entry) in found.iter().enumerate() {
        if n > 0 {
            writeln!(w)?;
        }
        writeln!(w, "{}", entry.name)?;
        writeln!(w, "  publisher: {}", publisher_text(&entry.publisher))?;
        for version in &entry.versions {
            writeln!(w, "  {}  {}  {}", version.version, version.digest, version.signature)?;
        }
        if let Some(line) = entry.readme.lines().map(str::trim).find(|l| !l.is_empty()) {
            writeln!(w, "  readme: {line}")?;
        }
    }
    Ok(())
}

fn publisher_text(publisher: &SignerIdentity) -> String {
    match publisher {
        SignerIdentity::Keyless { issuer, subject } => {
            format!("keyless:{subject} (issuer {issuer})")
        }
        SignerIdentity::Key { key_id } => format!("key:{key_id}"),
    }
}

/// One JSON object per line (JSON Lines, like `check --format json`):
/// machine-readable without dragging in a serialization story beyond the
/// string escaper `render` already owns.
fn json_line(entry: &BlockEntry) -> String {
    let mut out = String::new();
    out.push_str("{\"name\":");
    out.push_str(&crate::render::json_str(&entry.name));
    out.push_str(",\"publisher\":");
    out.push_str(&publisher_json(&entry.publisher));
    out.push_str(",\"readme\":");
    out.push_str(&crate::render::json_str(&entry.readme));
    out.push_str(",\"versions\":[");
    for (n, version) in entry.versions.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        out.push_str("{\"version\":");
        out.push_str(&crate::render::json_str(&version.version));
        out.push_str(",\"digest\":");
        out.push_str(&crate::render::json_str(&version.digest.to_string()));
        out.push_str(",\"signature\":");
        out.push_str(&crate::render::json_str(version.signature.as_str()));
        out.push('}');
    }
    out.push_str("]}");
    out
}

fn publisher_json(publisher: &SignerIdentity) -> String {
    match publisher {
        SignerIdentity::Keyless { issuer, subject } => format!(
            "{{\"kind\":\"keyless\",\"issuer\":{},\"subject\":{}}}",
            crate::render::json_str(issuer),
            crate::render::json_str(subject)
        ),
        SignerIdentity::Key { key_id } => {
            format!("{{\"kind\":\"key\",\"key_id\":{}}}", crate::render::json_str(key_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::ports::blocks::{BlockVersion, SignatureStatus};
    use ks_core::ports::supply_chain::Digest;

    fn entry() -> BlockEntry {
        BlockEntry {
            name: "acme/rollout".to_string(),
            publisher: SignerIdentity::Keyless {
                issuer: "https://token.example".to_string(),
                subject: "acme/deploy@v1".to_string(),
            },
            readme: "Rolls out a build.\n\nDetails:\n- blue/green\n".to_string(),
            versions: vec![BlockVersion {
                version: "1.2.0".to_string(),
                digest: Digest::parse(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .expect("a valid digest"),
                signature: SignatureStatus::Signed,
            }],
        }
    }

    #[test]
    fn the_index_flag_wins_over_the_environment() {
        assert_eq!(
            resolve_index(Some("http://flag"), Some("http://env")),
            Some("http://flag".into())
        );
        assert_eq!(resolve_index(None, Some("http://env")), Some("http://env".into()));
    }

    #[test]
    fn blank_configuration_counts_as_unset() {
        assert_eq!(resolve_index(Some("   "), Some("http://env")), Some("http://env".into()));
        assert_eq!(resolve_index(None, Some("  ")), None);
        assert_eq!(resolve_index(None, None), None);
    }

    #[test]
    fn the_query_must_not_be_empty() {
        assert_eq!(query_text(Some("  rollout  ")), Some("rollout"));
        assert_eq!(query_text(Some("   ")), None);
        assert_eq!(query_text(None), None);
    }

    #[test]
    fn the_policy_allowlists_the_index_host_only() {
        assert_eq!(host_of("http://index.example/v1"), "index.example");
        assert_eq!(host_of("http://index.example:8080"), "index.example");
        assert_eq!(host_of("http://INDEX.example"), "index.example");
        assert_eq!(host_of("http://127.0.0.1:41325"), "127.0.0.1");
    }

    #[test]
    fn human_output_keeps_one_meaningful_readme_line() {
        let found = entry();
        let mut out = Vec::new();
        human(&mut out, std::slice::from_ref(&found)).expect("rendering succeeds");
        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.contains("acme/rollout\n"), "{text}");
        assert!(text.contains("publisher: keyless:acme/deploy@v1 (issuer https://token.example)"));
        assert!(text.contains(&format!("1.2.0  {}  signed", found.versions[0].digest)));
        assert!(text.contains("readme: Rolls out a build."));
        assert!(!text.contains("blue/green"), "only the first readme line is shown");
    }

    #[test]
    fn json_output_is_one_exact_line_per_entry() {
        let line = json_line(&entry());
        assert_eq!(
            line,
            "{\"name\":\"acme/rollout\",\"publisher\":{\"kind\":\"keyless\",\
             \"issuer\":\"https://token.example\",\"subject\":\"acme/deploy@v1\"},\
             \"readme\":\"Rolls out a build.\\n\\nDetails:\\n- blue/green\\n\",\
             \"versions\":[{\"version\":\"1.2.0\",\
             \"digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\
             \"signature\":\"signed\"}]}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid json");
        assert_eq!(parsed["name"], "acme/rollout");
        assert_eq!(parsed["versions"][0]["signature"], "signed");
    }

    #[test]
    fn a_key_publisher_renders_both_ways() {
        let key = SignerIdentity::Key { key_id: "2026-q3".to_string() };
        assert_eq!(publisher_text(&key), "key:2026-q3");
        assert_eq!(publisher_json(&key), "{\"kind\":\"key\",\"key_id\":\"2026-q3\"}");
    }

    #[test]
    fn index_errors_are_worded_for_a_terminal() {
        let backend = BlocksIndexError::Backend { message: "the index answered 404".into() };
        let invalid = BlocksIndexError::InvalidResponse { reason: "no results field".into() };
        assert!(index_error_text(&backend).contains("could not be queried"));
        assert!(index_error_text(&invalid).contains("answered something unusable"));
    }
}
