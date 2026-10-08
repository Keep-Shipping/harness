//! The `blocks` subcommands: `blocks search` asks the configured blocks index
//! for metadata about blocks matching a query, and prints it as human text or
//! JSON lines. It never touches block contents — the index is metadata only
//! by contract. `blocks publish` is the other direction: it pushes a `.ks`
//! block file to an OCI registry and refuses a breaking interface change
//! inside a release line. The compatibility rule itself lives in
//! [`crate::blocks_publish`]; this module is the wiring.
//!
//! Exit codes follow the house rules: 0 when the command ran (for a search,
//! even with no results; for a publish, when the block was published), 1 when
//! the index could not be queried or a publish was refused or failed, 2 for
//! usage and configuration problems — including "no index configured", which
//! must not masquerade as an empty result set.
//! `blocks search --offline` inherits the last rule: a query with nothing
//! cached is a 2, because "no cached answer" is a configuration problem about
//! the machine, not an empty result set.

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ks_core::ports::blocks::{BlockEntry, BlockQuery, BlocksIndexError};
use ks_core::ports::http::HttpPolicy;
use ks_core::ports::supply_chain::{Registry, SignerIdentity};
use ks_oci_distribution::{CredentialStore, OciDistribution};

use crate::args::{Command, INDEX_ENV, USAGE, parse_args};
use crate::blocks_cache::BlocksCache;
use crate::blocks_index::{HostedBlocksIndex, parse_response};
use crate::blocks_publish::{self, Version};
use crate::http_client::TcpHttpClient;
use crate::render::Format;

/// The entry point for `keepshipping blocks <subcommand>`.
pub fn blocks(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("search") => search(&args[1..]),
        Some("publish") => publish(&args[1..]),
        _ => usage(""),
    }
}

/// `keepshipping blocks publish <FILE> --version X.Y.Z --to HOST/NAMESPACE`.
///
/// Exit codes follow the house rules: 0 when the block was published, 2 for
/// usage and configuration problems — a missing flag, a version that is not
/// `MAJOR.MINOR.PATCH`, a target that is not `host/namespace` — and 1 for a
/// refusal (a version already published, one that breaks its release line) or
/// a registry that would not take the push.
fn publish(args: &[String]) -> ExitCode {
    let Some(o) = parse_args(args, Command::BlocksPublish) else {
        return usage("");
    };
    let Some(file) = o.path.as_deref() else {
        return usage("blocks publish needs the block file to publish");
    };
    // A version this build cannot compare is a usage error, refused here
    // rather than pushed and discovered at the consumer's end.
    let Some(version) = o.version.as_deref().map(str::to_string) else {
        return usage("blocks publish needs --version MAJOR.MINOR.PATCH");
    };
    let version = match Version::parse(&version) {
        Ok(version) => version,
        Err(reason) => return usage(format!("--version {reason}")),
    };
    let Some((host, namespace)) = o.target.as_deref().and_then(target_of) else {
        return usage(
            "blocks publish needs --to <host>/<namespace>, e.g. --to localhost:5001/acme/blocks",
        );
    };
    // The authority is a host the http client has to be able to parse —
    // `[::1]:5001` is a host, `:5001` and `host:x` are not. Read through the
    // client's own rules (brackets stripped, port dropped, case folded), so
    // this is how the client will treat the host too.
    let Some((host_name, _)) = crate::http_client::url_host_port(&format!("http://{host}")) else {
        return usage(format!("--to {host} is not a registry host and port"));
    };
    let host_name = host_name.to_ascii_lowercase();
    // A loopback registry is the one this command speaks plain http to, because
    // that is what a registry on this machine actually serves. Anything else is
    // `https`, and the plain-http client says so.
    let insecure = matches!(host_name.as_str(), "localhost" | "127.0.0.1" | "::1")
        .then(|| host.to_ascii_lowercase());
    let Ok(source) = std::fs::read_to_string(file) else {
        return usage(format!("{file} could not be read"));
    };
    // A README is published only when the publisher named it: a `README.md`
    // that happens to sit beside the block file may be about something else,
    // and a named one that cannot be read is an error rather than a block
    // quietly shipped without it.
    let readme = match o.readme.as_deref() {
        None => None,
        Some(path) => match std::fs::read_to_string(path) {
            Ok(text) => Some(text),
            Err(error) => return usage(format!("--readme {path} could not be read: {error}")),
        },
    };
    let block = match blocks_publish::read_definition(&source) {
        Ok(block) => block,
        Err(reason) => return usage(format!("{file}: {reason}")),
    };
    // The policy allowlists the target host alone: this command talks to the
    // registry it was pointed at and to nothing else.
    let policy =
        HttpPolicy { allowed_hosts: [host_name].into_iter().collect(), ..HttpPolicy::default() };
    let adapter = OciDistribution::new(Arc::new(TcpHttpClient::new(policy)))
        .with_credentials(CredentialStore::load())
        .with_insecure_hosts(insecure);
    // `publish` builds `{root}/{block name}` itself, and a repository string
    // starts at the registry host — so what it is given is `--to` whole.
    let root = format!("{host}/{namespace}");
    let repository = format!("{root}/{}", block.name);
    // The tags already in the repository: what the version offered is compared
    // against, and what makes a re-publish a refusal.
    let tags = match wait(adapter.tags(&repository)) {
        Ok(tags) => tags,
        Err(error) => {
            eprintln!("error: {repository}: {error}");
            return ExitCode::from(1);
        }
    };
    let registry: Arc<dyn Registry> = Arc::new(adapter);
    let request = blocks_publish::PublishRequest {
        block: &block,
        source: &source,
        readme: readme.as_deref(),
        version,
    };
    match wait(blocks_publish::publish(&registry, &tags, &root, &request)) {
        Ok(published) => {
            println!(
                "published {} {} to {}@{}",
                block.name, published.version, published.repository, published.digest
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

/// A usage problem, spelled the way the rest of the CLI spells one: what is
/// wrong, then the usage. An empty message is an unrecognizable command line,
/// which needs no explanation of its own.
fn usage(message: impl std::fmt::Display) -> ExitCode {
    let message = message.to_string();
    if !message.is_empty() {
        eprintln!("error: {message}");
    }
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

/// `--to` split into the registry authority (host, port included) and the
/// namespace inside it. Both are required: `--to host` would publish into no
/// namespace, and `--to /ns` names no host to push to. A `--to` carrying a
/// scheme is refused too — this names where to push, not a url to fetch.
fn target_of(to: &str) -> Option<(&str, &str)> {
    let (host, namespace) = to.split_once('/')?;
    let namespace = namespace.trim_end_matches('/');
    (!host.is_empty() && !namespace.is_empty() && !host.contains("://"))
        .then_some((host, namespace))
}

fn search(args: &[String]) -> ExitCode {
    let Some(o) = parse_args(args, Command::BlocksSearch) else {
        return usage("");
    };
    let Some(text) = query_text(o.query.as_deref()) else {
        return usage("blocks search needs what to look for");
    };
    let Some(base) = resolve_index(o.index.as_deref(), std::env::var(INDEX_ENV).ok().as_deref())
    else {
        return usage(format!(
            "no blocks index configured; pass --index <url> or set {INDEX_ENV} to the index base url"
        ));
    };
    if base.starts_with("https://") {
        return usage(format!(
            "{base} uses https, which the command-line client cannot speak yet; point --index at the plain-http address of the index"
        ));
    }
    if !base.starts_with("http://") {
        return usage(format!("{base} is not an absolute http url"));
    }
    let policy = HttpPolicy {
        allowed_hosts: [host_of(&base)].into_iter().collect(),
        ..HttpPolicy::default()
    };
    let index = match HostedBlocksIndex::new(base.clone(), Arc::new(TcpHttpClient::new(policy))) {
        Ok(index) => index,
        Err(message) => return usage(message),
    };
    let query = BlockQuery { text: text.to_string(), limit: o.limit };
    // Resolved once, before the branch: the online path writes through it and
    // the offline path reads from it, and `None` means this machine has no
    // cache at all — which costs the online search nothing.
    let cache = BlocksCache::in_default_root();
    let found = if o.offline {
        let hit = cache
            .as_ref()
            .and_then(|cache| cache.get(index.base(), text, o.limit))
            // A body that no longer satisfies the index contract is a miss as
            // well: the cache is an optimisation, never a source of truth.
            .and_then(|hit| parse_response(&hit.body).ok().map(|found| (hit.fetched_at, found)));
        let Some((fetched_at, found)) = hit else {
            eprintln!(
                "error: nothing cached for {text:?} at {}; run without --offline to query the index first",
                index.base()
            );
            return ExitCode::from(2);
        };
        eprintln!(
            "note: {} — served from the local blocks cache",
            cache_age(fetched_at, unix_now())
        );
        found
    } else {
        let body = match wait(index.search_body(&query)) {
            Ok(body) => body,
            Err(error) => {
                eprintln!("error: {}", index_error_text(&error));
                return ExitCode::from(1);
            }
        };
        let found = match parse_response(&body) {
            Ok(found) => found,
            Err(error) => {
                eprintln!("error: {}", index_error_text(&error));
                return ExitCode::from(1);
            }
        };
        if let Some(cache) = &cache {
            cache.put(index.base(), text, o.limit, &body, unix_now());
        }
        found
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

/// Now, in unix seconds; 0 when the clock is before the epoch, which only
/// makes a cache entry look ancient, never invalid.
fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

/// How long ago a cached entry was fetched, for the note `--offline` prints.
/// `now` is a parameter so the wording can be tested without a clock.
fn cache_age(fetched_at: u64, now: u64) -> String {
    let elapsed = now.saturating_sub(fetched_at);
    if elapsed < 60 {
        return "cached just now".to_string();
    }
    let (n, unit) = match elapsed {
        seconds if seconds < 3600 => (seconds / 60, "minute"),
        seconds if seconds < 86_400 => (seconds / 3600, "hour"),
        seconds => (seconds / 86_400, "day"),
    };
    format!("cached {n} {unit}{} ago", if n == 1 { "" } else { "s" })
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
    fn the_cache_note_reads_by_how_stale_the_entry_is() {
        let now = 1_700_000_000;
        assert_eq!(cache_age(now, now), "cached just now");
        assert_eq!(cache_age(now - 59, now), "cached just now");
        assert_eq!(cache_age(now - 60, now), "cached 1 minute ago");
        assert_eq!(cache_age(now - 600, now), "cached 10 minutes ago");
        assert_eq!(cache_age(now - 3600, now), "cached 1 hour ago");
        assert_eq!(cache_age(now - 3 * 3600, now), "cached 3 hours ago");
        assert_eq!(cache_age(now - 86_400, now), "cached 1 day ago");
        assert_eq!(cache_age(now - 3 * 86_400, now), "cached 3 days ago");
        // An entry stamped in the future (a clock that moved back) reads as
        // fresh rather than as a negative age.
        assert_eq!(cache_age(now + 100, now), "cached just now");
    }

    #[test]
    fn index_errors_are_worded_for_a_terminal() {
        let backend = BlocksIndexError::Backend { message: "the index answered 404".into() };
        let invalid = BlocksIndexError::InvalidResponse { reason: "no results field".into() };
        assert!(index_error_text(&backend).contains("could not be queried"));
        assert!(index_error_text(&invalid).contains("answered something unusable"));
    }
}
