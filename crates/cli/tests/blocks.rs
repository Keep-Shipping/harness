//! End-to-end tests of `keepshipping blocks search`: configuration and
//! usage errors, the wire traffic against a local index, the local cache
//! behind `--offline`, and the exit-code contract — a search that ran is 0
//! even with no results, an index that could not be queried is 1, and a
//! missing or misconfigured index is 2, never a silent empty answer.

use std::io::{BufRead, BufReader, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const INDEX_ANSWER: &str = r##"{"results":[{"name":"acme/rollout","publisher":{"kind":"keyless","issuer":"https://token.example","subject":"acme/deploy@v1"},"readme":"Rolls out a build.\n","versions":[{"version":"1.2.0","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature":"signed"}]}]}
"##;

fn keepshipping(args: &[&str]) -> (i32, String, String) {
    run_with(None, args, &[])
}

/// A fresh cache directory, removed when the test ends. The workspace has no
/// `tempfile` dependency, so this is the whole of it: a unique name under the
/// system temp directory, and a `Drop` that takes the tree with it.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TempDir {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "keepshipping-{label}-{}-{next}",
            std::process::id(),
            next = NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a cache directory");
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A port with nothing listening: the socket is bound to learn the number and
/// then dropped, so a connection to it is refused.
fn dead_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    drop(listener);
    address
}

/// Runs the binary with extra `KEY=VALUE` environment pairs for the child.
fn run_with(
    dir: Option<&std::path::Path>,
    args: &[&str],
    env: &[(&str, &str)],
) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keepshipping"));
    cmd.args(args);
    cmd.env_remove("KEEPSSHIPPING_BLOCKS_INDEX");
    for (key, value) in env {
        cmd.env(key, value);
    }
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    let out = cmd.output().expect("run keepshipping");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A one-connection HTTP server: answers with `head` + body verbatim and
/// records the request it received.
///
/// The listener lives inside the serving thread, so the port stays open for as
/// long as that thread runs and closes only when its closure returns. The
/// `JoinHandle` is therefore part of the result: a caller that needs to know
/// the port is dead must `join()` it, which proves the closure returned and the
/// listener was dropped. Dropping it detaches, which is fine for callers that
/// never look at reachability.
fn serve_one(response: String) -> (SocketAddr, Arc<Mutex<String>>, JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    let captured = Arc::new(Mutex::new(String::new()));
    let record = Arc::clone(&captured);
    let server = std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else { return };
        let mut reader = BufReader::new(stream.try_clone().expect("clone the socket"));
        let mut text = String::new();
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let head_done = line == "\r\n";
                    text.push_str(&line);
                    if head_done {
                        break;
                    }
                }
            }
        }
        *record.lock().expect("request record") = text;
        let mut stream = stream;
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    });
    (address, captured, server)
}

fn http_response(status_line: &str, body: &str) -> String {
    format!(
        "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// An index that stays up until the test ends and records every request it
/// serves, so a test can show that a command opened no connection.
///
/// Reachability of the port cannot stand in for that fact. Other tests in this
/// binary run child processes, and a child forked while this listener is open
/// inherits the socket: the copy stays listening until the child `execve`s, so
/// the port can answer even after the serving thread is long gone and joined.
/// The server itself is the reliable witness — it is still listening, and a
/// connection to it is recorded rather than refused.
struct Index {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
}

impl Index {
    fn new(response: &str) -> Index {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        // Non-blocking, so dropping the index does not have to wait on an accept
        // that may never come.
        listener.set_nonblocking(true).expect("non-blocking");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let record = Arc::clone(&requests);
        let done = Arc::clone(&stop);
        let response = response.to_string();
        let server = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ =
                            stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
                        let mut text = String::new();
                        let mut reader =
                            BufReader::new(stream.try_clone().expect("clone the socket"));
                        let mut line = String::new();
                        loop {
                            line.clear();
                            match reader.read_line(&mut line) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {
                                    let head_done = line == "\r\n";
                                    text.push_str(&line);
                                    if head_done {
                                        break;
                                    }
                                }
                            }
                        }
                        // Recorded before the answer, so a client that has read
                        // its answer has already left its request in the log.
                        record.lock().expect("request record").push(text);
                        let mut stream = stream;
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });
        Index { address, requests, stop, server: Some(server) }
    }

    /// Every request served so far, oldest first.
    fn seen(&self) -> Vec<String> {
        self.requests.lock().expect("request record").clone()
    }
}

impl Drop for Index {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(server) = self.server.take() {
            server.join().expect("the index server");
        }
    }
}

#[test]
fn without_a_configured_index_the_search_is_refused_not_emptied() {
    let (code, stdout, stderr) = keepshipping(&["blocks", "search", "rollout"]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("no blocks index configured"), "{stderr}");
    assert!(stderr.contains("KEEPSSHIPPING_BLOCKS_INDEX"), "{stderr}");
}

#[test]
fn the_environment_configures_the_index_when_the_flag_is_absent() {
    let (address, captured, _) = serve_one(http_response("HTTP/1.1 200 OK", INDEX_ANSWER));
    let (code, stdout, stderr) = run_with(
        None,
        &["blocks", "search", "rollout", "--limit", "5"],
        &[("KEEPSSHIPPING_BLOCKS_INDEX", &format!("http://{address}"))],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.contains("acme/rollout"), "{stdout}");
    let sent = captured.lock().expect("request record").clone();
    assert!(sent.starts_with("GET /v1/blocks/search?q=rollout&limit=5 HTTP/1.1\r\n"), "{sent}");
    assert!(sent.to_ascii_lowercase().contains("accept: application/json"), "{sent}");
}

#[test]
fn a_search_against_a_local_index_prints_the_metadata() {
    let (address, captured, _) = serve_one(http_response("HTTP/1.1 200 OK", INDEX_ANSWER));
    let (code, stdout, stderr) = keepshipping(&[
        "blocks",
        "search",
        "rollout",
        "--index",
        &format!("http://{address}"),
        "--limit",
        "5",
    ]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.contains("acme/rollout\n"), "{stdout}");
    assert!(
        stdout.contains("publisher: keyless:acme/deploy@v1 (issuer https://token.example)"),
        "{stdout}"
    );
    assert!(stdout.contains(&format!("1.2.0  {DIGEST}  signed")), "{stdout}");
    assert!(stdout.contains("readme: Rolls out a build."), "{stdout}");
    let sent = captured.lock().expect("request record").clone();
    assert!(sent.starts_with("GET /v1/blocks/search?q=rollout&limit=5 HTTP/1.1\r\n"), "{sent}");
    assert!(
        sent.contains(&format!("Host: {address}\r\n")),
        "the request must address the index host: {sent}"
    );
}

#[test]
fn json_output_is_one_machine_readable_line_per_block() {
    let (address, _, _) = serve_one(http_response("HTTP/1.1 200 OK", INDEX_ANSWER));
    let (code, stdout, stderr) = keepshipping(&[
        "blocks",
        "search",
        "rollout",
        "--index",
        &format!("http://{address}"),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let expected = format!(
        r#"{{"name":"acme/rollout","publisher":{{"kind":"keyless","issuer":"https://token.example","subject":"acme/deploy@v1"}},"readme":"Rolls out a build.\n","versions":[{{"version":"1.2.0","digest":"{DIGEST}","signature":"signed"}}]}}"#
    );
    assert_eq!(stdout.trim_end(), expected);
}

#[test]
fn an_empty_result_set_is_exit_zero_and_says_so() {
    let (address, _, _) = serve_one(http_response("HTTP/1.1 200 OK", r#"{"results":[]}"#));
    let (code, stdout, stderr) =
        keepshipping(&["blocks", "search", "rollout", "--index", &format!("http://{address}")]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(stdout, "no blocks match \"rollout\"\n");
}

#[test]
fn an_index_that_cannot_be_queried_is_exit_one() {
    let (address, _, _) = serve_one(http_response("HTTP/1.1 404 Not Found", "{}"));
    let (code, _stdout, stderr) =
        keepshipping(&["blocks", "search", "rollout", "--index", &format!("http://{address}")]);
    assert_eq!(code, 1);
    assert!(stderr.contains("could not be queried"), "{stderr}");
    assert!(stderr.contains("404"), "{stderr}");
}

#[test]
fn a_broken_index_answer_is_exit_one_never_an_empty_result() {
    let (address, _, _) = serve_one(http_response("HTTP/1.1 200 OK", r#"{"results":42}"#));
    let (code, stdout, stderr) =
        keepshipping(&["blocks", "search", "rollout", "--index", &format!("http://{address}")]);
    assert_eq!(code, 1, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("answered something unusable"), "{stderr}");
}

#[test]
fn an_https_index_is_refused_before_any_traffic() {
    let (code, stdout, stderr) =
        keepshipping(&["blocks", "search", "rollout", "--index", "https://index.example"]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stderr.contains("cannot speak yet"), "{stderr}");
    assert!(stderr.contains("plain-http"), "{stderr}");
}

/// Runs the binary with `dir` as its `XDG_CACHE_HOME`, so the cache starts
/// empty and leaves nothing behind.
fn cached(dir: &TempDir, args: &[&str]) -> (i32, String, String) {
    let home = dir.path().to_str().expect("a utf-8 cache directory");
    run_with(None, args, &[("XDG_CACHE_HOME", home)])
}

#[test]
fn an_online_search_is_cached_and_then_answered_offline() {
    let cache = TempDir::new("blocks-cache");
    let (address, _captured, _) = serve_one(http_response("HTTP/1.1 200 OK", INDEX_ANSWER));
    let index = format!("http://{address}");
    let (code, online, stderr) =
        cached(&cache, &["blocks", "search", "rollout", "--index", &index]);
    assert_eq!(code, 0, "{online}{stderr}");
    assert!(!stderr.contains("cache"), "the online path says nothing about caching: {stderr}");

    // Nothing is serving that address any more; the answer comes off disk.
    let (code, offline, stderr) =
        cached(&cache, &["blocks", "search", "rollout", "--index", &index, "--offline"]);
    assert_eq!(code, 0, "{offline}{stderr}");
    assert_eq!(offline, online);
    assert!(stderr.contains("local blocks cache"), "{stderr}");
    assert!(stderr.contains("cached just now"), "{stderr}");
}

#[test]
fn offline_never_opens_a_connection() {
    let cache = TempDir::new("blocks-offline-silent");
    let index_server = Index::new(&http_response("HTTP/1.1 200 OK", INDEX_ANSWER));
    let index = format!("http://{}", index_server.address);
    let (code, online, stderr) =
        cached(&cache, &["blocks", "search", "rollout", "--index", &index]);
    assert_eq!(code, 0, "{online}{stderr}");
    let seen = index_server.seen();
    assert_eq!(seen.len(), 1, "the online search made one request: {seen:?}");
    assert!(
        seen[0].starts_with("GET /v1/blocks/search?q=rollout"),
        "the online search hit the index: {}",
        seen[0]
    );

    // The index is still up, still listening, and still willing to answer — so
    // an offline search that opened a connection would be served from it and
    // recorded below. What it must not do is touch it at all.
    let (code, offline, stderr) =
        cached(&cache, &["blocks", "search", "rollout", "--index", &index, "--offline"]);
    assert_eq!(code, 0, "{offline}{stderr}");
    assert!(offline.contains("acme/rollout"), "{offline}");
    assert!(stderr.contains("local blocks cache"), "{stderr}");
    let seen = index_server.seen();
    assert_eq!(seen.len(), 1, "the offline search opened a connection to the index: {seen:?}");
}

#[test]
fn offline_with_an_empty_cache_is_exit_two() {
    let cache = TempDir::new("blocks-cache-empty");
    let (code, stdout, stderr) = cached(
        &cache,
        &[
            "blocks",
            "search",
            "rollout",
            "--index",
            &format!("http://{}", dead_port()),
            "--offline",
        ],
    );
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("nothing cached"), "{stderr}");
    assert!(stderr.contains("rollout"), "{stderr}");
    assert!(stderr.contains("without --offline"), "{stderr}");
}

#[test]
fn offline_for_a_query_never_searched_online_is_exit_two() {
    let cache = TempDir::new("blocks-cache-uncached");
    let (address, _, _) = serve_one(http_response("HTTP/1.1 200 OK", INDEX_ANSWER));
    let index = format!("http://{address}");
    let (code, _online, stderr) =
        cached(&cache, &["blocks", "search", "rollout", "--index", &index]);
    assert_eq!(code, 0, "{stderr}");
    let (code, stdout, stderr) =
        cached(&cache, &["blocks", "search", "rollback", "--index", &index, "--offline"]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("rollback"), "{stderr}");
}

#[test]
fn a_second_index_does_not_read_the_first_ones_cache() {
    let cache = TempDir::new("blocks-cache-two-indexes");
    let (address, _, _) = serve_one(http_response("HTTP/1.1 200 OK", INDEX_ANSWER));
    let (code, _online, stderr) =
        cached(&cache, &["blocks", "search", "rollout", "--index", &format!("http://{address}")]);
    assert_eq!(code, 0, "{stderr}");
    let (code, stdout, stderr) = cached(
        &cache,
        &[
            "blocks",
            "search",
            "rollout",
            "--index",
            &format!("http://{address}/mirror"),
            "--offline",
        ],
    );
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("nothing cached"), "{stderr}");
}

#[test]
fn an_empty_result_set_is_cached_too() {
    let cache = TempDir::new("blocks-cache-empty-results");
    let (address, _, _) = serve_one(http_response("HTTP/1.1 200 OK", r#"{"results":[]}"#));
    let index = format!("http://{address}");
    let (code, online, stderr) =
        cached(&cache, &["blocks", "search", "rollout", "--index", &index]);
    assert_eq!(code, 0, "{online}{stderr}");
    let (code, offline, stderr) =
        cached(&cache, &["blocks", "search", "rollout", "--index", &index, "--offline"]);
    assert_eq!(code, 0, "{offline}{stderr}");
    assert_eq!(offline, online);
    assert_eq!(offline, "no blocks match \"rollout\"\n");
}

#[test]
fn usage_mistakes_are_exit_two() {
    for args in [
        vec!["blocks"],                    // no subcommand
        vec!["blocks", "frobnicate", "x"], // unknown subcommand
        vec!["blocks", "search"],          // no query
        vec!["blocks", "search", "  "],    // blank query
        vec!["blocks", "search", "rollout", "--limit", "0"],
        vec!["blocks", "search", "rollout", "--limit", "lots"],
        vec!["blocks", "search", "rollout", "--format", "github"],
        vec!["blocks", "search", "rollout", "--all"],
    ] {
        let (code, _stdout, stderr) = keepshipping(&args);
        assert_eq!(code, 2, "{args:?}: {stderr}");
    }
}

#[test]
fn blocks_publish_usage_mistakes_are_exit_two() {
    // No block file, no version, no target: each is checked before any traffic,
    // so none of these reaches a registry. The string beside each case is what
    // the message has to name, or nothing when the exit code is the whole point.
    let publish = |args: &[&'static str]| {
        let mut all = vec!["blocks", "publish"];
        all.extend_from_slice(args);
        all
    };
    for (args, named) in [
        (vec![], ""),
        (vec!["b.ks"], "MAJOR.MINOR.PATCH"),
        (vec!["b.ks", "--version", "3.1.0"], "--to <host>/<namespace>"),
        (vec!["b.ks", "--to", "localhost:5001/acme"], "MAJOR.MINOR.PATCH"),
        // `--to` wants an authority and a namespace, and names where to push
        // rather than a url to fetch.
        (vec!["b.ks", "--version", "3.1.0", "--to", "localhost:5001"], "--to <host>/<namespace>"),
        (vec!["b.ks", "--version", "3.1.0", "--to", "/acme/blocks"], "--to <host>/<namespace>"),
        (
            vec!["b.ks", "--version", "3.1.0", "--to", "http://localhost:5001/a"],
            "is not a registry host",
        ),
        (vec!["b.ks", "--version", "3.1.0", "--to", "localhost:port/a"], "is not a registry host"),
        // A version this build cannot compare is a usage error, not a push.
        (vec!["b.ks", "--version", "3.1", "--to", "localhost:5001/a"], "MAJOR.MINOR.PATCH"),
        (vec!["b.ks", "--version", "v3.1.0", "--to", "localhost:5001/a"], "MAJOR.MINOR.PATCH"),
        (vec!["b.ks", "--version", "3.1.0-rc1", "--to", "localhost:5001/a"], "MAJOR.MINOR.PATCH"),
        // Another command's flag is not this command's.
        (vec!["b.ks", "--version", "3.1.0", "--to", "localhost:5001/a", "--all"], ""),
        (vec!["b.ks", "--version", "3.1.0", "--to", "localhost:5001/a", "--index", "http://x"], ""),
    ] {
        let args = publish(&args);
        let (code, stdout, stderr) = keepshipping(&args);
        assert_eq!(code, 2, "{args:?}: {stdout}{stderr}");
        assert!(stdout.is_empty(), "nothing is pushed: {args:?}: {stdout}");
        assert!(stderr.contains(named), "{args:?}: {stderr}");
    }
}

/// A block that ships its own `policy:` is refused at the publisher's desk
/// (ADR 0012). The target is `localhost:1`, where nothing listens: the refusal
/// has to happen before the registry is asked for anything, so a regression
/// that let it through fails as a connection error rather than hanging.
#[test]
fn a_block_that_ships_its_own_policy_is_refused_without_contacting_a_registry() {
    let dir = TempDir::new("blocks-publish-policy");
    let file = dir.path().join("web-service.ks");
    std::fs::write(&file, "block: web-service\npolicy:\n  agents:\n    never: destroy prod\n")
        .expect("write the block file");
    let path = file.to_str().expect("a utf-8 path");

    let (code, stdout, stderr) = run_with(
        None,
        &["blocks", "publish", path, "--version", "1.0.0", "--to", "localhost:1/acme"],
        &[],
    );

    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stdout.is_empty(), "nothing is published: {stdout}");
    assert!(stderr.contains("may not ship its own policy"), "{stderr}");
    assert!(stderr.contains("policy"), "the message names the rule: {stderr}");
    assert!(
        !stderr.contains("connection refused") && !stderr.contains("localhost:1"),
        "the registry is never asked: {stderr}"
    );
}
