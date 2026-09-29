//! End-to-end tests of `keepshipping blocks search`: configuration and
//! usage errors, the wire traffic against a local index, and the exit-code
//! contract — a search that ran is 0 even with no results, an index that
//! could not be queried is 1, and a missing or misconfigured index is 2,
//! never a silent empty answer.

use std::io::{BufRead, BufReader, Write as _};
use std::net::SocketAddr;
use std::process::Command;
use std::sync::{Arc, Mutex};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const INDEX_ANSWER: &str = r##"{"results":[{"name":"acme/rollout","publisher":{"kind":"keyless","issuer":"https://token.example","subject":"acme/deploy@v1"},"readme":"Rolls out a build.\n","versions":[{"version":"1.2.0","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature":"signed"}]}]}
"##;

fn keepshipping(args: &[&str]) -> (i32, String, String) {
    run_with(None, args, &[])
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
fn serve_one(response: String) -> (SocketAddr, Arc<Mutex<String>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    let captured = Arc::new(Mutex::new(String::new()));
    let record = Arc::clone(&captured);
    std::thread::spawn(move || {
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
    (address, captured)
}

fn http_response(status_line: &str, body: &str) -> String {
    format!(
        "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
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
    let (address, captured) = serve_one(http_response("HTTP/1.1 200 OK", INDEX_ANSWER));
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
    let (address, captured) = serve_one(http_response("HTTP/1.1 200 OK", INDEX_ANSWER));
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
    let (address, _) = serve_one(http_response("HTTP/1.1 200 OK", INDEX_ANSWER));
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
    let (address, _) = serve_one(http_response("HTTP/1.1 200 OK", r#"{"results":[]}"#));
    let (code, stdout, stderr) =
        keepshipping(&["blocks", "search", "rollout", "--index", &format!("http://{address}")]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(stdout, "no blocks match \"rollout\"\n");
}

#[test]
fn an_index_that_cannot_be_queried_is_exit_one() {
    let (address, _) = serve_one(http_response("HTTP/1.1 404 Not Found", "{}"));
    let (code, _stdout, stderr) =
        keepshipping(&["blocks", "search", "rollout", "--index", &format!("http://{address}")]);
    assert_eq!(code, 1);
    assert!(stderr.contains("could not be queried"), "{stderr}");
    assert!(stderr.contains("404"), "{stderr}");
}

#[test]
fn a_broken_index_answer_is_exit_one_never_an_empty_result() {
    let (address, _) = serve_one(http_response("HTTP/1.1 200 OK", r#"{"results":42}"#));
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

#[test]
fn usage_mistakes_are_exit_two() {
    for args in [
        vec!["blocks"],                 // no subcommand
        vec!["blocks", "publish", "x"], // unknown subcommand
        vec!["blocks", "search"],       // no query
        vec!["blocks", "search", "  "], // blank query
        vec!["blocks", "search", "rollout", "--limit", "0"],
        vec!["blocks", "search", "rollout", "--limit", "lots"],
        vec!["blocks", "search", "rollout", "--format", "github"],
        vec!["blocks", "search", "rollout", "--all"],
    ] {
        let (code, _stdout, stderr) = keepshipping(&args);
        assert_eq!(code, 2, "{args:?}: {stderr}");
    }
}
