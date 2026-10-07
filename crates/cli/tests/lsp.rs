//! End-to-end tests of `keepshipping lsp`: the server driven over the wire,
//! the way an editor drives it. The client here is deliberately small —
//! framing, a request id, and a reader thread so that a server which stops
//! answering fails the test instead of hanging it.
//!
//! One test per feature over the wire; the behaviour behind each is covered
//! in more detail by the unit tests in `ks_lsp`.

use std::io::BufReader;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{Value, json};

/// How long a test waits for one answer before giving up on the server.
const TIMEOUT: Duration = Duration::from_secs(20);

const HERO: &str = include_str!("../../lang/tests/fixtures/site-hero.ks");
const BROKEN: &str = include_str!("fixtures/site/ship.ks");

const HERO_URI: &str = "file:///hero.ks";

/// A running `keepshipping lsp`, with a thread reading its answers.
struct Client {
    child: Child,
    stdin: Option<ChildStdin>,
    messages: Receiver<Value>,
    reader: JoinHandle<()>,
    next_id: i64,
    /// Notifications read while waiting for an answer, in order.
    seen: Vec<Value>,
}

impl Client {
    fn start() -> Client {
        let mut child = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
            .arg("lsp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn keepshipping lsp");
        let stdin = child.stdin.take().expect("stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let (tx, messages) = channel();
        let reader = thread::spawn(move || {
            while let Ok(Some(message)) = ks_lsp::rpc::read_message(&mut stdout) {
                if tx.send(message).is_err() {
                    break; // the test dropped the receiver
                }
            }
        });
        Client { child, stdin: Some(stdin), messages, reader, next_id: 0, seen: Vec::new() }
    }

    /// A server already initialized and holding `text` open under `uri`.
    fn open(uri: &str, text: &str) -> Client {
        let mut client = Client::start();
        let answer = client.request(
            "initialize",
            json!({
                "processId": null,
                "capabilities": { "general": { "positionEncodings": ["utf-16", "utf-8"] } },
            }),
        );
        client.notify("initialized", json!({}));
        assert_eq!(answer["result"]["capabilities"]["positionEncoding"], "utf-16");
        client.notify(
            "textDocument/didOpen",
            json!({ "textDocument": { "uri": uri, "languageId": "keepshipping", "text": text } }),
        );
        client.notification("textDocument/publishDiagnostics");
        client
    }

    fn send(&mut self, message: Value) {
        ks_lsp::rpc::write_message(self.stdin.as_mut().expect("stdin"), &message)
            .expect("write to the server");
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.send(json!({ "jsonrpc": "2.0", "method": method, "params": params }));
    }

    /// Send a request and wait for the answer with its id, keeping every
    /// notification that arrives in between.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        loop {
            let message = self.recv();
            if message["id"] == id {
                return message;
            }
            self.seen.push(message);
        }
    }

    /// The next notification, or the next message at all.
    fn recv(&mut self) -> Value {
        match self.messages.recv_timeout(TIMEOUT) {
            Ok(message) => message,
            Err(RecvTimeoutError::Timeout) => panic!("the server stopped answering"),
            Err(RecvTimeoutError::Disconnected) => panic!("the server closed its output"),
        }
    }

    /// The first notification of `method` seen, waiting for it if need be.
    fn notification(&mut self, method: &str) -> Value {
        if let Some(index) = self.seen.iter().position(|m| m["method"] == method) {
            return self.seen.remove(index);
        }
        loop {
            let message = self.recv();
            if message["method"] == method {
                return message;
            }
            self.seen.push(message);
        }
    }

    /// Replace the whole open document, as full sync asks a client to.
    fn change(&mut self, uri: &str, text: &str) {
        self.notify(
            "textDocument/didChange",
            json!({
                "textDocument": { "uri": uri, "version": 2 },
                "contentChanges": [{ "text": text }],
            }),
        );
    }

    fn shutdown_and_exit(mut self) -> i32 {
        self.request("shutdown", json!({}));
        self.notify("exit", json!({}));
        drop(self.stdin.take());
        let status = self.child.wait().expect("the server exits");
        self.reader.join().expect("the reader thread ends");
        status.code().expect("an exit code")
    }
}

fn at(uri: &str, line: u32, character: u32) -> Value {
    json!({ "textDocument": { "uri": uri }, "position": { "line": line, "character": character } })
}

/// The line `needle` is on in `src`, as an LSP position.
fn position_of(src: &str, needle: &str) -> (u32, u32) {
    let at = src.find(needle).unwrap_or_else(|| panic!("{needle} is in the file"));
    let head = &src[..at];
    let line = head.matches('\n').count() as u32;
    (line, (at - head.rfind('\n').map_or(0, |i| i + 1)) as u32)
}

fn labels(answer: &Value) -> Vec<String> {
    answer["result"]["items"]
        .as_array()
        .expect("completion items")
        .iter()
        .map(|i| i["label"].as_str().expect("a label").to_string())
        .collect()
}

#[test]
fn initialize_then_shutdown_and_exit_leaves_no_error() {
    let mut client = Client::start();
    let answer = client.request("initialize", json!({ "processId": null }));
    let capabilities = &answer["result"]["capabilities"];
    assert_eq!(capabilities["textDocumentSync"], 1, "full sync");
    assert_eq!(capabilities["hoverProvider"], true);
    assert_eq!(capabilities["definitionProvider"], true);
    assert_eq!(capabilities["renameProvider"]["prepareProvider"], true);
    assert_eq!(answer["result"]["serverInfo"]["name"], "keepshipping");
    // Formatting and code actions are other issues; advertising them would
    // promise something this server does not do.
    assert!(capabilities.get("documentFormattingProvider").is_none());
    assert!(capabilities.get("codeActionProvider").is_none());
    assert_eq!(client.shutdown_and_exit(), 0);
}

#[test]
fn opening_a_broken_file_publishes_its_diagnostics() {
    let uri = "file:///ship.ks";
    let mut client = Client::start();
    client.request("initialize", json!({ "processId": null }));
    client.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": uri, "languageId": "keepshipping", "text": BROKEN } }),
    );
    let published = client.notification("textDocument/publishDiagnostics");
    assert_eq!(published["params"]["uri"], uri);
    let items = published["params"]["diagnostics"].as_array().expect("diagnostics");
    let mismatch = items.iter().find(|d| d["code"] == "KS0101").expect("the type mismatch");
    assert_eq!(mismatch["severity"], 1);
    assert_eq!(mismatch["source"], "keepshipping");
    assert!(mismatch["message"].as_str().expect("a message").contains("oci.Digest"), "{mismatch}");
    let (line, _) = position_of(BROKEN, "build.tag");
    assert_eq!(mismatch["range"]["start"]["line"], line);
    assert_eq!(client.shutdown_and_exit(), 0);
}

#[test]
fn hovering_a_reference_names_its_type_and_the_step_behind_it() {
    let mut client = Client::open(HERO_URI, HERO);
    let (line, character) = position_of(HERO, "build.digest");
    let answer = client.request("textDocument/hover", at(HERO_URI, line, character + 2));
    let text = answer["result"]["contents"]["value"].as_str().expect("markdown");
    assert!(text.contains("build.digest: oci.Digest"), "{text}");
    assert!(text.contains("oci.image"), "the step's kind: {text}");
    assert!(
        text.contains("Build a container image from a Dockerfile"),
        "the doc line for that kind: {text}"
    );
    assert_eq!(answer["result"]["range"]["start"]["line"], line);
    assert_eq!(client.shutdown_and_exit(), 0);
}

#[test]
fn a_definition_jumps_from_a_reference_to_the_step_key() {
    let mut client = Client::open(HERO_URI, HERO);
    let (line, character) = position_of(HERO, "build.digest");
    let answer = client.request("textDocument/definition", at(HERO_URI, line, character));
    assert_eq!(answer["result"]["uri"], HERO_URI);
    assert_eq!(answer["result"]["range"]["start"]["line"], 5, "the `build:` key");
    assert_eq!(client.shutdown_and_exit(), 0);
}

#[test]
fn completion_offers_kinds_inputs_and_outputs() {
    let mut client = Client::open(HERO_URI, HERO);

    // A step header's value is a step kind.
    client.change(HERO_URI, "steps:\n  build: ");
    let answer = client.request("textDocument/completion", at(HERO_URI, 1, 10));
    assert!(labels(&answer).contains(&"oci.image".to_string()), "{answer}");

    // A key inside a step is one of that kind's inputs.
    client.change(HERO_URI, "steps:\n  build: oci.image\n    ");
    let answer = client.request("textDocument/completion", at(HERO_URI, 2, 4));
    assert_eq!(
        labels(&answer),
        [
            "from",
            "context",
            "args",
            "secrets",
            "platforms",
            "target",
            "push",
            "sign",
            "sbom",
            "cache",
            "when"
        ]
    );

    // `build.` is one of that step's outputs.
    client.change(HERO_URI, "steps:\n  build: oci.image\n  deploy: k8s.rollout\n    image: build.");
    let answer = client.request("textDocument/completion", at(HERO_URI, 3, 17));
    assert_eq!(labels(&answer), ["digest", "ref", "tag", "signed", "sbom", "platforms"]);
    assert_eq!(client.shutdown_and_exit(), 0);
}

#[test]
fn a_rename_rewrites_the_header_and_every_reference() {
    let mut client = Client::open(HERO_URI, HERO);
    let (line, character) = position_of(HERO, "build.digest");

    let prepared = client.request("textDocument/prepareRename", at(HERO_URI, line, character));
    assert_eq!(prepared["result"]["placeholder"], "build");

    let answer = client.request(
        "textDocument/rename",
        json!({
            "textDocument": { "uri": HERO_URI },
            "position": { "line": line, "character": character },
            "newName": "compile",
        }),
    );
    let edits = answer["result"]["changes"][HERO_URI].as_array().expect("edits").clone();
    assert_eq!(edits.len(), 2, "{answer}");
    assert_eq!(edits[0]["range"]["start"]["line"], 5, "the `build:` key");
    assert_eq!(edits[1]["range"]["start"]["line"], line, "the reference");
    assert_eq!(edits[1]["newText"], "compile");
    assert_eq!(client.shutdown_and_exit(), 0);
}
