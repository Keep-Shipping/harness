//! The server loop: one document store, one message at a time, over the
//! stdio transport LSP is defined on. Everything it answers comes from
//! [`crate::analysis`]; this module only speaks the protocol.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{Value, json};

use ks_core::script::ScriptOutputs;

use crate::analysis::{self, Doc};
use crate::rpc;
use crate::text::Encoding;

/// What the module a script step's kind names declares: the document's own
/// path and the text it currently holds, keyed by the kind path as spelled.
pub type ScriptProvider = fn(&Path, &str) -> BTreeMap<String, ScriptOutputs>;

/// JSON-RPC error codes, from the base protocol.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// Serve LSP on stdin and stdout until the client disconnects. Exits 0 when
/// the client asked to stop properly, 1 when the stream ended without a
/// shutdown — the exit code editors read as "do not reconnect quietly".
pub fn serve() -> ExitCode {
    serve_stream(&mut BufReader::new(io::stdin().lock()), io::stdout())
}

/// Serve as [`serve`], with what a `script` step's module declares.
///
/// The checker is pure, so the only way it can know what a TypeScript step
/// declares is if something reads the module for it. That something needs a
/// filesystem and a process, which this crate has no business owning — the
/// caller owns it and hands it over here.
pub fn serve_with(scripts: ScriptProvider) -> ExitCode {
    serve_stream_with(&mut BufReader::new(io::stdin().lock()), io::stdout(), Some(scripts))
}

/// The loop, over any pair of streams. Returns the process exit code.
pub fn serve_stream(input: &mut impl BufRead, output: impl Write) -> ExitCode {
    serve_stream_with(input, output, None)
}

/// The loop, with `scripts` answering what a `script` step in an open
/// document declares. `None` — the default — leaves every `script` step's
/// outputs unchecked.
pub fn serve_stream_with(
    input: &mut impl BufRead,
    output: impl Write,
    scripts: Option<ScriptProvider>,
) -> ExitCode {
    let mut server = Server::new(output, scripts);
    loop {
        let message = match rpc::read_message(input) {
            // A frame the protocol does not allow: say so and carry on.
            Err(_) => {
                server.error(None, PARSE_ERROR, "malformed message");
                continue;
            }
            Ok(None) => return server.exit_code(),
            Ok(Some(Value::Null)) => {
                server.error(None, PARSE_ERROR, "malformed message");
                continue;
            }
            Ok(Some(message)) => message,
        };
        match server.handle(&message) {
            Handled::Stop => return server.exit_code(),
            Handled::Continue => {}
        }
    }
}

/// The documents the client has open, what has been negotiated, and where
/// answers go.
struct Server<W> {
    docs: HashMap<String, Doc>,
    encoding: Encoding,
    shutting_down: bool,
    out: W,
    /// What a `script` step declares, when the caller can read it.
    scripts: Option<ScriptProvider>,
}

enum Handled {
    Continue,
    Stop,
}

impl<W: Write> Server<W> {
    fn new(out: W, scripts: Option<ScriptProvider>) -> Server<W> {
        Server {
            docs: HashMap::new(),
            encoding: Encoding::default(),
            shutting_down: false,
            out,
            scripts,
        }
    }

    fn exit_code(&self) -> ExitCode {
        if self.shutting_down { ExitCode::SUCCESS } else { ExitCode::from(1) }
    }

    fn handle(&mut self, message: &Value) -> Handled {
        // A message with no `method` is a response to something we never
        // asked for. JSON-RPC says a response is never answered, so it is
        // dropped rather than turned into an error about a missing method.
        let Some(method) = message["method"].as_str().map(str::to_string) else {
            return Handled::Continue;
        };
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let id = message.get("id").cloned().filter(|id| !id.is_null());
        match method.as_str() {
            "exit" => return Handled::Stop,
            "initialized" | "$/setTrace" => {}
            "textDocument/didOpen" | "textDocument/didChange" => self.change(&method, &params),
            "textDocument/didClose" => self.close(&params),
            // Every other notification (`$/cancelRequest`, `didSave`, …) is
            // something to ignore, not something to answer.
            _ => match id {
                None => {}
                Some(id) if self.shutting_down => {
                    self.error(Some(&id), INVALID_REQUEST, "the server is shutting down")
                }
                Some(id) => self.request(&id, &method, &params),
            },
        }
        Handled::Continue
    }

    fn request(&mut self, id: &Value, method: &str, params: &Value) {
        let result: Result<Option<Value>, String> = match method {
            "initialize" => Ok(Some(self.initialize(params))),
            "shutdown" => {
                self.shutting_down = true;
                Ok(Some(Value::Null))
            }
            "textDocument/hover" => Ok(self.with_doc(params, analysis::hover).flatten()),
            "textDocument/definition" => Ok(self
                .with_doc(params, |doc, offset| analysis::definition(doc, &uri_of(params), offset))
                .flatten()),
            "textDocument/completion" => Ok(self.with_doc(params, analysis::completion)),
            "textDocument/prepareRename" => {
                Ok(self.with_doc(params, analysis::prepare_rename).flatten())
            }
            "textDocument/rename" => self.rename(params),
            _ => Err(format!("unsupported request `{method}`")),
        };
        match result {
            Ok(Some(result)) => self.answer(id, result),
            Ok(None) => self.answer(id, Value::Null),
            Err(message) => {
                // A name we would refuse to rename is the client's mistake,
                // not an unknown method.
                let code =
                    if method == "textDocument/rename" { INVALID_PARAMS } else { METHOD_NOT_FOUND };
                self.error(Some(id), code, &message);
            }
        }
    }

    fn initialize(&mut self, params: &Value) -> Value {
        self.encoding = negotiate_encoding(params);
        json!({
            "capabilities": {
                "positionEncoding": encoding_name(self.encoding),
                "textDocumentSync": 1,
                "hoverProvider": true,
                "definitionProvider": true,
                "renameProvider": { "prepareProvider": true },
                "completionProvider": { "triggerCharacters": [".", ":", " "] },
            },
            "serverInfo": { "name": "keepshipping", "version": env!("CARGO_PKG_VERSION") },
        })
    }

    /// A full text sync: the last change carries the whole document.
    fn change(&mut self, method: &str, params: &Value) {
        let uri = uri_of(params);
        let text = if method == "textDocument/didOpen" {
            params["textDocument"]["text"].as_str().unwrap_or_default().to_string()
        } else {
            params["contentChanges"]
                .as_array()
                .and_then(|changes| changes.last())
                .and_then(|change| change["text"].as_str())
                .unwrap_or_default()
                .to_string()
        };
        let scripts = self.declared(&uri, &text).unwrap_or_default();
        let doc = Doc::new_with(text, self.encoding, &scripts);
        self.docs.insert(uri.clone(), doc);
        self.publish(&uri);
    }

    fn close(&mut self, params: &Value) {
        let uri = uri_of(params);
        self.docs.remove(&uri);
        // Diagnostics for a closed file are cleared, or the editor keeps
        // showing squiggles for a file it is no longer looking at.
        self.notify("textDocument/publishDiagnostics", json!({ "uri": uri, "diagnostics": [] }));
    }

    /// What a `script` step in `uri` declares, from the caller's provider.
    /// `None` when there is no provider or the document is not a file on
    /// disk — a document with no path has no module beside it.
    fn declared(&self, uri: &str, text: &str) -> Option<BTreeMap<String, ScriptOutputs>> {
        let scripts = self.scripts?;
        let path = path_of(uri)?;
        Some(scripts(&path, text))
    }

    /// Re-check the open document and publish its diagnostics.
    fn publish(&mut self, uri: &str) {
        let Some(doc) = self.docs.get(uri) else { return };
        let payload = analysis::diagnostics(doc, uri);
        self.notify("textDocument/publishDiagnostics", payload);
    }

    /// Run `f` against the document a position names, or answer `null`.
    fn with_doc<T>(&self, params: &Value, f: impl FnOnce(&Doc, u32) -> T) -> Option<T> {
        let doc = self.docs.get(&uri_of(params))?;
        Some(f(doc, doc.offset_at(&params["position"])))
    }

    fn rename(&self, params: &Value) -> Result<Option<Value>, String> {
        let new_name = params["newName"].as_str().unwrap_or_default();
        let uri = uri_of(params);
        self.with_doc(params, |doc, offset| analysis::rename(doc, &uri, offset, new_name))
            .transpose()
    }

    fn answer(&mut self, id: &Value, result: Value) {
        self.send(json!({ "jsonrpc": "2.0", "id": id, "result": result }));
    }

    fn error(&mut self, id: Option<&Value>, code: i64, message: &str) {
        let id = id.cloned().unwrap_or(Value::Null);
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": code, "message": message },
        }));
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.send(json!({ "jsonrpc": "2.0", "method": method, "params": params }));
    }

    fn send(&mut self, message: Value) {
        // A broken pipe means the editor went away; the exit code already
        // tells it so, and stderr is not ours to write to.
        let _ = rpc::write_message(&mut self.out, &message);
    }
}

/// The document a request is about (`file:///…`, exactly as the client
/// spelled it — the server keeps no other identifier).
fn uri_of(params: &Value) -> String {
    params["textDocument"]["uri"].as_str().unwrap_or_default().to_string()
}

/// The path a `file://` URI names, or `None` for anything else: enough of
/// RFC 3986 to open a file the client already has — the scheme, the empty
/// authority a local file has, and the percent-escapes a path can carry.
fn path_of(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    let rest = rest.get(rest.find('/')?..)?;
    let mut out: Vec<u8> = Vec::with_capacity(rest.len());
    let mut at = 0;
    while at < rest.len() {
        if rest[at..].starts_with('%') {
            out.push(u8::from_str_radix(rest.get(at + 1..at + 3)?, 16).ok()?);
            at += 3;
        } else {
            let ch = rest[at..].chars().next()?;
            out.extend_from_slice(&rest.as_bytes()[at..at + ch.len_utf8()]);
            at += ch.len_utf8();
        }
    }
    // A NUL in a path is not a path; anything else the client wrote is the
    // client's business, not this server's.
    String::from_utf8(out).ok().filter(|s| !s.contains('\0')).map(PathBuf::from)
}

/// UTF-16, the encoding LSP defaults to and every client lists, unless the
/// client says it can only speak UTF-8.
fn negotiate_encoding(params: &Value) -> Encoding {
    let offered = params["capabilities"]["general"]["positionEncodings"].as_array();
    match offered {
        Some(encodings) if !encodings.is_empty() && encodings.iter().all(|e| e == "utf-8") => {
            Encoding::Utf8
        }
        _ => Encoding::Utf16,
    }
}

fn encoding_name(encoding: Encoding) -> &'static str {
    match encoding {
        Encoding::Utf16 => "utf-16",
        Encoding::Utf8 => "utf-8",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive `serve_stream` over a scripted conversation, collecting every
    /// message it writes.
    fn talk(requests: &[&str]) -> (ExitCode, Vec<Value>) {
        let mut input = Vec::new();
        for request in requests {
            rpc::write_message(&mut input, &serde_json::from_str(request).expect("a message"))
                .expect("frame");
        }
        let mut output = Vec::new();
        let code = serve_stream(&mut input.as_slice(), &mut output);
        let messages = String::from_utf8(output).expect("utf8");
        let mut read = messages.as_bytes();
        let mut out = Vec::new();
        while let Some(message) = rpc::read_message(&mut read).expect("read") {
            out.push(message);
        }
        (code, out)
    }

    #[test]
    fn a_file_uri_names_the_path_it_can_open() {
        assert_eq!(path_of("file:///a/ship.ks"), Some(PathBuf::from("/a/ship.ks")));
        // A path a client percent-escaped is the path it means.
        assert_eq!(
            path_of("file:///a/my%20site/ship.ks"),
            Some(PathBuf::from("/a/my site/ship.ks"))
        );
        // A path a client percent-escaped wrongly is not one to guess at.
        assert_eq!(path_of("file:///a/ship.ks%zz"), None);
        // Anything that is not a file on disk names no path to read beside.
        assert_eq!(path_of("untitled:Untitled-1"), None);
        assert_eq!(path_of(""), None);
    }

    #[test]
    fn a_shutdown_then_exit_succeeds() {
        let (code, seen) = talk(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"initialized","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"shutdown"}"#,
            r#"{"jsonrpc":"2.0","method":"exit"}"#,
        ]);
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(seen.len(), 2, "one answer per request");
        assert_eq!(seen[0]["id"], 1);
        assert_eq!(seen[0]["result"]["capabilities"]["hoverProvider"], true);
        assert_eq!(seen[0]["result"]["capabilities"]["positionEncoding"], "utf-16");
        assert_eq!(seen[1]["result"], Value::Null);
    }

    #[test]
    fn a_stream_that_ends_without_a_shutdown_fails() {
        let (code, _) = talk(&[r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#]);
        assert_eq!(code, ExitCode::from(1));
    }

    #[test]
    fn a_client_that_can_only_speak_utf8_gets_utf8_positions() {
        let (_, seen) = talk(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{"general":{"positionEncodings":["utf-8"]}}}}"#,
        ]);
        assert_eq!(seen[0]["result"]["capabilities"]["positionEncoding"], "utf-8");
        let (_, seen) = talk(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{"general":{"positionEncodings":["utf-8","utf-16"]}}}}"#,
        ]);
        assert_eq!(seen[0]["result"]["capabilities"]["positionEncoding"], "utf-16");
    }

    #[test]
    fn a_request_after_shutdown_is_refused() {
        let (_, seen) = talk(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"shutdown"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"textDocument/hover","params":{}}"#,
        ]);
        assert_eq!(seen[1]["error"]["code"], INVALID_REQUEST);
    }

    #[test]
    fn an_unknown_method_is_method_not_found() {
        let (_, seen) = talk(&[r#"{"jsonrpc":"2.0","id":7,"method":"textDocument/codeAction"}"#]);
        assert_eq!(seen[0]["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(seen[0]["id"], 7);
    }

    #[test]
    fn an_unknown_notification_is_ignored_in_silence() {
        let (code, seen) = talk(&[
            r#"{"jsonrpc":"2.0","method":"$/setTrace","params":{"value":"verbose"}}"#,
            r#"{"jsonrpc":"2.0","method":"telemetry/somethingNew"}"#,
        ]);
        assert!(seen.is_empty(), "{seen:?}");
        assert_eq!(code, ExitCode::from(1));
    }

    /// A response to a request we never made. JSON-RPC says a response is
    /// never answered, so it must not come back as an error either.
    #[test]
    fn a_response_is_dropped_in_silence() {
        let (code, seen) = talk(&[r#"{"jsonrpc":"2.0","id":1,"result":null}"#]);
        assert!(seen.is_empty(), "{seen:?}");
        assert_eq!(code, ExitCode::from(1));
    }

    #[test]
    fn a_malformed_body_is_reported_as_a_parse_error() {
        let input = b"Content-Length: 7\r\n\r\nnot jsx".to_vec();
        let mut output = Vec::new();
        let code = serve_stream(&mut input.as_slice(), &mut output);
        assert_eq!(code, ExitCode::from(1));
        assert!(String::from_utf8(output).expect("utf8").contains("-32700"));
    }

    #[test]
    fn opening_a_file_publishes_its_diagnostics_and_closing_clears_them() {
        let broken = "steps:\n  build: oci.image\n  deploy: k8s.rollout\n    image: build.tag\n";
        let open = json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": { "textDocument": { "uri": "file:///ship.ks", "text": broken } },
        })
        .to_string();
        let close = json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didClose",
            "params": { "textDocument": { "uri": "file:///ship.ks" } },
        })
        .to_string();
        let (_, seen) = talk(&[&open, &close]);
        assert_eq!(seen.len(), 2);
        let items = seen[0]["params"]["diagnostics"].as_array().expect("diagnostics");
        assert!(items.iter().any(|d| d["code"] == "KS0101"), "{items:?}");
        assert_eq!(seen[0]["params"]["uri"], "file:///ship.ks");
        assert_eq!(seen[1]["params"]["diagnostics"], json!([]));
    }

    #[test]
    fn a_request_for_a_file_that_was_never_opened_answers_null() {
        let (_, seen) = talk(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"textDocument/hover","params":{"textDocument":{"uri":"file:///ghost.ks"},"position":{"line":0,"character":0}}}"#,
        ]);
        assert_eq!(seen[0]["result"], Value::Null);
    }

    #[test]
    fn a_rename_that_the_checker_would_refuse_is_an_invalid_params_error() {
        let text = "steps:\n  build: oci.image\n  deploy: k8s.rollout\n    image: build.digest\n";
        let open = json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": { "textDocument": { "uri": "file:///ship.ks", "text": text } },
        })
        .to_string();
        let rename = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/rename",
            "params": {
                "textDocument": { "uri": "file:///ship.ks" },
                "position": { "line": 3, "character": 13 },
                "newName": "not a name",
            },
        })
        .to_string();
        let (_, seen) = talk(&[&open, &rename]);
        let answer = seen.iter().find(|m| m["id"] == 3).expect("the answer");
        assert_eq!(answer["error"]["code"], INVALID_PARAMS);
    }
}
