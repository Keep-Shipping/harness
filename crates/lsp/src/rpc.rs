//! The LSP base protocol: `Content-Length`-framed JSON-RPC on a pair of
//! streams. Hand-rolled on [`serde_json`] so the CLI keeps its dependency
//! list (and its binary) small.

use std::io::{self, BufRead, Write};

/// The largest body we will read. A `Content-Length` a client sends by
/// mistake — or names to make us allocate — is refused rather than
/// believed: a language server that aborts on a malformed frame is worse
/// than one that says so.
const MAX_BODY: usize = 64 * 1024 * 1024;

/// Read one framed message. `Ok(None)` at end of stream; `Err` on a header
/// the protocol does not allow.
pub fn read_message(input: &mut impl BufRead) -> io::Result<Option<serde_json::Value>> {
    let mut length: Option<usize> = None;
    loop {
        let mut header = String::new();
        if input.read_line(&mut header)? == 0 {
            return Ok(None); // end of stream between messages
        }
        let header = header.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            break; // end of the header block
        }
        let Some((name, value)) = header.split_once(':') else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed header"));
        };
        if name.trim().eq_ignore_ascii_case("Content-Length") {
            length = value.trim().parse::<usize>().ok();
            if length.is_none() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad Content-Length"));
            }
        }
        // Other headers (`Content-Type`) carry no meaning for us.
    }
    let length = length.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no length"))?;
    if length > MAX_BODY {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
    }
    let mut body = vec![0u8; length];
    input.read_exact(&mut body)?;
    // A body that is not JSON is the client's mistake, not a reason to stop:
    // report it as a null message and let the caller answer ParseError.
    Ok(Some(serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)))
}

/// Write one message, framed and newline-terminated.
pub fn write_message(output: &mut impl Write, message: &serde_json::Value) -> io::Result<()> {
    let body = serde_json::to_vec(message)?;
    write!(output, "Content-Length: {}\r\n\r\n", body.len())?;
    output.write_all(&body)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(body: &str) -> String {
        format!("Content-Length: {}\r\n\r\n{body}", body.len())
    }

    #[test]
    fn a_message_round_trips_through_the_frames() {
        let mut wire = Vec::new();
        write_message(&mut wire, &serde_json::json!({ "id": 1 })).expect("write");
        assert_eq!(String::from_utf8(wire.clone()).expect("utf8"), frame(r#"{"id":1}"#));
        let mut input = wire.as_slice();
        assert_eq!(read_message(&mut input).expect("read"), Some(serde_json::json!({ "id": 1 })));
        assert_eq!(read_message(&mut input).expect("eof"), None);
    }

    #[test]
    fn extra_headers_are_skipped_and_a_bare_lf_is_accepted() {
        let body = r#"{"method":"exit"}"#;
        let wire = format!(
            "Content-Type: application/vscode-jsonrpc\nContent-Length: {}\n\n{body}",
            body.len()
        );
        let mut input = wire.as_bytes();
        assert_eq!(
            read_message(&mut input).expect("read"),
            Some(serde_json::json!({ "method": "exit" }))
        );
    }

    #[test]
    fn a_body_that_is_not_json_comes_back_as_null_rather_than_an_error() {
        let wire = frame("not json at all");
        let mut input = wire.as_bytes();
        assert_eq!(read_message(&mut input).expect("read"), Some(serde_json::Value::Null));
    }

    #[test]
    fn a_length_the_client_made_up_is_refused_rather_than_allocated() {
        let wire = "Content-Length: 1000000000000\r\n\r\n{}";
        let mut input = wire.as_bytes();
        assert!(read_message(&mut input).is_err());
    }

    #[test]
    fn a_header_without_a_length_is_an_error() {
        let mut input = b"Content-Type: whatever\r\n\r\n{}".as_slice();
        assert!(read_message(&mut input).is_err());
    }

    #[test]
    fn two_messages_in_one_read_are_taken_one_at_a_time() {
        let wire = format!("{}{}", frame(r#"{"id":1}"#), frame(r#"{"id":2}"#));
        let mut input = wire.as_bytes();
        assert_eq!(
            read_message(&mut input).expect("first").expect("some"),
            serde_json::json!({"id":1})
        );
        assert_eq!(
            read_message(&mut input).expect("second").expect("some"),
            serde_json::json!({"id":2})
        );
    }
}
