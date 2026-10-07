/// A test-only HTTP/1.1 server fixture, shared by this module's tests and
/// `github_actions_run_context`'s: both drive the real [`TcpHttpClient`] over a
/// real socket, so one fixture serves both.
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// What the server received: the request line plus headers, as text.
/// The request lines the server saw, shared with the test that spawned it.
pub type Captured = Arc<Mutex<Vec<String>>>;

/// A one-response HTTP server on a random port: answers every connection
/// with `status` + a content-length-framed `body`, recording the request
/// lines it saw. `hold` keeps connections unanswered (for the timeout
/// test). The third tuple member counts accepted connections.
pub fn spawn(status: &str, body: &str, hold: bool) -> (SocketAddr, Captured, Arc<AtomicUsize>) {
    serve(
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        ),
        hold,
    )
}

/// The same one-response server, for an answer this client would otherwise
/// refuse to parse: `response` is written verbatim, headers and all.
pub fn spawn_raw(response: &str, hold: bool) -> (SocketAddr, Captured, Arc<AtomicUsize>) {
    serve(response.to_string(), hold)
}

/// Serves `response` verbatim to every connection, recording the request
/// lines it saw.
fn serve(response: String, hold: bool) -> (SocketAddr, Captured, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let captured_clone = Arc::clone(&captured);
    let connections_clone = Arc::clone(&connections);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            connections_clone.fetch_add(1, Ordering::SeqCst);
            let captured = Arc::clone(&captured_clone);
            let response = response.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut lines = Vec::new();
                let mut line = String::new();
                while let Ok(n) = reader.read_line(&mut line) {
                    if n == 0 || line == "\r\n" {
                        break;
                    }
                    lines.push(line.trim_end().to_string());
                    line.clear();
                }
                captured.lock().expect("capture").extend(lines);
                if hold {
                    // Never answer; the client must time out.
                    std::thread::sleep(Duration::from_secs(5));
                    return;
                }
                let mut stream = stream;
                let _ = write!(stream, "{response}");
            });
        }
    });
    (address, captured, connections)
}
