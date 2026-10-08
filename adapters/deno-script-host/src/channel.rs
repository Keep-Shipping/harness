//! The secret channel: a FIFO the parent fills while the child runs, with the
//! values never in argv, the environment, stdio or on disk
//! ([ADR 0004](../../../docs/adr/0004-secrets.md)).
//!
//! ADR 0009 planned to `dup2` a pipe onto descriptor 3 and have the script
//! reopen `/proc/self/fd/3`. Deno 2.9.7 refuses that: any grant naming a
//! `/proc/self/fd/N` path escalates the request to *all* access, which would
//! mean `--allow-all` and no sandbox at all (measured, see the report on
//! [#90](https://github.com/Keep-Shipping/harness/issues/90)). A named FIFO
//! keeps the pipe — and the values stay in memory, in a kernel buffer — while
//! the grant stays a plain `--allow-read` of one path the script has no write
//! access to.
//!
//! The wire is length-prefixed frames, big-endian, repeated until the
//! terminator: `u32` name length, name, `u32` value length, value. A zero name
//! length ends the stream, so the reader never waits for an EOF it cannot get:
//! the parent holds the write end open for the whole run.
//!
//! The frames are handed over on their own thread, never before the child is
//! running. A pipe holds 64 KiB, so a parent that filled one first blocked
//! forever on any bundle larger than that — before Deno had even started, and
//! with nothing on this side able to notice.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ks_core::ports::script_host::ScriptHostError;
use ks_core::ports::secrets::SecretBundle;

use crate::install::io_error;

/// A private FIFO holding one run's secrets.
pub struct SecretChannel {
    directory: PathBuf,
    fifo: PathBuf,
    /// The parent's `O_RDWR` handle. Held for the child's whole life so the
    /// child's `open(O_RDONLY)` never blocks, and so the wire never ends on an
    /// EOF the parent caused. Closed before the filler is joined.
    writer: Option<std::fs::File>,
    /// The thread handing the frames over, so a bundle larger than the pipe
    /// buffer waits for the child instead of waiting for a reader that does not
    /// exist yet.
    filler: Option<std::thread::JoinHandle<std::io::Result<()>>>,
}

impl SecretChannel {
    /// Creates the FIFO and starts handing `bundle`'s frames to it. The values
    /// live in a kernel pipe buffer and in this `File`; nothing is written to
    /// disk.
    ///
    /// This returns before the frames are on the wire, which is the point: a
    /// pipe holds 64 KiB, so writing a larger bundle here would block until
    /// something read it — and the child, which is the only reader, has not
    /// been started yet.
    pub fn open(bundle: &SecretBundle) -> Result<SecretChannel, ScriptHostError> {
        let directory = private_directory()?;
        let fifo = directory.join("secrets");
        make_fifo(&fifo)?;
        let writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .map_err(io_error("could not open the secret pipe", &fifo))?;
        // The filler's own handle is write-only, and that is load-bearing. A
        // clone of the `O_RDWR` handle would be a reader too, so the filler
        // could never see `EPIPE` and would sit in `write` for ever once the
        // child was gone. Write-only, the last reader to close decides: the
        // child while it is reading, and the parent on the way out.
        // This open does not block — the `O_RDWR` handle above is already a
        // reader, which is what an `O_WRONLY` open on a FIFO waits for.
        let mut pipe = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo)
            .map_err(io_error("could not open the secret pipe", &fifo))?;
        let wire = frames(bundle);
        let filler = std::thread::spawn(move || {
            use std::io::Write as _;
            pipe.write_all(&wire).and_then(|()| pipe.flush())
        });
        Ok(SecretChannel { directory, fifo, writer: Some(writer), filler: Some(filler) })
    }

    /// The path the child opens. Not a secret — it names a pipe, not a value.
    pub fn path(&self) -> &Path {
        &self.fifo
    }
}

impl Drop for SecretChannel {
    fn drop(&mut self) {
        // The parent's own handle goes first, deliberately. It is the only
        // reader left once the child is gone, and a writer blocked on a full
        // pipe only unblocks when the last reader closes — with `EPIPE`, since
        // the runtime ignores `SIGPIPE`. Joining before that would hang on
        // exactly the case this exists to survive: a child that died before it
        // ever opened the pipe.
        drop(self.writer.take());
        if let Some(filler) = self.filler.take() {
            // A failed handover can only mean the child is already gone, and
            // its exit status is the better story than an `EPIPE` here.
            let _ = filler.join();
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// A zero-length name: the end-of-stream marker, so the reader stops on data
/// rather than on an EOF the parent is holding open.
const TERMINATOR: [u8; 4] = [0, 0, 0, 0];

/// Frames one `(name, value)` pair onto `out`.
fn push_frame(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.extend_from_slice(&(name.len() as u32).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

/// The wire encoding of a whole bundle, terminator included — the bytes
/// [`SecretChannel::open`] hands the child, and what the tests hold it to.
pub fn frames(bundle: &SecretBundle) -> Vec<u8> {
    let mut out = Vec::new();
    bundle.iter().for_each(|(name, value)| {
        value.with_bytes(|bytes| {
            push_frame(&mut out, name.as_bytes(), bytes);
        });
    });
    out.extend_from_slice(&TERMINATOR);
    out
}

/// A fresh, private directory for one run's pipe.
fn private_directory() -> Result<PathBuf, ScriptHostError> {
    use std::os::unix::fs::DirBuilderExt;

    let directory = std::env::temp_dir().join(format!(
        "keepshipping-secrets-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)
        .map_err(io_error("could not create a directory for the secret pipe", &directory))?;
    Ok(directory)
}

static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Creates `path` as a FIFO with mode 0600: only this user, and only the run
/// that made it, can put a byte in it.
#[cfg(unix)]
fn make_fifo(path: &Path) -> Result<(), ScriptHostError> {
    nix::unistd::mkfifo(path, nix::sys::stat::Mode::from_bits_truncate(0o600))
        .map_err(|errno| io_error("could not create the secret pipe", path)(errno.into()))
}

/// A host without `/proc/self/fd` has no verified route to an inherited
/// descriptor (ADR 0009), so it gets the error instead of a FIFO.
#[cfg(not(unix))]
fn make_fifo(_path: &Path) -> Result<(), ScriptHostError> {
    Err(crate::install::unsupported_platform(std::env::consts::ARCH))
}

/// The `(name, value)` pairs a bundle encodes to, for the round-trip test.
///
/// This is *not* what the child runs. The decoder on the other end of the
/// wire is `readSecrets` in `bootstrap.ts`, TypeScript this crate only embeds,
/// and nothing in production calls `decode`: it is the test-side reference
/// decoder for the same framing, kept here so the wire has exactly one
/// description on this side of it. `bootstrap.ts` tolerates the same
/// truncation it is shown below — an incomplete frame ends the loop and waits
/// for more bytes rather than slicing past the end — so a stream that arrives
/// in pieces decodes the same way in both.
///
/// The lengths come off the wire, so they are checked against what is left of
/// it: a truncated or lying frame is a [`ScriptHostError`], never a slice past
/// the end of the buffer. `decode` is `pub` because a test asserts that on
/// bytes it is handed, not on bytes it produced, so it must answer for them
/// rather than abort the process on them.
pub fn decode(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, ScriptHostError> {
    let mut out = BTreeMap::new();
    let mut at = 0;
    while let Some(name_len) = length(bytes, at) {
        if name_len == 0 {
            break;
        }
        at += 4;
        let name = take(bytes, at, name_len)?;
        at += name_len;
        let Some(value_len) = length(bytes, at) else {
            break;
        };
        at += 4;
        let value = take(bytes, at, value_len)?.to_vec();
        at += value_len;
        out.insert(String::from_utf8_lossy(name).into_owned(), value);
    }
    Ok(out)
}

/// The `u32` length at `at`, or `None` if fewer than four bytes are left —
/// which is how a stream that simply ends is told from one that lies.
fn length(bytes: &[u8], at: usize) -> Option<usize> {
    bytes
        .get(at..at.checked_add(4)?)
        .map(|slice| u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize)
}

/// The `len` bytes at `at`, or the error a short frame deserves.
fn take(bytes: &[u8], at: usize, len: usize) -> Result<&[u8], ScriptHostError> {
    // A length that overflows an offset is a lie, and `get` says so rather
    // than wrapping into a slice that is there.
    let end = at.saturating_add(len);
    bytes.get(at..end).ok_or_else(|| ScriptHostError::Protocol {
        message: format!(
            "the secret frames promise {len} bytes at offset {at} of a {}-byte stream: \
             it is truncated or malformed",
            bytes.len()
        ),
    })
}
#[cfg(test)]
mod tests {
    use ks_core::ports::secrets::SecretValue;

    use super::*;

    fn bundle_with(name: &str, value: &[u8]) -> SecretBundle {
        let mut bundle = SecretBundle::new();
        bundle.insert(name, SecretValue::new(value.to_vec()));
        bundle
    }

    #[test]
    fn a_well_formed_bundle_round_trips() {
        let bundle = bundle_with("token", b"hunter2");
        let decoded = decode(&frames(&bundle)).expect("a well-formed wire decodes");
        assert_eq!(decoded["token"], b"hunter2".to_vec());
        assert_eq!(decoded.len(), 1, "the terminator is not a secret");
    }

    #[test]
    fn a_truncated_frame_is_an_error_not_a_panic() {
        // A name length of four over a five-byte buffer: the old decoder
        // sliced 4..8 and aborted the process on it.
        let truncated = [0, 0, 0, 4, b'a'];
        let error = decode(&truncated).expect_err("a frame that runs off the end is not one");
        assert!(matches!(error, ScriptHostError::Protocol { .. }), "{error}");

        // The same lie about the name length, which is the four bytes at 0..4.
        let mut lying = Vec::new();
        push_frame(&mut lying, b"name", b"value");
        lying.splice(0..4, 1_000u32.to_be_bytes());
        assert!(decode(&lying).is_err(), "a name length past the end is not a frame");

        // And about the value, one frame further in: after the `u32` name
        // length and the name itself, the value length is 8..12. Splicing over
        // 6..10 instead would have eaten the last two bytes of the *name* and
        // proved only that the name half is checked.
        let mut lying = Vec::new();
        push_frame(&mut lying, b"name", b"value");
        lying.splice(8..12, 1_000u32.to_be_bytes());
        assert!(decode(&lying).is_err(), "a value length past the end is not a frame");
    }

    #[test]
    fn a_bundle_larger_than_a_pipe_buffer_does_not_hang_the_run() {
        // The reproduced hang: 256 KiB of wire against a 64 KiB pipe, filled
        // before anything was reading it. `open` runs on its own thread with a
        // deadline so the regression is a failed assertion rather than a test
        // suite that never finishes.
        let mut bundle = SecretBundle::new();
        bundle.insert("big", SecretValue::new(vec![b'x'; 256 * 1024]));
        let expected = frames(&bundle);
        let wire_len = expected.len();
        assert!(wire_len > 64 * 1024, "this test is about a bundle past the pipe buffer");

        let (sent, opened) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sent.send(SecretChannel::open(&bundle));
        });
        let channel = match opened.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(Ok(channel)) => channel,
            Ok(Err(error)) => panic!("the secret pipe opens: {error}"),
            Err(_) => panic!("opening the secret pipe blocked on a full pipe"),
        };

        let path = channel.path().to_path_buf();
        let read = std::thread::spawn(move || {
            use std::io::Read as _;
            let mut reader = std::fs::OpenOptions::new().read(true).open(&path).expect("readable");
            let mut wire = vec![0u8; wire_len];
            reader.read_exact(&mut wire).expect("the whole wire is readable");
            wire
        });
        let wire = read.join().expect("the reader thread");
        assert_eq!(wire, expected, "every frame arrives, in the framing the wire uses");
        drop(channel);
    }

    #[test]
    fn dropping_a_pipe_nobody_read_does_not_hang() {
        // The error path: a child that died before opening the pipe, or never
        // existed. `Drop` joins the filler, and a filler whose handle were
        // readable as well as writable would wait on a pipe nobody drains for
        // ever instead of seeing `EPIPE`.
        let mut bundle = SecretBundle::new();
        bundle.insert("big", SecretValue::new(vec![b'x'; 256 * 1024]));
        let channel = SecretChannel::open(&bundle).expect("a private FIFO");
        let fifo = channel.path().to_path_buf();
        // Let the filler get as far as it can with no reader at all.
        std::thread::sleep(std::time::Duration::from_millis(50));
        drop(channel);
        assert!(!fifo.exists(), "the pipe is gone with the channel, and Drop returned");
    }

    #[test]
    fn a_stream_that_ends_mid_header_is_the_end_not_an_error() {
        assert_eq!(decode(&[]).expect("no bytes is no frames"), BTreeMap::new());
        assert_eq!(decode(&[0, 0, 0]).expect("a half-written header is the end"), BTreeMap::new());
        let mut cut = Vec::new();
        push_frame(&mut cut, b"token", b"hunter2");
        cut.truncate(cut.len() - 3);
        let error = decode(&cut).expect_err("the value is promised but absent");
        assert!(matches!(error, ScriptHostError::Protocol { .. }), "{error}");
    }
}
