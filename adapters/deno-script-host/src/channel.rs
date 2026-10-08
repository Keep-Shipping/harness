//! The secret channel: a FIFO the parent fills before spawning and the child
//! reads, with the values never in argv, the environment, stdio or on disk
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
    /// child's `open(O_RDONLY)` never blocks, and closed with the child.
    writer: Option<std::fs::File>,
}

impl SecretChannel {
    /// Creates the FIFO and frames `bundle` into it. The values live in a
    /// kernel pipe buffer and in this `File`; nothing is written to disk.
    pub fn open(bundle: &SecretBundle) -> Result<SecretChannel, ScriptHostError> {
        let directory = private_directory()?;
        let fifo = directory.join("secrets");
        make_fifo(&fifo)?;
        let mut writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .map_err(io_error("could not open the secret pipe", &fifo))?;
        let mut frames = Vec::new();
        bundle.iter().for_each(|(name, value)| {
            value.with_bytes(|bytes| {
                push_frame(&mut frames, name.as_bytes(), bytes);
            });
        });
        frames.extend_from_slice(&TERMINATOR);
        use std::io::Write as _;
        writer
            .write_all(&frames)
            .and_then(|()| writer.flush())
            .map_err(io_error("could not fill the secret pipe", &fifo))?;
        Ok(SecretChannel { directory, fifo, writer: Some(writer) })
    }

    /// The path the child opens. Not a secret — it names a pipe, not a value.
    pub fn path(&self) -> &Path {
        &self.fifo
    }
}

impl Drop for SecretChannel {
    fn drop(&mut self) {
        // Close before unlinking: the child's read ends at the terminator, so
        // the pipe is only being held open to keep its `open` from blocking.
        drop(self.writer.take());
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

/// The wire encoding of a whole bundle, terminator included — what a test or
/// the bootstrap's counterpart sees.
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
pub fn decode(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut at = 0;
    let be = |slice: &[u8]| u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
    while at + 4 <= bytes.len() {
        let name_len = be(&bytes[at..at + 4]);
        if name_len == 0 {
            break;
        }
        at += 4;
        let name = String::from_utf8_lossy(&bytes[at..at + name_len]).into_owned();
        at += name_len;
        if at + 4 > bytes.len() {
            break;
        }
        let value_len = be(&bytes[at..at + 4]);
        at += 4;
        out.insert(name, bytes[at..at + value_len].to_vec());
        at += value_len;
    }
    out
}
