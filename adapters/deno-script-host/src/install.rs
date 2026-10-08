//! The pinned runtime: which Deno, from where, and how it is proven to be that
//! one (ADR 0009).

use std::io::Cursor;
use std::path::{Path, PathBuf};

use ks_core::ports::script_host::ScriptHostError;
use sha2::{Digest as _, Sha256};

/// The one Deno this adapter ever runs. ADR 0009 ratifies the pin; the issue
/// asked for a `ship.lock`, which this repository does not have — the pin is
/// compiled in instead, so one `keepshipping` version means one Deno.
pub const DENO_VERSION: &str = "2.9.7";

/// The release target this adapter supports.
pub const DENO_TARGET: &str = "x86_64-unknown-linux-gnu";

/// SHA-256 of `deno-x86_64-unknown-linux-gnu.zip` for [`DENO_VERSION`], from
/// ADR 0009. A mismatch is a hard error and nothing is installed.
pub const DENO_ARCHIVE_SHA256: &str =
    "c6527f24f4b16031d3ae4fa9f658d5f11534c8d84ce7dc8502420280919c3490";

/// The entry inside the release archive: the whole zip is one binary.
const ARCHIVE_ENTRY: &str = "deno";

/// How the archive is fetched, so a test can hand over bytes without a
/// network and an air-gapped machine can pre-seed the cache.
pub trait Fetcher: Send + Sync {
    /// Returns the bytes at `url`, or why it could not.
    fn fetch(&self, url: &str) -> std::io::Result<Vec<u8>>;
}

/// The default transport: `curl`, restricted to HTTPS. Integrity comes from
/// the pinned [`DENO_VERSION`] digest, not from the transport, so nothing here is a
/// trust decision — it is the convenience of not linking a TLS stack (and its
/// licence) into every binary.
pub struct CurlFetcher;

impl Fetcher for CurlFetcher {
    fn fetch(&self, url: &str) -> std::io::Result<Vec<u8>> {
        let output = std::process::Command::new("curl")
            .args(["-fsSL", "--proto", "=https", "--connect-timeout", "30", url])
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "curl {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(output.stdout)
    }
}

/// `$XDG_CACHE_HOME/keepshipping/deno`, falling back to
/// `$HOME/.cache/keepshipping/deno` — the same shape as the engine's
/// `DirCache::default_root`.
pub fn default_cache_root() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(base.join("keepshipping").join("deno"))
}

/// The one platform this adapter is verified on. Everything else — the
/// `/proc/self/fd` route to the secret pipe included — is Linux, so anything
/// else is a clear error rather than a surprise.
pub fn platform() -> &'static str {
    std::env::consts::ARCH
}

/// Whether [`platform`] can run this adapter, with the message to show when it
/// cannot.
pub fn check_platform() -> Result<(), ScriptHostError> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Ok(());
    }
    Err(unsupported_platform(platform()))
}

/// The error for a platform this adapter has no verified mechanism on.
pub fn unsupported_platform(platform: &str) -> ScriptHostError {
    ScriptHostError::Protocol {
        message: format!(
            "the Deno script host runs on linux-x86_64 only, and this is {}-{}: \
             the secret pipe needs /proc/self/fd, which ADR 0009 records as unverified elsewhere",
            std::env::consts::OS,
            platform
        ),
    }
}

/// `root/<version>`, where one Deno lives.
pub fn version_dir(root: &Path) -> PathBuf {
    root.join(DENO_VERSION)
}

/// `root/<version>/deno`: the binary itself.
pub fn deno_path(root: &Path) -> PathBuf {
    version_dir(root).join("deno")
}

/// `root/<version>/host`: the embedded bootstrap, next to the binary.
pub fn host_dir(root: &Path) -> PathBuf {
    version_dir(root).join("host")
}

/// `root/<version>/deno_dir`: the private module cache the child runs against.
pub fn deno_dir(root: &Path) -> PathBuf {
    version_dir(root).join("deno_dir")
}

/// Deno's own release host — not a host we run, so ADR 0005's "no network call
/// to us" is untouched.
pub fn archive_url() -> String {
    format!("https://dl.deno.land/release/v{DENO_VERSION}/deno-{DENO_TARGET}.zip")
}

/// The stamp written next to an installed binary: the digest of the *archive*
/// it was installed from.
///
/// It is not, on its own, a statement about the file on disk — the binary is
/// unpacked from the archive, so the two do not hash the same and the archive
/// digest cannot be checked against it later. It says the download was the
/// pinned one; [`binary_stamp_path`] is what says the file is still what that
/// download produced.
fn stamp_path(root: &Path) -> PathBuf {
    version_dir(root).join("deno.sha256")
}

/// The stamp of the *installed binary's* own digest — the only check that can
/// notice somebody else's Deno having been dropped in over it after the fact.
///
/// Kept apart from the archive stamp because the two answer different
/// questions and cost different amounts to ask. Re-installing is guarded by a
/// string comparison against a 64-byte file; "the cache still holds what we
/// put there" is a SHA-256 over ~100 MB, which is why it is not folded into
/// the cheap check and why a cache that has been tampered with is re-fetched
/// rather than re-examined.
fn binary_stamp_path(root: &Path) -> PathBuf {
    version_dir(root).join("deno.binary.sha256")
}

/// `<root>/<version>/deno-<target>.zip`: where an air-gapped machine puts the
/// release archive, by hand or by whatever its own cache policy allows.
fn preseeded_archive(root: &Path) -> PathBuf {
    version_dir(root).join(format!("deno-{DENO_TARGET}.zip"))
}

/// Returns the path to the pinned Deno, installing it from `fetch` if the cache
/// does not hold it yet.
///
/// An existing binary is only used when its archive stamp names the pinned
/// digest *and* the binary still hashes to the digest recorded when it was
/// installed; anything else is treated as no cache at all and installed afresh.
/// Self-healing rather than fatal: the replacement is verified against the same
/// pinned digest either way, and a cache nobody has to clear by hand recovers
/// on the next run instead of never. A download whose digest does not match
/// writes nothing at all: the bytes are verified before a single byte is put on
/// disk.
pub fn ensure(root: &Path, fetch: &dyn Fetcher) -> Result<PathBuf, ScriptHostError> {
    ensure_digest(root, fetch, DENO_ARCHIVE_SHA256)
}

/// [`ensure`] with the expected digest as a parameter, so the install path
/// itself is testable without the 40 MB release archive.
fn ensure_digest(
    root: &Path,
    fetch: &dyn Fetcher,
    expected: &str,
) -> Result<PathBuf, ScriptHostError> {
    check_platform()?;
    let binary = deno_path(root);
    if binary.is_file() && stamp_matches(root, expected) && binary_unchanged(root, &binary) {
        return Ok(binary);
    }
    let url = archive_url();
    let preseeded = preseeded_archive(root);
    // The air-gapped install ADR 0009 promises: the same archive, the same
    // pinned digest, put in the cache by hand instead of fetched. It is
    // verified exactly like a download — the point is that no *network* is
    // needed, not that no *check* is.
    let (archive, from) = match std::fs::read(&preseeded) {
        Ok(bytes) => (bytes, format!("the pre-seeded archive {}", preseeded.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            fetch.fetch(&url).map_err(|error| ScriptHostError::Protocol {
                message: format!(
                    "could not download the pinned Deno {DENO_VERSION} from {url}: {error}. \
                         On an air-gapped machine, pre-seed {} in the cache directory instead",
                    preseeded.display()
                ),
            })?,
            url.clone(),
        ),
        Err(error) => {
            return Err(io_error("could not read the pre-seeded Deno archive", &preseeded)(error));
        }
    };
    let digest = hex(&Sha256::digest(&archive));
    if digest != expected {
        return Err(ScriptHostError::Protocol {
            message: format!(
                "the Deno {DENO_VERSION} archive from {from} hashes to {digest}, not the pinned \
                 {expected}; nothing was installed"
            ),
        });
    }
    let bytes = extract(&archive)?;
    install_binary(root, &bytes)?;
    stamp(&stamp_path(root), expected, "the installed Deno")?;
    stamp(&binary_stamp_path(root), &hex(&Sha256::digest(&bytes)), "the installed Deno binary")?;
    Ok(binary)
}

/// Whether the installed binary was installed from the expected archive.
fn stamp_matches(root: &Path, expected: &str) -> bool {
    std::fs::read_to_string(stamp_path(root)).is_ok_and(|stamp| stamp.trim() == expected)
}

/// Whether `<root>/<version>/deno` still hashes to what it hashed to when it
/// was written out. Streamed, so the ~100 MB binary is never held in memory.
fn binary_unchanged(root: &Path, binary: &Path) -> bool {
    let Ok(expected) = std::fs::read_to_string(binary_stamp_path(root)) else {
        return false;
    };
    let Ok(mut file) = std::fs::File::open(binary) else {
        return false;
    };
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        match std::io::Read::read(&mut file, &mut buffer) {
            Ok(0) => break,
            Ok(read) => digest.update(&buffer[..read]),
            Err(_) => return false,
        }
    }
    hex(&digest.finalize()) == expected.trim()
}

/// Writes one stamp, with the failure that says which one.
fn stamp(path: &Path, digest: &str, what: &str) -> Result<(), ScriptHostError> {
    std::fs::write(path, format!("{digest}\n")).map_err(|error| ScriptHostError::Protocol {
        message: format!("could not record the digest of {what}: {error}"),
    })
}

/// Pulls the single `deno` entry out of the release archive.
fn extract(archive: &[u8]) -> Result<Vec<u8>, ScriptHostError> {
    let mut zip =
        zip::ZipArchive::new(Cursor::new(archive)).map_err(|error| ScriptHostError::Protocol {
            message: format!("the Deno {DENO_VERSION} download is not a readable zip: {error}"),
        })?;
    let mut entry = zip.by_name(ARCHIVE_ENTRY).map_err(|error| ScriptHostError::Protocol {
        message: format!(
            "the Deno {DENO_VERSION} download has no {ARCHIVE_ENTRY:?} entry: {error}"
        ),
    })?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut bytes).map_err(|error| {
        ScriptHostError::Protocol {
            message: format!("could not unpack the Deno {DENO_VERSION} archive: {error}"),
        }
    })?;
    Ok(bytes)
}

/// Writes the binary executable, through a temporary file and a rename, so a
/// concurrent reader never sees a half-written executable.
fn install_binary(root: &Path, bytes: &[u8]) -> Result<(), ScriptHostError> {
    use std::os::unix::fs::PermissionsExt;

    let dir = version_dir(root);
    std::fs::create_dir_all(&dir)
        .map_err(io_error("could not create the Deno cache directory", &dir))?;
    let binary = deno_path(root);
    let temporary = dir.join(format!("deno.{}.tmp", std::process::id()));
    let write = || -> std::io::Result<()> {
        std::fs::write(&temporary, bytes)?;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755))
    };
    write().map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        ScriptHostError::Protocol {
            message: format!(
                "could not install the Deno binary at {}: {error}",
                temporary.display()
            ),
        }
    })?;
    if let Err(error) = std::fs::rename(&temporary, &binary) {
        let _ = std::fs::remove_file(&temporary);
        return Err(ScriptHostError::Protocol {
            message: format!("could not install the Deno binary at {}: {error}", binary.display()),
        });
    }
    Ok(())
}

/// An I/O failure as a protocol error, with the path that failed.
pub fn io_error<'a>(
    what: &'a str,
    path: &'a Path,
) -> impl FnOnce(std::io::Error) -> ScriptHostError + 'a {
    move |error| ScriptHostError::Protocol {
        message: format!("{what} {}: {error}", path.display()),
    }
}

/// Lowercase hex of a digest.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
#[cfg(test)]
mod tests {
    use super::*;

    /// The gate on every test below that installs anything:
    /// [`ensure_digest`] calls [`check_platform`] first and refuses anything
    /// but linux-x86_64, so off that platform these assert the platform, or
    /// panic on an `expect` — and the two that use `expect_err` would pass on
    /// it without ever reaching the digest check they are named for. It is
    /// *gating*, not `#[ignore]`: `cargo test --workspace` on Linux still runs
    /// every one of them.
    ///
    /// The helpers below carry it too, for the same reason: off that platform
    /// nothing names them, and an unused item is a warning, and warnings are
    /// errors in this repository.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    /// A fetcher that hands back fixed bytes and counts its calls, so a test
    /// can tell "installed" from "reused what was there".
    struct Stub {
        bytes: Vec<u8>,
        calls: std::sync::Mutex<usize>,
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    impl Stub {
        fn new(bytes: Vec<u8>) -> Stub {
            Stub { bytes, calls: std::sync::Mutex::new(0) }
        }

        fn calls(&self) -> usize {
            *self.calls.lock().expect("stub fetch count")
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    impl Fetcher for Stub {
        fn fetch(&self, _url: &str) -> std::io::Result<Vec<u8>> {
            *self.calls.lock().expect("stub fetch count") += 1;
            Ok(self.bytes.clone())
        }
    }

    /// The release archive's shape: one stored entry named `deno`.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn archive() -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer.start_file("deno", options).expect("the stub archive is writable");
        use std::io::Write as _;
        writer.write_all(b"#!/bin/sh\necho deno\n").expect("the stub archive is writable");
        writer.finish().expect("the stub archive is writable").into_inner()
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("ks-deno-install-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn the_pin_names_denos_own_release_host() {
        assert_eq!(
            archive_url(),
            format!("https://dl.deno.land/release/v{DENO_VERSION}/deno-{DENO_TARGET}.zip")
        );
        assert_eq!(DENO_ARCHIVE_SHA256.len(), 64);
        assert!(
            DENO_ARCHIVE_SHA256.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn a_wrong_digest_installs_nothing() {
        let root = root("mismatch");
        let fetch = Stub::new(archive());
        let error = ensure(&root, &fetch).expect_err("a stub archive is not the pinned one");
        assert!(
            matches!(&error, ScriptHostError::Protocol { message } if message.contains("nothing was installed")),
            "{error}"
        );
        assert!(!deno_path(&root).exists(), "the cache directory is left empty");
        assert_eq!(fetch.calls(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn a_verified_archive_installs_once_and_is_reused_afterwards() {
        use std::os::unix::fs::PermissionsExt;

        let root = root("reuse");
        let bytes = archive();
        let digest = hex(&Sha256::digest(&bytes));
        let fetch = Stub::new(bytes);
        let installed =
            ensure_digest(&root, &fetch, &digest).expect("the verified archive installs");
        assert_eq!(installed, deno_path(&root));
        assert_eq!(fetch.calls(), 1);
        assert!(std::fs::read(&installed).expect("the binary is there").starts_with(b"#!/bin/sh"));
        let mode = std::fs::metadata(&installed).expect("the binary is there").permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "an installed Deno is executable");
        // Second call: the cache holds the pin, so nothing is fetched.
        ensure_digest(&root, &fetch, &digest).expect("the cached Deno is reused");
        assert_eq!(fetch.calls(), 1, "a cached Deno is never downloaded again");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn a_pre_seeded_archive_installs_without_a_network_call() {
        let root = root("preseed");
        let bytes = archive();
        let digest = hex(&Sha256::digest(&bytes));
        std::fs::create_dir_all(version_dir(&root)).expect("the cache directory is writable");
        std::fs::write(preseeded_archive(&root), &bytes).expect("the pre-seed is writable");

        let fetch = Stub::new(Vec::new());
        let installed =
            ensure_digest(&root, &fetch, &digest).expect("a verified pre-seed installs");
        assert_eq!(installed, deno_path(&root));
        assert_eq!(fetch.calls(), 0, "a pre-seeded cache needs no network at all");
        assert!(std::fs::read(&installed).expect("the binary is there").starts_with(b"#!/bin/sh"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn a_pre_seeded_archive_is_verified_like_a_download() {
        let root = root("preseed-mismatch");
        // A pre-seed of some *other* release: the name says 2.9.7 and the pin
        // is what decides.
        let bytes = archive();
        std::fs::create_dir_all(version_dir(&root)).expect("the cache directory is writable");
        std::fs::write(preseeded_archive(&root), &bytes).expect("the pre-seed is writable");
        let digest = hex(&Sha256::digest(b"a different archive entirely"));

        let fetch = Stub::new(Vec::new());
        let error = ensure_digest(&root, &fetch, &digest)
            .expect_err("a pre-seed is not trusted over the pin");
        assert!(
            matches!(&error, ScriptHostError::Protocol { message } if message.contains("nothing was installed")),
            "{error}"
        );
        assert!(
            !deno_path(&root).exists(),
            "nothing is installed from a pre-seed that does not match"
        );
        assert_eq!(fetch.calls(), 0, "a pre-seed that does not match is a refusal, not a download");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn an_overwritten_cached_binary_is_re_installed_not_run() {
        let root = root("tampered");
        let bytes = archive();
        let digest = hex(&Sha256::digest(&bytes));
        let fetch = Stub::new(bytes);
        ensure_digest(&root, &fetch, &digest).expect("the verified archive installs");
        assert_eq!(fetch.calls(), 1);

        // What the review reproduced: the archive stamp still matches, and the
        // binary underneath it is somebody else's.
        std::fs::write(deno_path(&root), "#!/bin/sh\necho not deno\n")
            .expect("the cache is writable by its owner");
        assert!(
            stamp_matches(&root, &digest),
            "the archive stamp is untouched by this: it is a statement about the download"
        );
        ensure_digest(&root, &fetch, &digest).expect("the cache is re-installed rather than run");
        assert_eq!(fetch.calls(), 2, "the tampered cache is replaced, not trusted");
        assert!(
            std::fs::read(deno_path(&root)).expect("the binary is there").starts_with(b"#!/bin/sh")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn an_unverifiable_download_never_reaches_the_disk() {
        struct Failing;
        impl Fetcher for Failing {
            fn fetch(&self, _url: &str) -> std::io::Result<Vec<u8>> {
                Err(std::io::Error::other("no network"))
            }
        }
        let root = root("offline");
        let error = ensure(&root, &Failing).expect_err("an air-gapped machine cannot install");
        assert!(error.to_string().contains("pre-seed"), "{error}");
        assert!(!deno_path(&root).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unsupported_platform_says_so_by_name() {
        let error = unsupported_platform("aarch64");
        assert!(error.to_string().contains("linux-x86_64"), "{error}");
        assert!(error.to_string().contains("aarch64"), "{error}");
    }
}
