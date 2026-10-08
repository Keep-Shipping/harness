//! `keepshipping blocks publish` against **real** OCI registries
//! ([#82](https://github.com/Keep-Shipping/harness/issues/82)).
//!
//! `KS_OCI_CONFORMANCE_REGISTRIES` is a comma-separated list of registry hosts,
//! e.g. `localhost:5000,localhost:5001`. Unset — the case in
//! `cargo test --workspace` — the test prints that it was skipped and returns, so
//! the ordinary test run stays service-free (ADR 0002). The same gating the
//! distribution adapter's own conformance test uses.
//!
//! The interesting half is the read back: everything after the first publish goes
//! through a real [`OciDistribution`], the way `blocks fetch` will, and the
//! interface decoded from the registry's own bytes is what the compatibility rule
//! compared against.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ks_cli::http_client::TcpHttpClient;
use ks_core::ports::http::HttpPolicy;
use ks_core::ports::supply_chain::{Digest, ImageRef, Registry};
use ks_oci_distribution::OciDistribution;
use ks_testing::block_on;

/// 16 MiB of response headroom, as the adapter's own conformance test allows.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// The README a publish carries when the publisher asks for one.
const README: &str = "# web-service\n\nShips a container.\n";

const BLOCK: &str = "\
block: web-service
summary: \"Builds and ships a web service.\"
inputs:
  image: oci.Digest
  replicas: int = 2
outputs:
  url: string
";

/// The same block with one input fewer: removing `replicas` breaks every
/// consumer that set it, so it may only be published on a new line.
const BLOCK_WITHOUT_REPLICAS: &str = "\
block: web-service
summary: \"Builds and ships a web service.\"
inputs:
  image: oci.Digest
outputs:
  url: string
";

#[test]
fn blocks_publish_round_trips_through_every_configured_registry() {
    let Ok(configured) = std::env::var("KS_OCI_CONFORMANCE_REGISTRIES") else {
        println!("skipping the blocks publish round trip: KS_OCI_CONFORMANCE_REGISTRIES is unset");
        return;
    };
    let registries: Vec<String> = configured
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_string)
        .collect();
    assert!(!registries.is_empty(), "KS_OCI_CONFORMANCE_REGISTRIES is set but empty");

    // The hosts, port stripped: that is what the client's allowlist matches.
    let hosts = registries
        .iter()
        .map(|host| host.split(':').next().unwrap_or(host).to_ascii_lowercase())
        .collect::<std::collections::BTreeSet<_>>();
    let client = Arc::new(TcpHttpClient::new(HttpPolicy {
        allowed_hosts: hosts,
        timeout: Duration::from_secs(60),
        max_response_bytes: MAX_RESPONSE_BYTES,
    }));
    let registry = OciDistribution::new(client).with_insecure_hosts(registries.clone());

    // A namespace nobody else is publishing into, so a run against a shared
    // registry cannot collide with itself or with another run.
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).expect("a clock").as_nanos();
    for host in &registries {
        let namespace = format!("{host}/blocks-{unique}");
        let dir = TempDir::new();
        dir.write("web-service.ks", BLOCK);
        dir.write("README.md", README);
        println!("publishing {namespace}/web-service against {host}");

        let first = published(&dir, BLOCK, &namespace, "1.0.0", true);
        assert!(first.stdout.contains("published web-service 1.0.0"), "{first}");
        assert!(first.stdout.contains("@sha256:"), "the digest is reported: {first}");

        // The use side: read it back through the registry, not through the file
        // that produced it.
        let repository = format!("{namespace}/web-service");
        let reference =
            ImageRef::parse(&format!("{repository}:1.0.0")).expect("a tagged reference");
        let digest = block_on(registry.resolve(&reference)).expect("the tag resolves");
        let manifest: serde_json::Value = serde_json::from_slice(
            &block_on(registry.pull(&repository, &digest)).expect("the manifest pulls"),
        )
        .expect("a manifest is json");
        assert_eq!(manifest["artifactType"], "application/vnd.keepshipping.block.v1");
        assert_eq!(manifest["annotations"]["org.opencontainers.image.version"], "1.0.0");
        assert_eq!(manifest["mediaType"], "application/vnd.oci.image.manifest.v1+json");
        assert_eq!(
            manifest["annotations"]["io.keepshipping.block.layers"],
            "interface,definition,readme"
        );

        // Layer 0 is the interface a consumer pins; layer 1 is the file the
        // publisher wrote, byte for byte.
        let read_back: serde_json::Value =
            serde_json::from_slice(&pull_layer(&registry, &repository, &manifest, 0))
                .expect("the interface layer is json");
        assert_eq!(read_back["name"], "web-service");
        assert_eq!(read_back["version"], "1.0.0");
        assert_eq!(read_back["inputs"][0]["name"], "image");
        assert_eq!(read_back["inputs"][0]["required"], true);
        assert_eq!(read_back["inputs"][1]["name"], "replicas");
        assert_eq!(read_back["inputs"][1]["required"], false);
        assert_eq!(read_back["outputs"][0]["name"], "url");
        assert_eq!(pull_layer(&registry, &repository, &manifest, 1), BLOCK.as_bytes());
        assert_eq!(pull_layer(&registry, &repository, &manifest, 2), README.as_bytes());

        // A breaking change without a major bump is refused, and says which
        // input broke and what to publish instead.
        let broken = refused(&dir, BLOCK_WITHOUT_REPLICAS, &namespace, "1.1.0", "replicas");
        assert!(broken.stderr.contains("2.0.0"), "the refusal names the version: {broken}");

        // The same change as a major bump is accepted: a new line is a new
        // interface. And the unchanged block publishes inside the 1.x line, so
        // the line now holds a 1.1.0 to compare against.
        published(&dir, BLOCK_WITHOUT_REPLICAS, &namespace, "2.0.0", false);
        published(&dir, BLOCK, &namespace, "1.1.0", true);
        // A version below its own line goes backwards rather than branching:
        // 1.0.1 is under the 1.1.0 the line now holds.
        refused(&dir, BLOCK_WITHOUT_REPLICAS, &namespace, "1.0.1", "below the published 1.1.0");

        // And no refusal was ever tagged: the tags are exactly the three that
        // published.
        let tags = block_on(registry.tags(&repository)).expect("the tags list");
        for wanted in ["1.0.0", "1.1.0", "2.0.0"] {
            assert!(tags.contains(&wanted.to_string()), "{wanted} published: {tags:?}");
        }
        assert!(!tags.contains(&"1.0.1".to_string()), "a refusal published nothing: {tags:?}");
    }
}

/// One `blocks publish`, carrying the README only when it is asked for. The
/// binary runs in a fresh process from `dir`, so this is end to end: exit code,
/// streams, and the block file read off disk.
fn publish(dir: &TempDir, namespace: &str, version: &str, readme: bool) -> Run {
    let mut args =
        vec!["blocks", "publish", "web-service.ks", "--version", version, "--to", namespace];
    if readme {
        args.extend(["--readme", "README.md"]);
    }
    let out = Command::new(env!("CARGO_BIN_EXE_keepshipping"))
        .args(args)
        .current_dir(&dir.0)
        // The empty `DOCKER_CONFIG` beside the fixture, so the developer
        // running this keeps their own docker credentials.
        .env("DOCKER_CONFIG", dir.0.join("docker"))
        .output()
        .expect("run keepshipping");
    Run {
        code: out.status.code().expect("an exit code"),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Publishes `source` as `version`, which must be accepted.
fn published(dir: &TempDir, source: &str, namespace: &str, version: &str, readme: bool) -> Run {
    dir.write("web-service.ks", source);
    let run = publish(dir, namespace, version, readme);
    assert_eq!(run.code, 0, "{version} must publish: {run}");
    run
}

/// Publishes `source` as `version`, which must be refused with a message naming
/// `because`.
fn refused(dir: &TempDir, source: &str, namespace: &str, version: &str, because: &str) -> Run {
    dir.write("web-service.ks", source);
    let run = publish(dir, namespace, version, false);
    assert_ne!(run.code, 0, "{version} must not publish: {run}");
    assert!(run.stderr.contains(because), "{version}: {run}");
    run
}

/// Layer `index` of a manifest, pulled through the registry.
fn pull_layer(
    registry: &OciDistribution,
    repository: &str,
    manifest: &serde_json::Value,
    index: usize,
) -> Vec<u8> {
    let digest = manifest["layers"][index]["digest"].as_str().expect("a layer digest");
    let digest = Digest::parse(digest).expect("a valid digest");
    block_on(registry.pull(repository, &digest)).expect("the layer pulls")
}

/// One command's exit code, stdout and stderr, for an assertion message.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl std::fmt::Display for Run {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exit {}\nstdout: {}\nstderr: {}", self.code, self.stdout, self.stderr)
    }
}

/// A directory under the system temp dir, removed when the test ends — the
/// block file the binary reads has to be a real file on disk. Its `docker/`
/// subdirectory is an empty `DOCKER_CONFIG`.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).expect("a clock").as_nanos();
        let path = std::env::temp_dir().join(format!("ks-blocks-publish-{unique}"));
        std::fs::create_dir_all(path.join("docker")).expect("create the temp dir");
        TempDir(path)
    }

    fn write(&self, name: &str, contents: &str) {
        std::fs::write(self.0.join(name), contents).expect("write the fixture");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
