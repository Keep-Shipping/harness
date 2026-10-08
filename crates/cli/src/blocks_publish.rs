//! `blocks publish`: packaging a `.ks` block file as an OCI artifact and pushing
//! it to a registry, refusing a breaking interface change within a release line.
//!
//! The artifact is one OCI image manifest with an `artifactType` of
//! [`BLOCK_ARTIFACT_TYPE`] and layers in a fixed order: the interface (the JSON
//! encoding of the block's `inputs` and `outputs`), the `.ks` file verbatim, and
//! the README when one was given. Position alone is not the contract, so the
//! manifest also carries [`LAYERS_ANNOTATION`] naming them.
//!
//! The version is a tag, and a tag here is immutable: within a *release line* —
//! the major, or while the major is `0` the minor, the way cargo treats `0.x` —
//! the interface is held still, and a new line starts a new one.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use ks_core::ports::block_source::{BlockDefinition, BlockField};
use ks_core::ports::supply_chain::{ArtifactUpload, Digest, ImageRef, Registry, RegistryError};
use ks_oci_distribution::OCI_MANIFEST;
use serde_json::json;

/// The `artifactType` a block is published under.
pub const BLOCK_ARTIFACT_TYPE: &str = "application/vnd.keepshipping.block.v1";

/// The manifest annotation naming the layers, comma separated in manifest order,
/// so a reader does not have to trust position alone.
pub const LAYERS_ANNOTATION: &str = "io.keepshipping.block.layers";

/// A block version: `MAJOR.MINOR.PATCH`, digits only.
///
/// Deliberately narrower than semver: no `v` prefix, no pre-release, no partial
/// versions. A tag that is not one of these is ignored when picking a base, and
/// refused when offered as the version to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    /// Parses `MAJOR.MINOR.PATCH`. Every component must be a non-empty run of
    /// digits; anything else is an error naming what was offered.
    pub fn parse(text: &str) -> Result<Version, String> {
        let not_digits =
            || format!("{text:?} is not a version: expected MAJOR.MINOR.PATCH of digits");
        let mut parts = text.split('.');
        let (Some(major), Some(minor), Some(patch), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(format!(
                "{text:?} is not a version: expected MAJOR.MINOR.PATCH, e.g. 3.1.0"
            ));
        };
        let component = |part: &str| -> Result<u64, String> {
            part.parse()
                .ok()
                .filter(|_| part.bytes().all(|byte| byte.is_ascii_digit()))
                .ok_or_else(not_digits)
        };
        Ok(Version { major: component(major)?, minor: component(minor)?, patch: component(patch)? })
    }

    /// The release line: `(major, 0)` above `0.x`, and `(0, minor)` below it.
    fn line(&self) -> (u64, u64) {
        if self.major == 0 { (0, self.minor) } else { (self.major, 0) }
    }

    /// The first version of the next line: what a breaking change against this
    /// base has to be published as. Saturating, because a version at the top of a
    /// `u64` has no successor and a panic is not an answer.
    fn next_line(&self) -> Version {
        if self.major == 0 {
            Version { major: 0, minor: self.minor.saturating_add(1), patch: 0 }
        } else {
            Version { major: self.major.saturating_add(1), minor: 0, patch: 0 }
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A block file as this command reads it: the name it is published under, and
/// the interface a consumer pins. A file that does not parse, declares no
/// `block:` name, or names a block the registry could not hold, is refused here:
/// an artifact nobody can name is not a block.
#[derive(Debug)]
pub struct Block {
    pub name: String,
    pub definition: BlockDefinition,
}

pub fn read_definition(src: &str) -> Result<Block, String> {
    let parsed = ks_lang::parse(src);
    let errors = parsed
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.severity == ks_lang::Severity::Error)
        .map(|diagnostic| {
            format!("{} at {}: {}", diagnostic.code.as_str(), diagnostic.span, diagnostic.message)
        })
        .collect::<Vec<_>>()
        .join("\n  ");
    if !errors.is_empty() {
        return Err(format!("the block file does not parse:\n  {errors}"));
    }
    let mut name = None;
    let mut definition = BlockDefinition::default();
    for entry in parsed.file().entries() {
        match entry.key_name() {
            Some("block") => name = Some(entry_text(entry)),
            Some("summary") => definition.summary = entry_text(entry),
            Some("inputs") => definition.inputs = fields(src, entry.children(), false),
            Some("outputs") => definition.outputs = fields(src, entry.children(), true),
            _ => {}
        }
    }
    let name =
        name.filter(|name| !name.is_empty()).ok_or("the block file declares no `block:` name")?;
    if !is_path_component(&name) {
        return Err(format!(
            "{name:?} is not a name a registry can hold; a block name is lower-case \
             alphanumerics in runs, separated by `.`, `_` or `-`, e.g. `web-service`"
        ));
    }
    Ok(Block { name, definition })
}

/// Whether `name` is one OCI path component: lower-case alphanumerics in runs,
/// separated by `.`, `_` or `-`. A name carrying a `/` would land the block outside
/// its namespace.
fn is_path_component(name: &str) -> bool {
    !name.is_empty()
        && name.split(['.', '_', '-']).all(|run| {
            !run.is_empty() && run.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// The `inputs:` or `outputs:` children as interface fields. A child with no value
/// at all contributes an untyped field rather than being skipped. `always_required`
/// is an output's own rule: an input is optional when it carries a default
/// (`replicas: int = 2`), anything else must be supplied.
fn fields<'a>(
    src: &str,
    entries: impl Iterator<Item = ks_lang::Entry<'a>>,
    always_required: bool,
) -> Vec<BlockField> {
    entries
        .filter_map(|entry| {
            let name = entry.key_name()?.to_string();
            let expr = entry.expr();
            Some(BlockField {
                type_name: expr.as_ref().map(|expr| type_of(src, expr)).unwrap_or_default(),
                required: always_required || !matches!(expr, Some(ks_lang::Expr::Default { .. })),
                name,
            })
        })
        .collect()
}

/// The type a field declares, as the source spells it: `list(string)` and
/// `list(int)` are different types, and a union is whatever it was written as.
fn type_of(src: &str, expr: &ks_lang::Expr<'_>) -> String {
    let declared = match expr {
        ks_lang::Expr::Default { lhs, .. } => lhs.as_ref(),
        other => other,
    };
    declared.span().slice(src).trim().to_string()
}

/// An entry's value as text: a block string dedented, a quoted string unescaped,
/// a bare value as written.
fn entry_text(entry: ks_lang::Entry<'_>) -> String {
    if let Some(block) = entry.block_string() {
        return block.text();
    }
    let Some(expr) = entry.expr() else { return String::new() };
    expr.atoms()
        .iter()
        .map(|atom| match atom {
            ks_lang::Atom::Word(word) => word.text().to_string(),
            ks_lang::Atom::Str(text) => text.value(),
            ks_lang::Atom::Paren { .. } => String::new(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The interface as the JSON layer: what the compatibility rule compares, so it
/// carries exactly what a consumer pins and nothing that would change without a
/// version bump.
fn encode_interface(block: &Block, version: Version) -> Result<Vec<u8>, String> {
    let fields = |fields: &[BlockField]| {
        fields
            .iter()
            .map(|field| {
                json!({
                    "name": field.name,
                    "type": field.type_name,
                    "required": field.required,
                })
            })
            .collect::<Vec<_>>()
    };
    let interface = json!({
        "schemaVersion": 1,
        "name": block.name,
        "version": version.to_string(),
        "summary": block.definition.summary,
        "inputs": fields(&block.definition.inputs),
        "outputs": fields(&block.definition.outputs),
    });
    serde_json::to_vec(&interface).map_err(|error| format!("the interface is not json: {error}"))
}

/// One string member of a json value, absent or of another type reading as none.
fn text<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

/// Reads an interface layer back into a [`BlockDefinition`]. Both lists are
/// required rather than defaulted: one missing is a layer this build did not write,
/// and comparing it as empty would call every field on one side a removal.
fn decode_interface(bytes: &[u8]) -> Result<BlockDefinition, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("the interface is not json: {error}"))?;
    let fields = |key: &str| -> Result<Vec<BlockField>, String> {
        value
            .get(key)
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("the interface has no `{key}` list"))?
            .iter()
            .map(|entry| {
                Ok(BlockField {
                    name: text(entry, "name").ok_or("a field has no name")?.to_string(),
                    type_name: text(entry, "type").unwrap_or_default().to_string(),
                    required: entry
                        .get("required")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                })
            })
            .collect()
    };
    Ok(BlockDefinition {
        summary: text(&value, "summary").unwrap_or_default().to_string(),
        inputs: fields("inputs")?,
        outputs: fields("outputs")?,
    })
}

/// The ways one interface breaks another, as sentences a publisher can act on.
/// Compatible — and so absent from this list — means a new optional input, a
/// required input that became optional, a new output, or a dropped default value.
pub fn breaking_changes(old: &BlockDefinition, new: &BlockDefinition) -> Vec<String> {
    fn find<'a>(fields: &'a [BlockField], name: &str) -> Option<&'a BlockField> {
        fields.iter().find(|field| field.name == name)
    }
    let retype = |kind: &str, before: &BlockField, after: &BlockField| {
        format!(
            "{kind} `{}` changed type from `{}` to `{}`",
            before.name, before.type_name, after.type_name
        )
    };
    let mut changes = Vec::new();
    for field in &old.inputs {
        match find(&new.inputs, &field.name) {
            None => changes.push(format!("input `{}` was removed", field.name)),
            Some(after) if after.type_name != field.type_name => {
                changes.push(retype("input", field, after));
            }
            Some(after) if !field.required && after.required => {
                changes.push(format!("input `{}` became required", field.name));
            }
            Some(_) => {}
        }
    }
    for field in &new.inputs {
        if field.required && find(&old.inputs, &field.name).is_none() {
            changes.push(format!("input `{}` is new and required", field.name));
        }
    }
    // Outputs are reported in the order the old interface declared them,
    // which is the order a consumer reads them in.
    for field in &old.outputs {
        match find(&new.outputs, &field.name) {
            None => changes.push(format!("output `{}` was removed", field.name)),
            Some(after) if after.type_name != field.type_name => {
                changes.push(retype("output", field, after));
            }
            Some(_) => {}
        }
    }
    changes
}

/// What `blocks publish` was asked to publish.
pub struct PublishRequest<'a> {
    pub block: &'a Block,
    /// The `.ks` block file, verbatim: layer 1.
    pub source: &'a str,
    pub readme: Option<&'a str>,
    pub version: Version,
}

/// Where a published block landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub repository: String,
    pub version: Version,
    pub digest: Digest,
}

/// Why a publish was refused, or what went wrong talking to the registry.
///
/// A refusal is the command working — exit 1, with a message naming what to change
/// — while [`Registry`](Self::Registry) is something outside the file that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// The version cannot be published: already there, below what its line holds,
    /// breaking the interface that line holds, or published under a manifest this
    /// build cannot read.
    Refused {
        /// The version offered.
        version: Version,
        /// What is wrong, safe to print.
        reason: String,
        /// The changes, one sentence each, when a change is what was refused.
        changes: Vec<String>,
        /// What to publish instead, when there is one answer.
        suggestion: Option<Version>,
    },
    /// The registry refused or failed.
    Registry {
        /// The repository it was talking to.
        repository: String,
        /// What it said, safe to print.
        message: String,
    },
}

impl PublishError {
    /// A refusal with nothing else to say: no changes, no alternative version.
    fn refused(version: Version, reason: impl Into<String>) -> PublishError {
        PublishError::Refused {
            version,
            reason: reason.into(),
            changes: Vec::new(),
            suggestion: None,
        }
    }
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublishError::Refused { version, reason, changes, suggestion } => {
                write!(f, "{version} was not published: {reason}")?;
                for change in changes {
                    write!(f, "\n  - {change}")?;
                }
                if let Some(suggestion) = suggestion {
                    write!(f, "\npublish it as {suggestion} instead")?;
                }
                Ok(())
            }
            PublishError::Registry { repository, message } => {
                write!(f, "{repository} could not be written: {message}")
            }
        }
    }
}

impl std::error::Error for PublishError {}

/// Publishes `request` into `{root}/{block name}`, refusing a change that breaks
/// the interface its release line already holds.
///
/// `published_tags` is what the repository already holds, and it is what makes
/// every refusal possible. A line with nothing in it has no interface to break,
/// which is why a new major is accepted whatever it changes.
pub async fn publish(
    registry: &Arc<dyn Registry>,
    published_tags: &[String],
    root: &str,
    request: &PublishRequest<'_>,
) -> Result<Published, PublishError> {
    let version = request.version;
    let repository = format!("{root}/{}", request.block.name);
    let published: Vec<Version> =
        published_tags.iter().filter_map(|tag| Version::parse(tag).ok()).collect();
    if published.contains(&version) {
        return Err(PublishError::Refused {
            version,
            reason: "it is already published, and a published version never changes".to_string(),
            changes: Vec::new(),
            suggestion: Some(version.next_line()),
        });
    }
    if let Some(base) = base_of(&published, version) {
        if version < base {
            return Err(PublishError::refused(
                version,
                format!("it is below the published {base} in its release line"),
            ));
        }
        let before = read_published_interface(registry, &repository, base).await?;
        let changes = breaking_changes(&before, &request.block.definition);
        if !changes.is_empty() {
            return Err(PublishError::Refused {
                version,
                reason: format!("it breaks the {base} this release line holds"),
                changes,
                suggestion: Some(base.next_line()),
            });
        }
    }

    // The layers in manifest order, each with the name the annotation spells.
    let mut layers = vec![
        (
            "interface",
            encode_interface(request.block, version)
                .map_err(|reason| PublishError::refused(version, reason))?,
        ),
        ("definition", request.source.as_bytes().to_vec()),
    ];
    if let Some(readme) = request.readme {
        layers.push(("readme", readme.as_bytes().to_vec()));
    }
    let names = layers.iter().map(|(name, _)| *name).collect::<Vec<_>>().join(",");
    let upload = ArtifactUpload {
        media_type: OCI_MANIFEST.to_string(),
        artifact_type: BLOCK_ARTIFACT_TYPE.to_string(),
        blobs: layers.into_iter().map(|(_, bytes)| bytes).collect(),
        annotations: BTreeMap::from([
            ("org.opencontainers.image.title".to_string(), request.block.name.clone()),
            ("org.opencontainers.image.version".to_string(), version.to_string()),
            (LAYERS_ANNOTATION.to_string(), names),
        ]),
        subject: None,
    };
    let descriptor = registry
        .push_artifact(&repository, &upload)
        .await
        .map_err(|error| registry_error(&repository, error))?;
    registry
        .tag(&repository, &version.to_string(), &descriptor.digest)
        .await
        .map_err(|error| registry_error(&repository, error))?;
    Ok(Published { repository, version, digest: descriptor.digest })
}

/// The published version this one is compared against: the highest in its own
/// release line.
fn base_of(published: &[Version], version: Version) -> Option<Version> {
    let line = version.line();
    published.iter().copied().filter(|other| other.line() == line).max()
}

/// The interface of an already-published version, read back through the registry.
/// A manifest that is not a block is refused rather than read as an empty interface
/// every field of this block would then remove.
async fn read_published_interface(
    registry: &Arc<dyn Registry>,
    repository: &str,
    base: Version,
) -> Result<BlockDefinition, PublishError> {
    let unreadable = |reason: String| {
        PublishError::refused(base, format!("the published {base} could not be read: {reason}"))
    };
    let reference = ImageRef::parse(&format!("{repository}:{base}"))
        .map_err(|error| unreadable(error.to_string()))?;
    let manifest_digest =
        registry.resolve(&reference).await.map_err(|error| registry_error(repository, error))?;
    let manifest = registry
        .pull(repository, &manifest_digest)
        .await
        .map_err(|error| registry_error(repository, error))?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest)
        .map_err(|error| unreadable(format!("its manifest is not json: {error}")))?;
    let found = text(&manifest, "artifactType");
    if found != Some(BLOCK_ARTIFACT_TYPE) {
        return Err(unreadable(format!("it is not a block (artifactType is {found:?})")));
    }
    let layer = manifest
        .get("layers")
        .and_then(serde_json::Value::as_array)
        .and_then(|layers| layers.first())
        .and_then(|layer| text(layer, "digest"))
        .ok_or_else(|| unreadable("it has no interface layer".to_string()))?;
    let layer = Digest::parse(layer)
        .map_err(|error| unreadable(format!("its interface layer names {layer:?}: {error}")))?;
    let bytes = registry
        .pull(repository, &layer)
        .await
        .map_err(|error| registry_error(repository, error))?;
    decode_interface(&bytes).map_err(unreadable)
}

fn registry_error(repository: &str, error: RegistryError) -> PublishError {
    PublishError::Registry { repository: repository.to_string(), message: error.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_testing::block_on;
    use ks_testing::supply_chain::FakeRegistry;

    const SOURCE: &str = "\
block: web-service
summary: \"Builds and ships a web service.\"
inputs:
  image: oci.Digest
  replicas: int = 2
outputs:
  url: string
";

    const ROOT: &str = "localhost:5001/acme/blocks";

    /// A fresh fake as the trait object `publish` takes, with the tag list a real
    /// registry would answer beside it: `FakeRegistry` has no listing of its own.
    fn shelf() -> (Arc<dyn Registry>, Vec<String>) {
        (Arc::new(FakeRegistry::new()), Vec::new())
    }

    /// One publish at `version`, remembering the tag for the next call.
    fn publish_at(
        registry: &Arc<dyn Registry>,
        tags: &mut Vec<String>,
        source: &str,
        version: &str,
    ) -> Result<Published, PublishError> {
        let source = &source;
        let block = read_definition(source).unwrap();
        let version = Version::parse(version).unwrap();
        let request = PublishRequest { block: &block, source, readme: None, version };
        let published = block_on(publish(registry, tags, ROOT, &request))?;
        tags.push(version.to_string());
        Ok(published)
    }

    #[test]
    fn versions_are_three_digit_runs_and_nothing_else() {
        assert_eq!(Version::parse("3.1.0"), Ok(Version { major: 3, minor: 1, patch: 0 }));
        assert_eq!(Version::parse("01.0.0").unwrap(), Version::parse("1.0.0").unwrap());
        assert!(Version::parse("2.9.9").unwrap() < Version::parse("3.0.0").unwrap());
        for not in ["3.1", "v3.1.0", "3.1.0-rc1", "3.1.x", "1.2.3.4", ""] {
            assert!(Version::parse(not).is_err(), "{not:?} is not a version");
        }
    }

    #[test]
    fn a_block_file_reads_into_its_interface() {
        let block = read_definition(SOURCE).expect("a publishable block");
        assert_eq!(block.name, "web-service");
        assert_eq!(block.definition.summary, "Builds and ships a web service.");
        assert_eq!(
            block.definition.inputs,
            vec![
                BlockField { name: "image".into(), type_name: "oci.Digest".into(), required: true },
                BlockField { name: "replicas".into(), type_name: "int".into(), required: false },
            ]
        );
        assert_eq!(block.definition.outputs.len(), 1);

        // A type is the text the file spells, not the words inside it:
        // `list(string)` and `list(int)` flatten alike.
        let type_of = |declaration: &str| {
            let block = read_definition(&format!("block: b\ninputs:\n  a: {declaration}\n"))
                .expect("one input");
            block.definition.inputs.into_iter().next().expect("one field").type_name
        };
        assert_eq!(type_of("list(string)"), "list(string)");
        assert_eq!(type_of("list(int)"), "list(int)");
        assert_eq!(type_of("string or int"), "string or int");
        assert_eq!(type_of("int = 2"), "int", "the left of the `=`");

        // And the interface round-trips through its own json.
        let bytes = encode_interface(&block, Version::parse("1.0.0").unwrap())
            .expect("an interface encodes");
        assert_eq!(decode_interface(&bytes).expect("readable"), block.definition);
        assert!(decode_interface(b"not json").is_err());
        // A missing list is not an empty one: read as empty, every field on
        // the other side would read as a removal.
        assert!(decode_interface(br#"{"inputs":[]}"#).is_err(), "no `outputs` list");
    }

    #[test]
    fn a_file_that_does_not_parse_or_cannot_be_named_is_refused() {
        let broken = read_definition("block: x\ninputs:\n  a: \"unclosed\n");
        assert!(broken.is_err(), "a parse error is refused");
        assert!(broken.unwrap_err().contains("does not parse"));
        assert!(read_definition("inputs:\n  a: string\n").is_err(), "no `block:` name");
        for name in ["Web-Service", "-web", "web--service", "web/service", "web service"] {
            assert!(
                read_definition(&format!("block: {name}\n")).is_err(),
                "{name:?} is not a name"
            );
        }
        for name in ["web-service", "rollout.v2", "acme_2"] {
            assert!(read_definition(&format!("block: {name}\n")).is_ok(), "{name:?} is one");
        }
    }

    #[test]
    fn breaking_changes_name_what_breaks_and_leave_compatible_edits_alone() {
        let definition = |inputs: &[(&str, &str, bool)], outputs: &[(&str, &str, bool)]| {
            let field = |(name, type_name, required): &(&str, &str, bool)| BlockField {
                name: (*name).into(),
                type_name: (*type_name).into(),
                required: *required,
            };
            BlockDefinition {
                summary: String::new(),
                inputs: inputs.iter().map(field).collect(),
                outputs: outputs.iter().map(field).collect(),
            }
        };
        let old = definition(
            &[("image", "digest", true), ("domain", "string", false), ("region", "string", true)],
            &[("url", "string", true), ("host", "string", true)],
        );
        // A type changed, an optional input made required, an input removed,
        // a new required input, an output removed, an output retyped.
        assert_eq!(
            breaking_changes(
                &old,
                &definition(
                    &[
                        ("image", "string", true),
                        ("domain", "string", true),
                        ("token", "string", true)
                    ],
                    &[("url", "digest", true)],
                ),
            ),
            vec![
                "input `image` changed type from `digest` to `string`",
                "input `domain` became required",
                "input `region` was removed",
                "input `token` is new and required",
                "output `url` changed type from `string` to `digest`",
                "output `host` was removed",
            ]
        );
        // A new optional input, a required input that became optional and a new
        // output are all compatible.
        assert!(
            breaking_changes(
                &old,
                &definition(
                    &[
                        ("image", "digest", false),
                        ("domain", "string", false),
                        ("region", "string", true),
                        ("zone", "string", false),
                    ],
                    &[("url", "string", true), ("host", "string", true), ("tls", "string", true)],
                ),
            )
            .is_empty()
        );
    }

    #[test]
    fn a_release_line_holds_its_interface_and_a_new_line_starts_one() {
        let (registry, mut tags) = shelf();
        publish_at(&registry, &mut tags, SOURCE, "1.0.0")
            .expect("a first publish is never breaking");
        let shorter = "block: web-service\ninputs:\n  image: oci.Digest\noutputs:\n  url: string\n";

        // Removing an input inside the line is refused, and the message says
        // what broke and which version would be allowed to do it.
        let refused = publish_at(&registry, &mut tags, shorter, "1.1.0");
        let rendered = refused.as_ref().err().map(ToString::to_string).unwrap_or_default();
        let Err(PublishError::Refused { suggestion: Some(suggestion), changes, .. }) = refused
        else {
            panic!("a removed input on a minor bump is a refusal, got {rendered}");
        };
        assert_eq!(changes, vec!["input `replicas` was removed"]);
        assert_eq!(suggestion, Version::parse("2.0.0").unwrap());
        assert!(rendered.starts_with("1.1.0 was not published"), "{rendered}");
        assert!(rendered.contains("- input `replicas` was removed"), "{rendered}");
        assert!(rendered.ends_with("publish it as 2.0.0 instead"), "{rendered}");

        // A new line is a new interface: anything goes.
        let published = publish_at(&registry, &mut tags, shorter, "2.0.0").expect("a new major");
        assert_eq!(published.repository, format!("{ROOT}/web-service"));
        assert_eq!(published.version, Version::parse("2.0.0").unwrap());
        publish_at(&registry, &mut tags, &format!("{SOURCE}  zone: string = eu\n"), "2.1.0")
            .expect("a new optional input is compatible");

        // A version already published cannot be republished, however it is
        // spelled; a version below its line's published ones goes backwards.
        let mut tags = vec!["1.0.0".to_string(), "1.1.0".to_string()];
        assert!(publish_at(&registry, &mut tags, SOURCE, "1.0.0").is_err(), "republished");
        let Err(PublishError::Refused { reason, suggestion: None, .. }) =
            publish_at(&registry, &mut tags, SOURCE, "1.0.1")
        else {
            panic!("1.0.1 is below the published 1.1.0, so it is a refusal");
        };
        assert!(reason.contains("below the published 1.1.0"), "{reason}");
        assert!(publish_at(&registry, &mut tags, SOURCE, "0.9.0").is_ok(), "a new line");
    }

    #[test]
    fn while_the_major_is_zero_the_minor_is_the_breaking_axis() {
        let (registry, mut tags) = shelf();
        publish_at(&registry, &mut tags, SOURCE, "0.1.0").expect("published");
        let shorter = "block: web-service\ninputs:\n  image: oci.Digest\n";
        assert!(publish_at(&registry, &mut tags, shorter, "0.1.1").is_err(), "the same 0.1 line");
        let published =
            publish_at(&registry, &mut tags, shorter, "0.2.0").expect("0.2.0 breaks it");
        assert_eq!(published.version, Version::parse("0.2.0").unwrap());
    }
}
