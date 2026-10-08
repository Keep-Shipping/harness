//! A signed run log: the half of tamper-evidence a hash chain cannot give
//! ([#112](https://github.com/Keep-Shipping/harness/issues/112)).
//!
//! [`run_log`]'s chain catches an edited entry, a deleted one and two swapped —
//! every entry names the hash of the one before it. It cannot catch truncating entries off the end
//! (the prefix left behind is still a good chain) nor a writer that recomputes the chain as it goes
//! (self-consistent, just not the run that happened). Both need a signature over the tip, made from
//! outside the writer.
//!
//! So a *seal* is a signature over the log's last entry, kept beside the log in a **sidecar**:
//! `.keepshipping/runs/<RunId>.seals.jsonl`, one sorted-key JSON object per line —
//! `{"head":"…","identity":{"key":"ed25519:…"},"run":"01H…","seq":4,"signature":"…"}`.
//!
//! A sidecar rather than an in-band `RunEvent` on purpose: a seal is not an event the run *did* but
//! an assertion about the log made afterwards by something other than the run, so an in-band
//! variant would put a signature inside the chain it signs and change the on-disk format every
//! reader already has. As a sidecar the chain's format and its committed golden are untouched, and
//! a log with no seals still verifies as a chain: an old log is an unasserted one, not a broken
//! one. Several seals per run are expected — one at each approval, one at run end ([`seal`]) — and
//! [`verify_sealed`] enforces the rule that matters: the log's *last* entry must be covered by the
//! *last* seal. With no seals at all the answer is a refusal, not a pass, because nothing about an
//! unsealed log can be ruled out. Signing is the [`Signer`] port and nothing more;
//! [`crate::local_key`] is one implementation, and sealing is manual for now.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ks_core::ids::RunId;
use ks_core::ports::supply_chain::{
    ArtifactUpload, Descriptor, Digest, ImageRef, Registry, SignPayload, Signature, Signer,
    SignerIdentity,
};
use serde_json::Value;

use crate::run_log::{self, ChainBreak, JsonlRunLog};

/// The suffix a run's seals file carries, beside `<RunId>.jsonl`. Chosen so the stem
/// (`<RunId>.seals`) does not parse as a [`RunId`], which keeps [`JsonlRunLog::latest`] from
/// mistaking a sidecar for a run log.
pub const SEALS_SUFFIX: &str = ".seals.jsonl";

/// The `artifactType` a signed run log is pushed under: a referrer of the digest it shipped, so
/// `referrers` finds the log exactly as it finds an SBOM. Mirrors the naming in `oci_artifact.rs`.
pub const RUN_LOG_ARTIFACT_TYPE: &str = "application/vnd.keepshipping.run-log.v1";

/// The run the log belongs to, on the artifact manifest.
pub const RUN_ANNOTATION: &str = "io.keepshipping.run-log.run";

/// The head the last seal covers, so a referrer listing can be read without pulling the log.
pub const HEAD_ANNOTATION: &str = "io.keepshipping.run-log.head";

/// Where a run's seals are kept, beside its entries.
pub fn seals_path(dir: &Path, run: &RunId) -> PathBuf {
    dir.join(format!("{run}{SEALS_SUFFIX}"))
}

/// One signature over one entry's head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seal {
    /// The run the seal is about.
    pub run: String,
    /// The `seq` of the entry this seal covers.
    pub seq: u64,
    /// That entry's `hash`.
    pub head: String,
    /// The identity the signature claims.
    pub identity: SignerIdentity,
    /// The signature bytes, in the signer's own format.
    pub signature: Vec<u8>,
}

/// The bytes a seal signs. Domain-separated and line-oriented, so the same text can never be read
/// as a signature over anything else this crate signs — a signature over a bare hash would be.
pub fn seal_payload(run: &str, seq: u64, head: &str) -> SignPayload {
    SignPayload::Bytes(
        format!("keepshipping run-log seal v1\nrun {run}\nseq {seq}\nhead {head}\n").into_bytes(),
    )
}

impl Seal {
    /// The line this seal is stored as: sorted keys, one object, no spaces.
    pub fn to_line(&self) -> String {
        let identity = match &self.identity {
            SignerIdentity::Key { key_id } => format!("{{\"key\":{}}}", quoted(key_id)),
            SignerIdentity::Keyless { issuer, subject } => {
                format!("{{\"issuer\":{},\"subject\":{}}}", quoted(issuer), quoted(subject))
            }
        };
        format!(
            "{{\"head\":{},\"identity\":{},\"run\":{},\"seq\":{},\"signature\":{}}}",
            quoted(&self.head),
            identity,
            quoted(&self.run),
            self.seq,
            quoted(&hex(&self.signature))
        )
    }

    /// The identity as a verifier resolves it: `key:<id>` for a key, `<subject> from <issuer>` for
    /// a keyless one — `signing.rs`'s grammar, so one matcher reads both.
    pub fn identity_text(&self) -> String {
        ks_engine::signing::identity_text(&self.identity)
    }

    fn parse(line: &str) -> Result<Seal, String> {
        let value: Value =
            serde_json::from_str(line).map_err(|e| format!("not a JSON object ({e})"))?;
        let object = value.as_object().ok_or("not a JSON object")?;
        let field = |object: &serde_json::Map<String, Value>, key: &str| {
            object.get(key).and_then(Value::as_str).map(str::to_string).ok_or_else(|| missing(key))
        };
        let text = |key: &str| field(object, key);
        let identity =
            object.get("identity").and_then(Value::as_object).ok_or_else(|| missing("identity"))?;
        let keyless = |key: &str| {
            field(identity, key).map_err(|_| format!("the seal names neither a key nor {key}"))
        };
        let identity = match identity.get("key") {
            Some(_) => SignerIdentity::Key { key_id: field(identity, "key")? },
            None => {
                SignerIdentity::Keyless { issuer: keyless("issuer")?, subject: keyless("subject")? }
            }
        };
        Ok(Seal {
            run: text("run")?,
            seq: object.get("seq").and_then(Value::as_u64).ok_or_else(|| missing("seq"))?,
            head: text("head")?,
            identity,
            signature: unhex(&text("signature")?)?,
        })
    }

    fn signature(&self) -> Signature {
        Signature { bytes: self.signature.clone(), identity: self.identity.clone() }
    }
}

/// What a field the line does not have is called.
fn missing(key: &str) -> String {
    format!("the seal has no `{key}`")
}

/// Why a run log is not what it claims to be. Every variant that names a line names it 1-based, in
/// the log or in the seals file as that variant says — which file it is in is the caller's to name,
/// since the seals live beside the log, not inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealBreak {
    /// The hash chain does not hold.
    Chain { line: usize, reason: String },
    /// The log has no seals at all. A refusal, not a pass.
    Unsealed,
    /// A line of the seals file does not hold.
    Seal { line: usize, reason: String },
    /// A log entry does not match the seal that claims it.
    Entry { line: usize, seal_line: usize, reason: String },
    /// A signature did not verify.
    Signature { line: usize, reason: String },
    /// The log continues past the last seal: that line is covered by nothing.
    Uncovered { line: usize },
    /// The entry the last seal covers is not a `run.finished`, so the run went on past it and
    /// whatever came after may have been cut off along with the seals over it. The line is the
    /// one after the covered tip — the first one that is missing or, if the log is intact,
    /// uncovered by any seal left behind.
    Incomplete { line: usize },
    /// The log ends before the last seal's entry. The line is the first one *missing* from the file
    /// — what to go and look for — so it is one past the last entry that is there, which is the
    /// seal's own entry only when the cut is at the seal itself.
    Truncated { line: usize },
}

impl std::fmt::Display for SealBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealBreak::Chain { reason, .. } => write!(f, "chain broken: {reason}"),
            SealBreak::Unsealed => {
                write!(f, "not sealed: truncation and rewrite cannot be ruled out")
            }
            SealBreak::Seal { reason, .. } => write!(f, "seal does not hold: {reason}"),
            SealBreak::Entry { seal_line, reason, .. } => {
                write!(f, "entry does not match the seal at seals line {seal_line}: {reason}")
            }
            SealBreak::Signature { reason, .. } => write!(f, "signature does not verify: {reason}"),
            SealBreak::Uncovered { .. } => {
                write!(f, "entry not covered by any seal (appended after sealing)")
            }
            SealBreak::Incomplete { .. } => write!(
                f,
                "no `run.finished` after the last seal — the run is unfinished or the log was truncated"
            ),
            SealBreak::Truncated { .. } => write!(f, "entry missing — log truncated after seal"),
        }
    }
}

/// Why sealing failed. `Io`, `Sign` and the registry variants carry a message safe to print.
#[derive(Debug)]
pub enum SealError {
    Io {
        message: String,
    },
    /// The log is empty, or has no entry to sign.
    Empty,
    /// The chain does not hold, so a signature would only certify a lie.
    Chain(ChainBreak),
    Sign {
        message: String,
    },
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealError::Io { message } => write!(f, "{message}"),
            SealError::Empty => write!(f, "the run log is empty — there is no entry to seal"),
            SealError::Chain(broken) => {
                write!(f, "line {}: chain broken: {}", broken.line, broken.reason)
            }
            SealError::Sign { message } => write!(f, "signing the run log failed ({message})"),
        }
    }
}

impl From<std::io::Error> for SealError {
    fn from(error: std::io::Error) -> SealError {
        SealError::Io { message: error.to_string() }
    }
}

/// One approval as the log recorded it: who, through which channel, for which step. The channel is
/// part of the claim — an approval that arrived over `github` is not one that arrived over `slack`,
/// and the log is the only place that says which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub approver: String,
    pub channel: String,
    pub step: String,
}

/// What a verified run log says, in the order a reader asks: who proposed it, who approved each
/// step, what shipped, and under which seals. Names come from the log, never invented here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Story {
    pub run: String,
    pub entries: usize,
    /// Each seal as the `seq` it covers and the identity that signed it, in the order appended.
    pub seals: Vec<(u64, String)>,
    /// `run.started`'s `actor`, when the log names one.
    pub proposed_by: Option<String>,
    /// Every `approval.granted`, in log order.
    pub approvals: Vec<Approval>,
    /// `run.finished`'s `shipped`, as the log recorded them.
    pub shipped: Vec<String>,
    /// `run.finished`'s `status`, when the run finished.
    pub status: Option<String>,
}

impl std::fmt::Display for Story {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "run {}  {} entries", self.run, self.entries)?;
        if let Some(actor) = &self.proposed_by {
            writeln!(f, "  proposed by  {actor}")?;
        }
        for (seq, identity) in &self.seals {
            writeln!(f, "  sealed at    seq {seq} by {identity}")?;
        }
        for a in &self.approvals {
            writeln!(f, "  approved by  {} via {} ({})", a.approver, a.channel, a.step)?;
        }
        if !self.shipped.is_empty() {
            writeln!(f, "  shipped      {}", self.shipped.join(", "))?;
        }
        if let Some(status) = &self.status {
            writeln!(f, "  status       {status}")?;
        }
        Ok(())
    }
}

/// What a chain and its seals agree on, once checked without a key. The signature bytes are checked
/// separately ([`verify_sealed`]) because pushing an artifact must not need the public key —
/// publishing the log is not the same act as vouching for it.
struct Checked {
    story: Story,
    seals: Vec<Seal>,
}

/// Signs the log's tip and appends the seal to the sidecar. The chain is verified first: a signature
/// over a broken log would certify a log that says something else than what happened, which is
/// worse than no seal. An empty log is refused — there is no entry to attest.
pub async fn seal(dir: &Path, run: &RunId, signer: &dyn Signer) -> Result<Seal, SealError> {
    let text = std::fs::read_to_string(JsonlRunLog::path_for(dir, run)).map_err(|e| {
        SealError::Io { message: format!("cannot read the log for run {run}: {e}") }
    })?;
    let entries = run_log::verify(&text).map_err(SealError::Chain)?;
    if entries == 0 {
        return Err(SealError::Empty);
    }
    let head = hashes(&text).pop().unwrap_or_default();
    let seq = (entries - 1) as u64;
    let signature = signer
        .sign(&seal_payload(&run.to_string(), seq, &head))
        .await
        .map_err(|e| SealError::Sign { message: e.to_string() })?;
    let seal = Seal {
        run: run.to_string(),
        seq,
        head,
        identity: signature.identity,
        signature: signature.bytes,
    };
    let mut file =
        std::fs::OpenOptions::new().create(true).append(true).open(seals_path(dir, run))?;
    use std::io::Write as _;
    writeln!(file, "{}", seal.to_line())?;
    file.flush()?;
    Ok(seal)
}

/// Checks a log against its seals: the chain, then every seal's shape, then that the log's last
/// entry is the one the last seal covers. The signature bytes are *not* checked — [`verify_sealed`]
/// does that with a key.
fn check_seals(log_text: &str, seals_text: &str) -> Result<Checked, SealBreak> {
    let entries = run_log::verify(log_text)
        .map_err(|b| SealBreak::Chain { line: b.line, reason: b.reason })?;
    if entries == 0 {
        return Err(SealBreak::Unsealed);
    }
    let hashes = hashes(log_text);
    let entry_run = run_of(log_text).unwrap_or_default();
    let mut seals = Vec::new();
    for (n, line) in seals_text.lines().enumerate() {
        let at = n + 1;
        let seal = Seal::parse(line).map_err(|reason| SealBreak::Seal { line: at, reason })?;
        // A seal about another run is not a seal about this one, however well it verifies.
        if seal.run != entry_run {
            return Err(SealBreak::Seal {
                line: at,
                reason: format!("it is about run {}, not {entry_run}", seal.run),
            });
        }
        match hashes.get(seal.seq as usize) {
            // The chain holds, so what is there is a prefix of the run, and the line after the
            // last entry that is there is the first one missing.
            None => return Err(SealBreak::Truncated { line: entries + 1 }),
            Some(hash) if *hash != seal.head => {
                return Err(SealBreak::Entry {
                    line: seal.seq as usize + 1,
                    seal_line: at,
                    reason: format!("its hash is {hash}, not the sealed {}", seal.head),
                });
            }
            Some(_) => seals.push(seal),
        }
    }
    if seals.is_empty() {
        return Err(SealBreak::Unsealed);
    }
    // The rule that catches both what the chain cannot: entries after the last seal were appended
    // after it (`Truncated` above is the other half of that pair, per seal).
    let last = seals.last().expect("a seal was just pushed");
    if entries as u64 > last.seq + 1 {
        return Err(SealBreak::Uncovered { line: last.seq as usize + 2 });
    }
    // And completeness: the entry the last seal covers has to be the run's last one. Without this,
    // cutting the tail entries *and* the seals over them leaves a good chain under a good seal —
    // a shorter run that verifies. A seal over a tip that is not `run.finished` says the run went
    // on past it, so what followed is exactly what a tamperer would remove.
    if !ends_run(log_text, last.seq) {
        return Err(SealBreak::Incomplete { line: last.seq as usize + 2 });
    }
    Ok(Checked { story: story(log_text, entries, &seals), seals })
}

/// Checks a log, its seals and every signature, and returns the story. This is the whole of
/// `keepshipping log verify`: nothing else may report a run as verified. A run only counts as
/// verified when the last seal covers a `run.finished`, so a log cut back to an earlier seal —
/// entries and seals removed together — fails rather than reading as a shorter run.
pub async fn verify_sealed(
    log_text: &str,
    seals_text: &str,
    verifier: &dyn Signer,
) -> Result<Story, SealBreak> {
    let checked = check_seals(log_text, seals_text)?;
    for (n, seal) in checked.seals.iter().enumerate() {
        let at = n + 1;
        let identity = verifier
            .verify(&seal_payload(&seal.run, seal.seq, &seal.head), &seal.signature())
            .await
            .map_err(|e| SealBreak::Signature { line: at, reason: e.to_string() })?;
        if identity != seal.identity {
            let claimed = seal.identity_text();
            return Err(SealBreak::Signature {
                line: at,
                reason: format!(
                    "it verifies as {}, but the seal claims {claimed}",
                    ks_engine::signing::identity_text(&identity)
                ),
            });
        }
    }
    Ok(checked.story)
}

/// Pushes a sealed run log as an artifact referring to `subject` — the digest the run says it
/// shipped. A log may only be attached to a digest it says it shipped: otherwise anyone could pin a
/// log that claims to have shipped something they did not. The signature bytes are not checked here
/// (that needs the public key), but the chain and the seals' shape are, so a log whose chain is
/// broken, or whose tip no seal covers, is never pushed at all.
pub async fn attach(
    registry: &dyn Registry,
    repository: &str,
    subject: &Digest,
    log_text: &str,
    seals_text: &str,
) -> Result<Descriptor, AttachError> {
    let checked = check_seals(log_text, seals_text).map_err(AttachError::Seal)?;
    if !checked.story.shipped.iter().any(|digest| digest == &subject.to_string()) {
        return Err(AttachError::NotShipped { digest: subject.clone() });
    }
    let mut annotations = BTreeMap::new();
    annotations.insert(RUN_ANNOTATION.to_string(), checked.story.run.clone());
    annotations.insert(
        HEAD_ANNOTATION.to_string(),
        checked.seals.last().map(|seal| seal.head.clone()).unwrap_or_default(),
    );
    registry
        .push_artifact(
            repository,
            &ArtifactUpload {
                media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                artifact_type: RUN_LOG_ARTIFACT_TYPE.to_string(),
                // Entries first, seals second: the manifest carries no per-layer media type an
                // adapter would have to invent, so the order is the contract, and
                // `verify_from_registry` fails loudly rather than silently if the two are the
                // other way round.
                blobs: vec![log_text.as_bytes().to_vec(), seals_text.as_bytes().to_vec()],
                annotations,
                subject: Some(subject.clone()),
            },
        )
        .await
        .map_err(|error| AttachError::Registry { message: error.to_string() })
}

/// Reads back the run logs attached to `image` and checks each one: the referrers of that digest,
/// filtered to [`RUN_LOG_ARTIFACT_TYPE`], pulled and verified against `verifier`, and the digest
/// must be one the log says it shipped.
///
/// `image` must be by digest — a tag can be moved between the moment the log was attached and the
/// moment it is read, and then the log would be about a different run than the tag names. Several
/// run logs on one digest (a matrix of runs shipping the same image) are all verified, and the
/// first that fails fails the lot: a digest with one unverifiable run log attached is not one
/// anyone should ship.
pub async fn verify_from_registry(
    registry: &dyn Registry,
    image: &ImageRef,
    verifier: &dyn Signer,
) -> Result<Vec<Story>, RegistryStoryError> {
    let subject = image.digest().ok_or_else(|| {
        RegistryStoryError::Reference(format!(
            "{image} is not a digest — a tag can move, and a moved tag would name a different run"
        ))
    })?;
    let repository = image.repository();
    let referrers = registry.referrers(repository, subject).await.map_err(registry_error)?;
    let mut stories = Vec::new();
    for descriptor in referrers {
        let bytes = registry.pull(repository, &descriptor.digest).await.map_err(registry_error)?;
        // The artifact type lives in the manifest, not the descriptor, so it is the manifest that
        // decides: a referrer that is not a run log (an SBOM, a signature) is none of this
        // command's business.
        let manifest: Value =
            serde_json::from_slice(&bytes).map_err(|e| RegistryStoryError::Manifest {
                message: format!("a referrer of {subject} is not JSON ({e})"),
            })?;
        if manifest.get("artifactType").and_then(Value::as_str) != Some(RUN_LOG_ARTIFACT_TYPE) {
            continue;
        }
        // A referrer listing is the registry's word about what refers to what, and this is the log's
        // own word. A registry that lists a run log under the wrong digest would otherwise have a
        // perfectly valid log of a different run read as this one.
        if manifest.get("subject").and_then(|subject| subject.get("digest")).and_then(Value::as_str)
            != Some(&subject.to_string())
        {
            return Err(RegistryStoryError::Manifest {
                message: format!("a run log attached to something other than {subject}"),
            });
        }
        // Entries first, seals second — the order `attach` pushed them in.
        let layers = layers_of(&manifest)?;
        let count = layers.len();
        let [entries, seals]: [Digest; 2] =
            layers.try_into().map_err(|_| RegistryStoryError::Manifest {
                message: format!(
                    "a run log artifact has the entries and the seals, got {count} blobs"
                ),
            })?;
        let log_text = text_of(registry, repository, &entries).await?;
        let seals_text = text_of(registry, repository, &seals).await?;
        let story = verify_sealed(&log_text, &seals_text, verifier)
            .await
            .map_err(RegistryStoryError::Seal)?;
        if !story.shipped.iter().any(|digest| digest == &subject.to_string()) {
            return Err(RegistryStoryError::NotShipped { digest: subject.clone() });
        }
        stories.push(story);
    }
    match stories.is_empty() {
        true => Err(RegistryStoryError::NotAttached(image.to_string())),
        false => Ok(stories),
    }
}

/// The digests a run log manifest's layers name, in order.
fn layers_of(manifest: &Value) -> Result<Vec<Digest>, RegistryStoryError> {
    let layers = manifest.get("layers").and_then(Value::as_array).ok_or_else(|| {
        RegistryStoryError::Manifest { message: "the run log manifest has no `layers`".to_string() }
    })?;
    layers
        .iter()
        .filter_map(|layer| layer.get("digest").and_then(Value::as_str))
        .map(|text| {
            Digest::parse(text).map_err(|_| RegistryStoryError::Manifest {
                message: format!("a layer's digest `{text}` does not parse"),
            })
        })
        .collect()
}

/// A blob pulled from a registry as UTF-8 text.
async fn text_of(
    registry: &dyn Registry,
    repository: &str,
    digest: &Digest,
) -> Result<String, RegistryStoryError> {
    let bytes = registry.pull(repository, digest).await.map_err(registry_error)?;
    String::from_utf8(bytes).map_err(|e| RegistryStoryError::Manifest { message: e.to_string() })
}

/// The registry's own refusal, as this module reports it.
fn registry_error(error: impl std::fmt::Display) -> RegistryStoryError {
    RegistryStoryError::Registry { message: error.to_string() }
}

/// Why a run log could not be attached.
#[derive(Debug)]
pub enum AttachError {
    /// The log does not hold.
    Seal(SealBreak),
    /// The log does not say it shipped the digest it was being attached to.
    NotShipped { digest: Digest },
    /// The registry refused.
    Registry { message: String },
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttachError::Seal(broken) => write!(f, "{broken}"),
            AttachError::NotShipped { digest } => {
                write!(f, "the run log does not say it shipped {digest}")
            }
            AttachError::Registry { message } => write!(f, "{message}"),
        }
    }
}

/// Why a run log could not be read back from a registry.
#[derive(Debug)]
pub enum RegistryStoryError {
    /// The reference is not a digest.
    Reference(String),
    /// Nothing is attached to the digest.
    NotAttached(String),
    /// A run log attached to it does not verify.
    Seal(SealBreak),
    /// The log does not say it shipped the digest it was attached to.
    NotShipped { digest: Digest },
    /// The registry refused, or answered something unusable.
    Registry { message: String },
    /// The artifact's manifest is not a run log.
    Manifest { message: String },
}

impl std::fmt::Display for RegistryStoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryStoryError::Reference(message) => write!(f, "{message}"),
            RegistryStoryError::NotAttached(image) => write!(f, "no run log attached to {image}"),
            RegistryStoryError::Seal(broken) => write!(f, "{broken}"),
            RegistryStoryError::NotShipped { digest } => {
                write!(f, "the attached run log does not say it shipped {digest}")
            }
            RegistryStoryError::Registry { message } => write!(f, "{message}"),
            RegistryStoryError::Manifest { message } => {
                write!(f, "the attached artifact is not a run log ({message})")
            }
        }
    }
}

/// Every entry's `hash`, in file order — index `i` is the entry with `seq` `i`, which
/// [`run_log::verify`] has just established.
fn hashes(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            serde_json::from_str::<Value>(line)
                .ok()?
                .get("hash")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

/// The run id the log's first entry carries.
fn run_of(text: &str) -> Option<String> {
    let first = text.lines().next()?;
    serde_json::from_str::<Value>(first).ok()?.get("run")?.as_str().map(str::to_string)
}

/// Whether the entry at `seq` — which `run_log::verify` has established exists — is the run's last
/// event. Anything other than `run.finished` means the run went on past it.
fn ends_run(text: &str, seq: u64) -> bool {
    text.lines()
        .nth(seq as usize)
        .and_then(|line| serde_json::from_str::<Value>(line).ok())
        .and_then(|entry| entry.get("type").and_then(Value::as_str).map(str::to_string))
        .is_some_and(|kind| kind == "run.finished")
}

/// The story a verified log tells, read off the entries themselves.
fn story(text: &str, entries: usize, seals: &[Seal]) -> Story {
    let mut story = Story {
        run: run_of(text).unwrap_or_default(),
        entries,
        seals: seals.iter().map(|seal| (seal.seq, seal.identity_text())).collect(),
        proposed_by: None,
        approvals: Vec::new(),
        shipped: Vec::new(),
        status: None,
    };
    for line in text.lines() {
        let Ok(Value::Object(entry)) = serde_json::from_str::<Value>(line) else { continue };
        let field =
            |key: &str| entry.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
        let named = |text: String| (!text.is_empty()).then_some(text);
        match entry.get("type").and_then(Value::as_str).unwrap_or_default() {
            "run.started" => story.proposed_by = named(field("actor")),
            "approval.granted" => story.approvals.push(Approval {
                approver: field("approver"),
                channel: field("channel"),
                step: field("step"),
            }),
            "run.finished" => {
                story.shipped = entry
                    .get("shipped")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items.iter().filter_map(Value::as_str).map(str::to_string).collect()
                    })
                    .unwrap_or_default();
                story.status = named(field("status"));
            }
            _ => {}
        }
    }
    story
}

fn quoted(text: &str) -> String {
    serde_json::to_string(text).expect("a string serializes")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Hex to bytes, or why it is not hex. ASCII first: the slices below are byte offsets, and a
/// non-ASCII character would be cut in half rather than reported. Lowercase only, so a signature
/// has exactly one spelling on disk and two spellings cannot both pass.
fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if !text.is_ascii() {
        return Err("the signature is not hexadecimal".to_string());
    }
    if !text.len().is_multiple_of(2) {
        return Err(format!("the signature is {} characters, not whole bytes", text.len()));
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            let pair = &text[at..at + 2];
            if pair.bytes().any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte)) {
                return Err(format!("`{pair}` is not lowercase hex"));
            }
            u8::from_str_radix(pair, 16).map_err(|_| format!("`{pair}` is not hex"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use ks_core::ports::run_log::{RunEvent, RunLog};
    use ks_testing::supply_chain::{FakeRegistry, FakeSigner};
    use ks_testing::{block_on, clock::FakeClock};

    /// The spec's example ULID, so a run in a test names a known file.
    const RUN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    /// What the run says it shipped; also the subject a log may be attached to.
    const SHIPPED: &str = "sha256:00000000000000000000000000000000000000000000000000000000000000cc";
    /// The key every fixture seals with, so the seal's identity reads the same everywhere.
    const KEY: &str = "ed25519:0123456789abcdef";

    /// A tamper, and the line the chain reports it at.
    type Damage<'a> = (&'a str, &'a dyn Fn(&mut Vec<String>), usize);

    /// A run that proposed, built, got an approval and shipped a digest.
    fn events() -> Vec<RunEvent> {
        vec![
            RunEvent::RunStarted {
                file_hash: "sha256:aa".into(),
                event: "push main".into(),
                actor: "ci".into(),
                is_agent: false,
            },
            RunEvent::StepStarted { step: "build".into() },
            RunEvent::ApprovalGranted {
                step: "deploy".into(),
                approver: "alice".into(),
                channel: "github".into(),
                artifacts: vec!["sha256:bb".into()],
            },
            RunEvent::RunFinished { status: "shipped".into(), shipped: vec![SHIPPED.into()] },
        ]
    }

    /// A directory of this test's own, emptied so every fixture starts from nothing.
    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("keepshipping-seal-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// One run's log, written event by event — a fresh log per test, so a forged one can reuse the
    /// run id and differ only in what it says.
    fn run_of_events(name: &str, events: Vec<RunEvent>) -> (PathBuf, RunId) {
        let dir = dir(name);
        let run = RunId::parse(RUN).expect("the spec");
        let log = JsonlRunLog::new(dir.clone(), Arc::new(FakeClock::new()));
        for event in events {
            block_on(log.append(&run, event)).expect("append");
        }
        (dir, run)
    }

    /// The standard four-entry log, in a directory of its own.
    fn log(name: &str) -> (PathBuf, RunId) {
        run_of_events(name, events())
    }

    fn text_of(dir: &Path, run: &RunId) -> String {
        std::fs::read_to_string(JsonlRunLog::path_for(dir, run)).expect("the run's log")
    }

    fn seals_of(dir: &Path, run: &RunId) -> String {
        std::fs::read_to_string(seals_path(dir, run)).expect("the seals")
    }

    /// The same log with `damage` applied, as a writer of the tamper would.
    fn damaged(text: &str, damage: impl Fn(&mut Vec<String>)) -> String {
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        damage(&mut lines);
        lines.join("\n")
    }

    /// The log, signed at its tip.
    fn sealed(name: &str) -> (PathBuf, RunId, String, String, FakeSigner) {
        let (dir, run) = log(name);
        let signer = FakeSigner::with_key(KEY);
        block_on(seal(&dir, &run, &signer)).expect("seal");
        let text = text_of(&dir, &run);
        let seals = seals_of(&dir, &run);
        (dir, run, text, seals, signer)
    }

    /// An untouched sealed run verifies, and the story says what the log says.
    #[test]
    fn an_untouched_sealed_run_verifies_and_tells_its_story() {
        let (_dir, run, text, seals, signer) = sealed("intact");
        let story = block_on(verify_sealed(&text, &seals, &signer)).expect("sealed and intact");
        assert_eq!(story.run, run.to_string());
        assert_eq!((story.entries, story.proposed_by.as_deref()), (4, Some("ci")));
        let alice =
            Approval { approver: "alice".into(), channel: "github".into(), step: "deploy".into() };
        assert_eq!(story.approvals, vec![alice]);
        assert_eq!(story.shipped, vec![SHIPPED.to_string()]);
        assert_eq!(story.status.as_deref(), Some("shipped"));
        assert_eq!(story.seals, vec![(3, format!("key:{KEY}"))]);
    }

    /// What the chain catches on its own — an edit, a deletion and a swap — each breaks at a named
    /// line, and the seal check runs the chain before it looks at any seal.
    #[test]
    fn damage_the_chain_catches_breaks_it_at_that_line() {
        let cases: Vec<Damage> = vec![
            ("edit", &|lines| lines[1] = lines[1].replace("build\"", "build \""), 2),
            (
                "delete",
                &|lines| {
                    lines.remove(1);
                },
                2,
            ),
            (
                "swap",
                &|lines| {
                    lines.swap(1, 2);
                },
                2,
            ),
        ];
        for (name, damage, line) in cases {
            let (_dir, _run, text, seals, signer) = sealed(name);
            let broken =
                block_on(verify_sealed(&damaged(&text, damage), &seals, &signer)).expect_err(name);
            assert!(
                matches!(broken, SealBreak::Chain { line: at, .. } if at == line),
                "{name}: {broken:?}"
            );
        }
    }

    /// What the chain cannot see: entries cut off the end leave a good prefix. The line named is
    /// the first one missing from the file — here line 3, even though the seal covered line 4,
    /// because that is where the file stops.
    #[test]
    fn a_truncated_log_is_caught_at_the_missing_entry() {
        let (_dir, _run, text, seals, signer) = sealed("truncated");
        let truncated = damaged(&text, |lines| {
            lines.truncate(2);
        });
        let broken = block_on(verify_sealed(&truncated, &seals, &signer)).expect_err("truncated");
        assert_eq!(broken, SealBreak::Truncated { line: 3 }, "{broken:?}");
        assert_eq!(broken.to_string(), "entry missing — log truncated after seal");
    }

    /// Entries appended after the last seal are not covered by it, however good the chain they
    /// extend is.
    #[test]
    fn entries_appended_after_sealing_are_not_covered() {
        let (dir, run) = log("appended");
        let signer = FakeSigner::with_key(KEY);
        block_on(seal(&dir, &run, &signer)).expect("seal");
        // The run continues after the seal — a second approval, say.
        let log = JsonlRunLog::new(dir.clone(), Arc::new(FakeClock::new()));
        block_on(log.append(
            &run,
            RunEvent::ApprovalDenied {
                step: "deploy".into(),
                approver: "bob".into(),
                channel: "github".into(),
                artifacts: vec![],
                reason: "not today".into(),
            },
        ))
        .expect("append");
        let broken = block_on(verify_sealed(&text_of(&dir, &run), &seals_of(&dir, &run), &signer))
            .expect_err("appended");
        assert_eq!(broken, SealBreak::Uncovered { line: 5 }, "{broken:?}");
    }

    /// A writer that recomputes the chain leaves a log that verifies perfectly — and whose head is
    /// not the head that was signed. The forged log is written through a fresh run log, so every
    /// hash after the edit is genuinely recomputed: exactly the attack the chain cannot see.
    #[test]
    fn a_recomputed_chain_does_not_match_the_seal() {
        let (_dir, _run, _text, seals, signer) = sealed("recomputed");
        let mut forged = events();
        forged.pop();
        forged
            .push(RunEvent::RunFinished { status: "failed".into(), shipped: vec![SHIPPED.into()] });
        let (dir, run) = run_of_events("recomputed-forged", forged);
        let forged = text_of(&dir, &run);
        assert_eq!(run_log::verify(&forged).expect("the chain still holds"), 4);
        match block_on(verify_sealed(&forged, &seals, &signer)).expect_err("forged") {
            SealBreak::Entry { line, seal_line, .. } => assert_eq!((line, seal_line), (4, 1)),
            other => panic!("a recomputed chain must fail at the seal, got {other:?}"),
        }
    }

    /// What a seal itself can get wrong: none of it is a line of the log, so none of it may be
    /// reported as one, and none of it passes.
    #[test]
    fn a_seal_that_does_not_hold_is_named_in_the_seals_file() {
        let (_dir, _run, text, seals, signer) = sealed("bad-seal");
        let relabelled = seals.replace(KEY, "ed25519:fedcba9876543210");
        let broken = block_on(verify_sealed(&text, &relabelled, &signer)).expect_err("relabelled");
        assert!(matches!(broken, SealBreak::Signature { line: 1, .. }), "{broken:?}");
        let broken = block_on(verify_sealed(&text, "{\"head\":\n", &signer)).expect_err("not JSON");
        assert!(matches!(broken, SealBreak::Seal { line: 1, .. }), "{broken:?}");
    }

    /// A log with no seals at all is refused rather than passed, and neither is a log there is
    /// nothing to attest: an empty one, or one whose chain does not hold.
    #[test]
    fn nothing_unsealed_or_unintact_is_signed_or_passed() {
        let signer = FakeSigner::with_key("k");
        let (empty_dir, run) = log("unsealed");
        let broken =
            block_on(verify_sealed(&text_of(&empty_dir, &run), "", &signer)).expect_err("no seals");
        assert_eq!(broken, SealBreak::Unsealed, "{broken:?}");
        assert_eq!(broken.to_string(), "not sealed: truncation and rewrite cannot be ruled out");

        let (dir, run) = (dir("empty"), RunId::parse(RUN).expect("the spec"));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(JsonlRunLog::path_for(&dir, &run), "").expect("an empty log");
        let broken = block_on(seal(&dir, &run, &signer)).expect_err("empty");
        assert!(matches!(broken, SealError::Empty), "{broken:?}");

        let (dir, run) = log("broken-chain");
        let text = text_of(&dir, &run);
        // An edit to an entry's own contents: its `hash` no longer fits it.
        let edited = damaged(&text, |lines| {
            lines[2] = lines[2].replace("\"channel\":\"github\"", "\"channel\":\"slack\"");
        });
        std::fs::write(JsonlRunLog::path_for(&dir, &run), edited).expect("write");
        let broken = block_on(seal(&dir, &run, &signer)).expect_err("broken");
        assert!(matches!(broken, SealError::Chain(_)), "{broken:?}");
    }

    /// The sidecar is beside the log, not inside it: the entries and the golden chain are untouched
    /// by a seal, and a seals file is not mistaken for a run of its own.
    #[test]
    fn sealing_does_not_touch_the_log() {
        let (dir, run) = log("sidecar");
        let before = text_of(&dir, &run);
        block_on(seal(&dir, &run, &FakeSigner::with_key("k"))).expect("seal");
        assert_eq!(text_of(&dir, &run), before);
        assert_eq!(run_log::verify(&before).expect("chain intact"), 4);
        let sidecar = seals_path(&dir, &run);
        let name = sidecar.file_name().expect("a file name").to_string_lossy().into_owned();
        assert_eq!(name, format!("{RUN}{SEALS_SUFFIX}"));
        assert_eq!(JsonlRunLog::latest(&dir), Some(run));
    }

    /// Several seals per run are normal, and the last one is the one that has to cover the tip.
    #[test]
    fn several_seals_verify_with_the_last_covering_the_tip() {
        let (dir, run) = run_of_events("two-seals", events().into_iter().take(3).collect());
        let signer = FakeSigner::with_key(KEY);
        // The fixture has logged everything but the end, so this first seal covers the approval.
        let first = block_on(seal(&dir, &run, &signer)).expect("seal the tip so far");
        assert_eq!(first.seq, 2);
        let log = JsonlRunLog::new(dir.clone(), Arc::new(FakeClock::new()));
        let finished =
            RunEvent::RunFinished { status: "shipped".into(), shipped: vec![SHIPPED.into()] };
        block_on(log.append(&run, finished)).expect("append");
        let last = block_on(seal(&dir, &run, &signer)).expect("seal the tip");
        let story = block_on(verify_sealed(&text_of(&dir, &run), &seals_of(&dir, &run), &signer))
            .expect("two seals");
        assert_eq!(story.seals.first().map(|seal| seal.0), Some(first.seq));
        assert_eq!(story.seals.last().expect("a seal").0, last.seq);
    }

    /// The truncation a seal alone does not catch: cut the tail entries *and* the seals over
    /// them, and what is left is a good chain under a good signature — a shorter run that would
    /// otherwise verify. It does not any more, because the seal left behind does not cover a
    /// `run.finished`.
    #[test]
    fn a_truncation_that_takes_the_seals_with_it_is_caught() {
        let (dir, run) = run_of_events("shortened", events().into_iter().take(3).collect());
        let signer = FakeSigner::with_key(KEY);
        block_on(seal(&dir, &run, &signer)).expect("seal the approval");
        let log = JsonlRunLog::new(dir.clone(), Arc::new(FakeClock::new()));
        block_on(log.append(
            &run,
            RunEvent::RunFinished { status: "shipped".into(), shipped: vec![SHIPPED.into()] },
        ))
        .expect("append");
        block_on(seal(&dir, &run, &signer)).expect("seal the tip");
        let text = text_of(&dir, &run);
        let seals = seals_of(&dir, &run);
        assert_eq!(run_log::verify(&text).expect("the chain still holds"), 4);

        let shorter = damaged(&text, |lines| {
            lines.truncate(3);
        });
        let shorter_seals = seals.lines().take(1).collect::<Vec<_>>().join("\n");
        let broken = block_on(verify_sealed(&shorter, &shorter_seals, &signer)).expect_err("cut");
        assert_eq!(broken, SealBreak::Incomplete { line: 4 }, "{broken:?}");
        assert_eq!(
            broken.to_string(),
            "no `run.finished` after the last seal — the run is unfinished or the log was truncated"
        );
    }

    /// A signature is hex, and only one spelling of hex: a line that is not — a non-ASCII pair, or
    /// an uppercase one — is reported, not sliced in half or accepted.
    #[test]
    fn a_signature_that_is_not_hex_is_reported_rather_than_read() {
        let (_dir, _run, text, seals, signer) = sealed("not-hex");
        let at = seals.find("\"signature\":\"").expect("a signature") + "\"signature\":\"".len();
        let end = at + seals[at..].find('"').expect("the closing quote");
        for signature in ["\u{20ac}\u{20ac}", &hex(&[0xab, 0xcd]).to_uppercase()] {
            let line = format!("{}{signature}\"{}", &seals[..at], &seals[end..]);
            let broken = block_on(verify_sealed(&text, &line, &signer)).expect_err(signature);
            assert!(matches!(broken, SealBreak::Seal { line: 1, .. }), "{signature}: {broken:?}");
        }
    }

    /// A run log is attached to the digest it shipped, and read back given nothing but
    /// `repository@digest` and the key.
    #[test]
    fn a_run_log_round_trips_through_the_registry_by_digest() {
        let (_dir, _run, text, seals, signer) = sealed("registry");
        let registry = FakeRegistry::new();
        let subject = Digest::parse(SHIPPED).expect("canonical");
        // The digest has to be there for the log to refer to it.
        let layout = ks_core::ports::supply_chain::OciLayoutContents {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            manifest: b"{}".to_vec(),
            blobs: Vec::new(),
        };
        block_on(registry.push_layout("registry.example/team/app", &layout))
            .expect("push the image");

        let attached =
            block_on(attach(&registry, "registry.example/team/app", &subject, &text, &seals))
                .expect("attach");
        assert_eq!(attached.annotations.get(RUN_ANNOTATION).map(String::as_str), Some(RUN));

        let image =
            ImageRef::parse(&format!("registry.example/team/app@{subject}")).expect("a ref");
        let stories =
            block_on(verify_from_registry(&registry, &image, &signer)).expect("read back");
        assert_eq!(stories.len(), 1);
        assert_eq!(stories[0].shipped, vec![SHIPPED.to_string()]);
        assert_eq!(stories[0].approvals[0].approver, "alice");
    }

    /// A digest is only ever attached to, or read back as, a log that says it shipped it — and
    /// reading back needs a digest and something attached, since a tag can move and nothing
    /// attached is not a verified run.
    #[test]
    fn a_digest_needs_a_log_that_says_it_shipped_it() {
        let (_dir, _run, text, seals, _signer) = sealed("not-shipped");
        let registry = FakeRegistry::new();
        let other = Digest::parse(&format!("sha256:{}", "ab".repeat(32))).expect("canonical");
        let broken =
            block_on(attach(&registry, "registry.example/team/app", &other, &text, &seals))
                .expect_err("not shipped");
        assert!(matches!(broken, AttachError::NotShipped { .. }), "{broken:?}");
        assert_eq!(broken.to_string(), format!("the run log does not say it shipped {other}"));

        let signer = FakeSigner::with_key("k");
        let tag = ImageRef::parse("registry.example/team/app:1.0.0").expect("a ref");
        let broken = block_on(verify_from_registry(&registry, &tag, &signer)).expect_err("a tag");
        assert!(matches!(broken, RegistryStoryError::Reference(_)), "{broken:?}");
        let empty = Digest::parse(&format!("sha256:{}", "cd".repeat(32))).expect("canonical");
        let image = ImageRef::parse(&format!("registry.example/team/app@{empty}")).expect("a ref");
        let broken = block_on(verify_from_registry(&registry, &image, &signer))
            .expect_err("nothing attached");
        assert!(matches!(broken, RegistryStoryError::NotAttached(_)), "{broken:?}");
        assert!(broken.to_string().contains("no run log attached to"), "{broken}");
    }

    /// The sidecar line is a sorted-key object, the same shape every other file this crate writes,
    /// and `run.started` may name no actor, in which case the story does not invent one.
    #[test]
    fn the_seal_line_is_sorted_and_parsers_read_it_back() {
        let (dir, run) = log("line");
        let keyless = FakeSigner::keyless("https://issuer", "workflow");
        let signed = block_on(seal(&dir, &run, &keyless)).expect("seal");
        let line = signed.to_line();
        assert!(line.starts_with("{\"head\":\""), "{line}");
        assert_eq!(Seal::parse(&line).expect("parses back"), signed);
        assert_eq!(signed.identity_text(), "workflow from https://issuer");

        // The log has to reach `run.finished`, or the last seal cannot vouch for the whole run.
        let step = vec![
            RunEvent::StepStarted { step: "build".into() },
            RunEvent::RunFinished { status: "shipped".into(), shipped: vec![] },
        ];
        let (dir, run) = run_of_events("no-actor", step);
        let signer = FakeSigner::with_key("k");
        block_on(seal(&dir, &run, &signer)).expect("seal");
        let story = block_on(verify_sealed(&text_of(&dir, &run), &seals_of(&dir, &run), &signer))
            .expect("verify");
        assert_eq!(story.proposed_by, None);
        assert!(!story.to_string().contains("proposed by"), "{}", story);
    }
}
