//! Service-free tests of the hosted run-log module — everything in memory, so
//! `cargo test --workspace` never opens a socket. The keys are real
//! `ed25519_dalek` keys built here rather than a fake signer: the seal check is
//! the one thing this module exists to get right, and a fake that always says
//! yes would test nothing.
//!
//! The run logs are built by hand through [`ks_module_runlog::canonical`] and
//! [`ks_module_runlog::entry_hash`], the same two functions `crates/cli` hashes
//! with, so every hash in these tests is a real one rather than a fixture string
//! copied out of a file.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use ks_core::ports::supply_chain::SignerIdentity;
use ks_module_runlog::chain::{Entry, GENESIS, canonical, entry_hash};
use ks_module_runlog::seal::{Seal, TrustedKeys, identity_of, seal_payload};
use ks_module_runlog::store::{Blob, Db, MemoryBlob, MemoryDb};
use ks_module_runlog::upload::{Batch, Reject, Viewer, batches};
use ks_module_runlog::view::{self, Badge, Status};
use ks_module_runlog::{MAX_BATCH_BYTES, RunIndex};
use serde_json::{Map, Value, json};

const REPO: &str = "acme/platform";
const RUN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
/// The digest the run says it shipped.
const SHIPPED: &str = "sha256:cc";
/// The seed every fixture signs with, so a forged log and a genuine one differ
/// only in what they say.
const SEED: [u8; 32] = [7u8; 32];

/// A signer over this test's key, and its public key.
fn signing() -> (SigningKey, [u8; 32]) {
    let key = SigningKey::from_bytes(&SEED);
    let public = key.verifying_key().to_bytes();
    (key, public)
}

/// A public key as the 64 hex characters an operator pastes.
fn public_hex(public: &[u8; 32]) -> String {
    public.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A keyring holding this test's key.
fn keyring() -> TrustedKeys {
    let (_, public) = signing();
    let mut keys = TrustedKeys::new();
    keys.insert(&public_hex(&public)).expect("a valid public key");
    keys
}

/// One entry as the chain holds it, with the line a runner would have written.
fn entry(prev: &str, seq: u64, fields: &[(&str, Value)]) -> (String, String) {
    entry_for(RUN, prev, seq, fields)
}

/// As [`entry`], for a run id of the caller's choosing. Needed by the tests that
/// build an attacker's log, where every entry must claim the run the attacker
/// claims or the refusal would be for the wrong reason.
fn entry_for(run: &str, prev: &str, seq: u64, fields: &[(&str, Value)]) -> (String, String) {
    let mut object: Map<String, Value> = Map::new();
    for (key, value) in fields {
        object.insert((*key).to_string(), value.clone());
    }
    // The same order `crates/cli`'s `append_sync` builds one in: the event's own
    // fields, then the five every entry carries, then the hash.
    object.insert("at".into(), json!(1_700_000_000_000 + seq));
    object.insert("prev".into(), json!(prev));
    object.insert("run".into(), json!(run));
    object.insert("seq".into(), json!(seq));
    let hash = entry_hash(&object);
    object.insert("hash".into(), json!(hash));
    (canonical(&object), hash)
}

/// A five-entry run: proposed, a step, an approval, a decision, shipped. Every
/// hash is computed, not written down.
fn run_log() -> String {
    run_log_for(RUN)
}

/// As [`run_log`], for a run id of the caller's choosing.
fn run_log_for(run: &str) -> String {
    let fields: [Vec<(&str, Value)>; 5] = [
        vec![
            ("type", json!("run.started")),
            ("actor", json!("ci")),
            ("trigger", json!("push main")),
            ("file_hash", json!("sha256:aa")),
            ("is_agent", json!(false)),
        ],
        vec![("type", json!("step.started")), ("step", json!("build"))],
        vec![
            ("type", json!("step.finished")),
            ("step", json!("build")),
            ("ok", json!(true)),
            ("outputs", json!(["digest"])),
            ("duration_ms", json!(1234)),
        ],
        vec![
            ("type", json!("approval.granted")),
            ("step", json!("deploy")),
            ("approver", json!("alice")),
            ("channel", json!("github")),
            ("artifacts", json!(["sha256:bb"])),
        ],
        vec![
            ("type", json!("run.finished")),
            ("status", json!("shipped")),
            ("shipped", json!([SHIPPED])),
        ],
    ];
    let mut prev = GENESIS.to_string();
    let mut out = Vec::new();
    for (seq, fields) in fields.iter().enumerate() {
        let (line, hash) = entry_for(run, &prev, seq as u64, fields);
        prev = hash;
        out.push(line);
    }
    out.join("\n")
}

/// A seal over the tip of `text`, signed by this test's key.
fn seal_over(text: &str) -> Seal {
    let (key, public) = signing();
    let lines: Vec<&str> = text.lines().collect();
    let tip = tip_of(lines.last().expect("a log with lines"));
    let payload = seal_payload(RUN, tip.1, &tip.0);
    Seal {
        head: tip.0.clone(),
        run: RUN.to_string(),
        seq: tip.1,
        identity: SignerIdentity::Key { key_id: identity_of(&public) },
        signature: key.sign(&payload).to_bytes().to_vec(),
    }
}

/// The hash and seq of a line, read straight off it.
fn tip_of(line: &str) -> (String, u64) {
    let value: Value = serde_json::from_str(line).expect("one object");
    (value["hash"].as_str().expect("a hash").to_string(), value["seq"].as_u64().expect("a seq"))
}

/// A viewer over fresh in-memory stores and this test's keyring.
fn viewer() -> (Viewer, Arc<MemoryBlob>, Arc<MemoryDb>) {
    let blob = Arc::new(MemoryBlob::new());
    let db = Arc::new(MemoryDb::new());
    (Viewer::new(blob.clone(), db.clone(), Arc::new(keyring())), blob, db)
}

/// A batch of `lines` from `text`, without a seal.
fn batch(index: u64, lines: Vec<String>) -> Batch {
    Batch { repo: REPO.to_string(), run: RUN.to_string(), index, lines, seal: None }
}

/// Uploads `text` whole, in batches of at most `max_bytes`, sealing the last.
fn upload(viewer: &Viewer, text: &str, max_bytes: usize) -> Vec<RunIndex> {
    let groups = batches(text, max_bytes).expect("splittable");
    let mut indexes = Vec::new();
    for (index, lines) in groups.iter().enumerate() {
        let seal = if index + 1 == groups.len() { Some(seal_over(text)) } else { None };
        indexes.push(
            viewer
                .accept(&Batch {
                    repo: REPO.to_string(),
                    run: RUN.to_string(),
                    index: index as u64,
                    lines: lines.clone(),
                    seal,
                })
                .unwrap_or_else(|reject| panic!("batch {index} was refused: {reject}")),
        );
    }
    indexes
}

/// The acceptance criterion: a signed run log goes up in batches and comes back
/// browsable, with its bytes exactly as the runner wrote them.
#[test]
fn a_signed_run_log_round_trips_and_browses() {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    // A cap that forces the log over several requests, so the batch boundary is
    // actually crossed on the way up.
    let index = upload(&viewer, &text, 700).last().expect("a batch").clone();
    assert!(index.verified && index.sealed, "{index:?}");
    assert_eq!((index.entries, index.batches), (5, 3));

    // One run in the repo, and the runs table has a row for it.
    let runs = viewer.runs(REPO).expect("the repo's runs");
    assert_eq!(runs.len(), 1);
    let summary = view::summarize(&runs[0]);
    assert_eq!(summary.status, Status::Verified);
    assert_eq!(view::badge(summary.status), Badge::Verified);
    assert!(view::index_page(REPO, &[summary]).contains(RUN));

    // The story says what the log says: who proposed it, who approved, what it
    // shipped — and nothing it does not.
    let story = view::story(&text, &index).expect("the chain holds");
    assert_eq!(story.proposed_by.as_deref(), Some("ci"));
    assert_eq!(story.approved_by, vec!["alice".to_string()]);
    assert_eq!(story.shipped, vec![SHIPPED.to_string()]);
    assert!(story.decisions.is_empty(), "the fixture decides nothing: {:?}", story.decisions);
    assert_eq!(story.head, index.head);
    assert_eq!(story.entries, 5);

    // The bytes come back as they went up, which is the whole point of storing the
    // line rather than a re-serialization of it.
    let (stored, got) = viewer.run(REPO, RUN).expect("a stored run").expect("the run is there");
    assert_eq!(stored, index);
    assert_eq!(got, text);
}

/// The degenerate case: a short log fits in one batch, and one batch is still the
/// whole round trip.
#[test]
fn a_single_batch_upload_is_the_same_round_trip() {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    let index = viewer
        .accept(&Batch {
            seal: Some(seal_over(&text)),
            ..batch(0, text.lines().map(String::from).collect())
        })
        .expect("one batch");
    assert_eq!((index.entries, index.batches), (5, 1));
    assert!(index.verified);
    let (_stored, got) = viewer.run(REPO, RUN).expect("read back").expect("there is a run");
    assert_eq!(got, text);
}

/// The chain catches an edit. A byte flipped inside a line leaves the `hash`
/// stale, and the line is refused on its own terms rather than as a chain
/// complaint one batch later.
#[test]
fn a_tampered_line_is_refused_on_its_own_terms() {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    // One byte of one line, changed. The `hash` it carries was taken over the
    // line as it was, so it no longer fits — and the line is refused on that
    // alone, rather than as a chain complaint one batch later.
    lines[3] = lines[3].replace("alice", "mallory");
    match viewer.accept(&batch(0, lines)).expect_err("an edited line") {
        Reject::BadEntry { line, reason } => {
            assert_eq!(line, 4, "the refusal names the line that was edited");
            assert!(reason.contains("do not hash"), "{reason}");
        }
        other => panic!("an edited line is a bad entry, got {other:?}"),
    }
}

/// A line taken out of the middle leaves the entry above it pointing at a hash
/// that is no longer there — which is the check a batch boundary makes possible
/// and a single line cannot.
#[test]
fn a_deleted_line_breaks_the_chain() {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    let lines: Vec<String> = text.lines().map(String::from).collect();
    viewer.accept(&batch(0, lines[..3].to_vec())).expect("batch 0");
    // Batch 1 skips the entry that should have been at its head and starts at the
    // one after it, so the line that survives names an entry that was deleted.
    match viewer.accept(&batch(1, lines[4..].to_vec())).expect_err("a hole in the chain") {
        Reject::BrokenChain { found, expected } => {
            assert_eq!(found, tip_of(&lines[3]).0, "the line names the entry that was deleted");
            assert_eq!(expected, tip_of(&lines[2]).0, "the head is the entry it should follow");
        }
        other => panic!("a deletion breaks the chain, got {other:?}"),
    }
}

/// The chain-continuity check across batches: a first line whose `prev` does not
/// meet the stored head is refused, even though every line is internally perfect.
#[test]
fn a_forged_prev_at_a_batch_boundary_breaks_the_chain() {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    let lines: Vec<String> = text.lines().map(String::from).collect();
    viewer.accept(&batch(0, lines[..3].to_vec())).expect("batch 0");
    // Rebuilt from the wrong predecessor: every hash in it is real, and the first
    // one links to something this run never had.
    let (forged, _) = entry(&"0".repeat(64), 3, &[("type", json!("step.finished"))]);
    match viewer.accept(&batch(1, vec![forged])).expect_err("a forged prev") {
        Reject::BrokenChain { found, expected } => {
            assert_eq!(found, "0".repeat(64));
            assert_eq!(expected, tip_of(&lines[2]).0);
        }
        other => panic!("a forged prev breaks the chain, got {other:?}"),
    }
}

/// **The case a hash chain alone cannot catch.** An attacker who rewrites the log
/// *and recomputes every hash* leaves a chain that verifies perfectly — that is
/// what `crates/cli`'s seal module says a hash chain cannot see, alongside
/// end-truncation: a writer that recomputes the chain as it goes leaves
/// self-consistent entries that are simply not the run that happened. The only
/// thing that says otherwise is a signature made from outside the writer, so the
/// runner's seal over the genuine tip is what refuses this.
#[test]
fn a_wholly_recomputed_chain_does_not_match_the_runners_seal() {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    let genuine = seal_over(&text);

    // The forged run: the same five entries, saying the run failed, was proposed by
    // somebody else, and shipped nothing. Every hash below is computed, so the
    // chain is real and holds on its own terms — which is the point.
    let fields: [Vec<(&str, Value)>; 5] = [
        vec![
            ("type", json!("run.started")),
            ("actor", json!("mallory")),
            ("trigger", json!("push main")),
            ("file_hash", json!("sha256:aa")),
            ("is_agent", json!(false)),
        ],
        vec![("type", json!("step.started")), ("step", "build\u{0}<script>".into())],
        vec![
            ("type", json!("step.finished")),
            ("step", json!("build")),
            ("ok", json!(true)),
            ("outputs", json!(["digest"])),
            ("duration_ms", json!(1234)),
        ],
        vec![
            ("type", json!("approval.granted")),
            ("step", json!("deploy")),
            ("approver", json!("mallory")),
            ("channel", json!("github")),
            ("artifacts", json!(["sha256:bb"])),
        ],
        vec![("type", json!("run.finished")), ("status", json!("failed")), ("shipped", json!([]))],
    ];
    let mut prev = GENESIS.to_string();
    let mut lines = Vec::new();
    for (seq, fields) in fields.iter().enumerate() {
        let (line, hash) = entry(&prev, seq as u64, fields);
        prev = hash;
        lines.push(line);
    }
    for line in &lines {
        let value: Value = serde_json::from_str(line).expect("one object");
        let object = value.as_object().expect("an object");
        assert_eq!(value["hash"].as_str(), Some(entry_hash(object).as_str()));
    }

    // The seal is the runner's own — same run, same seq, same signature bytes —
    // with only its head moved onto the forged tip. It matches the log in every
    // way a chain check can see, and it is still not the runner's seal: the
    // signature was made over the other head.
    let forged_seal = Seal { head: prev, ..genuine.clone() };
    match viewer
        .accept(&Batch { seal: Some(forged_seal), ..batch(0, lines) })
        .expect_err("a rewritten run")
    {
        Reject::SealRefused(reason) => assert!(reason.contains("does not verify"), "{reason}"),
        other => panic!("only the signature catches this, got {other:?}"),
    }
    // The refusal above was the forged run and not the fixture: the same viewer,
    // which stored nothing, still takes the genuine log and its own seal.
    let intact = upload(&viewer, &run_log(), MAX_BATCH_BYTES).last().expect("an index").clone();
    assert!(intact.verified);
}

/// **`seq` is the position in the run, not in the batch.** A batch whose lines
/// chain correctly by `prev` can still skip a `seq` or repeat one, and it has to
/// be refused anyway: the chain cannot see it, because every hash is re-derived
/// over whatever `seq` the entry carries. The batches below are built honestly —
/// each hash computed with [`entry_hash`], each `prev` naming the entry above —
/// so a good chain with a wrong position is the only thing wrong with them.
#[test]
fn a_batch_whose_seq_does_not_continue_the_run_is_refused() {
    let (viewer, _blob, _db) = viewer();
    let step = [("type", json!("step.started")), ("step", json!("build"))];
    let finished = [("type", json!("run.finished")), ("status", json!("shipped"))];

    // Three entries at their real positions, then a fourth that calls itself the
    // fifth. Every `prev` lines up; only `seq` is wrong.
    let mut prev = GENESIS.to_string();
    let mut lines = Vec::new();
    for seq in [0u64, 1, 2, 4] {
        let (line, hash) = entry(&prev, seq, &step);
        assert!(
            Entry::parse(&line).expect("the runner's own line").continues_from(&prev),
            "seq {seq} does not continue the chain"
        );
        prev = hash;
        lines.push(line);
    }
    match viewer.accept(&batch(0, lines)).expect_err("a seq that skips the run") {
        Reject::BrokenChain { found, expected } => {
            assert_eq!(found, "seq 4");
            assert_eq!(expected, "seq 3");
        }
        other => panic!("a skipped seq breaks the chain, got {other:?}"),
    }

    // And the repeat, on a run of its own: the first entry arrives calling itself
    // the second, chained off GENESIS as correctly as anything.
    let (repeat, _) = entry(GENESIS, 1, &finished);
    assert!(Entry::parse(&repeat).expect("the runner's own line").continues_from(GENESIS));
    match viewer.accept(&batch(0, vec![repeat])).expect_err("a seq that repeats") {
        Reject::BrokenChain { found, expected } => {
            assert_eq!((found, expected), ("seq 1".to_string(), "seq 0".to_string()));
        }
        other => panic!("a repeated seq breaks the chain, got {other:?}"),
    }

    // Neither attempt stored anything, so the sequence the run expects has not
    // moved and a genuine batch still lands.
    let index = upload(&viewer, &run_log(), MAX_BATCH_BYTES).last().expect("an index").clone();
    assert!(index.verified, "{index:?}");
}

/// A batch whose index has already been taken is a replay, and is refused as one
/// rather than concatenated a second time.
#[test]
fn a_replayed_batch_is_refused() {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    let lines: Vec<String> = text.lines().map(String::from).collect();
    viewer.accept(&batch(0, lines.clone())).expect("batch 0");
    match viewer.accept(&batch(0, lines)).expect_err("a replay") {
        Reject::OutOfOrder { found, expected } => {
            assert_eq!((found, expected), (0, 1));
        }
        other => panic!("a replay is out of order, got {other:?}"),
    }
}

/// The cap is this module's own refusal, not a platform error the caller has to
/// learn the shape of.
#[test]
fn a_batch_over_the_cap_is_refused() {
    let (viewer, _blob, _db) = viewer();
    let filler = "x".repeat(MAX_BATCH_BYTES);
    let batch = Batch { lines: vec![filler], ..batch(0, Vec::new()) };
    match viewer.accept(&batch).expect_err("over the cap") {
        Reject::TooLarge { found, limit } => {
            assert_eq!(limit, MAX_BATCH_BYTES);
            assert!(found > MAX_BATCH_BYTES, "{found}");
        }
        other => panic!("an oversized batch is refused on size, got {other:?}"),
    }
}

/// A seal that covers the wrong entry is a mismatch, not a signature failure —
/// it never got as far as a key.
#[test]
fn a_seal_over_the_wrong_head_is_a_mismatch() {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    let mut seal = seal_over(&text);
    seal.head = "ab".repeat(32);
    match viewer
        .accept(&Batch { seal: Some(seal), ..batch(0, text.lines().map(String::from).collect()) })
        .expect_err("a seal over another head")
    {
        Reject::SealMismatch { reason } => assert!(reason.contains("head"), "{reason}"),
        other => panic!("a mismatched head is a mismatch, got {other:?}"),
    }
}

/// The completeness rule `crates/cli`'s `check_seals` enforces: a seal over a tip
/// that is not `run.finished` says the run went on past it, so what followed is
/// exactly what a tamperer would remove.
#[test]
fn a_seal_over_an_unfinished_run_is_a_mismatch() {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    // The log as it stands one entry short: everything up to the approval.
    let short: String = text.lines().take(4).collect::<Vec<_>>().join("\n");
    let seal = seal_over(&short);
    assert_eq!(seal.seq, 3);
    match viewer
        .accept(&Batch { seal: Some(seal), ..batch(0, short.lines().map(String::from).collect()) })
        .expect_err("a seal over a step")
    {
        Reject::SealMismatch { reason } => {
            assert!(reason.contains("run.finished"), "{reason}");
        }
        other => panic!("a seal over a step is a mismatch, got {other:?}"),
    }
}

/// A sealed run is closed: nothing may be appended to it after the fact.
#[test]
fn nothing_is_accepted_after_the_seal() {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    viewer
        .accept(&Batch {
            seal: Some(seal_over(&text)),
            ..batch(0, text.lines().map(String::from).collect())
        })
        .expect("the sealed run");
    // A sixth entry, chained correctly onto the sealed tip — so the chain holds
    // and only the seal says no.
    let tip = tip_of(text.lines().last().expect("a tip"));
    let (extra, _) = entry(&tip.0, 5, &[("type", json!("step.started")), ("step", json!("after"))]);
    match viewer.accept(&batch(1, vec![extra])).expect_err("after the seal") {
        Reject::AlreadySealed { run } => assert_eq!(run, RUN),
        other => panic!("a sealed run is closed, got {other:?}"),
    }
}

/// A keyring holds named keys. Three refusals, in the order the keyring makes
/// them: a key id it does not hold, a keyless identity, and — the one the
/// previous version of this test claimed to cover but did not — an id that *is*
/// held and is not what that key derives.
///
/// That last case is the substitution: the lookup succeeds, so nothing about the
/// keyring would catch it, and only re-deriving the id from the key it names
/// does. So the fixture puts the real public key into the keyring under a
/// *different* id and presents a seal claiming that id with the real key's
/// signature. The refusal has to be the substitution one, not `UntrustedKey` —
/// a test that reached `no trusted key` never touched the check it was written
/// for.
#[test]
fn an_untrusted_keyless_or_substituted_key_is_refused() {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    let lines: Vec<String> = text.lines().map(String::from).collect();

    let mut stranger = seal_over(&text);
    stranger.identity = SignerIdentity::Key { key_id: "ed25519:0123456789abcdef".to_string() };
    match viewer
        .accept(&Batch { seal: Some(stranger), ..batch(0, lines.clone()) })
        .expect_err("a key nobody trusts")
    {
        Reject::SealRefused(reason) => assert!(reason.contains("no trusted key"), "{reason}"),
        other => panic!("an untrusted key is refused, got {other:?}"),
    }

    // A keyless identity: a hosted keyring knows keys, not issuers.
    let mut keyless = seal_over(&text);
    keyless.identity = SignerIdentity::Keyless {
        issuer: "https://issuer.example".to_string(),
        subject: "workflow".to_string(),
    };
    match viewer
        .accept(&Batch { seal: Some(keyless), ..batch(0, lines.clone()) })
        .expect_err("a keyless identity")
    {
        Reject::SealRefused(reason) => assert!(reason.contains("named keys"), "{reason}"),
        other => panic!("a keyless identity is refused, got {other:?}"),
    }

    // The substitution. The real key goes into the keyring under a wrong id, and
    // the seal claims that wrong id while carrying the real key's signature — so
    // the lookup hits and the only thing left to catch it is the re-derivation.
    let (_, public) = signing();
    let real = identity_of(&public);
    let wrong = format!("{real}-x");
    let mut substituted = seal_over(&text);
    substituted.identity = SignerIdentity::Key { key_id: wrong.clone() };
    // The signature is untouched: it is genuinely this key's, over this payload.
    assert_ne!(substituted.signature, Vec::<u8>::new());
    let mut keys = TrustedKeys::new();
    keys.insert_under(&wrong, &public_hex(&public)).expect("a valid key");
    assert_eq!(keys.ids().collect::<Vec<_>>(), vec![&wrong]);
    let viewer =
        Viewer::new(Arc::new(MemoryBlob::new()), Arc::new(MemoryDb::new()), Arc::new(keys));
    match viewer
        .accept(&Batch { seal: Some(substituted), ..batch(0, lines) })
        .expect_err("a substituted key id")
    {
        Reject::SealRefused(reason) => {
            assert!(reason.contains("is not what that key derives"), "{reason}");
            assert!(reason.contains(&real), "the refusal names what the key really is: {reason}");
            assert!(
                !reason.contains("no trusted key"),
                "the lookup was supposed to succeed: {reason}"
            );
        }
        other => panic!("a substituted key id is refused as a substitution, got {other:?}"),
    }
}

// This test keeps a known gap visible. `seal_payload` signs `run`, `seq` and
// `head` — not `repo` — so nothing in a seal ties it to the repository it was
// uploaded under. Closing that needs a change to the runner's wire format, which
// is a versioned change to what `crates/cli` signs and this crate verifies. **This
// test must change when that happens**: when `repo` is in the signed payload, the
// upload below should be refused, and the assertion that it is accepted becomes
// the one that fails.
#[test]
fn a_valid_seal_from_another_repo_is_not_yet_bound_to_its_repo() {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    // A genuine, fully verified run under one repository.
    let home = upload(&viewer, &text, MAX_BATCH_BYTES).last().expect("an index").clone();
    assert!(home.verified, "the fixture is a genuine sealed run");

    // The same bytes, the same genuine seal, uploaded under a repository they have
    // nothing to do with. Every check passes: the chain walks, the seal verifies
    // under the trusted key, and nothing compares the seal to the repo it arrived
    // under.
    let elsewhere = Batch {
        repo: "attacker/elsewhere".to_string(),
        run: RUN.to_string(),
        index: 0,
        lines: text.lines().map(String::from).collect(),
        seal: Some(seal_over(&text)),
    };
    let index = viewer.accept(&elsewhere).expect("accepted — this is the gap being pinned");
    assert!(index.verified, "and it renders with a verified badge in the new repo");

    // It is listed there, as a verified run of that repository.
    let listed = viewer.runs("attacker/elsewhere").expect("listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(view::badge(view::summarize(&listed[0]).status), Badge::Verified);

    // The genuine run is untouched: a replay is a second copy, not a move.
    let (kept, body) = viewer.run(REPO, RUN).expect("read back").expect("the run is there");
    assert_eq!(kept, home);
    assert_eq!(body, text);
}

/// Splitting respects the cap and never cuts a line: every line comes back whole,
/// and no batch is over the cap.
#[test]
fn batches_split_at_the_cap_and_never_split_a_line() {
    let text = run_log();
    let long = text.repeat(60);
    for max in [700usize, 4096, 32_768] {
        let groups = batches(&long, max).expect("splittable");
        assert!(groups.len() > 1, "at max {max} the log should not fit in one batch");
        for group in &groups {
            let size: usize = group.iter().map(|line| line.len() + 1).sum();
            assert!(size <= max, "a batch of {size} over the cap of {max}");
            for line in group {
                assert!(long.contains(line.as_str()), "a line was cut: {line}");
            }
        }
        // Reassembled, it is the same log.
        let rejoined: Vec<&str> =
            groups.iter().flat_map(|group| group.iter().map(String::as_str)).collect();
        assert_eq!(rejoined, long.lines().collect::<Vec<_>>());
    }
    // A line longer than the cap has nowhere to go, and is refused rather than cut.
    let huge = "x".repeat(200);
    match batches(&format!("short\n{huge}"), 64).expect_err("an oversized line") {
        ks_module_runlog::BatchError::LineTooLong { bytes } => assert_eq!(bytes, 200),
    }
}

/// A `ship.ks` file is not trusted input, and a step name out of one is the
/// least-trusted string on the page. It cannot break out of the markup.
#[test]
fn a_hostile_step_name_cannot_break_out_of_the_page() {
    let hostile = "<script>alert('x')</script>\"'";
    let mut story = view::story(&run_log(), &fixture_index()).expect("the fixture");
    story.decisions.push(view::Decision {
        step: hostile.to_string(),
        at: 0,
        verdict: hostile.to_string(),
        by: hostile.to_string(),
        score: None,
    });
    story.proposed_by = Some(hostile.to_string());
    story.approved_by = vec![hostile.to_string()];

    let page = view::run_page(&story);
    assert!(!page.contains("<script>"), "a script tag reached the page");
    assert!(page.contains("&lt;script&gt;"));
    assert!(page.contains("&#39;"), "a single quote was not escaped");

    let summary = view::summarize(&fixture_index());
    let mut hostile_summary = summary.clone();
    hostile_summary.run = hostile.to_string();
    let page = view::index_page(hostile, &[hostile_summary]);
    assert!(!page.contains("<script>"), "a script tag reached the index page");
}

/// An index to hang a story off, for the page tests: the same shape a sealed run
/// leaves behind.
fn fixture_index() -> RunIndex {
    let (viewer, _blob, _db) = viewer();
    let text = run_log();
    upload(&viewer, &text, MAX_BATCH_BYTES).last().expect("an index").clone()
}

/// The two byte-for-byte promises the issue rests on: the signed payload and the
/// seal's sidecar line. A hosted module that changed either would verify nothing
/// the runner signed.
#[test]
fn the_seal_wire_format_is_the_runners() {
    // The exact bytes `crates/cli`'s `seal_payload` signs.
    assert_eq!(
        seal_payload("01ABC", 3, "ab…"),
        "keepshipping run-log seal v1\nrun 01ABC\nseq 3\nhead ab…\n".as_bytes().to_vec()
    );

    // And the sidecar line: sorted keys, in this order, signature as lowercase hex.
    let (key, public) = signing();
    let seal = Seal {
        head: "ab".repeat(32),
        run: "01ABC".to_string(),
        seq: 3,
        identity: SignerIdentity::Key { key_id: identity_of(&public) },
        signature: key.sign(&seal_payload("01ABC", 3, &"ab".repeat(32))).to_bytes().to_vec(),
    };
    let line = seal.to_line();
    assert!(
        line.starts_with(&format!(
            "{{\"head\":\"{}\",\"identity\":{{\"key\":\"ed25519:",
            "ab".repeat(32)
        )),
        "{line}"
    );
    assert!(
        line.ends_with(&format!(
            "\"run\":\"01ABC\",\"seq\":3,\"signature\":\"{}\"}}",
            hex(&seal.signature)
        )),
        "{line}"
    );
    // And it parses back to the same seal, so a reader and the runner agree.
    assert_eq!(Seal::parse(&line).expect("the line parses back"), seal);

    // A keyless identity names an issuer and a subject instead.
    let keyless = Seal {
        identity: SignerIdentity::Keyless { issuer: "i".into(), subject: "s".into() },
        ..seal.clone()
    };
    assert!(
        keyless.to_line().contains("\"identity\":{\"issuer\":\"i\",\"subject\":\"s\"}"),
        "{}",
        keyless.to_line()
    );
    // A signature that is not lowercase hex is reported, not read in two spellings.
    let upper = seal.to_line().replace(&hex(&seal.signature), &hex(&seal.signature).to_uppercase());
    assert!(Seal::parse(&upper).is_err(), "uppercase hex must not parse");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The upload envelope is not the sidecar line. It carries the seal as a field,
/// and the field reuses the sidecar's own key names so the two cannot drift — but
/// a request body is not a `.seals.jsonl` file, and reading one as the other is the
/// mistake this test exists to keep from being made silently.
#[test]
fn the_upload_envelope_is_not_the_sidecar_line() {
    let text = run_log();
    let seal = seal_over(&text);
    let body =
        Batch { seal: Some(seal.clone()), ..batch(0, text.lines().map(String::from).collect()) };
    let json = serde_json::to_string(&body).expect("the envelope is JSON");
    let back: Batch = serde_json::from_str(&json).expect("and reads back");
    assert_eq!(back.seal, Some(seal.clone()), "the seal survives the envelope");
    // The envelope's seal is an object with the sidecar's keys, not a sidecar line.
    let value: Value = serde_json::from_str(&json).expect("JSON");
    assert!(value["seal"]["head"].is_string(), "{value}");
    assert!(value["seal"]["identity"]["key"].is_string(), "{value}");
    assert_eq!(value["seal"]["seq"], json!(4));
}

/// The stores refuse what they are supposed to: an unusable key, and an object
/// over the cap. Both are the store's own answer, not a platform error.
#[test]
fn the_stores_refuse_an_unusable_key_and_an_oversized_object() {
    let blob = MemoryBlob::new();
    for key in ["", "a//b", "/leading", "control\u{7}char"] {
        assert!(
            matches!(blob.put(key, b"x"), Err(ks_module_runlog::StoreError::BadKey(_))),
            "{key}"
        );
    }
    let over = vec![0u8; ks_module_runlog::MAX_BLOB_BYTES + 1];
    assert!(matches!(blob.put("a/b", &over), Err(ks_module_runlog::StoreError::TooLarge { .. })));
    assert_eq!(blob.get("a/b").expect("read back"), None);

    let db = MemoryDb::new();
    let index = fixture_index();
    db.put_run(&index).expect("stored");
    assert_eq!(db.get_run(REPO, RUN).expect("read back"), Some(index.clone()));
    assert_eq!(db.runs_in_repo(REPO).expect("listed"), vec![index.clone()]);
    assert_eq!(db.runs_in_repo("other/repo").expect("empty"), Vec::new());
    // A clone is the same store, not a second one.
    let copy = db.clone();
    assert_eq!(copy.runs_in_repo(REPO).expect("listed").len(), 1);
    assert_eq!(copy.get_run(REPO, RUN).expect("read back"), Some(index));
}

/// The strongest compatibility check there is: the log `crates/cli` actually
/// writes, byte for byte, is the one this crate hashes and reads. If the
/// canonical form here ever drifted from `run_log.rs`'s, this line would stop
/// parsing — which is the point of reading a committed fixture rather than
/// re-deriving the expectation.
#[test]
fn the_committed_runner_log_parses_and_chains_here() {
    let golden = include_str!("../../cli/tests/fixtures/run-log/golden.jsonl");
    let entries: Vec<ks_module_runlog::Entry> = golden
        .lines()
        .map(|line| ks_module_runlog::Entry::parse(line).expect("the runner's line"))
        .collect();
    assert_eq!(entries.len(), 9);
    let mut prev = GENESIS.to_string();
    for entry in &entries {
        assert!(entry.continues_from(&prev), "seq {} does not continue the chain", entry.seq);
        prev = entry.hash.clone();
    }
    assert_eq!(entries[0].kind, "run.started");
    assert_eq!(entries[0].run, RUN);

    // And a viewer stores that exact log without touching a byte of it.
    let (viewer, _blob, _db) = viewer();
    let batch = Batch { seal: None, ..batch(0, golden.lines().map(String::from).collect()) };
    let index = viewer.accept(&batch).expect("the runner's own log");
    assert_eq!((index.entries, index.sealed), (9, false));
    let (_stored, got) = viewer.run(REPO, RUN).expect("read back").expect("there is a run");
    assert_eq!(got, golden.trim_end_matches('\n'));
}

/// **The key collision.** A run lives under the blob key `acme/platform/RUN`,
/// and so does the pair `acme` + `platform/RUN` — the two compose the same
/// string, and before the names were checked the second was a different run as
/// far as the index knew and the same object as far as the store knew. So an
/// unsigned writer, holding no seal and no trusted key, could name the object
/// belonging to a run somebody else sealed and put its own log there: the
/// entries all say the attacker's run, so `WrongRun` never fires, and the genuine
/// index is untouched and still says `verified`. Nothing but the name check
/// stands between that and a reader shown a rewritten run under a verified badge.
#[test]
fn a_key_collision_cannot_overwrite_a_sealed_run() {
    let (viewer, blob, db) = viewer();
    let genuine = run_log();
    let genuine_bytes = genuine.clone().into_bytes();
    let sealed = upload(&viewer, &genuine, MAX_BATCH_BYTES).last().expect("an index").clone();
    assert!(sealed.verified, "the fixture is a sealed, verified run");

    // The attack, built honestly: a real five-entry chain whose entries all
    // claim the run the batch claims, so the refusal cannot be `WrongRun`.
    let forged_run = "platform/RUN";
    let forged = run_log_for(forged_run);
    let collision = Batch {
        repo: "acme".to_string(),
        run: forged_run.to_string(),
        index: 0,
        lines: forged.lines().map(String::from).collect(),
        seal: None,
    };
    match viewer.accept(&collision).expect_err("a name that means two runs") {
        Reject::BadName(error) => assert!(error.to_string().contains("/"), "{error}"),
        other => panic!("a colliding name is refused on the name, got {other:?}"),
    }

    // And the genuine run is byte for byte what it was — the same index and the
    // same body, with nothing of the forged log anywhere in the store.
    let (stored_index, stored_text) =
        viewer.run(REPO, RUN).expect("read back").expect("the run is there");
    assert_eq!(stored_index, sealed, "the genuine index is unchanged");
    assert_eq!(stored_text, genuine, "the genuine log is unchanged");
    assert_eq!(
        blob.get(&ks_module_runlog::blob_key(REPO, RUN)).expect("read back"),
        Some(genuine_bytes),
        "the stored object is unchanged"
    );
    assert_eq!(db.runs_in_repo("acme").expect("listed"), Vec::new(), "no run under `acme`");
    assert!(
        !stored_text.contains("mallory") && !genuine.contains("mallory"),
        "the forged log is nowhere in the genuine one"
    );
}

/// **The read path is name-checked too.** `accept` refuses a name that could
/// mean two objects, but `Viewer::run` used to compose its blob key with a bare
/// `format!` and read whatever came back — so `run("acme", "platform/RUN")`
/// named the object belonging to repo `acme/platform`, run `RUN`, and handed the
/// reader that run's whole log under a name they never asked for. `runs` had the
/// same gap on the repository half.
#[test]
fn a_name_that_is_not_a_name_is_refused_on_the_read_path_too() {
    let (viewer, _blob, db) = viewer();
    let text = run_log();
    let genuine = upload(&viewer, &text, MAX_BATCH_BYTES).last().expect("an index").clone();

    // The collision, spelled the way a reader could spell it by accident. Before
    // the check this returned `Ok` with the genuine run's index and body.
    match viewer.run("acme", "platform/RUN").expect_err("a run that is not a name") {
        ks_module_runlog::StoreError::BadKey(reason) => {
            assert!(reason.contains('/'), "{reason}");
        }
        other => panic!("a colliding name is refused on the read path, got {other:?}"),
    }
    // And every other shape `accept` refuses, refused on the way in rather than
    // silently answering about nothing.
    for (repo, run) in [
        ("acme/platform", ""),
        ("acme/platform", ".."),
        ("", RUN),
        ("acme/", RUN),
        ("acme//platform", RUN),
        ("acme/../x", RUN),
    ] {
        let refused = viewer.run(repo, run).expect_err("a name that is not a name");
        assert!(
            matches!(refused, ks_module_runlog::StoreError::BadKey(_)),
            "run({repo:?}, {run:?}) gave {refused:?}"
        );
    }
    // `runs` checks the repository half for the same reason.
    for repo in ["", "/leading", "acme/", "acme//platform", "acme/./x"] {
        let refused = viewer.runs(repo).expect_err("a repository that is not a name");
        assert!(
            matches!(refused, ks_module_runlog::StoreError::BadKey(_)),
            "runs({repo:?}) gave {refused:?}"
        );
    }

    // None of it touched the store, and the genuine run still reads.
    let (index, got) = viewer.run(REPO, RUN).expect("read back").expect("the run is there");
    assert_eq!(index, genuine);
    assert_eq!(got, text);
    assert_eq!(db.runs_in_repo(REPO).expect("listed").len(), 1);
}

/// The names themselves. A repository is `owner/name`, so a `/` is part of its
/// shape; a run is one id, so a `/` in it is not — and neither is a `.`, a space,
/// a control character, or an empty piece of either name. Each is refused before
/// anything is read, and refused rather than rewritten, because a rewrite would
/// map two spellings onto one key and hide the caller that got it wrong.
#[test]
fn a_repo_or_run_that_is_not_a_name_is_refused() {
    let (viewer, blob, db) = viewer();

    // Runs that could name more than one object, or escape the directory the
    // key sits in.
    for run in ["platform/RUN", "../RUN", "", "RUN\u{7}", "RUN ", "RUN?", ".."] {
        let refused = viewer
            .accept(&Batch { run: run.to_string(), ..batch(0, Vec::new()) })
            .expect_err("a run that is not a name");
        assert!(matches!(refused, Reject::BadName(_)), "{run:?} gave {refused:?}");
    }
    // Repositories: `owner/name` is fine, an empty or dotted segment is not.
    for repo in ["", "/leading", "acme/", "acme//platform", "acme/./platform", "acme/../x"] {
        let refused = viewer
            .accept(&Batch { repo: repo.to_string(), ..batch(0, Vec::new()) })
            .expect_err("a repository that is not a name");
        assert!(matches!(refused, Reject::BadName(_)), "{repo:?} gave {refused:?}");
    }
    // Nothing above reached a store, so nothing was written.
    assert_eq!(blob.get("").expect("read back"), None);
    assert!(db.runs_in_repo(REPO).expect("listed").is_empty(), "no run was created");

    // And a genuine two-part repository is untouched by any of it.
    let index = upload(&viewer, &run_log(), MAX_BATCH_BYTES).last().expect("an index").clone();
    assert!(index.verified);
}

/// `accept` is a read-check-write across two stores, so two threads sending the
/// same batch index both have to be able to lose. `Reject::OutOfOrder` is a
/// comparison against what the other thread has not written yet — it is not a
/// mutual-exclusion primitive — so without a lock around the whole of the read,
/// the decision and both writes, both threads read `batches == 0` and both
/// succeed. The run they leave behind would have the batch counted once and the
/// lines stored twice, which is exactly what a reader would see as a chain that
/// does not hold.
#[test]
fn two_concurrent_accepts_of_one_batch_index_do_not_both_land() {
    for _ in 0..16 {
        let (viewer, blob, db) = viewer();
        let shared = Arc::new(viewer);
        let text = run_log();
        let lines: Vec<String> = text.lines().map(String::from).collect();
        // Enough threads that the race is not a lucky schedule if the lock is
        // not there.
        let sends: Vec<_> = (0..8)
            .map(|_| {
                let viewer = Arc::clone(&shared);
                let batch = Batch {
                    repo: REPO.to_string(),
                    run: RUN.to_string(),
                    index: 0,
                    lines: lines.clone(),
                    seal: None,
                };
                std::thread::spawn(move || viewer.accept(&batch))
            })
            .collect();
        let outcomes: Vec<Result<RunIndex, Reject>> =
            sends.into_iter().map(|send| send.join().expect("a thread")).collect();

        let accepted = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        assert_eq!(accepted, 1, "exactly one sender may write the run, got {outcomes:?}");
        for refused in outcomes.iter().filter_map(|outcome| outcome.as_ref().err()) {
            assert!(
                matches!(refused, Reject::OutOfOrder { found: 0, expected: 1 }),
                "the losers are refused as replays, got {refused:?}"
            );
        }

        // The run the winner left is coherent: one batch of lines, not one
        // batch each.
        let index = shared.run(REPO, RUN).expect("read back").expect("there is a run").0;
        assert_eq!((index.batches, index.entries), (1, 5), "{index:?}");
        let stored = String::from_utf8(
            blob.get(&ks_module_runlog::blob_key(REPO, RUN)).expect("read back").expect("a body"),
        )
        .expect("utf-8");
        assert_eq!(stored, text, "the lines are stored once, not once per sender");
        assert_eq!(db.runs_in_repo(REPO).expect("listed").len(), 1);
        assert!(view::story(&stored, &index).is_ok(), "the stored run still reads");
    }
}

/// The check behind the other two. A prefix of a good chain is a good chain, so
/// a log cut short of the end still walks from GENESIS without complaint — and
/// before the index was compared, it came back `Ok` with the index's own
/// "verified" status and a story assembled out of the entries that survived. That
/// is the rendering an attacker wants, so the walk ends by asking whether it
/// landed where the index says it lands.
#[test]
fn a_log_that_does_not_match_its_index_is_not_rendered_as_verified() {
    let (viewer, blob, _db) = viewer();
    let text = run_log();
    let index = upload(&viewer, &text, MAX_BATCH_BYTES).last().expect("an index").clone();
    assert_eq!(view::story(&text, &index).expect("the genuine log").status, Status::Verified);
    let key = ks_module_runlog::blob_key(REPO, RUN);
    let lines: Vec<&str> = text.lines().collect();

    // Cut short. Every one of these is a prefix of the genuine log, so it walks
    // from GENESIS without a complaint — the count is the only thing that gives
    // it away, which is exactly the check that is being made here.
    for kept in [0usize, 1, 3, 4] {
        let short = lines[..kept].join("\n");
        blob.put(&key, short.as_bytes()).expect("the store takes what it is given");
        match view::story(&short, &index) {
            Err(ks_module_runlog::ChainBreak::Count { found, expected }) => {
                assert_eq!(
                    (found, expected),
                    (kept, 5),
                    "the count it holds and the count it should"
                );
            }
            Ok(story) => {
                panic!("{kept} of 5 entries rendered a {:?} story", story.status)
            }
            Err(other) => panic!("{kept} lines is a count mismatch, got {other:?}"),
        }
    }

    // Longer, and the longer log is a good chain — every hash real, every `prev`
    // correct, starting from GENESIS. The index still describes five entries, so
    // the story is an error rather than a page.
    let mut prev = tip_of(lines[4]).0;
    let mut extended = lines.iter().map(|line| line.to_string()).collect::<Vec<_>>();
    for seq in 5..9 {
        let (line, hash) =
            entry(&prev, seq, &[("type", json!("step.started")), ("step", json!("extra"))]);
        prev = hash;
        extended.push(line);
    }
    let extended = extended.join("\n");
    match view::story(&extended, &index) {
        Err(ks_module_runlog::ChainBreak::Count { found, expected }) => {
            assert_eq!((found, expected), (9, 5));
        }
        Ok(story) => panic!("nine entries against a five-entry index rendered {:?}", story.status),
        Err(other) => panic!("a longer log is a count mismatch, got {other:?}"),
    }

    // And a log of exactly the right length that ends somewhere else — five real
    // entries, chained, but not the five the index recorded. The count agrees and
    // the head does not, which is the other half of the same question.
    let other_run = "01OTHER00000000000000000000";
    let spliced = run_log_for(other_run);
    match view::story(&spliced, &index) {
        Err(ks_module_runlog::ChainBreak::Head { found, expected }) => {
            assert_eq!(expected, index.head, "the head the index records");
            assert_ne!(found, index.head, "the head the other log ends at");
        }
        Ok(story) => panic!("another run's log rendered a {:?} story", story.status),
        Err(other) => panic!("a spliced log is a head mismatch, got {other:?}"),
    }

    // And the store is left holding the genuine log, which still reads.
    blob.put(&key, text.as_bytes()).expect("restored");
    assert!(view::story(&text, &index).is_ok());
}
