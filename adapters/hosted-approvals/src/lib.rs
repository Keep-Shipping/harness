//! Hosted approvals (#98): a web review page and Slack Approve/Deny buttons, two
//! [`ApprovalChannel`] adapters over one in-memory ticket store. Neither decides
//! *who may* approve — that is [`ApprovalRequest::accepts`] and the engine's
//! `Directory` — only *who decided*: from a sign-in or an immutable Slack id,
//! never from anything a person typed. Each decision binds the artifacts they were
//! shown, so a plan that moved underneath fails `accepts` rather than releasing the
//! run. The first decision wins, and nobody deciding is not approval: `poll` is
//! `Ok(None)`, `wait` is `Undecided`.
//!
//! [`Directory`]: ks_core::ports::approval::Directory
//! [`ApprovalChannel`]: ks_core::ports::approval::ApprovalChannel
//! [`ApprovalRequest::accepts`]: ks_core::ports::approval::ApprovalRequest::accepts

#![forbid(unsafe_code)]

pub mod slack;
pub mod web;

use std::collections::BTreeMap;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use ks_core::ports::BoxFuture;
use ks_core::ports::approval::{
    ApprovalChannel, ApprovalError, ApprovalRequest, Artifact, ArtifactKind, Identity, Outcome,
    Ticket, Verdict,
};
use ks_core::ports::supply_chain::Digest;

pub use slack::{SlackError, SlackIdentities, handle_interaction, message};
pub use web::{GitHubSession, ReviewForm, WebError, review_page, submit};

/// Which surface a decision came from; the id is what the run log records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Channel {
    /// The hosted review page, after a GitHub sign-in.
    Web,
    /// A Slack message's Approve/Deny buttons.
    Slack,
}

impl Channel {
    /// The channel's stable id, e.g. `web` — what `Journal` records.
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Web => "web",
            Channel::Slack => "slack",
        }
    }
}

/// One person's answer. `shown` is what they looked at, not what the store holds:
/// it is what the verdict binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Who decided — resolved by the channel, never read out of the form.
    pub approver: Identity,
    /// Approved or refused.
    pub outcome: Outcome,
    /// The comment they left, if any.
    pub comment: Option<String>,
    /// The artifacts they were shown.
    pub shown: Vec<Artifact>,
    /// The surface they answered on.
    pub channel: Channel,
}

impl Decision {
    /// A decision of either outcome, with no comment.
    pub fn new(
        approver: Identity,
        outcome: Outcome,
        shown: Vec<Artifact>,
        channel: Channel,
    ) -> Self {
        Decision { approver, outcome, comment: None, shown, channel }
    }
}

/// For a ticket this store never minted: answering one would report a decision
/// nobody gave.
fn unknown(ticket: &Ticket) -> ApprovalError {
    ApprovalError::UnknownTicket { ticket: ticket.as_str().to_string() }
}

/// One outstanding request and the answer, if any, that closed it.
#[derive(Clone)]
struct Entry {
    seq: u64,
    request: ApprovalRequest,
    verdict: Option<Verdict>,
    channel: Option<Channel>,
}

/// The store's lock, recovering from a panic elsewhere: every update is one
/// critical section that cannot be seen half-done, so a poisoned mutex still
/// guards a consistent map.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One process, in memory, both channels: a mutex and a condvar, so a decision
/// on a request thread unblocks a run waiting on another without polling.
#[derive(Default)]
pub struct HostedApprovals {
    entries: Mutex<BTreeMap<String, Entry>>,
    answered: Condvar,
}

impl HostedApprovals {
    /// An empty store.
    pub fn new() -> HostedApprovals {
        HostedApprovals::default()
    }

    /// Records `decision` as the answer to `ticket`. The first decision wins: a
    /// second is [`ApprovalError::Unavailable`], so a reloaded page cannot change
    /// what was approved.
    pub fn decide(&self, ticket: &Ticket, decision: Decision) -> Result<Verdict, ApprovalError> {
        let mut entries = lock(&self.entries);
        let entry = entries.get_mut(ticket.as_str()).ok_or_else(|| unknown(ticket))?;
        if let Some(answered) = &entry.verdict {
            return Err(ApprovalError::Unavailable {
                message: format!(
                    "approval ticket {ticket} was already answered by {}; the first answer stands",
                    answered.approver
                ),
            });
        }
        let verdict = Verdict::new(
            decision.approver.clone(),
            SystemTime::now(),
            decision.outcome,
            decision.shown.clone(),
        );
        let verdict = match &decision.comment {
            Some(comment) => verdict.with_comment(comment.clone()),
            None => verdict,
        };
        entry.channel = Some(decision.channel);
        entry.verdict = Some(verdict.clone());
        drop(entries);
        self.answered.notify_all();
        Ok(verdict)
    }

    /// The channel that answered `ticket`: what the engine's approval step
    /// journals, since nothing in it reads a channel.
    pub fn channel_of(&self, ticket: &Ticket) -> Option<Channel> {
        self.entry(ticket).and_then(|entry| entry.channel)
    }

    /// The request behind `ticket`, for rendering a review page or a message.
    pub fn pending(&self, ticket: &Ticket) -> Option<ApprovalRequest> {
        self.entry(ticket).map(|entry| entry.request)
    }

    /// Every ticket still waiting for an answer, oldest first.
    pub fn outstanding(&self) -> Vec<Ticket> {
        let mut waiting: Vec<(u64, Ticket)> = lock(&self.entries)
            .iter()
            .filter(|(_, entry)| entry.verdict.is_none())
            .map(|(id, entry)| (entry.seq, Ticket::new(id.clone())))
            .collect();
        waiting.sort_by_key(|(seq, _)| *seq);
        waiting.into_iter().map(|(_, ticket)| ticket).collect()
    }

    /// The entry for `ticket`, or `None` if this store never minted it.
    fn entry(&self, ticket: &Ticket) -> Option<Entry> {
        lock(&self.entries).get(ticket.as_str()).cloned()
    }

    /// Mints `ha-{n}`, `n` counting the tickets minted. Not a credential, and free
    /// of run-controlled text: the id lands in a form action's URL path.
    fn mint(&self, request: &ApprovalRequest) -> Ticket {
        let mut entries = lock(&self.entries);
        let seq = entries.len() as u64 + 1;
        let id = format!("ha-{seq}");
        entries.insert(
            id.clone(),
            Entry { seq, request: request.clone(), verdict: None, channel: None },
        );
        Ticket::new(id)
    }

    /// Blocks until `ticket` is answered or `timeout` is up — the host answers on
    /// its own threads, so the thread running a step waits here.
    fn wait_for(&self, ticket: &Ticket, timeout: Duration) -> Result<Verdict, ApprovalError> {
        let mut entries = lock(&self.entries);
        if !entries.contains_key(ticket.as_str()) {
            return Err(unknown(ticket));
        }
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(verdict) =
                entries.get(ticket.as_str()).and_then(|entry| entry.verdict.clone())
            {
                return Ok(verdict);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(ApprovalError::Undecided {
                    ticket: ticket.as_str().to_string(),
                    after: timeout,
                });
            }
            let (guard, _) = self
                .answered
                .wait_timeout(entries, deadline - now)
                .unwrap_or_else(PoisonError::into_inner);
            entries = guard;
        }
    }
}

impl ApprovalChannel for HostedApprovals {
    fn request<'a>(
        &'a self,
        request: &'a ApprovalRequest,
    ) -> BoxFuture<'a, Result<Ticket, ApprovalError>> {
        Box::pin(std::future::ready(Ok(self.mint(request))))
    }

    fn poll<'a>(
        &'a self,
        ticket: &'a Ticket,
    ) -> BoxFuture<'a, Result<Option<Verdict>, ApprovalError>> {
        let answered = self.entry(ticket).map(|entry| entry.verdict).ok_or_else(|| unknown(ticket));
        Box::pin(std::future::ready(answered))
    }

    fn wait<'a>(
        &'a self,
        ticket: &'a Ticket,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Verdict, ApprovalError>> {
        // Lazy, but it blocks the thread that polls: a condvar wait has no
        // executor-free way to suspend, the same trade `TcpHttpClient::send`
        // makes with its synchronous exchange.
        Box::pin(async move { self.wait_for(ticket, timeout) })
    }
}

/// One artifact as a field both channels round-trip: `plan-file|sha256:…`. An
/// unparseable field is refused, never dropped.
pub(crate) fn artifact_field(artifact: &Artifact) -> String {
    format!("{}|{}", kind_label(&artifact.kind), artifact.digest)
}

/// The artifact an [`artifact_field`] carried, or why not. Split at the *last*
/// `|`, so a name may hold one; a digest cannot.
pub(crate) fn artifact_from_field(field: &str) -> Result<Artifact, String> {
    let (label, digest) = field.rsplit_once('|').ok_or("no kind and digest")?;
    let kind = match label.strip_prefix("other: ") {
        Some(name) => ArtifactKind::Other(name.to_string()),
        None if label == "plan-file" => ArtifactKind::PlanFile,
        None if label == "image" => ArtifactKind::Image,
        None => return Err(format!("{label:?} is not an artifact kind")),
    };
    let digest =
        Digest::parse(digest).map_err(|error| format!("artifact digest {digest:?}: {error}"))?;
    Ok(Artifact::new(kind, digest))
}

/// Bytes as lower-case hex, the form every signature and token travels in.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 32 bytes of hex, or `None` if `text` is not exactly that — the length is
/// checked before decoding, so a short value cannot pass as a prefix of a good
/// one.
pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    if text.len() != 64 {
        return None;
    }
    let bytes = text.as_bytes();
    (0..32).map(|at| Some(digit(bytes[2 * at])? * 16 + digit(bytes[2 * at + 1])?)).collect()
}

/// `plan-file`, `image`, or `other: <name>`.
pub(crate) fn kind_label(kind: &ArtifactKind) -> String {
    match kind {
        ArtifactKind::PlanFile => "plan-file".to_string(),
        ArtifactKind::Image => "image".to_string(),
        ArtifactKind::Other(name) => format!("other: {name}"),
    }
}
