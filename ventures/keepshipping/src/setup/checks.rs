//! Live status for the setup checklist: what the public internet can see
//! right now, over DNS-over-HTTPS and one policy fetch — read-only, no
//! zone API, no credentials. Every lookup can fail, and a failed lookup
//! never becomes a claim: the chip falls back to what the checklist asked
//! for and says it couldn't check.

use std::collections::BTreeSet;

use cratefield_core::HttpClient;
use cratefield_core::axum::body::Bytes;
use cratefield_core::axum::http::{Method, Request};

use super::{Desired, ITEMS};

/// Where the plain-words DNS questions go: Cloudflare's DoH endpoint,
/// answered as JSON (`accept: application/dns-json`).
const DOH: &str = "https://cloudflare-dns.com/dns-query";

/// A record that carries the MTA-STS policy.
fn mta_sts_policy_url(domain: &str) -> String {
    format!("https://mta-sts.{domain}/.well-known/mta-sts.txt")
}

/// How one checklist item stands, as the page shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chip {
    /// The internet already shows it (or the operator clicked "I did this").
    Done,
    /// Selected; the records are not answering yet.
    Pending,
    /// A record cannot do this part — a person has to click or paste.
    NeedsYou,
    /// Deselected; nothing is published.
    Off,
}

impl Chip {
    /// The id the status JSON and the chip's CSS class carry.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Chip::Done => "done",
            Chip::Pending => "pending",
            Chip::NeedsYou => "needs-you",
            Chip::Off => "off",
        }
    }

    /// The plain word the page shows.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Chip::Done => "Done",
            Chip::Pending => "Turning on",
            Chip::NeedsYou => "Needs you",
            Chip::Off => "Off",
        }
    }
}

/// One item's row in the status answer: chip, one sentence of plain words,
/// and — for needs-you items — the one link to click.
#[derive(Debug, Clone)]
pub struct ItemStatus {
    pub key: &'static str,
    pub label: &'static str,
    pub chip: Chip,
    pub detail: String,
    pub link: Option<String>,
    /// Whether the page offers the "I did this" button.
    pub confirmable: bool,
}

/// What a lookup found: live, absent, or unchecked (the request itself
/// failed — distinct from "asked and told us no", which is [`Found::No`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Found {
    Yes,
    No,
    Unchecked,
}

impl Found {
    fn of(live: Result<bool, ()>) -> Found {
        match live {
            Ok(true) => Found::Yes,
            Ok(false) => Found::No,
            Err(()) => Found::Unchecked,
        }
    }
}

/// A GET that answers `Ok(body)` on success and `Err` on anything else —
/// the whole transport vocabulary the checks need.
async fn get(http: &dyn HttpClient, uri: String, accept: &str) -> Result<Bytes, ()> {
    let request =
        Request::builder().method(Method::GET).uri(uri).header("accept", accept).body(Bytes::new());
    let request = request.map_err(|_| ())?;
    let response = http.send(request).await.map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    Ok(response.into_body())
}

/// The TXT records of `qname`, quote-stripped the way DoH frames them.
/// `Ok(empty)` is a name that answered with no records; `Err` is a
/// transport or parse failure, never "absent" — a body without a `Status`
/// did not really answer, so it is a failure too.
async fn txt_records(http: &dyn HttpClient, qname: &str) -> Result<Vec<String>, ()> {
    let body = get(http, format!("{DOH}?name={qname}&type=TXT"), "application/dns-json").await?;
    let answer: serde_json::Value = serde_json::from_slice(&body).map_err(|_| ())?;
    let status = answer.get("Status").and_then(serde_json::Value::as_i64).ok_or(())?;
    if status != 0 {
        // NXDOMAIN and friends: asked and told no, which is not a failure.
        return Ok(Vec::new());
    }
    Ok(answer
        .get("Answer")
        .and_then(serde_json::Value::as_array)
        .map(|answers| {
            answers
                .iter()
                // Only TXT answers (type 16) count: a CNAME (5) or any
                // other record must not pass for the one we asked about.
                .filter(|entry| entry.get("type").and_then(serde_json::Value::as_i64) == Some(16))
                .filter_map(|entry| entry.get("data").and_then(serde_json::Value::as_str))
                // DoH quotes TXT data (`"v=spf1 …"`), long records as
                // several quoted chunks; the quotes are framing, not text.
                .map(|data| data.replace('"', ""))
                .collect()
        })
        .unwrap_or_default())
}

/// Whether any TXT record of `qname` contains `needle`.
async fn txt_has(http: &dyn HttpClient, qname: &str, needle: &str) -> Result<bool, ()> {
    let records = txt_records(http, qname).await?;
    Ok(records.iter().any(|record| record.contains(needle)))
}

/// Whether the body at `url` contains `needle` — the MTA-STS policy fetch.
async fn body_has(http: &dyn HttpClient, url: &str, needle: &str) -> Result<bool, ()> {
    let body = get(http, url.to_owned(), "text/plain").await?;
    Ok(String::from_utf8_lossy(&body).contains(needle))
}

/// The whole board, checked against the live internet, in the checklist's
/// order. `sent` is whether a change was already sent for this domain
/// (it turns "will be turned on" into "on its way"); `confirmed` holds the
/// items the operator clicked "I did this" for.
pub async fn assess(
    http: &dyn HttpClient,
    domain: &str,
    desired: &Desired,
    sent: bool,
    confirmed: &BTreeSet<String>,
) -> Vec<ItemStatus> {
    // The apex TXT serves two items (SPF and the Search Console token), so
    // it is asked once, first; the rest follow in checklist order. The
    // policy fetch runs only when the MTA-STS record is live — no record,
    // nothing for the policy to add.
    let apex = txt_records(http, domain).await;
    // One answer, two predicates; a failed lookup stays a failure.
    let (spf, verification) = match &apex {
        Ok(records) => (
            Ok(records.iter().any(|record| record.contains("v=spf1"))),
            Ok(records.iter().any(|record| record.starts_with("google-site-verification="))),
        ),
        Err(()) => (Err(()), Err(())),
    };
    let dkim_qname = super::change::dkim_name(&desired.dkim_selector, domain);
    let dkim_txt =
        Found::of(txt_records(http, &dkim_qname).await.map(|records| !records.is_empty()));
    let dmarc = Found::of(txt_has(http, &format!("_dmarc.{domain}"), "v=DMARC1").await);
    let sts = txt_has(http, &format!("_mta-sts.{domain}"), "v=STSv1").await;
    let mta_sts = match sts {
        Ok(true) => body_has(http, &mta_sts_policy_url(domain), "version: STSv1").await,
        other => other,
    };
    let tls = Found::of(txt_has(http, &format!("_smtp._tls.{domain}"), "v=TLSRPTv1").await);

    let mut statuses = Vec::with_capacity(ITEMS.len());
    for (index, item) in ITEMS.iter().enumerate() {
        let mut status = ItemStatus {
            key: item.key,
            label: item.label,
            chip: Chip::Off,
            detail: String::new(),
            link: None,
            confirmable: item.external,
        };
        if !desired.on[index] {
            status.detail = "Unticked — nothing will be published for this.".to_owned();
            statuses.push(status);
            continue;
        }
        match item.key {
            "spf" => finish_dns(&mut status, Found::of(spf), sent),
            "dkim" if desired.dkim_key.is_none() => {
                status.chip = Chip::NeedsYou;
                status.link = Some("https://admin.google.com".to_owned());
                status.detail = "Generate the key in the Google Admin console (Apps → Google \
                                 Workspace → Gmail → Authenticate email), paste it above, then \
                                 send the change."
                    .to_owned();
            }
            "dkim" => finish_dns(&mut status, dkim_txt, sent),
            "dmarc" => finish_dns(&mut status, dmarc, sent),
            "mta_sts" => {
                if sts == Ok(true) && mta_sts == Ok(false) {
                    // Record live, policy missing: the one honest middle
                    // state visible from outside.
                    status.chip = Chip::Pending;
                    status.detail = "The policy page isn't answering yet.".to_owned();
                } else {
                    finish_dns(&mut status, Found::of(mta_sts), sent);
                }
            }
            "tls_rpt" => finish_dns(&mut status, tls, sent),
            // The outside services: done when confirmed, done for Search
            // Console when its verification record is live, else a click.
            "search_console" if verification == Ok(true) => {
                status.chip = Chip::Done;
                status.detail = "The verification record is live.".to_owned();
            }
            "search_console" | "postmaster" | "bing" => {
                if confirmed.contains(item.key) {
                    status.chip = Chip::Done;
                    status.detail = "You said this is done.".to_owned();
                } else {
                    status.chip = Chip::NeedsYou;
                    status.link = Some(link_for(item.key, domain));
                    status.detail = detail_for(item.key).to_owned();
                }
            }
            other => unreachable!("ITEMS and assess agree by construction: {other}"),
        }
        statuses.push(status);
    }
    statuses
}

/// The needs-you link for an outside service.
fn link_for(key: &str, domain: &str) -> String {
    match key {
        "search_console" => {
            format!("https://search.google.com/search-console?resource_id=sc-domain%3A{domain}")
        }
        "postmaster" => format!("https://postmaster.google.com/manage?domain={domain}"),
        _ => "https://www.bing.com/webmasters".to_owned(),
    }
}

/// The one sentence that says what to click.
fn detail_for(key: &str) -> &'static str {
    match key {
        "search_console" => "Open Search Console and click Verify",
        "postmaster" => "Add the domain in Postmaster Tools",
        _ => "Import from Google Search Console",
    }
}

/// The chip of an ordinary DNS item: live is done; not live is on its way
/// (or waiting for the send); an unchecked lookup keeps the chip the
/// checklist's state implies and says so instead of guessing.
fn finish_dns(status: &mut ItemStatus, live: Found, sent: bool) {
    match live {
        Found::Yes => {
            status.chip = Chip::Done;
            status.detail = "Published and answering.".to_owned();
        }
        Found::No => {
            status.chip = Chip::Pending;
            status.detail = if sent {
                "Your change is on its way — records usually appear within a few minutes."
                    .to_owned()
            } else {
                "Will be turned on when you send the change.".to_owned()
            };
        }
        Found::Unchecked => {
            status.chip = Chip::Pending;
            status.detail = "Couldn't check just now.".to_owned();
        }
    }
}
