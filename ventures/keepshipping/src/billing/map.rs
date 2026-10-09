//! Maps verified Polar events onto `cratefield-core`'s provider-neutral
//! billing lifecycle (ADR 0025) — the judgement the adapter deliberately
//! leaves to the venture: what each Polar event means for this venture's
//! one paid plan, and which events billing has no use for. Pure: no
//! network, no database.

use time::OffsetDateTime;

use cratefield_adapter_polar::{OrderChange, PolarEvent, RefundChange, SubscriptionChange};
use cratefield_core::billing::{
    CancelReason, DisputeOutcome, Environment, ExpirationReason, LifecycleEvent, LifecycleKind,
    Ownership, Period, PeriodType, Provider, ProviderCustomer, RefundOrigin, SourceRef, Store,
};
use cratefield_core::{Dispute, DisputePhase, WebhookEvent};

/// The entitlement key every Polar source grants: the venture's one product.
pub(crate) const ENTITLEMENT: &str = "keepshipping";

const POLAR: &str = "polar";

/// A mapped event: the lifecycle event plus the ids the module needs to
/// resolve the account and store alongside it.
pub(crate) struct Mapped {
    pub account_id: Option<String>,
    pub subscription_id: Option<String>,
    pub order_id: Option<String>,
    pub product_id: Option<String>,
    pub event: LifecycleEvent,
}

impl Mapped {
    /// Webhook id plus the mapped type: a redelivery claims the same key
    /// and is dropped; the two events one webhook can carry do not.
    pub fn dedup_key(&self, webhook_id: &str) -> String {
        format!("{webhook_id}:{}", self.event.raw_kind)
    }
}

/// The identity an `order.paid` carries: the order id billing keeps — the
/// reference a dispute without a customer id resolves by — and the
/// subscription it belongs to.
pub(crate) struct PaidOrder {
    pub account_id: Option<String>,
    pub subscription_id: Option<String>,
    pub order_id: String,
}

/// An `order.paid`, for the module to record. Identity only, never access:
/// subscription events drive the lifecycle, so a late redelivered order
/// cannot re-grant what a refund revoked.
pub(crate) fn paid_order(polar: &PolarEvent) -> Option<PaidOrder> {
    let PolarEvent::Order(event) = polar else { return None };
    if event.change != OrderChange::Paid {
        return None;
    }
    Some(PaidOrder {
        account_id: event.external_customer_id.clone(),
        subscription_id: event.subscription_id.clone(),
        order_id: event.id.clone(),
    })
}

/// Maps one normalized Polar event, or `None` when billing has no use for
/// it. `now` stands in for the provider's occurrence time: Polar payloads
/// carry none, and a delivery is close enough for stale-event ordering.
pub(crate) fn to_lifecycle(
    polar: &PolarEvent,
    webhook: &WebhookEvent,
    environment: Environment,
    now: OffsetDateTime,
) -> Option<Mapped> {
    let (source, kind, period_end, account_id, subscription_id, order_id, product_id) = match polar
    {
        PolarEvent::Subscription(event) => {
            let kind = match event.change {
                SubscriptionChange::Created | SubscriptionChange::Active => LifecycleKind::Started,
                SubscriptionChange::Cycled => LifecycleKind::Renewed { trial_conversion: false },
                SubscriptionChange::Canceled => {
                    LifecycleKind::CancellationScheduled { reason: CancelReason::Unsubscribe }
                }
                SubscriptionChange::Uncanceled => LifecycleKind::Uncancelled,
                SubscriptionChange::Revoked => {
                    LifecycleKind::Expired { reason: ExpirationReason::Other("revoked".to_owned()) }
                }
                // Polar retries a failed renewal until the period ends;
                // that end is the grace window.
                SubscriptionChange::PastDue => {
                    LifecycleKind::BillingIssue { grace_until: event.current_period_end }
                }
                SubscriptionChange::Paused => LifecycleKind::Paused,
                SubscriptionChange::Resumed => LifecycleKind::Resumed,
                // `updated` (seats, add-ons) and `migrated` (provider move)
                // say nothing access depends on.
                SubscriptionChange::Updated | SubscriptionChange::Migrated => return None,
            };
            (
                SourceRef::Subscription(event.id.clone()),
                kind,
                event.current_period_end,
                event.external_customer_id.clone(),
                Some(event.id.clone()),
                None,
                Some(event.product_id.clone()),
            )
        }
        // Only a *succeeded* refund revokes: `refund.created` is a promise,
        // and Polar refunds are issued from the merchant dashboard.
        PolarEvent::Refund(event) => {
            if event.change != RefundChange::Updated || event.status != "succeeded" {
                return None;
            }
            let subscription_id = event.subscription_id.clone()?;
            (
                SourceRef::Subscription(subscription_id.clone()),
                LifecycleKind::Refunded { partial: false, origin: RefundOrigin::Merchant },
                None,
                None,
                Some(subscription_id),
                Some(event.payment_ref.clone()),
                None,
            )
        }
        // The checkout itself never grants anything: its completion fires
        // `subscription.created`. Orders are recorded as identity only (see
        // `paid_order`). Disputes do not arrive as webhooks from Polar; the
        // module polls them into `dispute_lifecycle` instead.
        PolarEvent::Checkout(_)
        | PolarEvent::Customer(_)
        | PolarEvent::Dispute(_)
        | PolarEvent::Order(_)
        | _ => return None,
    };
    Some(Mapped {
        account_id,
        subscription_id,
        order_id,
        product_id,
        event: event_of(
            webhook.id.clone(),
            webhook.kind.clone(),
            environment,
            now,
            source,
            kind,
            period_end,
        ),
    })
}

/// Maps a dispute step read by the hourly poll exactly as a webhook would
/// be: opened keeps the plan and only flags the account; lost downgrades;
/// won restores. The event id is the poll's dedup key.
pub(crate) fn dispute_lifecycle(
    dispute: &Dispute,
    environment: Environment,
    now: OffsetDateTime,
) -> Mapped {
    let kind = match dispute.status.phase() {
        DisputePhase::Open => LifecycleKind::DisputeOpened,
        DisputePhase::Won => LifecycleKind::DisputeClosed { outcome: DisputeOutcome::Won },
        DisputePhase::Lost => LifecycleKind::DisputeClosed { outcome: DisputeOutcome::Lost },
        DisputePhase::Closed => LifecycleKind::DisputeClosed {
            outcome: DisputeOutcome::Other(dispute.provider_status.clone()),
        },
    };
    Mapped {
        account_id: dispute.customer_ref.clone(),
        subscription_id: None,
        order_id: Some(dispute.payment_ref.clone()),
        product_id: None,
        event: event_of(
            dispute.event_key(),
            format!("dispute.{}", dispute.provider_status),
            environment,
            now,
            SourceRef::OneTimePurchase(dispute.payment_ref.clone()),
            kind,
            None,
        ),
    }
}

/// The common shape of every mapped event: Polar as provider and store, the
/// venture's one entitlement key, normal purchased periods. Polar reports
/// only a period's *end*, so `starts_at` is the delivery time — nothing
/// downstream reads it.
fn event_of(
    event_id: String,
    raw_kind: String,
    environment: Environment,
    now: OffsetDateTime,
    source: SourceRef,
    kind: LifecycleKind,
    period_end: Option<OffsetDateTime>,
) -> LifecycleEvent {
    LifecycleEvent {
        provider: Provider::Other(POLAR.to_owned()),
        store: Store::Other(POLAR.to_owned()),
        event_id,
        occurred_at: now,
        environment,
        provider_customer: ProviderCustomer {
            id: String::new(),
            original_id: None,
            aliases: vec![],
        },
        source,
        product_id: String::new(),
        entitlement_keys: vec![ENTITLEMENT.to_owned()],
        period: period_end.map(|ends_at| Period { starts_at: now, ends_at }),
        period_type: PeriodType::Normal,
        ownership: Ownership::Purchased,
        kind,
        raw_kind,
    }
}

/// The audit vocabulary `billing_audit.kind` speaks.
pub(crate) fn kind_label(kind: &LifecycleKind) -> String {
    match kind {
        LifecycleKind::Started => "subscription.started",
        LifecycleKind::Renewed { .. } => "subscription.renewed",
        LifecycleKind::CancellationScheduled { .. } => "subscription.canceled",
        LifecycleKind::Uncancelled => "subscription.uncanceled",
        LifecycleKind::BillingIssue { .. } => "subscription.billing_issue",
        LifecycleKind::Paused => "subscription.paused",
        LifecycleKind::Resumed => "subscription.resumed",
        LifecycleKind::Expired { .. } => "subscription.expired",
        LifecycleKind::Refunded { .. } | LifecycleKind::RefundReversed => "subscription.refunded",
        LifecycleKind::DisputeOpened => "dispute.opened",
        LifecycleKind::DisputeClosed { outcome } => match outcome {
            DisputeOutcome::Won => "dispute.won",
            DisputeOutcome::Lost => "dispute.lost",
            DisputeOutcome::Other(raw) => return format!("dispute.{raw}"),
            _ => "dispute.updated",
        },
        _ => "subscription.event",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_adapter_polar::SubscriptionEvent;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-02-14 08:00 UTC);
    const END: OffsetDateTime = datetime!(2027-02-14 08:00 UTC);

    fn webhook(kind: &str) -> WebhookEvent {
        WebhookEvent { id: "evt_1".to_owned(), kind: kind.to_owned(), data: Value::Null }
    }

    fn subscription(change: SubscriptionChange) -> PolarEvent {
        PolarEvent::Subscription(SubscriptionEvent {
            change,
            id: "sub_1".to_owned(),
            status: "active".to_owned(),
            customer_id: "cus_1".to_owned(),
            external_customer_id: Some("acc_1".to_owned()),
            product_id: "prod_annual".to_owned(),
            cancel_at_period_end: false,
            current_period_end: Some(END),
            metadata: BTreeMap::new(),
        })
    }

    #[test]
    fn subscription_events_map_onto_the_lifecycle() {
        let active = to_lifecycle(
            &subscription(SubscriptionChange::Active),
            &webhook("subscription.active"),
            Environment::Production,
            NOW,
        )
        .expect("active maps");
        assert_eq!(active.account_id.as_deref(), Some("acc_1"));
        assert_eq!(active.subscription_id.as_deref(), Some("sub_1"));
        assert_eq!(kind_label(&active.event.kind), "subscription.started");
        assert_eq!(active.dedup_key("evt_1"), "evt_1:subscription.active");
        assert_eq!(active.event.period.expect("a period").ends_at, END);
        assert_eq!(active.event.environment, Environment::Production);

        // A failed renewal keeps the plan only as long as its grace window.
        let past_due = to_lifecycle(
            &subscription(SubscriptionChange::PastDue),
            &webhook("subscription.past_due"),
            Environment::Sandbox,
            NOW,
        )
        .expect("past_due maps");
        assert!(matches!(
            past_due.event.kind,
            LifecycleKind::BillingIssue { grace_until: Some(grace) } if grace == END
        ));

        // Seats, add-ons, provider moves: nothing access depends on.
        for noise in [SubscriptionChange::Updated, SubscriptionChange::Migrated] {
            assert!(
                to_lifecycle(
                    &subscription(noise),
                    &webhook("subscription.updated"),
                    Environment::Production,
                    NOW
                )
                .is_none()
            );
        }
    }
}
