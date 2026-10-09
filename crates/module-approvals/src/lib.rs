//! The module's own rules, in short: the summary is capped at 64 KiB and
//! refused by name; a decision and its dispatch commit together; and nobody
//! approves their own run against a team membership read at the click.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod github;
mod handlers;
mod sign;
mod store;
mod validate;

use cratefield_core::axum;
use cratefield_core::{
    AnyError, BoxFuture, Clock, Config, ConfigError, DataKind, Disposition, Migrations, Module,
    ModuleConfig, ModuleContext, PersonalDataSet, Port, SqlMigration, StreamRoute, SystemClock,
};
use std::sync::Arc;

/// The hosted summary ceiling: `ks_core::plan_summary::HOSTED_BODY_LIMIT`.
pub const SUMMARY_LIMIT_BYTES: usize = 64 * 1024;

/// The body ceiling for `POST /requests`. Above the harness's own 64 KiB, so a
/// body carrying a 64 KiB + 1 summary plus its JSON scaffolding reaches this
/// module's check instead of the runtime's anonymous 413.
const REQUEST_BODY_LIMIT: usize = 96 * 1024;

/// A decision is a verb and a comment; it is streamed only because the review
/// page's form posts it urlencoded rather than as JSON.
const DECISION_BODY_LIMIT: usize = 8 * 1024;

// `POST /requests` is streamed because a *buffered* body stops at the harness's
// 64 KiB, which would refuse a legal, maximal summary before this module saw it.
// Streaming lifts the ceiling to `REQUEST_BODY_LIMIT` and leaves the summary
// ceiling to the problem that can explain it.
const STREAMED: &[StreamRoute] = &[
    StreamRoute::post("/requests", REQUEST_BODY_LIMIT),
    StreamRoute::post("/requests/{ticket}/decision", DECISION_BODY_LIMIT),
];

/// How long a request stays open when the runner names no TTL.
const DEFAULT_TTL_SECS: u64 = 86_400;

/// The ceiling on a runner-chosen TTL: a run may ask for less time, never more.
const MAX_TTL_SECS: u64 = 7 * 86_400;

/// The topic a decision is enqueued under, and the `event_type` the repository
/// listens for.
pub(crate) const TOPIC_DISPATCH: &str = "github.repository_dispatch";
pub(crate) const EVENT_TYPE: &str = "keepshipping-approval";

/// The table core's [`cratefield_core::Outbox`] leases from; matches the DDL
/// and [`Approvals::tables`].
pub(crate) const OUTBOX_TABLE: &str = "approvals_outbox";

const MIGRATION_INIT: SqlMigration =
    SqlMigration::new("0001", "init", include_str!("../migrations/sqlite/0001_init.sql"));

/// Every column in these three tables holds an identifier subject; only the
/// disposition and the human wording differ, so only they are spelled out.
const fn set(
    table: &'static str,
    subject: &'static str,
    disposition: Disposition,
    description: &'static str,
) -> PersonalDataSet {
    PersonalDataSet {
        table,
        subject,
        kind: DataKind::Identifier,
        disposition,
        description,
        redacted: &[],
        subject_via: None,
    }
}

/// Hosted approvals for a Keep Shipping run. Every value is deployment
/// configuration, so a test can build this without a real GitHub token.
pub struct Approvals;

impl Default for Approvals {
    fn default() -> Self {
        Self
    }
}

impl Approvals {
    /// A module instance; nothing to configure.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// The `Clock` this deployment provides, or the system clock. Expiry,
/// timestamps and the outbox lease all read time here, so a test moves them
/// together.
pub(crate) fn clock(ctx: &ModuleContext) -> Arc<dyn Clock> {
    ctx.ports.clock.clone().unwrap_or_else(|| Arc::new(SystemClock))
}

impl Module for Approvals {
    fn name(&self) -> &'static str {
        "approvals"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// None of these four has a safe fallback, so a composition missing any of
    /// them is refused here rather than at the click.
    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Auth, Port::HttpClient, Port::Clock]
    }

    /// Absent, a decision is announced only by the dispatch and a ticket falls
    /// back to [`cratefield_core::UlidIdGen`].
    fn optional(&self) -> &'static [Port] {
        &[Port::Realtime, Port::IdGen]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["approval_requests", "approval_decisions", OUTBOX_TABLE]
    }

    /// A login is who is answerable for the change, and "who approved this" is
    /// the only question the decision table exists to answer — so the two login
    /// columns are retained. The outbox row names the approver only so a queued
    /// dispatch is reachable by a subject at all, and goes once it is delivered.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[
            set(
                "approval_requests",
                "proposed_by",
                Disposition::Retain(
                    "the login is who is answerable for the proposed change; an approval \
                     history with the people removed from it cannot answer who proposed what",
                ),
                "The step you asked a team to review: the run, repository and step, the plan \
                 summary you sent, the artifact digests it names, the team you asked, why you \
                 asked, and when the request expires.",
            ),
            set(
                "approval_decisions",
                "approver",
                Disposition::Retain(
                    "the login is who took responsibility for the change; it is kept with \
                     the decision it signed, for the same one question",
                ),
                "Your answer on a review request: whether you approved or denied the step, \
                 the comment you left, when you answered, and the signature that tells the \
                 run who decided.",
            ),
            set(
                OUTBOX_TABLE,
                "subject",
                Disposition::Erase,
                "A decision waiting to be dispatched back to the repository, keyed to you so \
                 it can be delivered and found if you ask for your data.",
            ),
        ];
        SETS
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [MIGRATION_INIT];
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations { sqlite: &MIGRATIONS, postgres: &[] }
    }

    /// Four secrets and two URLs, checked together so a misconfigured
    /// deployment is one report rather than one surprise per request.
    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new("approvals", cfg);
        let mut errors = ConfigError::default();

        for key in ["RUNNER_TOKEN", "SIGNING_SECRET", "GITHUB_TOKEN", "GITHUB_ORGS"] {
            if module.get_opt(key).is_none_or(|value| value.trim().is_empty()) {
                errors.push(format!("approvals: {} is required", module.key(key)));
            }
        }
        for key in ["PUBLIC_BASE_URL", "GITHUB_API_BASE"] {
            if let Some(raw) = module.get_opt(key)
                && !(raw.starts_with("https://") || raw.starts_with("http://"))
            {
                errors.push(format!(
                    "approvals: {} must be an absolute http(s) URL, got {raw:?}",
                    module.key(key)
                ));
            }
        }
        if let Some(raw) = module.get_opt("MAX_TTL_SECS")
            && !raw.parse::<u64>().is_ok_and(|secs| secs > 0)
        {
            errors.push(format!(
                "approvals: {} must be a positive number of seconds",
                module.key("MAX_TTL_SECS")
            ));
        }

        errors.into_result()
    }

    fn max_body_bytes(&self, _cfg: &dyn Config) -> usize {
        REQUEST_BODY_LIMIT
    }

    fn streaming_routes(&self) -> &'static [StreamRoute] {
        STREAMED
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        handlers::router(ctx)
    }

    /// Delivers the decisions the request path enqueued. Nothing here decides
    /// anything: by the time a row reaches the drain the decision is committed
    /// and signed. A failed dispatch is retried with a backoff, and the outbox
    /// lease is what keeps two ticks from sending it twice.
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(async move {
            let (Some(db), Some(http)) = (ctx.ports.db.clone(), ctx.ports.http.clone()) else {
                return Ok(());
            };
            let config = ModuleConfig::new("approvals", &*ctx.config);
            let Some(token) = config.get_opt("GITHUB_TOKEN") else {
                return Ok(());
            };
            let clock = clock(ctx);
            let api = Arc::new(github::GitHub::new(
                http,
                token,
                config.get_str("GITHUB_API_BASE", github::API_BASE),
            ));
            let report = cratefield_core::Outbox::new(OUTBOX_TABLE)
                .drain_within(
                    &*db,
                    &*clock,
                    &ctx.scheduled,
                    cratefield_core::DrainOptions {
                        limit: 20,
                        lease: time::Duration::minutes(5),
                        subrequests_per_item: 1,
                    },
                    |record| {
                        let api = Arc::clone(&api);
                        let clock = Arc::clone(&clock);
                        async move {
                            match github::dispatch(&api, &record.payload).await {
                                Ok(()) => cratefield_core::Processed::Done,
                                Err(failure) if failure.permanent || record.attempts >= MAX_ATTEMPTS => {
                                    // Repeating this will not make it go out, and a row
                                    // retried for ever is a run parked for ever.
                                    tracing::error!(
                                        attempts = record.attempts,
                                        error = %failure.reason,
                                        cron,
                                        "giving up on an approval dispatch"
                                    );
                                    cratefield_core::Processed::Done
                                }
                                Err(failure) => {
                                    tracing::warn!(error = %failure.reason, cron, "approval dispatch failed; will retry");
                                    cratefield_core::Processed::RetryAt(
                                        clock.now() + backoff(record.attempts),
                                    )
                                }
                            }
                        }
                    },
                )
                .await
                .map_err(|error| Box::new(error) as AnyError)?;
            if report.processed > 0 {
                tracing::info!(processed = report.processed, cron, "delivered approval dispatches");
            }
            Ok(())
        })
    }
}

/// How many times a dispatch is sent before it is given up on. At the doubling
/// below, that is a little over a day of GitHub being down.
const MAX_ATTEMPTS: i64 = 12;

/// A minute, doubling to a quarter of an hour: a run waiting on a GitHub
/// outage is better off retried than abandoned, and the doubling keeps a broken
/// token from burning the budget on every tick.
fn backoff(attempts: i64) -> time::Duration {
    time::Duration::minutes(1_i64 << attempts.clamp(0, 8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::{MapConfig, Module};

    fn config(pairs: [(&str, &str); 5]) -> MapConfig {
        MapConfig(
            pairs.into_iter().map(|(key, value)| (key.to_owned(), value.to_owned())).collect(),
        )
    }

    #[test]
    fn every_problem_in_the_config_is_reported_at_once() {
        let module = Approvals::new();
        let bad = config([
            ("APPROVALS_PUBLIC_BASE_URL", "not-a-url"),
            ("APPROVALS_MAX_TTL_SECS", "never"),
            ("APPROVALS_RUNNER_TOKEN", ""),
            ("APPROVALS_SIGNING_SECRET", ""),
            ("APPROVALS_GITHUB_ORGS", ""),
        ]);
        let errors = module.validate_config(&bad).expect_err("an incomplete config").to_string();
        for key in [
            "APPROVALS_RUNNER_TOKEN",
            "APPROVALS_SIGNING_SECRET",
            "APPROVALS_GITHUB_TOKEN",
            "APPROVALS_PUBLIC_BASE_URL",
            "APPROVALS_MAX_TTL_SECS",
            "APPROVALS_GITHUB_ORGS",
        ] {
            assert!(errors.contains(key), "{key} missing from {errors}");
        }

        let good = config([
            ("APPROVALS_RUNNER_TOKEN", "runner-token"),
            ("APPROVALS_SIGNING_SECRET", "signing-secret"),
            ("APPROVALS_GITHUB_TOKEN", "gh-token"),
            ("APPROVALS_PUBLIC_BASE_URL", "https://approvals.example"),
            ("APPROVALS_GITHUB_ORGS", "keep-shipping"),
        ]);
        module.validate_config(&good).expect("a complete config validates");
    }

    #[test]
    fn the_summary_ceiling_is_reachable_through_the_route_ceiling() {
        // A buffered body stops at the harness's own 64 KiB, so the streamed
        // route is the only way a maximal summary ever reaches this module.
        let module = Approvals::new();
        let streamed = module.streaming_routes();
        let create = streamed
            .iter()
            .find(|route| route.path == "/requests")
            .expect("the create route streams");
        assert!(create.max_bytes > SUMMARY_LIMIT_BYTES);
        assert!(module.max_body_bytes(&MapConfig::default()) > SUMMARY_LIMIT_BYTES);
    }
}
