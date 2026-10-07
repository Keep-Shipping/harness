//! The [`PolicyStore`] port: an org's baseline policy, read from outside the
//! repository ([#56](https://github.com/Keep-Shipping/harness/issues/56),
//! [ADR 0012](https://github.com/Keep-Shipping/harness/blob/main/docs/adr/0012-policy-authority.md)).
//!
//! ADR 0012's whole problem is that `ship.ks` is the file a coding agent can
//! write: an agent that can add a step can move `apply` from `ask:` to `can:`.
//! The baseline is the answer — a policy that lives in an org repository, a CI
//! variable or a hosted store, which a workflow file cannot author. This port
//! is the read of one such baseline document; the intersection with the file's
//! own `policy:` block is
//! [#101](https://github.com/Keep-Shipping/harness/issues/101).
//!
//! What this port deliberately does *not* do:
//!
//! - **It has no write path.** ADR 0012: "The port is a read of one baseline
//!   document — it has no write path, because a workflow file must never be
//!   able to author the thing that constrains it." There is no `set_baseline`,
//!   no `approve`, no method at all that mutates authority. If a caller can
//!   write the baseline, the control is decorative.
//! - **It does not intersect.** Nothing here reads a `ship.ks`, and nothing
//!   here decides what an effective policy is. A [`Baseline`] is one input to
//!   that computation, which lives elsewhere.
//! - **"No baseline configured" is not an error.** ADR 0012 makes it a
//!   first-class state that "anything that reads the effective policy must
//!   handle as a first-class state, not as an error", so
//!   [`baseline`](PolicyStore::baseline) returns `Ok(None)` and
//!   [`effective_baseline`] decides what absence means. Absence is not
//!   failure; it is a configuration that has not happened yet.
//!
//! The default when nothing is configured is conservative and fails closed:
//! see [`Baseline::conservative`].

use std::fmt;

use super::BoxFuture;
use crate::ports::run_context::ActorKind;

/// What a rule says about one action.
///
/// The [`Ord`] derive orders the variants **least restrictive to most
/// restrictive** — `Allow < Ask < Never`. That is a convenience ordering, not a
/// severity ranking, and it is deliberately *not* how two policies are to be
/// combined: [`Baseline::decide`] is first-match-wins and never compares two
/// dispositions, because "intersect two baselines by taking the max" is
/// fail-open reasoning written down (`max(Ask, Allow) == Allow`). A caller that
/// wants the strictest of two answers must say [`Disposition::Never`] (or take
/// the strictest by hand), not reach for `.max()` or `.min()` and trust the
/// derive. Intersecting baselines at all is
/// [#101](https://github.com/Keep-Shipping/harness/issues/101); what this enum
/// promises is only that its own order reads the way the rule names read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Disposition {
    /// No prompt; the action may proceed.
    Allow,
    /// Ask a human. The default for anything no rule names.
    Ask,
    /// Refused outright, whoever is acting.
    Never,
}

impl Disposition {
    /// The lowercase wire and display form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Disposition::Allow => "allow",
            Disposition::Ask => "ask",
            Disposition::Never => "never",
        }
    }
}

impl fmt::Display for Disposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a baseline document lives — the three adapters ADR 0012 lists, in the
/// order a company adopts them.
///
/// This is an inventory of *where to look*, not a configuration format: no
/// method here fetches anything, and no rule in a [`Baseline`] is bound to one
/// of these. It exists so an operator asking "which of these is in use?" has a
/// vocabulary to answer with, and so a baseline document can say where it came
/// from without the port having to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineSource {
    /// An org `.keepshipping` repository, read at `git_ref` — the first thing a
    /// company adopts, because a policy reviewed in pull requests is one they
    /// can still reason about.
    RepoFile {
        /// The org that owns the baseline repository.
        org: String,
        /// The path of the baseline document within it.
        path: String,
        /// The ref to read: a branch, a tag or a commit. Never a moving
        /// symbolic default the reader resolves for itself.
        git_ref: String,
    },
    /// A CI variable carrying the baseline as text, for an org that would
    /// rather not run a second repository.
    Variable {
        /// The variable's name.
        name: String,
    },
    /// A hosted store, the only option that needs one of us.
    Hosted {
        /// Where it is served from.
        location: String,
    },
}

/// Where one rule came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    /// The built-in conservative default, not a document anyone wrote. ADR
    /// 0012's `keepshipping policy explain` owes an operator the difference
    /// between "we decided this" and "someone chose this", and this is how it
    /// knows.
    Default,
    /// A baseline document, and where that document was read from.
    Baseline {
        /// The document's home.
        source: BaselineSource,
    },
}

/// Who a rule binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// One kind of principal — an agent run, a human run, a CI run.
    Actor(
        /// Which kind: the rule binds this principal and no other.
        ActorKind,
    ),
    /// Every principal, whatever kind.
    ///
    /// This exists because the conservative default forbids `destroy` and
    /// `secrets` for *everyone*, and enumerating one `Actor` per
    /// [`ActorKind`] variant would be wrong twice over: adding a variant to
    /// `ActorKind` would silently leave that principal unprotected, and a rule
    /// that reads "never, for the three kinds we know" is a weaker claim than
    /// the one being made. `Any` cannot forget a kind that does not exist yet.
    Any,
}

/// One rule: who may do what, and what happens if they try.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Who the rule binds.
    pub subject: Subject,
    /// The action class (`check`, `build`, `destroy`, `read`, …).
    pub verb: String,
    /// The environment the action names, or [`ANY_OBJECT`] for every one.
    pub object: String,
    /// What the rule says.
    pub disposition: Disposition,
    /// Where this rule came from.
    pub provenance: Provenance,
}

/// The object that stands for every environment, so one rule can cover `prod`,
/// `staging` and an environment that does not exist yet.
///
/// A concrete environment name binds exactly. A baseline that must name five
/// environments to allow a `check` on each is a baseline that quietly forbids
/// the sixth; `*` is how a rule says what it means once.
pub const ANY_OBJECT: &str = "*";

/// An org's baseline policy: the rules, and where the document they came from
/// was read.
///
/// `source` is `None` only for [`Baseline::conservative`], the built-in default,
/// which no document produced. A `Some` says a document was read, and every
/// rule it carried is attributed to it — a rule with
/// [`Provenance::Default`] in a baseline that claims a source would be the
/// built-in wearing someone else's authority, which is exactly the confusion
/// `explain` exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    /// The rules, in declaration order.
    ///
    /// Order is load-bearing, not presentational: [`decide`](Baseline::decide)
    /// takes the first rule that matches, so the document is read top to
    /// bottom. A baseline is a deny-first list, so the strict rules come first.
    pub rules: Vec<Rule>,
    /// The document these rules were read from, or `None` for the built-in
    /// default.
    pub source: Option<BaselineSource>,
}

impl Baseline {
    /// The conservative built-in: what applies when nothing is configured.
    ///
    /// Agents may `check`, `build` and `plan`. Two things are never, for any
    /// principal:
    ///
    /// - **`secrets`**, under any verb the default knows. Not "`read` on
    ///   `secrets`" — *secrets*. An adapter that reaches a secret store
    ///   through an action class this crate has never heard of must not
    ///   thereby talk its way past the refusal, so the `secrets` rules name
    ///   every verb the allows below grant, and they come first. A verb this
    ///   default has never heard of is `Ask` on `secrets` too, so nothing here
    ///   is ever an `Allow` on a secret.
    /// - **`destroy`**, under any environment and whoever is acting.
    ///
    /// **Everything else asks.** A verb this default has never heard of is
    /// [`Disposition::Ask`], not [`Disposition::Allow`], because an allowlist
    /// that defaults to allow is not one.
    ///
    /// The `Never` rules are declared before the `Allow` rules, and that is
    /// what makes them stick: [`decide`](Baseline::decide) is first-match-wins
    /// in declaration order, so an `Allow` further down the list cannot rescue
    /// what a `Never` above it refuses.
    ///
    /// This is deliberately stricter than an unconfigured organization needs
    /// to be usable, and it is the point: the unconfigured case must not be a
    /// hole. A company that wants `deploy` to run unattended configures a
    /// baseline that says so.
    #[must_use]
    pub fn conservative() -> Baseline {
        let never = Provenance::Default;
        let mut secrets = vec![Rule {
            subject: Subject::Any,
            verb: "read".to_string(),
            object: "secrets".to_string(),
            disposition: Disposition::Never,
            provenance: never.clone(),
        }];
        // Every verb the allows below grant, denied on `secrets` first: an
        // action class is a name this crate chose, and a rule that only
        // refused the word "read" would be a rule an adapter could walk around
        // by calling the same read something else.
        for verb in ["check", "build", "plan"] {
            secrets.push(Rule {
                subject: Subject::Any,
                verb: verb.to_string(),
                object: "secrets".to_string(),
                disposition: Disposition::Never,
                provenance: never.clone(),
            });
        }
        let mut rules = vec![Rule {
            subject: Subject::Any,
            verb: "destroy".to_string(),
            object: ANY_OBJECT.to_string(),
            disposition: Disposition::Never,
            provenance: never.clone(),
        }];
        rules.append(&mut secrets);
        rules.extend([
            Rule {
                subject: Subject::Actor(ActorKind::Agent),
                verb: "check".to_string(),
                object: ANY_OBJECT.to_string(),
                disposition: Disposition::Allow,
                provenance: never.clone(),
            },
            Rule {
                subject: Subject::Actor(ActorKind::Agent),
                verb: "build".to_string(),
                object: ANY_OBJECT.to_string(),
                disposition: Disposition::Allow,
                provenance: never.clone(),
            },
            Rule {
                subject: Subject::Actor(ActorKind::Agent),
                verb: "plan".to_string(),
                object: ANY_OBJECT.to_string(),
                disposition: Disposition::Allow,
                provenance: never,
            },
        ]);
        Baseline { rules, source: None }
    }

    /// What `subject` is permitted to do `verb` on `object`.
    ///
    /// Pure: no I/O, no adapter, no clock, so it is callable from the same
    /// offline path as `check`.
    ///
    /// **First match wins, in declaration order.** A rule matches when its verb
    /// is exactly `verb`, its subject is [`Subject::Any`] or exactly `subject`,
    /// and its object is [`ANY_OBJECT`] or exactly `object`. The first rule in
    /// [`rules`](Baseline::rules) that matches decides, and nothing later in the
    /// list is consulted — so a baseline is a deny-first list, and the strict
    /// rules are declared first. That is a convention the caller can check by
    /// reading the document, and the built-in
    /// [`Baseline::conservative`] follows it.
    ///
    /// **The obligation this puts on whoever writes a [`Baseline`].** A
    /// producer of one — an org policy document, an adapter that synthesises a
    /// baseline — is responsible for listing deny rules before allow rules,
    /// because under first-match-wins an `Allow` declared *later* rescues an
    /// earlier `Never`: `(Any, destroy, prod) → Never` followed by
    /// `(Agent, destroy, *) → Allow` decides `Allow` for an agent on `prod`.
    /// Nothing in the type forbids that document, and a reader of a baseline
    /// cannot tell a deliberate ordering from a careless one. Both halves of
    /// that are shown by
    /// `an_allow_declared_after_a_matching_never_cannot_rescue_it` below,
    /// which exhibits the rescue.
    /// [`Baseline::conservative`] gets it right internally by declaring every
    /// `Never` above every `Allow`.
    ///
    /// Scoring the rules for "how specific" was the alternative, and it is
    /// worse. It does not remove the ordering requirement — it replaces it with
    /// a rule the caller cannot see, and one whose answer depends on an
    /// arbitrary priority *between* axes. With subject scored ahead of object,
    /// a `Never` for `(Any, "destroy", "prod")` loses to a later `Allow` for
    /// `(Agent, "destroy", "*")`, because naming the subject outranks naming
    /// the environment. That is a fail-open outcome, and it is invisible at
    /// the call site: nothing about `decide`'s signature hints that a
    /// narrower-looking refusal can be overturned.
    ///
    /// **No match is [`Disposition::Ask`]**, which is the fail-closed half of
    /// this function and the property worth stating out loud: a baseline that
    /// forgot a rule permits nothing, and permits nothing *without saying so*,
    /// because the answer a caller gets back is an explicit `Ask`.
    #[must_use]
    pub fn decide(&self, subject: ActorKind, verb: &str, object: &str) -> Disposition {
        for rule in &self.rules {
            if rule.verb != verb {
                continue;
            }
            if let Subject::Actor(kind) = rule.subject
                && kind != subject
            {
                continue;
            }
            if rule.object != ANY_OBJECT && rule.object != object {
                continue;
            }
            return rule.disposition;
        }
        Disposition::Ask
    }
}

/// The baseline in force, given what the store was asked for.
///
/// `None` — no baseline configured, which ADR 0012 calls a first-class state
/// rather than an error — yields [`Baseline::conservative`]. `Some` is
/// returned untouched: this function does not intersect with anything, does
/// not validate what it was handed, and does not invent a rule. Widening and
/// narrowing are #101's business.
#[must_use]
pub fn effective_baseline(configured: Option<Baseline>) -> Baseline {
    configured.unwrap_or_else(Baseline::conservative)
}

/// Why a [`PolicyStore`] read failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyStoreError {
    /// The backend itself failed: transport, credentials, a repository that
    /// would not open. What the backend reported, safe to print. Never a
    /// baseline's contents — a policy document is not a secret, but an error
    /// string is the wrong place for one anyway.
    Backend {
        /// What went wrong, safe to print.
        message: String,
    },
}

impl fmt::Display for PolicyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyStoreError::Backend { message } => write!(f, "policy store failed: {message}"),
        }
    }
}

impl std::error::Error for PolicyStoreError {}

/// The `PolicyStore` port: read an org's baseline policy, and nothing else.
///
/// One method, deliberately. There is no way to write, amend or approve a
/// baseline through this trait — ADR 0012 gives the reason in one line: "a
/// workflow file must never be able to author the thing that constrains it". A
/// port that could set the baseline would let every caller that holds it set
/// the baseline, and the read would be theatre.
pub trait PolicyStore: Send + Sync {
    /// Reads the baseline for `org`/`repo`, or `Ok(None)` when the org has not
    /// configured one.
    ///
    /// `Ok(None)` is a configuration that has not happened, not a failure to
    /// find one: an org with no baseline is the normal state of every org on
    /// day one, and reporting it as an error would train callers to treat
    /// "unprotected" as a crash. Callers that need a policy either way go
    /// through [`effective_baseline`].
    fn baseline<'a>(
        &'a self,
        org: &'a str,
        repo: &'a str,
    ) -> BoxFuture<'a, Result<Option<Baseline>, PolicyStoreError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: ?Sized + Send + Sync>() {}

    #[test]
    fn the_policy_store_trait_is_dyn_compatible() {
        assert_send_sync::<dyn PolicyStore>();
    }

    #[test]
    fn dispositions_display_as_their_wire_form() {
        assert_eq!(Disposition::Allow.as_str(), "allow");
        assert_eq!(Disposition::Ask.to_string(), "ask");
        assert_eq!(Disposition::Never.as_str(), "never");
    }

    #[test]
    fn store_errors_display_actionably() {
        let message = PolicyStoreError::Backend { message: "404".to_string() }.to_string();
        assert!(message.contains("policy store") && message.contains("404"), "{message}");
    }

    /// The conservative default, asserted as the issue states it: an agent may
    /// check, build and plan; an agent verb the default has never heard of asks;
    /// and `destroy` and `secrets` are never — for a human and an agent alike,
    /// and for CI, and whatever the verb.
    #[test]
    fn a_new_baseline_decides_allow_ask_never() {
        let baseline = Baseline::conservative();
        assert_eq!(baseline.source, None, "the built-in default came from no document");

        for verb in ["check", "build", "plan"] {
            assert_eq!(
                baseline.decide(ActorKind::Agent, verb, "prod"),
                Disposition::Allow,
                "an agent may {verb}"
            );
        }

        // Not named by any rule: an ask, never a silent allow.
        assert_eq!(baseline.decide(ActorKind::Agent, "deploy", "prod"), Disposition::Ask);
        assert_eq!(baseline.decide(ActorKind::Agent, "publish", "prod"), Disposition::Ask);

        // The two hard rules, for every principal and every environment.
        for actor in [ActorKind::Human, ActorKind::Agent, ActorKind::Ci] {
            assert_eq!(
                baseline.decide(actor, "destroy", "prod"),
                Disposition::Never,
                "{actor:?} never destroys"
            );
            assert_eq!(
                baseline.decide(actor, "destroy", "anything-at-all"),
                Disposition::Never,
                "{actor:?} never destroys, in any environment"
            );
            assert_eq!(
                baseline.decide(actor, "read", "secrets"),
                Disposition::Never,
                "{actor:?} never reads secrets"
            );
        }

        // Secrets are refused whatever the verb is called. A refusal that named
        // only the literal word "read" would be one an adapter walks around by
        // naming the same read something else, so the default refuses
        // `secrets` under the verbs it otherwise allows too.
        for actor in [ActorKind::Human, ActorKind::Agent, ActorKind::Ci] {
            for verb in ["check", "build", "plan"] {
                assert_eq!(
                    baseline.decide(actor, verb, "secrets"),
                    Disposition::Never,
                    "{actor:?} never reaches secrets, however the action is named"
                );
            }
        }
        assert_eq!(
            baseline.decide(ActorKind::Agent, "check", "secrets"),
            Disposition::Never,
            "an allowed verb does not become an allowed read of secrets"
        );

        // A human running the same actions the agent may is still asked.
        assert_eq!(baseline.decide(ActorKind::Human, "check", "prod"), Disposition::Ask);
    }

    /// No baseline configured is a state, not an error, and it resolves to the
    /// conservative default rather than to nothing at all.
    #[test]
    fn an_unconfigured_store_yields_the_conservative_baseline() {
        let baseline = effective_baseline(None);
        assert_eq!(baseline, Baseline::conservative());
        assert_eq!(baseline.decide(ActorKind::Agent, "check", "staging"), Disposition::Allow);
        assert_eq!(baseline.decide(ActorKind::Agent, "destroy", "staging"), Disposition::Never);

        // A configured baseline is passed through untouched.
        let configured = Baseline {
            rules: vec![Rule {
                subject: Subject::Actor(ActorKind::Agent),
                verb: "deploy".to_string(),
                object: "prod".to_string(),
                disposition: Disposition::Allow,
                provenance: Provenance::Baseline {
                    source: BaselineSource::RepoFile {
                        org: "acme".to_string(),
                        path: ".keepshipping/policy.ks".to_string(),
                        git_ref: "main".to_string(),
                    },
                },
            }],
            source: Some(BaselineSource::RepoFile {
                org: "acme".to_string(),
                path: ".keepshipping/policy.ks".to_string(),
                git_ref: "main".to_string(),
            }),
        };
        assert_eq!(effective_baseline(Some(configured.clone())), configured);
    }

    /// Order is the whole rule: the first matching rule decides, and a later
    /// one is never consulted.
    ///
    /// The narrow allow here is deliberately *narrower* than the broad `Never`
    /// above it — it names both a subject and an environment where the `Never`
    /// names neither and one. If specificity were scored, the narrower rule
    /// would win and the refusal would be overturned. Under first-match-wins
    /// the `Never` holds, which is what makes "declare the strict rules first"
    /// a rule anyone can check by reading the list.
    #[test]
    fn an_allow_declared_after_a_matching_never_cannot_rescue_it() {
        let source = BaselineSource::Hosted { location: "https://policy.example.com".to_string() };
        let never_first = Baseline {
            rules: vec![
                Rule {
                    subject: Subject::Any,
                    verb: "destroy".to_string(),
                    object: "prod".to_string(),
                    disposition: Disposition::Never,
                    provenance: Provenance::Baseline { source: source.clone() },
                },
                Rule {
                    subject: Subject::Actor(ActorKind::Agent),
                    verb: "destroy".to_string(),
                    object: ANY_OBJECT.to_string(),
                    disposition: Disposition::Allow,
                    provenance: Provenance::Baseline { source: source.clone() },
                },
            ],
            source: Some(source.clone()),
        };
        assert_eq!(never_first.decide(ActorKind::Agent, "destroy", "prod"), Disposition::Never);

        // The mirror image is the caller's responsibility: put the allow
        // first and it wins, for the very same probe.
        let allow_first = Baseline {
            rules: vec![
                Rule {
                    subject: Subject::Actor(ActorKind::Agent),
                    verb: "destroy".to_string(),
                    object: ANY_OBJECT.to_string(),
                    disposition: Disposition::Allow,
                    provenance: Provenance::Baseline { source: source.clone() },
                },
                Rule {
                    subject: Subject::Any,
                    verb: "destroy".to_string(),
                    object: "prod".to_string(),
                    disposition: Disposition::Never,
                    provenance: Provenance::Baseline { source },
                },
            ],
            source: Some(BaselineSource::Hosted {
                location: "https://policy.example.com".to_string(),
            }),
        };
        assert_eq!(allow_first.decide(ActorKind::Agent, "destroy", "prod"), Disposition::Allow);
    }
}
