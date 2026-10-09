# GitLab CI

How a run identifies itself inside a GitLab pipeline, and how the pipeline hands
the run off to a person. The adapter is `GitlabCiRunContext`
(`crates/cli/src/gitlab_ci_run_context.rs`)
([#131](https://github.com/Keep-Shipping/harness/issues/131)); it fills the
[`RunContext`](https://docs.rs/ks-core/latest/ks_core/ports/run_context/trait.RunContext.html)
port — `actor` / `event` / `capabilities` / `workspace` / `oidc_token` — for the
second native CI integration decided in
[ADR 0008](adr/0008-github-actions-first.md).

Like the GitHub Actions adapter, it never reads the ambient environment: the
caller hands it a `&BTreeMap<String, String>` snapshot
(`GitlabCiRunContext::from_env`), so the decision is pure and testable.

The flow: a job declares `id_tokens: KEEP_SHIPPING_ID_TOKEN: { aud:
keepshipping }`; GitLab mints the JWT **before the job starts** and passes it in
as an ordinary variable (there is no token endpoint on GitLab, and therefore no
HTTP client in the adapter); `from_env` reads its `iss` and `sub` into the
actor; a step that needs a person parks the run, writes
`.keepshipping/runs/<run>/state.json` and exits 4 (`waiting_for_approval` — see
[CLI.md](CLI.md)), and a human's answer lets a later job resume from that state.

A pipeline whose jobs declare no `id_tokens:` token is not describable honestly —
a strong establishment requires one — so the constructor returns
`GitlabCiError::NotGitlabCi { missing }` and the caller falls back to the local
adapter.

## The variables

| What the adapter reads | GitLab's variable | What it becomes |
|---|---|---|
| the sentinel | `GITLAB_CI=true` | the gate; anything else is not a GitLab job |
| the commit | `CI_COMMIT_SHA` | `GitInfo::sha` |
| the checkout | `CI_PROJECT_DIR` | `Workspace::root` |
| the ref name | `CI_COMMIT_REF_NAME` | `GitInfo::git_ref`, under `refs/heads/` |
| the tag | `CI_COMMIT_TAG` | `Trigger::Tag` and `refs/tags/<tag>` |
| what started the pipeline | `CI_PIPELINE_SOURCE` | `Trigger`, and the first half of the provenance answer |
| the merge request | `CI_MERGE_REQUEST_IID`, `CI_MERGE_REQUEST_REF_PATH` | `Trigger::PullRequest`, `refs/merge-requests/<iid>/head` |
| where the head branch lives | `CI_MERGE_REQUEST_SOURCE_PROJECT_ID` | one half of the fork test, against the row below |
| where the merge request lands | `CI_MERGE_REQUEST_PROJECT_ID` | the other half of the fork test |
| who triggered it | `GITLAB_USER_LOGIN`, else the token's `user_login`, else its `sub` | `Actor::display_name` |
| the identity | `KEEP_SHIPPING_ID_TOKEN` | `Establishment::CiOidc`, and `oidc_token`'s answer |

Those three are GitLab's own predefined variables, set by the platform rather than
written by the pipeline author. The two project ids are set on a merge-request
pipeline and nowhere else, which is why a push pipeline never has a pair of ids that
can disagree with each other.

Every name above is in GitLab's
[predefined variables reference](https://docs.gitlab.com/ci/variables/predefined_variables/);
the token is the one GitLab mints, whose claims are documented under
[ID tokens](https://docs.gitlab.com/ci/secrets/id_token_authentication/).

**GitLab has no merge-request-author variable.** Nothing in the predefined
variables for an MR pipeline names who opened it, and the ID token does not carry
an author claim either — its `user_login` is the user *executing the job*. So the
actor is who triggered the pipeline: on a merge request from a fork, that is the
fork's own contributor. Treat this as "who ran it", never as "who wrote it".

`CI_COMMIT_REF_NAME` is a bare name (`main`, `v1.2.3`), so the adapter builds the
ref itself — the `RunContext` contract requires a `git_ref` under `refs/`, and a
`Tag` trigger's ref to be exactly `refs/tags/<name>`.

## The id token

`oidc_token(audience)` hands back the pre-minted token, but only after reading
its `aud` claim and checking it names the audience that was asked for. GitLab
lets a job declare any `aud` it likes, so a token minted for `keepshipping` is
not automatically a credential for the cloud account somebody else's step asked
for. A token whose `aud` is absent, malformed, or a list that does not include
the caller gets `RunContextError::OidcUnavailable { audience }` — never the
token. An `aud` that is an array of strings is accepted when it contains the
caller.

A run whose provenance is untrusted gets none of it. Such a context carries
`oidc: false`, so `oidc_token` answers `OidcUnavailable` for every audience —
including the one the job's pre-minted token's `aud` names exactly. Otherwise the
failure would be the token's, and the pipeline that asked for that token is the one
whose code is under test. See [Fork merge requests](#fork-merge-requests).

## The trigger

| `CI_PIPELINE_SOURCE` | trigger |
|---|---|
| `merge_request_event` | `PullRequest { number }` from `CI_MERGE_REQUEST_IID`, falling back to `Push` when it is missing or unparseable |
| `web`, `api`, `trigger`, `chat`, `webide`, `schedule` | `Manual` — a person, or a scheduled prompt, asked for it |
| `push` with a non-empty `CI_COMMIT_TAG` | `Tag { name }` |
| anything else (`push` on a branch, `external`, `parent_pipeline`, `pipeline`) | `Push` |

A branch with an open merge request produces **both** a `push` pipeline and a
`merge_request_event` pipeline, so `merge_request_event` is matched first rather
than derived from the ref.

The agent/human split has one fewer piece of evidence here than on GitHub: GitLab
has no `user.type` and no event payload to read a proposer out of, so the
organisation's `ActorBaseline` list is what says a login is an agent's — and a
baseline that names the triggering user an agent's makes the run an
`ActorKind::Agent` run without weakening its establishment.

## The hand-off

[`templates/gitlab/keepshipping.yml`](../templates/gitlab/keepshipping.yml) is
the include-able template: an `include:remote:` file rather than a CI/CD
component, because a component is addressed within one instance's own component
library while a template in any public git repository can be included by every
instance.

```yaml
include:
  - remote: https://raw.githubusercontent.com/Keep-Shipping/harness/main/templates/gitlab/keepshipping.yml
```

The gate is a `when: manual` job with `allow_failure: false`. GitLab has two
ways to require a person — a protected environment with deployment approvals,
and a blocking manual job — and only the second is available on every tier:
[protected environments and their approval rules](https://docs.gitlab.com/ci/environments/protected_environments/)
are Premium/Ultimate, so the free-tier path is the manual job.
`allow_failure: false` is the load-bearing part; with the default `true`, GitLab
would let the pipeline finish green without the gate ever being answered.

## Fork merge requests

GitLab runs a fork's merge-request pipelines **in the fork**, on the fork's own
variables and runners. So there are no parent project secrets in that job to leak
— nothing protected is handed to code the fork's author controls — but there are
no protected variables either: `id_tokens:` works (GitLab mints the token for
the fork project, so the identity is the fork's), while anything the parent marked
protected or masked is simply absent.

That is the platform's model. The adapter does not rest on it: a classification that
depends on a property of the platform is a property of somebody else's deployment,
and the answer the harness gives has to hold wherever the job runs. So the code the
job is *about* is classified separately, from the variables, and it fails closed:

| On GitLab | Provenance |
|---|---|
| `CI_PIPELINE_SOURCE=external_pull_request_event` | a fork, always, whatever the project ids say — a mirror of a pull request from another Git repository is by construction another project's code |
| `merge_request_event`, with `CI_MERGE_REQUEST_SOURCE_PROJECT_ID` differing from `CI_MERGE_REQUEST_PROJECT_ID` | a fork: the head branch lives in another project |
| `merge_request_event`, with either id missing or empty | a fork: a payload the adapter cannot read is not consent |
| `push`, `schedule`, a tag, `web`, and a merge request whose two ids are equal | the repository's own code |

The third row is the one that matters most, and it is deliberate. Only a
merge-request pipeline sets those two ids at all, so nothing ordinary is condemned by
it — but a runner that withholds `CI_MERGE_REQUEST_SOURCE_PROJECT_ID` gets an untrusted
run rather than a trusted one. Trust is an affirmative claim, never a default that
silence falls into.

An untrusted run keeps its identity: it still establishes *who* is running, which is
a different question from whose code it is about. What it loses is everything that
hands its code a credential — the context is built with `oidc: false` (see [The id
token](#the-id-token)), so a `role:` cannot be federated, and the policy gate offers
it no secret resolver: no `apply`, no `deploy`, no `destroy`, no secret reads. `build`
and `plan` still run.

## Known limits

- **The token's signature is not verified.** GitLab signs ID tokens with RS256
  and publishes the key at the instance's OIDC discovery document, but this crate
  carries no JWT or JWKS machinery: the three segments are decoded and the claims
  are taken at face value. `Establishment::CiOidc` and
  `IdentityStrength::Strong` therefore mean *"handed to this job by GitLab as an
  `id_tokens:` variable"*, never *"cryptographically verified"*. Anything that
  rests access control on the identity — a server exchanging the token for a
  cloud credential — must check the signature against GitLab's JWKS, and the
  `iss`/`aud`/`exp` claims, itself first.
- **The token is short-lived and single-purpose.** It is minted for the job and
  dies with it (GitLab expires it at the job timeout, or five minutes); a step
  that parks for approval and resumes in another job gets a different token.
- **The adapter is not wired into dispatch yet.** Like the GitHub Actions one,
  it is built and tested but unreachable from `run` until CI-versus-local
  selection lands. What has reached production is its provenance reader:
  `keepshipping resume` classifies a GitLab run with it (see
  [CREDENTIALS.md](CREDENTIALS.md#what-the-harness-itself-does)), which is where
  a fork's `ship.ks` is actually refused.

## See also

- [ADR 0008](adr/0008-github-actions-first.md) — GitLab CI as the second native
  integration
- [CLI.md](CLI.md) — exit code 4, `waiting_for_approval`