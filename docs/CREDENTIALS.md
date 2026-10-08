# Per-step cloud credentials

A plan reads your cloud; an apply writes to it. Not the same permission, not the
same step.

keepshipping gives each step its **own** `role:` — the plan step federates into a
read-only role, the apply step into a write one. They are separate assumptions
held by separate steps, so an agent handed only the plan step's credentials
cannot apply with them: it would have to reach a role it was never issued a token
for. The least privilege is structural, and does not depend on the agent
behaving itself.

```ks
name: infra
steps:
  plan:   tofu.plan
    dir:   ./infra/prod
    role:  "arn:aws:iam::123456789012:role/ks-plan"

  review: approval
    show:  plan.changes
    from:  @platform

  apply:  tofu.apply
    plan:  plan.file              # the exact plan that was approved
    role:  "arn:aws:iam::123456789012:role/ks-apply"
```

`role:` is optional, and declared only on `tofu.plan` and `tofu.apply` — any
other step rejects it as an undeclared input. Both spellings parse: an AWS IAM
role ARN or an Azure application (client) id. A string that is neither is
refused by `ks_engine::credentials::CloudRole::parse`, which the run loop will
call as the `role:` is read. Local runs do not assume a role — see below.

## What the run log records

Each step that resolves credentials emits one entry, so the log answers "which
role did this step hold" without ever holding a token:

```
00:00:12  credentials.resolved  cloud=aws  role=arn:aws:iam::123456789012:role/ks-plan  step=plan  via=oidc
00:01:44  credentials.resolved  cloud=aws  role=arn:aws:iam::123456789012:role/ks-apply  step=apply  via=oidc
```

`cloud` is `aws` or `azure`; `role` is absent when nothing was assumed; `via` is
`oidc`, `profile:<name>` or `ambient`. Read it back with `keepshipping log
[RUN-ID]`.

The token is never in the log, nor in a subprocess's environment — a token in an
environment vector is readable by anything that can read `/proc`. An adapter
writes it to a file and passes the *path*:

| Step | Environment it is given |
|---|---|
| AWS, federated | `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_SESSION_NAME` |
| Azure, federated | `ARM_USE_OIDC=true`, `ARM_CLIENT_ID`, `ARM_OIDC_TOKEN_FILE_PATH` |
| Anything local | nothing — it inherits your own environment |

## AWS: OIDC federation

Two IAM roles and one OIDC provider, in the account holding the roles.

**The provider:**

```json
{
  "Url": "https://token.actions.githubusercontent.com",
  "ClientIDList": ["sts.amazonaws.com"],
  "ThumbprintList": ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}
```

**The plan role** — read-only, trusted by any branch:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:ORG/REPO:*"
      }
    }
  }]
}
```

Read-only means the provider's own read access plus what a plan genuinely needs:
`s3:GetObject`/`s3:ListBucket` on the state bucket, and the three
`dynamodb:*Item` verbs on the lock table — a plan takes the lock even though it
writes nothing. Start from `ReadOnlyAccess` and subtract.

**The apply role** is the same document with one line changed, and it is the
line that matters:

```json
"token.actions.githubusercontent.com:sub": "repo:ORG/REPO:environment:prod"
```

That subject only exists for a job declaring `environment: prod` — a reviewer
approved the deployment. The apply role carries write permissions; the plan role
does not.

## Azure: a federated credential

Create an app registration, then a federated credential on its service
principal with issuer `https://token.actions.githubusercontent.com` and subject
`repo:ORG/REPO:environment:prod` — the same split as AWS. Give the plan identity
**Reader**, the apply identity **Contributor**. The workflow sets
`ARM_TENANT_ID` and `ARM_SUBSCRIPTION_ID`; keepshipping federates the step with
a token minted for the audience `api://AzureADTokenExchange`.

## GCP: not built yet

Per-step federation on GCP is **not** implemented: `CloudRole::parse` accepts no
GCP shape and the error says so. Use application default credentials (`gcloud
auth application-default login`) — ADC is ambient credentials, one identity for
every step, no plan/apply split.

## GitHub Actions: two files, two jobs

The plan and the apply are separate steps with separate roles, and they are also
separate amounts of trust. `on: pull_request` is the correct trigger for a `ship.ks`
nobody in the organisation wrote — it is what GitHub's own hardening guidance,
*Security hardening for GitHub Actions*, tells you to use — but a trigger on its own
is not a boundary. It bounds anything only if the job that runs on it has nothing to
hand the code it just checked out.

So put the two halves in two **files**. The trust boundary in a GitHub Actions
repository is the file boundary, and the give-away that a repository has not made it
is a single workflow file carrying both `pull_request` and an `apply` job with
`id-token: write` on it. That file is one step away from handing a fork the apply
role: the fork edits `ship.ks`, the workflow file is unchanged and still declares the
apply job, and the apply job still federates. The trigger was correct and irrelevant.

### `.github/workflows/plan.yml` — untrusted code, no credentials

```yaml
name: infra (plan only)
on:
  pull_request:

jobs:
  plan:
    # Everything a fork can reach: the repository, read-only.
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: keepshipping run ship.ks --until plan --non-interactive
```

There is no `id-token: write` here, so GitHub mints no OIDC token for the job at all
and a `role:` on any step has nothing to federate — the step fails with the error
below rather than quietly falling back to the job's secrets. That failure is GitHub's,
not the harness's: it follows from the permission block alone. There is no
`environment:`, so there is no environment subject for anything to claim, and no
secrets are passed to the step. `--until plan` runs the plan and what it depends on
and stops: it parks a plan file, it does not apply it. `resume` consults the policy
gate (*the harness itself*, below), which treats `build` and `plan` as the actions an
untrusted run may reach — exactly the set this job runs; `run` does not consult it
yet.

Note what this job's plan is for: telling you whether the pull request builds. It is
not the plan that lands. The plan that lands is made in the trusted half, under the
trusted role, so the artifact that reaches production was produced by code the
organisation wrote.

### `.github/workflows/apply.yml` — trusted code, credentials

The template as it stands today, moved onto a trigger that only this repository's own
code can fire:

```yaml
name: infra
on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  plan:
    permissions:
      contents: read
      id-token: write          # without this, `role:` cannot be federated
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: keepshipping run ship.ks --until plan --non-interactive

  apply:
    needs: plan
    permissions:
      contents: read
      id-token: write
    runs-on: ubuntu-latest
    environment: prod          # this makes the subject environment-scoped
    steps:
      - uses: actions/checkout@v4
      - run: keepshipping run ship.ks --only apply --non-interactive
```

The apply job sits behind a GitHub *environment*, so its OIDC subject is the
environment's — `repo:ORG/REPO:environment:prod` — which is the line the apply
role's trust policy names and the plan role's does not.

`workflow_run` works here too, and is worth knowing about: it fires when the
untrusted workflow finishes, and the privileged half runs the *default branch's*
workflow file. That is why `actions/checkout` on a `workflow_run` job checks out the
default branch rather than the pull request head — pin `ref:` explicitly if you want
it to, and never check out `github.event.pull_request.head.sha`, which is the code
under test. `push` to the default branch and `workflow_dispatch` have no such
ambiguity, which is why they are what is shown above.

`--until plan` runs the plan and what it depends on, and stops; `--only apply`
runs the apply alone against the parked plan file. A resume refuses to continue
if `ship.ks` no longer hashes to the digest the run parked
([`ks_engine::state::resume`](../crates/engine/src/state.rs)), so an apply
cannot land a plan nobody reviewed.

If a job forgets `id-token: write`, the step fails rather than quietly falling
back to the job's long-lived `AWS_ACCESS_KEY_ID` secrets. The error names the
step and the fix:

```
step `apply` asks for "arn:aws:iam::123456789012:role/ks-apply" but this CI job
cannot federate into it: the run context has no OIDC token. Grant the job
`permissions: id-token: write`
```

The fix in that message is right for a trusted job that forgot the permission. It is
the wrong fix for the untrusted job above, which must not have the permission at all —
there the missing `id-token: write` *is* the configuration.

## Why not `pull_request_target`

The obvious way to get the apply half running on pull requests while keeping the base
branch's workflow file is `on: pull_request_target`. It does keep the workflow file —
that is what it is for — and that is the problem. It runs the base branch's file with
a privileged token and a writable repository scope against whatever the pull request
checks out, so an attacker who only controls the *contents* of a pull request gets the
base branch's credentials to run it. That is the exact shape of the vulnerability
[#126](https://github.com/Keep-Shipping/harness/issues/126) is about, and reaching for
`pull_request_target` to keep credentials close to the apply step walks into it.

GitHub's own hardening guidance is unambiguous on the choice: for code you do not
trust, use `pull_request`, and keep the workflow file's privileges minimal. The
guidance does not offer `pull_request_target` as a way to run untrusted code
privately; it lists it among the events that require care precisely because the
privileges come from the base branch while the code comes from the fork.

If you want a privileged half to respond to a pull request, the correct mechanism is
`workflow_run` or `workflow_dispatch` — a *separate* file, on a *separate* trigger,
that checks out code you trust.

## What the harness itself does

> **Partly wired.** Everything in this section is built and tested, and one command
> is connected to it: `keepshipping resume` reads the provenance from the
> environment ([`provenance_from_env`](../crates/cli/src/github_actions_run_context.rs))
> and builds a [`PolicyGate`](../crates/engine/src/policy_gate.rs) with
> `.with_provenance(...)`, so a parked fork or `pull_request_target` run is refused
> `apply`, `deploy`, `destroy` and secret reads at the resume preflight — before
> anything is approved or written. What is *not* connected is `keepshipping run`,
> which still builds neither a `PolicyGate` nor a `GithubActionsRunContext`: a run
> that never parks is not provenance-gated. The OIDC-withholding half is likewise
> unbuilt in production — `GithubActionsRunContext::from_env` is called only from
> its own tests, and the module is `#[allow(dead_code)]` in `main.rs`. The two-file
> YAML split described above therefore remains the working defence and is
> load-bearing on its own; this is not yet defence in depth, but the reason is that
> `run` is ungated, not that nothing is wired.

Why the harness wants a second line of defence: the YAML split is the only control
that depends on every future job in the repository getting it right, and a repository
that gets it wrong fails silently. The machinery below exists to close that gap, and
`resume` is where it bites today; it is not closed for a run that never parks.

The GitHub Actions adapter classifies the provenance of the code a run is *about*,
separately from the identity of whoever ran the job — an OIDC identity, a token from
GitHub's OIDC endpoint whose signature this adapter does not verify, says GitHub ran
the job, not whose `ship.ks` it just checked out
([`Provenance`](../crates/core/src/ports/run_context.rs)). It is one of three:

| Provenance | When | Trusted |
|---|---|---|
| `Repository` | a push, a tag, or a pull request whose head branch is in the same repository | yes |
| `Fork` | a pull request whose head lives in another repository | no |
| `Target` | any `pull_request_target`, `workflow_run` or `merge_group` run, whoever opened it and wherever the head lives | no |

`Fork` and `Target` are both untrusted by construction: whoever wrote the `ship.ks`,
the TypeScript script or the Dockerfile is not anybody this organisation granted
anything to. A `pull_request_target` run is untrusted even when the head branch is
internal — the base branch's workflow file is exactly the thing an outside
contributor is trying to reach through.

Read the `Target` row together with the `workflow_run` recommendation above, because
they point in opposite directions and both are deliberate. `workflow_run` is the
right *workflow* pattern — a separate file, a separate trigger, checking out code you
trust — and the adapter still classifies such a job as `Target`, so a privileged
half triggered by `workflow_run` is refused `apply`, `deploy`, `destroy` and secret
reads exactly as a `pull_request_target` run is. The reason is that the adapter sees
a trusted workflow following up on a run that checked out somebody else's code, and
cannot tell from `GITHUB_EVENT_NAME` alone that the checkout was pinned to the base
branch; `merge_group` is the same shape, a merge queue deciding about code the
repository has not merged yet. So a privileged half on `workflow_run` is refused
`apply` under `keepshipping resume` today: the only path that is not classified is
`keepshipping run`, which builds no gate at all — and which does not execute steps
either, so it is no route to production today. `push` to the default branch and
`workflow_dispatch` are `Provenance::Repository` and are unaffected; that is why
the apply workflow above uses them.

The classification **fails closed**. On a pull request, a missing or empty
`GITHUB_HEAD_REPOSITORY` or `GITHUB_REPOSITORY` is read as a fork, not as trusted:
`Repository` is the only value that grants anything, and on a pull request it is a
claim the adapter has to make affirmatively, never a default a missing variable falls
into. `push`, `workflow_dispatch` and `schedule` are trusted by shape — the
repository's own events, with no fork to speak of — which is why they reach
`Repository` when no repository variables are set at all. A workflow that scrubs the
provenance variables to escape the classification gets a stricter answer, not a
looser one.

For an untrusted run the adapter builds the context with OIDC **off**, so a `role:`
cannot be federated — the error above, and no token in the job to mint one with. The
policy gate then refuses the run, consulted ahead of the file's own rules and ahead of
the org baseline: no `apply`, no `deploy`, no `destroy`, no secret reads; `build` and
`plan` — and any step kind the catalogue has not classified, which lands on `other`
and stays inside the checkout — still run. The refusal is `never` rather than `ask`
because the human an `ask` would wait for is the thing that is missing — nobody in a
fork's run can be shown a diff and asked whether it may apply, and an `ask` a fork pull
request parks forever is an approval nobody ever reads. A `can: apply` line in a fork's
own `ship.ks` widens nothing: the file's rules are themselves attacker input once the
code is.

Which leaves the honest position today, and it is narrower than "nothing is wired"
and wider than "the machinery is live". A run that parks at an approval and is
carried on by `keepshipping resume` *is* provenance-gated: `resume` classifies the
run from the environment and refuses apply, deploy, destroy and secret reads for a
fork or a `pull_request_target`/`workflow_run`/`merge_group` run before anything is
approved. A run that never parks is not — `keepshipping run` builds no
`GithubActionsRunContext` and no `PolicyGate` at all, so it gates on the default
`Provenance::Repository` and provenance distinguishes nothing there. And the
withholding of OIDC for an untrusted run is still library code: `from_env` is called
only from its own tests, so the `role:` a fork asks for is refused by the *workflow's*
missing `id-token: write`, not by the adapter's answer.

The YAML split is worth doing for exactly the reasons above (keeps `plan.yml`
honest about what it can reach, and stops the trusted half from being reachable by a
trigger a stranger can fire), and it is still the whole of the defence for any run
that does not park.

## Local runs

```bash
aws sso login --profile dev        # or: export AWS_PROFILE=dev
az login
gcloud auth application-default login
keepshipping run ship.ks
```

The run records `via=profile:dev` when `AWS_PROFILE` names one and `via=ambient`
otherwise — for Azure always `via=ambient`, because `az login` has no profile
name to report. `role` is absent either way: nothing was assumed. A `role:` on a
laptop is honoured by nobody and is not an error — there is no token to
federate.

## What is not wired yet

The harness side is built and tested: parsing a `role:`, refusing an unrecognised
one, resolving the four cases above, minting the token into a `SecretValue`, the
log entry, and the subprocess environment. Three things are not, each a line of
work rather than a design question:

- `keepshipping run` does not execute steps
  ([#45](https://github.com/Keep-Shipping/harness/issues/45)), so nothing calls
  [`resolve`](../crates/engine/src/credentials.rs) and the jobs above do nothing;
- `keepshipping run` builds neither a `GithubActionsRunContext` nor a
  [`PolicyGate`](../crates/engine/src/policy_gate.rs), so a run that never parks is
  not provenance-gated; `keepshipping resume` is, and
  `GithubActionsRunContext::from_env` is still called only from its own tests (see
  *the harness itself*);
- the `IacTool` port has no adapter, so no `tofu` subprocess is handed the token
  file or the environment in the table;
- the checker does not call `CloudRole::parse`, so `check` accepts any string as
  a role today.

The **end-to-end path** — federating into a real account and applying — has not
been exercised by anyone with an AWS account. Check the policy documents before
the first production apply, not after.