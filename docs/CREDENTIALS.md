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

## GitHub Actions: two jobs, two roles

The plan and the apply are separate jobs because they are separate steps with
separate roles. The apply job sits behind a GitHub *environment*, so its OIDC
subject is the environment's — what the apply role's trust policy allows.

```yaml
name: infra
on:
  pull_request:

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
- the `IacTool` port has no adapter, so no `tofu` subprocess is handed the token
  file or the environment in the table;
- the checker does not call `CloudRole::parse`, so `check` accepts any string as
  a role today.

The **end-to-end path** — federating into a real account and applying — has not
been exercised by anyone with an AWS account. Check the policy documents before
the first production apply, not after.