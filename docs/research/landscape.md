# Competitive landscape

Internal research for [#157](https://github.com/Keep-Shipping/harness/issues/157),
researched 2026-10-08. It records what each neighbouring tool is documented to
do today, so any comparison we publish can be checked line by line against a
source.

**Private.** Internal working notes, not site copy. Nothing here goes on the
website unless the source is rechecked on the day it is published. Recheck every
row whose *Checked* date is older than about six months.

## How to read this

Each tool section gives what it does better than a new early-access deploy tool,
where it overlaps with Keep Shipping, licence and pricing, a dated status
signal, and numbered sources with the date accessed. Reference numbers are
scoped to each tool's section and resolve in that section's own Sources list,
not globally; the numbering keeps each section's history, so the GitHub Actions
and GitLab lists jump 25→27 and 41→43 (numbers 26 and 42 are unused). Facts
come only from pages fetched on the day; where a page would not answer the
question, the entry says "not verified" rather than filling the gap from memory.

## Where Keep Shipping stands

Facts from this repo, not from the site:

- One typed `ship.ks` site file per repo, checked before anything runs
  ([`../../README.md`](../../README.md)).
- Steps only see ports; adapters are the only vendor-aware code. That is what
  makes the same file behave the same on a laptop and in CI
  ([`../../README.md`](../../README.md)).
- `plan` and `apply` are separate steps, and an approval is bound to the plan's
  sha256. Apply applies the approved plan or stops and asks again; with
  `recheck` on a changed change set stops it too
  ([`../STALE_PLANS.md`](../STALE_PLANS.md)).
- An approval in CI parks the run and exits 4; `keepshipping approve` or a
  resume job continues it ([`../GITHUB_APPROVALS.md`](../GITHUB_APPROVALS.md)).
- Environments are declared under `envs:` with `approvers:`, `ci-only:`,
  `secrets:` and `require-verified:` ([`../LANGUAGE.md`](../LANGUAGE.md)).
- Built-in steps cover `oci.image`, `oci.artifact`, `oci.verify`, `tofu.plan`,
  `tofu.apply`, `k8s.rollout` and `vm.deploy`. `tofu`/`terraform` shell out to
  the user's own binary; nothing is downloaded or redistributed.
- Honest status: the README says "Nothing here runs yet"
  ([`../../README.md`](../../README.md), line 5) and M2 "Early-access alpha" is
  still ahead. Nothing here describes a shipped capability.

## At a glance

| Tool | Category | What it does better (one line) | Status signal (with date) | Checked |
|---|---|---|---|---|
| Dagger | CI-as-code | Eight first-party SDKs, content-addressed caching, managed cloud | v0.21.10 released 2026-09-30 | 2026-10-08 |
| Earthly | CI-as-code | Nothing further; the project and its cloud are finished | Cloud stopped 2025-07-16; last release v0.8.16 | 2026-10-08 |
| Atlantis | IaC workflow | Nine years of PR-driven apply, deep approval rules | v0.48.1 released 07 Oct (year not shown) | 2026-10-08 |
| Spacelift | IaC workflow | OPA policy over plans and approvals, state-aware workflows | No official release feed (404) | 2026-10-08 |
| env0 | IaC workflow | A free tier with real capacity; drift with blast-radius context | Rebranded to "env zero"; no dated notice | 2026-10-08 |
| HCP Terraform | IaC workflow | The reference Terraform platform; agents in customer networks | IBM acquisition completed 2025-02-27 | 2026-10-08 |
| Digger/OpenTaco | IaC workflow | MIT-licensed IaC orchestration inside a pipeline you already have | Renamed to OpenTaco 2025-11-07 | 2026-10-08 |
| Argo CD | GitOps | Kubernetes reconciliation, project-scoped RBAC, CNCF Graduated | v3.5.4 released 2026-10-06 | 2026-10-08 |
| Flux | GitOps | Progressive delivery (Flagger), vendor-independent foundation | v2.9.6 released 2026-10-01 | 2026-10-08 |
| Kargo | GitOps | Promotion as a first-class object, modelled across environments | v1.12.3 released 2026-10-08 | 2026-10-08 |
| Harness CD | Deploy orchestration | Canary gates, post-deploy verification, flag guardrails | Monthly roundups through August 2026 | 2026-10-08 |
| Octopus Deploy | Deploy orchestration | Two approval mechanisms; change windows; database deploys | Server 2026.3 build 15878, 2026-09-30 | 2026-10-08 |
| Garden | Deploy orchestration | Stack Graph, ephemeral per-PR Kubernetes environments | 0.13.65 published 2026-08-24 | 2026-10-08 |
| GitHub Actions environments | Native CI | Required reviewers, custom protection rules, branch policies | Docs still say "public preview" for custom rules | 2026-10-08 |
| GitLab environments | Native CI | Group-level protected environments keyed by deployment tier | 19.4 released 2026-09-17 | 2026-10-08 |

## CI-as-code engines

### Dagger

- **Category:** CI-as-code engine; an Apache-2.0 engine plus a commercial cloud.
- **What it is:** a programmable, container-based engine for build, test and
  deploy, "the missing software stack for CI", meant to replace shell scripts
  and proprietary YAML [1][2].
- **Does better:** eight first-party SDKs ship in-tree (Go, Python, TypeScript,
  PHP, Java, .NET, Elixir, Rust) on the engine's version number [2][3];
  content-addressed caching reused across local and CI runs [2]; a managed cloud
  with no self-hosted runners [5]; OpenTelemetry traces [2][5]; secrets never
  injected for forked PRs [5].
- **Overlaps:** pipeline-as-code with a typed API rather than YAML, and the
  same-runs-locally-and-in-CI property [1][2][5]. Not deployment-targeting as
  far as the fetched pages show: no environment approval or promotion model was
  found (not verified).
- **Licence / pricing:** engine Apache-2.0 [4]. Cloud: Individual Free (1 user,
  1M events/month), Team $50/month after a two-week trial (up to 10 users,
  10M events/month), Enterprise custom. Compute-minute and concurrency
  allowances are not published (not verified) [6].
- **Status:** v0.21.10 published 2026-09-30 with matching SDK tags [3];
  repository not archived and pushed on the research date [4].
- **Sources (accessed 2026-10-08):**
  1. Dagger, "the missing software stack for CI" — https://dagger.io/
  2. dagger/dagger README — https://github.com/dagger/dagger#readme
  3. dagger/dagger releases — https://api.github.com/repos/dagger/dagger/releases
  4. dagger/dagger repository via GitHub API (licence, archived, push date) — https://api.github.com/repos/dagger/dagger
  5. Dagger Cloud overview — https://docs.dagger.io/cloud/overview
  6. Dagger pricing — https://dagger.io/pricing

### Earthly

- **Category:** CI-as-code engine (Earthfiles on BuildKit); effectively finished.
- **What it is:** a build framework with Earthfiles syntax, "like Dockerfile and
  Makefile had a baby", on BuildKit [7][8]. The company has shut down the hosted
  and self-hosted services and ended maintenance of the open-source project [9].
- **Does better:** nothing further can be built on it. The company stated "we
  are ending active maintenance of the Earthly open-source project", keeping
  only "critical bug fixes", and "we are no longer accepting PRs" [9]. The repo
  README and the docs both carry an unmaintained warning [8][10].
- **Overlaps:** historically the closest analogue to declarative CI, since
  Earthfiles run identically locally and in CI [9]. The shutdown is itself a
  datapoint: the April 2025 post records a migration path arranged with Dagger,
  a year free on Dagger Cloud Team, but also that "Dagger is not a drop-in
  replacement for Earthfiles" [9].
- **Licence / pricing:** MPL-2.0 [11]. The pricing page showed no plan names or
  prices on the research date [14]. Pricing for the successor product (Lunar)
  is not verified.
- **Status:** Earthly CI shut down 1 October 2023 (post published 2023-09-12)
  [13]. "Earthly Cloud, including Satellites, will stop working on July 16th,
  2025" [9]. Last release v0.8.16, published 2025-07-16 [11][12]; repository not
  archived, last push 2025-10-23 [11]. The company has since pivoted to Earthly
  Lunar, with release notes through 2026-10-06 [15][16].
- **Sources (accessed 2026-10-08):**
  7. Earthly — https://earthly.dev/
  8. earthly/earthly README — https://github.com/earthly/earthly#readme
  9. Shutting down Earthfiles Cloud (2025-04-16) — https://earthly.dev/blog/shutting-down-earthfiles-cloud/
  10. Earthly docs, unmaintained notice — https://docs.earthly.dev/
  11. earthly/earthly repository via GitHub API (MPL-2.0, push date) — https://api.github.com/repos/earthly/earthly
  12. earthly/earthly releases — https://api.github.com/repos/earthly/earthly/releases
  13. Shutting down Earthly CI (2023-09-12) — https://earthly.dev/blog/shutting-down-earthly-ci/
  14. Earthly pricing — https://earthly.dev/pricing
  15. Earthly Lunar — https://earthly.dev/lunar
  16. Lunar release notes, 2026 — https://docs-lunar.earthly.dev/release-notes/product/2026

## IaC workflow tools

### Atlantis

- **Category:** open-source, self-hosted, PR-based Terraform apply automation.
- **What it is:** a self-hosted Go server that listens for pull/merge-request
  webhooks and replies to commands (`plan`, `apply`, `unlock`, `cancel`,
  `import`) as PR comments [1][2].
- **Does better:** the site claims production use "since 2017", "600 repos" and
  "300 developers" [3]; `apply_requirements` can require the PR be mergeable,
  require a policy check pass, scope apply permission to a team, and invalidate
  an approval whenever a new plan is produced [2]; Conftest policy-as-code runs
  server-side after the plan [2]; drift detection and gated remediation [2];
  project locking and a command allow-list [1][2].
- **Overlaps:** approvals before apply are the primitive Keep Shipping calls an
  approval [2]; `atlantis.yaml` is the direct ancestor of a `ship.ks` [2];
  per-project targeting before apply [1].
- **Licence / pricing:** Apache-2.0 [4]. Self-hosted and free; no paid tier
  documented [1][3].
- **Status:** v0.48.1 released 07 Oct, the year not shown on the releases page,
  with v0.48.0 on 22 Sep [1]. 9.3k stars, 4,670 commits [4]. The repo CHANGELOG
  is deprecated in favour of the releases page [4].
- **Sources (accessed 2026-10-08):**
  1. runatlantis/atlantis releases — https://github.com/runatlantis/atlantis/releases
  2. Atlantis server configuration reference — https://www.runatlantis.io/docs/server-configuration
  3. Atlantis site, "In production since 2017" — https://www.runatlantis.io/
  4. runatlantis/atlantis repository (stars, commits, CHANGELOG notice) — https://github.com/runatlantis/atlantis

### Spacelift

- **Category:** commercial SaaS and self-hostable IaC orchestration.
- **What it is:** a control plane running plans and applies across Terraform,
  OpenTofu, CloudFormation, Pulumi, Kubernetes and Ansible, layering policy,
  drift detection, RBAC and state-aware workflows over them [1][2].
- **Does better:** OPA policy governing plans, approvals and notifications, not
  just post-plan checks [1]; drift detection that drives remediation [1]; stack
  dependencies and state modelled as first-class objects [1]; delegated RBAC via
  Spaces and Contexts, with audit trails [1]; private workers and self-hosting
  in any cloud or on-premises [1][2]; "Golden Paths" blueprints for
  standardised self-service [1].
- **Overlaps:** approvals before apply gated by policy [1]; Contexts and stack
  dependencies map onto environments and ordered steps [1]; blueprints and
  templates as pipeline-as-code [1].
- **Licence / pricing:** proprietary [2]. Free ($0, 2 users, 1 public worker);
  Starter+ $20,000 billed annually; Business, Enterprise and Enterprise+
  quote-only. Trial with no credit card and no time limit [2].
- **Status:** no versioned release feed found, spacelift.io/releases returns 404,
  so version and status are not verified from an official changelog [4]. Blog
  posts are dated by image path only, July and September 2026 [3].
- **Sources (accessed 2026-10-08):**
  1. Spacelift product — https://spacelift.io/product
  2. Spacelift pricing — https://spacelift.io/pricing
  3. Spacelift blog — https://spacelift.io/blog
  4. spacelift.io/releases (404) — https://spacelift.io/releases

### env0 (branded "env zero")

- **Category:** commercial SaaS and self-hostable IaC workflow platform.
- **What it is:** a control plane that connects to existing GitHub, GitLab or
  Bitbucket code without requiring changes, and orchestrates environments,
  deploys and drift across clouds [1][2]. `env0.com` 301-redirects to
  `envzero.com`; page copy brands the company "env zero" while accounts stay
  `env0`. No formal rebrand announcement was found [1].
- **Does better:** a free tier with real capacity, 250 runs per month and 30
  active environments with unlimited users [1]; speculative plans in pull
  requests [2]; approvals, cost limits and security rules applied consistently
  [2]; drift with "full blast-radius context" and a rescan to verify the fix [2];
  a unified policy layer of policy-as-code, CSPM and IAM rules [2].
- **Overlaps:** on-demand environment request with policies applied in the
  background [2]; templates for self-service, against a checked-in pipeline file
  [2]; Git-keyed workflows against a local CLI run [2].
- **Licence / pricing:** proprietary [1]. Free tier as above; Cloud Navigator and
  Cloud Pilot custom-priced per successful apply or environment. No per-seat
  prices shown [1].
- **Status:** the domain migration and new branding are visible; no dated
  announcement page exists [1]. The most recent funding post on the company's
  own site is a $35M Series A from 2023; anything later is not verified [3].
- **Sources (accessed 2026-10-08):**
  1. env zero pricing (301 from https://www.env0.com/pricing) — https://www.envzero.com/pricing
  2. env zero product — https://www.envzero.com/product
  3. env0 raises $35M Series A, Business Wire (2023-03-29; search-confirmed, direct fetch blocked) — https://www.businesswire.com/news/home/20230329005400/en/CORRECTING-and-REPLACING-env0-Raises-%2435-Million-Series-A-Led-by-Venture-Guides

### HCP Terraform (HashiCorp, now IBM)

- **Category:** commercial hosted Terraform platform. Terraform itself is
  separately licensed.
- **What it is:** HashiCorp's hosted service for running plans and applies in
  disposable cloud VMs, with remote state and variables per workspace [1][2].
- **Does better:** Sentinel and OPA policy that can warn, block, or be bypassed
  by compliance teams [1][2]; speculative plans on pull requests and automatic
  plans after merge [1]; SAML SSO on every plan, custom RBAC from Essentials
  upwards, audit logging on Premium [1]; agents executing inside
  customer-controlled networks, concurrency 1 to 300 by tier [1]; Stacks keep
  state isolated per deployment [2].
- **Overlaps:** plan, approve, apply as the core loop, gated by policy [2];
  workspaces as named environments with scoped state [2]; centralised run logs.
- **Licence / pricing:** Terraform is under **BSL 1.1** for 1.6.0 and later,
  changing to MPL 2.0 four years from each version's publication; the exact
  change date for a specific release is not verified [4]. HCP Terraform pricing,
  now branded "IBM HCP Terraform": Essentials from $0.10 per resource per month,
  Standard $0.47, Premium $0.99. Billing is per resource under management, not
  per activity [5].
- **Status:** IBM completed its acquisition of HashiCorp on 2025-02-27 [6].
  Legacy Free plans reached end of life 2026-03-31 and were auto-migrated,
  irreversibly, per the 2025-12-17 blog post [3].
- **Sources (accessed 2026-10-08):**
  1. HCP Terraform overview and plan comparison — https://developer.hashicorp.com/terraform/cloud-docs/overview
  2. HCP Terraform documentation — https://developer.hashicorp.com/terraform/cloud-docs/
  3. Continuing HCP Terraform's enhanced free tier experience (2025-12-17) — https://www.hashicorp.com/en/blog/continuing-hcp-terraform-s-enhanced-free-tier-experience
  4. Terraform LICENSE (BSL 1.1) — https://github.com/hashicorp/terraform/blob/main/LICENSE
  5. HashiCorp pricing — https://www.hashicorp.com/en/pricing
  6. IBM completes acquisition of HashiCorp (2025-02-27) — https://newsroom.ibm.com/2025-02-27-ibm-completes-acquisition-of-hashicorp,-creates-comprehensive,-end-to-end-hybrid-cloud-platform

### Digger / OpenTaco

- **Category:** open-source, self-hostable Terraform/OpenTofu orchestrator that
  runs inside an existing CI pipeline.
- **What it is:** MIT-licensed orchestration running plans and applies in a
  pipeline such as GitHub Actions, now also offering state management, remote
  runs and drift detection. **Digger rebranded to OpenTaco on 7 November
  2025**; the company remains Digger and the engine is unchanged [1][2][3].
- **Does better:** the most permissively licensed and best-known open-source
  entrant here, at 5.0k stars [3]; it runs in the customer's existing CI rather
  than requiring a control plane to host or pay for [3]; centralised state with
  access controls, version history and rollback [2]; remote runs (Beta) with
  streamed logs [2]; scheduled drift detection with Slack or GitHub Issue
  notifications [2].
- **Overlaps:** approvals before apply in a PR-driven flow [2]; state management
  and project targeting inside the pipeline [2]; pipeline-as-code through the CI
  config plus a per-project spec [3].
- **Licence / pricing:** MIT [3]. The docs call it open source and self-hostable;
  no paid tier or hosted offering documented [2].
- **Status:** renamed 2025-11-07, "the same battle-tested engine, just a more
  apt name and a bigger vision" [3]. The docs carry an undated rebranding note
  [2]. Latest release version and date not verified from the pages fetched.
- **Sources (accessed 2026-10-08):**
  1. OpenTaco — https://opentaco.dev/
  2. OpenTaco documentation — https://docs.opentaco.dev/
  3. diggerhq/digger repository — https://github.com/diggerhq/digger

## GitOps and continuous delivery

### Argo CD

- **Category:** GitOps continuous delivery for Kubernetes (CNCF Graduated).
- **What it is:** a declarative GitOps tool where Git holds desired state and a
  Kubernetes controller reconciles the difference [1][2].
- **Does better:** continuous drift detection and visualisation, an app marked
  `OutOfSync` when live state differs from Git [2]; a real-time UI [2];
  multi-cluster management from one control plane [2]; project-scoped RBAC
  restricting source repos, destinations and resource kinds [5]; rollback to any
  previous revision [2][4]. Graduated 2022-12-06; a 2025 end-user survey found
  nearly 60% of respondents' clusters relied on Argo CD [1][6].
- **Human gating, precisely:** there is **no built-in approval step**. The
  mechanisms are manual sync, by setting `automated.enabled: false` so the
  controller skips sync and a human triggers it, and sync windows, which
  restrict when syncing is allowed. Destructive operations do need
  confirmation: `Prune=confirm` or `Delete=confirm` must be confirmed before
  pruning or deleting resources, by UI, CLI, or a `deletion-approved`
  annotation [2].
- **Overlaps:** Git-declared deployment logic with PreSync/Sync/PostSync hooks
  [2]; environment-per-cluster/namespace targeting with scoped RBAC [5];
  stage-like separation by Application, though Argo CD does not itself promote
  and Kargo layers that on top [8].
- **Licence / pricing:** Apache 2.0 [3]. CNCF-hosted; no paid tier of its own.
- **Status:** v3.5.4 published 2026-10-06, with v3.6.0-rc2 the same day and v3.6
  RC1 announced 2026-09-16 [9][10]. Four minor releases a year, only the three
  newest supported [7].
- **Sources (accessed 2026-10-08):**
  1. CNCF project page: Argo — https://www.cncf.io/projects/argo/
  2. Argo CD user guide: auto sync — https://argo-cd.readthedocs.io/en/stable/user-guide/auto_sync/ (sync windows: .../sync_windows/, sync options: .../sync-options/)
  3. argoproj/argo-cd repository (Apache-2.0) — https://github.com/argoproj/argo-cd
  4. `argocd app rollback` reference — https://argo-cd.readthedocs.io/en/stable/user-guide/commands/argocd_app_rollback/
  5. Argo CD projects — https://argo-cd.readthedocs.io/en/stable/user-guide/projects/
  6. CNCF end-user survey (2025-07-24) — https://www.cncf.io/announcements/2025/07/24/cncf-end-user-survey-finds-argo-cd-as-majority-adopted-gitops-solution-for-kubernetes/
  7. Release process and cadence — https://argo-cd.readthedocs.io/en/stable/developer-guide/release-process-and-cadence/
  8. Kargo — https://kargo.io/
  9. argoproj/argo-cd releases — https://github.com/argoproj/argo-cd/releases
  10. v3.6 RC1 announcement (2026-09-16; search-confirmed, direct fetch blocked) — https://blog.argoproj.io/argo-cd-v3-6-rc1-is-here-c0b562dc78d1

### Flux

- **Category:** GitOps continuous and progressive delivery (CNCF Graduated).
- **What it is:** "An open and extensible continuous delivery solution for
  Kubernetes", powered by the GitOps Toolkit: source, kustomize, helm,
  notification and image-reflector/automation controllers [1][2][4].
- **Does better:** every built-in controller reconciles, rather than one
  opinionated sync path [2][4]; Flagger ships canary, A/B and blue/green with
  automated rollback [5]; analysis integrations against Prometheus, Datadog,
  CloudWatch, New Relic and others, plus custom webhooks [5]; notifications to
  Slack, Teams, Discord and Rocket [4][5].
- **Overlaps:** everything, including pipeline logic, as Git-reconciled custom
  resources [1][2]; environments as clusters/namespaces plus Flagger's target
  workloads [4][5]. Flagger's analysis-driven promotion is an automated gate,
  not a human approval gate [5].
- **Staying power:** Graduated 2022-11-30; Weaveworks ceased commercial
  operations in early February 2024; CNCF organised a support coalition in
  March 2024 [3][1].
- **Licence / pricing:** Apache 2.0 [6]. Community support is free and
  explicitly best-effort with no guaranteed response time; vendors sell 24/7
  support and SLAs [9].
- **Status:** v2.9.6 published 2026-10-01, v2.9.0 on 2026-06-30 [7][8];
  repository pushed 2026-10-08, 8,442 stars.
- **Sources (accessed 2026-10-08):**
  1. CNCF project page: Flux — https://www.cncf.io/projects/flux/
  2. Flux — https://fluxcd.io/
  3. CNCF: Flux project gains new corporate support (2024-03-19) — https://www.cncf.io/announcements/2024/03/19/cloud-native-computing-foundations-fluxcd-project-gains-new-corporate-support/
  4. Flux components — https://fluxcd.io/flux/components/
  5. Flagger — https://flagger.app/
  6. flux2 LICENSE (Apache-2.0) — https://github.com/fluxcd/flux2/blob/main/LICENSE
  7. fluxcd/flux2 releases — https://github.com/fluxcd/flux2/releases
  8. fluxcd/flux2 repository via GitHub API (push date, stars) — https://api.github.com/repos/fluxcd/flux2
  9. Flux support — https://fluxcd.io/support/

### Kargo (Akuity)

- **Category:** GitOps promotion and environment-promotion orchestration,
  sitting alongside Argo CD.
- **What it is:** an orchestration layer that tracks changes in Git artifacts,
  images and Helm charts and promotes them between environments, with
  guardrails, rollback and a UI [1][2].
- **Does better:** promotion is the primary object, modelling relationships
  among application instances across environments and diffing them [1]; audit
  trails on approval responses with responder, action, timestamp and message [4];
  reviewer eligibility by OIDC claim pairs or Kargo project roles [4]; promotion
  as code, with reusable steps such as `http`, `json-parse` and `jira` [3];
  built by Akuity, "the creators of Argo" [1].
- **Human approval, precisely:** in **open-source Kargo** a human initiates a
  promotion by hand, by dragging Freight into a Stage or using the Stage menu's
  *Promote* action, and that is what the quickstart demonstrates [5]. What is
  **Akuity Platform / Enterprise only** is the `wait-for-approval` promotion
  step, documented as "only available in Kargo on the Akuity Platform, versions
  v1.12.0 and above" [4], along with promotion windows and audit-event export,
  announced in Enterprise 1.12 on 2026-09-30 [6]. So: manual promotion is OSS;
  a suspended promotion awaiting N distinct approvals is not.
- **Overlaps:** stages as environments [1]; human gates inside a promotion [4];
  the promotion process as a declarative resource with named step types [3].
- **Licence / pricing:** Apache 2.0 for the community edition [7]. No OSS
  pricing page found.
- **Status:** v1.12.3 published 2026-10-08, with patches for four earlier lines
  the same day; v1.12.0 GA on 2026-09-30 [1][8]. 3,706 stars, repository pushed
  2026-10-08 [9].
- **Sources (accessed 2026-10-08):**
  1. Kargo — https://kargo.io/
  2. Kargo documentation — https://docs.kargo.io/
  3. Promotion steps reference — https://docs.kargo.io/user-guide/reference-docs/promotion-steps
  4. `wait-for-approval` reference — https://docs.kargo.io/user-guide/reference-docs/promotion-steps/wait-for-approval
  5. Kargo quickstart — https://docs.kargo.io/quickstart/
  6. Kargo Enterprise 1.12: promotion windows, approvals, audit events (2026-09-30) — https://akuity.io/blog/kargo-enterprise-1.12-promotion-windows-approvals-and-audit-events
  7. akuity/kargo LICENSE (Apache-2.0) — https://github.com/akuity/kargo/blob/main/LICENSE
  8. akuity/kargo releases — https://github.com/akuity/kargo/releases
  9. akuity/kargo repository via GitHub API (stars, push date) — https://api.github.com/repos/akuity/kargo

## Deploy orchestration

### Harness CD

Harness Inc. (`harness.io`), unrelated to this repository's name; kept only
because "Harness" is a common search collision.

- **Category:** commercial continuous-delivery and deployment-orchestration
  platform.
- **What it is:** automates the path from application or infrastructure changes
  to production across multiple platforms, with GitOps deployments and
  verification [1].
- **Does better:** Continuous Verification is a first-class capability [1];
  canary phases at 25/50/100% with a fixed pod budget, where verification and
  manual approval checkpoints stop an unsuccessful release early (July 2026) [2];
  bulk post-production rollback and blue/green rollback restoring capacity (July
  2026) [2]; a Metric Check guardrail halting feature-flag rollouts when
  performance worsens (August 2026) [3]; policy checks on code committed
  directly to Git, stopping pipelines at step level (August 2026) [3].
- **Overlaps:** environments and pipelines as first-class objects with resources
  and schedules [1]; manual approvals as stage gates, including inside canary
  rollouts [2]; verification and rollback gates on a run [1][2].
- **Licence / pricing:** proprietary SaaS. Free tier $0; Essentials and
  Enterprise quote-only, no published per-user price. Enterprise lists unlimited
  users, 25 months of history as an add-on and a dedicated account manager;
  Essentials lists up to 500 users and 60 concurrent pipeline executions [4].
- **Status:** monthly "shipped in <Month> 2026" roundups, July 2026 published
  2026-08-03 and August 2026 dated 2026-09-02 [2][3]. No semantic version scheme
  is published for the platform on these pages.
- **Sources (accessed 2026-10-08):**
  1. Harness Continuous Delivery & GitOps documentation — https://developer.harness.io/docs/continuous-delivery/
  2. Shipped in July 2026 (2026-08-03) — https://www.harness.io/blog/shipped-in-july-2026
  3. Shipped in August 2026 (2026-09-02) — https://www.harness.io/blog/shipped-in-august-2026
  4. Harness pricing — https://www.harness.io/pricing

### Octopus Deploy

- **Category:** commercial continuous-delivery and release-orchestration
  platform, cloud or self-hosted.
- **What it is:** a CD platform for applications, APIs, microservices and
  databases, positioned downstream of GitHub Actions, Jenkins, Azure DevOps,
  GitLab CI and TeamCity [1][2].
- **Does better:** two approval mechanisms, a Manual intervention step that
  pauses, releases its task slot, can be claimed by exactly one eligible user
  and records Proceed/Abort, and Octopus Approvals, a space-level change request
  with configurable minimum approval counts that terminates the task on
  rejection [3][4]; approval activity written to the task log [4]; an approved
  change window can delay execution [4]; automatic promotion between
  environments with rolling, blue/green and canary strategies [1]; database
  deployments and a runbooks product with 500+ step templates [1].
- **Overlaps:** environments plus one deployment process reused across them, the
  same shape as `ship.ks` [1]; approval gates inside the pipeline [3][4];
  promotion between environments [1].
- **Licence / pricing:** proprietary, annual billing. Cloud: Free $0,
  Professional $4,330/yr, Enterprise $24,600/yr. Server: Free $0, Professional
  $2,080/yr, Enterprise $15,600/yr. Free tier: 10 projects, 10 users, 1 space,
  5 concurrent tasks. Tenants and machines are $770/yr each [2].
- **Status:** self-hosted 2026.3 build 15878 shipped 2026-09-30, with nightlies
  through 2026-10-06 [5]. Octopus Approvals is in **Public Preview** for cloud,
  with self-hosted planned for 2026.3 behind a feature toggle [4]. The server
  source is not published at github.com/OctopusDeploy/OctopusDeploy, which
  returned 404 on the research date [4].
- **Sources (accessed 2026-10-08):**
  1. Octopus Deploy — https://octopus.com/
  2. Octopus pricing — https://octopus.com/pricing
  3. Manual intervention and approvals step — https://octopus.com/docs/projects/built-in-step-templates/manual-intervention-and-approvals
  4. Octopus Approvals — https://octopus.com/docs/approvals
  5. Previous Octopus versions — https://octopus.com/downloads/previous

### Garden

- **Category:** Kubernetes-oriented CI automation and production-like ephemeral
  environments (MPL-2.0 core plus a hosted cloud).
- **What it is:** "Automation for Kubernetes development and testing" that
  spins up production-like environments on demand, with shared result caching
  [1][2].
- **Does better:** the Stack Graph generates an execution graph from component
  configurations and dependencies, and the pipeline adapts when they change [3];
  ephemeral per-PR environments, staging after merge, and a dev environment with
  live log streaming [3]. It is deliberately not a deploy orchestrator, "Garden
  isn't a hosting platform at all", a narrower scope that means less conflict
  with an incumbent [3].
- **Overlaps:** environments, with the same word and a different lifecycle intent
  [3]; a declarative stack graph with typed actions [3]. No approval, promotion
  window or drift mechanism appears on the pages fetched (not verified beyond
  those pages).
- **Licence / pricing:** MPL-2.0 core [1]. Garden Cloud introduced a "Garden
  Team Tier" with the Remote Container Builder available to everyone, but **no
  price figures are published** on the pages fetched [4].
- **Status:** Incredibuild announced its acquisition of Garden, page dated
  2024-10-31, dateline 2024-11-04 [5]. The repository is not archived and was
  last pushed 2026-08-24 [1], but release lines are out of step, 0.13.65 on
  2026-08-24 against a 0.14.20 from 2026-02-27, so maintenance appears to have
  moved back to 0.13 [2]. Whether Garden Cloud is still sold, and under what
  brand, is not verified; garden.io redirects to docs.garden.io with no pricing
  content [6][7][8].
- **Sources (accessed 2026-10-08):**
  1. garden-io/garden repository — https://github.com/garden-io/garden
  2. garden-io/garden releases — https://github.com/garden-io/garden/releases
  3. Garden vs other tools — https://docs.garden.io/overview/garden-vs-other-tools
  4. Garden Cloud announcement — https://docs.garden.io/misc/cloud-announcement
  5. Incredibuild acquires Garden — https://www.incredibuild.com/news/incredibuild-acquires-garden
  6. Garden documentation — https://docs.garden.io/
  7. Garden deprecations — https://docs.garden.io/misc/deprecations
  8. garden.io/pricing (redirects to docs.garden.io) — https://garden.io/pricing

## Native CI features

### GitHub Actions environments

- **Category:** first-party deployment environments and protection rules,
  bundled with the hosted runner fleet.
- **What it is:** a named deployment target a workflow job references; before
  such a job runs, and before it receives that environment's secrets, it must
  satisfy the environment's protection rules [17].
- **Does better:** required reviewers scale to teams, "up to six people or teams
  may be designated", and one approval is enough [17]; branch and tag
  deployment policies in three modes, including name patterns [19]; custom
  protection rules let a GitHub App gate a deployment, up to 6 per environment,
  each able to wait up to 30 days for a webhook response [21]; environment
  secrets are available only to jobs that reference the environment, and not
  until approval is given [17]; documented deletion and bypass semantics with a
  mandatory bypass reason [17][18][22].
- **Overlaps:** a named target, a set of gates, a reviewer, then release
  [17][18]; secrets released only after approval [17]; pipeline-as-code as
  declared, versioned deploy logic tied to a ref, though the unit is YAML
  [17][19].
- **Licence / pricing, and what actually gates this.** Bundled with the
  platform, not sold separately [23], and the gating is plan-shaped:
  - "Users with GitHub Free plans can only configure environments for public
    repositories"; Team organisations and Pro users can configure environments
    for private repositories [17].
  - Environment secrets are public-only on Free; private and internal access
    needs "GitHub Pro, GitHub Team, or GitHub Enterprise" [19].
  - Deployment branches and tags, and environment variables, are also available
    for private repositories on Pro and Team [19].
  - The reference page states that **required reviewers are only available for
    public repositories** on Free, Pro and Team [19]. Which plan carries
    required reviewers on a *private* repository is not clearly stated on the
    pages fetched (not verified).
  - Custom deployment protection rules: "available in public repositories for
    all plans"; private and internal repositories require Enterprise [22][23].
- **Status:** custom deployment protection rules were announced in public beta
  on 2023-04-20 [20]. The docs source on `main` still carries the reusable note
  "Custom deployment protection rules are currently in public preview and
  subject to change" [25], while roadmap issue #199 is closed and labelled
  "Generally available" and "Shipped" with no date [24]. Docs and roadmap
  disagree, so treat GA as unconfirmed. A breaking change effective 2025-12-08
  makes environment branch protection rules evaluate against `GITHUB_REF`
  rather than the PR head [27]. Repository `deployable` and `deployed`
  properties were added 2026-04-14 [28]. A workflow may wait up to 30 days for
  environment approval [29]; waiting time is not billable [19].
- **Sources (accessed 2026-10-08):**
  17. Manage environments — https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments
  18. Review deployments — https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/review-deployments
  19. Deployments and environments reference — https://docs.github.com/en/actions/reference/deployments-and-environments
  20. Changelog: create and share your own deployment protection rules (2023-04-20) — https://github.blog/changelog/2023-04-20-github-actions-create-and-share-your-own-deployment-protection-rules-for-safe-and-controlled-deployments/
  21. Configure custom deployment protection rules — https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/configure-custom-protection-rules
  22. custom-deployment-protection-rules-availability reusable — https://github.com/github/docs/blob/main/data/reusables/actions/custom-deployment-protection-rules-availability.md
  23. GitHub's plans — https://docs.github.com/en/get-started/learning-about-github/githubs-plans
  24. github/roadmap#199 — https://github.com/github/roadmap/issues/199
  25. custom-deployment-protection-rules-beta-note reusable — https://github.com/github/docs/blob/main/data/reusables/actions/custom-deployment-protection-rules-beta-note.md
  27. Changelog: pull_request_target and environment branch protections changes (2025-11-07) — https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/
  28. Changelog: deployment context in repository properties and alerts (2026-04-14) — https://github.blog/changelog/2026-04-14-deployment-context-in-repository-properties-and-alerts/
  29. GitHub Actions limits reference — https://docs.github.com/en/actions/reference/limits

### GitLab environments

- **Category:** first-party CI/CD environments, protected environments and
  manual deployment approvals.
- **What it is:** "A GitLab environment represents a specific deployment target
  for your application, like development, staging, or production" [31].
  Environments are created in the UI or by a job declaring `environment:name`;
  "there is usually only one active deployment per environment" [31][33].
- **Does better:** **group-level protected environments** use the deployment
  tier as their name, so projects with different environment names are protected
  together [32]; composable rules, where where both project and group config
  exist "to run a deployment job, the user must be allowed in both rulesets",
  and subgroups cannot override a parent group [32]; approvers can be users,
  roles or invited groups, with per-rule `required_approvals` counts
  [32][34][37]; resource groups, outdated-job prevention and freeze windows on
  Free, Premium and Ultimate [36]; lifecycle states, review-app environments and
  `auto_stop_in` [31][33].
- **Overlaps:** named environments, human approval gates and tiering, a direct
  structural analogue [31][34]; the keying insight worth borrowing is that
  **deployment tiers decouple "which tier is this?" from "what is this
  environment called?"** [31][32]; environment-scoped variables as the
  secret-release boundary [35].
- **Licence / pricing:** current plans are **Free, Premium and Ultimate**; GitLab
  shows no Pro tier [40][41]. Premium is $29 per user/month, Ultimate is custom
  [40]. Verbatim "Tier:" lines from the docs:
  - Environments, deployments, CI/CD variables and deployment safety: **Free,
    Premium, Ultimate** [31][33][35][36].
  - **Protected environments, project and group: Premium, Ultimate** [32].
  - **Deployment approvals: Premium, Ultimate** [34].
  - Protected environments API, group-level variable scope and Environments
    Dashboard: **Premium, Ultimate** [35][37][38][39].
  - Environment alerts and Auto Rollback: **Ultimate only** [31].
  - Deployment tiers carry no standalone tier line; they are the name key of
    group protected environments, which are Premium and Ultimate. Not verified
    as separately paid [31][32].
- **Status:** yearly majors (next GitLab 20.0 scheduled for 2027-05-20), monthly
  minors on the third Thursday, patches twice monthly [43]. GitLab 19.4 released
  2026-09-17, with 19.5 upcoming; neither note lists a protected-environment or
  approval change [44][45]. Open approval-UX issues include #345140 [32].
- **Sources (accessed 2026-10-08):**
  31. GitLab environments — https://docs.gitlab.com/ci/environments/ (Tier: Free, Premium, Ultimate)
  32. Protected environments — https://docs.gitlab.com/ci/environments/protected_environments/ (Tier: Premium, Ultimate)
  33. Deployments — https://docs.gitlab.com/ci/environments/deployments/
  34. Deployment approvals — https://docs.gitlab.com/ci/environments/deployment_approvals/ (Tier: Premium, Ultimate)
  35. CI/CD variables — https://docs.gitlab.com/ci/variables/
  36. Deployment safety — https://docs.gitlab.com/ci/environments/deployment_safety/
  37. Protected environments API — https://docs.gitlab.com/api/protected_environments/
  38. Group protected environments API — https://docs.gitlab.com/api/group_protected_environments/
  39. Environments dashboard — https://docs.gitlab.com/ci/environments/environments_dashboard/
  40. GitLab pricing — https://about.gitlab.com/pricing/
  41. GitLab feature comparison — https://about.gitlab.com/pricing/feature-comparison/
  43. GitLab maintenance policy — https://docs.gitlab.com/policy/maintenance/
  44. GitLab 19.4 released (2026-09-17) — https://docs.gitlab.com/releases/19/gitlab-19-4-released/
  45. GitLab 19.5 release note (upcoming) — https://docs.gitlab.com/releases/19/gitlab-19-5-released/

## The comparison table

The site table lives in
[Keep-Shipping/website](https://github.com/Keep-Shipping/website), not in this
repository. We have not seen its exact wording, so what follows is the rule we
intend to hold it to, not an edit of the table itself. The copy issue is
[Keep-Shipping/website#5](https://github.com/Keep-Shipping/website/issues/5).

### The rule

A row may only state what a numbered source above supports. If no source supports
it, the row either gets a source or it comes out. The **"Maturity, New. That's
why it's early access."** row stays as it is: it is the accurate description of a
project whose README says nothing runs yet, and softening it in either
direction would be worse than leaving it.

### Sourced facts that constrain the categorical rows

These constrain any row reading "YAML-based CI" or "shell scripts, glued". Such
a row must not imply that YAML CI has no approvals, because the incumbents have
them:

- GitHub Actions environments have required reviewers, wait timers, self-review
  prevention, admin bypass and branch and tag policies ([19], [17]). Custom
  protection rules are available in public repositories for all plans, and
  require Enterprise in private and internal repositories ([22], [23]).
- GitLab's deployment approvals and protected environments are Premium and
  Ultimate ([32], [34]).
- Atlantis gates apply on `apply_requirements`, and can invalidate an approval
  whenever a new plan is produced ([2]).
- Octopus Deploy has both an in-process manual intervention step and a
  space-level Approvals system in Public Preview ([3], [4]).
- Kargo lets a human promote Freight to a Stage in open-source Kargo ([5]); it
  does not document an OSS approval *step*.
- Argo CD and Flux have no first-class human approval gate. Argo CD gates on
  manual sync and sync windows ([2]); Flagger's promotion is analysis-driven
  ([5]).

So the differences we can support, and only these, are properties of the file
rather than of the category:

- **The approval is bound to the plan's digest.** The engine refuses a verdict
  whose artifact list differs by one digest, and apply applies the saved plan or
  stops and asks again ([`../STALE_PLANS.md`](../STALE_PLANS.md),
  [`../GITHUB_APPROVALS.md`](../GITHUB_APPROVALS.md)). Note the limit stated in
  the same doc: with `recheck` off, attribute-value drift under an action the
  plan already takes is **not** caught.
- **The file is checked before anything runs**, so a broken or undeclared
  reference is refused rather than discovered mid-deploy
  ([`../../README.md`](../../README.md), [`../LANGUAGE.md`](../LANGUAGE.md)).
- **The same file runs on a laptop and in CI**, because steps only see ports and
  adapters are the only vendor-aware code ([`../../README.md`](../../README.md)).
- **Environments declare their approvers, secrets and CI-only flag in the same
  file** ([`../LANGUAGE.md`](../LANGUAGE.md)).

### Rows to check on the site

- [ ] Does any row say YAML CI cannot gate a deploy? Cut or reword; cite [17],
      [19], [32], [34], [3].
- [ ] Does any row imply an approval is bound to reviewed content? Only true for
      us, and only for the digests we bind. Check against
      [`../STALE_PLANS.md`](../STALE_PLANS.md), including the `recheck` limit.
- [ ] Does any row claim approvals work on private repos without naming the
      plan? Name it, or drop the claim ([19], [22], [23], [32], [34]).
- [ ] Does the Earthly row say "no longer maintained" without a date? Cite [9],
      [11], [12].
- [ ] Does the env0 row use a name we cannot source? The company brands itself
      "env zero" while accounts stay `env0` [1]; use one consistently.
- [ ] Does any row imply Keep Shipping is running today? It is not; the maturity
      row carries that and must stay ([`../../README.md`](../../README.md), 5).
- [ ] Is every vendor row's status claim dated, and no older than the sources in
      this page?

### Open questions, and what is not verified

- Which plan gives **required reviewers on a private repository** at GitHub. The
  reference page says public-only on Free, Pro and Team [19] and does not name
  the private-repo tier (not verified).
- Whether **custom deployment protection rules** are GA. Docs still say public
  preview [25]; the roadmap issue says shipped [24]. Treat as unconfirmed.
- GitHub's **deployment history retention period** and the **number of
  environments** per plan (not verified).
- **Spacelift's** current version and cadence: no official feed found [4].
- **OpenTaco's** latest release version and date; **env0's** funding since the
  2023 Series A; **Garden's** commercial status after the 2024 acquisition.
- **Harness CD's** platform version scheme, and any semver for the platform.
- Kargo's **OSS/Enterprise boundary beyond** manual promotion,
  `wait-for-approval` and the Enterprise 1.12 items recorded above.
- Whether we should say anything about **Argo CD's and Flux's** exact EOL dates
  per minor version. Not researched.

## Refreshing this page

Whoever takes it next: re-fetch the sources per tool, compare each bullet, and
update the *Checked* column. Refresh a tool in the week you write about it, not
the week you last read about it. If a row cannot be re-sourced on the day it is
published, it does not get published.