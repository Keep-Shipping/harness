# Helm

`ks-helm-cli` implements the [`Cluster`](PORTS.md) port by driving the `helm`
CLI. There is no mature Helm implementation in Rust, so the adapter shells out
— and it shells out to *Helm*, not to `kubectl`, because a chart is the unit the
port speaks in.

```rust
use ks_core::ports::cluster::{Chart, ChartUpgrade, Cluster, ImagePin, Values};
use ks_core::ports::supply_chain::ImageRef;
use ks_helm_cli::HelmCli;

let cluster = HelmCli::new("kind-kind").with_namespace("production");
let request = ChartUpgrade::new(
    "api",
    Chart::oci(ImageRef::parse(
        "reg.example.com/team/chart@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )?)?,
)?
.with_values(Values::new("replicaCount: 3"))
.with_set("ingress.host", "api.example.com")
.with_image(ImagePin::new(ImageRef::parse(
    "reg.example.com/team/api@sha256:…",
)?)?);

let rollout = cluster.upgrade(&request).await?;
```

## Constructors

| Constructor | What it is for |
| --- | --- |
| `HelmCli::new(context)` | Drives the kubeconfig context `context`. Panics on a blank context. |
| `HelmCli::try_new(context)` | The same, returning `ClusterError::Empty` for a blank context. |
| `HelmCli::with_handle(handle)` | Drives a `ClusterRef` the caller built — for an auth method or endpoint this adapter would not guess. |
| `.with_binary(path)` | Drives a wrapper script or a pinned Helm instead of `helm` on `PATH`. |
| `.with_kubeconfig(path)` | Sets `KUBECONFIG` explicitly, so a run does not depend on where it started. |
| `.with_namespace(ns)` | The namespace for a release whose request names none. |

The handle reports `AuthMethod::WorkloadIdentity`. The credential is whatever
Helm resolves from its own kubeconfig for the context; the adapter never holds,
copies or logs it.

## Charts are pinned by digest, in the URL

An OCI chart becomes

```
oci://reg.example.com/team/chart@sha256:<hex>
```

The digest goes **in the URL**, not in `--version`. Helm supports this from
**3.17.0**, and it rejects a digest alongside a `--version` that disagrees with
it — so this adapter emits no `--version` for any OCI reference.

**A tag is not a way to install a chart.** `Chart::oci(..)` refuses an
`ImageRef` that names a tag with `ClusterError::NotPinned { what: "chart" }`,
before any command runs. A tag can be repointed between the plan and the
apply, which is the thing a plan/apply split exists to prevent. Resolve the tag
to a digest first (`helm pull`, `crane digest`, the registry API — anything
that returns a `sha256:`) and pass that. The `Chart::Oci` variant is still
public, so a caller that has already resolved a reference may build one
directly; the adapter then emits `oci://<reference>` as given, tag or digest.
That path exists so such a chart still produces a working command rather than a
panic, not because it is recommended — prefer `Chart::oci(..)`. A
`Chart::Path` is passed through exactly as given.

## Atomic upgrade, and what "failed" means

Every install and upgrade is

```
helm upgrade --install <release> <chart> --atomic --cleanup-on-fail …
```

`--atomic` implies `--wait` and rolls the previous revision back when the new
one does not settle, so a failed upgrade leaves the release where it found it
rather than half-applied. On a **first-ever install** that fails there is no
previous revision to roll back to, and Helm says
`unable to find a previously successful release…`; that surfaces as
`ClusterError::Upgrade` carrying Helm's own stderr.

**An exit code is not a status.** Every Helm failure exits `1`, so a non-zero
exit cannot tell "installed" from "rolled back to a good revision", and exit `0`
only means Helm did not complain. After either outcome the adapter re-reads
`helm status -o json` and reports what the release actually is. A non-zero exit
is always `ClusterError::Upgrade` — including when the status query shows the
release `deployed` again, because a deploy that was rolled back did not deploy.

## Secret values

A `Values::secret` document **never reaches a command line**. It is written to a
temporary file created with mode `0600`, passed as `-f <path>`, and deleted when
the call returns — on every path, including an error or a panic, because the
deletion is a `Drop` guard rather than a line at the end of the function.

This matters because an argument is readable by every other process on the
machine for as long as the call runs, and by Helm's own process listing.

`Values::new` (non-secret) values take **the same path**. One code path is
easier to keep correct than two, and `-f` is what Helm reads best.

`ChartUpgrade::with_set` is a `--set` *argument* and therefore must never carry
a secret. That is a property of the caller, not something the port can enforce.

## The `image.digest` convention

`ImagePin` writes the container image's digest into the chart's values under a
key, by default `image.digest`:

```
--set-string image.digest=sha256:<hex>
```

`--set-string`, not `--set`: a digest has to stay a string, and `--set` would let
Helm's own coercion rules turn it into something else.

Charts that use a different shape name their own key:

```rust
ImagePin::at(image, "container.image.sha")?
// --set-string container.image.sha=sha256:<hex>
```

Both constructors — `ImagePin::new(..)` and `ImagePin::at(..)` — return
`Result`, and both refuse an `ImageRef` naming a tag with
`ClusterError::NotPinned { what: "image pin" }`. A mutable tag written under a
key called `digest` is a lie the cluster only discovers at rollout time. The
adapter holds the same rule independently: even a hand-built `ImagePin` carrying
a tag fails the call with `ClusterError::NotPinned` rather than emitting a
`--set-string image.digest=1.2.3`.

Dots in the key nest (`image.digest` → `{image: {digest: …}}`). Colons are safe
in a value, so a digest needs no escaping. Commas do need backslash-escaping —
but the adapter passes argv directly, with no shell, so escaping is Helm's
parser's business and yours only in a `--set` value.

## Health

`helm status <release> -o json` is the only read. `info.status` maps to the
shared [`Health`](PORTS.md) vocabulary:

| `info.status` | `Health` |
| --- | --- |
| `deployed` | `Healthy` |
| `pending-install`, `pending-upgrade`, `pending-rollback`, `uninstalling` | `Progressing` |
| `failed` | `Failed` |
| `superseded`, `uninstalled`, `unknown` | `Degraded` |
| anything else Helm grows later | `Degraded` — never optimistic |
| no `info.status` at all | `NoData` |
| release not found | `NoData`, with a reason |

`HealthReport::with_reason` carries Helm's own `info.description`, which is the
wording a run log shows while a `wait` gate polls.

**Silence is not health.** A release Helm does not have is `Health::NoData`,
which never satisfies a `wait: healthy` gate and never settles — a waiter keeps
polling rather than passing. `rollout`, which has to name something, returns
`ClusterError::NotFound` instead.

## Rollback

```
helm rollback <release> <revision> --wait [--namespace <ns>]
```

The revision the port names is always passed explicitly — Helm's optional
"previous revision" form is never used, because the port's rule is that a
revision asked for is a revision rolled back to. A revision the cluster no
longer retains is `ClusterError::RevisionUnknown`; the current revision is never
substituted for one that was asked for. The rollout is then read back from
`helm status`.

## Private registries

Pulling from a private OCI registry relies on credentials Helm already has:
`~/.docker/config.json`, or Helm's own registry config. Login separately:

```sh
helm registry login <host> -u <user> --password-stdin
```

This adapter does **not** implement registry login and does not handle a
password. `HELM_REGISTRY_USERNAME` / `HELM_REGISTRY_PASSWORD` are a CI
convention, not Helm variables — setting them does nothing here.

`HOME` is deliberately left in the environment for exactly this reason: it is
where Helm finds those credentials.

## Hermetic runs

`HELM_KUBECONTEXT` and `KUBECONFIG` are set explicitly on every invocation
rather than inherited, and the other Helm-shaped variables are cleared first
(`HELM_NAMESPACE`, `HELM_DRIVER`, `HELM_DEBUG`, the various `HELM_*_HOME`, …), so
an ambient `HELM_NAMESPACE` cannot redirect a release. `HOME` and `PATH` are the
two left in place: Helm needs `PATH` to be found, and `HOME` for the registry
config above.

## Limitations

- **No `apply`.** Helm does not apply raw manifests. `Cluster::apply` returns
  `ClusterError::Apply` and the adapter never shells out to `kubectl`. Use a
  manifest-oriented adapter for server-side apply.
- **No registry login.** See above.
- **Helm ≥ 3.17.0** is required for digest-pinned OCI pulls. Older Helm rejects
  the `oci://…@sha256:…` URL.
- **Blocking.** Every call waits on a child process. That is what Helm offers.
- **No `helm history`.** Rollback detection reads Helm's stderr wording rather
  than querying the revision history, so a Helm that changes that wording could
  report an unknown revision as an ordinary rollback failure — never the other
  way round.

## Tests

The unit tests drive a fake `Runner` and assert on the exact argv Helm would
have been given, so the digest-in-the-URL and secret-values rules are enforced
without a cluster, a kubeconfig or a `helm` binary.

The conformance kit installs a real chart on a real cluster and is gated on
`KS_HELM_CONFORMANCE=1`; unset — the case in `cargo test --workspace` — it skips.
See `adapters/helm-cli/tests/conformance.rs`.