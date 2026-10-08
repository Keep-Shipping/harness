# Clusters

Which cluster a run targets, and how it authenticates
([#75](https://github.com/Keep-Shipping/harness/issues/75)).

The rule underneath everything: **a step says what should be running; a
`Cluster` says where, and how it authenticates — never with what credential.**
A step applies manifests, installs a chart, waits on a rollout; it does not know
or care which cluster answered.
[`k8s::Cluster`](https://github.com/Keep-Shipping/harness/blob/main/crates/core/src/k8s.rs)
is the value that carries the *where* and the *method*: a kubeconfig context or
an API server URL, an optional namespace, and one of four named ways to
authenticate. What that method commits an adapter to is resolving it at call
time — minting a token, invoking a credential plugin, reading the node's own
projected service account — and holding the result for the length of one call;
**the credential the run authenticates with is never in the value.** What an
exec plugin's environment has to be able to carry is the configuration the
plugin *mints* one from, and those values are stored, because a plugin called
without its key cannot get one. They are ordinary strings and nothing inspects
one. What keeps them out of a log is redaction, not construction:
[`Debug`](#debug-redacts-environment-values) prints the variable names and
never a value, which is what makes printing and cloning a `Cluster` safe.

The same value comes from three places — an IaC output's flat records read by
`Cluster::from_record`, a named kubeconfig context (`Target::Context`), a plain
URL (`Target::Server`) — which is why it is a type and not a convention.
`ks-core` reads none of them itself: it has no YAML dependency and does no file
I/O, so parsing a kubeconfig is the adapter's job and this type only decides
what a target *is*, and refuses what it must not be.

## Targeting

There are two ways to name a cluster.

`Target::Context` names a **kubeconfig context** — the string `kind` writes
locally, the string a cloud provider's own CLI writes in a managed cluster. It
carries up to three fields: the context name, an optional kubeconfig path to
read it from when it is not the file the environment points at, and an optional
API server URL when the source named one.

```rust
use ks_core::k8s::{Auth, Cluster, Target};

let cluster = Cluster::new(
    Target::Context {
        context: "kind-kind".to_string(),
        kubeconfig: Some("/etc/kube/acme.yaml".to_string()),
        server: None,
    },
    Some("apps".to_string()),
    Auth::InCluster,
)
.expect("a named target");

assert_eq!(cluster.target().context(), Some("kind-kind"));
assert_eq!(cluster.target().kubeconfig(), Some("/etc/kube/acme.yaml"));
assert_eq!(cluster.namespace(), Some("apps"));
```

`Target::Server` names the **API server URL** directly, for a target no
kubeconfig names — a kind cluster reached by its own address, or an in-cluster
address the pod knows without a file.

```rust
use ks_core::k8s::Target;

let target = Target::Server { server: "https://127.0.0.1:6443".to_string() };
assert_eq!(target.server(), Some("https://127.0.0.1:6443"));
```

Three accessors read the target back without matching on it: `context()`,
`kubeconfig()` and `server()`. Each answers `None` for the variant that cannot
supply it — `context()` and `kubeconfig()` are `None` for `Target::Server`, and
`server()` is `None` for a `Target::Context` that named no endpoint.

### A context and its endpoint

`Target::Context` carries an optional `server`. `Some(url)` is the endpoint the
source named. `None` means *resolve this*, which means reading a kubeconfig —
and resolving one is the adapter's job: `ks-core` has no YAML dependency and no
file I/O, so nothing in this repository reads a kubeconfig at all. The only
implementation of the `Cluster` port is `FakeCluster`, which does no
authentication.

What the type does support is stated as a field's meaning rather than as a
precedence rule. `Cluster::to_ref()` hands the port `(context, endpoint, auth)`
and, where the target named no `server`, **synthesises `endpoint` as the
context name** — a stand-in for the adapter to overwrite once it has read the
kubeconfig. See [Safety of the
handle](#safety-of-the-handle) for the other synthesised field. The
`kubeconfig` path itself does not travel on the `ClusterRef`; it stays on the
`Cluster`, for the adapter that resolves it.

A `kubeconfig` path is a path. It is never a credential, and it is why a
`Context` target plus a kubeconfig path is safe to hand to an adapter whole.

`Cluster::new` refuses a target that names nothing — an empty context, an empty
URL, a `server` that is present but blank — with `ClusterError::Empty { name:
"cluster target" }`. A present-but-blank namespace is refused the same way, with
`name: "namespace"`.

## Authentication

`Auth` is an enum of four methods, and the invariant is the shape rather than a
convention: **no variant carries the credential the run will authenticate
with.** What a variant does carry is the method, and whatever configuration is
needed to mint one from — see below.

| Variant | What the method commits an adapter to doing at call time |
| --- | --- |
| `Auth::InCluster` | Read the service account the harness itself is running as — a pod's projected token, mounted by the platform. |
| `Auth::WorkloadIdentity` | Exchange the platform's own identity (IRSA, Workload Identity Federation, a CI job's OIDC token) for Kubernetes credentials, with no static secret anywhere in the run. |
| `Auth::ServiceAccount(ServiceAccount)` | Look a named account up through the cluster's own API. Built through `Auth::service_account`, and read back through `service_account_name()`. |
| `Auth::ExecPlugin(ExecPlugin)` | Spawn the external credential plugin named in the value and use what it prints, inside the adapter. |

```rust
use ks_core::k8s::Auth;

let account = Auth::service_account("deployer").expect("a named account");
let pod = Auth::InCluster;
let federated = Auth::WorkloadIdentity;

assert_eq!(account.service_account_name(), Some("deployer"));
// Three of the four variants name no account, so the accessor is Option-shaped.
assert_eq!(pod.service_account_name(), None);
assert_eq!(federated.service_account_name(), None);
```

`Auth::service_account` is the convenient constructor, wrapping the port's
`ServiceAccount` newtype, whose field is private. The variant itself is public,
so downstream code may write `Auth::ServiceAccount(ServiceAccount::named(…)?)`
directly; what the private field buys is that the name can only arrive through
a validating constructor, so `Auth::ServiceAccount { name: "  " }` does not
compile and `ServiceAccount::named` refuses `""`, `"   "` and `"\t\n"` alike, all
three with `ClusterError::Empty { name: "service account name" }`. **A blank
account name cannot be constructed at all**, which is the real invariant. That
check lives in the newtype, not in `Cluster::new`, because an account with no
name is a misconfigured target, not a lookup worth attempting. Read the name
back with `Auth::service_account_name(&self) -> Option<&str>`.

### Exec plugins

`ExecPlugin` is the managed-cloud case: EKS's `aws eks get-token`, GKE's
`gke-gcloud-auth-plugin`, AKS's `kubelogin`, and the older
`aws-iam-authenticator`. It holds the *name* of a program to spawn, its
arguments, an environment to call it with, and the `exec` stanza's `apiVersion`
— and nothing the plugin ever returned.

```rust
use ks_core::k8s::{ExecPlugin, DEFAULT_EXEC_API_VERSION};

let plugin = ExecPlugin::new(
    "aws",
    vec![
        "eks".to_string(),
        "get-token".to_string(),
        "--cluster-name".to_string(),
        "prod-eu".to_string(),
    ],
    vec![("AWS_PROFILE".to_string(), "prod".to_string())],
    DEFAULT_EXEC_API_VERSION,
)
.expect("a plain command");

assert_eq!(plugin.command(), "aws");
assert_eq!(plugin.args(), ["eks", "get-token", "--cluster-name", "prod-eu"]);
assert_eq!(plugin.env(), [("AWS_PROFILE".to_string(), "prod".to_string())]);
```

`DEFAULT_EXEC_API_VERSION` is `ks_core::k8s::DEFAULT_EXEC_API_VERSION`, and is
`"client.authentication.k8s.io/v1beta1"` — the version used when a record names
none.

The environment is **conventionally configuration, not a credential**: a
profile, a region, a path. That is a convention, though, not an enforced rule —
nothing inspects a value, and a static key is accepted and stored, because a
plugin called without its key cannot mint a token. What makes the difference
safe is not the convention but the redaction: [`ExecPlugin`'s
`Debug`](#debug-redacts-environment-values) prints the variable *names* and
never their values, so `AWS_PROFILE=prod` and `AWS_SECRET_ACCESS_KEY=<a fake value>`
reach the `Cluster` intact and leave it as a name and an `…`. The credential the
run authenticates with is still the adapter's to mint at call time, and still
never lands in the value.

#### Why the command is checked and the arguments are not

A credential plugin is **spawned directly, never through a shell.** That single
fact fixes both halves of the validation:

- `ExecPlugin::new` refuses a `command` that is anything but one plain program
  name. Any whitespace, or any of the shell metacharacters `'` `"` `` ` `` `$`
  `|` `&` `;` `<` `>` `(` `)` `{` `}` `*` `?` `!` `~` `#` `\`, is refused with
  `ClusterError::Auth`. This is what refuses `sh -c '…'` outright — a shell line
  is not a program name — and it is refused *here*, while the record that named
  it is still in hand, rather than at spawn time after the reader has moved on.
- The **arguments are not checked at all**, on purpose. They go to the
  program, not to a shell, so `eks,get-token` is exactly right and an argument
  may hold anything. `aws` with an argument reading `get-token; rm -rf /` is a
  string handed to `aws`, which rejects it, not a command line that runs.

An empty command or an empty API version is refused with `ClusterError::Empty`
(`name: "exec plugin command"` / `"exec plugin api version"`), and an
environment variable whose name is not POSIX — `[A-Za-z_][A-Za-z0-9_]*`, so not
`AWS-PROFILE`, not `1AWS`, not `AWS PROFILE` — is refused with
`ClusterError::Auth`, because no adapter could export it. A blank variable name
is refused as `Empty { name: "exec plugin environment variable name" }`.

## From an IaC output

`Cluster::from_record` reads the flat key/value shape a `tofu.apply` output of
type `k8s.Cluster` carries, flattened by the adapter. Values are trimmed, and a
key set to blank counts as absent — a record that sets `namespace` to nothing
has not set a namespace.

| Key | Meaning |
| --- | --- |
| `context` | The kubeconfig context to target. Required unless `server` is given. |
| `server` | The API server URL. Alongside `context`, it is the endpoint `to_ref` uses; on its own it makes a `Target::Server`. |
| `kubeconfig` | The kubeconfig file to read the context from. A path. |
| `namespace` | The namespace to scope the run to. Optional. |
| `auth` | Required. One of `in-cluster`, `workload-identity`, `service-account`, `exec`. |
| `serviceAccount` (or `service-account`) | The account name, required by `auth: service-account`. |
| `exec.command` | The plugin to spawn. Required by `auth: exec`. |
| `exec.args` | Comma-separated arguments, trimmed; a trailing comma's empty entry is dropped. |
| `exec.env` | Comma-separated `NAME=value` entries, in the order written. An entry with no `=` is refused; an empty entry — a doubled or trailing comma — is dropped, exactly as it is in `exec.args`. |
| `exec.apiVersion` (or `exec.api-version`) | The stanza version; defaults to `DEFAULT_EXEC_API_VERSION`. |

A record with neither `context` nor `server` is refused with
`ClusterError::Empty { name: "context or server" }`. A missing `auth` is refused
with `ClusterError::Auth` naming the four values it accepts, and an `auth`
nobody recognises is refused with `ClusterError::Auth` naming the value it did
not.

```rust
use std::collections::BTreeMap;
use ks_core::k8s::{Auth, Cluster};

let mut record = BTreeMap::new();
record.insert("context".to_string(), "arn:aws:eks:eu-west-1:1:cluster/prod-eu".to_string());
record.insert("namespace".to_string(), "apps".to_string());
record.insert("auth".to_string(), "exec".to_string());
record.insert("exec.command".to_string(), "aws".to_string());
// A trailing comma leaves an empty argument behind, and it is not one.
record.insert("exec.args".to_string(), "eks,get-token,--cluster-name,prod-eu,".to_string());
record.insert("exec.env".to_string(), "AWS_PROFILE=prod,AWS_REGION=eu-west-1".to_string());

let cluster = Cluster::from_record(&record).expect("a well-formed record");
let Auth::ExecPlugin(plugin) = cluster.auth() else { unreachable!() };

assert_eq!(plugin.command(), "aws");
assert_eq!(plugin.args(), ["eks", "get-token", "--cluster-name", "prod-eu"]);
assert_eq!(plugin.api_version(), ks_core::k8s::DEFAULT_EXEC_API_VERSION);
assert_eq!(cluster.namespace(), Some("apps"));
```

### A record is state

**A record may never carry a credential as a field of its own.** This is not a
style preference and not a lint: an IaC output is *state*. It is committed, it
is in the plan a reviewer reads, it is in the apply log, and it outlives the run
that created it. A token written there has to be rotated by hand, and nothing in
the run that leaked it will say so. Discouraging it would be worthless here, so
`from_record` refuses it by name — see below. A value inside an `exec.env`
entry is a different case: a plugin may need a key before it can mint its own,
so that one is stored and kept out of `Debug` instead.

A *path* is fine, and public data is fine: `certificate-authority-data`,
`tokenFile` and `client-key` are all accepted, because a path is not a secret
and a CA certificate is public by definition. Only inline content is refused.

## What is refused

Every refusal below is a `ClusterError`. A missing field is
`ClusterError::Empty`; anything about *how* the run would authenticate is
`ClusterError::Auth`, because that is the question its message answers.

The last column mixes two things, deliberately and legibly: for every `Auth`
row it quotes the **inner `message`**, which is the part that answers the
question. `Display` wraps each of those in the port's own frame — a user
reading a run log sees `cluster authentication failed: <message>; check the
auth method's credentials`. For the `Empty` rows there is no wrapping to do: the
`Display` line is the variant's `name` plus one fixed sentence, so each is quoted
whole, as the user sees it. The two `auth` refusals build their list from one private
`AUTH_METHODS` constant, so the four values read the same whichever way the
record got them wrong.

| What | Error | Inner `message` (`Auth` rows); whole `Display` (`Empty` rows) |
| --- | --- | --- |
| A record key that *is* a credential: `token`, `id-token`, `idToken`, `access-token`, `accessToken`, `bearerToken`, `bearer-token`, `password`, `username`, `client-certificate-data`, `clientCertificateData`, `client-key-data`, `clientKeyData` | `Auth { message }` | `"token" would put the credential itself in the record, and an IaC output is state: authenticate with an exec plugin or the platform's identity instead` — it names the **key** and never echoes the value, even when that value is empty. |
| A nested credential key, e.g. `users[0].token` | `Auth { message }` | The same, with the full key. The leaf is what carries the value: matching splits on `.`, `[` and `]` and compares the last non-empty segment. |
| A shell metacharacter or whitespace in an exec plugin's `command` | `Auth { message }` | `exec plugin command "sh -c 'x'" must be one program name; ' ' is read by a shell, but a credential plugin is spawned directly` — the *first* offending character is named, so a shell line is reported against its space. |
| An env variable name that is not POSIX | `Auth { message }` | ``exec plugin environment variable "AWS-PROFILE" is not a POSIX name (`[A-Za-z_][A-Za-z0-9_]*`), so no adapter could export it`` |
| An `exec.env` entry with no `=` | `Auth { message }` | `exec.env entry "AWS_PROFILE" is not \`NAME=VALUE\`` — refused rather than dropped, because a plugin called without the variable it was promised fails at the API server, a long way from the record that lost it. Only this case is refused: an *empty* entry (`A=1,,B=2`) is dropped by the same filter that drops a trailing comma from `exec.args`, and never reaches this check. |
| A missing `auth` | `Auth { message }` | ``a cluster record must name `auth`: `in-cluster`, `workload-identity`, `service-account` or `exec` `` |
| An `auth` nobody recognises | `Auth { message }` | ``unknown auth method "gke": use `in-cluster`, `workload-identity`, `service-account` or `exec` `` |
| Neither `context` nor `server` | `Empty { name: "context or server" }` | `context or server must not be empty; set it in the cluster target` |
| An empty context or URL | `Empty { name: "cluster target" }` | `cluster target must not be empty; set it in the cluster target` |
| An empty namespace | `Empty { name: "namespace" }` | `namespace must not be empty; set it in the cluster target` |
| An empty plugin command | `Empty { name: "exec plugin command" }` | `exec plugin command must not be empty; set it in the cluster target` |
| An empty plugin API version | `Empty { name: "exec plugin api version" }` | `exec plugin api version must not be empty; set it in the cluster target` |
| A missing or blank service account name | `Empty { name: "service account name" }` | `service account name must not be empty; set it in the cluster target` |

Note what the refusals do *not* say: none of them echoes the offending value. A
record with `token` set to a real bearer token produces a message naming
`"token"` and nothing more, so the failure path is as safe as the success path.

## Worked examples

### kind, locally, over a kubeconfig

`kind create cluster --name kind` writes a context named `kind-kind` into your
default kubeconfig. Target it by that name:

```rust
use ks_core::k8s::{Auth, Cluster, Target};

let cluster = Cluster::new(
    Target::Context {
        context: "kind-kind".to_string(),
        kubeconfig: None,   // the default kubeconfig
        server: None,       // the adapter reads the endpoint from it
    },
    Some("apps".to_string()),
    Auth::InCluster,
)
.expect("a named target");

assert_eq!(cluster.target().to_string(), "context kind-kind");
```

To target a non-default `KUBECONFIG`, set `kubeconfig` to the path rather than
exporting anything into the adapter's environment — the path travels in the
value, so two runs against two files need no environment juggling:

```rust
use ks_core::k8s::{Auth, Cluster, Target};

let cluster = Cluster::new(
    Target::Context {
        context: "kind-kind".to_string(),
        kubeconfig: Some("/tmp/kind-ci.yaml".to_string()),
        server: Some("https://127.0.0.1:6443".to_string()),
    },
    None,
    Auth::InCluster,
)
.expect("a named target");

assert_eq!(
    cluster.target().to_string(),
    "context kind-kind (kubeconfig /tmp/kind-ci.yaml)",
);
```

**`kubectl config use-context` must not be needed.** Harness addresses the
context explicitly, by name, on the value; it does not mutate your current
context, so two steps in the same run — or two runs in the same terminal — do
not interfere with each other's idea of "now". A kubeconfig write is never part
of this path.

The round trip is covered by `a_kind_context_round_trips` in
`crates/core/src/k8s.rs`, which builds the context `kind-kind` with *both* a
kubeconfig (`/etc/kube/acme.yaml`) and a server (`https://127.0.0.1:6443`) —
the shape the `kind` CLI leaves behind — and checks that all three survive
construction unchanged, along with the namespace, the auth and the `Display` a
log line uses. The other tests in that file, all offline and none needing a
cluster:

| Test | What it pins down |
| --- | --- |
| `a_cluster_is_send_and_sync` | A `Cluster` and an `ExecPlugin` cross a thread boundary — the engine holds them. |
| `an_exec_plugin_reads_back_its_arguments` | EKS's `aws` read back with its arguments and environment, and GKE's `gke-gcloud-auth-plugin`, AKS's `kubelogin` and an absolute-path `aws-iam-authenticator` all accepted: the check is on shape, not on a plugin list. |
| `a_shell_metacharacter_in_a_command_is_refused` | Seven shell lines refused, and an argument reading `get-token; rm -rf /` accepted. |
| `an_empty_command_or_api_version_is_refused` | A blank command and a blank api version. |
| `an_unusable_environment_variable_name_is_refused` | `AWS-PROFILE`, `1AWS`, `AWS PROFILE` and a blank name. |
| `a_record_never_carries_a_credential` | Every spelling in the table above, an empty value, and `users[0].token`. |
| `a_path_and_public_data_are_not_a_credential` | `certificate-authority-data`, `tokenFile` and `client-key` accepted. |
| `an_exec_record_builds_the_whole_plugin` | The whole EKS record, trailing comma and default API version included. |
| `the_other_auth_methods_build_from_a_record` | `service-account`, `workload-identity` and `in-cluster`, the last by `server` alone. |
| `a_malformed_record_is_refused_with_a_usable_message` | No target, no `auth`, an unknown `auth`, an `exec.env` entry with no `=`. |
| `a_clusters_debug_output_carries_no_token` | A record carrying `AWS_SECRET_ACCESS_KEY=<a fake value>`: `env()` still holds the value, `Debug` keeps the name, the api version and `get-token` but not the value — and the refusal for an inline `token` never contains that value either. |
| `a_plugins_debug_output_carries_no_environment_value` | `ExecPlugin`'s own `Debug`, without a `Cluster` around it: two environment values redact to exactly two ellipses, every name and every argument survives. |
| `a_rejected_auth_method_lists_the_four_it_accepts` | Both the missing-`auth` and unknown-`auth` refusals name the same four values, from one constant. |
| `a_blank_service_account_name_is_refused` | `""`, `"   "` and `"\t\n"` refused through `Auth::service_account`; `service_account_name()` returns the name for the variant and `None` for `InCluster`; `to_ref()` carries the account to the port. |
| `the_port_handle_carries_the_method_and_nothing_else` | `to_ref()` and `TryFrom` produce the same handle. |
| `a_stand_in_context_and_endpoint_still_produce_a_handle` | The synthesised context name and endpoint, both ways. |
| `a_blank_field_is_empty_not_a_target` | A blank context, URL or namespace is `Empty`, not a target. |

### A managed cloud cluster (EKS)

**A live EKS test needs a real account, real cloud credentials and a human, and
it is not covered by the automated suite.** Nothing in this repository has
authenticated against a real EKS cluster, and the rows below carry no claim
that one has. What *is* covered is the typed value the record builds, by the
offline tests listed above — chiefly `an_exec_record_builds_the_whole_plugin`
and `a_clusters_debug_output_carries_no_token`. Read the untested rows in
[REGISTRIES.md](REGISTRIES.md) for the same reasoning applied to pushes; this
page is that page's argument made for clusters.

The record a provider's tool would produce:

```text
context        = arn:aws:eks:eu-west-1:1:cluster/prod-eu
namespace      = apps
auth           = exec
exec.command   = aws
exec.args      = eks,get-token,--cluster-name,prod-eu
exec.env       = AWS_PROFILE=prod,AWS_REGION=eu-west-1
```

What an adapter is *required* to do with it — the contract the port imposes, not
a description of code in this repository — is to spawn `aws` directly with those
arguments, in that environment, and to use the short-lived token the command
prints for the length of one call, holding it only in the adapter's own frame
and never writing it to the run's state or its log. **No adapter in this
repository implements `Cluster` authentication yet.** The only implementation is
`FakeCluster` in `crates/testing/src/cluster.rs`, which does none of the above
and authenticates by workload identity; everything on this page about spawning
and tokens is the port's requirement, not a claim about a caller that exists.

What is real today is the other half. The port's handle carries an
`AuthMethod::ExecCredential` naming `aws` — the plugin, not its output — so a
`Clone` or a `Debug` of anything this repository does build has no token in it
to spread, whatever an adapter goes on to do with the plugin's stdout.

GKE and AKS work through the same mechanism, with their own plugin commands:

| Provider | `exec.command` | Typical `exec.args` |
| --- | --- | --- |
| EKS | `aws` | `eks,get-token,--cluster-name,<cluster>` |
| EKS (older) | `aws-iam-authenticator` | `token,-i,<cluster-name>` |
| GKE | `gke-gcloud-auth-plugin` | *(none)* |
| AKS | `kubelogin` | `get-token,--login,<server-id>` |

The check is on the command's *shape*, not on a list of known plugins: one
plain program name with no whitespace and no metacharacter is accepted,
whatever it is called. That is what lets a vendor ship a plugin this repository
has never heard of.

## Safety of the handle

`Cluster::to_ref()` — and `TryFrom<&Cluster> for ClusterRef`, which is the same
call — hands the port a `ClusterRef`: a **context**, an **endpoint** and an
**`AuthMethod`**. That is the whole contract between the value and the adapter,
and none of the three can hold a credential.

```rust
use ks_core::ports::cluster::{AuthMethod, ClusterRef};

let handle = ClusterRef::new("prod-eu", "https://10.0.0.1:6443", AuthMethod::WorkloadIdentity)
    .expect("a named target");

assert_eq!(handle.context(), "prod-eu");
assert_eq!(handle.endpoint(), "https://10.0.0.1:6443");
assert_eq!(handle.auth(), &AuthMethod::WorkloadIdentity);
```

`ClusterRef::new` refuses an empty context or endpoint with
`ClusterError::Empty`, because a handle that names no target cannot fail safely.
`AuthMethod` is one of `InCluster`, `WorkloadIdentity`,
`ServiceAccount(ServiceAccount)` and `ExecCredential(ExecCredential)` — the two
named variants hold validated newtypes rather than bare strings, so an account
or a plugin with an empty name cannot be constructed at all. That makes
"safe in a log line" an invariant rather than a convention.

A `Cluster` is `Clone` and `Debug` too, so one can be cloned and printed into
whatever a run record is made of without leaking anything — but that is not this
shape's doing. A `Cluster` holds an `ExecPlugin`, and it is the plugin's own
hand-written `Debug`, described next, that keeps the value out.

### `Debug` redacts environment values

There is exactly one place a value a credential could be minted from is stored
in this type: an `ExecPlugin`'s environment. It has to be there — the plugin is
spawned with it — so what changes is only what gets printed. `ExecPlugin` has a
hand-written `Debug` that keeps the command, the arguments in full and the api
version, and replaces every environment *value* with a single `…`:

```text
ExecPlugin { command: "aws", args: ["eks", "get-token", "--cluster-name", "prod-eu"], env: [("AWS_SECRET_ACCESS_KEY", "…")], api_version: "client.authentication.k8s.io/v1beta1" }
```

The name survives on purpose: it is what a reader uses to find the variable and
decide for themselves where its value came from. `Cluster` and `Auth` keep
their derived `Debug`, so a `Cluster` printed on its own is safe transitively —
`redaction happens at the Debug boundary, not at construction`.
`a_plugins_debug_output_carries_no_environment_value` pins this down on the
plugin alone, and `a_clusters_debug_output_carries_no_token` on the whole
value: it builds a record carrying `AWS_SECRET_ACCESS_KEY=<a fake value>`,
asserts `env()` still holds it, that `Debug` omits the value while keeping the
name, the api version and `get-token` — and, from the same record with a `token`
key added, that the refusal does not contain that value either.

Two fields are synthesised on the way to the handle, because the port names
both a context *and* an endpoint:

- Targeting by `Target::Server`, the URL is also the context name — there is no
  other name for that cluster.
- Targeting a `Target::Context` that named no `server`, the context name stands
  in as the endpoint, for the adapter to overwrite once it has read the
  kubeconfig.

As [A context and its endpoint](#a-context-and-its-endpoint) says, that second
stand-in is all this repository can offer: nothing here reads a kubeconfig, so
`None` for `server` stays `None` until an adapter resolves it.

An `ExecPlugin` keeps its arguments, environment and `apiVersion` on the
`Cluster`. The port's `ExecCredential` names the plugin alone; the rest is the
adapter's to spawn with.

## Seeing the auth method

`Target` implements `Display`, and that is what a log line gets:

```text
context prod-eu (kubeconfig /etc/kube/acme.yaml)
context kind-kind
server https://127.0.0.1:6443
```

A context with a kubeconfig path names the path in parentheses; a context without
one is just the name; a server target is the URL prefixed by `server`. A name
and a URL are not secrets, so this format is safe in a run log. The auth method
is not printed by `Display` — it is read through `auth()`, and it is visible in
the `Debug` of an `AuthMethod`, which names the account or the plugin and holds
nothing else.