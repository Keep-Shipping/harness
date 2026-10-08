# Writing steps and adapters

A step is one `StepKind` implementation: a named, versioned unit of work with
a declared input and output schema. An adapter is one port trait
implementation: the only code in the workspace that knows how to talk to a
vendor. Steps ask, adapters answer, and nothing in between holds a credential
or a socket ([ADR 0002](adr/0002-ports-and-adapters.md)).

Two files carry the contracts this page points at:
[PORTS.md](PORTS.md) versions the port traits and holds their changelog, and
[STEPS.md](STEPS.md) is generated from the built-in step kinds — do not edit it
by hand. [COMPATIBILITY.md](COMPATIBILITY.md) is the table a step author reads
before depending on a version.

## What a step is

`StepKind` ([crates/core/src/step.rs](../crates/core/src/step.rs)) is the whole
interface, and it has eleven methods. Five of them you never write: `step_api`
defaults to the current `STEP_API`, `optional` to no ports, `capabilities` to
local-safe, `caching` to `Caching::Never` and `verify_cached` to "stale", so a
step that opts into caching but forgets verification never skips.

Of the six you do write, four are declaration and are checked for free at
`HarnessBuilder::build`: the name, the schema, the ports in `requires()`, and
the `STEP_API` the step was built against. The other two are behaviour and are
only as good as the tests: `action`, which says what policy should think of
this run, and `run`, which is a future returning the outputs.

A step's name is dot-namespaced by family (`oci.image`, `tofu.plan`,
`k8s.rollout`) — a convention, not something the harness checks — and it must
be unique within a harness, which `build()` does check. The name goes into the
run log. The version shows in generated docs and is hashed into the cache key;
bump it when the schema changes in a way a composition can notice. `step_api()`
reports the `STEP_API` this step was compiled against, and `build()` refuses a
mismatch rather than running a step against a contract it was not written for.

## The rules

- **Ports only.** A step never opens a socket, reads `std::env`, runs a
  process, or calls a vendor SDK. It reaches the world through
  `ctx.ports()`, and it gets handed only the ports it declared.
- **Declare what you need.** `requires()` is the ports without which the step
  cannot run; the harness refuses the whole composition
  (`CompositionError::MissingPort`) if one of them has no adapter.
  `optional()` is the ports the step uses when present — say so there rather
  than failing at the point of use.
- **Take time from the clock.** `ctx.clock()` is a port, not the system clock;
  a step that sleeps must sleep through it so its tests stay instant. The
  harness refuses a composition with no clock at all.
- **Honour cancellation.** `ctx.cancel()` is checked around long work. A run
  cancelled before the step starts never reaches `run`; the kit checks that.
- **Declare the action.** `action()` decides approvals, timeouts and log
  wording. A `deploy` into `prod` is not a `plan`, and it may be computed from
  the prepared inputs.
- **Never leak a secret.** Outputs are checked by `reject_secret_outputs` and
  fail the step rather than being masked; `StepError` messages bypass the
  redactor entirely; log lines pass through it. A secret belongs in a
  `Secrets` resolution and nowhere else.
- **Be a function of your inputs.** Two runs with the same inputs return the
  same outputs. No counters, no ambient time, no iteration order of a `HashMap`
  (use a `BTreeMap`).
- **Declare what the step needs of its environment** through
  `capabilities()` (`ci_only`, `oidc`, `network`), which defaults to
  local-safe. Opt into caching with `caching()`; the default is `Caching::Never`,
  and a step that opts in without `verify_cached()` never skips.
- **One crate, one family.** A step in its own crate holds one step family and
  depends on `ks-core` only, with `ks-testing` as a dev-dependency. A built-in
  today lives in `ks-engine`, which already depends on both.

## Registering a step

**A built-in.** Today the built-ins live inside `ks-engine`, not in
`steps/*` — [ARCHITECTURE.md](ARCHITECTURE.md#crates) marks that move as a
later epic. Adding one touches five places: the implementation in
`crates/engine/src/<name>.rs` (a `pub const NAME` there is recommended but only
two built-ins carry one — the rest return the literal from `name()`), a `pub
mod <name>;` line in `crates/engine/src/lib.rs`, an `Arc<dyn StepKind>` arm in
`builtin_steps()` (`crates/engine/src/steps.rs`), an entry in
`Catalog::builtin()` (`crates/core/src/catalog.rs`) so a `.ks` file naming the
step is checked rather than passing with no spec, and `docs/STEPS.md`,
regenerated with `KS_BLESS=1 cargo test -p ks-engine --test steps_doc` and
drift-checked otherwise.

`action()` and the catalog must agree. `crates/engine/tests/steps_doc.rs`
asserts every built-in's `action()` equals `ks_core::action_kind`, which falls
back to `ActionKind::Other` for a name the catalog does not know — so a step
added to `builtin_steps()` and not to the catalog silently becomes `other`.

**A step in its own crate.** Register it on the builder with `.step()` (or
`.step_arc()` for a step already behind an `Arc`); the compiled example below
does both registration and the conformance run. The builder collects every
error before failing: duplicate names, a missing port, a step-API mismatch, an
output that must not be secret, and each schema field's type, null rule and
default.

## Worked example: `hello.echo`

A step that echoes a message back, uppercased, and says whether it was handed a
token. The crate's manifest — `ks-core` is the only dependency, and
`ks-testing` is a dev-dependency, because a conformance library must not depend
on the engine it tests:

```toml
[package]
name = "ks-hello-echo"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true
repository.workspace = true

[dependencies]
ks-core.workspace = true

[dev-dependencies]
ks-testing.workspace = true

[lints]
workspace = true
```

The step, and the test that proves it. This is compiled and run as a doctest of
`ks_testing::StepAuthoringGuide`, so CI fails if the example below stops
building or stops passing the conformance kit
([#142](https://github.com/Keep-Shipping/harness/issues/142)). It is the same
scenario `ks_testing::step::HelloEcho` drives in its own unit test. That step
ships with the kit so that every check has one step that passes it; its
deliberately broken counterparts — a mistyped output, a counter in `run`, a
secret in a log line — live in `crates/testing/tests/step.rs`, and are what
stop the kit from passing vacuously.

```rust
use std::sync::Arc;

use ks_core::harness::Harness;
use ks_core::ports::BoxFuture;
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::step::{
    ActionClass, ActionKind, Field, Inputs, Outputs, Port, Ports, StepCtx, StepError, StepKind,
    StepSchema, TypeRef, Version,
};
use ks_testing::block_on;
use ks_testing::clock::FakeClock;
use ks_testing::step::{StepCase, step_conformance, text};

/// Echoes a message back, uppercased, and reports whether it was given a token.
pub struct HelloEcho;

impl HelloEcho {
    /// The step's registered name; what the conformance case below drives.
    pub const NAME: &'static str = "hello.echo";
}

impl StepKind for HelloEcho {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    fn schema(&self) -> StepSchema {
        StepSchema {
            doc: "Echoes a message back, uppercased, and reports whether it was given a token.",
            inputs: vec![
                Field::new("message", TypeRef::Builtin(ValueType::String), "the text to echo")
                    .with_default(Value::from("hello")),
                Field::new(
                    "token",
                    TypeRef::Builtin(ValueType::String),
                    "a token standing in for a resolved secret; it is never logged",
                )
                .with_default(Value::from("")),
            ],
            outputs: vec![
                Field::new("message", TypeRef::Builtin(ValueType::String), "the echoed message"),
                Field::new("upper", TypeRef::Builtin(ValueType::String), "the message, uppercased"),
            ],
        }
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn optional(&self) -> &'static [Port] {
        &[]
    }

    fn action(&self, _inputs: &Inputs) -> ActionClass {
        ActionClass::new(ActionKind::Other)
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let (message, token) = (text(&inputs, "message"), text(&inputs, "token"));
            // Whether a token is in use is worth recording; the token is not.
            // A field that says `set` cannot leak when the log is pasted into
            // a bug report.
            let state = if token.is_empty() { "unset" } else { "set" };
            ctx.log().info(&format!("echoing {message}"), &[("token", state)]);
            let mut outputs = Outputs::new();
            outputs.insert("message".to_string(), Value::from(message));
            outputs.insert("upper".to_string(), Value::from(message.to_uppercase()));
            Ok(outputs)
        })
    }
}

fn main() {
    // The composition under test: a fake clock, and the one step.
    let harness = Harness::builder()
        .ports(Ports::default().with_clock(Arc::new(FakeClock::new())))
        .step(HelloEcho)
        .build()
        .expect("the sample composition is valid");

    // The scenario: `token` carries a synthetic secret and `message` is left
    // out, so the step runs on its declared default.
    let mut inputs = Inputs::new();
    inputs.insert("token".to_string(), Value::from("not-a-real-token"));
    let case = StepCase::new(HelloEcho::NAME, inputs).with_secret("token", "not-a-real-token");

    block_on(step_conformance(&harness, case));
}
```

`step_conformance` panics rather than returning a `Result`: a conformance run
is a test, and the message naming the broken contract is the whole output. It
checks that the step runs on conforming inputs and returns exactly its declared
outputs, that a second identical run returns the same thing, that the marked
secret reaches neither a log record nor a `StepError`, and that a run cancelled
before the step starts is refused without logging.

## Writing an adapter

An adapter crate lives in `adapters/<name>`, depends on `ks-core`, and
implements one port trait. Async methods return `BoxFuture<'_, _>` — that is
what keeps the traits dyn-compatible, so an adapter can be handed to the builder
as an `Arc<dyn Trait>` through `.ports(...)` before `build()`, and swapped at
composition time. `ks-testing` is a dev-dependency again, and the adapter's own
tests run service-free.

The recommended test shape, in `adapters/<name>/tests/`:

- `adapter.rs` drives the adapter over `ks_testing`'s fakes, asserting the
  requests it builds and the responses it accepts or refuses.
- `conformance.rs` runs the port's own kit, gated behind an environment
  variable. Unset — the case in `cargo test --workspace` — the test prints that
  it skipped and returns, so the ordinary run stays free of live services
  ([ADR 0002](adr/0002-ports-and-adapters.md)).

In-tree adapters do not all split it that way: `ks-helm-cli` and `ks-tofu-cli`
carry only `conformance.rs`, `ks-hosted-approvals` runs the approval kit from
inside `adapter.rs`, and `ks-github` splits four ways because it implements two
ports. Take the shape, not the file count.

[`adapters/tofu-cli/tests/conformance.rs`](../adapters/tofu-cli/tests/conformance.rs)
is the clearest example — one test per binary, each skipping through a helper
that returns `None`, and a provider-free configuration written into a fresh
temp directory so the run needs no registry:

```text
fn temp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("ks-tofu-cli-{label}-{nanos}"));
    fs::create_dir_all(&dir).expect("a temp directory");
    fs::write(dir.join("main.tf"), CONFIG).expect("the configuration");
    dir
}

fn adapter(kind: IacKind, env: &str) -> Option<IacCli> {
    match std::env::var(env) {
        Ok(bin) if !bin.is_empty() => {
            Some(IacCli::new(kind, bin).expect("the binary answers `version -json`"))
        }
        _ => {
            eprintln!("skipping the {kind:?} conformance test: {env} is not set");
            None
        }
    }
}

#[test]
fn opentofu_passes_the_conformance_kit() {
    let Some(tool) = adapter(IacKind::OpenTofu, "KS_TOFU_BIN") else { return };
    block_on(conformance(&tool, &temp_dir("tofu")));
}
```

Which kit to run, and where it lives, is in the port table in
[PORTS.md](PORTS.md#port-reference).

## Review checklist

- [ ] The step is one `StepKind`, in one crate, depending on `ks-core` only.
- [ ] `name()` is unique in the harness and dot-namespaced by convention;
      `version()` moved if the schema did.
- [ ] `step_api()` is left at the default unless the step is built against a
      newer contract.
- [ ] Every port the step reaches for is in `requires()` or `optional()`, and
      nothing else is.
- [ ] No socket, no `std::env`, no process, no clock outside `ctx`.
- [ ] `ctx.cancel()` is checked around long work, and a cancelled run stops.
- [ ] `action()` is right for the step's worst case, not its usual one, and
      agrees with `ks_core::action_kind` if it is a built-in.
- [ ] No secret reaches an output, a log line or an error message.
- [ ] Two runs with the same inputs return the same outputs.
- [ ] `step_conformance` passes against a real `Harness`.
- [ ] `capabilities()` and `caching()` say what they mean, or say nothing.
- [ ] An adapter runs its port's `ks_testing` conformance kit, env-gated so
      the workspace test run stays service-free.
- [ ] A port trait was **not** changed. If it was, `STEP_API`, the changelog
      entry in [PORTS.md](PORTS.md#changelog) and the pinned digest all moved
      together — see [CONTRIBUTING.md](../CONTRIBUTING.md).

## What this does not do

This page does not cover the `.ks` surface syntax, which is
[LANGUAGE.md](LANGUAGE.md); the built-in step list, which is generated into
[STEPS.md](STEPS.md); or the policy and approval rules a step's `action` feeds
into. It also does not promise a step crate layout the workspace does not have
yet: `steps/*` is still a later epic, so a step in its own crate is a crate
nobody depends on until something composes it.