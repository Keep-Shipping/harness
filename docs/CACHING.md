# Step caching

Skip a step's work when the inputs provably have not changed
([#43](https://github.com/Keep-Shipping/harness/issues/43)).

The rule underneath everything: **a wrong hit is worse than no hit.** Anything the engine cannot
read — a cache entry that will not decode, a build context it cannot walk — is a miss, logged
as such. Never a guess.

## What participates

A step opts in, per run, through `StepKind::caching`. The default is `Caching::Never`, so
nothing skips unless it says so:

```rust
fn caching(&self, inputs: &Inputs) -> Caching {
    Caching::Keyed(vec![CacheInput::File(context)])
}
```

`oci.image` opts in — a build of the same context is the same bytes. `tofu.plan` and `deploy`
never do: the world they read changes between runs, and no key can cover that.

## What the key covers

`ks_engine::cache::cache_key` hashes, with SHA-256: the key domain tag, so an encoding change
makes every entry a miss; the step's name, version and `STEP_API` contract; **every resolved
input**, after defaults are applied, in sorted order; then each declared `CacheInput` in order —
a `File` (or directory) hashed by relative path, kind and contents, symlinks by target and never
followed, a `Tool` version, or a `Value`.

Every field is length-prefixed and every sequence counted, so two different inputs can never
produce the same bytes, and no map is walked in hash order. The key renders as `sha256:<hex>`.

## Verification before skip

A key match is not enough. Before skipping, the engine hands the cached outputs back to the
step through `StepKind::verify_cached`, with a context holding only the step's declared ports.
Only `CacheCheck::Valid` skips; `CacheCheck::Stale` rebuilds. The default is `Stale`, so a step
that opts in and forgets to verify never skips.

The engine logs the evidence through the run's redacting logger, which is how a skip says why:
`Hit` logs `step skipped` with `reason="cache hit: inputs unchanged"` plus `key` and `evidence`;
`Stale` logs `cache entry stale` with `key` and `evidence`, then `rebuilding`; `Miss` logs
`cache miss` with `key`.

## Where the local cache lives

`DirCache`, one file per key, under `$XDG_CACHE_HOME/keepshipping/steps` (falling back to
`$HOME/.cache/keepshipping/steps`). Entries are written to a temporary file and renamed into
place, so a reader never sees a half-written entry; one that will not decode is a miss, not an
error. `StepCache` is engine-local storage, not a port — nothing outside the engine depends on
it.

## Not done yet

- **No CI cache.** Nothing here uses the GitHub Actions cache API or a registry-backed cache;
  both follow ADR 0008's GitHub Actions-first ordering.
- **No `keepshipping run` wiring.** `run_step_cached` is the seam; the executor (#41) calls it
  once there is a run loop.
- **No built-in step caches yet.** `builtin_steps()` is still empty; `oci.image` arrives with
  #59.
- **No cache eviction.** Entries are small and never expire.