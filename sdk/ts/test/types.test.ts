// Type-level tests. There is nothing to run here: each case either carries a
// `@ts-expect-error` (it must be an error, and `tsc` fails on an unused one)
// or is an assignment that must compile.
import { test } from "node:test"

import {
  bool,
  digest,
  enumOf,
  int,
  list,
  optional,
  ref,
  secret,
  step,
  string,
  withDefault,
  type Digest,
  type Ref,
  type Secret,
} from "../src/index.ts"

test("the type-level cases are checked by tsc, not at run time", () => {})

// Positive: an enum infers its literals without `as const`, and each
// constructor hands `run` the documented type.
const mode = enumOf("rollout", "rollback")

step({
  inputs: {
    tag: string(),
    replicas: int(),
    on: bool(),
    db: secret(),
    image: digest(),
    previous: ref(),
    note: optional(string()),
    tags: list(string()),
    port: withDefault(int(), 8080),
    phase: mode,
  },
  async run({ db, image, previous, replicas, tags, port, phase }) {
    const a: Secret = db
    const b: Digest = image
    const c: Ref = previous
    const d: number = replicas + port
    const e: string[] = tags
    const f: string | undefined = undefined
    const g: "rollout" | "rollback" = phase
    return { used: [a.reveal(), b, c, String(d), e.length, f, g].length }
  },
})

// Positive: the context carries the run's non-secret values.
step({
  inputs: {},
  run: ({ env, signal, workdir, log }) => {
    const git: string = env.git.sha
    const branch: string | undefined = env.git.branch
    const dir: string = workdir
    const aborted: boolean = signal.aborted
    log(`${git}${branch}${dir}${aborted}`)
    return { ok: true }
  },
})

// Positive: the site's example, as it extracts: one secret in, a number out.
step({
  inputs: { db: secret() },
  async run({ db, log }) {
    const n = await Promise.resolve(db.reveal().length)
    log(`applied ${n} migrations`)
    return { applied: n }
  },
})

/**
 * Every case below is one `tsc` must reject, so none of it may run: the
 * reserved name throws and a mistyped output is not something to execute.
 */
function mustNotTypeCheck(): void {
  // @ts-expect-error `log`, `workdir` and `env` are the host's, never inputs.
  step({ inputs: { log: string() }, run: () => ({}) })
  // @ts-expect-error `workdir` is the host's too.
  step({ inputs: { workdir: string() }, run: () => ({}) })
  // @ts-expect-error `env` is the host's too.
  step({ inputs: { signal: bool() }, run: () => ({}) })

  // @ts-expect-error outputs cannot be Secret in v1.
  step({ inputs: {}, outputs: { token: secret() }, run: () => ({ token: "" }) })

  // Kept on one line: TypeScript 7 reports the overload failure on the `outputs`
  // property rather than on the call, so a wrapped call would leave the
  // directive unused and the error unclaimed.
  // @ts-expect-error `applied` is an int, so `run` may not return a string for it.
  step({ inputs: {}, outputs: { applied: int(), name: string() }, run: () => ({ applied: "3", name: "migrations" }) })

  // @ts-expect-error a declared output may not be missing from the return.
  step({ inputs: {}, outputs: { applied: int() }, run: () => ({ skipped: 0 }) })

  // @ts-expect-error an enum output only takes a value from its set.
  step({ inputs: {}, outputs: { mode: enumOf("rollout", "rollback") }, run: () => ({ mode: "ship" }) })

  // @ts-expect-error outputs must be JSON-serialisable, so a function is not one.
  step({ inputs: {}, run: () => ({ done: () => {} }) })

  // @ts-expect-error a digest is branded: a plain string is not an oci.Digest.
  const plain: Digest = "sha256:abc"

  // @ts-expect-error a ref is branded too: a bare digest is not `<repo>@<digest>`.
  const unpinned: Ref = `sha256:${"a".repeat(64)}`

  // @ts-expect-error and a Secret is not a string, however it prints.
  const leaks: string = new Secret("hunter2")
  void [plain, unpinned, leaks]
}

void mustNotTypeCheck