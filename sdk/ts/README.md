# `@keepshipping/sdk`

The TypeScript escape hatch ([ADR 0009](../../docs/adr/0009-typescript-escape-hatch-runtime.md)): a script step is a module that
default-exports one `step({...})`. Its `inputs` are typed descriptors — `string()`, `int()`,
`secret()`, `digest()`, … — that `keepshipping check` reads as the step's schema; `run` receives
them decoded, beside `log`, `signal`, `workdir` and `env`.

```ts
// ship/migrate.ts
import { step, secret, int } from "@keepshipping/sdk"

export default step({
  inputs: { db: secret(), batch: int() },
  outputs: { applied: int() },
  async run({ db, batch, log }) {
    const applied = await migrate(db.reveal(), batch)
    log(`applied ${applied} migrations`)
    return { applied }
  },
})
```

## Testing a step: `@keepshipping/sdk/testing`

`runStep(step, inputs, options?)` runs one step in your own test runner — `node --test`, Vitest,
Deno — with no host, no network and no real secrets. It calls the step the way the host does
(decode the inputs, run, check the outputs against what the step declares) and returns
`{ outputs, logs }`, every log line as `{ level, message }`.

A `secret()` input is given as a plain string: pass an obviously fake value. Every value a secret
input was handed is scrubbed to `***` out of each log line and each error message, so asserting
that a step never logged its secret means something. Every failure — a step that throws, an input
that does not decode, an output that is missing, mistyped or undeclared, or an output that carries
a secret's value — rejects with `StepFailed`, whose `message` and `logs` are scrubbed. Its `cause`
is the step's own error, unscrubbed: the one thing not to paste anywhere.

```ts
// ship/migrate.test.ts
import assert from "node:assert/strict"
import { test } from "node:test"
import { runStep } from "@keepshipping/sdk/testing"
import migrate from "./migrate.ts"

test("migrate applies the batch and never logs the database secret", async () => {
  const fake = "fake-db-value"
  const run = await runStep(migrate, { db: fake, batch: 3 })
  assert.equal(run.outputs.applied, 3)
  assert.ok(run.logs.every((line) => !line.message.includes(fake)))
})
```

To run the step itself from the command line with hand-picked inputs instead, `keepshipping run
--only migrate --input batch=3 --input db=@secret:dev-db --dry-run` checks and echoes them; see
[docs/DIAGNOSTICS.md](../../docs/DIAGNOSTICS.md).

## Developing the SDK

```sh
bun install --frozen-lockfile
bun run check   # type-check src, test and examples
bun run build   # dist/
bun run test    # node --test
```
