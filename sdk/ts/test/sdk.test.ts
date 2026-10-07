// Runtime behaviour: what a secret prints, what a decode refuses, and what
// `invoke` hands `run` and takes back.
import assert from "node:assert/strict"
import { test } from "node:test"

import { digest, enumOf, int, list, optional, planFile, ref, Secret, step, string, withDefault } from "../src/index.ts"

const ctx = { workdir: "/repo", env: { git: { sha: "abc123", branch: "main" } } }

test("a secret prints *** however it is printed, and reveals only on request", () => {
  const secret = new Secret("hunter2")
  assert.equal(String(secret), "***")
  assert.equal(`${secret}`, "***")
  assert.equal(JSON.stringify({ secret }), '{"secret":"***"}')
  const hooks = secret as unknown as Record<symbol, () => string>
  assert.equal(hooks[Symbol.for("nodejs.util.inspect.custom")]!(), "***")
  assert.equal(hooks[Symbol.for("Deno.customInspect")]!(), "***")
  assert.equal(secret.reveal(), "hunter2")
})

test("a secret input decodes into a Secret, not a string", async () => {
  const migrate = step({
    inputs: { db: { kind: "secret" } },
    run: ({ db }) => {
      assert.ok(db instanceof Secret)
      return { len: db.reveal().length }
    },
  })
  assert.deepEqual(await migrate.invoke({ db: "hunter2" }, ctx), { len: 7 })
})

test("int refuses a fraction", async () => {
  const s = step({ inputs: { replicas: int() }, run: ({ replicas }) => ({ replicas }) })
  assert.deepEqual(await s.invoke({ replicas: 3 }, ctx), { replicas: 3 })
  await assert.rejects(() => s.invoke({ replicas: 1.5 }, ctx), /not a whole number/)
  await assert.rejects(() => s.invoke({ replicas: "3" }, ctx), /not a number/)
})

test("enum refuses a value outside the set", async () => {
  const s = step({ inputs: { mode: enumOf("a", "b") }, run: ({ mode }) => ({ mode }) })
  assert.deepEqual(await s.invoke({ mode: "a" }, ctx), { mode: "a" })
  await assert.rejects(() => s.invoke({ mode: "c" }, ctx), /not one of "a", "b"/)
})

test("a digest and a ref are checked the way the catalog names them", async () => {
  const s = step({ inputs: { image: digest(), ref: ref() }, run: ({ image }) => ({ image }) })
  const pin = `sha256:${"a".repeat(64)}`
  assert.deepEqual(await s.invoke({ image: pin, ref: `ghcr.io/acme/api@${pin}` }, ctx), { image: pin })
  await assert.rejects(() => s.invoke({ image: "latest", ref: "ghcr.io/acme/api:latest" }, ctx), /not a digest/)
  await assert.rejects(() => s.invoke({ image: pin, ref: "ghcr.io/acme/api:latest" }, ctx), /not a digest-pinned reference/)
})

test("a plan file needs all three members", async () => {
  const s = step({ inputs: { plan: planFile() }, run: ({ plan }) => ({ dir: plan.dir }) })
  const plan = { path: ".ks/plan.tfplan", sha256: "b".repeat(64), dir: "infra" }
  assert.deepEqual(await s.invoke({ plan }, ctx), { dir: "infra" })
  await assert.rejects(() => s.invoke({ plan: { ...plan, sha256: "nope" } }, ctx), /sha256/)
  await assert.rejects(() => s.invoke({ plan: { ...plan, path: "" } }, ctx), /path/)
})

test("a list decodes every item, naming the one that failed", async () => {
  const s = step({ inputs: { hosts: list(string()) }, run: ({ hosts }) => ({ n: hosts.length }) })
  assert.deepEqual(await s.invoke({ hosts: ["a", "b"] }, ctx), { n: 2 })
  await assert.rejects(() => s.invoke({ hosts: ["a", 2] }, ctx), /`hosts\[1\]`/)
})

test("a default applies when the value is absent", async () => {
  const s = step({ inputs: { tag: withDefault(string(), "latest") }, run: ({ tag }) => ({ tag }) })
  assert.deepEqual(await s.invoke({}, ctx), { tag: "latest" })
  assert.deepEqual(await s.invoke({ tag: "1.2" }, ctx), { tag: "1.2" })
})

test("an absent optional is undefined, an absent required input is refused by name", async () => {
  const s = step({ inputs: { note: optional(string()) }, run: ({ note }) => ({ note: note ?? "none" }) })
  assert.deepEqual(await s.invoke({}, ctx), { note: "none" })
  const required = step({ inputs: { tag: string() }, run: ({ tag }) => ({ tag }) })
  await assert.rejects(() => required.invoke({}, ctx), /`tag` is required/)
})

test("a reserved input name is refused at run time too", () => {
  assert.throws(() => step({ inputs: { log: string() } as never, run: () => ({}) }), /`log` is reserved/)
})

test("invoke spreads the decoded inputs beside log, signal, workdir and env", async () => {
  const lines: string[] = []
  const s = step({
    inputs: { tag: string() },
    run: ({ tag, log, signal, workdir, env }) => {
      log(`${tag} in ${workdir}`)
      return { sha: env.git.sha, aborted: signal.aborted }
    },
  })
  const out = await s.invoke({ tag: "1.2" }, {
    ...ctx,
    log: Object.assign((msg: string) => lines.push(msg), {
      debug() {},
      info() {},
      warn() {},
      error() {},
    }),
  })
  assert.deepEqual(out, { sha: "abc123", aborted: false })
  assert.deepEqual(lines, ["1.2 in /repo"])
})

test("declared outputs are validated, extras refused, as validate_outputs is", async () => {
  const s = step({
    inputs: { n: int() },
    outputs: { applied: int(), name: string() },
    run: ({ n }) => ({ applied: n, name: "migrations" }),
  })
  assert.deepEqual(await s.invoke({ n: 2 }, ctx), { applied: 2, name: "migrations" })

  const lying = step({
    inputs: {},
    outputs: { applied: int() },
    run: () => ({ applied: "3" }) as never,
  })
  await assert.rejects(() => lying.invoke({}, ctx), /`applied` is not a number/)

  const chatty = step({
    inputs: {},
    outputs: { applied: int() },
    run: () => ({ applied: 1, skipped: 0 }) as never,
  })
  await assert.rejects(() => chatty.invoke({}, ctx), /undeclared output `skipped`/)
})