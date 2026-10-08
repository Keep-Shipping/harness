// `@keepshipping/sdk/testing`: a step run in a test, with fake secrets that
// never reach a log line, an error or an output.
import assert from "node:assert/strict"
import { test } from "node:test"

import { int, list, secret, step, string } from "../src/index.ts"
import { runStep, StepFailed } from "../src/testing.ts"

// Obviously fake values: the helper exists so a step is tested without a real
// credential anywhere near it.
const FAKE = "fake-db-value"
const LONGER = `${FAKE}-replica`

test("a step runs with its inputs and its log is captured by level", async () => {
  const s = step({
    inputs: { tag: string(), n: int() },
    run: ({ tag, n, log }) => {
      log(`tagging ${tag}`)
      log.warn(`${n} left`)
      return { tagged: tag }
    },
  })
  const run = await runStep(s, { tag: "v1.2.3", n: 2 })
  assert.deepEqual(run.outputs, { tagged: "v1.2.3" })
  assert.deepEqual(run.logs, [
    { level: "info", message: "tagging v1.2.3" },
    { level: "warn", message: "2 left" },
  ])
})

test("a secret input's value is scrubbed from every line, the longest first", async () => {
  const s = step({
    inputs: { db: secret(), replicas: list(secret()) },
    run: ({ db, replicas, log }) => {
      log(`connecting with ${db.reveal()}`)
      log.debug(`replica ${replicas[0]?.reveal()}`)
      log.error(`printed: ${db}`)
      return { ok: true }
    },
  })
  const run = await runStep(s, { db: FAKE, replicas: [LONGER] })
  assert.deepEqual(run.logs.map((line) => line.message), [
    "connecting with ***",
    "replica ***",
    "printed: ***",
  ])
  assert.ok(!JSON.stringify(run.logs).includes(FAKE), "no tail of either value is left")
})

test("a step that throws rejects with StepFailed, its message scrubbed and its log kept", async () => {
  const s = step({
    inputs: { db: secret() },
    run: ({ db, log }) => {
      log("starting")
      throw new Error(`could not connect with ${db.reveal()}`)
    },
  })
  await assert.rejects(runStep(s, { db: FAKE }), (error: unknown) => {
    assert.ok(error instanceof StepFailed)
    assert.equal(error.message, "could not connect with ***")
    assert.deepEqual(error.logs, [{ level: "info", message: "starting" }])
    // The step's own error is handed back as it was, which is why it is the
    // one thing not to print.
    assert.ok(error.cause instanceof Error)
    return true
  })
})

test("a missing or mistyped input is a StepFailed naming it, before the step runs", async () => {
  let ran = false
  const s = step({
    inputs: { n: int() },
    run: ({ n }) => {
      ran = true
      return { n }
    },
  })
  await assert.rejects(runStep(s, {}), (error: unknown) => {
    assert.ok(error instanceof StepFailed)
    assert.match(error.message, /`n` is required/)
    return true
  })
  await assert.rejects(runStep(s, { n: "3" }), StepFailed)
  assert.equal(ran, false)
})

test("declared outputs are checked as the host checks them", async () => {
  const s = step({
    inputs: {},
    outputs: { applied: int() },
    run: () => ({ applied: "3" }) as never,
  })
  await assert.rejects(runStep(s, {}), /`applied` is not a number/)
})

test("an output carrying a secret's value is refused: a step cannot return a secret", async () => {
  const s = step({
    inputs: { db: secret() },
    run: ({ db }) => ({ url: `postgres://${db.reveal()}@db` }),
  })
  await assert.rejects(runStep(s, { db: FAKE }), (error: unknown) => {
    assert.ok(error instanceof StepFailed)
    assert.match(error.message, /cannot return a secret/)
    assert.ok(!error.message.includes(FAKE))
    return true
  })
})

test("the run context can be set, and defaults to the host's", async () => {
  const s = step({
    inputs: {},
    run: ({ workdir, env }) => ({ workdir, sha: env.git.sha }),
  })
  assert.deepEqual((await runStep(s, {})).outputs, { workdir: ".", sha: "" })
  const run = await runStep(s, {}, { workdir: "/repo", env: { git: { sha: "abc123" } } })
  assert.deepEqual(run.outputs, { workdir: "/repo", sha: "abc123" })
})
