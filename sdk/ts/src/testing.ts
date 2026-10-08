/**
 * `@keepshipping/sdk/testing` — runs one step in your own test runner, with no
 * host, no real secrets and no network. It calls the step exactly as the host
 * does (`Step.invoke`: decode the inputs, run, check the outputs), and adds
 * what a unit test wants around that: the step's log captured as lines, and
 * every value a `secret()` input was handed scrubbed out of those lines and out
 * of any error, so a test can assert a step never logged its secret and have
 * the assertion mean something.
 *
 * A secret input is given here as the plain string the host would read off
 * fd 3. Pass an obviously fake value — the point of the helper is that a step
 * can be tested without a real credential anywhere near it.
 */
import type { Env, Input, Inputs, Log, Step } from "./index.ts"

/** What every scrubbed value reads as — the same marker a `Secret` prints. */
const REDACTED = "***"

/** The level a captured line was logged at; a bare `log(msg)` is `info`. */
export type Level = "debug" | "info" | "warn" | "error"

/** One line the step logged, with every secret input's value already scrubbed. */
export interface LogLine {
  readonly level: Level
  readonly message: string
}

/** The run context a test may set; every field has the host's default. */
export interface RunOptions {
  readonly env?: Env
  readonly workdir?: string
  readonly signal?: AbortSignal
}

/** What one {@link runStep} produced. */
export interface StepRun<O> {
  /**
   * The outputs, checked against the step's declared outputs. Not scrubbed: a
   * test asserts on them by value, and a step cannot return a secret's value
   * here — {@link runStep} refuses one that does.
   */
  readonly outputs: O
  /** Every line the step logged, in order, scrubbed. */
  readonly logs: readonly LogLine[]
}

/**
 * A step that failed under {@link runStep}: it threw, its inputs did not
 * decode, its outputs did not match, or an output carried a secret's value.
 * `message` is scrubbed, and `logs` holds what the step logged before it
 * failed, scrubbed too. `cause` is the step's own error, **unscrubbed**: it is
 * the object the step threw, handed back as it was, so it is the one string
 * here not to paste into a ticket.
 */
export class StepFailed extends Error {
  readonly logs: readonly LogLine[]

  constructor(message: string, logs: readonly LogLine[], cause: unknown) {
    super(message, { cause })
    this.name = "StepFailed"
    this.logs = logs
  }
}

/** Whether a descriptor decodes into a secret, directly or as a list of them. */
function isSecret(input: Input): boolean {
  if (input.kind === "secret") return true
  return input.kind === "list" && isSecret(input.of)
}

/** Every string a secret input was handed, longest first. */
function secretValues(inputs: Inputs, values: Record<string, unknown>): string[] {
  const found: string[] = []
  const collect = (raw: unknown): void => {
    if (typeof raw === "string" && raw !== "") found.push(raw)
    else if (Array.isArray(raw)) raw.forEach(collect)
  }
  for (const [name, input] of Object.entries(inputs)) {
    if (isSecret(input)) collect(values[name])
  }
  // Longest first, so a secret that is a prefix of another cannot leave the
  // longer one's tail behind.
  return [...new Set(found)].sort((a, b) => b.length - a.length)
}

/**
 * Runs `step` with `values` as its inputs, the way the host runs a script step,
 * and returns its outputs and what it logged.
 *
 * Rejects with {@link StepFailed} — never with a bare `Error` — when the step
 * throws, when an input does not decode or a required one is missing, when an
 * output is missing, mistyped or undeclared, and when an output carries the
 * value of a secret input: a step cannot return a secret, here as on the host.
 */
export async function runStep<I extends Inputs, O>(
  step: Step<I, O>,
  values: Record<string, unknown>,
  options: RunOptions = {},
): Promise<StepRun<O>> {
  const secrets = secretValues(step.inputs, values)
  const scrub = (text: string): string =>
    secrets.reduce((out, secret) => out.split(secret).join(REDACTED), text)
  const logs: LogLine[] = []
  const at = (level: Level) => (message: string): void => {
    logs.push({ level, message: scrub(String(message)) })
  }
  const log: Log = Object.assign(at("info"), {
    debug: at("debug"),
    info: at("info"),
    warn: at("warn"),
    error: at("error"),
  })

  let outputs: O
  try {
    outputs = await step.invoke(values, {
      log,
      ...(options.env === undefined ? {} : { env: options.env }),
      ...(options.workdir === undefined ? {} : { workdir: options.workdir }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    })
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause)
    throw new StepFailed(scrub(message), logs, cause)
  }

  const carried = JSON.stringify(outputs) ?? ""
  if (secrets.some((secret) => carried.includes(secret))) {
    throw new StepFailed(
      "an output carries the value of a secret input; a step cannot return a secret",
      logs,
      undefined,
    )
  }
  return { outputs, logs }
}
