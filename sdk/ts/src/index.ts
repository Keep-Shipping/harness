/**
 * `@keepshipping/sdk` — the TypeScript escape hatch (ADR 0009). A step file
 * default-exports one `step({...})`; its `inputs` carry a literal `kind` per
 * descriptor, which is what the extractor's schema is read from. The shapes
 * mirror `ks_core::catalog`, and the wire protocol belongs to the script host
 * adapter, which calls `Step.invoke`.
 */

/** A JSON-serialisable value: the only shape a step's outputs may take. */
export type Json =
  | null | boolean | number | string | readonly Json[] | { readonly [key: string]: Json }

/** Outputs are a named object; the extractor reads one type per field. */
export type JsonObject = { readonly [name: string]: Json }

/** `oci.Digest`, branded so a tag cannot be passed where a digest is wanted. */
declare const digestBrand: unique symbol
export type Digest = string & { readonly [digestBrand]: "oci.Digest" }

/** `oci.Ref`, branded: a reference pinned to a digest, never a tag. */
declare const refBrand: unique symbol
export type Ref = string & { readonly [refBrand]: "oci.Ref" }

/** The value each plain input `kind` decodes to. */
type Decoded = {
  string: string
  int: number
  bool: boolean
  secret: Secret
  "oci.Digest": Digest
  "oci.Ref": Ref
  "tofu.PlanFile": PlanFile
}

/** Every input kind `ks_core::catalog` names, as the extractor reads them. */
export type Kind = keyof Decoded

/** `tofu.PlanFile`: the plan file, its sha256 (64 hex), and its module dir. */
export interface PlanFile {
  readonly path: string
  readonly sha256: string
  readonly dir: string
}

/** An enum input; the value must be one of `values`. */
export interface EnumInput<V extends string> {
  readonly kind: "enum"
  readonly values: readonly V[]
}

/** A list input whose items are `of`. */
export interface ListInput<I extends Input> {
  readonly kind: "list"
  readonly of: I
}

/**
 * Every input descriptor. `secret()` is absent from {@link OutputInput}: a
 * `StepError` bypasses the run's redactor (`ks_core::catalog`).
 */
export type Input = { readonly kind: Kind } | EnumInput<string> | ListInput<Input>

/** Every descriptor an output may use. */
export type OutputInput =
  | { readonly kind: Exclude<Kind, "secret"> } | EnumInput<string> | ListInput<OutputInput>

/** The descriptor for one `kind`. */
type Of<K extends Kind> = { readonly kind: K }

/** An input descriptor wrapped as optional: absent decodes to `undefined`. */
export type Optional<I> = I & { readonly optional: true }

/** An input descriptor given a default: absent decodes to it, never `undefined`. */
export type Defaulted<I> = I & { readonly default: ValueOf<I> }

/** The value an input descriptor decodes to, ignoring optionality. */
type Unwrapped<I> =
  I extends EnumInput<infer V> ? V
    : I extends ListInput<infer E> ? ValueOf<E>[]
    : I extends Of<infer K> ? Decoded[K] : never

/** The value `run` is handed for input `I`; optional inputs may be `undefined`. */
export type ValueOf<I> =
  I extends { readonly optional: true } ? Unwrapped<I> | undefined : Unwrapped<I>

/** The value each declared output carries, which is what `run` must return. */
export type ValueOfMap<D> = { [K in keyof D]: ValueOf<D[K]> }

/** A record of declared inputs, keyed by input name. */
export type Inputs = { readonly [name: string]: Input }

/**
 * The four names the host fills in itself: a claimed one would be overwritten
 * before `run` saw it, so `step()` refuses it at the type level and on use.
 */
export type Unreserved = {
  readonly log?: never
  readonly signal?: never
  readonly workdir?: never
  readonly env?: never
}

/** The run's non-secret context; a secret is an input, never this. */
export interface Env {
  /** The commit under test, and the branch it was reached from, if any. */
  readonly git: { readonly sha: string; readonly branch?: string }
  readonly [key: string]: unknown
}

/** Structured logging: callable at info level, with a method per level. */
export type Log = ((msg: string) => void) &
  Record<"debug" | "info" | "warn" | "error", (msg: string) => void>

/**
 * What the host adds beside the decoded inputs: the logger, the cancellation
 * signal, the workspace root, and the non-secret run context.
 */
export interface BaseCtx {
  readonly log: Log
  readonly signal: AbortSignal
  readonly workdir: string
  readonly env: Env
}

/** What `run` receives: its typed inputs, spread beside the host's context. */
export type Ctx<I> = { [K in keyof I]: ValueOf<I[K]> } & BaseCtx

/** What the host passes beside the inputs; every field has a default. */
export type InvokeCtx = Partial<BaseCtx>

/** What every print of a secret reads as, on the Rust side too. */
const REDACTED = "***"

const nodeInspect: unique symbol = Symbol.for("nodejs.util.inspect.custom")
const denoInspect: unique symbol = Symbol.for("Deno.customInspect")

/**
 * A secret value. `reveal()` is the only way out; `toString`, `toJSON` and
 * both runtimes' inspect hooks give `***`, so printing one never leaks it.
 */
export class Secret {
  #value: string

  constructor(value: string) {
    this.#value = value
  }

  /** The value in the clear. Everything else about a secret is redacted. */
  reveal(): string {
    return this.#value
  }

  toString(): string {
    return REDACTED
  }
  toJSON(): string {
    return REDACTED
  }
  [nodeInspect](): string {
    return REDACTED
  }
  [denoInspect](): string {
    return REDACTED
  }
}

/** A string input. */
export const string = (): Of<"string"> => ({ kind: "string" })

/** A whole-number input; a fractional value is refused at run time. */
export const int = (): Of<"int"> => ({ kind: "int" })

/** A boolean input. */
export const bool = (): Of<"bool"> => ({ kind: "bool" })

/** A secret input, decoded into a {@link Secret}. */
export const secret = (): Of<"secret"> => ({ kind: "secret" })

/** An `oci.Digest` input. */
export const digest = (): Of<"oci.Digest"> => ({ kind: "oci.Digest" })

/** An `oci.Ref` input: a repository pinned to a digest, never a tag. */
export const ref = (): Of<"oci.Ref"> => ({ kind: "oci.Ref" })

/** A `tofu.PlanFile` input. */
export const planFile = (): Of<"tofu.PlanFile"> => ({ kind: "tofu.PlanFile" })

/** An enum input. The literals are inferred, so no `as const` is needed. */
export function enumOf<const V extends string>(...values: V[]): EnumInput<V> {
  return { kind: "enum", values }
}

/** A list input of `of`. */
export function list<I extends Input>(of: I): ListInput<I> {
  return { kind: "list", of }
}

/** Marks an input optional: absent it decodes to `undefined`. */
export function optional<I extends Input>(of: I): Optional<I> {
  return { ...of, optional: true }
}

/** Gives an input a default, so it is never `undefined`. */
export function withDefault<I extends Input>(of: I, value: ValueOf<I>): Defaulted<I> {
  return { ...of, default: value }
}

/** The four input names the host owns. */
const RESERVED = ["log", "signal", "workdir", "env"] as const

/** `sha256:` or `sha512:` plus exactly that many lowercase hex digits. */
const DIGEST = /^(?:sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$/

/** `<repository>@<digest>`, as `ks_engine::steps::builtin_types` pins one. */
const REF = /^.+@(?:sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$/

/** How a raw value reads in an error, so a message names what arrived. */
function got(raw: unknown): string {
  if (raw === null) return "null"
  if (Array.isArray(raw)) return "a list"
  return `a ${typeof raw}`
}

/** Decodes one raw value against one descriptor, naming the field on failure. */
function decode(name: string, input: Input, raw: unknown): unknown {
  const bad = (why: string): never => {
    throw new Error(`\`${name}\` is ${why}`)
  }
  const str = (): string => (typeof raw === "string" ? raw : bad(`not a string (got ${got(raw)})`))
  if (raw === undefined) {
    const fallback = (input as { readonly default?: unknown }).default
    if (fallback !== undefined) return decode(name, input, fallback)
    if ("optional" in input) return undefined
    return bad("required, but the run supplied no value")
  }
  switch (input.kind) {
    case "string":
    case "secret":
      return input.kind === "secret" ? new Secret(str()) : str()
    case "int":
      if (typeof raw !== "number") return bad(`not a number (got ${got(raw)})`)
      return Number.isInteger(raw) ? raw : bad(`not a whole number (got ${raw})`)
    case "bool":
      return typeof raw === "boolean" ? raw : bad(`not a boolean (got ${got(raw)})`)
    case "oci.Digest":
      return DIGEST.test(str()) ? (str() as Digest) : bad(`not a digest (got ${JSON.stringify(raw)})`)
    case "oci.Ref":
      return REF.test(str()) ? (str() as Ref) : bad(`not a digest-pinned reference (got ${JSON.stringify(raw)})`)
    case "tofu.PlanFile": {
      if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
        return bad("not the `tofu.PlanFile` `tofu.plan` wrote, as {path, sha256, dir}")
      }
      const plan = raw as Record<string, unknown>
      const member = (key: string): string => {
        const value = plan[key]
        if (typeof value !== "string" || value === "") throw new Error(`\`${name}.${key}\` is missing or is not a string`)
        return value
      }
      const sha256 = member("sha256")
      if (!/^[0-9a-f]{64}$/.test(sha256)) {
        return bad(`\`sha256\` not a digest: ${JSON.stringify(sha256)}`)
      }
      return { path: member("path"), sha256, dir: member("dir") }
    }
    case "enum":
      return input.values.includes(raw as string)
        ? raw
        : bad(`not one of ${input.values.map((v) => JSON.stringify(v)).join(", ")} (got ${JSON.stringify(raw)})`)
    case "list":
      return Array.isArray(raw)
        ? raw.map((item, at) => decode(`${name}[${at}]`, input.of, item))
        : bad(`not a list (got ${got(raw)})`)
  }
}

const silent = (): void => {}

/** The log a run gets when the host passed none: every level, doing nothing. */
const SILENT: Log = Object.assign(silent, { debug: silent, info: silent, warn: silent, error: silent })

/** What one `step({...})` call declares: inputs, optional outputs, and `run`. */
export interface StepDef<I extends Inputs, O> {
  readonly inputs: I
  readonly outputs?: Record<string, OutputInput>
  readonly run: (ctx: Ctx<I>) => O | Promise<O>
}

/** A declared step: its inputs, its outputs, and the `run` that uses them. */
export class Step<I extends Inputs, O> {
  readonly #def: StepDef<I, O>

  constructor(def: StepDef<I, O>) {
    for (const name of RESERVED) {
      if (name in def.inputs) {
        throw new Error(`input \`${name}\` is reserved: the host provides it, so a step may not claim it`)
      }
    }
    this.#def = def
  }

  /** The declared inputs, as the extractor reads their schema from. */
  get inputs(): I {
    return this.#def.inputs
  }
  /** The declared outputs, when the step declared any. */
  get outputs(): Record<string, OutputInput> | undefined {
    return this.#def.outputs
  }

  /**
   * Runs the step: decodes `values` against the declared inputs, calls `run`
   * with them spread beside `ctx`, then validates the result against the
   * declared outputs — extras included, as `validate_outputs` refuses them. A
   * `secret()` input arrives here as its raw string: the host has read it off
   * fd 3, and it must never be in argv, the environment or stdio.
   */
  async invoke(values: Record<string, unknown>, ctx: InvokeCtx = {}): Promise<O> {
    const { inputs, outputs, run } = this.#def
    const decoded: Record<string, unknown> = {}
    for (const [name, input] of Object.entries(inputs)) {
      decoded[name] = decode(name, input, values[name])
    }
    const result = await run({
      ...decoded,
      log: ctx.log ?? SILENT,
      signal: ctx.signal ?? new AbortController().signal,
      workdir: ctx.workdir ?? ".",
      env: ctx.env ?? { git: { sha: "" } },
    } as Ctx<I>)
    if (outputs === undefined) return result
    if (typeof result !== "object" || result === null || Array.isArray(result)) {
      throw new Error(`outputs are not an object (got ${got(result)})`)
    }
    const out = result as Record<string, unknown>
    for (const [name, output] of Object.entries(outputs)) {
      if (out[name] === undefined) throw new Error(`output \`${name}\` is missing`)
      decode(name, output, out[name])
    }
    for (const name of Object.keys(out)) {
      if (!(name in outputs)) throw new Error(`undeclared output \`${name}\``)
    }
    return result
  }
}

/** Declares a step with declared outputs; `run` must return exactly those. */
export function step<I extends Inputs & Unreserved, D extends Record<string, OutputInput>>(
  def: { inputs: I; outputs: D; run: (ctx: Ctx<I>) => ValueOfMap<D> | Promise<ValueOfMap<D>> },
): Step<I, ValueOfMap<D>>

/** Declares a step whose outputs are inferred from `run`'s return type. */
export function step<I extends Inputs & Unreserved, O extends JsonObject>(
  def: { inputs: I; run: (ctx: Ctx<I>) => O | Promise<O> },
): Step<I, O>

export function step<I extends Inputs, O>(def: StepDef<I, O>): Step<I, O> {
  return new Step(def)
}