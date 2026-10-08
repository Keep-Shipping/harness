// The host side of the JSON-stdio protocol (ADR 0009), embedded in the binary
// and written next to the pinned Deno. A step module's *default export* is the
// step:
//
//   export default {
//     inputs?: { name: "string" | "number" | "bool" | "list" | "map" },
//     outputs?: { ... },
//     net?: string[],                       // hosts the step asked for
//     async run(inputs, ctx) { return { ...outputs } },
//   }
//
// A future `@keepshipping/sdk` `step()` will simply return that object, so a
// step written against this shape needs no change when the SDK lands. A field
// may also be written as a runtime tag — `int()`, `optional(string())`,
// `list(string())`, `db: secret()` — and `describe` normalises both spellings
// into the five types the port has; see `KIND_OF`.
//
// argv after the module: <describe|run> <script path> [<secret fifo>].

import { pathToFileURL } from "node:url";

/**
 * How a declared field's tag maps onto a type the port understands. `int` and
 * `float` are both numbers, and `path`/`url`/`duration` are all strings —
 * every tag an `@keepshipping/sdk` `step()` may hand over, so a step written
 * against the SDK needs no change here. Anything else is passed through
 * unrecognised on purpose: the host reports it as an invalid schema rather
 * than quietly treating it as something it is not.
 */
const KIND_OF: Record<string, string> = {
  int: "number",
  float: "number",
  string: "string",
  path: "string",
  url: "string",
  duration: "string",
  bool: "bool",
  list: "list",
  map: "map",
  secret: "secret",
};

/** One declared field, as a plain type name — or `null` if it is neither. */
function normalize(tag: unknown): string | null {
  if (typeof tag === "string") return tag;
  if (tag !== null && typeof tag === "object") {
    const record = tag as { kind?: unknown; of?: unknown };
    // `optional(of)` is not a type: it is the type inside it.
    if (record.kind === "optional") return normalize(record.of);
    if (typeof record.kind === "string") return KIND_OF[record.kind] ?? record.kind;
  }
  return null;
}

/**
 * The declared fields as plain type names. A `secret` input is not a schema
 * input at all — secrets arrive through `ctx.secrets`, never on stdin — so it
 * is dropped rather than declared as something the caller must supply.
 */
function fields(declared: unknown, dropSecrets: boolean): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [name, tag] of Object.entries((declared ?? {}) as Record<string, unknown>)) {
    const kind = normalize(tag);
    if (kind === "secret" && dropSecrets) continue;
    out[name] = kind === null ? tag : kind;
  }
  return out;
}

const encoder = new TextEncoder();

/** Writes one JSON frame, bypassing `console` so a step cannot interleave. */
function emit(frame: unknown): void {
  const bytes = encoder.encode(JSON.stringify(frame) + "\n");
  let written = 0;
  while (written < bytes.length) {
    written += Deno.stdout.writeSync(bytes.subarray(written));
  }
}

/** The one way out of this module: a message on stderr and a nonzero exit. */
function die(message: string): never {
  Deno.stderr.writeSync(encoder.encode(message + "\n"));
  Deno.exit(1);
}

/**
 * Length-prefixed secret frames: `u32` name length, name, `u32` value length,
 * value, repeated until a zero name length. The terminator is why the reader
 * never waits for an EOF — the parent holds the pipe open for the whole run.
 */
async function readSecrets(path: string | undefined): Promise<Record<string, string>> {
  const decoder = new TextDecoder();
  const secrets: Record<string, string> = {};
  if (!path) return secrets;
  const file = Deno.openSync(path, { read: true });
  const reader = file.readable.getReader();
  let buffer = new Uint8Array(0);
  const be = (at: number) =>
    (buffer[at] << 24) | (buffer[at + 1] << 16) | (buffer[at + 2] << 8) | buffer[at + 3];
  for (;;) {
    const { done, value } = await reader.read();
    if (value) {
      const grown = new Uint8Array(buffer.length + value.length);
      grown.set(buffer, 0);
      grown.set(value, buffer.length);
      buffer = grown;
    }
    let at = 0;
    let finished = false;
    for (;;) {
      if (at + 4 > buffer.length) break;
      const nameLength = be(at);
      if (nameLength === 0) {
        finished = true;
        break;
      }
      if (at + 4 + nameLength + 4 > buffer.length) break;
      const name = decoder.decode(buffer.subarray(at + 4, at + 4 + nameLength));
      const valueAt = at + 4 + nameLength;
      const valueLength = be(valueAt);
      if (valueAt + 4 + valueLength > buffer.length) break;
      secrets[name] = decoder.decode(buffer.subarray(valueAt + 4, valueAt + 4 + valueLength));
      at = valueAt + 4 + valueLength;
    }
    if (finished || done) break;
    buffer = buffer.slice(at);
  }
  reader.releaseLock();
  file.close();
  return secrets;
}

/** One JSON object of inputs, from stdin. */
async function readInputs(): Promise<Record<string, unknown>> {
  const text = await new Response(Deno.stdin.readable).text();
  const inputs: unknown = text.trim() === "" ? {} : JSON.parse(text);
  if (inputs === null || typeof inputs !== "object" || Array.isArray(inputs)) {
    die("the inputs on stdin must be one JSON object");
  }
  return inputs as Record<string, unknown>;
}

async function main(): Promise<void> {
  const [mode, script, secretFifo] = Deno.args;
  if ((mode !== "describe" && mode !== "run") || !script) {
    die("usage: bootstrap.ts <describe|run> <script> [<secret fifo>]");
  }
  const step = (await import(pathToFileURL(script).href)).default;
  if (!step || typeof step.run !== "function") {
    die(`${script} has no default export with a run(inputs, ctx)`);
  }
  if (mode === "describe") {
    emit({
      describe: {
        inputs: fields(step.inputs, true),
        outputs: fields(step.outputs, false),
        net: step.net ?? [],
      },
    });
    return;
  }
  const inputs = await readInputs();
  const secrets = await readSecrets(secretFifo);
  const ctx = {
    secrets: {
      get: (name: string): string | undefined =>
        Object.prototype.hasOwnProperty.call(secrets, name) ? secrets[name] : undefined,
    },
    log: (level: string, msg: string): void => {
      emit({ log: { level: String(level), msg: String(msg) } });
    },
  };
  const outputs = await step.run(inputs, ctx);
  emit({ output: outputs ?? {} });
}

try {
  await main();
} catch (error) {
  die(error instanceof Error ? (error.stack ?? error.message) : String(error));
}