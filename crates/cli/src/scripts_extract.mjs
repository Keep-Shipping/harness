// The `script` step's extractor: what a TypeScript step declares, read out of
// the module without calling `run`.
//
// `@keepshipping/sdk` resolves to a stub, so extraction needs no
// `npm install` and no network. The constructors below carry the type tags a
// real module declares at import time; `run` is never touched — a signature
// is a read, not a run.
//
// One line of JSON on stdout: `{"inputs":…,"outputs":…}`. Anything that goes
// wrong prints `{"error":…}` instead, which the caller reads as "nothing is
// known about this step".
import { registerHooks } from "node:module";
import { pathToFileURL } from "node:url";

const SDK = "@keepshipping/sdk";

// The stub. `step()` returns the descriptor it is given and the type
// constructors return tags rather than values: a descriptor is data, so
// reading its types needs no runtime.
const STUB = `
const tag = (kind, of) => (of === undefined ? { kind } : { kind, of });
export const step = (desc) => desc;
export const int = () => tag("int");
export const float = () => tag("float");
export const string = () => tag("string");
export const bool = () => tag("bool");
export const secret = () => tag("secret");
export const path = () => tag("path");
export const url = () => tag("url");
export const duration = () => tag("duration");
export const list = (of) => tag("list", of);
export const optional = (of) => tag("optional", of);
export const log = () => {};
log.info = log.warn = log.error = () => {};
`;

const stubUrl = "data:text/javascript;base64," + Buffer.from(STUB).toString("base64");

registerHooks({
  resolve(specifier, context, next) {
    if (specifier === SDK) {
      return { url: stubUrl, shortCircuit: true };
    }
    return next(specifier, context);
  },
});

// One declared value as a tag. The constructors are what the stub makes;
// `Number`, `String` and `Boolean` are what a module writes when it means the
// TypeScript type rather than a constructor, and anything else says what it
// was so the message can name it.
function tagOf(value) {
  if (value === Number) return { kind: "number" };
  if (value === String) return { kind: "string" };
  if (value === Boolean) return { kind: "boolean" };
  if (value && typeof value === "object" && typeof value.kind === "string") {
    return value.of === undefined ? { kind: value.kind } : { kind: value.kind, of: tagOf(value.of) };
  }
  return { kind: "unknown", got: typeof value };
}

function tagsOf(declared) {
  const out = {};
  for (const [name, value] of Object.entries(declared ?? {})) {
    out[name] = tagOf(value);
  }
  return out;
}

const file = process.argv[2] ?? process.argv[1];
try {
  // Importing the module is as much as extraction does. A module that does
  // its work at import time does it here — which is why `run` is never called
  // and why a module is expected to be import-shaped.
  const mod = await import(pathToFileURL(file).href);
  const descriptor = mod.default ?? {};
  const out = JSON.stringify({ file, inputs: tagsOf(descriptor.inputs), outputs: tagsOf(descriptor.outputs) });
  process.stdout.write(out + "\n");
} catch (e) {
  process.stdout.write(JSON.stringify({ file, error: String(e?.message ?? e) }) + "\n");
}