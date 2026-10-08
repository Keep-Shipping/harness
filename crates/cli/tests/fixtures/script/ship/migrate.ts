// A TypeScript step. `check` reads the descriptor this module exports; it
// never calls `run`, which throws here to prove it. The module's own body
// does run — reaching the descriptor means importing the module — so a step
// keeps its work in `run` and its side effects out of the body.
import { step, int, secret, log } from "@keepshipping/sdk";

export default step({
  inputs: {
    dsn: secret(),
  },
  outputs: {
    applied: int(),
  },
  async run({ inputs, outputs }) {
    throw new Error(`run() must never be called by check: ${inputs.dsn} ${outputs.applied}`);
  },
});

log.info("a step's body runs; its run() does not");