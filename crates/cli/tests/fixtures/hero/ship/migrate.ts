// The escape hatch: a step the language has no name for runs as this script.
// It runs outside the process — the JSON-stdio protocol of ADR 0009 — and its
// `step({...})` call is what `check` reads the schema from.

import { step } from "jsr:@keepshipping/step";

export default step({
  // The database this step migrates. A secret input arrives over a dedicated
  // file descriptor, never in argv or the environment.
  db: secret("db-url"),
});

export async function run(input: { db: string }): Promise<{ applied: number }> {
  const client = await connect(input.db);
  return { applied: await client.migrate() };
}