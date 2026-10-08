// ship/migrate.ts
import { step, secret, type Secret } from "@keepshipping/sdk"

/** Stands in for the migration runner a repository would bring along. */
declare function migrate(db: Secret): Promise<number>

export default step({
  inputs: { db: secret() },
  async run({ db, log }) {
    const n = await migrate(db)
    log(`applied ${n} migrations`)
    return { applied: n }
  },
})