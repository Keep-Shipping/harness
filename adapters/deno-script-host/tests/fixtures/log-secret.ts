// The conformance kit's log-secret: it is handed the secret `conformance-token`,
// logs it as the message, and returns nothing. Nothing is observable in the
// return value: the kit asserts on the log, where the token must read `***`.
export default {
  inputs: {},
  outputs: {},
  async run(_inputs: Record<string, unknown>, ctx: any) {
    const token = ctx.secrets.get("conformance-token") ?? "";
    ctx.log("info", "connecting with " + token);
    return {};
  },
};
