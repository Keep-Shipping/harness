// The conformance kit's echo: one string in, one string out.
export default {
  inputs: { name: "string" },
  outputs: { greeting: "string" },
  async run(_inputs: Record<string, unknown>) {
    return { greeting: "hello, conformance" };
  },
};
