// Returns an output nobody declared.
export default {
  inputs: {},
  outputs: { x: "string" },
  async run() {
    return { x: "ok", surprise: null };
  },
};
