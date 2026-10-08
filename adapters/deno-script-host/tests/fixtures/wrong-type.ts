// Declares a string, hands back a number. `run` must say so, not coerce.
export default {
  inputs: {},
  outputs: { x: "string" },
  async run() {
    return { x: 7 };
  },
};
