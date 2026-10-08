// Declares two outputs and returns one. `run` must name the missing one.
export default {
  inputs: {},
  outputs: { x: "string", y: "number" },
  async run() {
    return { x: "ok" };
  },
};
