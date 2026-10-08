// The caller hands `count` a string where the step declared a number: the
// host must refuse before the process ever starts.
export default {
  inputs: { count: "number" },
  outputs: { x: "string" },
  async run() {
    return { x: "ok" };
  },
};
