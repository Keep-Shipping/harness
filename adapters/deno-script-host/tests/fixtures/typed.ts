// Every container type crossing the wire at once.
export default {
  inputs: { count: "number" },
  outputs: { tags: "list", labels: "map" },
  async run(_inputs: Record<string, unknown>) {
    return { tags: ["web", "app"], labels: { env: "staging" } };
  },
};
