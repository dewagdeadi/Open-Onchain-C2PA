// In-memory Arweave gateway for tests: GraphQL (ids, tags, owners), data, blocks.
class FakeArweave {
  constructor() {
    this.items = new Map();
    this.height = 1000;
    this.time = Math.floor(Date.now() / 1000) - 3600;
    this.url = "https://fake.arweave";
    this.fetch = this.fetch.bind(this);
  }

  put({ id, data, tags, owner }) {
    this.items.set(id, { id, data: Buffer.from(data), tags, owner, block: null });
  }

  /** Mine every pending item into the next block. */
  mine(advanceSec = 120) {
    this.height += 1;
    this.time += advanceSec;
    for (const it of this.items.values()) if (!it.block) it.block = { height: this.height, timestamp: this.time };
  }

  async fetch(url, init = {}) {
    if (url === `${this.url}/graphql`) {
      const { ids, tags = [], owners } = JSON.parse(init.body).variables;
      const edges = [...this.items.values()]
        .filter((it) => !ids || ids.includes(it.id))
        .filter((it) => !owners || owners.includes(it.owner))
        .filter((it) => tags.every((f) => it.tags.some((t) => t.name === f.name && f.values.includes(t.value))))
        .sort((a, b) => (a.block?.height ?? Infinity) - (b.block?.height ?? Infinity))
        .map((it) => ({ cursor: it.id, node: { id: it.id, owner: { address: it.owner }, tags: it.tags, block: it.block } }));
      return { ok: true, json: async () => ({ data: { transactions: { pageInfo: { hasNextPage: false }, edges } } }) };
    }
    const it = this.items.get(url.slice(this.url.length + 1));
    if (!it) return { ok: false, status: 404 };
    return { ok: true, arrayBuffer: async () => it.data.buffer.slice(it.data.byteOffset, it.data.byteOffset + it.data.length) };
  }
}

module.exports = { FakeArweave };
