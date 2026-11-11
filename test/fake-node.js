// Simulated Arweave node for direct-mode tests: /price, /tx_anchor, /wallet/:a/balance,
// POST /tx and POST /chunk. Every transaction signature and chunk proof is checked
// with arweave-js; completed uploads land in a FakeArweave gateway.
const Arweave = require("arweave");
const { validatePath } = require("arweave/node/lib/merkle");
const crypto = require("crypto");

const b64u = (s) => Buffer.from(s, "base64url");

class FakeNode {
  constructor(gateway, { pricePerByte = 1000n, balance = 10n ** 15n } = {}) {
    this.gw = gateway;
    this.url = "https://fake.node";
    this.pricePerByte = pricePerByte;
    this.balance = balance;
    this.pending = new Map(); // data_root -> { tx, parts }
    this.posted = { tx: 0, chunk: 0 };
    this.ar = Arweave.init({});
    this.fetch = this.fetch.bind(this);
  }

  text(body, status = 200) {
    return new Response(String(body), { status });
  }

  land(tx, data) {
    const tags = tx.tags.map((t) => ({ name: b64u(t.name).toString(), value: b64u(t.value).toString() }));
    const owner = crypto.createHash("sha256").update(b64u(tx.owner)).digest("base64url");
    this.gw.put({ id: tx.id, data, tags, owner });
    this.balance -= BigInt(tx.reward);
  }

  async fetch(url, init = {}) {
    const path = url.slice(this.url.length);
    let m;
    if ((m = path.match(/^\/price\/(\d+)$/))) return this.text(BigInt(m[1]) * this.pricePerByte + 100n);
    if (path === "/tx_anchor") return this.text(crypto.randomBytes(48).toString("base64url"));
    if (/^\/wallet\/[\w-]{43}\/balance$/.test(path)) return this.text(this.balance);
    if (path === "/tx" && init.method === "POST") {
      const tx = JSON.parse(init.body);
      const ok = await this.ar.transactions.verify(this.ar.transactions.fromRaw({ ...tx }));
      if (!ok) return this.text("invalid signature", 400);
      if (BigInt(tx.reward) < BigInt(tx.data_size) * this.pricePerByte) return this.text("reward too low", 400);
      this.posted.tx++;
      if (tx.data) {
        const data = b64u(tx.data);
        if (data.length !== Number(tx.data_size)) return this.text("data size mismatch", 400);
        this.land(tx, data);
      } else {
        this.pending.set(tx.data_root, { tx, parts: new Map() });
      }
      return this.text("OK");
    }
    if (path === "/chunk" && init.method === "POST") {
      const c = JSON.parse(init.body);
      const p = this.pending.get(c.data_root);
      if (!p) return this.text("unknown data_root", 400);
      const ok = await validatePath(b64u(c.data_root), Number(c.offset), 0, Number(c.data_size), b64u(c.data_path));
      if (!ok) return this.text("invalid proof", 400);
      this.posted.chunk++;
      p.parts.set(ok.offset ?? Number(c.offset), b64u(c.chunk));
      const total = [...p.parts.values()].reduce((n, b) => n + b.length, 0);
      if (total === Number(c.data_size)) {
        const data = Buffer.concat([...p.parts.entries()].sort((a, b) => a[0] - b[0]).map(([, b]) => b));
        this.pending.delete(c.data_root);
        this.land(p.tx, data);
      }
      return this.text("OK");
    }
    return this.text("not found", 404);
  }
}

module.exports = { FakeNode };
