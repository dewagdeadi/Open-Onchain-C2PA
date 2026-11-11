// Local stand-in for Arweave, for `wrangler pages dev` without network access.
// One port serves a gateway (GraphQL + data), a bundler (POST /v1/tx/arweave) and
// a node (/price, /tx_anchor, /wallet/:a/balance, POST /tx, POST /chunk).
// Signatures are checked with arbundles / arweave-js. GET /__mine mines pending uploads.
const http = require("http");
const crypto = require("crypto");
const { DataItem } = require("@dha-team/arbundles");
const { FakeArweave } = require("../test/fake-arweave");
const { FakeNode } = require("../test/fake-node");

const PORT = Number(process.env.PORT || 9000);
const ar = new FakeArweave();
ar.url = `http://127.0.0.1:${PORT}`;
const node = new FakeNode(ar);
node.url = ar.url;

http
  .createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    const send = async (r) => {
      res.writeHead(r.status, { "content-type": r.headers?.get?.("content-type") || "text/plain" });
      res.end(Buffer.from(await r.arrayBuffer()));
    };
    try {
      if (req.url === "/__mine") {
        ar.mine();
        return send(new Response("mined"));
      }
      if (req.url === "/v1/tx/arweave") {
        if (!(await DataItem.verify(body))) return send(new Response("bad data item", { status: 400 }));
        const it = new DataItem(body);
        ar.put({ id: it.id, data: it.rawData, tags: it.tags, owner: crypto.createHash("sha256").update(it.rawOwner).digest("base64url") });
        return send(Response.json({ id: it.id, winc: "0" }));
      }
      if (["/tx", "/chunk", "/tx_anchor"].includes(req.url) || /^\/(price|wallet)\//.test(req.url)) {
        return send(await node.fetch(node.url + req.url, { method: req.method, body: body.toString() }));
      }
      const r = await ar.fetch(ar.url + req.url, { body: body.toString() });
      if (!r.ok) return send(new Response("not found", { status: 404 }));
      if (r.json) return send(Response.json(await r.json()));
      return send(new Response(await r.arrayBuffer()));
    } catch (e) {
      send(new Response(e.message, { status: 500 }));
    }
  })
  .listen(PORT, () => console.log(`fake Arweave (gateway + bundler + node) on http://127.0.0.1:${PORT}`));
