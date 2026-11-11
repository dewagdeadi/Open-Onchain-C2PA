// Local stand-in for an Arweave gateway + Turbo bundler, for `wrangler pages dev` smoke tests.
const http = require("http");
const crypto = require("crypto");
const { DataItem } = require("@dha-team/arbundles");
const { FakeArweave } = require("../test/fake-arweave");
const ar = new FakeArweave();
ar.url = "http://127.0.0.1:9000";
http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);
  if (req.url === "/v1/tx/arweave") {
    const ok = await DataItem.verify(body);
    if (!ok) { res.writeHead(400); return res.end("bad data item"); }
    const it = new DataItem(body);
    ar.put({ id: it.id, data: it.rawData, tags: it.tags, owner: crypto.createHash("sha256").update(it.rawOwner).digest("base64url") });
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ id: it.id, winc: "0" }));
  }
  if (req.url === "/__mine") { ar.mine(); res.writeHead(200); return res.end("mined"); }
  const r = await ar.fetch(ar.url + req.url, { body: body.toString() });
  if (!r.ok) { res.writeHead(404); return res.end(); }
  if (r.json) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify(await r.json())); }
  res.writeHead(200); res.end(Buffer.from(await r.arrayBuffer()));
}).listen(9000, () => console.log("fake arweave on :9000"));
