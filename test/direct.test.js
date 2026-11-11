// Direct mode: native Arweave transactions, no bundler.
const { test, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const Arweave = require("arweave");
const { validatePath } = require("arweave/node/lib/merkle");
const op = require("../index");
const { FakeArweave } = require("./fake-arweave");
const { FakeNode } = require("./fake-node");

const rand = () => "0x" + crypto.randomBytes(32).toString("hex");
const wallet = op.generateArweaveWallet();
let gw, node, gateway, uploader;

beforeEach(() => {
  gw = new FakeArweave();
  node = new FakeNode(gw);
  gateway = op.createGateway({ url: gw.url, fetch: gw.fetch });
  uploader = op.createDirectUploader({ jwk: wallet.jwk, node: node.url, fetch: node.fetch });
});

test("transactions match arweave-js: signature, id, data_root and chunk proofs", async () => {
  const ar = Arweave.init({});
  for (const size of [1, 1000, 256 * 1024, 256 * 1024 + 10, 600 * 1024, 1024 * 1024 + 5]) {
    const data = crypto.randomBytes(size);
    const tags = [{ name: "App-Name", value: "OpenProvenance" }, { name: "Type", value: "manifest-store" }];
    const lastTx = op.b64uEncode(crypto.randomBytes(48));
    const s = await op.createSignedTransaction({ data, tags, jwk: wallet.jwk, reward: "12345", lastTx });
    assert.equal(await ar.transactions.verify(ar.transactions.fromRaw({ ...s.tx })), true, `verify at ${size}`);
    const ref = await ar.createTransaction({ data, last_tx: lastTx, reward: "12345" }, wallet.jwk);
    await ref.prepareChunks(data);
    assert.equal(s.tx.data_root, op.b64uEncode(ref.chunks.data_root), `data_root at ${size}`);
    assert.equal(s.chunks.length, ref.chunks.chunks.length);
    for (const c of s.chunks)
      assert.ok(await validatePath(op.b64uDecode(s.tx.data_root), +c.offset, 0, +c.data_size, op.b64uDecode(c.data_path)));
  }
});

test("small records go up in one /tx call and verify end to end", async () => {
  const e = {
    urn: op.randomUrn(), storeBytes: crypto.randomBytes(3000),
    claimHash: rand(), signatureHash: rand(), bindingHash: rand(), signerCertHash: rand(),
  };
  const { receipts, cost } = await op.publishStores({ entries: [e], uploader });
  assert.equal(node.posted.tx, 1);
  assert.equal(node.posted.chunk, 0);
  assert.equal(receipts[0].uploader, wallet.address);
  assert.equal(BigInt(cost.winc), 3000n * 1000n + 100n);
  gw.mine();
  const { storeBytes, ...manifest } = e;
  const r = await op.verifyManifest({ gateway, manifest, storeBytes });
  assert.deepEqual(r.codes.map((c) => c.code), ["org.openprovenance.anchor.match"]);
  assert.equal(r.anchor.owner, wallet.address);
});

test("large records are uploaded in chunks with valid proofs", async () => {
  const data = crypto.randomBytes(700 * 1024);
  const { id } = await uploader.upload(data, [{ name: "App-Name", value: "OpenProvenance" }]);
  assert.equal(node.posted.chunk, 3);
  assert.equal(Buffer.compare(Buffer.from(await gateway.data(id)), data), 0);
});

test("private mode and statements work the same in direct mode", async () => {
  const entries = Array.from({ length: 10 }, () => ({ urn: op.randomUrn(), claimHash: rand(), signatureHash: rand(), bindingHash: rand(), signerCertHash: rand() }));
  const { receipts } = await op.publishRoot({ entries, uploader });
  const keys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const key = op.p256KeyFrom(keys.publicKey);
  const st = op.createStatement({ kind: "manifest-status", key, privateKey: keys.privateKey, manifestId: receipts[3].manifestId, status: "withdrawn" });
  await op.publishStatement({ statement: st, uploader });
  gw.mine();
  const r = await op.verifyManifest({ gateway, manifest: entries[3], receipt: receipts[3], signerKey: key });
  assert.deepEqual(r.codes.map((c) => c.code), ["org.openprovenance.anchor.match", "org.openprovenance.manifest.withdrawn"]);
});

test("refuses uploads over the cost cap or the wallet balance, before signing anything", async () => {
  const capped = op.createDirectUploader({ jwk: wallet.jwk, node: node.url, fetch: node.fetch, maxRewardWinston: "5000" });
  await assert.rejects(capped.upload(crypto.randomBytes(100), []), /above the 5000 cap/);
  node.balance = 10n;
  await assert.rejects(uploader.upload(crypto.randomBytes(100), []), /holds 10 winston/);
  await assert.rejects(uploader.upload(new Uint8Array(0), []), /empty data/);
  assert.equal(node.posted.tx, 0);
});
