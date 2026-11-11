// Web Crypto port and ANS-104 signer, checked against Node crypto, OpenZeppelin and arbundles.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const { DataItem, ArweaveSigner, createData } = require("@dha-team/arbundles");
const op = require("../index");

const rand = () => "0x" + crypto.randomBytes(32).toString("hex");

test("ANS-104 data items verify with arbundles and match its id and tag bytes", async () => {
  const w = op.generateArweaveWallet();
  const tags = [
    { name: "App-Name", value: "OpenProvenance" },
    { name: "Content-Type", value: "application/c2pa" },
    { name: "Ünicode-ü", value: "x".repeat(300) },
  ];
  const data = crypto.randomBytes(5000);
  const item = await op.createSignedDataItem({ data, tags, jwk: w.jwk });
  assert.equal(await DataItem.verify(Buffer.from(item.raw)), true);
  const parsed = new DataItem(Buffer.from(item.raw));
  assert.equal(parsed.id, item.id);
  assert.equal(item.owner, w.address);
  assert.deepEqual(parsed.tags, tags);
  assert.equal(Buffer.compare(Buffer.from(op.serializeTags(tags)), createData(data, new ArweaveSigner(w.jwk), { tags }).rawTags), 0);
});

test("leaf hash matches OpenZeppelin StandardMerkleTree", () => {
  for (let i = 0; i < 25; i++) {
    const a = {
      manifestId: rand(), claimHash: rand(), signatureHash: rand(), bindingHash: rand(), signerCertHash: rand(),
      storeUri: i % 3 ? "ar://" + "y".repeat(i * 5) : "",
      parents: Array.from({ length: i % 4 }, rand),
    };
    assert.equal(op.leafHashWeb(a), op.leafHash(a));
  }
});

test("certificate key extraction, cert hash and ES256 match Node crypto", async () => {
  const pem = require("fs").readFileSync(require("path").join(__dirname, "fixtures/es256-cert.pem"), "utf8");
  const key = crypto.createPrivateKey(require("fs").readFileSync(require("path").join(__dirname, "fixtures/es256-key.pem")));
  const n = op.p256KeyFrom(pem);
  const w = op.p256FromPem(pem);
  assert.deepEqual([w.x, w.y], [n.x, n.y]);
  assert.equal(await op.signerCertHashWeb(pem), op.signerCertHash(pem));
  assert.equal(await op.keyIdForWeb(w.x, w.y), n.keyId);
  const sig = op.es256Sign(Buffer.from("payload"), key);
  assert.equal(await op.es256VerifyWeb("payload", sig, n.x, n.y), true);
  assert.equal(await op.es256VerifyWeb("payloaD", sig, n.x, n.y), false);
});
