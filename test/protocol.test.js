const { test, describe, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const op = require("../index");
const { FakeArweave } = require("./fake-arweave");

const rand = () => "0x" + crypto.randomBytes(32).toString("hex");
const entry = () => ({
  urn: op.randomUrn(),
  storeBytes: crypto.randomBytes(3000),
  claimHash: rand(),
  signatureHash: rand(),
  bindingHash: rand(),
  signerCertHash: rand(),
  softBindings: [{ alg: "com.example.watermark.1", value: "0x" + crypto.randomBytes(8).toString("hex") }],
});
const manifestOf = (e) => ({
  urn: e.urn,
  claimHash: e.claimHash,
  signatureHash: e.signatureHash,
  bindingHash: e.bindingHash,
  signerCertHash: e.signerCertHash,
  parents: [],
});
const codes = (r) => r.codes.map((c) => c.code.replace("org.openprovenance.", ""));

let ar, gateway, publisher;
beforeEach(async () => {
  ar = new FakeArweave();
  gateway = op.createGateway({ url: ar.url, fetch: ar.fetch });
  publisher = await op.createUploader({ dryRun: true, sink: ar });
});

describe("public mode: the manifest store is the anchor", () => {
  test("pending until mined, then a timestamp proof", async () => {
    const e = entry();
    const { receipts, cost } = await op.publishStores({ entries: [e], uploader: publisher });
    assert.equal(cost.uploads, 1);
    assert.match(receipts[0].store.url, /^ar:\/\//);

    let r = await op.verifyManifest({ gateway, manifest: manifestOf(e), storeBytes: e.storeBytes });
    assert.deepEqual(codes(r), ["anchor.pending"]);

    ar.mine();
    r = await op.verifyManifest({ gateway, manifest: manifestOf(e), storeBytes: e.storeBytes });
    assert.deepEqual(codes(r), ["anchor.match"]);
    assert.equal(r.anchor.block.timestamp, ar.time);
  });

  test("a different manifest or store is not a match", async () => {
    const e = entry();
    await op.publishStores({ entries: [e], uploader: publisher });
    ar.mine();
    let r = await op.verifyManifest({ gateway, manifest: { ...manifestOf(e), claimHash: rand() } });
    assert.deepEqual(codes(r), ["anchor.missing"]);
    r = await op.verifyManifest({ gateway, manifest: manifestOf(e), storeBytes: crypto.randomBytes(10) });
    assert.deepEqual(codes(r), ["anchor.missing"]);
  });

  test("spoofed uploads are filtered by trusted publishers", async () => {
    const e = entry();
    const attacker = await op.createUploader({ dryRun: true, sink: ar });
    await op.publishStores({ entries: [{ ...e, claimHash: rand() }], uploader: attacker }); // same URN, wrong claim
    await op.publishStores({ entries: [e], uploader: publisher });
    ar.mine();

    let r = await op.verifyManifest({ gateway, manifest: manifestOf(e), trustedUploaders: [publisher.address] });
    assert.deepEqual(codes(r), ["anchor.match"]);
    r = await op.verifyManifest({ gateway, manifest: manifestOf(e), trustedUploaders: [attacker.address] });
    assert.deepEqual(codes(r), ["anchor.mismatch"]);
  });

  test("bytes that do not match their Store-SHA256 tag fail", async () => {
    const e = entry();
    const anchor = { manifestId: op.manifestId(e.urn), claimHash: e.claimHash, signatureHash: e.signatureHash, bindingHash: e.bindingHash, signerCertHash: e.signerCertHash, parents: [] };
    await publisher.upload(crypto.randomBytes(100), op.storeTags({ urn: e.urn, anchor, storeSha256: op.sha256(e.storeBytes) }));
    ar.mine();
    const r = await op.verifyManifest({ gateway, manifest: manifestOf(e) });
    assert.deepEqual(codes(r), ["anchor.mismatch"]);
  });

  test("an anchor older than its own TSA time stamp is flagged", async () => {
    const e = entry();
    await op.publishStores({ entries: [e], uploader: publisher });
    ar.mine();
    const r = await op.verifyManifest({ gateway, manifest: manifestOf(e), tsaTime: ar.time + 86_400 });
    assert.deepEqual(codes(r), ["anchor.match", "time.inconsistent"]);
  });

  test("stores are findable by soft binding", async () => {
    const e = entry();
    await op.publishStores({ entries: [e], uploader: publisher });
    const key = await op.softBindingKey(e.softBindings[0].alg, e.softBindings[0].value);
    const hits = await gateway.byTag(op.Type.STORE, "Soft-Binding-Key", key);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].tags["C2PA-Manifest-URN"], e.urn);
  });
});

describe("private mode: one Merkle root per batch", () => {
  test("every receipt verifies; altered manifests do not", async () => {
    const entries = Array.from({ length: 50 }, entry);
    const { receipts, cost } = await op.publishRoot({ entries, uploader: publisher });
    assert.equal(cost.uploads, 1);
    assert.equal(ar.items.size, 1);
    ar.mine();
    for (const [i, e] of entries.entries()) {
      const r = await op.verifyManifest({ gateway, manifest: manifestOf(e), receipt: receipts[i] });
      assert.deepEqual(codes(r), ["anchor.match"]);
    }
    const r = await op.verifyManifest({ gateway, manifest: { ...manifestOf(entries[0]), bindingHash: rand() }, receipt: receipts[0] });
    assert.deepEqual(codes(r), ["anchor.mismatch"]);
  });
});

describe("statements and read-time rules", () => {
  let keys, key, e, delegateUp, stranger;

  beforeEach(async () => {
    keys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    key = op.p256KeyFrom(keys.publicKey);
    e = entry();
    await op.publishStores({ entries: [e], uploader: publisher });
    delegateUp = await op.createUploader({ dryRun: true, sink: ar });
    stranger = await op.createUploader({ dryRun: true, sink: ar });
    ar.mine();
  });

  const post = (kind, fields, { signed = true, by = publisher } = {}) =>
    op.publishStatement({
      statement: op.createStatement({ kind, key, privateKey: signed ? keys.privateKey : undefined, ...fields }),
      uploader: by,
    });
  const check = () => op.verifyManifest({ gateway, manifest: manifestOf(e), signerKey: key });
  const mId = () => op.manifestId(e.urn);

  test("key-signed withdrawal is reported", async () => {
    await post("manifest-status", { manifestId: mId(), status: "withdrawn", reasonUri: "ar://why" });
    assert.deepEqual(codes(await check()), ["anchor.match"]); // pending statements do not count
    ar.mine();
    assert.deepEqual(codes(await check()), ["anchor.match", "manifest.withdrawn"]);
  });

  test("status only moves forward", async () => {
    await post("manifest-status", { manifestId: mId(), status: "withdrawn" });
    ar.mine();
    await post("manifest-status", { manifestId: mId(), status: "superseded" });
    ar.mine();
    assert.equal((await check()).signer.manifests[mId()].status, "withdrawn");
  });

  test("a delegate counts only in blocks after its delegation", async () => {
    await post("delegate", { delegate: delegateUp.address, active: true });
    await post("manifest-status", { manifestId: mId(), status: "superseded" }, { signed: false, by: delegateUp }); // same block
    ar.mine();
    let r = await check();
    assert.deepEqual(codes(r), ["anchor.match"]);
    assert.equal(r.signer.ignored[0].reason, "uploader is not an active delegate");

    await post("manifest-status", { manifestId: mId(), status: "superseded" }, { signed: false, by: delegateUp });
    ar.mine();
    assert.deepEqual(codes(await check()), ["anchor.match", "manifest.superseded"]);
  });

  test("unsigned statements from strangers and forged signatures are ignored", async () => {
    await post("manifest-status", { manifestId: mId(), status: "withdrawn" }, { signed: false, by: stranger });
    const other = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const forged = op.createStatement({ kind: "revoke", key, privateKey: other.privateKey });
    await op.publishStatement({ statement: forged, uploader: stranger });
    ar.mine();
    const r = await check();
    assert.deepEqual(codes(r), ["anchor.match"]);
    assert.deepEqual(r.signer.ignored.map((i) => i.reason).sort(), ["bad signature", "uploader is not an active delegate"]);
  });

  test("revocation is final, ends delegates, and the key can still clean up", async () => {
    await post("delegate", { delegate: delegateUp.address, active: true });
    ar.mine();
    await post("revoke", { reasonUri: "ar://incident" });
    ar.mine();
    const firstRevoke = ar.time;
    await post("revoke", { reasonUri: "ar://later" });
    await post("manifest-status", { manifestId: mId(), status: "superseded" }, { signed: false, by: delegateUp });
    ar.mine();
    let r = await check();
    assert.equal(r.signer.revoked.timestamp, firstRevoke);
    assert.equal(r.signer.revoked.reasonUri, "ar://incident");
    assert.deepEqual(codes(r), ["anchor.match", "signer.revoked"]);

    await post("manifest-status", { manifestId: mId(), status: "withdrawn" });
    ar.mine();
    r = await check();
    assert.deepEqual(codes(r), ["anchor.match", "signer.revoked", "manifest.withdrawn"]);
  });

  test("delegate and revoke must be key-signed", () => {
    assert.throws(() => op.createStatement({ kind: "revoke", key }), /signed by the key/);
  });
});

describe("keys and wallets", () => {
  test("keyId is sha256 of the uncompressed point in the SPKI", () => {
    const k = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const spki = k.publicKey.export({ format: "der", type: "spki" });
    assert.equal(op.p256KeyFrom(k.publicKey).keyId, op.sha256(spki.subarray(spki.length - 65)));
  });

  test("generated Arweave wallets work with the real Turbo client", async () => {
    const w = op.generateArweaveWallet();
    assert.match(w.address, /^[\w-]{43}$/);
    const up = await op.createUploader({ token: "arweave", privateKey: w.jwk });
    assert.equal(up.address, w.address);
  });
});
