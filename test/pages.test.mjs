// Pages Functions, end to end: real handlers + middleware, a simulated Arweave
// gateway, and a simulated Turbo bundler that checks every ANS-104 signature.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import * as mw from "../functions/api/_middleware.js";
import * as health from "../functions/api/health.js";
import * as verify from "../functions/api/verify.js";
import * as find from "../functions/api/find.js";
import * as publish from "../functions/api/publish.js";

const require = createRequire(import.meta.url);
const { DataItem } = require("@dha-team/arbundles");
const op = require("../index.js");
const { FakeArweave } = require("./fake-arweave.js");
const { FakeNode } = require("./fake-node.js");

const rand = () => "0x" + crypto.randomBytes(32).toString("hex");
const wallet = op.generateArweaveWallet();
const certPem = fs.readFileSync(new URL("./fixtures/es256-cert.pem", import.meta.url), "utf8");
const certKey = crypto.createPrivateKey(fs.readFileSync(new URL("./fixtures/es256-key.pem", import.meta.url)));

let ar, ar2, env, bundled, node;
beforeEach(() => {
  ar = new FakeArweave();
  ar2 = new FakeArweave();
  ar2.url = "https://fake2.arweave";
  bundled = 0;
  node = new FakeNode(ar);
  env = { GATEWAYS: ar.url, BUNDLER_URL: "https://fake.bundler", ARWEAVE_JWK: JSON.stringify(wallet.jwk), PUBLISH_TOKEN: "s3cret-token" };
  globalThis.fetch = async (url, init) => {
    if (url.startsWith("https://fake.bundler/v1/tx/arweave")) {
      const raw = Buffer.from(init.body);
      assert.equal(await DataItem.verify(raw), true, "bundler received an invalid data item");
      const item = new DataItem(raw);
      const owner = crypto.createHash("sha256").update(item.rawOwner).digest("base64url");
      for (const g of [ar, ar2]) g.put({ id: item.id, data: item.rawData, tags: item.tags, owner });
      bundled++;
      return new Response(JSON.stringify({ id: item.id, winc: "0" }), { status: 200 });
    }
    if (url.startsWith(node.url)) return node.fetch(url, init);
    if (url.startsWith(ar2.url)) return ar2.fetch(url, init);
    return ar.fetch(url, init);
  };
});

/** Run a handler through the middleware, like Pages does. */
async function call(handler, { method = "GET", path, body, token }) {
  const request = new Request(`https://op.pages.dev${path}`, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const ctx = { request, env };
  const res = await mw.onRequest({ ...ctx, next: () => handler(ctx) });
  return { status: res.status, body: await res.json(), headers: res.headers };
}

const entry = () => ({
  urn: op.randomUrn(),
  store: crypto.randomBytes(1500),
  claimHash: rand(),
  signatureHash: rand(),
  bindingHash: rand(),
  signerCertHash: rand(),
  softBindings: [{ alg: "com.example.watermark.1", value: "0x" + crypto.randomBytes(6).toString("hex") }],
});
const wire = ({ store, ...e }) => ({ ...e, storeBase64: store.toString("base64") });
const manifestOf = ({ store, softBindings, ...m }) => m;
const codes = (r) => r.body.codes.map((c) => c.code.replace("org.openprovenance.", ""));
const mineAll = () => { ar.mine(); ar2.mine(); };

test("health reports gateways and the publisher address", async () => {
  const r = await call(health.onRequestGet, { path: "/api/health" });
  assert.equal(r.status, 200);
  assert.equal(r.body.publisher, wallet.address);
  assert.equal(r.body.publishing, true);
  assert.equal(r.headers.get("access-control-allow-origin"), "*");
});

test("publishing needs the token", async () => {
  const body = { mode: "public", entries: [wire(entry())] };
  assert.equal((await call(publish.onRequestPost, { method: "POST", path: "/api/publish", body })).status, 401);
  assert.equal((await call(publish.onRequestPost, { method: "POST", path: "/api/publish", body, token: "wrong" })).status, 401);
  assert.equal(bundled, 0);
});

test("public mode: publish, then verify across two gateways", async () => {
  env.GATEWAYS = `${ar.url},${ar2.url}`;
  const e = entry();
  const pub = await call(publish.onRequestPost, { method: "POST", path: "/api/publish", body: { mode: "public", entries: [wire(e)] }, token: env.PUBLISH_TOKEN });
  assert.equal(pub.status, 200);
  assert.equal(pub.body.receipts[0].uploader, wallet.address);

  let r = await call(verify.onRequestPost, { method: "POST", path: "/api/verify", body: { manifest: manifestOf(e) } });
  assert.deepEqual(codes(r), ["anchor.pending"]);

  mineAll();
  r = await call(verify.onRequestPost, { method: "POST", path: "/api/verify", body: { manifest: manifestOf(e), storeBase64: e.store.toString("base64") } });
  assert.deepEqual(codes(r), ["anchor.match"]);
  assert.equal(r.body.perGateway.length, 2);

  const hits = await call(find.onRequestGet, { path: `/api/find?by=softbinding&alg=${e.softBindings[0].alg}&value=${e.softBindings[0].value}` });
  assert.equal(hits.body.results[0].tags["C2PA-Manifest-URN"], e.urn);
});

test("a gateway that hides records is reported as disagreement", async () => {
  env.GATEWAYS = `${ar.url},${ar2.url}`;
  const e = entry();
  await call(publish.onRequestPost, { method: "POST", path: "/api/publish", body: { mode: "public", entries: [wire(e)] }, token: env.PUBLISH_TOKEN });
  mineAll();
  ar2.items.clear();
  const r = await call(verify.onRequestPost, { method: "POST", path: "/api/verify", body: { manifest: manifestOf(e) } });
  assert.deepEqual(codes(r), ["anchor.match", "gateway.disagreement"]);
});

test("private mode: one upload, every receipt verifies", async () => {
  const es = Array.from({ length: 30 }, entry);
  const pub = await call(publish.onRequestPost, {
    method: "POST", path: "/api/publish", token: env.PUBLISH_TOKEN,
    body: { mode: "private", entries: es.map(({ store, softBindings, ...m }) => m) },
  });
  assert.equal(pub.status, 200);
  assert.equal(bundled, 1);
  mineAll();
  for (const [i, e] of es.entries()) {
    const r = await call(verify.onRequestPost, { method: "POST", path: "/api/verify", body: { manifest: manifestOf(e), receipt: pub.body.receipts[i] } });
    assert.deepEqual(codes(r), ["anchor.match"]);
  }
});

test("statements: a key-signed withdrawal is published and reported", async () => {
  const e = entry();
  await call(publish.onRequestPost, { method: "POST", path: "/api/publish", body: { mode: "public", entries: [wire(e)] }, token: env.PUBLISH_TOKEN });
  const key = op.p256KeyFrom(certPem);
  const st = op.createStatement({ kind: "manifest-status", key, privateKey: certKey, manifestId: op.manifestId(e.urn), status: "withdrawn", reasonUri: "ar://why" });
  const r1 = await call(publish.onRequestPost, { method: "POST", path: "/api/publish", token: env.PUBLISH_TOKEN, body: { mode: "statement", statement: JSON.parse(st.body.toString()) } });
  assert.equal(r1.status, 200);
  mineAll();
  const r = await call(verify.onRequestPost, { method: "POST", path: "/api/verify", body: { manifest: manifestOf(e), signerCertPem: certPem } });
  assert.deepEqual(codes(r), ["anchor.match", "manifest.withdrawn"]);
});

test("forged and unsigned statements are refused before upload", async () => {
  const key = op.p256KeyFrom(certPem);
  const other = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const forged = op.createStatement({ kind: "revoke", key, privateKey: other.privateKey });
  const unsigned = op.createStatement({ kind: "manifest-status", key, manifestId: rand(), status: "withdrawn" });
  for (const st of [forged, unsigned]) {
    const r = await call(publish.onRequestPost, { method: "POST", path: "/api/publish", token: env.PUBLISH_TOKEN, body: { mode: "statement", statement: JSON.parse(st.body.toString()) } });
    assert.equal(r.status, 400);
  }
  assert.equal(bundled, 0);
});

test("bad input becomes a 400, never a crash", async () => {
  let r = await call(verify.onRequestPost, { method: "POST", path: "/api/verify", body: { manifest: { urn: "urn:c2pa:x", claimHash: "nope" } } });
  assert.equal(r.status, 400);
  const big = { ...entry(), store: crypto.randomBytes(200_000) };
  r = await call(publish.onRequestPost, { method: "POST", path: "/api/publish", token: env.PUBLISH_TOKEN, body: { mode: "public", entries: [wire(big)] } });
  assert.equal(r.status, 400);
  r = await call(publish.onRequestPost, { method: "POST", path: "/api/publish", token: env.PUBLISH_TOKEN, body: { mode: "public", entries: [{ ...wire(entry()), claimHash: "0x12" }] } });
  assert.equal(r.status, 400);
  r = await call(find.onRequestGet, { path: "/api/find?by=nope&value=1" });
  assert.equal(r.status, 400);
  assert.equal(bundled, 0);
});

test("publishing is off when secrets are missing", async () => {
  delete env.PUBLISH_TOKEN;
  const r = await call(publish.onRequestPost, { method: "POST", path: "/api/publish", body: {}, token: "x" });
  assert.equal(r.status, 503);
});

test("direct mode: native Arweave transactions, no bundler", async () => {
  Object.assign(env, { UPLOAD_MODE: "direct", ARWEAVE_NODE_URL: node.url });
  const h = await call(health.onRequestGet, { path: "/api/health" });
  assert.equal(h.body.uploadMode, "direct");
  const e = entry();
  const pub = await call(publish.onRequestPost, { method: "POST", path: "/api/publish", body: { mode: "public", entries: [wire(e)] }, token: env.PUBLISH_TOKEN });
  assert.equal(pub.status, 200);
  assert.equal(bundled, 0);
  assert.equal(node.posted.tx, 1);
  ar.mine();
  const r = await call(verify.onRequestPost, { method: "POST", path: "/api/verify", body: { manifest: manifestOf(e) } });
  assert.deepEqual(codes(r), ["anchor.match"]);
});

test("direct mode respects the cost cap", async () => {
  Object.assign(env, { UPLOAD_MODE: "direct", ARWEAVE_NODE_URL: node.url, MAX_REWARD_WINSTON: "1000" });
  const r = await call(publish.onRequestPost, { method: "POST", path: "/api/publish", body: { mode: "public", entries: [wire(entry())] }, token: env.PUBLISH_TOKEN });
  assert.equal(r.status, 402);
  assert.match(r.body.error, /cap/);
  assert.equal(node.posted.tx, 0);
});

test("checking from a real photo: fingerprints only, older labels, non-ES256 signer", async () => {
  const { readFile } = await import("../public/js/c2pa-reader.mjs");
  const limited = await call(health.onRequestGet, { path: "/api/health" });
  assert.equal(limited.body.maxStoreBytes, 102400);
  env.MAX_STORE_BYTES = "1048576";
  const { store, manifest: m } = await readFile(new Uint8Array(fs.readFileSync(new URL("./fixtures/c2pa/CA.jpg", import.meta.url))));
  const entry = { urn: m.urn, claimHash: m.claimHash, signatureHash: m.signatureHash, bindingHash: m.bindingHash, signerCertHash: m.signerCertHash };
  const pub = await call(publish.onRequestPost, { method: "POST", path: "/api/publish", token: env.PUBLISH_TOKEN, body: { mode: "public", entries: [{ ...entry, storeBase64: Buffer.from(store).toString("base64") }] } });
  assert.equal(pub.status, 200);
  ar.mine();
  const r = await call(verify.onRequestPost, { method: "POST", path: "/api/verify", body: { manifest: entry, storeSha256: m.storeSha256, signerCertPem: m.certificatePem } });
  assert.deepEqual(codes(r), ["anchor.match", "signer.unsupported"]);
  const wrongStore = await call(verify.onRequestPost, { method: "POST", path: "/api/verify", body: { manifest: entry, storeSha256: rand() } });
  assert.deepEqual(codes(wrongStore), ["anchor.missing"]);
  const byStore = await call(find.onRequestGet, { path: `/api/find?by=store&value=${m.storeSha256}` });
  assert.equal(byStore.body.results.length, 1);
});
