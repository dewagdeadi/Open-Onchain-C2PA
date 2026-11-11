// Isomorphic publishing to Arweave. Two modes, both gas-free:
//   public  — upload each full manifest store; the store itself is the anchor.
//   private — upload only a Merkle root of hash-only anchor records; stores stay private.
// `uploader` is createUploader() (Node, Turbo SDK) or createWebUploader() (Workers).
const { PROTOCOL, storeTags, rootTags, treeTags } = require("./gateway");
const { buildBatch } = require("./batch");
const { sha256Hex, manifestIdWeb, hexToBytes, concat } = require("./web");

const enc = new TextEncoder();

/** Soft-binding lookup key: sha256(alg || 0x00 || value bytes). */
const softBindingKey = (alg, valueHex) => sha256Hex(concat(enc.encode(alg), Uint8Array.of(0), hexToBytes(valueHex)));

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i], i);
      }
    })
  );
  return out;
}

const HASH = /^0x[0-9a-f]{64}$/i;
async function toAnchor(e) {
  for (const f of ["claimHash", "signatureHash", "bindingHash", "signerCertHash"])
    if (!HASH.test(e[f] || "")) throw new Error(`invalid entry ${e.urn || ""}: ${f} must be a 0x-prefixed SHA-256`);
  if (!/^urn:c2pa:/.test(e.urn || "")) throw new Error(`invalid manifest URN: ${e.urn}`);
  for (const p of e.parents || []) if (!HASH.test(p)) throw new Error(`invalid entry ${e.urn}: bad parent id`);
  return {
    manifestId: await manifestIdWeb(e.urn),
    claimHash: e.claimHash,
    signatureHash: e.signatureHash,
    bindingHash: e.bindingHash,
    signerCertHash: e.signerCertHash,
    storeUri: e.storeUri || "",
    parents: e.parents || [],
  };
}

/**
 * Public mode. entries: [{ urn, storeBytes, claimHash, signatureHash, bindingHash,
 * signerCertHash, parents?, softBindings?: [{ alg, value }] }]
 */
async function publishStores({ entries, uploader, concurrency = 8, log = () => {} }) {
  let winc = 0n;
  let free = 0;
  const receipts = await mapLimit(entries, concurrency, async (e) => {
    if (!e.storeBytes?.length) throw new Error(`invalid entry ${e.urn}: store required in public mode`);
    const anchor = { ...(await toAnchor(e)), storeUri: "" };
    const storeSha256 = await sha256Hex(e.storeBytes);
    const keys = await Promise.all((e.softBindings || []).map((s) => softBindingKey(s.alg, s.value)));
    const res = await uploader.upload(e.storeBytes, storeTags({ urn: e.urn, anchor, storeSha256, softBindingKeys: keys }));
    winc += BigInt(res.winc);
    if (res.winc === "0") free++;
    log(`store ${e.urn} -> ar://${res.id} (${e.storeBytes.length} B, ${res.winc} winc)`);
    return {
      protocol: PROTOCOL,
      mode: "store",
      manifest: e.urn,
      manifestId: anchor.manifestId,
      claimHash: anchor.claimHash,
      tx: res.id,
      store: { url: `ar://${res.id}`, alg: "sha256", hash: storeSha256 },
      uploader: uploader.address,
    };
  });
  return { receipts, cost: { winc: winc.toString(), uploads: entries.length, freeUploads: free } };
}

/**
 * Private mode: one small upload per batch, whatever its size. entries need no store.
 * publishTree: also upload the full leaf list (makes every anchor in it public).
 */
async function publishRoot({ entries, uploader, publishTree = false, log = () => {} }) {
  const anchors = await Promise.all(entries.map(toAnchor));
  const batch = buildBatch(anchors);
  const body = enc.encode(JSON.stringify({ protocol: PROTOCOL, root: batch.root, count: anchors.length }));
  const res = await uploader.upload(body, rootTags({ root: batch.root, count: anchors.length }));
  log(`root ${batch.root} -> ar://${res.id} (${anchors.length} anchors, ${body.length} B)`);
  let tree = null;
  if (publishTree) {
    const t = await uploader.upload(enc.encode(JSON.stringify(batch.dump())), treeTags({ root: batch.root }));
    tree = `ar://${t.id}`;
  }
  const receipts = anchors.map((a, i) => ({
    protocol: PROTOCOL,
    mode: "root",
    manifest: entries[i].urn,
    manifestId: a.manifestId,
    claimHash: a.claimHash,
    tx: res.id,
    merkleRoot: batch.root,
    proof: batch.proofFor(a),
    leaf: { storeUri: a.storeUri, parents: a.parents },
    tree,
    uploader: uploader.address,
  }));
  return { root: batch.root, tx: res.id, receipts, cost: { winc: res.winc, uploads: publishTree ? 2 : 1 } };
}

/** Upload a statement built with createStatement() (or received pre-signed). */
async function publishStatement({ statement, uploader }) {
  const res = await uploader.upload(statement.body, statement.tags);
  return { tx: res.id, kind: statement.payload.type, keyId: statement.payload.keyId };
}

const randomUrn = () => `urn:c2pa:${globalThis.crypto.randomUUID()}`;

module.exports = { softBindingKey, publishStores, publishRoot, publishStatement, randomUrn };
