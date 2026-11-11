// Isomorphic validator side. Runs AFTER normal C2PA validation and never changes its
// result: it adds Arweave evidence as separate result codes.
const { Type } = require("./gateway");
const { sha256Hex, manifestIdWeb, keyIdForWeb, leafHashWeb, verifyProofWeb } = require("./web");
const { parseStatement, resolveSigner } = require("./rules");

const code = (c, severity, detail = {}) => ({ code: `org.openprovenance.${c}`, severity, ...detail });

/**
 * @param manifest   { urn | manifestId, claimHash, signatureHash, bindingHash, signerCertHash, parents? }
 *                   — taken from the C2PA manifest the validator already parsed
 * @param storeBytes the embedded manifest store bytes, if any (exact-store match)
 * @param storeSha256 or just their SHA-256, so the store never has to leave the device
 * @param receipt    receipt from publishRoot (private mode); omit for public lookup
 * @param signerKey  { x, y } of the claim signer's P-256 key, to check statements
 * @param tsaTime    unix seconds from the sigTst2 time stamp, to check ordering
 * @param trustedUploaders  Arweave addresses of publishers you recognise
 */
async function verifyManifest({ gateway, manifest, storeBytes, storeSha256, receipt, signerKey, tsaTime, trustedUploaders, toleranceSec = 7200 }) {
  const mId = manifest.manifestId || (await manifestIdWeb(manifest.urn));
  const codes = [];
  let anchor = null;

  // --- 1. anchor -------------------------------------------------------------
  if (receipt && receipt.mode === "root") {
    const [tx] = await gateway.byIds([receipt.tx]);
    const leaf = leafHashWeb({ ...manifest, manifestId: mId, storeUri: receipt.leaf.storeUri, parents: receipt.leaf.parents });
    if (!tx) codes.push(code("anchor.missing", "info", { detail: "root transaction not found" }));
    else if (tx.tags.Type !== Type.ROOT || tx.tags["Merkle-Root"] !== receipt.merkleRoot)
      codes.push(code("anchor.mismatch", "failure", { detail: "root record does not match receipt" }));
    else if (!verifyProofWeb(receipt.merkleRoot, leaf, receipt.proof))
      codes.push(code("anchor.mismatch", "failure", { detail: "manifest is not in this batch" }));
    else {
      const body = JSON.parse(new TextDecoder().decode(await gateway.data(tx.id)));
      if (body.root !== receipt.merkleRoot) codes.push(code("anchor.mismatch", "failure", { detail: "root body differs from tags" }));
      else anchor = { mode: "root", tx: tx.id, owner: tx.owner, block: tx.block };
    }
  } else {
    const hits = await gateway.byTag(Type.STORE, "C2PA-Manifest-Id", mId, trustedUploaders);
    const storeHash = storeSha256 ? storeSha256.toLowerCase() : storeBytes ? await sha256Hex(storeBytes) : null;
    const matches = hits.filter(
      (h) =>
        h.tags["C2PA-Claim-Hash"] === manifest.claimHash &&
        h.tags["C2PA-Signature-Hash"] === manifest.signatureHash &&
        h.tags["C2PA-Binding-Hash"] === manifest.bindingHash &&
        (!storeHash || h.tags["Store-SHA256"] === storeHash)
    );
    const best = matches.find((h) => h.block) || matches[0];
    if (best) {
      const data = await gateway.data(best.id).catch(() => null);
      if (!data) codes.push(code("store.unavailable", "warning", { tx: best.id }));
      else if ((await sha256Hex(data)) !== best.tags["Store-SHA256"])
        codes.push(code("anchor.mismatch", "failure", { detail: "stored bytes differ from tag" }));
      else anchor = { mode: "store", tx: best.id, owner: best.owner, block: best.block, store: `ar://${best.id}` };
    } else if (hits.length && trustedUploaders) {
      codes.push(code("anchor.mismatch", "failure", { detail: "a trusted publisher holds a different manifest under this id" }));
    } else {
      codes.push(code("anchor.missing", "info", { conflicting: hits.length }));
    }
  }

  if (anchor) {
    if (!anchor.block) codes.push(code("anchor.pending", "info", { tx: anchor.tx }));
    else {
      codes.push(code("anchor.match", "success", { tx: anchor.tx, height: anchor.block.height, timestamp: anchor.block.timestamp }));
      if (tsaTime && anchor.block.timestamp + toleranceSec < tsaTime)
        codes.push(code("time.inconsistent", "failure", { detail: "anchored before its own TSA time stamp" }));
    }
  }

  // --- 2. signer and manifest status ----------------------------------------
  let signer = null;
  if (signerKey) {
    const keyId = await keyIdForWeb(signerKey.x, signerKey.y);
    const txs = await gateway.byTag(Type.STATEMENT, "Signer-Key-Id", keyId);
    const parsed = await Promise.all(
      txs.map(async (tx) => parseStatement(tx, await gateway.data(tx.id).catch(() => new Uint8Array(0))))
    );
    signer = { keyId, ...resolveSigner(parsed) };
    if (signer.revoked)
      codes.push(code("signer.revoked", "warning", {
        at: signer.revoked.timestamp,
        afterClaim: tsaTime ? signer.revoked.timestamp > tsaTime : null,
        reasonUri: signer.revoked.reasonUri,
      }));
    const st = signer.manifests[mId];
    if (st) codes.push(code(`manifest.${st.status}`, "warning", { at: st.timestamp, reasonUri: st.reasonUri }));
  }

  return { manifestId: mId, anchor, signer, codes };
}

/**
 * Run the same check through several gateways and compare. Disagreement on the
 * anchor or status codes is itself reported, since one gateway could be lying.
 */
async function verifyAcrossGateways({ gateways, ...input }) {
  const results = await Promise.all(
    gateways.map((g) => verifyManifest({ ...input, gateway: g }).then((r) => ({ gateway: g.url, ...r }), (e) => ({ gateway: g.url, error: e.message })))
  );
  const ok = results.filter((r) => !r.error);
  if (!ok.length) throw new Error(`No gateway answered: ${results.map((r) => `${r.gateway}: ${r.error}`).join("; ")}`);
  const sig = (r) => r.codes.map((c) => c.code).sort().join(",");
  const agree = ok.every((r) => sig(r) === sig(ok[0]));
  const primary = ok[0];
  const codes = [...primary.codes];
  if (!agree) codes.push(code("gateway.disagreement", "warning", { detail: "gateways returned different results; see perGateway" }));
  if (ok.length < results.length) codes.push(code("gateway.unavailable", "info", { failed: results.filter((r) => r.error).map((r) => r.gateway) }));
  return { ...primary, codes, perGateway: results.map((r) => ({ gateway: r.gateway, error: r.error, codes: r.codes?.map((c) => c.code) })) };
}

module.exports = { verifyManifest, verifyAcrossGateways };
