// Isomorphic statement parsing and the read-time rules that replace a smart contract.
//
// Body:  { "payload": "<JSON string>", "signature": { "alg": "ES256", "x", "y", "sig" } }
//        The signature covers the exact UTF-8 bytes of `payload`.
//        Delegate-posted statements omit `signature`; the Arweave data item owner
//        must then be an active delegate of the key.
//
// Kinds: delegate         key-signed       { delegate: <arweave address>, active: bool }
//        revoke           key-signed       { reasonUri }                      (final)
//        manifest-status  key or delegate  { manifestId, status: superseded|withdrawn, reasonUri }
const { PROTOCOL } = require("./gateway");
const { keyIdForWeb, es256VerifyWeb } = require("./web");

const KINDS = ["delegate", "revoke", "manifest-status"];
const STATUS_RANK = { none: 0, superseded: 1, withdrawn: 2 };

/** Check one statement record (gateway tx + its body bytes). Never throws. */
async function parseStatement(tx, bodyBytes) {
  const out = { id: tx.id, owner: tx.owner, block: tx.block, valid: false };
  try {
    const body = JSON.parse(new TextDecoder().decode(bodyBytes));
    const p = JSON.parse(body.payload);
    Object.assign(out, { kind: p.type, keyId: p.keyId, payload: p });
    if (p.protocol !== PROTOCOL) return { ...out, reason: "unknown protocol" };
    if (!KINDS.includes(p.type)) return { ...out, reason: "unknown kind" };
    if (tx.tags["Statement-Type"] !== p.type || tx.tags["Signer-Key-Id"] !== p.keyId) return { ...out, reason: "tags do not match payload" };
    if (p.type === "manifest-status" && !(p.status in STATUS_RANK && p.status !== "none")) return { ...out, reason: "bad status" };
    if (body.signature) {
      const { alg, x, y, sig } = body.signature;
      if (alg !== "ES256" || (await keyIdForWeb(x, y)) !== p.keyId) return { ...out, reason: "key does not match keyId" };
      if (!(await es256VerifyWeb(body.payload, sig, x, y))) return { ...out, reason: "bad signature" };
      return { ...out, valid: true, signedBy: "key" };
    }
    if (p.type !== "manifest-status") return { ...out, reason: `${p.type} must be key-signed` };
    return { ...out, valid: true, signedBy: "delegate" };
  } catch (e) {
    return { ...out, reason: `unreadable: ${e.message}` };
  }
}

const order = (a, b) =>
  a.block.height - b.block.height || String(a.payload.issuedAt).localeCompare(b.payload.issuedAt) || a.id.localeCompare(b.id);

/**
 * The read-time rules. Input: parsed statements for ONE keyId.
 *  1. Only mined statements count; pending ones are reported but not applied.
 *  2. Order: block height, then issuedAt, then id.
 *  3. The first valid revoke is final. After it, delegates stop counting.
 *  4. A delegate counts for statements in blocks strictly after its delegation.
 *  5. Manifest status only moves forward: none -> superseded -> withdrawn.
 *     The key itself may still post it after revocation, to clean up.
 */
function resolveSigner(statements) {
  const valid = statements.filter((s) => s.valid);
  const state = {
    revoked: null,
    delegates: {},
    manifests: {},
    pending: valid.filter((s) => !s.block).map((s) => s.id),
    ignored: statements.filter((s) => !s.valid).map((s) => ({ id: s.id, reason: s.reason })),
  };
  for (const s of valid.filter((s) => s.block).sort(order)) {
    const at = { height: s.block.height, timestamp: s.block.timestamp, id: s.id };
    if (s.kind === "revoke") {
      if (!state.revoked) state.revoked = { ...at, reasonUri: s.payload.reasonUri || null };
    } else if (s.kind === "delegate") {
      if (state.revoked) state.ignored.push({ id: s.id, reason: "after revocation" });
      else if (s.payload.active === false) delete state.delegates[s.payload.delegate];
      else state.delegates[s.payload.delegate] = at;
    } else if (s.kind === "manifest-status") {
      const d = state.delegates[s.owner];
      const ok = s.signedBy === "key" || (!state.revoked && d && d.height < s.block.height);
      if (!ok) {
        state.ignored.push({ id: s.id, reason: "uploader is not an active delegate" });
        continue;
      }
      const cur = state.manifests[s.payload.manifestId];
      if (!cur || STATUS_RANK[s.payload.status] > STATUS_RANK[cur.status])
        state.manifests[s.payload.manifestId] = { status: s.payload.status, reasonUri: s.payload.reasonUri || null, ...at };
    }
  }
  return state;
}

module.exports = { KINDS, STATUS_RANK, parseStatement, resolveSigner };
