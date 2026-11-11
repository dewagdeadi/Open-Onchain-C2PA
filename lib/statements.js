// Node: build and sign statements with a C2PA ES256 key. Parsing and rules live in rules.js.
const { PROTOCOL, es256Sign } = require("./core");
const { statementTags } = require("./gateway");
const rules = require("./rules");

/**
 * Build a statement ready to upload. Pass privateKey to sign with the C2PA key;
 * omit it for a delegate-posted manifest-status.
 */
function createStatement({ kind, key, privateKey, issuedAt = new Date().toISOString(), ...fields }) {
  if (!rules.KINDS.includes(kind)) throw new Error(`Unknown statement kind ${kind}`);
  if (kind !== "manifest-status" && !privateKey) throw new Error(`${kind} must be signed by the key itself`);
  if (kind === "manifest-status" && !(fields.status in rules.STATUS_RANK && fields.status !== "none"))
    throw new Error("status must be superseded or withdrawn");
  const payloadObj = { protocol: PROTOCOL, type: kind, keyId: key.keyId, issuedAt, ...fields };
  const payload = JSON.stringify(payloadObj);
  const body = { payload };
  if (privateKey) body.signature = { alg: "ES256", x: key.x, y: key.y, sig: es256Sign(Buffer.from(payload), privateKey) };
  const subject = kind === "delegate" ? fields.delegate : kind === "manifest-status" ? fields.manifestId : undefined;
  return { body: Buffer.from(JSON.stringify(body)), tags: statementTags({ kind, keyId: key.keyId, subject }), payload: payloadObj };
}

module.exports = { ...rules, createStatement };
