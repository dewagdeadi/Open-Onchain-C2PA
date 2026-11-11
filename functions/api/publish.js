// POST /api/publish   Authorization: Bearer <PUBLISH_TOKEN>
//   { mode: "public",  entries: [{ urn, storeBase64, claimHash, signatureHash, bindingHash, signerCertHash, parents?, softBindings? }] }
//   { mode: "private", entries: [{ urn, claimHash, signatureHash, bindingHash, signerCertHash, parents? }], publishTree? }
//   { mode: "statement", statement: { payload: "<json>", signature?: {...} } }   (signed offline with the C2PA key)
import pages from "../../lib/pages.js";

const MAX_ENTRIES = 500;

export async function onRequestPost({ request, env }) {
  if (!env.PUBLISH_TOKEN) return pages.fail(503, "publishing is not configured (PUBLISH_TOKEN)");
  const auth = request.headers.get("authorization") || "";
  if (!pages.sameSecret(auth.replace(/^Bearer\s+/i, ""), env.PUBLISH_TOKEN)) return pages.fail(401, "unauthorized");
  const pub = pages.publisherFrom(env);
  if (!pub) return pages.fail(503, "publishing is not configured (ARWEAVE_JWK)");

  const body = await request.json();
  const maxStore = Number(env.MAX_STORE_BYTES || 102400);
  const { op } = pages;

  if (body.mode === "statement") {
    const st = body.statement;
    if (!st || typeof st.payload !== "string") return pages.fail(400, "statement.payload (JSON string) required");
    const p = JSON.parse(st.payload);
    const subject = p.type === "delegate" ? p.delegate : p.type === "manifest-status" ? p.manifestId : undefined;
    const tags = op.statementTags({ kind: p.type, keyId: p.keyId, subject });
    const bytes = new TextEncoder().encode(JSON.stringify(st));
    // Refuse anything validators would ignore. Delegate-posted statements must be
    // uploaded by the delegate's own wallet, so only key-signed ones are accepted here.
    const check = await op.parseStatement({ id: "-", tags: Object.fromEntries(tags.map((t) => [t.name, t.value])) }, bytes);
    if (!check.valid || check.signedBy !== "key") return pages.fail(400, `invalid statement: ${check.reason || "must be key-signed"}`);
    return pages.json(await op.publishStatement({ statement: { body: bytes, tags, payload: p }, uploader: pub.uploader }));
  }

  const entries = body.entries;
  if (!Array.isArray(entries) || !entries.length) return pages.fail(400, "entries required");
  if (entries.length > MAX_ENTRIES) return pages.fail(413, `at most ${MAX_ENTRIES} entries per request`);

  if (body.mode === "private") {
    const res = await op.publishRoot({ entries, uploader: pub.uploader, publishTree: Boolean(body.publishTree) });
    return pages.json(res);
  }
  if (body.mode === "public") {
    const withBytes = entries.map((e) => {
      const storeBytes = pages.b64ToBytes(e.storeBase64);
      if (storeBytes.length > maxStore) throw new Error(`bad request: ${e.urn} store is ${storeBytes.length} bytes; limit is ${maxStore}`);
      const { storeBase64, ...rest } = e;
      return { ...rest, storeBytes };
    });
    const res = await op.publishStores({ entries: withBytes, uploader: pub.uploader, concurrency: 4 });
    return pages.json(res);
  }
  return pages.fail(400, "mode must be public, private or statement");
}
