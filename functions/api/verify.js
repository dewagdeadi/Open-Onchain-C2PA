// POST /api/verify
// { manifest: { urn | manifestId, claimHash, signatureHash, bindingHash, signerCertHash, parents? },
//   receipt?, storeSha256? | storeBase64?, signerCertPem? | signerKey?: {x,y}, tsaTime?, trustedUploaders? }
import pages from "../../lib/pages.js";

const HASH = /^0x[0-9a-f]{64}$/i;
const MAX_STORE = 5 * 1024 * 1024;

export async function onRequestPost({ request, env }) {
  const body = await request.json();
  const m = body.manifest || {};
  if (!m.urn && !HASH.test(m.manifestId || "")) return pages.fail(400, "manifest.urn or manifest.manifestId required");
  for (const f of ["claimHash", "signatureHash", "bindingHash", "signerCertHash"])
    if (!HASH.test(m[f] || "")) return pages.fail(400, `manifest.${f} must be a 0x-prefixed SHA-256`);

  let storeBytes;
  if (body.storeBase64) {
    storeBytes = pages.b64ToBytes(body.storeBase64);
    if (storeBytes.length > MAX_STORE) return pages.fail(413, "store too large");
  }
  if (body.storeSha256 && !HASH.test(body.storeSha256)) return pages.fail(400, "storeSha256 must be a 0x-prefixed SHA-256");
  let signerKey = body.signerKey;
  let signerNote = null;
  if (!signerKey && body.signerCertPem) {
    try {
      signerKey = pages.op.p256FromPem(body.signerCertPem);
    } catch {
      signerNote = { code: "org.openprovenance.signer.unsupported", severity: "info", detail: "status records exist only for ES256 (P-256) signers" };
    }
  }

  const trusted = body.trustedUploaders?.length ? body.trustedUploaders : pages.list(env.TRUSTED_UPLOADERS);
  const result = await pages.op.verifyAcrossGateways({
    gateways: pages.gatewaysFrom(env),
    manifest: m,
    receipt: body.receipt,
    storeBytes,
    storeSha256: body.storeSha256,
    signerKey,
    tsaTime: body.tsaTime ? Number(body.tsaTime) : undefined,
    trustedUploaders: trusted.length ? trusted : undefined,
  });
  if (signerNote) result.codes.push(signerNote);
  return pages.json(result);
}
