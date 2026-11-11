// Shared helpers for the Cloudflare Pages Functions in /functions.
const op = require("./worker");

const json = (body, status = 200, extra = {}) =>
  new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra },
  });

const fail = (status, message) => json({ error: message }, status);

const list = (v) => (v || "").split(",").map((s) => s.trim()).filter(Boolean);

function gatewaysFrom(env) {
  const urls = list(env.GATEWAYS);
  return (urls.length ? urls : ["https://arweave.net"]).map((url) => op.createGateway({ url: url.replace(/\/$/, "") }));
}

function b64ToBytes(s) {
  if (typeof s !== "string") throw new Error("expected base64 string");
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** Constant-time string compare for the bearer token. */
function sameSecret(a, b) {
  const x = new TextEncoder().encode(a || "");
  const y = new TextEncoder().encode(b || "");
  let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0);
  return d === 0 && x.length > 0;
}

function publisherFrom(env) {
  if (!env.ARWEAVE_JWK) return null;
  const jwk = typeof env.ARWEAVE_JWK === "string" ? JSON.parse(env.ARWEAVE_JWK) : env.ARWEAVE_JWK;
  const mode = (env.UPLOAD_MODE || "bundler").toLowerCase();
  if (mode !== "bundler" && mode !== "direct") throw new Error(`UPLOAD_MODE must be bundler or direct, got ${env.UPLOAD_MODE}`);
  const uploader =
    mode === "direct"
      ? op.createDirectUploader({ jwk, node: env.ARWEAVE_NODE_URL || "https://arweave.net", maxRewardWinston: env.MAX_REWARD_WINSTON || undefined })
      : op.createWebUploader({ jwk, url: env.BUNDLER_URL || "https://upload.ardrive.io" });
  return { jwk, mode, uploader };
}

const arweaveAddress = async (jwk) => op.b64uEncode(await op.sha256Bytes(op.b64uDecode(jwk.n)));

module.exports = { op, json, fail, list, gatewaysFrom, b64ToBytes, sameSecret, publisherFrom, arweaveAddress };
