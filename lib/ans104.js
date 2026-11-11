// Minimal ANS-104 data item signer (Arweave RSA-PSS, signature type 1) on Web Crypto,
// plus an uploader for Turbo's HTTP API. Lets Cloudflare Workers publish without
// the Node-only Turbo SDK.
const { toBytes, concat, sha256Bytes: sha256, sha384, b64uEncode, b64uDecode } = require("./web");

const SIG_TYPE_ARWEAVE = 1;
const enc = new TextEncoder();

function u16le(n) {
  return Uint8Array.of(n & 0xff, (n >> 8) & 0xff);
}
function u64le(n) {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++, v >>= 8n) b[i] = Number(v & 0xffn);
  return b;
}
// Avro zig-zag varint for longs
function zigzag(n) {
  let v = (BigInt(n) << 1n) ^ (BigInt(n) >> 63n);
  const out = [];
  while (v > 0x7fn) {
    out.push(Number((v & 0x7fn) | 0x80n));
    v >>= 7n;
  }
  out.push(Number(v));
  return Uint8Array.from(out);
}
const avroBytes = (b) => concat(zigzag(b.length), b);

/** Avro-encoded tag array, exactly as arbundles serializes it. */
function serializeTags(tags) {
  if (!tags.length) return new Uint8Array(0);
  return concat(
    zigzag(tags.length),
    ...tags.map((t) => concat(avroBytes(enc.encode(t.name)), avroBytes(enc.encode(t.value)))),
    Uint8Array.of(0)
  );
}

async function deepHash(data) {
  if (Array.isArray(data)) {
    let acc = await sha384(concat(enc.encode("list"), enc.encode(String(data.length))));
    for (const chunk of data) acc = await sha384(concat(acc, await deepHash(chunk)));
    return acc;
  }
  const tag = concat(enc.encode("blob"), enc.encode(String(data.length)));
  return sha384(concat(await sha384(tag), await sha384(data)));
}

async function importJwk(jwk) {
  return globalThis.crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n: jwk.n, e: jwk.e, d: jwk.d, p: jwk.p, q: jwk.q, dp: jwk.dp, dq: jwk.dq, qi: jwk.qi, ext: true },
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

/**
 * Build and sign a data item.
 * @returns {{ id: string, raw: Uint8Array, owner: string }}
 */
async function createSignedDataItem({ data, tags = [], jwk }) {
  const owner = b64uDecode(jwk.n);
  if (owner.length !== 512) throw new Error("Arweave JWK must be RSA-4096");
  const body = toBytes(data);
  const tagBytes = serializeTags(tags);
  const message = await deepHash([
    enc.encode("dataitem"),
    enc.encode("1"),
    enc.encode(String(SIG_TYPE_ARWEAVE)),
    owner,
    new Uint8Array(0), // target
    new Uint8Array(0), // anchor
    tagBytes,
    body,
  ]);
  const key = await importJwk(jwk);
  const signature = new Uint8Array(await globalThis.crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, key, message));
  const raw = concat(
    u16le(SIG_TYPE_ARWEAVE),
    signature,
    owner,
    Uint8Array.of(0), // no target
    Uint8Array.of(0), // no anchor
    u64le(tags.length),
    u64le(tagBytes.length),
    tagBytes,
    body
  );
  return { id: b64uEncode(await sha256(signature)), raw, owner: b64uEncode(await sha256(owner)) };
}

/**
 * Uploader with the same interface as createUploader() in lib/arweave.js, for
 * Workers. Posts signed data items to Turbo (or any compatible bundler).
 */
function createWebUploader({ jwk, url = "https://upload.ardrive.io", fetch: f = (...a) => fetch(...a) }) {
  let address = null;
  return {
    get address() {
      return address;
    },
    async upload(data, tags) {
      const item = await createSignedDataItem({ data, tags, jwk });
      address = item.owner;
      const res = await f(`${url}/v1/tx/arweave`, {
        method: "POST",
        headers: { "content-type": "application/octet-stream" },
        body: item.raw,
      });
      if (!res.ok) throw new Error(`Bundler ${res.status}: ${await res.text().catch(() => "")}`);
      const json = await res.json().catch(() => ({}));
      if (json.id && json.id !== item.id) throw new Error(`Bundler returned id ${json.id}, expected ${item.id}`);
      return { id: item.id, winc: String(json.winc ?? "0") };
    },
  };
}

module.exports = { serializeTags, deepHash, createSignedDataItem, createWebUploader };
