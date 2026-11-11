// Isomorphic primitives (Web Crypto). Run unchanged in Cloudflare Workers / Pages
// Functions, browsers and Node >= 20. No Node built-ins.
const { keccak256 } = require("ethereum-cryptography/keccak");

const subtle = () => globalThis.crypto.subtle;
const enc = new TextEncoder();

const toBytes = (x) => (typeof x === "string" ? enc.encode(x) : x instanceof Uint8Array ? x : new Uint8Array(x));
const hexToBytes = (h) => {
  const s = h.replace(/^0x/, "");
  if (s.length % 2 || /[^0-9a-f]/i.test(s)) throw new Error("bad hex");
  return Uint8Array.from(s.match(/../g) || [], (b) => parseInt(b, 16));
};
const bytesToHex = (b) => "0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) out.set(p, (o += p.length) - p.length);
  return out;
};
const b64uEncode = (bytes) => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const b64uDecode = (str) => {
  const s = atob(str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
};
const b64Decode = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));

const sha256Bytes = async (data) => new Uint8Array(await subtle().digest("SHA-256", toBytes(data)));
const sha256Hex = async (data) => bytesToHex(await sha256Bytes(data));
const sha384 = async (data) => new Uint8Array(await subtle().digest("SHA-384", toBytes(data)));

const manifestIdWeb = (urn) => sha256Hex(urn);
const keyIdForWeb = (x, y) => sha256Hex(concat(Uint8Array.of(4), hexToBytes(x), hexToBytes(y)));

// ---------------------------------------------------------------------------
// Anchor leaf (OpenZeppelin StandardMerkleTree compatible) without ethers
// abi.encode(bytes32 x5, string storeUri, bytes32[] parents)
// ---------------------------------------------------------------------------

const word = (n) => {
  const w = new Uint8Array(32);
  let v = BigInt(n);
  for (let i = 31; i >= 0 && v > 0n; i--, v >>= 8n) w[i] = Number(v & 0xffn);
  return w;
};
const pad32 = (b) => concat(b, new Uint8Array((32 - (b.length % 32)) % 32));
const b32 = (h) => {
  const b = hexToBytes(h);
  if (b.length !== 32) throw new Error("expected bytes32");
  return b;
};

function abiEncodeAnchor(a) {
  const uri = enc.encode(a.storeUri || "");
  const parents = a.parents || [];
  const head = 7 * 32;
  const strTail = concat(word(uri.length), pad32(uri));
  const arrTail = concat(word(parents.length), ...parents.map(b32));
  return concat(
    b32(a.manifestId),
    b32(a.claimHash),
    b32(a.signatureHash),
    b32(a.bindingHash),
    b32(a.signerCertHash),
    word(head),
    word(head + strTail.length),
    strTail,
    arrTail
  );
}

const leafHashWeb = (a) => bytesToHex(keccak256(keccak256(abiEncodeAnchor(a))));

function verifyProofWeb(root, leaf, proof) {
  let h = hexToBytes(leaf);
  for (const p of proof) {
    const q = hexToBytes(p);
    let lt = false;
    for (let i = 0; i < 32; i++) if (h[i] !== q[i]) { lt = h[i] < q[i]; break; }
    h = keccak256(lt ? concat(h, q) : concat(q, h));
  }
  return bytesToHex(h).toLowerCase() === root.toLowerCase();
}

// ---------------------------------------------------------------------------
// ES256 (P-256) verification and certificate key extraction
// ---------------------------------------------------------------------------

async function es256VerifyWeb(bytes, sigB64u, x, y) {
  try {
    const key = await subtle().importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: b64uEncode(hexToBytes(x)), y: b64uEncode(hexToBytes(y)), ext: true },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    return await subtle().verify({ name: "ECDSA", hash: "SHA-256" }, key, b64uDecode(sigB64u), toBytes(bytes));
  } catch {
    return false;
  }
}

// OIDs id-ecPublicKey (1.2.840.10045.2.1) followed by prime256v1 (1.2.840.10045.3.1.7)
const EC_P256_ALG = hexToBytes("0x06072a8648ce3d020106082a8648ce3d030107");

/** P-256 public point from a PEM certificate or SPKI public key, without an ASN.1 library. */
function p256FromPem(pem) {
  const der = b64Decode(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
  outer: for (let i = 0; i + EC_P256_ALG.length < der.length; i++) {
    for (let j = 0; j < EC_P256_ALG.length; j++) if (der[i + j] !== EC_P256_ALG[j]) continue outer;
    const k = i + EC_P256_ALG.length; // BIT STRING 03 42 00 04 || x || y
    if (der[k] === 0x03 && der[k + 1] === 0x42 && der[k + 2] === 0x00 && der[k + 3] === 0x04) {
      return { x: bytesToHex(der.slice(k + 4, k + 36)), y: bytesToHex(der.slice(k + 36, k + 68)) };
    }
  }
  throw new Error("No P-256 public key found (only ES256 signer keys are supported)");
}

const signerCertHashWeb = (pem) => sha256Hex(b64Decode(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")));

module.exports = {
  toBytes,
  hexToBytes,
  bytesToHex,
  concat,
  b64uEncode,
  b64uDecode,
  sha256Bytes,
  sha256Hex,
  sha384,
  manifestIdWeb,
  keyIdForWeb,
  abiEncodeAnchor,
  leafHashWeb,
  verifyProofWeb,
  es256VerifyWeb,
  p256FromPem,
  signerCertHashWeb,
};
