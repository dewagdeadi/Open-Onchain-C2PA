// Hashing, Merkle batches, P-256 (ES256) keys and Arweave wallets.
const crypto = require("crypto");

const PROTOCOL = "openprovenance/1";
const sha256 = (data) => "0x" + crypto.createHash("sha256").update(data).digest("hex");
const b64u = (buf) => Buffer.from(buf).toString("base64url");
const hex = (buf) => "0x" + Buffer.from(buf).toString("hex");
const unhex = (h) => Buffer.from(h.replace(/^0x/, ""), "hex");

/** manifestId = sha256 of the manifest URN string ("urn:c2pa:<uuid>..."). */
const manifestId = (urn) => sha256(Buffer.from(urn, "utf8"));

// ---------------------------------------------------------------------------
// P-256 / ES256 (the key type most C2PA signers use)
// ---------------------------------------------------------------------------

/** Raw public point (x, y) and keyId = sha256(0x04||x||y) from a cert, key or KeyObject. */
function p256KeyFrom(keyOrCert) {
  let pub;
  if (keyOrCert instanceof crypto.KeyObject) pub = keyOrCert.type === "public" ? keyOrCert : crypto.createPublicKey(keyOrCert);
  else if (typeof keyOrCert === "string" && keyOrCert.includes("CERTIFICATE")) pub = new crypto.X509Certificate(keyOrCert).publicKey;
  else pub = crypto.createPublicKey(keyOrCert);
  const jwk = pub.export({ format: "jwk" });
  if (jwk.crv !== "P-256") throw new Error(`Only P-256 (ES256) keys are supported for statements, got ${jwk.crv}`);
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  return { x: hex(x), y: hex(y), keyId: keyIdFor(hex(x), hex(y)) };
}

const keyIdFor = (x, y) => sha256(Buffer.concat([Buffer.from([4]), unhex(x), unhex(y)]));

/** sha256 of the DER end-entity certificate. */
const signerCertHash = (pemCert) => sha256(new crypto.X509Certificate(pemCert).raw);

/** ES256 signature (raw r||s, base64url) over the exact bytes given. */
function es256Sign(bytes, privateKey) {
  return b64u(crypto.sign("sha256", Buffer.from(bytes), { key: privateKey, dsaEncoding: "ieee-p1363" }));
}

function es256Verify(bytes, sigB64u, x, y) {
  const key = crypto.createPublicKey({
    key: { kty: "EC", crv: "P-256", x: b64u(unhex(x)), y: b64u(unhex(y)) },
    format: "jwk",
  });
  return crypto.verify("sha256", Buffer.from(bytes), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(sigB64u, "base64url"));
}

// ---------------------------------------------------------------------------
// Arweave wallets (RSA-4096 JWK). Free-tier Turbo uploads need a signer, not funds.
// ---------------------------------------------------------------------------

function generateArweaveWallet() {
  const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 4096, publicExponent: 65537 });
  const jwk = privateKey.export({ format: "jwk" });
  return { jwk, address: arweaveAddress(jwk) };
}

const arweaveAddress = (jwk) => b64u(crypto.createHash("sha256").update(Buffer.from(jwk.n, "base64url")).digest());

module.exports = {
  ...require("./batch"),
  PROTOCOL,
  sha256,
  hex,
  unhex,
  manifestId,
  p256KeyFrom,
  keyIdFor,
  signerCertHash,
  es256Sign,
  es256Verify,
  generateArweaveWallet,
  arweaveAddress,
};
