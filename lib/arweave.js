// Node uploader through the Turbo SDK. Tags and reads live in gateway.js.
const crypto = require("crypto");
const gateway = require("./gateway");

// ---------------------------------------------------------------------------
// Uploading
// ---------------------------------------------------------------------------

/**
 * Turbo uploader. Signs data items with an Arweave JWK by default: uploads under
 * Turbo's free-size limit need a signer but no funds. Use token "pol",
 * "ethereum", "solana", ... with a funded key for larger uploads.
 *
 * { dryRun: true } returns an offline uploader (ids derived from content).
 */
async function createUploader({ dryRun = false, token = "arweave", privateKey, sink } = {}) {
  if (dryRun) {
    const address = "dry-run-" + crypto.randomBytes(6).toString("hex");
    return {
      address,
      dryRun: true,
      async upload(data, tags) {
        const buf = Buffer.from(data);
        const id = crypto.createHash("sha256").update(buf).update(JSON.stringify(tags)).update(address).digest("base64url").slice(0, 43);
        if (sink) sink.put({ id, data: buf, tags, owner: address });
        return { id, winc: "0" };
      },
    };
  }
  if (!privateKey) throw new Error("No signer: pass an Arweave JWK (token arweave) or a hex key for EVM/Solana tokens");
  const { TurboFactory } = require("@ardrive/turbo-sdk");
  const turbo = TurboFactory.authenticated({ privateKey, token });
  const address = await turbo.signer.getNativeAddress();
  return {
    address,
    dryRun: false,
    turbo,
    async upload(data, tags) {
      const buf = Buffer.from(data);
      const res = await turbo.uploadFile({
        fileStreamFactory: () => buf,
        fileSizeFactory: () => buf.length,
        dataItemOpts: { tags },
      });
      return { id: res.id, winc: res.winc };
    },
  };
}

module.exports = { ...gateway, createUploader };
