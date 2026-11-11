#!/usr/bin/env node
// oprov — Open Provenance on Arweave
//
//   oprov wallet                                   create an Arweave wallet (wallet.json)
//   oprov publish  <batch.json> [--private] [--tree]   upload stores, or one hash root
//   oprov status   <withdrawn|superseded> <urn> --key key.pem [--reason uri]
//   oprov delegate <arweave-address> --key key.pem [--off]
//   oprov revoke   --key key.pem [--reason uri]
//   oprov verify   <manifest.json> [--receipt r.json] [--store file.c2pa] [--signer cert.pem] [--tsa unix]
//
// Env: ARWEAVE_WALLET (default wallet.json), TURBO_TOKEN (default arweave),
//      TURBO_PRIVATE_KEY (for EVM/Solana tokens), ARWEAVE_GATEWAY_URL, TRUSTED_UPLOADERS, DRY_RUN=1
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const op = require("../index");

const args = process.argv.slice(2);
const flag = (n) => args.includes(`--${n}`);
const opt = (n) => (args.includes(`--${n}`) ? args[args.indexOf(`--${n}`) + 1] : undefined);
const readJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const print = (o) => console.log(JSON.stringify(o, null, 2));

async function uploader() {
  const env = process.env;
  if (env.DRY_RUN === "1") return op.createUploader({ dryRun: true });
  const token = env.TURBO_TOKEN || "arweave";
  const privateKey = token === "arweave" ? readJson(env.ARWEAVE_WALLET || "wallet.json") : env.TURBO_PRIVATE_KEY;
  return op.createUploader({ token, privateKey });
}

function signingKey() {
  const f = opt("key");
  if (!f) throw new Error("--key <pem> required: the C2PA ES256 signing key (or use a KMS and op.createStatement)");
  const privateKey = crypto.createPrivateKey(fs.readFileSync(f));
  return { privateKey, key: op.p256KeyFrom(crypto.createPublicKey(privateKey)) };
}

async function statement(kind, fields) {
  const { privateKey, key } = signingKey();
  const st = op.createStatement({ kind, key, privateKey, ...fields });
  print(await op.publishStatement({ statement: st, uploader: await uploader() }));
}

async function main() {
  const [cmd, a, b] = args;
  switch (cmd) {
    case "wallet": {
      const out = opt("out") || "wallet.json";
      if (fs.existsSync(out)) throw new Error(`${out} exists`);
      const w = op.generateArweaveWallet();
      fs.writeFileSync(out, JSON.stringify(w.jwk), { mode: 0o600 });
      console.log(`Arweave wallet ${w.address} -> ${out}. Keep it secret; it signs your uploads.`);
      break;
    }
    case "publish": {
      const dir = path.dirname(path.resolve(a));
      const entries = readJson(a).map((e) => ({ ...e, storeBytes: e.storeFile ? fs.readFileSync(path.resolve(dir, e.storeFile)) : undefined }));
      const up = await uploader();
      const log = (m) => console.error(m);
      const res = flag("private")
        ? await op.publishRoot({ entries, uploader: up, publishTree: flag("tree"), log })
        : await op.publishStores({ entries, uploader: up, log });
      fs.writeFileSync("receipts.json", JSON.stringify(res.receipts, null, 2));
      console.error(`${entries.length} manifests, ${res.cost.uploads} upload(s), ${res.cost.winc} winc. Wrote receipts.json`);
      console.error("Receipts become timestamp proofs once the bundle is mined (usually minutes).");
      break;
    }
    case "status":
      await statement("manifest-status", { status: a, manifestId: op.manifestId(b), reasonUri: opt("reason") || null });
      break;
    case "delegate":
      await statement("delegate", { delegate: a, active: !flag("off") });
      break;
    case "revoke":
      await statement("revoke", { reasonUri: opt("reason") || null });
      break;
    case "verify": {
      const signer = opt("signer") ? op.p256KeyFrom(fs.readFileSync(opt("signer"), "utf8")) : undefined;
      print(
        await op.verifyManifest({
          gateway: op.createGateway(),
          manifest: readJson(a),
          receipt: opt("receipt") && readJson(opt("receipt")),
          storeBytes: opt("store") && fs.readFileSync(opt("store")),
          signerKey: signer,
          tsaTime: opt("tsa") && Number(opt("tsa")),
          trustedUploaders: process.env.TRUSTED_UPLOADERS?.split(","),
        })
      );
      break;
    }
    default:
      console.log(fs.readFileSync(__filename, "utf8").split("\n").slice(1, 13).join("\n").replace(/^\/\/ ?/gm, ""));
  }
}

main().catch((e) => {
  console.error(e.message);
  process.exitCode = 1;
});
