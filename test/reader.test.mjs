// The in-browser C2PA reader, checked against c2pa-ts on real C2PA sample files.
import "reflect-metadata";
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";
import { createAsset } from "@trustnxt/c2pa-ts/asset";
import { SuperBox } from "@trustnxt/c2pa-ts/jumbf";
import { ManifestStore } from "@trustnxt/c2pa-ts/manifest";
import { readFile, extractManifestStore } from "../public/js/c2pa-reader.mjs";

const fx = (f) => new Uint8Array(fs.readFileSync(new URL(`./fixtures/c2pa/${f}`, import.meta.url)));
const H = (b) => "0x" + crypto.createHash("sha256").update(b).digest("hex");

for (const f of ["CA.jpg", "C.jpg", "cloud_manifest.c2pa"]) {
  test(`${f}: same store, label and certificate as c2pa-ts`, async () => {
    const bytes = fx(f);
    const refStore = f.endsWith(".c2pa") ? bytes : await (await createAsset(Buffer.from(bytes))).getManifestJUMBF();
    const ref = ManifestStore.read(SuperBox.fromBuffer(refStore)).getActiveManifest();
    const { store, manifest: m } = await readFile(bytes);
    assert.equal(H(store), H(refStore));
    assert.equal(m.storeSha256, H(refStore));
    assert.equal(m.urn, ref.label);
    assert.equal(m.signerCertHash, H(Buffer.from(ref.signature.signatureData.certificate.rawData)));
    assert.equal(m.signer, "C2PA Test Signing Cert");
    assert.match(m.claimHash, /^0x[0-9a-f]{64}$/);
    assert.match(m.bindingHash, /^0x[0-9a-f]{64}$/);
    assert.equal(new crypto.X509Certificate(m.certificatePem).subject.includes("C2PA Test Signing Cert"), true);
  });
}

test("files without Content Credentials return null", async () => {
  assert.equal(await readFile(fx("no_manifest.jpg")), null);
  assert.equal(extractManifestStore(new Uint8Array([1, 2, 3])), null);
});

test("truncated or corrupted credentials are never misread", async () => {
  const store = extractManifestStore(fx("CA.jpg"));
  assert.equal(await readFile(store.slice(0, store.length >> 1)), null);
  const bad = store.slice();
  const claimAt = Buffer.from(bad).indexOf("c2pa.claim");
  bad.fill(0xff, claimAt + 16, claimAt + 24); // break the claim's CBOR box header
  await assert.rejects(readFile(bad));
});
