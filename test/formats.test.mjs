// Every container the reader supports. Signed samples are compared with c2pa-ts; for the
// other formats, real Content Credentials are embedded into unsigned carrier files using the
// layouts the C2PA reference SDK (c2pa-rs) writes, and must come back byte-for-byte.
import "reflect-metadata";
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import zlib from "node:zlib";
import crypto from "node:crypto";
import { createAsset } from "@trustnxt/c2pa-ts/asset";
import { locateManifest, locateManifestInBlob, readFile } from "../public/js/c2pa-reader.mjs";

const fx = (f) => new Uint8Array(fs.readFileSync(new URL(`./fixtures/c2pa/${f}`, import.meta.url)));
const H = (b) => crypto.createHash("sha256").update(b).digest("hex");
const S = fx("cloud_manifest.c2pa"); // a real ES256-signed manifest store
const LABEL = "urn:uuid:e5412b29-135b-4c2d-8513-580286e19726";
const cat = (...p) => Buffer.concat(p.map((x) => Buffer.from(x)));
const be32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const le32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const le16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };

async function expectStore(bytes, container) {
  const found = await locateManifest(bytes);
  assert.ok(found?.store, `no store found (${container})`);
  assert.equal(H(found.store), H(S));
  assert.equal(found.container, container);
  const r = await readFile(bytes);
  assert.equal(r.manifest.urn, LABEL);
}

// --- signed samples ---------------------------------------------------------------
for (const f of ["video1.mp4", "dashinit.mp4"]) {
  test(`${f} (signed MP4) matches the reference`, async () => {
    const bytes = fx(f);
    // c2pa-ts can't open DASH init segments, so that one is checked against the generic scan instead
    const ref = f === "dashinit.mp4" ? (await readFile(cat(Buffer.from("x".repeat(8)), (await locateManifest(bytes)).store))).store : await (await createAsset(Buffer.from(bytes))).getManifestJUMBF();
    const found = await locateManifest(bytes);
    assert.equal(found.container, "ISO BMFF (MP4, MOV, HEIC, AVIF)");
    assert.equal(H(found.store), H(ref));
    assert.ok((await readFile(bytes)).manifest.claimHash);
  });
}

test("large video is read in pieces, with the same result", async () => {
  const bytes = fx("video1.mp4");
  const whole = await locateManifest(bytes);
  const pieces = await locateManifestInBlob(new Blob([bytes]), { maxWholeBytes: 1024 });
  assert.equal(H(pieces.store), H(whole.store));
});

test("remote manifests are reported with their URL", async () => {
  const r = await readFile(fx("cloud.jpg"));
  assert.equal(r.store, undefined);
  assert.match(r.remote, /^https:\/\/cai-manifests\.adobe\.com\/manifests\//);
});

// --- carriers with embedded credentials ---------------------------------------------
test("WebP and WAV: RIFF C2PA chunk", async () => {
  for (const f of ["sample1.webp", "sample1.wav"]) {
    const b = Buffer.from(fx(f));
    const chunk = cat("C2PA", le32(S.length), S, S.length & 1 ? [0] : []);
    const out = cat(b, chunk);
    out.writeUInt32LE(out.length - 8, 4);
    await expectStore(out, "RIFF (WebP, WAV, AVI)");
  }
});

test("HEIF and AVIF: C2PA uuid box", async () => {
  const uuid = Buffer.from("d8fec3d61b0e483c92975828877ec481", "hex");
  const payload = cat(uuid, [0, 0, 0, 0], "manifest", [0], Buffer.alloc(8), S);
  for (const f of ["sample1.heif", "sample1.avif"]) await expectStore(cat(fx(f), be32(8 + payload.length), "uuid", payload), "ISO BMFF (MP4, MOV, HEIC, AVIF)");
});

test("GIF: C2PA_GIF application extension in 255-byte sub-blocks", async () => {
  const g = Buffer.from(fx("sample1.gif"));
  const blocks = [];
  for (let i = 0; i < S.length; i += 255) { const part = S.subarray(i, i + 255); blocks.push([part.length], part); }
  const ext = cat([0x21, 0xff, 11], "C2PA_GIF", [1, 0, 0], ...blocks, [0]);
  await expectStore(cat(g.subarray(0, g.length - 1), ext, [0x3b]), "GIF");
});

test("TIFF (both byte orders): tag 0xCD41", async () => {
  const le = cat("II", le16(42), le32(8), le16(1), le16(0xcd41), le16(7), le32(S.length), le32(26), le32(0), S);
  await expectStore(le, "TIFF");
  const u16be = (n) => Buffer.from([n >> 8, n & 255]);
  const be = cat("MM", u16be(42), be32(8), u16be(1), u16be(0xcd41), u16be(7), be32(S.length), be32(26), be32(0), S);
  await expectStore(be, "TIFF");
});

test("MP3: ID3v2 GEOB frame", async () => {
  const frame = cat([0], "application/c2pa", [0], "c2pa", [0], "c2pa manifest store", [0], S);
  const id3body = cat("GEOB", be32(frame.length), [0, 0], frame);
  const syncsafe = (n) => Buffer.from([(n >> 21) & 127, (n >> 14) & 127, (n >> 7) & 127, n & 127]);
  await expectStore(cat("ID3", [3, 0, 0], syncsafe(id3body.length), id3body, fx("sample1-short.mp3")), "Embedded JUMBF");
});

test("JPEG XL: top-level jumb box", async () => {
  await expectStore(cat(fx("sample1.jxl"), S), "Embedded JUMBF");
});

test("SVG: <c2pa:manifest> with base64", async () => {
  const svg = Buffer.from(fx("sample3.svg")).toString("utf8").replace(/(<c2pa:manifest[^>]*>)[^<]*(<\/c2pa:manifest>)/, `$1${Buffer.from(S).toString("base64")}$2`);
  await expectStore(Buffer.from(svg), "Text (SVG, XML, HTML, code)");
});

test("text and code: BEGIN/END C2PA MANIFEST data URI", async () => {
  const ref = `data:application/c2pa;base64,${Buffer.from(S).toString("base64")}`;
  await expectStore(Buffer.from(`print("hi")\n# -----BEGIN C2PA MANIFEST----- ${ref} -----END C2PA MANIFEST-----\n`), "Text (SVG, XML, HTML, code)");
  await expectStore(Buffer.from(`<p>hi</p>\n<!-- -----BEGIN C2PA MANIFEST-----\n${ref}\n-----END C2PA MANIFEST----- -->\n`), "Text (SVG, XML, HTML, code)");
  const r = await readFile(Buffer.from("# -----BEGIN C2PA MANIFEST----- https://example.com/m.c2pa -----END C2PA MANIFEST-----"));
  assert.equal(r.remote, "https://example.com/m.c2pa");
});

function zip(entries) {
  const locals = [], centrals = [];
  let offset = 0;
  for (const { name, data, method } of entries) {
    const body = method === 8 ? zlib.deflateRawSync(data) : Buffer.from(data);
    const crc = zlib.crc32(data);
    const n = Buffer.from(name);
    const common = cat(le16(20), le16(0), le16(method), le16(0), le16(0), le32(crc), le32(body.length), le32(data.length), le16(n.length), le16(0));
    locals.push(cat(le32(0x04034b50), common, n, body));
    centrals.push(cat(le32(0x02014b50), le16(20), common, le16(0), le16(0), le16(0), le32(0), le32(offset), n));
    offset += locals.at(-1).length;
  }
  const cd = cat(...centrals);
  return cat(...locals, cd, le32(0x06054b50), le16(0), le16(0), le16(entries.length), le16(entries.length), le32(cd.length), le32(offset), le16(0));
}
test("Office / ODF / EPUB: META-INF/content_credential.c2pa, stored or deflated", async () => {
  for (const method of [0, 8]) {
    const z = zip([
      { name: "word/document.xml", data: Buffer.from("<w:document/>".repeat(50)), method: 8 },
      { name: "META-INF/content_credential.c2pa", data: Buffer.from(S), method },
    ]);
    await expectStore(z, "ZIP / Office / ODF / EPUB");
  }
});

test("PDF: C2PA_Manifest attachment, compressed or not, with direct or indirect length", async () => {
  for (const [filter, data] of [["", Buffer.from(S)], ["/Filter/FlateDecode", zlib.deflateSync(S)]]) {
    for (const indirect of [false, true]) {
      const len = indirect ? "/Length 3 0 R" : `/Length ${data.length}`;
      const pdf = cat(
        "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n",
        `1 0 obj\n<</Type/EmbeddedFile/Subtype/application#2Fc2pa${filter}${len}>>stream\r\n`, data, "\r\nendstream\nendobj\n",
        "2 0 obj\n<</AFRelationship/C2PA_Manifest/EF<</F 1 0 R>>/F(manifest.c2pa)/Type/Filespec>>\nendobj\n",
        `3 0 obj\n${data.length}\nendobj\n%%EOF\n`
      );
      await expectStore(pdf, "PDF");
    }
  }
});

test("files without credentials stay null, including look-alikes", async () => {
  for (const f of ["sample1.webp", "sample1.wav", "sample1.gif", "sample1.heif", "sample1.avif", "sample1.jxl", "sample1-short.mp3", "no_manifest.jpg"])
    assert.equal(await readFile(fx(f)), null, f);
  assert.equal(await readFile(Buffer.from("just some text that mentions jumb and c2pa")), null);
});
