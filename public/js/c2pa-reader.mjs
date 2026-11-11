// Minimal, dependency-free C2PA reader for the browser (and Node, Workers).
// Finds the manifest store in a file and pulls out what Open Provenance needs:
// the store bytes, the active manifest's label, claim and signature hashes, the
// hard-binding hash, the signer certificate and a few human-readable details.
// It does NOT validate signatures: run a full C2PA validator for that.
//
// Containers (layouts as written by the C2PA reference SDK, c2pa-rs):
//   JPEG APP11 · PNG caBX · GIF "C2PA_GIF" application extension · TIFF/DNG tag 0xCD41
//   ISO BMFF uuid box (MP4, MOV, M4A, HEIC, HEIF, AVIF, 3GP) · RIFF "C2PA" chunk (WebP, WAV, AVI)
//   ID3v2 GEOB frame (MP3, FLAC) · JPEG XL "jumb" box · PDF C2PA_Manifest attachment
//   ZIP META-INF/content_credential.c2pa (DOCX, XLSX, PPTX, ODT, EPUB, ZIP)
//   SVG <c2pa:manifest> · text "-----BEGIN C2PA MANIFEST-----" · raw .c2pa sidecars
// Anything else that embeds the manifest store as one contiguous JUMBF box is found by a
// generic scan. Files that only point to credentials online (XMP dcterms:provenance or a
// URL manifest reference) are reported as { remote }.

const td = new TextDecoder();
const te = new TextEncoder();
const u32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const u16 = (b, o) => (b[o] << 8) | b[o + 1];
const u32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const u16le = (b, o) => b[o] | (b[o + 1] << 8);
const ascii = (b, o, n) => String.fromCharCode(...b.subarray(o, o + n));
const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) (out.set(p, o), (o += p.length));
  return out;
};
function indexOf(b, needle, from = 0, to = b.length) {
  const n = typeof needle === "string" ? te.encode(needle) : needle;
  outer: for (let i = from; i <= to - n.length; i++) {
    if (b[i] !== n[0]) continue;
    for (let j = 1; j < n.length; j++) if (b[i + j] !== n[j]) continue outer;
    return i;
  }
  return -1;
}
const b64decode = (s) => Uint8Array.from(atob(s.replace(/[^A-Za-z0-9+/=]/g, "")), (c) => c.charCodeAt(0));
async function inflate(bytes, format) {
  const ds = new DecompressionStream(format);
  const out = new Response(new Blob([bytes]).stream().pipeThrough(ds));
  return new Uint8Array(await out.arrayBuffer());
}
const checked = (s) => (s && isC2paStore(s) ? s : null);

// --- images -------------------------------------------------------------------

function jpegStore(b) {
  if (b[0] !== 0xff || b[1] !== 0xd8) return null;
  const groups = new Map(); // JPEG XT instance -> parts
  let o = 2;
  while (o + 4 <= b.length) {
    if (b[o] !== 0xff) break;
    const marker = b[o + 1];
    if (marker === 0xd9 || marker === 0xda) break; // end of image / start of scan
    if (marker >= 0xd0 && marker <= 0xd7) {
      o += 2;
      continue;
    }
    const len = u16(b, o + 2);
    const seg = b.subarray(o + 4, o + 2 + len);
    if (marker === 0xeb && seg[0] === 0x4a && seg[1] === 0x50) {
      // APP11 JPEG XT: 'JP' | En(2) | Z(4) | LBox(4) TBox(4) [XLBox] | payload
      const en = u16(seg, 2);
      const hdr = u32(seg, 8) === 1 ? 16 : 8;
      if (!groups.has(en)) groups.set(en, { tbox: ascii(seg, 12, 4), parts: [] });
      groups.get(en).parts.push({ z: u32(seg, 4), first: seg.subarray(8), rest: seg.subarray(8 + hdr) });
    }
    o += 2 + len;
  }
  for (const { tbox, parts } of groups.values()) {
    if (tbox !== "jumb") continue;
    parts.sort((a, c) => a.z - c.z);
    const store = checked(concat([parts[0].first, ...parts.slice(1).map((p) => p.rest)]));
    if (store) return store;
  }
  return null;
}

function pngStore(b) {
  if (ascii(b, 1, 3) !== "PNG" || b[0] !== 0x89) return null;
  for (let o = 8; o + 8 <= b.length; ) {
    const len = u32(b, o);
    const type = ascii(b, o + 4, 4);
    if (type === "caBX") return checked(b.slice(o + 8, o + 8 + len));
    if (type === "IEND") break;
    o += 12 + len;
  }
  return null;
}

function gifStore(b) {
  if (ascii(b, 0, 3) !== "GIF") return null;
  let o = 13;
  if (b[10] & 0x80) o += 3 * (1 << ((b[10] & 7) + 1)); // global color table
  const subBlocks = (p) => {
    const parts = [];
    while (p < b.length && b[p] !== 0) {
      parts.push(b.subarray(p + 1, p + 1 + b[p]));
      p += 1 + b[p];
    }
    return { data: concat(parts), next: p + 1 };
  };
  while (o < b.length) {
    const intro = b[o];
    if (intro === 0x3b) break; // trailer
    if (intro === 0x21) {
      const label = b[o + 1];
      if (label === 0xff && b[o + 2] === 11 && ascii(b, o + 3, 8) === "C2PA_GIF") {
        const { data } = subBlocks(o + 14);
        return checked(data);
      }
      o = subBlocks(o + 2).next;
    } else if (intro === 0x2c) {
      let p = o + 10;
      if (b[o + 9] & 0x80) p += 3 * (1 << ((b[o + 9] & 7) + 1)); // local color table
      o = subBlocks(p + 1).next; // skip LZW minimum code size
    } else break;
  }
  return null;
}

function tiffStore(b) {
  const le = ascii(b, 0, 2) === "II";
  if (!le && ascii(b, 0, 2) !== "MM") return null;
  const r16 = le ? u16le : u16;
  const r32 = le ? u32le : u32;
  if (r16(b, 2) !== 42) return null; // BigTIFF falls through to the generic scan
  let ifd = r32(b, 4);
  for (let guard = 0; ifd && ifd + 2 <= b.length && guard < 64; guard++) {
    const n = r16(b, ifd);
    for (let i = 0; i < n; i++) {
      const e = ifd + 2 + i * 12;
      if (r16(b, e) === 0xcd41) {
        const count = r32(b, e + 4);
        const at = count <= 4 ? e + 8 : r32(b, e + 8);
        return checked(b.slice(at, at + count));
      }
    }
    ifd = r32(b, ifd + 2 + n * 12);
  }
  return null;
}

function riffStore(b) {
  if (ascii(b, 0, 4) !== "RIFF") return null;
  for (let o = 12; o + 8 <= b.length; ) {
    const id = ascii(b, o, 4);
    const len = u32le(b, o + 4);
    if (id === "C2PA") return checked(b.slice(o + 8, o + 8 + len));
    o += 8 + len + (len & 1);
  }
  return null;
}

// --- ISO BMFF (MP4, MOV, HEIC, AVIF ...) ----------------------------------------

const C2PA_UUID = [0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81];

/** Store bytes from the payload of a C2PA uuid box (after the 16-byte uuid), or null. */
function bmffPayload(p) {
  if (p.length < 6) return null;
  const end = p.indexOf(0, 4);
  if (end < 0) return null;
  const purpose = td.decode(p.subarray(4, end));
  if (purpose !== "manifest") return null;
  return checked(p.slice(end + 1 + 8)); // skip the 8-byte merkle offset
}

function isBmff(b) {
  return ["ftyp", "moov", "mdat", "free", "wide", "skip", "uuid", "styp"].includes(ascii(b, 4, 4));
}

function bmffStore(b) {
  if (!isBmff(b)) return null;
  for (let o = 0; o + 8 <= b.length; ) {
    let len = u32(b, o);
    const type = ascii(b, o + 4, 4);
    let hdr = 8;
    if (len === 1) {
      len = Number((BigInt(u32(b, o + 8)) << 32n) | BigInt(u32(b, o + 12)));
      hdr = 16;
    } else if (len === 0) len = b.length - o;
    if (len < hdr) break;
    if (type === "uuid" && C2PA_UUID.every((v, i) => b[o + hdr + i] === v)) {
      const s = bmffPayload(b.subarray(o + hdr + 16, o + len));
      if (s) return s;
    }
    o += len;
  }
  return null;
}

// --- documents and archives -------------------------------------------------------

async function zipStore(b) {
  if (u32le(b, 0) !== 0x04034b50) return null;
  const name = "META-INF/content_credential.c2pa";
  // central directory
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (u32le(b, i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) return null;
  let p = u32le(b, eocd + 16);
  const total = u16le(b, eocd + 10);
  for (let i = 0; i < total && u32le(b, p) === 0x02014b50; i++) {
    const method = u16le(b, p + 10);
    const csize = u32le(b, p + 20);
    const nlen = u16le(b, p + 28);
    const elen = u16le(b, p + 30);
    const clen = u16le(b, p + 32);
    const local = u32le(b, p + 42);
    if (td.decode(b.subarray(p + 46, p + 46 + nlen)) === name) {
      const start = local + 30 + u16le(b, local + 26) + u16le(b, local + 28);
      const data = b.subarray(start, start + csize);
      if (method === 0) return checked(data.slice());
      if (method === 8) return checked(await inflate(data, "deflate-raw"));
      return null;
    }
    p += 46 + nlen + elen + clen;
  }
  return null;
}

/** Byte offset of "N G obj" as a whole token (not inside "11 0 obj"). */
function findPdfObject(b, num, gen) {
  const needle = `${num} ${gen} obj`;
  for (let i = indexOf(b, needle); i >= 0; i = indexOf(b, needle, i + 1)) {
    const prev = b[i - 1];
    if (i === 0 || prev === 0x0a || prev === 0x0d || prev === 0x20 || prev === 0x09 || prev === 0x3e) return i;
  }
  return -1;
}

async function pdfStore(b) {
  if (ascii(b, 0, 5) !== "%PDF-") return null;
  const text = td.decode(b); // byte offsets stay valid only for ASCII; we search bytes below
  const spec = /\/AFRelationship\s*\/C2PA_Manifest/.exec(text);
  if (!spec) return null;
  // the Filespec dictionary around it holds /EF << /F n g R >>
  const around = text.slice(Math.max(0, spec.index - 2000), spec.index + 2000);
  const ef = /\/EF\s*<<[^>]*\/F\s+(\d+)\s+(\d+)\s+R/.exec(around);
  if (!ef) return null;
  const objAt = findPdfObject(b, ef[1], ef[2]);
  if (objAt < 0) return null;
  const dictEnd = indexOf(b, "stream", objAt);
  if (dictEnd < 0) return null;
  const dict = td.decode(b.subarray(objAt, dictEnd));
  let dataStart = dictEnd + 6;
  if (b[dataStart] === 0x0d) dataStart++;
  if (b[dataStart] === 0x0a) dataStart++;
  let length;
  const direct = /\/Length\s+(\d+)(?!\s+\d+\s+R)/.exec(dict);
  const indirect = /\/Length\s+(\d+)\s+(\d+)\s+R/.exec(dict);
  if (indirect) {
    const at = findPdfObject(b, indirect[1], indirect[2]);
    length = at >= 0 ? Number(/obj\s*(\d+)/.exec(td.decode(b.subarray(at, at + 64)))?.[1]) : NaN;
  } else if (direct) length = Number(direct[1]);
  if (!Number.isFinite(length)) length = indexOf(b, "endstream", dataStart) - dataStart;
  let data = b.slice(dataStart, dataStart + length);
  if (/\/Filter\s*\/FlateDecode/.test(dict)) data = await inflate(data, "deflate");
  return checked(data);
}

function textReferences(b) {
  // only for files that look like text (SVG, XML, HTML, source code, plain text)
  const head = b.subarray(0, 2048);
  if (head.some((x) => x === 0)) return {};
  const text = td.decode(b);
  const svg = /<c2pa:manifest[^>]*>([\s\S]*?)<\/c2pa:manifest>/.exec(text);
  if (svg) return { store: checked(b64decode(svg[1])) };
  const begin = text.indexOf("-----BEGIN C2PA MANIFEST-----");
  const end = begin >= 0 ? text.indexOf("-----END C2PA MANIFEST-----", begin) : -1;
  if (end > begin) {
    const ref = text
      .slice(begin + "-----BEGIN C2PA MANIFEST-----".length, end)
      .split(/\r?\n/)
      .map((l) => l.replace(/^\s*(#|\/\/|--|%|;|\*|\/\*|<!--)\s?/, "").replace(/\s*(\*\/|-->)\s*$/, "").trim())
      .join("")
      .trim();
    const DATA_URI = "data:application/c2pa;base64,";
    if (ref.startsWith(DATA_URI)) return { store: checked(b64decode(ref.slice(DATA_URI.length))) };
    if (/^https:\/\//.test(ref)) return { remote: ref };
  }
  return {};
}

// --- fallbacks ------------------------------------------------------------------

/** Any contiguous JUMBF box labelled "c2pa" (MP3/FLAC ID3, JPEG XL, BigTIFF, ...). */
function scanStore(b) {
  for (let i = indexOf(b, "jumb", 4); i >= 4; i = indexOf(b, "jumb", i + 1)) {
    const start = i - 4;
    const len = u32(b, start);
    if (len < 16 || start + len > b.length) continue;
    const s = checked(b.slice(start, start + len));
    if (s) return s;
  }
  return null;
}

function remoteReference(b) {
  const xmp = indexOf(b, "dcterms:provenance");
  if (xmp < 0) return null;
  const text = td.decode(b.subarray(xmp, xmp + 2048));
  const m = /dcterms:provenance\s*=\s*"([^"]+)"|<dcterms:provenance>([^<]+)</.exec(text);
  const url = m && (m[1] || m[2]).trim();
  return url && /^https:\/\//.test(url) ? url : null;
}

const FORMATS = [
  ["C2PA manifest store", (b) => (ascii(b, 4, 4) === "jumb" ? checked(b) : null)],
  ["JPEG", jpegStore],
  ["PNG", pngStore],
  ["GIF", gifStore],
  ["TIFF", tiffStore],
  ["RIFF (WebP, WAV, AVI)", riffStore],
  ["ISO BMFF (MP4, MOV, HEIC, AVIF)", bmffStore],
  ["ZIP / Office / ODF / EPUB", zipStore],
  ["PDF", pdfStore],
];

/**
 * Find Content Credentials in any file.
 * @returns {Promise<{ store?: Uint8Array, remote?: string, container: string } | null>}
 */
export async function locateManifest(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (b.length < 8) return null;
  for (const [name, find] of FORMATS) {
    const store = await find(b);
    if (store) return { store, container: name };
  }
  const t = textReferences(b);
  if (t.store) return { store: t.store, container: "Text (SVG, XML, HTML, code)" };
  const scanned = scanStore(b);
  if (scanned) return { store: scanned, container: "Embedded JUMBF" };
  const remote = t.remote || remoteReference(b);
  if (remote) return { remote, container: "Remote manifest" };
  return null;
}

/** The C2PA manifest store bytes embedded in a file, or null. */
export async function extractManifestStore(bytes) {
  return (await locateManifest(bytes))?.store || null;
}

/**
 * Large files (video) without reading everything into memory: walks ISO BMFF boxes
 * with Blob slices; other formats are read whole up to `maxWholeBytes`.
 */
export async function locateManifestInBlob(blob, { maxWholeBytes = 512 * 1024 * 1024 } = {}) {
  const read = async (o, n) => new Uint8Array(await blob.slice(o, o + n).arrayBuffer());
  const head = await read(0, 16);
  if (blob.size > maxWholeBytes || (isBmff(head) && blob.size > 32 * 1024 * 1024)) {
    if (!isBmff(head)) throw new Error("File too large to read in the browser");
    for (let o = 0; o + 8 <= blob.size; ) {
      const h = await read(o, 32);
      let len = u32(h, 0);
      let hdr = 8;
      if (len === 1) {
        len = Number((BigInt(u32(h, 8)) << 32n) | BigInt(u32(h, 12)));
        hdr = 16;
      } else if (len === 0) len = blob.size - o;
      if (len < hdr) break;
      if (ascii(h, 4, 4) === "uuid" && C2PA_UUID.every((v, i) => h[hdr + i] === v)) {
        const s = bmffPayload((await read(o, len)).subarray(hdr + 16));
        if (s) return { store: s, container: "ISO BMFF (MP4, MOV, HEIC, AVIF)" };
      }
      o += len;
    }
    return null;
  }
  return locateManifest(await read(0, blob.size));
}

// ---------------------------------------------------------------------------
// JUMBF boxes
// ---------------------------------------------------------------------------

function readBoxes(b, start = 0, end = b.length) {
  const boxes = [];
  let o = start;
  while (o + 8 <= end) {
    let len = u32(b, o);
    const type = ascii(b, o + 4, 4);
    let hdr = 8;
    if (len === 1) {
      len = Number((BigInt(u32(b, o + 8)) << 32n) | BigInt(u32(b, o + 12)));
      hdr = 16;
    } else if (len === 0) len = end - o;
    if (len < hdr || o + len > end) throw new Error("malformed JUMBF box");
    boxes.push({ type, start: o, payload: b.subarray(o + hdr, o + len) });
    o += len;
  }
  return boxes;
}

/** Parse a 'jumb' superbox into { label, children, contents }. */
function superbox(box) {
  const inner = readBoxes(box.payload);
  const desc = inner[0];
  if (!desc || desc.type !== "jumd") throw new Error("superbox without description");
  const d = desc.payload;
  const toggles = d[16];
  let label = "";
  if (toggles & 0x02) {
    const endIdx = d.indexOf(0, 17);
    label = td.decode(d.subarray(17, endIdx < 0 ? d.length : endIdx));
  }
  const rest = inner.slice(1);
  return {
    label,
    children: rest.filter((x) => x.type === "jumb").map(superbox),
    contents: rest.filter((x) => x.type !== "jumb"),
  };
}

function isC2paStore(b) {
  try {
    const [top] = readBoxes(b);
    return top?.type === "jumb" && superbox(top).label === "c2pa";
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// CBOR (enough for claims, assertions and COSE headers)
// ---------------------------------------------------------------------------

export function decodeCbor(b) {
  let o = 0;
  const len = (ai) => {
    if (ai < 24) return ai;
    if (ai === 24) return b[o++];
    if (ai === 25) return (o += 2), u16(b, o - 2);
    if (ai === 26) return (o += 4), u32(b, o - 4);
    if (ai === 27) {
      const v = (BigInt(u32(b, o)) << 32n) | BigInt(u32(b, o + 4));
      o += 8;
      return Number(v);
    }
    if (ai === 31) return -1;
    throw new Error("bad CBOR length");
  };
  const item = () => {
    const ib = b[o++];
    const mt = ib >> 5;
    const ai = ib & 31;
    if (mt === 7) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22 || ai === 23) return null;
      const dv = new DataView(b.buffer, b.byteOffset + o);
      if (ai === 25) {
        o += 2;
        const h = dv.getUint16(0);
        const e = (h >> 10) & 31, f = h & 1023, s = h >> 15 ? -1 : 1;
        return e === 0 ? s * f * 2 ** -24 : e === 31 ? (f ? NaN : s * Infinity) : s * (1 + f / 1024) * 2 ** (e - 15);
      }
      if (ai === 26) return (o += 4), dv.getFloat32(0);
      if (ai === 27) return (o += 8), dv.getFloat64(0);
      if (ai === 31) return BREAK;
      return undefined;
    }
    const n = len(ai);
    switch (mt) {
      case 0: return n;
      case 1: return -1 - n;
      case 2:
      case 3: {
        let bytes;
        if (n === -1) {
          const parts = [];
          for (let p; (p = item()) !== BREAK; ) parts.push(typeof p === "string" ? new TextEncoder().encode(p) : p);
          bytes = concat(parts);
        } else {
          bytes = b.subarray(o, o + n);
          o += n;
        }
        return mt === 2 ? bytes : td.decode(bytes);
      }
      case 4: {
        const a = [];
        if (n === -1) for (let v; (v = item()) !== BREAK; ) a.push(v);
        else for (let i = 0; i < n; i++) a.push(item());
        return a;
      }
      case 5: {
        const m = new Map();
        if (n === -1) for (let k; (k = item()) !== BREAK; ) m.set(k, item());
        else for (let i = 0; i < n; i++) m.set(item(), item());
        return m;
      }
      case 6: return { tag: n, value: item() };
    }
  };
  const BREAK = Symbol("break");
  return item();
}

const get = (m, k) => (m instanceof Map ? m.get(k) : undefined);

// ---------------------------------------------------------------------------
// X.509 (just enough to name the signer)
// ---------------------------------------------------------------------------

function der(b, o = 0) {
  const tag = b[o];
  let l = b[o + 1];
  let h = 2;
  if (l & 0x80) {
    const n = l & 0x7f;
    l = 0;
    for (let i = 0; i < n; i++) l = l * 256 + b[o + 2 + i];
    h += n;
  }
  return { tag, start: o, body: o + h, end: o + h + l };
}
function children(b, node) {
  const out = [];
  for (let o = node.body; o < node.end; ) {
    const c = der(b, o);
    out.push(c);
    o = c.end;
  }
  return out;
}
const OIDS = { "55 04 03": "CN", "55 04 0a": "O", "55 04 0b": "OU", "55 04 06": "C" };

/** { subject: { CN, O, ... }, issuer: {...}, notBefore, notAfter } from DER. */
export function describeCertificate(certDer) {
  const name = (node) => {
    const out = {};
    for (const set of children(certDer, node))
      for (const atv of children(certDer, set)) {
        const [oid, val] = children(certDer, atv);
        const key = OIDS[Array.from(certDer.subarray(oid.body, oid.end), (x) => x.toString(16).padStart(2, "0")).join(" ")];
        if (key) out[key] = td.decode(certDer.subarray(val.body, val.end));
      }
    return out;
  };
  const time = (node) => {
    const s = ascii(certDer, node.body, node.end - node.body);
    const y = node.tag === 0x17 ? (Number(s.slice(0, 2)) < 50 ? "20" : "19") + s.slice(0, 2) : s.slice(0, 4);
    const r = node.tag === 0x17 ? s.slice(2) : s.slice(4);
    return `${y}-${r.slice(0, 2)}-${r.slice(2, 4)}T${r.slice(4, 6)}:${r.slice(6, 8)}:${r.slice(8, 10)}Z`;
  };
  try {
    const tbs = children(certDer, children(certDer, der(certDer))[0]);
    const i = tbs[0].tag === 0xa0 ? 1 : 0; // optional [0] version
    const validity = children(certDer, tbs[i + 3]);
    return { issuer: name(tbs[i + 2]), subject: name(tbs[i + 4]), notBefore: time(validity[0]), notAfter: time(validity[1]) };
  } catch {
    return { issuer: {}, subject: {} };
  }
}

export function certificateToPem(certDer) {
  let s = "";
  for (const x of certDer) s += String.fromCharCode(x);
  const b64 = btoa(s).match(/.{1,64}/g).join("\n");
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

// ---------------------------------------------------------------------------
// Manifest store -> Open Provenance fields
// ---------------------------------------------------------------------------

const hex = (b) => "0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));

/**
 * Read the active manifest of a store.
 * @returns {Promise<{ urn, title, generator, signer, certificate, hasThumbnail, assertions,
 *   claimHash, signatureHash, bindingHash, signerCertHash, storeSha256, manifestCount }>}
 */
export async function readManifestStore(store) {
  const [top] = readBoxes(store);
  const root = superbox(top);
  if (root.label !== "c2pa") throw new Error("not a C2PA manifest store");
  const manifests = root.children;
  const active = manifests[manifests.length - 1];
  if (!active) throw new Error("manifest store is empty");

  const claimBox = active.children.find((c) => /^c2pa\.claim(\.v\d+)?$/.test(c.label));
  const sigBox = active.children.find((c) => c.label === "c2pa.signature");
  const assertionStore = active.children.find((c) => c.label === "c2pa.assertions");
  if (!claimBox || !sigBox) throw new Error("manifest has no claim or signature");
  const claimBytes = claimBox.contents.find((x) => x.type === "cbor")?.payload;
  const sigBytes = sigBox.contents.find((x) => x.type === "cbor")?.payload;
  if (!claimBytes || !sigBytes) throw new Error("claim or signature is not CBOR");

  const claim = decodeCbor(claimBytes);
  const info = get(claim, "claim_generator_info");
  const genInfo = Array.isArray(info) ? info[0] : info;
  const generator =
    (genInfo && [get(genInfo, "name"), get(genInfo, "version")].filter(Boolean).join(" ")) ||
    (get(claim, "claim_generator") || "").split(" ")[0] ||
    null;

  // COSE_Sign1: [protected bstr, unprotected map, payload, signature]
  let cose = decodeCbor(sigBytes);
  if (cose && cose.tag !== undefined) cose = cose.value;
  const prot = cose[0]?.length ? decodeCbor(cose[0]) : new Map();
  const x5 = get(prot, 33) ?? get(cose[1], 33) ?? get(cose[1], "x5chain");
  const leaf = Array.isArray(x5) ? x5[0] : x5 instanceof Uint8Array ? x5 : null;

  const assertions = (assertionStore?.children || []).map((a) => a.label);
  const bindingBox = assertionStore?.children.find((a) => /^c2pa\.hash\.(data|bmff|boxes|collection)/.test(a.label));
  let bindingHash = null;
  if (bindingBox) {
    const content = bindingBox.contents.find((x) => x.type === "cbor")?.payload;
    const h = content ? get(decodeCbor(content), "hash") : null;
    bindingHash = hex(h instanceof Uint8Array && h.length === 32 ? h : await sha256(h instanceof Uint8Array ? h : content));
  }

  const cert = leaf ? describeCertificate(leaf) : null;
  return {
    urn: active.label,
    title: get(claim, "dc:title") || null,
    generator,
    signer: cert ? cert.subject.O || cert.subject.CN || null : null,
    certificate: cert,
    certificatePem: leaf ? certificateToPem(leaf) : null,
    hasThumbnail: assertions.some((l) => l.startsWith("c2pa.thumbnail")),
    assertions,
    manifestCount: manifests.length,
    claimHash: hex(await sha256(claimBytes)),
    signatureHash: hex(await sha256(sigBytes)),
    bindingHash,
    signerCertHash: leaf ? hex(await sha256(leaf)) : null,
    storeSha256: hex(await sha256(store)),
  };
}

/** One call for a whole file: { store, manifest, container }, { remote, container } or null. */
export async function readFile(bytes) {
  return fromLocated(await locateManifest(bytes));
}

/** Same as readFile, for a File/Blob (reads large videos in pieces). */
export async function readBlob(blob) {
  return fromLocated(await locateManifestInBlob(blob));
}

async function fromLocated(found) {
  if (!found) return null;
  if (!found.store) return { remote: found.remote, container: found.container };
  return { store: found.store, container: found.container, manifest: await readManifestStore(found.store) };
}
