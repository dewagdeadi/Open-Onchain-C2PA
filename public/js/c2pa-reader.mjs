// Minimal, dependency-free C2PA reader for the browser (and Node, Workers).
// Finds the manifest store in a file and pulls out what Open Provenance needs:
// the store bytes, the active manifest's label, claim and signature hashes, the
// hard-binding hash, the signer certificate and a few human-readable details.
// It does NOT validate signatures: run a full C2PA validator for that.
//
// Supported containers: JPEG (APP11), PNG (caBX), raw .c2pa / JUMBF files.

const td = new TextDecoder();
const u32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const u16 = (b, o) => (b[o] << 8) | b[o + 1];
const ascii = (b, o, n) => String.fromCharCode(...b.subarray(o, o + n));
const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) (out.set(p, o), (o += p.length));
  return out;
};

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

function jpegStore(b) {
  if (b[0] !== 0xff || b[1] !== 0xd8) return null;
  const groups = new Map(); // instance -> [{ seq, bytes }]
  let o = 2;
  while (o + 4 <= b.length) {
    if (b[o] !== 0xff) break;
    const marker = b[o + 1];
    if (marker === 0xd9 || marker === 0xda) break; // EOI / start of scan
    if (marker >= 0xd0 && marker <= 0xd7) {
      o += 2;
      continue;
    }
    const len = u16(b, o + 2);
    const seg = b.subarray(o + 4, o + 2 + len);
    if (marker === 0xeb && seg[0] === 0x4a && seg[1] === 0x50) {
      // APP11 JPEG XT: 'JP' | En(2) | Z(4) | LBox(4) TBox(4) [XLBox] | payload
      const en = u16(seg, 2);
      const z = u32(seg, 4);
      const lbox = u32(seg, 8);
      const tbox = ascii(seg, 12, 4);
      const hdr = lbox === 1 ? 16 : 8;
      if (!groups.has(en)) groups.set(en, { tbox, parts: [] });
      groups.get(en).parts.push({ z, first: seg.subarray(8), rest: seg.subarray(8 + hdr) });
    }
    o += 2 + len;
  }
  for (const { tbox, parts } of groups.values()) {
    if (tbox !== "jumb") continue;
    parts.sort((a, c) => a.z - c.z);
    const store = concat([parts[0].first, ...parts.slice(1).map((p) => p.rest)]);
    if (isC2paStore(store)) return store;
  }
  return null;
}

function pngStore(b) {
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (!sig.every((v, i) => b[i] === v)) return null;
  let o = 8;
  while (o + 8 <= b.length) {
    const len = u32(b, o);
    const type = ascii(b, o + 4, 4);
    if (type === "caBX") return b.slice(o + 8, o + 8 + len);
    if (type === "IEND") break;
    o += 12 + len;
  }
  return null;
}

function rawStore(b) {
  return b.length > 8 && ascii(b, 4, 4) === "jumb" && isC2paStore(b) ? b : null;
}

/** The C2PA manifest store bytes embedded in a file, or null. */
export function extractManifestStore(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return rawStore(b) || jpegStore(b) || pngStore(b);
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

/** One call for a whole file: { store, manifest } or null when it has no credentials. */
export async function readFile(bytes) {
  const store = extractManifestStore(bytes);
  if (!store) return null;
  return { store, manifest: await readManifestStore(store) };
}
