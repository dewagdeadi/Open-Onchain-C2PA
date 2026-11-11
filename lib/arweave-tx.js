// Direct Arweave transactions (format 2) on Web Crypto: no bundler in the path.
// Builds the chunk Merkle tree (data_root + proofs), signs with RSA-PSS and posts
// to an Arweave node or gateway (/tx, then /chunk for multi-chunk data).
// Paid in AR (winston) per byte; runs in Workers, browsers and Node.
const { concat, sha256Bytes, b64uEncode, b64uDecode, toBytes } = require("./web");
const { deepHash } = require("./ans104");

const MAX_CHUNK_SIZE = 256 * 1024;
const MIN_CHUNK_SIZE = 32 * 1024;
const enc = new TextEncoder();

const hash = async (parts) => sha256Bytes(Array.isArray(parts) ? concat(...parts) : parts);

function intToBuffer(n) {
  const b = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    const byte = n % 256;
    b[i] = byte;
    n = (n - byte) / 256;
  }
  return b;
}

// --- chunking and Merkle tree, identical to arweave-js lib/merkle ------------

async function chunkData(data) {
  const chunks = [];
  let rest = data;
  let cursor = 0;
  while (rest.byteLength >= MAX_CHUNK_SIZE) {
    let size = MAX_CHUNK_SIZE;
    const next = rest.byteLength - MAX_CHUNK_SIZE;
    if (next > 0 && next < MIN_CHUNK_SIZE) size = Math.ceil(rest.byteLength / 2);
    const chunk = rest.slice(0, size);
    cursor += chunk.byteLength;
    chunks.push({ dataHash: await hash(chunk), minByteRange: cursor - chunk.byteLength, maxByteRange: cursor });
    rest = rest.slice(size);
  }
  chunks.push({ dataHash: await hash(rest), minByteRange: cursor, maxByteRange: cursor + rest.byteLength });
  return chunks;
}

async function buildLayers(nodes) {
  if (nodes.length < 2) return nodes[0];
  const next = [];
  for (let i = 0; i < nodes.length; i += 2) {
    const [l, r] = [nodes[i], nodes[i + 1]];
    next.push(
      r
        ? {
            type: "branch",
            id: await hash([await hash(l.id), await hash(r.id), await hash(intToBuffer(l.maxByteRange))]),
            byteRange: l.maxByteRange,
            maxByteRange: r.maxByteRange,
            left: l,
            right: r,
          }
        : l
    );
  }
  return buildLayers(next);
}

function proofs(node, path = new Uint8Array(0)) {
  if (node.type === "leaf") return [{ offset: node.maxByteRange - 1, proof: concat(path, node.dataHash, intToBuffer(node.maxByteRange)) }];
  const p = concat(path, node.left.id, node.right.id, intToBuffer(node.byteRange));
  return [...proofs(node.left, p), ...proofs(node.right, p)];
}

async function prepareChunks(data) {
  const chunks = await chunkData(data);
  const leaves = await Promise.all(
    chunks.map(async (c) => ({ type: "leaf", id: await hash([await hash(c.dataHash), await hash(intToBuffer(c.maxByteRange))]), ...c }))
  );
  const root = await buildLayers(leaves);
  const pr = proofs(root);
  const last = chunks[chunks.length - 1];
  if (last.maxByteRange - last.minByteRange === 0) {
    chunks.pop();
    pr.pop();
  }
  return { dataRoot: root.id, chunks, proofs: pr };
}

// --- transactions -------------------------------------------------------------

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
 * Build and sign a format-2 transaction. `reward` (winston, string) and `lastTx`
 * (anchor) come from the network; createDirectUploader fetches them.
 * Returns the JSON body for POST /tx (without data) plus chunk uploads.
 */
async function createSignedTransaction({ data, tags = [], jwk, reward, lastTx }) {
  const bytes = toBytes(data);
  if (!bytes.length) throw new Error("invalid upload: empty data");
  const prepared = await prepareChunks(bytes);
  const owner = b64uDecode(jwk.n);
  const tagPairs = tags.map((t) => [enc.encode(t.name), enc.encode(t.value)]);
  const signatureData = await deepHash([
    enc.encode("2"),
    owner,
    new Uint8Array(0), // target
    enc.encode("0"), // quantity
    enc.encode(String(reward)),
    b64uDecode(lastTx),
    tagPairs,
    enc.encode(String(bytes.length)),
    prepared.dataRoot,
  ]);
  const key = await importJwk(jwk);
  const signature = new Uint8Array(await globalThis.crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, key, signatureData));
  const id = b64uEncode(await sha256Bytes(signature));
  const tx = {
    format: 2,
    id,
    last_tx: lastTx,
    owner: jwk.n,
    tags: tagPairs.map(([n, v]) => ({ name: b64uEncode(n), value: b64uEncode(v) })),
    target: "",
    quantity: "0",
    data: "",
    data_size: String(bytes.length),
    data_root: b64uEncode(prepared.dataRoot),
    reward: String(reward),
    signature: b64uEncode(signature),
  };
  const chunks = prepared.chunks.map((c, i) => ({
    data_root: tx.data_root,
    data_size: tx.data_size,
    data_path: b64uEncode(prepared.proofs[i].proof),
    offset: String(prepared.proofs[i].offset),
    chunk: b64uEncode(bytes.slice(c.minByteRange, c.maxByteRange)),
  }));
  return { id, tx, chunks, inBody: chunks.length <= 1 ? b64uEncode(bytes) : null };
}

/**
 * Uploader with the same interface as the bundler uploaders, posting native
 * Arweave transactions. Every upload is paid in AR.
 *
 * maxRewardWinston: refuse any single upload that would cost more (safety cap).
 */
function createDirectUploader({ jwk, node = "https://arweave.net", maxRewardWinston, fetch: f = (...a) => fetch(...a) }) {
  let address = null;
  const getText = async (path) => {
    const res = await f(`${node}${path}`);
    if (!res.ok) throw new Error(`Arweave node ${res.status} for ${path}`);
    return (await res.text()).trim();
  };
  const post = async (path, body) => {
    const res = await f(`${node}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    if (!res.ok) throw new Error(`Arweave node ${res.status} on ${path}: ${(await res.text().catch(() => "")).slice(0, 200)}`);
  };

  return {
    get address() {
      return address;
    },
    async upload(data, tags) {
      address ??= b64uEncode(await sha256Bytes(b64uDecode(jwk.n)));
      const size = toBytes(data).length;
      if (!size) throw new Error("invalid upload: empty data");
      const [reward, lastTx, balance] = await Promise.all([
        getText(`/price/${size}`),
        getText("/tx_anchor"),
        getText(`/wallet/${address}/balance`),
      ]);
      if (!/^\d+$/.test(reward)) throw new Error(`bad price from node: ${reward}`);
      if (maxRewardWinston && BigInt(reward) > BigInt(maxRewardWinston))
        throw new Error(`upload of ${size} B costs ${reward} winston, above the ${maxRewardWinston} cap`);
      if (/^\d+$/.test(balance) && BigInt(balance) < BigInt(reward))
        throw new Error(`wallet ${address} holds ${balance} winston; this upload needs ${reward}`);

      const signed = await createSignedTransaction({ data, tags, jwk, reward, lastTx });
      if (signed.inBody !== null) {
        await post("/tx", { ...signed.tx, data: signed.inBody });
      } else {
        await post("/tx", signed.tx);
        for (const c of signed.chunks) await post("/chunk", c);
      }
      return { id: signed.id, winc: reward };
    },
  };
}

module.exports = { MAX_CHUNK_SIZE, prepareChunks, createSignedTransaction, createDirectUploader };
