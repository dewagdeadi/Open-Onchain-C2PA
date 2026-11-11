// Isomorphic: record tags and Arweave gateway reads (Workers, browsers, Node).
const PROTOCOL = "openprovenance/1";
const APP_NAME = "OpenProvenance";
const APP_VERSION = "2";

const Type = Object.freeze({
  STORE: "manifest-store", // a full C2PA manifest store (public mode)
  ROOT: "anchor-root", // Merkle root of hash-only anchors (private mode)
  TREE: "anchor-tree", // optional: the full tree behind a root
  STATEMENT: "statement", // signed signer / manifest status statement
});

const base = (type, contentType) => [
  { name: "App-Name", value: APP_NAME },
  { name: "App-Version", value: APP_VERSION },
  { name: "Type", value: type },
  { name: "Content-Type", value: contentType },
];

function storeTags({ urn, anchor, storeSha256, softBindingKeys = [] }) {
  return [
    ...base(Type.STORE, "application/c2pa"),
    { name: "C2PA-Manifest-URN", value: urn },
    { name: "C2PA-Manifest-Id", value: anchor.manifestId },
    { name: "C2PA-Claim-Hash", value: anchor.claimHash },
    { name: "C2PA-Signature-Hash", value: anchor.signatureHash },
    { name: "C2PA-Binding-Hash", value: anchor.bindingHash },
    { name: "C2PA-Signer-Cert-Hash", value: anchor.signerCertHash },
    { name: "Store-SHA256", value: storeSha256 },
    ...anchor.parents.map((p) => ({ name: "C2PA-Parent", value: p })),
    ...softBindingKeys.map((k) => ({ name: "Soft-Binding-Key", value: k })),
  ];
}

const rootTags = ({ root, count }) => [
  ...base(Type.ROOT, "application/json"),
  { name: "Merkle-Root", value: root },
  { name: "Count", value: String(count) },
];

const treeTags = ({ root }) => [...base(Type.TREE, "application/json"), { name: "Merkle-Root", value: root }];

const statementTags = ({ kind, keyId, subject }) => [
  ...base(Type.STATEMENT, "application/json"),
  { name: "Statement-Type", value: kind },
  { name: "Signer-Key-Id", value: keyId },
  ...(subject ? [{ name: "Subject", value: subject }] : []),
];

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

const QUERY = `query($ids: [ID!], $tags: [TagFilter!], $owners: [String!], $first: Int, $after: String) {
  transactions(ids: $ids, tags: $tags, owners: $owners, first: $first, after: $after, sort: HEIGHT_ASC) {
    pageInfo { hasNextPage }
    edges { cursor node { id owner { address } tags { name value } block { height timestamp } } }
  }
}`;

/**
 * Gateway client. Read from two independent gateways in production and compare;
 * one gateway alone is a single point of trust.
 */
function createGateway({ url = process.env.ARWEAVE_GATEWAY_URL || "https://arweave.net", fetch: f = (...a) => fetch(...a) } = {}) {
  async function query(vars, limit = 500) {
    const out = [];
    let after = null;
    do {
      const res = await f(`${url}/graphql`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: QUERY, variables: { ...vars, first: 100, after } }),
      });
      if (!res.ok) throw new Error(`Arweave GraphQL ${res.status}`);
      const { data } = await res.json();
      const page = data.transactions;
      for (const { cursor, node } of page.edges) {
        out.push({
          id: node.id,
          owner: node.owner.address,
          block: node.block, // null while pending: readable, but not yet a timestamp proof
          tags: Object.fromEntries(node.tags.map((t) => [t.name, t.value])),
          tagList: node.tags,
        });
        after = cursor;
      }
      if (!page.pageInfo.hasNextPage) break;
    } while (out.length < limit);
    return out;
  }

  const appTags = (type, extra = []) => [
    { name: "App-Name", values: [APP_NAME] },
    ...(type ? [{ name: "Type", values: [type] }] : []),
    ...extra,
  ];

  return {
    url,
    byIds: (ids) => query({ ids }),
    byTag: (type, name, value, owners) => query({ tags: appTags(type, [{ name, values: [value] }]), owners }),
    async data(id) {
      const res = await f(`${url}/${id}`);
      if (!res.ok) throw new Error(`Gateway ${res.status} for ${id}`);
      return new Uint8Array(await res.arrayBuffer());
    },
  };
}

module.exports = { PROTOCOL, APP_NAME, APP_VERSION, Type, storeTags, rootTags, treeTags, statementTags, createGateway };
