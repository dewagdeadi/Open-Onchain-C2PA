// Isomorphic Merkle batches (OpenZeppelin StandardMerkleTree).
const { StandardMerkleTree } = require("@openzeppelin/merkle-tree");
const { verifyProofWeb } = require("./web");

const LEAF_TYPES = ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "string", "bytes32[]"];

/** Anchor fields in fixed order. storeUri may be "" when the store stays private. */
const anchorValues = (a) => [
  a.manifestId,
  a.claimHash,
  a.signatureHash,
  a.bindingHash,
  a.signerCertHash,
  a.storeUri || "",
  a.parents || [],
];

function buildBatch(anchors) {
  const tree = StandardMerkleTree.of(anchors.map(anchorValues), LEAF_TYPES);
  return {
    root: tree.root,
    leafFor: (a) => tree.leafHash(anchorValues(a)),
    proofFor: (a) => tree.getProof(anchorValues(a)),
    dump: () => tree.dump(),
  };
}

const leafHash = (a) => StandardMerkleTree.of([anchorValues(a)], LEAF_TYPES).leafHash(anchorValues(a));

/** Sorted-pair keccak Merkle proof check (OpenZeppelin MerkleProof). */
const verifyProof = verifyProofWeb;

module.exports = { LEAF_TYPES, anchorValues, buildBatch, leafHash, verifyProof };
