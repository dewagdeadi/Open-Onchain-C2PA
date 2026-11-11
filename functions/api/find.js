// GET /api/find?by=urn|manifest|store|softbinding|root&value=...[&alg=...][&owners=a,b]
import pages from "../../lib/pages.js";

export async function onRequestGet({ request, env }) {
  const q = new URL(request.url).searchParams;
  const by = q.get("by");
  const value = (q.get("value") || "").trim();
  if (!value) return pages.fail(400, "missing value");
  const owners = pages.list(q.get("owners"));
  const { op } = pages;
  let type, tag, tagValue;
  if (by === "urn") [type, tag, tagValue] = [op.Type.STORE, "C2PA-Manifest-Id", await op.manifestIdWeb(value)];
  else if (by === "manifest") [type, tag, tagValue] = [op.Type.STORE, "C2PA-Manifest-Id", value];
  else if (by === "store") [type, tag, tagValue] = [op.Type.STORE, "Store-SHA256", value.toLowerCase()];
  else if (by === "softbinding") {
    const alg = q.get("alg");
    if (!alg) return pages.fail(400, "missing alg");
    [type, tag, tagValue] = [op.Type.STORE, "Soft-Binding-Key", await op.softBindingKey(alg, value)];
  } else if (by === "root") [type, tag, tagValue] = [op.Type.ROOT, "Merkle-Root", value];
  else return pages.fail(400, "by must be urn, manifest, store, softbinding or root");

  const [gateway] = pages.gatewaysFrom(env);
  const hits = await gateway.byTag(type, tag, tagValue, owners.length ? owners : undefined);
  return pages.json({
    gateway: gateway.url,
    note: "Tags are self-asserted. Verify hashes and signatures before trusting a result.",
    results: hits.map(({ tagList, ...h }) => ({ ...h, uri: `ar://${h.id}`, url: `${gateway.url}/${h.id}` })),
  });
}
