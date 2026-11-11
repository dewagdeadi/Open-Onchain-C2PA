import pages from "../../lib/pages.js";

export async function onRequestGet({ env }) {
  const pub = pages.publisherFrom(env);
  return pages.json({
    protocol: pages.op.PROTOCOL,
    gateways: pages.gatewaysFrom(env).map((g) => g.url),
    publishing: Boolean(pub && env.PUBLISH_TOKEN),
    publisher: pub ? await pages.arweaveAddress(pub.jwk) : null,
    uploadMode: pub ? pub.mode : null,
    maxStoreBytes: pub ? Number(env.MAX_STORE_BYTES || (pub.mode === "direct" ? 10485760 : 102400)) : null,
  });
}
