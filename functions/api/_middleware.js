// JSON errors and CORS for the read-only endpoints. Publishing is not CORS-enabled.
import pages from "../../lib/pages.js";

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type",
};

export async function onRequest(context) {
  const { pathname } = new URL(context.request.url);
  const publicApi = !pathname.startsWith("/api/publish");
  if (context.request.method === "OPTIONS") return new Response(null, { status: 204, headers: publicApi ? CORS : {} });
  let res;
  try {
    res = await context.next();
  } catch (e) {
    const client = e instanceof SyntaxError || /^(bad|expected|missing|invalid)/i.test(e.message);
    res = pages.fail(client ? 400 : 502, e.message);
  }
  if (publicApi) {
    res = new Response(res.body, res);
    for (const [k, v] of Object.entries(CORS)) res.headers.set(k, v);
  }
  return res;
}
