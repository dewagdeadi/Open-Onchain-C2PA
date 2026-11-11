// Open Provenance front end. Plain ES module, no build step.
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
let gatewayUrl = "https://arweave.net";

// ---- tabs -------------------------------------------------------------------
function show() {
  const tab = (location.hash || "#verify").slice(1);
  for (const s of document.querySelectorAll(".panel")) s.hidden = s.id !== tab;
  for (const a of document.querySelectorAll(".tabs a")) {
    if (a.dataset.tab === tab) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  if (!document.getElementById(tab)) location.hash = "#verify";
}
addEventListener("hashchange", show);
show();

fetch("/api/health").then((r) => r.json()).then((h) => {
  gatewayUrl = h.gateways?.[0] || gatewayUrl;
  $("#net").textContent = `Arweave · ${h.gateways.length} gateway${h.gateways.length > 1 ? "s" : ""} · no wallet needed to verify`;
}).catch(() => {});

// ---- helpers ----------------------------------------------------------------
async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { "content-type": "application/json", ...(opts.headers || {}) } });
  const body = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}
const readJsonFile = async (input) => (input.files[0] ? JSON.parse(await input.files[0].text()) : undefined);
async function fileToBase64(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "pending");
const short = (id) => (id && id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-6)}` : id);
const arLink = (id) => `<a href="${esc(gatewayUrl)}/${esc(id)}" target="_blank" rel="noopener"><code>ar://${esc(short(id))}</code></a>`;
function busy(form, on) {
  const b = form.querySelector("button[type=submit]");
  b.disabled = on;
  b.dataset.label ??= b.textContent;
  b.textContent = on ? "Working…" : b.dataset.label;
}
const errorBox = (msg) => `<div class="result"><div class="card verdict"><div class="dot bad" aria-hidden="true">!</div><div><h2>Couldn't complete that</h2><p class="muted">${esc(msg)}</p></div></div></div>`;

// ---- verify -----------------------------------------------------------------
const TEXT = {
  "anchor.match": ["Anchored on Arweave", (c) => `Existed no later than block ${c.height} (${when(c.timestamp)}). Hashes match the record.`],
  "anchor.pending": ["Uploaded, not yet mined", () => "The record exists but isn't in a block yet, so there's no timestamp proof. Check again in a few minutes."],
  "anchor.missing": ["No Arweave record", (c) => `Nothing matching this manifest was found${c.conflicting ? ` (${c.conflicting} unrelated record(s) use the same id)` : ""}. That doesn't make it invalid.`],
  "anchor.mismatch": ["Record doesn't match", (c) => c.detail || "An Arweave record for this manifest has different hashes."],
  "time.inconsistent": ["Timestamps conflict", () => "The Arweave block is earlier than the manifest's own TSA time stamp."],
  "store.unavailable": ["Store couldn't be fetched", () => "The record exists, but its bytes couldn't be downloaded right now."],
  "signer.revoked": ["Signer key revoked", (c) => `Revoked ${when(c.at)}${c.afterClaim === true ? ", after this manifest was signed" : c.afterClaim === false ? ", before this manifest was signed" : ""}.`],
  "manifest.superseded": ["Superseded by the author", (c) => `Marked superseded ${when(c.at)}.`],
  "manifest.withdrawn": ["Withdrawn by the author", (c) => `Marked withdrawn ${when(c.at)}.`],
  "gateway.disagreement": ["Gateways disagree", () => "Two Arweave gateways returned different results. Treat this result with caution."],
  "gateway.unavailable": ["A gateway didn't answer", (c) => `Checked with the remaining gateway(s). Failed: ${(c.failed || []).join(", ")}.`],
};
const MARK = { success: "✓", warning: "!", failure: "✕", info: "i" };

function renderVerify(r) {
  const codeName = (c) => c.code.replace("org.openprovenance.", "");
  const worst = ["failure", "warning", "success", "info"].find((s) => r.codes.some((c) => c.severity === s)) || "info";
  const head = {
    failure: ["bad", "Arweave evidence conflicts with this manifest"],
    warning: ["warn", "Anchored, with warnings"],
    success: ["good", "Anchored on Arweave"],
    info: ["info", "No timestamp proof on Arweave yet"],
  }[worst];
  const items = r.codes.map((c) => {
    const [title, text] = TEXT[codeName(c)] || [codeName(c), () => ""];
    return `<li><span class="chip ${esc(c.severity)}" aria-hidden="true">${MARK[c.severity] || "i"}</span><div><b>${esc(title)}</b><div class="muted small">${esc(text(c))}</div><code class="muted">${esc(c.code)}</code></div></li>`;
  }).join("");
  const a = r.anchor;
  const anchorKv = a ? `<dl class="kv">
      <div><dt>Record</dt><dd>${arLink(a.tx)}</dd></div>
      <div><dt>Mode</dt><dd>${a.mode === "store" ? "Public (manifest store)" : "Private (hash root)"}</dd></div>
      <div><dt>Block</dt><dd>${a.block ? `${esc(a.block.height)} · ${esc(when(a.block.timestamp))}` : "pending"}</dd></div>
      <div><dt>Uploaded by</dt><dd><code>${esc(short(a.owner))}</code></dd></div>
    </dl>` : "";
  const s = r.signer;
  const signerKv = s ? `<dl class="kv">
      <div><dt>Signer key id</dt><dd><code>${esc(short(s.keyId))}</code></dd></div>
      <div><dt>Revoked</dt><dd>${s.revoked ? esc(when(s.revoked.timestamp)) : "No"}</dd></div>
      <div><dt>Active delegates</dt><dd>${Object.keys(s.delegates).length}</dd></div>
      <div><dt>Ignored statements</dt><dd>${s.ignored.length}</dd></div>
    </dl>` : "";
  return `<div class="result">
    <div class="card verdict"><div class="dot ${head[0]}" aria-hidden="true">${MARK[worst]}</div>
      <div><h2>${esc(head[1])}</h2><p class="muted small">Manifest id <code>${esc(r.manifestId)}</code>. This is extra evidence; your C2PA validation result stands on its own.</p></div></div>
    <section class="card evidence"><h3>Arweave evidence</h3><ul class="codes" style="margin-top:12px">${items}</ul>${anchorKv ? `<hr style="border:0;border-top:1px solid #EEF0F3;margin:16px 0">${anchorKv}` : ""}</section>
    ${signerKv ? `<section class="card"><h3>Signer status log</h3><div style="margin-top:12px">${signerKv}</div></section>` : ""}
    <details><summary>Per-gateway results and raw JSON</summary><pre>${esc(JSON.stringify(r, null, 2))}</pre></details>
  </div>`;
}

$("#manifest-file").addEventListener("change", async (e) => {
  try {
    const m = await readJsonFile(e.target);
    for (const k of ["urn", "claimHash", "signatureHash", "bindingHash", "signerCertHash"]) if (m?.[k]) $(`#verify-form [name=${k}]`).value = m[k];
  } catch {
    $("#verify-out").innerHTML = errorBox("That file isn't valid JSON.");
  }
});

$("#verify-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const v = (n) => f.elements[n].value.trim();
  busy(f, true);
  try {
    const body = {
      manifest: { urn: v("urn"), claimHash: v("claimHash"), signatureHash: v("signatureHash"), bindingHash: v("bindingHash"), signerCertHash: v("signerCertHash") },
      receipt: await readJsonFile($("#receipt-file")),
      storeBase64: $("#store-file").files[0] ? await fileToBase64($("#store-file").files[0]) : undefined,
      signerCertPem: v("signerCertPem") || undefined,
      tsaTime: v("tsaTime") || undefined,
      trustedUploaders: v("trusted") ? v("trusted").split(",").map((s) => s.trim()) : undefined,
    };
    $("#verify-out").innerHTML = renderVerify(await api("/api/verify", { method: "POST", body: JSON.stringify(body) }));
  } catch (err) {
    $("#verify-out").innerHTML = errorBox(err.message);
  } finally {
    busy(f, false);
  }
});

// ---- lookup -----------------------------------------------------------------
const lookupForm = $("#lookup-form");
lookupForm.elements.by.addEventListener("change", (e) => {
  $("#alg-wrap").hidden = e.target.value !== "softbinding";
  lookupForm.elements.value.placeholder = { urn: "urn:c2pa:…", manifest: "0x… manifest id", softbinding: "0x… watermark value", root: "0x… Merkle root" }[e.target.value];
});
lookupForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  busy(f, true);
  try {
    const q = new URLSearchParams({ by: f.elements.by.value, value: f.elements.value.value.trim() });
    if (f.elements.by.value === "softbinding") q.set("alg", f.elements.alg.value.trim());
    const r = await api(`/api/find?${q}`);
    gatewayUrl = r.gateway;
    const rows = r.results.map((h) => `<tr>
        <td>${arLink(h.id)}</td>
        <td>${esc(h.tags.Type)}</td>
        <td><code>${esc(h.tags["C2PA-Manifest-URN"] || h.tags["Merkle-Root"] || "")}</code></td>
        <td>${h.block ? `${esc(h.block.height)}<div class="muted small">${esc(when(h.block.timestamp))}</div>` : '<span class="chip info">pending</span>'}</td>
        <td><code>${esc(short(h.owner))}</code></td></tr>`).join("");
    $("#lookup-out").innerHTML = `<div class="result"><div class="card">
      <h2>${r.results.length} record${r.results.length === 1 ? "" : "s"}</h2>
      <p class="muted small">${esc(r.note)}</p>
      ${r.results.length ? `<div class="scroll"><table><thead><tr><th>Record</th><th>Type</th><th>Manifest / root</th><th>Block</th><th>Uploader</th></tr></thead><tbody>${rows}</tbody></table></div>` : ""}
    </div></div>`;
  } catch (err) {
    $("#lookup-out").innerHTML = errorBox(err.message);
  } finally {
    busy(f, false);
  }
});

// ---- publish ----------------------------------------------------------------
$("#publish-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  busy(f, true);
  try {
    const mode = f.elements.mode.value;
    const batch = await readJsonFile($("#batch-file"));
    if (!Array.isArray(batch)) throw new Error("batch.json must be an array of entries");
    const files = new Map([...$("#store-files").files].map((x) => [x.name, x]));
    const entries = await Promise.all(batch.map(async (entry) => {
      const { storeFile, ...rest } = entry;
      if (mode !== "public") return rest;
      const name = storeFile?.split("/").pop();
      if (!name || !files.has(name)) throw new Error(`Select the store file "${storeFile}" for ${entry.urn}`);
      return { ...rest, storeBase64: await fileToBase64(files.get(name)) };
    }));
    const r = await api("/api/publish", {
      method: "POST",
      headers: { authorization: `Bearer ${f.elements.token.value}` },
      body: JSON.stringify({ mode, entries }),
    });
    const url = URL.createObjectURL(new Blob([JSON.stringify(r.receipts, null, 2)], { type: "application/json" }));
    const rows = r.receipts.map((x) => `<tr><td><code>${esc(x.manifest)}</code></td><td>${arLink(x.tx)}</td></tr>`).join("");
    $("#publish-out").innerHTML = `<div class="result"><div class="card">
      <h2>Published ${r.receipts.length} manifest${r.receipts.length === 1 ? "" : "s"}</h2>
      <p class="muted small">${esc(r.cost.uploads)} upload(s), ${esc(r.cost.winc)} winc. Records count as timestamps once their bundle is mined, usually within minutes.</p>
      <p><a href="${url}" download="receipts.json">Download receipts.json</a></p>
      <div class="scroll"><table><thead><tr><th>Manifest</th><th>Arweave record</th></tr></thead><tbody>${rows}</tbody></table></div>
    </div></div>`;
  } catch (err) {
    $("#publish-out").innerHTML = errorBox(err.message);
  } finally {
    busy(f, false);
  }
});
