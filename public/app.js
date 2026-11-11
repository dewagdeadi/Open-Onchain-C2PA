// Open Provenance front end. Plain ES modules, no build step.
// Files are read on the user's device; only fingerprints go to the API.
import { readBlob } from "./js/c2pa-reader.mjs";

const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const ZERO = "0x" + "0".repeat(64);
let gatewayUrl = "https://arweave.net";
let maxStoreBytes = null;

// ---- navigation ---------------------------------------------------------------
function show() {
  const tab = (location.hash || "#check").slice(1);
  if (!document.getElementById(tab)?.classList.contains("panel")) return void (location.hash = "#check");
  for (const s of document.querySelectorAll(".panel")) s.hidden = s.id !== tab;
  for (const a of document.querySelectorAll(".tabs a")) {
    if (a.dataset.tab === tab) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
}
addEventListener("hashchange", show);
show();
fetch("/api/health")
  .then((r) => r.json())
  .then((h) => {
    gatewayUrl = h.gateways?.[0] || gatewayUrl;
    maxStoreBytes = h.maxStoreBytes;
  })
  .catch(() => {});

// ---- helpers ------------------------------------------------------------------
class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}
async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { "content-type": "application/json", ...(opts.headers || {}) } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(body.error || `HTTP ${res.status}`, res.status);
  return body;
}
function friendly(err) {
  if (err.status === 401) return "That access code didn't work. Check it with the site operator.";
  if (err.status === 402) return "The site's archive wallet doesn't have enough funds for this recording. Please contact the site operator.";
  if (err.status === 413 || /too large|limit is/.test(err.message)) return "One of the files has Content Credentials that are too large to record here.";
  if (err.status === 503) return "Recording isn't set up on this site yet.";
  if (err.status >= 500 || err instanceof TypeError) return "The public archive couldn't be reached just now. Please try again in a minute.";
  return err.message;
}
const fmtDate = (ts) => new Intl.DateTimeFormat(undefined, { dateStyle: "long", timeStyle: "short" }).format(new Date(ts * 1000));
function ago(ts) {
  const s = Math.round(Date.now() / 1000 - ts);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  for (const [unit, sec] of [["year", 31536000], ["month", 2592000], ["day", 86400], ["hour", 3600], ["minute", 60]])
    if (Math.abs(s) >= sec) return rtf.format(-Math.round(s / sec), unit);
  return "just now";
}
const recordLink = (id, label = "View the record") => `<a href="${esc(gatewayUrl)}/${esc(id)}" target="_blank" rel="noopener">${esc(label)}</a>`;
const bytesToB64 = (bytes) => {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
};
const icon = {
  good: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="11" fill="#E7F5EE"/><path d="M7 12.5l3.2 3L17 9" stroke="#146C40" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  warn: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="11" fill="#FDF1E3"/><path d="M12 7v6M12 16.5v.5" stroke="#8A3F06" stroke-width="2.2" stroke-linecap="round"/></svg>',
  bad: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="11" fill="#FBEBEB"/><path d="M8.5 8.5l7 7M15.5 8.5l-7 7" stroke="#9A2C1F" stroke-width="2.2" stroke-linecap="round"/></svg>',
  info: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="11" fill="#F0F1F4"/><path d="M12 11v6M12 7.5v.5" stroke="#374151" stroke-width="2.2" stroke-linecap="round"/></svg>',
};
const card = (cls, inner) => `<section class="card ${cls}">${inner}</section>`;
const errorBlock = (msg) => card("verdict-card v-bad", `<div class="verdict">${icon.bad}<div><h2>Something went wrong</h2><p>${esc(msg)}</p></div></div>`);
const errorCard = (msg) => `<div class="result">${errorBlock(msg)}</div>`;
function dropzone(el, input, onFiles) {
  for (const ev of ["dragenter", "dragover"]) el.addEventListener(ev, (e) => (e.preventDefault(), el.classList.add("over")));
  for (const ev of ["dragleave", "drop"]) el.addEventListener(ev, () => el.classList.remove("over"));
  el.addEventListener("drop", (e) => {
    e.preventDefault();
    if (e.dataTransfer.files.length) onFiles([...e.dataTransfer.files]);
  });
  input.addEventListener("change", () => input.files.length && onFiles([...input.files]));
}

// ---- turning result codes into plain language ---------------------------------
const linkReason = (u) =>
  /^ar:\/\//.test(u) ? recordLink(u.slice(5), "See their note") : /^https:\/\//.test(u) ? `<a href="${esc(u)}" target="_blank" rel="noopener">See their note</a>` : "";

function interpret(r) {
  const has = (c) => r.codes.find((x) => x.code === `org.openprovenance.${c}`);
  const notes = [];
  const withdrawn = has("manifest.withdrawn");
  const superseded = has("manifest.superseded");
  const revoked = has("signer.revoked");
  if (withdrawn) notes.push(["warn", `The publisher <b>withdrew</b> these Content Credentials on ${esc(fmtDate(withdrawn.at))}. Treat this version with caution.${withdrawn.reasonUri ? ` ${linkReason(withdrawn.reasonUri)}` : ""}`]);
  if (superseded) notes.push(["warn", `The publisher marked these Content Credentials as <b>replaced by a newer version</b> on ${esc(fmtDate(superseded.at))}.`]);
  if (revoked)
    notes.push(["warn", `The signer's key was <b>revoked</b> on ${esc(fmtDate(revoked.at))}${revoked.afterClaim === false ? ", before this file was signed. Be careful: the signature may not be genuine." : revoked.afterClaim ? ", after this file was signed." : "."}`]);
  if (has("gateway.disagreement")) notes.push(["warn", "Two archive servers gave different answers. The result may be incomplete; try again later."]);
  if (has("store.unavailable")) notes.push(["info", "The record exists, but its full contents couldn't be downloaded just now."]);

  const match = has("anchor.match");
  let v;
  if (has("anchor.mismatch") || has("time.inconsistent"))
    v = { tone: "bad", title: "Doesn't match the public record", text: "A record exists for these Content Credentials, but it's different from what's in your file. The credentials may have been altered, or this is a different version." };
  else if (match)
    v = {
      tone: notes.some((n) => n[0] === "warn") ? "warn" : "good",
      title: "Recorded in the public archive",
      text: `These Content Credentials were permanently recorded on <b>${esc(fmtDate(match.timestamp))}</b> (${esc(ago(match.timestamp))}). They match the record exactly, so they haven't been changed since.`,
    };
  else if (has("anchor.pending"))
    v = { tone: "info", title: "Recorded, confirmation in progress", text: "The record was just added and is being confirmed. This usually takes a few minutes, so check again shortly." };
  else
    v = { tone: "info", title: "Not in the public archive", text: `This doesn't mean the file is fake: most files are never recorded here. Its Content Credentials can still be checked with other tools, such as <a href="https://contentcredentials.org/verify" target="_blank" rel="noopener">contentcredentials.org/verify</a>.` };
  return { ...v, notes };
}

function verdictHtml(r) {
  const v = interpret(r);
  const notes = v.notes.length ? `<ul class="notes">${v.notes.map(([t, h]) => `<li>${icon[t]}<span>${h}</span></li>`).join("")}</ul>` : "";
  const link = r.anchor ? `<p class="small" style="margin-top:12px">${recordLink(r.anchor.tx)}</p>` : "";
  return card(`verdict-card v-${v.tone}`, `<div class="verdict">${icon[v.tone]}<div><h2>${esc(v.title)}</h2><p>${v.text}</p>${notes}${link}</div></div>`);
}

function techHtml(r, m) {
  const rows = [
    m && ["Content Credentials ID", `<code>${esc(m.urn)}</code>`],
    m?.container && ["Found in", esc(m.container)],
    ["Record", r.anchor ? `<code>ar://${esc(r.anchor.tx)}</code>` : "—"],
    ["Archive block", r.anchor?.block ? `${esc(r.anchor.block.height)} · ${esc(fmtDate(r.anchor.block.timestamp))}` : r.anchor ? "pending" : "—"],
    ["Recorded by", r.anchor ? `<code>${esc(r.anchor.owner)}</code>` : "—"],
    ["Result codes", r.codes.map((c) => `<code>${esc(c.code)}</code>`).join("<br>")],
    m && ["Claim fingerprint", `<code>${esc(m.claimHash)}</code>`],
    m && ["Credentials file fingerprint", `<code>${esc(m.storeSha256)}</code>`],
    m && ["Signer certificate", m.certificate ? `${esc(m.certificate.subject.CN || "")} · issued by ${esc(m.certificate.issuer.O || m.certificate.issuer.CN || "unknown")}` : "—"],
  ].filter(Boolean);
  return `<details class="tech"><summary class="small muted">Technical details</summary><div class="card" style="margin-top:8px"><div class="scroll"><table><tbody>${rows
    .map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`)
    .join("")}</tbody></table></div><details style="margin-top:12px"><summary>Raw response</summary><pre>${esc(JSON.stringify(r, null, 2))}</pre></details></div></details>`;
}

// ---- what kind of file is this? ---------------------------------------------------
const ext = (name) => (name.includes(".") ? name.split(".").pop().toUpperCase() : "");
function kindOf(file) {
  const t = file.type;
  const e = ext(file.name);
  const k = t.startsWith("image/") || ["DNG", "HEIC", "HEIF", "AVIF", "JXL", "TIF", "TIFF"].includes(e) ? "Image"
    : t.startsWith("video/") || ["MOV", "MP4", "M4V", "AVI"].includes(e) ? "Video"
    : t.startsWith("audio/") || ["MP3", "WAV", "M4A", "FLAC"].includes(e) ? "Audio"
    : e === "C2PA" ? "Content Credentials file"
    : ["PDF", "DOCX", "XLSX", "PPTX", "ODT", "ODS", "ODP", "EPUB"].includes(e) ? "Document"
    : "File";
  return e && k !== "Content Credentials file" ? `${k} (${e})` : k;
}

// ---- check a file --------------------------------------------------------------
let previewUrl = null;
function previewFor(file) {
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;
  const t = file.type;
  const label = `Preview of ${esc(file.name)}`;
  if (/^(image|video|audio)\//.test(t)) previewUrl = URL.createObjectURL(file);
  if (t.startsWith("image/") && !/tiff|heic|heif/.test(t)) return `<img class="preview" src="${previewUrl}" alt="${label}">`;
  if (t.startsWith("video/")) return `<video class="preview" src="${previewUrl}" controls muted playsinline aria-label="${label}"></video>`;
  if (t.startsWith("audio/")) return `<div class="preview audio"><span>${esc(file.name)}</span><audio src="${previewUrl}" controls aria-label="${label}"></audio></div>`;
  return `<div class="preview doc"><svg width="36" height="36" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M7 3h7l5 5v13H7z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M14 3v5h5" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg><span>${esc(ext(file.name) || "FILE")}</span></div>`;
}
async function checkFile(file) {
  const out = $("#check-out");
  const preview = previewFor(file);
  out.innerHTML = `<div class="result">${card("", `<p class="muted">Reading ${esc(file.name)}…</p>`)}</div>`;

  let parsed;
  try {
    parsed = await readBlob(file);
  } catch (e) {
    parsed = { error: e.message };
  }

  if (parsed?.remote) {
    out.innerHTML = `<div class="result">${card("", `<div class="summary">${preview}<div>
      <span class="badge good">Content Credentials stored online</span>
      <h2 style="margin-top:10px">This file points to Content Credentials kept on another website</h2>
      <p>Instead of carrying them inside, it links to <a href="${esc(parsed.remote)}" target="_blank" rel="noopener noreferrer">${esc(new URL(parsed.remote).host)}</a>. To check them against the public archive, download that file (it ends in .c2pa) and drop it here.</p>
      </div></div>`)}</div>`;
    return;
  }

  if (!parsed || parsed.error) {
    out.innerHTML = `<div class="result">${card("", `<div class="summary">${preview}<div>
      <span class="badge none">No Content Credentials</span>
      <h2 style="margin-top:10px">This file has no Content Credentials we can read</h2>
      <p>${parsed?.error ? "Its Content Credentials look damaged or use a format this page can't read yet." : "Social networks and messaging apps often remove them when a file is shared."}</p>
      <ul class="small">
        <li>Try the original file from the photographer or publisher.</li>
        <li>If the publisher added an invisible watermark, <a href="#search">search by its code</a>.</li>
        <li>Not every file type can carry them. See <a href="#about">which files work</a>.</li>
      </ul></div></div>`)}</div>`;
    return;
  }

  const m = { ...parsed.manifest, container: parsed.container };
  const facts = [
    ["Signed by", m.signer || "Unknown signer"],
    ["File type", kindOf(file)],
    ["Made with", m.generator || "Not stated"],
    m.title && ["Title", m.title],
    m.manifestCount > 1 && ["Edit history", `${m.manifestCount} signed steps`],
  ].filter(Boolean);
  const summary = card("", `<div class="summary">${preview}<div>
      <span class="badge good">Content Credentials found</span>
      <dl class="facts">${facts.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("")}</dl>
      <p class="disclaimer" style="margin-top:14px">This is what the file says about itself. Use a full C2PA tool to validate the signature.</p>
    </div></div>`);
  out.innerHTML = `<div class="result">${summary}${card("", '<p class="muted">Checking the public archive…</p>')}</div>`;

  try {
    const r = await api("/api/verify", {
      method: "POST",
      body: JSON.stringify({
        manifest: { urn: m.urn, claimHash: m.claimHash, signatureHash: m.signatureHash, bindingHash: m.bindingHash || ZERO, signerCertHash: m.signerCertHash || ZERO },
        storeSha256: m.storeSha256,
        signerCertPem: m.certificatePem || undefined,
      }),
    });
    out.innerHTML = `<div class="result">${summary}${verdictHtml(r)}<p class="disclaimer">A record shows when these Content Credentials existed and that they haven't changed. It doesn't prove that what the file shows is true.</p>${techHtml(r, m)}</div>`;
  } catch (e) {
    out.innerHTML = `<div class="result">${summary}${errorBlock(friendly(e))}</div>`;
  }
}
dropzone($("#drop"), $("#check-file"), (files) => checkFile(files[0]));

// ---- advanced check -----------------------------------------------------------
$("#verify-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const v = (n) => f.elements[n].value.trim();
  try {
    const receiptFile = $("#receipt-file").files[0];
    const r = await api("/api/verify", {
      method: "POST",
      body: JSON.stringify({
        manifest: { urn: v("urn"), claimHash: v("claimHash"), signatureHash: v("signatureHash"), bindingHash: v("bindingHash"), signerCertHash: v("signerCertHash") },
        receipt: receiptFile ? JSON.parse(await receiptFile.text()) : undefined,
        signerCertPem: v("signerCertPem") || undefined,
        trustedUploaders: v("trusted") ? v("trusted").split(",").map((s) => s.trim()) : undefined,
      }),
    });
    $("#verify-out").innerHTML = `<div class="result">${verdictHtml(r)}${techHtml(r)}</div>`;
  } catch (err) {
    $("#verify-out").innerHTML = errorCard(friendly(err));
  }
});

// ---- search -------------------------------------------------------------------
const lookupForm = $("#lookup-form");
const syncLookup = () => {
  const by = lookupForm.elements.by.value;
  $("#alg-wrap").hidden = by !== "softbinding";
  lookupForm.elements.alg.required = by === "softbinding";
  lookupForm.elements.value.placeholder = { softbinding: "e.g. 0x7c3ea91f", urn: "e.g. urn:c2pa:3fa85f64-…", root: "0x… from a receipt" }[by];
};
lookupForm.elements.by.addEventListener("change", syncLookup);
syncLookup();
lookupForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  try {
    const q = new URLSearchParams({ by: f.elements.by.value, value: f.elements.value.value.trim() });
    if (f.elements.by.value === "softbinding") q.set("alg", f.elements.alg.value.trim());
    const r = await api(`/api/find?${q}`);
    gatewayUrl = r.gateway;
    const items = r.results
      .map((h) => `<tr>
        <td><code>${esc(h.tags["C2PA-Manifest-URN"] || h.tags["Merkle-Root"] || h.id)}</code></td>
        <td>${h.block ? `${esc(fmtDate(h.block.timestamp))}<span class="muted small"> · ${esc(ago(h.block.timestamp))}</span>` : '<span class="muted">Being confirmed</span>'}</td>
        <td>${recordLink(h.id, "View")}</td></tr>`)
      .join("");
    $("#lookup-out").innerHTML = `<div class="result">${card(
      "",
      r.results.length
        ? `<h2>Found ${r.results.length} record${r.results.length === 1 ? "" : "s"}</h2>
         <p class="muted small">Anyone can add records, so treat these as leads. Get the original file and check it on the first tab to confirm.</p>
         <div class="scroll"><table><thead><tr><th>Content Credentials ID</th><th>Recorded</th><th><span class="sr">Link</span></th></tr></thead><tbody>${items}</tbody></table></div>`
        : `<h2>No records found</h2><p class="muted">Check the code and try again. Watermark codes usually come from the publisher's watermark reader.</p>`
    )}</div>`;
  } catch (err) {
    $("#lookup-out").innerHTML = errorCard(friendly(err));
  }
});

// ---- publish ------------------------------------------------------------------
const pub = { files: [] };
const pubForm = $("#publish-form");
const pubMode = () => document.querySelector("input[name=mode]:checked").value;
const tooBig = (x) => pubMode() === "public" && maxStoreBytes && x.parsed && x.parsed.store.length > maxStoreBytes;
function renderPubList() {
  const ready = pub.files.filter((x) => x.parsed && !tooBig(x));
  const btn = $("#publish-btn");
  btn.disabled = !ready.length;
  btn.textContent = ready.length ? `Record ${ready.length} file${ready.length === 1 ? "" : "s"}` : "Record files";
  $("#thumb-note").hidden = !(pubMode() === "public" && ready.some((x) => x.parsed.manifest.hasThumbnail));
  if (!pub.files.length) return void ($("#pub-list").innerHTML = "");
  $("#pub-list").innerHTML = `<div class="scroll" style="margin-top:12px"><table class="files"><thead><tr><th>File</th><th>Signed by</th><th>Status</th></tr></thead><tbody>${pub.files
    .map(
      (x) => `<tr><td>${esc(x.file.name)}</td><td>${esc(x.parsed?.manifest.signer || "—")}</td><td>${
        !x.parsed
          ? `<span class="status-no">Can't record</span><span class="muted small">${esc(x.reason)}</span>`
          : tooBig(x)
            ? `<span class="status-no">Too large for a public record</span><span class="muted small">Its credentials are ${Math.ceil(x.parsed.store.length / 1024)} KB; the limit here is ${Math.floor(maxStoreBytes / 1024)} KB. Choose "Proof only" to record it.</span>`
            : '<span class="status-ok">Ready</span>'
      }</td></tr>`
    )
    .join("")}</tbody></table></div>`;
}
dropzone($("#pub-drop"), $("#pub-files"), async (files) => {
  for (const file of files) {
    try {
      const parsed = await readBlob(file);
      if (parsed?.remote) pub.files.push({ file, reason: "Its credentials are stored online. Download the .c2pa file they link to and add that instead." });
      else pub.files.push(parsed ? { file, parsed } : { file, reason: "No Content Credentials in this file" });
    } catch {
      pub.files.push({ file, reason: "Content Credentials couldn't be read" });
    }
  }
  renderPubList();
});
for (const r of document.querySelectorAll("input[name=mode]")) r.addEventListener("change", renderPubList);

function downloadLink(receipts, label) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(receipts, null, 2)], { type: "application/json" }));
  return `<a href="${url}" download="receipts.json">${esc(label)}</a>`;
}
function publishedHtml(r, names, mode) {
  const rows = r.receipts.map((x, i) => `<tr><td>${esc(names[i] || x.manifest)}</td><td>${recordLink(x.tx, "View")}</td></tr>`).join("");
  return `<div class="result">${card(
    "verdict-card v-good",
    `<div class="verdict">${icon.good}<div>
      <h2>Recorded ${r.receipts.length} file${r.receipts.length === 1 ? "" : "s"}</h2>
      <p>The records are being confirmed in the public archive, which usually takes a few minutes. After that, anyone can check these files on the first tab.</p>
      <p style="margin-top:12px">${
        mode === "private"
          ? `<strong>${downloadLink(r.receipts, "Download your receipts")}</strong> and keep them safe: proof-only records can't be checked without them.`
          : downloadLink(r.receipts, "Download receipts (optional)")
      }</p>
      <div class="scroll" style="margin-top:12px"><table><thead><tr><th>File</th><th>Record</th></tr></thead><tbody>${rows}</tbody></table></div>
    </div></div>`
  )}</div>`;
}
pubForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#publish-btn");
  const ready = pub.files.filter((x) => x.parsed && !tooBig(x));
  const mode = pubMode();
  btn.disabled = true;
  btn.textContent = "Recording…";
  try {
    const entries = ready.map(({ parsed: { store, manifest: m } }) => ({
      urn: m.urn,
      claimHash: m.claimHash,
      signatureHash: m.signatureHash,
      bindingHash: m.bindingHash || ZERO,
      signerCertHash: m.signerCertHash || ZERO,
      ...(mode === "public" ? { storeBase64: bytesToB64(store) } : {}),
    }));
    const r = await api("/api/publish", {
      method: "POST",
      headers: { authorization: `Bearer ${pubForm.elements.token.value}` },
      body: JSON.stringify({ mode, entries }),
    });
    $("#publish-out").innerHTML = publishedHtml(r, ready.map((x) => x.file.name), mode);
    pub.files = pub.files.filter((x) => !ready.includes(x));
  } catch (err) {
    $("#publish-out").innerHTML = errorCard(friendly(err));
  } finally {
    renderPubList();
  }
});

// ---- advanced batch publish ----------------------------------------------------
$("#batch-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const batch = JSON.parse(await $("#batch-file").files[0].text());
    if (!Array.isArray(batch)) throw new Error("batch.json must be a list of entries");
    const files = new Map([...$("#store-files").files].map((x) => [x.name, x]));
    const isPublic = batch.some((x) => x.storeFile);
    const entries = await Promise.all(
      batch.map(async ({ storeFile, ...rest }) => {
        if (!storeFile) return rest;
        const f = files.get(storeFile.split("/").pop());
        if (!f) throw new Error(`Add the store file "${storeFile}"`);
        return { ...rest, storeBase64: bytesToB64(new Uint8Array(await f.arrayBuffer())) };
      })
    );
    const r = await api("/api/publish", {
      method: "POST",
      headers: { authorization: `Bearer ${pubForm.elements.token.value}` },
      body: JSON.stringify({ mode: isPublic ? "public" : "private", entries }),
    });
    $("#publish-out").innerHTML = publishedHtml(r, batch.map((x) => x.urn), isPublic ? "public" : "private");
  } catch (err) {
    $("#publish-out").innerHTML = errorCard(err.status ? friendly(err) : err.message);
  }
});
