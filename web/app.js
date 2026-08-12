"use strict";
// Scryxen console front end. Pure renderer: it never scores or packs — it POSTs
// the current controls to the FastAPI engine (/api/plan et al.) and draws the
// response. All maths lives in the Python engine (epic #6: no logic in the view).

// ---------------- state ----------------
let ENV = null;                 // GET /api/environment (static: map, presets, …)
let BOARD = null;               // POST /api/plan (the whole board for the controls)
let W = { cvss: .25, epss: .30, kev: .20, importance: .25 };  // raw weights 0–1
let cap = { patching: 40, appsec: 16, change_window: 8 };
let kevSim = [];                // CVEs flipped to KEV in the sim
let editingRow = null;          // cve_id whose override form is open
let selectedAsset = null;

const TIERS = ["critical", "high", "medium", "low"];
const TIERCOL = { critical: "--crit", high: "--high", medium: "--med", low: "--low" };
const CAP_LABEL = { patching: "pv_pat", appsec: "pv_app", change_window: "pv_cw" };
const cssv = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? "" : s).replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// ---------------- api ----------------
const controls = () => ({ weights: W, capacity: cap, kev_sim: kevSim });
async function apiGet(path) { const r = await fetch(path); return r.json(); }
async function apiPost(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body == null ? controls() : body) });
  return { ok: r.ok, status: r.status, body: await r.json().catch(() => null) };
}

// ---------------- helpers ----------------
function norm(w) { const s = w.cvss + w.epss + w.kev + w.importance || 1;
  return { cvss: w.cvss / s, epss: w.epss / s, kev: w.kev / s, importance: w.importance / s }; }
const tierPill = t => `<span class="pill t-${t}"><span class="dot bg-${t}"></span>${esc(t)}</span>`;
const effortLabel = f => `${f.effort}${f.pool === "change_window" ? " slots" : "h"}`;
const num = v => (v == null ? 0 : v);

// ---------------- init ----------------
// Apply an /api/environment (or /api/upload, /api/reset) payload to the console:
// reset the controls to the environment's defaults and repaint the intake meta.
function applyEnv(env) {
  ENV = env;
  W = { ...ENV.default_weights };
  cap = { ...ENV.default_capacity };
  $("metaFindings").textContent = ENV.finding_count;
  $("metaSource").textContent = ENV.source;
  $("setupMeta").textContent = `${(ENV.asset_map.nodes || []).length} systems · ${ENV.finding_count} CVEs`;
  ["ci_pat", "ci_app", "ci_cw"].forEach((id, i) =>
    $(id).value = [cap.patching, cap.appsec, cap.change_window][i]);
  renderPresets();
  renderSliders();
  buildLegend();
}

async function init() {
  applyEnv(await apiGet("/api/environment"));
}

// ---------------- risk-engine controls ----------------
function renderPresets() {
  $("presets").innerHTML = Object.keys(ENV.presets).map((name, i) =>
    `<button data-preset="${esc(name)}"${i === 0 ? ' class="on"' : ""}>${esc(name)}</button>`).join("");
  $("presets").querySelectorAll("button").forEach(b =>
    b.addEventListener("click", () => applyPreset(b.dataset.preset, b)));
}
function renderSliders() {
  const S = [["cvss", "Severity (CVSS)"], ["epss", "Exploit prob. (EPSS)"],
    ["kev", "Known exploited (KEV)"], ["importance", "Asset importance"]];
  const n = norm(W);
  $("sliders").innerHTML = S.map(([k, lab]) =>
    `<div class="slider"><div class="row"><span class="nm">${lab}</span><span class="vv">${Math.round(n[k] * 100)}%</span></div>
     <input type="range" min="0" max="100" value="${Math.round(W[k] * 100)}" oninput="setW('${k}',this.value)"></div>`).join("");
}
function setW(k, v) {
  W[k] = +v / 100;
  $("presets").querySelectorAll("button").forEach(b => b.classList.remove("on"));
  renderSliders();
  scheduleRefresh();
}
function applyPreset(name, btn) {
  W = { ...ENV.presets[name] };
  $("presets").querySelectorAll("button").forEach(b => b.classList.remove("on"));
  btn.classList.add("on");
  renderSliders();
  refresh();
}

// ---------------- capacity / sim ----------------
function setCap(k, v) {
  cap[k] = +v;
  $(CAP_LABEL[k]).textContent = v;
  scheduleRefresh();
}
function toggleKevSim() {
  const id = $("kevSim").value;
  if (!id) return;
  const i = kevSim.indexOf(id);
  if (i >= 0) kevSim.splice(i, 1); else kevSim.push(id);
  refresh();
}

// ---------------- refresh (the hot path) ----------------
let refreshTimer = null;
function scheduleRefresh() { clearTimeout(refreshTimer); refreshTimer = setTimeout(refresh, 180); }
async function refresh() {
  const res = await apiPost("/api/plan", controls());
  BOARD = res.body;
  renderAll();
}
function renderAll() {
  renderKpis(); renderDashboard(); renderTable(); renderPlan(); renderAudit();
  populateKevSim();
  if ($("view-map").classList.contains("active")) buildMap();
  if (selectedAsset) selectAsset(selectedAsset);
}

// ---------------- KPIs + dashboard ----------------
function renderKpis() {
  const k = BOARD.kpis;
  const r = v => Math.round(v).toLocaleString();
  $("kpis").innerHTML = `
    <div class="kpi feat"><div class="kl">Optimizer buys</div><div class="kv">+${k.improvement_pct.toFixed(1)}%</div><div class="ks">more risk removed, same hours</div></div>
    <div class="kpi"><div class="kl">Risk removed</div><div class="kv">${r(k.optimized_risk)}</div><div class="ks"><b>${k.optimized_fixes} fixes</b> scheduled</div></div>
    <div class="kpi"><div class="kl">Severity-first removes</div><div class="kv" style="color:var(--ink-2)">${r(k.baseline_risk)}</div><div class="ks">${k.baseline_fixes} fixes · same budget</div></div>
    <div class="kpi"><div class="kl">Critical assets addressed</div><div class="kv">${k.critical_covered} <span style="font-size:15px;color:var(--ink-3)">of ${k.critical_total}</span></div><div class="ks">crown-jewel-adjacent</div></div>
    <div class="kpi"><div class="kl">Under active exploitation</div><div class="kv" style="color:var(--kev)">${k.kev_count}</div><div class="ks">on CISA KEV</div></div>`;
}
function renderDashboard() {
  $("topPicks").innerHTML = BOARD.top_picks.map((f, n) => `
    <button class="toppick" onclick="openFinding('${esc(f.cve_id)}')">
      <span class="rk">${n + 1}</span>
      <span class="m"><span class="cve">${esc(f.cve_id)}</span><span class="as">${esc(f.asset_name || "—")} · ${esc(f.pool || "")} · ${effortLabel(f)}</span></span>
      <span style="display:flex;align-items:center;gap:8px">${f.kev_flag ? '<span class="kev-pill">KEV</span>' : ""}${f.importance_tier ? tierPill(f.importance_tier) : ""}<span class="sc" style="color:var(--ink)">${Math.round(num(f.composite_score))}</span></span>
    </button>`).join("") || '<div style="padding:14px;color:var(--ink-3)">No fixes scheduled at this capacity.</div>';

  const cov = BOARD.coverage, pct = cov.pct || 0;
  const dash = `${(pct * 100).toFixed(0)} ${(100 - pct * 100).toFixed(0)}`;
  $("donut").innerHTML = `
    <circle cx="21" cy="21" r="15.9" fill="none" stroke="var(--panel-3)" stroke-width="5"/>
    <circle cx="21" cy="21" r="15.9" fill="none" stroke="var(--good)" stroke-width="5" stroke-dasharray="${dash}" stroke-dashoffset="25" stroke-linecap="round"/>
    <text x="21" y="23.5" text-anchor="middle" font-size="9" font-weight="700" fill="var(--ink)" font-family="${cssv("--mono")}">${(pct * 100).toFixed(0)}%</text>`;
  $("donutLgd").innerHTML = `<div class="big">${cov.covered} of ${cov.total} covered</div>
    <div class="row"><span class="dot bg-good"></span>fix scheduled</div>
    <div class="row"><span class="dot" style="background:var(--panel-3);border:1px solid var(--line-2)"></span>${cov.total - cov.covered} still exposed</div>`;

  const spread = BOARD.tier_spread, max = Math.max(1, ...Object.values(spread));
  $("tierSpread").innerHTML = TIERS.map(t => `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:9px">
      <span style="width:64px;font-size:12px;color:var(--ink-2);text-transform:capitalize">${t}</span>
      <div style="flex:1;height:8px;border-radius:5px;background:var(--panel-3);overflow:hidden"><i style="display:block;height:100%;width:${spread[t] / max * 100}%;background:var(${TIERCOL[t]})"></i></div>
      <span class="mono" style="font-size:12px;width:16px;text-align:right">${spread[t]}</span>
    </div>`).join("");
}

// ---------------- risk-engine table ----------------
function filteredRows() {
  const q = $("search").value.trim().toLowerCase();
  const ft = $("ftier").value, fk = $("fkev").checked;
  return BOARD.rank_table.filter(f =>
    (!q || String(f.cve_id).toLowerCase().includes(q)) &&
    (!ft || f.importance_tier === ft) && (!fk || f.kev_flag));
}
function renderTable() {
  const rows = filteredRows();
  const maxS = Math.max(1, ...BOARD.rank_table.map(f => num(f.final_score)));
  $("count").textContent = `${rows.length} of ${BOARD.rank_table.length} findings`;
  const n = norm(W);
  $("wsum").textContent = `weights → cvss ${Math.round(n.cvss * 100)} · epss ${Math.round(n.epss * 100)} · kev ${Math.round(n.kev * 100)} · imp ${Math.round(n.importance * 100)}`;
  const tb = $("rows"); tb.innerHTML = "";
  rows.forEach((f, rank) => {
    const sc = Math.round(num(f.final_score));
    const col = sc >= 80 ? "--crit" : sc >= 60 ? "--high" : "--med";
    const tr = document.createElement("tr");
    tr.className = "clk" + (f.is_overridden ? " ov" : "");
    tr.innerHTML = `<td class="rank">${rank + 1}</td><td class="cve">${esc(f.cve_id)}</td>
      <td class="r num">${num(f.cvss_score).toFixed(1)}</td><td class="r num">${Math.round(num(f.epss_score) * 100)}%</td>
      <td>${f.kev_flag ? '<span class="kev-pill">KEV</span>' : '<span style="color:var(--ink-3)">—</span>'}</td>
      <td><span class="mono" style="font-size:11px">${esc(f.asset_name || "—")}</span> ${f.importance_tier ? tierPill(f.importance_tier) : ""}</td>
      <td class="r"><div class="scorecell"><div class="bar"><span style="width:${sc / maxS * 100}%;background:var(${col})"></span></div>
        <span class="scoreval">${sc}${f.is_overridden ? " ✎" : ""}</span></div></td>
      <td class="r"><button class="ovbtn ${editingRow === f.cve_id ? "active" : ""}" title="Override score" onclick="event.stopPropagation();toggleOverride('${esc(f.cve_id)}')">⚖</button></td>`;
    tr.onclick = () => openFinding(f.cve_id);
    tb.appendChild(tr);
    if (editingRow === f.cve_id) tb.appendChild(overrideForm(f, sc));
  });
}
function overrideForm(f, sc) {
  const fr = document.createElement("tr"); fr.className = "formrow";
  fr.innerHTML = `<td colspan="8"><div class="ovform">
    <div class="g"><label>New score (0–100)</label><input class="score mono" id="ov_score" type="number" min="0" max="100" value="${sc}"></div>
    <div class="g"><label>Reason (required)</label><input class="reason" id="ov_reason" placeholder="e.g. compensating control in place"></div>
    <div class="g"><label>Your name</label><input class="user" id="ov_user" placeholder="analyst"></div>
    <button class="save" id="ov_save" disabled onclick="saveOverride('${esc(f.cve_id)}')">Save override</button>
    <button class="cancel" onclick="toggleOverride('${esc(f.cve_id)}')">Cancel</button>
    ${f.is_overridden ? `<button class="cancel" style="border-color:var(--crit);color:var(--crit)" onclick="clearOverride('${esc(f.cve_id)}')">Clear</button>` : ""}
  </div></td>`;
  const val = () => { $("ov_save").disabled = !($("ov_reason").value.trim() && $("ov_user").value.trim()); };
  setTimeout(() => { fr.querySelector("#ov_reason").oninput = val; fr.querySelector("#ov_user").oninput = val; }, 0);
  return fr;
}
function toggleOverride(id) { editingRow = editingRow === id ? null : id; renderTable(); }
async function saveOverride(id) {
  const score = Math.max(0, Math.min(100, +$("ov_score").value));
  const reason = $("ov_reason").value.trim(), user = $("ov_user").value.trim();
  if (!reason || !user) return;
  const res = await apiPost("/api/override", { cve_id: id, score, user, reason, ...controls() });
  if (res.ok) { BOARD = res.body; editingRow = null; renderAll(); }
}
async function clearOverride(id) {
  const res = await apiPost("/api/override/clear", { cve_id: id, score: 0, user: "—", reason: "cleared", ...controls() });
  if (res.ok) { BOARD = res.body; editingRow = null; renderAll(); }
}
function renderAudit() {
  const el = $("auditlog"), audit = BOARD.audit || [];
  if (!audit.length) { el.innerHTML = '<div class="aud-empty">No overrides yet — hit ⚖ on any row.</div>'; return; }
  el.innerHTML = audit.map(a => {
    const from = Math.round(a.from), to = Math.round(a.to);
    const ts = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : "";
    return `<div class="aud"><div class="mv"><span class="cve" style="font-size:11.5px">${esc(a.cve_id)}</span>
      <span class="f">${from}</span>→<span class="t ${to > from ? "up" : "down"}">${to}</span></div>
      <div><span class="who">${esc(a.user)}</span> · <span class="reason">${esc(a.reason)}</span><span class="ts">${esc(ts)}</span></div></div>`;
  }).join("");
}

// ---------------- plan ----------------
function planRow(f, { cls = "", strike = false } = {}) {
  const sc = Math.round(num(f.composite_score));
  return `<button class="row ${cls}" onclick="openFinding('${esc(f.cve_id)}')">
    <span class="sc" style="color:${strike ? "var(--ink-3)" : "var(--ink)"}">${sc}</span>
    <span class="mid"><span class="cve ${strike ? "strike" : ""}">${esc(f.cve_id)}</span><span class="as">${esc(f.asset_name || "—")} · ${effortLabel(f)}</span></span>
    <span class="rt">${f.kev_flag ? '<span class="kev-pill">KEV</span>' : ""}${f.importance_tier ? tierPill(f.importance_tier) : ""}</span></button>`;
}
function renderPlan() {
  const opt = BOARD.plans.optimized, base = BOARD.plans.baseline;
  $("optRows").innerHTML = opt.map(f => planRow(f, { cls: f.is_new ? "newpick" : "" })).join("");
  $("baseRows").innerHTML = base.map(f => planRow(f, { cls: f.dropped ? "dropped" : "", strike: f.dropped })).join("");
  const dropCount = base.filter(f => f.dropped).length;
  $("baseFoot").innerHTML = `Fixes <b>${base.length}</b> · removes <b>${Math.round(BOARD.kpis.baseline_risk).toLocaleString()}</b> risk. ${dropCount} of these the optimizer <b>drops</b> for higher-value work.`;
  const pu = BOARD.pool_utilization;
  $("poolbars").innerHTML = Object.keys(pu).map(k => {
    const u = pu[k].used, c = pu[k].capacity, pct = c ? Math.min(100, u / c * 100) : 0;
    const name = k.replace("_", "-").replace(/\b\w/g, m => m.toUpperCase());
    return `<div class="poolbar"><div class="row"><span>${esc(name)}</span><span class="mono">${Math.round(u)}/${Math.round(c)} ${esc(pu[k].unit)}</span></div>
      <div class="tk"><i class="${pct >= 99 ? "full" : ""}" style="width:${pct}%"></i></div></div>`;
  }).join("");
}
function populateKevSim() {
  const opts = BOARD.rank_table.filter(f => !f.kev_flag).map(f => f.cve_id);
  const sel = $("kevSim"), cur = sel.value;
  sel.innerHTML = opts.map(c => `<option ${kevSim.includes(c) ? "selected" : ""}>${esc(c)}</option>`).join("");
  if (opts.includes(cur)) sel.value = cur;
}

// ---------------- asset map (client-side layout from the engine's node/edge set) ----------------
function mapScale() {
  const nodes = ENV.asset_map.nodes, W_ = 940, H_ = 600, PAD = 60;
  const xs = nodes.map(n => n.x), ys = nodes.map(n => n.y);
  const xmin = Math.min(...xs), xmax = Math.max(...xs), ymin = Math.min(...ys), ymax = Math.max(...ys);
  const sx = v => PAD + (xmax === xmin ? .5 : (v - xmin) / (xmax - xmin)) * (W_ - PAD * 2);
  const sy = v => PAD + (ymax === ymin ? .5 : (v - ymin) / (ymax - ymin)) * (H_ - PAD * 2);
  return { sx, sy };
}
function neighboursOf(id) {
  const out = [];
  ENV.asset_map.edges.forEach(e => { if (e.source === id) out.push(e.target); else if (e.target === id) out.push(e.source); });
  return out;
}
function buildMap() {
  const svg = $("net"), nodes = ENV.asset_map.nodes, edges = ENV.asset_map.edges;
  const { sx, sy } = mapScale();
  const inPlan = new Set(BOARD ? BOARD.in_plan_assets : []);
  const byId = {}; nodes.forEach(n => byId[n.asset_id] = n);
  let s = "";
  edges.forEach(e => { const a = byId[e.source], b = byId[e.target]; if (!a || !b) return;
    s += `<path class="edge" d="M${sx(a.x)} ${sy(a.y)} L${sx(b.x)} ${sy(b.y)}"/>`; });
  nodes.forEach(n => {
    const col = n.tier_color || cssv(TIERCOL[n.tier] || "--low");
    const isS = inPlan.has(n.asset_id), r = n.crown ? 15 : 11;
    s += `<g class="node" data-id="${esc(n.asset_id)}" onclick="selectAsset('${esc(n.asset_id)}')" tabindex="0"
        onmousemove="showTip(event,'${esc(n.name)} · ${esc(n.tier)}')" onmouseleave="hideTip()">
      <circle class="ring" cx="${sx(n.x)}" cy="${sy(n.y)}" r="${r + 4}" fill="none"/>
      <circle class="core" cx="${sx(n.x)}" cy="${sy(n.y)}" r="${r}" fill="${col}" opacity=".92"/>`;
    if (n.crown) s += `<path d="M${sx(n.x) - 6} ${sy(n.y) + 1} l2.4 -4 l2.4 3.2 l2.4 -4.8 l2.4 4.8 l2.4 -3.2 l2.4 4 z" fill="#fff" opacity=".92"/>`;
    if (isS) s += `<circle cx="${sx(n.x) + r - 1}" cy="${sy(n.y) - r + 1}" r="4" fill="${cssv("--good")}" stroke="${cssv("--panel")}" stroke-width="1.5"/>`;
    s += `<text x="${sx(n.x)}" y="${sy(n.y) + r + 11}" text-anchor="middle">${esc(n.name.length > 15 ? n.name.slice(0, 14) + "…" : n.name)}</text></g>`;
  });
  svg.innerHTML = s;
}
function buildLegend() {
  const hops = { critical: "0–1", high: "2–3", medium: "4–5", low: "6+" };
  $("legend").innerHTML = TIERS.map(t => `<div class="li"><span class="dot bg-${t}"></span>${t} <span style="color:var(--ink-3)">· ${hops[t]} hops</span></div>`).join("")
    + `<div class="li"><span class="dot bg-good"></span>fix scheduled</div>`;
}
function selectAsset(id) {
  selectedAsset = id;
  const node = ENV.asset_map.nodes.find(n => n.asset_id === id);
  if (!node) return;
  const neigh = neighboursOf(id), neighSet = new Set(neigh);
  document.querySelectorAll(".node").forEach(el => {
    const nid = el.dataset.id;
    el.classList.toggle("sel", nid === id);
    el.classList.toggle("dim", nid !== id && !neighSet.has(nid));
  });
  const fs = BOARD.rank_table.filter(f => f.asset_id === id);
  const inPlan = new Set(BOARD.in_plan_assets);
  const covered = inPlan.has(id);
  const neighNames = neigh.map(nid => (ENV.asset_map.nodes.find(n => n.asset_id === nid) || {}).name).filter(Boolean);
  $("detail").innerHTML = `
    <div class="dname">${esc(node.name)} ${node.crown ? '<span style="color:var(--accent-ink)">◆</span>' : ""}</div>
    <div class="chips" style="margin-top:8px">${tierPill(node.tier)}<span class="pill" style="color:var(--ink-2);background:var(--panel-3)">${node.hop} hop${node.hop === 1 ? "" : "s"} out</span></div>
    <dl>
      <dt>Hops to crown jewel</dt><dd>${node.hop}</dd>
      <dt>Findings on system</dt><dd>${fs.length}</dd>
      <dt>Plan coverage</dt><dd style="color:${covered ? "var(--good)" : "var(--ink-3)"}">${covered ? "scheduled" : "none"}</dd>
    </dl>
    <div style="font-size:11.5px;color:var(--ink-3);margin-bottom:6px">Connected to: ${esc(neighNames.join(", ") || "—")}</div>
    <div class="fl">${fs.length ? fs.map(f => `<button class="fli" onclick="openFinding('${esc(f.cve_id)}')">
        ${f.kev_flag ? '<span class="kev-pill">KEV</span>' : ""}<span class="c">${esc(f.cve_id)}</span><span class="s" style="color:var(${Math.round(num(f.final_score)) >= 80 ? "--crit" : "--ink"})">${Math.round(num(f.final_score))}</span></button>`).join("")
      : '<div class="empty">No scored findings on this system.</div>'}</div>`;
}
function showTip(e, t) { const el = $("tip"); el.textContent = t; el.style.opacity = 1; el.style.left = (e.clientX + 12) + "px"; el.style.top = (e.clientY + 12) + "px"; }
function hideTip() { $("tip").style.opacity = 0; }

// ---------------- finding modal ----------------
async function openFinding(cve) {
  const res = await apiPost("/api/finding/" + encodeURIComponent(cve), controls());
  if (!res.ok) return;
  const f = res.body, b = f.breakdown;
  const parts = [["CVSS", b.cvss, "--crit"], ["EPSS", b.epss, "--high"], ["KEV", b.kev, "--med"], ["Importance", b.importance, "--good"]];
  const tot = b.cvss + b.epss + b.kev + b.importance || 1;
  const sc = Math.round(num(f.composite_score));
  openModal(`
    <div class="modal-h"><div><div class="mt">Why this finding ranks here</div><h3>${esc(f.cve_id)}</h3></div>
      <button class="x" onclick="closeModal()" aria-label="Close">×</button></div>
    <div class="modal-b">
      <div style="font-weight:620;font-size:14px;margin-bottom:8px">${esc(f.asset_name || "—")}</div>
      <div class="chips">${f.importance_tier ? tierPill(f.importance_tier) : ""}${f.kev_flag ? '<span class="kev-pill">KEV</span>' : ""}
        <span class="pill" style="color:var(--ink-2);background:var(--panel-3)">${esc(f.pool || "")} · ${f.effort != null ? f.effort : "—"}${f.pool === "change_window" ? " slots" : "h"}</span></div>
      <div class="drow"><span class="k">CVSS severity</span><span class="v mono">${num(f.cvss_score).toFixed(1)} / 10</span></div>
      <div class="drow"><span class="k">Exploitation likelihood (EPSS)</span><span class="v mono">${Math.round(num(f.epss_score) * 100)}%</span></div>
      <div class="drow"><span class="k">Active exploitation (KEV)</span><span class="v">${f.kev_flag ? "yes" : "not listed"}</span></div>
      <div class="decomp"><div class="lab">Composite score <b>${sc} / 100</b></div>
        <div class="track">${parts.map(([l, v, cc]) => `<i style="width:${v / tot * 100}%;background:var(${cc})" title="${l}"></i>`).join("")}</div>
        <div class="key">${parts.map(([l, v, cc]) => `<span><span class="dot" style="background:var(${cc})"></span>${l} ${Math.round(v / tot * 100)}%</span>`).join("")}</div></div>
      <div class="reason"><div class="rl">Ranked here because</div>${esc(f.reason_sentence || "").replace(/^Ranked here because /, "")}</div>
      <div class="modal-foot">
        <span class="pill" style="background:${f.scheduled ? "var(--good-wash)" : "var(--panel-3)"};color:${f.scheduled ? "var(--good)" : "var(--ink-3)"}">${f.scheduled ? "✓ scheduled in the optimized plan" : "not scheduled — capacity full"}</span>
        <button class="ghost" style="margin-left:auto" onclick="closeModal();gotoTab('map');selectAsset('${esc(f.asset_id || "")}')">View system ▸</button>
      </div>
    </div>`);
}
function openModal(html) { $("modal").innerHTML = html; $("scrim").classList.add("on"); document.body.style.overflow = "hidden"; }
function closeModal() { $("scrim").classList.remove("on"); document.body.style.overflow = ""; }
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

// ---------------- tabs / intake ----------------
function gotoTab(name) {
  document.querySelectorAll("#tabs button").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  $("view-" + name).classList.add("active");
  if (name === "map" && BOARD) buildMap();
}
async function showBoard() {
  if (sourceMode === "upload" && !uploaded) {
    flashUpload("Choose a CSV first, or switch to the sample environment.");
    return;
  }
  cap.patching = +$("ci_pat").value || 0;
  cap.appsec = +$("ci_app").value || 0;
  cap.change_window = +$("ci_cw").value || 0;
  $("cap_pat").value = cap.patching; $("pv_pat").textContent = cap.patching;
  $("cap_app").value = cap.appsec; $("pv_app").textContent = cap.appsec;
  $("cap_cw").value = cap.change_window; $("pv_cw").textContent = cap.change_window;
  $("intake").style.display = "none"; $("board").classList.add("on");
  $("editBtn").style.display = "inline-flex"; window.scrollTo(0, 0);
  await refresh();
}
function showIntake() { $("board").classList.remove("on"); $("intake").style.display = "block"; $("editBtn").style.display = "none"; window.scrollTo(0, 0); }

// ---------------- asset source / upload ----------------
let sourceMode = "sample";   // "sample" | "upload"
let uploaded = false;        // a user CSV has been validated + scanned this session

async function segPick(b, mode) {
  b.parentNode.querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", "false"));
  b.setAttribute("aria-pressed", "true");
  sourceMode = mode;
  $("dropSample").style.display = mode === "sample" ? "block" : "none";
  $("dropUpload").style.display = mode === "upload" ? "block" : "none";
  // Leaving an uploaded environment for the sample: restore it server-side.
  if (mode === "sample" && uploaded) {
    uploaded = false;
    applyEnv((await apiPost("/api/reset")).body);
  }
}

function onPickFile(e) { const f = e.target.files && e.target.files[0]; if (f) uploadAssets(f); }
function onDropFile(e) {
  e.preventDefault();
  $("dropUpload").classList.remove("over");
  const f = e.dataTransfer.files && e.dataTransfer.files[0];
  if (f) uploadAssets(f);
}

function setUploadStatus(html, cls) {
  $("uploadIdle").style.display = "none";
  const s = $("uploadStatus");
  s.style.display = "block"; s.className = "up-status" + (cls ? " " + cls : ""); s.innerHTML = html;
}
function flashUpload(msg) { setUploadStatus(esc(msg), "err"); }

async function uploadAssets(file) {
  setUploadStatus(`Scanning <b>${esc(file.name)}</b> against the cached feeds…`, "busy");
  const fd = new FormData();
  fd.append("file", file);
  let r, body;
  try {
    r = await fetch("/api/upload", { method: "POST", body: fd });
    body = await r.json().catch(() => null);
  } catch (err) { flashUpload("Upload failed — is the server running?"); return; }
  if (!r.ok) { flashUpload((body && body.detail) || "That file could not be read as an asset CSV."); return; }
  uploaded = true;
  applyEnv(body);
  setUploadStatus(
    `<b>${esc(file.name)}</b> loaded — ${ENV.finding_count} findings across ` +
    `${(ENV.asset_map.nodes || []).length} systems. Press Build.`, "ok");
}
function toggleTheme() {
  const r = document.documentElement;
  const cur = r.getAttribute("data-theme") || (matchMedia("(prefers-color-scheme:dark)").matches ? "dark" : "light");
  const next = cur === "dark" ? "light" : "dark";
  r.setAttribute("data-theme", next);
  $("themeIcon").textContent = next === "dark" ? "◐" : "◑";
  if (BOARD) renderAll();
}

$("tabs").addEventListener("click", e => { const b = e.target.closest("button"); if (b) gotoTab(b.dataset.tab); });
["search", "ftier", "fkev"].forEach(id => $(id).addEventListener("input", () => { if (BOARD) renderTable(); }));

init();
