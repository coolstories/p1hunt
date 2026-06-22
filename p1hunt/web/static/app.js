"use strict";
// P1HUNT Threat Operations Center — client. Polls /api/tail, aggregates the raw event stream
// into live state, and renders the ops panels. No framework, no build step.

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const clip = (s, n) => { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n) + "…" : s; };

const AGENT = (a) => String(a).split(".")[0].split(":")[0];  // the real agent id (child_b1, fuzzer_1, …)
const ROLE = (a) => {
  const b = String(a).split(".")[0].split(":")[0];
  if (b === "parent_a") return "lead";
  if (b.startsWith("child_b")) return b.includes("2nd") ? "2nd-opinion" : "hunter";
  if (b.startsWith("fuzzer")) return "fuzzer";
  if (b === "falsifier") return "falsifier";
  if (b === "poc_prover") return "prover";
  if (b === "debate") return "debate";
  if (b === "dedup") return "dedup";
  if (b === "scopeguard") return "guard";
  return b;
};

const S = {
  eng: null, offset: 0, feed: [], agents: {}, settings: {}, stats: {},
  tokens: { total: 0, cost: 0 }, findings: { confirmed_criticals: [], needs_human_review: [], candidates: [] },
  debate: [], dedup: [], running: false, lastRx: 0,
};
let feedRendered = 0;     // how many S.feed lines are already in the DOM (incremental append)
let panelsDirty = true;   // metrics/roster/findings re-render on a throttle, not per-event
let es = null;            // the live EventSource
const evTimes = [];       // event arrival times → live events/sec meter
let view = "unified";     // "unified" | 1 | 2 | 4 | 6  (split-screen pane count)
let panes = [];           // which agent each split pane shows
let focusFilter = null;   // when set, the UNIFIED feed shows only this agent (roster stays put)

function fmtDur(s) {
  if (s == null) return "--"; s = Math.max(0, Math.floor(s));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h ? `${h}h${String(m).padStart(2,"0")}m` : m ? `${m}m${String(sec).padStart(2,"0")}s` : `${sec}s`;
}
function fmtTok(n) { n = n || 0; return n >= 1e6 ? (n/1e6).toFixed(2)+"M" : n >= 1e3 ? (n/1e3).toFixed(1)+"K" : ""+n; }

// ---- event -> display line ------------------------------------------------
function fmtEvent(e) {
  const d = e.data || {}, k = e.kind, ag = AGENT(e.agent);
  const L = (cls, text) => ({ ts: e.ts, ag, cls, text });
  if (k === "thinking") return L("thinking", clip(d.text, 260));
  if (k === "output") return L("output", clip(d.text, 260));
  if (k === "tool_call") return L("tool", `${d.tool || ""}  ${clip(d.target, 110)}`);
  if (k === "finding_reported") return L("finding", `★ posted: ${clip(d.title,90)} [${d.severity||"?"}]`);
  if (k === "finding") return L("finding", d.event === "critical_confirmed"
      ? `★★★ CRITICAL CONFIRMED ×${d.count||1}` : `★ ${clip(d.title,90)} [${d.severity||""}]`);
  if (k === "guard_decision") return d.allow ? null : L("deny", `DENY ${d.tool||""} → ${clip(d.target,60)} :: ${clip(d.reason,60)}`);
  if (k === "reframe") return L("system", "↻ reframe: " + clip(d.reason || d.frame, 120));
  if (k === "message") {
    if (d.kind === "assign") return L("assign", `⇒ ${d.to||""}  «${clip(d.mission||d.lens,70)}»`);
    if ("verdict" in d) return L(String(d.verdict).startsWith("debate") ? "debate" : "verdict",
        `⚖ ${d.verdict}: ${clip(d.title||d.hyp,70)}`);
    const p = d.phase;
    if (p === "scoping") return L("system", "🔬 cold reconnaissance");
    if (p === "scoped") return L("system", `derived ${d.tracks||"?"} tracks · critical = ${clip(d.critical_means,80)}`);
    if (p === "round") return L("round", `──── ROUND ${d.round} (${d.lenses ?? d.depth ?? "?"} tracks) ────`);
    if (p === "round_summary") return L("system", `round ${d.round} — criticals ${d.criticals_total||0}, candidates ${d.candidates_total||0}, cpu ${d.cpu_pct ?? "?"}%`);
    if (p === "hunt") return L("system", `🔎 hunting ${d.lens||""} (pass ${d.depth||""})`);
    if (p === "map") return L("system", `🧠 mapping ${clip(d.subsystem,60)}`);
    if (p === "mapped") return L("system", `🧠 model built (${d.model_chars||0} chars)`);
    if (p === "fuzz") return L("system", `⚗ ${d.mode||""} fuzz «${clip(d.subsystem,50)}»`);
    if (p === "debate") return L("debate", `⚖ debate convened: ${clip(d.title,70)}`);
    if (p === "poc") return L("system", `🧪 PoC: ${clip(d.title,70)}`);
    if (p === "materialize") return L("system", `🧰 materialize harness: ${clip(d.title,60)}`);
    if (p === "repair") return L("system", `🔧 repair harness: ${clip(d.title,60)}`);
    if (p === "resteer") return L("system", "🧭 re-steering the team…");
    if (p === "notice") return L("round", `📨 NOTICE: ${clip(d.notice,90)}`);
    return null;
  }
  if (k === "lifecycle") {
    const ev = d.event;
    const M = { reproduction:"🧪", candidate_not_reproduced:"⚑", needs_human_review:"⚠", duplicate_dropped:"♻",
      debate_upheld:"⚖✓", debate_downgraded:"⚖↓", debate_rejected:"⚖✗", criticals_target_reached:"🎯",
      backoff:"⏸", stall_detected:"🩺", self_healed:"🩺", toolchain_missing_warning:"⛔",
      dynamic_armed:"🌐", memory_recalled:"🧬", reference_detected:"🔬", patterns_loaded:"🧬",
      build_status:"🏗", fork_ready:"⛓", cost_cap_reached:"💰", stop:"■" };
    if (ev === "settings") return null;
    if (ev === "duplicate_dropped") return L("dedup", `♻ DUPLICATE of #${d.of||"?"} dropped — ${clip(d.reason,70)}`);
    if (ev === "debate_rejected") return L("debate", `⚖✗ REJECTED: ${clip(d.title,55)} — ${clip(d.reason,55)}`);
    if (ev === "debate_downgraded") return L("debate", `⚖↓ DOWNGRADED→${d.to}: ${clip(d.title,50)}`);
    if (ev === "debate_upheld") return L("finding", `⚖✓ UPHELD CRITICAL: ${clip(d.title,60)}`);
    if (ev === "needs_human_review") return L("verdict", `⚠ NEEDS-HUMAN: ${clip(d.title,60)}`);
    if (ev === "criticals_target_reached") return L("round", `🎯 TARGET ${d.confirmed_criticals}/${d.target} — STOPPING`);
    if (ev === "reproduction") return L("system", `🧪 ${d.runner||"runner"}: ran=${d.ran} reproduced=${d.reproduced}`);
    if (M[ev]) return L("system", `${M[ev]} ${ev}: ${clip(d.reason||d.detail||d.diagnosis||"",90)}`);
    return null;
  }
  return null;
}

// ---- ingest a batch -------------------------------------------------------
function ingest(events) {
  for (const e of events) {
    const base = AGENT(e.agent);
    if (e.agent && base) {
      const a = S.agents[base] || (S.agents[base] = { role: ROLE(e.agent), last: 0, busy: false });
      a.last = e.ts || (Date.now()/1000); a.role = ROLE(e.agent);
      a.busy = e.kind === "tool_call" && (e.data?.tool === "Agent" || e.data?.tool === "Task");
    }
    if (e.kind === "usage") { S.tokens.total += e.data?.total || 0; S.tokens.cost += e.data?.cost || 0; continue; }
    if (e.kind === "lifecycle" && e.data?.event === "settings") { S.settings = e.data; continue; }
    if (e.kind === "message" && e.data?.phase === "round_summary") S.stats = e.data;
    if (e.kind === "lifecycle" && e.data?.event === "duplicate_dropped")
      S.dedup.unshift({ cls: "", t: `♻ dup of #${e.data.of||"?"} — ${clip(e.data.reason,80)}` });
    if (e.kind === "lifecycle" && (e.data?.event||"").startsWith("debate_")) {
      const ev = e.data.event;
      S.debate.unshift({ cls: ev==="debate_upheld"?"up":ev==="debate_downgraded"?"down":"rej",
        t: `${ev==="debate_upheld"?"✓ upheld":ev==="debate_downgraded"?"↓ "+e.data.to:"✗ rejected"}: ${clip(e.data.title,55)}` });
    }
    const line = fmtEvent(e);
    if (line) S.feed.push(line);
  }
  if (S.feed.length > 2000) { const rm = S.feed.length - 2000; S.feed.splice(0, rm); feedRendered = Math.max(0, feedRendered - rm); }
  if (S.debate.length > 40) S.debate.length = 40;
  if (S.dedup.length > 40) S.dedup.length = 40;
}

// ---- render ---------------------------------------------------------------
function render() {
  const f = S.findings || {};
  const crit = (f.confirmed_criticals || []).length, nh = (f.needs_human_review || []).length;
  const cand = (f.counts ? f.counts.candidates : (f.candidates||[]).length) || 0;
  $("mCrit").textContent = crit; $("mNH").textContent = nh; $("mCand").textContent = cand;
  $("mRound").textContent = S.stats.round ?? "0";
  $("mUptime").textContent = fmtDur(S.stats.elapsed_s);
  $("mCpu").textContent = S.stats.cpu_pct != null ? S.stats.cpu_pct + "%" : "--";
  $("mTok").textContent = fmtTok(S.tokens.total);
  $("mCost").textContent = "$" + (S.tokens.cost || 0).toFixed(2);
  $("critCount").textContent = crit; $("nhCount").textContent = nh;

  // threat level
  const lvl = crit >= 3 ? ["CRITICAL", 100] : crit === 2 ? ["SEVERE", 78] : crit === 1 ? ["ELEVATED", 55]
            : nh > 0 ? ["GUARDED", 32] : ["NOMINAL", 12];
  $("mThreat").textContent = lvl[0]; $("threatFill").style.width = lvl[1] + "%";
  $("mThreat").style.color = crit ? "var(--red)" : nh ? "var(--amber)" : "var(--green)";

  // roster
  const now = Date.now()/1000;
  const names = Object.keys(S.agents).sort();
  $("agentCount").textContent = names.length;
  $("roster").innerHTML = names.map(n => {
    const a = S.agents[n], age = now - a.last, st = a.busy ? "busy" : age < 90 ? "active" : "";
    const foc = (focusFilter === n || (view !== "unified" && panes.includes(n))) ? "focus" : "";
    return `<div class="agent ${st} ${foc}" data-agent="${esc(n)}" title="click to focus this agent">`
      + `<span class="light"></span><span class="aname">${esc(n)}</span>`
      + `<span class="arole">${esc(a.role)}</span><span class="aage">${a.last?fmtDur(age)+" ago":""}</span></div>`;
  }).join("") || '<div class="muted">no agents yet</div>';
  document.querySelectorAll("#roster .agent").forEach(el => el.onclick = () => focusAgent(el.dataset.agent));

  // settings
  const s = S.settings, m = s.models || {};
  if (Object.keys(s).length) {
    const row = (k, v) => `<div class="srow"><span class="sk">${esc(k)}</span><span class="sv">${esc(v)}</span></div>`;
    $("settings").innerHTML =
      row("program", s.program) + row("target class", s.target_class) + row("run mode", s.run_mode) +
      `<div class="sgroup">STOP / SCALE</div>` +
      row("stop @ criticals", s.max_criticals || "never-quit") +
      row("max rounds", s.max_rounds == null ? "unbounded" : s.max_rounds) +
      row("cost cap", s.cost_cap_usd ? "$"+s.cost_cap_usd : "none") +
      row("fuzz campaigns", s.fuzz_campaigns) + row("second opinion", s.second_opinion ? "on":"off") +
      `<div class="sgroup">GATES</div>` +
      row("dedup", s.dedup ? "on":"off") + row("debate panel", "max "+s.debate_max) + row("recon turns", s.recon_turns) +
      `<div class="sgroup">MODELS</div>` +
      Object.entries(m).map(([k,v]) => row(k, v)).join("");
  }

  // findings cards
  const card = (x, nhFlag) => `<div class="fcard ${nhFlag?'nh':''}" data-k='${esc(JSON.stringify(x))}'>`
    + `<span class="fsev">${esc(x.severity||(nhFlag?'NEEDS-HUMAN':'CRITICAL'))}</span>`
    + `<div class="ft">${esc(clip(x.title,120))}</div><div class="floc">${esc(x.location||"")}</div></div>`;
  $("confirmed").innerHTML = (f.confirmed_criticals||[]).map(x => card(x,false)).join("") || '<div class="muted">none confirmed</div>';
  $("needshuman").innerHTML = (f.needs_human_review||[]).map(x => card(x,true)).join("") || '<div class="muted">none</div>';
  document.querySelectorAll(".fcard").forEach(el => el.onclick = () => openModal(JSON.parse(el.dataset.k)));

  // debate + dedup mini logs
  $("debate").innerHTML = S.debate.map(x => `<div class="mln ${x.cls}">${esc(x.t)}</div>`).join("") || '<div class="muted">no debates yet</div>';
  $("dedup").innerHTML = S.dedup.map(x => `<div class="mln">${esc(x.t)}</div>`).join("") || '<div class="muted">no duplicates dropped</div>';
  if (view !== "unified") renderPanes();
}

// ---- view modes: unified feed | split panes -------------------------------
function topAgents(n) {
  return Object.keys(S.agents).sort((a, b) => S.agents[b].last - S.agents[a].last).slice(0, n);
}
function agentOptions(sel) {
  const names = Object.keys(S.agents).sort();
  return names.map(n => `<option value="${esc(n)}" ${n === sel ? "selected" : ""}>${esc(n)} · ${esc(S.agents[n].role)}</option>`).join("")
    || '<option value="">(no agents)</option>';
}
function buildViewModes() {
  const modes = [["unified", "UNIFIED"], [1, "1"], [2, "2"], [4, "4"], [6, "6"]];
  $("viewModes").innerHTML = modes.map(([v, lbl]) =>
    `<button data-v="${v}" class="${String(view) === String(v) ? "on" : ""}">${lbl}</button>`).join("");
  document.querySelectorAll("#viewModes button").forEach(b =>
    b.onclick = () => setView(b.dataset.v === "unified" ? "unified" : +b.dataset.v));
}
function setView(v) {
  view = v;
  focusFilter = null;  // any explicit view switch clears a single-agent focus
  if (v !== "unified") { const top = topAgents(v); panes = []; for (let i = 0; i < v; i++) panes[i] = top[i] || ""; }
  buildViewModes(); renderStage();
  setFeedTitle();
}
// Clicking a roster agent FILTERS the unified feed to that agent — the layout (roster, findings,
// debate, dedup) stays exactly where it is. The "✕ all" chip / UNIFIED button clears it.
function focusAgent(base) {
  view = "unified"; focusFilter = base; panes = [];
  buildViewModes(); renderStage(); setFeedTitle();
}
function clearFocus() {
  focusFilter = null; setFeedTitle(); renderStage();
}
function setFeedTitle() {
  const t = $("feedTitle");
  if (focusFilter) t.innerHTML = `AGENT · ${esc(focusFilter)} <span class="clrfocus" id="clrFocus">✕ all</span>`;
  else t.textContent = view === "unified" ? "LIVE INTERCEPT FEED" : `SPLIT VIEW · ${view} AGENTS`;
  const c = $("clrFocus"); if (c) c.onclick = clearFocus;
}
function renderStage() {
  const stage = $("centerStage");
  if (view === "unified") {
    stage.className = "pbody stage";
    stage.innerHTML = '<div class="feed" id="feed"></div>';
    feedRendered = 0; renderFeed(); return;
  }
  stage.className = "pbody stage grid g" + view;
  let html = "";
  for (let i = 0; i < view; i++)
    html += `<div class="agpane"><div class="agpane-h"><select class="paneSel" data-i="${i}">${agentOptions(panes[i])}</select></div><div class="agpane-b" id="pane${i}"></div></div>`;
  stage.innerHTML = html;
  stage.querySelectorAll(".paneSel").forEach(sel =>
    sel.onchange = (e) => { panes[+e.target.dataset.i] = e.target.value; renderPanes(); });
  renderPanes();
}
function renderPanes() {
  if (view === "unified") return;
  for (let i = 0; i < view; i++) {
    const box = $("pane" + i); if (!box) continue;
    const ag = panes[i];
    const near = box.scrollHeight - box.scrollTop - box.clientHeight < 90;
    const rows = S.feed.filter(l => l.ag === ag).slice(-250);
    box.innerHTML = rows.map(l => `<div class="feedline k-${l.cls}"><span class="fts">`
      + `${l.ts ? new Date(l.ts * 1000).toLocaleTimeString("en-GB") : ""}</span>`
      + `<span class="ftx">${esc(l.text)}</span></div>`).join("") || '<div class="muted">no activity yet</div>';
    if ($("autoscroll").checked && near) box.scrollTop = box.scrollHeight;
  }
}

// Incrementally append only the NEW feed lines (so it streams like a live wire, no full rebuild).
function appendFeedDelta() {
  const filt = $("feedFilter").value.toLowerCase();
  if (filt || focusFilter) { renderFeed(); return; }   // a filter/focus is active: full rebuild
  const box = $("feed");
  const near = box.scrollHeight - box.scrollTop - box.clientHeight < 90;
  const frag = document.createDocumentFragment();
  for (let i = feedRendered; i < S.feed.length; i++) {
    const l = S.feed[i], div = document.createElement("div");
    div.className = "feedline k-" + l.cls;
    const t = l.ts ? new Date(l.ts * 1000).toLocaleTimeString("en-GB") : "";
    div.innerHTML = `<span class="fts">${t}</span><span class="fag">${esc(l.ag)}</span><span class="ftx">${esc(l.text)}</span>`;
    frag.appendChild(div);
  }
  box.appendChild(frag);
  feedRendered = S.feed.length;
  while (box.children.length > 700) box.removeChild(box.firstChild);
  if ($("autoscroll").checked && near) box.scrollTop = box.scrollHeight;
}

function renderFeed() {
  const box = $("feed"); if (!box) return;  // split view active — no unified feed element
  const filt = $("feedFilter").value.toLowerCase();
  const near = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
  const rows = S.feed.filter(l => (!focusFilter || l.ag === focusFilter)
    && (!filt || (l.ag+" "+l.text).toLowerCase().includes(filt)));
  box.innerHTML = rows.map(l => {
    const t = l.ts ? new Date(l.ts*1000).toLocaleTimeString("en-GB") : "";
    return `<div class="feedline k-${l.cls}"><span class="fts">${t}</span>`
      + `<span class="fag">${esc(l.ag)}</span><span class="ftx">${esc(l.text)}</span></div>`;
  }).join("");
  feedRendered = S.feed.length;  // DOM now reflects the whole buffer
  if ($("autoscroll").checked && near) box.scrollTop = box.scrollHeight;
}

function openModal(x) {
  const kv = (k, v) => v ? `<div class="kv"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>` : "";
  $("modalBody").innerHTML = `<h2>${esc(x.title||"")}</h2>` +
    kv("LOCATION", x.location) + kv("SEVERITY", x.severity) +
    kv("ROOT CAUSE", x.root_cause) + kv("COUNTERFACTUAL (attacker gains)", x.counterfactual) +
    kv("WHY UNPROVEN", x.why_unproven) + kv("REMEDIATION", x.remediation);
  $("modal").classList.add("open");
}

// ---- networking -----------------------------------------------------------
async function loadEngagements() {
  try {
    const list = await (await fetch("/api/engagements")).json();
    const sel = $("engSelect"), cur = S.eng;
    sel.innerHTML = list.map(e => `<option value="${esc(e.id)}">${e.running?"● ":"○ "}${esc(e.program)} `
      + `[${e.confirmed}P1 · ${e.candidates}c]</option>`).join("");
    if (!cur && list.length) { S.eng = list[0].id; sel.value = S.eng; }
    else if (cur) sel.value = cur;
  } catch (_) {}
}

// LIVE stream — Server-Sent Events. Each event arrives the instant it's written; the browser
// auto-reconnects with Last-Event-ID so a dropped link resumes with no gaps.
function connect() {
  if (es) { es.close(); es = null; }
  if (!S.eng) return;
  es = new EventSource(`/api/stream?eng=${encodeURIComponent(S.eng)}&offset=${S.offset}`);
  es.onmessage = (m) => {
    let e; try { e = JSON.parse(m.data); } catch (_) { return; }
    if (m.lastEventId) { const o = parseInt(m.lastEventId); if (o) S.offset = o; }
    ingest([e]); if (view === "unified") appendFeedDelta(); panelsDirty = true;
    evTimes.push(Date.now()); S.lastRx = Date.now();
  };
  es.addEventListener("findings", (m) => { try { S.findings = JSON.parse(m.data); panelsDirty = true; } catch (_) {} });
  es.addEventListener("meta", (m) => {
    try { const d = JSON.parse(m.data); S.running = d.running; if (d.offset) S.offset = d.offset; setConn(d.running); } catch (_) {}
  });
  es.onerror = () => setConn(false);  // EventSource reconnects on its own
}

function setConn(live) {
  while (evTimes.length && evTimes[0] < Date.now() - 1000) evTimes.shift();
  const rate = evTimes.length;
  $("conn").className = "conn " + (live ? "live" : "dead");
  $("connText").textContent = (live ? "LIVE" : "IDLE") + (rate ? ` · ${rate}/s` : "");
  $("rec").style.opacity = live ? "1" : "0.25";
  $("footstat").textContent = live ? "ENGAGEMENT ACTIVE — LIVE WIRE" : "ENGAGEMENT IDLE / COMPLETE";
}

function switchEng(id) {
  S.eng = id; S.offset = 0; S.feed = []; feedRendered = 0; S.agents = {}; S.debate = []; S.dedup = [];
  S.tokens = { total: 0, cost: 0 }; S.settings = {}; S.stats = {};
  S.findings = { confirmed_criticals: [], needs_human_review: [], candidates: [] };
  renderStage(); panelsDirty = true; render(); connect();
}

// ---- boot -----------------------------------------------------------------
$("engSelect").onchange = (e) => switchEng(e.target.value);
$("feedFilter").oninput = renderFeed;   // rebuilds the feed for the filter + resyncs the append pointer
$("modalClose").onclick = () => $("modal").classList.remove("open");
$("modal").onclick = (e) => { if (e.target === $("modal")) $("modal").classList.remove("open"); };
setInterval(() => { $("clock").textContent = new Date().toLocaleTimeString("en-GB"); }, 1000);
// Throttle the heavy panels (metrics/roster/findings) to ~3 Hz while the feed streams freely.
setInterval(() => { if (panelsDirty) { panelsDirty = false; render(); } setConn(S.running); }, 320);

(async function () {
  buildViewModes();
  await loadEngagements();
  connect();
  setInterval(loadEngagements, 8000);
})();
