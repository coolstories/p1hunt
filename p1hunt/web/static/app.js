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
  eng: null, offset: 0, feed: [], agents: {}, settings: {}, stats: {}, models: {},
  tokens: { total: 0, cost: 0 }, findings: { confirmed_criticals: [], needs_human_review: [], candidates: [] },
  debate: [], dedup: [], running: false, lastRx: 0,
};
const rosterRows = {};    // agent name -> cached row nodes, updated in place (no flicker)
let feedRendered = 0;     // how many S.feed lines are already in the DOM (incremental append)
let panelsDirty = true;   // metrics/roster/findings re-render on a throttle, not per-event
let es = null;            // the live EventSource
const evTimes = [];       // event arrival times → live events/sec meter
let view = "unified";     // "unified" | 1 | 2 | 4 | 6  (split-screen pane count)
let panes = [];           // which agent each split pane shows
let focusFilter = null;   // when set, the UNIFIED feed shows only this agent (roster stays put)
let expandAll = false;    // global: show full (unclamped) text for every feed line

// Apply the global expand flag to the feed + every split pane (called after each render so new
// content honors it). Per-line expand (click) is independent and survives this.
function applyExpand() {
  const f = $("feed"); if (f) f.classList.toggle("expanded", expandAll);
  for (let i = 0; i < 8; i++) { const p = $("pane" + i); if (p) p.classList.toggle("expanded", expandAll); }
}

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
  if (k === "thinking") return L("thinking", clip(d.text, 4000));
  if (k === "output") return L("output", clip(d.text, 4000));
  if (k === "tool_call") return L("tool", `${d.tool || ""}  ${clip(d.target, 600)}`);
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
    if (e.kind === "lifecycle" && e.data?.event === "model_status") {
      const m = e.data.model || "?";
      S.models[m] = { engine: e.data.engine || "", state: e.data.state || "?",
                      cooldown: e.data.cooldown_s || 0, ts: e.ts || (Date.now()/1000) };
      continue;
    }
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

  // roster — update rows IN PLACE (no wholesale innerHTML rebuild) so it never flickers and the
  // click target survives between renders.
  renderRoster();

  // settings
  const s = S.settings, m = s.models || {};
  if (Object.keys(s).length) {
    const row = (k, v) => `<div class="srow"><span class="sk">${esc(k)}</span><span class="sv">${esc(v)}</span></div>`;
    const pill = (on) => `<span class="pill ${on ? "on" : "off"}">${on ? "on" : "off"}</span>`;
    const rowP = (k, on) => `<div class="srow"><span class="sk">${esc(k)}</span><span class="sv">${pill(on)}</span></div>`;
    const eng = s.discovery_engine || "claude";
    const engPill = `<span class="pill ${eng === "codex" ? "codex" : "claude"}">${esc(eng)}</span>`;
    $("settings").innerHTML =
      row("program", s.program) + row("target class", s.target_class) + row("run mode", s.run_mode) +
      `<div class="sgroup">DISCOVERY ENGINE</div>` +
      `<div class="srow"><span class="sk">engine</span><span class="sv">${engPill}</span></div>` +
      rowP("deep discovery", s.deep_discovery) + rowP("no-downgrade", s.no_model_downgrade) +
      `<div class="sgroup">STOP / SCALE</div>` +
      row("stop @ criticals", s.max_criticals || "never-quit") +
      row("max rounds", s.max_rounds == null ? "unbounded" : s.max_rounds) +
      row("cost cap", s.cost_cap_usd ? "$"+s.cost_cap_usd : "none") +
      row("fuzz campaigns", s.fuzz_campaigns) + rowP("second opinion", !!s.second_opinion) +
      `<div class="sgroup">GATES</div>` +
      rowP("dedup", s.dedup) + row("debate panel", "max "+s.debate_max) +
      rowP("deepdive", s.deepdive) +
      (s.deepdive ? row("· depth", (s.deepdive_top_n||"?")+" leads × "+(s.deepdive_turns||"?")+" turns") : "") +
      (s.recon_turns ? row("recon turns", s.recon_turns) : "") +
      `<div class="sgroup">MODELS</div>` +
      Object.entries(m).map(([k,v]) => row(k, v)).join("");
  }

  // model status (observed availability: rate-limited vs available, per engine/model)
  const mk = Object.keys(S.models);
  if (mk.length) {
    mk.sort();
    $("modelStatus").innerHTML = mk.map(name => {
      const x = S.models[name];
      const ok = x.state === "available";
      const cd = (!ok && x.cooldown) ? ` ${fmtDur(x.cooldown)}` : "";
      const label = name === "" || name === "codex-default" ? "codex (default)" : name;
      return `<div class="mrow"><span class="meng">${esc(x.engine||"")}</span>`
        + `<span class="mname" title="${esc(label)}">${esc(label)}</span>`
        + `<span class="pill ${ok ? "on" : "off"}">${ok ? "ready" : "limited"+cd}</span></div>`;
    }).join("");
    if ($("modelMeta")) $("modelMeta").textContent = mk.length;
  }

  // findings cards (variant: ''=critical | 'nh' | 'cand')
  const card = (x, variant) => {
    const sev = x.severity || (variant === "nh" ? "NEEDS-HUMAN" : variant === "cand" ? "candidate" : "CRITICAL");
    const loc = x.location || x.file || "";
    return `<div class="fcard ${variant}" data-k='${esc(JSON.stringify(x))}'>`
      + `<span class="fsev">${esc(sev)}</span>`
      + `<div class="ft">${esc(clip(x.title || x.hyp || "", 120))}</div><div class="floc">${esc(loc)}</div></div>`;
  };
  const cands = f.candidates || [];
  $("confirmed").innerHTML = (f.confirmed_criticals||[]).map(x => card(x,"")).join("") || '<div class="muted">none confirmed</div>';
  $("candidates").innerHTML = cands.map(x => card(x,"cand")).join("") || '<div class="muted">none yet</div>';
  $("needshuman").innerHTML = (f.needs_human_review||[]).map(x => card(x,"nh")).join("") || '<div class="muted">none</div>';
  $("candCount").textContent = (f.counts ? f.counts.candidates : cands.length) || 0;
  document.querySelectorAll(".fcard").forEach(el => el.onclick = () => openModal(JSON.parse(el.dataset.k)));

  // debate + dedup mini logs
  $("debate").innerHTML = S.debate.map(x => `<div class="mln ${x.cls}">${esc(x.t)}</div>`).join("") || '<div class="muted">no debates yet</div>';
  $("dedup").innerHTML = S.dedup.map(x => `<div class="mln">${esc(x.t)}</div>`).join("") || '<div class="muted">no duplicates dropped</div>';
  if (view !== "unified") renderPanes();
}

// Roster updated IN PLACE: rows are created once and only their status class / age text mutate.
// No innerHTML rebuild => no flicker, and the click target persists so selecting an agent is reliable.
function renderRoster() {
  const box = $("roster");
  const now = Date.now() / 1000;
  const names = Object.keys(S.agents).sort();
  $("agentCount").textContent = names.length;
  if (!names.length) {
    if (!box.querySelector(".muted")) box.innerHTML = '<div class="muted">no agents yet</div>';
    return;
  }
  const ph = box.querySelector(".muted"); if (ph) ph.remove();
  for (const n of names) {
    const a = S.agents[n], age = now - a.last;
    const cls = "agent " + (a.busy ? "busy" : age < 90 ? "active" : "")
      + ((focusFilter === n || (view !== "unified" && panes.includes(n))) ? " focus" : "");
    let row = rosterRows[n];
    if (!row) {
      const el = document.createElement("div");
      el.dataset.agent = n;
      el.title = "click to focus this agent's transcript";
      el.innerHTML = `<span class="light"></span><span class="aname">${esc(n)}</span>`
        + `<span class="arole"></span><span class="aage"></span>`;
      el.onclick = () => focusAgent(n);
      box.appendChild(el);
      row = rosterRows[n] = { el, age: el.querySelector(".aage"), role: el.querySelector(".arole") };
    }
    if (row.el.className !== cls) row.el.className = cls;        // only mutate what changed
    if (row.role.textContent !== a.role) row.role.textContent = a.role;
    const ageTxt = a.last ? fmtDur(age) + " ago" : "";
    if (row.age.textContent !== ageTxt) row.age.textContent = ageTxt;
  }
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
    feedRendered = 0; renderFeed(); applyExpand(); return;
  }
  stage.className = "pbody stage grid g" + view;
  let html = "";
  for (let i = 0; i < view; i++)
    html += `<div class="agpane"><div class="agpane-h"><select class="paneSel" data-i="${i}">${agentOptions(panes[i])}</select></div><div class="agpane-b" id="pane${i}"></div></div>`;
  stage.innerHTML = html;
  stage.querySelectorAll(".paneSel").forEach(sel =>
    sel.onchange = (e) => { panes[+e.target.dataset.i] = e.target.value; renderPanes(); });
  renderPanes(); applyExpand();
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

// Incrementally append only the NEW feed lines that match the current filter/focus — so it streams
// like a live wire with NO full rebuild, even when a single agent is focused (no flicker).
function appendFeedDelta() {
  const box = $("feed"); if (!box) return;
  const filt = $("feedFilter").value.toLowerCase();
  const near = box.scrollHeight - box.scrollTop - box.clientHeight < 90;
  const frag = document.createDocumentFragment();
  let appended = 0;
  for (let i = feedRendered; i < S.feed.length; i++) {
    const l = S.feed[i];
    if (focusFilter && l.ag !== focusFilter) continue;                       // focused on one agent
    if (filt && !((l.ag + " " + l.text).toLowerCase().includes(filt))) continue;
    const div = document.createElement("div");
    div.className = "feedline k-" + l.cls;
    const t = l.ts ? new Date(l.ts * 1000).toLocaleTimeString("en-GB") : "";
    div.innerHTML = `<span class="fts">${t}</span><span class="fag">${esc(l.ag)}</span><span class="ftx">${esc(l.text)}</span>`;
    frag.appendChild(div); appended++;
  }
  feedRendered = S.feed.length;
  if (!appended) return;                          // nothing matched → don't touch the DOM (no flicker)
  box.appendChild(frag);
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
    ingest([e]); if (view === "unified" && !hasSelection()) appendFeedDelta(); panelsDirty = true;
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
  S.tokens = { total: 0, cost: 0 }; S.settings = {}; S.stats = {}; S.models = {};
  S.findings = { confirmed_criticals: [], needs_human_review: [], candidates: [] };
  for (const k in rosterRows) delete rosterRows[k];   // drop cached rows from the prior engagement
  $("roster").innerHTML = "";
  renderStage(); panelsDirty = true; render(); connect();
}

// ---- boot -----------------------------------------------------------------
$("engSelect").onchange = (e) => switchEng(e.target.value);
$("feedFilter").oninput = renderFeed;   // rebuilds the feed for the filter + resyncs the append pointer
$("modalClose").onclick = () => $("modal").classList.remove("open");
$("modal").onclick = (e) => { if (e.target === $("modal")) $("modal").classList.remove("open"); };
// EXPAND: global toggle (button) + per-line click to expand just one line.
$("expandBtn").onclick = () => {
  expandAll = !expandAll;
  $("expandBtn").classList.toggle("on", expandAll);
  $("expandBtn").textContent = expandAll ? "⤡ collapse" : "⤢ expand";
  applyExpand();
};
$("centerStage").addEventListener("click", (e) => {
  if (hasSelection()) return;                       // a click that's really a text selection — leave it
  const ln = e.target.closest && e.target.closest(".feedline");
  if (ln) ln.classList.toggle("expanded");          // expand/collapse just this line
});
setInterval(() => { $("clock").textContent = new Date().toLocaleTimeString("en-GB"); }, 1000);
// Throttle the heavy panels (metrics/roster/findings) to ~3 Hz while the feed streams freely.
// True when the user has text highlighted — pause ALL re-rendering so a selection (for copy) survives.
function hasSelection() {
  const s = window.getSelection && window.getSelection();
  return !!(s && !s.isCollapsed && String(s).length > 0);
}
setInterval(() => {
  if (hasSelection()) return;                 // don't disturb the user mid-selection; resume on deselect
  if (view === "unified") appendFeedDelta();  // flush any feed lines that queued while selecting
  if (panelsDirty) { panelsDirty = false; render(); }
  setConn(S.running);
}, 320);

(async function () {
  buildViewModes();
  await loadEngagements();
  connect();
  setInterval(loadEngagements, 8000);
})();
