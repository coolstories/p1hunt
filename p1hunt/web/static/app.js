"use strict";
// P1HUNT operations console client. Polls /api/tail, aggregates the raw event stream
// into live state, and renders the ops panels. No framework, no build step.

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const clip = (s, n) => { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n) + "…" : s; };

const AGENT = (a) => {
  const b = String(a).split(".")[0].split(":")[0];
  if (b === "exploit_dev") return "exploit_developer";
  return b;
};  // the real agent id (child_b1, fuzzer_1, …)
const ROLE = (a) => {
  const b = AGENT(a);
  if (b === "parent_a") return "lead";
  if (b.startsWith("child_b")) return b.includes("2nd") ? "2nd-opinion" : "hunter";
  if (b.startsWith("fuzzer")) return "fuzzer";
  if (b === "falsifier") return "falsifier";
  if (b === "poc_prover") return "prover";
  if (b === "exploit_developer" || b === "exploit_dev") return "exploit-dev";
  if (b === "candidate_sweeper") return "sweeper";
  if (b === "debate") return "debate";
  if (b === "dedup") return "dedup";
  if (b === "scopeguard") return "guard";
  return b;
};

const SERVICE_AGENTS = ["parent_a", "candidate_sweeper", "falsifier", "poc_prover", "exploit_developer", "debate", "dedup"];
const STATUS_RANK = {
  refuted: -30, rejected: -30, debate_rejected: -30, attribution_blocked: -20,
  posted: 1, live_candidate: 1, selected_for_verification: 2, running: 3,
  unverified: 4, deferred: 5, retry_next_round: 6, intervened: 7,
  real: 8, not_reproduced: 9, autonomous_followup: 10,
  harness_materialized: 11, reproduced: 14, reproduced_pending_deepdive: 15,
  reproduced_pending_debate: 16, exploit_confirmed_pending_debate: 18,
  debate_upheld: 19, upheld: 19, confirmed: 20, confirmed_critical_reproduced: 22,
};
const PIPELINE_STEPS = [
  ["blackboard", "POST"],
  ["verifier", "VERIFY"],
  ["poc_prover", "PROOF"],
  ["exploit_developer", "EXPLOIT"],
  ["debate", "DEBATE"],
  ["confirmed", "REPORT"],
];
const TERMINAL_BAD = new Set(["refuted", "rejected", "debate_rejected", "attribution_blocked", "not_reproduced", "exhausted", "maxed"]);
const TERMINAL_GOOD = new Set(["confirmed", "confirmed_critical_reproduced", "upheld", "debate_upheld"]);

function statusRank(status) {
  const s = String(status || "").toLowerCase();
  if (s in STATUS_RANK) return STATUS_RANK[s];
  if (s.includes("confirmed")) return 20;
  if (s.includes("reproduced") && !s.includes("not_")) return 14;
  return 0;
}

function isLowPriorityCandidate(x) {
  const sev = String(x?.severity || "").trim().toLowerCase();
  return sev === "low" || sev === "info" || sev === "informational";
}

function pipelineOf(x) {
  return x && x.pipeline && typeof x.pipeline === "object" ? x.pipeline : {};
}

function pipelineCurrent(x, rec = null) {
  if (rec && rec.latest) return rec.latest;
  const p = pipelineOf(x);
  return p.current && typeof p.current === "object" ? p.current : p;
}

function currentAgent(x, rec = null) {
  const p = pipelineOf(x);
  const cur = pipelineCurrent(x, rec);
  return AGENT(cur.current_agent || cur.target_agent || p.current_agent || cur.agent || "");
}

function rootKey(x) {
  const title = String(x?.title || x?.hyp || "").trim().toLowerCase();
  const root = String(x?.root_cause || "").trim().toLowerCase();
  const loc = String(x?.location || x?.file || "").trim().toLowerCase().split(":")[0];
  return [title, root || loc].filter(Boolean).join("\x1f");
}

function isConfirmedLike(x) {
  const p = pipelineOf(x);
  return !!x?.already_confirmed || statusRank(p.status || x?.status) >= statusRank("confirmed");
}

function pipelineLabel(x) {
  const p = pipelineOf(x);
  const status = String(p.status || x.status || "").toLowerCase();
  if (isConfirmedLike(x)) return "CONFIRMED P1";
  if (status === "real") return "FALSIFIER REAL";
  if (status === "not_reproduced") return "NOT REPRODUCED";
  if (status === "autonomous_followup") return "FOLLOW-UP QUEUED";
  if (status === "reproduced_pending_deepdive") return "REPRODUCED · DEEPDIVE";
  if (status === "reproduced_pending_debate") return "REPRODUCED · DEBATE";
  if (status === "exploit_confirmed_pending_debate") return "EXPLOIT CONFIRMED · DEBATE";
  if (status === "posted") return `${p.stage || "BLACKBOARD"} · AWAITING PARENT`;
  if (status === "rejected" || status === "refuted" || status === "debate_rejected") return "REJECTED";
  if (status) return `${p.stage || "PIPELINE"} · ${status}`.toUpperCase();
  return "UNSTAGED";
}

function pipelineClass(x) {
  const p = pipelineOf(x), status = String(p.status || x.status || "").toLowerCase();
  if (isConfirmedLike(x) || status.includes("upheld") || status.includes("reproduced")) return "ok";
  if (status.includes("reject") || status.includes("refut") || status.includes("not_reproduced")) return "bad";
  if (status === "real" || status.includes("followup") || status.includes("pending")) return "warn";
  return "info";
}

function ensureAgent(name, last = 0, role = "") {
  const base = AGENT(name);
  if (!base) return;
  const a = S.agents[base] || (S.agents[base] = { role: role || ROLE(base), last: 0, busy: false });
  const ts = Number(last) || 0;
  if (ts > (a.last || 0)) a.last = ts;
  a.role = role || a.role || ROLE(base);
}

function seedServiceAgents() {
  for (const name of SERVICE_AGENTS) ensureAgent(name, 0);
}

const S = {
  eng: null, offset: 0, feed: [], agents: {}, settings: {}, stats: {}, models: {},
  tokens: { total: 0, cost: 0 }, findings: { confirmed_criticals: [], needs_human_review: [], candidates: [] },
  debate: [], dedup: [], blackboard: [], processes: {}, supervisor: null, running: false, lastRx: 0,
};
const rosterRows = {};    // agent name -> cached row nodes, updated in place (no flicker)
let feedRendered = 0;     // how many S.feed lines are already in the DOM (incremental append)
let panelsDirty = true;   // metrics/roster/findings re-render on a throttle, not per-event
let es = null;            // the live EventSource
const evTimes = [];       // event arrival times → live events/sec meter
let focusFilter = null;   // when set, the UNIFIED feed shows only this agent (roster stays put)
let expandAll = false;    // global: show full (unclamped) text for every feed line
let showAllCandidates = false;
let sessionCheckBusy = false;
let sessionCheckMsg = "";
let runControlBusy = false;

function findingPayload(e) {
  const d = e.data || {};
  return d.finding && typeof d.finding === "object" ? d.finding : d;
}

function findingKey(x) {
  if (x.dedup_key) return "dedup:" + String(x.dedup_key).toLowerCase();
  return [x.title || x.hyp || "", x.severity || "", x.location || x.file || "", x.endpoint || x.url || ""]
    .join("\x1f").toLowerCase();
}

function processTitleKey(title) {
  const t = String(title || "").trim().toLowerCase().replace(/\s+/g, " ");
  return t ? "title:" + t : "";
}

function processKeyFromCandidate(x) {
  if (!x) return "";
  if (x.dedup_key) return "dedup:" + String(x.dedup_key).toLowerCase();
  return processTitleKey(x.title || x.hyp) || ("finding:" + findingKey(x));
}

function processKeyFromStatus(data) {
  if (!data) return "";
  if (data.dedup_key) return "dedup:" + String(data.dedup_key).toLowerCase();
  return processTitleKey(data.title || data.hyp);
}

function canonicalStage(stage, status, target) {
  const s = String(stage || "").toLowerCase();
  const st = String(status || "").toLowerCase();
  const t = String(target || "").toLowerCase();
  if (TERMINAL_GOOD.has(st) || st.includes("confirmed") || st.includes("upheld")) return "confirmed";
  if (s.includes("debate") || st.includes("debate")) return "debate";
  if (s.includes("exploit") || t.includes("exploit")) return "exploit_developer";
  if (s.includes("poc") || s.includes("proof") || s.includes("harness") || s.includes("runner")
      || t.includes("poc") || st.includes("reproduced") || st.includes("harness")) return "poc_prover";
  if (s.includes("verifier") || s.includes("falsifier") || t.includes("falsifier")
      || st === "real" || st === "unverified" || st === "selected_for_verification") return "verifier";
  if (s.includes("parent") || st === "intervened") return t ? canonicalStage(t, "", "") : "verifier";
  return "blackboard";
}

function stepIndex(stage, status, target) {
  const id = canonicalStage(stage, status, target);
  const idx = PIPELINE_STEPS.findIndex(([k]) => k === id);
  return idx >= 0 ? idx : 0;
}

function processClass(status) {
  const st = String(status || "").toLowerCase();
  if (TERMINAL_GOOD.has(st) || st.includes("confirmed") || st.includes("upheld")) return "ok";
  if (TERMINAL_BAD.has(st) || st.includes("reject") || st.includes("refut") || st.includes("not_reproduced")) return "bad";
  if (st === "running" || st === "intervened" || st.includes("pending") || st.includes("followup") || st.includes("follow_up")) return "active";
  if (st === "real" || st === "reproduced" || st === "deferred" || st.includes("retry") || st.includes("harness")) return "warn";
  return "info";
}

function ensureProcess(key, seed = {}) {
  if (!key) return null;
  const rec = S.processes[key] || (S.processes[key] = {
    key, title: "", severity: "", location: "", lane: "", events: [], seen: new Set(), latest: null, candidate: null,
  });
  if (seed.title || seed.hyp) rec.title = seed.title || seed.hyp;
  if (seed.severity) rec.severity = seed.severity;
  if (seed.location || seed.file) rec.location = seed.location || seed.file;
  if (seed.lane) rec.lane = seed.lane;
  if (seed.candidate) rec.candidate = seed.candidate;
  return rec;
}

function recordProcessEvent(key, ev) {
  const rec = ensureProcess(key, ev);
  if (!rec) return null;
  const ts = Number(ev.updated_ts || ev.ts || Date.now() / 1000) || 0;
  const item = {
    ts,
    stage: ev.stage || "",
    status: ev.status || "",
    agent: AGENT(ev.agent || ""),
    target_agent: ev.target_agent || ev.target || "",
    current_agent: ev.current_agent || "",
    next_action: ev.next_action || ev.action || "",
    blocked_by: ev.blocked_by || "",
    reason: ev.reason || ev.detail || "",
    title: ev.title || rec.title,
  };
  const dedupe = [Math.round(ts * 10), item.stage, item.status, item.agent, item.target_agent, item.current_agent, item.blocked_by, item.reason].join("\x1f");
  if (!rec.seen.has(dedupe)) {
    rec.seen.add(dedupe);
    rec.events.push(item);
    rec.events.sort((a, b) => (a.ts || 0) - (b.ts || 0));
    if (rec.events.length > 80) rec.events.splice(0, rec.events.length - 80);
  }
  if (!rec.latest || ts > (rec.latest.ts || 0)
      || (ts === (rec.latest.ts || 0) && statusRank(item.status) >= statusRank(rec.latest.status))) {
    rec.latest = item;
  }
  return rec;
}

function seedProcessFromCandidate(x, lane = "candidate") {
  if (!x || !(x.title || x.hyp)) return;
  const key = processKeyFromCandidate(x);
  const p = pipelineOf(x);
  const rec = ensureProcess(key, { ...x, lane, candidate: x });
  if (!rec) return;
  const hist = (p.history || []).filter(h => h && typeof h === "object");
  if (hist.length) {
    for (const h of hist) recordProcessEvent(key, { ...h, title: x.title || x.hyp, severity: x.severity, location: x.location || x.file });
  }
  if (p.current && typeof p.current === "object") {
    recordProcessEvent(key, {
      ...p.current,
      title: x.title || x.hyp,
      severity: x.severity,
      location: x.location || x.file,
    });
  }
  recordProcessEvent(key, {
    title: x.title || x.hyp,
    severity: x.severity,
    location: x.location || x.file,
    stage: p.stage || (lane === "confirmed" ? "confirmed" : "blackboard"),
    status: p.status || (lane === "confirmed" ? "confirmed_critical_reproduced" : "posted"),
    target_agent: p.target_agent || "",
    next_action: p.next_action || "",
    blocked_by: p.blocked_by || "",
    reason: p.reason || x.root_cause || "",
    updated_ts: p.updated_ts || x.last_seen_ts || x.ts || Date.now() / 1000,
    agent: x.source_agent || "",
  });
}

function seedProcessesFromFindings() {
  const f = S.findings || {};
  for (const x of (f.confirmed_criticals || [])) seedProcessFromCandidate(x, "confirmed");
  for (const x of (f.candidates || [])) seedProcessFromCandidate(x, "candidate");
  for (const x of (f.needs_human_review || [])) seedProcessFromCandidate(x, "followup");
  const hist = f.activity && f.activity.candidate_history ? f.activity.candidate_history : {};
  for (const [k, rows] of Object.entries(hist)) {
    for (const h of rows || []) recordProcessEvent("dedup:" + String(k).toLowerCase(), h);
  }
}

function recordProcessFromEvent(e) {
  const d = e.data || {};
  if (e.kind === "finding_reported" || e.kind === "finding") {
    const x = findingPayload(e);
    if (!x || !(x.title || x.hyp)) return;
    const key = processKeyFromCandidate(x);
    const xp = x.pipeline && typeof x.pipeline === "object" ? x.pipeline : {};
    const cur = xp.current && typeof xp.current === "object" ? xp.current : xp;
    ensureProcess(key, { ...x, lane: e.kind === "finding" ? "confirmed" : "candidate", candidate: x });
    recordProcessEvent(key, {
      title: x.title || x.hyp, severity: x.severity, location: x.location || x.file,
      stage: cur.stage || xp.stage || (e.kind === "finding" && d.event === "critical_confirmed" ? "confirmed" : "blackboard"),
      status: cur.status || xp.status || x.status || (e.kind === "finding" && d.event === "critical_confirmed" ? "confirmed_critical_reproduced" : "posted"),
      target_agent: cur.target_agent || xp.target_agent || "", current_agent: xp.current_agent || "",
      blocked_by: cur.blocked_by || xp.blocked_by || x.blocked_by || "",
      reason: cur.reason || xp.reason || x.root_cause || "", updated_ts: cur.updated_ts || e.ts, agent: cur.agent || xp.agent || e.agent,
    });
    return;
  }
  if (e.kind === "lifecycle" && d.event === "candidate_status") {
    const key = processKeyFromStatus(d);
    recordProcessEvent(key, { ...d, updated_ts: e.ts, agent: e.agent });
    return;
  }
  if (e.kind === "message" && d.phase === "intervention") {
    const key = processKeyFromStatus(d);
    recordProcessEvent(key, {
      title: d.title || d.directive || "", stage: "parent_a", status: "intervened",
      target_agent: d.to || "", next_action: d.directive || "", blocked_by: d.blocked_by || "",
      reason: d.reason || "", updated_ts: e.ts, agent: e.agent,
    });
    return;
  }
  if (e.kind === "message" && "verdict" in d && (d.title || d.hyp)) {
    const verdict = String(d.verdict || "");
    recordProcessEvent(processKeyFromStatus(d), {
      title: d.title || d.hyp, stage: verdict.startsWith("debate") ? "debate" : "verifier",
      status: verdict, reason: d.reason || "", updated_ts: e.ts, agent: e.agent,
    });
  }
}

function processList() {
  return Object.values(S.processes).filter(p => p.title).sort((a, b) => {
    const la = a.latest || {}, lb = b.latest || {};
    const ca = processClass(la.status) === "active" ? 1 : 0;
    const cb = processClass(lb.status) === "active" ? 1 : 0;
    if (ca !== cb) return cb - ca;
    return (lb.ts || 0) - (la.ts || 0);
  });
}

function renderStepper(rec, mini = false) {
  const latest = rec?.latest || {};
  const idx = stepIndex(latest.stage, latest.status, latest.target_agent);
  const cls = processClass(latest.status);
  return `<div class="stepper ${mini ? "mini" : ""} ${cls}">` + PIPELINE_STEPS.map(([id, label], i) => {
    const state = i < idx ? "done" : i === idx ? "cur" : "todo";
    return `<span class="st ${state}" title="${esc(label)}"><i></i>${mini ? "" : `<b>${esc(label)}</b>`}</span>`;
  }).join("") + `</div>`;
}

function processSummary(rec) {
  const l = rec?.latest || {};
  const h = processHealth(rec);
  const cls = processClass(l.status);
  const at = PIPELINE_STEPS[stepIndex(l.stage, l.status, l.target_agent)]?.[1] || "PIPELINE";
  const owner = AGENT(l.current_agent || l.target_agent || "");
  if (h.state === "stuck") return `stuck at ${at} · no update for ${fmtDur(h.lastAge)}`;
  if (h.state === "quiet") return `quiet at ${at} · no candidate-stage event for ${fmtDur(h.lastAge)}`;
  if (h.state === "parked") return `parked at ${at} · ${l.blocked_by || h.reason}`;
  if (h.state === "queued") return `queued at ${at} · waiting for Parent A routing`;
  if (h.state === "routed") return `routed at ${at}${owner ? " · " + owner : ""}`;
  if (h.state === "working") return `working at ${at}${owner ? " · " + owner : ""}`;
  if (h.state === "blocked") return `blocked at ${at} · ${l.blocked_by || h.reason}`;
  if (h.state === "waiting") return `waiting at ${at} · ${String(l.status || "deferred").replaceAll("_", " ")}`;
  if (cls === "bad") return `stopped at ${at}${l.blocked_by ? " · " + l.blocked_by : ""}`;
  if (cls === "ok") return `complete at ${at}`;
  if (cls === "active") return `${h.label.toLowerCase()} at ${at}${owner ? " · " + owner : ""}`;
  return `${at}${l.status ? " · " + l.status : ""}`;
}

function currentStageId(rec) {
  const l = rec?.latest || {};
  return canonicalStage(l.stage, l.status, l.target_agent);
}

function stageLabel(stageId) {
  return PIPELINE_STEPS.find(([k]) => k === stageId)?.[1] || "PIPELINE";
}

function processHealth(rec, now = Date.now() / 1000) {
  const latest = rec?.latest || {};
  const events = rec?.events || [];
  const stageId = currentStageId(rec);
  const status = String(latest.status || "").toLowerCase();
  const blockedBy = String(latest.blocked_by || "").toLowerCase();
  const targetAgent = AGENT(latest.current_agent || latest.target_agent || latest.agent || "");
  const targetLast = targetAgent && S.agents[targetAgent] ? S.agents[targetAgent].last : 0;
  const targetAge = targetLast ? Math.max(0, now - targetLast) : null;
  let stageStart = latest.ts || now;
  let statusStart = latest.ts || now;
  let statusStillCurrent = true;
  for (let i = events.length - 1; i >= 0; i--) {
    const ev = events[i];
    if (canonicalStage(ev.stage, ev.status, ev.target_agent) !== stageId) break;
    stageStart = ev.ts || stageStart;
    if (statusStillCurrent && String(ev.status || "").toLowerCase() === status) statusStart = ev.ts || statusStart;
    else statusStillCurrent = false;
  }
  const lastAge = latest.ts ? Math.max(0, now - latest.ts) : 0;
  const stageAge = stageStart ? Math.max(0, now - stageStart) : 0;
  const statusAge = statusStart ? Math.max(0, now - statusStart) : 0;
  const isTerminalGood = TERMINAL_GOOD.has(status) || status.includes("confirmed") || status.includes("upheld");
  const isTerminalBad = TERMINAL_BAD.has(status) || status.includes("reject") || status.includes("refut") || status.includes("not_reproduced");
  let state = "running", cls = "active", label = "RUNNING", reason = "agent is still working this stage";
  if (isTerminalGood) {
    state = "complete"; cls = "ok"; label = "COMPLETE"; reason = "confirmed or upheld";
  } else if (isTerminalBad) {
    state = "stopped"; cls = "bad"; label = "STOPPED"; reason = latest.blocked_by || "terminal rejection/not reproduced";
  } else if (status === "intervened") {
    if (lastAge >= 90 * 60) {
      state = "stuck"; cls = "bad"; label = "STUCK"; reason = `directive has had no follow-up event for ${fmtDur(lastAge)}`;
    } else {
      state = "routed"; cls = "active"; label = "ROUTED"; reason = `Parent A directive queued${targetAgent ? " for " + targetAgent : ""}`;
    }
  } else if (blockedBy.includes("attacker_win") || blockedBy.includes("exploit_chain_exhausted") || blockedBy.includes("non_target_behavior")) {
    state = "parked"; cls = "warn"; label = "PARKED"; reason = latest.blocked_by || "proof gap recorded; waiting for new evidence";
  } else if (blockedBy === "awaiting_parent_pipeline") {
    state = "queued"; cls = "active"; label = "QUEUED"; reason = "posted to blackboard; waiting for autonomous routing";
  } else if (targetAge != null && targetAge < 20 * 60 && !latest.blocked_by) {
    state = "working"; cls = "active"; label = "WORKING"; reason = `${targetAgent} active ${fmtDur(targetAge)} ago`;
  } else if (latest.blocked_by) {
    state = "blocked"; cls = "warn"; label = "BLOCKED"; reason = latest.blocked_by;
  } else if (status.includes("retry") || status === "deferred") {
    state = "waiting"; cls = "warn"; label = "WAITING"; reason = "queued for the next autonomous pass";
  } else if (lastAge >= 90 * 60) {
    state = "stuck"; cls = "bad"; label = "STUCK"; reason = `no event for ${fmtDur(lastAge)}`;
  } else if (lastAge >= 30 * 60) {
    state = "quiet"; cls = "warn"; label = "QUIET"; reason = `candidate pipeline quiet for ${fmtDur(lastAge)}; scan may still be active`;
  } else if (lastAge >= 10 * 60) {
    state = "quiet"; cls = "warn"; label = "QUIET"; reason = `candidate pipeline quiet for ${fmtDur(lastAge)}`;
  } else if (status === "real" || status === "reproduced" || status.includes("harness")) {
    state = "promising"; cls = "warn"; label = "PROMISING"; reason = "survived a verification/proof gate";
  }
  return {
    stageId,
    stage: stageLabel(stageId),
    status: latest.status || "",
    state,
    cls,
    label,
    reason,
    lastAge,
    stageAge,
    statusAge,
    latestTs: latest.ts || 0,
    stageStart,
    statusStart,
  };
}

function attentionFor(x, rec) {
  const p = pipelineOf(x);
  const h = processHealth(rec);
  const status = String(p.status || x.status || h.status || "").toLowerCase();
  const stage = h.stageId || canonicalStage(p.stage, status, p.target_agent);
  let score = 0;
  if (String(x.severity || "").toLowerCase().includes("critical")) score += 45;
  if (stage === "exploit_developer") score += 45;
  else if (stage === "debate") score += 40;
  else if (stage === "poc_prover") score += 32;
  else if (stage === "verifier") score += 20;
  else score += 8;
  if (status.includes("reproduced") || status.includes("exploit_confirmed")) score += 45;
  if (status === "real") score += 35;
  if (status === "unverified") score += 8;
  if (x._dupeCount > 1) score += Math.min(15, x._dupeCount * 2);
  if (h.state === "stuck") score += 80;
  else if (h.state === "blocked") score += 45;
  else if (h.state === "parked") score -= 10;
  else if (h.state === "quiet") score += 20;
  else if (h.state === "waiting") score += 42;
  else if (h.state === "routed") score += 30;
  else if (h.state === "queued") score += 18;
  else if (h.state === "working") score += 36;
  else if (h.state === "promising") score += 50;
  else if (h.state === "running") score += 35;
  else if (h.state === "stopped") score -= 55;
  else if (h.state === "complete") score += 20;
  if (p.blocked_by && p.blocked_by !== "awaiting_parent_pipeline") score += 12;
  const isImmediate = status.includes("reproduced") || status.includes("exploit_confirmed")
    || status.includes("confirmed") || (stage === "debate" && !h.state.includes("stopped"));
  const tier = score >= 150 && isImmediate ? "URGENT" : score >= 115 ? "HOT" : score >= 80 ? "WATCH" : score >= 45 ? "QUEUE" : "LOW";
  const cls = tier === "URGENT" ? "urgent" : score >= 115 ? "hot" : score >= 80 ? "watch" : score >= 45 ? "queue" : "low";
  const why = `${h.label}: ${h.stage} for ${fmtDur(h.stageAge)}, latest ${fmtDur(h.lastAge)} ago`
    + (h.reason ? ` · ${h.reason}` : "");
  return { score, tier, cls, why, health: h };
}

function variantList(x) {
  const out = [];
  const add = (v) => {
    if (!v || !(v.title || v.hyp)) return;
    const key = findingKey(v);
    if (!out.some(o => findingKey(o) === key)) {
      const { _variants, _dupeCount, ...copy } = v;
      out.push(copy);
    }
  };
  add(x);
  for (const v of (x._variants || [])) add(v);
  return out;
}

function mergeCandidate(a, b) {
  const pa = pipelineOf(a), pb = pipelineOf(b);
  const ra = statusRank(pa.status || a.status) + (a.already_confirmed ? 100 : 0);
  const rb = statusRank(pb.status || b.status) + (b.already_confirmed ? 100 : 0);
  const strong = rb >= ra ? b : a;
  const weak = rb >= ra ? a : b;
  const strongPipe = rb >= ra ? pb : pa;
  const weakPipe = rb >= ra ? pa : pb;
  const out = { ...weak, ...strong };
  const hist = [...((weakPipe.history || []).filter(Boolean)), ...((strongPipe.history || []).filter(Boolean))];
  const seen = new Set(), mergedHist = [];
  for (const h of hist.sort((x, y) => (Number(x.updated_ts || x.ts || 0) - Number(y.updated_ts || y.ts || 0)))) {
    const k = [Math.round(Number(h.updated_ts || h.ts || 0) * 10), h.stage || "", h.status || "", h.agent || "", h.target_agent || "", h.blocked_by || ""].join("\x1f");
    if (seen.has(k)) continue;
    seen.add(k); mergedHist.push(h);
  }
  out.pipeline = { ...weakPipe, ...strongPipe };
  if (mergedHist.length) {
    const cur = mergedHist[mergedHist.length - 1];
    out.pipeline.history = mergedHist.slice(-40);
    out.pipeline.current = cur;
    out.pipeline.current_agent = cur.current_agent || cur.target_agent || cur.agent || out.pipeline.current_agent || "";
  }
  out._variants = [...variantList(a), ...variantList(b)].filter((v, i, arr) =>
    arr.findIndex(z => findingKey(z) === findingKey(v)) === i).slice(0, 12);
  out._dupeCount = out._variants.length;
  out.already_confirmed = !!(a.already_confirmed || b.already_confirmed);
  return out;
}

function dedupeCandidates(items) {
  const merged = new Map();
  for (const x of items || []) {
    if (!x || !(x.title || x.hyp)) continue;
    const key = rootKey(x) || findingKey(x);
    merged.set(key, merged.has(key) ? mergeCandidate(merged.get(key), x) : x);
  }
  return [...merged.values()];
}

function mergeMini(bucket, rows, limit = 80) {
  if (!Array.isArray(rows) || !rows.length) return;
  const incoming = rows.map(x => ({
    cls: x.cls || "",
    t: x.t || x.text || "",
  })).filter(x => x.t);
  const combined = [...incoming.reverse(), ...bucket];
  const out = [], seen = new Set();
  for (const x of combined) {
    const k = `${x.cls}\x1f${x.t}`;
    if (seen.has(k)) continue;
    seen.add(k); out.push(x);
    if (out.length >= limit) break;
  }
  bucket.length = 0;
  bucket.push(...out);
}

function mergeActivity(activity) {
  if (!activity || typeof activity !== "object") return;
  for (const a of (activity.agents || [])) ensureAgent(a.agent, a.last_ts);
  mergeMini(S.debate, activity.debate || []);
  mergeMini(S.dedup, activity.dedup || []);
}

function mergeFindingState(next) {
  const prev = S.findings || {};
  next = next || {};
  mergeActivity(next.activity);
  const merged = {
    confirmed_criticals: next.confirmed_criticals || prev.confirmed_criticals || [],
    needs_human_review: next.needs_human_review || prev.needs_human_review || [],
    candidates: dedupeCandidates([...(next.candidates || []), ...((prev.candidates || []).filter(c => c.live))]),
    counts: { ...(next.counts || {}) },
    activity: next.activity || prev.activity || {},
  };
  const confirmedRoots = new Set((merged.confirmed_criticals || []).map(rootKey).filter(Boolean));
  const visibleCandidates = merged.candidates.filter(c => {
    const rk = rootKey(c);
    return !isConfirmedLike(c) && !(rk && confirmedRoots.has(rk));
  });
  const actionableCandidates = visibleCandidates.filter(c => !isLowPriorityCandidate(c));
  const lowPriorityCandidates = visibleCandidates.filter(c => isLowPriorityCandidate(c));
  merged.counts.confirmed_critical = merged.confirmed_criticals.length;
  merged.counts.needs_human_review = merged.needs_human_review.length;
  merged.counts.raw_candidates = merged.candidates.length;
  merged.counts.candidates = actionableCandidates.length;
  merged.counts.actionable_candidates = actionableCandidates.length;
  merged.counts.low_priority_candidates = lowPriorityCandidates.length;
  S.findings = merged;
  seedProcessesFromFindings();
}

function addLiveCandidate(e) {
  const x = findingPayload(e);
  if (!x || !(x.title || x.hyp)) return;
  const cands = S.findings.candidates || (S.findings.candidates = []);
  const item = { ...x, ts: x.ts || e.ts, live: true };
  const key = rootKey(item) || findingKey(item);
  const idx = cands.findIndex(c => (rootKey(c) || findingKey(c)) === key);
  if (idx >= 0) cands[idx] = mergeCandidate(cands[idx], item);
  else cands.unshift(item);
}

function addBlackboardLine(e) {
  const d = e.data || {};
  let text = "";
  let cls = "";
  if (e.kind === "bb_write") {
    const bits = [d.what, d.id, d.state, d.program, d.claim].filter(Boolean);
    text = bits.join(" · ");
  } else if (e.kind === "finding_reported") {
    const x = findingPayload(e);
    text = `posted [${x.severity || "?"}] ${x.title || x.hyp || ""}`;
    cls = "up";
  } else if (e.kind === "finding") {
    text = d.event === "critical_confirmed"
      ? `critical confirmed x${d.count || 1}`
      : `finding [${d.severity || "?"}] ${d.title || ""}`;
    cls = "up";
  } else if (e.kind === "message" && d.phase === "intervention") {
    text = `Parent A -> ${d.to || "service"}: ${d.title || d.directive || ""}`;
    cls = "down";
  } else if (e.kind === "lifecycle" && d.event === "candidate_status") {
    text = `${d.title || ""}: ${d.stage || "pipeline"}:${d.status || "?"}`
      + (d.blocked_by ? ` blocked_by=${d.blocked_by}` : "");
    cls = d.status === "upheld" || d.status === "confirmed" ? "up" : d.status === "rejected" ? "rej" : "";
  } else if (e.kind === "lifecycle" && (d.event === "needs_human_review" || d.event === "autonomous_followup")) {
    text = `follow-up queued: ${d.title || ""}`;
    cls = "down";
  }
  if (!text) return;
  const agent = AGENT(e.agent);
  const recent = S.blackboard.find(x => x.agent === agent && x.text === text);
  if (recent && Math.abs((e.ts || 0) - (recent.ts || 0)) < 3600) {
    recent.ts = Math.max(recent.ts || 0, e.ts || 0);
    if (cls && !recent.cls) recent.cls = cls;
    return;
  }
  S.blackboard.unshift({ ts: e.ts, agent, text, cls });
  if (S.blackboard.length > 120) S.blackboard.length = 120;
}

// Apply the global expand flag to the feed. Per-line expand (click) is independent and survives this.
function applyExpand() {
  const f = $("feed"); if (f) f.classList.toggle("expanded", expandAll);
}

function fmtDur(s) {
  if (s == null) return "--"; s = Math.max(0, Math.floor(s));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h ? `${h}h${String(m).padStart(2,"0")}m` : m ? `${m}m${String(sec).padStart(2,"0")}s` : `${sec}s`;
}
function fmtClock(ts) {
  return ts ? new Date(ts * 1000).toLocaleTimeString("en-GB") : "--";
}
function fmtTok(n) { n = n || 0; return n >= 1e6 ? (n/1e6).toFixed(2)+"M" : n >= 1e3 ? (n/1e3).toFixed(1)+"K" : ""+n; }

function toolProgressText(d) {
  const cmd = String(d?.target || "");
  const lower = cmd.toLowerCase();
  const shortPath = (s) => {
    s = String(s || "").replace(/^['"]|['"]$/g, "").trim();
    if (!s) return "";
    const bits = s.split("/");
    return bits.length > 4 ? bits.slice(-4).join("/") : s;
  };
  let m = cmd.match(/\bsed\s+-n\s+['"][^'"]+['"]\s+([^|;&]+)/);
  if (!m) m = cmd.match(/\bnl\s+-ba\s+([^|;&]+)/);
  if (m) return `reading ${shortPath(m[1])}`;
  if (lower.includes("rg --files")) return "mapping repository files";
  if (/\brg\b/.test(lower)) return "searching symbols and invariants";
  if (lower.includes("git status")) return "checking workspace state";
  if (lower.includes("forge test") || /\bforge\b/.test(lower)) return "running Foundry validation";
  if (lower.includes("pytest") || lower.includes("ctest") || /\bmake\b/.test(lower) || lower.includes("cmake")) return "building or running tests";
  if (lower.includes("curl ")) return "checking endpoint";
  return `${d?.tool || ""}  ${clip(d?.target, 600)}`;
}

// ---- event -> display line ------------------------------------------------
function fmtEvent(e) {
  const d = e.data || {}, k = e.kind, ag = AGENT(e.agent);
  const L = (cls, text) => ({ ts: e.ts, ag, cls, text });
  if (k === "thinking") return L("thinking", clip(d.text, 4000));
  if (k === "output") return L("output", clip(d.text, 4000));
  if (k === "tool_call") return L("tool", toolProgressText(d));
  if (k === "finding_reported") return L("finding", `posted: ${clip(d.title,90)} [${d.severity||"?"}]`);
  if (k === "finding") return L("finding", d.event === "critical_confirmed"
      ? `critical confirmed x${d.count||1}` : `${clip(d.title,90)} [${d.severity||""}]`);
  if (k === "guard_decision") return d.allow ? null : L("deny", `deny ${d.tool||""}: ${clip(d.target,60)} - ${clip(d.reason,60)}`);
  if (k === "reframe") return L("system", "reframe: " + clip(d.reason || d.frame, 120));
  if (k === "message") {
    if (d.kind === "assign") return L("assign", `assigned to ${d.to||""}: ${clip(d.mission||d.lens,70)}`);
    if ("verdict" in d) return L(String(d.verdict).startsWith("debate") ? "debate" : "verdict",
        `${d.verdict}: ${clip(d.title||d.hyp,70)}`);
    const p = d.phase;
    if (p === "scoping") return L("system", "cold reconnaissance");
    if (p === "scoped") return L("system", `derived ${d.tracks||"?"} tracks · critical = ${clip(d.critical_means,80)}`);
    if (p === "round") return L("round", `round ${d.round} · ${d.lenses ?? d.depth ?? "?"} tracks`);
    if (p === "round_summary") return L("system", `round ${d.round} — criticals ${d.criticals_total||0}, candidates ${d.candidates_total||0}, cpu ${d.cpu_pct ?? "?"}%`);
    if (p === "hunt") return L("system", `hunting ${d.lens||""} · pass ${d.depth||""}`);
    if (p === "map") return L("system", `mapping ${clip(d.subsystem,60)}`);
    if (p === "mapped") return L("system", `model built (${d.model_chars||0} chars)`);
    if (p === "fuzz") return L("system", `${d.mode||""} fuzz: ${clip(d.subsystem,50)}`);
    if (p === "debate") return L("debate", `debate convened: ${clip(d.title,70)}`);
    if (p === "poc") return L("system", `PoC: ${clip(d.title,70)}`);
    if (p === "materialize") return L("system", `materialize harness: ${clip(d.title,60)}`);
    if (p === "repair") return L("system", `repair harness: ${clip(d.title,60)}`);
    if (p === "progress") return L("system", clip(d.detail || d.target || "working", 140));
    if (p === "intervention") return L("assign", `Parent A to ${d.to || "service"}: ${clip(d.title || d.directive || "", 90)}${d.blocked_by ? " · blocked by " + clip(d.blocked_by, 50) : ""}`);
    if (p === "resteer") return L("system", "re-steering the team");
    if (p === "notice") return L("round", `notice: ${clip(d.notice,90)}`);
    return null;
  }
  if (k === "lifecycle") {
    const ev = d.event;
    const M = { reproduction:"reproduction", candidate_not_reproduced:"candidate", needs_human_review:"follow-up", autonomous_followup:"follow-up",
      duplicate_dropped:"duplicate", debate_upheld:"debate upheld", debate_downgraded:"debate downgraded", debate_rejected:"debate rejected",
      criticals_target_reached:"target reached", candidate_status:"candidate status", backoff:"backoff", stall_detected:"stall detected",
      self_healed:"self-healed", toolchain_missing_warning:"toolchain warning", dynamic_armed:"dynamic armed",
      memory_recalled:"memory recalled", reference_detected:"reference detected", patterns_loaded:"legacy patterns ignored",
      build_status:"build status", fork_ready:"fork ready", cost_cap_reached:"cost cap reached", codex_waiting:"reasoning", stop:"stop" };
    if (ev === "settings") return null;
    if (ev === "duplicate_dropped") return L("dedup", `duplicate of #${d.of||"?"} dropped - ${clip(d.reason,70)}`);
    if (ev === "debate_rejected") return L("debate", `rejected: ${clip(d.title,55)} - ${clip(d.reason,55)}`);
    if (ev === "debate_downgraded") return L("debate", `downgraded to ${d.to}: ${clip(d.title,50)}`);
    if (ev === "debate_upheld") return L("finding", `upheld critical: ${clip(d.title,60)}`);
    if (ev === "candidate_status") return L("verdict", `${clip(d.title,52)} - ${d.stage || "pipeline"}:${d.status || "?"}${d.blocked_by ? " · blocked by " + clip(d.blocked_by,55) : ""}`);
    if (ev === "needs_human_review" || ev === "autonomous_followup") return L("verdict", `follow-up: ${clip(d.title,60)}`);
    if (ev === "criticals_target_reached") return L("round", `target ${d.confirmed_criticals}/${d.target} reached; stopping`);
    if (ev === "reproduction") return L("system", `${d.runner||"runner"}: ran=${d.ran} reproduced=${d.reproduced}`);
    if (M[ev]) return L("system", `${M[ev]}: ${clip(d.reason||d.detail||d.diagnosis||"",90)}`);
    return null;
  }
  return null;
}

// ---- ingest a batch -------------------------------------------------------
function ingest(events) {
  for (const e of events) {
    const base = AGENT(e.agent);
    if (e.agent && base) {
      ensureAgent(e.agent, e.ts || (Date.now()/1000));
      const a = S.agents[base];
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
    if (e.kind === "finding_reported" || e.kind === "finding") addLiveCandidate(e);
    recordProcessFromEvent(e);
    addBlackboardLine(e);
    if (e.kind === "lifecycle" && e.data?.event === "duplicate_dropped")
      S.dedup.unshift({ cls: "", t: `duplicate of #${e.data.of||"?"} - ${clip(e.data.reason,80)}` });
    if (e.kind === "lifecycle" && (e.data?.event||"").startsWith("debate_")) {
      const ev = e.data.event;
      S.debate.unshift({ cls: ev==="debate_upheld"?"up":ev==="debate_downgraded"?"down":"rej",
        t: `${ev==="debate_upheld"?"✓ upheld":ev==="debate_downgraded"?"↓ "+e.data.to:"✗ rejected"}: ${clip(e.data.title,55)}` });
    }
    const line = fmtEvent(e);
    if (line) S.feed.push(line);
  }
  if (S.feed.length > 800) { const rm = S.feed.length - 800; S.feed.splice(0, rm); feedRendered = Math.max(0, feedRendered - rm); }
  if (S.debate.length > 40) S.debate.length = 40;
  if (S.dedup.length > 40) S.dedup.length = 40;
}

// ---- render ---------------------------------------------------------------
function render() {
  const f = S.findings || {};
  const confirmedRoots = new Set((f.confirmed_criticals || []).map(rootKey).filter(Boolean));
  const allCandidates = dedupeCandidates(f.candidates || []);
  const visibleCandidates = allCandidates.filter(c => {
    const rk = rootKey(c);
    return !isConfirmedLike(c) && !(rk && confirmedRoots.has(rk));
  });
  const attentionRows = visibleCandidates.map(x => {
    const rec = S.processes[processKeyFromCandidate(x)];
    return { x, rec, att: attentionFor(x, rec) };
  }).sort((a, b) => (b.att.score - a.att.score) || ((b.rec?.latest?.ts || 0) - (a.rec?.latest?.ts || 0)));
  const actionableRows = attentionRows.filter(r => !isLowPriorityCandidate(r.x));
  const lowPriorityRows = attentionRows.filter(r => isLowPriorityCandidate(r.x));
  const defaultRows = actionableRows;
  const candidateLimit = 12;
  const displayedRows = showAllCandidates ? attentionRows : defaultRows.slice(0, candidateLimit);
  const crit = (f.confirmed_criticals || []).length, nh = (f.needs_human_review || []).length;
  const cand = actionableRows.length;
  $("mCrit").textContent = crit; $("mNH").textContent = nh; $("mCand").textContent = cand;
  $("mRound").textContent = S.stats.round ?? "0";
  $("mUptime").textContent = fmtDur(S.stats.elapsed_s);
  $("mCpu").textContent = S.stats.cpu_pct != null ? S.stats.cpu_pct + "%" : "--";
  $("mTok").textContent = fmtTok(S.tokens.total);
  $("mCost").textContent = "$" + (S.tokens.cost || 0).toFixed(2);
  $("critCount").textContent = crit; $("nhCount").textContent = nh;

  // risk level
  const lvl = crit >= 3 ? ["Critical", 100] : crit === 2 ? ["Severe", 78] : crit === 1 ? ["Elevated", 55]
            : nh > 0 ? ["Guarded", 32] : ["Nominal", 12];
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
    const eng = s.engine || s.discovery_engine || "codex";
    const engPill = `<span class="pill ${eng === "codex" ? "codex" : "claude"}">${esc(eng)}</span>`;
    const routing = s.role_routing === "all_roles" || eng === "codex" ? "all roles" : "legacy";
    const codexModel = m.orchestrator || (eng === "codex" ? "codex:default/xhigh" : "");
    $("settings").innerHTML =
      row("program", s.program) + row("target class", s.target_class) +
      `<div class="sgroup">ENGINE</div>` +
      `<div class="srow"><span class="sk">engine</span><span class="sv">${engPill}</span></div>` +
      row("role routing", routing) +
      (codexModel ? row("model", codexModel) : "") +
      (s.discovery_engine && s.discovery_engine !== eng ? row("discovery", s.discovery_engine) : "") +
      `<div class="sgroup">PROOF PIPELINE</div>` +
      rowP("deep discovery", s.deep_discovery) +
      rowP("dedup", s.dedup) +
      row("debate", s.debate_max ? `max ${s.debate_max}` : "off") +
      rowP("exploit depth", s.deepdive) +
      (s.deepdive ? row("depth budget", `${s.deepdive_top_n || "?"} leads x ${s.deepdive_turns || "?"} turns`) : "") +
      `<div class="sgroup">LIMITS</div>` +
      row("run mode", s.run_mode) +
      row("max rounds", s.max_rounds == null ? "unbounded" : s.max_rounds) +
      row("stop at P1s", s.max_criticals || "never") +
      row("fuzz campaigns", s.fuzz_campaigns) +
      row("cost cap", s.cost_cap_usd ? "$"+s.cost_cap_usd : "none");
  }
  renderSupervisor();

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
  const card = (x, variant, att = null, rank = 0) => {
    const sev = x.severity || (variant === "nh" ? "FOLLOW-UP" : variant === "cand" ? "candidate" : "CRITICAL");
    const loc = x.location || x.file || "";
    const p = pipelineOf(x);
    const proc = S.processes[processKeyFromCandidate(x)];
    const attention = att || attentionFor(x, proc);
    const health = attention.health;
    const owner = currentAgent(x, proc);
    const cur = pipelineCurrent(x, proc);
    const pipe = variant === "cand" || p.status
      ? `<div class="fmeta"><span class="pipe ${pipelineClass(x)}">${esc(pipelineLabel(x))}</span>`
        + `<span class="attention ${attention.cls}">${esc(attention.tier)}</span>`
        + `${x._dupeCount > 1 ? `<span class="dupes">×${x._dupeCount} variants</span>` : ""}`
        + `${owner ? `<span class="owner">now ${esc(owner)}</span>` : ""}</div>`
      : "";
    const sub = cur.blocked_by || cur.next_action || p.blocked_by || p.next_action || "";
    return `<div class="fcard ${variant}" data-k='${esc(JSON.stringify(x))}'>`
      + `<span class="fsev">${esc(sev)}</span>`
      + (rank ? `<span class="rank">#${rank}</span>` : "")
      + `<div class="ft">${esc(clip(x.title || x.hyp || "", 120))}</div>${pipe}`
      + `<div class="fstate ${health.cls}"><b>${esc(health.label)}</b><span>${esc(health.stage)} · in stage ${esc(fmtDur(health.stageAge))} · last update ${esc(fmtDur(health.lastAge))} ago</span></div>`
      + `<div class="fsub">${esc(clip(attention.why, 170))}</div>`
      + (sub ? `<div class="fsub">${esc(clip(sub, 140))}</div>` : "")
      + (proc ? renderStepper(proc, true) + `<div class="fsub">${esc(clip(processSummary(proc), 140))}</div>` : "")
      + `<div class="floc">${esc(loc)}</div></div>`;
  };
  $("confirmed").innerHTML = (f.confirmed_criticals||[]).map(x => card(x,"")).join("") || '<div class="muted">none confirmed</div>';
  const hiddenLow = lowPriorityRows.length;
  const headerTotal = showAllCandidates ? attentionRows.length : actionableRows.length;
  const candHeader = attentionRows.length
    ? `<div class="attentionbar"><span>${showAllCandidates ? "all" : "actionable"} ${displayedRows.length}/${headerTotal}`
      + `${hiddenLow && !showAllCandidates ? ` · ${hiddenLow} low hidden` : ""} · sorted by actionability</span>`
      + `${(attentionRows.length > candidateLimit || hiddenLow) ? `<button id="candToggle">${showAllCandidates ? "show actionable" : "show all"}</button>` : ""}</div>`
    : "";
  $("candidates").innerHTML = candHeader + (displayedRows.map((r, i) => card(r.x, "cand", r.att, i + 1)).join("")
    || '<div class="muted">none actionable; confirmed duplicates are collapsed into the confirmed lane</div>');
  $("needshuman").innerHTML = (f.needs_human_review||[]).map(x => card(x,"nh")).join("") || '<div class="muted">none</div>';
  $("candCount").textContent = cand;
  const candToggle = $("candToggle");
  if (candToggle) candToggle.onclick = () => { showAllCandidates = !showAllCandidates; panelsDirty = true; render(); };
  document.querySelectorAll(".fcard").forEach(el => el.onclick = () => focusFinding(JSON.parse(el.dataset.k)));

  // debate + dedup mini logs
  $("debate").innerHTML = S.debate.map(x => `<div class="mln ${x.cls}">${esc(x.t)}</div>`).join("")
    || (crit ? '<div class="muted warn">confirmed critical present, but no debate events were retained or recorded</div>' : '<div class="muted">no debates yet</div>');
  $("dedup").innerHTML = S.dedup.map(x => `<div class="mln">${esc(x.t)}</div>`).join("")
    || '<div class="muted">no duplicates dropped</div>';
  $("blackboard").innerHTML = S.blackboard.map(x => `<div class="mln ${x.cls}"><span class="bbag">${esc(x.agent)}</span> ${esc(x.text)}</div>`).join("")
    || '<div class="muted">no blackboard writes yet</div>';
  $("bbCount").textContent = S.blackboard.length;
}

function renderSupervisor() {
  const box = $("supervisorStatus");
  if (!box) return;
  const x = S.supervisor || {};
  const row = (k, v, cls = "") => `<div class="srow"><span class="sk">${esc(k)}</span><span class="sv ${cls}">${esc(v)}</span></div>`;
  const sess = x.session_limit || {};
  const limited = sess.throttled === true;
  const remaining = sess.remaining_s == null ? "--" : fmtDur(sess.remaining_s);
  const reset = sess.reset_ts
    ? new Date(sess.reset_ts * 1000).toLocaleTimeString("en-GB", { timeZone: "UTC", hour12: false }) + " UTC"
    : "";
  const lastProbe = sess.last_probe_ts == null ? "" : fmtDur(Date.now() / 1000 - sess.last_probe_ts) + " ago";
  const sessionRows =
    row("rate limit", limited ? `limited · ${remaining}` : "clear", limited ? "bad" : "ok") +
    (reset ? row("reset", reset) : "") +
    (lastProbe ? row("last check", lastProbe) : "") +
    (sessionCheckMsg ? row("check result", sessionCheckMsg, sessionCheckMsg.includes("waiting") ? "bad" : "ok") : "") +
    `<div class="sactions">`
    + `<button id="sessionCheckBtn" class="sbtn" ${sessionCheckBusy ? "disabled" : ""}>${sessionCheckBusy ? "checking..." : "recheck"}</button>`
    + `<button id="sessionForceBtn" class="sbtn danger" ${sessionCheckBusy ? "disabled" : ""}>retry now</button>`
    + `</div>`;
  const sw = x.candidate_sweeper || {};
  const swStatus = String(sw.status || "");
  const swCls = swStatus === "queued" ? "ok" : swStatus === "cooldown" ? "bad" : swStatus === "routing" ? "ok" : "";
  const sweeperRows = sw.agent
      ? row("candidate sweeper", `${swStatus || "unknown"} · ${sw.high_value_candidate_count ?? sw.candidate_count ?? 0} high/${sw.candidate_count ?? 0} total`, swCls)
      + (sw.low_priority_candidate_count ? row("low priority", `${sw.low_priority_candidate_count} background`) : "")
      + (sw.title ? row("picked", clip(sw.title, 80)) : "")
      + (sw.target_agent ? row("target", sw.target_agent) : "")
      + (sw.reason ? row("note", clip(sw.reason, 100), swStatus === "cooldown" ? "bad" : "") : "")
    : "";
  if (!x.configured) {
    box.innerHTML = '<div class="muted">supervisor heartbeat not found</div>' + sweeperRows + sessionRows;
    if ($("supervisorMeta")) $("supervisorMeta").textContent = "";
    const btn = $("sessionCheckBtn"); if (btn) btn.onclick = checkSessionLimit;
    const forceBtn = $("sessionForceBtn"); if (forceBtn) forceBtn.onclick = () => checkSessionLimit(true);
    return;
  }
  const alive = x.process_alive === true;
  const heartbeat = x.last_heartbeat_age_s == null ? "--" : fmtDur(x.last_heartbeat_age_s) + " ago";
  const engagements = (x.engagements || []).join(", ") || "all visible";
  const web = x.web && x.web.port ? `${x.web.host || "127.0.0.1"}:${x.web.port}` : "--";
  if ($("supervisorMeta")) $("supervisorMeta").textContent = alive ? "online" : "offline";
  box.innerHTML =
    row("status", alive ? "online" : "offline", alive ? "ok" : "bad") +
    row("pid", x.pid || "--") +
    row("heartbeat", heartbeat, x.last_heartbeat_age_s != null && x.last_heartbeat_age_s > 90 ? "bad" : "ok") +
    row("scope", engagements) +
    row("web", web) +
    row("interval", x.interval_s == null ? "--" : `${x.interval_s}s`) +
    row("limit probe", x.session_probe_s == null ? "--" : `${x.session_probe_s}s`) +
    row("candidate stale", x.candidate_stale_s == null ? "--" : `${x.candidate_stale_s}s`) +
    row("resume hunts", x.resume_hunts ? "on" : "off") +
    sweeperRows +
    sessionRows;
  const btn = $("sessionCheckBtn"); if (btn) btn.onclick = checkSessionLimit;
  const forceBtn = $("sessionForceBtn"); if (forceBtn) forceBtn.onclick = () => checkSessionLimit(true);
}

async function checkSessionLimit(force = false) {
  if (sessionCheckBusy) return;
  sessionCheckBusy = true;
  sessionCheckMsg = "";
  panelsDirty = true;
  renderSupervisor();
  try {
    const res = await fetch("/api/session-limit-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ eng: S.eng || "", force: !!force }),
    });
    const out = await res.json();
    if (!res.ok || out.error) throw new Error(out.error || "check failed");
    if (out.state && S.supervisor) S.supervisor.session_limit = out.state;
    const st = out.state || {};
    sessionCheckMsg = out.cleared
      ? (out.forced ? "forced jumpstart sent" : "jumpstart sent")
      : `waiting ${fmtDur(st.remaining_s || 0)}`;
    await loadSupervisor();
  } catch (err) {
    sessionCheckMsg = String(err && err.message ? err.message : err);
  } finally {
    sessionCheckBusy = false;
    panelsDirty = true;
    renderSupervisor();
  }
}

async function queueRunControl(kind) {
  if (runControlBusy || !S.eng) return;
  const labels = {
    pause: "Pause this scan after the current round? No new round will start until you resume.",
    resume: "Resume this paused scan?",
    stop: "Stop this scan after the current round? Autopilot will not resume it unless you clear or override the stop.",
  };
  if (!window.confirm(labels[kind] || `Send ${kind}?`)) return;
  runControlBusy = true;
  const buttons = ["pauseScanBtn", "resumeScanBtn", "stopScanBtn"].map($).filter(Boolean);
  buttons.forEach(b => b.disabled = true);
  try {
    const res = await fetch("/api/control", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        eng: S.eng,
        kind,
        message: `${kind} requested from web dashboard`,
      }),
    });
    const out = await res.json();
    if (!res.ok || out.error) throw new Error(out.error || `${kind} failed`);
    S.blackboard.unshift({
      ts: Date.now() / 1000,
      agent: "operator",
      text: `${kind} directive queued`,
      cls: kind === "stop" ? "rej" : "up",
    });
  } catch (err) {
    S.blackboard.unshift({
      ts: Date.now() / 1000,
      agent: "operator",
      text: `${kind} failed: ${err && err.message ? err.message : err}`,
      cls: "rej",
    });
  } finally {
    runControlBusy = false;
    buttons.forEach(b => b.disabled = false);
    panelsDirty = true;
    render();
  }
}

// Roster updated IN PLACE: rows are created once and only their status class / age text mutate.
// No innerHTML rebuild => no flicker, and the click target persists so selecting an agent is reliable.
function renderRoster() {
  seedServiceAgents();
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
    const cls = "agent " + (a.busy ? "busy" : (a.last && age < 90) ? "active" : "")
      + (focusFilter === n ? " focus" : "");
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
    const ageTxt = a.last ? fmtDur(age) + " ago" : "not seen";
    if (row.age.textContent !== ageTxt) row.age.textContent = ageTxt;
  }
}

// Clicking a roster agent filters the single live feed to that agent.
function focusAgent(base) {
  focusFilter = base;
  renderStage(); setFeedTitle();
}
function clearFocus() {
  focusFilter = null; setFeedTitle(); renderStage();
}
function focusFinding(x) {
  seedProcessFromCandidate(x, isConfirmedLike(x) ? "confirmed" : "candidate");
  openModal(x);
}
function setFeedTitle() {
  const t = $("feedTitle");
  if (focusFilter) t.innerHTML = `Agent · ${esc(focusFilter)} <span class="clrfocus" id="clrFocus">all</span>`;
  else t.textContent = "Event Stream";
  const c = $("clrFocus"); if (c) c.onclick = clearFocus;
}
function renderStage() {
  const stage = $("centerStage");
  stage.className = "pbody stage";
  stage.innerHTML = '<div class="feed" id="feed"></div>';
  feedRendered = 0; renderFeed(); applyExpand();
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
  while (box.children.length > 450) box.removeChild(box.firstChild);
  if ($("autoscroll").checked && near) box.scrollTop = box.scrollHeight;
}

function renderFeed() {
  const box = $("feed"); if (!box) return;
  const filt = $("feedFilter").value.toLowerCase();
  const near = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
  const rows = S.feed.filter(l => (!focusFilter || l.ag === focusFilter)
    && (!filt || (l.ag+" "+l.text).toLowerCase().includes(filt))).slice(-450);
  box.innerHTML = rows.map(l => {
    const t = l.ts ? new Date(l.ts*1000).toLocaleTimeString("en-GB") : "";
    return `<div class="feedline k-${l.cls}"><span class="fts">${t}</span>`
      + `<span class="fag">${esc(l.ag)}</span><span class="ftx">${esc(l.text)}</span></div>`;
  }).join("");
  feedRendered = S.feed.length;  // DOM now reflects the whole buffer
  if ($("autoscroll").checked && near) box.scrollTop = box.scrollHeight;
}

function openModal(x) {
  seedProcessFromCandidate(x, isConfirmedLike(x) ? "confirmed" : "candidate");
  const rec = S.processes[processKeyFromCandidate(x)];
  const latest = rec?.latest || {};
  const health = processHealth(rec);
  const procCls = health.cls || processClass(latest.status);
  const procEvents = rec ? rec.events.slice(-32) : [];
  const isCurrent = (ev) => ev === latest || (
    Math.abs((ev.ts || 0) - (latest.ts || 0)) < 0.001
    && ev.stage === latest.stage
    && ev.status === latest.status
    && ev.agent === latest.agent
    && ev.target_agent === latest.target_agent
  );
  const eventRows = procEvents.map(ev => {
    const rowCls = processClass(ev.status);
    const cur = isCurrent(ev);
    const t = fmtClock(ev.ts);
    const stage = PIPELINE_STEPS[stepIndex(ev.stage, ev.status, ev.target_agent)]?.[1] || ev.stage || "PIPELINE";
    const status = [stage, ev.status].filter(Boolean).join(": ");
    const detail = ev.next_action || ev.blocked_by || ev.reason || ev.title || "";
    const emitter = AGENT(ev.agent || "");
    const owner = AGENT(ev.current_agent || ev.target_agent || "");
    const agentLabel = emitter && owner && emitter !== owner ? `${emitter} -> ${owner}` : (owner || emitter || "system");
    return `<div class="pevent ${rowCls}${cur ? " current" : ""}" ${cur ? 'id="currentProcessStep"' : ""}>`
      + `<span class="pet">${esc(t)}</span><span class="pea">${esc(agentLabel)}</span>`
      + `<span class="pestatus">${esc(status)}</span><span class="petxt">${esc(detail)}</span></div>`;
  }).join("");
  const loc = x.location || x.file || rec?.location || "";
  const stuckText = health.state === "stuck" ? "yes"
    : health.state === "quiet" ? "quiet"
    : health.state === "parked" ? "parked"
    : health.state === "blocked" ? "blocked"
    : health.state === "waiting" ? "waiting"
    : health.state === "routed" ? "routed"
    : health.state === "queued" ? "queued"
    : health.state === "working" ? "working"
    : "no";
  const owner = currentAgent(x, rec);
  const emitter = AGENT(latest.agent || pipelineOf(x).agent || "");
  const processBlock = rec ? `<section class="pfind ${procCls} modalprocess">`
    + `<div class="pfhead"><div><h3>${esc(rec.title || x.title || x.hyp || "")}</h3>${loc ? `<div class="pfloc">${esc(loc)}</div>` : ""}</div>`
    + `<button id="viewCurrentStep" class="pdetail">view current step</button></div>`
    + renderStepper(rec, false)
    + `<div class="pnow ${procCls}"><span>${esc(processSummary(rec))}</span>`
    + `<b>${esc(health.label)} · ${esc(owner || latest.status || "latest step")}</b></div>`
    + `<div class="procstats">`
    + `<div><span>current stage</span><b>${esc(health.stage)}</b></div>`
    + `<div><span>current agent</span><b>${esc(owner || "--")}</b></div>`
    + `<div><span>last event by</span><b>${esc(emitter || "--")}</b></div>`
    + `<div><span>in stage</span><b>${esc(fmtDur(health.stageAge))}</b></div>`
    + `<div><span>latest status</span><b>${esc(latest.status || "--")}</b></div>`
    + `<div><span>status age</span><b>${esc(fmtDur(health.statusAge))}</b></div>`
    + `<div><span>last update</span><b>${esc(fmtDur(health.lastAge))} ago</b></div>`
    + `<div><span>stuck?</span><b class="${esc(health.cls)}">${esc(stuckText)}</b></div>`
    + `<div><span>stage since</span><b>${esc(fmtClock(health.stageStart))}</b></div>`
    + `<div><span>why</span><b>${esc(health.reason || "--")}</b></div>`
    + `</div>`
    + `<div class="ptimeline">${eventRows || '<div class="muted">no process events yet</div>'}</div>`
    + `</section>` : "";
  const kv = (k, v) => v ? `<div class="kv"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>` : "";
  const p = x.pipeline || {};
  const variants = (x._variants || []).filter(v => findingKey(v) !== findingKey(x));
  const variantText = variants.map(v => {
    const vp = pipelineOf(v);
    const where = v.location || v.file || "";
    return `${v.dedup_key || "no-key"} · ${vp.stage || "pipeline"}:${vp.status || v.status || "unknown"} · ${v.title || v.hyp || ""}${where ? " · " + where : ""}`;
  }).join("\n");
  const controls = x.title ? `<div class="modalctl">
    <button data-agent="parent_a">Parent check-in</button>
    <button data-agent="poc_prover">PoC proof</button>
    <button data-agent="exploit_developer">Deep dive</button>
  </div>` : "";
  $("modalBody").innerHTML = `<h2>${esc(x.title||"")}</h2>` +
    processBlock +
    kv("LOCATION", loc) + kv("SEVERITY", x.severity) +
    kv("ROOT CAUSE", x.root_cause) + kv("COUNTERFACTUAL (attacker gains)", x.counterfactual) +
    kv("PIPELINE STAGE", p.stage) + kv("PIPELINE STATUS", p.status) +
    kv("PIPELINE LABEL", pipelineLabel(x)) + kv("TARGET AGENT", p.target_agent) +
    kv("NEXT ACTION", p.next_action) + kv("BLOCKED BY", p.blocked_by) + kv("PIPELINE REASON", p.reason) +
    kv("DUPLICATE VARIANTS", variantText) +
    kv("WHY UNPROVEN", x.why_unproven) + kv("REMEDIATION", x.remediation) + controls;
  const jump = $("viewCurrentStep");
  if (jump) jump.onclick = () => {
    const el = $("currentProcessStep");
    if (!el) return;
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    el.classList.add("flash");
    setTimeout(() => el.classList.remove("flash"), 1200);
  };
  document.querySelectorAll(".modalctl button").forEach(b => b.onclick = () => queueTriage(x, b.dataset.agent));
  $("modal").classList.add("open");
}

async function queueTriage(x, agent) {
  const action = agent === "poc_prover"
    ? "Materialize and run the smallest proof harness for this finding now."
    : agent === "exploit_developer"
      ? "Close the full attacker-win chain or return a precise blocker for this finding."
      : "Check this finding's pipeline state, explain the blocker, and route the next service now.";
  try {
    const res = await fetch("/api/control", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        eng: S.eng,
        kind: "triage",
        finding_key: x.dedup_key || "",
        title: x.title || x.hyp || "",
        target_agent: agent,
        action,
        message: "Queued from web dashboard candidate modal.",
      }),
    });
    const out = await res.json();
    const msg = out.ok ? `queued triage for ${agent}: ${x.title || x.hyp || ""}` : `triage failed: ${out.error || res.status}`;
    S.blackboard.unshift({ ts: Date.now() / 1000, agent: "operator", text: msg, cls: out.ok ? "up" : "rej" });
    panelsDirty = true;
  } catch (e) {
    S.blackboard.unshift({ ts: Date.now() / 1000, agent: "operator", text: `triage failed: ${e}`, cls: "rej" });
    panelsDirty = true;
  }
}

// ---- networking -----------------------------------------------------------
async function loadEngagements() {
  try {
    const list = await (await fetch("/api/engagements")).json();
    const sel = $("engSelect"), cur = S.eng;
    const ids = list.map(e => e.id);
    sel.innerHTML = list.map(e => `<option value="${esc(e.id)}">${e.running?"● ":"○ "}${esc(e.program)} `
      + `[${e.confirmed}P1 · ${e.candidates}c]</option>`).join("");
    if (!list.length) { S.eng = null; return; }
    if (!cur || !ids.includes(cur)) { switchEng(list[0].id); }
    else sel.value = cur;
  } catch (_) {}
}

async function loadSupervisor() {
  try {
    S.supervisor = await (await fetch("/api/supervisor")).json();
    panelsDirty = true;
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
    ingest([e]); if (!hasSelection()) appendFeedDelta(); panelsDirty = true;
    evTimes.push(Date.now()); S.lastRx = Date.now();
  };
  es.addEventListener("findings", (m) => { try { mergeFindingState(JSON.parse(m.data)); panelsDirty = true; } catch (_) {} });
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
  $("footstat").textContent = live ? "ENGAGEMENT LIVE" : "ENGAGEMENT IDLE / COMPLETE";
}

function switchEng(id) {
  S.eng = id; S.offset = 0; S.feed = []; feedRendered = 0; S.agents = {}; S.debate = []; S.dedup = []; S.blackboard = []; S.processes = {};
  S.tokens = { total: 0, cost: 0 }; S.settings = {}; S.stats = {}; S.models = {};
  S.findings = { confirmed_criticals: [], needs_human_review: [], candidates: [] };
  for (const k in rosterRows) delete rosterRows[k];   // drop cached rows from the prior engagement
  $("roster").innerHTML = "";
  renderStage(); panelsDirty = true; render(); connect();
}

// ---- boot -----------------------------------------------------------------
$("engSelect").onchange = (e) => switchEng(e.target.value);
$("pauseScanBtn").onclick = () => queueRunControl("pause");
$("resumeScanBtn").onclick = () => queueRunControl("resume");
$("stopScanBtn").onclick = () => queueRunControl("stop");
$("feedFilter").oninput = renderFeed;   // rebuilds the feed for the filter + resyncs the append pointer
$("modalClose").onclick = () => $("modal").classList.remove("open");
$("modal").onclick = (e) => { if (e.target === $("modal")) $("modal").classList.remove("open"); };
// EXPAND: global toggle (button) + per-line click to expand just one line.
$("expandBtn").onclick = () => {
  expandAll = !expandAll;
  $("expandBtn").classList.toggle("on", expandAll);
  $("expandBtn").textContent = expandAll ? "Collapse" : "Expand";
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
  appendFeedDelta();  // flush any feed lines that queued while selecting
  if (panelsDirty) { panelsDirty = false; render(); }
  setConn(S.running);
}, 320);

(async function () {
  await loadEngagements();
  await loadSupervisor();
  if (!es) connect();
  setInterval(loadEngagements, 8000);
  setInterval(loadSupervisor, 8000);
})();
