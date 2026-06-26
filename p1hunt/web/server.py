"""Stdlib HTTP server for the P1HUNT Threat Operations Center (loopback).

Endpoints:
  GET /                         -> the dashboard (static/index.html)
  GET /app.css /app.js          -> static assets
  GET /api/engagements          -> [{id, program, mtime, confirmed, candidates, running}]
  GET /api/supervisor           -> autopilot heartbeat/status from autopilot_state.json
  GET /api/tail?eng=ID&offset=N -> {offset, events:[{ts,agent,kind,data}], findings, running}
  POST /api/control             -> append a live control directive to an engagement control.jsonl
  POST /api/session-limit-check -> clear the shared session gate if the cooldown/reset has passed

The UI does all aggregation/formatting client-side from the raw event stream, so the server stays
thin: it tails ``events.jsonl`` from a byte offset, ships ``findings.json``, and appends explicit
operator/Parent-A control directives to ``control.jsonl``. Bind address defaults to 127.0.0.1.
"""

from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

_STATIC = Path(__file__).parent / "static"
# Cap how much of events.jsonl we ship to the browser in one tail (bytes). Keep this small: SSE
# sends one event per JSONL row, so a multi-MB initial backlog can make the page look frozen even
# though the server is alive.
_MAX_TAIL_BYTES = int(os.environ.get("P1HUNT_WEB_TAIL_BYTES", "131072"))
_MAX_TAIL_EVENTS = int(os.environ.get("P1HUNT_WEB_TAIL_EVENTS", "300"))
# Backend aggregation can scan a larger recent window because it does not stream every row to the UI.
_MAX_SCAN_BYTES = int(os.environ.get("P1HUNT_WEB_SCAN_BYTES", "4000000"))
_RUNNING_WINDOW_S = 90.0  # events.jsonl touched within this window => engagement is "live"


def _engagements_root() -> Path:
    return Path(os.environ.get("P1HUNT_ENGAGEMENTS", "engagements"))


def _web_engagement_filter() -> set[str]:
    raw = os.environ.get("P1HUNT_WEB_ENGAGEMENTS", "")
    return {p.strip() for p in raw.split(",") if p.strip()}


def _engagement_visible(name: str) -> bool:
    allowed = _web_engagement_filter()
    return not allowed or name in allowed


def _safe_eng_dir(eng: str) -> Path | None:
    """Resolve an engagement id to its folder, refusing any path escape."""
    root = _engagements_root().resolve()
    if not eng:
        return None
    cand = (root / eng).resolve()
    try:
        cand.relative_to(root)
    except ValueError:
        return None
    if not _engagement_visible(cand.name):
        return None
    return cand if (cand / "events.jsonl").exists() else None


def _recent_event_candidate_count(ev: Path) -> int:
    """Count distinct live-posted findings in the recent event tail.

    Active scans may post findings to events.jsonl well before findings.json is materialized at
    a round boundary or final report write. This keeps the dashboard honest during that window.
    """
    try:
        size = ev.stat().st_size
        start = max(0, size - _MAX_SCAN_BYTES)
        keys: set[tuple[str, str, str, str]] = set()
        with ev.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(start)
            if start:
                fh.readline()  # discard a possible partial first line
            for line in fh:
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if doc.get("kind") != "finding_reported":
                    continue
                data = doc.get("data") or {}
                if isinstance(data.get("finding"), dict):
                    data = data["finding"]
                title = str(data.get("title") or data.get("hyp") or "")
                if not title:
                    continue
                keys.add((
                    title.lower(),
                    str(data.get("severity") or "").lower(),
                    str(data.get("location") or data.get("file") or "").lower(),
                    str(data.get("endpoint") or data.get("url") or "").lower(),
                ))
        return len(keys)
    except OSError:
        return 0


def _finding_key(x: dict) -> tuple[str, str, str, str]:
    return (
        str(x.get("title") or x.get("hyp") or "").lower(),
        str(x.get("severity") or "").lower(),
        str(x.get("location") or x.get("file") or "").lower(),
        str(x.get("endpoint") or x.get("url") or "").lower(),
    )


def _finding_id(x: dict):
    return str(x.get("dedup_key") or "").strip() or _finding_key(x)


def _is_low_priority_candidate(x: dict) -> bool:
    return str(x.get("severity") or "").strip().lower() in {"low", "informational", "info"}


_STATUS_RANK = {
    "refuted": -30,
    "rejected": -30,
    "debate_rejected": -30,
    "attribution_blocked": -20,
    "posted": 1,
    "live_candidate": 1,
    "selected_for_verification": 2,
    "running": 3,
    "unverified": 4,
    "real": 8,
    "not_reproduced": 9,
    "autonomous_followup": 10,
    "harness_materialized": 11,
    "reproduced": 14,
    "reproduced_pending_deepdive": 15,
    "reproduced_pending_debate": 16,
    "exploit_confirmed_pending_debate": 18,
    "debate_upheld": 19,
    "upheld": 19,
    "confirmed": 20,
    "confirmed_critical_reproduced": 22,
}


def _status_rank(status: str) -> int:
    s = str(status or "").strip().lower()
    if s in _STATUS_RANK:
        return _STATUS_RANK[s]
    if "confirmed" in s:
        return 20
    if "reproduced" in s and "not_" not in s:
        return 14
    return 0


def _current_agent(row: dict) -> str:
    """Return the agent currently expected to advance this candidate."""
    return str(
        row.get("current_agent")
        or row.get("target_agent")
        or row.get("owner_agent")
        or row.get("agent")
        or ""
    )


def _history_key_for_status(data: dict) -> str:
    """Stable key used to correlate lifecycle rows with candidate cards.

    Newer events carry ``dedup_key``. Older/manual records sometimes only have a title, so keep a
    title fallback instead of dropping their status history from first-load web snapshots.
    """
    key = str(data.get("dedup_key") or "").strip()
    if key:
        return key
    title = str(data.get("title") or data.get("hyp") or "").strip().lower()
    return "title:" + title if title else ""


def _normalize_pipeline(doc: dict, *, confirmed: bool = False) -> dict:
    """Pick the strongest meaningful pipeline state for a candidate.

    Live blackboard posts can arrive after an operator-confirmed record for the same title, and the
    old merge logic let the later "posted" event visually demote an already-confirmed candidate.
    The UI should show the highest-confidence state, with the raw history still available.
    """
    pipe = doc.get("pipeline") if isinstance(doc.get("pipeline"), dict) else {}
    hist = [h for h in (pipe.get("history") or []) if isinstance(h, dict)]
    cur = {
        "stage": pipe.get("stage") or doc.get("stage") or "",
        "status": pipe.get("status") or doc.get("status") or "",
        "target_agent": pipe.get("target_agent") or "",
        "agent": pipe.get("agent") or doc.get("source_agent") or doc.get("agent") or "",
        "next_action": pipe.get("next_action") or "",
        "blocked_by": pipe.get("blocked_by") or "",
        "reason": pipe.get("reason") or "",
        "updated_ts": pipe.get("updated_ts") or doc.get("last_seen_ts") or doc.get("ts"),
    }
    if cur["status"]:
        hist.append(cur)
    if confirmed:
        hist.append({
            "stage": "parent_a",
            "status": "confirmed_critical_reproduced",
            "target_agent": "parent_a",
            "agent": "parent_a",
            "next_action": "Confirmed critical is already in the report lane.",
            "blocked_by": "",
            "reason": doc.get("counterfactual") or doc.get("root_cause") or "",
            "updated_ts": doc.get("last_seen_ts") or doc.get("ts"),
        })
    if not hist:
        return pipe
    ordered: list[dict] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for h in sorted(hist, key=lambda x: float(x.get("updated_ts") or x.get("ts") or 0)):
        k = (
            str(h.get("updated_ts") or h.get("ts") or ""),
            str(h.get("stage") or ""),
            str(h.get("status") or ""),
            str(h.get("target_agent") or ""),
            str(h.get("agent") or ""),
            str(h.get("blocked_by") or ""),
        )
        if k in seen:
            continue
        seen.add(k)
        ordered.append(h)
    hist = ordered
    best = max(
        hist,
        key=lambda h: (_status_rank(str(h.get("status") or "")), float(h.get("updated_ts") or h.get("ts") or 0)),
    )
    current = max(hist, key=lambda h: float(h.get("updated_ts") or h.get("ts") or 0))
    out = dict(pipe)
    out.update({
        "stage": best.get("stage", ""),
        "status": best.get("status", ""),
        "target_agent": best.get("target_agent", ""),
        "agent": best.get("agent", ""),
        "next_action": best.get("next_action", ""),
        "blocked_by": best.get("blocked_by", ""),
        "reason": best.get("reason", ""),
        "updated_ts": best.get("updated_ts") or best.get("ts"),
        "current": {
            "stage": current.get("stage", ""),
            "status": current.get("status", ""),
            "target_agent": current.get("target_agent", ""),
            "agent": current.get("agent", ""),
            "next_action": current.get("next_action", ""),
            "blocked_by": current.get("blocked_by", ""),
            "reason": current.get("reason", ""),
            "updated_ts": current.get("updated_ts") or current.get("ts"),
        },
        "current_agent": _current_agent(current),
        "history": hist[-20:],
    })
    return out


def _root_key(x: dict) -> str:
    """Coarse key for grouping duplicate-looking cards in the UI."""
    title = str(x.get("title") or x.get("hyp") or "").strip().lower()
    root = str(x.get("root_cause") or "").strip().lower()
    loc = str(x.get("location") or x.get("file") or "").strip().lower().split(":")[0]
    return "\x1f".join(p for p in (title, root or loc) if p)


def _event_finding_payload(doc: dict) -> dict | None:
    """Return a dashboard candidate from a live blackboard/finding event, if any."""
    kind = doc.get("kind")
    data = doc.get("data") or {}
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("finding"), dict):
        data = data["finding"]
    elif kind not in ("finding_reported", "finding"):
        return None
    if kind == "finding" and data.get("event"):
        return None
    title = str(data.get("title") or data.get("hyp") or "").strip()
    if not title:
        return None
    out = dict(data)
    out.setdefault("title", title)
    out.setdefault("severity", "candidate")
    out.setdefault("source_agent", doc.get("agent", ""))
    out.setdefault("live", True)
    if doc.get("ts") is not None:
        out.setdefault("ts", doc.get("ts"))
    return out


def _activity_from_events(ev: Path, limit: int = 160) -> dict:
    """Summarize retained event activity for panels that must be useful on first load.

    The browser's debate/dedup panels used to start empty unless those events arrived after the page
    opened. This bounded scan reconstructs the current retained logs and agent roster hints.
    """
    agents: dict[str, dict] = {}
    debate: list[dict] = []
    dedup: list[dict] = []
    statuses: dict[str, dict] = {}
    status_history: dict[str, list[dict]] = {}
    try:
        size = ev.stat().st_size
        start = max(0, size - _MAX_SCAN_BYTES)
        with ev.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(start)
            if start:
                fh.readline()
            for line in fh:
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    continue
                agent = str(doc.get("agent") or "")
                ts = doc.get("ts")
                if agent:
                    base = agent.split(".")[0].split(":")[0]
                    rec = agents.setdefault(base, {"agent": base, "last_ts": 0, "events": 0})
                    rec["events"] += 1
                    try:
                        rec["last_ts"] = max(float(rec.get("last_ts") or 0), float(ts or 0))
                    except (TypeError, ValueError):
                        pass
                kind = doc.get("kind")
                data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
                event = str(data.get("event") or "")
                if kind == "lifecycle" and event == "candidate_status":
                    k = _history_key_for_status(data)
                    if k:
                        cand_status = {
                            "stage": data.get("stage", ""),
                            "status": data.get("status", ""),
                            "target_agent": data.get("target_agent", ""),
                            "agent": agent,
                            "next_action": data.get("next_action", ""),
                            "blocked_by": data.get("blocked_by", ""),
                            "reason": data.get("reason", ""),
                            "title": data.get("title", ""),
                            "updated_ts": ts,
                        }
                        status_history.setdefault(k, []).append(cand_status)
                        cur = statuses.get(k)
                        if cur is None or _status_rank(cand_status["status"]) >= _status_rank(str(cur.get("status") or "")):
                            statuses[k] = cand_status
                    continue
                if kind == "lifecycle" and event == "duplicate_dropped":
                    dedup.append({
                        "ts": ts, "cls": "", "text": f"duplicate of #{data.get('of') or '?'} dropped - {data.get('reason') or ''}",
                    })
                if kind == "message" and "duplicate" in str(data.get("verdict", "")).lower():
                    dedup.append({
                        "ts": ts, "cls": "", "text": f"{data.get('verdict')}: {data.get('title') or data.get('reason') or ''}",
                    })
                if kind in ("message", "lifecycle") and (
                    event.startswith("debate_") or str(data.get("verdict", "")).startswith("debate")
                    or data.get("phase") == "debate"
                ):
                    label = event or data.get("verdict") or "debate"
                    title = data.get("title") or data.get("reason") or ""
                    cls = "up" if "upheld" in str(label) else "down" if "downgrad" in str(label) else "rej" if "reject" in str(label) else ""
                    debate.append({"ts": ts, "cls": cls, "text": f"{label}: {title}"})
    except OSError:
        pass
    return {
        "agents": sorted(agents.values(), key=lambda x: x.get("agent", "")),
        "debate": debate[-limit:],
        "dedup": dedup[-limit:],
        "candidate_status": statuses,
        "candidate_history": {k: v[-40:] for k, v in status_history.items()},
    }


def _recent_event_findings(ev: Path, limit: int = 120) -> list[dict]:
    """Read live finding/blackboard posts from the bounded event tail."""
    try:
        size = ev.stat().st_size
        start = max(0, size - _MAX_SCAN_BYTES)
        merged: dict[object, dict] = {}
        order: list[object] = []
        status_by_key: dict[str, dict] = {}
        with ev.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(start)
            if start:
                fh.readline()  # discard a possible partial first line
            for line in fh:
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    continue
                data = doc.get("data") or {}
                if doc.get("kind") == "lifecycle" and isinstance(data, dict) and data.get("event") == "candidate_status":
                    k = _history_key_for_status(data)
                    if k:
                        status_by_key[k] = {
                            "stage": data.get("stage", ""),
                            "status": data.get("status", ""),
                            "target_agent": data.get("target_agent", ""),
                            "agent": doc.get("agent", ""),
                            "next_action": data.get("next_action", ""),
                            "blocked_by": data.get("blocked_by", ""),
                            "reason": data.get("reason", ""),
                            "updated_ts": doc.get("ts"),
                        }
                    continue
                cand = _event_finding_payload(doc)
                if not cand:
                    continue
                key = _finding_id(cand)
                if isinstance(key, tuple) and not key[0]:
                    continue
                if key not in merged:
                    order.append(key)
                merged[key] = cand
        for k, status in status_by_key.items():
            if k in merged:
                merged[k]["pipeline"] = status
                continue
            if k.startswith("title:"):
                want = k.removeprefix("title:")
                for cand in merged.values():
                    title = str(cand.get("title") or cand.get("hyp") or "").strip().lower()
                    if title == want:
                        cand["pipeline"] = status
                        break
        return [merged[k] for k in order][-limit:]
    except OSError:
        return []


def _load_candidate_file(path: Path) -> list[dict]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(doc, dict):
        return []
    cands = doc.get("candidates")
    return [c for c in cands if isinstance(c, dict)] if isinstance(cands, list) else []


def _read_findings_doc(eng_dir: Path) -> dict | None:
    """Load findings.json and merge live blackboard candidates from events.jsonl.

    Older running scans only flush ``findings.json`` at round boundaries. The event stream can have
    newer ``finding_reported`` posts, so every API response that carries findings must merge the two
    sources or the UI will show correct counts but blank/stale candidate cards.
    """
    fj = eng_dir / "findings.json"
    doc: dict = {}
    if fj.is_file():
        try:
            loaded = json.loads(fj.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                doc = loaded
        except (OSError, ValueError):
            doc = {}
    if not doc:
        doc = {"program": eng_dir.name, "confirmed_criticals": [], "needs_human_review": [],
               "candidates": [], "counts": {}}
    confirmed = doc.get("confirmed_criticals")
    needs_human = doc.get("needs_human_review")
    existing = doc.get("candidates")
    if not isinstance(confirmed, list):
        confirmed = []
    if not isinstance(needs_human, list):
        needs_human = []
    if not isinstance(existing, list):
        existing = []

    ev = eng_dir / "events.jsonl"
    activity = _activity_from_events(ev)

    normalized_confirmed: list[dict] = []
    confirmed_roots: set[str] = set()
    for item in confirmed:
        if not isinstance(item, dict):
            continue
        c = dict(item)
        c["pipeline"] = _normalize_pipeline(c, confirmed=True)
        rk = _root_key(c)
        if rk:
            confirmed_roots.add(rk)
        normalized_confirmed.append(c)

    normalized_needs_human = []
    for item in needs_human:
        if isinstance(item, dict):
            c = dict(item)
            c["pipeline"] = _normalize_pipeline(c)
            normalized_needs_human.append(c)

    merged: dict[object, dict] = {}
    live = _load_candidate_file(eng_dir / "live_findings.json")
    for cand in [*existing, *live, *_recent_event_findings(ev)]:
        if not isinstance(cand, dict):
            continue
        cand = dict(cand)
        key = _finding_id(cand)
        if isinstance(key, tuple) and not key[0]:
            continue
        pipe = cand.get("pipeline") if isinstance(cand.get("pipeline"), dict) else {}
        hist = [h for h in (pipe.get("history") or []) if isinstance(h, dict)]
        k = str(cand.get("dedup_key") or "").strip()
        title_key = _history_key_for_status(cand)
        status_key = k if k and k in activity.get("candidate_status", {}) else title_key
        if status_key and status_key in activity.get("candidate_status", {}):
            hist.extend(activity.get("candidate_history", {}).get(k, []))
            if status_key != k:
                hist.extend(activity.get("candidate_history", {}).get(status_key, []))
            if not hist:
                hist.append(activity["candidate_status"][status_key])
            pipe = {**pipe, "history": hist, **activity["candidate_status"][status_key]}
            cand["pipeline"] = pipe
        prev = merged.get(key, {})
        merged[key] = {**prev, **cand}

    normalized_candidates: list[dict] = []
    for cand in merged.values():
        status = ""
        if isinstance(cand.get("pipeline"), dict):
            status = str(cand["pipeline"].get("status") or "")
        status = status or str(cand.get("status") or "")
        confirmed_like = _root_key(cand) in confirmed_roots or _status_rank(status) >= _status_rank("confirmed")
        c = dict(cand)
        c["pipeline"] = _normalize_pipeline(c, confirmed=confirmed_like)
        if confirmed_like:
            c["already_confirmed"] = True
        normalized_candidates.append(c)

    if normalized_confirmed and not activity.get("debate"):
        activity["debate"] = [{
            "ts": None,
            "cls": "down",
            "text": "No debate events retained or recorded for the confirmed critical; current state came from findings.json/operator confirmation.",
        }]
    if normalized_candidates and not activity.get("dedup"):
        root_counts: dict[str, int] = {}
        for c in normalized_candidates:
            rk = _root_key(c)
            if rk:
                root_counts[rk] = root_counts.get(rk, 0) + 1
        dupes = sum(1 for n in root_counts.values() if n > 1)
        if dupes:
            activity["dedup"] = [{
                "ts": None,
                "cls": "",
                "text": f"{dupes} duplicate-looking candidate group(s) reconstructed from finding titles/root causes.",
            }]

    doc["confirmed_criticals"] = normalized_confirmed
    doc["needs_human_review"] = normalized_needs_human
    doc["candidates"] = normalized_candidates[-120:]
    actionable_keys: set[object] = set()
    low_priority_keys: set[object] = set()
    for c in doc["candidates"]:
        if c.get("already_confirmed"):
            continue
        key = _root_key(c) or _finding_id(c)
        if _is_low_priority_candidate(c):
            low_priority_keys.add(key)
            continue
        actionable_keys.add(key)
    raw_candidate_count = len(doc["candidates"])
    actionable_count = len(actionable_keys)
    doc["counts"] = {
        "confirmed_critical": len(normalized_confirmed),
        "needs_human_review": len(normalized_needs_human),
        "candidates": actionable_count,
        "actionable_candidates": actionable_count,
        "low_priority_candidates": len(low_priority_keys),
        "raw_candidates": raw_candidate_count,
    }
    doc["activity"] = {
        "agents": activity.get("agents", []),
        "debate": activity.get("debate", []),
        "dedup": activity.get("dedup", []),
        "candidate_history": activity.get("candidate_history", {}),
    }
    return doc


def _pid_alive(pid: int | None) -> bool | None:
    if not pid:
        return None
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None


def _process_info(d: Path, ev: Path, running: bool) -> dict:
    info: dict = {
        "last_event_age_s": round(max(0.0, time.time() - ev.stat().st_mtime), 1),
        "event_log_size": ev.stat().st_size,
    }
    proc = d / "process.json"
    if proc.is_file():
        try:
            doc = json.loads(proc.read_text(encoding="utf-8"))
            pid = int(doc.get("pid") or 0) or None
            info.update({
                "pid": pid,
                "process_kind": doc.get("kind", ""),
                "started_ts": doc.get("started_ts"),
                "report_path": doc.get("report_path", ""),
                "process_alive": _pid_alive(pid),
            })
        except (OSError, ValueError, TypeError):
            pass
    else:
        info["process_alive"] = None
    info["health"] = "running" if (info.get("process_alive") is True or running) else "stopped"
    return info


def _list_engagements() -> list[dict]:
    root = _engagements_root()
    out: list[dict] = []
    if not root.exists():
        return out
    for d in root.iterdir():
        ev = d / "events.jsonl"
        if not ev.is_file() or not _engagement_visible(d.name):
            continue
        program, confirmed, candidates = d.name, 0, 0
        fj = d / "findings.json"
        doc = _read_findings_doc(d)
        if doc:
            program = doc.get("program", d.name)
            c = doc.get("counts", {})
            confirmed = c.get("confirmed_critical", 0)
            candidates = c.get("actionable_candidates", c.get("candidates", 0))
        mtime = ev.stat().st_mtime
        event_recent = (time.time() - mtime) < _RUNNING_WINDOW_S
        if candidates == 0:
            candidates = max(candidates, _recent_event_candidate_count(ev))
        meta = _process_info(d, ev, event_recent)
        if meta.get("process_alive") is False:
            running = False
            meta["health"] = "stopped"
        elif meta.get("process_alive") is True:
            running = True
            meta["health"] = "running"
        else:
            running = event_recent
        out.append({"id": d.name, "program": program, "mtime": mtime,
                    "confirmed": confirmed, "candidates": candidates,
                    "running": running, **meta})
    out.sort(key=lambda x: (
        0 if x.get("running") or x.get("process_alive") is True else 1,
        -float(x.get("mtime") or 0),
    ))
    return out


def _supervisor_status() -> dict:
    root = _engagements_root()
    doc: dict = {}
    state_path = root / "autopilot_state.json"
    if state_path.is_file():
        try:
            loaded = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                doc = loaded
        except (OSError, ValueError):
            doc = {}
    sup = doc.get("supervisor") if isinstance(doc.get("supervisor"), dict) else {}
    session_limit = _supervisor_session_limit(root, doc)
    sweeper = _supervisor_candidate_sweeper(doc)
    pid = None
    try:
        pid = int(sup.get("pid") or 0) or None
    except (TypeError, ValueError):
        pid = None
    updated = None
    try:
        updated = float(sup.get("updated_ts") or doc.get("updated_ts") or 0) or None
    except (TypeError, ValueError):
        updated = None
    return {
        "configured": bool(sup),
        "pid": pid,
        "process_alive": _pid_alive(pid),
        "last_heartbeat_ts": updated,
        "last_heartbeat_age_s": round(max(0.0, time.time() - updated), 1) if updated else None,
        "engagements": sup.get("engagements") if isinstance(sup.get("engagements"), list) else sorted(_web_engagement_filter()),
        "interval_s": sup.get("interval_s"),
        "candidate_stale_s": sup.get("candidate_stale_s"),
        "hunt_stale_s": sup.get("hunt_stale_s"),
        "triage_cooldown_s": sup.get("triage_cooldown_s"),
        "session_probe_s": sup.get("session_probe_s"),
        "resume_hunts": sup.get("resume_hunts"),
        "supervise_web": sup.get("supervise_web"),
        "web": sup.get("web") if isinstance(sup.get("web"), dict) else {},
        "session_limit": session_limit,
        "candidate_sweeper": sweeper,
        "state_path": str(state_path),
    }


def _supervisor_candidate_sweeper(doc: dict) -> dict:
    states: list[dict] = []
    engagements = doc.get("engagements") if isinstance(doc.get("engagements"), dict) else {}
    wanted = _web_engagement_filter()
    for name, eng_state in engagements.items():
        if wanted and name not in wanted:
            continue
        if not isinstance(eng_state, dict):
            continue
        sw = eng_state.get("candidate_sweeper")
        if isinstance(sw, dict):
            row = dict(sw)
            row["engagement"] = name
            states.append(row)
    if not states:
        return {}
    states.sort(key=lambda x: float(x.get("last_run_ts") or 0), reverse=True)
    return states[0]


def _supervisor_session_limit(root: Path, doc: dict) -> dict:
    states: list[dict] = []
    engagements = doc.get("engagements") if isinstance(doc.get("engagements"), dict) else {}
    for name, eng_state in engagements.items():
        if not _engagement_visible(str(name)) or not isinstance(eng_state, dict):
            continue
        sess = eng_state.get("session_limit")
        if isinstance(sess, dict):
            states.append(sess)
    if states:
        return max(states, key=lambda s: float(s.get("last_probe_ts") or s.get("last_limit_event_ts") or s.get("at") or 0))
    try:
        visible = [
            p for p in root.iterdir()
            if p.is_dir() and (p / "events.jsonl").is_file() and _engagement_visible(p.name)
        ]
    except OSError:
        visible = []
    visible.sort(key=lambda p: (p / "events.jsonl").stat().st_mtime if (p / "events.jsonl").is_file() else 0, reverse=True)
    try:
        from ..session_limit import session_limit_state
        return session_limit_state(visible[0] if visible else None)
    except Exception as exc:
        return {"error": str(exc)}


def _tail(eng_dir: Path, offset: int) -> dict:
    ev = eng_dir / "events.jsonl"
    size = ev.stat().st_size
    if offset <= 0 or offset > size:
        # First load (or rotated): jump near the end so the page paints fast, not from byte 0.
        offset = max(0, size - _MAX_TAIL_BYTES)
    events: list[dict] = []
    try:
        with ev.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            chunk = fh.read(_MAX_TAIL_BYTES)
            new_offset = fh.tell()
        # Drop a possible partial last line (no trailing newline yet).
        lines = chunk.split("\n")
        if chunk and not chunk.endswith("\n"):
            partial = lines.pop()
            new_offset -= len(partial.encode("utf-8", "replace"))
        for ln in lines[-_MAX_TAIL_EVENTS:]:
            ln = ln.strip()
            if ln:
                try:
                    events.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
    except OSError:
        new_offset = offset
    findings = _read_findings_doc(eng_dir)
    if findings and isinstance(findings.get("candidates"), list):
        findings["candidates"] = findings["candidates"][-60:]
    running = (time.time() - ev.stat().st_mtime) < _RUNNING_WINDOW_S
    return {"offset": new_offset, "events": events, "findings": findings, "running": running}


_CT = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
       ".js": "application/javascript; charset=utf-8", ".svg": "image/svg+xml"}


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def _static(self, name: str) -> None:
        p = (_STATIC / name).resolve()
        try:
            p.relative_to(_STATIC.resolve())
        except ValueError:
            return self._send(403, b"forbidden", "text/plain")
        if not p.is_file():
            return self._send(404, b"not found", "text/plain")
        self._send(200, p.read_bytes(), _CT.get(p.suffix, "application/octet-stream"))

    def _stream(self, eng_dir: Path, offset: int) -> None:
        """Server-Sent Events: push each new line of events.jsonl in ~real time, plus findings.json
        when it changes. Each line carries ``id:`` = the byte offset AFTER it, so an EventSource
        reconnect (Last-Event-ID) resumes exactly where it left off — no gaps, no replays."""
        ev = eng_dir / "events.jsonl"
        fj = eng_dir / "findings.json"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")  # disable any proxy buffering
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

        def w(s: str) -> None:
            self.wfile.write(s.encode("utf-8", "replace"))
            self.wfile.flush()

        try:
            size = ev.stat().st_size
            if offset <= 0 or offset > size:
                offset = max(0, size - _MAX_TAIL_BYTES)  # first paint: jump near the tail
            last_fmtime: float | None = None
            idle = 0
            while True:
                cur = ev.stat().st_size
                if cur > offset:
                    with ev.open("r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(offset)
                        chunk = fh.read(min(cur - offset, _MAX_TAIL_BYTES))
                    parts = chunk.split("\n")
                    pos = offset
                    for ln in parts[:-1]:  # last element is "" (complete) or a partial line — skip it
                        pos += len((ln + "\n").encode("utf-8", "replace"))
                        s = ln.strip()
                        if s:
                            w(f"id: {pos}\ndata: {s}\n\n")
                    offset = pos
                    idle = 0
                else:
                    idle += 1
                try:  # ship findings.json/live finding snapshot initially and when it changes
                    m = fj.stat().st_mtime if fj.is_file() else 0.0
                    if last_fmtime is None or m > last_fmtime:
                        last_fmtime = m
                        doc = _read_findings_doc(eng_dir) or {}
                        if isinstance(doc.get("candidates"), list):
                            doc["candidates"] = doc["candidates"][-60:]
                        w("event: findings\ndata: " + json.dumps(doc) + "\n\n")
                except (OSError, ValueError):
                    pass
                running = (time.time() - ev.stat().st_mtime) < _RUNNING_WINDOW_S
                w(f"event: meta\ndata: {{\"running\":{str(running).lower()},\"offset\":{offset}}}\n\n")
                w(": ping\n\n")  # keep-alive
                time.sleep(0.4)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return  # client disconnected — end the stream thread

    def do_GET(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path
        if path == "/" or path == "/index.html":
            return self._static("index.html")
        if path in ("/app.css", "/app.js"):
            return self._static(path.lstrip("/"))
        if path == "/api/engagements":
            return self._json(_list_engagements())
        if path == "/api/supervisor":
            return self._json(_supervisor_status())
        if path == "/api/stream":
            eng_dir = _safe_eng_dir(q.get("eng", [""])[0])
            if eng_dir is None:
                return self._json({"error": "unknown engagement"}, 404)
            lei = self.headers.get("Last-Event-ID")  # browser resume marker (byte offset)
            try:
                offset = int(lei) if lei is not None else int(q.get("offset", ["0"])[0])
            except ValueError:
                offset = 0
            return self._stream(eng_dir, offset)
        if path == "/api/tail":
            eng = (q.get("eng", [""])[0])
            eng_dir = _safe_eng_dir(eng)
            if eng_dir is None:
                return self._json({"error": "unknown engagement"}, 404)
            try:
                offset = int(q.get("offset", ["0"])[0])
            except ValueError:
                offset = 0
            return self._json(_tail(eng_dir, offset))
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        if u.path not in ("/api/control", "/api/session-limit-check"):
            return self._send(404, b"not found", "text/plain")
        try:
            n = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            n = 0
        if n > 64_000 or (n <= 0 and u.path == "/api/control"):
            return self._json({"error": "invalid body"}, 400)
        data = {}
        try:
            if n > 0:
                body = self.rfile.read(n).decode("utf-8", "replace")
                data = json.loads(body)
        except (OSError, ValueError):
            return self._json({"error": "invalid json"}, 400)
        if not isinstance(data, dict):
            return self._json({"error": "invalid json"}, 400)
        if u.path == "/api/session-limit-check":
            eng_dir = _safe_eng_dir(str(data.get("eng") or ""))
            if data.get("eng") and eng_dir is None:
                return self._json({"error": "unknown engagement"}, 404)
            try:
                from ..session_limit import jumpstart_if_clear
                out = jumpstart_if_clear(
                    eng_dir,
                    force=bool(data.get("force")),
                    note="web supervisor session-limit check",
                )
            except Exception as exc:
                return self._json({"error": str(exc)}, 500)
            return self._json({"ok": True, **out})
        eng_dir = _safe_eng_dir(str(data.get("eng") or ""))
        if eng_dir is None:
            return self._json({"error": "unknown engagement"}, 404)
        kind = str(data.get("kind") or "triage").strip() or "triage"
        if kind not in ("notify", "triage", "pause", "resume", "stop", "reload", "hot_reload"):
            return self._json({"error": "unsupported kind"}, 400)
        rec = {
            "kind": "reload" if kind == "hot_reload" else kind,
            "message": str(data.get("message") or "")[:2000],
            "paths": [str(p).strip() for p in (data.get("paths") or []) if str(p).strip()][:20],
        }
        if kind in ("pause", "resume", "stop"):
            rec["source"] = "web"
        if kind in ("reload", "hot_reload"):
            rec["modules"] = [
                str(m).strip() for m in (data.get("modules") or [])
                if str(m).strip().startswith("p1hunt.")
            ][:30]
        if kind == "triage":
            rec.update({
                "finding_key": str(data.get("finding_key") or "")[:120],
                "title": str(data.get("title") or "")[:300],
                "target_agent": str(data.get("target_agent") or "parent_a")[:80],
                "action": str(data.get("action") or "prioritize verifier/prover/deep-dive now")[:1000],
            })
            if data.get("source_agent"):
                rec["source_agent"] = str(data.get("source_agent") or "")[:80]
            if not rec["finding_key"] and not rec["title"]:
                return self._json({"error": "triage requires finding_key or title"}, 400)
        ctrl = eng_dir / "control.jsonl"
        try:
            with ctrl.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
        except OSError as exc:
            return self._json({"error": str(exc)}, 500)
        return self._json({"ok": True, "directive": rec})

    def log_message(self, *_a) -> None:  # silence default access log
        return


def serve(host: str = "127.0.0.1", port: int = 8787) -> int:
    """Run the dashboard until Ctrl-C. Returns a process exit code."""
    root = _engagements_root()
    srv = ThreadingHTTPServer((host, port), _Handler)
    print("\n  P1HUNT // THREAT OPERATIONS CENTER")
    print(f"  ├─ engagements : {root.resolve()}")
    print(f"  ├─ serving     : http://{host}:{port}")
    print("  └─ viewer + control queue · loopback · Ctrl-C to stop\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  shutting down…")
    finally:
        srv.server_close()
    return 0
