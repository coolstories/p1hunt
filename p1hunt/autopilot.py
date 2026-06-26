"""Autonomous operations loop for P1HUNT engagements.

This is deliberately not a new detector. It is the missing operations layer: keep the dashboard
available, keep saved hunts moving, and keep promising candidates from sitting in an unowned state.
Rate-limit/account rotation is intentionally out of scope here; the model sessions already handle
their own cooldown behavior. Autopilot does own the operator-facing recovery loop: when a shared
session-limit gate is active, it records status and periodically clears the gate once the reset
window has passed.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .session_limit import jumpstart_if_clear, session_limit_state


_HIGH_SEV = {"critical", "high"}
_LOW_PRIORITY_SEV = {"low", "informational", "info"}
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "info": 1}
_SWEEPER_MIN_CANDIDATES = 10
_SWEEPER_AGENT = "candidate_sweeper"
_MAX_TRIAGE_PER_ROUND = 3
_EXPLOIT_BLOCKER_RETRY_S = 1800.0
_DONE_STATUSES = {"confirmed", "confirmed_critical_reproduced", "upheld", "rejected", "downgraded", "exhausted"}
_ACTIVE_STATUSES = {"running", "materializing", "harness_materialized"}
_VERIFY_STATUSES = {"", "posted", "live_candidate", "candidate", "selected_for_verification"}
_PROOF_STATUSES = {"real", "no_harness", "not_reproduced", "deferred"}
_FOLLOWUP_STATUSES = {"autonomous_followup", "autonomous_backlog", "needs_human_review", "retry_next_round", "maxed"}
_CONFIRMED_PIN_FILE = "operator_confirmed_criticals.json"


@dataclass
class AutopilotConfig:
    root: Path
    interval_s: float = 30.0
    candidate_stale_s: float = 900.0
    hunt_stale_s: float = 600.0
    triage_cooldown_s: float = 600.0
    session_probe_s: float = 300.0
    host: str = "127.0.0.1"
    port: int = 8787
    supervise_web: bool = True
    resume_hunts: bool = True
    include_stopped: bool = False
    engagements: list[str] = field(default_factory=list)
    dry_run: bool = False
    once: bool = False


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return default


def _write_json_atomic(path: Path, doc: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True, default=str), encoding="utf-8")
    tmp.replace(path)


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _event_age(eng_dir: Path, now: float) -> float:
    ev = eng_dir / "events.jsonl"
    try:
        return max(0.0, now - ev.stat().st_mtime)
    except OSError:
        return 10**9


def _candidate_key(cand: dict) -> str:
    explicit = str(cand.get("dedup_key") or "").strip()
    if explicit:
        return explicit
    basis = "\x1f".join(
        str(cand.get(k) or "").strip().lower()
        for k in ("title", "severity", "location", "file", "endpoint", "url", "root_cause")
    )
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


def _candidate_root_key(cand: dict) -> str:
    """Collapse duplicate-looking variants before the operator loop spends tokens on them."""
    title = str(cand.get("title") or cand.get("hyp") or "").strip().lower()
    root = str(cand.get("root_cause") or cand.get("why") or "").strip().lower()
    loc = _candidate_location(cand).strip().lower().split(":")[0]
    basis = "\x1f".join(p for p in (title, root or loc) if p)
    if not basis:
        return ""
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


def _candidate_title(cand: dict) -> str:
    return str(cand.get("title") or cand.get("hyp") or "").strip()


def _candidate_location(cand: dict) -> str:
    loc = str(cand.get("location") or cand.get("file") or cand.get("endpoint") or cand.get("url") or "").strip()
    if not loc and isinstance(cand.get("poc"), dict):
        loc = str(cand["poc"].get("path") or "").strip()
    return loc


def _event_candidate(doc: dict) -> dict | None:
    kind = doc.get("kind")
    data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
    if isinstance(data.get("finding"), dict):
        data = data["finding"]
    elif kind not in ("finding_reported", "finding"):
        return None
    if kind == "finding" and data.get("event"):
        return None
    if not _candidate_title(data):
        return None
    out = dict(data)
    out.setdefault("source_agent", doc.get("agent", ""))
    out.setdefault("last_seen_ts", doc.get("ts") or 0)
    return out


def _recent_event_candidates(eng_dir: Path, max_bytes: int = 4_000_000) -> tuple[list[dict], dict[str, dict]]:
    ev = eng_dir / "events.jsonl"
    out: dict[str, dict] = {}
    order: list[str] = []
    statuses: dict[str, dict] = {}
    try:
        size = ev.stat().st_size
        with ev.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(max(0, size - max_bytes))
            if size > max_bytes:
                fh.readline()
            for line in fh:
                try:
                    doc = json.loads(line)
                except ValueError:
                    continue
                data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
                if doc.get("kind") == "lifecycle" and data.get("event") == "candidate_status":
                    key = str(data.get("dedup_key") or "").strip()
                    if key:
                        statuses[key] = {
                            "stage": str(data.get("stage") or ""),
                            "status": str(data.get("status") or ""),
                            "target_agent": str(data.get("target_agent") or ""),
                            "next_action": str(data.get("next_action") or ""),
                            "blocked_by": str(data.get("blocked_by") or ""),
                            "reason": str(data.get("reason") or ""),
                            "updated_ts": float(doc.get("ts") or time.time()),
                        }
                    continue
                cand = _event_candidate(doc)
                if not cand:
                    continue
                key = _candidate_key(cand)
                cand["dedup_key"] = key
                if key not in out:
                    order.append(key)
                out[key] = {**out.get(key, {}), **cand}
    except OSError:
        pass
    return [out[k] for k in order], statuses


def load_candidates(eng_dir: Path) -> list[dict]:
    """Load candidate-like records from findings, live ledger, and recent events."""
    merged: dict[str, dict] = {}
    for path in (eng_dir / "findings.json", eng_dir / "live_findings.json"):
        doc = _read_json(path, {})
        if not isinstance(doc, dict):
            continue
        for section in ("candidates", "needs_human_review", "confirmed_criticals"):
            vals = doc.get(section)
            if not isinstance(vals, list):
                continue
            for item in vals:
                if not isinstance(item, dict) or not _candidate_title(item):
                    continue
                key = _candidate_key(item)
                item = dict(item)
                item["dedup_key"] = key
                merged[key] = {**merged.get(key, {}), **item}
    event_cands, event_statuses = _recent_event_candidates(eng_dir)
    for item in event_cands:
        key = _candidate_key(item)
        merged[key] = {**merged.get(key, {}), **item}
    for key, status in event_statuses.items():
        if key in merged:
            merged[key]["pipeline"] = {**merged[key].get("pipeline", {}), **status}
    return list(merged.values())


def repair_confirmed_criticals(eng_dir: Path, *, dry_run: bool = False) -> dict | None:
    """Keep operator-verified criticals durable across live round-boundary rewrites.

    A running hunt owns its in-memory finding set and may rewrite findings.json at the end of a
    round. Operator/imported confirmations are external evidence, so autopilot preserves them from
    a small pin file instead of letting the dashboard temporarily forget a reproduced P1.
    """
    pins_doc = _read_json(eng_dir / _CONFIRMED_PIN_FILE, {})
    pins = pins_doc.get("confirmed_criticals") if isinstance(pins_doc, dict) else pins_doc
    if not isinstance(pins, list):
        return None
    pins = [dict(x) for x in pins if isinstance(x, dict) and _candidate_title(x)]
    if not pins:
        return None
    path = eng_dir / "findings.json"
    doc = _read_json(path, {})
    if not isinstance(doc, dict):
        doc = {}
    doc.setdefault("program", eng_dir.name)
    confirmed = doc.get("confirmed_criticals") if isinstance(doc.get("confirmed_criticals"), list) else []
    needs = doc.get("needs_human_review") if isinstance(doc.get("needs_human_review"), list) else []
    cands = doc.get("candidates") if isinstance(doc.get("candidates"), list) else []

    merged: dict[str, dict] = {}
    for item in [*confirmed, *pins]:
        if not isinstance(item, dict) or not _candidate_title(item):
            continue
        key = _candidate_key(item)
        row = dict(item)
        row["dedup_key"] = key
        row.setdefault("verified", True)
        merged[key] = {**merged.get(key, {}), **row}
    repaired = list(merged.values())
    changed = len(repaired) != len(confirmed)
    if not changed:
        old_keys = {_candidate_key(x) for x in confirmed if isinstance(x, dict)}
        pin_keys = {_candidate_key(x) for x in pins}
        changed = not pin_keys.issubset(old_keys)
    if not changed:
        return None
    doc["confirmed_criticals"] = repaired
    doc["needs_human_review"] = needs
    doc["candidates"] = cands
    doc["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    doc["counts"] = {
        "confirmed_critical": len(repaired),
        "needs_human_review": len(needs),
        "candidates": len(cands),
    }
    if not dry_run:
        _write_json_atomic(path, doc)
    return {
        "event": "confirmed_criticals_repaired",
        "engagement": eng_dir.name,
        "dry_run": dry_run,
        "count": len(repaired),
    }


def _pipeline(cand: dict) -> dict:
    p = cand.get("pipeline")
    return p if isinstance(p, dict) else {}


def _status_age(cand: dict, now: float) -> float:
    pipe = _pipeline(cand)
    for key in ("updated_ts", "last_seen_ts", "ts"):
        try:
            ts = float(pipe.get(key) if key in pipe else cand.get(key) or 0)
            if ts > 0:
                return max(0.0, now - ts)
        except (TypeError, ValueError):
            continue
    return 10**9


def directive_for_candidate(
    cand: dict,
    *,
    now: float | None = None,
    stale_s: float = 900.0,
    high_severity_only: bool = True,
) -> dict | None:
    """Return a triage directive for a candidate that needs autonomous movement."""
    now = time.time() if now is None else now
    title = _candidate_title(cand)
    if not title:
        return None
    severity = str(cand.get("severity") or "").strip().lower()
    if high_severity_only and severity not in _HIGH_SEV:
        return None

    pipe = _pipeline(cand)
    stage = str(pipe.get("stage") or "").strip().lower()
    status = str(pipe.get("status") or cand.get("status") or "").strip().lower()
    blocked = str(pipe.get("blocked_by") or cand.get("blocked_by") or "").strip().lower()
    age = _status_age(cand, now)
    if status in _DONE_STATUSES or "confirmed" in status:
        return None
    if status in _ACTIVE_STATUSES and age < stale_s:
        return None

    if "debate" in stage or "debate" in blocked or "pending_debate" in status:
        return {
            "target_agent": "debate",
            "action": "Adjudicate this reproduced/exploit-confirmed critical now; uphold, downgrade, or reject with code-cited reasoning.",
            "message": "Autopilot: candidate is blocked on the debate gate.",
        }
    if status in _FOLLOWUP_STATUSES or "attacker_win" in blocked or "lead_attempt" in blocked:
        if age < max(stale_s, _EXPLOIT_BLOCKER_RETRY_S):
            return None
        return {
            "target_agent": "exploit_developer",
            "action": "Continue exploit-depth autonomously: close the full attacker-win chain or write a precise impossibility blocker.",
            "message": "Autopilot: high-value lead is unconfirmed because attacker-win proof is incomplete.",
        }
    if status in _PROOF_STATUSES or "reproduction" in blocked or "not_reproduced" in blocked or "materialization" in blocked:
        return {
            "target_agent": "poc_prover",
            "action": "Build or repair the deterministic proof harness, rerun it, and hand to exploit_developer if the runner still cannot prove impact.",
            "message": "Autopilot: verifier/proof pipeline is blocked before deterministic reproduction.",
        }
    if status in _VERIFY_STATUSES:
        return {
            "target_agent": "parent_a",
            "action": "Pull this candidate into verifier -> PoC prover -> runner -> exploit-depth without waiting for operator input.",
            "message": "Autopilot: blackboard/high-severity candidate needs first pipeline ownership.",
        }
    if age >= stale_s:
        return {
            "target_agent": str(pipe.get("target_agent") or "parent_a"),
            "action": "Unstick this stale candidate and move it to the next proof stage or record a precise blocker.",
            "message": f"Autopilot: candidate state {stage}:{status or 'unknown'} is stale.",
        }
    return None


def _candidate_stage_priority(cand: dict) -> int:
    pipe = _pipeline(cand)
    stage = str(pipe.get("stage") or "").lower()
    status = str(pipe.get("status") or cand.get("status") or "").lower()
    blocked = str(pipe.get("blocked_by") or cand.get("blocked_by") or "").lower()
    if "debate" in stage or "pending_debate" in status:
        return 70
    if "exploit" in stage or "attacker_win" in blocked or status in _FOLLOWUP_STATUSES:
        return 60
    if "poc" in stage or "runner" in stage or status in _PROOF_STATUSES:
        return 45
    if "verifier" in stage or status in _VERIFY_STATUSES:
        return 30
    return 10


def candidate_sweeper_pick(candidates: list[dict], *, now: float | None = None, stale_s: float = 900.0) -> tuple[dict, dict] | None:
    """Pick one open candidate for the autonomous sweeper.

    The sweeper is intentionally conservative: it does not take work from a service that is already
    actively running a fresh candidate. It only creates a routing directive when there are enough
    candidates for backlog management to matter.
    """
    now = time.time() if now is None else now
    if len(candidates) < _SWEEPER_MIN_CANDIDATES:
        return None
    ranked: list[tuple[int, float, dict, dict]] = []
    for cand in candidates:
        if not _candidate_title(cand):
            continue
        pipe = _pipeline(cand)
        status = str(pipe.get("status") or cand.get("status") or "").strip().lower()
        if status in _DONE_STATUSES or "confirmed" in status:
            continue
        age = _status_age(cand, now)
        if status in _ACTIVE_STATUSES and age < stale_s:
            continue
        directive = directive_for_candidate(cand, now=now, stale_s=stale_s)
        if not directive:
            continue
        sev = _SEVERITY_RANK.get(str(cand.get("severity") or "").strip().lower(), 0)
        score = sev * 100 + _candidate_stage_priority(cand)
        if age >= stale_s:
            score += 25
        if str(pipe.get("blocked_by") or cand.get("blocked_by") or "").strip():
            score += 20
        directive = {
            **directive,
            "source_agent": _SWEEPER_AGENT,
            "message": (
                "Candidate sweeper: selected highest-severity open backlog item without taking "
                "over a fresh active agent task. "
                + str(directive.get("message") or "")
            ),
        }
        ranked.append((score, age, cand, directive))
    if not ranked:
        return None
    ranked.sort(key=lambda row: (row[0], row[1]), reverse=True)
    return ranked[0][2], ranked[0][3]


def _append_control(eng_dir: Path, rec: dict) -> None:
    with (eng_dir / "control.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def _queue_key(cand: dict, directive: dict) -> str:
    key = _candidate_root_key(cand) or _candidate_key(cand)
    return key + "|" + str(directive.get("target_agent") or "") + "|" + str(directive.get("action") or "")[:80]


def queue_triage_if_due(
    eng_dir: Path,
    cand: dict,
    directive: dict,
    state: dict,
    *,
    now: float,
    cooldown_s: float,
    dry_run: bool = False,
) -> dict | None:
    qkey = _queue_key(cand, directive)
    triage = state.setdefault("triage", {})
    prev = triage.get(qkey) if isinstance(triage.get(qkey), dict) else {}
    prev_count = int(prev.get("count") or 0) if prev else 0
    effective_cooldown = cooldown_s * max(1, min(6, prev_count + 1))
    if prev and now - float(prev.get("last_ts") or 0) < effective_cooldown:
        return None
    rec = {
        "kind": "triage",
        "finding_key": _candidate_key(cand),
        "title": _candidate_title(cand),
        "message": directive.get("message", ""),
        "target_agent": directive.get("target_agent", "parent_a"),
        "action": directive.get("action", "prioritize verifier/prover/deep-dive now"),
    }
    if directive.get("source_agent"):
        rec["source_agent"] = str(directive.get("source_agent"))[:80]
    if not dry_run:
        _append_control(eng_dir, rec)
    triage[qkey] = {
        "last_ts": now,
        "count": prev_count + 1,
        "title": rec["title"],
        "target_agent": rec["target_agent"],
        "action": rec["action"],
    }
    return {"event": "triage_queued", "engagement": eng_dir.name, "dry_run": dry_run, **rec}


def _last_control_kind(eng_dir: Path) -> str:
    ctrl = eng_dir / "control.jsonl"
    last = ""
    try:
        for line in ctrl.read_text(encoding="utf-8").splitlines():
            try:
                d = json.loads(line)
            except ValueError:
                continue
            last = str(d.get("kind") or "")
    except OSError:
        pass
    return last


def _resume_command(proc_doc: dict) -> list[str] | None:
    argv = proc_doc.get("argv")
    if not isinstance(argv, list) or "hunt" not in argv:
        return None
    try:
        idx = argv.index("hunt")
    except ValueError:
        return None
    cmd = [sys.executable, "-m", "p1hunt.main", *[str(a) for a in argv[idx:]]]
    if "--resume" not in cmd:
        cmd.append("--resume")
    return cmd


def maybe_resume_hunt(eng_dir: Path, state: dict, *, now: float, stale_s: float, dry_run: bool = False) -> dict | None:
    proc_doc = _read_json(eng_dir / "process.json", {})
    if not isinstance(proc_doc, dict) or proc_doc.get("kind") != "hunt":
        return None
    try:
        pid = int(proc_doc.get("pid") or 0) or None
    except (TypeError, ValueError):
        pid = None
    if _pid_alive(pid):
        return None
    if _event_age(eng_dir, now) < stale_s:
        return None
    latest_control = _last_control_kind(eng_dir)
    if latest_control in ("stop", "pause"):
        return {"event": "resume_skipped", "engagement": eng_dir.name,
                "reason": f"latest control directive is {latest_control}"}
    if not (eng_dir / "state.json").is_file():
        return {"event": "resume_skipped", "engagement": eng_dir.name, "reason": "no state.json to resume from"}
    cmd = _resume_command(proc_doc)
    if not cmd:
        return {"event": "resume_skipped", "engagement": eng_dir.name, "reason": "missing hunt argv in process.json"}
    launched = state.setdefault("launches", {})
    last = launched.get("hunt") if isinstance(launched.get("hunt"), dict) else {}
    if last and now - float(last.get("last_ts") or 0) < stale_s:
        return None
    if not dry_run:
        log = (eng_dir / "autopilot-hunt.log").open("ab")
        env = os.environ.copy()
        local_bin = str(Path.home() / ".local" / "bin")
        env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")
        subprocess.Popen(
            cmd,
            cwd=str(proc_doc.get("cwd") or Path.cwd()),
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
    launched["hunt"] = {"last_ts": now, "cmd": cmd, "dry_run": dry_run}
    return {"event": "hunt_resumed", "engagement": eng_dir.name, "dry_run": dry_run, "cmd": cmd}


def _hunt_pid_alive(eng_dir: Path) -> bool:
    proc_doc = _read_json(eng_dir / "process.json", {})
    if not isinstance(proc_doc, dict) or proc_doc.get("kind") != "hunt":
        return False
    try:
        pid = int(proc_doc.get("pid") or 0) or None
    except (TypeError, ValueError):
        pid = None
    return _pid_alive(pid)


def _has_resume_metadata(eng_dir: Path) -> bool:
    if _last_control_kind(eng_dir) in ("stop", "pause") or not (eng_dir / "state.json").is_file():
        return False
    proc_doc = _read_json(eng_dir / "process.json", {})
    return isinstance(proc_doc, dict) and proc_doc.get("kind") == "hunt" and _resume_command(proc_doc) is not None


def _engagement_in_scope(eng_dir: Path, cfg: AutopilotConfig, now: float) -> bool:
    """Default to live/restartable work so archives are not nudged forever."""
    wanted = _engagement_filter(cfg)
    if wanted and eng_dir.name not in wanted:
        return False
    if cfg.include_stopped:
        return True
    if _hunt_pid_alive(eng_dir):
        return True
    if _event_age(eng_dir, now) < cfg.hunt_stale_s:
        return True
    return cfg.resume_hunts and _has_resume_metadata(eng_dir)


def _engagement_filter(cfg: AutopilotConfig) -> set[str]:
    wanted: set[str] = set()
    for raw in cfg.engagements:
        for part in str(raw).split(","):
            part = part.strip()
            if part:
                wanted.add(part)
    return wanted


def _port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ensure_web(cfg: AutopilotConfig, state: dict, *, now: float) -> dict | None:
    host = "127.0.0.1" if cfg.host in ("0.0.0.0", "::") else cfg.host
    if _port_open(host, cfg.port):
        return None
    web = state.setdefault("web", {})
    if web and now - float(web.get("last_ts") or 0) < 10:
        return None
    cmd = [sys.executable, "-m", "p1hunt.main", "web", "--host", cfg.host, "--port", str(cfg.port)]
    if not cfg.dry_run:
        cfg.root.mkdir(parents=True, exist_ok=True)
        log = (cfg.root / "autopilot-web.log").open("ab")
        env = os.environ.copy()
        env["P1HUNT_ENGAGEMENTS"] = str(cfg.root)
        wanted = _engagement_filter(cfg)
        if wanted:
            env["P1HUNT_WEB_ENGAGEMENTS"] = ",".join(sorted(wanted))
        subprocess.Popen(
            cmd,
            cwd=str(Path.cwd()),
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
    web.update({"last_ts": now, "cmd": cmd, "dry_run": cfg.dry_run})
    return {"event": "web_started", "dry_run": cfg.dry_run, "url": f"http://{host}:{cfg.port}", "cmd": cmd}


def maybe_probe_session_limit(eng_dir: Path, cfg: AutopilotConfig, state: dict, *, now: float) -> dict | None:
    """Record shared session-limit state and safe-clear it on a five-minute probe cadence."""
    if not _hunt_pid_alive(eng_dir):
        return None
    sess = state.setdefault("session_limit", {})
    status = session_limit_state(eng_dir, now=now)
    sess.update(status)
    if not status.get("throttled"):
        return None
    last_probe = _as_float(sess.get("last_probe_ts"), 0.0)
    if now - last_probe < cfg.session_probe_s:
        return None
    result = jumpstart_if_clear(
        eng_dir,
        now=now,
        note=f"autopilot probe for {eng_dir.name}",
        dry_run=cfg.dry_run,
    )
    latest = result.get("state") if isinstance(result.get("state"), dict) else session_limit_state(eng_dir, now=now)
    sess.update(latest)
    sess["last_probe_ts"] = now
    sess["last_probe_result"] = {
        "cleared": bool(result.get("cleared")),
        "forced": bool(result.get("forced")),
        "dry_run": bool(result.get("dry_run")),
        "remaining_s": latest.get("remaining_s"),
        "reset_ts": latest.get("reset_ts"),
    }
    if result.get("cleared"):
        return {
            "event": "session_limit_jumpstarted",
            "engagement": eng_dir.name,
            "dry_run": cfg.dry_run,
            "remaining_s": latest.get("remaining_s"),
            "reset_ts": latest.get("reset_ts"),
        }
    return {
        "event": "session_limit_waiting",
        "engagement": eng_dir.name,
        "remaining_s": latest.get("remaining_s"),
        "reset_ts": latest.get("reset_ts"),
        "reason": latest.get("reason") or latest.get("reset_text") or "session limit still active",
    }


def supervise_engagement(eng_dir: Path, cfg: AutopilotConfig, state: dict, *, now: float | None = None) -> list[dict]:
    now = time.time() if now is None else now
    events: list[dict] = []
    repaired = repair_confirmed_criticals(eng_dir, dry_run=cfg.dry_run)
    if repaired:
        events.append(repaired)
    if _last_control_kind(eng_dir) in ("stop", "pause"):
        return events
    session_event = maybe_probe_session_limit(eng_dir, cfg, state, now=now)
    if session_event:
        events.append(session_event)
    if cfg.resume_hunts:
        ev = maybe_resume_hunt(eng_dir, state, now=now, stale_s=cfg.hunt_stale_s, dry_run=cfg.dry_run)
        if ev:
            events.append(ev)
    candidates = load_candidates(eng_dir)
    high_value_candidates = [
        c for c in candidates
        if str(c.get("severity") or "").strip().lower() in _HIGH_SEV
    ]
    low_priority_candidates = [
        c for c in candidates
        if str(c.get("severity") or "").strip().lower() in _LOW_PRIORITY_SEV
    ]
    sweeper_state = state.setdefault("candidate_sweeper", {})
    sweeper_state.update({
        "agent": _SWEEPER_AGENT,
        "candidate_count": len(candidates),
        "high_value_candidate_count": len(high_value_candidates),
        "low_priority_candidate_count": len(low_priority_candidates),
        "threshold": _SWEEPER_MIN_CANDIDATES,
        "last_run_ts": now,
    })
    sweep = candidate_sweeper_pick(candidates, now=now, stale_s=cfg.candidate_stale_s)
    if sweep:
        cand, directive = sweep
        sweeper_state.update({
            "status": "routing",
            "title": _candidate_title(cand),
            "finding_key": _candidate_key(cand),
            "severity": str(cand.get("severity") or ""),
            "target_agent": directive.get("target_agent", "parent_a"),
            "action": directive.get("action", ""),
            "reason": directive.get("message", ""),
        })
        queued = queue_triage_if_due(
            eng_dir,
            cand,
            directive,
            state,
            now=now,
            cooldown_s=cfg.triage_cooldown_s,
            dry_run=cfg.dry_run,
        )
        if queued:
            queued["event"] = "candidate_sweeper_queued"
            sweeper_state["status"] = "queued"
            sweeper_state["last_queue_ts"] = now
            events.append(queued)
        else:
            sweeper_state["status"] = "cooldown"
            sweeper_state["reason"] = "equivalent directive already queued recently; not duplicating another agent's work"
    else:
        sweeper_state.update({
            "status": "standby" if len(candidates) < _SWEEPER_MIN_CANDIDATES else "idle",
            "reason": (
                f"waiting for {_SWEEPER_MIN_CANDIDATES} candidates"
                if len(candidates) < _SWEEPER_MIN_CANDIDATES
                else "no open high/critical candidate needs routing; low/info findings remain background records"
            ),
            "title": "",
            "finding_key": "",
            "severity": "",
            "target_agent": "",
            "action": "",
        })
    pending: list[tuple[int, float, dict, dict]] = []
    seen_roots: set[str] = set()
    for cand in candidates:
        directive = directive_for_candidate(cand, now=now, stale_s=cfg.candidate_stale_s)
        if not directive:
            continue
        root = _candidate_root_key(cand) or _candidate_key(cand)
        if root in seen_roots:
            continue
        seen_roots.add(root)
        pipe = _pipeline(cand)
        severity = str(cand.get("severity") or "").strip().lower()
        age = _status_age(cand, now)
        score = _SEVERITY_RANK.get(severity, 0) * 100 + _candidate_stage_priority(cand)
        if age >= cfg.candidate_stale_s:
            score += 25
        if str(pipe.get("blocked_by") or cand.get("blocked_by") or "").strip():
            score += 20
        pending.append((score, age, cand, directive))
    pending.sort(key=lambda row: (row[0], row[1]), reverse=True)
    for _, _, cand, directive in pending[:_MAX_TRIAGE_PER_ROUND]:
        queued = queue_triage_if_due(
            eng_dir,
            cand,
            directive,
            state,
            now=now,
            cooldown_s=cfg.triage_cooldown_s,
            dry_run=cfg.dry_run,
        )
        if queued:
            events.append(queued)
    return events


def engagement_dirs(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(
        [p for p in root.iterdir() if (p / "events.jsonl").is_file()],
        key=lambda p: (p / "events.jsonl").stat().st_mtime,
        reverse=True,
    )


def run_autopilot(cfg: AutopilotConfig) -> int:
    cfg.root.mkdir(parents=True, exist_ok=True)
    state_path = cfg.root / "autopilot_state.json"
    state = _read_json(state_path, {})
    if not isinstance(state, dict):
        state = {}
    while True:
        now = time.time()
        events: list[dict] = []
        if cfg.supervise_web:
            ev = ensure_web(cfg, state, now=now)
            if ev:
                events.append(ev)
        for eng_dir in engagement_dirs(cfg.root):
            if not _engagement_in_scope(eng_dir, cfg, now):
                continue
            events.extend(supervise_engagement(eng_dir, cfg, state.setdefault("engagements", {}).setdefault(eng_dir.name, {}), now=now))
        state["supervisor"] = {
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "updated_ts": now,
            "root": str(cfg.root),
            "interval_s": cfg.interval_s,
            "candidate_stale_s": cfg.candidate_stale_s,
            "hunt_stale_s": cfg.hunt_stale_s,
            "triage_cooldown_s": cfg.triage_cooldown_s,
            "session_probe_s": cfg.session_probe_s,
            "supervise_web": cfg.supervise_web,
            "resume_hunts": cfg.resume_hunts,
            "include_stopped": cfg.include_stopped,
            "engagements": sorted(_engagement_filter(cfg)),
            "web": {"host": cfg.host, "port": cfg.port},
            "dry_run": cfg.dry_run,
        }
        state["updated_ts"] = now
        _write_json_atomic(state_path, state)
        for ev in events:
            print(json.dumps({"ts": now, **ev}, default=str), flush=True)
        if cfg.once:
            return 0
        time.sleep(max(1.0, cfg.interval_s))
