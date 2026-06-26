"""Shared session-limit throttle state and operator jumpstart helpers."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import time
from pathlib import Path
from typing import Any


THROTTLE_FILE = Path(os.environ.get("P1HUNT_THROTTLE_FILE", "/tmp/p1hunt_throttle.json"))
_MAX_EVENT_SCAN_BYTES = 4_000_000
_RESET_RE = re.compile(
    r"\bresets?\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\s*(?:\((utc|gmt)\))?",
    re.IGNORECASE,
)
_LIMIT_HINTS = ("session limit", "usage limit", "rate limit", "rate-limited", "quota")


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def read_throttle(throttle_file: Path | None = None) -> dict:
    path = throttle_file or THROTTLE_FILE
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def parse_reset_epoch(text: str, *, reference_ts: float | None = None, now: float | None = None) -> float | None:
    """Parse model notices like ``resets 12:30pm (UTC)`` into an epoch timestamp."""
    if not text:
        return None
    match = None
    for match in _RESET_RE.finditer(text):
        pass
    if match is None:
        return None
    ref = _as_float(reference_ts, 0.0) or _as_float(now, 0.0) or time.time()
    hour = _as_int(match.group(1))
    minute = _as_int(match.group(2), 0)
    meridiem = (match.group(3) or "").lower()
    if hour < 1 or hour > 24 or minute < 0 or minute > 59:
        return None
    if meridiem:
        if hour > 12:
            return None
        hour = hour % 12
        if meridiem == "pm":
            hour += 12
    elif hour == 24:
        hour = 0
    base = dt.datetime.fromtimestamp(ref, dt.timezone.utc)
    target = base.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target.timestamp() < ref - 60:
        target += dt.timedelta(days=1)
    return target.timestamp()


def _event_text(doc: dict) -> str:
    data = doc.get("data")
    if not isinstance(data, dict):
        return ""
    parts = []
    for key in ("text", "reason", "detail", "message"):
        value = data.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
    return " ".join(parts)


def latest_session_reset_from_events(eng_dir: Path | None, *, now: float | None = None) -> dict | None:
    if eng_dir is None:
        return None
    ev = eng_dir / "events.jsonl"
    if not ev.is_file():
        return None
    latest: dict | None = None
    try:
        size = ev.stat().st_size
        start = max(0, size - _MAX_EVENT_SCAN_BYTES)
        with ev.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(start)
            if start:
                fh.readline()
            for line in fh:
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    continue
                text = _event_text(doc)
                low = text.lower()
                if not text or "reset" not in low or not any(h in low for h in _LIMIT_HINTS):
                    continue
                ts = _as_float(doc.get("ts"), _as_float(now, time.time()))
                reset_ts = parse_reset_epoch(text, reference_ts=ts, now=now)
                if reset_ts is None:
                    continue
                latest = {
                    "reset_ts": reset_ts,
                    "reset_text": text[:300],
                    "event_ts": ts,
                    "agent": str(doc.get("agent") or ""),
                }
    except OSError:
        return None
    return latest


def session_limit_state(
    eng_dir: Path | None = None,
    *,
    throttle_file: Path | None = None,
    now: float | None = None,
) -> dict:
    now = time.time() if now is None else float(now)
    path = throttle_file or THROTTLE_FILE
    doc = read_throttle(path)
    throttled = bool(doc.get("throttled"))
    at = _as_float(doc.get("at"), 0.0)
    seconds = _as_float(doc.get("seconds"), 0.0)
    cooldown_remaining = max(0.0, at + seconds - now) if throttled and at and seconds else 0.0
    reset = latest_session_reset_from_events(eng_dir, now=now)
    reset_ts = _as_float(reset.get("reset_ts"), 0.0) if reset else 0.0
    reset_remaining = max(0.0, reset_ts - now) if reset_ts else 0.0
    remaining = reset_remaining if throttled and reset_ts else cooldown_remaining
    if throttled and remaining <= 0 and not reset_ts:
        remaining = cooldown_remaining
    state = {
        "throttled": throttled,
        "remaining_s": round(remaining, 1),
        "cooldown_remaining_s": round(cooldown_remaining, 1),
        "reset_remaining_s": round(reset_remaining, 1) if reset else None,
        "reset_ts": reset_ts or None,
        "reason": str(doc.get("reason") or ""),
        "strikes": doc.get("strikes"),
        "at": at or None,
        "manual": bool(doc.get("manual")) if doc else False,
        "throttle_file": str(path),
        "engagement": eng_dir.name if eng_dir else None,
        "can_jumpstart": (not throttled) or remaining <= 0,
        "now": now,
    }
    if reset:
        state.update({
            "reset_text": reset.get("reset_text"),
            "last_limit_event_ts": reset.get("event_ts"),
            "last_limit_agent": reset.get("agent"),
        })
    return state


def write_manual_clear(
    *,
    throttle_file: Path | None = None,
    now: float | None = None,
    note: str = "",
    dry_run: bool = False,
) -> dict:
    now = time.time() if now is None else float(now)
    path = throttle_file or THROTTLE_FILE
    payload = {"throttled": False, "manual": True, "at": now}
    if note:
        payload["note"] = note[:300]
    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    return payload


def jumpstart_if_clear(
    eng_dir: Path | None = None,
    *,
    throttle_file: Path | None = None,
    now: float | None = None,
    force: bool = False,
    note: str = "",
    dry_run: bool = False,
) -> dict:
    now = time.time() if now is None else float(now)
    state = session_limit_state(eng_dir, throttle_file=throttle_file, now=now)
    should_clear = force or state.get("can_jumpstart") is True
    if should_clear:
        payload = write_manual_clear(
            throttle_file=throttle_file,
            now=now,
            note=note or ("forced jumpstart" if force else "session limit clear"),
            dry_run=dry_run,
        )
        return {
            "cleared": True,
            "forced": bool(force),
            "dry_run": dry_run,
            "payload": payload,
            "state": session_limit_state(eng_dir, throttle_file=throttle_file, now=now) if not dry_run else state,
        }
    return {"cleared": False, "forced": False, "dry_run": dry_run, "state": state}
