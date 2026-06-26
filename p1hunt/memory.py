"""Optional cross-engagement operational memory.

Preset-free hunts keep this disabled by default. When explicitly enabled, memory stores only
sanitized run metadata such as target class, subclass, runner kind, and outcome. It must never store
or recall root causes, titles, exploit narratives, lenses, or reusable failure patterns.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path


def memory_enabled() -> bool:
    return os.environ.get("P1HUNT_MEMORY", "0") == "1"


def default_memory_path(engagements_root: str) -> Path:
    """Global store shared across every engagement under this root (or P1HUNT_MEMORY_DIR)."""
    base = os.environ.get("P1HUNT_MEMORY_DIR", "").strip()
    root = Path(base) if base else Path(engagements_root) / ".memory"
    return root / "confirmed.jsonl"


def _clean(value: object, limit: int = 80) -> str:
    """Small bounded field sanitizer for operational metadata."""
    text = " ".join(str(value or "").split())
    return text[:limit]


class MemoryStore:
    """Append-only store of sanitized run metadata. Never raises."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    # --- write ------------------------------------------------------------
    def record(self, *, target_class: str, subclass: str, finding: dict) -> None:
        """Persist operational metadata for one confirmed run.

        The caller may pass the full finding object for compatibility, but only non-vulnerability
        fields are retained. This prevents memory from becoming a hidden preset failure-pattern feed.
        """
        harness = _clean(finding.get("harness_kind") or finding.get("runner"), 60)
        outcome = _clean(finding.get("outcome") or "confirmed_reproduced", 60)
        rec = {
            "ts": int(time.time()),
            "target_class": _clean(target_class, 48).upper(),
            "subclass": _clean(subclass, 48).lower(),
            "severity_tier": _clean(finding.get("severity"), 24).lower(),
            "harness_kind": harness,
            "outcome": outcome,
        }
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        except OSError:
            pass

    # --- read -------------------------------------------------------------
    def _load(self) -> list[dict]:
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                return [json.loads(ln) for ln in fh if ln.strip()]
        except (OSError, ValueError):
            return []

    def recall(self, target_class: str, subclass: str = "", *, limit: int = 8) -> list[str]:
        """Return up to ``limit`` distinct operational notes for matching target classes.

        The returned strings intentionally contain no root cause, exploit shape, target title, file,
        or failure pattern. They are safe for UI/operator context, but active Codex hunts do not
        inject them into hunter prompts.
        """
        tc = (target_class or "").upper()
        sc = (subclass or "").lower()
        recs = self._load()
        same_class = [r for r in recs if r.get("target_class") == tc]
        # subclass match floats to the top; then recency.
        same_class.sort(key=lambda r: (0 if (sc and r.get("subclass") == sc) else 1,
                                       -int(r.get("ts", 0))))
        out: list[str] = []
        seen: set[str] = set()
        for r in same_class:
            parts = [f"class={r.get('target_class', '')}"]
            if r.get("subclass"):
                parts.append(f"subclass={r.get('subclass')}")
            if r.get("harness_kind"):
                parts.append(f"runner={r.get('harness_kind')}")
            if r.get("outcome"):
                parts.append(f"outcome={r.get('outcome')}")
            note = "prior operational run: " + ", ".join(parts)
            key = note.lower()[:120]
            if key not in seen:
                seen.add(key)
                out.append(note)
            if len(out) >= limit:
                break
        return out

    def count(self) -> int:
        return len(self._load())
