"""Cross-engagement memory — learning from THIS TOOL'S OWN confirmed findings.

This is NOT a preset and NOT hand-authored bug knowledge. The store accumulates ONLY findings the
swarm itself CONFIRMED (deterministically reproduced) on past engagements, generalizes each to a
one-line bug-class pattern, and offers them back at recon as FALLIBLE PRIORS: "we confirmed a bug
like this in similar code before — hunt a NEW variant here (the old instance is likely patched)."

Why this respects NOTHING-PRESET: the content is derived entirely from the system's own verified
wins, not from a baked-in catalog; it is retrieved by relevance to the target class; and it feeds
the SAME ``known_patterns`` channel recon already uses (which Parent A treats as fallible hints to
hunt variants of, never a checklist). Parent A still derives everything. Disable with
``P1HUNT_MEMORY=0``; relocate the store with ``P1HUNT_MEMORY_DIR``.

The store is a plain append-only JSONL file, fully offline-graceful — any IO failure degrades to
"no memory" and never affects a hunt.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path


def memory_enabled() -> bool:
    return os.environ.get("P1HUNT_MEMORY", "1") != "0"


def default_memory_path(engagements_root: str) -> Path:
    """Global store shared across every engagement under this root (or P1HUNT_MEMORY_DIR)."""
    base = os.environ.get("P1HUNT_MEMORY_DIR", "").strip()
    root = Path(base) if base else Path(engagements_root) / ".memory"
    return root / "confirmed.jsonl"


def _generalize(finding: dict) -> str:
    """Turn a confirmed finding into a one-line, target-AGNOSTIC bug-class pattern (the reusable
    prior). Uses the root cause + what the attacker gained + the lens — never the program's name or
    full file path, so it reads as a class-level 'watch for this shape', not a per-target playbook."""
    lens = str(finding.get("lens", "")).strip()
    root = " ".join(str(finding.get("root_cause", "")).split())[:240]
    cf = " ".join(str(finding.get("counterfactual", "")).split())[:160]
    parts = []
    if lens:
        parts.append(f"[{lens}]")
    if root:
        parts.append(root)
    if cf:
        parts.append(f"→ attacker gains: {cf}")
    return " ".join(parts).strip()


class MemoryStore:
    """Append-only store of confirmed findings, with class-scoped recall. Never raises."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    # --- write ------------------------------------------------------------
    def record(self, *, target_class: str, subclass: str, finding: dict) -> None:
        """Persist one CONFIRMED finding as a reusable prior. Caller passes a dict with at least
        title/root_cause/counterfactual/lens/severity (+ optional program, harness_kind)."""
        pattern = _generalize(finding)
        if not pattern:
            return
        rec = {
            "ts": int(time.time()),
            "program": str(finding.get("program", ""))[:120],
            "target_class": (target_class or "").upper(),
            "subclass": (subclass or "").lower(),
            "lens": str(finding.get("lens", "")),
            "severity": str(finding.get("severity", "")),
            "title": str(finding.get("title", ""))[:200],
            "pattern": pattern,
            "harness_kind": str(finding.get("harness_kind", "")),
        }
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
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
        """Return up to ``limit`` distinct prior-confirmed patterns relevant to this target,
        ranked: same class AND subclass first, then same class, most-recent first. Returns the
        generalized pattern strings (ready to drop into ``known_patterns``)."""
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
            p = str(r.get("pattern", "")).strip()
            key = p.lower()[:80]
            if p and key not in seen:
                seen.add(key)
                out.append(p)
            if len(out) >= limit:
                break
        return out

    def count(self) -> int:
        return len(self._load())
