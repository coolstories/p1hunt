"""static_analysis — run the generic critical-impact detectors over source (spec §12).

Read-only. Returns derived signal hits; it does not exploit, modify, or contact anything.
"""

from __future__ import annotations

from ..classify.signals import scan_artifacts
from .base import ToolResult


class StaticAnalysis:
    name = "static_analysis"
    read_only = True

    async def run(self, args: dict) -> ToolResult:
        root = args.get("path") or args.get("target") or "."
        lens = args.get("lens")
        hits = scan_artifacts(root)
        if lens:
            hits = [h for h in hits if h.signal.lens == lens]
        data = {
            "hits": [
                {
                    "signal": h.signal.id,
                    "lens": h.signal.lens,
                    "title": h.signal.title,
                    "file": h.file,
                    "line": h.line,
                    "snippet": h.snippet,
                    "rationale": h.signal.rationale,
                }
                for h in hits
            ]
        }
        return ToolResult(True, self.name, f"{len(hits)} signal hit(s)", data)
