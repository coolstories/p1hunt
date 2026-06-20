"""apk_inspect — static APK/source secret + manifest review (spec §12). Read-only."""

from __future__ import annotations

from ..classify.signals import scan_artifacts
from .base import ToolResult


class ApkInspect:
    name = "apk_inspect"
    read_only = True

    async def run(self, args: dict) -> ToolResult:
        root = args.get("path") or args.get("target") or "."
        hits = [h for h in scan_artifacts(root) if h.signal.lens in ("trusted-execution", "confidentiality")]
        data = {
            "embedded_secrets": [
                {"file": h.file, "line": h.line, "snippet": h.snippet}
                for h in hits
                if h.signal.id == "secret-in-source"
            ],
            "other_findings": [
                {"signal": h.signal.id, "file": h.file, "line": h.line} for h in hits
            ],
        }
        return ToolResult(True, self.name, f"static APK review: {len(hits)} signal(s)", data)
