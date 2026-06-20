"""source_fetch — read in-scope source/artifacts (spec §12). Read-only."""

from __future__ import annotations

from pathlib import Path

from .base import ToolResult


class SourceFetch:
    name = "source_fetch"
    read_only = True

    async def run(self, args: dict) -> ToolResult:
        target = Path(args.get("path") or args.get("target") or ".")
        if not target.exists():
            return ToolResult(False, self.name, f"path not found: {target}")
        if target.is_file():
            text = target.read_text(encoding="utf-8", errors="ignore")
            return ToolResult(
                True, self.name, f"read {target} ({len(text)} bytes)", {"content": text}
            )
        files = [str(p.relative_to(target)) for p in target.rglob("*") if p.is_file()]
        return ToolResult(
            True, self.name, f"enumerated {len(files)} file(s) under {target}", {"files": files}
        )
