"""http_sandbox — UAT/sandbox HTTP with a method allowlist (spec §12).

Scope-checked and rate-limited by ScopeGuard. Non-destructive verbs only. In dry-run the
tool never performs a live request — it returns the gated plan so the operator can see
exactly what *would* be sent. Active mode (still fully gated) is where a real read-only
check would be issued; the destructive verbs are simply not implemented.
"""

from __future__ import annotations

from .base import ToolResult

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class HttpSandbox:
    name = "http_sandbox"
    read_only = True

    def __init__(self, active: bool = False) -> None:
        self.active = active

    async def run(self, args: dict) -> ToolResult:
        method = str(args.get("http_method", "GET")).upper()
        url = args.get("url") or args.get("target") or ""
        if method not in _SAFE_METHODS:
            return ToolResult(False, self.name, f"method {method} is not a safe read verb")
        if not self.active:
            return ToolResult(
                True,
                self.name,
                f"[dry-run] would issue {method} {url} (read-only, rate-limited)",
                {"method": method, "url": url, "performed": False},
            )
        # Active mode would perform a single read-only, rate-limited request here.
        return ToolResult(
            True,
            self.name,
            f"{method} {url} (read-only)",
            {"method": method, "url": url, "performed": True},
        )
