"""http_sandbox — authorized, scope-checked live HTTP (spec §12).

Every call passes ScopeGuard first (the egress jail: in-scope host + method allowlist + rate
limit). In dry-run the tool never touches the network — it returns the gated plan so the operator
sees exactly what *would* be sent. In active mode it issues ONE real request with stdlib
``urllib`` (no third-party dependency), bounded by a timeout, and returns a structured, redacted
result. Destructive verbs are simply not implemented; only the methods the policy allows can be
issued, and the host must already have cleared the guard.

OFFLINE-GRACEFUL: a network/connection error returns ``ok=False`` with the reason — it never
raises out of ``run`` — so a hunt is never aborted by a flaky endpoint.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from .base import ToolResult

# Read verbs are always safe; write verbs require the policy to have unlocked them (active +
# authorized dynamic target) — the ScopeGuard wrapper enforces that before we are ever called.
_KNOWN_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}
_MAX_BODY = 8192  # bytes of response body captured (least-data evidence, §9)


class HttpSandbox:
    name = "http_sandbox"
    read_only = False  # may issue authorized writes in active mode; the guard gates which verbs

    def __init__(self, active: bool = False, *, timeout: float = 15.0) -> None:
        self.active = active
        self.timeout = timeout

    async def run(self, args: dict) -> ToolResult:
        method = str(args.get("http_method", args.get("method", "GET"))).upper()
        # URL must arrive under `url` (not `target`) so the ScopeGuard network branch always sees
        # it as a live call and applies the egress jail — no alias can route around the gate.
        url = args.get("url") or ""
        if method not in _KNOWN_METHODS:
            return ToolResult(False, self.name, f"method {method} is not a supported verb")
        if not url:
            return ToolResult(False, self.name, "no url provided")
        if not self.active:
            return ToolResult(
                True, self.name,
                f"[dry-run] would issue {method} {url} (gated, rate-limited)",
                {"method": method, "url": url, "performed": False},
            )

        headers = {k: str(v) for k, v in (args.get("headers") or {}).items()}
        body = args.get("body")
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            import asyncio

            def _send() -> tuple[int, str, str]:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 — guarded host
                    raw = resp.read(_MAX_BODY)
                    return resp.status, dict(resp.headers).get("Content-Type", ""), raw.decode("utf-8", "replace")

            status, ctype, text = await asyncio.to_thread(_send)
            return ToolResult(
                True, self.name, f"{method} {url} -> {status}",
                {"method": method, "url": url, "performed": True, "status": status,
                 "content_type": ctype, "body_excerpt": text[:_MAX_BODY]},
            )
        except urllib.error.HTTPError as exc:  # a real HTTP response (4xx/5xx) — still a result
            text = ""
            try:
                text = exc.read(_MAX_BODY).decode("utf-8", "replace")
            except Exception:
                pass
            return ToolResult(
                True, self.name, f"{method} {url} -> {exc.code}",
                {"method": method, "url": url, "performed": True, "status": exc.code,
                 "body_excerpt": text[:_MAX_BODY]},
            )
        except (urllib.error.URLError, OSError, ValueError) as exc:  # offline-graceful
            return ToolResult(
                False, self.name, f"{method} {url} could not be reached: {exc}",
                {"method": method, "url": url, "performed": False, "error": str(exc)},
            )
