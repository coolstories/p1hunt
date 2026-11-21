"""http_sandbox — authorized, scope-checked live HTTP (spec §12).

Every call passes ScopeGuard first (the egress jail: in-scope host + method allowlist + rate
limit). In dry-run the tool never touches the network — it returns the gated plan so the operator
sees exactly what *would* be sent. In active mode it issues ONE real request with stdlib
``urllib`` (no third-party dependency), bounded by a timeout, and returns a structured, redacted
result. Destructive verbs are simply not implemented; only the methods the policy allows can be
issued, and the host must already have cleared the guard.

REDIRECTS ARE RE-CHECKED. The guard clears the host of the FIRST request only; a 302 (or an
in-scope OPEN REDIRECT, a routine bounty finding) would otherwise send the follow-up request
off-allowlist with the ``Authorization`` header attached, because the default urllib opener
follows redirects silently. Every hop now goes through the same egress check, and credentials are
stripped whenever the host changes (see ``_ScopedRedirectHandler``).

OFFLINE-GRACEFUL: a network/connection error returns ``ok=False`` with the reason — it never
raises out of ``run`` — so a hunt is never aborted by a flaky endpoint.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from ..dynamic.egress import normalize_host, url_allowed
from .base import ToolResult

# Read verbs are always safe; write verbs require the policy to have unlocked them (active +
# authorized dynamic target) — the ScopeGuard wrapper enforces that before we are ever called.
_KNOWN_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}
_MAX_BODY = 8192  # bytes of response body captured (least-data evidence, §9)
# Headers that must never survive a hop to a different host (they are the engagement's creds).
_CRED_HEADERS = ("Authorization", "Cookie", "Cookie2", "Proxy-authorization", "X-api-key",
                 "X-auth-token", "Authentication")


class RedirectDenied(urllib.error.URLError):
    """A redirect hop left the egress allowlist. A URLError subclass so ``run``'s existing
    offline-graceful branch reports it instead of letting it escape (never fail open)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.denied_reason = reason


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-check EVERY redirect hop against the egress jail; strip creds on a host change.

    With an allowlist, a hop is permitted only if ``url_allowed`` clears it. With no allowlist
    (the tool constructed bare, where ScopeGuard is the authority for the first URL), the only
    permitted hops are those that stay on the ALREADY-APPROVED host — a host change has not been
    through any gate, so it is denied rather than assumed safe."""

    def __init__(self, allowlist: list[str] | None, origin_url: str) -> None:
        self._allowlist = [str(h) for h in (allowlist or []) if str(h).strip()]
        self._has_allowlist = bool(self._allowlist)
        self._origin = normalize_host(origin_url)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_host = normalize_host(newurl)
        same_host = bool(new_host) and new_host == self._origin
        if not same_host:
            if self._has_allowlist:
                ok, why = url_allowed(newurl, self._allowlist)
            else:
                ok, why = False, (f"redirect to '{new_host or newurl}' leaves the approved host "
                                  f"'{self._origin}' and was never scope-checked")
            if not ok:
                raise RedirectDenied(
                    f"redirect ({code}) to {newurl} blocked by the egress jail: {why}")
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is not None and not same_host:
            # Cross-host hop to an in-scope host: allowed, but the engagement's credentials do not
            # travel with it (that is how a redirect turns into a credential leak).
            for name in _CRED_HEADERS:
                new_req.remove_header(name)
        return new_req


class HttpSandbox:
    name = "http_sandbox"
    read_only = False  # may issue authorized writes in active mode; the guard gates which verbs

    def __init__(self, active: bool = False, *, timeout: float = 15.0,
                 egress_allowlist: list[str] | None = None) -> None:
        self.active = active
        self.timeout = timeout
        # Optional: the authorized egress allowlist. When given, this tool re-checks the initial
        # URL and every redirect hop itself (defense in depth behind ScopeGuard). When omitted,
        # redirects may not change host at all.
        self.egress_allowlist = [str(h) for h in (egress_allowlist or []) if str(h).strip()]

    async def run(self, args: dict) -> ToolResult:
        method = str(args.get("http_method", args.get("method", "GET"))).upper()
        # The URL must arrive under `url`: that is the key ScopeGuard treats as the primary target
        # for a network call, and the one its `_connect_urls` check reports. (The guard now checks
        # EVERY connect-bearing key, so an alias such as `target` can no longer show the guard one
        # host while this tool contacts another — it used to.)
        url = args.get("url") or ""
        if method not in _KNOWN_METHODS:
            return ToolResult(False, self.name, f"method {method} is not a supported verb")
        if not url:
            return ToolResult(False, self.name, "no url provided")
        if self.egress_allowlist:
            ok, why = url_allowed(str(url), self.egress_allowlist)
            if not ok:
                return ToolResult(False, self.name, f"{method} {url} denied by the egress jail: {why}",
                                  {"method": method, "url": url, "performed": False, "error": why})
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
                # A dedicated opener: its redirect handler re-checks every hop. The DEFAULT opener
                # installs a plain HTTPRedirectHandler, which follows a 302 anywhere.
                opener = urllib.request.build_opener(
                    _ScopedRedirectHandler(self.egress_allowlist, str(url)))
                with opener.open(req, timeout=self.timeout) as resp:  # noqa: S310 — guarded host
                    raw = resp.read(_MAX_BODY)
                    return resp.status, dict(resp.headers).get("Content-Type", ""), raw.decode("utf-8", "replace")

            status, ctype, text = await asyncio.to_thread(_send)
            return ToolResult(
                True, self.name, f"{method} {url} -> {status}",
                {"method": method, "url": url, "performed": True, "status": status,
                 "content_type": ctype, "body_excerpt": text[:_MAX_BODY]},
            )
        except RedirectDenied as exc:  # off-allowlist hop — the follow-up was NOT sent
            return ToolResult(
                False, self.name, f"{method} {url}: {exc.denied_reason}",
                {"method": method, "url": url, "performed": True, "redirect_blocked": True,
                 "error": exc.denied_reason},
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
