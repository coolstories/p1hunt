"""The interaction engine harnesses import to test a live, authorized target (spec §10, §12).

This is the batteries-included client a web/API exploit harness uses instead of hand-rolling
``requests`` against hardcoded URLs. It is STDLIB-ONLY and SELF-CONTAINED (no p1hunt imports) so
the swarm can copy this one file into the PoC sandbox and a separate pytest process can import it.

What it gives a harness:
  * Multi-identity sessions — authenticate as principal A, B, a low-role user, etc., from tokens
    supplied via the environment (never hardcoded). Two identities are the core of IDOR/BOLA.
  * A scope-ENFORCED transport — every request host must be in the authorized egress allowlist (or
    loopback); a request to anything else raises ``ScopeError`` before a packet leaves. This makes
    the harness itself safe-harbor-correct, independent of the agent's bash jail.
  * Differential authz helpers — ``assert_forbidden`` / ``idor_probe`` express "B must not reach
    A's object" directly, so an IDOR PoC is a few lines.
  * Injection oracles — timing, boolean, and reflection helpers for SQLi/command-injection.
  * Out-of-band confirmation — ``oob_url(token)`` + ``oob_received(token)`` turn a BLIND SSRF/
    injection into a deterministic pass/fail via the loopback OOB listener.

All config comes from the environment (set by the swarm at arming time):
  P1HUNT_BASE_URL, P1HUNT_GQL_URL, P1HUNT_OOB_URL, P1HUNT_OOB_HITS,
  P1HUNT_EGRESS_ALLOWLIST (comma-separated hosts), and identity tokens
  P1HUNT_TOKEN / P1HUNT_TOKEN_A / P1HUNT_TOKEN_B / P1HUNT_TOKEN_LOW / P1HUNT_TOKEN_<NAME>.
"""

from __future__ import annotations

import json as _json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


class ScopeError(RuntimeError):
    """Raised when a harness tries to contact a host outside the authorized egress allowlist."""


def _host(url: str) -> str:
    return (urllib.parse.urlparse(url).hostname or "").lower().rstrip(".")


def _allowed(host: str, allowlist: list[str]) -> bool:
    if host in _LOOPBACK or host.endswith(".localhost"):
        return True
    for entry in allowlist:
        e = entry.strip().lower()
        if e and (host == e or host.endswith("." + e)):
            return True
    return False


class Response:
    """A minimal, dependency-free HTTP response wrapper."""

    def __init__(self, status: int, headers: dict, body: bytes, elapsed: float, url: str) -> None:
        self.status = status
        self.status_code = status  # requests-style alias
        self.headers = headers
        self.content = body
        self.text = body.decode("utf-8", "replace")
        self.elapsed = elapsed
        self.url = url

    def json(self):
        return _json.loads(self.text) if self.text else None

    def __repr__(self) -> str:
        return f"<Response {self.status} {self.url} {len(self.content)}b {self.elapsed:.3f}s>"


class Client:
    """A scope-enforced, multi-identity HTTP client for live dynamic testing."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        egress_allowlist: list[str] | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.base_url = (base_url or os.environ.get("P1HUNT_BASE_URL", "")).rstrip("/")
        env_allow = [h for h in os.environ.get("P1HUNT_EGRESS_ALLOWLIST", "").split(",") if h.strip()]
        self.egress_allowlist = [h.strip() for h in (egress_allowlist or env_allow)]
        if self.base_url and _host(self.base_url) not in self.egress_allowlist:
            self.egress_allowlist.append(_host(self.base_url))
        self.timeout = timeout

    # --- identity ---------------------------------------------------------
    def token_for(self, identity: str | None) -> str:
        """Resolve a principal's bearer token from the environment. '' / None / 'default' map to
        P1HUNT_TOKEN; a named identity 'X' maps to P1HUNT_TOKEN_X."""
        if not identity or identity.strip().lower() == "default":
            return os.environ.get("P1HUNT_TOKEN", "")
        return os.environ.get(f"P1HUNT_TOKEN_{identity.strip().upper()}", "")

    def identities(self) -> list[str]:
        """Names of every identity with a token configured in the environment."""
        out = []
        for k in os.environ:
            if k.startswith("P1HUNT_TOKEN_") and os.environ[k]:
                out.append(k[len("P1HUNT_TOKEN_"):].lower())
            elif k == "P1HUNT_TOKEN" and os.environ[k]:
                out.append("default")
        return sorted(set(out))

    # --- core transport ---------------------------------------------------
    def _url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return f"{self.base_url}/{path_or_url.lstrip('/')}"

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        identity: str | None = None,
        token: str | None = None,
        headers: dict | None = None,
        json: object = None,
        data: bytes | str | None = None,
        params: dict | None = None,
    ) -> Response:
        """Issue ONE scope-checked request. Raises ScopeError if the host is out of scope."""
        url = self._url(path_or_url)
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        host = _host(url)
        if not _allowed(host, self.egress_allowlist):
            raise ScopeError(
                f"refusing to contact out-of-scope host {host!r}; authorized: "
                f"{self.egress_allowlist or '(none)'}")
        hdrs = {k: str(v) for k, v in (headers or {}).items()}
        bearer = token if token is not None else self.token_for(identity)
        if bearer and "Authorization" not in hdrs:
            hdrs["Authorization"] = f"Bearer {bearer}"
        body: bytes | None = None
        if json is not None:
            body = _json.dumps(json).encode()
            hdrs.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            body = data.encode()
        elif isinstance(data, (bytes, bytearray)):
            body = bytes(data)
        req = urllib.request.Request(url, data=body, method=method.upper(), headers=hdrs)
        started = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 — scope-checked
                return Response(resp.status, dict(resp.headers), resp.read(), time.time() - started, url)
        except urllib.error.HTTPError as exc:  # 4xx/5xx are real, useful results
            body_b = b""
            try:
                body_b = exc.read()
            except Exception:
                pass
            finally:
                exc.close()
            return Response(exc.code, dict(exc.headers or {}), body_b, time.time() - started, url)

    def get(self, p, **kw):     return self.request("GET", p, **kw)
    def post(self, p, **kw):    return self.request("POST", p, **kw)
    def put(self, p, **kw):     return self.request("PUT", p, **kw)
    def patch(self, p, **kw):   return self.request("PATCH", p, **kw)
    def head(self, p, **kw):    return self.request("HEAD", p, **kw)

    # --- authorization / IDOR-BOLA helpers --------------------------------
    def is_authorized(self, resp: Response) -> bool:
        """True if the server PERMITTED the action (2xx). An IDOR/BOLA bug is a 2xx where a refusal
        (401/403/404) was required for the requesting principal."""
        return 200 <= resp.status < 300

    def assert_forbidden(self, method: str, path_or_url: str, *, identity: str, **kw) -> Response:
        """Assert ``identity`` is REFUSED (401/403/404) on ``path``. Raises AssertionError (an
        authz bypass — the PoC) if the action was permitted instead."""
        resp = self.request(method, path_or_url, identity=identity, **kw)
        assert resp.status in (401, 403, 404), (
            f"AUTHZ BYPASS: {identity} {method} {path_or_url} -> {resp.status} "
            f"(a refusal was required) — IDOR/BOLA/auth-bypass")
        return resp

    def idor_probe(self, method: str, path_template: str, *, owner: str, attacker: str,
                   resource_id) -> Response:
        """Owner creates/holds ``resource_id``; assert the attacker principal cannot reach it.
        ``path_template`` contains ``{id}``. Returns the attacker's (refused) response."""
        path = path_template.format(id=resource_id)
        return self.assert_forbidden(method, path, identity=attacker)

    # --- injection oracles ------------------------------------------------
    def timing_oracle(self, method: str, path_or_url: str, *, baseline_payload, slow_payload,
                      param: str, threshold: float = 4.0, identity: str | None = None) -> dict:
        """Blind/time-based oracle: compare response time of a benign vs a delay-inducing payload.
        Returns {triggered, baseline_s, slow_s, delta_s}. ``triggered`` means the slow payload took
        at least ``threshold`` seconds longer — evidence of time-based SQLi/command injection."""
        b = self.request(method, path_or_url, params={param: baseline_payload}, identity=identity)
        s = self.request(method, path_or_url, params={param: slow_payload}, identity=identity)
        delta = s.elapsed - b.elapsed
        return {"triggered": delta >= threshold, "baseline_s": b.elapsed,
                "slow_s": s.elapsed, "delta_s": delta}

    def reflects(self, resp: Response, marker: str) -> bool:
        """True if a unique marker is echoed in the response (reflection/error-based injection)."""
        return marker in resp.text

    def marker(self, prefix: str = "p1h") -> str:
        return f"{prefix}{uuid.uuid4().hex[:12]}"

    # --- out-of-band (blind) confirmation ---------------------------------
    def oob_url(self, token: str | None = None) -> tuple[str, str]:
        """Return ``(url, token)`` pointing at the loopback OOB listener. Embed ``url`` where the
        target may dereference it (SSRF sink, webhook, XML entity); later assert ``oob_received``."""
        base = os.environ.get("P1HUNT_OOB_URL", "").rstrip("/")
        tok = token or uuid.uuid4().hex[:16]
        return (f"{base}/{tok}" if base else f"/{tok}"), tok

    def oob_received(self, token: str, *, wait: float = 3.0) -> bool:
        """True if the OOB listener recorded a callback carrying ``token`` (polls up to ``wait``s).
        Reads the hits file the swarm's listener appends to (cross-process channel)."""
        hits = os.environ.get("P1HUNT_OOB_HITS", "")
        if not hits:
            return False
        deadline = time.time() + max(0.0, wait)
        while True:
            try:
                with open(hits, encoding="utf-8") as fh:
                    if any(token in line for line in fh):
                        return True
            except OSError:
                pass
            if time.time() >= deadline:
                return False
            time.sleep(0.25)


def from_env() -> Client:
    """Construct a Client wholly from the swarm-provided environment (the harness entrypoint)."""
    return Client()
