"""The interaction engine harnesses import to test a live, authorized target (spec §10, §12).

This is the batteries-included client a web/API exploit harness uses instead of hand-rolling
``requests`` against hardcoded URLs. It is STDLIB-ONLY and SELF-CONTAINED (no p1hunt imports) so
the swarm can copy this one file into the PoC sandbox and a separate pytest process can import it.

SELF-CONTAINED ON PURPOSE — AND THAT IS WHY THE EGRESS JAIL IS VENDORED HERE.
``agents/claude_swarm.py::_arm_dynamic`` ships THIS ONE FILE into the PoC sandbox as
``p1hunt_dyn.py``; a separate pytest process then imports it with no ``p1hunt`` package on
``sys.path``. So this file may not import ``p1hunt.tools.http_sandbox`` or ``p1hunt.dynamic.egress``
even though they hold the same logic: the import would raise ``ModuleNotFoundError`` in the
sandbox and the harness would die (or, worse, a ``try/except ImportError`` around it would silently
drop the jail — a fail-OPEN path). The redirect jail (``_ScopedRedirectHandler``) and host
normalization (``_norm_host``) are therefore DUPLICATED from ``tools/http_sandbox.py`` /
``dynamic/egress.py`` as stdlib-only code, and ``tests/test_dynamic_client.py`` pins the two copies
to the same behavior (``TestVendoredJailParity``) so the duplication cannot drift.

What it gives a harness:
  * Multi-identity sessions — authenticate as principal A, B, a low-role user, etc., from tokens
    supplied via the environment (never hardcoded).
  * A scope-ENFORCED transport — every request host must be in the authorized egress allowlist (or
    loopback); a request to anything else raises ``ScopeError`` before a packet leaves. This makes
    the harness itself safe-harbor-correct, independent of the agent's bash jail. The allowlist is
    NEVER widened by the client itself: a ``base_url`` the operator did not authorize is a
    ``ScopeError`` at construction, not a new allowlist entry.
  * REDIRECT RE-CHECKING — every 30x hop is re-checked against the allowlist and credentials are
    stripped on a host change, so an in-scope open redirect (a routine bounty finding) cannot walk
    the ``Authorization`` header off-allowlist.
  * A RATE LIMIT + METHOD FLOOR — a per-host token bucket paces requests to the program's
    rate-of-engagement ceiling (``P1HUNT_RATE_LIMIT``), ``Retry-After`` is honored with jittered
    backoff, and destructive verbs (DELETE and friends) are refused unless explicitly unlocked.
  * Differential refusal helpers — ``assert_forbidden`` / ``idor_probe`` express "this principal
    must not reach that principal's object" directly.
  * BLOCKED/liveness classification — ``classify_block`` / ``baseline_health`` separate an EDGE
    (WAF/CDN/bot-challenge) block from an APPLICATION authorization decision. A blocked response
    is not evidence either way: the request never reached the code under test, so a refusal
    helper raises ``BlockedError`` instead of silently reporting "correctly refused".
  * Input-behavior oracles — timing, boolean, and reflection helpers.
  * Out-of-band confirmation — ``oob_url(token)`` + ``oob_received(token)`` turn callback-based
    behavior into a deterministic pass/fail via the loopback OOB listener.

All config comes from the environment (set by the swarm at arming time):
  P1HUNT_BASE_URL, P1HUNT_GQL_URL, P1HUNT_OOB_URL, P1HUNT_OOB_HITS,
  P1HUNT_EGRESS_ALLOWLIST (comma-separated hosts), and identity tokens
  P1HUNT_TOKEN / P1HUNT_TOKEN_A / P1HUNT_TOKEN_B / P1HUNT_TOKEN_LOW / P1HUNT_TOKEN_<NAME>.

Rate-of-engagement / fingerprint knobs (all optional, all fail-closed when malformed):
  P1HUNT_RATE_LIMIT       requests per minute per HOST (default 30; <=0 means NO live contact)
  P1HUNT_RATE_BURST       token-bucket capacity (default min(rate, 5))
  P1HUNT_RATE_MAX_WAIT    max seconds the limiter will pace ONE request before refusing (default 30)
  P1HUNT_RETRY_MAX        429/503 retries honoring Retry-After (default 2)
  P1HUNT_RETRY_MAX_WAIT   cap on one Retry-After sleep (default 60)
  P1HUNT_USER_AGENT       User-Agent to send (default: a realistic desktop-browser UA)
  P1HUNT_ID_HEADER        one operator identification header, "Name: value"
                          (e.g. "X-Bug-Bounty: my-h1-handle" — several programs REQUIRE one)
  P1HUNT_EXTRA_HEADERS    additional headers, "A: 1; B: 2" or newline-separated
  P1HUNT_ALLOW_DESTRUCTIVE_METHODS
                          comma-separated verbs to UNLOCK past the destructive floor (e.g. "DELETE")
"""

from __future__ import annotations

import email.utils
import json as _json
import os
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


class ScopeError(RuntimeError):
    """Raised when a harness tries to contact a host outside the authorized egress allowlist."""


class RedirectDenied(ScopeError):
    """A 30x hop left the egress allowlist, so the follow-up request was NOT sent.

    A ``ScopeError`` subclass: it IS an out-of-scope contact attempt, just one the target asked
    for rather than one the harness wrote. Harnesses that already catch ``ScopeError`` keep
    working, and a runner can tell the two apart when it wants to."""


class MethodDenied(ScopeError):
    """A destructive HTTP verb was refused by the client's method floor.

    A ``ScopeError`` subclass for the same reason ``RedirectDenied`` is: the safety layer refused
    to put the request on the wire. Deliberately NOT an ``AssertionError`` — a refused DELETE is a
    harness bug, never a finding."""


class RateLimitExceeded(RuntimeError):
    """The per-host token bucket could not admit this request within ``P1HUNT_RATE_MAX_WAIT``.

    Fail-CLOSED: nothing was sent. Deliberately NOT an ``AssertionError`` (not a finding) and not
    a ``BlockedError`` (no edge answered — we never asked)."""


class BlockedError(RuntimeError):
    """Raised when an EDGE (WAF/CDN/bot-challenge/rate-limiter) answered instead of the target.

    This is deliberately NOT an ``AssertionError``. An ``AssertionError`` out of a refusal helper
    means "the application permitted something it must not" — the PoC signal. A ``BlockedError``
    means the application was never consulted, so the response is evidence of NOTHING: not a
    refusal, not a bypass. Runners map it to ``ran=False`` so the finding stays a candidate rather
    than being stamped reproduced (or quarantined) off an edge block.
    """


# A stable sentinel embedded in every BlockedError message. The harness runs in a separate pytest
# process, so the runner can only see this through the captured output — it greps for this token.
BLOCKED_MARKER = "P1HUNT_BLOCKED"

# Headers by which an edge EXPLICITLY states it mitigated the request. Decisive on their own.
_MITIGATION_HEADERS = ("cf-mitigated", "x-cf-mitigated")

# Markers that only prove a WAF/CDN sits IN FRONT of the origin. These are NOT a block by
# themselves: most authorized targets are fronted by Cloudflare/Akamai/Imperva and still return
# genuine application 403s. They count only WITH corroboration (see ``classify_block`` rule 4).
_VENDOR_HEADER_MARKERS = ("cf-ray", "x-akamai", "x-iinfo")
_VENDOR_SERVER_TOKENS = ("cloudflare", "akamaighost", "akamai", "incapsula", "imperva")
_VENDOR_COOKIE_TOKENS = ("incap_ses", "visid_incap", "__cf_bm", "cf_clearance")

# Interstitial / block-page body text. An application authorization refusal never renders a
# bot-challenge page, so these are decisive at ANY status code.
_CHALLENGE_BODY_MARKERS = (
    "just a moment",
    "checking your browser",
    "attention required",
    "enable javascript and cookies to continue",
    "cf-browser-verification",
    "_cf_chl_opt",
    "cf_chl_",
    "ddos protection by",
    "request unsuccessful. incapsula incident id",
    "incapsula incident id",
    "access denied: you don't have permission to access",
    "sorry, you have been blocked",
    "you have been blocked",
)

# Statuses at which a mere vendor marker may corroborate into a block (with an HTML block page).
_VENDOR_BLOCK_STATUSES = frozenset({403, 503})
_BODY_SCAN_LIMIT = 8192


def _lower_headers(resp: object) -> dict:
    raw = getattr(resp, "headers", None) or {}
    try:
        items = raw.items()
    except AttributeError:
        return {}
    return {str(k).lower(): str(v).lower() for k, v in items}


def _vendor_marker(headers: dict) -> str:
    """Name the WAF/CDN vendor visible in ``headers``, or '' when none is."""
    for key in headers:
        for marker in _VENDOR_HEADER_MARKERS:
            if key.startswith(marker):
                return f"vendor header {key!r}"
    server = headers.get("server", "")
    for token in _VENDOR_SERVER_TOKENS:
        if token in server:
            return f"server: {token}"
    cookies = headers.get("set-cookie", "")
    for token in _VENDOR_COOKIE_TOKENS:
        if token in cookies:
            return f"vendor cookie {token}"
    return ""


def _looks_like_html(headers: dict, body: str) -> bool:
    if "text/html" in headers.get("content-type", ""):
        return True
    return body.lstrip()[:200].startswith(("<!doctype html", "<html"))


def classify_block(resp: object) -> str:
    """Return a non-empty REASON when ``resp`` is an edge BLOCK, or '' when the application answered.

    '' means "the target decided" — including a genuine ``403``/``401``/``404`` refusal, which is
    exactly what an authorization harness must be able to observe.

    CONSERVATIVE BY DESIGN. A bare ``403`` with no block markers is a legitimate authorization
    refusal and returns ''. Even a ``403`` from behind Cloudflare stays a refusal unless the edge
    says it mitigated, serves a challenge/block PAGE, or rate-limits. The cost of the two mistakes
    is asymmetric: calling a WAF page a "refusal" corrupts the verdict (bug 2 of this module's
    audit), while calling a real refusal "blocked" only forces a re-run (``ran=False``).
    """
    status = int(getattr(resp, "status", getattr(resp, "status_code", 0)) or 0)
    headers = _lower_headers(resp)
    body = (getattr(resp, "text", "") or "")[:_BODY_SCAN_LIMIT].lower()

    # 1. The edge explicitly states it acted. Decisive at any status.
    for h in _MITIGATION_HEADERS:
        if h in headers:
            return f"edge mitigation header {h!r}={headers[h] or '(set)'}"

    # 2. A JS-challenge / vendor block page. Decisive at any status: an application authz refusal
    #    never renders a browser-verification interstitial.
    for marker in _CHALLENGE_BODY_MARKERS:
        if marker in body:
            return f"challenge/block page body marker {marker!r}"

    # 3. Rate limiting is never an authorization verdict.
    if status == 429:
        return "HTTP 429 rate-limited at the edge (not an authorization decision)"

    # 4. A vendor marker PLUS a blocking status PLUS an HTML (not application/JSON) body. A
    #    JSON/empty 403 from behind a CDN is a real application refusal and must stay refused.
    if status in _VENDOR_BLOCK_STATUSES:
        vendor = _vendor_marker(headers)
        if vendor and _looks_like_html(headers, body):
            return f"HTTP {status} with {vendor} and an HTML edge block page"
        if vendor and status == 503:
            return f"HTTP {status} with {vendor} — edge unavailable, origin never consulted"
    return ""


def is_blocked(resp: object) -> bool:
    """True when an edge (WAF/CDN/challenge/rate-limiter) answered instead of the target."""
    return bool(classify_block(resp))


def _norm_host(url_or_host: str) -> str:
    """Lowercased hostname with any port/userinfo/brackets stripped. Accepts a full URL, a
    ``host:port``, or a bare host; returns "" when nothing host-like is present.

    VENDORED from ``p1hunt.dynamic.egress.normalize_host`` — see the module docstring for why this
    file cannot import it. ``tests/test_dynamic_client.py::TestVendoredJailParity`` asserts the two
    agree on a corpus of inputs, so the copy cannot drift.

    Normalizing ALLOWLIST entries too (not just targets) is what lets an operator authorize
    ``https://api.example.com`` or ``example.com:8443`` and have it mean the host they wrote."""
    if not url_or_host:
        return ""
    s = str(url_or_host).strip()
    if "://" in s:
        s = urllib.parse.urlparse(s).hostname or ""
    else:
        s = s.split("/")[0]
        if "@" in s:
            s = s.rsplit("@", 1)[1]
        if s.startswith("["):  # [::1]:8080
            s = s[1: s.find("]")] if "]" in s else s[1:]
        elif s.count(":") == 1:  # host:port (a lone colon => port; many => IPv6, leave it)
            s = s.split(":")[0]
    return s.strip().lower().rstrip(".")


# Back-compat alias: ``_host`` was the original name and is used by harnesses in the wild.
_host = _norm_host


def _allowed(host: str, allowlist: list[str]) -> bool:
    """True when ``host`` is loopback or equals/is a subdomain of an authorized allowlist entry."""
    h = _norm_host(host)
    if not h:
        return False
    if h in _LOOPBACK or h.endswith(".localhost"):
        return True
    for entry in allowlist:
        e = _norm_host(entry)
        if e and (h == e or h.endswith("." + e)):
            return True
    return False


# Headers that must never survive a hop to a different host (they are the engagement's creds).
_CRED_HEADERS = ("Authorization", "Cookie", "Cookie2", "Proxy-authorization", "X-api-key",
                 "X-auth-token", "Authentication")


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-check EVERY redirect hop against the egress allowlist; strip creds on a host change.

    VENDORED from ``p1hunt.tools.http_sandbox._ScopedRedirectHandler`` (stdlib-only; see the module
    docstring for why the import is not available here). The default urllib opener installs a plain
    ``HTTPRedirectHandler``, which follows a 302 ANYWHERE with the original headers attached — so
    an in-scope host that 302s off-allowlist, or an in-scope OPEN REDIRECT (a routine bounty
    finding), would hand the target's ``Authorization`` header to a third party. Every hop now goes
    through the same check that cleared the first request, and a hop that fails it raises
    ``RedirectDenied`` INSTEAD of sending anything.

    Note the asymmetry with the first-request check in :meth:`Client.request`: that one is also the
    gate here. A same-host hop needs no re-authorization (the host already cleared); a host CHANGE
    must clear the allowlist on its own, and keeps none of the credentials."""

    def __init__(self, allowlist: list[str], origin_url: str) -> None:
        self._allowlist = [str(h) for h in (allowlist or []) if str(h).strip()]
        self._origin = _norm_host(origin_url)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # ``newurl`` has already been resolved against the request URL by urllib, so a relative
        # ``Location: /next`` arrives absolute here.
        scheme = urllib.parse.urlparse(newurl).scheme.lower()
        if scheme not in ("http", "https"):
            # urllib's own handler would still follow an ftp:// hop. There is no reason for an
            # HTTP harness to change protocol mid-chain, so it is refused rather than inspected.
            raise RedirectDenied(
                f"refusing to follow redirect ({code}) to {newurl!r}: scheme {scheme or '(none)'!r} "
                "is not http/https. The follow-up request was NOT sent.")
        new_host = _norm_host(newurl)
        same_host = bool(new_host) and new_host == self._origin
        if not same_host and not _allowed(new_host, self._allowlist):
            raise RedirectDenied(
                f"refusing to follow redirect ({code}) to {newurl!r}: host {new_host or '(none)'!r} "
                f"is not in the authorized egress allowlist {self._allowlist or '(none)'}. "
                "The follow-up request was NOT sent.")
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is not None and not same_host:
            # Cross-host hop to an in-scope host: permitted, but the engagement's credentials do
            # NOT travel with it — that is exactly how a redirect becomes a credential leak.
            for name in _CRED_HEADERS:
                new_req.remove_header(name)
        return new_req


# --- rate of engagement ------------------------------------------------------------------------
# A realistic desktop-browser UA. ``Python-urllib/3.x`` is bot-blocked on sight by most real
# targets (every request then becomes an edge block, i.e. evidence of nothing). Override with
# P1HUNT_USER_AGENT — and set P1HUNT_ID_HEADER when the program requires an identifying header.
_DEFAULT_USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")

# The destructive-verb floor, mirroring ``safety/policies._LIVE_WRITE_METHODS``: reads plus the
# non-destructive writes needed to demonstrate an authorized workflow. DELETE is excluded because
# it is the one common verb whose accidental success is irreversible even on an owned/UAT object.
_DEFAULT_METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH")

_DEFAULT_RATE_PER_MINUTE = 30   # matches safety/policies._rate_from_rules' fallback
_DEFAULT_RATE_MAX_WAIT = 30.0
_DEFAULT_RETRY_MAX = 2
# Cap on ONE in-line retry sleep. Deliberately SMALL: a target that answers "Retry-After: 600" must
# not freeze the harness for ten minutes — the throttled response is returned instead (so
# ``classify_block`` flags the 429 and the run is ``ran=False``), and the host COOLDOWN below is
# what actually keeps us from hammering it. Raise it only if you want in-line waits that long.
_DEFAULT_RETRY_MAX_WAIT = 5.0
# Backoff applied to a host that throttled us but sent no Retry-After, so "no header" still means
# "slow down" rather than "retry immediately".
_DEFAULT_THROTTLE_COOLDOWN = 10.0
# Ceiling on a host cooldown taken from Retry-After. A program asking for 10 minutes is honored;
# a buggy or hostile ``Retry-After: 86400`` must not brick the engagement for a day.
_COOLDOWN_CAP = 300.0
_THROTTLED_STATUSES = frozenset({429, 503})


def _env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    """An env-configured float that FAILS CLOSED: a malformed value falls back to the default
    rather than to "no limit"."""
    try:
        val = float(str(os.environ.get(name, "")).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, val)


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    try:
        val = int(float(str(os.environ.get(name, "")).strip()))
    except (TypeError, ValueError):
        return default
    return max(minimum, val)


class _TokenBucket:
    """Per-HOST token bucket that PACES requests instead of denying them.

    Keyed on the host, never the full URL: a program's rate limit is a ceiling for a HOST, and
    keying on the URL makes it meaningless (vary the path and every request starts a fresh window).
    This mirrors ``safety.scopeguard.RateLimiter.key_for``, but with the opposite remedy: the
    ScopeGuard is a GUARD, so a breach there is a deny; a harness that merely wants to go faster
    than the program allows should be SLOWED, not failed — otherwise the fix costs capability and
    gets switched off. A request that cannot be admitted within ``max_wait`` is refused outright
    (``RateLimitExceeded``), so there is no unbounded hang and no fail-open path.

    LOOPBACK IS EXEMPT: the local OOB listener and a locally stood-up instance are not the
    program's host and have no rate of engagement to honor.
    """

    def __init__(self, per_minute: float, burst: float, max_wait: float) -> None:
        self.per_minute = float(per_minute)
        self.rate = self.per_minute / 60.0           # tokens per second
        self.burst = max(1.0, float(burst))
        self.max_wait = max(0.0, float(max_wait))
        self._lock = threading.Lock()
        self._tokens: dict[str, float] = {}
        self._last: dict[str, float] = {}
        self._cooldown: dict[str, float] = {}   # host -> monotonic deadline from a 429/503

    @staticmethod
    def _key(host: str) -> str:
        return _norm_host(host) or str(host or "").strip().lower()

    @staticmethod
    def _exempt(key: str) -> bool:
        """Loopback is exempt: the local OOB listener / a locally stood-up instance is not the
        program's host and has no rate of engagement (or backoff) to honor."""
        return key in _LOOPBACK or key.endswith(".localhost")

    def penalize(self, host: str, seconds: float, *, now=time.monotonic) -> None:
        """Hold off ``host`` for ``seconds`` because it just throttled us (429/503).

        This, not the in-line retry, is what keeps a harness from hammering a target that asked
        for a long pause: the NEXT request to the host waits out (or refuses on) the remainder."""
        key = self._key(host)
        if self._exempt(key) or seconds <= 0:
            return
        with self._lock:
            deadline = now() + float(seconds)
            self._cooldown[key] = max(self._cooldown.get(key, 0.0), deadline)

    def take(self, host: str, *, sleep=time.sleep, now=time.monotonic) -> float:
        """Consume one token for ``host``, sleeping if needed. Returns the seconds slept.

        Raises ``RateLimitExceeded`` when admission would take longer than ``max_wait`` — nothing
        is sent in that case."""
        key = self._key(host)
        if self._exempt(key):
            return 0.0
        if self.per_minute <= 0:
            # Same floor as ScopeGuard's limiter: no rate => no live contact is permitted.
            raise RateLimitExceeded(
                f"{BLOCKED_MARKER}: P1HUNT_RATE_LIMIT is {self.per_minute:g} requests/min — no "
                f"live contact to {key!r} is permitted, so nothing was sent and this run proves "
                "nothing. Set P1HUNT_RATE_LIMIT to the program's documented rate.")
        cooling = max(0.0, self._cooldown.get(key, 0.0) - now())
        if cooling > 0:
            if cooling > self.max_wait:
                raise RateLimitExceeded(
                    f"{BLOCKED_MARKER}: {key!r} throttled us and asked for {cooling:.0f}s more "
                    f"before the next request, over the {self.max_wait:g}s P1HUNT_RATE_MAX_WAIT "
                    "cap — nothing was sent, so this run proves nothing.")
            sleep(cooling)
            self._cooldown.pop(key, None)
        # The pacing sleep below is held UNDER the lock on purpose: if it were released first,
        # every waiting thread would compute ``need`` from the same token state and all of them
        # would proceed, which is exactly the burst the limit exists to prevent.
        with self._lock:
            t = now()
            tokens = self._tokens.get(key, self.burst)
            tokens = min(self.burst, tokens + (t - self._last.get(key, t)) * self.rate)
            self._last[key] = t
            if tokens >= 1.0:
                self._tokens[key] = tokens - 1.0
                return cooling
            need = (1.0 - tokens) / self.rate
            if need > self.max_wait:
                self._tokens[key] = tokens
                raise RateLimitExceeded(
                    f"{BLOCKED_MARKER}: rate limit for {key!r} ({self.per_minute:g}/min) needs "
                    f"{need:.1f}s to admit this request, over the {self.max_wait:g}s "
                    "P1HUNT_RATE_MAX_WAIT cap — nothing was sent, so this run proves nothing. "
                    "Slow the harness down or raise the cap.")
            sleep(need)
            t2 = now()
            tokens = min(self.burst, tokens + (t2 - self._last[key]) * self.rate)
            self._last[key] = t2
            self._tokens[key] = max(0.0, tokens - 1.0)
            return cooling + need


def _retry_after_seconds(headers: dict, *, cap: float) -> float:
    """``Retry-After`` in seconds (delta-seconds OR an HTTP-date), clamped to ``[0, cap]``.
    Returns 0.0 when the header is absent or unparseable."""
    raw = ""
    for key, val in (headers or {}).items():
        if str(key).lower() == "retry-after":
            raw = str(val).strip()
            break
    if not raw:
        return 0.0
    try:
        return max(0.0, min(cap, float(raw)))
    except (TypeError, ValueError):
        pass
    try:
        when = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return 0.0
    if when is None:
        return 0.0
    try:
        delta = when.timestamp() - time.time()
    except (OSError, OverflowError, ValueError):
        return 0.0
    return max(0.0, min(cap, delta))


def _final_url(resp: object, requested: str) -> str:
    """The URL a response actually came from (after any re-checked, in-scope redirect hops)."""
    getter = getattr(resp, "geturl", None)
    if callable(getter):
        try:
            return str(getter() or requested)
        except Exception:
            return requested
    return str(getattr(resp, "url", "") or requested)


def _parse_header_pairs(raw: str) -> dict:
    """``"A: 1; B: 2"`` (or newline-separated) -> ``{"A": "1", "B": "2"}``. Malformed entries are
    skipped rather than guessed at."""
    out: dict = {}
    for chunk in str(raw or "").replace("\n", ";").split(";"):
        if ":" not in chunk:
            continue
        name, _, value = chunk.partition(":")
        name, value = name.strip(), value.strip()
        if name and value:
            out[name] = value
    return out


class Response:
    """A minimal, dependency-free HTTP response wrapper."""

    def __init__(self, status: int, headers: dict, body: bytes, elapsed: float, url: str,
                 final_url: str = "") -> None:
        self.status = status
        self.status_code = status  # requests-style alias
        self.headers = headers
        self.content = body
        self.text = body.decode("utf-8", "replace")
        self.elapsed = elapsed
        self.url = url
        # Where the response actually came from after any (re-checked, in-scope) redirect hops.
        # ``url`` stays the URL the harness ASKED for, so existing assertions keep their meaning.
        self.final_url = final_url or url

    @property
    def redirected(self) -> bool:
        """True when in-scope redirect hops moved the response off the requested URL."""
        return self.final_url != self.url

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
        rate_limit: float | None = None,
        rate_burst: float | None = None,
        rate_max_wait: float | None = None,
        allow_methods: list[str] | None = None,
        user_agent: str | None = None,
        default_headers: dict | None = None,
    ) -> None:
        self.base_url = (base_url or os.environ.get("P1HUNT_BASE_URL", "")).rstrip("/")
        env_allow = [h.strip() for h in
                     os.environ.get("P1HUNT_EGRESS_ALLOWLIST", "").split(",") if h.strip()]
        asked = [str(h).strip() for h in (egress_allowlist or env_allow) if str(h).strip()]
        # THE OPERATOR'S ALLOWLIST IS A CEILING, NOT A DEFAULT. When the swarm exported one, an
        # ``egress_allowlist=[...]`` argument may only NARROW it: a harness is LLM-authored, so
        # letting its own constructor argument ADD a host is the same self-authorization hole as
        # the ``base_url`` one below, just spelled differently.
        if env_allow:
            self.egress_allowlist = [h for h in asked if _allowed(h, env_allow)] or list(env_allow)
        else:
            self.egress_allowlist = asked
        # THE ALLOWLIST IS NOT SELF-EXTENDING. This used to append ``_host(base_url)`` when it was
        # absent, which made the "independent transport check" unfalsifiable: harnesses are
        # LLM-authored and run in a separate pytest process, so one that hardcoded its own
        # ``Client("https://attacker.tld", ...)`` authorized its own destination and the jail
        # became a no-op. A base_url the operator did not authorize is now an error, not a grant.
        if self.base_url and not _allowed(_norm_host(self.base_url), self.egress_allowlist):
            raise ScopeError(
                f"base_url host {_norm_host(self.base_url)!r} is NOT in the authorized egress "
                f"allowlist {self.egress_allowlist or '(none)'}. The client does not authorize its "
                "own target: add the host to the engagement scope (P1HUNT_EGRESS_ALLOWLIST) if it "
                "is genuinely in scope, or point the harness at an authorized target.")
        self.timeout = timeout

        # --- rate of engagement (per-host pacing; loopback exempt) ---
        per_minute = (float(rate_limit) if rate_limit is not None
                      else _env_float("P1HUNT_RATE_LIMIT", float(_DEFAULT_RATE_PER_MINUTE)))
        burst = (float(rate_burst) if rate_burst is not None
                 else _env_float("P1HUNT_RATE_BURST", max(1.0, min(per_minute, 5.0)), minimum=1.0))
        max_wait = (float(rate_max_wait) if rate_max_wait is not None
                    else _env_float("P1HUNT_RATE_MAX_WAIT", _DEFAULT_RATE_MAX_WAIT))
        self.rate_limit = per_minute
        self._bucket = _TokenBucket(per_minute, burst, max_wait)
        self.retry_max = _env_int("P1HUNT_RETRY_MAX", _DEFAULT_RETRY_MAX)
        self.retry_max_wait = _env_float("P1HUNT_RETRY_MAX_WAIT", _DEFAULT_RETRY_MAX_WAIT)

        # --- method floor: destructive verbs stay locked unless explicitly unlocked ---
        unlocked = [m.strip().upper() for m in
                    os.environ.get("P1HUNT_ALLOW_DESTRUCTIVE_METHODS", "").split(",") if m.strip()]
        base_methods = ([m.strip().upper() for m in allow_methods] if allow_methods is not None
                        else list(_DEFAULT_METHODS))
        self.allow_methods = list(dict.fromkeys([*base_methods, *unlocked]))

        # --- fingerprint: a realistic UA + any operator identification header ---
        self.user_agent = (user_agent if user_agent is not None
                           else os.environ.get("P1HUNT_USER_AGENT", "").strip() or _DEFAULT_USER_AGENT)
        hdrs: dict = {}
        hdrs.update(_parse_header_pairs(os.environ.get("P1HUNT_EXTRA_HEADERS", "")))
        hdrs.update(_parse_header_pairs(os.environ.get("P1HUNT_ID_HEADER", "")))
        hdrs.update({k: str(v) for k, v in (default_headers or {}).items()})
        self.default_headers = hdrs

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
        """Issue ONE scope-checked, rate-paced request.

        Four ways this refuses to put a request on the wire, all fail-closed and none of them an
        ``AssertionError`` (so none can be mistaken for a finding):
          * ``ScopeError``        — the host is not in the authorized egress allowlist.
          * ``MethodDenied``     — the verb is past the destructive floor and was not unlocked.
          * ``RateLimitExceeded``— the program's rate of engagement cannot admit it in time.
          * ``RedirectDenied``   — a 30x hop pointed off-allowlist (the hop was NOT followed).

        ``Retry-After`` on a 429/503 is honored with jittered backoff up to ``P1HUNT_RETRY_MAX``
        attempts; the throttled response is still RETURNED when they run out, so
        ``classify_block`` keeps seeing the 429 and the verdict stays ``ran=False``.
        """
        verb = str(method).upper()
        if verb not in self.allow_methods:
            raise MethodDenied(
                f"refusing to issue {verb} — it is past the destructive-verb floor "
                f"(authorized: {', '.join(self.allow_methods)}). A destructive verb's accidental "
                "success is irreversible even on an owned/UAT object, so it must be unlocked "
                "explicitly: set P1HUNT_ALLOW_DESTRUCTIVE_METHODS or pass allow_methods=[...].")
        url = self._url(path_or_url)
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        host = _norm_host(url)
        if not _allowed(host, self.egress_allowlist):
            raise ScopeError(
                f"refusing to contact out-of-scope host {host!r}; authorized: "
                f"{self.egress_allowlist or '(none)'}")
        hdrs = {"User-Agent": self.user_agent}
        hdrs.update(self.default_headers)
        hdrs.update({k: str(v) for k, v in (headers or {}).items()})
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

        attempt = 0
        last: Response | None = None
        while True:
            # Pace to the program's rate of engagement BEFORE starting the clock, so a throttle
            # sleep never shows up as target latency (``timing_oracle`` depends on that).
            try:
                self._bucket.take(host)
            except RateLimitExceeded:
                if last is None:
                    raise           # nothing was ever sent — the harness must hear about it
                # We already have the target's (throttled) answer and the limiter now refuses the
                # RETRY. Return what we have: ``classify_block`` reads it as an edge block, which
                # is the same ``ran=False`` verdict but keeps the status and headers as evidence.
                return last
            # A dedicated opener per request: its redirect handler re-checks every hop against
            # THIS request's origin. The default opener follows a 302 anywhere, creds attached.
            opener = urllib.request.build_opener(_ScopedRedirectHandler(self.egress_allowlist, url))
            req = urllib.request.Request(url, data=body, method=verb, headers=hdrs)
            started = time.time()
            try:
                with opener.open(req, timeout=self.timeout) as resp:  # noqa: S310 — scope-checked
                    out = Response(resp.status, dict(resp.headers), resp.read(),
                                   time.time() - started, url, _final_url(resp, url))
            except urllib.error.HTTPError as exc:  # 4xx/5xx are real, useful results
                body_b = b""
                try:
                    body_b = exc.read()
                except Exception:
                    pass
                finally:
                    exc.close()
                out = Response(exc.code, dict(exc.headers or {}), body_b,
                               time.time() - started, url, _final_url(exc, url))
            if out.status not in _THROTTLED_STATUSES:
                return out
            # Being throttled is the program telling us to slow down, and the FIRST duty is to
            # stop pushing: hold the host off for the pause it named (or a default when it named
            # none) so every LATER request honors it, whether or not we retry this one now.
            pause = _retry_after_seconds(out.headers, cap=_COOLDOWN_CAP)
            self._bucket.penalize(host, pause or _DEFAULT_THROTTLE_COOLDOWN)
            if attempt >= self.retry_max or pause <= 0 or pause > self.retry_max_wait:
                # Either out of attempts, or the server named no pause / a pause too long to sit
                # on. Return the throttled response: ``classify_block`` reads a 429 as "an edge
                # answered, not the target", which is the honest ``ran=False`` verdict.
                return out
            # Jittered exponential backoff that never undercuts what the server asked for. The
            # jitter keeps parallel harnesses from resynchronizing into a new burst.
            wait = min(self.retry_max_wait, max(pause, 2.0 ** attempt))
            time.sleep(wait * (1.0 + random.random() * 0.25))
            last = out
            attempt += 1

    def get(self, p, **kw):     return self.request("GET", p, **kw)
    def post(self, p, **kw):    return self.request("POST", p, **kw)
    def put(self, p, **kw):     return self.request("PUT", p, **kw)
    def patch(self, p, **kw):   return self.request("PATCH", p, **kw)
    def head(self, p, **kw):    return self.request("HEAD", p, **kw)
    def options(self, p, **kw): return self.request("OPTIONS", p, **kw)

    # --- authorization / cross-principal refusal helpers -------------------
    def is_authorized(self, resp: Response) -> bool:
        """True if the server PERMITTED the action (2xx)."""
        return 200 <= resp.status < 300

    def is_blocked(self, resp: Response) -> bool:
        """True when an edge (WAF/CDN/challenge/rate-limiter) answered instead of the target."""
        return is_blocked(resp)

    def assert_forbidden(self, method: str, path_or_url: str, *, identity: str,
                         allow_blocked: bool = False, **kw) -> Response:
        """Assert ``identity`` is REFUSED by the APPLICATION (401/403/404) on ``path``.

        Three distinct outcomes, kept strictly separate:
          * returns normally — the application refused. The boundary holds.
          * ``AssertionError`` — the application PERMITTED the action. This is the PoC signal.
          * ``BlockedError`` — an EDGE blocked the request, so the application never decided. Not
            a refusal and not a bypass; the runner maps it to ``ran=False``.

        The third case is the point: without it a WAF that blanket-403s every request satisfies
        every refusal assertion in the harness, and a blanket block gets stamped as a verified
        authorization boundary. Pass ``allow_blocked=True`` only to inspect a block deliberately.
        """
        resp = self.request(method, path_or_url, identity=identity, **kw)
        if not allow_blocked:
            reason = classify_block(resp)
            if reason:
                raise BlockedError(
                    f"{BLOCKED_MARKER}: {identity} {method} {path_or_url} -> {resp.status} was "
                    f"blocked at the edge ({reason}). The application never saw the request, so "
                    f"this is NOT a refusal and NOT a finding — re-run without the block.")
        assert resp.status in (401, 403, 404), (
            f"UNEXPECTED PERMIT: {identity} {method} {path_or_url} -> {resp.status} "
            f"(a refusal was required)")
        return resp

    def idor_probe(self, method: str, path_template: str, *, owner: str, attacker: str,
                   resource_id, allow_blocked: bool = False) -> Response:
        """Owner creates/holds ``resource_id``; assert the attacker principal cannot reach it.
        ``path_template`` contains ``{id}``. Returns the attacker's (refused) response.

        Inherits the three-way outcome of :meth:`assert_forbidden`: an edge block raises
        ``BlockedError`` rather than passing as "the attacker was correctly refused"."""
        path = path_template.format(id=resource_id)
        return self.assert_forbidden(method, path, identity=attacker, allow_blocked=allow_blocked)

    # --- baseline liveness / blocked pre-flight ---------------------------
    def baseline_health(self, path_or_url: str = "/", *, identity: str | None = None,
                        **kw) -> dict:
        """Probe the target BEFORE asserting anything, so a dead or blocked endpoint is
        distinguishable from a refusing one.

        Returns ``{ok, reachable, blocked, status, block_reason, detail}``. ``ok`` is True only
        when the endpoint answered AND an edge did not block AND it is not 5xx — i.e. the target
        is actually in a state where a refusal assertion carries information. Never raises except
        ``ScopeError`` (an out-of-scope probe — including a ``RedirectDenied`` hop — is a
        safe-harbor fault and must not be swallowed).
        """
        try:
            resp = self.request("GET", path_or_url, identity=identity, **kw)
        except ScopeError:
            raise
        except RateLimitExceeded as exc:  # we never asked, so the target's state is UNKNOWN
            return {"ok": False, "reachable": False, "blocked": False, "status": 0,
                    "block_reason": "", "detail": f"rate limit refused the baseline probe: {exc}"}
        except Exception as exc:  # transport/DNS/TLS/timeout — the endpoint is simply not there
            return {"ok": False, "reachable": False, "blocked": False, "status": 0,
                    "block_reason": "", "detail": f"endpoint unreachable: {exc}"}
        reason = classify_block(resp)
        server_error = resp.status >= 500
        ok = not reason and not server_error
        if reason:
            detail = f"edge blocked the baseline probe ({reason})"
        elif server_error:
            detail = f"target returned HTTP {resp.status} on the baseline probe (unhealthy)"
        else:
            detail = f"baseline probe answered HTTP {resp.status} — target is live"
        return {"ok": ok, "reachable": True, "blocked": bool(reason), "status": resp.status,
                "block_reason": reason, "detail": detail}

    def require_live_baseline(self, path_or_url: str = "/", *, identity: str | None = None,
                              **kw) -> dict:
        """:meth:`baseline_health`, but raise ``BlockedError`` when the target is not in a
        state where assertions mean anything. Call this FIRST in a live harness: it converts
        "the whole endpoint is blocked/dead" from a pile of passing refusal assertions (a false
        boundary) into a single ``ran=False`` verdict."""
        health = self.baseline_health(path_or_url, identity=identity, **kw)
        if not health["ok"]:
            raise BlockedError(
                f"{BLOCKED_MARKER}: baseline health probe on {path_or_url!r} failed — "
                f"{health['detail']}. Refusal assertions would be meaningless, so this run "
                f"proves nothing.")
        return health

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
        target may call back or fetch it; later assert ``oob_received``."""
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
    """Construct a Client wholly from the swarm-provided environment (the harness entrypoint).

    Raises ``ScopeError`` when ``P1HUNT_BASE_URL`` names a host that is not in
    ``P1HUNT_EGRESS_ALLOWLIST``. That pairing is exported together by
    ``claude_swarm._arm_dynamic`` from the SAME authorized scope, so a mismatch means the target
    was never authorized (e.g. ``authorize_dynamic`` rejected its environment) — and the right
    answer is to stop, not to add the host to the allowlist and start testing it."""
    return Client()
