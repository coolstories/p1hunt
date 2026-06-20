"""Egress allowlisting — the safe-harbor floor for ALL live contact (spec §9, §17).

The one hard rule for live dynamic testing: an outbound request may reach ONLY a host the
operator authorized as in-scope (plus loopback, for the local OOB listener / a locally-stood-up
app, and a small set of package registries needed to BUILD a harness). Every other host is
denied — this is what keeps authorized testing from ever touching a third party's system or a
production service.

Everything here is a PURE function (no I/O, no sockets), so it is exhaustively unit-testable and
can be reused by three call sites with one definition of "allowed": the ScopeGuard egress gate,
the in-process HTTP tool (``tools.http_sandbox``), and the agent's bash network jail
(``agents.claude_session.bash_safety``).
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# Package registries / source mirrors a harness legitimately needs to build itself (pip, npm,
# cargo, go, system fetch). Allowed for fetches even under the egress jail because they are not a
# target and reaching them cannot touch a third party's *system under test*. Kept deliberately
# small; never includes a generic paste/exfil sink beyond these well-known build endpoints.
_BUILD_HOSTS: frozenset[str] = frozenset({
    "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "registry.yarnpkg.com",
    "crates.io", "static.crates.io",
    "proxy.golang.org", "sum.golang.org", "goproxy.io",
    "github.com", "raw.githubusercontent.com", "codeload.github.com", "objects.githubusercontent.com",
})

_LOOPBACK: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost", "0.0.0.0"})

# http(s) URLs embedded anywhere in a shell command.
_URL_RE = re.compile(r"https?://[^\s'\"`)>|&;]+", re.IGNORECASE)
# bare host[:port] handed to a raw socket tool (nc/ncat/netcat/telnet host port).
_NC_RE = re.compile(r"\b(?:nc|ncat|netcat|telnet)\b\s+(?:-\S+\s+)*([A-Za-z0-9._-]+)\s+\d{1,5}", re.IGNORECASE)


def normalize_host(url_or_host: str) -> str:
    """Lowercased hostname with any port/userinfo/brackets stripped. Accepts a full URL, a
    ``host:port``, or a bare host. Returns "" when nothing host-like is present."""
    if not url_or_host:
        return ""
    s = str(url_or_host).strip()
    if "://" in s:
        s = urlparse(s).hostname or ""
    else:
        # strip any path, then userinfo, then port; tolerate IPv6 brackets.
        s = s.split("/")[0]
        if "@" in s:
            s = s.rsplit("@", 1)[1]
        if s.startswith("["):  # [::1]:8080
            s = s[1: s.find("]")] if "]" in s else s[1:]
        elif s.count(":") == 1:  # host:port (a lone colon → port; many colons → IPv6, leave it)
            s = s.split(":")[0]
    return s.strip().lower().rstrip(".")


def is_loopback(host: str) -> bool:
    h = normalize_host(host)
    return h in _LOOPBACK or h.endswith(".localhost")


def host_in_allowlist(host: str, allowlist: list[str] | frozenset[str]) -> bool:
    """A host matches if it equals an allowlist entry or is a subdomain of one. Allowlist entries
    are themselves normalized to hostnames, so callers may pass raw URLs/values from the scope."""
    h = normalize_host(host)
    if not h:
        return False
    for raw in allowlist:
        entry = normalize_host(raw)
        if not entry:
            continue
        if h == entry or h.endswith("." + entry):
            return True
    return False


def url_allowed(
    url: str,
    allowlist: list[str] | frozenset[str],
    *,
    allow_loopback: bool = True,
    allow_build_hosts: bool = True,
) -> tuple[bool, str]:
    """Decide whether a single URL/host may be contacted. Returns ``(ok, reason)``.

    Order: loopback (local OOB/app) → in-scope allowlist → build-host carve-out → deny. The
    default ``allow_loopback`` lets harnesses talk to the local OOB listener and a locally
    stood-up instance; pass False to forbid even that (e.g. a pure remote-only policy)."""
    host = normalize_host(url)
    if not host:
        return False, "no host in target"
    if allow_loopback and is_loopback(host):
        return True, "loopback (local)"
    if host_in_allowlist(host, allowlist):
        return True, f"in scope ({host})"
    if allow_build_hosts and host in _BUILD_HOSTS:
        return True, f"build/registry host ({host})"
    return False, f"out of scope: {host} is not in the authorized egress allowlist — denied"


def extract_hosts(command: str) -> list[str]:
    """Every host a shell command would CONTACT: from http(s) URLs and from raw-socket tools.
    Order-preserving, de-duplicated. Used by the bash network jail to vet outbound calls."""
    if not command:
        return []
    hosts: list[str] = []
    seen: set[str] = set()
    for m in _URL_RE.finditer(command):
        h = normalize_host(m.group(0))
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)
    for m in _NC_RE.finditer(command):
        h = normalize_host(m.group(1))
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)
    return hosts


def bash_egress_ok(command: str, allowlist: list[str] | frozenset[str]) -> tuple[bool, str]:
    """The bash network jail: deny the command if ANY host it would contact is not authorized.
    A command with no outbound host is allowed (local work). This is enforced ONLY when dynamic
    mode is armed (an allowlist is configured); otherwise the caller skips it entirely so ordinary
    static-analysis runs are unaffected."""
    for host in extract_hosts(command):
        ok, reason = url_allowed(host, allowlist)
        if not ok:
            return False, reason
    return True, "egress in scope"
