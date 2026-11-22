"""Turn a pasted bug-bounty scope into the host list a hunt should be confined to.

WHY THIS EXISTS
---------------
The console used to ask for a "target URL", so an operator pasted the URL they actually
had in hand -- the PROGRAM PAGE, `https://hackerone.com/anthropic?type=team` -- and the
hunt was pointed at HackerOne's own production website instead of at any asset in
Anthropic's program. The attestation checkbox was ticked in good faith; the form had
simply asked the wrong question.

So the question changed. An operator now supplies the two things they genuinely have: the
program URL (reference only, NEVER a target) and the scope text, pasted from the program
page. The in-scope hosts are DERIVED from that text, which means:

  * the program-page URL can no longer become a target, because it is not in the scope
    text's asset list;
  * the egress allowlist comes from the operator's own authoritative source rather than
    from retyping;
  * an out-of-scope section is read as out-of-scope rather than ignored.

Deterministic on purpose -- no model, no network. It parses what it was given and shows
the operator exactly what it concluded, for confirmation, before anything runs. A parser
that guessed would be worse than a text box.
"""

from __future__ import annotations

import re
import urllib.parse

# Bug-bounty PLATFORMS. Pasting a program page is the normal way to arrive here, so these
# are flagged rather than silently accepted -- being listed on a platform does not make the
# platform a target. Not a hard block: HackerOne genuinely runs a program for
# hackerone.com, so an operator can still confirm one explicitly. Loud, then theirs.
_PLATFORMS = frozenset({
    "hackerone.com", "h1.com", "bugcrowd.com", "intigriti.com", "yeswehack.com",
    "immunefi.com", "hackenproof.com", "synack.com", "cobalt.io", "openbugbounty.org",
    "huntr.dev", "bounty.github.com", "zerocopter.com", "federacy.com",
})

# Source-code and package hosts. An in-scope repository is something to READ, never a live
# host to send traffic at, and scope tables list them alongside web assets.
_SOURCE_HOSTS = frozenset({
    "github.com", "gitlab.com", "bitbucket.org", "sourceforge.net", "npmjs.com",
    "pypi.org", "crates.io", "rubygems.org", "hub.docker.com", "go.dev",
})

# App STORE / distribution hosts. A scope listing a mobile or extension client links to
# its store page -- "Claude iOS App: https://apps.apple.com/us/app/claude/..." -- and that
# page belongs to Apple, not to the app's publisher. Treated like a source host: the
# listed asset is the CLIENT, which is not something to point an HTTP hunt at.
_STORE_HOSTS = frozenset({
    "apple.com", "google.com", "microsoft.com", "amazon.com", "mozilla.org",
    "chrome.google.com", "chromewebstore.google.com", "play.google.com",
    "apps.apple.com", "addons.mozilla.org", "marketplace.visualstudio.com",
})

# Lines after one of these head toward exclusions rather than assets.
_OOS_HEADING = re.compile(
    r"(?i)\b(out[\s-]?of[\s-]?scope|not in scope|excluded|exclusions?|ineligible|"
    r"do not test|don'?t test|off[\s-]?limits)\b")
_IN_HEADING = re.compile(
    r"(?i)\b(in[\s-]?scope|scope|assets?|targets?|domains?|eligible|covered)\b")

# A hostname, or a URL we take the host from. Deliberately conservative: a label must
# start alphanumeric, and the TLD must be alphabetic, so version numbers and file names
# ("app.js", "v1.2.3") do not become hosts.
_HOST_RE = re.compile(
    r"(?<![\w.-])"
    r"(?:(?:https?://)?(?:\*\.)?)"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})"
    r"(?![\w-])")

# TLDs a scope realistically names. An ALLOWLIST, not a blocklist of noise.
#
# WHY: the blocklist version accepted "com.anthropic.claude" -- an ANDROID APP BUNDLE ID
# from the scope table -- as the hostname "anthropic.claude", because ".claude" is five
# alphabetic characters and nothing said it had to be a real TLD. That reached a launch.
# A bundle id reads exactly like a domain in reverse, so scope tables are full of them.
_VALID_TLD = frozenset("""
com net org edu gov mil int io ai co dev app cloud sh me tv cc us uk ca au nz de fr es
it nl se no fi dk pl pt ie be at ch cz gr hu ro bg hr si sk lt lv ee is lu mt cy br mx
ar cl pe ve in jp cn kr tw hk sg my th id ph vn il ae sa tr za ng ke eg ma ru ua by kz
info biz name pro mobi asia tel travel jobs xxx post xyz top site online store tech
space website press host fun icu club live life world today news blog shop cat eu
""".split())

# An IPv4 literal. A self-owned target is often a local app, and the hostname pattern
# above correctly refuses "127.0.0.1" because its last label is not alphabetic.
_IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?(?![\w.])")

# Table/list furniture and the severity words that sit beside an asset in a scope table.
# Stripped before judging whether a line IS an asset entry rather than prose about one.
_FURNITURE = re.compile(
    r"(?i)(\||^\s*[-*•‣◦+]\s*|^\s*\d+[.)]\s*|`|\*\*|"
    r"\b(critical|high|medium|low|informational|info|none|p[1-5]|"
    r"domain|url|api|endpoint|host|website|web|wildcard|subdomain|ip|cidr|"
    r"asset|type|severity|in|scope|target|eligible|tier|bounty)\b|[:,;()\[\]])")

# How much non-host text a line may carry and still be read as an asset ENTRY rather than
# a sentence that happens to mention a host. A table row leaves almost nothing behind once
# the furniture and severity words are stripped; a sentence leaves a lot.
_MAX_RESIDUE = 24


def _is_asset_line(line: str, hosts: list[str]) -> bool:
    """Is this line an asset ENTRY, or prose that merely mentions a host?

    THIS DISTINCTION IS THE WHOLE PARSER. Without it, the first live use mined `m.range`
    out of the sentence "a sibling MOBILE WEB HOST is simulated with the header
    X-Range-Host: m.range", `example.com` out of a `security@example.com` contact address,
    and `docs.example.com` out of a link to the policy -- then launched a hunt at a
    hostname that does not exist, while missing the actual asset.

    A scope table row reduces to almost nothing once pipes, bullets and severity words are
    removed. A sentence does not. So the test is how much text is left over.
    """
    residue = line
    for h in hosts:
        residue = residue.replace(h, " ")
    residue = _FURNITURE.sub(" ", residue)
    residue = re.sub(r"https?://|[\s./*_#>-]+", " ", residue)
    letters = re.sub(r"[^A-Za-z]", "", residue)
    return len(letters) <= _MAX_RESIDUE


def _clean_host(raw: str) -> str:
    h = (raw or "").strip().strip(".,;:()[]<>\"'`").lower()
    if not h:
        return ""
    if "://" in h:
        h = urllib.parse.urlsplit(h).hostname or ""
    h = h.lstrip("*.").rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    return h


def _registrable(host: str) -> str:
    """The registrable apex of a host. Used for CLASSIFYING (is this a platform? a store?),
    never for deciding what to authorize -- see _scope_entry."""
    parts = host.split(".")
    return host if len(parts) <= 2 else ".".join(parts[-2:])


def _scope_entry(host: str, wildcard: bool) -> str:
    """What this scope line actually AUTHORIZES.

    THE RULE: collapse to the apex only when the scope said `*.`. Otherwise the exact
    hostname is what was authorized.

    An earlier version collapsed everything, and that was the most dangerous bug in this
    file. Run against Anthropic's real HackerOne scope it turned:

        anthropic.atlassian.com   ->  atlassian.com     (ALL of Atlassian)
        apps.apple.com/.../claude ->  apple.com         (ALL of Apple)
        support/docs/console/api.anthropic.com -> anthropic.com (every subdomain, though
                                                   the scope lists four by name)

    The first two are third-party infrastructure that the program explicitly disclaims:
    "This is not to be construed as an authorization to conduct security testing against
    the infrastructure of SaaS/Cloud vendors." A scope naming one tenant host on a SaaS
    domain authorizes that tenant, never the vendor.

    Keeping the exact host is also no loss of reach: the egress jail matches subdomains of
    an allowlist entry, so `api.anthropic.com` still covers anything beneath it.
    """
    if wildcard:
        return _registrable(host)
    return host


def _plausible(host: str) -> bool:
    """Could this string be a real public hostname?

    The TLD must be one a scope actually names. Anything else -- a file extension, a
    reversed app bundle id, a Java package -- looks like a domain and is not one.
    """
    if "." not in host or len(host) < 4:
        return False
    tld = host.rsplit(".", 1)[-1]
    if not tld.isalpha() or tld not in _VALID_TLD:
        return False
    return True


def _looks_like_bundle_id(token: str) -> bool:
    """A reversed-DNS identifier: com.anthropic.claude, io.example.app.

    Scope tables list mobile assets this way, right beside web assets, so the parser meets
    them constantly. The giveaway is a leading `com.`/`io.`/`org.` style label followed by
    more labels, read left to right -- the opposite of a hostname.
    """
    parts = token.lower().strip().split(".")
    if len(parts) < 3:
        return False
    return parts[0] in {"com", "io", "org", "net", "co", "app", "dev", "me", "ai"}


def parse_scope(text: str, *, program_url: str = "") -> dict:
    """Derive hosts from pasted scope text.

    Returns ``{in_scope, out_of_scope, flagged, program_host}``. ``flagged`` holds entries
    that parsed as hosts but should not be hunted without the operator saying so
    explicitly, each with the reason -- a platform domain or a source-code host.
    """
    program_host = _clean_host(program_url)
    # host -> {"line": the text it was read from, "strong": from a real table row}
    #
    # THE EVIDENCE IS THE POINT. The version without it returned a bare list, and that
    # list contained apple.com and google.com -- mined from the chrome of a pasted
    # HackerOne policy page -- with nothing to show the operator WHY. Six unrelated
    # registrable domains went to a launch unquestioned. A parser that cannot show its
    # working should not be trusted with an allowlist.
    in_scope: dict[str, dict] = {}
    out_of_scope: dict[str, None] = {}
    flagged: dict[str, str] = {}
    mentioned: dict[str, None] = {}   # seen in prose, not presented as an asset

    section_oos = False
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # A heading flips which bucket subsequent bare entries land in. Checked before the
        # hosts on the line itself, so "Out of scope: admin.example.com" works inline too.
        if _OOS_HEADING.search(stripped):
            section_oos = True
        elif _IN_HEADING.search(stripped) and not _OOS_HEADING.search(stripped):
            section_oos = False

        line_oos = section_oos or bool(_OOS_HEADING.search(stripped))

        # Collect candidates first, then decide whether this LINE is an asset entry.
        raw_hits: list[str] = []
        wildcarded: set[str] = set()
        for match in _HOST_RE.finditer(stripped):
            # An email address is not an asset. "security@example.com" used to contribute
            # example.com to the allowlist.
            if match.start() and stripped[match.start() - 1] == "@":
                continue
            # A reversed-DNS identifier is not a host. The TLD allowlist alone catches
            # `com.anthropic.claude` (".claude" is not a TLD) but NOT `io.example.app`,
            # where every label is legitimate -- so the shape has to be tested too.
            if _looks_like_bundle_id(match.group(1)):
                continue
            # Did the SCOPE write "*.host"? That is the only thing that authorizes a whole
            # registrable domain rather than the one host named.
            prefix = stripped[max(0, match.start() - 2):match.start()]
            if prefix.endswith("*."):
                wildcarded.add(match.group(1).lower())
            raw_hits.append(match.group(1))
        for match in _IPV4_RE.finditer(stripped):
            octets = match.group(1).split(".")
            if all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
                raw_hits.append(match.group(1))

        if not raw_hits:
            continue
        if not _is_asset_line(stripped, raw_hits):
            # Shown to the operator as "mentioned in the notes" so a host the parser was
            # too strict about is still one tick away -- the parser must not be the only
            # path to a legitimate target.
            for raw in raw_hits:
                host = _clean_host(raw)
                if host and (_plausible(host) or _IPV4_RE.match(host)):
                    mentioned.setdefault(host, None)
            continue

        for raw in raw_hits:
            host = _clean_host(raw)
            is_ip = bool(_IPV4_RE.match(host))
            if not host or (not is_ip and not _plausible(host)):
                continue
            classify = host if is_ip else _registrable(host)
            if not is_ip and (host in _STORE_HOSTS or classify in _STORE_HOSTS):
                flagged.setdefault(
                    host,
                    "an app STORE / distribution page. The listed asset is the client "
                    "itself; this host belongs to the store operator, not to the "
                    "program.")
                continue
            apex = host if is_ip else _scope_entry(host, raw.lower() in wildcarded
                                                   or host in wildcarded)
            if line_oos:
                out_of_scope.setdefault(host, None)
                continue
            if classify in _PLATFORMS:
                flagged.setdefault(
                    host,
                    "this is a bug-bounty PLATFORM, not an asset. Being listed on it does "
                    "not make it a target. Confirm only if the platform itself is the "
                    "program you are testing.")
                continue
            if classify in _SOURCE_HOSTS:
                flagged.setdefault(
                    host,
                    "a source-code or package host: something to READ, not a live host to "
                    "send traffic at.")
                continue
            # A TABLE ROW is strong evidence: a scope table pairs an asset with a type and
            # a severity. A bare bullet is weak -- a nav list, a customer-logo list and an
            # asset list are all bullets, which is how apple.com got in.
            strong = "|" in stripped and len(
                [c for c in stripped.split("|") if c.strip()]) >= 2
            in_scope.setdefault(apex, {"line": stripped[:160], "strong": strong})

    # The program page's own host is never a target just because it was pasted above.
    if program_host:
        apex = _registrable(program_host)
        in_scope.pop(apex, None)
        if apex in _PLATFORMS:
            flagged.setdefault(
                program_host,
                "this is the program PAGE's own host -- where you read the policy. It is "
                "not an asset of the program.")

    for h in list(mentioned):
        if h in in_scope or h in out_of_scope:
            mentioned.pop(h, None)
    # ARE THESE PLAUSIBLY ONE PROGRAM'S ASSETS? A scope normally covers a handful of
    # domains belonging to one organisation. A derived set spanning many unrelated
    # registrable domains is the signature of a page that was pasted whole -- nav, footer,
    # customer logos, other programs -- and it is exactly the shape that produced
    # apple.com and google.com. Reported so the UI can refuse to pre-tick them.
    strong_hosts = [h for h, meta in in_scope.items() if meta["strong"]]
    spread = len(in_scope)
    suspicious = spread >= 4 and len(strong_hosts) < spread
    return {
        "in_scope": sorted(in_scope),
        "evidence": {h: in_scope[h] for h in sorted(in_scope)},
        "strong": sorted(strong_hosts),
        "suspicious_spread": suspicious,
        "out_of_scope": sorted(out_of_scope),
        "flagged": [{"host": h, "why": w} for h, w in sorted(flagged.items())],
        "mentioned": sorted(mentioned),
        "program_host": program_host,
    }


def is_platform_host(host: str) -> bool:
    """Is this a bug-bounty platform's own domain?"""
    return _registrable(_clean_host(host)) in _PLATFORMS
