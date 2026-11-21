"""Derive a black-box target's attack surface FROM THE RUNNING TARGET.

WHY THIS EXISTS
---------------
``agents/surface_enum.detect_web_entrypoints`` derives surface from a REPOSITORY: route
declarations, OpenAPI schemas, filesystem routing. A public bug-bounty target has no
repository. So for every black-box engagement ``entrypoints_for`` returned ``[]``, and
an empty surface list starves everything downstream -- the coverage loop has nothing to
mark uncovered, the asymmetry hunter has no pair to compare, the escalation loop has
nowhere to escalate to, and a hunter is left guessing paths. Persistence is worthless
without something to be persistent ABOUT.

This module answers "what IS this application" from the outside.

THE RICHEST SOURCE IS THE APPLICATION'S OWN JAVASCRIPT. A modern front end ships its
API client, its route table, its feature flags and often its sibling hostnames as string
literals in a bundle. Mining those gives the REAL endpoint list -- including the ones no
documentation mentions -- rather than a wordlist's guesses. Second richest is what the
app actually DOES: every fetch/XHR it issues while you use it, with real parameter
shapes.

WHAT THIS MODULE DOES, AND WHAT IT DELIBERATELY DOES NOT
--------------------------------------------------------
This module MEASURES and EXTRACTS. It does not judge.

Everything here is a deterministic instrument: mine a bundle for path literals, join
concatenated paths, name the identifier SHAPE of a path segment, collapse a thousand
observed URLs into a handful of templates, record what the application actually
requested. Those are facts, and facts belong in code -- a model re-deriving them per call
would be slower, costlier and less reliable.

Deciding WHICH of those facts is worth attacking is NOT here. It lives in
``dynamic/triage.py``, where the model gets the facts plus a catalogue of what each
instrument measures, and produces its own hypotheses. An earlier version of this module
scored the surface with keyword lists -- redirect-parameter names, "admin"-ish fragments,
a fixed weight per bug class, a fixed next action per class -- and that was wrong in a way
worth recording: it ceilings the hunt at whatever the author thought of, and the findings
that actually pay are usually a comparison that has no name yet. "Serve the same share
page to the apex host and to the mobile host and diff the renders" is in no wordlist, is
not a bug class, and was a critical.

``fallback_rank_leads`` below is what remains of that approach. It is retained ONLY as an
explicitly degraded ordering for an offline run with no engine available, it is named so
that no caller can reach for it by accident, and its output must never be presented as a
plan.

PURITY: every miner is a pure function over text, testable with no browser and no
network. ``discover()`` is the only part needing a live target, and it only collects.

STDLIB ONLY. Shipped standalone into the PoC sandbox alongside browser.py.
"""

from __future__ import annotations

import json
import re
import urllib.parse

# ---------------------------------------------------------------------------
# What is worth looking at, and what is noise.
# ---------------------------------------------------------------------------

# Asset extensions: a bundle is full of these and none of them is an endpoint.
_ASSET_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|css|map|mp4|webm|wav|mp3|"
    r"pdf|zip|gz|br|txt|xml|wasm)$", re.IGNORECASE)

# A quoted string that looks like a server path, including JS template placeholders
# (`/accounts/${id}/lines`) and already-templated ones (`/accounts/{id}`).
#
# Built from named pieces rather than written inline: the first version inlined the
# segment class WITHOUT a repetition quantifier, so a path segment matched exactly one
# character and every real multi-character path was silently missed. Quote characters are
# deliberately excluded from the segment class so a match can never run past the closing
# delimiter.
_SEG_CHAR = r"[A-Za-z0-9_\-.~%:@!&()*+,;=]"
_PLACEHOLDER = r"\$\{[^}]{1,40}\}|\{[A-Za-z0-9_]{1,30}\}"
_SEG = rf"(?:{_SEG_CHAR}|{_PLACEHOLDER})*"
_PATH_LITERAL = re.compile(rf"""['"`](/{_SEG}(?:/{_SEG})*)['"`]""")

# Concatenated paths: `"/accounts/" + id + "/billing"`. This is the dominant shape in a
# hand-written API client, and extracting the literals separately yields two useless
# fragments ("/accounts/" and "/billing") instead of one real endpoint. Joining them with
# a placeholder recovers `/accounts/{id}/billing` -- which is also exactly the IDOR
# hypothesis, since the joined position IS the identifier.
_CONCAT = re.compile(
    rf"""['"](/{_SEG}(?:/{_SEG})*)['"]\s*\+\s*"""           # leading literal, then +
    rf"""([A-Za-z_$][A-Za-z0-9_$.\[\]]{{0,48}})"""            # an expression (the id)
    rf"""(?:\s*\+\s*['"](/?{_SEG}(?:/{_SEG})*)['"])?""")     # optional trailing literal


def _join_concats(src: str, *, limit: int = 800) -> list[str]:
    """Recover endpoint templates from string concatenation. PURE.

    Only the two-literal shape is handled; a longer chain
    (``"/a/" + v + "/b/" + id + "/c"``) yields its leading pair, which is still a far
    better lead than the bare fragments. The joined slot becomes ``{id}`` because that is
    what it is: a caller-supplied identifier.
    """
    out: list[str] = []
    seen: set[str] = set()
    for m in _CONCAT.finditer(src or ""):
        left, _expr, right = m.group(1), m.group(2), m.group(3)
        joined = left if left.endswith("/") else left + "/"
        joined += "{id}"
        if right:
            joined += right if right.startswith("/") else "/" + right
        joined = re.sub(r"/{2,}", "/", joined)
        if joined not in seen and _interesting_path(joined):
            seen.add(joined)
            out.append(joined)
        if len(out) >= limit:
            break
    return out


# Absolute URLs, for sibling-host discovery.
_ABS_URL = re.compile(r"https?://([A-Za-z0-9](?:[A-Za-z0-9\-._]{0,251}[A-Za-z0-9])?\.[A-Za-z]{2,24})")

# GraphQL operations shipped in the bundle.
_GQL_OP = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{0,60})\s*[({]")
_GQL_OPNAME = re.compile(r"""['"]operationName['"]\s*:\s*['"]([A-Za-z_][A-Za-z0-9_]{0,60})['"]""")

# Client-side route tables: React Router / Next / Vue all emit a path key.
_ROUTE_KEY = re.compile(r"""['"]?path['"]?\s*:\s*['"`](/[^'"`]{0,200})['"`]""")

# HTTP methods named next to a URL, so a lead can state the verb instead of assuming GET.
_METHOD_NEAR = re.compile(
    r"""(?:method\s*:\s*['"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]|"""
    r"""\.(get|post|put|patch|delete|head|options)\s*\()""", re.IGNORECASE)

# Parameter names that are themselves the finding.
_REDIRECT_PARAMS = frozenset({
    "redirect", "redirect_uri", "redirect_url", "redirecturl", "return", "returnto",
    "return_to", "return_url", "returnurl", "next", "continue", "url", "target",
    "dest", "destination", "callback", "callback_url", "goto", "forward", "rurl",
    "checkout_url", "success_url", "cancel_url", "back", "backurl", "ref_url",
})
_SSRF_PARAMS = frozenset({
    "url", "uri", "src", "source", "link", "remote", "fetch", "load", "image_url",
    "imageurl", "avatar_url", "webhook", "webhook_url", "callback_url", "endpoint",
    "host", "domain", "proxy", "feed", "rss", "import", "import_url", "upstream",
})
_ID_PARAMS = frozenset({
    "id", "uid", "user_id", "userid", "account_id", "accountid", "customer_id",
    "profile_id", "order_id", "orderid", "invoice_id", "subscription_id", "line_id",
    "msisdn", "ban", "sim", "imei", "iccid", "device_id", "conversation_id", "doc_id",
    "file_id", "object_id", "org_id", "organization_id", "team_id", "group_id",
    "member_id", "ticket_id", "case_id", "payment_id", "card_id", "address_id",
})
_AUTH_HINTS = ("login", "signin", "sign-in", "logout", "signout", "register", "signup",
               "sign-up", "password", "reset", "forgot", "verify", "otp", "mfa", "2fa",
               "token", "oauth", "authorize", "callback", "session", "refresh", "sso",
               "saml", "invite", "magic", "consent", "impersonat")
_PRIV_HINTS = ("admin", "internal", "staff", "support", "operator", "backoffice",
               "back-office", "manage", "management", "console", "dashboard", "debug",
               "metrics", "health", "status", "actuator", "graphiql", "swagger",
               "openapi", "api-docs", "apidocs", "trace", "env", "config", "sudo",
               "superuser", "root", "privileged", "override", "masquerade")
_SECRET_HINTS = ("token", "secret", "credential", "apikey", "api_key", "api-key",
                 "password", "passwd", "private_key", "privatekey", "session",
                 "bearer", "authorization", "client_secret", "refresh_token")

# An identifier-shaped path segment, so a concrete path becomes a TEMPLATE plus a shape.
_SHAPES = (
    ("uuid", re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")),
    ("int", re.compile(r"^\d{1,19}$")),
    # objectid BEFORE hex: a Mongo ObjectId is exactly 24 hex characters, so the broader
    # hex pattern swallows it and the lead loses the information that the identifier is
    # a timestamp-prefixed, partially PREDICTABLE value rather than opaque.
    ("objectid", re.compile(r"^[0-9a-fA-F]{24}$")),
    ("hex", re.compile(r"^[0-9a-fA-F]{16,64}$")),
    ("b64", re.compile(r"^[A-Za-z0-9_\-]{20,120}={0,2}$")),
    ("msisdn", re.compile(r"^\+?[1-9]\d{9,14}$")),
)


def id_shape(segment: str) -> str:
    """Name the identifier shape of one path segment, or "" when it is a literal.

    Naming the shape is what makes an IDOR lead actionable: a UUID needs a second
    account's real identifier, an integer can simply be decremented, and an msisdn is a
    phone number on a telecom target.
    """
    s = (segment or "").strip()
    if not s or len(s) > 128:
        return ""
    for name, rx in _SHAPES:
        if rx.match(s):
            # A short all-hex token is far more likely a word than an identifier.
            if name == "hex" and s.lower() in ("deadbeef", "cafebabe"):
                return ""
            return name
    return ""


def templatize(path: str) -> tuple[str, list[dict]]:
    """Replace identifier-shaped segments with ``{id}``; report each one's shape.

    ``/api/v2/accounts/550e8400-e29b-41d4-a716-446655440000/lines/7`` becomes
    ``/api/v2/accounts/{id}/lines/{id}`` with shapes ``uuid`` and ``int``. Collapsing to
    a template is what makes a thousand observed URLs into a handful of real endpoints,
    and the shapes are the IDOR hypotheses.
    """
    parts = (path or "").split("/")
    ids: list[dict] = []
    out: list[str] = []
    for i, seg in enumerate(parts):
        # Normalize JS template placeholders the bundle itself used.
        if seg.startswith("${") or (seg.startswith("{") and seg.endswith("}")):
            ids.append({"index": i, "shape": "template", "value": seg})
            out.append("{id}")
            continue
        shape = id_shape(seg)
        if shape:
            ids.append({"index": i, "shape": shape, "value": seg})
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out), ids


def _interesting_path(p: str) -> bool:
    if not p or not p.startswith("/") or len(p) > 300 or len(p) < 2:
        return False
    if _ASSET_EXT.search(p.split("?")[0]):
        return False
    if p.startswith(("//",)):
        return False
    # Pure static asset directories carry no logic.
    if re.match(r"^/(?:_next/static|static|assets|fonts|images|img|css|js)/", p):
        return False
    return True


def mine_js(text: str, *, limit: int = 4000) -> dict:
    """Extract surface from one JavaScript bundle. PURE; never raises.

    A front-end bundle ships the application's own API client, so its string literals are
    a far better endpoint list than any wordlist: these are paths the application really
    calls, including undocumented ones.
    """
    out = {"paths": [], "hosts": [], "graphql": [], "routes": [], "methods": [],
            "secretish": []}
    if not text:
        return out
    src = text[: 4_000_000]  # a few MB is plenty; bundles can be enormous

    seen_p: set[str] = set()
    # Joined concatenations first: they are whole endpoints, while the literals they are
    # built from are fragments.
    joined = _join_concats(src, limit=limit)
    fragments: set[str] = set()
    for j in joined:
        seen_p.add(j)
        out["paths"].append(j)
        head = j.split("{id}")[0]
        if head:
            fragments.add(head)
            fragments.add(head.rstrip("/"))
        tail = j.split("{id}")[-1]
        if tail and tail != "/":
            fragments.add(tail)
    for m in _PATH_LITERAL.finditer(src):
        p = m.group(1)
        if not _interesting_path(p) or p in seen_p or p in fragments:
            continue
        seen_p.add(p)
        out["paths"].append(p)
        if len(seen_p) >= limit:
            break

    seen_h: set[str] = set()
    for m in _ABS_URL.finditer(src):
        h = m.group(1).lower().rstrip(".")
        if h not in seen_h:
            seen_h.add(h)
            out["hosts"].append(h)

    seen_g: set[str] = set()
    for m in _GQL_OP.finditer(src):
        name = f"{m.group(1).lower()} {m.group(2)}"
        if name not in seen_g:
            seen_g.add(name)
            out["graphql"].append(name)
    for m in _GQL_OPNAME.finditer(src):
        name = f"operation {m.group(1)}"
        if name not in seen_g:
            seen_g.add(name)
            out["graphql"].append(name)

    seen_r: set[str] = set()
    for m in _ROUTE_KEY.finditer(src):
        r = m.group(1)
        if r.startswith("/") and r not in seen_r and len(r) < 200:
            seen_r.add(r)
            out["routes"].append(r)

    out["methods"] = sorted({(m.group(1) or m.group(2) or "").upper()
                             for m in _METHOD_NEAR.finditer(src)} - {""})

    low = src.lower()
    out["secretish"] = sorted({h for h in _SECRET_HINTS if h in low})
    return out


def fallback_classify_path(path: str, *, params: list[str] | None = None,
                           method: str = "GET") -> dict:
    """DEGRADED keyword classification. Use ``dynamic.triage`` instead.

    Retained only for an offline run with no engine. It can recognise the shapes someone
    already thought to list and nothing else, so it cannot produce the cross-host or
    cross-session comparison that yields the best findings. Its one genuinely useful
    output is ``template``/``shapes``, which come from ``templatize`` and are measurement
    rather than judgement.
    """
    p = (path or "")
    low = p.lower()
    qs = [x.lower() for x in (params or [])]
    template, ids = templatize(p.split("?")[0])
    classes: list[str] = []
    reasons: list[str] = []

    if ids:
        classes.append("idor")
        shapes = ", ".join(sorted({i["shape"] for i in ids}))
        reasons.append(
            f"path carries {len(ids)} identifier-shaped segment(s) ({shapes}); replay as a "
            f"second principal and compare the response, not just the status code")
    id_qs = [q for q in qs if q in _ID_PARAMS or q.endswith("_id") or q.endswith("id")]
    if id_qs:
        if "idor" not in classes:
            classes.append("idor")
        reasons.append(f"object identifier in the query string ({', '.join(sorted(set(id_qs))[:6])})")

    hit_priv = [h for h in _PRIV_HINTS if h in low]
    if hit_priv:
        classes.append("authz")
        reasons.append(
            f"privileged-looking path segment ({', '.join(hit_priv[:4])}); if it answers at all "
            f"to an unprivileged or anonymous principal that IS the finding")

    hit_auth = [h for h in _AUTH_HINTS if h in low]
    if hit_auth:
        classes.append("auth")
        reasons.append(
            f"authentication surface ({', '.join(hit_auth[:4])}); check state-change without "
            f"re-auth, token reuse across accounts, and whether the flow is bound to one session")

    red = [q for q in qs if q in _REDIRECT_PARAMS]
    if red:
        classes.append("redirect")
        reasons.append(
            f"URL-valued parameter ({', '.join(sorted(set(red))[:4])}); an open redirect here is "
            f"also the pivot that walks a token or an OAuth code off-origin")

    ssrf = [q for q in qs if q in _SSRF_PARAMS]
    if ssrf:
        classes.append("ssrf")
        reasons.append(
            f"parameter the SERVER may fetch ({', '.join(sorted(set(ssrf))[:4])}); confirm with "
            f"the OOB listener, not with a timing guess")

    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        classes.append("state-change")
        reasons.append(
            f"{method.upper()} mutates state; check whether it is reachable cross-site and "
            f"whether authorization is re-evaluated per object rather than per session")

    return {"template": template, "classes": classes, "reasons": reasons,
            "id_params": sorted(set(id_qs)), "shapes": [i["shape"] for i in ids]}


class Lead:
    """One concrete, testable hypothesis with the reason it exists."""

    __slots__ = ("kind", "target", "method", "score", "reasons", "action", "evidence")

    def __init__(self, kind, target, *, method="GET", score=0, reasons=None,
                 action="", evidence=None):
        self.kind = kind
        self.target = target
        self.method = method
        self.score = score
        self.reasons = list(reasons or [])
        self.action = action
        self.evidence = dict(evidence or {})

    def as_dict(self) -> dict:
        return {"kind": self.kind, "target": self.target, "method": self.method,
                "score": self.score, "reasons": self.reasons, "action": self.action,
                "evidence": self.evidence}

    def __repr__(self):
        return f"<Lead {self.score} {self.kind} {self.method} {self.target}>"


# Scores are coarse on purpose: they order the queue, they are not a severity claim.
_KIND_WEIGHT = {
    "idor": 55, "authz": 50, "render_gate": 48, "ssrf": 45, "secret": 45,
    "redirect": 30, "auth": 35, "injection": 40, "state-change": 25, "surface": 5,
}


def fallback_rank_leads(surface: dict, *, limit: int = 200) -> list[Lead]:
    """DEGRADED surface ordering for a run with NO engine available.

    This is not a plan and must not be shown as one. It orders a surface by hardcoded
    weights so an offline run has somewhere to start; it has no model of the application,
    so it cannot propose varying a host, skipping a step, or any other comparison that is
    not in its tables. ``dynamic.triage.triage()`` is the real path, and it fails loudly
    rather than falling back here, because a wordlist's output dressed up as reasoning is
    worse than an honest absence.
    """
    leads: list[Lead] = []

    for ep in surface.get("endpoints", []) or []:
        path = ep.get("path") or ""
        method = (ep.get("method") or "GET").upper()
        params = list(ep.get("params") or [])
        info = fallback_classify_path(path, params=params, method=method)
        if not info["classes"]:
            leads.append(Lead("surface", info["template"], method=method, score=_KIND_WEIGHT["surface"],
                              reasons=["observed surface with no obvious class yet"],
                              action="enumerate parameters and compare across identities",
                              evidence={"source": ep.get("source", "")}))
            continue
        for cls in info["classes"]:
            score = _KIND_WEIGHT.get(cls, 10)
            # Something the application itself was seen calling is worth more than a
            # string scraped out of a bundle that may be dead code.
            if ep.get("source") == "observed":
                score += 12
            if ep.get("authenticated"):
                score += 8
            action = {
                "idor": "replay as a second identity and DIFF the body; a 200 with another "
                        "principal's data is the finding, a 403 is not proof of safety until "
                        "the baseline shows the endpoint is live",
                "authz": "request as anonymous and as a low-privilege identity; any non-404, "
                         "non-block answer is the lead",
                "auth": "test state change without re-auth and token reuse across accounts",
                "redirect": "send an in-scope value, then an off-origin one, and follow the hop "
                            "to see whether credentials survive it",
                "ssrf": "point it at the OOB listener and assert a callback",
                "state-change": "attempt cross-site and cross-principal invocation",
            }.get(cls, "probe and compare against a control")
            leads.append(Lead(cls, info["template"], method=method, score=score,
                              reasons=info["reasons"], action=action,
                              evidence={"source": ep.get("source", ""),
                                        "raw": path,
                                        "shapes": info["shapes"],
                                        "id_params": info["id_params"]}))

    # Render-gate candidates: the same resource across sibling hosts or session states.
    hosts = sorted(set(surface.get("hosts", []) or []))
    for path in (surface.get("gate_paths", []) or []):
        if len(hosts) >= 2:
            leads.append(Lead(
                "render_gate", path, score=_KIND_WEIGHT["render_gate"] + 10,
                reasons=[f"{len(hosts)} sibling hosts serve this application; a render gate "
                         f"applied on one host is routinely missing on another, which removes "
                         f"a precondition rather than adding a new bug"],
                action="differential(path, [{'host': h} for h in hosts]) and diff the renders; "
                       "then repeat with and without a session cookie",
                evidence={"hosts": hosts[:12]}))
        else:
            leads.append(Lead(
                "render_gate", path, score=_KIND_WEIGHT["render_gate"],
                reasons=["public resource worth comparing signed-in against signed-out"],
                action="differential(path, [{'name':'anon'}, {'name':'victim','cookies':[...]}])",
                evidence={}))

    for item in (surface.get("secretish_responses", []) or []):
        leads.append(Lead("secret", item.get("url", ""), score=_KIND_WEIGHT["secret"] + 10,
                          reasons=[f"response hands the client {item.get('what', 'a credential')}; "
                                   f"if script on this origin can read it, an injection anywhere "
                                   f"on the origin becomes account takeover"],
                          action="confirm what the value authorizes, in a clean session, before "
                                 "claiming impact",
                          evidence=item))

    for op in (surface.get("graphql", []) or [])[:80]:
        leads.append(Lead("surface", f"graphql:{op}", method="POST",
                          score=_KIND_WEIGHT["surface"] + 15,
                          reasons=["GraphQL operation shipped in the client bundle; per-field "
                                   "authorization is frequently weaker than per-endpoint"],
                          action="invoke as a low-privilege identity and look for fields it "
                                 "should not receive",
                          evidence={"source": "bundle"}))

    # Stable order: score first, then target, so a rerun produces the same queue.
    leads.sort(key=lambda L: (-L.score, L.kind, L.target, L.method))
    # Collapse duplicates of (kind, target, method), keeping the best-scored.
    out: list[Lead] = []
    seen: set[tuple] = set()
    for L in leads:
        key = (L.kind, L.target, L.method)
        if key in seen:
            continue
        seen.add(key)
        out.append(L)
        if len(out) >= limit:
            break
    return out


def merge_surface(*parts: dict) -> dict:
    """Union several collected surfaces, de-duplicating while preserving order."""
    out: dict = {"hosts": [], "endpoints": [], "routes": [], "graphql": [],
                 "scripts": [], "forms": [], "gate_paths": [],
                 "secretish_responses": [], "notes": []}
    seen: dict[str, set] = {k: set() for k in out}
    for part in parts:
        for key in out:
            for item in (part.get(key) or []):
                marker = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                if marker in seen[key]:
                    continue
                seen[key].add(marker)
                out[key].append(item)
    return out


def entrypoints_from_surface(surface: dict, *, limit: int = 400,
                             leads: list | None = None) -> list[str]:
    """Render a surface as the ``"METHOD /path"`` strings the coverage loop expects.

    ``leads`` lets a REASONED plan drive this instead of the degraded ordering; pass
    ``triage.plan_to_entrypoints``'s input or Lead objects. Only when it is None does
    the keyword fallback run.

    This is the bridge: ``agents/surface_enum.entrypoints_for`` returns [] for a target
    with no repository, which starves the coverage loop. A live-derived surface produces
    the same shape of list, so every existing mechanism -- uncovered hints, the
    falsification ledger, escalation -- works unchanged on a black-box target.
    """
    out: list[str] = []
    seen: set[str] = set()
    for lead in (leads if leads is not None else fallback_rank_leads(surface, limit=limit)):
        t = lead.target
        if t.startswith("graphql:"):
            entry = f"POST {t}"
        else:
            entry = f"{lead.method} {t}"
        if entry not in seen:
            seen.add(entry)
            out.append(entry)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Live collection. Only this part needs a browser, and it only COLLECTS.
# ---------------------------------------------------------------------------

def _params_of(url: str) -> list[str]:
    try:
        return sorted(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).keys())
    except Exception:
        return []


def discover(browser, seeds, *, max_pages: int = 12, max_scripts: int = 25,
             same_host_only: bool = True) -> dict:
    """Walk an authorized target with a real browser and collect its surface.

    ``browser`` is a started ``dynamic.browser.Browser`` -- the egress jail and the rate
    limit are its, so this function cannot reach anything the operator did not authorize.
    Collection only: no verdicts, no payloads, nothing destructive. Every GET is a page
    the application already serves to a visitor.
    """
    collected: dict = {"hosts": [], "endpoints": [], "routes": [], "graphql": [],
                       "scripts": [], "forms": [], "gate_paths": [],
                       "secretish_responses": [], "notes": []}
    queue = list(seeds or [])
    visited: set[str] = set()
    script_urls: list[str] = []

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            obs = browser.goto(url)
        except Exception as exc:
            collected["notes"].append(f"goto {url}: {exc}")
            continue

        host = urllib.parse.urlsplit(obs.final_url or url).netloc.split("@")[-1]
        if host and host not in collected["hosts"]:
            collected["hosts"].append(host.split(":")[0].lower())
        collected["gate_paths"].append(urllib.parse.urlsplit(obs.final_url or url).path or "/")

        # Everything the app actually requested, with real parameter shapes. This beats
        # any wordlist because the application told us these exist.
        for req in (obs.requests or []):
            u = req.get("url") or ""
            rtype = req.get("type") or ""
            if rtype == "script":
                if u not in script_urls:
                    script_urls.append(u)
                continue
            if rtype in ("image", "font", "stylesheet", "media", "manifest"):
                continue
            path = urllib.parse.urlsplit(u).path or "/"
            if not _interesting_path(path):
                continue
            collected["endpoints"].append({
                "path": path + (("?" + urllib.parse.urlsplit(u).query)
                                if urllib.parse.urlsplit(u).query else ""),
                "method": req.get("method") or "GET",
                "params": _params_of(u),
                "source": "observed",
                "authenticated": bool(obs.cookies),
            })

        # Forms are declared, authenticated-adjacent state change.
        try:
            forms = browser.eval_js(
                "() => Array.from(document.querySelectorAll('form')).slice(0,40).map(f => ({"
                " action: f.getAttribute('action') || location.pathname,"
                " method: (f.getAttribute('method') || 'GET').toUpperCase(),"
                " fields: Array.from(f.querySelectorAll('input,select,textarea')).slice(0,40)"
                "   .map(i => i.getAttribute('name')).filter(Boolean) }))") or []
        except Exception:
            forms = []
        for f in forms:
            collected["forms"].append(f)
            if _interesting_path(f.get("action") or ""):
                collected["endpoints"].append({
                    "path": f.get("action"), "method": f.get("method") or "GET",
                    "params": list(f.get("fields") or []), "source": "form",
                    "authenticated": bool(obs.cookies)})

        # In-scope links, for the next hop.
        try:
            links = browser.eval_js(
                "() => Array.from(document.querySelectorAll('a[href]')).slice(0,300)"
                " .map(a => a.href)") or []
        except Exception:
            links = []
        base_host = urllib.parse.urlsplit(obs.final_url or url).netloc
        for href in links:
            try:
                parts = urllib.parse.urlsplit(href)
            except Exception:
                continue
            if parts.scheme not in ("http", "https"):
                continue
            if same_host_only and parts.netloc != base_host:
                if parts.netloc:
                    h = parts.netloc.split(":")[0].lower()
                    if h not in collected["hosts"]:
                        collected["hosts"].append(h)
                continue
            clean = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                             parts.query, ""))
            if clean not in visited and len(queue) < max_pages * 4:
                queue.append(clean)

        # A response that hands the client a credential is its own lead.
        low_html = (obs.raw_html or "")[:200_000].lower()
        found = [h for h in _SECRET_HINTS if f'"{h}"' in low_html]
        if found:
            collected["secretish_responses"].append(
                {"url": obs.final_url or url, "what": ", ".join(sorted(set(found))[:6]),
                 "where": "document body"})

    # Mine the bundles. The richest single source of real endpoints.
    for su in script_urls[:max_scripts]:
        try:
            obs = browser.goto(su)
            text = obs.raw_html or ""
        except Exception as exc:
            collected["notes"].append(f"script {su}: {exc}")
            continue
        collected["scripts"].append(su)
        mined = mine_js(text)
        for p in mined["paths"]:
            collected["endpoints"].append({"path": p, "method": "GET",
                                           "params": _params_of(p), "source": "bundle",
                                           "authenticated": False})
        for h in mined["hosts"]:
            if h not in collected["hosts"]:
                collected["hosts"].append(h)
        for g in mined["graphql"]:
            if g not in collected["graphql"]:
                collected["graphql"].append(g)
        for r in mined["routes"]:
            if r not in collected["routes"]:
                collected["routes"].append(r)
            collected["endpoints"].append({"path": r, "method": "GET", "params": [],
                                           "source": "route", "authenticated": False})
        if mined["secretish"]:
            collected["secretish_responses"].append(
                {"url": su, "what": ", ".join(mined["secretish"][:6]), "where": "bundle"})

    # De-duplicate gate paths while keeping order.
    seen_g: set[str] = set()
    collected["gate_paths"] = [p for p in collected["gate_paths"]
                               if not (p in seen_g or seen_g.add(p))]
    return merge_surface(collected)
