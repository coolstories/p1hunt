"""Hand the model the FACTS and the INSTRUMENTS, and let it decide what to attack.

WHY THIS REPLACES A KEYWORD LIST
--------------------------------
The first version of the triage layer scored a surface with hardcoded wordlists --
redirect-parameter names, "admin"-ish path fragments, a fixed weight per bug class -- and
mapped each class to a fixed next action. That ceilings the hunt at whatever the author
thought of while writing the table, and it fails in the way that matters most: the
findings that pay are usually a comparison nobody had a name for. "Serve the same share
page to the apex host and to the mobile host and diff the renders" is not in any
wordlist, is not a bug class, and was a critical.

So the division of labour here is deliberate:

  * CODE MEASURES. The tokenizer, the escaping census, the execution oracle, the bundle
    miners, the scope jail -- deterministic instruments. Asking a model to re-derive
    "is this byte offset inside a quoted attribute" would be slower, costlier and less
    reliable than a tokenizer, and the census exists precisely to stop a human (or a
    model) from eyeballing that wrong.
  * THE MODEL DECIDES. What is worth attacking, what the application's trust model
    probably is, which instrument answers the question, and what would REFUTE the idea.
    None of that is a lookup table.

The brief therefore describes what each instrument MEASURES and never what to conclude,
states the facts gathered from the live target, lists what has already been refuted so
effort is not re-spent, and asks for mechanisms in the model's own words. It explicitly
invites a comparison that is not on any list, because that is where the criticals are.

FALSIFIABILITY IS REQUIRED. Every hypothesis must state what would refute it. That is
what lets the falsification ledger retire a dead idea instead of the swarm circling it,
and it is the difference between persistence and thrashing.
"""

from __future__ import annotations

import json
import re

# ---------------------------------------------------------------------------
# The instrument catalogue. Describes CAPABILITY and what each one MEASURES.
# Deliberately not a playbook: no instrument is paired with a conclusion, and no bug
# class is enumerated as a checklist to walk.
# ---------------------------------------------------------------------------
INSTRUMENTS = """
AVAILABLE INSTRUMENTS — what each one MEASURES. Choose; nothing here is a sequence to follow.

  Browser (p1hunt_browser.Browser) — a real browser, scope-jailed.
    .goto(url)                 -> Observation
    Observation.raw_html       the bytes the SERVER sent
    Observation.dom_html       the document AFTER scripts ran (a SERIALIZATION: a text
                               node's "<" is re-escaped, so the absence of a raw
                               metacharacter here measures nothing)
    Observation.executed       whether script actually RAN. Observed, not inferred.
    Observation.execution_proof what ran, and with what argument
    Observation.sinks          writes to innerHTML/outerHTML/document.write/
                               insertAdjacentHTML/iframe.srcdoc, with the value
    Observation.message_listeners  message handlers the page registered
    Observation.requests / .blocked / .console / .cookies / .storage
    .dom_injection(marker)     asks the LIVE document whether your input became ELEMENTS
                               or created an ATTRIBUTE NAME (survives serialization)
    .differential(path, variants)
                               renders ONE resource under several hosts / sessions /
                               header sets and reports what differs
    .escaping_differential(render_fn, control_marker, probe_marker)
                               benign control render vs metacharacter render; reports only
                               the landings the control does not already explain
    .click/.fill/.eval_js/.screenshot

  htmlctx — context-aware escaping measurement.
    census(html, marker)       per landing: the HTML parse context, which characters are
                               dangerous IN THAT CONTEXT, which survived raw, and a
                               verdict with its reasoning. A raw "<" is a finding in a
                               text node and inert inside a quoted attribute; entities do
                               not decode inside <script>. Report ITS verdict rather than
                               your reading of the HTML.
    differential_census(...)   control vs probe, so an application that simply emits one
                               value into several sinks is not mistaken for an injection

  Client (p1hunt_dyn.Client) — scope-enforced HTTP, multiple identities.
    .get/.post/...(path, identity=...)   act as a named principal
    .require_live_baseline(path)         distinguishes DEAD / EDGE-BLOCKED from a real
                                         application answer. A blanket block satisfies
                                         every refusal assertion, so an unprobed "403"
                                         is not evidence of anything
    .assert_forbidden / .idor_probe      a principal must not reach another's object
    .oob_url() / .oob_received(token)    turn callback behavior into pass/fail

  Surface facts (dynamic.recon) — already gathered below. Bundle-mined endpoints,
    observed requests with real parameter shapes, client-side routes, GraphQL operations,
    forms, sibling hosts. templatize() names the identifier SHAPE of a path segment
    (uuid / int / hex / objectid / b64 / msisdn), which determines whether another
    principal's identifier must be obtained or can simply be enumerated.

  Runner — a harness you write is executed and judged. Convention: assert the SECURE
    behavior with expect="fail", so a reproduced bug makes the test FAIL.
"""

METHOD = """
HOW THE BEST FINDINGS ACTUALLY ARRIVE — read this before proposing anything.

1. COMPARE BEFORE YOU INJECT. The strongest findings are two renders or two responses of
   ONE resource that differ in what they expose, and they need no payload at all. Vary
   ONE thing: the host, the session, a header, the identity, the order of two steps, the
   casing of a path, whether a step is skipped. Then ask what the difference implies
   about where the decision is made.

2. A PRECONDITION IS A TARGET, NOT A FOOTNOTE. If something is exploitable only when the
   victim is signed out, or only on one host, the next question is whether that
   precondition can be REMOVED. Removing it is often a separate, independently fixable
   defect, and it is what turns a capped finding into an unconditional one.

3. MEASURE, DO NOT ESTIMATE. Escaping, execution and authorization each have an
   instrument above. Use it and report what it returned. "Looks escaped" is not a result.

4. PROVE IMPACT SEPARATELY FROM PROVING THE BUG. An injection that does not execute is a
   lead. A credential you have not confirmed authorizes something is not impact.

5. SAY WHAT WOULD REFUTE YOU. Required for every hypothesis. An idea that cannot be
   refuted cannot be retired, and the hunt will circle it forever.

Do NOT limit yourself to familiar bug classes, and do not propose a generic checklist.
Name the specific mechanism, on THIS target, in your own words. A comparison nobody has a
name for is the most valuable thing you can produce here.
"""

_SCHEMA = """
Answer with ONE fenced ```json block holding an array of hypotheses, ordered best first.
Each object:

  {
    "target":      "the concrete URL, path template, host pair, or flow",
    "mechanism":   "what you believe is wrong and WHY, in your own words. Not a class name.",
    "vary":        "the single thing you change between the two observations",
    "instrument":  "which instrument above you will use, and the call you will make",
    "confirm_if":  "the specific observation that would CONFIRM it",
    "refute_if":   "the specific observation that would REFUTE it",
    "impact_if_true": "what an attacker gains, and what you would still need to prove it",
    "confidence":  0.0-1.0
  }

No prose outside the block.
"""


def _fmt_facts(surface: dict, *, max_endpoints: int = 120, max_hosts: int = 30) -> str:
    """Compact the gathered surface into something worth spending context on.

    Source is kept per endpoint because it changes how much an endpoint is worth: a path
    the application was SEEN calling is live, while a string mined from a bundle may be
    dead code.
    """
    lines: list[str] = []
    hosts = list(surface.get("hosts") or [])[:max_hosts]
    if hosts:
        lines.append(f"HOSTS SEEN ({len(surface.get('hosts') or [])}): " + ", ".join(hosts))

    eps = list(surface.get("endpoints") or [])
    by_src: dict[str, list] = {}
    for e in eps:
        by_src.setdefault(e.get("source", "?"), []).append(e)
    # Emitted only when there ARE endpoints: an unconditional header made an empty
    # surface look like gathered facts, which would have the model invent targets.
    if eps:
        lines.append(f"ENDPOINTS ({len(eps)} total; 'observed' = the app really called it, "
                     f"'bundle' = mined from its JavaScript and may be dead code):")
    budget = max_endpoints
    for src in ("observed", "form", "route", "bundle"):
        group = by_src.get(src) or []
        if not group:
            continue
        take = group[: max(5, budget // 2)]
        budget -= len(take)
        lines.append(f"  [{src}] {len(group)}:")
        for e in take:
            params = ",".join((e.get("params") or [])[:8])
            lines.append(f"    {e.get('method', 'GET')} {e.get('path')}"
                         + (f"   params={params}" if params else ""))
        if len(group) > len(take):
            lines.append(f"    ... {len(group) - len(take)} more")
        if budget <= 0:
            break

    gql = list(surface.get("graphql") or [])[:60]
    if gql:
        lines.append(f"GRAPHQL OPERATIONS IN THE BUNDLE ({len(surface.get('graphql') or [])}): "
                     + ", ".join(gql))
    forms = list(surface.get("forms") or [])[:20]
    if forms:
        lines.append("FORMS:")
        for f in forms:
            lines.append(f"  {f.get('method')} {f.get('action')}  fields="
                         + ",".join((f.get("fields") or [])[:12]))
    gates = list(surface.get("gate_paths") or [])[:40]
    if gates:
        lines.append("PATHS RENDERED DURING RECON (candidates for a cross-host or "
                     "cross-session comparison): " + ", ".join(gates))
    sec = list(surface.get("secretish_responses") or [])[:15]
    if sec:
        lines.append("RESPONSES THAT NAME CREDENTIAL-LIKE KEYS (unverified):")
        for s in sec:
            lines.append(f"  {s.get('url')}  [{s.get('where')}] {s.get('what')}")
    notes = list(surface.get("notes") or [])[:10]
    if notes:
        lines.append("RECON NOTES: " + " | ".join(str(n) for n in notes))
    return "\n".join(lines) if lines else "(no surface gathered)"


def build_brief(surface: dict, *, target_name: str = "", scope_note: str = "",
                ruled_out: list[str] | None = None,
                identities: list[str] | None = None,
                confirmed_so_far: list[str] | None = None,
                max_endpoints: int = 120) -> str:
    """The prompt: facts, instruments, method, and what is already dead.

    ``ruled_out`` is the falsification ledger's content. Passing it is what makes the
    loop persistent rather than repetitive: an idea already refuted with evidence must
    not come back, and the model can only honour that if it is told.
    """
    parts = [
        f"You are hunting for CRITICAL vulnerabilities on an AUTHORIZED target"
        + (f": {target_name}" if target_name else "") + ".",
        "",
        "Only contact hosts the scope allows; the instruments enforce that for you and a "
        "request elsewhere raises rather than leaking.",
    ]
    if scope_note:
        parts += ["", "SCOPE / RULES OF ENGAGEMENT:", scope_note]
    parts += ["", "FACTS GATHERED FROM THE LIVE TARGET:", _fmt_facts(surface, max_endpoints=max_endpoints)]
    if identities:
        parts += ["", "TEST IDENTITIES AVAILABLE (use them to compare, not just to "
                  "authenticate): " + ", ".join(identities)]
    if confirmed_so_far:
        parts += ["", "ALREADY CONFIRMED on this target — do not re-report these; instead ask "
                  "whether a precondition can be removed, whether the same defect exists "
                  "somewhere unconditional, or whether the blast radius is wider than stated:"]
        parts += [f"  - {c}" for c in confirmed_so_far[:30]]
    if ruled_out:
        parts += ["", "ALREADY REFUTED WITH EVIDENCE — do not propose these again. If you "
                  "believe one was refuted for the wrong reason, say so explicitly and state "
                  "what NEW observation would change the verdict:"]
        parts += [f"  - {r}" for r in ruled_out[:40]]
    parts += [INSTRUMENTS, METHOD, _SCHEMA]
    return "\n".join(parts)


def _repair_json(raw: str) -> str:
    """Repair the two ways a model's JSON block is habitually malformed.

    1. A RAW NEWLINE INSIDE A STRING. JSON forbids it, but a model writing a long
       ``mechanism`` across several lines emits it constantly, and a strict parser then
       throws away an otherwise perfect plan. Control characters inside string literals
       are escaped rather than the reply being discarded.
    2. A TRAILING COMMA before ``}`` or ``]``.

    Repair is attempted only AFTER a strict parse has already failed, so well-formed
    output is never touched.
    """
    out: list[str] = []
    in_str = False
    esc = False
    for ch in raw or "":
        if esc:
            out.append(ch)
            esc = False
            continue
        if ch == "\\" and in_str:
            out.append(ch)
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            out.append(ch)
            continue
        if in_str and ch in "\n\r\t":
            out.append({"\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
            continue
        if in_str and ord(ch) < 0x20:
            out.append(" ")
            continue
        out.append(ch)
    return re.sub(r",\s*([}\]])", r"\1", "".join(out))


_FENCE = re.compile(r"```(?:json)?\s*(\[.*?\])\s*```", re.DOTALL)
_BARE = re.compile(r"(\[\s*\{.*?\}\s*\])", re.DOTALL)
_REQUIRED = ("target", "mechanism", "instrument", "confirm_if", "refute_if")


def parse_plan(text: str) -> list[dict]:
    """Extract hypotheses from a model reply. Tolerant of prose around the block.

    A hypothesis MISSING ``refute_if`` is dropped rather than repaired: without a
    refutation condition the ledger cannot retire it, so accepting one would quietly
    reintroduce the thrashing this layer exists to prevent.
    """
    if not text:
        return []
    raw = None
    m = _FENCE.search(text) or _BARE.search(text)
    if m:
        raw = m.group(1)
    if raw is None:
        return []
    try:
        data = json.loads(raw)
    except Exception:
        try:
            data = json.loads(_repair_json(raw))
        except Exception:
            return []
    if not isinstance(data, list):
        return []
    out: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        if any(not str(item.get(k) or "").strip() for k in _REQUIRED):
            continue
        try:
            conf = float(item.get("confidence", 0.5))
        except Exception:
            conf = 0.5
        out.append({
            "target": str(item["target"]).strip()[:400],
            "mechanism": str(item["mechanism"]).strip()[:1200],
            "vary": str(item.get("vary") or "").strip()[:400],
            "instrument": str(item["instrument"]).strip()[:600],
            "confirm_if": str(item["confirm_if"]).strip()[:600],
            "refute_if": str(item["refute_if"]).strip()[:600],
            "impact_if_true": str(item.get("impact_if_true") or "").strip()[:800],
            "confidence": max(0.0, min(1.0, conf)),
        })
    out.sort(key=lambda h: -h["confidence"])
    return out


async def triage(surface: dict, *, session=None, session_factory=None, cwd: str = ".",
                 **brief_kw) -> dict:
    """Ask the engine what to attack. Returns ``{"plan": [...], "ok":..., "brief":...}``.

    ``session`` or ``session_factory`` supplies an engine session
    (``agents.claude_session.make_session``), whose ``run(prompt, cwd)`` returns a
    ``SessionResult``. With neither, this returns ok=False and a loud degraded note --
    it does NOT silently fall back to a heuristic, because a keyword list's output
    dressed up as a plan is worse than an honest absence.
    """
    brief = build_brief(surface, **brief_kw)
    sess = session or (session_factory() if session_factory else None)
    if sess is None:
        return {"ok": False, "plan": [], "brief": brief,
                "error": "no engine session: triage is a REASONING step and has no "
                         "non-reasoning equivalent. Use recon.fallback_rank_leads() only "
                         "as an explicitly degraded surface ordering."}
    try:
        res = await sess.run(brief, cwd)
    except Exception as exc:
        return {"ok": False, "plan": [], "brief": brief, "error": f"session failed: {exc}"}
    plan = parse_plan(getattr(res, "text", "") or "")
    return {"ok": bool(getattr(res, "ok", False)) and bool(plan),
            "plan": plan, "brief": brief,
            "text": getattr(res, "text", "") or "",
            "error": getattr(res, "error", "") or ("" if plan else "no parseable hypotheses")}


def plan_to_entrypoints(plan: list[dict], *, limit: int = 200) -> list[str]:
    """Render a model-authored plan as the ``"METHOD /path"`` entries the coverage loop
    consumes, so a reasoned plan drives the SAME persistence machinery (uncovered hints,
    the ledger, escalation) that a repo-derived surface drives."""
    out: list[str] = []
    seen: set[str] = set()
    for h in plan:
        t = (h.get("target") or "").strip()
        if not t:
            continue
        m = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+)$", t, re.IGNORECASE)
        entry = f"{m.group(1).upper()} {m.group(2).strip()}" if m else f"ANY {t}"
        if entry not in seen:
            seen.add(entry)
            out.append(entry)
        if len(out) >= limit:
            break
    return out
