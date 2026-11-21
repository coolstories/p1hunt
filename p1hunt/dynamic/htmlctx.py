"""Context-aware escaping analysis: where did my input land, and is it inert THERE?

WHY THIS MODULE EXISTS
----------------------
"Is my marker escaped?" is the wrong question. The right question is "is my marker
inert *in the parse context it landed in*?" The two differ, and the difference is
where real bugs hide in both directions:

  * A raw ``<`` in a TEXT NODE is a tag injection.
  * A raw ``<`` inside a DOUBLE-QUOTED ATTRIBUTE is completely inert -- ``<`` is not a
    tag opener there. Reporting it is a false positive.
  * ``&quot;`` inside a ``<script>`` block is six literal characters, because script is
    RAWTEXT and HTML entities are NEVER decoded there. Reporting it is a false positive.
  * But a raw ``&`` in an ATTRIBUTE, where the application already put ``&quot;`` of its
    own around structural JSON, means an attacker-supplied ``&quot;`` decodes to a REAL
    quote on parse. That is a true positive that a naive "is < escaped?" check misses
    entirely.
  * An UNQUOTED attribute value needs no quote at all -- a single space lets you add
    ``onfocus=...``. Highest-risk context, and the one a ``<``/``>``-only check ignores.

So this module answers, per occurrence: which HTML parse state is this offset in, and
which characters are dangerous in THAT state. A verdict of INERT means "escaped
correctly for its context", not "contains no angle brackets".

STDLIB ONLY, NO p1hunt IMPORTS. ``agents/claude_swarm.py`` ships this file into the PoC
sandbox alongside ``p1hunt_dyn.py``, where no ``p1hunt`` package is on ``sys.path``.
"""

from __future__ import annotations

import re
from bisect import bisect_right as _bisect_right
from functools import lru_cache as _lru_cache

# ---------------------------------------------------------------------------
# Parse contexts. Names match the HTML tokenizer states they correspond to, so a
# reader can check them against the spec rather than against our prose.
# ---------------------------------------------------------------------------
TEXT = "text"                  # character data: <p>HERE</p>
ATTR_DQ = "attr_double"        # attr="HERE"
ATTR_SQ = "attr_single"        # attr='HERE'
ATTR_UNQ = "attr_unquoted"     # attr=HERE
TAG_NAME = "tag_name"          # <HERE ...>
ATTR_NAME = "attr_name"        # <div HERE=...>
SCRIPT = "script"              # <script>HERE</script>   (RAWTEXT; entities NOT decoded)
STYLE = "style"                # <style>HERE</style>     (RAWTEXT)
RCDATA = "rcdata"              # <title>HERE</title>, <textarea>HERE</textarea>
COMMENT = "comment"            # <!-- HERE -->
UNKNOWN = "unknown"

# Elements whose content is RAWTEXT (no entity decoding, no markup).
_RAWTEXT_TAGS = {"script": SCRIPT, "style": STYLE}
# Elements whose content is RCDATA (entities decode, but markup does not).
_RCDATA_TAGS = {"title": RCDATA, "textarea": RCDATA}

# Attributes whose VALUE is executed as JavaScript. Anything landing here is already
# in a script context, so the only thing standing between input and execution is the
# quote character.
_EVENT_ATTR_RE = re.compile(r"^on[a-z]+$", re.IGNORECASE)
# Attributes whose value is a URL: a ``javascript:`` or ``data:`` scheme executes even
# with every HTML metacharacter perfectly escaped.
_URL_ATTRS = frozenset({
    "href", "src", "action", "formaction", "data", "poster", "codebase",
    "cite", "background", "longdesc", "profile", "usemap", "manifest",
    "xlink:href", "srcdoc", "ping",
})
_WS = " \t\n\r\f"


def segments(html: str) -> list[tuple]:
    """Tokenize ONCE into ``(start_offset, context, tag, attr)`` state segments.

    A single forward pass. ``html_context_at`` used to re-run the machine from offset 0
    on every query, which is O(n) per lookup and O(n*m) for a census of m landings --
    unusable on a real several-hundred-KB render. Segments are computed once, cached,
    and answered by bisect.
    """
    segs: list[tuple] = [(0, TEXT, "", "")]

    def emit(off: int, ctx: str, tag: str, attr: str) -> None:
        if segs and segs[-1][1:] == (ctx, tag, attr):
            return
        if segs and segs[-1][0] == off:
            segs[-1] = (off, ctx, tag, attr)
            return
        segs.append((off, ctx, tag, attr))

    state = TEXT
    tag = ""
    attr = ""
    buf_tag = ""
    buf_attr = ""
    after_name = False
    i = 0
    n = len(html)

    while i < n:
        c = html[i]

        if state == TEXT:
            if c == "<":
                if html.startswith("<!--", i):
                    state = COMMENT
                    emit(i, COMMENT, tag, "")
                    i += 4
                    continue
                if html.startswith("<!", i) or html.startswith("<?", i):
                    state = COMMENT
                    emit(i, COMMENT, tag, "")
                    i += 2
                    continue
                j = i + 1
                if j < n and html[j] == "/":
                    j += 1
                if j < n and html[j].isalpha():
                    state = TAG_NAME
                    buf_tag = ""
                    emit(i, TAG_NAME, "", "")
                    i = j
                    continue
            i += 1
            continue

        if state == COMMENT:
            k = html.find("-->", i)
            if k == -1:
                break
            state = TEXT
            i = k + 3
            emit(i, TEXT, tag, "")
            continue

        if state == TAG_NAME:
            if c in _WS or c == "/" or c == ">":
                tag = buf_tag.lower()
                if c == ">":
                    state = _open_element(tag)
                    emit(i + 1, state, tag, "")
                else:
                    state = ATTR_NAME
                    buf_attr = ""
                    after_name = False
                    emit(i, ATTR_NAME, tag, "")
                i += 1
                continue
            buf_tag += c
            i += 1
            continue

        if state == ATTR_NAME:
            if c == ">":
                state = _open_element(tag)
                emit(i + 1, state, tag, "")
                i += 1
                continue
            if c == "=":
                attr = buf_attr.lower()
                j = i + 1
                while j < n and html[j] in _WS:
                    j += 1
                if j >= n:
                    state = ATTR_UNQ
                    emit(j, ATTR_UNQ, tag, attr)
                    break
                q = html[j]
                if q == '"':
                    state = ATTR_DQ
                    i = j + 1
                    emit(i, ATTR_DQ, tag, attr)
                elif q == "'":
                    state = ATTR_SQ
                    i = j + 1
                    emit(i, ATTR_SQ, tag, attr)
                elif q == ">":
                    state = _open_element(tag)
                    i = j + 1
                    emit(i, state, tag, "")
                else:
                    state = ATTR_UNQ
                    i = j
                    emit(i, ATTR_UNQ, tag, attr)
                buf_attr = ""
                after_name = False
                continue
            if c in _WS:
                after_name = True
                i += 1
                continue
            if c == "/":
                i += 1
                continue
            if after_name:
                buf_attr = ""
                after_name = False
            buf_attr += c
            i += 1
            continue

        if state == ATTR_DQ:
            if c == '"':
                state = ATTR_NAME
                attr = ""
                buf_attr = ""
                after_name = False
                emit(i + 1, ATTR_NAME, tag, "")
            i += 1
            continue

        if state == ATTR_SQ:
            if c == "'":
                state = ATTR_NAME
                attr = ""
                buf_attr = ""
                after_name = False
                emit(i + 1, ATTR_NAME, tag, "")
            i += 1
            continue

        if state == ATTR_UNQ:
            if c in _WS:
                state = ATTR_NAME
                attr = ""
                buf_attr = ""
                after_name = False
                emit(i + 1, ATTR_NAME, tag, "")
            elif c == ">":
                state = _open_element(tag)
                attr = ""
                emit(i + 1, state, tag, "")
            i += 1
            continue

        if state in (SCRIPT, STYLE, RCDATA):
            end = "</" + tag
            k = _ifind(html, end, i)
            if k == -1:
                break
            state = TEXT
            i = k
            emit(i, TEXT, tag, "")
            i = k + len(end)
            continue

        i += 1

    return segs


@_lru_cache(maxsize=16)
def _segments_cached(html: str) -> tuple:
    return tuple(segments(html))


def html_context_at(html: str, offset: int, segs: tuple | None = None) -> dict:
    """Return the HTML parse context at ``offset``.

    Keys: ``context``, ``tag`` (enclosing or current element, lowercased) and ``attr``
    (attribute name when inside a value, lowercased).
    """
    if offset < 0 or offset > len(html):
        return {"context": UNKNOWN, "tag": "", "attr": ""}
    segs = segs if segs is not None else _segments_cached(html)
    k = _bisect_right([sg[0] for sg in segs], offset) - 1
    if k < 0:
        k = 0
    _, ctx, tag, attr = segs[k]
    return {"context": ctx, "tag": tag, "attr": attr}


def span_skeleton(html: str, start: int, end: int, segs: tuple | None = None) -> tuple:
    """The ordered sequence of ``(context, attr)`` states a span traverses.

    This is what makes a differential sensitive to an INJECTED attribute. Comparing
    only the span's endpoints cannot tell ``value="X" title="X"`` from
    ``value="X" onfocus=alert(1) title="X"`` -- both start in one attribute value and
    end in another. The traversal differs, and that is the finding.
    """
    segs = segs if segs is not None else _segments_cached(html)
    out = []
    for off, ctx, _tag, attr in segs:
        if off > end:
            break
        if off >= start or (out == [] and off <= start):
            pair = (ctx, attr)
            if not out or out[-1] != pair:
                out.append(pair)
    if not out:
        c = html_context_at(html, start, segs)
        out = [(c["context"], c["attr"])]
    return tuple(out)


def _open_element(tag: str) -> str:
    """State entered after the ``>`` of a start tag for ``tag``."""
    if tag in _RAWTEXT_TAGS:
        return _RAWTEXT_TAGS[tag]
    if tag in _RCDATA_TAGS:
        return _RCDATA_TAGS[tag]
    return TEXT


def _ifind(hay: str, needle: str, start: int) -> int:
    """Case-insensitive ``str.find``; HTML tag names are case-insensitive."""
    return hay.lower().find(needle.lower(), start)


# ---------------------------------------------------------------------------
# Danger rules, per context.
# ---------------------------------------------------------------------------

def dangerous_chars(context: str, attr: str = "", tag: str = "") -> dict:
    """Characters that let input ESCAPE ``context``, each mapped to why.

    This is the whole point of the module: the answer differs per context, and a
    checker that asks only about ``<`` is wrong in both directions.
    """
    a = (attr or "").lower()

    if context == TEXT:
        return {"<": "opens a tag in character data"}

    if context == ATTR_DQ:
        d = {'"': "closes the attribute value, allowing a new attribute"}
        if _EVENT_ATTR_RE.match(a):
            d['"'] = "closes the value of an EVENT HANDLER attribute -- already a JS context"
        return d

    if context == ATTR_SQ:
        d = {"'": "closes the attribute value, allowing a new attribute"}
        if _EVENT_ATTR_RE.match(a):
            d["'"] = "closes the value of an EVENT HANDLER attribute -- already a JS context"
        return d

    if context == ATTR_UNQ:
        # No quote to break: any whitespace starts a new attribute.
        d = {c: "whitespace ends an unquoted value, allowing a new attribute" for c in " \t\n\r\f"}
        d.update({
            ">": "ends the tag",
            '"': "quote in an unquoted value",
            "'": "quote in an unquoted value",
            "`": "backtick is a value delimiter in some legacy parsers",
            "=": "starts another attribute value",
        })
        return d

    if context in (SCRIPT, STYLE, RCDATA):
        return {"</": f"the closing-tag sequence is the ONLY exit from <{tag or context}>"}

    if context == COMMENT:
        return {"-->": "ends the comment and returns to character data"}

    if context in (TAG_NAME, ATTR_NAME):
        return {" ": "injects a new attribute directly into the tag",
                ">": "ends the tag"}

    return {}


def entities_decode_in(context: str) -> bool:
    """Does the HTML parser decode character references in ``context``?

    False inside RAWTEXT (``<script>``/``<style>``): ``&quot;`` there is six literal
    characters and can never become a quote. Getting this backwards produces a
    confident false positive on every JSON-in-script payload.
    """
    return context not in (SCRIPT, STYLE, COMMENT)


def url_sink(context: str, attr: str) -> bool:
    """True when this is a URL-valued attribute, where a scheme alone executes."""
    return context in (ATTR_DQ, ATTR_SQ, ATTR_UNQ) and (attr or "").lower() in _URL_ATTRS


def js_sink(context: str, attr: str) -> bool:
    """True when the value is executed as JavaScript (event handler, or raw script)."""
    if context in (SCRIPT,):
        return True
    return context in (ATTR_DQ, ATTR_SQ, ATTR_UNQ) and bool(_EVENT_ATTR_RE.match((attr or "").lower()))


_DANGEROUS_SCHEMES = ("javascript:", "data:", "vbscript:")


# Widest gap between a probe's two tokens that still counts as one landing. An
# application that entity-encodes a long payload expands it several-fold, so this is
# generous; it exists to stop two DISTANT landings of a bare token from being paired.
_MAX_SPAN = 1024


def census(html: str, marker: str, *, window: int = 90) -> list[dict]:
    """Locate every ``marker`` landing and judge it IN ITS OWN CONTEXT.

    Two independent kinds of evidence, in order of strength:

    1. STRUCTURAL -- the parse context at the closing marker differs from the context
       at the opening marker. Our input moved the tokenizer: it left the attribute
       value, closed the ``<script>``, ended the text node. This needs no character
       heuristics and no payload guessing, and it is how a successful breakout always
       looks. Caveat: an application that simply emits the same value into two
       DIFFERENT sinks produces the same shape, so structural evidence is a candidate
       until ``differential_census`` rules that out against a benign control.

    2. CHARACTER -- the context did not change, but a character that is dangerous in
       THIS context survived raw in the span. Catches a payload that could break out
       but did not in this particular probe.

    Returns one record per landing. ``verdict`` is one of
    ``BREAKOUT`` | ``SCHEME`` | ``DOUBLE_DECODE`` | ``INERT``, and ``evidence`` is
    ``structural`` | ``character`` | ``scheme`` | ``double_decode`` | ``none``.
    """
    out: list[dict] = []
    if not marker:
        return out
    segs = _segments_cached(html)
    start = 0
    while True:
        idx = html.find(marker, start)
        if idx == -1:
            break
        ctx = html_context_at(html, idx, segs)
        context, tag, attr = ctx["context"], ctx["tag"], ctx["attr"]

        # Pair with the nearest following occurrence. For a self-delimiting probe (see
        # PROBE, whose metacharacters sit BETWEEN the two tokens) that is the close
        # token of this same landing.
        end = html.find(marker, idx + len(marker))
        span_end = idx + len(marker)
        close_ctx = dict(ctx)
        paired = False
        if end != -1 and (end - idx) <= _MAX_SPAN:
            close_ctx = html_context_at(html, end, segs)
            span_end = end + len(marker)
            paired = True
        span = html[idx:span_end]

        # A context change between the two tokens means our input moved the parser.
        # ``tag`` is excluded: in character-data states it holds "last start tag seen"
        # rather than the enclosing element (no element stack is kept), so a payload
        # that emits any tag would otherwise look like a context change by itself.
        state_change = bool(paired) and (
            close_ctx["context"] != context
            or (context in (ATTR_DQ, ATTR_SQ, ATTR_UNQ) and close_ctx["attr"] != attr)
        )

        danger = dangerous_chars(context, attr, tag)
        raw_hits, esc_hits = [], []
        for ch, why in danger.items():
            if ch in span:
                raw_hits.append({"char": ch, "why": why})
            else:
                esc_hits.append(ch)

        verdict, evidence = "INERT", "none"
        why = f"every character dangerous in {context} was neutralized"
        if state_change:
            verdict, evidence = "BREAKOUT", "structural"
            why = (f"input moved the parse state {context} -> {close_ctx['context']}"
                   + (f" (attribute {attr!r} -> {close_ctx['attr']!r})"
                      if context in (ATTR_DQ, ATTR_SQ, ATTR_UNQ) else ""))
        elif raw_hits:
            verdict, evidence = "BREAKOUT", "character"
            why = raw_hits[0]["why"]
        elif url_sink(context, attr) and any(
                sch in span.lower().replace(" ", "").replace("\t", "").replace("\n", "")
                for sch in _DANGEROUS_SCHEMES):
            verdict, evidence = "SCHEME", "scheme"
            why = f"{attr} is a URL sink and the value carries an executable scheme"
        elif (entities_decode_in(context) and context in (ATTR_DQ, ATTR_SQ, ATTR_UNQ)
                and "&" in span and "&amp;" not in span
                and re.search(r"&(?:quot|apos|#0*3[49]|#x0*2[27]);", span, re.I)):
            # Our "&" survived raw inside an attribute while an entity is present, so an
            # entity we supply decodes to a real quote on parse.
            verdict, evidence = "DOUBLE_DECODE", "double_decode"
            why = ("our '&' survived raw in an attribute, so an entity we supply decodes "
                   "to a real quote on parse")

        start = max(span_end, idx + 1)
        out.append({
            "offset": idx,
            "skeleton": span_skeleton(html, idx, span_end, segs),
            "context": context,
            "close_context": close_ctx["context"],
            "paired": paired,
            "state_change": state_change,
            "tag": tag,
            "attr": attr,
            "entities_decode": entities_decode_in(context),
            "js_sink": js_sink(context, attr),
            "url_sink": url_sink(context, attr),
            "raw": raw_hits,
            "escaped": esc_hits,
            "verdict": verdict,
            "evidence": evidence,
            "why": why,
            "snippet": html[max(0, idx - window): span_end + window],
        })
    return out


def sink_layout(records: list[dict]) -> list[tuple]:
    """The shape of where a marker landed, independent of the payload's characters.

    Comparing this between a benign control render and a probe render separates "our
    metacharacters moved the parser" from "this application always emits the value into
    several different sinks".
    """
    return [(r["context"], r["close_context"], r["attr"], r.get("skeleton", ()))
            for r in records]


def differential_census(benign_html: str, probe_html: str,
                        benign_marker: str, probe_marker: str) -> dict:
    """Compare a benign control render against a probe render.

    Structural evidence alone cannot tell a real breakout from an application that
    emits one value into several sinks, because both look like a context change. The
    control render settles it: send a marker with NO metacharacters, record where it
    lands, then send the probe and compare. Only a layout that CHANGED is attributable
    to the metacharacters.

    Returns ``{"confirmed": [...], "layout_changed": bool, "control": [...],
    "probe": [...]}`` where ``confirmed`` holds the probe records whose verdict is a
    finding AND which are not explained away by the control's own layout.
    """
    control = census(benign_html, benign_marker)
    probe = census(probe_html, probe_marker)
    control_layout = sink_layout(control)
    probe_layout = sink_layout(probe)
    layout_changed = control_layout != probe_layout

    confirmed = []
    for rec in probe:
        if rec["verdict"] == "INERT":
            continue
        if rec["evidence"] == "structural" and not layout_changed:
            # The control shows the same context pairing with no metacharacters in it,
            # so this is the application's own multi-sink layout, not our injection.
            continue
        confirmed.append(rec)
    return {
        "confirmed": confirmed,
        "layout_changed": layout_changed,
        "control": control_layout,
        "probe": probe_layout,
    }


def breakouts(records: list[dict]) -> list[dict]:
    """Only the occurrences that are actually exploitable in their context."""
    return [r for r in records if r["verdict"] != "INERT"]


# A probe marker carrying every metacharacter that matters, in a form that survives
# a round trip through most applications. Paired so ``census`` can bound the span.
PROBE = "p1hZ<>\"'`&/=;:p1hZ"
PROBE_TOKEN = "p1hZ"
