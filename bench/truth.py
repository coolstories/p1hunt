"""Ground-truth matching, shared by the planning scorer and the execution scorer.

WHY THIS IS ITS OWN MODULE
--------------------------
There are two scorers now -- run_range.py scores the PLAN (did it propose the right
things to look at) and run_exec.py scores the EXECUTION (did it then prove them). They
must agree on what "this hypothesis/finding is about planted defect X" means, because the
two numbers are read side by side: a planning recall of 1.0 next to an execution recall
of 0.3 is a statement about the hunt, but only if both used the same matcher. When the
matching lived inside run_range.py, the execution scorer would have had to reimplement
it, and the first silent divergence would have turned that comparison into noise.

Nothing here is a judgement about security. It is only string matching against a list of
defects the range's author planted on purpose, and it exists to score a test range -- it
is not part of the hunt and nothing in p1hunt imports it.
"""

from __future__ import annotations

import re
import urllib.parse

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from range_app import DECOYS, PLANTED  # noqa: E402,F401  (re-exported on purpose)

from p1hunt.dynamic import recon as R  # noqa: E402

_VERBS = ("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "ANY ", "HEAD ", "OPTIONS ",
          "GRAPHQL ", "FLOW: ")

# A model names a target the way a person would, so the string often carries a trailing
# clause: "/share/{id} - default host versus X-Range-Host: m.range".
_TRAILING_CLAUSE = re.compile(
    r"\s+[—–-]\s+|\s*\(|\s{2,}|,\s|\s+(?:with|using|vs\.?|versus|then|followed)\s+")


def norm_path(target: str) -> str:
    """A plan target or a finding location -> a comparable path template.

    Two ordering bugs lived here and both UNDER-reported a good run, which is the
    dangerous direction for a scorer -- it makes the tool look worse than it is and sends
    you fixing the wrong thing:

      1. Feeding the whole string through templatize meant the trailing prose clause was
         still attached, so the identifier segment no longer looked like a UUID, the
         template never matched, and a correctly found defect was scored as a miss while
         being listed as an unrelated target.
      2. Truncating at whitespace BEFORE stripping the method verb reduced
         "GET /api/v1/accounts/{id}" to "GET", which scored a perfect plan as 0.0 recall.

    So: verb first, then the prose clause, then the template.
    """
    t = (target or "").strip()
    for verb in _VERBS:
        if t.upper().startswith(verb):
            t = t[len(verb):].strip()
            break
    t = _TRAILING_CLAUSE.split(t, maxsplit=1)[0].strip()
    t = t.split()[0] if t.split() else t
    if "://" in t:
        t = urllib.parse.urlsplit(t).path or t
    t = t.split("?")[0].split("#")[0].strip()
    # A live finding's location is sometimes "url:0" or "path:line" (the pipeline's
    # file:line convention, with line 0 for web findings).
    t = re.sub(r":\d+$", "", t)
    tpl, _ = R.templatize(t)
    return (tpl.replace("/:id", "/{id}").replace("/<id>", "/{id}").rstrip("/") or "/")


def stem(path: str) -> str:
    """The distinctive leading segments, for a looser second-chance match."""
    p = norm_path(path)
    parts = [x for x in p.split("/") if x and x != "{id}"]
    return "/" + "/".join(parts[:3])


def paths_match(a: str, b: str) -> bool:
    """Does one location refer to the same place as another?

    Deliberately a little generous on the path and strict on the mechanism (see
    mechanism_matches). Getting the path slightly wrong -- "/api/v1/accounts" for
    "/api/v1/accounts/{id}" -- is a notation difference; getting the mechanism wrong is a
    different finding.
    """
    na, nb = norm_path(a), norm_path(b)
    if na == nb:
        return True
    if stem(a) == stem(b):
        return True
    if na != "/" and nb != "/" and (na.startswith(nb) or nb.startswith(na)):
        return True
    return False


def mechanism_matches(text: str, planted: dict) -> bool:
    """Does this text show the planted defect's IDEA, not just its address?

    Naming the path with the wrong mechanism is progress, not a find. Counting it as a
    find would flatter the tool, so the two are reported separately everywhere.
    """
    low = (text or "").lower()
    return any(k in low for k in planted["keys"])


def planted_for(location: str, text: str = "") -> dict | None:
    """The planted defect this location+text is about, or None.

    When ``text`` is empty only the location is considered, so callers that want
    "located" vs "found" must pass the text and check mechanism_matches themselves.
    """
    for p in PLANTED:
        if paths_match(location, p["path"]):
            if not text or mechanism_matches(text, p):
                return p
    return None


def locations_in(text: str) -> list[str]:
    """The path-like tokens in a free-text claim. Use this, never the raw text.

    WHY: norm_path is a NORMALIZER, not a validator. Given "profile enumeration risk" it
    takes the first token, templatizes "profile", and stem() prepends a slash -- so the
    string matches the /profile decoy on the strength of one English word. Feeding a
    finding's TITLE straight to paths_match therefore manufactured location evidence:
    "search results are reflected" scored as naming /search, and since the decoy check has
    no mechanism test to save it, "profile enumeration risk" scored as a false positive on
    decoy-attr.

    So a token only counts as a location when it looks like one: rooted at "/" or carrying
    a scheme. That is strict on purpose -- the claim's `location`/`file` field is the real
    source, and this is only the fallback for a run whose docs lost it.
    """
    out: list[str] = []
    for tok in (text or "").replace(",", " ").replace("(", " ").replace(")", " ").split():
        tok = tok.strip("'\"`;:")
        if tok.startswith("/") or "://" in tok:
            out.append(tok)
    return out[:20]


def mentions_path(text: str, path: str) -> bool:
    """Does this free text NAME this location? Path-like tokens only (see locations_in)."""
    return any(paths_match(tok, path) for tok in locations_in(text))


def decoy_for(location: str) -> dict | None:
    """The decoy this location is about, or None.

    No mechanism check: a decoy has no defect to describe, so ANY claim naming its
    location is a false positive on it.
    """
    for d in DECOYS:
        if paths_match(location, d["path"]):
            return d
    return None
