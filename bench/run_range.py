"""Score the real pipeline against the range's known ground truth.

Runs recon with a real browser, then the planning pass with a REAL engine session, then
scores the plan against planted defects AND decoys. Both numbers matter: recall says
whether it finds bugs, precision says whether its output is worth triaging. A tool that
reports every endpoint scores 100% recall and is useless.

Usage:
  python3 bench/run_range.py              # recon + real engine plan + score
  python3 bench/run_range.py --recon-only # no model call (free, offline)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from range_app import DECOYS, PLANTED, Range  # noqa: E402

from p1hunt.dynamic import recon as R  # noqa: E402
from p1hunt.dynamic import triage as T  # noqa: E402
from p1hunt.dynamic.browser import Browser  # noqa: E402


def _norm_path(target: str) -> str:
    """A plan target -> a comparable path template."""
    t = (target or "").strip()
    for verb in ("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "ANY ", "HEAD ", "OPTIONS "):
        if t.upper().startswith(verb):
            t = t[len(verb):]
            break
    if "://" in t:
        import urllib.parse
        t = urllib.parse.urlsplit(t).path or t
    t = t.split("?")[0].split("#")[0].strip()
    tpl, _ = R.templatize(t)
    # :id / <id> style placeholders too
    return (tpl.replace("/:id", "/{id}").replace("/<id>", "/{id}").rstrip("/") or "/")


def _stem(path: str) -> str:
    """The distinctive leading segments, for a looser second-chance match."""
    p = _norm_path(path)
    parts = [x for x in p.split("/") if x and x != "{id}"]
    return "/" + "/".join(parts[:3])


def score(plan: list[dict]) -> dict:
    """Score a plan. Matching is deliberately strict enough to be meaningful.

    A planted defect counts as FOUND only when a hypothesis both names its location and
    shows the right idea in its mechanism text. Naming the path with the wrong mechanism
    is reported separately as 'located only' -- it is progress, not a find, and counting
    it as a find would flatter the tool.
    """
    norm = []
    for h in plan:
        norm.append({
            "h": h,
            "path": _norm_path(h.get("target", "")),
            "stem": _stem(h.get("target", "")),
            "text": " ".join([
                str(h.get("mechanism") or ""), str(h.get("vary") or ""),
                str(h.get("instrument") or ""), str(h.get("confirm_if") or ""),
                str(h.get("impact_if_true") or ""),
            ]).lower(),
        })

    found, located, missed = [], [], []
    matched_idx: set[int] = set()
    for p in PLANTED:
        want = _norm_path(p["path"])
        want_stem = _stem(p["path"])
        hits = [i for i, n in enumerate(norm)
                if n["path"] == want or n["stem"] == want_stem
                or want.startswith(n["path"]) and n["path"] != "/"
                or n["path"].startswith(want) and want != "/"]
        if not hits:
            missed.append({**p, "why": "no hypothesis named this location"})
            continue
        good = [i for i in hits if any(k in norm[i]["text"] for k in p["keys"])]
        matched_idx.update(hits)
        if good:
            h = norm[good[0]]["h"]
            found.append({"id": p["id"], "class": p["class"], "target": h.get("target"),
                          "mechanism": (h.get("mechanism") or "")[:260],
                          "confidence": h.get("confidence")})
        else:
            located.append({"id": p["id"], "class": p["class"],
                            "target": norm[hits[0]]["h"].get("target"),
                            "mechanism": (norm[hits[0]]["h"].get("mechanism") or "")[:200],
                            "why": "right location, mechanism did not show the defect"})

    false_pos = []
    for d in DECOYS:
        want = _norm_path(d["path"])
        want_stem = _stem(d["path"])
        for i, n in enumerate(norm):
            if n["path"] == want or n["stem"] == want_stem:
                false_pos.append({"id": d["id"], "target": n["h"].get("target"),
                                  "why_safe": d["why"],
                                  "claimed": (n["h"].get("mechanism") or "")[:200]})
                matched_idx.add(i)
                break

    unmatched = [norm[i]["h"].get("target") for i in range(len(norm)) if i not in matched_idx]
    tp = len(found)
    denom = tp + len(false_pos) + len(unmatched)
    return {
        "planted": len(PLANTED), "decoys": len(DECOYS), "hypotheses": len(plan),
        "found": found, "located_only": located, "missed": missed,
        "false_positives": false_pos, "unscored_targets": unmatched,
        "recall": round(tp / max(1, len(PLANTED)), 3),
        "precision": round(tp / max(1, denom), 3),
    }


def do_recon(base: str) -> dict:
    with Browser(allowlist=[], base_url=base, rate_limit=0, settle_ms=300) as b:
        return R.discover(b, [base + "/"], max_pages=10, max_scripts=6)


def make_real_session():
    from p1hunt.agents.claude_session import make_session
    from p1hunt.config import Config

    cfg = Config()
    m = cfg.models
    return make_session(model=m.falsifier, engine=m.engine, effort=m.codex_effort,
                        codex_model=m.codex_model, agent_name="range:planner")


def main() -> int:
    recon_only = "--recon-only" in sys.argv
    out_dir = os.path.dirname(__file__)
    with Range() as rng:
        print(f"range up on {rng.base}  ({len(PLANTED)} planted, {len(DECOYS)} decoys)")
        t0 = time.time()
        surface = do_recon(rng.base)
        print(f"recon: {time.time() - t0:.1f}s  "
              f"endpoints={len(surface['endpoints'])} hosts={len(surface['hosts'])} "
              f"graphql={len(surface['graphql'])} forms={len(surface['forms'])} "
              f"routes={len(surface['routes'])}")
        for e in surface["endpoints"]:
            print(f"   [{e['source']:8}] {e['method']:6} {e['path']}")
        with open(os.path.join(out_dir, "last_surface.json"), "w") as fh:
            json.dump(surface, fh, indent=2)

        if recon_only:
            # What the SURFACE alone covers -- the ceiling without any reasoning.
            eps = R.entrypoints_from_surface(surface, limit=60)
            print(f"\nsurface-only entrypoints ({len(eps)}):")
            for e in eps[:40]:
                print("   ", e)
            cov = sum(1 for p in PLANTED
                      if any(_norm_path(e) == _norm_path(p["path"])
                             or _stem(e) == _stem(p["path"]) for e in eps))
            print(f"\nplanted LOCATIONS reachable from surface alone: {cov}/{len(PLANTED)}")
            print("(location coverage only -- recon does not judge, so this is the input "
                  "the planner reasons over, not a finding count)")
            return 0

        print("\ncalling the real engine for a plan (xhigh; this takes a while)...")
        t1 = time.time()
        try:
            sess = make_real_session()
        except Exception as exc:
            print(f"!! could not build a session: {exc}")
            return 2
        out = asyncio.run(T.triage(
            surface, session=sess, cwd=os.path.abspath(out_dir),
            target_name=rng.base,
            scope_note=f"Authorized hosts ONLY: 127.0.0.1. This is a local range the "
                       f"operator owns. A sibling mobile host is simulated with the "
                       f"request header X-Range-Host: m.range (the browser can send it "
                       f"via a header variant), because a loopback server cannot own two "
                       f"real hostnames. Session cookie name: range_session.",
            identities=["anon", "session"],
        ))
        print(f"engine: {time.time() - t1:.1f}s  ok={out.get('ok')} "
              f"hypotheses={len(out.get('plan') or [])} err={out.get('error', '')[:160]}")
        with open(os.path.join(out_dir, "last_plan.json"), "w") as fh:
            json.dump({"plan": out.get("plan"), "raw": out.get("text", "")[:40000]}, fh, indent=2)
        with open(os.path.join(out_dir, "last_brief.txt"), "w") as fh:
            fh.write(out.get("brief", ""))

        plan = out.get("plan") or []
        if not plan:
            print("\nno plan parsed. raw reply head:")
            print((out.get("text") or "")[:1500])
            return 3

        print("\n--- PLAN ---")
        for i, h in enumerate(plan, 1):
            print(f"{i}. [{h.get('confidence')}] {h.get('target')}")
            print(f"   mech: {h.get('mechanism', '')[:220]}")
            print(f"   vary: {h.get('vary', '')[:120]}")
            print(f"   inst: {h.get('instrument', '')[:140]}")

        s = score(plan)
        print("\n================ SCORE ================")
        print(f"hypotheses: {s['hypotheses']}   recall: {s['recall']}   precision: {s['precision']}")
        print(f"\nFOUND ({len(s['found'])}/{s['planted']}):")
        for f in s["found"]:
            print(f"  + {f['id']:18} [{f['class']}]  {f['target']}")
        if s["located_only"]:
            print(f"\nLOCATED BUT MECHANISM WRONG ({len(s['located_only'])}):")
            for f in s["located_only"]:
                print(f"  ~ {f['id']:18} {f['target']}  -- {f['mechanism'][:110]}")
        if s["missed"]:
            print(f"\nMISSED ({len(s['missed'])}):")
            for f in s["missed"]:
                print(f"  - {f['id']:18} [{f['class']}] {f['path']}  ({f['insight'][:80]})")
        if s["false_positives"]:
            print(f"\nFALSE POSITIVES on decoys ({len(s['false_positives'])}):")
            for f in s["false_positives"]:
                print(f"  ! {f['id']:18} {f['target']}  (safe because: {f['why_safe']})")
        if s["unscored_targets"]:
            print(f"\nOTHER TARGETS PROPOSED ({len(s['unscored_targets'])}) "
                  f"- neither planted nor decoy:")
            for t in s["unscored_targets"][:15]:
                print(f"  ? {t}")
        with open(os.path.join(out_dir, "last_score.json"), "w") as fh:
            json.dump(s, fh, indent=2)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
