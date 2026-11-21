"""Score the EXECUTION half of the hunt against the range's ground truth.

WHAT THIS MEASURES, AND WHY IT IS A DIFFERENT NUMBER
----------------------------------------------------
run_range.py scores the PLAN: given the live surface, does the pipeline propose the right
things to look at. That number was 1.000 recall black-box, and it is worth exactly what it
says and no more -- "it correctly identifies what to examine".

This scores what happens next: hunter -> harness -> DETERMINISTIC RUNNER -> verdict. A
planted defect only counts here when a real toolchain ran a real harness against the live
range and the runner -- not a model's say-so -- decided the bug was demonstrated. That is
the number that justifies a claim like "it will find bad stuff on a program you hand it",
because it is the only one that involves a proof.

It reads the engagement folder the product itself writes (events.jsonl, findings.json,
live_findings.json, report_artifacts/, falsified.jsonl). Nothing here instruments the
hunt: if the scorer were wired into the pipeline it would be scoring itself.

THE OUTCOME LADDER, STRONGEST FIRST
-----------------------------------
For each planted defect:
  CONFIRMED         a runner verdict of reproduced on a claim at its location, with the
                    right mechanism, not held by the attribution/impact gate. The only
                    outcome that counts as "found".
  PROVEN_GATED      the harness ran and reproduced, but a promotion gate held it (missing
                    target attribution, no concrete loss). Honest middle: the mechanical
                    proof exists, the severity claim does not.
  CLAIMED_UNPROVEN  a claim names it with the right mechanism; no reproduced verdict.
  LOCATED           a claim names its location with the wrong mechanism.
  ATTEMPTED         the pipeline touched it (ledger attempt / candidate status) and got
                    no verdict.
  FALSELY_REFUTED   the ledger ruled it out. The worst outcome for a real defect, worse
                    than missing it, because the ledger will not re-issue it.
  MISSED            never named.

For each decoy (correct code that looks defective):
  REFUTED           ledger-falsified. The ideal: tested, ruled out, retired cheaply.
  UNTOUCHED         never named. Also fine.
  CLAIMED           reported as a finding without proof -- triage cost.
  FALSE_CONFIRM     a runner verdict of reproduced on a decoy. This one is a correctness
                    emergency, not a precision complaint: it means a harness "proved"
                    something that is not there, so every other CONFIRMED is suspect.
  LEFT_OPEN         touched, never resolved either way -- the circling the ledger exists
                    to prevent.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from truth import (  # noqa: E402
    DECOYS, PLANTED, mechanism_matches, mentions_path, paths_match,
)

# Ladder positions, so a claim that reaches several stages is reported at its best one.
_RANK = {
    "MISSED": 0, "FALSELY_REFUTED": 1, "ATTEMPTED": 2, "LOCATED": 3,
    "CLAIMED_UNPROVEN": 4, "PROVEN_GATED": 5, "CONFIRMED": 6,
}


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _read_jsonl(path: Path) -> list[dict]:
    """Tolerate a half-written final line: a run killed mid-append must not lose history."""
    out: list[dict] = []
    try:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return out
    return out


def _claim_text(doc: dict) -> str:
    """Everything the claim says about the mechanism, for mechanism_matches.

    Deliberately NOT the title alone. A hunter's title is a headline ("IDOR on accounts")
    and the mechanism often only appears in root_cause or evidence, so scoring on the
    title would under-report real finds.
    """
    parts = [
        doc.get("title"), doc.get("root_cause"), doc.get("counterfactual"),
        doc.get("reproduction"), doc.get("evidence"), doc.get("remediation"),
        doc.get("target_code_attribution"),
    ]
    poc = doc.get("poc")
    if isinstance(poc, dict):
        parts += [poc.get("description"), poc.get("path")]
    elif isinstance(poc, str):
        parts.append(poc)
    return " ".join(str(p) for p in parts if p)


def _claim_location(doc: dict) -> str:
    return str(doc.get("location") or doc.get("file") or doc.get("endpoint")
               or doc.get("url") or "")


def _runner_verdict(doc: dict) -> tuple[str, str]:
    """(verdict, blocked_by) from the pipeline history a finding doc carries.

    The runner stage is the judge. Scanning the whole history rather than only the current
    stage matters because a candidate that reproduced and then moved on to the debate
    panel shows stage="debate" at the top; the proof still happened.
    """
    pipe = doc.get("pipeline") if isinstance(doc.get("pipeline"), dict) else {}
    verdict, blocked = "", ""
    history = pipe.get("history") if isinstance(pipe.get("history"), list) else []
    for entry in history:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("stage")) == "runner":
            verdict = str(entry.get("status") or "")
            blocked = str(entry.get("blocked_by") or "")
    if not verdict and str(pipe.get("stage")) == "runner":
        verdict = str(pipe.get("status") or "")
        blocked = str(pipe.get("blocked_by") or "")
    return verdict, blocked


def collect_claims(eng: Path) -> list[dict]:
    """Every distinct thing the hunt claimed, from every artifact that records one.

    Several sources on purpose. findings.json is written at round boundaries, so a run
    stopped mid-round has claims only in live_findings.json and the event stream; and the
    per-finding packs under report_artifacts/ survive a findings.json rewrite. Deduped by
    dedup_key, then by location+title.
    """
    claims: dict[str, dict] = {}

    def _add(doc: dict, tier: str) -> None:
        if not isinstance(doc, dict):
            return
        loc = _claim_location(doc)
        title = str(doc.get("title") or "").strip()
        if not loc and not title:
            return
        key = str(doc.get("dedup_key") or "").strip() or f"{loc}|{title.lower()[:60]}"
        prior = claims.get(key)
        rec = {
            "key": key, "title": title, "location": loc, "tier": tier,
            "text": _claim_text(doc), "severity": str(doc.get("severity") or ""),
        }
        rec["runner_verdict"], rec["blocked_by"] = _runner_verdict(doc)
        if prior is None:
            claims[key] = rec
            return
        # Merge: keep the strongest tier and any verdict either copy carries. A doc read
        # from live_findings.json may predate the runner stage that findings.json records.
        if _TIER_RANK.get(tier, 0) > _TIER_RANK.get(prior["tier"], 0):
            prior["tier"] = tier
        if rec["runner_verdict"] and not prior["runner_verdict"]:
            prior["runner_verdict"] = rec["runner_verdict"]
            prior["blocked_by"] = rec["blocked_by"]
        if len(rec["text"]) > len(prior["text"]):
            prior["text"] = rec["text"]
        if not prior["location"]:
            prior["location"] = loc

    findings = _read_json(eng / "findings.json")
    for tier, field in (("confirmed_critical", "confirmed_criticals"),
                        ("needs_human_review", "needs_human_review"),
                        ("candidate", "candidates")):
        for doc in findings.get(field) or []:
            _add(doc, tier)

    for doc in (_read_json(eng / "live_findings.json").get("candidates") or []):
        _add(doc, "candidate")

    pack_dir = eng / "report_artifacts"
    if pack_dir.is_dir():
        for sub in sorted(pack_dir.iterdir()):
            if sub.is_dir():
                _add(_read_json(sub / "finding.json"), "candidate")

    # The event stream carries findings posted mid-session, which is the only record if
    # the run died before a round boundary.
    for ev in _read_jsonl(eng / "events.jsonl"):
        data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
        if ev.get("kind") == "finding_reported":
            doc = data.get("finding") if isinstance(data.get("finding"), dict) else data
            _add(doc, "candidate")

    # Overlay runner verdicts from the status stream, by dedup_key. candidate_status does
    # not carry a location, which is why it is an overlay on the docs above and not a
    # claim source of its own.
    by_key = {c["key"]: c for c in claims.values()}
    for ev in _read_jsonl(eng / "events.jsonl"):
        data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
        if data.get("event") != "candidate_status" or data.get("stage") != "runner":
            continue
        tgt = by_key.get(str(data.get("dedup_key") or ""))
        if tgt is None:
            # Fall back to the title, which the hunter usually writes with the endpoint in
            # it. Only used when the dedup_key is unknown to the docs.
            title = str(data.get("title") or "").strip().lower()
            tgt = next((c for c in claims.values()
                        if title and c["title"].strip().lower() == title), None)
        if tgt is None:
            continue
        status = str(data.get("status") or "")
        if status == "reproduced" or not tgt["runner_verdict"]:
            tgt["runner_verdict"] = status
            tgt["blocked_by"] = str(data.get("blocked_by") or "")
    return list(claims.values())


_TIER_RANK = {"candidate": 0, "needs_human_review": 1, "confirmed_critical": 2}


def collect_runs(eng: Path) -> dict:
    """Aggregate reproduction activity, as a cross-check on the per-claim verdicts.

    These events (poc_prover / "reproduction") carry no title, so they cannot be
    attributed to a defect -- they only answer "did the toolchain ever actually run".
    They exist in this report because a confirmed count of zero means something very
    different when no harness ever executed than when twenty ran and none reproduced.
    """
    ran = reproduced = 0
    runners: dict[str, int] = {}
    materialized = repairs = 0
    # WHY A ZERO HAPPENED, not just that it did. A score of 0/9 means something completely
    # different when every session was refused by the provider's safety classifier than
    # when the hunt searched hard and found nothing -- and the first run of this harness
    # was exactly the former. Without these counts the report was a confident zero with no
    # explanation, which is the most misleading artifact this whole exercise can produce.
    refused: dict[str, int] = {}
    toolchain_broken = ""
    agents_seen: set[str] = set()
    for ev in _read_jsonl(eng / "events.jsonl"):
        data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
        event = data.get("event")
        agent = str(ev.get("agent") or "?")
        if event == "reproduction":
            ran += 1 if data.get("ran") else 0
            reproduced += 1 if data.get("reproduced") else 0
            r = str(data.get("runner") or "?")
            runners[r] = runners.get(r, 0) + 1
        elif event == "poc_retry":
            repairs += 1
        elif data.get("verdict") == "harness materialized":
            materialized += 1
        elif event in ("error", "codex_error", "live_plan_refused", "hunter_roles_refused"):
            blob = " ".join(str(data.get(k) or "") for k in
                            ("detail", "error", "impact", "reason")).lower()
            if "flagged for possible cybersecurity risk" in blob or "refus" in blob:
                refused[agent] = refused.get(agent, 0) + 1
                agents_seen.add(agent)
        elif event == "toolchain_broken":
            toolchain_broken = str(data.get("detail") or "")[:200]
    return {"harness_runs_executed": ran, "runs_reporting_reproduced": reproduced,
            "harnesses_materialized": materialized, "repair_attempts": repairs,
            "by_runner": runners,
            "sessions_refused": sum(refused.values()),
            "agents_refused": sorted(agents_seen),
            "toolchain_broken": toolchain_broken}


def collect_ledger(eng: Path) -> list[dict]:
    """The falsification ledger: what was tested and ruled out.

    Read straight off disk rather than through FalsificationLedger so the scorer stays a
    reader of artifacts and cannot be affected by a change in the ledger's in-memory
    behaviour.
    """
    return _read_jsonl(eng / "falsified.jsonl")


def _ledger_hits(records: list[dict], path: str) -> dict[str, list[str]]:
    """Ledger outcomes mentioning a location, grouped by outcome.

    A ledger line is prose, so it is matched through the same strict path-token extractor
    the claim titles use -- one definition, so a loosening in one place cannot quietly
    disagree with the other.
    """
    out: dict[str, list[str]] = {}
    for rec in records:
        text = " ".join(str(rec.get(k) or "") for k in
                        ("hypothesis", "mechanism", "family", "note", "evidence"))
        if not mentions_path(text, path):
            continue
        out.setdefault(str(rec.get("outcome") or "?"), []).append(text[:200])
    return out


def score_execution(eng_dir: str | Path) -> dict:
    """Score one engagement folder. Pure reader; never raises on a partial run."""
    eng = Path(eng_dir)
    claims = collect_claims(eng)
    ledger = collect_ledger(eng)
    runs = collect_runs(eng)

    planted_out: list[dict] = []
    for p in PLANTED:
        best = {"id": p["id"], "class": p["class"], "outcome": "MISSED",
                "claim": "", "location": "", "detail": ""}
        for c in claims:
            # The claim's own location field is the evidence. The title is a FALLBACK and
            # only its path-like tokens count -- see truth.locations_in for the bug that
            # taught me not to match on bare words.
            if not (paths_match(c["location"], p["path"])
                    or mentions_path(c["title"], p["path"])):
                continue
            right_mech = mechanism_matches(c["text"], p)
            verdict = c["runner_verdict"]
            if verdict == "reproduced" and right_mech:
                outcome = "PROVEN_GATED" if c["blocked_by"] else "CONFIRMED"
            elif right_mech:
                outcome = "CLAIMED_UNPROVEN"
            else:
                outcome = "LOCATED"
            if _RANK[outcome] > _RANK[best["outcome"]]:
                best = {"id": p["id"], "class": p["class"], "outcome": outcome,
                        "claim": c["title"][:140], "location": c["location"][:120],
                        "detail": (c["blocked_by"] or c["runner_verdict"] or "")[:160],
                        "tier": c["tier"]}
        hits = _ledger_hits(ledger, p["path"])
        if best["outcome"] == "MISSED" and hits:
            # A real defect the ledger ruled out is worse than one never looked at: the
            # ledger is designed not to re-issue it, so the run has closed the door.
            if "falsified" in hits:
                best["outcome"] = "FALSELY_REFUTED"
                best["detail"] = hits["falsified"][0]
            else:
                best["outcome"] = "ATTEMPTED"
                best["detail"] = next(iter(hits.values()))[0]
        best["ledger"] = {k: len(v) for k, v in hits.items()}
        planted_out.append(best)

    decoy_out: list[dict] = []
    for d in DECOYS:
        rec = {"id": d["id"], "why_safe": d["why"], "outcome": "UNTOUCHED",
               "claim": "", "detail": ""}
        # No mechanism check here on purpose: a decoy has no defect to describe, so any
        # claim naming its location is a false positive on it. That makes the location
        # test the ONLY gate, which is exactly why it has to be strict.
        matched = [c for c in claims
                   if paths_match(c["location"], d["path"])
                   or mentions_path(c["title"], d["path"])]
        hits = _ledger_hits(ledger, d["path"])
        if any(c["runner_verdict"] == "reproduced" for c in matched):
            c = next(c for c in matched if c["runner_verdict"] == "reproduced")
            rec.update(outcome="FALSE_CONFIRM", claim=c["title"][:140],
                       detail="a harness reported this NON-defect as reproduced")
        elif "falsified" in hits:
            rec.update(outcome="REFUTED", detail=hits["falsified"][0])
        elif matched:
            rec.update(outcome="CLAIMED", claim=matched[0]["title"][:140],
                       detail=matched[0]["runner_verdict"] or "no runner verdict")
        elif hits:
            rec.update(outcome="LEFT_OPEN", detail=next(iter(hits.values()))[0])
        rec["ledger"] = {k: len(v) for k, v in hits.items()}
        decoy_out.append(rec)

    def _count(items: list[dict], *outcomes: str) -> int:
        return sum(1 for i in items if i["outcome"] in outcomes)

    confirmed = _count(planted_out, "CONFIRMED")
    # The headline. Deliberately NOT counting PROVEN_GATED: a proof a gate refused to
    # promote is real work, but it is not a finding you can hand anybody.
    return {
        "planted": len(PLANTED), "decoys": len(DECOYS), "claims": len(claims),
        "planted_outcomes": planted_out,
        "decoy_outcomes": decoy_out,
        "runs": runs,
        "ledger_records": len(ledger),
        "confirmed": confirmed,
        "exec_recall": round(confirmed / max(1, len(PLANTED)), 3),
        "proven_gated": _count(planted_out, "PROVEN_GATED"),
        "claimed_unproven": _count(planted_out, "CLAIMED_UNPROVEN"),
        "located_only": _count(planted_out, "LOCATED"),
        "attempted": _count(planted_out, "ATTEMPTED"),
        "falsely_refuted": _count(planted_out, "FALSELY_REFUTED"),
        "missed": _count(planted_out, "MISSED"),
        "decoys_refuted": _count(decoy_out, "REFUTED"),
        "decoys_untouched": _count(decoy_out, "UNTOUCHED"),
        "decoys_claimed": _count(decoy_out, "CLAIMED"),
        "decoys_left_open": _count(decoy_out, "LEFT_OPEN"),
        "decoy_false_confirms": _count(decoy_out, "FALSE_CONFIRM"),
        # Is this score a measurement at all? See render().
        "measurement_valid": not (runs.get("sessions_refused") or runs.get("toolchain_broken")),
    }


def render(s: dict) -> str:
    """The report. Leads with the number that is hardest to flatter."""
    lines = []
    lines.append("=============== EXECUTION SCORE ===============")
    r0 = s.get("runs") or {}
    # LEAD WITH THE INVALIDATION. A reader who sees "0/9" first has already drawn a
    # conclusion about the hunt by the time they reach the explanation.
    if r0.get("sessions_refused"):
        lines.append(
            f"!! THIS IS NOT A CAPABILITY MEASUREMENT. {r0['sessions_refused']} session(s) "
            f"were REFUSED by the provider's safety classifier "
            f"({', '.join(r0.get('agents_refused') or []) or 'unknown agents'}).\n"
            f"   A refused session returns no findings, which is indistinguishable from a "
            f"clean result. The score below\n   measures the engine's willingness to do the "
            f"work, not the pipeline's ability to find bugs.")
    if r0.get("toolchain_broken"):
        lines.append(
            f"!! THIS IS NOT A CAPABILITY MEASUREMENT. The harness toolchain was broken: "
            f"{r0['toolchain_broken']}\n   No harness could execute, so the confirmed count "
            f"was capped at zero before the hunt began.")
    lines.append(f"CONFIRMED (reproduced by a runner, ungated): {s['confirmed']}/{s['planted']}"
                 f"   exec_recall={s['exec_recall']}")
    if s["decoy_false_confirms"]:
        lines.append(f"!! {s['decoy_false_confirms']} DECOY FALSE CONFIRM(S) -- a harness 'proved' a "
                     f"non-defect. Every CONFIRMED above is suspect until this is explained.")
    r = s["runs"]
    lines.append(f"\nmeasurement valid: {s.get('measurement_valid')}")
    lines.append(f"toolchain activity: {r['harnesses_materialized']} harnesses materialized, "
                 f"{r['harness_runs_executed']} executed, {r['runs_reporting_reproduced']} reproduced, "
                 f"{r['repair_attempts']} repair attempts  {r['by_runner'] or ''}")
    lines.append(f"claims recorded: {s['claims']}   ledger records: {s['ledger_records']}")
    lines.append("\nplanted defects:")
    for p in s["planted_outcomes"]:
        extra = f"  [{p['detail']}]" if p["detail"] else ""
        lines.append(f"  {p['outcome']:17} {p['id']:16} {p['location'][:60]}{extra}")
    lines.append("\ndecoys (correct code that looks defective):")
    for d in s["decoy_outcomes"]:
        extra = f"  [{d['detail'][:70]}]" if d["detail"] else ""
        lines.append(f"  {d['outcome']:17} {d['id']:16}{extra}")
    lines.append("\nladder: CONFIRMED > PROVEN_GATED > CLAIMED_UNPROVEN > LOCATED > ATTEMPTED "
                 "> MISSED; FALSELY_REFUTED is worse than MISSED.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if not argv:
        print("usage: python3 bench/exec_score.py <engagement-dir>")
        return 2
    s = score_execution(argv[0])
    print(render(s))
    out = Path(argv[0]) / "exec_score.json"
    try:
        out.write_text(json.dumps(s, indent=2), encoding="utf-8")
        print(f"\nwritten: {out}")
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
