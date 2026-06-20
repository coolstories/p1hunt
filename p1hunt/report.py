"""Report package generator (spec §2.9) + human-review checklist (§15.9).

Produces a concise, reproducible, least-data report with a safe-harbor attestation. The
report is a DRAFT — no submission happens without a human approving scope, evidence,
impact, wording, and disclosure channel (§16).
"""

from __future__ import annotations

import time

from .agents.parent_a import HuntResult
from .models import Scope


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def render_report(scope: Scope, result: HuntResult) -> str:
    crit = [f for f in result.findings if f.severity == "critical"]
    # A finding is CONFIRMED only when a deterministic runner reproduced it (poc.reproduced).
    reproduced_crit = [f for f in crit if getattr(f.poc, "reproduced", False)]
    # Executive verdict — the single line a reviewer reads first.
    if reproduced_crit:
        verdict = (f"✅ {len(reproduced_crit)} critical finding(s) CONFIRMED — deterministically "
                   "REPRODUCED by a class runner. Ready for human review.")
    elif crit:
        verdict = (f"⚠ {len(crit)} critical finding(s) recorded but NOT deterministically reproduced "
                   "— treat as CANDIDATES; human confirmation required before any action.")
    else:
        verdict = (f"⏳ No critical reproduced across {result.rounds_run} round(s); "
                   f"{len(result.candidates)} candidate(s) surfaced for review (none reproduced).")
    lines = [
        "# P1Hunt Report (DRAFT — human review required)",
        "",
        f"> **Verdict:** {verdict}",
        "",
        f"- Program: {scope.program} ({scope.platform})",
        f"- Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"- Detector: {result.brain} swarm (Parent A + Child B/C + Falsifier)",
        f"- Target class: {result.plan.target_class.value}",
        f"- Toolset (derived): {', '.join(result.plan.toolset)}",
        f"- Engagement status: {result.status.value}",
        f"- Rounds run: {result.rounds_run} | reframes: {result.reframes}"
        + (" | demoted to warm pool" if result.demoted_to_warm_pool else ""),
        f"- Candidates surfaced: {len(result.candidates)} | confirmed critical: {len(crit)}"
        + f" ({len(reproduced_crit)} deterministically reproduced)",
        "",
        "## Safe-harbor attestation",
        "",
        result.attestation,
        "- No production writes, DoS, credential use, persistence, lateral movement, or third-party data access.",
        "- Only findings DETERMINISTICALLY REPRODUCED by a class runner are promoted to confirmed; "
        "the candidates listed below are NOT reproduced and must not be reported as confirmed.",
        "",
    ]

    if not result.findings:
        lines += [
            "## No confirmed finding",
            "",
            "The hunt did not reproduce a critical candidate in the rounds run. The swarm did "
            "not self-terminate — it reframed through the ranked surfaces and "
            + ("demoted to the warm pool" if result.demoted_to_warm_pool else "remained active")
            + ", and will re-escalate on novelty. Nothing was promoted without a reproduced artifact.",
            "",
        ]
    else:
        lines += ["## Confirmed findings (deterministically reproduced)", ""]
        for i, f in enumerate(result.findings, start=1):
            vtag = ("PoC-REPRODUCED (deterministic runner)" if getattr(f.poc, "reproduced", False)
                    else "NOT reproduced — candidate, needs human confirmation")
            lines += [
                f"### {i}. {f.title} [{f.severity}] — {vtag}",
                "",
                f"- Finding ID: `{f.id}` (hypothesis `{f.hypothesis_id}`)",
                f"- Location / PoC: `{f.poc.path}` — {f.poc.description}",
                f"- Root cause: {f.root_cause}",
                f"- Counterfactual: {f.counterfactual}",
                f"- Severity rationale: {f.severity_rationale}",
                f"- Remediation: {f.remediation}",
                "",
            ]

    if result.candidates:
        # Dedup by location+title and sort strongest-first so reviewers triage top-down.
        seen: set[str] = set()
        uniq = []
        for c in result.candidates:
            key = f"{c.get('file','')}:{c.get('line','')}:{str(c.get('title','')).lower()[:40]}"
            if key in seen:
                continue
            seen.add(key)
            uniq.append(c)
        uniq.sort(key=lambda c: (_SEV_ORDER.get(str(c.get("severity", "")).lower(), 9),
                                 str(c.get("file", ""))))
        lines += [f"## Candidates — NOT reproduced ({len(uniq)}) — do NOT report as confirmed", ""]
        for c in uniq:
            sev = str(c.get("severity", "?")).lower()
            loc = f"{c.get('file','?')}:{c.get('line','?')}"
            mark = "★" if sev == "critical" else ("•" if sev == "high" else "·")
            lines.append(f"- {mark} [{sev}] {c.get('title','untitled')} — `{loc}` ({c.get('lens','')})")
            if c.get("root_cause"):
                lines.append(f"    - {str(c['root_cause'])[:300]}")
        lines.append("")

    lines += [
        "## Human-review checklist (§16 — required before any submission)",
        "",
        "- [ ] Authorization confirmed: program open, asset unambiguously in scope.",
        "- [ ] Every touched asset was in scope (see attestation).",
        "- [ ] Evidence is least-data; no third-party or unredacted sensitive data.",
        "- [ ] Severity matches the program taxonomy, led by the counterfactual.",
        "- [ ] Reproduction steps are safe and minimal.",
        "- [ ] Wording and disclosure channel are correct.",
        "",
    ]
    return "\n".join(lines)
