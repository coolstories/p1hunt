"""Terminal observability UI + control plane (spec §11).

Tee everything -> one append-only log; the UI subscribes for a live, complete view. You see
each agent — Parent A, every Child B, the ephemeral Child C, the Falsifier — and *what each
is saying* (Claude's reasoning), color-coded by agent, plus the live blackboard (scope,
plan, hypotheses by state, artifacts, findings). Per-agent transcripts are also persisted so
you can read back exactly what each agent said. The operator can tap any addressable agent
and inject directives without halting the swarm.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from typing import TextIO

from ..models import ControlDirective, Event, HypState
from ..orchestrator.blackboard import Blackboard
from ..orchestrator.bus import MessageBus
from ..orchestrator.event_log import EventLog

try:
    _COLOR = sys.stdout.isatty()
except Exception:  # pragma: no cover
    _COLOR = False

_AGENT_COLORS = ["36", "34", "32", "92", "94", "96"]  # cycled for child_b agents


def _paint(text: str, code: str) -> str:
    if not _COLOR or not code:
        return text
    return f"\033[{code}m{text}\033[0m"


def _agent_color(agent: str) -> str:
    if agent == "parent_a":
        return "35;1"
    if agent.startswith("falsifier"):
        return "33"
    if agent == "scopeguard":
        return "31"
    if agent in ("blackboard", "orchestrator", "operator"):
        return "90"
    if agent.startswith("child_b"):
        base = agent.split(".")[0]
        try:
            idx = int("".join(c for c in base if c.isdigit()) or "0")
        except ValueError:
            idx = 0
        return _AGENT_COLORS[idx % len(_AGENT_COLORS)]
    return "0"


def format_event(event: Event) -> str:
    agent, kind, d = event.agent, event.kind, event.data
    color = _agent_color(agent)
    tag = _paint(f"{agent:>14}", color)

    if kind == "thinking":
        return f"{tag} {_paint('▸', color)} {d.get('text','')}"
    if kind == "tool_call":
        return f"{tag} {_paint('·tool', '90')} {d.get('tool','')} {str(d.get('target',''))[:90]}"
    if kind == "guard_decision":
        ok = d.get("allow")
        verdict = _paint("ALLOW", "32") if ok else _paint("DENY", "31;1")
        return f"{_paint('    scopeguard','31')} {verdict} {d.get('tool','')} -> {str(d.get('target',''))[:60]} :: {d.get('reason','')}"
    if kind == "reframe":
        return f"{tag} {_paint('↻ REFRAME', '36;1')} {d.get('reason') or d.get('frame','')}"
    if kind == "finding":
        if d.get("event") == "critical_confirmed":
            return _paint(f"\n{'='*8} CRITICAL CONFIRMED x{d.get('count',1)} {'='*8}", "32;1")
        return _paint(f"{tag} ★ FINDING {d.get('title','')} [{d.get('severity','')}]", "32;1")
    if kind == "message":
        return f"{tag} {_message_body(agent, d)}"
    if kind == "bb_write":
        return f"{tag} {_paint('blackboard', '90')} {_bb_body(d)}"
    if kind == "lifecycle":
        return f"{tag} {_paint('·', '90')} {_kv(d)}"
    return f"{tag} {kind} {_kv(d)}"


def _message_body(agent: str, d: dict) -> str:
    if d.get("kind") == "assign":
        inv = d.get("investigate") or []
        extra = f"  · investigate: {inv[0]}" if inv else ""
        return _paint(f"⇒ {d.get('to','')}  ASSIGN [{d.get('lens','')}]{extra}", "35")
    if d.get("phase") == "scoping":
        return _paint("🔬 SCOPING — cold reconnaissance of the target (no prior knowledge)", "36;1")
    if d.get("phase") == "scoped":
        return _paint(f"derived {d.get('tracks','?')} tracks. critical here = {d.get('critical_means','')}", "36")
    if "verdict" in d:
        mark = "✓ REAL" if d["verdict"] == "real" else "✗ refuted"
        c = "32" if d["verdict"] == "real" else "33"
        return _paint(f"⚖ {mark}: {d.get('title','')} — {d.get('reason','')}", c)
    if d.get("phase") == "dispatch":
        assignment = d.get("assignment", {})
        rows = "; ".join(f"{ln}→[{', '.join(fl)}]" for ln, fl in assignment.items())
        return _paint(f"⇒ DISPATCH {d.get('files_ranked','?')} ranked files across agents: {rows}", "35")
    if d.get("phase") == "round":
        return _paint(f"── round {d.get('round')} ({d.get('lenses','?')} lenses) ──", "1")
    if d.get("phase") == "round_summary":
        return _paint(f"   round {d.get('round')} summary: criticals so far={d.get('criticals_total',0)}, "
                      f"candidates={d.get('candidates_total',0)} — continuing (find-all)", "90")
    if d.get("phase") == "hunt":
        return _paint(f"🔎 hunting {d.get('lens','')} (depth {d.get('depth','')})", "0")
    if d.get("phase") == "derivation":
        return _paint(f"deriving plan for {d.get('program','')}", "0")
    return _kv(d)


def _bb_body(d: dict) -> str:
    what = d.get("what", "")
    if what == "hypothesis":
        return f"+hypothesis {d.get('id','')}: {str(d.get('claim',''))[:80]}"
    if what == "hyp_state":
        return f"hypothesis {d.get('id','')} -> {d.get('state','')}"
    if what == "plan":
        return f"plan: {d.get('target_class','')} tools={d.get('toolset','')}"
    if what == "artifact":
        return f"+artifact {d.get('id','')} reproduced={d.get('reproduced')}"
    return _kv(d)


def _kv(d: dict) -> str:
    return ", ".join(f"{k}={str(v)[:80]}" for k, v in d.items() if k not in ("directive", "text"))


class LiveDashboard:
    """Stream every event to the operator; print a blackboard panel on round boundaries."""

    def __init__(self, event_log: EventLog, blackboard: Blackboard | None = None, out: TextIO | None = None) -> None:
        self.event_log = event_log
        self.bb = blackboard
        self.out = out or sys.stdout
        self._unsub = event_log.subscribe(self._on_event)

    def _on_event(self, event: Event) -> None:
        print(format_event(event), file=self.out, flush=True)
        if self.bb is not None and event.kind == "reframe":
            print(render_blackboard(self.bb), file=self.out, flush=True)

    def close(self) -> None:
        self._unsub()


class TranscriptWriter:
    """Persist each agent's transcript (what it said + did) to notes/<agent>.log (§11)."""

    def __init__(self, event_log: EventLog, notes_dir: str | Path) -> None:
        self.dir = Path(notes_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._unsub = event_log.subscribe(self._on_event)

    def _on_event(self, event: Event) -> None:
        if event.kind not in ("thinking", "message", "tool_call", "reframe", "finding"):
            return
        agent = event.agent.split(".")[0] or "system"
        line = format_event(event)
        # strip ANSI for the file
        import re

        clean = re.sub(r"\033\[[0-9;]*m", "", line)
        with (self.dir / f"{agent}.log").open("a", encoding="utf-8") as fh:
            fh.write(clean + "\n")

    def close(self) -> None:
        self._unsub()


def render_blackboard(bb: Blackboard) -> str:
    states = Counter(h.state for h in bb.hypotheses.values())
    parts = [_paint("  ┌─ blackboard ", "90")]
    if bb.plan is not None:
        parts.append(f"  │ plan: {bb.plan.target_class.value} | tools: {', '.join(bb.plan.toolset)}")
    parts.append(
        "  │ hypotheses: "
        + " ".join(f"{s.value}={states.get(s,0)}" for s in HypState)
        + f" | artifacts={len(bb.artifacts)}"
    )
    if bb.findings:
        parts.append("  │ findings:")
        for f in bb.findings.values():
            parts.append(_paint(f"  │   ★ [{f.severity}] {f.title} ({f.id})", "32"))
    else:
        parts.append("  │ findings: none confirmed yet")
    parts.append(_paint("  └─", "90"))
    return "\n".join(parts)


def render_snapshot(event_log: EventLog, blackboard: Blackboard, bus: MessageBus) -> str:
    lines: list[str] = ["", "=== P1Hunt snapshot ==="]
    agents = bus.registry()
    lines.append(f"Agents ({len(agents)}): " + ", ".join(a.name for a in agents))
    if blackboard.plan is not None:
        p = blackboard.plan
        lines += [
            f"Target class: {p.target_class.value}",
            f"Toolset: {', '.join(p.toolset)}",
            f"Surfaces ranked: {len(p.surface_ranking)}",
            f"Impact definition: {p.impact_definition}",
        ]
    states = Counter(h.state for h in blackboard.hypotheses.values())
    lines.append(
        "Hypotheses: " + ", ".join(f"{s.value}={states.get(s,0)}" for s in HypState)
        + f" (total {len(blackboard.hypotheses)})"
    )
    guard = [e for e in event_log.events if e.kind == "guard_decision"]
    denied = sum(1 for e in guard if not e.data.get("allow"))
    lines.append(f"Guard decisions: {len(guard)} ({denied} denied)")
    lines.append(f"Findings: {len(blackboard.findings)}")
    for f in blackboard.findings.values():
        lines.append(f"  - [{f.severity}] {f.title} ({f.id})")
    lines.append("=======================")
    return "\n".join(lines)


# --- control plane (§11) --------------------------------------------------
def inject(blackboard: Blackboard, bus: MessageBus, target_agent: str, kind: str, payload: str = "") -> bool:
    if target_agent != "*" and target_agent not in bus.addressable_agents():
        return False
    blackboard.push_directive(ControlDirective(target_agent=target_agent, kind=kind, payload=payload))
    return True
