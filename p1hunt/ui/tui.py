"""Claude-Code-style terminal viewer for a hunt (spec §11).

Renders the engagement's event stream (events.jsonl) as a live, hierarchical transcript:
you see Parent A's reconnaissance, the exact instructions it hands each Child B (and B's
ephemeral Child C subtasks), each agent's reasoning and tool calls, the Falsifier's
verdicts, finding cards, and a live blackboard panel. Works live (``--follow`` tails the
file as the swarm runs) or as a replay of a finished engagement.
"""

from __future__ import annotations

import json
import sys
import textwrap
import time
from pathlib import Path
from typing import Iterator, TextIO

try:
    _COLOR = sys.stdout.isatty()
except Exception:  # pragma: no cover
    _COLOR = False

_PALETTE = ["36", "34", "32", "92", "94", "96"]
_WIDTH = 98


def _c(text: str, code: str) -> str:
    return text if (not _COLOR or not code) else f"\033[{code}m{text}\033[0m"


def _color_for(agent: str) -> str:
    base = agent.split(".")[0]
    if base == "parent_a":
        return "35;1"
    if base.startswith("falsifier"):
        return "33"
    if base in ("scopeguard",):
        return "31"
    if base in ("blackboard", "orchestrator", "operator"):
        return "90"
    if base.startswith("child_b"):
        idx = int("".join(ch for ch in base if ch.isdigit()) or "0")
        return _PALETTE[idx % len(_PALETTE)]
    return "0"


def _tag(agent: str) -> str:
    base = agent.split(".")[0]
    if base == "parent_a":
        label = "A"
    elif base.startswith("falsifier"):
        label = "F"
    elif base.startswith("child_b"):
        label = "B" + "".join(ch for ch in base if ch.isdigit())
    else:
        label = base[:3].upper()
    depth = "  " if "." in agent else ""  # child C indents under its parent
    return depth + _c(f"[{label}]", _color_for(agent))


def _wrap(text: str, indent: str) -> str:
    out = []
    for para in text.splitlines() or [text]:
        wrapped = textwrap.wrap(para, width=_WIDTH - len(indent)) or [""]
        out.extend(indent + ln for ln in wrapped)
    return "\n".join(out)


class _Board:
    """Accumulates blackboard state from bb_write/finding events for the panel."""

    def __init__(self) -> None:
        self.target = ""
        self.tools = ""
        self.hyp: dict[str, str] = {}
        self.findings: list[tuple[str, str]] = []

    def apply(self, e: dict) -> None:
        d = e.get("data", {})
        if e["kind"] == "bb_write":
            if d.get("what") == "plan":
                self.target = d.get("target_class", "")
                self.tools = ", ".join(d.get("toolset", []) or [])
            elif d.get("what") == "hypothesis":
                self.hyp[d.get("id", "")] = "CANDIDATE" if "CANDIDATE" in str(d) else "OPEN"
            elif d.get("what") == "hyp_state":
                self.hyp[d.get("id", "")] = d.get("state", "")
        elif e["kind"] == "finding" and d.get("id"):
            self.findings.append((d.get("severity", "?"), d.get("title", "")))

    def panel(self) -> str:
        from collections import Counter

        counts = Counter(self.hyp.values())
        line = _c("  ┌─ blackboard ────────────────────────────────────────────", "90")
        rows = [line]
        if self.target:
            rows.append(_c(f"  │ target: {self.target}   tools: {self.tools}", "90"))
        rows.append(_c("  │ hypotheses: " + "  ".join(f"{k}={v}" for k, v in counts.items()) or "  │ hypotheses: (none)", "90"))
        if self.findings:
            rows.append(_c("  │ findings:", "90"))
            for sev, title in self.findings:
                rows.append(_c(f"  │   ★ [{sev}] {title[:70]}", "32"))
        else:
            rows.append(_c("  │ findings: none yet", "90"))
        rows.append(_c("  └──────────────────────────────────────────────────────────", "90"))
        return "\n".join(rows)


def _render(e: dict, board: _Board, out: TextIO, live: bool = False) -> None:
    agent, kind, d = e["agent"], e["kind"], e.get("data", {})
    board.apply(e)
    p = lambda s: print(s, file=out, flush=True)  # noqa: E731

    # Live token stream: close an in-progress streamed line before any other event prints.
    if getattr(board, "_streaming", False) and kind not in ("stream", "stream_start"):
        out.write("\n")
        out.flush()
        board._streaming = False
    if kind == "stream_start":
        if live:
            out.write(f"\n{_tag(agent)} {_c('▸', _color_for(agent))} ")
            out.flush()
            board._streaming = True
        return
    if kind == "stream":
        if live:
            out.write(str(d.get("text", "")))
            out.flush()
            board._streaming = True
        return
    if kind == "thinking" and live:
        return  # already shown live via the token stream

    if kind == "message":
        if d.get("phase") == "scoping":
            p("\n" + _c("🔬 parent_a — cold reconnaissance (no prior knowledge of the target)", "36;1"))
        elif d.get("phase") == "scoped":
            p(_c(f"   derived {d.get('tracks','?')} tracks · critical here = {str(d.get('critical_means',''))[:120]}", "36"))
        elif d.get("kind") == "assign":
            # The instruction Parent A hands a Child B — show it as a card.
            p(f"\n{_tag('parent_a')} {_c('──▶', '35')} {_tag(d.get('to',''))}  «{d.get('lens','')}»")
            directive = d.get("directive")  # deterministic path: full directive prompt
            if directive:
                p(_wrap(str(directive), "      │ "))
            else:  # claude path: derived investigate + focus
                for q in (d.get("investigate") or [])[:6]:
                    p(_c(f"      │ • {q}", "0"))
                if d.get("focus"):
                    p(_c(f"      │ focus: {', '.join(d['focus'])}", "90"))
        elif d.get("phase") == "round":
            n = d.get("lenses") or d.get("depth") or "?"
            p("\n" + _c(f"════════════════════  ROUND {d.get('round')}  ({n} tracks)  ════════════════════", "1"))
        elif d.get("phase") == "round_summary":
            p(_c(f"   round {d.get('round')} summary — criticals: {d.get('criticals_total',0)}, "
                 f"candidates: {d.get('candidates_total',0)} (continuing)", "90"))
            p(board.panel())
        elif d.get("phase") == "hunt":
            p(f"{_tag(agent)} {_c('🔎 hunting', _color_for(agent))} {d.get('lens','')} (pass {d.get('depth','')})")
        elif "verdict" in d:
            v = d["verdict"]
            marks = {"real": _c("✓ REAL", "32;1"), "survives": _c("✓ REAL", "32;1"),
                     "refuted": _c("✗ refuted", "33"), "killed": _c("✗ refuted", "33"),
                     "unverified": _c("⚠ unverified", "33;1")}
            label = d.get("title") or d.get("hyp") or ""
            p(f"{_tag('falsifier')} {_c('⚖', '33')} {marks.get(v, v)}  {str(label)[:70]}")
            if d.get("reason"):
                p(_wrap(str(d["reason"]), "        "))
    elif kind == "thinking":
        p(f"{_tag(agent)} {_c('▸', _color_for(agent))}")
        p(_wrap(str(d.get("text", "")), "        "))
    elif kind == "tool_call":
        p(_c(f"        · {d.get('tool','')} {str(d.get('target',''))[:78]}", "90"))
    elif kind == "guard_decision":
        if not d.get("allow"):
            p(_c(f"        ⛔ DENY {d.get('tool','')} → {str(d.get('target',''))[:50]} :: {d.get('reason','')}", "31;1"))
    elif kind == "finding":
        if d.get("event") == "critical_confirmed":
            p("\n" + _c(f"  ★★★  CRITICAL CONFIRMED ×{d.get('count',1)}  ★★★", "32;1"))
        else:
            p("\n" + _c(f"  ★ FINDING [{d.get('severity','')}] {d.get('title','')}", "32;1"))
            p(board.panel())
    elif kind == "lifecycle":
        ev = d.get("event")
        if ev == "spawn":  # Child C subtask (deterministic path)
            p(f"{_tag(agent)} {_c('↳ spawned for', '90')} {str(d.get('path',''))[:70]}")
        elif ev in ("scope_fallback", "model_downgrade", "safety_event", "stop", "warm_pool_demotion", "cap_reached"):
            p(_c(f"   ⚙ {ev}: {d.get('reason') or d.get('detail','')}", "90"))


class LiveTui:
    """Subscribe to a running EventLog and render it live in the Claude-Code style."""

    def __init__(self, event_log, out: TextIO | None = None) -> None:
        self.board = _Board()
        self.out = out or sys.stdout
        self._unsub = event_log.subscribe(self._on)

    def _on(self, event) -> None:
        _render({"agent": event.agent, "kind": event.kind, "data": event.data}, self.board, self.out, live=True)

    def close(self) -> None:
        self._unsub()


def _read_events(path: Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def banner(program: str, out: TextIO) -> None:
    bar = "─" * (_WIDTH - 2)
    print(_c(f"╭{bar}╮", "36"), file=out)
    print(_c(f"│ {'P1HUNT — autonomous critical-bug swarm':<{_WIDTH-3}}│", "36;1"), file=out)
    print(_c(f"│ {program[:_WIDTH-4]:<{_WIDTH-3}}│", "36"), file=out)
    print(_c(f"╰{bar}╯", "36"), file=out)


def watch(path: str | Path, *, follow: bool = False, out: TextIO | None = None) -> None:
    out = out or sys.stdout
    path = Path(path)
    if path.is_dir():
        path = path / "events.jsonl"
    board = _Board()
    program = ""
    # discover program name from the engagement scope if present
    scope_json = path.parent / "scope.json"
    if scope_json.exists():
        try:
            program = json.loads(scope_json.read_text()).get("program", "")
        except Exception:
            program = ""
    banner(program or str(path), out)

    if not path.exists():
        print(_c(f"(waiting for {path} …)", "90"), file=out)

    seen = 0
    while True:
        if path.exists():
            events = list(_read_events(path))
            for e in events[seen:]:
                _render(e, board, out)
            seen = len(events)
        if not follow:
            break
        # follow: poll for new lines until the run ends and no new events arrive
        time.sleep(1.0)
        if path.exists() and len(list(_read_events(path))) == seen and _run_done(seen, path):
            # heuristic stop: a Result/finished marker or no growth handled by caller
            pass
    print("", file=out)
    print(board.panel(), file=out)


def _run_done(seen: int, path: Path) -> bool:
    return False  # follow loop is interrupted by the user (Ctrl-C); replay mode exits naturally
