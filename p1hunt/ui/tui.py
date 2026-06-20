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

from . import theme as T

try:
    _COLOR = sys.stdout.isatty()
except Exception:  # pragma: no cover
    _COLOR = False

_WIDTH = 98


def _c(text: str, code: str) -> str:
    return T.paint(text, code, color=_COLOR)


def _color_for(agent: str) -> str:
    return T.agent_identity(agent)[1]


def _tag(agent: str) -> str:
    return T.agent_tag(agent, color=_COLOR)


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
        self._streaming = False           # a live token stream is mid-line
        self._stream_type = "output"      # "thinking" | "output" of the current stream
        self._streamed: set[str] = set()  # block types delivered live this turn (dedup the final)

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
        hyp = "  ".join(f"{k}={v}" for k, v in counts.items()) or "(none)"
        rows.append(_c(f"  │ hypotheses: {hyp}", "90"))
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
            is_think = d.get("block") == "thinking"
            board._stream_type = "thinking" if is_think else "output"
            board._streamed.add(board._stream_type)
            # Thinking gets a dim "⋯ thinking" gutter; the answer gets a bright ▸ — like Claude Code.
            head = _c(f"{T.THINK} thinking", "90") if is_think else _c(T.ACTION, _color_for(agent))
            out.write(f"\n{_tag(agent)} {head} ")
            out.flush()
            board._streaming = True
        return
    if kind == "stream":
        if live:
            txt = str(d.get("text", ""))
            out.write(_c(txt, "90") if board._stream_type == "thinking" else txt)  # thinking dimmed
            out.flush()
            board._streaming = True
        return
    if kind in ("thinking", "output") and live:
        # In live mode the streamed deltas already showed this block; drop the duplicate FINAL
        # block — UNLESS this type never streamed (answer delivered whole), then render it below.
        if kind in board._streamed:
            board._streamed.discard(kind)
            return

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
    elif kind in ("thinking", "output"):
        # thinking = dim reasoning (⋯); output = the model's ANSWER (▸), rendered with markdown.
        is_think = kind == "thinking"
        head = _c(f"{T.THINK} thinking", "90") if is_think else _c(T.ACTION, _color_for(agent))
        p(f"{_tag(agent)} {head}")
        for para in str(d.get("text", "")).splitlines() or [""]:
            if is_think:  # plain + dim (no nested ANSI fighting the dim)
                p(_c("        " + T.md_to_ansi(para, color=False), "90"))
            else:         # the answer — full inline markdown (bold/italic/code)
                p("        " + T.md_to_ansi(para, color=_COLOR))
    elif kind == "tool_call":
        tool = str(d.get("tool", ""))
        args = " ".join(str(d.get("target", "")).split())[:74]
        p("        " + _c(f"{T.ACTION} {tool}", _color_for(agent)) + _c(f" ({args})", T.REF_ANSI))
    elif kind == "guard_decision":
        if not d.get("allow"):
            p(_c(f"        ⛔ DENY {d.get('tool','')} → {str(d.get('target',''))[:50]} :: {d.get('reason','')}", "31;1"))
    elif kind == "finding":
        if d.get("event") == "critical_confirmed":
            p("\n" + _c(f"  {T.FINDING*3}  CRITICAL CONFIRMED ×{d.get('count',1)}  {T.FINDING*3}", "32;1"))
        elif d.get("id"):
            # A full finding CARD — the product of the hunt, rendered to be read first.
            p("\n" + T.finding_card(
                severity=d.get("severity", "?"), title=d.get("title", ""),
                location=d.get("location", ""), lens=d.get("lens", ""),
                counterfactual=str(d.get("counterfactual", ""))[:120],
                reproduced_by=("yes" if d.get("reproduced") else ""),
                remediation=str(d.get("remediation", ""))[:120],
                confirmed=bool(d.get("reproduced", True)), width=_WIDTH - 24, color=_COLOR))
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

    # Byte-offset tail: only read what was appended since the last poll (O(new bytes), not O(file)
    # every second). A trailing partial line is held in ``buf`` until its newline arrives.
    offset = 0
    buf = ""
    try:
        while True:
            if path.exists():
                with path.open("r", encoding="utf-8") as fh:
                    fh.seek(offset)
                    chunk = fh.read()
                    offset = fh.tell()
                if chunk:
                    buf += chunk
                    *lines, buf = buf.split("\n")
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            _render(json.loads(line), board, out)
                        except json.JSONDecodeError:
                            continue
            if not follow:
                break
            time.sleep(0.5)  # follow ends on Ctrl-C; replay (no follow) exits after one pass
    except KeyboardInterrupt:
        pass
    print("", file=out)
    print(board.panel(), file=out)
