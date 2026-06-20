"""Interactive full-screen TUI (spec §11).

A keyboard-navigable cockpit for a live hunt: a left tab list of every spawned agent plus a
Blackboard tab; ↑/↓ switches tabs and the main pane shows only that agent's thread. The
header shows cumulative token usage and cost. Each line is labelled by type — the agent's
*thinking* (extended reasoning) vs its *output* (printed text) vs tool calls, guard denials,
and findings. Pure ``TuiState`` holds the model (testable); ``run_tui`` drives curses.
"""

from __future__ import annotations

import sys
import threading
import time
from collections import defaultdict

from . import theme as T
from .tui import _Board


def _set_mouse(curses, on: bool) -> None:
    """Enable mouse-WHEEL reporting so trackpad/wheel up-down ALWAYS scrolls the agent stream.

    We emit the xterm DEC-private sequences directly:
      1000h = button tracking (wheel arrives as buttons 4/5), 1002h = button-event tracking
      (some terminals only deliver the wheel under this), 1006h = SGR extended coords,
      1007l = DISABLE alternate-scroll (else macOS Terminal turns the wheel into ↑/↓ arrows,
      which would switch agents instead of scrolling).
    The mask requests ALL events incl. position so wheel-down (BUTTON5) is never dropped.
    ``on=False`` is used only on exit to restore the terminal's native wheel/selection."""
    try:
        if on:
            mask = curses.ALL_MOUSE_EVENTS | getattr(curses, "REPORT_MOUSE_POSITION", 0)
            curses.mousemask(mask)
            curses.mouseinterval(0)
            sys.stdout.write("\033[?1000h\033[?1002h\033[?1006h\033[?1007l")
        else:
            curses.mousemask(0)
            sys.stdout.write("\033[?1000l\033[?1002l\033[?1006l\033[?1007h")
        sys.stdout.flush()
    except Exception:
        pass

_SYSTEM_AGENTS = {"scopeguard", "blackboard", "orchestrator", "operator"}


def fmt_tokens(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1e6:.2f}M"
    if n >= 1_000:
        return f"{n / 1e3:.1f}K"
    return str(n)


class TuiState:
    """Model behind the TUI — routes events into per-agent threads + blackboard + tokens."""

    def __init__(self, program: str = "") -> None:
        self.program = program
        self.agent_order: list[str] = []
        self.threads: dict[str, list[tuple[str, str]]] = defaultdict(list)  # agent -> [(tag, text)]
        self._pending: dict[str, tuple[str, str]] = {}  # agent -> (tag, partial text)
        self.board = _Board()
        self.tokens = {"total": 0, "input": 0, "output": 0, "cost": 0.0}
        # Per-agent record of which block types (thinking|output) arrived as LIVE token deltas this
        # turn, so the duplicate FINAL block of that type is dropped — but a final block of a type
        # that did NOT stream (e.g. the answer delivered whole) is still shown. Cleared as each
        # final block is consumed so the next turn starts fresh.
        self._streamed: dict[str, set[str]] = defaultdict(set)
        self.selected = 0
        self.lock = threading.Lock()
        self.dirty = True
        self.nevents = 0          # total events ingested (liveness signal)
        self.last_mono = 0.0      # monotonic time of the last ingested event (any agent)
        self.last_mono_by_agent: dict[str, float] = {}  # per-agent last-activity time
        self.delegating: set[str] = set()  # agents currently waiting on a sub-agent (busy, but silent)
        self.combined: list[tuple[str, str, str]] = []  # global chronological (agent, tag, text) firehose
        self.last_active = ""     # base name of the agent that most recently did something
        self.confirmed: list[tuple[str, str]] = []                # (severity, title) Falsifier-verified
        self.reported: list[tuple[str, str, str, str, str]] = []  # (sev, title, loc, agent, time) live posts
        self.scroll = 0  # lines scrolled up from the live tail (0 = following)
        self.dark = True            # True = night mode (white font); False = normal (black font)
        self.show_thinking = False  # thinking is collapsed until the user presses Ctrl+O
        self.run_log_path = None    # raw process log (NOT AI) shown in its own tab if present
        self.mouse_on = True        # wheel/trackpad scroll is ALWAYS on (kept for back-compat)
        self._t0 = time.monotonic()  # wall-clock start, for the header's elapsed timer
        self.round = 0               # latest round number seen (header headline)
        self.findings_full: list[dict] = []  # enriched confirmed-finding events → finding cards

    # --- tabs -------------------------------------------------------------
    def tabs(self) -> list[str]:
        extra = ["run.log"] if self.run_log_path else []
        return ["blackboard", "findings", "firehose"] + self.agent_order + extra

    def toggle_theme(self) -> None:
        self.dark = not self.dark
        self.dirty = True

    def toggle_thinking(self) -> None:
        self.show_thinking = not self.show_thinking
        self.dirty = True

    def selected_tab(self) -> str:
        tabs = self.tabs()
        return tabs[min(self.selected, len(tabs) - 1)]

    def move(self, delta: int) -> None:
        with self.lock:
            self.selected = max(0, min(self.selected + delta, len(self.tabs()) - 1))
            self.scroll = 0  # new tab starts at the live tail
            self.dirty = True

    # --- scroll (within the selected thread) ------------------------------
    # ``scroll`` is lines from the bottom: 0 = following the live tail; >0 = scrolled up.
    def scroll_lines(self, delta: int) -> None:
        self.scroll = max(0, self.scroll + delta)
        self.dirty = True

    def scroll_to_live(self) -> None:
        self.scroll = 0
        self.dirty = True

    # --- ingest -----------------------------------------------------------
    def liveness(self) -> tuple[int, float]:
        """(events ingested, seconds since the last event). Age is -1 before any event."""
        age = (time.monotonic() - self.last_mono) if self.last_mono else -1.0
        return self.nevents, age

    def agent_age(self, tab: str) -> float:
        """Seconds since the SELECTED agent last did anything (-1 if it never has)."""
        t = self.last_mono_by_agent.get(tab.split(".")[0])
        return (time.monotonic() - t) if t else -1.0

    def ingest(self, agent: str, kind: str, data: dict, ts: float | None = None) -> None:
        with self.lock:
            self.dirty = True
            self.nevents += 1
            self.last_mono = time.monotonic()
            if agent:
                _base = agent.split(".")[0]
                self.last_mono_by_agent[_base] = self.last_mono
                # an agent is "delegating" from when it spawns a sub-agent until its own next event
                if kind == "tool_call" and str(data.get("tool", "")) in ("Agent", "Task"):
                    self.delegating.add(_base)
                else:
                    self.delegating.discard(_base)
            if kind == "usage":
                self.tokens["total"] += data.get("total", 0)
                self.tokens["input"] += data.get("input", 0)
                self.tokens["output"] += data.get("output", 0)
                self.tokens["cost"] += data.get("cost", 0) or 0
                return
            if kind in ("bb_write", "finding"):
                self.board.apply({"agent": agent, "kind": kind, "data": data})
            if kind == "finding" and data.get("id"):
                self.confirmed.append((str(data.get("severity", "?")), str(data.get("title", ""))))
                self.findings_full.append(dict(data))  # full payload → render a finding card
            if kind == "finding_reported":
                # a hunter posted a finding live via the write-only blackboard tool (mid-session)
                loc = f"{data.get('file','?')}:{data.get('line','?')}"
                clock = time.strftime("%H:%M:%S", time.localtime(ts)) if ts else time.strftime("%H:%M:%S")
                self.reported.append((str(data.get("severity", "?")), str(data.get("title", "")),
                                      loc, agent.split(".")[0], clock))
                self.board.apply({"agent": agent, "kind": "finding",
                                  "data": {"id": "live", "severity": data.get("severity", "?"),
                                           "title": "(reported) " + str(data.get("title", ""))}})
                self._add(agent, "finding", f"★ posted to blackboard: {data.get('title','')} [{data.get('severity','')}]")
                return

            base = agent.split(".")[0]
            if kind == "stream_start":
                self._flush(agent)
                tag = "thinking" if data.get("block") == "thinking" else "output"
                self._streamed[base].add(tag)
                self._pending[agent] = (tag, "")
                return
            if kind == "stream":
                cur = self._pending.get(agent, ("output", ""))
                tag = "thinking" if data.get("thinking") else cur[0]
                self._streamed[base].add(tag)
                self._pending[agent] = (tag, cur[1] + str(data.get("text", "")))
                return
            if kind in ("thinking", "output"):
                # The FINAL whole block. If this type already streamed live this turn, it's a
                # duplicate — drop it and clear the flag (so the NEXT turn shows again). If it did
                # NOT stream (answer/reasoning delivered whole), render it.
                if kind in self._streamed.get(base, ()):
                    self._streamed[base].discard(kind)
                    return
                self._flush(agent)
                txt = str(data.get("text", "")).strip()
                if txt:
                    self._add(agent, kind, txt)   # tag "thinking" (collapsible) or "output" (answer)
                return

            self._flush(agent)
            if kind == "tool_call":
                # store tool + target split by a unit-separator so the renderer can style them
                self._add(agent, "tool", f"{data.get('tool','')}\x1f{str(data.get('target',''))[:120]}")
            elif kind == "guard_decision":
                if not data.get("allow"):
                    who = data.get("agent", agent)
                    self._add(who, "deny", f"DENY {data.get('tool','')} → {str(data.get('target',''))[:48]} :: {data.get('reason','')}")
            elif kind == "reframe":
                self._add(agent, "system", "↻ reframe: " + str(data.get("reason") or data.get("frame", "")))
            elif kind == "finding":
                if data.get("event") == "critical_confirmed":
                    self._add(agent, "finding", f"★★★ CRITICAL CONFIRMED ×{data.get('count',1)}")
                else:
                    self._add(agent, "finding", f"★ {data.get('title','')} [{data.get('severity','')}]")
            elif kind == "lifecycle":
                ev = data.get("event")
                if ev == "spawn":
                    self._add(agent, "system", "↳ spawned: " + str(data.get("path", ""))[:80])
                elif ev == "poc_refuted":
                    self._add(agent, "verdict", f"🧪✗ PoC DISPROVED (dropped): {str(data.get('title',''))[:60]} — {str(data.get('detail',''))[:90]}")
                elif ev == "stall_detected":
                    self._add(agent, "round", f"🩺 STALL detected ({data.get('idle_s','?')}s silent) — Parent A self-healing…")
                elif ev == "self_healed":
                    self._add(agent, "round", f"🩺 self-healed: cancelled {data.get('cancelled',0)} stuck task(s){' · rate-limited' if data.get('rate_limited') else ''} — {str(data.get('diagnosis',''))[:80]}")
                elif ev == "backoff":
                    self._add(agent, "system", f"⏸ {data.get('reason','backing off')}")
                elif ev == "hunter_timeout":
                    self._add(agent, "round", f"⏱ {agent} cut: {data.get('detail','wall-clock exceeded')}")
                elif ev == "reference_detected":
                    self._add("parent_a", "round", f"🔬 differential oracle available: {str(data.get('detail',''))[:90]}")
                elif ev == "patterns_loaded":
                    self._add("parent_a", "round", f"🧬 {data.get('count',0)} known bug patterns loaded — hunting new variants")
                elif ev in ("model_downgrade", "scope_fallback", "stop", "safety_event", "cap_reached", "findings_written"):
                    self._add(agent, "system", f"⚙ {ev}: {data.get('reason') or data.get('detail') or data.get('path','')}")
            elif kind == "message":
                self._message(agent, data)

    def _message(self, agent: str, d: dict) -> None:
        if d.get("kind") == "assign":
            if d.get("mode"):  # fuzzer assignment
                self._add(agent, "assign", f"⇒ {d.get('to','')}  ⚗ {d.get('mode','')} fuzz «{d.get('subsystem','')}»")
                for inv in (d.get("invariants") or [])[:4]:
                    self._add(agent, "assign", f"    ∴ invariant: {inv}")
            else:
                self._add(agent, "assign", f"⇒ {d.get('to','')}  «{d.get('mission') or d.get('lens','')}»")
                for inv in (d.get("invariants") or [])[:4]:
                    self._add(agent, "assign", f"    ∴ invariant: {inv}")
                for q in (d.get("investigate") or [])[:6]:
                    self._add(agent, "assign", f"    • {q}")
        elif "verdict" in d:
            self._add(agent, "verdict", f"⚖ {d['verdict']}: {str(d.get('title') or d.get('hyp',''))[:70]}")
        elif d.get("phase") == "scoping":
            self._add(agent, "system", "🔬 cold reconnaissance (no prior knowledge)")
        elif d.get("phase") == "scoped":
            self._add(agent, "system", f"derived {d.get('tracks','?')} tracks · critical = {str(d.get('critical_means',''))[:80]}")
        elif d.get("phase") == "round":
            self.round = int(d.get("round", self.round) or self.round)
            self._add(agent, "round", f"──── ROUND {d.get('round')} ({d.get('lenses', d.get('depth','?'))} tracks) ────")
        elif d.get("phase") == "hunt":
            self._add(agent, "system", f"🔎 hunting {d.get('lens','')} (pass {d.get('depth','')})")
        elif d.get("phase") == "fuzz":
            self._add(agent, "system", f"⚗ {d.get('mode','')} fuzzing «{d.get('subsystem','')}» — {d.get('invariants',0)} invariants")
        elif d.get("phase") == "round_summary":
            self._add(agent, "system", f"round {d.get('round')} — criticals {d.get('criticals_total',0)}, candidates {d.get('candidates_total',0)}")
        elif d.get("phase") == "notice":
            self._add(agent, "round", f"📨 OPERATOR NOTICE: {d.get('notice','')}")
        elif d.get("phase") == "resteer":
            self._add(agent, "system", "🧭 Parent A reviewing the team's progress to re-steer next round…")
        elif d.get("phase") == "resteered":
            self._add(agent, "round", f"🧭 re-steered {d.get('count', 0)} track(s) for the next round")
        elif d.get("phase") == "poc":
            self._add(agent, "system", f"🧪 building + running a PoC to prove: {str(d.get('title',''))[:70]}")

    def _add(self, agent: str, tag: str, text: str) -> None:
        if agent in _SYSTEM_AGENTS or not agent:
            agent = "parent_a" if agent in ("blackboard", "orchestrator", "operator") else agent
        if agent in _SYSTEM_AGENTS:
            return
        base = agent.split(".")[0]
        if base not in self.agent_order:
            self.agent_order.append(base)
        self.last_active = base  # most recent agent to produce visible content
        buf = self.threads[base]
        buf.append((tag, text))
        if len(buf) > 4000:
            del buf[:1000]
        # global chronological firehose (everyone's stream merged, in order)
        self.combined.append((base, tag, text))
        if len(self.combined) > 6000:
            del self.combined[:1500]

    def _flush(self, agent: str) -> None:
        pend = self._pending.pop(agent, None)
        if pend and pend[1].strip():
            self._add(agent, pend[0], pend[1].strip())

    # --- render data ------------------------------------------------------
    def header(self) -> str:
        t = self.tokens
        p1 = sum(1 for s, _ in self.confirmed if str(s).lower() == "critical")
        elapsed = T.fmt_duration(time.monotonic() - self._t0)
        rnd = f"r{self.round} · " if self.round else ""
        # Lead with the headline metric — confirmed P1 count — then round, elapsed, tokens, cost.
        p1str = f"{T.FINDING} {p1} P1" if p1 else "0 P1"
        return (f"{self.program or 'hunt'}  ·  {p1str}  ·  {rnd}{elapsed}  ·  "
                f"{fmt_tokens(t['total'])} tok · ${t['cost']:.2f}")

    def thread_entries(self, tab: str) -> list[tuple[str, str]]:
        with self.lock:
            if tab == "run.log":
                import re
                from pathlib import Path
                rows: list[tuple[str, str]] = [
                    ("assign", "run.log — RAW process stdout: all agents' output INTERLEAVED (so it looks garbled)"),
                    ("system", "↑/↓ to a child_bN / parent_a tab for each agent's CLEAN reasoning. This tab is for spotting process errors."),
                    ("system", ""),
                ]
                try:
                    lines = Path(self.run_log_path).read_text(errors="replace").splitlines()
                except Exception as exc:
                    rows.append(("system", f"(could not read run.log: {exc})"))
                    return rows
                # Surface genuine PROCESS-level problems at the top (not agent reasoning that
                # merely contains words like 'error'/'denied'), then the raw tail.
                pat = re.compile(
                    r"Traceback \(most recent|usage limit|session limit|rate limit|You've hit your|"
                    r"^Result:|Engagement BLOCKED|cap_reached|model_downgrade|MemoryError|"
                    r"No space left|Killed|zsh: killed|command not found")
                flagged = [ln for ln in lines if pat.search(ln)]
                if flagged:
                    rows.append(("deny", f"⚠ {len(flagged)} process/error line(s) flagged:"))
                    for ln in flagged[-12:]:
                        rows.append(("verdict", ln.strip()[:200]))
                    rows.append(("system", ""))
                rows.append(("round", "──── raw interleaved tail ────"))
                for ln in lines[-400:]:
                    rows.append(("output", ln))
                return rows
            if tab == "firehose":
                rows: list[tuple[str, str]] = [
                    ("assign", "FIREHOSE — every agent's thinking, output & tool calls merged into one live stream"),
                    ("system", ""),
                ]
                for ag, tag, text in self.combined[-2000:]:
                    if tag == "tool":
                        # keep the real tool name (so _render_tool picks the right glyph); label
                        # which agent ran it inside the target column
                        tool, _, target = text.partition("\x1f")
                        rows.append(("tool", f"{tool}\x1f❲{ag}❳ {target}"))
                    else:
                        # thinking/output keep their tag so markdown (bold/italic/code) renders
                        rows.append((tag, f"❲{ag}❳ {text}"))
                return rows
            if tab == "blackboard":
                head = [
                    ("assign", "BLACKBOARD — the shared findings board"),
                    ("system", "WRITE → Child B/C hunters post findings here (write-only; they cannot read it back)"),
                    ("system", "READ  → Parent A + Falsifier + Report agents pick findings up from here"),
                    ("system", ""),
                ]
                return head + [("system", ln) for ln in self.board.panel().splitlines()]
            if tab == "findings":
                cards_w = 86
                crits = [f for f in self.findings_full if str(f.get("severity", "")).lower() == "critical"]
                others = [f for f in self.findings_full if str(f.get("severity", "")).lower() != "critical"]
                rows: list[tuple[str, str]] = [
                    ("assign", "FINDINGS — hunters post_finding → Falsifier verifies → reproduced → CONFIRMED"),
                    ("spacer", ""),
                    ("round", f"{T.FINDING} CONFIRMED CRITICALS / P1s (the focus) — {len(crits)}"),
                    ("spacer", ""),
                ]
                for f in crits:
                    rows.extend(_finding_card_lines(f, cards_w))
                if not crits:
                    rows.append(("system", "  (no P1 confirmed yet — this is what we're hunting for)"))
                    rows.append(("spacer", ""))
                rows.append(("round", f"✓ OTHER CONFIRMED FINDINGS (Falsifier-verified) — {len(others)}"))
                rows.append(("spacer", ""))
                for f in others:
                    rows.extend(_finding_card_lines(f, cards_w))
                if not others:
                    rows.append(("system", "  (none)"))
                    rows.append(("spacer", ""))
                rows.append(("round", f"… REPORTED by hunters (live, awaiting verification) — {len(self.reported)}"))
                for sev, title, loc, ag, clock in self.reported:
                    rows.append(("verdict", f"  [{clock}] {T.sev_badge(sev, color=False).strip()} {title} — {loc} ({ag})"))
                if not self.reported:
                    rows.append(("system", "  (a hunter writes here the moment it posts via post_finding)"))
                return rows
            base = tab.split(".")[0]
            entries = list(self.threads.get(base, []))
            pend = self._pending.get(base)
            if pend and pend[1].strip():
                entries.append((pend[0], pend[1].strip() + " ▌"))
            return entries


# --- curses renderer ------------------------------------------------------
_GLYPH = {
    "thinking": "⋯ ", "output": "▸ ", "tool": "· ", "deny": "⛔ ", "finding": "★ ",
    "assign": "", "verdict": "⚖ ", "round": "", "system": "", "round_summary": "",
}


def _finding_card_lines(f: dict, width: int) -> list[tuple[str, str]]:
    """Render one finding as a curses CARD — a list of (tag, text) rows whose ``card*`` tags are
    drawn VERBATIM (no re-wrap, no glyph), so the box stays aligned. Same structure as the ANSI
    card in theme.finding_card, so every surface shows an identical card."""
    inner = max(24, min(width, 88) - 2)
    sev = str(f.get("severity", "?")).lower()
    reproduced = bool(f.get("reproduced", True))
    rows = T.finding_rows(
        title=str(f.get("title", "")), location=str(f.get("location", "")),
        lens=str(f.get("lens", "")), counterfactual=str(f.get("counterfactual", "")),
        reproduced_by=("yes" if reproduced else ""), remediation=str(f.get("remediation", "")))

    def clip(s: str) -> str:
        s = T.strip_ansi(s)
        return s if len(s) <= inner - 2 else s[: inner - 3] + "…"

    ttl = f" {T.finding_title(sev, confirmed=reproduced)} "
    out: list[tuple[str, str]] = [("card_b", "╭" + ttl + "─" * max(0, inner - len(ttl)) + "╮")]
    role_tag = {"title": "card_b", "loc": "card_dim", "cf": "card", "repro": "card_ok", "fix": "card_fix"}
    for role, text in rows:
        c = clip(text)
        out.append((role_tag.get(role, "card"), "│ " + c + " " * (inner - 2 - len(c)) + " │"))
    out.append(("card_b", "╰" + "─" * inner + "╯"))
    out.append(("spacer", ""))
    return out


def _strip(text: str) -> str:
    return "".join(ch for ch in text if ch == "\n" or ord(ch) >= 32)


def watch_tui(path, *, program: str = "") -> None:
    """Attach the interactive cockpit to an existing/live engagement ``events.jsonl``.

    Tails the event stream in a background thread and feeds each ``{agent, kind, data}``
    line into a :class:`TuiState`, so a hunt already running in another process can be
    explored here with ↑/↓ tab switching, the Blackboard tab, and live token totals.
    """
    import json
    import time
    from pathlib import Path

    from .tui import _read_events

    path = Path(path)
    if path.is_dir():
        path = path / "events.jsonl"

    program = program or ""
    scope_json = path.parent / "scope.json"
    if not program and scope_json.exists():
        try:
            program = json.loads(scope_json.read_text()).get("program", "")
        except Exception:
            program = ""

    state = TuiState(program or path.parent.name)
    # Locate the raw process log (NOT AI) for its own tab — usually beside the engagement dir.
    for cand in (path.with_name("run.log"), path.parent / "run.log", path.parent.parent / "run.log"):
        if cand.exists():
            state.run_log_path = str(cand)
            break
    flag = {"quit": False, "done": False}

    def _ingest_line(raw: str) -> None:
        raw = raw.strip()
        if not raw:
            return
        try:
            e = json.loads(raw)
        except Exception:
            return
        data = e.get("data", {}) or {}
        state.ingest(e.get("agent", ""), e.get("kind", ""), data, e.get("ts"))
        if e.get("kind") == "lifecycle" and isinstance(data, dict) and data.get("event") == "stop":
            flag["done"] = True

    # Pre-load everything written so far synchronously, so the cockpit paints fully
    # populated the instant curses starts (no blank "loading" screen), and remember
    # the byte offset so the tail thread only reads what's appended after this.
    offset = 0
    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                _ingest_line(line)
            offset = fh.tell()

    def _feed() -> None:
        off = offset
        while not flag["quit"]:
            try:
                if path.exists():
                    with path.open("r", encoding="utf-8") as fh:
                        fh.seek(off)
                        new = fh.read()
                        off = fh.tell()
                    if new:
                        for line in new.splitlines():
                            _ingest_line(line)
            except Exception:
                pass
            time.sleep(0.5)

    feeder = threading.Thread(target=_feed, daemon=True)
    feeder.start()
    try:
        run_tui(state, lambda: flag["done"])
    finally:
        flag["quit"] = True


def run_tui(state: "TuiState", done) -> None:
    """Drive the curses cockpit. ``done`` is a callable returning True when the hunt ended."""
    import curses
    import textwrap

    def _loop(stdscr: "curses._CursesWindow") -> None:
        curses.curs_set(0)
        try:
            curses.use_default_colors()
            curses.start_color()
            hi = (getattr(curses, "COLORS", 8) or 8) >= 256  # true black/white need 256-color
            pairs = {
                "thinking": 7, "output": 7, "tool": 8, "deny": 1, "finding": 2, "assign": 5,
                "verdict": 3, "round": 6, "system": 4, "sel": 6, "head": 6, "code": 6,
                # body text: crisp white (15) for night, TRUE black (16) for normal — plain 0/7
                # render as grey in most palettes, so prefer the 256-color extremes when available.
                "txt_w": 15 if hi else 7, "txt_b": 16 if hi else 0, "toolname": 6,
                # file/target reference after a tool call — a darker blue (256: DeepSkyBlue4).
                "ref": T.REF_CURSES_256 if hi else T.REF_CURSES_8,
            }
            for i, (_k, col) in enumerate(pairs.items(), start=1):
                curses.init_pair(i, col, -1)
            cp = {k: curses.color_pair(i) for i, k in enumerate(pairs, start=1)}
        except Exception:
            cp = defaultdict(int)
        _set_mouse(curses, True)  # ALWAYS on: trackpad/wheel up-down scrolls the agent stream
        stdscr.timeout(200)

        frame = 0
        while True:
            ch = stdscr.getch()
            h, _w = stdscr.getmaxyx()
            page = max(1, h - 6)
            # Re-assert wheel capture periodically so scrolling keeps working AT ALL TIMES, even if a
            # child process or a terminal quirk reset the mode mid-hunt (~every 5s; cheap).
            if frame % 25 == 0:
                _set_mouse(curses, True)
            if ch in (ord("q"), ord("Q")):
                break
            elif ch in (ord("t"), ord("T")):
                state.toggle_theme()                 # normal (black) ↔ night (white)
            elif ch in (ord("o"), ord("O"), 15):     # 'o' (Ctrl+O is swallowed by macOS Terminal)
                state.toggle_thinking()              # show/hide the agents' thinking
            elif ch in (ord("m"), ord("M")):         # 'm' = re-assert mouse capture (never disables scroll)
                _set_mouse(curses, True)
                state.dirty = True
            elif ch in (curses.KEY_UP, curses.KEY_LEFT, curses.KEY_BTAB):
                state.move(-1)                       # previous agent
            elif ch in (curses.KEY_DOWN, curses.KEY_RIGHT, ord("\t")):
                state.move(1)                        # next agent
            elif ch == curses.KEY_MOUSE:             # trackpad / wheel → scroll the current pane
                try:
                    _id, _mx, _my, _mz, bstate = curses.getmouse()
                except curses.error:
                    bstate = 0
                up = curses.BUTTON4_PRESSED
                down = getattr(curses, "BUTTON5_PRESSED", 0) or (1 << 21)  # BUTTON5 absent on some ncurses
                if bstate & up:                         # wheel/trackpad up → older lines
                    state.scroll_lines(3)
                elif bstate & down:                     # wheel/trackpad down → newer lines
                    state.scroll_lines(-3)
            elif ch == curses.KEY_PPAGE:
                state.scroll_lines(page)             # page up (keyboard fallback)
            elif ch == curses.KEY_NPAGE:
                state.scroll_lines(-page)            # page down
            elif ch in (curses.KEY_HOME, ord("g")):
                state.scroll_lines(10**9)            # jump to top (clamped in _draw)
            elif ch in (curses.KEY_END, ord("G")):
                state.scroll_to_live()               # jump back to the live tail
            elif ch == curses.KEY_RESIZE:
                _set_mouse(curses, True)  # a resize can drop mouse mode — re-assert so scroll survives
                state.dirty = True
            frame += 1
            # Redraw on new data OR on a timer (~every 400ms) so the spinner animates and
            # the "last update Xs ago" counter keeps ticking — constant proof it's alive.
            if state.dirty or frame % 2 == 0:
                _draw(stdscr, state, cp, done(), curses, textwrap, frame)
                state.dirty = False

    try:
        curses.wrapper(_loop)
    except Exception as exc:  # no TTY etc.
        print(f"[tui unavailable: {exc}] — use `watch` or `--live` instead.")
    finally:
        try:  # restore the terminal's native wheel/selection on the way out
            sys.stdout.write("\033[?1000l\033[?1006l\033[?1007h")
            sys.stdout.flush()
        except Exception:
            pass


_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# Inline markdown the model emits: code spans, **bold**/__bold__, *italic*/_italic_.
# Bold alternatives precede italic so `**x**` isn't mis-split as two italics.
import re as _re

_MD_RE = _re.compile(r"`[^`]+`|\*\*[^*]+\*\*|__[^_]+__|\*[^*\s][^*]*\*|_[^_\s][^_]*_")


def _md_segments(text: str):
    """Split ``text`` into (segment, style) pairs; style ∈ {None,'bold','italic','code'}."""
    out: list[tuple[str, str | None]] = []
    i = 0
    for m in _MD_RE.finditer(text):
        if m.start() > i:
            out.append((text[i:m.start()], None))
        tok = m.group()
        if tok[0] == "`":
            out.append((tok[1:-1], "code"))
        elif tok[:2] in ("**", "__"):
            out.append((tok[2:-2], "bold"))
        else:
            out.append((tok[1:-1], "italic"))
        i = m.end()
    if i < len(text):
        out.append((text[i:], None))
    return out or [(text, None)]


def _render_md(stdscr, y, x, text, base, maxw, curses, cp) -> None:
    """Draw ``text`` at (y,x) applying inline markdown styling, clipped to ``maxw`` cols."""
    end = x + maxw
    italic = getattr(curses, "A_ITALIC", curses.A_UNDERLINE)
    for seg, style in _md_segments(text):
        if x >= end or not seg:
            continue
        attr = base
        if style == "bold":
            attr |= curses.A_BOLD
        elif style == "italic":
            attr |= italic
        elif style == "code":
            attr = base | curses.A_REVERSE  # inline `code` as a chip — readable on both themes
        n = min(len(seg), end - x)
        try:
            stdscr.addnstr(y, x, seg[:n], n, attr)
        except curses.error:
            pass
        x += n


_HEAD_RE = _re.compile(r"^\s{0,3}(#{1,6})\s+(.*)$")
_BULLET_RE = _re.compile(r"^(\s*)[-*+]\s+(.*)$")


def _md_block_lines(text, width, textwrap):
    """Turn a markdown text block into styled (block_tag, line) pairs: headings, fenced code,
    and bullets become real structure instead of raw ``###``/```` ``` ````/``-`` markers."""
    out: list[tuple[str, str]] = []
    in_code = False
    for raw in _strip(text).split("\n"):
        s = raw.rstrip()
        if s.lstrip().startswith("```"):
            in_code = not in_code  # swallow the fence line; render contents with a gutter
            continue
        if in_code:
            for seg in textwrap.wrap(s, max(8, width - 4), drop_whitespace=False) or [""]:
                out.append(("md_code", "│ " + seg))
            continue
        mh = _HEAD_RE.match(s)
        if mh:
            out.append(("md_head", mh.group(2).strip()))
            continue
        mb = _BULLET_RE.match(s)
        if mb:
            for j, seg in enumerate(textwrap.wrap(mb.group(2), max(8, width - 4)) or [""]):
                out.append(("md_text", ("• " if j == 0 else "  ") + seg))
            continue
        for seg in textwrap.wrap(s, max(8, width - 2)) or [""]:
            out.append(("md_text", seg))
    return out or [("md_text", "")]


_TOOL_GLYPH = {
    "Read": "▤", "Write": "✎", "Edit": "✎", "MultiEdit": "✎", "NotebookEdit": "✎",
    "Grep": "⌕", "Glob": "▦", "Bash": "❯", "WebSearch": "⊕", "WebFetch": "⊕",
    "Agent": "⟐", "Task": "⟐",
}


def _render_tool(stdscr, y, x, tool, target, maxw, curses, cp, neutral) -> None:
    """Render a tool call as `‹glyph› TOOL  target` — tool name accented, target dimmed."""
    if tool.startswith("mcp__"):
        glyph, tool = T.FINDING, tool.split("__")[-1]
    else:
        glyph = T.ACTION  # uniform Claude-Code action marker (⏺)
    end = x + maxw
    label = f" {glyph} {tool} "
    try:
        stdscr.addnstr(y, x, label, max(0, end - x), cp.get("toolname", neutral) | curses.A_BOLD)
    except curses.error:
        pass
    x2 = x + len(label) + 1
    target = " ".join(str(target).split())
    if target and x2 < end:
        try:
            stdscr.addnstr(y, x2, target[: end - x2], end - x2, cp.get("ref", neutral))
        except curses.error:
            pass


def _draw(stdscr, state, cp, is_done, curses, textwrap, frame=0) -> None:
    h, w = stdscr.getmaxyx()
    stdscr.erase()
    side = min(22, max(14, w // 5))

    # header — leading spinner (or ✓) is an always-animating "still running" signal
    head_glyph = "✓" if is_done else _SPINNER[frame % len(_SPINNER)]
    status = "RUNNING" if not is_done else "DONE"
    stdscr.addnstr(0, 0, _strip(f"P1HUNT {head_glyph} {status}  ·  {state.header()}").ljust(w - 1), w - 1, cp["head"] | curses.A_BOLD)
    tabs = state.tabs()
    sel = min(state.selected, len(tabs) - 1)

    # sidebar (tabs)
    for i, tab in enumerate(tabs):
        row = 2 + i
        if row >= h - 1:
            break
        label = ("▸ " if i == sel else "  ") + tab
        attr = (cp["sel"] | curses.A_REVERSE) if i == sel else cp["system"]
        stdscr.addnstr(row, 0, label.ljust(side - 1), side - 1, attr)
        # status marker per agent: spinner = working now (emitted in the last ~90s),
        # ✓ = idle/done this round. Lets you tell "done" from "stuck" at a glance.
        if tab in state.agent_order and not is_done:
            ag_age = state.agent_age(tab)
            if tab in state.delegating:  # busy via a sub-agent (silent but working) — not idle
                mark, mattr = _SPINNER[frame % len(_SPINNER)], cp["assign"] | curses.A_BOLD
            elif 0 <= ag_age < 90:
                mark, mattr = _SPINNER[frame % len(_SPINNER)], cp["finding"] | curses.A_BOLD
            else:
                mark, mattr = "✓", cp["system"] | curses.A_DIM
            try:
                stdscr.addnstr(row, side - 2, mark, 1, mattr)
            except curses.error:
                pass

    cur = tabs[sel]
    pane_w = w - side - 1
    pane_h = h - 5

    # Wrap the WHOLE thread into display lines so we can scroll back through all of it. This is
    # cached (keyed by tab+width+content signature) so idle/spinner redraws don't re-wrap, and
    # active scrolling stays responsive.
    entries = state.thread_entries(cur)
    sig = (cur, pane_w, len(entries), state.show_thinking, entries[-1][1][-48:] if entries else "")
    if getattr(state, "_wrap_sig", None) != sig:
        wl: list[tuple[str, str]] = []
        for tag, text in entries:
            if tag == "thinking" and not state.show_thinking:
                # collapsed: one-line preview, expandable with Ctrl+O (Claude-Code style)
                prev = " ".join(_strip(text).split())
                wl.append(("thinking_collapsed", f"⋯ thinking · {prev[:64]}…  [Ctrl+O]"))
                continue
            if tag == "tool":
                wl.append(("tool", text))  # kept as one line; rendered by _render_tool
                continue
            if tag.startswith("card") or tag == "spacer":
                wl.append((tag, text))  # pre-aligned card box / blank — render verbatim, no glyph
                continue
            if tag in ("thinking", "output"):
                # full markdown rendering: headings/code/bullets/inline bold-italic-code
                glyph = "⋯ " if tag == "thinking" else "▸ "
                blk = _md_block_lines(text, pane_w, textwrap)
                for idx, (btag, line) in enumerate(blk):
                    wl.append((btag, (glyph + line) if idx == 0 else line))
                wl.append(("spacer", ""))  # paragraph spacing between turns
                continue
            glyph = _GLYPH.get(tag, "")
            for j, seg in enumerate(textwrap.wrap(_strip(text), width=pane_w - 2) or [""]):
                wl.append((tag, (glyph if j == 0 else "  ") + seg))
        state._wrap_sig = sig
        state._wrap_lines = wl
    lines = state._wrap_lines

    total = len(lines)
    max_scroll = max(0, total - pane_h)
    # Anchor the view: if scrolled up and new lines arrived, keep the same lines on screen.
    if getattr(state, "_prev_tab", None) == cur and state.scroll > 0:
        delta = total - getattr(state, "_prev_total", total)
        if delta > 0:
            state.scroll += delta
    state._prev_tab = cur
    state._prev_total = total
    state.scroll = min(state.scroll, max_scroll)  # clamp (also resolves Home's jump-to-top)
    off = state.scroll
    end = total - off
    start = max(0, end - pane_h)
    view = lines[start:end]

    # main pane title — show scroll position / live state
    if off > 0:
        pos = f"  [scrolled ↑{off} · End=live]"
    else:
        pos = "  [live ↓]"
    stdscr.addnstr(2, side, _strip(f"THREAD: {cur}{pos}").ljust(w - side - 1), w - side - 1, curses.A_BOLD)

    # Body text color follows the theme: night = white, normal = black.
    neutral = cp["txt_w"] if state.dark else cp["txt_b"]
    for k, (tag, ln) in enumerate(view):
        y = 4 + k
        if tag == "spacer":
            continue
        if tag == "tool":
            tool, _, target = ln.partition("\x1f")
            _render_tool(stdscr, y, side, tool, target, pane_w, curses, cp, neutral)
            continue
        if tag == "md_text":  # body paragraph/bullet — inline bold/italic/code
            _render_md(stdscr, y, side, ln, neutral, pane_w, curses, cp)
            continue
        if tag == "md_head":  # markdown heading — bold, marker stripped
            try:
                stdscr.addnstr(y, side, ln, pane_w, neutral | curses.A_BOLD)
            except curses.error:
                pass
            continue
        if tag == "md_code":  # fenced code block — dim, gutter
            try:
                stdscr.addnstr(y, side, ln, pane_w, neutral | curses.A_DIM)
            except curses.error:
                pass
            continue
        if tag.startswith("card"):  # finding-card rows — pre-aligned, colored by role
            attr = {
                "card_b": cp["finding"] | curses.A_BOLD,   # border + title
                "card_dim": cp["system"],                  # location
                "card_ok": cp["finding"],                  # reproduced line
                "card_fix": cp["toolname"],                # remediation
            }.get(tag, neutral)                            # "card" = neutral body
            try:
                stdscr.addnstr(y, side, ln, pane_w, attr)
            except curses.error:
                pass
            continue
        if tag == "thinking_collapsed":
            attr = neutral | curses.A_DIM
        else:
            attr = cp.get(tag, 0)
            if tag in ("finding", "round", "assign"):
                attr |= curses.A_BOLD
        try:
            stdscr.addnstr(y, side, ln, pane_w, attr)
        except curses.error:
            pass

    nev, gage = state.liveness()  # global health drives the "quiet" warning
    is_agent = cur in state.agent_order
    cur_age = state.agent_age(cur) if is_agent else gage  # the number is per-selected-agent
    spin = _SPINNER[frame % len(_SPINNER)]
    if is_done:
        live = "✓ hunt complete"
    elif gage < 0:
        live = f"{spin} starting…"
    elif gage > 90:
        live = f"⚠ quiet {int(gage)}s · {nev} events — check run.log (may be rate-limited)"
    elif is_agent and cur in state.delegating:
        live = f"{spin} live · {nev} ev · {cur} delegating (sub-agent working)"
    else:
        agetxt = f"{int(cur_age)}s ago" if cur_age >= 0 else "no activity yet"
        who = f"{cur} last" if is_agent else "last"
        live = f"{spin} live · {nev} ev · {who} {agetxt}"
    theme = "night" if state.dark else "normal"
    think = "o:hide-think" if state.show_thinking else "o:show-think"
    foot = (f"↑/↓ agent · scroll: trackpad/wheel or PgUp/Dn · {think} · t:{theme} · End live · "
            f"q quit · (shift+drag to select)   ·   " + live)
    stdscr.addnstr(h - 1, 0, _strip(foot).ljust(w - 1), w - 1, cp["head"])
    stdscr.refresh()
