"""Shared UI design language (spec §11) — ONE source of truth for how a hunt is rendered.

The line viewer (``tui.py``), the end-of-run snapshot (``dashboard.py``), and the curses
cockpit (``tui_app.py``) all draw from this module so agent labels, colors, the glyph
vocabulary, severity badges, inline markdown, and the finding / summary cards stay consistent
(no more drifting palettes). It is pure + import-safe (no curses, no I/O at import).

Style goal: Claude-Code-like restraint — a small glyph set, a clear left gutter, dim secondary
text, bold for the few things that matter (the action, the finding, the headline number).
"""

from __future__ import annotations

import re

# --- glyph vocabulary (curated; the whole UI uses only these) ----------------------------
ACTION = "⏺"     # a tool call / concrete action
RESULT = "⎿"     # a result / sub-line under an action
TURN = "●"       # an agent turn (reasoning/output header)
THINK = "⋯"      # collapsed thinking
FINDING = "★"    # a finding
DENY = "⛔"       # a blocked action
REFRAME = "↻"    # a reframe / pivot
VERDICT = "⚖"    # a Falsifier verdict
ARROW = "⮑"      # counterfactual / consequence
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# Tool → glyph (Claude-Code-style action icons).
TOOL_GLYPH = {
    "Read": "▤", "Write": "✎", "Edit": "✎", "MultiEdit": "✎", "NotebookEdit": "✎",
    "Grep": "⌕", "Glob": "▦", "Bash": "❯", "WebSearch": "⊕", "WebFetch": "⊕",
    "Agent": "⟐", "Task": "⟐",
}

# --- ANSI ---------------------------------------------------------------------------------
# File / target references (the path after a tool call, a finding's location) — a darker blue,
# distinct from dim-grey secondary text. 256-color index 25 (DeepSkyBlue4); 4 is the 8-color fallback.
REF_ANSI = "38;5;25"
REF_CURSES_256 = 25
REF_CURSES_8 = 4


def paint(text: str, code: str, *, color: bool = True) -> str:
    """Wrap ``text`` in an ANSI SGR ``code`` (e.g. ``"36;1"``) when ``color`` and a code exist."""
    return text if (not color or not code) else f"\033[{code}m{text}\033[0m"


def strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)


# --- agents -------------------------------------------------------------------------------
# Cyans/greens cycled for the worker (child_b) agents so each track reads as its own voice.
_WORKER_CYCLE = ["36", "32", "92", "94", "96", "34"]


def _digits(s: str) -> str:
    return "".join(ch for ch in s if ch.isdigit())


def agent_identity(agent: str) -> tuple[str, str, str]:
    """Return ``(short_label, ansi_color, semantic_key)`` for an agent name.

    ``semantic_key`` lets the curses cockpit map to its own color pairs without re-deriving
    the classification. Child C subagents (``child_b1.C3``) inherit their parent's identity.
    """
    base = agent.split(".")[0]
    if base == "parent_a":
        return "A", "35;1", "parent"
    if base.startswith("falsifier"):
        return "F", "33", "falsifier"
    if base.startswith("poc_prover") or base == "prover":
        return "PoC", "34", "prover"
    if base.startswith("fuzzer"):
        return "Z" + (_digits(base) or ""), "96", "fuzzer"
    if base.startswith("child_b"):
        n = _digits(base) or "0"
        return "B" + n, _WORKER_CYCLE[int(n) % len(_WORKER_CYCLE)], "worker"
    if base == "scopeguard":
        return "⛨", "31", "guard"
    if base in ("blackboard", "orchestrator", "operator", "intake", "build_env"):
        return base[:2].upper(), "90", "system"
    return base[:3].upper(), "0", "system"


def agent_tag(agent: str, *, color: bool = True) -> str:
    """A colored ``[B1]`` tag, indented one level for child-C subagents."""
    short, ansi, _ = agent_identity(agent)
    indent = "  " if "." in agent else ""
    return indent + paint(f"[{short}]", ansi, color=color)


# --- severity -----------------------------------------------------------------------------
# label, ansi, rank (lower = worse), curses-color name (for the cockpit's pair map).
SEVERITY: dict[str, tuple[str, str, int, str]] = {
    "critical": ("CRITICAL", "31;1", 0, "crit"),
    "high":     ("HIGH",     "38;5;208", 1, "high"),
    "medium":   ("MEDIUM",   "33", 2, "med"),
    "low":      ("LOW",      "90", 3, "low"),
    "info":     ("INFO",     "90", 4, "low"),
}


def sev_meta(severity: str) -> tuple[str, str, int, str]:
    return SEVERITY.get(str(severity).lower().strip(), ("?", "37", 5, "low"))


def sev_rank(severity: str) -> int:
    return sev_meta(severity)[2]


def sev_badge(severity: str, *, color: bool = True) -> str:
    """A reverse-video severity chip, e.g. ``␣CRITICAL␣``."""
    label, ansi, _, _ = sev_meta(severity)
    return paint(f" {label} ", ansi + ";7", color=color)


# --- inline markdown (shared with the cockpit) -------------------------------------------
# Code spans, **bold**/__bold__, *italic*/_italic_. Bold alts precede italic so `**x**` isn't
# mis-split as two italics.
_MD_RE = re.compile(r"`[^`]+`|\*\*[^*]+\*\*|__[^_]+__|\*[^*\s][^*]*\*|_[^_\s][^_]*_")


def md_segments(text: str) -> list[tuple[str, str | None]]:
    """Split ``text`` into ``(segment, style)`` pairs; style ∈ {None,'bold','italic','code'}."""
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


_MD_ANSI = {"bold": "1", "italic": "3", "code": "7"}  # code as a reverse-video chip


def md_to_ansi(text: str, *, color: bool = True) -> str:
    """Render inline markdown (**bold** / *italic* / `code`) to ANSI for the line viewer; with
    ``color=False`` the markers are simply stripped so the plain text stays clean."""
    parts = []
    for seg, style in md_segments(text):
        parts.append(paint(seg, _MD_ANSI[style], color=color) if (style and color) else seg)
    return "".join(parts)


# --- boxes / cards (ANSI; for the line viewer + snapshot) --------------------------------
def _clip(s: str, width: int) -> str:
    s = strip_ansi(s)
    return s if len(s) <= width else s[: max(0, width - 1)] + "…"


def box(title: str, rows: list[tuple[str, str]], *, width: int = 74, border: str = "90",
        color: bool = True) -> str:
    """A rounded box with ``title`` embedded in the top rule. ``rows`` is ``(ansi_code, text)``;
    text is clipped to the inner width. Plain, width-1 glyphs only so padding stays aligned."""
    inner = max(20, width - 2)
    ttl = f" {title} " if title else ""
    dashes = "─" * max(0, inner - len(strip_ansi(ttl)))
    top = paint(f"╭{ttl}{dashes}╮", border, color=color)
    bot = paint("╰" + "─" * inner + "╯", border, color=color)
    body = []
    for code, text in rows:
        content = _clip(text, inner - 2)
        pad = " " * (inner - 2 - len(content))
        body.append(paint("│ ", border, color=color) + paint(content, code, color=color)
                    + pad + paint(" │", border, color=color))
    return "\n".join([top, *body, bot])


def finding_title(severity: str, *, confirmed: bool = True) -> str:
    """The card's top-rule title, e.g. ``P1 · CONFIRMED`` / ``HIGH · CANDIDATE``."""
    label, _, _, _ = sev_meta(severity)
    tag = "P1" if label == "CRITICAL" else label.title()
    return f"{tag} · {'CONFIRMED' if confirmed else 'CANDIDATE'}"


def finding_rows(*, title: str, location: str = "", lens: str = "", counterfactual: str = "",
                 reproduced_by: str = "", remediation: str = "") -> list[tuple[str, str]]:
    """Shared CONTENT of a finding card as ``(role, text)`` — roles: title|loc|cf|repro|fix.
    Both the ANSI card and the cockpit's curses card render from this, so they stay identical."""
    rows: list[tuple[str, str]] = [("title", title)]
    if location:
        rows.append(("loc", location + (f" · {lens}" if lens else "")))
    if counterfactual:
        rows.append(("cf", f"{ARROW} {counterfactual}"))
    if reproduced_by:
        rows.append(("repro", f"{RESULT} reproduced: {reproduced_by}"))
    if remediation:
        rows.append(("fix", f"fix: {remediation}"))
    return rows


# role → ANSI code for the line/snapshot card.
_ROLE_ANSI = {"title": "1", "loc": "90", "cf": "0", "repro": "32", "fix": "36"}


def finding_card(*, severity: str, title: str, location: str = "", lens: str = "",
                 counterfactual: str = "", reproduced_by: str = "", remediation: str = "",
                 confirmed: bool = True, width: int = 74, color: bool = True) -> str:
    """A prominent ANSI card for one finding — the product of a hunt, rendered to be read first."""
    _, ansi, _, _ = sev_meta(severity)
    rows = finding_rows(title=title, location=location, lens=lens, counterfactual=counterfactual,
                        reproduced_by=reproduced_by, remediation=remediation)
    ansi_rows = [(_ROLE_ANSI.get(role, "0"), text) for role, text in rows]
    return box(finding_title(severity, confirmed=confirmed), ansi_rows,
               width=width, border=ansi, color=color)


def report_card(*, program: str, status: str, rounds: int, reframes: int, p1_count: int,
                candidate_count: int, tokens_total: int = 0, tokens_in: int = 0,
                tokens_out: int = 0, cost: float = 0.0, elapsed_s: float = 0.0,
                brain: str = "", target_class: str = "", next_step: str = "",
                width: int = 74, color: bool = True) -> str:
    """A scannable end-of-run summary card; leads with the P1 count (the headline metric)."""
    p1c = "32;1" if p1_count else "90"
    rows = [
        ("90", f"status     {status}"),
        (p1c,  f"P1 found   {p1_count} confirmed        candidates {candidate_count}"),
        ("90", f"progress   {rounds} round(s) · {reframes} reframe(s)"
               + (f" · {target_class}" if target_class else "")),
    ]
    if tokens_total or cost:
        rows.append(("90", f"cost       {fmt_tokens(tokens_total)} tok "
                           f"(in {fmt_tokens(tokens_in)}/out {fmt_tokens(tokens_out)}) · ${cost:.2f}"
                           + (f" · {fmt_duration(elapsed_s)}" if elapsed_s else "")))
    if next_step:
        rows.append(("36", f"next       {next_step}"))
    title = f"P1HUNT · {program}" + (f" · {brain}" if brain else "")
    return box(title, rows, width=width, border=("32" if p1_count else "36"), color=color)


# --- small formatters --------------------------------------------------------------------
def fmt_tokens(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1e6:.2f}M"
    if n >= 1_000:
        return f"{n / 1e3:.1f}K"
    return str(int(n))


def fmt_duration(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m"
