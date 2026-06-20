"""Intake agent — fetches the bug-bounty program and reads the rules (spec §2.1, §2.3).

A real Claude session with web access (WebFetch/WebSearch) that reads the program page,
extracts the safe-harbor rules, severity taxonomy, and in-scope SOURCE repositories, and
maps the researcher's focus (e.g. "Seaport" in "OpenSea") to repo paths. Returns a
structured scope brief the launcher confirms with the human before any hunting begins.
"""

from __future__ import annotations

import tempfile

from .agents.claude_session import ClaudeSession
from .agents.claude_swarm import _parse_json_object


def _prompt(name: str, url: str, focus: str) -> str:
    focus_line = f'The researcher wants to focus on: "{focus}".' if focus else "The researcher wants to hunt the entire program."
    return f"""You are a bug-bounty intake analyst. A researcher is preparing an AUTHORIZED audit of the
program "{name}".
Program URL: {url}
{focus_line}

Use WebFetch and WebSearch to read the program's scope and rules (try the URL, and search for
the program's scope/repository if the page is thin). Determine, grounded in what you find:
- a 2-3 sentence summary of what the target system is and its threat model,
- the key safe-harbor / testing rules (what is allowed and what is prohibited),
- the severity taxonomy — specifically what the program counts as critical / P1,
- the in-scope assets, and especially the SOURCE-CODE repositories (git/GitHub URLs),
- if a focus area was given, the repository path(s) that correspond to it.

Return ONLY JSON (no prose):
{{"summary":"...",
  "rules":["short rule", "..."],
  "critical_means":"what the program treats as critical/P1",
  "in_scope":[{{"label":"...","value":"...","kind":"repo|contract|domain"}}],
  "repos":["https://github.com/org/repo"],
  "focus_paths":["relative/dir/if/any"],
  "rate_limit":"if stated",
  "notes":"anything important, e.g. if scope is unclear"}}"""


async def research_program(name: str, url: str, focus: str, *, model: str | None, on_event=None) -> dict:
    """Run the intake agent. Returns the parsed brief, or {} if unavailable/unparseable."""
    with tempfile.TemporaryDirectory() as tmp:
        session = ClaudeSession(
            agent_name="intake", model=model, on_event=on_event or (lambda *_a: None),
            guard_check=None, max_turns=20,
        )
        result = await session.run(_prompt(name, url, focus), tmp)
    brief = _parse_json_object(result.text)
    brief["_ok"] = bool(result.ok and brief)
    brief["_error"] = result.error
    return brief
