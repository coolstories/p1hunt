"""Intake agent — finds the bug-bounty program and reads the rules (spec §2.1, §2.3).

An engine-agnostic live AI session with web access that — given a program NAME (+ platform) or an
explicit URL — locates the official program page, reads the safe-harbor rules and severity taxonomy,
and extracts the IN-SCOPE source repositories and the OUT-OF-SCOPE assets. Returns a structured
scope brief the launcher confirms before any hunting begins.

NOTHING PRESET (spec §1): there is no built-in program/scope database. Everything is researched
live from the program's own page; if it can't be confirmed, the brief says so and stays empty
(the launcher refuses to guess at scope).
"""

from __future__ import annotations

import tempfile

from .agents.claude_session import make_session
from .agents.claude_swarm import _parse_json_object


def _prompt(name: str, url: str, focus: str, platform: str) -> str:
    if url:
        locate = f"Program URL (start here): {url}"
    else:
        where = f"on the {platform} platform" if platform and platform not in ("", "local") else ""
        locate = (
            f'No URL was given — use WebSearch to FIND the OFFICIAL bug-bounty program page for "{name}" '
            f'{where} (e.g. search \'{name} {platform} bug bounty scope\', then open the program page).'
        )
    focus_line = (
        f'The researcher will audit ONLY: "{focus}". Identify the single in-scope asset/repository that corresponds to it.'
        if focus else "The researcher may hunt any in-scope asset."
    )
    return f"""You are a bug-bounty intake analyst preparing an AUTHORIZED audit of the program "{name}".
{locate}
{focus_line}

Use WebFetch and WebSearch to locate and READ the program's scope and rules. Ground EVERYTHING in
what you actually find on the program's own page. If you cannot confirm the program or its scope,
say so in "notes" and leave the lists EMPTY — do NOT guess or invent repositories.

Determine:
- the official program/policy URL you used,
- whether the program offers SAFE HARBOR / authorizes this security testing (true/false),
- a 2-3 sentence summary of the target system and its threat model,
- the safe-harbor / testing rules (what is allowed and what is prohibited),
- the severity taxonomy — specifically what the program treats as critical / P1,
- the IN-SCOPE assets, especially the SOURCE-CODE repositories (git/GitHub URLs),
- the OUT-OF-SCOPE assets/paths the program explicitly excludes,
- if a focus area was given, the repository path(s) that correspond to it.

Return ONLY JSON (no prose):
{{"summary":"...",
  "safe_harbor":true,
  "policy_url":"https://...",
  "rules":["short rule", "..."],
  "critical_means":"what the program treats as critical/P1",
  "in_scope":[{{"label":"...","value":"...","kind":"repo|contract|domain"}}],
  "repos":["https://github.com/org/repo"],
  "out_of_scope":[{{"label":"...","value":"...","kind":"repo|domain|path"}}],
  "focus_paths":["relative/dir/if/any"],
  "rate_limit":"if stated",
  "notes":"anything important, e.g. if scope is unclear or unconfirmed"}}"""


async def research_program(
    name: str, url: str, focus: str, *, platform: str = "", model: str | None, on_event=None,
    engine: str | None = None, codex_model: str | None = None, codex_effort: str | None = None,
) -> dict:
    """Run the intake agent. ``url`` may be empty — then the agent searches ``platform`` for the
    program by name. Returns the parsed brief, or a brief with ``_ok=False`` if unavailable."""
    with tempfile.TemporaryDirectory() as tmp:
        session = make_session(
            agent_name="intake", model=model, on_event=on_event or (lambda *_a: None),
            guard_check=None, max_turns=24, engine=engine,
            codex_model=codex_model, effort=codex_effort,
            allow_web=True, web_budget=8,
        )
        result = await session.run(_prompt(name, url, focus, platform), tmp)
    brief = _parse_json_object(result.text)
    brief["_ok"] = bool(result.ok and brief)
    brief["_error"] = result.error
    return brief
