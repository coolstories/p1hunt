"""Tool interface contract (spec §12).

Tools are pluggable and **non-destructive by construction**. The system ships the
*interfaces* and safe defaults; no module contains weaponized/destructive payloads. Every
tool runs **behind ScopeGuard** — the wrapper calls the PreToolUse gate before execution
and refuses to run a denied action. The safe path is "no such tool is available."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..safety.scopeguard import ScopeGuard


@dataclass
class ToolResult:
    ok: bool
    tool: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    denied: bool = False
    reason: str = ""


@runtime_checkable
class Tool(Protocol):
    name: str
    read_only: bool

    async def run(self, args: dict) -> ToolResult: ...


class GuardedTool:
    """Wraps a Tool so every call passes ScopeGuard first (§12, §9)."""

    def __init__(self, tool: Tool, guard: ScopeGuard, agent: str) -> None:
        self._tool = tool
        self._guard = guard
        self._agent = agent

    @property
    def name(self) -> str:
        return self._tool.name

    async def run(self, args: dict) -> ToolResult:
        guard_input = dict(args)
        guard_input.setdefault("read_only", getattr(self._tool, "read_only", True))
        decision = self._guard.pre_tool_use(self._agent, self._tool.name, guard_input)
        if not decision.allow:
            return ToolResult(
                ok=False,
                tool=self._tool.name,
                summary=f"ScopeGuard denied: {decision.reason}",
                denied=True,
                reason=decision.reason,
            )
        return await self._tool.run(args)
