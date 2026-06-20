"""Tool registry — build the derived toolset behind ScopeGuard (spec §6 step 2, §12)."""

from __future__ import annotations

from ..safety.scopeguard import ScopeGuard
from .apk_inspect import ApkInspect
from .base import GuardedTool, Tool
from .evm_fork import EvmFork
from .http_sandbox import HttpSandbox
from .source_fetch import SourceFetch
from .static_analysis import StaticAnalysis


def _factory(name: str, active: bool) -> Tool | None:
    if name == "source_fetch":
        return SourceFetch()
    if name == "static_analysis":
        return StaticAnalysis()
    if name == "apk_inspect":
        return ApkInspect()
    if name == "http_sandbox":
        return HttpSandbox(active=active)
    if name == "evm_fork":
        return EvmFork(active=active)
    return None


def build_toolset(
    toolset: list[str], guard: ScopeGuard, agent: str, *, active: bool = False
) -> dict[str, GuardedTool]:
    """Instantiate only the derived toolset; each tool is wrapped by ScopeGuard."""
    built: dict[str, GuardedTool] = {}
    for name in toolset:
        tool = _factory(name, active)
        if tool is not None:
            built[name] = GuardedTool(tool, guard, agent)
    return built
