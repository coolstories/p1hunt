"""Best-effort hot reload support for long-running hunts.

Python cannot safely replace an arbitrary active coroutine frame in the middle of a round. This
module implements the useful, safe subset: at a round boundary, reload prompt/session/helper modules,
rebind existing role objects to the fresh classes, and refresh env-backed scheduler knobs. That lets
prompt, parser, Codex-session, verifier/prover/depth, and many orchestration-helper fixes apply to a
running hunt without a full restart. Changes to the currently executing `hunt()` loop body still need
a resume/restart to be guaranteed.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
from types import ModuleType
from typing import Any

DEFAULT_RELOAD_MODULES: tuple[str, ...] = (
    "p1hunt.config",
    "p1hunt.agents.claude_session",
    "p1hunt.agents.codex_session",
    "p1hunt.agents.fuzz_engine",
    "p1hunt.agents.claude_hunter",
    "p1hunt.severity",
    "p1hunt.runners.base",
    "p1hunt.runners.web",
    "p1hunt.agents.claude_swarm",
)


def _reload_module(name: str) -> tuple[str, str]:
    if not name.startswith("p1hunt."):
        return "skipped", "outside p1hunt package"
    mod = sys.modules.get(name)
    if not isinstance(mod, ModuleType):
        return "skipped", "not loaded"
    importlib.reload(mod)
    return "reloaded", ""


def _rebind_instance(obj: Any) -> bool:
    """Move an existing pure-Python instance onto the freshly reloaded class object."""
    if obj is None:
        return False
    cls = getattr(obj, "__class__", None)
    mod_name = getattr(cls, "__module__", "")
    cls_name = getattr(cls, "__name__", "")
    mod = sys.modules.get(mod_name)
    if not isinstance(mod, ModuleType) or not cls_name:
        return False
    fresh = getattr(mod, cls_name, None)
    if fresh is None or fresh is cls:
        return False
    try:
        obj.__class__ = fresh
        return True
    except TypeError:
        return False


def _int_env(name: str, default: int, *, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.environ.get(name, str(default)) or default))
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)) or default)
    except ValueError:
        return default


def _refresh_swarm_knobs(swarm: Any) -> list[str]:
    """Refresh mutable env-backed knobs that are safe at round boundaries."""
    changed: list[str] = []

    old = getattr(swarm, "_deep_discovery", False)
    swarm._deep_discovery = os.environ.get("P1HUNT_DEEP_DISCOVERY", "0") == "1"
    if old != swarm._deep_discovery:
        changed.append("deep_discovery")

    max_concurrency = _int_env("P1HUNT_MAX_CONCURRENCY", 0)
    if max_concurrency <= 0:
        max_concurrency = 3
        if swarm._deep_discovery:
            max_concurrency = min(max_concurrency, _int_env("P1HUNT_DEEP_DISCOVERY_CONCURRENCY", 3, minimum=1))
    if getattr(swarm, "_max_concurrency", None) != max_concurrency:
        swarm._max_concurrency = max_concurrency
        swarm.sem = asyncio.Semaphore(max_concurrency)
        changed.append("child_concurrency")

    side_concurrency = _int_env("P1HUNT_SIDE_LANE_CONCURRENCY", 1, minimum=1)
    if getattr(swarm, "_side_lane_concurrency", None) != side_concurrency:
        swarm._side_lane_concurrency = side_concurrency
        swarm.side_sem = asyncio.Semaphore(side_concurrency)
        changed.append("side_lane_concurrency")

    old_cap = getattr(swarm, "_cost_cap", None)
    cap = _float_env("P1HUNT_MAX_COST_USD", 0.0)
    swarm._cost_cap = cap if cap > 0 else None
    if old_cap != swarm._cost_cap:
        changed.append("cost_cap")

    old_max = getattr(swarm, "_max_criticals", None)
    max_crit = _int_env("P1HUNT_MAX_CRITICALS", 0)
    swarm._max_criticals = max_crit if max_crit > 0 else None
    if old_max != swarm._max_criticals:
        changed.append("max_criticals")

    old_debate = getattr(swarm, "_debate_max", 3)
    swarm._debate_max = _int_env("P1HUNT_DEBATE_MAX", 3, minimum=0)
    if old_debate != swarm._debate_max:
        changed.append("debate_max")

    old_deepdive = getattr(swarm, "_deepdive_on", True)
    swarm._deepdive_on = os.environ.get("P1HUNT_DEEPDIVE", "1") != "0"
    if old_deepdive != swarm._deepdive_on:
        changed.append("deepdive")
    swarm._deepdive_top_n = _int_env("P1HUNT_DEEPDIVE_TOP_N", 4, minimum=1)
    swarm._deepdive_turns = _int_env("P1HUNT_DEEPDIVE_TURNS", 60, minimum=20)
    swarm._lead_max_attempts = _int_env("P1HUNT_LEAD_MAX_ATTEMPTS", 10, minimum=1)
    changed.extend(["deepdive_budget", "lead_attempt_budget"])

    try:
        from .config import Config

        fresh = Config.from_env()
        swarm.config.models = fresh.models
        swarm.config.use_claude = fresh.use_claude
        if hasattr(swarm, "_configure_engine"):
            swarm._configure_engine()
        changed.append("model_routing")
    except Exception:
        pass

    return list(dict.fromkeys(changed))


def apply_runtime_reload(owner: Any | None = None, *, modules: list[str] | None = None) -> dict:
    """Apply a safe hot reload and return a JSON-safe summary."""
    importlib.invalidate_caches()
    requested = [str(m).strip() for m in (modules or DEFAULT_RELOAD_MODULES) if str(m).strip()]
    reloaded: list[str] = []
    skipped: dict[str, str] = {}
    for name in requested:
        status, reason = _reload_module(name)
        if status == "reloaded":
            reloaded.append(name)
        else:
            skipped[name] = reason

    rebound: list[str] = []
    if owner is not None and _rebind_instance(owner):
        rebound.append("swarm")
    if owner is not None:
        for role in list(getattr(owner, "_live_hunters", []) or []):
            if _rebind_instance(role):
                rebound.append(getattr(role, "agent_name", role.__class__.__name__))
        roles = getattr(owner, "_live_roles", {}) or {}
        for name, role in list(roles.items()):
            if isinstance(role, list):
                for item in role:
                    if _rebind_instance(item):
                        rebound.append(getattr(item, "agent_name", str(name)))
            elif _rebind_instance(role):
                rebound.append(getattr(role, "agent_name", str(name)))

    refreshed = _refresh_swarm_knobs(owner) if owner is not None else []
    return {
        "reloaded": reloaded,
        "skipped": skipped,
        "rebound": rebound,
        "refreshed": refreshed,
        "limitations": (
            "Applied at a round boundary. Existing active coroutine frames keep their current "
            "bytecode; prompt/session/helper/class changes apply to future role calls. Restart or "
            "resume is still required for guaranteed changes to the main hunt loop body."
        ),
    }
