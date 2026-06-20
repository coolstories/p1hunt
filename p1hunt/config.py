"""Configuration (spec §13).

Models, run mode, budgets, program registry, and warm-pool cadence. `run_mode` defaults
to ``dry_run`` — active actions are disabled until explicitly enabled by config *and* an
in-scope check (§9). Budgets are throttles, not stops (§8).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Models:
    """Per-tier model strings (verify current). Orchestrator/verifier on the strongest
    tier, workers a step down, warm-pool watcher cheapest (§3)."""

    orchestrator: str = "claude-opus-4-8"
    worker: str = "claude-opus-4-8"   # the reasoning hunters run on the strongest model — deep
    #                                   reasoning is the primary way a P1 is found on hardened code
    warm_pool: str = "claude-haiku-4-5"
    falsifier: str = "claude-opus-4-8"


@dataclass
class Budgets:
    """Per-track ceilings. Exhaustion DEMOTES to warm-pool; it never ends an engagement (§8)."""

    max_frames_per_track: int = 24
    max_subagents_per_track: int = 8
    max_tokens_per_track: int | None = None
    warm_pool_cadence_seconds: float = 60.0


@dataclass
class Config:
    models: Models = field(default_factory=Models)
    budgets: Budgets = field(default_factory=Budgets)
    run_mode: str = "dry_run"  # dry_run (default) | active (still fully gated by ScopeGuard)
    permission_mode: str = "deny"  # most restrictive default; never "ask" unattended (§3, §9)
    unattended: bool = True
    use_claude: bool = False  # the AI is the detector: real Claude swarm when available (§3)
    engagements_root: str = "engagements"
    program_registry: str = ""  # how to fetch program brief, rules, taxonomy (§13)
    # Controlled build-environment bootstrap of the audit target (fetch submodules, install
    # declared deps, compile) BEFORE the swarm hunts — the unblocker that lets fuzz/PoC stages
    # actually deploy and run a target that does not compile from a bare clone. Provisioning is a
    # narrow, logged, allowlisted audit-target provisioner (build_env.py), separate from the
    # agent bash filter; `provision_network` lets it fetch the target's declared dependencies.
    provision: bool = True
    provision_network: bool = True
    # Optional mainnet-fork RPC for EVM targets: the swarm starts a LOCAL anvil fork (127.0.0.1
    # only, never a mainnet write) so PoCs/fuzzers can run against real on-chain token/proxy
    # state via `forge test --fork-url`. Empty = no fork (local-deploy harnesses only).
    fork_rpc_url: str = ""
    fork_block: int | None = None

    @classmethod
    def from_env(cls) -> "Config":
        cfg = cls()
        cfg.run_mode = os.environ.get("P1HUNT_RUN_MODE", cfg.run_mode)
        cfg.engagements_root = os.environ.get("P1HUNT_ENGAGEMENTS", cfg.engagements_root)
        cfg.unattended = os.environ.get("P1HUNT_UNATTENDED", "1") != "0"
        # The real detector is a Claude swarm — enabled whenever the Claude Agent SDK + CLI
        # are reachable (no API key needed; uses the local `claude` auth). Override with
        # P1HUNT_USE_CLAUDE=0/1. Falls back to the deterministic brain when unavailable.
        from .agents.claude_session import sdk_available

        env_flag = os.environ.get("P1HUNT_USE_CLAUDE")
        cfg.use_claude = (env_flag == "1") if env_flag is not None else sdk_available()
        cfg.provision = os.environ.get("P1HUNT_PROVISION", "1") != "0"
        cfg.provision_network = os.environ.get("P1HUNT_PROVISION_NETWORK", "1") != "0"
        cfg.fork_rpc_url = os.environ.get("P1HUNT_FORK_RPC_URL", cfg.fork_rpc_url)
        _blk = os.environ.get("P1HUNT_FORK_BLOCK", "")
        if _blk.strip().isdigit():
            cfg.fork_block = int(_blk.strip())
        if not _has_agent_credentials():
            cfg.run_mode = "dry_run"
        return cfg

    @property
    def active(self) -> bool:
        return self.run_mode == "active"


def _has_agent_credentials() -> bool:
    return any(
        os.environ.get(name)
        for name in (
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_USE_VERTEX",
            "CLAUDE_CODE_USE_GATEWAY",
        )
    )
