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
    # DISCOVERY ENGINE: which model drives the HUNTERS (the discovery phase). "claude" (default)
    # runs the Claude hunters; "codex" runs OpenAI's Codex CLI (GPT-5.5-Codex) at xhigh reasoning
    # — a second strong model to widen what gets found (EVMbench model-alloy). Verification, PoC,
    # and the exploit-development depth phase ALWAYS stay on Claude regardless.
    discovery_engine: str = "claude"        # "claude" | "codex"
    codex_model: str = ""                   # "" = codex account default (ChatGPT auth rejects slugs)
    codex_effort: str = "xhigh"             # minimal | low | medium | high | xhigh


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
    # Which Claude account the swarm authenticates as, via CLAUDE_CONFIG_DIR (mirrors the shell
    # aliases: c5 -> ~/.claude-5x [Max 5x], c20 -> ~/.claude-20x [Max 20x]). Lets a run use a
    # fresh-quota account instead of an exhausted one. "" leaves CLAUDE_CONFIG_DIR untouched.
    claude_account: str = "c5"
    claude_config_dir: str = ""  # resolved CLAUDE_CONFIG_DIR actually applied (for visibility)
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
    # Auto-provision the reproduction TOOLCHAIN (Foundry: forge/anvil) when it is missing. The
    # confirmed-critical gate cannot fire without it — on an EVM target with no forge, every
    # candidate is quarantined forever. OFF by default because it executes the official remote
    # installer; opt in with P1HUNT_AUTO_INSTALL_TOOLCHAIN=1 (needs provision_network). It only
    # installs a well-known toolchain and never weakens the artifact floor.
    auto_install_toolchain: bool = False
    # Authorized LIVE dynamic target (web/API/auth — the bulk of bug bounty). When set together
    # with run_mode=active, the CLI attaches a DynamicTarget so the swarm can interact with the
    # RUNNING instance and prove web criticals (IDOR/SSRF/auth-bypass) instead of only reading
    # source. Never a production URL — only a UAT/owned/testnet/staging instance. Empty = static.
    live_base_url: str = ""        # P1HUNT_BASE_URL  (REST/HTTP)
    live_gql_url: str = ""         # P1HUNT_GQL_URL   (GraphQL)
    live_environment: str = "uat"  # P1HUNT_LIVE_ENV  (uat | owned | testnet | staging | local)

    def apply_claude_account(self) -> None:
        """Resolve ``claude_account`` -> ``CLAUDE_CONFIG_DIR`` so the Claude CLI/SDK authenticates as
        the chosen account (c5 -> ~/.claude-5x, c20 -> ~/.claude-20x; or P1HUNT_CLAUDE_CONFIG_DIR for
        a direct path). Only applied when the dir exists, so it never breaks a host lacking it. Set
        in os.environ so every Claude subprocess the swarm spawns inherits it."""
        acct = (self.claude_account or "").strip().lower()
        cfgdir = os.environ.get("P1HUNT_CLAUDE_CONFIG_DIR", "").strip()
        if not cfgdir:
            if acct in ("c5", "5x"):
                cfgdir = os.path.expanduser("~/.claude-5x")
            elif acct in ("c20", "20x"):
                cfgdir = os.path.expanduser("~/.claude-20x")
        if cfgdir and os.path.isdir(cfgdir):
            os.environ["CLAUDE_CONFIG_DIR"] = cfgdir
            self.claude_config_dir = cfgdir
        else:
            self.claude_config_dir = os.environ.get("CLAUDE_CONFIG_DIR", "")

    @classmethod
    def from_env(cls) -> "Config":
        cfg = cls()
        cfg.run_mode = os.environ.get("P1HUNT_RUN_MODE", cfg.run_mode)
        cfg.engagements_root = os.environ.get("P1HUNT_ENGAGEMENTS", cfg.engagements_root)
        cfg.unattended = os.environ.get("P1HUNT_UNATTENDED", "1") != "0"
        # CLAUDE ACCOUNT: select which logged-in account the swarm uses (fresh quota vs exhausted).
        cfg.claude_account = os.environ.get("P1HUNT_CLAUDE_ACCOUNT", cfg.claude_account)
        cfg.apply_claude_account()
        # The real detector is a Claude swarm — enabled whenever the Claude Agent SDK + CLI
        # are reachable (no API key needed; uses the local `claude` auth). Override with
        # P1HUNT_USE_CLAUDE=0/1. Falls back to the deterministic brain when unavailable.
        from .agents.claude_session import sdk_available

        env_flag = os.environ.get("P1HUNT_USE_CLAUDE")
        cfg.use_claude = (env_flag == "1") if env_flag is not None else sdk_available()
        # DISCOVERY ENGINE selector (Claude hunters by default; Codex GPT-5.5-Codex xhigh opt-in).
        _eng = os.environ.get("P1HUNT_DISCOVERY_ENGINE", cfg.models.discovery_engine).strip().lower()
        cfg.models.discovery_engine = _eng if _eng in ("claude", "codex") else "claude"
        cfg.models.codex_model = os.environ.get("P1HUNT_CODEX_MODEL", cfg.models.codex_model)
        cfg.models.codex_effort = os.environ.get("P1HUNT_CODEX_EFFORT", cfg.models.codex_effort)
        cfg.provision = os.environ.get("P1HUNT_PROVISION", "1") != "0"
        cfg.provision_network = os.environ.get("P1HUNT_PROVISION_NETWORK", "1") != "0"
        cfg.auto_install_toolchain = os.environ.get("P1HUNT_AUTO_INSTALL_TOOLCHAIN", "0") == "1"
        cfg.fork_rpc_url = os.environ.get("P1HUNT_FORK_RPC_URL", cfg.fork_rpc_url)
        _blk = os.environ.get("P1HUNT_FORK_BLOCK", "")
        if _blk.strip().isdigit():
            cfg.fork_block = int(_blk.strip())
        cfg.live_base_url = os.environ.get("P1HUNT_BASE_URL", cfg.live_base_url)
        cfg.live_gql_url = os.environ.get("P1HUNT_GQL_URL", cfg.live_gql_url)
        cfg.live_environment = os.environ.get("P1HUNT_LIVE_ENV", cfg.live_environment)
        if not _has_agent_credentials():
            cfg.run_mode = "dry_run"
        return cfg

    def dynamic_targets(self) -> list:
        """Build DynamicTarget(s) from the configured live URLs (CLI convenience for ad-hoc hunts).
        Empty unless a live URL was provided. A ``production`` environment is REFUSED outright (not
        relabeled) — production is never an authorized live target, so a misconfigured
        P1HUNT_LIVE_ENV=production yields no dynamic target rather than a silently-downgraded one."""
        from .models import DynamicTarget
        env = (self.live_environment or "uat").strip().lower()
        if env == "production":
            return []  # never authorize production for live contact (safe-harbor floor)
        out = []
        if self.live_base_url:
            out.append(DynamicTarget(base_url=self.live_base_url, environment=env, kind="rest"))
        if self.live_gql_url:
            out.append(DynamicTarget(base_url=self.live_gql_url, environment=env, kind="graphql"))
        return out

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
