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
    """Per-tier model strings (Claude 5 family). Orchestrator/verifier on the strongest
    tier — Fable 5.2, whose 1M context carries the long-horizon never-quit loop's
    accumulated record of what has already been tried — workers a step down on Opus 5.5,
    warm-pool watcher cheapest on Haiku 5.5 (§3)."""

    orchestrator: str = "claude-fable-5-2"  # current Claude slug, ignored when engine=codex
    worker: str = "claude-opus-5-5"         # current Claude slug, ignored when engine=codex
    warm_pool: str = "claude-haiku-5-5"     # current Claude slug, ignored when engine=codex
    falsifier: str = "claude-fable-5-2"     # current Claude slug, ignored when engine=codex
    # GLOBAL ENGINE: Codex is the default for EVERY AI role: orchestrator, hunters, verifier,
    # prover, exploit-depth, debate, dedup, and fuzz harness writing. The Claude model strings
    # stay only as compatibility fields for explicit P1HUNT_ENGINE=claude runs.
    engine: str = "codex"                  # GLOBAL engine for ALL roles ("codex" | "claude")
    discovery_engine: str = "codex"        # discovery hunters; follows engine unless overridden
    codex_model: str = ""                   # "" = codex account default (ChatGPT auth rejects slugs)
    codex_effort: str = "xhigh"             # minimal | low | medium | high | xhigh


@dataclass
class Budgets:
    """Per-track ceilings. Exhaustion DEMOTES to warm-pool; it never ends an engagement (§8)."""

    max_frames_per_track: int = 120
    max_subagents_per_track: int = 8
    max_tokens_per_track: int | None = None
    warm_pool_cadence_seconds: float = 60.0
    # PERSISTENCE DIALS (§8). A frame closes only after this many CONSECUTIVE dry passes -- one
    # dry round is not evidence that a surface is exhausted. Escalation re-enters a CONFIRMED
    # finding into the hunt (remove a precondition / find an unconditional location / widen blast
    # radius) instead of terminating on it; set max_escalation_attempts=0 to restore the old
    # terminate-on-confirmation behavior. Escalation is bounded per-finding AND engagement-wide,
    # and the bound survives a restart by counting attempts already recorded on disk.
    frame_falsify_after: int = 3
    max_escalation_attempts: int = 3
    max_escalation_total: int = 24
    conclusion_min_members: int = 3
    asymmetry_max_probes: int = 200
    ruled_out_in_brief: int = 40


@dataclass
class Config:
    models: Models = field(default_factory=Models)
    budgets: Budgets = field(default_factory=Budgets)
    run_mode: str = "dry_run"  # dry_run (default) | active (still fully gated by ScopeGuard)
    permission_mode: str = "deny"  # most restrictive default; never "ask" unattended (§3, §9)
    unattended: bool = True
    use_claude: bool = False  # legacy name: true means the live AI swarm is enabled (§3)
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
    # RUNNING instance and prove engagement-derived web/API criticals instead of only reading
    # source. Never a production URL — only a UAT/owned/testnet/staging instance. Empty = static.
    live_base_url: str = ""        # P1HUNT_BASE_URL  (REST/HTTP)
    live_gql_url: str = ""         # P1HUNT_GQL_URL   (GraphQL)
    live_environment: str = "uat"  # P1HUNT_LIVE_ENV  (uat | owned | testnet | staging | local)

    def apply_claude_account(self) -> None:
        """Resolve ``claude_account`` -> ``CLAUDE_CONFIG_DIR`` for explicit Claude-engine runs.

        Only applied when the dir exists, so it never breaks Codex-default hosts lacking a Claude
        account. Set in os.environ so compatibility subprocesses inherit it."""
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
        # The real detector is the live AI swarm. Codex is the default engine; Claude remains only
        # as an explicit compatibility engine. P1HUNT_USE_AGENT is the preferred on/off switch;
        # P1HUNT_USE_CLAUDE is accepted as a legacy alias.
        from .agents.claude_session import engine_available

        # GLOBAL ENGINE: P1HUNT_ENGINE=codex runs the ENTIRE swarm on Codex — orchestrator, hunters,
        # falsifier, prover, exploit-developer, debate, dedup, fuzz — so NOTHING depends on Claude Code.
        _global_eng = os.environ.get("P1HUNT_ENGINE", "codex").strip().lower()
        if _global_eng not in ("claude", "codex"):
            _global_eng = "codex"
        os.environ["P1HUNT_ENGINE"] = _global_eng  # canonical value the make_session factory reads
        cfg.models.engine = _global_eng
        # DISCOVERY ENGINE: explicit override, else FOLLOWS the global engine (so codex-global => codex discovery).
        _eng = os.environ.get("P1HUNT_DISCOVERY_ENGINE", _global_eng).strip().lower()
        cfg.models.discovery_engine = _eng if _eng in ("claude", "codex") else _global_eng
        # AI brain is ON iff the chosen engine is actually runnable (codex CLI / claude SDK+CLI).
        env_flag = os.environ.get("P1HUNT_USE_AGENT", os.environ.get("P1HUNT_USE_CLAUDE"))
        cfg.use_claude = (env_flag == "1") if env_flag is not None else engine_available(_global_eng)
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
        # Active dynamic testing needs a runnable agent brain, but that may be local Claude CLI auth
        # or the Codex CLI. Do not key this off Anthropic API env vars only.
        if cfg.run_mode == "active" and not cfg.use_claude:
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


def _has_agent_credentials(engine: str = "") -> bool:
    eng = (engine or os.environ.get("P1HUNT_ENGINE", "codex")).strip().lower()
    if eng == "codex":
        try:
            from .agents.codex_session import codex_available
            return codex_available()
        except Exception:
            return False
    return any(
        os.environ.get(name)
        for name in (
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_USE_VERTEX",
            "CLAUDE_CODE_USE_GATEWAY",
        )
    )
