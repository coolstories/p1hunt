"""Data models (spec §5).

Everything domain-specific is *derived at runtime* (§2, §6). These structures are the
shared vocabulary the orchestrator, agents, ScopeGuard, and UI all speak. Nothing in
this module encodes a per-target surface list, hypothesis list, tool set, or playbook.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class TargetClass(Enum):
    """Derived by the classifier (§6 step 1) from the artifacts themselves."""

    EVM_CONTRACT = "EVM_CONTRACT"
    CRYPTO_LIB = "CRYPTO_LIB"
    MOBILE_APP = "MOBILE_APP"
    WEB_API = "WEB_API"
    INFRA = "INFRA"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    OTHER = "OTHER"  # derived, extensible


class EngagementStatus(Enum):
    INTAKE = "INTAKE"
    READY = "READY"
    RUNNING = "RUNNING"
    WARM_POOL = "WARM_POOL"
    BLOCKED_NEEDS_HUMAN_SCOPE_DECISION = "BLOCKED_NEEDS_HUMAN_SCOPE_DECISION"
    REPORT_READY = "REPORT_READY"
    STOPPED = "STOPPED"


class HypState(Enum):
    OPEN = "OPEN"
    TESTING = "TESTING"
    FALSIFIED = "FALSIFIED"
    CANDIDATE = "CANDIDATE"
    CONFIRMED = "CONFIRMED"


@dataclass
class Asset:
    id: str
    label: str
    kind: str  # "domain" | "repo" | "package" | "contract" | "apk" | "host" | "other"
    value: str
    environment: str = "unknown"  # local | fork | testnet | uat | production | unknown


@dataclass
class Scope:
    """Captured at intake (§2.3). `rules` are raw program text, parsed into policy by §6."""

    program: str
    platform: str = ""
    disclosure_channel: str = ""
    safe_harbor_text: str = ""
    severity_taxonomy: dict[str, str] = field(default_factory=dict)  # the PROGRAM's own chart
    in_scope: list[Asset] = field(default_factory=list)
    out_of_scope: list[Asset] = field(default_factory=list)
    ambiguous: list[Asset] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    rate_limit: str = ""
    source_urls: list[str] = field(default_factory=list)
    # Path globs that are present in the repo but NOT the in-scope deployed code (e.g. a
    # reference implementation, tests, helpers). Findings here are never promoted to P1s — the
    # code is used only as a readable oracle for differential analysis.
    out_of_scope_globs: list[str] = field(default_factory=list)
    scope_note: str = ""  # free-text rules-of-engagement note surfaced to Parent A + hunters
    captured_at: float = field(default_factory=time.time)


@dataclass
class ScopeGuardPolicy:
    """Engagement-specific (§6 step 5, §9). Contents are derived, never preset."""

    allowlist: list[str] = field(default_factory=list)
    destructive_denylist: list[str] = field(default_factory=list)
    out_of_scope_denylist: list[str] = field(default_factory=list)
    sandbox_environments: list[str] = field(default_factory=list)
    allowed_http_methods: list[str] = field(default_factory=list)
    allowed_chain_ids: list[int] = field(default_factory=list)
    max_requests_per_minute: int = 0
    unattended_mode: bool = True
    run_mode: str = "dry_run"  # dry_run | active (active still fully gated, §13)
    evidence_mode: str = "least-data"


@dataclass
class ImpactSurface:
    """Output of surface mapping (§2.4). Ranked by reachability -> impact for THIS target."""

    id: str
    title: str
    lens: str  # one of the §2.4 critical lenses
    target_asset: str
    trust_boundary: str
    safe_validation_environment: str
    criticality_rationale: str
    priority: int


@dataclass
class EngagementPlan:
    """100% derived by Parent A (§6) — nothing preset."""

    target_class: TargetClass
    toolset: list[str]
    surface_ranking: list[ImpactSurface]
    hypothesis_seeds: list[str]
    scopeguard_policy: ScopeGuardPolicy
    impact_definition: str  # what "P1" means under THIS program's taxonomy
    derived_at: float = field(default_factory=time.time)


@dataclass
class ArtifactRef:
    """A reproduced artifact (§10) — a PoC, fork test, decode proof, etc."""

    id: str
    kind: str  # "repro" | "falsifier" | "log" | "screenshot" | "fork-trace"
    path: str
    description: str
    reproduced: bool = False  # the anti-hallucination floor; promotion requires True


@dataclass
class SafeValidationPlan:
    environment: str  # local | fork | testnet | UAT | owned-account live check
    max_contact: str  # read-only or explicitly permitted low-rate action
    data_handling: str  # synthetic, owned, redacted, or aggregate only


@dataclass
class Hypothesis:
    """Written before any testing (§2.6). No safe_validation_plan + stop_conditions => no test."""

    id: str
    claim: str
    owner_agent: str
    lens: str
    target_assets: list[str]
    assumptions: list[str]
    safe_validation_plan: SafeValidationPlan
    stop_conditions: list[str]
    evidence_required: list[str]
    state: HypState = HypState.OPEN
    evidence: list[ArtifactRef] = field(default_factory=list)
    counterfactual: str | None = None  # filled before promotion (§10)

    def is_testable(self) -> bool:
        return bool(self.safe_validation_plan and self.stop_conditions)


@dataclass
class Finding:
    """Exists ONLY when backed by a reproduced artifact (§10, §2.8)."""

    id: str
    hypothesis_id: str
    title: str
    root_cause: str
    poc: ArtifactRef  # MUST be present and reproduced
    severity: str
    severity_rationale: str  # leads with the counterfactual, not a dollar figure
    counterfactual: str
    remediation: str
    safe_harbor_attestation: str  # generated from the guard decision log
    verified: bool = True  # False = surfaced but auto-verification was unavailable (needs human)


@dataclass
class ControlDirective:
    """operator -> agent, consumed at a hook checkpoint (§11)."""

    target_agent: str
    kind: str  # "steer" | "pause" | "resume" | "stop" | "focus"
    payload: str
    id: str = field(default_factory=lambda: new_id("ctrl"))
    ts: float = field(default_factory=time.time)
    consumed: bool = False


@dataclass
class Event:
    """Everything tees here -> observability (§11)."""

    agent: str
    kind: str  # message | tool_call | guard_decision | bb_write | reframe | finding | lifecycle
    data: dict[str, Any]
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: new_id("evt"))


@dataclass
class GuardDecision:
    allow: bool
    reason: str
    tool: str
    target: str
    agent: str
    ts: float = field(default_factory=time.time)
