"""Minimal engagement derivation.

This layer is execution plumbing only: classify enough of the acquired artifact to choose a runner
and safety posture. It must not seed failure modes, target names, surfaces, hypotheses, or priorities;
Parent A derives those live from the repository during cold reconnaissance.
"""

from __future__ import annotations

from pathlib import Path

from ..classify.classifier import classify_artifacts
from ..models import (
    EngagementPlan,
    ImpactSurface,
    Scope,
    TargetClass,
    new_id,
)
from ..safety.policies import derive_scopeguard_policy

# Class -> candidate safe tool modules (§12). A derivation rule, not a playbook: each
# module is a non-destructive interface, selected only when the class warrants it.
_TOOLSET_BY_CLASS: dict[TargetClass, list[str]] = {
    TargetClass.EVM_CONTRACT: ["source_fetch", "static_analysis", "evm_fork"],
    TargetClass.CRYPTO_LIB: ["source_fetch", "static_analysis"],
    TargetClass.MOBILE_APP: ["source_fetch", "apk_inspect", "http_sandbox"],
    TargetClass.WEB_API: ["source_fetch", "static_analysis", "http_sandbox"],
    TargetClass.INFRA: ["source_fetch", "static_analysis", "http_sandbox"],
    TargetClass.SUPPLY_CHAIN: ["source_fetch", "static_analysis"],
    TargetClass.OTHER: ["source_fetch", "static_analysis"],
}

# Lens -> default safe validation environment (a derivation rule tied to the §2.4 lenses).
_ENV_BY_CLASS: dict[TargetClass, str] = {
    TargetClass.EVM_CONTRACT: "fork",
    TargetClass.CRYPTO_LIB: "local",
    TargetClass.MOBILE_APP: "uat",
    TargetClass.WEB_API: "uat",
    TargetClass.INFRA: "local",
    TargetClass.SUPPLY_CHAIN: "local",
    TargetClass.OTHER: "local",
}


def derive_plan(scope: Scope, artifact_dir: str) -> EngagementPlan:
    target_class = classify_artifacts(artifact_dir, scope)
    toolset = list(_TOOLSET_BY_CLASS.get(target_class, _TOOLSET_BY_CLASS[TargetClass.OTHER]))
    surfaces = _repo_surfaces(artifact_dir, target_class, scope)
    hypothesis_seeds: list[str] = []
    policy = derive_scopeguard_policy(scope, target_class)
    impact_definition = _impact_definition(scope)

    return EngagementPlan(
        target_class=target_class,
        toolset=toolset,
        surface_ranking=surfaces,
        hypothesis_seeds=hypothesis_seeds,
        scopeguard_policy=policy,
        impact_definition=impact_definition,
    )


def _repo_surfaces(artifact_dir: str, target_class: TargetClass, scope: Scope) -> list[ImpactSurface]:
    """Create neutral file-cluster placeholders when a legacy caller needs an EngagementPlan."""
    env = _ENV_BY_CLASS.get(target_class, "local")
    fallback_asset = scope.in_scope[0].value if scope.in_scope else "local source snapshot"
    root = Path(artifact_dir)
    counts: dict[str, int] = {}
    for p in root.rglob("*"):
        if not p.is_file() or any(part.startswith(".") for part in p.parts):
            continue
        try:
            rel = p.relative_to(root)
        except ValueError:
            continue
        if not rel.parts:
            continue
        key = rel.parts[0] if len(rel.parts) > 1 else rel.stem
        if key.lower() in {"test", "tests", "mock", "mocks", "example", "examples", "build", "dist"}:
            continue
        counts[key] = counts.get(key, 0) + 1
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:6]
    if not ordered:
        ordered = [("repo", 0)]
    surfaces: list[ImpactSurface] = []
    for index, (component, count) in enumerate(ordered, start=1):
        surfaces.append(
            ImpactSurface(
                id=f"SURF-{index:03d}",
                title=f"Repository component: {component}",
                lens=f"component:{component}",
                target_asset=fallback_asset,
                trust_boundary="To be derived by Parent A from code-level entrypoints and actors.",
                safe_validation_environment=env,
                criticality_rationale=f"Neutral component placeholder from repository structure ({count} files).",
                priority=index,
            )
        )
    return surfaces


def _impact_definition(scope: Scope) -> str:
    # Derive the program's OWN critical-tier key (NOTHING PRESET — don't assume it's literally
    # "P1"/"critical"; a program may use Sev1/TierA/Alpha/…). Reuses the severity mapper's detector.
    from ..severity import detect_critical_key

    tax = scope.severity_taxonomy or {}
    key = detect_critical_key(tax) if tax else ""
    p1 = tax.get(key) if key else None
    if p1:
        return f"Critical ('{key}') under {scope.program}: {p1}"
    return (
        f"P1 under {scope.program}: use the program's own critical-severity definition; "
        "promotion requires reproduced impact that the program would classify as critical."
    )


def make_hypothesis_id() -> str:
    return new_id("HYP")
