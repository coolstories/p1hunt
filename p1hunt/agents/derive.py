"""Derivation engine (spec §6) — Parent A's first action on every engagement.

Replaces ALL presets. Given the ``Scope`` and the acquired artifacts, it classifies the
target, selects only the appropriate toolset, ranks the surface by reachability -> impact
*for this target*, seeds emergent hypothesis classes, derives the ScopeGuard policy, and
returns the ``EngagementPlan``. Feeding three different scopes MUST yield three materially
different plans (§6 acceptance, §16).

The only things baked in are *derivation rules* (class -> candidate toolset; generic
detector -> lens). No surface list, hypothesis list, or per-target playbook is hardcoded.
"""

from __future__ import annotations

from collections import defaultdict

from ..classify.classifier import classify_artifacts
from ..classify.evm_signals import scan_combined
from ..classify.signals import SignalHit
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
    hits = scan_combined(artifact_dir)
    surfaces = _rank_surfaces(target_class, hits, scope)
    hypothesis_seeds = _seed_hypotheses(surfaces)
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


def _rank_surfaces(
    target_class: TargetClass, hits: list[SignalHit], scope: Scope
) -> list[ImpactSurface]:
    by_lens: dict[str, list[SignalHit]] = defaultdict(list)
    for hit in hits:
        by_lens[hit.signal.lens].append(hit)

    env = _ENV_BY_CLASS.get(target_class, "local")
    fallback_asset = scope.in_scope[0].value if scope.in_scope else "local source snapshot"

    if not by_lens:
        return [
            ImpactSurface(
                id="SURF-BASELINE",
                title="No critical signal matched yet — keep mapping trust boundaries",
                lens="business-logic",
                target_asset=fallback_asset,
                trust_boundary="To be derived from routes, roles, and protected objects.",
                safe_validation_environment=env,
                criticality_rationale="Continue mapping high-value boundaries before validation.",
                priority=5,
            )
        ]

    # Lens weight: asset-custody and authorization boundaries rank highest for P1.
    lens_weight = {
        "asset-custody": 1,
        "authorization-boundary": 1,
        "trusted-execution": 2,
        "confidentiality": 3,
        "business-logic": 3,
        "availability-if-allowed": 4,
    }
    ordered = sorted(by_lens.items(), key=lambda kv: (lens_weight.get(kv[0], 9), -len(kv[1])))

    surfaces: list[ImpactSurface] = []
    for index, (lens, lens_hits) in enumerate(ordered, start=1):
        top = lens_hits[0]
        surfaces.append(
            ImpactSurface(
                id=f"SURF-{index:03d}",
                title=f"{_label(lens)} surface in {target_class.value}",
                lens=lens,
                target_asset=fallback_asset,
                trust_boundary=f"{top.signal.rationale} (e.g. {top.file}:{top.line})",
                safe_validation_environment=env,
                criticality_rationale=(
                    f"{len(lens_hits)} derived signal(s) map to {_label(lens).lower()} impact."
                ),
                priority=lens_weight.get(lens, 9),
            )
        )
    return surfaces


def _seed_hypotheses(surfaces: list[ImpactSurface]) -> list[str]:
    seeds: list[str] = []
    for surface in surfaces:
        if surface.id == "SURF-BASELINE":
            continue
        seeds.append(
            f"A reachable {surface.lens} weakness on {surface.target_asset} "
            f"({surface.trust_boundary}) may produce critical impact."
        )
    return seeds


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


def _label(lens: str) -> str:
    return " ".join(part.capitalize() for part in lens.split("-"))


def make_hypothesis_id() -> str:
    return new_id("HYP")
