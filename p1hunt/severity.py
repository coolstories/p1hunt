"""Deterministic severity mapping (spec §1 NOTHING PRESET, believe-but-verify floor).

The model proposes a severity; we do NOT trust it. A P1 hunter that lets a Claude session label
its own finding "critical" will inflate. This module replaces that judgement with a DETERMINISTIC
mapping from an :class:`ImpactAssessment` (objective facts about the proof) onto the PROGRAM'S OWN
bounty taxonomy — never a hardcoded tier scheme.

NOTHING PRESET: the tier labels come entirely from ``Scope.severity_taxonomy`` (e.g. ``{"P1": ...}``
or ``{"Critical": ...}`` or any other scheme the program publishes). We detect which key means
"critical" at runtime; we never assume "P1" or "Critical" literally exists. When the taxonomy lacks
a conceptual tier we fall back to a generic label so the mapper still returns something usable.

The core rule: the TOP tier is awarded ONLY when EVERY objective gate holds —
``reproduced AND protected_asset AND attacker_capability AND concrete_loss != "none" AND in_scope``.
If the bug was not reproduced it can never reach the top tier (it stays a CANDIDATE); if it is out
of scope it maps to an out-of-scope label regardless of impact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# Conceptual tiers, most-severe first. Mapped onto the program's own labels by ``label_for_tier``.
_TIER_CRITICAL = "critical"
_TIER_HIGH = "high"
_TIER_MEDIUM = "medium"
_TIER_LOW = "low"

# Generic fallback labels when the program taxonomy does not expose a tier we need.
_GENERIC_LABELS: dict[str, str] = {
    _TIER_CRITICAL: "Critical",
    _TIER_HIGH: "High",
    _TIER_MEDIUM: "Medium",
    _TIER_LOW: "Low",
}

# Substrings (matched case-insensitively against a taxonomy KEY or its DEFINITION text) that signal
# a conceptual tier. Ordered keys per tier; matching is "any substring present".
_TIER_KEY_HINTS: dict[str, tuple[str, ...]] = {
    _TIER_CRITICAL: ("p1", "crit", "sev1", "sev-1", "severe", "highest"),
    _TIER_HIGH: ("p2", "high", "sev2", "sev-2"),
    _TIER_MEDIUM: ("p3", "med", "moderate", "sev3", "sev-3"),
    _TIER_LOW: ("p4", "p5", "low", "info", "minor", "sev4", "sev-4", "negligible"),
}

_CONCRETE_LOSSES = ("funds", "data", "control", "availability", "none")


@dataclass
class ImpactAssessment:
    """Objective facts about a proof — the deterministic inputs to severity. The model may *propose*
    these, but the orchestrator should set them from REAL signals (e.g. ``reproduced`` from a
    :class:`~p1hunt.runners.base.ReproResult`, ``in_scope`` from ScopeGuard)."""

    reproduced: bool = False          # did a runner DEMONSTRATE the bug (not model say-so)?
    protected_asset: bool = False     # does it touch an asset the program actually protects?
    attacker_capability: bool = False # can a realistic attacker trigger it (vs. a theoretical edge)?
    concrete_loss: str = "none"       # "funds" | "data" | "control" | "availability" | "none"
    in_scope: bool = True             # is the affected asset within authorized scope?
    note: str = ""                    # free-text evidence the rationale can quote

    def normalized_loss(self) -> str:
        loss = (self.concrete_loss or "none").strip().lower()
        return loss if loss in _CONCRETE_LOSSES else "none"


def detect_critical_key(taxonomy: dict[str, str]) -> str:
    """Find the taxonomy key that means 'critical' (NOTHING PRESET — detected, never assumed).

    Priority: a key whose name hints critical (``P1``/``critical``/``crit``/...); else a key whose
    DEFINITION text hints critical; else the first key (taxonomies are typically ordered most-severe
    first); else the literal ``"critical"`` when the taxonomy is empty."""
    if not taxonomy:
        return _GENERIC_LABELS[_TIER_CRITICAL].lower()
    keys = list(taxonomy.keys())
    for key in keys:
        if _key_hints_tier(key, _TIER_CRITICAL):
            return key
    for key in keys:
        if _text_hints_tier(taxonomy.get(key, ""), _TIER_CRITICAL):
            return key
    return keys[0]


def _key_hints_tier(key: str, tier: str) -> bool:
    k = (key or "").strip().lower()
    if not k:
        return False
    for hint in _TIER_KEY_HINTS[tier]:
        # Word-ish boundary so "p1" doesn't match inside "shipping"; allow exact and prefixed forms.
        if k == hint or re.search(rf"(?<![a-z0-9]){re.escape(hint)}", k):
            return True
    return False


def _text_hints_tier(text: str, tier: str) -> bool:
    t = (text or "").strip().lower()
    if not t:
        return False
    return any(hint in t for hint in _TIER_KEY_HINTS[tier])


class SeverityMapper:
    """Maps an objective :class:`ImpactAssessment` onto the program's OWN taxonomy labels."""

    def __init__(self, severity_taxonomy: dict[str, str]):
        self.taxonomy: dict[str, str] = dict(severity_taxonomy or {})
        self.critical_key: str = detect_critical_key(self.taxonomy)

    # -- label resolution -----------------------------------------------------
    def label_for_tier(self, tier: str) -> str:
        """Return THIS program's actual label for a conceptual tier, or a generic label when the
        program's taxonomy has no key matching that tier."""
        tier = (tier or "").strip().lower()
        if tier == _TIER_CRITICAL and self.critical_key:
            return self.critical_key
        # Prefer a key whose NAME hints the tier, else one whose DEFINITION does — but never reuse
        # the critical key for a lower tier.
        for key in self.taxonomy:
            if key == self.critical_key:
                continue
            if _key_hints_tier(key, tier):
                return key
        for key in self.taxonomy:
            if key == self.critical_key:
                continue
            if _text_hints_tier(self.taxonomy.get(key, ""), tier):
                return key
        return _GENERIC_LABELS.get(tier, _GENERIC_LABELS[_TIER_LOW])

    # -- the deterministic verdict -------------------------------------------
    def map(self, impact: ImpactAssessment) -> tuple[str, str]:
        """Return ``(label_from_THIS_taxonomy, rationale)``. Deterministic; ignores any
        model-proposed severity."""
        loss = impact.normalized_loss()

        # Gate 0: scope. Out of scope is never a payable finding regardless of impact.
        if not impact.in_scope:
            return (
                "Out-of-scope",
                "Affected asset is outside the authorized scope; not eligible for a severity rating "
                "under this program even if impactful." + _suffix(impact.note),
            )

        # Gate 1: reproduction. Without a reproduced proof a finding can NEVER be top tier — it is a
        # candidate pending verification.
        if not impact.reproduced:
            return (
                "Candidate (unreproduced)",
                "Reproduction is required before any severity is awarded; the impact has not been "
                "demonstrated by execution, so this stays a candidate." + _suffix(impact.note),
            )

        # Top tier: every objective gate must hold.
        gates = {
            "reproduced": impact.reproduced,
            "protected_asset": impact.protected_asset,
            "attacker_capability": impact.attacker_capability,
            "concrete_loss": loss != "none",
            "in_scope": impact.in_scope,
        }
        if all(gates.values()):
            label = self.label_for_tier(_TIER_CRITICAL)
            return (
                label,
                f"All critical gates hold (reproduced, protected asset, attacker capability, "
                f"concrete {loss} loss, in scope) -> top tier '{label}'." + _suffix(impact.note),
            )

        # Otherwise step down deterministically. The number of remaining strong signals decides how
        # far below critical we land — all using the program's OWN labels.
        unmet = [name for name, ok in gates.items() if not ok]
        strong = sum(
            1 for ok in (impact.protected_asset, impact.attacker_capability, loss != "none") if ok
        )
        if strong >= 2:
            tier = _TIER_HIGH
        elif strong == 1:
            tier = _TIER_MEDIUM
        else:
            tier = _TIER_LOW
        label = self.label_for_tier(tier)
        return (
            label,
            f"Reproduced but not all critical gates hold (missing: {', '.join(unmet)}); "
            f"{strong} strong impact signal(s) -> '{label}'." + _suffix(impact.note),
        )

    def is_p1(self, impact: ImpactAssessment) -> bool:
        """True iff this impact maps to the program's TOP/critical tier."""
        label, _ = self.map(impact)
        return label == self.label_for_tier(_TIER_CRITICAL)


def _suffix(note: str) -> str:
    note = (note or "").strip()
    return f" Evidence: {note}" if note else ""
