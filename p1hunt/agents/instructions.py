"""Delegation instructions — specific, creative, file-anchored (spec §7).

Parent A does not tell Child B to "do better." It hands over a concrete brief: the lens,
the exact trust boundary and start points, a set of creative analytical paths to pursue,
the safe validation environment, and the stop conditions. Child B does the same for the
ephemeral Child C subagents it spawns (blank context => everything is packed in).

The investigation paths are generic *analytical techniques* tied to the §2.4 lenses, not
a per-target playbook. They are applied to whatever surface was derived for this target.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..classify.signals import SignalHit
from ..models import EngagementPlan, ImpactSurface

# Lens -> creative analytical paths (techniques, not target playbooks). Parent A selects
# and *anchors* these to real files/lines before handing them to Child B.
_PATHS_BY_LENS: dict[str, list[str]] = {
    "authorization-boundary": [
        "Trace every caller of the matched handler; find a path reachable by an unauthenticated or lower-privileged actor.",
        "Read the middleware/guard order; look for an early-return, an allowlist exception, or a debug bypass that skips the check.",
        "Find sibling routes that share the handler or the same object lookup but omit the ownership/tenant predicate.",
        "Check the test suite for a NEGATIVE cross-user/cross-tenant case; if it is missing, that boundary is likely untested.",
        "Look for an ID that is user-controlled and used directly in a lookup without an adjacent 'belongs to principal' constraint.",
    ],
    "asset-custody": [
        "Map every privileged role and upgrade path; determine who can move, freeze, mint, or burn the asset.",
        "Enumerate accounting invariants (balances sum, escrow release, one-time redemption) and check each state-changing path enforces them.",
        "Follow oracle/price dependencies; look for a path where stale or manipulable input changes a custody decision.",
        "Check authorization primitives (tx.origin vs msg.sender, signature replay, nonce reuse) on every value-moving function.",
    ],
    "trusted-execution": [
        "Trace untrusted input from entry to a dangerous sink (exec, deserialization, eval, template, dynamic require).",
        "Inspect signing/release/CI paths: can untrusted code or a pull-request reach a privileged token or write step?",
        "For delegatecall/dynamic dispatch, determine whether the target is attacker-influenceable and what storage it can touch.",
        "Look for a parser/loader configured to construct objects or resolve external entities from untrusted bytes.",
    ],
    "confidentiality": [
        "Find data-access paths missing a tenant/org scope; look for a query that selects across the boundary.",
        "Check CORS/IAM/bucket policy for wildcard origins, principals, actions, or public-read near sensitive data.",
        "Look for verbose error/debug/stack endpoints or logs that leak secrets, tokens, or other users' records.",
        "Prove exposure with least-data evidence only — counts, hashes, or an owned record — never third-party data.",
    ],
    "business-logic": [
        "Enumerate every explicitly stated invariant/assert; for each, find a sequence of legal calls that breaks it.",
        "Look for one-time / redemption / escrow / settlement logic and a re-entrancy or ordering window that double-spends it.",
        "Check state machines for an unreachable-by-design transition that is actually reachable via an alternate path.",
        "Hunt for race conditions: a check-then-act where the act can be repeated before the state updates.",
    ],
    "trusted-execution-supply": [
        "Map registry ownership and release provenance; look for an unsigned or attacker-publishable artifact in the chain.",
        "Check workflow permissions and dependency-update paths for an injection point into a trusted build.",
    ],
    "availability-if-allowed": [
        "Only if the program explicitly accepts availability impact and provides a safe method — otherwise record and skip.",
    ],
}


@dataclass
class TrackDirective:
    """Parent A -> Child B. A complete brief for one track."""

    track_id: str
    surface: ImpactSurface
    frame: str
    mission: str
    start_points: list[str]
    creative_paths: list[str]
    safe_validation_environment: str
    stop_conditions: list[str]
    impact_definition: str

    def as_prompt(self) -> str:
        bullets = "\n".join(f"  - {p}" for p in self.creative_paths)
        starts = "\n".join(f"  - {s}" for s in self.start_points) or "  - (map start points first)"
        stops = "\n".join(f"  - {s}" for s in self.stop_conditions)
        return (
            f"TRACK {self.track_id} — frame: {self.frame}\n"
            f"Mission: {self.mission}\n"
            f"Lens: {self.surface.lens} | Boundary: {self.surface.trust_boundary}\n"
            f"What '{self._p1_word()}' means here: {self.impact_definition}\n"
            f"Start points:\n{starts}\n"
            f"Creative paths to pursue (not exhaustive — invent more):\n{bullets}\n"
            f"Safe validation: {self.safe_validation_environment} only; least-data evidence.\n"
            f"Stop conditions:\n{stops}"
        )

    @staticmethod
    def _p1_word() -> str:
        return "critical / P1"


@dataclass
class SubTask:
    """Child B -> Child C (ephemeral, blank context). Everything is packed in."""

    sub_id: str
    hypothesis_id: str
    claim: str
    packed_context: str
    one_path: str
    evidence_required: list[str]
    stop_conditions: list[str] = field(default_factory=list)

    def as_prompt(self) -> str:
        ev = "\n".join(f"  - {e}" for e in self.evidence_required)
        return (
            f"SUBTASK {self.sub_id} (blank context — all context below)\n"
            f"Hypothesis {self.hypothesis_id}: {self.claim}\n"
            f"Context:\n{self.packed_context}\n"
            f"Pursue exactly this path: {self.one_path}\n"
            f"Return a reproduced artifact or a falsification. The defect must be attributable to "
            f"the in-scope target, not the harness/mocks/fixtures/external setup. Required evidence:\n{ev}\n"
            f"Safety: local/fork/UAT/owned only; no destructive validation; stop on out-of-scope or third-party data."
        )


def parent_directive(
    surface: ImpactSurface,
    plan: EngagementPlan,
    frame: str,
    *,
    hits: list[SignalHit] | None = None,
    track_index: int = 1,
) -> TrackDirective:
    """Build Parent A's concrete brief for a Child B track, anchored to real signals."""
    lens_paths = _PATHS_BY_LENS.get(surface.lens, _PATHS_BY_LENS["business-logic"])
    anchored = [h for h in (hits or []) if h.signal.lens == surface.lens]
    start_points = [f"{h.file}:{h.line} — {h.signal.title}" for h in anchored[:5]]

    # Creative paths are anchored to the first concrete hit when one exists.
    creative = list(lens_paths)
    if anchored:
        top = anchored[0]
        creative = [f"Begin at {top.file}:{top.line}. " + lens_paths[0]] + lens_paths[1:]

    mission = (
        f"Find and reproduce a {surface.lens} weakness on {surface.target_asset} that the "
        f"program would classify as critical. Hunt as if a P1 exists — persistence is the "
        f"job — but promote only on a reproduced, target-attributed artifact."
    )
    return TrackDirective(
        track_id=f"T{track_index:02d}",
        surface=surface,
        frame=frame,
        mission=mission,
        start_points=start_points,
        creative_paths=creative,
        safe_validation_environment=surface.safe_validation_environment,
        stop_conditions=[
            "Out-of-scope asset encountered",
            "Unexpected third-party data appears",
            "Validation would require a destructive or production action",
        ],
        impact_definition=plan.impact_definition,
    )


def child_subtask(
    sub_id: str,
    hypothesis_id: str,
    claim: str,
    hit: SignalHit,
    path: str,
    evidence_required: list[str],
) -> SubTask:
    """Build a packed, single-path brief for an ephemeral Child C."""
    packed = (
        f"Signal: {hit.signal.title} ({hit.signal.id}, lens={hit.signal.lens})\n"
        f"Location: {hit.file}:{hit.line}\n"
        f"Code: {hit.snippet}\n"
        f"Why it may be critical: {hit.signal.rationale}"
    )
    return SubTask(
        sub_id=sub_id,
        hypothesis_id=hypothesis_id,
        claim=claim,
        packed_context=packed,
        one_path=path,
        evidence_required=evidence_required,
        stop_conditions=[
            "Out-of-scope asset encountered",
            "Unexpected third-party data appears",
            "Validation would require a destructive action",
        ],
    )
