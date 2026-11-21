"""Precondition attacker — make the condition that caps a finding the TARGET of the next hunt.

A finding is almost never "critical" or "not critical"; it is critical *under conditions*. The
conditions are what a triager prices: "only exploitable while signed out", "needs an admin to
click", "only on one client". Those clauses are where severity leaks away, and the usual failure
is to accept them as properties of the bug. They are not — they are properties of *what has been
tested so far*.

So this module makes every condition explicit and then attacks it:

  1. MODEL — a finding's conditions become :class:`Precondition` records on generic dimensions
     (which principal, how much privilege, which client, whether a human must act, ...). Each one
     records which objective severity GATE it is holding down.
  2. ATTACK — each precondition gets its own :class:`RemovalObjective`: a dedicated hunt directive
     whose SOLE job is removing that one condition. Not "look deeper" — "make this bug fire
     without this condition, and here is what success looks like."
  3. RE-SCORE — when a precondition is actually removed, the finding is re-scored UPWARD through
     the program's own taxonomy (:mod:`p1hunt.severity`), because an unconditional bug is a
     different bug. This is the step that turns a capped finding into an unconditional one.

NOTHING PRESET: the dimensions describe *conditionality* — the shape of "it only works when…" —
not vulnerability classes, and they carry no target, product, or bug-class literals. Severity
never comes from a hardcoded tier scheme; it is always mapped through the program's published
taxonomy by the existing deterministic mapper, so removing a precondition can only move a finding
within the labels that program actually publishes.

Pure and unit-testable throughout: no I/O, no network, no model calls.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Iterable

from ..severity import ImpactAssessment, SeverityMapper

# --- the severity GATES a condition can hold down -------------------------------------------
# These mirror the objective gates of p1hunt.severity.ImpactAssessment. A precondition is
# interesting precisely because it keeps one of these gates from being satisfiable.
GATE_ATTACKER_CAPABILITY = "attacker_capability"  # can a realistic attacker trigger it at will?
GATE_PROTECTED_ASSET = "protected_asset"          # does it reach something the program protects?
GATE_CONCRETE_LOSS = "concrete_loss"              # does a real loss follow?

# --- conditionality dimensions --------------------------------------------------------------
# "In which way is this bug conditional?" Generic deployment/actor shapes, transferable to any
# target class. Never a bug class, CWE, or playbook entry.
DIM_AUTH_STATE = "auth-state"        # depends on whether the victim/attacker is authenticated
DIM_PRIVILEGE = "privilege"          # depends on holding a role/permission/capability
DIM_INTERACTION = "interaction"      # depends on a human performing an action
DIM_CLIENT = "client"                # depends on a particular client/render/negotiation path
DIM_CONFIGURATION = "configuration"  # depends on a non-default setting/feature state
DIM_TIMING = "timing"                # depends on a race/window/ordering
DIM_POSITION = "position"            # depends on network/session position or prior access
DIM_OTHER = "other"                  # conditional, dimension undetermined

DIMENSIONS = (
    DIM_AUTH_STATE,
    DIM_PRIVILEGE,
    DIM_INTERACTION,
    DIM_CLIENT,
    DIM_CONFIGURATION,
    DIM_TIMING,
    DIM_POSITION,
    DIM_OTHER,
)

# Which gate each dimension holds down. Every conditionality dimension narrows WHO can trigger
# the bug or WHEN, so they all bear on attacker capability — that is what "conditional" means.
_GATE_BY_DIMENSION: dict[str, str] = {
    DIM_AUTH_STATE: GATE_ATTACKER_CAPABILITY,
    DIM_PRIVILEGE: GATE_ATTACKER_CAPABILITY,
    DIM_INTERACTION: GATE_ATTACKER_CAPABILITY,
    DIM_CLIENT: GATE_ATTACKER_CAPABILITY,
    DIM_CONFIGURATION: GATE_ATTACKER_CAPABILITY,
    DIM_TIMING: GATE_ATTACKER_CAPABILITY,
    DIM_POSITION: GATE_ATTACKER_CAPABILITY,
    DIM_OTHER: GATE_ATTACKER_CAPABILITY,
}

# How to ATTACK each dimension — stated as a generic enumeration strategy, i.e. "where might this
# condition fail to hold?", not as an exploit recipe. These are search instructions for a hunter.
_STRATEGY_BY_DIMENSION: dict[str, str] = {
    DIM_AUTH_STATE: (
        "Enumerate every location and client path that serves this behavior and find one where the "
        "state-dependent branch is not taken, so the behavior is identical regardless of the "
        "viewer's authentication state."
    ),
    DIM_PRIVILEGE: (
        "Map every caller that reaches the same code path and find one reachable by a principal "
        "without that role — including internal callers, delegated flows, and paths that re-enter "
        "the operation after the check has already been made."
    ),
    DIM_INTERACTION: (
        "Find a path that performs the same operation without the human step: an automatic, "
        "background, or preloaded request to the same endpoint, or a flow where the action is "
        "initiated by the system rather than by a person."
    ),
    DIM_CLIENT: (
        "Enumerate every client variant the target serves differently (negotiation, render mode, "
        "API version, platform-specific host) and find one where the behavior occurs on the "
        "default client path instead of the special one."
    ),
    DIM_CONFIGURATION: (
        "Determine the default state of that setting for a new/typical account, and find whether "
        "the behavior also occurs under defaults or can be reached without changing the setting."
    ),
    DIM_TIMING: (
        "Determine whether the window can be created or widened on demand rather than waited for, "
        "making the condition reliably satisfiable instead of opportunistic."
    ),
    DIM_POSITION: (
        "Determine whether the same effect is reachable from an ordinary remote position with no "
        "prior access, rather than from the assumed position."
    ),
    DIM_OTHER: (
        "Characterize exactly what this condition depends on, then enumerate the locations or "
        "paths where that dependency does not hold."
    ),
}

# --- conditionality MARKERS (not vulnerability patterns) ------------------------------------
# Phrases that mark a clause as conditional. This vocabulary is about grammar — "only when",
# "requires", "unless" — so it stays target- and bug-class-agnostic.
_CONDITION_MARKERS = re.compile(
    r"\b(requires?|required|only|needs?|depends?\s+on|"
    r"unless|provided\s+that|assuming|limited\s+to|restricted\s+to|must\s+(?:be|have|first)|"
    r"gated\s+(?:by|on)|conditional\s+on|contingent\s+on|when\s+the\s+victim|if\s+the\s+victim)\b",
    re.IGNORECASE,
)

# Neutral cues that place a conditional clause on a dimension. Each cue names an ACTOR STATE or a
# DEPLOYMENT shape, never a bug. Order matters: the first dimension whose cues match wins.
_DIMENSION_CUES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (DIM_PRIVILEGE, ("privile", "admin", "role", "permission", "elevated", "staff",
                     "operator", "owner", "capability", "scope grant", "entitle")),
    (DIM_AUTH_STATE, ("signed out", "signed-out", "logged out", "logged-out", "unauthenticated",
                      "anonymous", "signed in", "signed-in", "logged in", "logged-in",
                      "authenticated", "session cookie", "no session", "session present")),
    # "accept" is deliberately NOT a bare cue: it collides with the HTTP Accept header, which is
    # a CLIENT dimension, not a human action.
    (DIM_INTERACTION, ("click", "interaction", "user action", "victim visits", "victim opens",
                       "manual", "paste", "confirm", "must accept", "user accepts",
                       "victim accepts", "drag", "submit the form", "social engineer")),
    (DIM_CLIENT, ("user agent", "user-agent", "browser", "mobile", "desktop", "embed",
                  "render", "api version", "accept header", "client", "app version",
                  "platform", "native")),
    (DIM_CONFIGURATION, ("setting", "config", "feature flag", "enabled", "disabled", "opt-in",
                         "opt in", "toggle", "non-default", "plan", "tier")),
    (DIM_TIMING, ("race", "window", "timing", "concurrent", "simultane", "before the",
                  "within ", "order of", "interleav")),
    (DIM_POSITION, ("network position", "same network", "mitm", "man-in-the-middle", "local access",
                    "physical", "already has access", "prior access", "adjacent")),
)

_MAX_TEXT = 400
_SPLIT = re.compile(r"(?<=[.;])\s+|\n+|\s+-\s+")


def _clean(value: object, limit: int = _MAX_TEXT) -> str:
    return " ".join(str(value or "").split())[:limit]


def classify_dimension(statement: object) -> str:
    """Place a condition statement on a conditionality dimension. PURE.

    Falls back to :data:`DIM_OTHER` rather than guessing: an unclassified condition is still
    attacked (with a characterize-first strategy), which is strictly better than mislabeling it."""

    text = str(statement or "").lower()
    if not text.strip():
        return DIM_OTHER
    for dimension, cues in _DIMENSION_CUES:
        if any(cue in text for cue in cues):
            return dimension
    return DIM_OTHER


def _pid(statement: str) -> str:
    """Content-addressed id. Punctuation and case are stripped first, so the same condition
    restated with different punctuation keys the same and is not modelled twice."""

    norm = re.sub(r"[^a-z0-9 ]+", " ", str(statement or "").lower())
    norm = " ".join(norm.split())
    return "PRE_" + hashlib.sha1(norm.encode("utf-8")).hexdigest()[:10]


@dataclass(frozen=True)
class Precondition:
    """One explicit condition under which a finding holds — and which gate it holds down."""

    id: str
    dimension: str
    statement: str
    gate: str = GATE_ATTACKER_CAPABILITY
    removed: bool = False
    removal_evidence: str = ""

    def with_removed(self, evidence: str = "") -> "Precondition":
        """A copy marked removed. Immutable record-keeping: the original stays in the ledger."""

        return Precondition(
            id=self.id, dimension=self.dimension, statement=self.statement, gate=self.gate,
            removed=True, removal_evidence=_clean(evidence),
        )

    def as_dict(self) -> dict:
        return {
            "id": self.id, "dimension": self.dimension, "statement": self.statement,
            "gate": self.gate, "removed": self.removed,
            "removal_evidence": self.removal_evidence,
        }


@dataclass(frozen=True)
class RemovalObjective:
    """A dedicated hunt directive whose SOLE objective is removing one precondition.

    ``hypothesis`` is the ledger-keyable claim being tested, so an objective that fails is
    recorded as falsified and never re-issued; ``success_criterion`` is what proof of removal
    looks like, so "removed" is an observation rather than an opinion."""

    precondition_id: str
    dimension: str
    objective: str
    strategy: str
    success_criterion: str
    hypothesis: str

    def as_prompt(self) -> str:
        return (
            f"SOLE OBJECTIVE — remove this precondition: {self.objective}\n"
            f"Why it matters: while this condition holds, the finding is capped; without it the "
            f"finding is unconditional and scores higher.\n"
            f"How to search ({self.dimension}): {self.strategy}\n"
            f"Hypothesis under test: {self.hypothesis}\n"
            f"Success: {self.success_criterion}\n"
            f"Do NOT re-prove the original finding; it is already confirmed. Either remove this "
            f"condition or establish positively that it cannot be removed, and say which mechanism "
            f"enforces it."
        )

    def as_dict(self) -> dict:
        return {
            "precondition_id": self.precondition_id, "dimension": self.dimension,
            "objective": self.objective, "strategy": self.strategy,
            "success_criterion": self.success_criterion, "hypothesis": self.hypothesis,
        }


@dataclass(frozen=True)
class Rescore:
    """The result of re-scoring a finding after preconditions were removed."""

    previous_label: str
    label: str
    raised: bool
    rationale: str
    removed: tuple[str, ...] = ()
    remaining: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "previous_severity": self.previous_label, "severity": self.label,
            "raised": self.raised, "rationale": self.rationale,
            "removed_preconditions": list(self.removed),
            "remaining_preconditions": list(self.remaining),
        }


# ------------------------------------------------------------------ modeling --
def preconditions_from(declared: Iterable[object]) -> list[Precondition]:
    """Model explicitly DECLARED conditions (the preferred path).

    Accepts plain strings or mappings with ``statement``/``dimension`` keys, so a hunter or an
    operator can hand over structured conditions without this module having to parse prose."""

    out: list[Precondition] = []
    seen: set[str] = set()
    for item in declared or ():
        if item is None:
            continue
        if isinstance(item, Precondition):
            if item.id not in seen:
                seen.add(item.id)
                out.append(item)
            continue
        if isinstance(item, dict):
            statement = _clean(item.get("statement") or item.get("condition") or "")
            dimension = str(item.get("dimension") or "").strip().lower()
            removed = bool(item.get("removed", False))
        else:
            statement = _clean(item)
            dimension = ""
            removed = False
        if not statement:
            continue
        if dimension not in DIMENSIONS:
            dimension = classify_dimension(statement)
        pid = _pid(statement)
        if pid in seen:
            continue
        seen.add(pid)
        out.append(Precondition(
            id=pid, dimension=dimension, statement=statement,
            gate=_GATE_BY_DIMENSION.get(dimension, GATE_ATTACKER_CAPABILITY),
            removed=removed,
        ))
    return out


def extract_preconditions(text: object, *, limit: int = 12) -> list[Precondition]:
    """Derive preconditions from free-text narrative (the fallback path). PURE.

    Splits on clause boundaries and keeps the clauses that carry a conditionality MARKER. This
    reads grammar, not vulnerabilities: it finds "only works when X" regardless of what X is, so
    it cannot smuggle in bug-class priors. Returns [] when nothing is conditional — a finding with
    no stated conditions is treated as unconditional rather than given invented caps."""

    body = str(text or "")
    if not body.strip():
        return []
    statements: list[str] = []
    for raw in _SPLIT.split(body):
        clause = _clean(raw)
        if not clause or len(clause) < 8:
            continue
        if not _CONDITION_MARKERS.search(clause):
            continue
        statements.append(clause)
        if len(statements) >= max(1, int(limit)):
            break
    return preconditions_from(statements)


def removal_objectives(
    preconditions: Iterable[Precondition], *, finding_title: str = ""
) -> list[RemovalObjective]:
    """One dedicated objective per UNREMOVED precondition. PURE.

    Removed conditions are skipped (that work is done), which is what keeps a re-entering hunt
    from re-attacking a condition it already defeated."""

    title = _clean(finding_title, 160) or "the confirmed finding"
    out: list[RemovalObjective] = []
    for pre in preconditions or ():
        if pre is None or pre.removed:
            continue
        strategy = _STRATEGY_BY_DIMENSION.get(pre.dimension, _STRATEGY_BY_DIMENSION[DIM_OTHER])
        out.append(RemovalObjective(
            precondition_id=pre.id,
            dimension=pre.dimension,
            objective=(
                f"Make '{title}' hold WITHOUT this condition: {pre.statement}"
            ),
            strategy=strategy,
            success_criterion=(
                "A reproduced artifact showing the same impact at a location or on a path where "
                f"this condition does not apply — or a positive, mechanism-named argument that it "
                f"applies everywhere (which closes this objective as a supported negative)."
            ),
            hypothesis=(
                f"the precondition '{pre.statement}' can be removed from '{title}' "
                f"via the {pre.dimension} dimension"
            ),
        ))
    return out


# ------------------------------------------------------------------ scoring --
def assessment_with(
    base: ImpactAssessment, preconditions: Iterable[Precondition]
) -> ImpactAssessment:
    """Apply unremoved preconditions to an impact assessment. PURE.

    Each unremoved precondition pulls DOWN the objective gate it holds. This is the honest
    encoding of a cap: the bug is real and reproduced, but a realistic attacker cannot trigger it
    at will while the condition stands, so the critical gate cannot be claimed."""

    gates = {p.gate for p in (preconditions or ()) if p is not None and not p.removed}
    return ImpactAssessment(
        reproduced=base.reproduced,
        protected_asset=base.protected_asset and GATE_PROTECTED_ASSET not in gates,
        attacker_capability=base.attacker_capability and GATE_ATTACKER_CAPABILITY not in gates,
        concrete_loss="none" if GATE_CONCRETE_LOSS in gates else base.concrete_loss,
        in_scope=base.in_scope,
        note=base.note,
    )


def rescore(
    mapper: SeverityMapper,
    base: ImpactAssessment,
    preconditions: Iterable[Precondition],
    *,
    removed_ids: Iterable[str] = (),
) -> Rescore:
    """Re-score a finding after some preconditions were removed. PURE and deterministic.

    Both labels come from the PROGRAM'S OWN taxonomy via the existing severity mapper, so this
    cannot invent a tier. ``raised`` is True only when the label actually changed, which makes an
    escalation auditable: the operator can see the before label, the after label, and exactly
    which condition fell to produce it.

    "Before" is always evaluated with EVERY listed precondition STANDING, independent of whether
    the caller already marked some removed on its own model. Without that the comparison
    silently collapses — a model that has already recorded the removal would score the same
    before and after, and a real escalation would be reported as "no change"."""

    removed = {str(r) for r in (removed_ids or ())}
    original = [p for p in (preconditions or ()) if p is not None]
    standing = [p if not p.removed else Precondition(
        id=p.id, dimension=p.dimension, statement=p.statement, gate=p.gate, removed=False,
    ) for p in original]
    updated = [p.with_removed(p.removal_evidence or "precondition removed by escalation")
               if p.id in removed else p for p in standing]

    before_label, _ = mapper.map(assessment_with(base, standing))
    after_impact = assessment_with(base, updated)
    after_label, after_rationale = mapper.map(after_impact)

    now_removed = tuple(p.statement for p in updated if p.removed)
    remaining = tuple(p.statement for p in updated if not p.removed)
    raised = after_label != before_label

    if raised:
        rationale = (
            f"Severity re-scored from '{before_label}' to '{after_label}': "
            f"{len(now_removed)} precondition(s) removed "
            f"({'; '.join(now_removed) or 'none'}). {after_rationale}"
        )
    elif remaining:
        rationale = (
            f"Severity unchanged at '{after_label}': {len(remaining)} precondition(s) still hold "
            f"({'; '.join(remaining)}). {after_rationale}"
        )
    else:
        rationale = f"Severity unchanged at '{after_label}'. {after_rationale}"

    return Rescore(
        previous_label=before_label, label=after_label, raised=raised, rationale=rationale,
        removed=now_removed, remaining=remaining,
    )


@dataclass
class PreconditionModel:
    """The mutable per-finding view: the conditions, and which have fallen so far.

    Thin by design — the durable record of what was tried lives in the falsification ledger, and
    the severity verdict comes from the deterministic mapper. This only tracks current state."""

    finding_title: str
    preconditions: list[Precondition] = field(default_factory=list)

    @classmethod
    def for_finding(
        cls,
        finding_title: str,
        *,
        declared: Iterable[object] = (),
        narrative: object = "",
    ) -> "PreconditionModel":
        """Build from declared conditions, falling back to narrative extraction."""

        pres = preconditions_from(declared)
        if not pres:
            pres = extract_preconditions(narrative)
        return cls(finding_title=_clean(finding_title, 200), preconditions=pres)

    def unremoved(self) -> list[Precondition]:
        return [p for p in self.preconditions if not p.removed]

    def objectives(self) -> list[RemovalObjective]:
        return removal_objectives(self.preconditions, finding_title=self.finding_title)

    def mark_removed(self, precondition_id: str, evidence: str = "") -> bool:
        """Mark one precondition removed. Returns True when it changed state."""

        for index, pre in enumerate(self.preconditions):
            if pre.id == precondition_id and not pre.removed:
                self.preconditions[index] = pre.with_removed(evidence)
                return True
        return False

    def rescore(self, mapper: SeverityMapper, base: ImpactAssessment) -> Rescore:
        return rescore(mapper, base, self.preconditions,
                       removed_ids=[p.id for p in self.preconditions if p.removed])

    def summary(self) -> dict:
        return {
            "finding": self.finding_title,
            "preconditions": [p.as_dict() for p in self.preconditions],
            "unremoved": len(self.unremoved()),
            "removed": len(self.preconditions) - len(self.unremoved()),
            "dimensions": sorted({p.dimension for p in self.preconditions}),
        }
