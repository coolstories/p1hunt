"""Escalation after confirmation — a confirmed finding RE-ENTERS the hunt instead of ending it.

The pipeline's reflex is that confirmation is the finish line: a reproduced critical returns
``REPORT_READY`` and the hunt stops. That throws away the highest-value question available, which
is not "is this real?" (answered) but "**what makes this worse?**". The gap between a capped
finding and an unconditional one is usually one enumeration nobody ran.

So a confirmation here produces an :class:`EscalationPlan` with three generic objective kinds:

  * ``remove-precondition`` — attack each condition that caps it (:mod:`.preconditions`);
  * ``find-unconditional-location`` — find a location where the control that caps it is simply
    not applied (:mod:`.asymmetry`);
  * ``widen-blast-radius`` — establish how far the crossed authority actually reaches: who else
    is affected, what else the same capability touches, whether one victim becomes all of them.

BOUNDED — three independent limits, because "re-enter the hunt on success" is exactly the shape
that loops forever:

  1. per-finding attempt cap (``P1HUNT_MAX_ESCALATION_ATTEMPTS``, default 3);
  2. ledger de-duplication — an objective whose hypothesis is already recorded as falsified is
     dropped, so the plan strictly shrinks and reaches empty; and
  3. an engagement-wide total cap (``P1HUNT_MAX_ESCALATION_TOTAL``, default 24) so several
     confirmed findings cannot multiply into an unbounded sweep.

Every attempt is written to the falsification ledger, so the bound survives a process restart:
a resumed hunt counts the attempts already on disk rather than starting the budget over.

The planning layer is PURE (an injected ``already_falsified`` predicate, no ledger, no I/O);
:class:`EscalationLoop` is the thin stateful wrapper that records and emits.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Iterable

from ..ledger import FalsificationLedger, hypothesis_key
from .preconditions import Precondition, RemovalObjective, removal_objectives

# The three ways a confirmed finding can get worse. Mechanisms, not bug classes.
KIND_REMOVE_PRECONDITION = "remove-precondition"
KIND_UNCONDITIONAL_LOCATION = "find-unconditional-location"
KIND_WIDEN_BLAST_RADIUS = "widen-blast-radius"
ESCALATION_KINDS = (
    KIND_REMOVE_PRECONDITION,
    KIND_UNCONDITIONAL_LOCATION,
    KIND_WIDEN_BLAST_RADIUS,
)

# Ledger family prefix: every escalation hypothesis for one finding shares a family, so when they
# are ALL falsified the ledger composes an architectural conclusion ("this finding cannot be
# escalated further, and here is why") instead of leaving a silent dead end.
FAMILY_PREFIX = "escalation"

_DEFAULT_MAX_ATTEMPTS = 3
_DEFAULT_MAX_TOTAL = 24
_MAX_TEXT = 400


def _clean(value: object, limit: int = _MAX_TEXT) -> str:
    return " ".join(str(value or "").split())[:limit]


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    raw = str(os.environ.get(name, "")).strip()
    if raw.lstrip("-").isdigit():
        value = int(raw)
        if value >= minimum:
            return value
    return default


def max_escalation_attempts() -> int:
    """Per-finding escalation passes.

    Dial: ``P1HUNT_MAX_ESCALATION_ATTEMPTS`` (default 3). 0 disables escalation entirely, which
    restores the old terminate-on-confirmation behavior for an operator who wants it."""

    return _env_int("P1HUNT_MAX_ESCALATION_ATTEMPTS", _DEFAULT_MAX_ATTEMPTS, minimum=0)


def max_escalation_total() -> int:
    """Engagement-wide ceiling on escalation passes across all findings.

    Dial: ``P1HUNT_MAX_ESCALATION_TOTAL`` (default 24)."""

    return _env_int("P1HUNT_MAX_ESCALATION_TOTAL", _DEFAULT_MAX_TOTAL, minimum=0)


@dataclass(frozen=True)
class EscalationObjective:
    """One thing to try in order to make a confirmed finding worse."""

    kind: str
    objective: str
    strategy: str
    success_criterion: str
    hypothesis: str
    precondition_id: str = ""

    def as_prompt(self) -> str:
        return (
            f"ESCALATION OBJECTIVE ({self.kind}): {self.objective}\n"
            f"How to search: {self.strategy}\n"
            f"Hypothesis under test: {self.hypothesis}\n"
            f"Success: {self.success_criterion}"
        )

    def as_dict(self) -> dict:
        return {
            "kind": self.kind, "objective": self.objective, "strategy": self.strategy,
            "success_criterion": self.success_criterion, "hypothesis": self.hypothesis,
            "precondition_id": self.precondition_id,
        }


@dataclass(frozen=True)
class EscalationPlan:
    """What to try next for one confirmed finding — or why there is nothing left to try."""

    finding_key: str
    finding_title: str
    attempt: int
    objectives: tuple[EscalationObjective, ...] = ()
    exhausted: bool = False
    reason: str = ""

    @property
    def family(self) -> str:
        return f"{FAMILY_PREFIX}:{self.finding_key}"

    def as_prompt(self) -> str:
        if self.exhausted:
            return f"No escalation objectives remain for '{self.finding_title}': {self.reason}"
        bullets = "\n\n".join(o.as_prompt() for o in self.objectives)
        return (
            f"ESCALATION PASS {self.attempt} on a CONFIRMED finding: {self.finding_title}\n"
            f"The finding is already proven — do NOT re-prove it. Your job is to make it WORSE, "
            f"or to establish positively that it cannot be made worse (a supported negative is a "
            f"real result and closes the question).\n\n{bullets}"
        )

    def as_dict(self) -> dict:
        return {
            "finding": self.finding_title, "finding_key": self.finding_key,
            "attempt": self.attempt, "exhausted": self.exhausted, "reason": self.reason,
            "objectives": [o.as_dict() for o in self.objectives],
        }


def _standard_objectives(title: str) -> list[EscalationObjective]:
    """The two objectives that apply to ANY confirmed finding, independent of its conditions."""

    return [
        EscalationObjective(
            kind=KIND_UNCONDITIONAL_LOCATION,
            objective=(
                f"Find a location where '{title}' is NOT subject to whatever control or condition "
                f"currently limits it."
            ),
            strategy=(
                "Identify the control that limits this finding, then enumerate every location that "
                "control should cover — sibling hosts, path and route families, client/render "
                "variants, and auth states — and differentially test each one. A location missing "
                "the control is a candidate; a location missing it where the affected behavior is "
                "also reachable is a severity escalation."
            ),
            success_criterion=(
                "A reproduced artifact at a location where the limiting control demonstrably does "
                "not run, with the baseline location proving the control normally does run."
            ),
            hypothesis=f"a location exists where '{title}' is not subject to its limiting control",
        ),
        EscalationObjective(
            kind=KIND_WIDEN_BLAST_RADIUS,
            objective=f"Establish how far the authority crossed by '{title}' actually reaches.",
            strategy=(
                "Characterize the capability this finding grants, then determine its true extent: "
                "which other principals, tenants, objects, or operations the same capability "
                "touches; whether it reaches one victim or any victim; whether it composes with "
                "the target's own features to cross a further boundary; and whether the effect is "
                "one-shot or persistent."
            ),
            success_criterion=(
                "A reproduced artifact showing the capability reaching a strictly larger set of "
                "affected principals/objects than the original proof, or crossing a further "
                "authority boundary."
            ),
            hypothesis=f"the authority crossed by '{title}' reaches further than the original proof",
        ),
    ]


def _from_removal(objective: RemovalObjective) -> EscalationObjective:
    return EscalationObjective(
        kind=KIND_REMOVE_PRECONDITION,
        objective=objective.objective,
        strategy=objective.strategy,
        success_criterion=objective.success_criterion,
        hypothesis=objective.hypothesis,
        precondition_id=objective.precondition_id,
    )


def plan_escalation(
    *,
    finding_title: str,
    finding_key: str = "",
    preconditions: Iterable[Precondition] = (),
    attempt: int = 1,
    max_attempts: int | None = None,
    already_falsified: Callable[[str], bool] | None = None,
    budget_remaining: int | None = None,
) -> EscalationPlan:
    """Build the next escalation plan for a confirmed finding. PURE.

    Objective order is deliberate: precondition removal first (it is the most direct route from a
    capped finding to an unconditional one), then the unconditional-location sweep, then blast
    radius. ``already_falsified`` is injected rather than read from a ledger so this stays pure
    and the bound is testable without a filesystem.

    Returns an exhausted plan — never an exception — when any bound is hit, which is how the
    caller knows to finish the finding and report."""

    title = _clean(finding_title, 200) or "the confirmed finding"
    key = str(finding_key or "") or hypothesis_key(title)
    cap = max_escalation_attempts() if max_attempts is None else max(0, int(max_attempts))
    seen = already_falsified or (lambda _h: False)

    if cap <= 0:
        return EscalationPlan(
            finding_key=key, finding_title=title, attempt=attempt, exhausted=True,
            reason="escalation is disabled (attempt cap is 0)",
        )
    if attempt > cap:
        return EscalationPlan(
            finding_key=key, finding_title=title, attempt=attempt, exhausted=True,
            reason=f"per-finding escalation attempt cap reached ({cap})",
        )
    if budget_remaining is not None and budget_remaining <= 0:
        return EscalationPlan(
            finding_key=key, finding_title=title, attempt=attempt, exhausted=True,
            reason="engagement-wide escalation budget is exhausted",
        )

    candidates: list[EscalationObjective] = [
        _from_removal(o) for o in removal_objectives(preconditions, finding_title=title)
    ]
    candidates += _standard_objectives(title)

    objectives: list[EscalationObjective] = []
    skipped = 0
    for objective in candidates:
        try:
            closed = bool(seen(objective.hypothesis))
        except Exception:
            closed = False  # a broken predicate must not silently close an objective
        if closed:
            skipped += 1
            continue
        objectives.append(objective)

    if not objectives:
        return EscalationPlan(
            finding_key=key, finding_title=title, attempt=attempt, exhausted=True,
            reason=(
                f"every escalation objective for this finding is already falsified "
                f"({skipped} closed) — it cannot be escalated further"
            ),
        )
    return EscalationPlan(
        finding_key=key, finding_title=title, attempt=attempt,
        objectives=tuple(objectives),
        reason=(f"{len(objectives)} objective(s) open"
                + (f", {skipped} already closed" if skipped else "")),
    )


class EscalationLoop:
    """Stateful, ledger-backed driver for escalation-after-confirmation. Never raises.

    Holds the per-finding attempt counters and the engagement-wide budget, records every attempt
    and outcome in the falsification ledger (so the bounds survive a restart), and emits each
    decision to the event log so the operator can watch a confirmed finding being pushed."""

    def __init__(
        self,
        ledger: FalsificationLedger | None = None,
        *,
        event_log: object | None = None,
        agent: str = "escalation",
        max_attempts: int | None = None,
        max_total: int | None = None,
    ) -> None:
        self.ledger = ledger
        self.log = event_log
        self.agent = agent
        self.max_attempts = max_escalation_attempts() if max_attempts is None else max(0, int(max_attempts))
        self.max_total = max_escalation_total() if max_total is None else max(0, int(max_total))
        self._attempts: dict[str, int] = {}
        self._total = 0

    # --- observability ----------------------------------------------------
    def _emit(self, kind: str, data: dict) -> None:
        if self.log is None:
            return
        try:
            self.log.emit(self.agent, kind, data)
        except Exception:
            return

    # --- bookkeeping ------------------------------------------------------
    def attempts_for(self, finding_key: str) -> int:
        """Attempts already spent on this finding, counting what is on disk from a prior run."""

        key = str(finding_key or "")
        spent = self._attempts.get(key, 0)
        if self.ledger is not None:
            family = f"{FAMILY_PREFIX}:{key}"
            try:
                persisted = sum(
                    1 for r in self.ledger.families().get(family, [])
                    if r.outcome == "attempted" and r.note.startswith("escalation pass")
                )
            except Exception:
                persisted = 0
            spent = max(spent, persisted)
        return spent

    def budget_remaining(self) -> int:
        return max(0, self.max_total - self._total)

    def _already_falsified(self, hypothesis: str) -> bool:
        if self.ledger is None:
            return False
        try:
            return self.ledger.already_falsified(hypothesis)
        except Exception:
            return False

    # --- the loop ---------------------------------------------------------
    def next_plan(
        self,
        *,
        finding_title: str,
        finding_key: str = "",
        preconditions: Iterable[Precondition] = (),
    ) -> EscalationPlan:
        """The next plan for a confirmed finding, or an exhausted plan when bounds are hit.

        Calling this IS the attempt: the counter advances and the attempt is written to the ledger,
        so a caller that loops on ``next_plan`` is guaranteed to terminate even if every objective
        keeps coming back open."""

        title = _clean(finding_title, 200) or "the confirmed finding"
        key = str(finding_key or "") or hypothesis_key(title)
        attempt = self.attempts_for(key) + 1

        plan = plan_escalation(
            finding_title=title,
            finding_key=key,
            preconditions=preconditions,
            attempt=attempt,
            max_attempts=self.max_attempts,
            already_falsified=self._already_falsified,
            budget_remaining=self.budget_remaining(),
        )

        if plan.exhausted:
            self._emit("lifecycle", {
                "event": "escalation_exhausted", "finding": title, "finding_key": key,
                "attempt": attempt, "reason": plan.reason,
            })
            return plan

        # Advance both bounds BEFORE handing the plan out, so an exception downstream cannot
        # produce an un-counted pass.
        self._attempts[key] = attempt
        self._total += 1
        if self.ledger is not None:
            try:
                self.ledger.note_attempt(
                    f"escalate '{title}' (pass {attempt})",
                    family=plan.family,
                    note=f"escalation pass {attempt}: {plan.reason}",
                    agent=self.agent,
                )
            except Exception:
                pass
        self._emit("message", {
            "phase": "escalation", "event": "escalation_planned", "finding": title,
            "finding_key": key, "attempt": attempt, "of": self.max_attempts,
            "objectives": [o.kind for o in plan.objectives],
            "budget_remaining": self.budget_remaining(),
            "directive": plan.as_prompt(),
        })
        return plan

    def record_outcome(
        self,
        plan: EscalationPlan,
        objective: EscalationObjective,
        *,
        succeeded: bool,
        mechanism: str = "",
        note: str = "",
    ) -> None:
        """Record one objective's result. A failure is a FALSIFICATION, not a silence.

        Falsifying the objective is what removes it from the next plan, and once every objective
        in the family is falsified the ledger emits the architectural conclusion that the finding
        cannot be escalated further."""

        if self.ledger is None:
            return
        try:
            if succeeded:
                self.ledger.record(
                    objective.hypothesis, outcome="survived", family=plan.family,
                    note=_clean(note) or "escalation objective achieved", agent=self.agent,
                )
            else:
                self.ledger.falsify(
                    objective.hypothesis, family=plan.family,
                    mechanism=_clean(mechanism) or "no path found on this pass",
                    note=_clean(note), agent=self.agent,
                )
        except Exception:
            return
        self._emit("message", {
            "phase": "escalation", "event": "escalation_outcome",
            "finding": plan.finding_title, "kind": objective.kind,
            "succeeded": bool(succeeded), "mechanism": _clean(mechanism, 200),
        })

    def conclusions(self) -> list:
        """Architectural conclusions newly supported by escalation work (closed escalations)."""

        if self.ledger is None:
            return []
        try:
            return [c for c in self.ledger.new_conclusions()
                    if c.family.startswith(FAMILY_PREFIX + ":")]
        except Exception:
            return []

    def summary(self) -> dict:
        return {
            "findings_escalated": len(self._attempts),
            "passes_spent": self._total,
            "passes_remaining": self.budget_remaining(),
            "per_finding_cap": self.max_attempts,
        }
