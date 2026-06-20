"""Blackboard — shared state for the swarm (spec §4, §5, §11).

Holds scope, the derived plan, the hypothesis backlog, artifacts, and the operator
control channel. Every mutation tees an Event to the log so the UI sees writes live.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import (
    ArtifactRef,
    ControlDirective,
    EngagementPlan,
    Finding,
    Hypothesis,
    HypState,
    Scope,
)

if TYPE_CHECKING:
    from .event_log import EventLog


class Blackboard:
    def __init__(self, event_log: "EventLog") -> None:
        self._log = event_log
        self.scope: Scope | None = None
        self.plan: EngagementPlan | None = None
        self.hypotheses: dict[str, Hypothesis] = {}
        self.findings: dict[str, Finding] = {}
        self.artifacts: dict[str, ArtifactRef] = {}
        self._control: list[ControlDirective] = []

    # --- scope / plan -----------------------------------------------------
    def set_scope(self, scope: Scope) -> None:
        self.scope = scope
        self._log.emit("blackboard", "bb_write", {"what": "scope", "program": scope.program})

    def set_plan(self, plan: EngagementPlan) -> None:
        self.plan = plan
        self._log.emit(
            "blackboard",
            "bb_write",
            {
                "what": "plan",
                "target_class": plan.target_class.value,
                "toolset": plan.toolset,
                "surfaces": len(plan.surface_ranking),
            },
        )

    # --- hypotheses -------------------------------------------------------
    def add_hypothesis(self, hyp: Hypothesis) -> None:
        self.hypotheses[hyp.id] = hyp
        self._log.emit(
            "blackboard", "bb_write", {"what": "hypothesis", "id": hyp.id, "claim": hyp.claim}
        )

    def set_state(self, hyp_id: str, state: HypState) -> None:
        hyp = self.hypotheses[hyp_id]
        hyp.state = state
        self._log.emit(
            "blackboard", "bb_write", {"what": "hyp_state", "id": hyp_id, "state": state.value}
        )

    def candidates(self) -> list[Hypothesis]:
        return [h for h in self.hypotheses.values() if h.state is HypState.CANDIDATE]

    # --- artifacts / findings --------------------------------------------
    def add_artifact(self, artifact: ArtifactRef) -> None:
        self.artifacts[artifact.id] = artifact
        self._log.emit(
            "blackboard",
            "bb_write",
            {"what": "artifact", "id": artifact.id, "reproduced": artifact.reproduced},
        )

    def add_finding(self, finding: Finding) -> None:
        self.findings[finding.id] = finding
        # Carry the fields the UI needs to render a full finding CARD (location, counterfactual,
        # remediation, reproduced) — additive; readers that only use id/title/severity still work.
        poc = getattr(finding, "poc", None)
        self._log.emit(
            "blackboard",
            "finding",
            {"id": finding.id, "title": finding.title, "severity": finding.severity,
             "location": getattr(poc, "path", "") or "", "lens": "",
             "counterfactual": getattr(finding, "counterfactual", "") or "",
             "remediation": getattr(finding, "remediation", "") or "",
             "reproduced": bool(getattr(poc, "reproduced", False)),
             "command": (getattr(poc, "description", "") or "")[:120]},
        )

    # --- control channel (§11) -------------------------------------------
    def push_directive(self, directive: ControlDirective) -> None:
        self._control.append(directive)
        self._log.emit(
            "operator",
            "bb_write",
            {"what": "directive", "target": directive.target_agent, "kind": directive.kind},
        )

    def take_directives(self, agent: str) -> list[ControlDirective]:
        """Consume any pending directives for ``agent`` (at its next hook checkpoint)."""
        pending = [
            d for d in self._control if d.target_agent in (agent, "*") and not d.consumed
        ]
        for directive in pending:
            directive.consumed = True
        return pending

    def has_stop(self, agent: str) -> bool:
        return any(
            d.target_agent in (agent, "*") and d.kind == "stop" for d in self._control
        )
