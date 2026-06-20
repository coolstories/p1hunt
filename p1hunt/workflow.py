"""Phase-gate workflow runner (spec §2.2, §15.2).

Each phase produces a durable artifact before the next phase may start. The runner
enforces the promotion gates: mapping cannot start before acquisition artifacts exist;
testing cannot start before a hypothesis has a safe validation plan and stop conditions
(§16).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Phase(Enum):
    INTAKE = "intake"
    SAFETY = "safety"
    ACQUISITION = "acquisition"
    MAPPING = "mapping"
    HYPOTHESIS = "hypothesis"
    TESTING = "testing"
    VERIFICATION = "verification"
    REPORTING = "reporting"


_ORDER = list(Phase)

_GATES: dict[Phase, str] = {
    Phase.INTAKE: "Human confirms the program is open and the asset is in scope.",
    Phase.SAFETY: "Guard tests deny out-of-scope and destructive actions.",
    Phase.ACQUISITION: "Only approved assets were fetched or contacted.",
    Phase.MAPPING: "Every surface maps back to an in-scope asset.",
    Phase.HYPOTHESIS: "Each hypothesis has a non-destructive proof strategy.",
    Phase.TESTING: "No production harm and no third-party data exposure.",
    Phase.VERIFICATION: "The candidate survives adversarial review (reproduced artifact).",
    Phase.REPORTING: "Human reviewer approves scope, impact, and wording.",
}


class PhaseGateError(RuntimeError):
    pass


@dataclass
class WorkflowRunner:
    completed: set[Phase] = field(default_factory=set)

    def can_start(self, phase: Phase) -> bool:
        idx = _ORDER.index(phase)
        return all(p in self.completed for p in _ORDER[:idx])

    def require(self, phase: Phase) -> None:
        if not self.can_start(phase):
            missing = [p.value for p in _ORDER[: _ORDER.index(phase)] if p not in self.completed]
            raise PhaseGateError(
                f"cannot start '{phase.value}': prior phase(s) not complete: {', '.join(missing)}"
            )

    def complete(self, phase: Phase, *, gate_passed: bool) -> None:
        self.require(phase)
        if not gate_passed:
            raise PhaseGateError(f"promotion gate failed for '{phase.value}': {_GATES[phase]}")
        self.completed.add(phase)

    @staticmethod
    def gate_text(phase: Phase) -> str:
        return _GATES[phase]

    def progress(self) -> list[tuple[str, bool]]:
        return [(p.value, p in self.completed) for p in _ORDER]
