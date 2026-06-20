"""Falsifier — dedicated agent with the opposite prior (spec §7, §10).

Receives every CANDIDATE and tries to kill it: unreachable, mitigated, duplicate, or
overclaimed. Only survivors are promoted to CONFIRMED.
"""

from __future__ import annotations

from ..classify.signals import SignalHit
from ..models import Hypothesis, HypState
from ..orchestrator.blackboard import Blackboard
from ..orchestrator.event_log import EventLog
from .reasoner import Reasoner, Verdict


class Falsifier:
    def __init__(
        self, reasoner: Reasoner, blackboard: Blackboard, event_log: EventLog, *, name: str = "falsifier"
    ) -> None:
        self.name = name
        self.reasoner = reasoner
        self.bb = blackboard
        self.log = event_log
        self._confirmed_keys: set[str] = set()

    def judge(self, hyp: Hypothesis, hit: SignalHit, artifact_dir: str, depth: int) -> Verdict:
        # Duplicate check: same signal at the same location already confirmed.
        dup_key = f"{hit.signal.id}:{hit.file}:{hit.line}"
        if dup_key in self._confirmed_keys:
            self.bb.set_state(hyp.id, HypState.FALSIFIED)
            self.log.emit(self.name, "message", {"verdict": "killed", "hyp": hyp.id, "reason": "duplicate"})
            return Verdict(True, "duplicate of an already-confirmed finding")

        verdict = self.reasoner.falsify(hit, artifact_dir, depth)
        if verdict.killed:
            self.bb.set_state(hyp.id, HypState.FALSIFIED)
            self.log.emit(
                self.name, "message", {"verdict": "killed", "hyp": hyp.id, "reason": verdict.reason}
            )
            return verdict

        self._confirmed_keys.add(dup_key)
        self.bb.set_state(hyp.id, HypState.CONFIRMED)
        self.log.emit(
            self.name, "message", {"verdict": "survives", "hyp": hyp.id, "reason": verdict.reason}
        )
        return verdict
