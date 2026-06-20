"""Child B — long-lived, addressable track worker (spec §7).

Owns one track. Writes a hypothesis before testing, then spawns ephemeral **Child C**
subagents (blank context — everything packed into the subtask) to pursue one creative path
each. Every Child C evidence-gathering tool call passes the same ScopeGuard (subagents do
not inherit permissions, §3, §9). Promotes a candidate only on a reproduced artifact (§10).
"""

from __future__ import annotations

from ..classify.signals import SignalHit
from ..models import (
    Hypothesis,
    HypState,
    SafeValidationPlan,
    new_id,
)
from ..orchestrator.blackboard import Blackboard
from ..orchestrator.event_log import EventLog
from ..tools.base import GuardedTool
from .instructions import TrackDirective, child_subtask
from .reasoner import Reasoner


class ChildB:
    def __init__(
        self,
        name: str,
        directive: TrackDirective,
        hits: list[SignalHit],
        *,
        artifact_dir: str,
        reasoner: Reasoner,
        blackboard: Blackboard,
        event_log: EventLog,
        tools: dict[str, GuardedTool],
    ) -> None:
        self.name = name
        self.directive = directive
        self.hits = hits
        self.artifact_dir = artifact_dir
        self.reasoner = reasoner
        self.bb = blackboard
        self.log = event_log
        self.tools = tools
        self.depth = 1
        self._child_c_count = 0
        self._hyp_for_hit: dict[tuple[str, int], str] = {}

    def reframe(self, directive: TrackDirective, depth: int) -> None:
        self.directive = directive
        self.depth = depth
        self.log.emit(self.name, "reframe", {"frame": directive.frame, "depth": depth})

    async def work(self) -> list[Hypothesis]:
        """One round of the track at the current frame/depth. Returns new CANDIDATES."""
        candidates: list[Hypothesis] = []
        lens_hits = [h for h in self.hits if h.signal.lens == self.directive.surface.lens]
        # If the lens is dry, fall back to ALL hits — a creative move, never more aggressive.
        if not lens_hits:
            lens_hits = self.hits

        for index, hit in enumerate(lens_hits):
            hyp = self._ensure_hypothesis(hit)
            if hyp.state in (HypState.CANDIDATE, HypState.CONFIRMED):
                continue
            self.bb.set_state(hyp.id, HypState.TESTING)

            path = self.directive.creative_paths[
                (self.depth - 1 + index) % len(self.directive.creative_paths)
            ]
            artifact = await self._spawn_child_c(hyp, hit, path)
            if artifact is not None and artifact.reproduced:
                hyp.evidence.append(artifact)
                hyp.counterfactual = self.reasoner.counterfactual(hit)
                self.bb.add_artifact(artifact)
                self.bb.set_state(hyp.id, HypState.CANDIDATE)
                self.log.emit(
                    self.name,
                    "message",
                    {"to": "parent_a", "kind": "report", "candidate": hyp.id, "claim": hyp.claim},
                )
                candidates.append(hyp)
        return candidates

    def _ensure_hypothesis(self, hit: SignalHit) -> Hypothesis:
        key = (hit.file, hit.line)
        if key in self._hyp_for_hit:
            return self.bb.hypotheses[self._hyp_for_hit[key]]
        hyp = Hypothesis(
            id=new_id("HYP"),
            claim=(
                f"{hit.signal.title} at {hit.file}:{hit.line} may produce critical "
                f"{hit.signal.lens} impact if the trust boundary is reachable."
            ),
            owner_agent=self.name,
            lens=hit.signal.lens,
            target_assets=[self.directive.surface.target_asset],
            assumptions=[
                "The matched path is reachable by an untrusted or lower-privileged actor.",
                "No upstream control fully removes the impact.",
            ],
            safe_validation_plan=SafeValidationPlan(
                environment=self.directive.safe_validation_environment,
                max_contact="read-only / no destructive action",
                data_handling="synthetic, owned, redacted, or aggregate only",
            ),
            stop_conditions=list(self.directive.stop_conditions),
            evidence_required=[
                "Minimal reproduced artifact from the safe environment.",
                "Least-data evidence; redact secrets; no third-party data.",
            ],
        )
        self.bb.add_hypothesis(hyp)
        self._hyp_for_hit[key] = hyp.id
        return hyp

    async def _spawn_child_c(self, hyp: Hypothesis, hit: SignalHit, path: str):
        """Spawn an ephemeral, blank-context subagent for one creative path."""
        self._child_c_count += 1
        child_name = f"{self.name}.C{self._child_c_count}"
        subtask = child_subtask(
            sub_id=child_name,
            hypothesis_id=hyp.id,
            claim=hyp.claim,
            hit=hit,
            path=path,
            evidence_required=hyp.evidence_required,
        )
        self.log.emit(
            child_name,
            "lifecycle",
            {"event": "spawn", "parent": self.name, "path": path, "hyp": hyp.id},
        )

        # Evidence gathering goes through a guarded tool — subagent coverage (§9, §16).
        tool = self.tools.get("static_analysis") or next(iter(self.tools.values()), None)
        if tool is not None:
            result = await tool.run(
                {
                    "target": self.directive.surface.target_asset,
                    "path": self.artifact_dir,
                    "lens": hit.signal.lens,
                    "read_only": True,
                }
            )
            self.log.emit(
                child_name,
                "tool_call",
                {"tool": tool.name, "ok": result.ok, "denied": result.denied, "summary": result.summary},
            )
            if result.denied:
                self.log.emit(child_name, "lifecycle", {"event": "stop", "reason": result.reason})
                return None

        artifact = self.reasoner.validate(hyp, hit, self.artifact_dir, self.depth)
        self.log.emit(
            child_name,
            "lifecycle",
            {"event": "return", "reproduced": bool(artifact and artifact.reproduced)},
        )
        return artifact
