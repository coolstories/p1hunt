"""Parent A — orchestrator, derivation, delegation, never-quit, severity gate (spec §6-§10).

Carries the optimistic "a P1 exists" prior. Runs the derivation engine first, decomposes
the plan into tracks with CONCRETE creative briefs, and drives the never-quit loop: on a
dry spell it REFRAMES (rotate lens/surface, deepen analysis) rather than stopping, demoting
to the warm pool when frames saturate. Promotes a finding only through the believe-but-
verify gate — reproduced artifact + Falsifier survival + counterfactual mapped to the
program's own critical definition. Never auto-submits.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..classify.evm_signals import scan_combined
from ..classify.signals import SignalHit
from ..config import Config
from ..models import (
    ArtifactRef,
    EngagementPlan,
    EngagementStatus,
    Finding,
    Hypothesis,
    Scope,
    new_id,
)
from ..orchestrator.blackboard import Blackboard
from ..orchestrator.bus import MessageBus
from ..orchestrator.event_log import EventLog
from ..safety.scopeguard import ScopeGuard
from ..tools.registry import build_toolset
from .child_b import ChildB
from .derive import derive_plan
from .falsifier import Falsifier
from .instructions import parent_directive
from .reasoner import Reasoner, make_reasoner

_REMEDIATION: dict[str, str] = {
    "secret-in-source": "Revoke and rotate the credential, move secrets to a managed store, add secret scanning to CI.",
    "command-injection": "Avoid shell execution; use fixed argument arrays and allowlisted values.",
    "unsafe-deser": "Use safe parsers, disable arbitrary object construction, validate schemas before parsing.",
    "evm-tx-origin": "Use msg.sender with explicit role checks; test calls through intermediate contracts.",
    "evm-delegatecall": "Restrict privileged primitives to audited upgrade paths; validate targets; add invariant tests.",
    "evm-unchecked-call": "Bind and require() every low-level call's success flag; account for partial/failed transfers; add an invariant test that asserts balance conservation.",
    "evm-bare-ecrecover": "Reject address(0) from ecrecover, pin the expected signer, and enforce EIP-712 domain separation and nonce/replay protection.",
    "evm-div-before-mul": "Reorder fill/share math to multiply before dividing (or use a mulDiv helper); add a property test asserting no attacker-favorable rounding.",
    "evm-raw-delegatecall": "Restrict delegatecall to a constant/allowlisted implementation behind an audited upgrade path; add an invariant test guarding the storage layout.",
    "evm-reentrancy-call": "Apply checks-effects-interactions, add a reentrancy guard, and write an invariant/handler test that re-enters through the callback (ERC777/1155).",
    "mass-assignment": "Use DTO/schema allowlists; separate privileged writes; add negative tests for protected fields.",
    "jwt-no-verify": "Verify issuer, audience, expiry, and signature with an allowlisted algorithm.",
    "ci-privileged-pr": "Separate untrusted PR validation from privileged workflows; pin least-privilege permissions.",
    "cloud-wildcard-iam": "Replace wildcard principals/actions/resources with least-privilege; add policy-as-code checks.",
    "authz-fail-open": "Centralize authorization, deny by default, require ownership/role, add negative regression tests.",
    "idor-direct-object": "Bind object lookup to the authenticated principal and tenant; test cross-user negatives.",
    "ssrf": "Enforce a destination allowlist, block internal ranges, disable redirects, validate parsed URLs.",
    "sql-injection": "Use parameterized queries / bind variables; test metacharacters against local fixtures.",
    "path-traversal": "Resolve against a fixed base, reject traversal after normalization, use opaque file IDs.",
    "invariant-comment": "Encode the invariant as an enforced check and a property/invariant test on every path.",
}


@dataclass
class HuntResult:
    status: EngagementStatus
    plan: EngagementPlan
    rounds_run: int
    findings: list[Finding]
    reframes: int
    demoted_to_warm_pool: bool
    attestation: str
    candidates: list = field(default_factory=list)  # all surfaced candidates (real-scan visibility)
    # Believed-real, high-confidence P1s the Falsifier accepted but the deterministic runner could
    # NOT auto-reproduce (no live target / no runner / hard-to-harness). GENUINE output — surfaced
    # here so confirmed_critical=0 never reads as "found nothing" (the reproduce-or-bust gate is
    # also what parks true positives). Triage these.
    needs_human: list = field(default_factory=list)
    brain: str = "deterministic"  # "claude" | "deterministic"
    confirmed_critical: bool = field(init=False)

    def __post_init__(self) -> None:
        self.confirmed_critical = any(f.severity == "critical" for f in self.findings)


class ParentA:
    def __init__(
        self,
        scope: Scope,
        artifact_dir: str,
        *,
        config: Config,
        bus: MessageBus,
        blackboard: Blackboard,
        event_log: EventLog,
        guard: ScopeGuard | None = None,
        reasoner: Reasoner | None = None,
    ) -> None:
        self.scope = scope
        self.artifact_dir = artifact_dir
        self.config = config
        self.bus = bus
        self.bb = blackboard
        self.log = event_log
        self.reasoner = reasoner or make_reasoner(config.run_mode)
        self.name = "parent_a"
        self.plan: EngagementPlan | None = None
        self.guard = guard
        self.tracks: list[ChildB] = []
        self.falsifier: Falsifier | None = None
        self._hits: list[SignalHit] = []
        self._reframes = 0
        self._safety_event = False
        self.bus.register(self.name, "parent")

    # --- §6 derivation ----------------------------------------------------
    def derive(self) -> EngagementPlan:
        self.log.emit(self.name, "message", {"phase": "derivation", "program": self.scope.program})
        plan = derive_plan(self.scope, self.artifact_dir)
        self.plan = plan
        self.bb.set_scope(self.scope)
        self.bb.set_plan(plan)
        if self.guard is None:
            self.guard = ScopeGuard(
                plan.scopeguard_policy,
                on_decision=lambda d: self.log.emit(
                    "scopeguard",
                    "guard_decision",
                    {"allow": d.allow, "reason": d.reason, "tool": d.tool, "target": d.target, "agent": d.agent},
                ),
                unattended=self.config.unattended,
            )
        else:
            self.guard.policy = plan.scopeguard_policy
        return plan

    # --- §7 delegation ----------------------------------------------------
    def setup_tracks(self, max_tracks: int = 6) -> list[ChildB]:
        assert self.plan is not None and self.guard is not None, "call derive() first"
        self._hits = scan_combined(self.artifact_dir)
        self.falsifier = Falsifier(self.reasoner, self.bb, self.log)
        self.bus.register(self.falsifier.name, "falsifier")

        surfaces = [s for s in self.plan.surface_ranking if s.id != "SURF-BASELINE"]
        surfaces = surfaces[:max_tracks] or self.plan.surface_ranking[:1]
        for index, surface in enumerate(surfaces, start=1):
            directive = parent_directive(
                surface, self.plan, frame=f"{surface.lens} search", hits=self._hits, track_index=index
            )
            name = f"child_b{index}"
            self.bus.register(name, "worker")
            tools = build_toolset(self.plan.toolset, self.guard, name, active=self.config.active)
            child = ChildB(
                name,
                directive,
                self._hits,
                artifact_dir=self.artifact_dir,
                reasoner=self.reasoner,
                blackboard=self.bb,
                event_log=self.log,
                tools=tools,
            )
            self.tracks.append(child)
            # Hand over the concrete brief (specific, creative — not "do better").
            self.log.emit(
                self.name,
                "message",
                {"to": name, "kind": "assign", "directive": directive.as_prompt()},
            )
        return self.tracks

    # --- §8 never-quit Stop hook ------------------------------------------
    def on_stop(self) -> dict:
        """Stop is allowed ONLY on operator stop or a safety/scope event; else reframe."""
        if self.bb.has_stop(self.name) or self._safety_event:
            return {}  # allow stop
        reframe = self._next_frame()
        self.log.emit(self.name, "reframe", {"reason": reframe})
        return {"decision": "block", "reason": reframe}

    def _next_frame(self) -> str:
        self._reframes += 1
        surfaces = [s for s in (self.plan.surface_ranking if self.plan else []) if s.id != "SURF-BASELINE"]
        if not surfaces:
            return "deepen analysis on the current surface"
        nxt = surfaces[self._reframes % len(surfaces)]
        return f"rotate to {nxt.lens} surface ({nxt.title}); deepen, do not escalate aggressiveness"

    # --- §8 + §10 the hunt ------------------------------------------------
    async def hunt(self, max_rounds: int = 8) -> HuntResult:
        assert self.plan is not None and self.guard is not None and self.falsifier is not None
        findings: list[Finding] = []
        demoted = False
        rounds = 0

        for rounds in range(1, max_rounds + 1):
            self.log.emit(self.name, "message", {"phase": "round", "round": rounds, "depth": self.tracks[0].depth if self.tracks else 1})
            self._consume_directives()
            if self.bb.has_stop(self.name) or self._safety_event:
                self.log.emit(self.name, "lifecycle", {"event": "stop", "reason": "operator/safety"})
                return self._result(EngagementStatus.STOPPED, rounds, findings, demoted)

            round_candidates: list[tuple[Hypothesis, SignalHit]] = []
            for track in self.tracks:
                for hyp in await track.work():
                    hit = self._hit_for(hyp)
                    if hit is not None:
                        round_candidates.append((hyp, hit))

            for hyp, hit in round_candidates:
                verdict = self.falsifier.judge(hyp, hit, self.artifact_dir, self._depth())
                if verdict.killed:
                    continue
                finding = self._promote(hyp, hit)
                if finding is not None:
                    findings.append(finding)

            if any(f.severity == "critical" for f in findings):
                # Goal reached: a reproduced, Falsifier-survived critical. Surface for a human.
                self.log.emit(
                    self.name,
                    "finding",
                    {"event": "critical_confirmed", "count": len([f for f in findings if f.severity == 'critical'])},
                )
                return self._result(EngagementStatus.REPORT_READY, rounds, findings, demoted)

            # Dry spell -> reframe (never quit). Rotate frames, deepen, maybe demote.
            self._reframe_tracks()
            if self._reframes >= self.config.budgets.max_frames_per_track and not demoted:
                demoted = True
                self.log.emit(self.name, "lifecycle", {"event": "warm_pool_demotion"})

        return self._result(
            EngagementStatus.WARM_POOL if demoted else EngagementStatus.RUNNING,
            rounds,
            findings,
            demoted,
        )

    # --- believe-but-verify severity gate (§10, §2.8) ---------------------
    def _promote(self, hyp: Hypothesis, hit: SignalHit) -> Finding | None:
        repro = next((a for a in hyp.evidence if a.kind == "repro" and a.reproduced), None)
        if repro is None:  # artifact floor — never promote on reasoning alone
            return None
        severity = self.reasoner.severity(hit)
        counterfactual = hyp.counterfactual or self.reasoner.counterfactual(hit)
        assert self.guard is not None
        finding = Finding(
            id=new_id("FND"),
            hypothesis_id=hyp.id,
            title=hit.signal.title,
            root_cause=hit.signal.rationale,
            poc=repro,
            severity=severity,
            severity_rationale=(
                f"Counterfactual: {counterfactual} "
                f"Mapped to program taxonomy as {severity}; {self.plan.impact_definition if self.plan else ''}"
            ),
            counterfactual=counterfactual,
            remediation=_REMEDIATION.get(hit.signal.id, "Fix the root cause and add a regression test."),
            safe_harbor_attestation=self.guard.attestation(),
        )
        self.bb.add_finding(finding)
        return finding

    # --- helpers ----------------------------------------------------------
    def trigger_safety_event(self, reason: str) -> None:
        self._safety_event = True
        self.log.emit(self.name, "lifecycle", {"event": "safety_event", "reason": reason})

    def _consume_directives(self) -> None:
        for directive in self.bb.take_directives(self.name):
            self.log.emit(self.name, "message", {"directive_consumed": directive.kind, "payload": directive.payload})
            if directive.kind == "focus":
                self._focus(directive.payload)

    def _focus(self, lens: str) -> None:
        for track in self.tracks:
            if track.directive.surface.lens == lens:
                self.log.emit(self.name, "message", {"refocused": track.name, "lens": lens})

    def _reframe_tracks(self) -> None:
        if self.plan is None:
            return
        surfaces = [s for s in self.plan.surface_ranking if s.id != "SURF-BASELINE"]
        if not surfaces:
            for track in self.tracks:
                track.reframe(track.directive, track.depth + 1)
            return
        for offset, track in enumerate(self.tracks):
            self._reframes += 1
            nxt = surfaces[(self._reframes + offset) % len(surfaces)]
            directive = parent_directive(
                nxt, self.plan, frame=self._next_frame(), hits=self._hits, track_index=offset + 1
            )
            track.reframe(directive, track.depth + 1)

    def _depth(self) -> int:
        return self.tracks[0].depth if self.tracks else 1

    def _hit_for(self, hyp: Hypothesis) -> SignalHit | None:
        try:
            file, line = hyp.evidence[0].path.split(":") if hyp.evidence else (None, None)
        except ValueError:
            file, line = None, None
        for hit in self._hits:
            if file is not None and hit.file == file and str(hit.line) == str(line):
                return hit
        # Fall back to lens match.
        for hit in self._hits:
            if hit.signal.lens == hyp.lens:
                return hit
        return None

    # --- "there IS a P1, find it" visibility (§8 optimistic prior, §11 observability) -----
    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def _candidate_view(self, findings: list[Finding]) -> list[dict]:
        """Surface EVERY derived signal as a ranked P1 candidate — even the ones the offline
        artifact floor could not deterministically reproduce. The optimistic prior is that a
        P1 exists; the operator must always SEE the leads (strongest first) rather than a silent
        "nothing found". A hit already promoted to a confirmed finding is annotated as such."""
        promoted = {(f.poc.path if f.poc else "") for f in findings}
        out: list[dict] = []
        seen: set[str] = set()
        for hit in self._hits:
            key = f"{hit.file}:{hit.line}:{hit.signal.id}"
            if key in seen:
                continue
            seen.add(key)
            loc = f"{hit.file}:{hit.line}"
            out.append({
                "title": hit.signal.title,
                "severity": self.reasoner.severity(hit),
                "file": hit.file,
                "line": hit.line,
                "lens": hit.signal.lens,
                "snippet": hit.snippet,
                "root_cause": hit.signal.rationale,
                "reproduced": loc in promoted,
            })
        out.sort(key=lambda c: (self._SEV_ORDER.get(str(c["severity"]).lower(), 9), c["file"]))
        return out

    def _result(self, status, rounds, findings, demoted) -> HuntResult:
        assert self.plan is not None and self.guard is not None
        return HuntResult(
            status=status,
            plan=self.plan,
            rounds_run=rounds,
            findings=findings,
            reframes=self._reframes,
            demoted_to_warm_pool=demoted,
            attestation=self.guard.attestation(),
            candidates=self._candidate_view(findings),
        )
