"""Parent A — orchestrator, derivation, delegation, never-quit, severity gate (spec §6-§10).

Carries the optimistic "a P1 exists" prior. Runs the derivation engine first, decomposes
the plan into tracks with CONCRETE creative briefs, and drives the never-quit loop: on a
dry spell it REFRAMES (rotate lens/surface, deepen analysis) rather than stopping, demoting
to the warm pool when frames saturate. Promotes a finding only through the believe-but-
verify gate — reproduced artifact + Falsifier survival + counterfactual mapped to the
program's own critical definition. Never auto-submits.

Three mechanisms keep the never-quit loop from degenerating into a never-PROGRESS loop:

  * MEMORY OF FAILURE — every reframe consults the falsification ledger
    (:mod:`p1hunt.ledger`) and refuses to re-issue a frame already ruled out, so rotation
    explores instead of cycling. A frame that goes dry for several passes is itself recorded
    as falsified, and when enough frames close, the ledger emits an architectural conclusion.
  * COMPOUNDING COVERAGE — each round records which entrypoints it actually reached in the
    corpus and steers the next round at the ones still dark
    (:mod:`p1hunt.agents.surface_enum` now supplies that surface for every target class, not
    just EVM).
  * ESCALATION AFTER CONFIRMATION — a confirmed critical RE-ENTERS the hunt with escalation
    objectives (:mod:`p1hunt.agents.escalation`) instead of ending it, bounded so it
    terminates.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from ..classify.evm_signals import scan_combined
from ..classify.signals import SignalHit
from ..config import Config
from ..corpus import CorpusStore
from ..ledger import FalsificationLedger, hypothesis_key
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
from .escalation import EscalationLoop
from .falsifier import Falsifier
from .instructions import escalation_directive, parent_directive
from .preconditions import PreconditionModel, rescore
from .reasoner import Reasoner, make_reasoner
from .surface_enum import covered_from_paths, entrypoints_for

# Persistence dials. Implemented here via os.environ (config.py is owned elsewhere) with a
# default that RAISES the shipped ceiling — see the module report for the config change wanted.
_DEFAULT_MAX_FRAMES = 120   # was Budgets.max_frames_per_track = 24: too low for a long hunt
_DEFAULT_FRAME_FALSIFY_AFTER = 3  # dry passes over one surface before it is recorded as closed


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = str(os.environ.get(name, "")).strip()
    if raw.isdigit() and int(raw) >= minimum:
        return int(raw)
    return default

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
    # Escalation work done AFTER a finding was confirmed (mechanism: a confirmed finding is not
    # terminal). Each entry is one escalation plan that was issued back into the hunt.
    escalations: list = field(default_factory=list)
    # Well-supported NEGATIVES: variant classes the ledger proved closed. A reportable
    # confidence artifact — "this variant is architecturally impossible", not wasted work.
    conclusions: list = field(default_factory=list)
    ledger_summary: dict = field(default_factory=dict)
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
        # --- persistence memory (wired in derive(), usable before it) ---------------------
        # The ledger is what stops the never-quit loop from re-testing dead ends. It is created
        # memory-only here and re-pointed at the engagement folder in derive(), so a ParentA
        # built without an engagement dir still works (offline-graceful).
        self.ledger = FalsificationLedger(None)
        self.corpus: CorpusStore | None = None
        self.escalation = EscalationLoop(self.ledger, event_log=self.log, agent=self.name)
        self._dry_passes: dict[str, int] = {}       # surface id -> consecutive dry passes
        self._escalation_plans: list = []           # every escalation plan issued this hunt
        self._conclusions: list = []                # architectural conclusions emitted
        self._precondition_models: dict[str, PreconditionModel] = {}
        self._entrypoints: list[str] = []
        self.bus.register(self.name, "parent")

    # --- persistence dials -------------------------------------------------
    def _max_frames(self) -> int:
        """Reframes before warm-pool demotion.

        Dial: ``P1HUNT_MAX_FRAMES_PER_TRACK``. ``Budgets.max_frames_per_track`` now ships at 120;
        it was 24, which is too low for a long-horizon hunt — a surface sweep plus a few deepening
        passes burns it before the compounding mechanisms have a chance to pay off. This floor is
        kept as a backstop so an old or hand-edited config cannot silently return the swarm to a
        short-horizon budget, and an explicitly configured LARGER budget still wins."""

        configured = int(getattr(self.config.budgets, "max_frames_per_track", 0) or 0)
        return _env_int("P1HUNT_MAX_FRAMES_PER_TRACK", max(configured, _DEFAULT_MAX_FRAMES))

    def _frame_falsify_after(self) -> int:
        """Dry passes over one surface before the frame is recorded as falsified.

        Dial: ``P1HUNT_FRAME_FALSIFY_AFTER`` (default 3). One dry round is not evidence; several
        passes with no surviving candidate is. Set high to keep every frame live forever."""

        return _env_int("P1HUNT_FRAME_FALSIFY_AFTER", _DEFAULT_FRAME_FALSIFY_AFTER)

    def _engagement_dir(self) -> Path | None:
        """The engagement folder, by the same convention the rest of the package uses: the
        directory holding the event log (where state.json / corpus.json already live)."""

        path = getattr(self.log, "path", None)
        if path is None:
            return None
        try:
            return Path(path).parent
        except (TypeError, ValueError):
            return None

    # --- frame hypotheses (what the ledger keys reframes on) ---------------
    @staticmethod
    def _frame_hypothesis(surface) -> str:
        """The claim a frame makes, keyed independently of which pass issued it.

        Pass number is deliberately excluded: "surface S yields a critical" is the same claim on
        pass 2 as on pass 7, and including the pass would make every frame unique — which is
        exactly how a ledger silently stops working as a loop guard."""

        return (
            f"surface '{getattr(surface, 'title', '')}' (lens {getattr(surface, 'lens', '')}) "
            f"yields a reproducible critical on {getattr(surface, 'target_asset', '')}"
        )

    FRAME_FAMILY = "derived-surface-frames"

    def _closed_frames(self) -> list[str]:
        """Frame claims the ledger has ruled out — handed to tracks as 'do not re-test'."""

        surfaces = [s for s in (self.plan.surface_ranking if self.plan else []) if s.id != "SURF-BASELINE"]
        out: list[str] = []
        for surface in surfaces:
            claim = self._frame_hypothesis(surface)
            if self.ledger.already_falsified(claim):
                out.append(claim)
        return out

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
        self._attach_memory(plan)
        return plan

    def _attach_memory(self, plan: EngagementPlan) -> None:
        """Point the falsification ledger and the coverage corpus at the engagement folder.

        Both are append-only and tolerate a missing/corrupt file, so a resumed engagement reads
        back everything already ruled out and already covered — which is what makes persistence
        survive a process restart rather than restarting the search from zero. Never raises."""

        engagement_dir = self._engagement_dir()
        if engagement_dir is not None:
            try:
                self.ledger = FalsificationLedger(engagement_dir)
            except Exception:
                self.ledger = FalsificationLedger(None)
            try:
                self.corpus = CorpusStore(engagement_dir)
            except Exception:
                self.corpus = None
        self.escalation = EscalationLoop(self.ledger, event_log=self.log, agent=self.name)

        # The attack surface for THIS target class — EVM keeps its Solidity signatures; web/API
        # targets now get a real route list instead of [], so uncovered_hint can steer rounds.
        try:
            self._entrypoints = entrypoints_for(plan.target_class, self.artifact_dir)
        except Exception:
            self._entrypoints = []

        summary = {}
        try:
            summary = self.ledger.summary()
        except Exception:
            summary = {}
        self.log.emit(self.name, "lifecycle", {
            "event": "persistence_memory_attached",
            "ledger": str(getattr(self.ledger, "path", "") or "(memory only)"),
            "prior_falsifications": summary.get("falsified", 0),
            "prior_hypotheses": summary.get("distinct_hypotheses", 0),
            "entrypoints_known": len(self._entrypoints),
            "max_frames": self._max_frames(),
        })

    def _coverage_hint(self, surface) -> str:
        """The corpus's steer for this surface: which entrypoints are still dark.

        "" when nothing is known or everything is covered — the hint is only ever added when it
        actually names unexplored surface, so a round is never handed a vacuous instruction."""

        if self.corpus is None or not self._entrypoints:
            return ""
        try:
            return self.corpus.uncovered_hint(str(getattr(surface, "lens", "")), self._entrypoints)
        except Exception:
            return ""

    # --- §7 delegation ----------------------------------------------------
    def setup_tracks(self, max_tracks: int = 6) -> list[ChildB]:
        assert self.plan is not None and self.guard is not None, "call derive() first"
        # Legacy deterministic signal scanning is opt-in only. Default runs must not seed Parent A
        # with preset failure modes; live/Codex hunts derive tracks and hypotheses from recon.
        self._hits = scan_combined(self.artifact_dir) if os.environ.get("P1HUNT_LEGACY_STATIC_SIGNALS") == "1" else []
        self.falsifier = Falsifier(self.reasoner, self.bb, self.log)
        self.bus.register(self.falsifier.name, "falsifier")

        surfaces = [s for s in self.plan.surface_ranking if s.id != "SURF-BASELINE"]
        surfaces = surfaces[:max_tracks] or self.plan.surface_ranking[:1]
        closed = self._closed_frames()
        for index, surface in enumerate(surfaces, start=1):
            directive = parent_directive(
                surface, self.plan, frame=f"{surface.lens} search", hits=self._hits, track_index=index,
                coverage_hint=self._coverage_hint(surface), ruled_out=closed,
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
        """The next frame to issue — never one the ledger has already ruled out.

        THE LOOP GUARD. Plain rotation re-issues a dead end as soon as it comes round again, so
        rotation alone is not persistence; it is a cycle that merely looks busy. Here every
        candidate frame is checked against the falsification ledger and skipped if it is closed,
        with the skip emitted so the operator can see the search narrowing. When every derived
        frame is closed, that is itself a result: the ledger composes an architectural conclusion
        and the loop falls back to deepening the current surface rather than spinning the rotor."""

        self._reframes += 1
        surfaces = [s for s in (self.plan.surface_ranking if self.plan else []) if s.id != "SURF-BASELINE"]
        if not surfaces:
            return f"deepen analysis on the current surface (pass {self._reframes})"

        skipped: list[str] = []
        # Walk the rotation at most once around, so a fully-closed surface set terminates.
        for offset in range(len(surfaces)):
            candidate = surfaces[(self._reframes + offset) % len(surfaces)]
            claim = self._frame_hypothesis(candidate)
            if self.ledger.already_falsified(claim):
                skipped.append(candidate.title)
                continue
            if skipped:
                self.log.emit(self.name, "reframe", {
                    "event": "frames_skipped_already_falsified",
                    "skipped": skipped,
                    "chosen": candidate.title,
                    "detail": "the ledger has these frames ruled out; not re-issuing them",
                })
            return (
                f"rotate to {candidate.lens} surface ({candidate.title}); deepen pass "
                f"{self._reframes}, do not escalate aggressiveness"
            )

        # Every derived frame is closed — a well-supported negative, not a failure.
        self._emit_conclusions()
        self.log.emit(self.name, "reframe", {
            "event": "all_frames_falsified",
            "frames": len(surfaces),
            "detail": (
                "every derived surface frame is recorded falsified; deepening the current surface "
                "instead of re-issuing a closed frame"
            ),
        })
        return (
            f"all derived surface frames are closed in the ledger — deepen the current surface "
            f"with a new analytical angle (pass {self._reframes})"
        )

    def _emit_conclusions(self) -> list:
        """Emit any newly-supported architectural conclusions. Never raises.

        A family of related falsifications that is now complete becomes a reportable artifact:
        "this variant class is closed, and these mechanisms close it." Written to the engagement
        folder and teed to the event log so it lands in the operator's view like any finding."""

        try:
            fresh = self.ledger.new_conclusions()
        except Exception:
            return []
        for conclusion in fresh:
            path = ""
            try:
                path = self.ledger.write_conclusion(conclusion)
            except Exception:
                path = ""
            self._conclusions.append(conclusion)
            self.log.emit(self.name, "finding", {
                "event": "architectural_conclusion",
                "variant_class": conclusion.family,
                "closed_variants": conclusion.closed_count,
                "mechanisms": list(conclusion.mechanisms),
                "statement": conclusion.statement,
                "artifact": path,
            })
        return fresh

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

            fresh: list[Finding] = []
            for hyp, hit in round_candidates:
                verdict = self.falsifier.judge(hyp, hit, self.artifact_dir, self._depth())
                if verdict.killed:
                    # A Falsifier kill IS a falsification — record it so no later reframe pays to
                    # re-derive the same dead end, and so related kills can compose a conclusion.
                    self.ledger.falsify(
                        hyp.claim,
                        mechanism=verdict.reason,
                        family=f"candidate:{hyp.lens}",
                        note=f"killed by the Falsifier in round {rounds}",
                        agent=self.falsifier.name,
                    )
                    continue
                finding = self._promote(hyp, hit)
                if finding is not None:
                    findings.append(finding)
                    fresh.append(finding)
                    # A surviving candidate re-opens its claim: new information beats an old
                    # negative, so a later reframe is free to pursue it again.
                    self.ledger.record(
                        hyp.claim, outcome="survived", family=f"candidate:{hyp.lens}",
                        note=f"promoted to a finding in round {rounds}", agent=self.name,
                    )

            # Round-over-round COVERAGE: record what this round actually reached so the next round
            # is steered at what is still dark instead of re-covering the same ground.
            self._record_round_coverage(round_candidates)
            # Frames that keep coming up dry are recorded closed (after several passes, not one).
            self._age_frames(fresh)
            self._emit_conclusions()

            criticals = [f for f in findings if f.severity == "critical"]
            if criticals:
                self.log.emit(
                    self.name,
                    "finding",
                    {"event": "critical_confirmed", "count": len(criticals)},
                )
                # A CONFIRMED FINDING IS NOT TERMINAL. Re-enter the hunt with escalation
                # objectives — remove a precondition, find a location where it is unconditional,
                # widen the crossed authority — until the bounded escalation budget is spent.
                if self._escalate(criticals, rounds):
                    continue
                return self._result(EngagementStatus.REPORT_READY, rounds, findings, demoted)

            # Dry spell -> reframe (never quit). Rotate frames, deepen, maybe demote.
            self._reframe_tracks()
            if self._reframes >= self._max_frames() and not demoted:
                demoted = True
                self.log.emit(self.name, "lifecycle", {"event": "warm_pool_demotion"})

        # Escalation may have consumed the remaining rounds; a confirmed critical still means the
        # engagement is report-ready, never "still running".
        if any(f.severity == "critical" for f in findings):
            return self._result(EngagementStatus.REPORT_READY, rounds, findings, demoted)
        return self._result(
            EngagementStatus.WARM_POOL if demoted else EngagementStatus.RUNNING,
            rounds,
            findings,
            demoted,
        )

    # --- compounding coverage (mechanism: rounds must accumulate) ----------
    def _record_round_coverage(self, round_candidates: list) -> None:
        """Record the surface this round actually touched, per lens. Never raises.

        Without this the coverage ledger stays empty and ``uncovered_hint`` returns "" forever,
        which is precisely why rounds did not compound on non-EVM targets."""

        if self.corpus is None:
            return
        touched: dict[str, list[str]] = {}
        for hyp, hit in round_candidates or ():
            lens = getattr(hyp, "lens", "") or getattr(getattr(hit, "signal", None), "lens", "")
            if not lens:
                continue
            touched.setdefault(lens, []).append(str(getattr(hit, "file", "")))
        for track in self.tracks:
            lens = getattr(track.directive.surface, "lens", "")
            if lens and lens not in touched:
                touched.setdefault(lens, [])
        for lens, files in touched.items():
            # Coverage is recorded at ENTRYPOINT granularity, not file granularity: the routes a
            # touched file actually declares are what the next round's uncovered hint reasons
            # about, so a file visit only ever marks the entrypoints it really contains.
            symbols = list(files)
            for path in {f for f in files if f}:
                try:
                    symbols.extend(entrypoints_for(
                        self.plan.target_class if self.plan else None,
                        self.artifact_dir, [path],
                    ))
                except Exception:
                    continue
            try:
                self.corpus.record(
                    lens,
                    coverage_notes=[f"pass at depth {self._depth()}"],
                    covered_symbols=covered_from_paths(symbols),
                )
            except Exception:
                continue

    def _age_frames(self, fresh: list[Finding]) -> None:
        """Count dry passes per surface and close a frame that stays dry. Never raises.

        A single empty round proves nothing, so a frame is only recorded falsified after
        ``_frame_falsify_after`` consecutive dry passes — at which point "this frame does not
        yield" is a supported negative, and the reframe path will stop re-issuing it."""

        if self.plan is None:
            return
        productive = {getattr(f, "title", "") for f in (fresh or [])}
        threshold = self._frame_falsify_after()
        for track in self.tracks:
            surface = track.directive.surface
            sid = getattr(surface, "id", "") or getattr(surface, "title", "")
            if not sid:
                continue
            if productive:
                self._dry_passes[sid] = 0
                continue
            count = self._dry_passes.get(sid, 0) + 1
            self._dry_passes[sid] = count
            if count < threshold:
                continue
            claim = self._frame_hypothesis(surface)
            if self.ledger.already_falsified(claim):
                continue
            self.ledger.falsify(
                claim,
                mechanism=f"{count} consecutive passes over this surface produced no surviving candidate",
                family=self.FRAME_FAMILY,
                note=f"frame closed at depth {self._depth()}",
                agent=self.name,
            )
            self.log.emit(self.name, "reframe", {
                "event": "frame_falsified",
                "surface": getattr(surface, "title", ""),
                "dry_passes": count,
                "detail": "recorded in the ledger; this frame will not be re-issued",
            })

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

    # --- escalation after confirmation (a confirmed finding is not terminal) ----
    def _severity_mapper(self):
        """A mapper over the PROGRAM'S OWN taxonomy — never a hardcoded tier scheme."""

        from ..severity import SeverityMapper

        return SeverityMapper(getattr(self.scope, "severity_taxonomy", {}) or {})

    def _base_assessment(self, finding: Finding):
        """The objective facts of a promoted finding, BEFORE preconditions are applied.

        Every gate here is already established by the promotion path rather than assumed: the
        finding exists only with a reproduced artifact (§10), on an in-scope asset the program
        protects, with a counterfactual showing an authority was crossed — which is what
        ``concrete_loss="control"`` records. Preconditions then pull gates back down, so the
        difference between the capped and uncapped score is exactly the conditions."""

        from ..severity import ImpactAssessment

        poc = getattr(finding, "poc", None)
        return ImpactAssessment(
            reproduced=bool(getattr(poc, "reproduced", False)),
            protected_asset=True,
            attacker_capability=True,
            concrete_loss="control",
            in_scope=True,
            note=str(getattr(finding, "counterfactual", "") or "")[:200],
        )

    def precondition_model(self, finding: Finding) -> PreconditionModel:
        """The explicit precondition model for a finding (cached per finding).

        Built from the finding's OWN text — its severity rationale, counterfactual, and root
        cause — because those are where a cap is actually stated ("only while signed out",
        "requires an admin to click"). Nothing is invented: a finding whose text states no
        condition gets an empty model and is treated as unconditional."""

        key = getattr(finding, "id", "") or getattr(finding, "title", "")
        model = self._precondition_models.get(key)
        if model is None:
            narrative = " ".join(str(x or "") for x in (
                getattr(finding, "severity_rationale", ""),
                getattr(finding, "counterfactual", ""),
                getattr(finding, "root_cause", ""),
            ))
            model = PreconditionModel.for_finding(
                getattr(finding, "title", ""), narrative=narrative
            )
            self._precondition_models[key] = model
            if model.preconditions:
                self.log.emit(self.name, "message", {
                    "phase": "preconditions",
                    "event": "preconditions_modeled",
                    **model.summary(),
                })
        return model

    def projected_severity(self, finding: Finding) -> dict:
        """What this finding would score if every precondition were removed. Never raises.

        The operator-facing reason to spend an escalation pass: it shows the capped label, the
        unconditional label, and the specific conditions standing between them."""

        try:
            model = self.precondition_model(finding)
            result = rescore(
                self._severity_mapper(), self._base_assessment(finding), model.preconditions,
                removed_ids=[p.id for p in model.preconditions],
            )
            return result.as_dict()
        except Exception:
            return {}

    def remove_precondition(self, finding: Finding, precondition_id: str, evidence: str = "") -> dict:
        """Mark a precondition removed and RE-SCORE the finding upward. Never raises.

        This is the step that turns a capped finding into an unconditional one: the removal is
        recorded, the finding's severity and rationale are rewritten through the program's own
        taxonomy, and the ledger records the removal hypothesis as SURVIVED so the escalation
        loop stops re-issuing an objective that has already succeeded."""

        try:
            model = self.precondition_model(finding)
            if not model.mark_removed(precondition_id, evidence):
                return {}
            mapper = self._severity_mapper()
            result = model.rescore(mapper, self._base_assessment(finding))
            previous = getattr(finding, "severity", "")
            if result.raised:
                finding.severity = result.label
                finding.severity_rationale = result.rationale
            # Record under the finding's escalation family so the loop sees this objective as
            # achieved (SURVIVED), not as an open objective to re-issue next pass.
            self.ledger.record(
                f"precondition {precondition_id} of '{getattr(finding, 'title', '')}' can be removed",
                outcome="survived",
                family=f"escalation:{hypothesis_key(getattr(finding, 'title', ''))}",
                note=evidence or "precondition removed",
                agent=self.name,
            )
            self.log.emit(self.name, "finding", {
                "event": "severity_rescored_after_precondition_removed",
                "finding": getattr(finding, "title", ""),
                "precondition": precondition_id,
                "from": previous,
                "to": getattr(finding, "severity", ""),
                "raised": result.raised,
                "evidence": str(evidence or "")[:200],
                **result.as_dict(),
            })
            return result.as_dict()
        except Exception:
            return {}

    def _escalate(self, criticals: list[Finding], round_no: int) -> bool:
        """Issue an escalation pass for each confirmed critical. True when the hunt continues.

        Bounded three ways (per-finding attempt cap, ledger de-duplication of objectives, and an
        engagement-wide total), so this cannot loop forever: once every finding's objectives are
        spent or closed, it returns False and the hunt reports. Never raises — an escalation
        problem degrades to "finish and report", which is the safe direction."""

        issued: list = []
        for finding in criticals:
            try:
                model = self.precondition_model(finding)
                projection = self.projected_severity(finding)
                if projection.get("raised"):
                    self.log.emit(self.name, "message", {
                        "phase": "escalation",
                        "event": "escalation_headroom",
                        "finding": getattr(finding, "title", ""),
                        "current": projection.get("previous_severity"),
                        "if_unconditional": projection.get("severity"),
                        "blocking_preconditions": projection.get("removed_preconditions", []),
                    })
                plan = self.escalation.next_plan(
                    finding_title=getattr(finding, "title", ""),
                    preconditions=model.preconditions,
                )
            except Exception:
                continue
            if getattr(plan, "exhausted", True):
                continue
            issued.append(plan)
            self._escalation_plans.append(plan)

        if not issued:
            self._emit_conclusions()
            self.log.emit(self.name, "lifecycle", {
                "event": "escalation_complete",
                "detail": "no escalation objective remains open; the finding set is final",
                **self.escalation.summary(),
            })
            return False

        # Re-brief the tracks onto the escalation objectives. The tracks keep working; only what
        # they are chasing changes — the finding is proven, so the pass is spent on impact.
        if self.plan is not None:
            for offset, track in enumerate(self.tracks):
                plan = issued[offset % len(issued)]
                try:
                    directive = escalation_directive(
                        track.directive.surface, self.plan, plan,
                        track_index=offset + 1, ruled_out=self._closed_frames(),
                    )
                    track.reframe(directive, track.depth + 1)
                except Exception:
                    continue
        self._reframes += 1
        self.log.emit(self.name, "reframe", {
            "event": "escalation_reentry",
            "round": round_no,
            "plans": [p.as_dict() for p in issued],
            "detail": "a confirmed finding re-entered the hunt with escalation objectives",
        })
        return True

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
        closed = self._closed_frames()
        # Prefer surfaces the ledger has NOT closed; fall back to the full set only when every
        # frame is closed (then the frame text itself says "deepen", via _next_frame).
        open_surfaces = [s for s in surfaces if not self.ledger.already_falsified(self._frame_hypothesis(s))]
        rotation = open_surfaces or surfaces
        for offset, track in enumerate(self.tracks):
            self._reframes += 1
            nxt = rotation[(self._reframes + offset) % len(rotation)]
            directive = parent_directive(
                nxt, self.plan, frame=self._next_frame(), hits=self._hits, track_index=offset + 1,
                coverage_hint=self._coverage_hint(nxt), ruled_out=closed,
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
            escalations=[p.as_dict() for p in self._escalation_plans],
            conclusions=[
                {"variant_class": c.family, "closed_variants": c.closed_count,
                 "mechanisms": list(c.mechanisms), "statement": c.statement}
                for c in self._conclusions
            ],
            ledger_summary=self._ledger_summary(),
        )

    def _ledger_summary(self) -> dict:
        """Counts of what has been ruled out, for the operator view / report. Never raises."""

        try:
            summary = dict(self.ledger.summary())
        except Exception:
            return {}
        summary["escalation"] = self.escalation.summary()
        return summary
