"""Wiring tests: the four mechanisms actually attached to Parent A's never-quit loop.

The mechanisms are unit-tested in test_ledger / test_asymmetry / test_preconditions /
test_escalation. What is tested HERE is that they are connected, because an unwired ledger is
the failure mode the whole exercise exists to remove — persistence that still loops:

  * ``_next_frame()`` must not re-issue a frame the ledger has ruled out;
  * a frame that stays dry must become a falsification (after several passes, not one);
  * a Falsifier kill must be recorded so later rounds do not pay to re-derive it;
  * the ledger (and so the loop guard) must survive a process restart;
  * a CONFIRMED finding must re-enter the hunt with escalation objectives, bounded; and
  * a web target's rounds must compound through the coverage ledger.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path

from p1hunt.agents.parent_a import ParentA
from p1hunt.config import Config
from p1hunt.ledger import FalsificationLedger
from p1hunt.models import Asset, ControlDirective, Scope
from p1hunt.orchestrator.blackboard import Blackboard
from p1hunt.orchestrator.bus import MessageBus
from p1hunt.orchestrator.event_log import EventLog

TAXONOMY = {"P1": "critical: unauthenticated takeover", "P2": "high: needs conditions"}


def _scope() -> Scope:
    return Scope(
        program="Wiring Co", platform="HackerOne", disclosure_channel="x@y",
        safe_harbor_text="UAT only.", severity_taxonomy=dict(TAXONOMY),
        in_scope=[Asset("a", "src", "repo", "target", "local")],
        rules=["no prod"], rate_limit="10/min",
    )


def _target(root: Path) -> str:
    """A web-shaped target with SEVERAL top-level components and declared routes.

    Several components matter: ``derive`` maps one surface per top-level directory, and proving
    that a reframe SKIPS a closed frame needs more than one frame to choose between. The
    vulnerable sample goes in one component so the deterministic brain can still confirm a
    critical (which is what the escalation-re-entry tests need)."""

    from p1hunt.samples import write_vulnerable_target

    root.mkdir(parents=True, exist_ok=True)
    write_vulnerable_target(root / "api", kind="web")
    (root / "web").mkdir(parents=True, exist_ok=True)
    (root / "web" / "share.js").write_text(
        'app.get("/doc/:id", (req,res)=>{ res.json(db.get(req.params.id)); });\n'
        'app.post("/share", (req,res)=>{ res.send(req.body.html); });\n',
        encoding="utf-8",
    )
    (root / "admin").mkdir(parents=True, exist_ok=True)
    (root / "admin" / "export.js").write_text(
        'app.get("/admin/export", (req,res)=>{ res.json(db.all()); });\n', encoding="utf-8"
    )
    (root / "billing").mkdir(parents=True, exist_ok=True)
    (root / "billing" / "charge.js").write_text(
        'app.post("/charge", (req,res)=>{ res.json(pay(req.body)); });\n', encoding="utf-8"
    )
    return str(root)


class _Harness:
    """A ParentA wired to a real engagement folder, so the ledger/corpus persist."""

    def __init__(self, tmp: str, *, engagement: str = "eng") -> None:
        self.root = Path(tmp)
        self.target = _target(self.root / "t")
        self.engagement = self.root / engagement
        self.engagement.mkdir(parents=True, exist_ok=True)
        self.log = EventLog(self.engagement / "events.jsonl")
        self.bus = MessageBus(self.log)
        self.bb = Blackboard(self.log)
        cfg = Config.from_env()
        cfg.use_claude = False
        self.parent = ParentA(_scope(), self.target, config=cfg, bus=self.bus,
                              blackboard=self.bb, event_log=self.log)
        self.parent.derive()
        self.parent.setup_tracks()

    def events(self, event: str) -> list[dict]:
        return [e.data for e in self.log.events if e.data.get("event") == event]

    def reframe_reasons(self) -> list[str]:
        return [e.data.get("reason", "") for e in self.log.events if e.kind == "reframe"]


class LedgerAttachmentTest(unittest.TestCase):
    def test_ledger_and_corpus_land_in_the_engagement_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            self.assertEqual(
                Path(str(h.parent.ledger.path)).parent.resolve(), h.engagement.resolve()
            )
            self.assertIsNotNone(h.parent.corpus)
            attached = h.events("persistence_memory_attached")
            self.assertEqual(len(attached), 1)
            # A web target must now have a non-empty entrypoint list (previously always 0).
            self.assertGreater(attached[0]["entrypoints_known"], 0)

    def test_parent_without_a_log_path_degrades_to_memory_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = EventLog()  # no path
            cfg = Config.from_env()
            cfg.use_claude = False
            parent = ParentA(_scope(), _target(Path(tmp) / "t"), config=cfg,
                             bus=MessageBus(log), blackboard=Blackboard(log), event_log=log)
            parent.derive()  # must not raise
            self.assertIsNone(parent.ledger.path)
            parent.ledger.falsify("x")
            self.assertTrue(parent.ledger.already_falsified("x"))


class ReframeGuardTest(unittest.TestCase):
    """THE wiring test: _next_frame must consult the ledger."""

    def test_next_frame_skips_a_falsified_frame(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            surfaces = [s for s in h.parent.plan.surface_ranking if s.id != "SURF-BASELINE"]
            self.assertGreaterEqual(len(surfaces), 2, "need >=2 surfaces to prove a skip")

            # Close every surface except one: the loop must land on the survivor every time.
            survivor = surfaces[-1]
            for surface in surfaces[:-1]:
                h.parent.ledger.falsify(
                    ParentA._frame_hypothesis(surface), mechanism="closed for the test",
                    family=ParentA.FRAME_FAMILY,
                )
            for _ in range(6):
                frame = h.parent._next_frame()
                self.assertIn(survivor.title, frame)

    def test_skips_are_emitted_so_the_operator_can_see_the_search_narrow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            surfaces = [s for s in h.parent.plan.surface_ranking if s.id != "SURF-BASELINE"]
            if len(surfaces) < 2:
                self.skipTest("target did not derive multiple surfaces")
            h.parent.ledger.falsify(ParentA._frame_hypothesis(surfaces[0]),
                                    family=ParentA.FRAME_FAMILY)
            for _ in range(len(surfaces) + 1):
                h.parent._next_frame()
            self.assertTrue(h.events("frames_skipped_already_falsified"))

    def test_all_frames_closed_falls_back_to_deepening(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            surfaces = [s for s in h.parent.plan.surface_ranking if s.id != "SURF-BASELINE"]
            for surface in surfaces:
                h.parent.ledger.falsify(ParentA._frame_hypothesis(surface),
                                        mechanism="closed", family=ParentA.FRAME_FAMILY)
            frame = h.parent._next_frame()
            self.assertIn("deepen", frame)
            self.assertTrue(h.events("all_frames_falsified"))

    def test_closing_all_frames_emits_an_architectural_conclusion(self) -> None:
        prev = os.environ.get("P1HUNT_CONCLUSION_MIN_MEMBERS")
        os.environ["P1HUNT_CONCLUSION_MIN_MEMBERS"] = "2"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                h = _Harness(tmp)
                surfaces = [s for s in h.parent.plan.surface_ranking if s.id != "SURF-BASELINE"]
                if len(surfaces) < 2:
                    self.skipTest("target did not derive multiple surfaces")
                for index, surface in enumerate(surfaces):
                    h.parent.ledger.falsify(
                        ParentA._frame_hypothesis(surface),
                        mechanism=f"mechanism {index}", family=ParentA.FRAME_FAMILY,
                    )
                h.parent._next_frame()
                conclusions = h.events("architectural_conclusion")
                self.assertTrue(conclusions)
                self.assertEqual(conclusions[0]["variant_class"], ParentA.FRAME_FAMILY)
                self.assertTrue(Path(conclusions[0]["artifact"]).is_file())
        finally:
            if prev is None:
                os.environ.pop("P1HUNT_CONCLUSION_MIN_MEMBERS", None)
            else:
                os.environ["P1HUNT_CONCLUSION_MIN_MEMBERS"] = prev

    def test_reframe_is_still_not_a_rerun(self) -> None:
        # The pre-existing never-quit contract must survive the new guard.
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            first = h.parent.on_stop()["reason"]
            second = h.parent.on_stop()["reason"]
            self.assertNotEqual(first, second)

    def test_stop_and_safety_still_win_over_the_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            h.bb.push_directive(ControlDirective(target_agent="parent_a", kind="stop", payload=""))
            self.assertEqual(h.parent.on_stop(), {})
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            h.parent.trigger_safety_event("third-party data")
            self.assertEqual(h.parent.on_stop(), {})

    def test_closed_frames_are_handed_to_tracks_as_do_not_re_test(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            surfaces = [s for s in h.parent.plan.surface_ranking if s.id != "SURF-BASELINE"]
            h.parent.ledger.falsify(ParentA._frame_hypothesis(surfaces[0]),
                                    family=ParentA.FRAME_FAMILY)
            h.parent._reframe_tracks()
            briefs = [t.directive.as_prompt() for t in h.parent.tracks]
            self.assertTrue(any("ALREADY FALSIFIED" in b for b in briefs))


class RestartTest(unittest.TestCase):
    def test_falsifications_survive_a_new_parent_over_the_same_engagement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = _Harness(tmp)
            surfaces = [s for s in first.parent.plan.surface_ranking if s.id != "SURF-BASELINE"]
            claim = ParentA._frame_hypothesis(surfaces[0])
            first.parent.ledger.falsify(claim, mechanism="closed in run 1",
                                        family=ParentA.FRAME_FAMILY)

            # A fresh process over the same engagement folder.
            resumed = _Harness(tmp)
            self.assertTrue(resumed.parent.ledger.already_falsified(claim))
            self.assertGreater(
                resumed.events("persistence_memory_attached")[0]["prior_falsifications"], 0
            )


class HuntLoopTest(unittest.TestCase):
    def test_falsifier_kills_are_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prev = os.environ.get("P1HUNT_LEGACY_STATIC_SIGNALS")
            os.environ["P1HUNT_LEGACY_STATIC_SIGNALS"] = "1"
            try:
                h = _Harness(tmp)
                h.parent.setup_tracks()
                asyncio.run(h.parent.hunt(max_rounds=2))
            finally:
                if prev is None:
                    os.environ.pop("P1HUNT_LEGACY_STATIC_SIGNALS", None)
                else:
                    os.environ["P1HUNT_LEGACY_STATIC_SIGNALS"] = prev
            # Either something was killed (recorded) or promoted (recorded as survived); the
            # ledger must not be silent about a round that ran.
            self.assertTrue(h.parent.ledger.records())

    def test_dry_frames_are_closed_only_after_several_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prev = os.environ.get("P1HUNT_FRAME_FALSIFY_AFTER")
            os.environ["P1HUNT_FRAME_FALSIFY_AFTER"] = "2"
            try:
                h = _Harness(tmp)
                # No static signals -> every round is dry.
                asyncio.run(h.parent.hunt(max_rounds=1))
                self.assertEqual(h.events("frame_falsified"), [])
                asyncio.run(h.parent.hunt(max_rounds=1))
                self.assertTrue(h.events("frame_falsified"))
            finally:
                if prev is None:
                    os.environ.pop("P1HUNT_FRAME_FALSIFY_AFTER", None)
                else:
                    os.environ["P1HUNT_FRAME_FALSIFY_AFTER"] = prev

    def test_round_coverage_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            asyncio.run(h.parent.hunt(max_rounds=1))
            assert h.parent.corpus is not None
            lenses = [s.lens for s in h.parent.plan.surface_ranking if s.id != "SURF-BASELINE"]
            self.assertTrue(any(h.parent.corpus.coverage_for(l).rounds > 0 for l in lenses))

    def test_result_carries_the_ledger_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            result = asyncio.run(h.parent.hunt(max_rounds=1))
            self.assertIn("records", result.ledger_summary)
            self.assertIn("escalation", result.ledger_summary)
            self.assertEqual(result.conclusions, [])


class EscalationWiringTest(unittest.TestCase):
    """A confirmed finding must re-enter the hunt, and the loop must still terminate."""

    @staticmethod
    def _run_with_signals(tmp: str, rounds: int, **env):
        prev = {k: os.environ.get(k) for k in ("P1HUNT_LEGACY_STATIC_SIGNALS", *env)}
        os.environ["P1HUNT_LEGACY_STATIC_SIGNALS"] = "1"
        for key, value in env.items():
            os.environ[key] = value
        try:
            h = _Harness(tmp)
            h.parent.setup_tracks()
            result = asyncio.run(h.parent.hunt(max_rounds=rounds))
            return h, result
        finally:
            for key, value in prev.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_a_confirmed_critical_re_enters_the_hunt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h, result = self._run_with_signals(tmp, rounds=6)
            if not result.confirmed_critical:
                self.skipTest("deterministic brain did not confirm a critical on this target")
            # It no longer terminates on the first confirmation.
            self.assertTrue(h.events("escalation_reentry"))
            self.assertTrue(result.escalations)
            self.assertGreater(result.rounds_run, 1)

    def test_escalation_terminates_and_still_reports_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h, result = self._run_with_signals(
                tmp, rounds=12, P1HUNT_MAX_ESCALATION_ATTEMPTS="2"
            )
            if not result.confirmed_critical:
                self.skipTest("deterministic brain did not confirm a critical on this target")
            from p1hunt.models import EngagementStatus

            self.assertEqual(result.status, EngagementStatus.REPORT_READY)
            self.assertTrue(result.confirmed_critical)
            # Bounded: no more than the per-finding cap, per confirmed finding.
            self.assertLessEqual(len(result.escalations), 2 * max(1, len(result.findings)))

    def test_escalation_disabled_restores_terminate_on_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h, result = self._run_with_signals(
                tmp, rounds=8, P1HUNT_MAX_ESCALATION_ATTEMPTS="0"
            )
            if not result.confirmed_critical:
                self.skipTest("deterministic brain did not confirm a critical on this target")
            self.assertEqual(result.escalations, [])
            self.assertEqual(h.events("escalation_reentry"), [])

    def test_escalation_directive_reaches_the_tracks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            from p1hunt.models import ArtifactRef, Finding

            finding = Finding(
                id="FND1", hypothesis_id="H1", title="stored sink on the share route",
                root_cause="output is not neutralized",
                poc=ArtifactRef(id="a", kind="repro", path="src/server.js:2",
                                description="d", reproduced=True),
                severity="critical",
                severity_rationale="Only exploitable for signed-out viewers.",
                counterfactual="an actor can cross the render boundary",
                remediation="neutralize output", safe_harbor_attestation="att",
            )
            self.assertTrue(h.parent._escalate([finding], 1))
            briefs = [t.directive.as_prompt() for t in h.parent.tracks]
            self.assertTrue(any("ESCALATE a CONFIRMED finding" in b for b in briefs))
            # It must tell the hunter not to spend the pass re-proving what is already proven.
            self.assertTrue(any("re-prove" in b for b in briefs))
            # And it must carry the precondition-removal objective derived from the finding.
            self.assertTrue(any("signed-out" in b for b in briefs))

    def test_preconditions_are_modeled_from_the_findings_own_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            from p1hunt.models import ArtifactRef, Finding

            finding = Finding(
                id="FND2", hypothesis_id="H2", title="capped sink",
                root_cause="r",
                poc=ArtifactRef(id="a", kind="repro", path="p", description="d", reproduced=True),
                severity="P2",
                severity_rationale="Only exploitable for signed-out viewers.",
                counterfactual="c", remediation="m", safe_harbor_attestation="att",
            )
            model = h.parent.precondition_model(finding)
            self.assertEqual(len(model.preconditions), 1)
            self.assertEqual(model.preconditions[0].dimension, "auth-state")

            # The headroom projection is what justifies spending an escalation pass.
            projection = h.parent.projected_severity(finding)
            self.assertTrue(projection["raised"])
            self.assertEqual(projection["severity"], "P1")

    def test_removing_a_precondition_rescores_the_finding_upward(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            from p1hunt.models import ArtifactRef, Finding

            finding = Finding(
                id="FND3", hypothesis_id="H3", title="capped sink",
                root_cause="r",
                poc=ArtifactRef(id="a", kind="repro", path="p", description="d", reproduced=True),
                severity="P2",
                severity_rationale="Only exploitable for signed-out viewers.",
                counterfactual="c", remediation="m", safe_harbor_attestation="att",
            )
            model = h.parent.precondition_model(finding)
            pid = model.preconditions[0].id
            result = h.parent.remove_precondition(
                finding, pid, evidence="one host never applies the gate"
            )
            self.assertTrue(result["raised"])
            self.assertEqual(finding.severity, "P1")
            self.assertIn("re-scored", finding.severity_rationale)
            rescored = h.events("severity_rescored_after_precondition_removed")
            self.assertEqual(len(rescored), 1)
            self.assertEqual(rescored[0]["to"], "P1")

    def test_removing_an_unknown_precondition_is_a_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            from p1hunt.models import ArtifactRef, Finding

            finding = Finding(
                id="FND4", hypothesis_id="H4", title="t", root_cause="r",
                poc=ArtifactRef(id="a", kind="repro", path="p", description="d", reproduced=True),
                severity="P2", severity_rationale="no conditions stated",
                counterfactual="c", remediation="m", safe_harbor_attestation="att",
            )
            self.assertEqual(h.parent.remove_precondition(finding, "PRE_nope"), {})
            self.assertEqual(finding.severity, "P2")


class DialTest(unittest.TestCase):
    def test_max_frames_default_is_long_horizon(self) -> None:
        """The effective reframe budget is long-horizon, and the SHIPPED config is too.

        This previously asserted the env floor exceeded the shipped budget -- i.e. it pinned the
        floor *compensating* for a too-low default of 24. Budgets.max_frames_per_track now ships
        at 120, so there is nothing to compensate for and that assertion is obsolete. The real
        invariants are stronger: the effective budget clears the long-horizon floor, the shipped
        default clears it WITHOUT needing the floor, and the floor may never LOWER a configured
        budget (complements test_a_larger_configured_budget_still_wins)."""
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            self.assertGreaterEqual(h.parent._max_frames(), 120)
            # the shipped default alone is long-horizon -- the env floor is not load-bearing
            self.assertGreaterEqual(h.parent.config.budgets.max_frames_per_track, 120)
            # the floor never reduces an operator's configured budget
            self.assertGreaterEqual(h.parent._max_frames(),
                                    h.parent.config.budgets.max_frames_per_track)

    def test_max_frames_env_override(self) -> None:
        prev = os.environ.get("P1HUNT_MAX_FRAMES_PER_TRACK")
        os.environ["P1HUNT_MAX_FRAMES_PER_TRACK"] = "7"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(_Harness(tmp).parent._max_frames(), 7)
        finally:
            if prev is None:
                os.environ.pop("P1HUNT_MAX_FRAMES_PER_TRACK", None)
            else:
                os.environ["P1HUNT_MAX_FRAMES_PER_TRACK"] = prev

    def test_a_larger_configured_budget_still_wins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _Harness(tmp)
            h.parent.config.budgets.max_frames_per_track = 500
            self.assertEqual(h.parent._max_frames(), 500)

    def test_ruled_out_budget_is_generous_by_default(self) -> None:
        # A short "do not re-test" list is how a dead end slips back into a brief.
        from p1hunt.agents.instructions import _ruled_out_budget

        self.assertGreaterEqual(_ruled_out_budget(), 40)

    def test_ruled_out_budget_dial(self) -> None:
        from p1hunt.agents.instructions import _ruled_out_budget

        prev = os.environ.get("P1HUNT_RULED_OUT_IN_BRIEF")
        os.environ["P1HUNT_RULED_OUT_IN_BRIEF"] = "2"
        try:
            self.assertEqual(_ruled_out_budget(), 2)
            with tempfile.TemporaryDirectory() as tmp:
                h = _Harness(tmp)
                surfaces = [s for s in h.parent.plan.surface_ranking if s.id != "SURF-BASELINE"]
                for surface in surfaces:
                    h.parent.ledger.falsify(ParentA._frame_hypothesis(surface),
                                            family=ParentA.FRAME_FAMILY)
                h.parent._reframe_tracks()
                brief = h.parent.tracks[0].directive.as_prompt()
                self.assertLessEqual(brief.count("ALREADY FALSIFIED"), 2)
        finally:
            if prev is None:
                os.environ.pop("P1HUNT_RULED_OUT_IN_BRIEF", None)
            else:
                os.environ["P1HUNT_RULED_OUT_IN_BRIEF"] = prev

    def test_long_hypotheses_are_not_truncated_to_a_stub(self) -> None:
        # Two distinct long dead ends must stay distinguishable in the ledger.
        with tempfile.TemporaryDirectory() as tmp:
            ledger = FalsificationLedger(Path(tmp))
            prefix = "the control is absent at " + ("x" * 500)
            ledger.falsify(prefix + " location-A")
            self.assertTrue(ledger.already_falsified(prefix + " location-A"))
            self.assertFalse(ledger.already_falsified(prefix + " location-B"))

    def test_frame_falsify_after_dial(self) -> None:
        prev = os.environ.get("P1HUNT_FRAME_FALSIFY_AFTER")
        os.environ["P1HUNT_FRAME_FALSIFY_AFTER"] = "9"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(_Harness(tmp).parent._frame_falsify_after(), 9)
        finally:
            if prev is None:
                os.environ.pop("P1HUNT_FRAME_FALSIFY_AFTER", None)
            else:
                os.environ["P1HUNT_FRAME_FALSIFY_AFTER"] = prev


if __name__ == "__main__":
    unittest.main()
