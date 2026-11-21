"""The reasoning pass is actually wired into the hunt, and degrades safely when it is not.

A capability nobody calls is dead weight, so these tests pin the integration rather than
the libraries: the plan is requested after arming, it reaches the hunters, it drives
entrypoints ahead of the derived surface, and every failure path leaves the hunt running.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest

from p1hunt.agents.harness_scaffold import plan_note


def _swarm(tmp: str):
    from p1hunt.agents.claude_swarm import ClaudeSwarm
    from p1hunt.config import Config
    from p1hunt.models import Asset, Scope
    from p1hunt.orchestrator.blackboard import Blackboard
    from p1hunt.orchestrator.bus import MessageBus
    from p1hunt.orchestrator.event_log import EventLog

    scope = Scope(program="P", safe_harbor_text="x", severity_taxonomy={"P1": "critical"},
                  in_scope=[Asset("a1", tmp, "repo", tmp, "local")])
    log = EventLog()
    return ClaudeSwarm(scope, tmp, config=Config(), bus=MessageBus(log),
                       blackboard=Blackboard(log), event_log=log)


_PLAN = [{
    "target": "GET /share/{id}",
    "mechanism": "the apex applies a cookie-presence render gate that the mobile host omits",
    "vary": "the host, nothing else",
    "instrument": "Browser.differential across two host variants",
    "confirm_if": "raw_html differs and only one host ships the lightweight renderer",
    "refute_if": "both hosts return byte-identical documents for the same cookie state",
    "impact_if_true": "removes the signed-out precondition",
    "confidence": 0.8,
}]

_SURFACE = {
    "hosts": ["t.example", "m.t.example"],
    "endpoints": [{"path": "/api/v1/accounts/7", "method": "GET", "params": [],
                   "source": "observed"}],
    "gate_paths": ["/share/abc"],
}


class TestPlanNote(unittest.TestCase):
    def test_an_empty_plan_renders_nothing(self):
        self.assertEqual(plan_note([]), "")

    def test_the_plan_is_framed_as_a_starting_point_not_a_script(self):
        note = " ".join(plan_note(_PLAN).split())
        self.assertIn("STARTING POINT, not a script", note)
        self.assertIn("follow YOURS instead", note,
                      "a hunter's own better mechanism must outrank the plan")

    def test_each_item_carries_its_refutation(self):
        note = plan_note(_PLAN)
        self.assertIn("REFUTED IF:", note)
        self.assertIn("do not keep circling it", note)

    def test_the_mechanism_and_instrument_survive(self):
        note = plan_note(_PLAN)
        self.assertIn("cookie-presence render gate", note)
        self.assertIn("Browser.differential", note)

    def test_the_note_is_bounded(self):
        many = [dict(_PLAN[0], target=f"/t{i}") for i in range(50)]
        note = plan_note(many, limit=5)
        self.assertIn("/t4", note)
        self.assertNotIn("/t9", note)


class TestPlanReachesTheHunter(unittest.TestCase):
    def test_the_scaffold_carries_the_plan_when_one_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._live_plan = _PLAN
            text = sw._scaffold_for("web", [])
            self.assertIn("PLANNED LINES OF ATTACK", text)
            self.assertIn("cookie-presence render gate", text)

    def test_the_scaffold_is_unchanged_with_no_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            self.assertNotIn("PLANNED LINES OF ATTACK", sw._scaffold_for("web", []))

    def test_the_scaffold_keeps_its_no_preset_reproduction_mechanics(self):
        # The plan is additive; it must not displace the mechanics the hunter needs.
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._live_plan = _PLAN
            text = sw._scaffold_for("web", [])
            self.assertIn("PROVE IT", text)
            self.assertIn("ReproSpec.expect", text)


class TestEntrypointPrecedence(unittest.TestCase):
    def test_a_reasoned_plan_outranks_the_derived_surface(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._live_surface = _SURFACE
            sw._live_entrypoints = ["ANY GET /share/{id}"]
            eps = sw._entrypoints_for("web", [])
            self.assertEqual(eps, ["ANY GET /share/{id}"])

    def test_the_derived_surface_is_used_when_there_is_no_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._live_surface = _SURFACE
            sw._live_entrypoints = []
            eps = sw._entrypoints_for("web", [])
            self.assertTrue(eps)
            self.assertTrue(any("accounts/{id}" in e for e in eps), eps)

    def test_a_black_box_target_with_neither_still_degrades_to_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            self.assertIsInstance(sw._entrypoints_for("web", []), list)


class TestPlanningPassDegradesSafely(unittest.TestCase):
    """Every failure path must leave the hunt running; none may raise."""

    def test_no_surface_means_no_plan_and_no_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._live_surface = None
            asyncio.run(sw._plan_live_attack())
            self.assertEqual(sw._live_plan, [])
            self.assertEqual(sw._live_entrypoints, [])

    def test_an_empty_surface_means_no_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._live_surface = {"endpoints": [], "hosts": []}
            asyncio.run(sw._plan_live_attack())
            self.assertEqual(sw._live_plan, [])

    def test_an_engine_that_raises_does_not_break_the_hunt(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._live_surface = _SURFACE

            def _boom():
                raise RuntimeError("no engine here")
            sw._make_planning_session = _boom
            asyncio.run(sw._plan_live_attack())      # must not raise
            self.assertEqual(sw._live_plan, [])

    def test_a_good_reply_becomes_a_plan_and_entrypoints(self):
        import json

        class _Sess:
            async def run(self, prompt, cwd, **kw):
                self.prompt = prompt

                class _R:
                    ok = True
                    error = ""
                    text = "```json\n" + json.dumps(_PLAN) + "\n```"
                return _R()

        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._live_surface = _SURFACE
            sess = _Sess()
            sw._make_planning_session = lambda: sess
            asyncio.run(sw._plan_live_attack())
            self.assertEqual(len(sw._live_plan), 1)
            self.assertEqual(sw._live_entrypoints, ["GET /share/{id}"])
            self.assertIn("m.t.example", sess.prompt, "the facts must reach the planner")
            self.assertIn("INSTRUMENTS", sess.prompt)

    def test_refuted_hypotheses_are_handed_to_the_planner_with_their_reason(self):
        from p1hunt.ledger import FalsificationLedger

        class _Sess:
            async def run(self, prompt, cwd, **kw):
                self.prompt = prompt

                class _R:
                    ok = True
                    error = ""
                    text = "[]"
                return _R()

        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._live_surface = _SURFACE
            led = FalsificationLedger(tmp)
            led.falsify("title sink is injectable",
                        mechanism="every sink escaped for its context")
            sw.ledger = led
            sess = _Sess()
            sw._make_planning_session = lambda: sess
            asyncio.run(sw._plan_live_attack())
            self.assertIn("ALREADY REFUTED", sess.prompt)
            self.assertIn("title sink is injectable", sess.prompt)
            self.assertIn("escaped for its context", sess.prompt,
                          "a refutation without its reason invites the idea back reworded")

    def test_the_planner_is_told_the_authorized_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._egress_hosts = ["t.example", "m.t.example"]
            note = sw._scope_note_for_plan()
            self.assertIn("t.example", note)
            self.assertIn("Authorized hosts ONLY", note)
            self.assertIn("destructive", note)

    def test_the_planner_runs_on_the_reasoning_tier(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            captured = {}

            import p1hunt.agents.claude_session as cs
            real = cs.make_session

            def _fake(**kw):
                captured.update(kw)

                class _S:
                    pass
                return _S()
            cs.make_session = _fake
            try:
                sw._make_planning_session()
            finally:
                cs.make_session = real
            self.assertEqual(captured.get("model"), sw.config.models.falsifier)
            self.assertEqual(captured.get("codex_model"), sw.config.models.codex_model)


if __name__ == "__main__":
    unittest.main()
