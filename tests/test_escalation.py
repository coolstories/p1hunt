"""Unit tests for the escalation-after-confirmation loop (p1hunt.agents.escalation).

A confirmed finding must RE-ENTER the hunt with escalation objectives instead of terminating it —
and that is exactly the shape that loops forever, so the bounding is tested as hard as the
behavior: a per-finding attempt cap, ledger de-duplication of closed objectives, an
engagement-wide total, and persistence of the bound across a restart.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from p1hunt.agents.escalation import (
    FAMILY_PREFIX,
    KIND_REMOVE_PRECONDITION,
    KIND_UNCONDITIONAL_LOCATION,
    KIND_WIDEN_BLAST_RADIUS,
    EscalationLoop,
    EscalationPlan,
    max_escalation_attempts,
    max_escalation_total,
    plan_escalation,
)
from p1hunt.agents.preconditions import preconditions_from
from p1hunt.ledger import FalsificationLedger


class _Log:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict]] = []

    def emit(self, agent: str, kind: str, data: dict) -> None:
        self.events.append((agent, kind, data))

    def find(self, event: str) -> list[dict]:
        return [d for _a, _k, d in self.events if d.get("event") == event]


class PlanTest(unittest.TestCase):
    def test_standard_objectives_always_present(self) -> None:
        plan = plan_escalation(finding_title="a confirmed bug")
        kinds = [o.kind for o in plan.objectives]
        self.assertIn(KIND_UNCONDITIONAL_LOCATION, kinds)
        self.assertIn(KIND_WIDEN_BLAST_RADIUS, kinds)
        self.assertFalse(plan.exhausted)

    def test_precondition_objectives_come_first(self) -> None:
        # Removing a cap is the most direct route from a capped finding to an unconditional one.
        pres = preconditions_from(["only exploitable for signed-out viewers"])
        plan = plan_escalation(finding_title="t", preconditions=pres)
        self.assertEqual(plan.objectives[0].kind, KIND_REMOVE_PRECONDITION)
        self.assertEqual(len(plan.objectives), 3)

    def test_one_objective_per_precondition(self) -> None:
        pres = preconditions_from(["only for signed-out viewers", "requires an admin role"])
        plan = plan_escalation(finding_title="t", preconditions=pres)
        removals = [o for o in plan.objectives if o.kind == KIND_REMOVE_PRECONDITION]
        self.assertEqual(len(removals), 2)

    def test_attempt_cap_exhausts_the_plan(self) -> None:
        plan = plan_escalation(finding_title="t", attempt=4, max_attempts=3)
        self.assertTrue(plan.exhausted)
        self.assertIn("attempt cap", plan.reason)
        self.assertEqual(plan.objectives, ())

    def test_zero_cap_disables_escalation(self) -> None:
        # The escape hatch: an operator who wants terminate-on-confirmation back.
        plan = plan_escalation(finding_title="t", max_attempts=0)
        self.assertTrue(plan.exhausted)
        self.assertIn("disabled", plan.reason)

    def test_exhausted_budget_exhausts_the_plan(self) -> None:
        plan = plan_escalation(finding_title="t", budget_remaining=0)
        self.assertTrue(plan.exhausted)
        self.assertIn("budget", plan.reason)

    def test_falsified_objectives_are_dropped(self) -> None:
        closed = {o.hypothesis for o in plan_escalation(finding_title="t").objectives}
        plan = plan_escalation(finding_title="t", already_falsified=lambda h: h in closed)
        self.assertTrue(plan.exhausted)
        self.assertIn("already falsified", plan.reason)

    def test_partially_falsified_keeps_the_rest_open(self) -> None:
        first = plan_escalation(finding_title="t").objectives[0].hypothesis
        plan = plan_escalation(finding_title="t", already_falsified=lambda h: h == first)
        self.assertFalse(plan.exhausted)
        self.assertEqual(len(plan.objectives), 1)
        self.assertIn("1 already closed", plan.reason)

    def test_a_broken_predicate_does_not_close_objectives(self) -> None:
        def boom(_h: str) -> bool:
            raise RuntimeError("ledger unavailable")

        plan = plan_escalation(finding_title="t", already_falsified=boom)
        self.assertFalse(plan.exhausted)
        self.assertEqual(len(plan.objectives), 2)

    def test_family_is_keyed_to_the_finding(self) -> None:
        plan = plan_escalation(finding_title="t", finding_key="abc")
        self.assertEqual(plan.family, f"{FAMILY_PREFIX}:abc")

    def test_key_is_derived_from_the_title_when_absent(self) -> None:
        a = plan_escalation(finding_title="same title")
        b = plan_escalation(finding_title="same title")
        self.assertTrue(a.finding_key)
        self.assertEqual(a.finding_key, b.finding_key)

    def test_prompt_tells_the_hunter_not_to_re_prove(self) -> None:
        prompt = plan_escalation(finding_title="the bug").as_prompt()
        self.assertIn("do NOT re-prove", prompt)
        self.assertIn("make it WORSE", prompt)

    def test_exhausted_prompt_states_the_reason(self) -> None:
        plan = plan_escalation(finding_title="t", max_attempts=0)
        self.assertIn("No escalation objectives remain", plan.as_prompt())

    def test_as_dict_is_log_safe(self) -> None:
        doc = plan_escalation(finding_title="t").as_dict()
        self.assertEqual(doc["attempt"], 1)
        self.assertEqual(len(doc["objectives"]), 2)

    def test_blank_title_degrades(self) -> None:
        plan = plan_escalation(finding_title="")
        self.assertEqual(plan.finding_title, "the confirmed finding")


class LoopBoundTest(unittest.TestCase):
    """The termination guarantees. Each is checked independently."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_loop_terminates_at_the_per_finding_cap(self) -> None:
        loop = EscalationLoop(FalsificationLedger(self.dir), max_attempts=3, max_total=100)
        issued = 0
        for _ in range(50):  # far more passes than the cap allows
            plan = loop.next_plan(finding_title="the bug")
            if plan.exhausted:
                break
            issued += 1
        self.assertEqual(issued, 3)

    def test_loop_terminates_on_the_engagement_total(self) -> None:
        loop = EscalationLoop(FalsificationLedger(self.dir), max_attempts=10, max_total=4)
        issued = 0
        for index in range(50):
            plan = loop.next_plan(finding_title=f"finding {index}")  # a new finding each time
            if plan.exhausted:
                break
            issued += 1
        self.assertEqual(issued, 4)
        self.assertEqual(loop.budget_remaining(), 0)

    def test_loop_terminates_when_every_objective_is_falsified(self) -> None:
        ledger = FalsificationLedger(self.dir)
        loop = EscalationLoop(ledger, max_attempts=10, max_total=100)
        plan = loop.next_plan(finding_title="the bug")
        self.assertFalse(plan.exhausted)
        for objective in plan.objectives:
            loop.record_outcome(plan, objective, succeeded=False, mechanism="enforced everywhere")
        self.assertTrue(loop.next_plan(finding_title="the bug").exhausted)

    def test_attempts_are_counted_even_without_a_ledger(self) -> None:
        loop = EscalationLoop(None, max_attempts=2)
        self.assertFalse(loop.next_plan(finding_title="t").exhausted)
        self.assertFalse(loop.next_plan(finding_title="t").exhausted)
        self.assertTrue(loop.next_plan(finding_title="t").exhausted)

    def test_bound_survives_a_restart(self) -> None:
        # A resumed hunt must not get a fresh escalation budget for a finding it already pushed.
        first = EscalationLoop(FalsificationLedger(self.dir), max_attempts=2, max_total=100)
        first.next_plan(finding_title="the bug")
        first.next_plan(finding_title="the bug")

        resumed = EscalationLoop(FalsificationLedger(self.dir), max_attempts=2, max_total=100)
        self.assertEqual(resumed.attempts_for(plan_key("the bug")), 2)
        self.assertTrue(resumed.next_plan(finding_title="the bug").exhausted)

    def test_separate_findings_have_separate_budgets(self) -> None:
        loop = EscalationLoop(FalsificationLedger(self.dir), max_attempts=1, max_total=100)
        self.assertFalse(loop.next_plan(finding_title="bug one").exhausted)
        self.assertTrue(loop.next_plan(finding_title="bug one").exhausted)
        self.assertFalse(loop.next_plan(finding_title="bug two").exhausted)


def plan_key(title: str) -> str:
    from p1hunt.ledger import hypothesis_key

    return hypothesis_key(title)


class LoopBehaviorTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_plan_is_emitted_to_the_event_log(self) -> None:
        log = _Log()
        loop = EscalationLoop(FalsificationLedger(self.dir), event_log=log)
        loop.next_plan(finding_title="the bug")
        planned = log.find("escalation_planned")
        self.assertEqual(len(planned), 1)
        self.assertEqual(planned[0]["attempt"], 1)
        self.assertIn("directive", planned[0])

    def test_exhaustion_is_emitted(self) -> None:
        log = _Log()
        loop = EscalationLoop(FalsificationLedger(self.dir), event_log=log, max_attempts=0)
        loop.next_plan(finding_title="the bug")
        self.assertEqual(len(log.find("escalation_exhausted")), 1)

    def test_attempt_is_recorded_in_the_ledger(self) -> None:
        ledger = FalsificationLedger(self.dir)
        loop = EscalationLoop(ledger, max_attempts=2)
        plan = loop.next_plan(finding_title="the bug")
        family = ledger.families().get(plan.family, [])
        self.assertTrue(any(r.note.startswith("escalation pass") for r in family))

    def test_failed_objective_is_recorded_as_falsified(self) -> None:
        ledger = FalsificationLedger(self.dir)
        loop = EscalationLoop(ledger)
        plan = loop.next_plan(finding_title="the bug")
        objective = plan.objectives[0]
        loop.record_outcome(plan, objective, succeeded=False, mechanism="the gate is global")
        self.assertTrue(ledger.already_falsified(objective.hypothesis))

    def test_successful_objective_is_recorded_as_survived(self) -> None:
        ledger = FalsificationLedger(self.dir)
        loop = EscalationLoop(ledger)
        plan = loop.next_plan(finding_title="the bug")
        objective = plan.objectives[0]
        loop.record_outcome(plan, objective, succeeded=True, note="found an ungated host")
        self.assertFalse(ledger.already_falsified(objective.hypothesis))

    def test_closing_every_objective_yields_an_architectural_conclusion(self) -> None:
        # The payoff of a well-supported negative: "this finding cannot be escalated, and here is
        # which mechanism blocks each route."
        prev = os.environ.get("P1HUNT_CONCLUSION_MIN_MEMBERS")
        os.environ["P1HUNT_CONCLUSION_MIN_MEMBERS"] = "2"
        try:
            ledger = FalsificationLedger(self.dir)
            loop = EscalationLoop(ledger, max_attempts=5)
            pres = preconditions_from(["only for signed-out viewers"])
            plan = loop.next_plan(finding_title="the bug", preconditions=pres)
            for index, objective in enumerate(plan.objectives):
                loop.record_outcome(plan, objective, succeeded=False,
                                    mechanism=f"mechanism {index}")
            conclusions = loop.conclusions()
            self.assertEqual(len(conclusions), 1)
            self.assertTrue(conclusions[0].family.startswith(FAMILY_PREFIX + ":"))
            self.assertGreaterEqual(len(conclusions[0].mechanisms), 2)
        finally:
            if prev is None:
                os.environ.pop("P1HUNT_CONCLUSION_MIN_MEMBERS", None)
            else:
                os.environ["P1HUNT_CONCLUSION_MIN_MEMBERS"] = prev

    def test_record_outcome_without_a_ledger_is_a_noop(self) -> None:
        loop = EscalationLoop(None)
        plan = loop.next_plan(finding_title="t")
        loop.record_outcome(plan, plan.objectives[0], succeeded=False)  # must not raise
        self.assertEqual(loop.conclusions(), [])

    def test_a_broken_log_cannot_break_the_loop(self) -> None:
        class Broken:
            def emit(self, *a, **k):
                raise RuntimeError("log down")

        loop = EscalationLoop(FalsificationLedger(self.dir), event_log=Broken())
        self.assertFalse(loop.next_plan(finding_title="t").exhausted)

    def test_summary_shape(self) -> None:
        loop = EscalationLoop(FalsificationLedger(self.dir), max_attempts=2, max_total=5)
        loop.next_plan(finding_title="t")
        summary = loop.summary()
        self.assertEqual(summary["findings_escalated"], 1)
        self.assertEqual(summary["passes_spent"], 1)
        self.assertEqual(summary["passes_remaining"], 4)
        self.assertEqual(summary["per_finding_cap"], 2)


class DialTest(unittest.TestCase):
    def test_attempt_dial(self) -> None:
        prev = os.environ.get("P1HUNT_MAX_ESCALATION_ATTEMPTS")
        try:
            os.environ["P1HUNT_MAX_ESCALATION_ATTEMPTS"] = "7"
            self.assertEqual(max_escalation_attempts(), 7)
            os.environ["P1HUNT_MAX_ESCALATION_ATTEMPTS"] = "0"
            self.assertEqual(max_escalation_attempts(), 0)
            os.environ["P1HUNT_MAX_ESCALATION_ATTEMPTS"] = "junk"
            self.assertEqual(max_escalation_attempts(), 3)
        finally:
            if prev is None:
                os.environ.pop("P1HUNT_MAX_ESCALATION_ATTEMPTS", None)
            else:
                os.environ["P1HUNT_MAX_ESCALATION_ATTEMPTS"] = prev

    def test_total_dial(self) -> None:
        prev = os.environ.get("P1HUNT_MAX_ESCALATION_TOTAL")
        try:
            os.environ["P1HUNT_MAX_ESCALATION_TOTAL"] = "9"
            self.assertEqual(max_escalation_total(), 9)
            os.environ.pop("P1HUNT_MAX_ESCALATION_TOTAL")
            self.assertEqual(max_escalation_total(), 24)
        finally:
            if prev is None:
                os.environ.pop("P1HUNT_MAX_ESCALATION_TOTAL", None)
            else:
                os.environ["P1HUNT_MAX_ESCALATION_TOTAL"] = prev


if __name__ == "__main__":
    unittest.main()
