"""Unit tests for the precondition attacker (p1hunt.agents.preconditions).

The mechanism that turns a capped finding into an unconditional one: model each condition
explicitly, emit a dedicated removal objective per condition, and RE-SCORE upward through the
program's own taxonomy when a condition falls. Pure — no I/O, no model calls.
"""

from __future__ import annotations

import unittest

from p1hunt.agents.preconditions import (
    DIM_AUTH_STATE,
    DIM_CLIENT,
    DIM_CONFIGURATION,
    DIM_INTERACTION,
    DIM_OTHER,
    DIM_POSITION,
    DIM_PRIVILEGE,
    DIM_TIMING,
    GATE_ATTACKER_CAPABILITY,
    Precondition,
    PreconditionModel,
    assessment_with,
    classify_dimension,
    extract_preconditions,
    preconditions_from,
    removal_objectives,
    rescore,
)
from p1hunt.severity import ImpactAssessment, SeverityMapper

# A program taxonomy with a distinct top tier, so an upgrade is observable by label.
TAXONOMY = {
    "P1": "critical: unauthenticated takeover or mass data exposure",
    "P2": "high: serious impact requiring conditions",
    "P3": "medium: limited impact",
    "P4": "low: minor issues",
}


def _confirmed() -> ImpactAssessment:
    """A reproduced finding whose underlying capability is real — the promotion floor already
    establishes these, so the only question left is whether conditions cap it."""

    return ImpactAssessment(
        reproduced=True, protected_asset=True, attacker_capability=True,
        concrete_loss="control", in_scope=True,
    )


class ClassifyTest(unittest.TestCase):
    def test_auth_state_cues(self) -> None:
        self.assertEqual(classify_dimension("only exploitable for signed-out viewers"), DIM_AUTH_STATE)
        self.assertEqual(classify_dimension("requires no session cookie"), DIM_AUTH_STATE)

    def test_privilege_cues(self) -> None:
        self.assertEqual(classify_dimension("requires an admin role"), DIM_PRIVILEGE)
        self.assertEqual(classify_dimension("needs elevated permission"), DIM_PRIVILEGE)

    def test_interaction_cues(self) -> None:
        self.assertEqual(classify_dimension("requires the victim to click a link"), DIM_INTERACTION)

    def test_client_cues(self) -> None:
        self.assertEqual(classify_dimension("only on the mobile render path"), DIM_CLIENT)
        self.assertEqual(classify_dimension("depends on the Accept header"), DIM_CLIENT)

    def test_configuration_cues(self) -> None:
        self.assertEqual(classify_dimension("requires a non-default setting"), DIM_CONFIGURATION)

    def test_timing_cues(self) -> None:
        self.assertEqual(classify_dimension("requires winning a race window"), DIM_TIMING)

    def test_position_cues(self) -> None:
        self.assertEqual(classify_dimension("requires prior access to the host"), DIM_POSITION)

    def test_unclassifiable_is_other_not_a_guess(self) -> None:
        self.assertEqual(classify_dimension("requires an unusual widget state"), DIM_OTHER)
        self.assertEqual(classify_dimension(""), DIM_OTHER)
        self.assertEqual(classify_dimension(None), DIM_OTHER)


class ModelingTest(unittest.TestCase):
    def test_preconditions_from_strings(self) -> None:
        pres = preconditions_from(["requires signed-out viewer", "requires an admin role"])
        self.assertEqual(len(pres), 2)
        self.assertEqual(pres[0].dimension, DIM_AUTH_STATE)
        self.assertEqual(pres[1].dimension, DIM_PRIVILEGE)
        self.assertTrue(all(p.gate == GATE_ATTACKER_CAPABILITY for p in pres))

    def test_preconditions_from_dicts_honor_declared_dimension(self) -> None:
        pres = preconditions_from([{"statement": "something odd", "dimension": DIM_TIMING}])
        self.assertEqual(pres[0].dimension, DIM_TIMING)

    def test_invalid_declared_dimension_falls_back_to_classification(self) -> None:
        pres = preconditions_from([{"statement": "requires an admin role", "dimension": "bogus"}])
        self.assertEqual(pres[0].dimension, DIM_PRIVILEGE)

    def test_duplicates_are_collapsed(self) -> None:
        pres = preconditions_from(["requires an admin role", "Requires an admin role."])
        self.assertEqual(len(pres), 1)

    def test_blank_entries_are_dropped(self) -> None:
        self.assertEqual(preconditions_from(["", "   ", None]), [])

    def test_existing_precondition_objects_pass_through(self) -> None:
        pre = Precondition(id="X", dimension=DIM_CLIENT, statement="s")
        self.assertEqual(preconditions_from([pre])[0].id, "X")

    def test_ids_are_content_addressed_and_stable(self) -> None:
        a = preconditions_from(["requires an admin role"])[0]
        b = preconditions_from(["requires an admin role"])[0]
        self.assertEqual(a.id, b.id)

    def test_extract_finds_conditional_clauses_only(self) -> None:
        narrative = (
            "The sink renders attacker input. It is only exploitable for signed-out viewers. "
            "The payload is stored permanently."
        )
        pres = extract_preconditions(narrative)
        self.assertEqual(len(pres), 1)
        self.assertEqual(pres[0].dimension, DIM_AUTH_STATE)

    def test_extract_returns_nothing_for_an_unconditional_narrative(self) -> None:
        # No stated condition means unconditional — never invent a cap.
        self.assertEqual(extract_preconditions("Any remote user can read any record."), [])
        self.assertEqual(extract_preconditions(""), [])

    def test_extract_handles_multiple_conditions(self) -> None:
        pres = extract_preconditions(
            "Only exploitable while signed out; requires the victim to click the link."
        )
        self.assertEqual({p.dimension for p in pres}, {DIM_AUTH_STATE, DIM_INTERACTION})

    def test_dimension_cues_are_ordered_most_limiting_first(self) -> None:
        # A clause naming both a role and an interaction is capped primarily by the ROLE: needing
        # a privileged actor is the stronger limit, so privilege wins deliberately.
        self.assertEqual(classify_dimension("requires an admin to click the link"), DIM_PRIVILEGE)

    def test_extract_respects_limit(self) -> None:
        narrative = " ".join(f"requires condition {i}." for i in range(20))
        self.assertEqual(len(extract_preconditions(narrative, limit=3)), 3)

    def test_with_removed_is_immutable(self) -> None:
        pre = preconditions_from(["requires an admin role"])[0]
        removed = pre.with_removed("found an unauthenticated path")
        self.assertFalse(pre.removed)
        self.assertTrue(removed.removed)
        self.assertEqual(removed.removal_evidence, "found an unauthenticated path")


class ObjectiveTest(unittest.TestCase):
    def test_one_objective_per_unremoved_precondition(self) -> None:
        pres = preconditions_from(["requires signed-out viewer", "requires an admin role"])
        objectives = removal_objectives(pres, finding_title="Stored sink on the share page")
        self.assertEqual(len(objectives), 2)
        self.assertEqual({o.precondition_id for o in objectives}, {p.id for p in pres})

    def test_removed_preconditions_get_no_objective(self) -> None:
        pres = preconditions_from(["requires signed-out viewer"])
        pres[0] = pres[0].with_removed("done")
        self.assertEqual(removal_objectives(pres), [])

    def test_objective_states_the_sole_goal_and_success_criterion(self) -> None:
        pres = preconditions_from(["only exploitable for signed-out viewers"])
        objective = removal_objectives(pres, finding_title="the sink")[0]
        prompt = objective.as_prompt()
        self.assertIn("SOLE OBJECTIVE", prompt)
        self.assertIn("signed-out", prompt)
        self.assertIn("Success:", prompt)
        # It must explicitly tell the hunter not to re-prove the confirmed finding.
        self.assertIn("already confirmed", prompt)

    def test_objective_strategy_is_dimension_specific(self) -> None:
        auth = removal_objectives(preconditions_from(["only for signed-out viewers"]))[0]
        interaction = removal_objectives(preconditions_from(["requires the victim to click"]))[0]
        self.assertNotEqual(auth.strategy, interaction.strategy)

    def test_hypothesis_is_ledger_keyable(self) -> None:
        objective = removal_objectives(
            preconditions_from(["requires an admin role"]), finding_title="t"
        )[0]
        self.assertIn("can be removed", objective.hypothesis)
        self.assertIn(DIM_PRIVILEGE, objective.hypothesis)

    def test_objective_as_dict(self) -> None:
        objective = removal_objectives(preconditions_from(["requires an admin role"]))[0]
        doc = objective.as_dict()
        for key in ("precondition_id", "dimension", "objective", "success_criterion", "hypothesis"):
            self.assertIn(key, doc)


class RescoreTest(unittest.TestCase):
    """The payoff: removing a precondition must RAISE the score, in the program's own labels."""

    def setUp(self) -> None:
        self.mapper = SeverityMapper(TAXONOMY)

    def test_a_precondition_caps_the_finding_below_top_tier(self) -> None:
        pres = preconditions_from(["only exploitable for signed-out viewers"])
        capped = assessment_with(_confirmed(), pres)
        self.assertFalse(capped.attacker_capability)
        label, _ = self.mapper.map(capped)
        self.assertNotEqual(label, "P1")

    def test_removing_the_last_precondition_raises_to_top_tier(self) -> None:
        pres = preconditions_from(["only exploitable for signed-out viewers"])
        result = rescore(self.mapper, _confirmed(), pres, removed_ids=[pres[0].id])
        self.assertTrue(result.raised)
        self.assertEqual(result.label, "P1")
        self.assertNotEqual(result.previous_label, "P1")
        self.assertIn("re-scored", result.rationale)
        self.assertEqual(result.remaining, ())

    def test_removing_one_of_two_does_not_raise_while_another_holds(self) -> None:
        pres = preconditions_from(["only for signed-out viewers", "requires an admin role"])
        result = rescore(self.mapper, _confirmed(), pres, removed_ids=[pres[0].id])
        self.assertFalse(result.raised)
        self.assertEqual(len(result.remaining), 1)
        self.assertIn("still hold", result.rationale)

    def test_removing_all_of_several_raises(self) -> None:
        pres = preconditions_from(["only for signed-out viewers", "requires an admin role"])
        result = rescore(self.mapper, _confirmed(), pres, removed_ids=[p.id for p in pres])
        self.assertTrue(result.raised)
        self.assertEqual(result.label, "P1")

    def test_no_preconditions_means_already_unconditional(self) -> None:
        result = rescore(self.mapper, _confirmed(), [])
        self.assertFalse(result.raised)
        self.assertEqual(result.label, "P1")

    def test_unreproduced_finding_can_never_reach_top_tier(self) -> None:
        # The artifact floor outranks escalation: removing every condition on an unproven finding
        # must not manufacture a critical.
        base = ImpactAssessment(reproduced=False, protected_asset=True,
                                attacker_capability=True, concrete_loss="control")
        pres = preconditions_from(["only for signed-out viewers"])
        result = rescore(self.mapper, base, pres, removed_ids=[pres[0].id])
        self.assertNotEqual(result.label, "P1")

    def test_out_of_scope_stays_out_of_scope(self) -> None:
        base = ImpactAssessment(reproduced=True, protected_asset=True, attacker_capability=True,
                                concrete_loss="control", in_scope=False)
        pres = preconditions_from(["only for signed-out viewers"])
        result = rescore(self.mapper, base, pres, removed_ids=[pres[0].id])
        self.assertEqual(result.label, "Out-of-scope")

    def test_labels_come_from_the_programs_own_taxonomy(self) -> None:
        # NOTHING PRESET: a program using Sev-1/Sev-2 must get ITS labels, not "P1"/"Critical".
        mapper = SeverityMapper({"Sev-1": "critical stuff", "Sev-2": "high stuff"})
        pres = preconditions_from(["only for signed-out viewers"])
        result = rescore(mapper, _confirmed(), pres, removed_ids=[pres[0].id])
        self.assertEqual(result.label, "Sev-1")

    def test_rescore_as_dict(self) -> None:
        pres = preconditions_from(["only for signed-out viewers"])
        doc = rescore(self.mapper, _confirmed(), pres, removed_ids=[pres[0].id]).as_dict()
        self.assertEqual(doc["severity"], "P1")
        self.assertTrue(doc["raised"])
        self.assertIn("removed_preconditions", doc)

    def test_assessment_with_tolerates_none_entries(self) -> None:
        self.assertTrue(assessment_with(_confirmed(), [None]).attacker_capability)


class ModelIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mapper = SeverityMapper(TAXONOMY)

    def test_for_finding_prefers_declared_over_narrative(self) -> None:
        model = PreconditionModel.for_finding(
            "t", declared=["requires an admin role"],
            narrative="only exploitable for signed-out viewers",
        )
        self.assertEqual(len(model.preconditions), 1)
        self.assertEqual(model.preconditions[0].dimension, DIM_PRIVILEGE)

    def test_for_finding_falls_back_to_narrative(self) -> None:
        model = PreconditionModel.for_finding(
            "t", narrative="This is only exploitable for signed-out viewers."
        )
        self.assertEqual(len(model.preconditions), 1)
        self.assertEqual(model.preconditions[0].dimension, DIM_AUTH_STATE)

    def test_mark_removed_then_rescore_raises(self) -> None:
        model = PreconditionModel.for_finding("t", declared=["only for signed-out viewers"])
        pid = model.preconditions[0].id
        self.assertTrue(model.mark_removed(pid, "found a host that never applies the gate"))
        self.assertEqual(model.unremoved(), [])
        result = model.rescore(self.mapper, _confirmed())
        self.assertTrue(result.raised)
        self.assertEqual(result.label, "P1")

    def test_mark_removed_is_idempotent_and_reports_no_change(self) -> None:
        model = PreconditionModel.for_finding("t", declared=["only for signed-out viewers"])
        pid = model.preconditions[0].id
        self.assertTrue(model.mark_removed(pid))
        self.assertFalse(model.mark_removed(pid))
        self.assertFalse(model.mark_removed("nonexistent"))

    def test_objectives_shrink_as_preconditions_fall(self) -> None:
        model = PreconditionModel.for_finding(
            "t", declared=["only for signed-out viewers", "requires an admin role"]
        )
        self.assertEqual(len(model.objectives()), 2)
        model.mark_removed(model.preconditions[0].id)
        self.assertEqual(len(model.objectives()), 1)

    def test_summary_shape(self) -> None:
        model = PreconditionModel.for_finding("t", declared=["only for signed-out viewers"])
        summary = model.summary()
        self.assertEqual(summary["unremoved"], 1)
        self.assertEqual(summary["removed"], 0)
        self.assertEqual(summary["dimensions"], [DIM_AUTH_STATE])


if __name__ == "__main__":
    unittest.main()
