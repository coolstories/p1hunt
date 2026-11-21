"""Unit tests for the falsification ledger (p1hunt.ledger).

Pure keying/normalization/composition plus append-only JSONL persistence. No network, no
external tools. Covers the two jobs the ledger exists for: (a) ``already_falsified`` as the
reframe loop guard, and (b) composing a family of falsifications into an architectural
conclusion — a well-supported negative is a reportable artifact, not waste.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from p1hunt.ledger import (
    OUTCOME_ATTEMPTED,
    OUTCOME_CONCLUSION,
    OUTCOME_FALSIFIED,
    OUTCOME_SURVIVED,
    ArchitecturalConclusion,
    FalsificationLedger,
    LedgerRecord,
    compose_conclusion,
    conclusion_min_members,
    group_by_family,
    hypothesis_key,
    normalize_hypothesis,
)


class KeyingTest(unittest.TestCase):
    """Keying must survive REFRAMES: a reworded claim has to key the same, or the guard is a no-op."""

    def test_normalize_collapses_case_punctuation_and_whitespace(self) -> None:
        self.assertEqual(
            normalize_hypothesis("  The  Gate, is BYPASSABLE!! "),
            "the gate is bypassable",
        )

    def test_key_is_stable_across_rewordings(self) -> None:
        a = hypothesis_key("The gate is bypassable")
        b = hypothesis_key("the  gate   is bypassable.")
        c = hypothesis_key("THE GATE IS BYPASSABLE!")
        self.assertEqual(a, b)
        self.assertEqual(a, c)

    def test_key_differs_for_different_claims(self) -> None:
        self.assertNotEqual(hypothesis_key("claim one"), hypothesis_key("claim two"))

    def test_empty_hypothesis_has_no_key(self) -> None:
        self.assertEqual(hypothesis_key(""), "")
        self.assertEqual(hypothesis_key("   "), "")
        self.assertEqual(hypothesis_key(None), "")


class LedgerBasicsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_record_and_already_falsified(self) -> None:
        ledger = FalsificationLedger(self.dir)
        self.assertFalse(ledger.already_falsified("x is reachable"))
        ledger.falsify("x is reachable", mechanism="a guard covers it")
        self.assertTrue(ledger.already_falsified("x is reachable"))

    def test_already_falsified_matches_a_reworded_claim(self) -> None:
        ledger = FalsificationLedger(self.dir)
        ledger.falsify("The sink is reachable anonymously")
        self.assertTrue(ledger.already_falsified("the sink is reachable anonymously."))

    def test_survived_reopens_a_previously_falsified_hypothesis(self) -> None:
        # New information must beat an old negative, or the ledger would permanently bury a
        # hypothesis that later turned out to be live.
        ledger = FalsificationLedger(self.dir)
        ledger.falsify("claim")
        self.assertTrue(ledger.already_falsified("claim"))
        ledger.record("claim", outcome=OUTCOME_SURVIVED)
        self.assertFalse(ledger.already_falsified("claim"))

    def test_attempted_does_not_close_a_hypothesis(self) -> None:
        ledger = FalsificationLedger(self.dir)
        ledger.note_attempt("claim")
        self.assertFalse(ledger.already_falsified("claim"))
        self.assertEqual(ledger.attempts("claim"), 1)

    def test_attempts_counts_every_record(self) -> None:
        ledger = FalsificationLedger(self.dir)
        ledger.note_attempt("c")
        ledger.note_attempt("c")
        ledger.falsify("c")
        self.assertEqual(ledger.attempts("c"), 3)

    def test_empty_hypothesis_is_not_recorded(self) -> None:
        ledger = FalsificationLedger(self.dir)
        self.assertIsNone(ledger.record(""))
        self.assertEqual(ledger.records(), [])

    def test_outcome_of_returns_latest(self) -> None:
        ledger = FalsificationLedger(self.dir)
        ledger.note_attempt("c")
        ledger.falsify("c")
        self.assertEqual(ledger.outcome_of("c"), OUTCOME_FALSIFIED)

    def test_unknown_outcome_degrades_to_attempted(self) -> None:
        ledger = FalsificationLedger(self.dir)
        ledger.record("c", outcome="banana")
        self.assertEqual(ledger.outcome_of("c"), OUTCOME_ATTEMPTED)

    def test_summary_counts(self) -> None:
        ledger = FalsificationLedger(self.dir)
        ledger.falsify("a", family="f")
        ledger.falsify("b", family="f")
        ledger.record("c", outcome=OUTCOME_SURVIVED)
        summary = ledger.summary()
        self.assertEqual(summary["falsified"], 2)
        self.assertEqual(summary["survived"], 1)
        self.assertEqual(summary["distinct_hypotheses"], 3)
        self.assertEqual(summary["families"], 1)


class PersistenceTest(unittest.TestCase):
    """The ledger must survive a PROCESS RESTART — that is what makes a resumed hunt stop
    re-testing what a killed run already ruled out."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_falsification_survives_a_restart(self) -> None:
        FalsificationLedger(self.dir).falsify("dead end", mechanism="blocked by design")
        reloaded = FalsificationLedger(self.dir)
        self.assertTrue(reloaded.already_falsified("dead end"))
        self.assertEqual(reloaded.records()[0].mechanism, "blocked by design")

    def test_file_is_append_only_jsonl(self) -> None:
        ledger = FalsificationLedger(self.dir)
        ledger.falsify("one")
        ledger.falsify("two")
        lines = (self.dir / FalsificationLedger.FILENAME).read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertEqual(json.loads(line)["outcome"], OUTCOME_FALSIFIED)

    def test_corrupt_line_does_not_lose_the_rest(self) -> None:
        # A run killed mid-append leaves a partial final line; everything before it must survive.
        path = self.dir / FalsificationLedger.FILENAME
        good = json.dumps({"key": hypothesis_key("kept"), "hypothesis": "kept",
                           "outcome": OUTCOME_FALSIFIED})
        path.write_text(good + "\n{not valid json\n", encoding="utf-8")
        ledger = FalsificationLedger(self.dir)
        self.assertTrue(ledger.already_falsified("kept"))
        self.assertEqual(len(ledger.records()), 1)

    def test_missing_file_is_tolerated(self) -> None:
        ledger = FalsificationLedger(self.dir / "nope")
        self.assertEqual(ledger.records(), [])
        self.assertFalse(ledger.already_falsified("anything"))

    def test_memory_only_mode_still_works(self) -> None:
        ledger = FalsificationLedger(None)
        ledger.falsify("x")
        self.assertTrue(ledger.already_falsified("x"))
        self.assertIsNone(ledger.path)

    def test_unwritable_dir_never_raises(self) -> None:
        path = self.dir / "blocked"
        path.write_text("i am a file, not a directory", encoding="utf-8")
        ledger = FalsificationLedger(path)  # must not raise
        ledger.falsify("x")                 # must not raise
        self.assertTrue(ledger.already_falsified("x"))  # still true in memory


class ConclusionTest(unittest.TestCase):
    """Composition: a closed FAMILY becomes an architectural conclusion."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    @staticmethod
    def _rec(hyp: str, outcome: str = OUTCOME_FALSIFIED, family: str = "V", mech: str = "") -> LedgerRecord:
        return LedgerRecord(key=hypothesis_key(hyp), hypothesis=hyp, outcome=outcome,
                            family=family, mechanism=mech)

    def test_compose_requires_min_members(self) -> None:
        records = [self._rec("a"), self._rec("b")]
        self.assertIsNone(compose_conclusion("V", records, min_members=3))
        records.append(self._rec("c"))
        self.assertIsNotNone(compose_conclusion("V", records, min_members=3))

    def test_a_single_survivor_blocks_the_conclusion(self) -> None:
        # One live variant means the class is NOT closed — the honest answer is "keep hunting".
        records = [self._rec("a"), self._rec("b"), self._rec("c"),
                   self._rec("d", outcome=OUTCOME_SURVIVED)]
        self.assertIsNone(compose_conclusion("V", records, min_members=3))

    def test_conclusion_names_the_blocking_mechanisms(self) -> None:
        records = [
            self._rec("a", mech="mechanism A"),
            self._rec("b", mech="mechanism B"),
            self._rec("c", mech="mechanism A"),
        ]
        conclusion = compose_conclusion("V", records, min_members=3)
        assert conclusion is not None
        self.assertEqual(conclusion.family, "V")
        self.assertEqual(conclusion.closed_count, 3)
        self.assertEqual(sorted(conclusion.mechanisms), ["mechanism A", "mechanism B"])
        self.assertIn("CLOSED", conclusion.statement)

    def test_duplicate_keys_count_once(self) -> None:
        records = [self._rec("same"), self._rec("same"), self._rec("same")]
        self.assertIsNone(compose_conclusion("V", records, min_members=3))

    def test_unknown_family_returns_none(self) -> None:
        self.assertIsNone(compose_conclusion("nope", [self._rec("a")], min_members=1))

    def test_markdown_renders_members_and_mechanisms(self) -> None:
        conclusion = ArchitecturalConclusion(
            family="zero-click", closed_count=2, mechanisms=("gate A", "gate B"),
            statement="closed.", members=("v1", "v2"),
        )
        text = conclusion.as_markdown()
        self.assertIn("# Architectural conclusion: zero-click", text)
        self.assertIn("gate A", text)
        self.assertIn("v1", text)

    def test_new_conclusions_emits_once_and_is_recorded(self) -> None:
        ledger = FalsificationLedger(self.dir)
        for name in ("a", "b", "c"):
            ledger.falsify(name, family="V", mechanism=f"mech {name}")
        first = ledger.new_conclusions(min_members=3)
        self.assertEqual(len(first), 1)
        # Emitting twice would spam the operator with the same negative every round.
        self.assertEqual(ledger.new_conclusions(min_members=3), [])
        self.assertTrue(any(r.outcome == OUTCOME_CONCLUSION for r in ledger.records()))

    def test_conclusion_emission_survives_restart(self) -> None:
        ledger = FalsificationLedger(self.dir)
        for name in ("a", "b", "c"):
            ledger.falsify(name, family="V", mechanism="m")
        self.assertEqual(len(ledger.new_conclusions(min_members=3)), 1)
        reloaded = FalsificationLedger(self.dir)
        self.assertEqual(reloaded.new_conclusions(min_members=3), [])

    def test_write_conclusion_creates_a_markdown_artifact(self) -> None:
        ledger = FalsificationLedger(self.dir)
        for name in ("a", "b", "c"):
            ledger.falsify(name, family="Variant Class X", mechanism="m")
        conclusions = ledger.new_conclusions(min_members=3)
        path = ledger.write_conclusion(conclusions[0])
        self.assertTrue(path)
        self.assertTrue(Path(path).is_file())
        self.assertIn("Variant Class X", Path(path).read_text(encoding="utf-8"))

    def test_write_conclusion_without_dir_returns_empty(self) -> None:
        ledger = FalsificationLedger(None)
        conclusion = ArchitecturalConclusion(family="V", closed_count=1, mechanisms=(), statement="s")
        self.assertEqual(ledger.write_conclusion(conclusion), "")

    def test_group_by_family_skips_unfamilied(self) -> None:
        grouped = group_by_family([self._rec("a", family="F"), self._rec("b", family="")])
        self.assertEqual(list(grouped), ["F"])
        self.assertEqual(len(grouped["F"]), 1)


class DialTest(unittest.TestCase):
    def test_min_members_dial(self) -> None:
        prev = os.environ.get("P1HUNT_CONCLUSION_MIN_MEMBERS")
        try:
            os.environ["P1HUNT_CONCLUSION_MIN_MEMBERS"] = "1"
            self.assertEqual(conclusion_min_members(), 1)
            os.environ["P1HUNT_CONCLUSION_MIN_MEMBERS"] = "garbage"
            self.assertEqual(conclusion_min_members(), 3)
            os.environ.pop("P1HUNT_CONCLUSION_MIN_MEMBERS")
            self.assertEqual(conclusion_min_members(), 3)
        finally:
            if prev is None:
                os.environ.pop("P1HUNT_CONCLUSION_MIN_MEMBERS", None)
            else:
                os.environ["P1HUNT_CONCLUSION_MIN_MEMBERS"] = prev


if __name__ == "__main__":
    unittest.main()
