"""Unit tests for the persistent fuzz corpus + coverage ledger (p1hunt.corpus).

Pure filesystem-JSON logic: record -> save -> reload, dedup, coverage queries, and the
uncovered-entrypoint hint. No network, no external tools.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from p1hunt.corpus import CorpusStore, SubsystemCoverage


class CorpusStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_record_save_reload(self) -> None:
        store = CorpusStore(self.dir)
        store.record(
            "matching",
            counterexamples=["calldata-A"],
            coverage_notes=["reached combiner"],
            covered_symbols=["fulfillOrder"],
        )
        self.assertTrue((self.dir / "corpus.json").exists())

        # A fresh store over the same dir must see everything persisted.
        reloaded = CorpusStore(self.dir)
        cov = reloaded.coverage_for("matching")
        self.assertEqual(cov.counterexamples, ["calldata-A"])
        self.assertEqual(cov.coverage_notes, ["reached combiner"])
        self.assertEqual(cov.covered_symbols, ["fulfillOrder"])
        self.assertEqual(cov.rounds, 1)

    def test_rounds_increment_and_merge(self) -> None:
        store = CorpusStore(self.dir)
        store.record("matching", counterexamples=["x"], covered_symbols=["a"])
        store.record("matching", counterexamples=["y"], covered_symbols=["b"])
        cov = store.coverage_for("matching")
        self.assertEqual(cov.rounds, 2)
        self.assertEqual(sorted(cov.counterexamples), ["x", "y"])
        self.assertEqual(sorted(cov.covered_symbols), ["a", "b"])

    def test_dedup_counterexamples_and_symbols(self) -> None:
        store = CorpusStore(self.dir)
        store.record(
            "matching",
            counterexamples=["dup", "dup", " dup ", "unique"],
            covered_symbols=["f", "f", "g"],
        )
        store.record("matching", counterexamples=["dup"], covered_symbols=["g"])
        cov = store.coverage_for("matching")
        self.assertEqual(cov.counterexamples, ["dup", "unique"])
        self.assertEqual(cov.covered_symbols, ["f", "g"])

    def test_blanks_and_none_skipped(self) -> None:
        store = CorpusStore(self.dir)
        store.record("s", counterexamples=["", "  ", None, "real"])  # type: ignore[list-item]
        self.assertEqual(store.seeds_for("s"), ["real"])

    def test_seeds_for(self) -> None:
        store = CorpusStore(self.dir)
        store.record("s", counterexamples=["seed1", "seed2"])
        self.assertEqual(store.seeds_for("s"), ["seed1", "seed2"])
        self.assertEqual(store.seeds_for("never-seen"), [])

    def test_coverage_for_unknown_is_empty(self) -> None:
        store = CorpusStore(self.dir)
        cov = store.coverage_for("nope")
        self.assertIsInstance(cov, SubsystemCoverage)
        self.assertEqual(cov.subsystem, "nope")
        self.assertEqual(cov.counterexamples, [])
        self.assertEqual(cov.rounds, 0)

    def test_coverage_for_returns_copy(self) -> None:
        store = CorpusStore(self.dir)
        store.record("s", covered_symbols=["a"])
        cov = store.coverage_for("s")
        cov.covered_symbols.append("mutation")
        # The ledger must be untouched by mutating the returned copy.
        self.assertEqual(store.coverage_for("s").covered_symbols, ["a"])

    def test_uncovered_hint_excludes_covered(self) -> None:
        store = CorpusStore(self.dir)
        store.record("s", covered_symbols=["fulfillOrder", "cancel"])
        hint = store.uncovered_hint("s", ["fulfillOrder", "matchOrders", "cancel", "validate"])
        self.assertIn("matchOrders", hint)
        self.assertIn("validate", hint)
        self.assertNotIn("fulfillOrder", hint)
        self.assertNotIn("cancel", hint)

    def test_uncovered_hint_matches_full_signature_vs_bare_name(self) -> None:
        # Production mismatch: detected entrypoints are FULL signatures while the fuzzer's
        # self-reported covered symbols are bare names (or short phrases). Coverage steering must
        # match on the bare function name, not exact string, or it would re-steer at covered code.
        store = CorpusStore(self.dir)
        store.record("s", covered_symbols=["fulfillOrder", "exercised cancel() this round"])
        hint = store.uncovered_hint(
            "s", ["fulfillOrder(Order,bytes32)", "matchOrders(Order[],Fulfillment[])", "cancel(Order[])"])
        self.assertIn("matchOrders", hint)
        self.assertNotIn("fulfillOrder", hint)   # covered by bare-name "fulfillOrder"
        self.assertNotIn("cancel(", hint)        # covered by "cancel" inside the phrase

    def test_uncovered_hint_all_covered_returns_empty(self) -> None:
        store = CorpusStore(self.dir)
        store.record("s", covered_symbols=["a", "b"])
        self.assertEqual(store.uncovered_hint("s", ["a", "b"]), "")

    def test_uncovered_hint_no_entrypoints_returns_empty(self) -> None:
        store = CorpusStore(self.dir)
        store.record("s", covered_symbols=["a"])
        self.assertEqual(store.uncovered_hint("s", []), "")

    def test_uncovered_hint_dedups_entrypoints(self) -> None:
        store = CorpusStore(self.dir)
        hint = store.uncovered_hint("s", ["alpha", "alpha", "beta"])
        self.assertEqual(hint.count("alpha"), 1)
        self.assertEqual(hint.count("beta"), 1)

    def test_missing_corpus_file_starts_empty(self) -> None:
        store = CorpusStore(self.dir)  # no file exists yet
        self.assertEqual(store.seeds_for("anything"), [])
        self.assertEqual(store.coverage_for("anything").rounds, 0)

    def test_corrupt_corpus_file_tolerated(self) -> None:
        (self.dir / "corpus.json").write_text("{ not valid json ", encoding="utf-8")
        store = CorpusStore(self.dir)  # must not raise
        self.assertEqual(store.seeds_for("anything"), [])
        # And recording over the corrupt file repairs it.
        store.record("s", counterexamples=["ok"])
        data = json.loads((self.dir / "corpus.json").read_text(encoding="utf-8"))
        self.assertIn("s", data["subsystems"])

    def test_non_dict_json_tolerated(self) -> None:
        (self.dir / "corpus.json").write_text("[1, 2, 3]", encoding="utf-8")
        store = CorpusStore(self.dir)
        self.assertEqual(store.seeds_for("x"), [])

    def test_save_creates_engagement_dir(self) -> None:
        nested = self.dir / "deep" / "engagement"
        store = CorpusStore(nested)
        store.record("s", counterexamples=["c"])
        self.assertTrue((nested / "corpus.json").exists())

    def test_multiple_subsystems_isolated(self) -> None:
        store = CorpusStore(self.dir)
        store.record("alpha", covered_symbols=["a"])
        store.record("beta", covered_symbols=["b"])
        self.assertEqual(store.coverage_for("alpha").covered_symbols, ["a"])
        self.assertEqual(store.coverage_for("beta").covered_symbols, ["b"])

    def test_load_recovers_bad_round_value(self) -> None:
        bad = {"subsystems": {"s": {"counterexamples": ["c"], "rounds": "oops"}}}
        (self.dir / "corpus.json").write_text(json.dumps(bad), encoding="utf-8")
        store = CorpusStore(self.dir)
        self.assertEqual(store.coverage_for("s").rounds, 0)
        self.assertEqual(store.seeds_for("s"), ["c"])


if __name__ == "__main__":
    unittest.main()
