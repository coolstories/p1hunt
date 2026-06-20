"""Cross-engagement memory: records the tool's OWN confirmed findings, recalls them as class-scoped
priors. Doctrine-safe (learned from our wins, not preset) and offline-graceful."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from p1hunt.memory import MemoryStore, _generalize


class TestMemory(unittest.TestCase):
    def _store(self) -> MemoryStore:
        return MemoryStore(Path(tempfile.mkdtemp()) / "confirmed.jsonl")

    def test_record_then_recall_same_class(self):
        m = self._store()
        m.record(target_class="EVM_CONTRACT", subclass="marketplace",
                 finding={"program": "Acme", "title": "reentrancy", "lens": "asset-custody",
                          "severity": "critical", "root_cause": "external call before state update",
                          "counterfactual": "drain escrow"})
        hits = m.recall("EVM_CONTRACT")
        self.assertEqual(len(hits), 1)
        self.assertIn("external call before state update", hits[0])
        self.assertIn("asset-custody", hits[0])

    def test_recall_filters_by_class(self):
        m = self._store()
        m.record(target_class="EVM_CONTRACT", subclass="",
                 finding={"title": "t", "root_cause": "evm bug", "lens": "x", "counterfactual": "y"})
        m.record(target_class="WEB_API", subclass="",
                 finding={"title": "t2", "root_cause": "idor bug", "lens": "authz", "counterfactual": "z"})
        self.assertEqual(m.recall("CRYPTO_LIB"), [])           # unrelated class → nothing
        self.assertTrue(all("idor" in h for h in m.recall("WEB_API")))

    def test_subclass_match_ranks_first(self):
        m = self._store()
        m.record(target_class="WEB_API", subclass="",
                 finding={"title": "a", "root_cause": "generic web", "lens": "l", "counterfactual": "c"})
        m.record(target_class="WEB_API", subclass="graphql",
                 finding={"title": "b", "root_cause": "graphql field authz", "lens": "l", "counterfactual": "c"})
        hits = m.recall("WEB_API", "graphql")
        self.assertIn("graphql field authz", hits[0])  # subclass match floats to the top

    def test_generalize_omits_program_name(self):
        # The reusable prior must be class-level, not name a specific program/target.
        pat = _generalize({"program": "SuperSecretBank", "lens": "asset-custody",
                           "root_cause": "negative amount accepted", "counterfactual": "credit self"})
        self.assertNotIn("SuperSecretBank", pat)
        self.assertIn("negative amount accepted", pat)

    def test_dedup_on_recall(self):
        m = self._store()
        for _ in range(3):
            m.record(target_class="EVM_CONTRACT", subclass="",
                     finding={"title": "t", "root_cause": "same root cause", "lens": "x",
                              "counterfactual": "same"})
        self.assertEqual(len(m.recall("EVM_CONTRACT")), 1)  # identical patterns collapse

    def test_missing_file_is_empty_not_error(self):
        m = MemoryStore(Path(tempfile.mkdtemp()) / "nope" / "confirmed.jsonl")
        self.assertEqual(m.recall("EVM_CONTRACT"), [])
        self.assertEqual(m.count(), 0)


if __name__ == "__main__":
    unittest.main()
