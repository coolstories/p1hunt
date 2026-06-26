"""Cross-engagement memory stores operational metadata, not vulnerability playbooks."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from p1hunt.memory import MemoryStore, memory_enabled


class TestMemory(unittest.TestCase):
    def _store(self) -> MemoryStore:
        return MemoryStore(Path(tempfile.mkdtemp()) / "confirmed.jsonl")

    def test_disabled_by_default(self):
        old = os.environ.pop("P1HUNT_MEMORY", None)
        try:
            self.assertFalse(memory_enabled())
            os.environ["P1HUNT_MEMORY"] = "1"
            self.assertTrue(memory_enabled())
        finally:
            if old is None:
                os.environ.pop("P1HUNT_MEMORY", None)
            else:
                os.environ["P1HUNT_MEMORY"] = old

    def test_record_then_recall_same_class_without_bug_pattern(self):
        m = self._store()
        m.record(target_class="EVM_CONTRACT", subclass="marketplace",
                 finding={"program": "Acme", "title": "reentrancy", "lens": "asset-custody",
                          "severity": "critical", "root_cause": "external call before state update",
                          "counterfactual": "drain escrow", "harness_kind": "forge"})
        hits = m.recall("EVM_CONTRACT")
        self.assertEqual(len(hits), 1)
        self.assertIn("class=EVM_CONTRACT", hits[0])
        self.assertIn("runner=forge", hits[0])
        self.assertNotIn("external call before state update", hits[0])
        self.assertNotIn("asset-custody", hits[0])

    def test_recall_filters_by_class(self):
        m = self._store()
        m.record(target_class="EVM_CONTRACT", subclass="",
                 finding={"title": "t", "root_cause": "evm bug", "lens": "x", "counterfactual": "y"})
        m.record(target_class="WEB_API", subclass="",
                 finding={"title": "t2", "root_cause": "idor bug", "lens": "authz", "counterfactual": "z"})
        self.assertEqual(m.recall("CRYPTO_LIB"), [])           # unrelated class → nothing
        self.assertTrue(all("idor" not in h.lower() for h in m.recall("WEB_API")))

    def test_subclass_match_ranks_first(self):
        m = self._store()
        m.record(target_class="WEB_API", subclass="",
                 finding={"title": "a", "root_cause": "generic web", "lens": "l", "counterfactual": "c"})
        m.record(target_class="WEB_API", subclass="graphql",
                 finding={"title": "b", "root_cause": "graphql field authz", "lens": "l", "counterfactual": "c"})
        hits = m.recall("WEB_API", "graphql")
        self.assertIn("subclass=graphql", hits[0])  # subclass match floats to the top
        self.assertNotIn("field authz", hits[0])

    def test_record_file_omits_program_and_bug_fields(self):
        m = self._store()
        m.record(target_class="WEB_API", subclass="accounts",
                 finding={"program": "SuperSecretBank", "title": "negative amount accepted",
                          "root_cause": "negative amount accepted", "counterfactual": "credit self",
                          "lens": "asset-custody", "harness_kind": "pytest"})
        rec = json.loads(m.path.read_text(encoding="utf-8").strip())
        for banned in ("program", "title", "root_cause", "counterfactual", "lens", "pattern"):
            self.assertNotIn(banned, rec)
        text = json.dumps(rec)
        self.assertNotIn("SuperSecretBank", text)
        self.assertNotIn("negative amount", text)

    def test_dedup_on_recall(self):
        m = self._store()
        for _ in range(3):
            m.record(target_class="EVM_CONTRACT", subclass="",
                     finding={"title": "t", "root_cause": "same root cause", "lens": "x",
                              "counterfactual": "same", "harness_kind": "forge"})
        self.assertEqual(len(m.recall("EVM_CONTRACT")), 1)  # identical metadata collapses

    def test_missing_file_is_empty_not_error(self):
        m = MemoryStore(Path(tempfile.mkdtemp()) / "nope" / "confirmed.jsonl")
        self.assertEqual(m.recall("EVM_CONTRACT"), [])
        self.assertEqual(m.count(), 0)


if __name__ == "__main__":
    unittest.main()
