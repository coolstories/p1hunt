"""Auto-scope selection logic (pure) — name+platform → which in-scope repo to scan, and which
out-of-scope path globs to enforce. No network/Claude; exercises the deterministic helpers only."""

import unittest

from p1hunt.main import out_of_scope_globs, select_in_scope_repo


class TestSelectInScopeRepo(unittest.TestCase):
    def _brief(self, repos, oos=None):
        return {"repos": repos, "out_of_scope": oos or []}

    def test_match_by_only(self):
        b = self._brief(["https://github.com/example/payments-engine",
                         "https://github.com/example/sdk-js"])
        chosen, others = select_in_scope_repo(b, only="payments", program="Example")
        self.assertIn("payments", chosen)
        self.assertEqual(others, ["https://github.com/example/sdk-js"])

    def test_match_by_program_when_no_only(self):
        b = self._brief(["https://github.com/org/widgets", "https://github.com/org/settlement-core"])
        chosen, _ = select_in_scope_repo(b, only="", program="Settlement")
        self.assertIn("settlement", chosen)

    def test_hyphen_space_insensitive(self):
        b = self._brief(["https://github.com/org/settlement-core"])
        chosen, _ = select_in_scope_repo(b, only="settlement core")
        self.assertIsNotNone(chosen)

    def test_falls_back_to_first_when_no_match(self):
        b = self._brief(["https://github.com/org/alpha", "https://github.com/org/beta"])
        chosen, others = select_in_scope_repo(b, only="nomatch", program="nomatch")
        self.assertEqual(chosen, "https://github.com/org/alpha")
        self.assertEqual(others, ["https://github.com/org/beta"])

    def test_empty_returns_none(self):
        chosen, others = select_in_scope_repo({"repos": []}, only="core")
        self.assertIsNone(chosen)
        self.assertEqual(others, [])


class TestOutOfScopeGlobs(unittest.TestCase):
    def test_only_path_kind_becomes_globs(self):
        b = {"out_of_scope": [
            {"kind": "path", "value": "reference/*"},
            {"kind": "repo", "value": "https://github.com/org/other"},
            {"kind": "path", "value": "test/**"},
            "not-a-dict",
        ]}
        self.assertEqual(out_of_scope_globs(b), ["reference/*", "test/**"])

    def test_empty(self):
        self.assertEqual(out_of_scope_globs({}), [])


if __name__ == "__main__":
    unittest.main()
