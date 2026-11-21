"""The ``expect`` convention, pinned ACROSS the scaffold/runner boundary.

This file exists because the correctness bug it guards could not be seen from either side alone.
``p1hunt/agents/harness_scaffold.py`` emitted a harness that ASSERTS REFUSAL while declaring
``ReproSpec.expect="pass"``, and ``p1hunt/runners/web.py`` faithfully implemented ``expect="pass"``
as "reproduced iff the tests PASSED". Each module was self-consistent and each module's own unit
tests passed. Composed, they inverted every web verdict:

  * a genuine reproduced IDOR made the refusal assertion FAIL -> parsed as "attack not
    demonstrated" -> the finding was quarantined forever (FALSE NEGATIVE);
  * a WAF that blanket-403s every request satisfied every refusal assertion -> parsed as
    "the unauthorized action succeeded" -> stamped ``reproduced: True`` (FALSE POSITIVE).

THE CONVENTION (defined in ``p1hunt/runners/web.py``'s module docstring)
    ``expect`` describes which direction the HARNESS'S OWN assertions point.
    ``expect="fail"`` -> the harness asserts the SECURE behavior; the bug is demonstrated when
        the targeted test FAILS. Every refusal-asserting harness is "fail".
    ``expect="pass"`` -> the harness asserts the INSECURE behavior (it performs the exploit and
        asserts it worked); the bug is demonstrated when the targeted test PASSES.

The tests below pin the CONVENTION rather than either implementation: they read the ``expect``
value each scaffold declares, synthesize the pytest output the harness that scaffold emits would
actually produce in the clean / reproduced / blocked / broken cases, and assert the runner's
verdict matches reality. Re-inverting either side breaks these regardless of how the code is
refactored.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from p1hunt.agents.harness_scaffold import scaffold_block
from p1hunt.runners.base import ReproSpec
from p1hunt.runners.web import parse_pytest

# Source bodies that steer detect_web_subclass to each web scaffold, with the assertion each
# emitted harness uses to state the SECURE behavior.
_WEB_SUBCLASSES = {
    "auth": {
        "filename": "auth_routes.py",
        "body": "def login(): pass  # oauth jwt session bearer token",
        "subsystem": "accounts",
        "secure_assertion": "401, 403, 404",
        "test_ids": [
            ".p1hunt-poc/test_authz.py::test_b_cannot_read_a_object",
            ".p1hunt-poc/test_authz.py::test_b_cannot_write_a_object",
        ],
    },
    "payments": {
        "filename": "billing.py",
        "body": "def charge(): pass  # payment refund idempotency-key ledger currency amount",
        "subsystem": "billing",
        "secure_assertion": "_balance()",
        "test_ids": [
            ".p1hunt-poc/test_payments.py::test_idempotency_key_not_replayable",
            ".p1hunt-poc/test_payments.py::test_refund_conserves_value",
        ],
    },
    "graphql": {
        "filename": "schema.py",
        "body": "resolver typedefs apollo introspection __schema query { mutation {",
        "subsystem": "api",
        "secure_assertion": "_denied(",
        "test_ids": [
            ".p1hunt-poc/test_graphql_authz.py::test_protected_field_denied_to_low_role",
            ".p1hunt-poc/test_graphql_authz.py::test_alias_does_not_bypass_authz",
        ],
    },
}


def _scaffold_for(spec: dict) -> str:
    repo = tempfile.mkdtemp()
    Path(repo, spec["filename"]).write_text(spec["body"], encoding="utf-8")
    return scaffold_block("WEB_API", spec["subsystem"], [f"src/{spec['filename']}"],
                          repo_path=repo)


def _declared_expect(block: str) -> str:
    """The ``expect`` value a scaffold tells the prover to use. Asserts it is unambiguous."""
    import re
    found = set(re.findall(r'ReproSpec\.expect="(\w+)"', block))
    assert len(found) == 1, f"a scaffold must declare exactly one expect value, got {found}"
    return found.pop()


def _emitted_harness(block: str) -> str:
    return block.split("```python", 1)[1].split("```", 1)[0]


# --------------------------------------------------------------------------- synthesized output
def _clean_run(test_ids: list[str]) -> str:
    """What a CLEAN target (or a blanket-blocking WAF) produces: every assertion holds."""
    lines = [f"{tid} PASSED" for tid in test_ids]
    return ("============================= test session starts ===========================\n"
            + "\n".join(lines)
            + f"\n==================== {len(test_ids)} passed in 0.40s ====================\n")


def _reproduced_run(test_ids: list[str]) -> str:
    """What a REPRODUCED bug produces: the secure-behavior assertion did NOT hold."""
    first, rest = test_ids[0], test_ids[1:]
    lines = [f"{first} FAILED"] + [f"{tid} PASSED" for tid in rest]
    return ("============================= test session starts ===========================\n"
            + "\n".join(lines)
            + "\n=================================== FAILURES ================================\n"
            + f"FAILED {first} - AssertionError: the secure behavior did not hold\n"
            + f"==================== 1 failed, {len(rest)} passed in 0.44s ==================\n")


def _broken_run() -> str:
    """What a harness with an undeclared dependency produces: a collection error, no results."""
    return ("============================= test session starts ===========================\n"
            "collected 0 items / 1 error\n"
            "ImportError while importing test module '/w/.p1hunt-poc/test_authz.py'.\n"
            "E   ModuleNotFoundError: No module named 'requests'\n"
            "=========================== 1 error in 0.09s ================================\n")


def _blocked_run(test_ids: list[str]) -> str:
    """What an edge/WAF block produces once the client raises BlockedError."""
    return ("============================= test session starts ===========================\n"
            f"{test_ids[0]} FAILED\n"
            "E   p1hunt_dyn.BlockedError: P1HUNT_BLOCKED: B GET /objects/1 -> 403 was blocked\n"
            "E   at the edge (challenge/block page body marker 'just a moment').\n"
            f"FAILED {test_ids[0]} - p1hunt_dyn.BlockedError\n"
            "========================= 1 failed in 0.30s =================================\n")


class ScaffoldDeclaresTheConventionTests(unittest.TestCase):
    """Every web scaffold's declared ``expect`` must match the direction it actually asserts."""

    def test_each_web_scaffold_asserts_the_secure_behavior(self):
        for name, spec in _WEB_SUBCLASSES.items():
            with self.subTest(subclass=name):
                harness = _emitted_harness(_scaffold_for(spec))
                self.assertIn(spec["secure_assertion"], harness,
                              "scaffold no longer asserts the secure behavior; if that is "
                              "intentional its declared expect must flip too")

    def test_each_web_scaffold_therefore_declares_expect_fail(self):
        # The inference the old code got backwards: asserting the SECURE behavior means a
        # reproduced bug FAILS the test, which is expect="fail".
        for name, spec in _WEB_SUBCLASSES.items():
            with self.subTest(subclass=name):
                self.assertEqual(_declared_expect(_scaffold_for(spec)), "fail")

    def test_no_web_scaffold_declares_expect_pass(self):
        for name, spec in _WEB_SUBCLASSES.items():
            with self.subTest(subclass=name):
                self.assertNotIn('expect="pass"', _scaffold_for(spec))

    def test_live_target_note_names_the_value_explicitly(self):
        # The live note used to describe the convention correctly in prose while the scaffolds
        # declared the opposite value. It must now name the value, so prose and value cannot drift.
        block = scaffold_block("WEB_API", "accounts", ["src/auth_routes.py"],
                               repo_path=tempfile.mkdtemp(), target_url="https://uat.example.com")
        self.assertIn('expect="fail"', block)
        self.assertNotIn('expect="pass"', block)

    def test_scaffold_block_docstring_documents_expect_fail_for_web(self):
        doc = scaffold_block.__doc__ or ""
        self.assertIn("expect='fail'", doc)
        self.assertNotIn("expect='pass'", doc)


class ScaffoldAndRunnerAgreeEndToEndTests(unittest.TestCase):
    """THE test the audit wanted: scaffold declaration + runner parser, composed.

    For each web scaffold, take the ``expect`` value it declares and feed the runner the output
    the harness it emits would really produce. Both directions are asserted, because a fix that
    only suppressed false positives (or only restored true positives) would be half a fix.
    """

    def _spec_for(self, scaffold_spec: dict) -> ReproSpec:
        return ReproSpec(expect=_declared_expect(_scaffold_for(scaffold_spec)),
                         harness_path=".p1hunt-poc/test_authz.py")

    def test_a_reproduced_bug_is_reported_as_reproduced(self):
        for name, spec in _WEB_SUBCLASSES.items():
            with self.subTest(subclass=name):
                r = parse_pytest(_reproduced_run(spec["test_ids"]), 1, self._spec_for(spec))
                self.assertTrue(r["reproduced"],
                                "a genuine reproduced bug must not be filed as 'not "
                                "demonstrated' — that is the false negative")

    def test_a_clean_target_is_not_reported_as_reproduced(self):
        for name, spec in _WEB_SUBCLASSES.items():
            with self.subTest(subclass=name):
                r = parse_pytest(_clean_run(spec["test_ids"]), 0, self._spec_for(spec))
                self.assertFalse(r["reproduced"],
                                 "every assertion holding means the boundary held — reporting "
                                 "that as a finding is the false positive")

    def test_a_blanket_waf_block_is_not_reported_as_reproduced(self):
        # A blanket block produces exactly the same all-green output as a clean target, which is
        # why liveness must be probed separately; either way it is not a finding.
        for name, spec in _WEB_SUBCLASSES.items():
            with self.subTest(subclass=name):
                r = parse_pytest(_clean_run(spec["test_ids"]), 0, self._spec_for(spec))
                self.assertFalse(r["reproduced"])

    def test_an_explicit_edge_block_is_a_non_result(self):
        for name, spec in _WEB_SUBCLASSES.items():
            with self.subTest(subclass=name):
                r = parse_pytest(_blocked_run(spec["test_ids"]), 1, self._spec_for(spec))
                self.assertFalse(r["reproduced"])
                self.assertTrue(r["blocked"])
                self.assertTrue(r["infrastructure_error"])

    def test_a_broken_harness_is_a_non_result(self):
        for name, spec in _WEB_SUBCLASSES.items():
            with self.subTest(subclass=name):
                r = parse_pytest(_broken_run(), 2, self._spec_for(spec))
                self.assertFalse(r["reproduced"])
                self.assertTrue(r["infrastructure_error"])

    def test_the_four_outcomes_are_all_distinguishable(self):
        # The whole point of the fix: four inputs, four distinct verdicts. Under the old code
        # "reproduced" and "clean" were swapped and "broken" collided with "reproduced".
        spec = _WEB_SUBCLASSES["auth"]
        rs = self._spec_for(spec)
        ids = spec["test_ids"]
        reproduced = parse_pytest(_reproduced_run(ids), 1, rs)
        clean = parse_pytest(_clean_run(ids), 0, rs)
        broken = parse_pytest(_broken_run(), 2, rs)
        blocked = parse_pytest(_blocked_run(ids), 1, rs)

        self.assertEqual(
            [reproduced["reproduced"], clean["reproduced"],
             broken["reproduced"], blocked["reproduced"]],
            [True, False, False, False])
        # ...and the two non-results are distinguishable from the clean run, which is what lets
        # the runner report ran=False for them instead of a verdict.
        self.assertFalse(clean.get("infrastructure_error", False))
        self.assertTrue(broken["infrastructure_error"])
        self.assertTrue(blocked["blocked"])


class ConventionIsDocumentedTests(unittest.TestCase):
    """The convention must be stated in code, not only in tests, so it cannot silently re-invert."""

    def test_web_runner_module_docstring_states_the_convention(self):
        from p1hunt.runners import web
        doc = web.__doc__ or ""
        self.assertIn("expect", doc)
        self.assertIn('``expect="fail"``', doc)
        self.assertIn('``expect="pass"``', doc)
        # The litmus test a future editor needs in order to get it right.
        self.assertIn("SECURE", doc)
        self.assertIn("INSECURE", doc)

    def test_scaffold_module_docstring_states_the_same_convention(self):
        from p1hunt.agents import harness_scaffold
        doc = harness_scaffold.__doc__ or ""
        self.assertIn('``expect="fail"``', doc)
        self.assertIn("SECURE", doc)

    def test_repro_spec_default_expect_is_the_common_case(self):
        # A missing/garbled expect must land on the refusal-harness convention, not invert it.
        self.assertEqual(ReproSpec().expect, "fail")
        self.assertTrue(ReproSpec().expects_fail())
        self.assertEqual(ReproSpec.from_dict({}).expect, "fail")
        self.assertEqual(ReproSpec.from_dict({"expect": ""}).expect, "fail")


if __name__ == "__main__":
    unittest.main()
