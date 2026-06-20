"""Unit tests for p1hunt/runners/web.py — PURE parsers + the tool-absent executor branch only.

Hermetic: no network, no Claude, no pytest/npx/node subprocess. The parsers are fed realistic
SAMPLE tool output strings; the executor (``WebRunner.run``) is exercised only in the tool-absent
path (assert ran=False) by pointing at a class with no toolchain installed and asserting we never
launch a process.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from p1hunt.runners import web
from p1hunt.runners.base import ReproSpec
from p1hunt.runners.web import (
    WebRunner,
    parse_playwright,
    parse_pytest,
)


def _spec(expect: str = "fail", **kw) -> ReproSpec:
    return ReproSpec(expect=expect, **kw)


# --------------------------------------------------------------------------- pytest samples
_PYTEST_FAIL = """\
============================= test session starts ==============================
collected 3 items

tests/test_authz.py::test_admin_route_blocked FAILED                      [ 33%]
tests/test_authz.py::test_idor_blocked PASSED                            [ 66%]
tests/test_authz.py::test_login PASSED                                   [100%]

=================================== FAILURES ===================================
FAILED tests/test_authz.py::test_admin_route_blocked - AssertionError: 200 == 403
========================= 1 failed, 2 passed in 0.12s ==========================
"""

_PYTEST_PASS = """\
============================= test session starts ==============================
collected 1 item

tests/test_exploit.py::test_idor_succeeds PASSED                         [100%]

============================== 1 passed in 0.05s ===============================
"""

_PYTEST_ERROR = """\
============================= test session starts ==============================
collected 1 item

tests/test_authz.py::test_x ERROR                                        [100%]
==================================== ERRORS ====================================
ERROR tests/test_authz.py::test_x - ConnectionError: refused
=========================== 1 error in 0.03s ===================================
"""

_PYTEST_NONE = """\
============================= test session starts ==============================
collected 0 items

============================ no tests ran in 0.01s =============================
"""

_PYTEST_COV = """\
============================= test session starts ==============================
collected 2 items

tests/test_authz.py::test_idor_succeeds PASSED                           [ 50%]
tests/test_authz.py::test_admin_open PASSED                              [100%]

---------- coverage: platform linux, python 3.11 -----------
Name                Stmts   Miss  Cover   Missing
-------------------------------------------------
app/routes.py          40      4    90%   12-15
app/auth.py            20      0   100%
-------------------------------------------------
TOTAL                  60      4    93%

============================== 2 passed in 0.20s ===============================
"""


class ParsePytestTests(unittest.TestCase):
    def test_fail_demonstrates_invariant_bug(self):
        r = parse_pytest(_PYTEST_FAIL, 1, _spec(expect="fail"))
        self.assertTrue(r["reproduced"])
        self.assertIn("tests/test_authz.py::test_admin_route_blocked", r["coverage"]["covered_symbols"])
        self.assertIn("demonstrated", r["detail"])

    def test_error_counts_as_failure_for_expect_fail(self):
        r = parse_pytest(_PYTEST_ERROR, 1, _spec(expect="fail"))
        self.assertTrue(r["reproduced"])

    def test_all_pass_does_not_demonstrate_for_expect_fail(self):
        r = parse_pytest(_PYTEST_PASS, 0, _spec(expect="fail"))
        self.assertFalse(r["reproduced"])

    def test_pass_demonstrates_exploit_for_expect_pass(self):
        r = parse_pytest(_PYTEST_PASS, 0, _spec(expect="pass"))
        self.assertTrue(r["reproduced"])
        self.assertIn("tests/test_exploit.py::test_idor_succeeds", r["coverage"]["covered_symbols"])
        self.assertIn("unauthorized action succeeded", r["detail"])

    def test_failure_does_not_demonstrate_for_expect_pass(self):
        r = parse_pytest(_PYTEST_FAIL, 1, _spec(expect="pass"))
        self.assertFalse(r["reproduced"])

    def test_no_tests_ran_stays_candidate(self):
        for ex in ("fail", "pass"):
            r = parse_pytest(_PYTEST_NONE, 5, _spec(expect=ex))
            self.assertFalse(r["reproduced"], ex)
            self.assertIn("no tests", r["detail"])

    def test_cov_total_and_per_file_parsed(self):
        r = parse_pytest(_PYTEST_COV, 0, _spec(expect="pass"))
        self.assertTrue(r["reproduced"])
        cov = r["coverage"]
        self.assertEqual(cov["total_percent"], 93)
        self.assertEqual(cov["statements"], 60)
        self.assertEqual(cov["missed"], 4)
        self.assertEqual(cov["files"]["app/routes.py"]["percent"], 90)
        self.assertEqual(cov["files"]["app/auth.py"]["percent"], 100)
        self.assertIn("tests/test_authz.py::test_idor_succeeds", cov["covered_symbols"])
        self.assertNotIn("TOTAL", cov.get("files", {}))


# --------------------------------------------------------------------------- playwright samples
_PW_FAIL = """\
Running 2 tests using 1 worker

  ✓  1 authz.spec.ts:5:3 › login works (1.2s)
  ✘  2 authz.spec.ts:12:3 › admin route is blocked (0.8s)

  1) authz.spec.ts:12:3 › admin route is blocked ==================================

    Error: expect(received).toBe(403)
    Received: 200

  1 failed
    authz.spec.ts:12:3 › admin route is blocked
  1 passed (2.1s)
"""

_PW_PASS = """\
Running 1 test using 1 worker

  ✓  1 exploit.spec.ts:8:3 › idor returns another tenant record (0.9s)

  1 passed (1.0s)
"""


class ParsePlaywrightTests(unittest.TestCase):
    def test_failed_spec_demonstrates_for_expect_fail(self):
        r = parse_playwright(_PW_FAIL, 1, _spec(expect="fail"))
        self.assertTrue(r["reproduced"])
        self.assertIn("demonstrated", r["detail"])

    def test_all_pass_no_demonstrate_for_expect_fail(self):
        r = parse_playwright(_PW_PASS, 0, _spec(expect="fail"))
        self.assertFalse(r["reproduced"])

    def test_pass_demonstrates_exploit_for_expect_pass(self):
        r = parse_playwright(_PW_PASS, 0, _spec(expect="pass"))
        self.assertTrue(r["reproduced"])
        self.assertIn("succeeded", r["detail"])
        self.assertTrue(r["coverage"]["covered_symbols"])

    def test_failed_exploit_not_demonstrated_for_expect_pass(self):
        r = parse_playwright(_PW_FAIL, 1, _spec(expect="pass"))
        self.assertFalse(r["reproduced"])

    def test_bare_node_no_summary_uses_exit_code_pass(self):
        r = parse_playwright("PoC ran, all good\n", 0, _spec(expect="pass"))
        self.assertTrue(r["reproduced"])
        self.assertIn("exited 0", r["detail"])

    def test_bare_node_no_summary_uses_exit_code_fail(self):
        r = parse_playwright("AssertionError thrown\n", 1, _spec(expect="fail"))
        self.assertTrue(r["reproduced"])
        self.assertIn("non-zero", r["detail"])

    def test_bare_node_exit_zero_not_demonstrated_for_expect_fail(self):
        r = parse_playwright("ok\n", 0, _spec(expect="fail"))
        self.assertFalse(r["reproduced"])


class SupportsTests(unittest.TestCase):
    def test_web_api_supported(self):
        self.assertTrue(WebRunner().supports("WEB_API"))

    def test_other_unknown_is_fallback(self):
        self.assertTrue(WebRunner().supports("OTHER"))
        self.assertTrue(WebRunner().supports(""))

    def test_dedicated_classes_not_taken_over(self):
        for cls in ("EVM_CONTRACT", "CRYPTO_LIB", "INFRA", "SUPPLY_CHAIN", "MOBILE_APP"):
            self.assertFalse(WebRunner().supports(cls), cls)


class RunGracefulTests(unittest.TestCase):
    def test_missing_harness_stays_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            res = WebRunner().run(d, _spec(harness_path="does_not_exist.py"))
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)
        self.assertEqual(res.runner, "web")

    def test_out_of_sandbox_harness_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            res = WebRunner().run(d, _spec(harness_path="../../etc/passwd"))
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)

    def test_tool_absent_pytest_branch_never_launches(self):
        with tempfile.TemporaryDirectory() as d:
            hp = os.path.join(d, "test_poc.py")
            with open(hp, "w") as fh:
                fh.write("def test_x():\n    assert True\n")
            with mock.patch.object(web, "run_command", wraps=web.run_command) as rc, \
                 mock.patch("p1hunt.runners.base.tool_available", return_value=False):
                res = WebRunner().run(d, _spec(harness_path="test_poc.py", expect="pass"))
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)
        self.assertIn("pytest", res.command)
        rc.assert_called_once()

    def test_tool_absent_playwright_branch(self):
        with tempfile.TemporaryDirectory() as d:
            hp = os.path.join(d, "authz.spec.ts")
            with open(hp, "w") as fh:
                fh.write("// e2e\n")
            with mock.patch("p1hunt.runners.base.tool_available", return_value=False):
                res = WebRunner().run(d, _spec(harness_path="authz.spec.ts", expect="pass"))
        self.assertFalse(res.ran)
        self.assertIn("npx playwright test", res.command)

    def test_tool_absent_node_branch(self):
        with tempfile.TemporaryDirectory() as d:
            hp = os.path.join(d, "poc.js")
            with open(hp, "w") as fh:
                fh.write("// node poc\n")
            with mock.patch("p1hunt.runners.base.tool_available", return_value=False):
                res = WebRunner().run(d, _spec(harness_path="poc.js", expect="pass"))
        self.assertFalse(res.ran)
        self.assertTrue(res.command.startswith("node "))

    def test_test_name_threads_into_pytest_argv(self):
        with tempfile.TemporaryDirectory() as d:
            hp = os.path.join(d, "test_poc.py")
            with open(hp, "w") as fh:
                fh.write("def test_x():\n    pass\n")
            with mock.patch("p1hunt.runners.base.tool_available", return_value=False):
                res = WebRunner().run(
                    d, _spec(harness_path="test_poc.py", test_name="test_x", expect="pass")
                )
        self.assertIn("-k test_x", res.command)


if __name__ == "__main__":
    unittest.main()
