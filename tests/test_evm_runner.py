"""Unit tests for the Foundry EVM reproduction runner (p1hunt/runners/evm.py).

Hermetic: the PURE parser is tested against realistic SAMPLE `forge` output strings; the executor
is exercised ONLY in the tool-absent / missing-harness branch (asserts ran=False). No network,
no Claude, no `forge` toolchain required.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from p1hunt.runners.base import ReproSpec
from p1hunt.runners.evm import (
    EvmRunner,
    parse_forge,
    parse_forge_coverage,
)


# --- realistic sample forge logs -------------------------------------------------------------
_FAILING_INVARIANT = """\
Running 2 tests for test/Invariant.t.sol:VaultInvariant
[PASS] invariant_solvency() (runs: 256, calls: 3840, reverts: 12)
[FAIL. Reason: assertion failed] invariant_totalSupply() (runs: 41, calls: 600, reverts: 3)
        [Sequence]
                sender=0x0000 addr=Handler calldata=deposit(uint256) args=[115792089237316195423570985008687907853269984665640564039457584007913129639935]
        counterexample: args=[deposit(115792089237316195423570985008687907853269984665640564039457584007913129639935)]
        Invariant result: FAILED
Test result: FAILED. 1 passed; 1 failed; 0 skipped; finished in 1.23s
"""

_ALL_PASS = """\
Running 3 tests for test/Invariant.t.sol:VaultInvariant
[PASS] invariant_solvency() (runs: 256, calls: 3840, reverts: 12)
[PASS] invariant_totalSupply() (runs: 256, calls: 3840, reverts: 9)
[PASS] invariant_noNegativeBalance() (runs: 256, calls: 3840, reverts: 0)
Test result: ok. 3 passed; 0 failed; 0 skipped; finished in 4.10s
"""

_EXPLOIT_PASS = """\
Running 1 test for test/Exploit.t.sol:ExploitTest
[PASS] testExploitDrainsFunds() (gas: 184213)
Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 0.42s
"""

_EXPLOIT_FAIL = """\
Running 1 test for test/Exploit.t.sol:ExploitTest
[FAIL. Reason: revert: not exploitable] testExploitDrainsFunds() (gas: 99)
Test result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 0.40s
"""

_COVERAGE_TABLE = """\
Analysing contracts...
Running tests...

| File                | % Lines        | % Statements   | % Branches    | % Funcs       |
|---------------------|----------------|----------------|---------------|---------------|
| src/Vault.sol       | 92.31% (24/26) | 88.00% (22/25) | 75.00% (3/4)  | 100.00% (4/4) |
| src/Token.sol       | 50.00% (5/10)  | 50.00% (5/10)  | 0.00% (0/2)   | 66.67% (2/3)  |
| Total               | 80.56% (29/36) | 77.14% (27/35) | 50.00% (3/6)  | 85.71% (6/7)  |
"""


class TestParseForgeFail(unittest.TestCase):
    def test_failing_invariant_reproduces(self):
        spec = ReproSpec(kind="invariant", expect="fail")
        r = parse_forge(_FAILING_INVARIANT, 1, spec)
        self.assertTrue(r["reproduced"])
        self.assertIn("invariant_totalSupply", r["detail"])
        self.assertIn("counterexample", r["detail"].lower())
        cov = r["coverage"]["covered_symbols"]
        self.assertIn("invariant_totalSupply", cov)
        self.assertIn("invariant_solvency", cov)
        self.assertEqual(r["coverage"]["tests_failed"], 1)

    def test_all_pass_does_not_reproduce_for_expect_fail(self):
        spec = ReproSpec(kind="invariant", expect="fail")
        r = parse_forge(_ALL_PASS, 0, spec)
        self.assertFalse(r["reproduced"])
        self.assertIn("held", r["detail"].lower())
        self.assertEqual(len(r["coverage"]["covered_symbols"]), 3)

    def test_targeted_test_name_must_match(self):
        spec = ReproSpec(kind="invariant", expect="fail", test_name="invariant_doesNotExist")
        r = parse_forge(_FAILING_INVARIANT, 1, spec)
        self.assertFalse(r["reproduced"])
        self.assertIn("none matched", r["detail"])

    def test_targeted_test_name_matches(self):
        spec = ReproSpec(kind="invariant", expect="fail", test_name="invariant_totalSupply")
        r = parse_forge(_FAILING_INVARIANT, 1, spec)
        self.assertTrue(r["reproduced"])


class TestParseForgePass(unittest.TestCase):
    def test_exploit_pass_reproduces(self):
        spec = ReproSpec(kind="exploit", expect="pass")
        r = parse_forge(_EXPLOIT_PASS, 0, spec)
        self.assertTrue(r["reproduced"])
        self.assertIn("testExploitDrainsFunds", r["detail"])
        self.assertIn("testExploitDrainsFunds", r["coverage"]["covered_symbols"])

    def test_exploit_fail_does_not_reproduce(self):
        spec = ReproSpec(kind="exploit", expect="pass")
        r = parse_forge(_EXPLOIT_FAIL, 1, spec)
        self.assertFalse(r["reproduced"])
        self.assertIn("failures", r["detail"])

    def test_exploit_pass_targeted_name(self):
        spec = ReproSpec(kind="exploit", expect="pass", test_name="testExploitDrainsFunds")
        r = parse_forge(_EXPLOIT_PASS, 0, spec)
        self.assertTrue(r["reproduced"])

    def test_exploit_pass_wrong_targeted_name(self):
        spec = ReproSpec(kind="exploit", expect="pass", test_name="testSomethingElse")
        r = parse_forge(_EXPLOIT_PASS, 0, spec)
        self.assertFalse(r["reproduced"])


class TestParseForgeCoverage(unittest.TestCase):
    def test_parses_table(self):
        cov = parse_forge_coverage(_COVERAGE_TABLE)
        files = {row["file"] for row in cov["files"]}
        self.assertIn("src/Vault.sol", files)
        self.assertIn("src/Token.sol", files)
        self.assertNotIn("Total", files)
        self.assertNotIn("File", files)
        self.assertIn("line_coverage_pct", cov)

    def test_empty_when_no_table(self):
        self.assertEqual(parse_forge_coverage("no table here"), {})
        self.assertEqual(parse_forge_coverage(""), {})


class TestEvmRunnerToolAbsent(unittest.TestCase):
    def test_supports(self):
        r = EvmRunner()
        self.assertEqual(r.name, "evm")
        self.assertTrue(r.supports("EVM_CONTRACT"))
        self.assertTrue(r.supports("evm_contract"))
        self.assertFalse(r.supports("WEB_API"))

    def test_missing_harness_path(self):
        r = EvmRunner()
        with tempfile.TemporaryDirectory() as d:
            spec = ReproSpec(harness_path="", kind="invariant", expect="fail")
            res = r.run(d, spec, timeout=5.0)
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)
        self.assertEqual(res.runner, "evm")

    def test_harness_outside_workspace_rejected(self):
        r = EvmRunner()
        with tempfile.TemporaryDirectory() as d:
            spec = ReproSpec(harness_path="../../etc/passwd", kind="invariant", expect="fail")
            res = r.run(d, spec, timeout=5.0)
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)

    def test_tool_absent_graceful(self):
        """With a real harness file present but `forge` derived onto a guaranteed-absent name,
        the runner must return ran=False without raising or hanging."""
        r = EvmRunner()
        with tempfile.TemporaryDirectory() as d:
            harness = Path(d) / "Exploit.t.sol"
            harness.write_text("// SPDX-License-Identifier: MIT\ncontract X {}\n")
            spec = ReproSpec(harness_path="Exploit.t.sol", kind="invariant", expect="fail")
            # Force the tool-absent branch deterministically by pointing PATH at an empty dir so
            # `forge` cannot be found regardless of host.
            empty = Path(d) / "emptybin"
            empty.mkdir()
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = str(empty)
            try:
                res = r.run(d, spec, timeout=5.0)
            finally:
                os.environ["PATH"] = old_path
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)
        self.assertEqual(res.runner, "evm")
        self.assertIn("forge", res.command)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
