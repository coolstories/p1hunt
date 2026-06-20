"""Unit tests for the INFRA reproduction runner (p1hunt.runners.infra).

Hermetic + offline: the PURE parser ``parse_policy`` is exercised with realistic semgrep, conftest,
and checkov sample JSON; the executor is exercised only in the tool-absent branch (ran=False). No
network, no Claude, no policy engine binaries.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from p1hunt.runners.base import ReproSpec
from p1hunt.runners.infra import (
    InfraRunner,
    build_argv,
    parse_policy,
    select_tool,
)

# --- Realistic sample outputs -------------------------------------------------
_SEMGREP_WITH_FINDINGS = json.dumps(
    {
        "results": [
            {
                "check_id": "terraform.aws.security.s3-public-acl",
                "path": "infra/s3.tf",
                "start": {"line": 12},
                "extra": {"message": "S3 bucket ACL is public-read"},
            },
            {
                "check_id": "terraform.aws.security.open-ingress-0000",
                "path": "infra/sg.tf",
                "start": {"line": 4},
            },
        ],
        "errors": [],
    }
)

_SEMGREP_NO_FINDINGS = json.dumps({"results": [], "errors": []})

# Some engines print a banner line before the JSON body.
_SEMGREP_WITH_BANNER = "Scanning 3 files.\n" + _SEMGREP_WITH_FINDINGS

_CONFTEST_WITH_FAILURES = json.dumps(
    [
        {
            "filename": "deployment.yaml",
            "namespace": "main",
            "successes": 1,
            "failures": [
                {"msg": "container must not run as root", "metadata": {"rule": "deny-root"}},
                {"msg": "resource limits are required"},
            ],
            "warnings": [],
        }
    ]
)

_CONFTEST_CLEAN = json.dumps(
    [{"filename": "deployment.yaml", "namespace": "main", "successes": 3, "failures": [], "warnings": []}]
)

_CHECKOV_WITH_FAILURES = json.dumps(
    {
        "results": {
            "failed_checks": [
                {"check_id": "CKV_AWS_18", "resource": "aws_s3_bucket.data"},
                {"check_id": "CKV_AWS_21", "resource": "aws_s3_bucket.data"},
            ],
            "passed_checks": [{"check_id": "CKV_AWS_19", "resource": "aws_s3_bucket.data"}],
        }
    }
)


class ParseSemgrepTest(unittest.TestCase):
    def test_findings_present_reproduces(self):
        spec = ReproSpec(kind="policy", expect="pass")
        out = parse_policy(_SEMGREP_WITH_FINDINGS, 1, spec, "semgrep")
        self.assertTrue(out["reproduced"])
        self.assertEqual(out["coverage"]["violation_count"], 2)
        self.assertIn("terraform.aws.security.s3-public-acl", out["coverage"]["covered_symbols"])
        self.assertIn("infra/s3.tf", out["coverage"]["covered_symbols"])
        self.assertIn("terraform.aws.security.s3-public-acl", out["coverage"]["rule_ids"])

    def test_no_findings_does_not_reproduce(self):
        spec = ReproSpec(kind="policy", expect="pass")
        out = parse_policy(_SEMGREP_NO_FINDINGS, 0, spec, "semgrep")
        self.assertFalse(out["reproduced"])
        self.assertEqual(out["coverage"]["violation_count"], 0)
        self.assertNotIn("covered_symbols", out["coverage"])

    def test_banner_before_json_is_tolerated(self):
        spec = ReproSpec(kind="policy", expect="pass")
        out = parse_policy(_SEMGREP_WITH_BANNER, 1, spec, "semgrep")
        self.assertTrue(out["reproduced"])
        self.assertEqual(out["coverage"]["violation_count"], 2)

    def test_expect_fail_inverts_semantics(self):
        # expect='fail' => the policy must hold clean; a clean pass demonstrates the bug.
        spec = ReproSpec(kind="policy", expect="fail")
        clean = parse_policy(_SEMGREP_NO_FINDINGS, 0, spec, "semgrep")
        self.assertTrue(clean["reproduced"])
        dirty = parse_policy(_SEMGREP_WITH_FINDINGS, 1, spec, "semgrep")
        self.assertFalse(dirty["reproduced"])


class ParseConftestTest(unittest.TestCase):
    def test_failures_reproduce(self):
        spec = ReproSpec(kind="policy", expect="pass")
        out = parse_policy(_CONFTEST_WITH_FAILURES, 1, spec, "conftest")
        self.assertTrue(out["reproduced"])
        self.assertGreaterEqual(out["coverage"]["violation_count"], 1)
        syms = out["coverage"]["covered_symbols"]
        self.assertTrue(any("deny-root" in s or "main" in s for s in syms))

    def test_clean_does_not_reproduce(self):
        spec = ReproSpec(kind="policy", expect="pass")
        out = parse_policy(_CONFTEST_CLEAN, 0, spec, "conftest")
        self.assertFalse(out["reproduced"])
        self.assertEqual(out["coverage"]["violation_count"], 0)


class ParseCheckovTest(unittest.TestCase):
    def test_failed_checks_reproduce(self):
        spec = ReproSpec(kind="policy", expect="pass")
        out = parse_policy(_CHECKOV_WITH_FAILURES, 1, spec, "checkov")
        self.assertTrue(out["reproduced"])
        self.assertIn("CKV_AWS_18", out["coverage"]["rule_ids"])
        self.assertIn("aws_s3_bucket.data", out["coverage"]["resources"])


class ParseDegenerateTest(unittest.TestCase):
    def test_empty_output_is_inconclusive(self):
        spec = ReproSpec(kind="policy", expect="pass")
        out = parse_policy("", 127, spec, "semgrep")
        self.assertFalse(out["reproduced"])
        self.assertIn("no parseable", out["detail"])

    def test_garbage_output_is_inconclusive(self):
        spec = ReproSpec(kind="policy", expect="pass")
        out = parse_policy("Traceback: boom", 1, spec, "checkov")
        self.assertFalse(out["reproduced"])

    def test_empty_output_expect_fail_not_reproduced(self):
        spec = ReproSpec(kind="policy", expect="fail")
        out = parse_policy("", 127, spec, "conftest")
        self.assertFalse(out["reproduced"])


class SelectToolTest(unittest.TestCase):
    def test_extra_rules_select_semgrep(self):
        with tempfile.TemporaryDirectory() as d:
            h = Path(d) / "infra"
            h.mkdir()
            spec = ReproSpec(harness_path="infra", extra={"rules": "rules/aws.yml"})
            tool, target = select_tool(h, spec)
            self.assertEqual(tool, "semgrep")
            argv = build_argv(tool, h, spec)
            self.assertEqual(argv[0], "semgrep")
            self.assertIn("--json", argv)
            self.assertIn("rules/aws.yml", argv)

    def test_rego_present_selects_conftest(self):
        with tempfile.TemporaryDirectory() as d:
            h = Path(d) / "infra"
            h.mkdir()
            (h / "policy.rego").write_text("package main\n")
            spec = ReproSpec(harness_path="infra")
            tool, _ = select_tool(h, spec)
            self.assertEqual(tool, "conftest")
            self.assertEqual(build_argv(tool, h, spec)[0], "conftest")

    def test_yaml_ruleset_selects_semgrep(self):
        with tempfile.TemporaryDirectory() as d:
            h = Path(d) / "infra"
            h.mkdir()
            (h / "ruleset.yml").write_text("rules: []\n")
            spec = ReproSpec(harness_path="infra")
            tool, _ = select_tool(h, spec)
            self.assertEqual(tool, "semgrep")
            argv = build_argv(tool, h, spec)
            self.assertIn(str(h / "ruleset.yml"), argv)

    def test_kind_forces_tool(self):
        with tempfile.TemporaryDirectory() as d:
            h = Path(d) / "infra"
            h.mkdir()
            spec = ReproSpec(harness_path="infra", kind="checkov")
            self.assertEqual(select_tool(h, spec)[0], "checkov")
            spec_opa = ReproSpec(harness_path="infra", kind="rego")
            self.assertEqual(select_tool(h, spec_opa)[0], "conftest")

    def test_bare_dir_falls_back_to_checkov(self):
        with tempfile.TemporaryDirectory() as d:
            h = Path(d) / "infra"
            h.mkdir()
            (h / "main.tf").write_text("resource {}\n")
            spec = ReproSpec(harness_path="infra")
            self.assertEqual(select_tool(h, spec)[0], "checkov")


class RunnerTest(unittest.TestCase):
    def test_supports_only_infra(self):
        r = InfraRunner()
        self.assertTrue(r.supports("INFRA"))
        self.assertTrue(r.supports("infra"))
        self.assertFalse(r.supports("WEB_API"))

    def test_missing_harness_does_not_run(self):
        r = InfraRunner()
        with tempfile.TemporaryDirectory() as d:
            spec = ReproSpec(harness_path="nope/missing", kind="policy")
            res = r.run(d, spec, timeout=5.0)
            self.assertFalse(res.ran)
            self.assertFalse(res.reproduced)
            self.assertEqual(res.runner, "infra")

    def test_tool_absent_branch_does_not_run(self):
        # Force a tool that does not exist via spec.kind so the executor hits tool-absent.
        r = InfraRunner()
        with tempfile.TemporaryDirectory() as d:
            h = Path(d) / "infra"
            h.mkdir()
            (h / "main.tf").write_text("resource {}\n")
            # checkov/conftest/semgrep are not installed in the hermetic test env.
            spec = ReproSpec(harness_path="infra", kind="checkov")
            res = r.run(d, spec, timeout=5.0)
            self.assertFalse(res.ran)
            self.assertFalse(res.reproduced)
            self.assertEqual(res.runner, "infra")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
