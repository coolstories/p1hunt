"""Unit tests for p1hunt/runners/crypto.py.

Pure parsers are exercised with realistic SAMPLE go/cargo/pytest output; the executor is
exercised only in the tool-absent / harness-missing branches (assert ran=False). NO network,
NO external toolchain, NO Claude.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from p1hunt.runners import crypto
from p1hunt.runners.base import ReproResult, ReproSpec
from p1hunt.runners.crypto import (
    CryptoRunner,
    parse_cargo,
    parse_go,
    parse_pytest,
)


def _spec(**kw) -> ReproSpec:
    return ReproSpec.from_dict(kw)


# ---------------------------------------------------------------------------
# go parser
# ---------------------------------------------------------------------------
class ParseGoTests(unittest.TestCase):
    GO_FAIL = (
        "=== RUN   TestSignatureMalleability\n"
        "    sig_test.go:42: forged signature accepted (counterexample s=0x01)\n"
        "--- FAIL: TestSignatureMalleability (0.01s)\n"
        "FAIL\n"
        "FAIL\texample.com/crypto\t0.123s\n"
    )
    GO_PASS_COVER = (
        "=== RUN   TestConstantTime\n"
        "--- PASS: TestConstantTime (0.00s)\n"
        "PASS\n"
        "ok  \texample.com/crypto\t0.222s\tcoverage: 87.5% of statements\n"
    )
    GO_FUZZ = (
        "fuzz: elapsed: 3s, execs: 1200 (400/sec)\n"
        "--- FAIL: FuzzVerify (0.50s)\n"
        "    Failing input written to testdata/fuzz/FuzzVerify/abc123\n"
        "FAIL\n"
    )

    def test_fail_property_reproduces_when_expect_fail(self):
        spec = _spec(kind="property", expect="fail", test_name="TestSignatureMalleability")
        r = parse_go(self.GO_FAIL, 1, spec)
        self.assertTrue(r["reproduced"])
        self.assertIn("FAILED", r["detail"])
        self.assertIn("TestSignatureMalleability", r["coverage"]["covered_symbols"])

    def test_pass_does_not_reproduce_when_expect_fail(self):
        spec = _spec(kind="property", expect="fail", test_name="TestConstantTime")
        r = parse_go(self.GO_PASS_COVER, 0, spec)
        self.assertFalse(r["reproduced"])
        self.assertEqual(r["coverage"]["statement_pct"], 87.5)
        self.assertIn("TestConstantTime", r["coverage"]["covered_symbols"])

    def test_no_target_any_failure_reproduces(self):
        spec = _spec(kind="differential", expect="fail")
        r = parse_go(self.GO_FAIL, 1, spec)
        self.assertTrue(r["reproduced"])

    def test_no_target_clean_does_not_reproduce(self):
        spec = _spec(kind="differential", expect="fail")
        r = parse_go(self.GO_PASS_COVER, 0, spec)
        self.assertFalse(r["reproduced"])

    def test_exploit_pass_reproduces_when_expect_pass(self):
        spec = _spec(kind="exploit", expect="pass", test_name="TestConstantTime")
        r = parse_go(self.GO_PASS_COVER, 0, spec)
        self.assertTrue(r["reproduced"])
        self.assertIn("PASSED", r["detail"])

    def test_exploit_fail_does_not_reproduce_when_expect_pass(self):
        spec = _spec(kind="exploit", expect="pass", test_name="TestSignatureMalleability")
        r = parse_go(self.GO_FAIL, 1, spec)
        self.assertFalse(r["reproduced"])

    def test_fuzz_crash_reproduces(self):
        spec = _spec(kind="fuzz", expect="fail", test_name="FuzzVerify")
        r = parse_go(self.GO_FUZZ, 1, spec)
        self.assertTrue(r["reproduced"])
        self.assertEqual(r["coverage"]["crasher"], "testdata/fuzz/FuzzVerify/abc123")
        self.assertIn("FuzzVerify", r["coverage"]["covered_symbols"])


# ---------------------------------------------------------------------------
# cargo parser
# ---------------------------------------------------------------------------
class ParseCargoTests(unittest.TestCase):
    CARGO_FAIL = (
        "running 3 tests\n"
        "test keys::derive_is_deterministic ... ok\n"
        "test sig::reject_malleable ... FAILED\n"
        "test mac::constant_time ... ok\n"
        "\nfailures:\n"
        "    sig::reject_malleable\n"
        "test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"
    )
    CARGO_PASS = (
        "running 2 tests\n"
        "test exploit::recover_private_key ... ok\n"
        "test exploit::forge_token ... ok\n"
        "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
    )
    CARGO_FUZZ = (
        "INFO: Running with entropic power schedule\n"
        "==12345== ERROR: libFuzzer: deadly signal\n"
        "Failing input: fuzz/artifacts/parse/crash-deadbeef\n"
        "artifact_prefix='fuzz/artifacts/parse/'; Test unit written to crash-deadbeef\n"
    )

    def test_fail_property_reproduces(self):
        spec = _spec(kind="property", expect="fail", test_name="sig::reject_malleable")
        r = parse_cargo(self.CARGO_FAIL, 101, spec)
        self.assertTrue(r["reproduced"])
        self.assertEqual(r["coverage"]["failed"], 1)
        self.assertEqual(r["coverage"]["passed"], 2)
        self.assertIn("sig::reject_malleable", r["coverage"]["covered_symbols"])

    def test_pass_does_not_reproduce_when_expect_fail(self):
        spec = _spec(kind="property", expect="fail")
        r = parse_cargo(self.CARGO_PASS, 0, spec)
        self.assertFalse(r["reproduced"])

    def test_no_target_failure_reproduces(self):
        spec = _spec(kind="differential", expect="fail")
        r = parse_cargo(self.CARGO_FAIL, 101, spec)
        self.assertTrue(r["reproduced"])

    def test_exploit_pass_reproduces(self):
        spec = _spec(kind="exploit", expect="pass", test_name="exploit::recover_private_key")
        r = parse_cargo(self.CARGO_PASS, 0, spec)
        self.assertTrue(r["reproduced"])

    def test_exploit_fail_does_not_reproduce(self):
        spec = _spec(kind="exploit", expect="pass", test_name="sig::reject_malleable")
        r = parse_cargo(self.CARGO_FAIL, 101, spec)
        self.assertFalse(r["reproduced"])

    def test_cargo_fuzz_crash_reproduces(self):
        spec = _spec(kind="fuzz", expect="fail", test_name="parse")
        r = parse_cargo(self.CARGO_FUZZ, 1, spec)
        self.assertTrue(r["reproduced"])
        self.assertIn("crash", r["coverage"].get("crasher", ""))


# ---------------------------------------------------------------------------
# pytest parser
# ---------------------------------------------------------------------------
class ParsePytestTests(unittest.TestCase):
    PYTEST_FAIL = (
        "test_crypto.py::test_nonce_reuse FAILED\n"
        "================== FAILURES ==================\n"
        "FAILED test_crypto.py::test_nonce_reuse - AssertionError: nonce reused\n"
        "1 failed, 2 passed in 0.12s\n"
    )
    PYTEST_PASS = (
        "test_exploit.py::test_recover_key PASSED\n"
        "2 passed in 0.05s\n"
    )
    PYTEST_NONE = "no tests ran in 0.01s\n"

    def test_fail_property_reproduces(self):
        spec = _spec(kind="property", expect="fail", test_name="test_nonce_reuse")
        r = parse_pytest(self.PYTEST_FAIL, 1, spec)
        self.assertTrue(r["reproduced"])
        self.assertEqual(r["coverage"]["failed"], 1)

    def test_no_target_failure_reproduces(self):
        spec = _spec(kind="property", expect="fail")
        r = parse_pytest(self.PYTEST_FAIL, 1, spec)
        self.assertTrue(r["reproduced"])

    def test_pass_does_not_reproduce_when_expect_fail(self):
        spec = _spec(kind="property", expect="fail")
        r = parse_pytest(self.PYTEST_PASS, 0, spec)
        self.assertFalse(r["reproduced"])

    def test_exploit_pass_reproduces(self):
        spec = _spec(kind="exploit", expect="pass", test_name="test_recover_key")
        r = parse_pytest(self.PYTEST_PASS, 0, spec)
        self.assertTrue(r["reproduced"])

    def test_no_tests_is_inconclusive(self):
        spec = _spec(kind="property", expect="fail")
        r = parse_pytest(self.PYTEST_NONE, 5, spec)
        self.assertFalse(r["reproduced"])
        self.assertIn("no tests", r["detail"])


# ---------------------------------------------------------------------------
# Runner: graceful / tool-absent paths only.
# ---------------------------------------------------------------------------
class RunnerSupportsTests(unittest.TestCase):
    def test_supports_crypto_and_native(self):
        rn = CryptoRunner()
        self.assertTrue(rn.supports("CRYPTO_LIB"))
        self.assertTrue(rn.supports("native"))
        self.assertTrue(rn.supports("NATIVE_CODE"))
        self.assertFalse(rn.supports("WEB_API"))
        self.assertEqual(rn.name, "crypto")


class RunnerGracefulTests(unittest.TestCase):
    def test_missing_harness_returns_not_ran(self):
        rn = CryptoRunner()
        with tempfile.TemporaryDirectory() as d:
            res = rn.run(d, _spec(harness_path="does_not_exist.py"))
        self.assertIsInstance(res, ReproResult)
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)
        self.assertEqual(res.runner, "crypto")

    def test_harness_outside_workspace_returns_not_ran(self):
        rn = CryptoRunner()
        with tempfile.TemporaryDirectory() as d:
            res = rn.run(d, _spec(harness_path="../../etc/passwd"))
        self.assertFalse(res.ran)

    def test_no_recognized_toolchain_returns_not_ran(self):
        rn = CryptoRunner()
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "harness.txt"), "w") as f:
                f.write("not a known harness")
            res = rn.run(d, _spec(harness_path="harness.txt"))
        self.assertFalse(res.ran)
        self.assertIn("toolchain", res.detail)

    def test_tool_absent_pytest_returns_not_ran(self):
        rn = CryptoRunner()
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "harness.py"), "w") as f:
                f.write("def test_x():\n    assert True\n")
            with mock.patch.object(crypto, "tool_available", return_value=False):
                res = rn.run(d, _spec(harness_path="harness.py", kind="property"))
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)

    def test_tool_absent_go_returns_not_ran(self):
        rn = CryptoRunner()
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "go.mod"), "w") as f:
                f.write("module example.com/crypto\n\ngo 1.21\n")
            with open(os.path.join(d, "harness.py"), "w") as f:
                f.write("x")
            with mock.patch.object(crypto, "tool_available", return_value=False):
                res = rn.run(d, _spec(harness_path="harness.py", test_name="TestX"))
        self.assertFalse(res.ran)

    def test_tool_absent_cargo_returns_not_ran(self):
        rn = CryptoRunner()
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "Cargo.toml"), "w") as f:
                f.write("[package]\nname='crypto'\n")
            with open(os.path.join(d, "harness.py"), "w") as f:
                f.write("x")
            with mock.patch.object(crypto, "tool_available", return_value=False):
                res = rn.run(d, _spec(harness_path="harness.py"))
        self.assertFalse(res.ran)


class ArgvDerivationTests(unittest.TestCase):
    def test_go_argv_run(self):
        argv = crypto._go_argv(_spec(test_name="TestX"))
        self.assertEqual(argv[:3], ["go", "test", "-run"])
        self.assertIn("TestX", argv)
        self.assertIn("-cover", argv)

    def test_go_argv_default_run_pattern(self):
        argv = crypto._go_argv(_spec())
        self.assertIn(".", argv)

    def test_go_argv_fuzz(self):
        argv = crypto._go_argv(_spec(kind="fuzz", test_name="FuzzX"))
        self.assertIn("-fuzz", argv)
        self.assertIn("FuzzX", argv)

    def test_cargo_toolchain_test(self):
        tool, argv, parser = crypto._cargo_toolchain(_spec(test_name="mymod::t"))
        self.assertEqual(tool, "cargo")
        self.assertEqual(argv[:2], ["cargo", "test"])
        self.assertIn("mymod::t", argv)

    def test_never_execs_spec_command(self):
        # spec.command must never appear in derived argv (injection sink).
        spec = _spec(test_name="TestX", command="rm -rf /")
        self.assertNotIn("rm", crypto._go_argv(spec))


if __name__ == "__main__":
    unittest.main()
