"""Tests for the C/C++ native reproduction verdict (runners/crypto.native_verdict).

The native path is what lets a C/C++ crypto/MPC finding REPRODUCE. Its verdict must preserve the
artifact floor (spec §10): a bare non-zero exit (a broken harness, a missing input file) is NOT a
reproduction — only a recognized fault/assertion/sanitizer report is. These tests pin that, so a
spurious crash can never be promoted to a confirmed P1. Pure-logic; no compiler needed.
"""

from __future__ import annotations

import unittest

from p1hunt.runners.base import ReproSpec
from p1hunt.runners.crypto import native_verdict

_FAIL = ReproSpec(kind="property", expect="fail")
_PASS = ReproSpec(kind="exploit", expect="pass")


class ExpectFail(unittest.TestCase):
    def test_asan_report_is_reproduced(self) -> None:
        out = "==12==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..."
        self.assertTrue(native_verdict(out, 1, _FAIL)["reproduced"])

    def test_ubsan_runtime_error_is_reproduced(self) -> None:
        self.assertTrue(native_verdict("x.c:9:5: runtime error: signed integer overflow", 1, _FAIL)["reproduced"])

    def test_assertion_failure_is_reproduced(self) -> None:
        out = "poc.cc:14: void check(): Assertion `recovered == secret' failed.\nAborted (core dumped)"
        self.assertTrue(native_verdict(out, 134, _FAIL)["reproduced"])

    def test_libfuzzer_crash_is_reproduced(self) -> None:
        self.assertTrue(native_verdict("==1==ERROR: libFuzzer: deadly signal", 77, _FAIL)["reproduced"])

    def test_bare_nonzero_without_marker_is_NOT_reproduced(self) -> None:
        # The key anti-false-positive guarantee: a harness that just exits non-zero (e.g. couldn't
        # open a file, or is simply broken) must NOT be promoted to a confirmed critical.
        v = native_verdict("could not open testvector.bin", 1, _FAIL)
        self.assertFalse(v["reproduced"])
        self.assertIn("no recognized", v["detail"].lower())

    def test_clean_exit_is_not_reproduced(self) -> None:
        self.assertFalse(native_verdict("all properties held", 0, _FAIL)["reproduced"])


class ExpectPass(unittest.TestCase):
    def test_clean_exit_is_reproduced(self) -> None:
        self.assertTrue(native_verdict("forged signature accepted by verify()", 0, _PASS)["reproduced"])

    def test_fault_marker_blocks_pass(self) -> None:
        # An exploit harness that itself crashed did not cleanly demonstrate the win.
        self.assertFalse(native_verdict("AddressSanitizer: SEGV on unknown address", 1, _PASS)["reproduced"])

    def test_nonzero_exit_is_not_pass(self) -> None:
        self.assertFalse(native_verdict("assertion that exploit worked failed", 1, _PASS)["reproduced"])


if __name__ == "__main__":
    unittest.main()
