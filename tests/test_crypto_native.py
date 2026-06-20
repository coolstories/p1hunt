"""Native C/C++ reproduction for CRYPTO_LIB — lets a C++ crypto/MPC PoC actually reproduce
(compile + run), instead of staying a candidate forever. Skips when no compiler is present."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from p1hunt.runners.base import ReproSpec
from p1hunt.runners.crypto import CryptoRunner

_HAVE_CXX = any(shutil.which(c) for c in ("c++", "g++", "clang++"))


def _mk_harness(src: str, name: str = "poc.cpp") -> str:
    d = tempfile.mkdtemp()
    (Path(d) / ".p1hunt-poc").mkdir()
    (Path(d) / ".p1hunt-poc" / name).write_text(src, encoding="utf-8")
    return d


@unittest.skipUnless(_HAVE_CXX, "no C++ compiler available")
class TestCryptoNative(unittest.TestCase):
    def test_expect_fail_assertion_breaks_reproduces(self):
        # expect='fail': a non-zero exit (assert/abort) DEMONSTRATES the bug.
        d = _mk_harness("#include <cassert>\nint main(){ assert(1==2); return 0; }\n")
        r = CryptoRunner().run(d, ReproSpec.from_dict(
            {"harness_path": ".p1hunt-poc/poc.cpp", "kind": "differential", "expect": "fail"}))
        self.assertTrue(r.ran)
        self.assertTrue(r.reproduced)

    def test_expect_fail_clean_run_not_reproduced(self):
        d = _mk_harness("int main(){ return 0; }\n")
        r = CryptoRunner().run(d, ReproSpec.from_dict(
            {"harness_path": ".p1hunt-poc/poc.cpp", "kind": "differential", "expect": "fail"}))
        self.assertTrue(r.ran)
        self.assertFalse(r.reproduced)

    def test_expect_pass_exploit_holds_reproduces(self):
        # expect='pass': exit 0 means the exploit assertion held.
        d = _mk_harness("int main(){ return 0; }\n")
        r = CryptoRunner().run(d, ReproSpec.from_dict(
            {"harness_path": ".p1hunt-poc/poc.cpp", "kind": "exploit", "expect": "pass"}))
        self.assertTrue(r.reproduced)

    def test_uncompilable_stays_candidate(self):
        d = _mk_harness("this is not valid c++ ;;;\n")
        r = CryptoRunner().run(d, ReproSpec.from_dict(
            {"harness_path": ".p1hunt-poc/poc.cpp", "expect": "fail"}))
        self.assertFalse(r.reproduced)
        self.assertFalse(r.ran)  # never compiled -> stays a candidate, not a false reproduction


if __name__ == "__main__":
    unittest.main()
