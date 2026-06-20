"""Unit tests for the EVM-aware static lens (p1hunt/classify/evm_signals.py).

Pure-logic only: builds tiny .sol / .js fixtures on a tmp dir and checks density, the
high-value detectors, and the keyword-demotion heuristic. No external tools, no network.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from p1hunt.classify.evm_signals import (
    EVM_SIGNALS,
    evm_assembly_density,
    scan_evm,
    should_demote_keyword_signals,
)
from p1hunt.classify.signals import Signal, SignalHit


_ASSEMBLY_HEAVY = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Hardened {
    function lo(address t) external {
        assembly {
            let p := mload(0x40)
        }
        assembly ("memory-safe") {
            let q := mload(0x40)
        }
    }
    function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        address signer = ecrecover(h, v, r, s);
        return signer;
    }
    function pay(address payable to) external {
        to.call{value: 1 ether}("");
    }
    function fill(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
        return a / b * c;
    }
}
"""

_PLAIN_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Plain {
    uint256 public x;
    function set(uint256 v) external {
        x = v;
    }
}
"""

_PLAIN_JS = """function add(a, b) {
  return a + b;
}
module.exports = { add };
"""


def _write(root: Path, name: str, content: str) -> None:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class TestAssemblyDensity(unittest.TestCase):
    def test_no_sol_is_zero(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "index.js", _PLAIN_JS)
            self.assertEqual(evm_assembly_density(d), 0.0)

    def test_heavy_higher_than_plain(self) -> None:
        with tempfile.TemporaryDirectory() as heavy, tempfile.TemporaryDirectory() as plain:
            _write(Path(heavy), "src/Hardened.sol", _ASSEMBLY_HEAVY)
            _write(Path(plain), "src/Plain.sol", _PLAIN_SOL)
            dh = evm_assembly_density(heavy)
            dp = evm_assembly_density(plain)
            self.assertGreater(dh, dp)
            self.assertEqual(dp, 0.0)
            self.assertGreaterEqual(dh, 2.0)  # two assembly blocks in one file

    def test_missing_repo_is_zero(self) -> None:
        self.assertEqual(evm_assembly_density("/no/such/path/xyz"), 0.0)


class TestScanEvm(unittest.TestCase):
    def test_flags_unchecked_call_and_bare_ecrecover(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "src/Hardened.sol", _ASSEMBLY_HEAVY)
            hits = scan_evm(d)
            ids = {h.signal.id for h in hits}
            self.assertIn("evm-unchecked-call", ids)
            self.assertIn("evm-bare-ecrecover", ids)
            self.assertIn("evm-div-before-mul", ids)
            # all hits carry a SignalHit shape
            for h in hits:
                self.assertIsInstance(h, SignalHit)
                self.assertIsInstance(h.signal, Signal)
                self.assertTrue(h.file.endswith(".sol"))
                self.assertGreaterEqual(h.line, 1)

    def test_plain_sol_no_high_value_hits(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "src/Plain.sol", _PLAIN_SOL)
            hits = scan_evm(d)
            self.assertEqual(hits, [])

    def test_only_scans_sol(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            # a .js file containing ecrecover-ish text must NOT be scanned
            _write(Path(d), "lib.js", "const x = ecrecover(h, v, r, s);")
            self.assertEqual(scan_evm(d), [])

    def test_ignores_vendor_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "node_modules/dep/Bad.sol", _ASSEMBLY_HEAVY)
            self.assertEqual(scan_evm(d), [])

    def test_missing_repo_no_raise(self) -> None:
        self.assertEqual(scan_evm("/no/such/path/xyz"), [])


class TestDemoteHeuristic(unittest.TestCase):
    def test_true_for_assembly_heavy_evm(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "src/Hardened.sol", _ASSEMBLY_HEAVY)
            self.assertTrue(should_demote_keyword_signals(d))

    def test_false_for_plain_js(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "index.js", _PLAIN_JS)
            self.assertFalse(should_demote_keyword_signals(d))

    def test_false_for_plain_sol(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "src/Plain.sol", _PLAIN_SOL)
            self.assertFalse(should_demote_keyword_signals(d))


class TestSignalShape(unittest.TestCase):
    def test_signals_are_well_formed(self) -> None:
        self.assertTrue(EVM_SIGNALS)
        ids = [s.id for s in EVM_SIGNALS]
        self.assertEqual(len(ids), len(set(ids)))  # unique ids
        for s in EVM_SIGNALS:
            self.assertIsInstance(s, Signal)
            self.assertTrue(s.id and s.title and s.lens and s.rationale)


if __name__ == "__main__":
    unittest.main()
