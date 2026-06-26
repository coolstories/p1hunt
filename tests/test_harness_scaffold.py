"""Unit tests for the harness scaffolder (Module 3).

Pure-logic coverage only — no Claude, no toolchain, no network: entrypoint extraction from a
.sol fixture, the order-marketplace heuristic (true + false), and that scaffold_block emits
EVM-specific Foundry guidance for EVM targets and a generic block otherwise.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from p1hunt.agents.harness_scaffold import (
    detect_evm_entrypoints,
    scaffold_block,
)

_MARKETPLACE_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

struct Order { address offerer; uint256 salt; }

contract Market {
    bytes32 public DOMAIN_SEPARATOR;

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\\x19\\x01", DOMAIN_SEPARATOR, structHash));
    }

    function fulfillOrder(Order calldata order, bytes calldata signature)
        external
        payable
        returns (bool)
    {
        // offer / consideration / fulfillment handling
        return true;
    }

    function incrementCounter() public returns (uint256) {
        return 1;
    }

    function _internalHelper(uint256 x) internal pure returns (uint256) {
        return x + 1;
    }

    function cancel(Order[] memory orders) external {}
}
"""

# A non-marketplace contract: has EIP-712 permit machinery but NO order/offer/fulfill vocabulary.
_TOKEN_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Token {
    bytes32 public DOMAIN_SEPARATOR;

    function permit(address owner, address spender, uint256 value) external {}

    function transfer(address to, uint256 amount) public returns (bool) {
        return true;
    }
}
"""


def _write(root: Path, name: str, body: str) -> None:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


class TestEntrypoints(unittest.TestCase):
    def test_extracts_external_public_only(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "src/Market.sol", _MARKETPLACE_SOL)
            eps = detect_evm_entrypoints(d)
            names = {sig.split("(")[0] for sig in eps}
            self.assertIn("fulfillOrder", names)
            self.assertIn("incrementCounter", names)
            self.assertIn("cancel", names)
            # internal helper must NOT surface as an entrypoint
            self.assertNotIn("_internalHelper", names)

    def test_signature_has_param_types(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "Market.sol", _MARKETPLACE_SOL)
            eps = detect_evm_entrypoints(d)
            ff = next(s for s in eps if s.startswith("fulfillOrder"))
            self.assertEqual(ff, "fulfillOrder(Order,bytes)")

    def test_limit_respected(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "Market.sol", _MARKETPLACE_SOL)
            self.assertEqual(len(detect_evm_entrypoints(d, limit=1)), 1)

    def test_missing_dir_empty(self) -> None:
        self.assertEqual(detect_evm_entrypoints("/no/such/path/xyz"), [])

    def test_focus_files_subset(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "src/Market.sol", _MARKETPLACE_SOL)
            _write(root, "src/Token.sol", _TOKEN_SOL)
            eps = detect_evm_entrypoints(d, focus_files=["src/Token.sol"])
            names = {sig.split("(")[0] for sig in eps}
            self.assertIn("permit", names)
            self.assertNotIn("fulfillOrder", names)


class TestScaffoldBlock(unittest.TestCase):
    def test_evm_emits_generic_foundry_mechanics(self) -> None:
        block = scaffold_block(
            "EVM_CONTRACT",
            "exchange-core",
            ["src/Market.sol"],
            signals=["evm-unchecked-call"],
            fork_url="http://127.0.0.1:8545",
            entrypoints=["fulfillOrder(Order,bytes)"],
        )
        # generic EVM test mechanics (sign over the contract's OWN typehash, deploy + approve)
        for needle in ("vm.sign", "_sign", "_mintAndApprove", "setUp", "approve", "DOMAIN_SEPARATOR"):
            self.assertIn(needle, block)
        # reentrancy hooks and mock tokens
        self.assertIn("onERC1155Received", block)
        self.assertIn("ERC777", block)
        # gate-bypass guidance is DERIVED, not a marketplace assumption
        self.assertIn("REACH PAST THE GATES", block)
        # fork instruction + observed signal + the real entrypoint are surfaced
        self.assertIn("--fork-url", block)
        self.assertIn("http://127.0.0.1:8545", block)
        self.assertIn("evm-unchecked-call", block)
        self.assertIn("fulfillOrder", block)
        # NOTHING PRESET: no protocol name, no marketplace/order-shape assumption
        self.assertNotIn("KnownProductA", block)
        self.assertNotIn("ORDER-BASED MARKETPLACE", block)
        for preset in ("consideration", "numerator", "_buildOrder", "_merkleRoot"):
            self.assertNotIn(preset, block, f"preset marketplace term leaked: {preset}")

    def test_evm_without_fork_says_local(self) -> None:
        block = scaffold_block("EVM_CONTRACT", "core", ["src/Market.sol"])
        self.assertNotIn("--fork-url", block)
        self.assertIn("forge test", block)

    def test_evm_scaffold_makes_no_marketplace_assumption(self) -> None:
        # Even for a target whose code uses order/offer/consideration vocabulary, the EVM scaffold
        # must NOT switch into a presumed marketplace playbook — it derives the input shape from
        # the ABI/typehash generically.
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "src/Market.sol", _MARKETPLACE_SOL)
            block = scaffold_block("EVM_CONTRACT", "core", ["src/Market.sol"], repo_path=d)
            self.assertNotIn("ORDER-BASED MARKETPLACE", block)
            self.assertNotIn("consideration", block)
            # but the generic gate-bypass (sign a valid struct via the contract's typehash) is there
            self.assertIn("vm.sign", block)
            self.assertIn("REACH PAST THE GATES", block)

    def test_non_evm_generic(self) -> None:
        block = scaffold_block("WEB_API", "auth", ["app/routes.py"])
        self.assertNotIn("vm.sign", block)
        self.assertIn("REAL harness", block)
        self.assertIn("Hypothesis", block)
        self.assertIn("WEB_API", block)

    def test_scaffold_includes_fee_on_transfer_mock(self) -> None:
        # The accounting edge harness remains available without a fork.
        block = scaffold_block("EVM_CONTRACT", "core", ["src/Market.sol"])
        self.assertIn("MockFeeOnTransferERC20", block)
        self.assertIn("fee-on-transfer", block.lower())
        self.assertIn("testFuzz_feeOnTransferConservation", block)


class TestNonEvmScaffolds(unittest.TestCase):
    """Each non-EVM class/subclass yields its specific framework + an explicit FAIL/PASS cue.

    Subclass detection (web/crypto) is driven by writing recognizable source into a temp dir that
    is passed as ``repo_path`` — exactly how the orchestrator supplies the audit-target root."""

    def _web_repo(self, name: str, body: str) -> str:
        d = tempfile.mkdtemp()
        _write(Path(d), name, body)
        return d

    def test_web_access_boundary_pytest_pass_cue(self) -> None:
        repo = self._web_repo("auth_routes.py", "def login(): pass  # oauth jwt session bearer token")
        block = scaffold_block("WEB_API", "accounts", ["src/auth_routes.py"], repo_path=repo)
        self.assertIn("pytest", block)
        self.assertIn("requests", block)
        # expect="pass" semantics stated explicitly: unauthorized access SUCCEEDING => bug => FAIL.
        self.assertIn('expect="pass"', block)
        for needle in ("cross-principal", "TOKEN_A", "TOKEN_B", "test_authz.py"):
            self.assertIn(needle, block)
        self.assertNotIn("IDOR", block)
        self.assertNotIn("BOLA", block)
        self.assertNotIn("vm.sign", block)

    def test_web_payment_idempotency_pytest_pass_cue(self) -> None:
        repo = self._web_repo(
            "billing.py", "def charge(): pass  # payment refund idempotency-key ledger currency amount")
        block = scaffold_block("WEB_API", "billing", ["src/billing.py"], repo_path=repo)
        self.assertIn("pytest", block)
        self.assertIn('expect="pass"', block)
        for needle in ("Idempotency-Key", "DOUBLE CHARGE", "conserve", "test_payments.py"):
            self.assertIn(needle, block)

    def test_graphql_resolver_authz_pytest_pass_cue(self) -> None:
        repo = self._web_repo(
            "schema.py", "resolver typedefs apollo introspection __schema query { mutation {")
        block = scaffold_block("WEB_API", "api", ["src/schema.py"], repo_path=repo)
        self.assertIn("pytest", block)
        self.assertIn('expect="pass"', block)
        for needle in ("GraphQL", "alias", "batch", "introspection", "test_graphql_authz.py"):
            self.assertIn(needle, block)

    def test_crypto_signature_pytest_fail_cue(self) -> None:
        repo = self._web_repo(
            "ecdsa.py", "def sign(): pass  # ecdsa secp256k1 signature verify nonce malleab low-s recover")
        block = scaffold_block("CRYPTO_LIB", "sig", ["src/ecdsa.py"], repo_path=repo)
        self.assertIn("pytest", block)
        # crypto is a property/invariant style harness — a broken invariant FAILS the test.
        self.assertIn('expect="fail"', block)
        for needle in ("non-malleab", "domain", "nonce", "differential", "test_crypto_props.py"):
            self.assertIn(needle.lower(), block.lower())
        self.assertIn("CRYPTO_LIB", block)

    def test_supply_chain_semgrep_fail_cue(self) -> None:
        block = scaffold_block("SUPPLY_CHAIN", "deps", ["package.json"])
        self.assertIn("semgrep", block)
        self.assertIn("rules:", block)
        self.assertIn('expect="fail"', block)
        for needle in ("postinstall", "dependency confusion", "typosquat", "supply_chain.semgrep.yml"):
            self.assertIn(needle, block.lower() if needle.islower() else needle)
        self.assertIn("MATCH", block)

    def test_infra_rego_fail_cue(self) -> None:
        block = scaffold_block("INFRA", "terraform", ["main.tf"])
        self.assertIn("rego", block.lower())
        self.assertTrue("conftest" in block or "opa" in block)
        self.assertIn('expect="fail"', block)
        for needle in ("WILDCARD IAM", "PUBLIC", "SECRET IN IAC", "iac_policy.rego", "deny"):
            self.assertIn(needle, block)

    def test_mobile_static_fail_cue(self) -> None:
        block = scaffold_block("MOBILE_APP", "android", ["AndroidManifest.xml"])
        self.assertIn("pytest", block)
        self.assertIn('expect="fail"', block)
        for needle in ("AndroidManifest", "debuggable", "allowBackup", "EXPORTED", "test_mobile_config.py"):
            self.assertIn(needle, block)

    def test_every_nonevm_states_run_command(self) -> None:
        # Each generator must surface a run command + materialized file path.
        cases = [
            ("SUPPLY_CHAIN", ["package.json"], "semgrep --config"),
            ("INFRA", ["main.tf"], "conftest test"),
            ("MOBILE_APP", ["AndroidManifest.xml"], "pytest ./.p1hunt-poc/test_mobile_config.py"),
        ]
        for tc, files, cmd in cases:
            block = scaffold_block(tc, "s", files)
            self.assertIn(cmd, block, f"{tc} missing run command")
            self.assertIn("./.p1hunt-poc/", block)

    def test_unknown_class_falls_back_generic(self) -> None:
        block = scaffold_block("OTHER", "misc", ["thing.bin"])
        self.assertIn("REAL harness", block)
        self.assertIn("OTHER", block)
        self.assertNotIn("vm.sign", block)

    def test_web_no_target_falls_back_generic(self) -> None:
        # No repo_path and a non-existent focus file: must NOT scan cwd; falls back to generic.
        block = scaffold_block("WEB_API", "auth", ["does/not/exist.py"])
        self.assertIn("REAL harness", block)
        self.assertIn("Hypothesis", block)

    def test_no_product_literals_in_nonevm(self) -> None:
        for tc, files in (("WEB_API", ["a.py"]), ("CRYPTO_LIB", ["a.py"]),
                          ("SUPPLY_CHAIN", ["package.json"]), ("INFRA", ["main.tf"]),
                          ("MOBILE_APP", ["AndroidManifest.xml"])):
            block = scaffold_block(tc, "s", files)
            for banned in ("KnownProductA", "KnownProductB", "Example Inc", "cloud account 123"):
                self.assertNotIn(banned, block)


if __name__ == "__main__":
    unittest.main()
