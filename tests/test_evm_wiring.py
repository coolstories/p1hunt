"""Tests for static detector utilities and preset-free planner wiring."""

from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path

from p1hunt.agents.derive import derive_plan
from p1hunt.agents.reasoner import _HARDENED_AWARE, _SIGNAL_PROFILE, DeterministicReasoner
from p1hunt.classify.evm_signals import EVM_SIGNALS, scan_combined
from p1hunt.classify.signals import scan_artifacts
from p1hunt.config import Config
from p1hunt.main import build_scope, run_engagement
from p1hunt.models import EngagementStatus, TargetClass


# A hardened, assembly-heavy, guard-saturated contract in the spirit of a real exchange.
_HARDENED_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract Exchange {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "only owner"); _; }

    function _verify(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        require(uint256(s) <= 0x7FFFFFFF, "bad s");
        address signer = ecrecover(digest, v, r, s);
        return signer;
    }

    function fulfill(address payable to, uint256 numerator, uint256 denominator, uint256 amount) external {
        require(to != address(0), "zero");
        uint256 filled = amount / denominator * numerator;
        assembly { let p := mload(0x40) }
        to.call{value: filled}("");
        require(filled <= amount, "overfill");
    }

    function upgrade(address impl, bytes calldata data) external onlyOwner {
        assembly ("memory-safe") { let q := mload(0x40) }
        impl.delegatecall(data);
    }
}
"""

_PLAIN_WEB = """import express from "express";
const app = express();
app.get("/u/:id", async (req, res) => {
  const u = await db.findUnique(req.params.id);
  res.json(u);
});
const apiKey = "sk_live_exampleSecretValue123456789";
"""


def _write(root: Path, rel: str, content: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


class ScanCombined(unittest.TestCase):
    def test_no_sol_equals_generic(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "routes.ts", _PLAIN_WEB)
            combined = scan_combined(d)
            generic = scan_artifacts(d)
            self.assertEqual(
                {(h.signal.id, h.file, h.line) for h in combined},
                {(h.signal.id, h.file, h.line) for h in generic},
            )

    def test_hardened_evm_includes_evm_signals(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "contracts/Exchange.sol", _HARDENED_SOL)
            ids = {h.signal.id for h in scan_combined(d)}
            self.assertIn("evm-bare-ecrecover", ids)
            self.assertIn("evm-unchecked-call", ids)
            self.assertIn("evm-div-before-mul", ids)
            self.assertIn("evm-raw-delegatecall", ids)

    def test_hardened_evm_demotes_generic_keyword_noise_in_sol(self) -> None:
        # On an assembly-heavy target, only NON-EVM generic keyword hits inside .sol files are
        # dropped as noise; the high-value EVM-class generic detectors (evm-tx-origin /
        # evm-delegatecall) are KEPT — they are the strongest leads on exactly this code class
        # (see scan_combined's documented contract in evm_signals.py). EVM-specific hits also remain.
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "contracts/Exchange.sol", _HARDENED_SOL)
            combined = scan_combined(d)
            evm_ids = {s.id for s in EVM_SIGNALS}
            dropped_noise = [h for h in combined if h.file.endswith(".sol")
                             and h.signal.id not in evm_ids and not h.signal.id.startswith("evm-")]
            self.assertEqual(dropped_noise, [], "non-EVM keyword noise in .sol should be demoted on hardened code")
            self.assertTrue([h for h in combined if h.signal.id in evm_ids])

    def test_generic_hits_in_non_sol_files_are_kept(self) -> None:
        # A CI/manifest/source file alongside hardened contracts still contributes generic hits.
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "contracts/Exchange.sol", _HARDENED_SOL)
            _write(Path(d), "scripts/deploy.ts", _PLAIN_WEB)
            combined = scan_combined(d)
            non_sol = [h for h in combined if not h.file.endswith(".sol")]
            self.assertTrue(non_sol, "generic hits outside .sol must survive demotion")
            self.assertIn("secret-in-source", {h.signal.id for h in non_sol})


class DerivationIsPresetFree(unittest.TestCase):
    def test_plan_surfaces_are_neutral_components_not_signal_lenses(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "contracts/Exchange.sol", _HARDENED_SOL)
            scope = build_scope("evm-derive-test", d)
            plan = derive_plan(scope, d)
            self.assertEqual(plan.target_class, TargetClass.EVM_CONTRACT)
            lenses = {s.lens for s in plan.surface_ranking}
            self.assertTrue(lenses)
            self.assertTrue(all(lens.startswith("component:") for lens in lenses))
            self.assertFalse(lenses & {"asset-custody", "authorization-boundary", "trusted-execution"})
            self.assertEqual(plan.hypothesis_seeds, [])


class ReasonerProfiles(unittest.TestCase):
    def test_every_evm_signal_has_a_profile(self) -> None:
        for sig in EVM_SIGNALS:
            self.assertIn(sig.id, _SIGNAL_PROFILE, f"{sig.id} missing a severity/repro profile")

    def test_hardened_set_matches_evm_signal_ids(self) -> None:
        self.assertEqual(_HARDENED_AWARE, {s.id for s in EVM_SIGNALS})


class PersistenceStance(unittest.TestCase):
    """The crux of "there IS a P1": a hardened-EVM lead next to a guard is NOT auto-killed —
    it persists and is confirmed by depth. A generic web sink next to a guard still dies."""

    def _hit(self, d: str, signal_id: str):
        hits = [h for h in scan_combined(d) if h.signal.id == signal_id]
        self.assertTrue(hits, f"expected a {signal_id} hit")
        return hits[0]

    def test_hardened_lead_survives_nearby_guard_with_depth(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            # unchecked low-level call wrapped in onlyOwner-style guards.
            _write(Path(d), "contracts/Vault.sol",
                   "pragma solidity ^0.8.0;\n"
                   "contract V {\n"
                   "  function onlyOwner() internal {}\n"
                   "  function pull(address payable to) external {\n"
                   "    require(msg.sender == owner, 'onlyOwner');\n"
                   "    assembly { let p := mload(0x40) }\n"
                   "    to.call{value: 1 ether}(\"\");\n"
                   "    require(true, 'onlyOwner');\n"
                   "  }\n"
                   "}\n")
            hit = self._hit(d, "evm-unchecked-call")
            r = DeterministicReasoner()
            # Round 1: not yet corroborated -> killed (persistence, not give-up: it stays a lead).
            self.assertTrue(r.falsify(hit, d, depth=1).killed)
            # After several reframes the same lead is corroborated and SURVIVES (not killed by the
            # nearby guard, unlike a generic sink).
            self.assertFalse(r.falsify(hit, d, depth=9).killed)

    def test_generic_sink_with_mitigation_still_dies_at_any_depth(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "q.ts",
                   "// parameterized and validated upstream\n"
                   'db.query("SELECT * FROM t WHERE id = " + req.query.id);\n'
                   "// parameterized binding — safe\n")
            hits = [h for h in scan_combined(d) if h.signal.id == "sql-injection"]
            self.assertTrue(hits)
            r = DeterministicReasoner()
            self.assertTrue(r.falsify(hits[0], d, depth=9).killed)


class HardenedTargetEndToEnd(unittest.TestCase):
    def test_deterministic_hunt_confirms_p1_and_surfaces_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "exchange"
            _write(repo, "contracts/Exchange.sol", _HARDENED_SOL)
            prev = os.environ.get("P1HUNT_USE_CLAUDE")
            prev_static = os.environ.get("P1HUNT_LEGACY_STATIC_SIGNALS")
            os.environ["P1HUNT_USE_CLAUDE"] = "0"  # force the deterministic brain
            os.environ["P1HUNT_LEGACY_STATIC_SIGNALS"] = "1"
            try:
                cfg = Config.from_env()
                cfg.engagements_root = str(Path(tmp) / "eng")
                scope = build_scope("Hardened Exchange (test)", str(repo))
                result = asyncio.run(run_engagement(scope, str(repo), config=cfg, rounds=8))[0]
            finally:
                if prev is None:
                    os.environ.pop("P1HUNT_USE_CLAUDE", None)
                else:
                    os.environ["P1HUNT_USE_CLAUDE"] = prev
                if prev_static is None:
                    os.environ.pop("P1HUNT_LEGACY_STATIC_SIGNALS", None)
                else:
                    os.environ["P1HUNT_LEGACY_STATIC_SIGNALS"] = prev_static
            self.assertEqual(result.plan.target_class, TargetClass.EVM_CONTRACT)
            self.assertTrue(result.confirmed_critical, "a hardened EVM target must yield a confirmed P1")
            self.assertEqual(result.status, EngagementStatus.REPORT_READY)
            # Total observability: every lead is surfaced as a ranked candidate.
            self.assertTrue(result.candidates)
            self.assertEqual(result.candidates[0]["severity"], "critical")  # strongest first
            self.assertTrue(any(c["reproduced"] for c in result.candidates))


class HunterPromptLeads(unittest.TestCase):
    def test_static_leads_do_not_render_into_prompt(self) -> None:
        from p1hunt.agents.claude_hunter import hunt_prompt

        leads = ["ecrecover used without a zero-address / signer check — contracts/Exchange.sol:9 "
                 "(lens: authorization-boundary; class: evm-bare-ecrecover)"]
        prompt = hunt_prompt("asset-custody", "loss of funds", 1, [], None, None, static_leads=leads)
        self.assertNotIn("DERIVED STATIC LEADS", prompt)
        self.assertNotIn("evm-bare-ecrecover", prompt)
        self.assertNotIn("DERIVED STATIC LEADS", hunt_prompt("x", "y", 1, [], None, None))


class SwarmStaticLeads(unittest.TestCase):
    def _swarm(self, repo: Path):
        from p1hunt.agents.claude_swarm import ClaudeSwarm
        from p1hunt.orchestrator.blackboard import Blackboard
        from p1hunt.orchestrator.bus import MessageBus
        from p1hunt.orchestrator.event_log import EventLog

        log = EventLog()
        return ClaudeSwarm(build_scope("swarm-leads", str(repo)), str(repo),
                           config=Config.from_env(), bus=MessageBus(log),
                           blackboard=Blackboard(log), event_log=log)

    def test_static_leads_disabled_even_when_scanner_has_hits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            _write(repo, "contracts/Exchange.sol", _HARDENED_SOL)
            _write(repo, "contracts/Other.sol",
                   "pragma solidity ^0.8.0;\ncontract O { function f(bytes32 h,uint8 v,bytes32 r,bytes32 s) external pure returns(address){return ecrecover(h,v,r,s);} }\n")
            swarm = self._swarm(repo)
            swarm._scan_hits = scan_combined(str(repo))
            self.assertTrue(swarm._scan_hits)
            leads = swarm._static_leads_for(["contracts/Exchange.sol"])
            self.assertEqual(leads, [])

    def test_out_of_scope_leads_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            _write(repo, "contracts/Exchange.sol", _HARDENED_SOL)
            _write(repo, "reference/Ref.sol", _HARDENED_SOL)
            swarm = self._swarm(repo)
            # Mark the reference impl out of scope (a differential oracle, never reported).
            swarm.scope.out_of_scope_globs = ["reference/*"]
            swarm._scan_hits = scan_combined(str(repo))
            leads = swarm._static_leads_for([])
            self.assertEqual(leads, [])


class LegacyParentStaticSignals(unittest.TestCase):
    def test_legacy_parent_does_not_load_static_signals_by_default(self) -> None:
        from p1hunt.agents.parent_a import ParentA
        from p1hunt.orchestrator.blackboard import Blackboard
        from p1hunt.orchestrator.bus import MessageBus
        from p1hunt.orchestrator.event_log import EventLog

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            _write(repo, "contracts/Exchange.sol", _HARDENED_SOL)
            prev = os.environ.pop("P1HUNT_LEGACY_STATIC_SIGNALS", None)
            try:
                log = EventLog()
                parent = ParentA(build_scope("no-static-default", str(repo)), str(repo),
                                 config=Config.from_env(), bus=MessageBus(log),
                                 blackboard=Blackboard(log), event_log=log)
                parent.derive()
                parent.setup_tracks()
                self.assertEqual(parent._hits, [])
            finally:
                if prev is not None:
                    os.environ["P1HUNT_LEGACY_STATIC_SIGNALS"] = prev


if __name__ == "__main__":
    unittest.main()
