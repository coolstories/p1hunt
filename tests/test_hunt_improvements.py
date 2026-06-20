"""Unit tests for the reasoning/throughput upgrades: compounding subsystem memory, the two-phase
map prompt, scoped-web prompt discipline, the PoC-repair prompt, adaptive budget, the needs-human
surfacing, and the toolchain warning. Covers the pure/constructible logic (LLM sessions aren't
exercised offline)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from p1hunt.agents.claude_hunter import (
    _parse_threads,
    hunt_prompt,
    map_prompt,
    parse_model_update,
    repair_prompt,
)
from p1hunt.agents.claude_session import ClaudeFinding


class TestModelMemory(unittest.TestCase):
    def test_parse_model_update_prefers_model_update(self):
        text = '{"findings": [], "ruled_out": [], "model_update": "ENTRYPOINTS: foo() @ a.go:10"}'
        self.assertEqual(parse_model_update(text), "ENTRYPOINTS: foo() @ a.go:10")

    def test_parse_model_update_falls_back_to_model(self):
        self.assertEqual(parse_model_update('{"model": "M", "threads": []}'), "M")

    def test_parse_model_update_empty_when_absent(self):
        self.assertEqual(parse_model_update('{"findings": []}'), "")

    def test_parse_threads(self):
        self.assertEqual(_parse_threads('{"model":"m","threads":["t1","t2"]}'), ["t1", "t2"])

    def test_hunt_prompt_injects_model_and_asks_for_update(self):
        p = hunt_prompt("auth", "loss", 2, [], None, None, model="PRIOR MODEL TEXT")
        self.assertIn("ACCUMULATED MODEL", p)
        self.assertIn("PRIOR MODEL TEXT", p)
        self.assertIn("model_update", p)

    def test_hunt_prompt_no_model_block_when_empty(self):
        self.assertNotIn("ACCUMULATED MODEL", hunt_prompt("auth", "loss", 1, [], None, None))


class TestTwoPhaseMap(unittest.TestCase):
    def test_map_prompt_is_reading_generous_and_no_poc(self):
        p = map_prompt("signing", "key extraction", ["sign.go"], ["check nonce"])
        self.assertIn("MAP phase", p)
        self.assertIn("reading is ENCOURAGED", p)
        self.assertIn('"model"', p)
        self.assertIn('"threads"', p)


class TestScopedWebDiscipline(unittest.TestCase):
    def test_web_rule_forbids_searching_for_product_bugs(self):
        p = hunt_prompt("auth", "loss", 1, [], None, None, allow_web=True)
        self.assertIn("WEB", p)
        # The exact failure mode the operator hit must be explicitly forbidden.
        self.assertIn("do NOT search for this program's disclosed bugs", p)

    def test_no_web_block_when_disabled(self):
        p = hunt_prompt("auth", "loss", 1, [], None, None, allow_web=False)
        self.assertNotIn("for TECHNIQUE, never the answer", p)


class TestRepairPrompt(unittest.TestCase):
    def test_repair_prompt_includes_runner_output(self):
        f = ClaudeFinding.from_dict({"title": "t", "file": "a.sol", "line": 1}, "lens")
        p = repair_prompt(f, {"harness_path": ".p1hunt-poc/x.t.sol"}, "error: undeclared identifier foo")
        self.assertIn("ITERATING on a proof harness", p)
        self.assertIn("REAL RUNNER OUTPUT", p)
        self.assertIn("undeclared identifier foo", p)  # the failure is fed back to the prover
        self.assertIn(".p1hunt-poc/x.t.sol", p)


def _swarm(tmp: str):
    from p1hunt.agents.claude_swarm import ClaudeSwarm
    from p1hunt.config import Config
    from p1hunt.models import Asset, Scope
    from p1hunt.orchestrator.blackboard import Blackboard
    from p1hunt.orchestrator.bus import MessageBus
    from p1hunt.orchestrator.event_log import EventLog

    scope = Scope(program="P", safe_harbor_text="x", severity_taxonomy={"P1": "critical"},
                  in_scope=[Asset("a1", tmp, "repo", tmp, "local")])
    log = EventLog()
    return ClaudeSwarm(scope, tmp, config=Config(), bus=MessageBus(log),
                       blackboard=Blackboard(log), event_log=log)


class TestAdaptiveBudget(unittest.TestCase):
    def test_promising_track_gets_more_turns(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)

            class _H:
                def __init__(self):
                    self.theme = "t"
                    self.max_turns = sw._hunter_base_turns()

            promising, cold = _H(), _H()
            crit = ClaudeFinding.from_dict({"title": "x", "severity": "critical"}, "t")
            sw._retune_budgets([promising, cold], [[crit], []])
            self.assertGreater(promising.max_turns, sw._hunter_base_turns())
            self.assertEqual(cold.max_turns, sw._hunter_base_turns())


class TestToolchainWarning(unittest.TestCase):
    def test_repro_tools_for_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._target_class = "EVM_CONTRACT"
            self.assertEqual(sw._repro_tools_for_class(), ["forge"])
            sw._target_class = "CRYPTO_LIB"
            self.assertIn("go", sw._repro_tools_for_class())
            self.assertIn("cargo", sw._repro_tools_for_class())

    def test_mobile_is_exempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._target_class = "MOBILE_APP"
            # Should not raise and should early-return (static-only class).
            sw._warn_if_no_repro_toolchain()


class TestNeedsHumanSurfacing(unittest.TestCase):
    def test_surface_for_human_is_unverified_and_unreproduced(self):
        from p1hunt.models import TargetClass
        from p1hunt.safety.policies import derive_scopeguard_policy
        from p1hunt.safety.scopeguard import ScopeGuard
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            guard = ScopeGuard(derive_scopeguard_policy(sw.scope, TargetClass.EVM_CONTRACT))
            cf = ClaudeFinding.from_dict(
                {"title": "balance underflow", "severity": "critical", "file": "V.sol", "line": 9,
                 "confidence": "high", "concrete_loss": "funds", "counterfactual": "drains vault"}, "asset")
            f = sw._surface_for_human(cf, "falsifier: real", "critical", guard, ran=True, detail="no repro")
            self.assertFalse(f.verified)            # clearly marked needs-human
            self.assertFalse(f.poc.reproduced)      # the reproduced=confirmed floor is intact
            self.assertIn("NEEDS HUMAN REVIEW", f.severity_rationale)


class TestCostGuard(unittest.TestCase):
    def test_spend_accumulates_from_usage_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            self.assertEqual(sw._spend_usd, 0.0)
            sw._emit("child_b1", "usage", {"cost": 0.5})
            sw._emit("child_b1", "usage", {"cost": 0.25})
            sw._emit("child_b1", "thinking", {"text": "no cost here"})
            self.assertAlmostEqual(sw._spend_usd, 0.75)

    def test_cost_cap_parsed_from_env(self):
        import os
        os.environ["P1HUNT_MAX_COST_USD"] = "12.5"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                sw = _swarm(tmp)
                self.assertEqual(sw._cost_cap, 12.5)
        finally:
            del os.environ["P1HUNT_MAX_COST_USD"]

    def test_cost_cap_off_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            self.assertIsNone(sw._cost_cap)


class TestDryRunEgress(unittest.TestCase):
    def _guard(self, run_mode):
        from p1hunt.models import Asset, DynamicTarget, Scope, TargetClass
        from p1hunt.safety.policies import derive_scopeguard_policy
        from p1hunt.safety.scopeguard import ScopeGuard
        scope = Scope(program="P", safe_harbor_text="x", severity_taxonomy={"P1": "c"},
                      in_scope=[Asset("a1", "https://uat.x.com", "domain", "https://uat.x.com", "uat")],
                      rate_limit="60 per minute",
                      dynamic_targets=[DynamicTarget("https://uat.x.com", "uat")])
        return ScopeGuard(derive_scopeguard_policy(scope, TargetClass.WEB_API, run_mode=run_mode))

    def test_dry_run_denies_remote_even_in_scope(self):
        d = self._guard("dry_run").check_egress("c", "https://uat.x.com/api", method="GET")
        self.assertFalse(d.allow)  # no live contact in dry-run

    def test_dry_run_allows_loopback(self):
        d = self._guard("dry_run").check_egress("c", "http://127.0.0.1:9000/cb", method="GET")
        self.assertTrue(d.allow)

    def test_active_allows_in_scope(self):
        d = self._guard("active").check_egress("c", "https://uat.x.com/api", method="GET")
        self.assertTrue(d.allow)


if __name__ == "__main__":
    unittest.main()
