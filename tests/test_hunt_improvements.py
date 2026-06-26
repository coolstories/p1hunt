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
    compact_model_memory,
    materialize_prompt,
    hunt_prompt,
    map_prompt,
    parse_model_update,
    repair_prompt,
    verify_prompt,
)
from p1hunt.agents.claude_session import ClaudeFinding
from p1hunt.agents.claude_swarm import normalize_exploit_tier
from p1hunt.main import _taxonomy_for_scope_note


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

    def test_parse_model_update_survives_noisy_braces_before_json(self):
        text = 'tool output {not json}\n```json\n{"model": "M", "threads": ["t1"]}\n```'
        self.assertEqual(parse_model_update(text), "M")
        self.assertEqual(_parse_threads(text), ["t1"])

    def test_parse_model_update_survives_braces_inside_strings(self):
        text = '{"model": "state includes {literal braces}", "threads": ["check {x}"]}'
        self.assertEqual(parse_model_update(text), "state includes {literal braces}")
        self.assertEqual(_parse_threads(text), ["check {x}"])

    def test_model_memory_is_compacted_without_losing_cited_high_signal_lines(self):
        noisy = "\n".join(
            [f"intro prose {i} " + ("x" * 80) for i in range(40)]
            + [
                "ENTRYPOINT fulfillOrder @ lib/Consideration.sol:120 attacker controls order",
                "TRUST boundary EIP1271 @ lib/SignatureVerification.sol:223",
                "OPEN THREAD: criteria proof may bind wrong item @ lib/Criteria.sol:88",
            ]
        )
        compact = compact_model_memory(noisy, limit=1400)
        self.assertLessEqual(len(compact), 1400)
        self.assertIn("fulfillOrder", compact)
        self.assertIn("SignatureVerification.sol:223", compact)
        self.assertIn("model memory compacted", compact)

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
        self.assertIn("do NOT search for this program's prior disclosures", p)

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


class TestGenericAttributionGate(unittest.TestCase):
    def test_finding_parser_carries_generic_attribution_fields(self):
        f = ClaudeFinding.from_dict({
            "title": "t",
            "target_code_attribution": "src/a.cpp:10 validates length after use",
            "non_target_attribution": "pytest fixture creates attacker input",
            "relies_on_non_target_behavior": "true",
            "attribution_notes": "fixture owns the bad behavior",
        }, "lens")
        self.assertEqual(f.target_code_attribution, "src/a.cpp:10 validates length after use")
        self.assertTrue(f.relies_on_non_target_behavior)
        self.assertIn("fixture", f.attribution_notes)

    def test_prompts_require_generic_target_ownership_not_bug_specific(self):
        f = ClaudeFinding.from_dict({"title": "t", "file": "a.sol", "line": 1}, "lens")
        for prompt in (
            hunt_prompt("auth", "loss", 1, [], None, None),
            verify_prompt(f),
            materialize_prompt(f),
            repair_prompt(f, {"harness_path": ".p1hunt-poc/x.t.sol"}, "runner failed"),
        ):
            self.assertIn("target_code_attribution", prompt)
            self.assertIn("non_target_attribution", prompt)
            self.assertIn("relies_on_non_target_behavior", prompt)
            self.assertIn("finding_claim", prompt)
            self.assertIn("harness", prompt.lower())
            self.assertIn("mock", prompt.lower())

    def test_materializer_requires_composed_honest_victim_proofs_without_presets(self):
        f = ClaudeFinding.from_dict({"title": "t", "file": "a.sol", "line": 1}, "lens")
        prompt = materialize_prompt(f).lower()
        for must in (
            "independent",
            "raw checker input",
            "pre-committed",
            "composed chain",
            "honest actor",
            "non-degenerate",
        ):
            self.assertIn(must, prompt)
        for banned in ("fireblocks", "eddsa", "mta", "seaport", "paillier"):
            self.assertNotIn(banned, prompt)

    def test_reprospec_blocks_missing_or_non_target_attribution(self):
        from p1hunt.runners.base import ReproSpec

        missing = ReproSpec.from_dict({"harness_path": "poc.py", "expect": "pass"})
        self.assertIn("missing target_code_attribution", missing.attribution_blocker())

        external = ReproSpec.from_dict({
            "harness_path": "poc.py",
            "target_code_attribution": "src/app.py:1",
            "relies_on_non_target_behavior": True,
            "attribution_notes": "bug is in the fake upstream service",
        })
        self.assertIn("fake upstream", external.attribution_blocker())

        ok = ReproSpec.from_dict({
            "harness_path": "poc.py",
            "target_code_attribution": "src/app.py:1 trusts attacker id",
            "non_target_attribution": "pytest client sends two users",
            "finding_claim": {"attacker_model": "user B"},
        })
        self.assertEqual(ok.attribution_blocker(), "")
        self.assertEqual(ok.finding_claim["attacker_model"], "user B")

    def test_swarm_reproduction_boundary_rejects_unattributed_specs(self):
        import asyncio

        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            sw._target_class = "WEB_API"
            cf = ClaudeFinding.from_dict({"title": "t", "file": "a.py", "line": 1}, "lens")
            res = asyncio.run(sw._reproduce(cf, {"harness_path": "poc.py", "expect": "pass"}))
            self.assertIsNotNone(res)
            self.assertFalse(res.reproduced)
            self.assertEqual(res.runner, "attribution-gate")
            self.assertIn("attribution gate", res.detail)

    def test_verifier_refutes_real_verdict_with_non_target_attribution(self):
        import asyncio
        from unittest import mock
        from p1hunt.agents import claude_hunter
        from p1hunt.agents.claude_hunter import ClaudeVerifier
        from p1hunt.agents.claude_session import SessionResult

        class _Session:
            async def run(self, *_args, **_kwargs):
                return SessionResult(
                    ok=True,
                    text=('{"verdict":"real","severity":"critical","reachable":true,'
                          '"relies_on_non_target_behavior":true,'
                          '"attribution_notes":"the fake storage backend owns the bad behavior"}'),
                )

        f = ClaudeFinding.from_dict({"title": "t", "file": "a.py", "line": 1}, "lens")
        verifier = ClaudeVerifier("falsifier", model="m", on_event=lambda *a: None, guard_check=None)
        with mock.patch.object(claude_hunter, "make_session", return_value=_Session()):
            status, _severity, reason = asyncio.run(verifier.verify(f, "/tmp"))
        self.assertEqual(status, "refuted")
        self.assertIn("attribution gate failed", reason)


class TestEngagementSpecificSeverity(unittest.TestCase):
    def test_scope_note_overrides_generic_taxonomy(self):
        note = (
            "Critical: Retrieving the key or rogue signature without triggering any failures or "
            "aborts, regardless of the number of transactions involved. Obtaining the key/rogue "
            "signature by causing fewer than 1000 failures/aborts. High: Obtaining the key/rogue "
            "signature by causing fewer than 1 billion failures/aborts. Medium: Leaking bits of "
            "the private key or causing memory corruption. Low: Exploit exposure to non-critical data."
        )
        tax = _taxonomy_for_scope_note(note)
        self.assertIn("fewer than 1000 failures/aborts", tax["P1"])
        self.assertIn("fewer than 1 billion", tax["P2"])
        self.assertIn("private key", tax["P3"])

    def test_exploit_tier_normalization_does_not_inflate_lower_tiers(self):
        self.assertEqual(normalize_exploit_tier("critical"), "critical")
        self.assertEqual(normalize_exploit_tier("high"), "high")
        self.assertEqual(normalize_exploit_tier("medium"), "medium")
        self.assertEqual(normalize_exploit_tier("low"), "low")
        self.assertEqual(normalize_exploit_tier("unexpected"), "high")


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
            self.assertFalse(f.verified)            # clearly marked follow-up, not confirmed
            self.assertFalse(f.poc.reproduced)      # the reproduced=confirmed floor is intact
            self.assertIn("AUTONOMOUS FOLLOW-UP", f.severity_rationale)


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


class TestDedupAndDebate(unittest.TestCase):
    def _cf(self, **kw):
        base = {"title": "t", "file": "a.cpp", "line": 1, "root_cause": "rc", "counterfactual": "cf"}
        base.update(kw)
        return ClaudeFinding.from_dict(base, "lens")

    def _finding(self, title, rc):
        from p1hunt.models import ArtifactRef, Finding, Hypothesis, SafeValidationPlan
        return Finding(id="F1", hypothesis_id="h", title=title, root_cause=rc,
                       poc=ArtifactRef(id="a", kind="repro", path="x.cpp:1", description="", reproduced=True),
                       severity="critical", severity_rationale="r", counterfactual="c",
                       remediation="fix", safe_harbor_attestation="att", verified=True)

    def test_dedup_prompt_lists_existing(self):
        from p1hunt.agents.claude_hunter import dedup_prompt
        p = dedup_prompt(self._cf(title="nonce reuse v2"),
                         [self._finding("nonce reuse", "presig resurrected")])
        self.assertIn("deduplicator", p.lower())
        self.assertIn("nonce reuse", p)            # existing one listed
        self.assertIn("duplicate", p)

    def test_debate_prompts_have_both_sides(self):
        from p1hunt.agents.claude_hunter import debate_prompt, debate_judge_prompt
        self.assertIn("PROSECUTOR", debate_prompt(self._cf(), "prosecutor"))
        self.assertIn("DEFENDER", debate_prompt(self._cf(), "defender"))
        j = debate_judge_prompt(self._cf(), "pros argument", "def argument")
        self.assertIn("uphold|downgrade|reject", j)
        self.assertIn("JUDGE", j)
        self.assertIn("attacker_controls_all_material_inputs", j)

    def test_debate_prompt_robust_to_promoted_finding(self):
        from p1hunt.agents.claude_hunter import debate_prompt, debate_judge_prompt
        f = self._finding("offline finalizer", "rc")
        p = debate_prompt(f, "prosecutor")
        self.assertIn("offline finalizer", p)
        self.assertIn("x.cpp:1", p)
        self.assertIn("honest-held", p)
        j = debate_judge_prompt(f, "pros", "def")
        self.assertIn("offline finalizer", j)
        self.assertIn("self-controlled artifact", j)


class TestStopAndPanelConfig(unittest.TestCase):
    def _swarm_with_env(self, tmp, **env):
        import os
        old = {k: os.environ.get(k) for k in env}
        os.environ.update({k: str(v) for k, v in env.items()})
        try:
            return _swarm(tmp)
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_max_criticals_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._swarm_with_env(tmp, P1HUNT_MAX_CRITICALS=3)._max_criticals, 3)

    def test_max_criticals_blank_means_never_quit(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(self._swarm_with_env(tmp, P1HUNT_MAX_CRITICALS=0)._max_criticals)
            self.assertIsNone(_swarm(tmp)._max_criticals)  # unset -> None

    def test_debate_and_dedup_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            sw = _swarm(tmp)
            self.assertTrue(sw._dedup_on)        # dedup on by default
            self.assertEqual(sw._debate_max, 3)  # bounded debate by default

    def test_debate_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._swarm_with_env(tmp, P1HUNT_DEBATE_MAX=0)._debate_max, 0)


if __name__ == "__main__":
    unittest.main()
