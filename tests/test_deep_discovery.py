"""Deep-discovery/rate-limit safeguards for the autonomous hunt workflow."""

import os
import asyncio
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from p1hunt.agents.claude_swarm import ClaudeSwarm, _env_float, _env_int, _parse_json_object
from p1hunt.agents.claude_session import SessionResult
from p1hunt.config import Config
from p1hunt.models import DynamicTarget, Scope
from p1hunt.runtime_reload import _refresh_swarm_knobs


class _TurnsShim:
    _hunter_base_turns = ClaudeSwarm._hunter_base_turns

    def __init__(self, deep):
        self._deep_discovery = deep


class _ReconShim:
    _recon_mode = ClaudeSwarm._recon_mode
    _recon_policy_text = ClaudeSwarm._recon_policy_text
    _has_live_web_targets = ClaudeSwarm._has_live_web_targets
    _dynamic_target_payload = ClaudeSwarm._dynamic_target_payload
    _live_web_scope_prompt = ClaudeSwarm._live_web_scope_prompt
    _parent_recon_brief = ClaudeSwarm._parent_recon_brief
    _live_web_recon_blocker = ClaudeSwarm._live_web_recon_blocker
    _scope_prompt = ClaudeSwarm._scope_prompt
    _scope_guidance = lambda self: ""

    def __init__(self, run_mode="dry_run"):
        self.config = types.SimpleNamespace(run_mode=run_mode)
        self._target_class = "OTHER"
        self.scope = Scope(program="test")


class TestDeepDiscoveryTurns(unittest.TestCase):
    def setUp(self):
        os.environ.pop("P1HUNT_HUNTER_TURNS", None)

    def test_deep_mode_raises_turn_floor(self):
        self.assertEqual(_TurnsShim(deep=False)._hunter_base_turns(), 28)
        self.assertEqual(_TurnsShim(deep=True)._hunter_base_turns(), 80)

    def test_env_override_wins_over_deep_default(self):
        os.environ["P1HUNT_HUNTER_TURNS"] = "120"
        try:
            self.assertEqual(_TurnsShim(deep=True)._hunter_base_turns(), 120)
            self.assertEqual(_TurnsShim(deep=False)._hunter_base_turns(), 120)
        finally:
            os.environ.pop("P1HUNT_HUNTER_TURNS", None)


class TestParentAReconMode(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("P1HUNT_RECON_MODE", None)

    def test_auto_recon_mode_lets_parent_choose_solo_hybrid_or_parallel(self):
        os.environ["P1HUNT_RECON_MODE"] = "auto"
        prompt = _ReconShim("dry_run")._scope_prompt()
        self.assertIn("RECON EXECUTION MODE: AUTO", prompt)
        self.assertIn("SOLO", prompt)
        self.assertIn("PARALLEL", prompt)
        self.assertIn("HYBRID", prompt)
        self.assertIn('"recon_strategy"', prompt)

    def test_parallel_recon_mode_is_dry_run_only(self):
        os.environ["P1HUNT_RECON_MODE"] = "parallel"
        self.assertEqual(_ReconShim("dry_run")._recon_mode(), "parallel")
        self.assertEqual(_ReconShim("active")._recon_mode(), "solo")

    def test_solo_recon_mode_forces_parent_owned_read(self):
        os.environ["P1HUNT_RECON_MODE"] = "solo"
        prompt = _ReconShim("dry_run")._scope_prompt()
        self.assertIn("RECON EXECUTION MODE: SOLO", prompt)
        self.assertIn("Do the deep reconnaissance yourself", prompt)

    def test_live_web_targets_get_dynamic_recon_not_repo_recon(self):
        shim = _ReconShim("active")
        shim._target_class = "WEB_API"
        shim.scope = Scope(
            program="web",
            dynamic_targets=[DynamicTarget("https://app.example.test/api", "uat", "rest")],
            scope_note="Only the listed live target is authorized.",
        )

        prompt = shim._scope_prompt()
        self.assertIn("AUTHORIZED LIVE TARGETS JSON", prompt)
        self.assertIn("subfinder -silent", prompt)
        self.assertIn("robots.txt", prompt)
        self.assertIn("curl -i", prompt)
        self.assertIn('"target_class":"WEB_API"', prompt)
        self.assertIn("app.example.test", prompt)
        self.assertNotIn("source in the current working directory", prompt)

    def test_live_web_recon_handles_ip_targets_without_subdomain_expansion(self):
        shim = _ReconShim("active")
        shim._target_class = "WEB_API"
        shim.scope = Scope(
            program="web",
            dynamic_targets=[DynamicTarget("http://192.0.2.10/flag.txt", "uat", "generic")],
        )

        prompt = shim._scope_prompt()
        self.assertIn("If the target is an IP address or exact URL-only host", prompt)
        self.assertIn("subdomain enumeration is not applicable", prompt)
        self.assertIn("192.0.2.10", prompt)

    def test_parent_scope_session_allows_web_for_live_targets(self):
        import inspect
        src = inspect.getsource(ClaudeSwarm._scope)
        self.assertIn("allow_web=self._has_live_web_targets()", src)

    def test_parent_recon_brief_carries_web_baseline_to_children(self):
        brief = _ReconShim("active")._parent_recon_brief({
            "summary": "GET /flag timed out; no HTTP status observed.",
            "critical_means": "retrieve protected proof artifact",
            "crown_jewels": ["flag endpoint"],
            "attack_surface": ["GET exact URL timed out", "HEAD exact URL timed out"],
            "top_hypothesis": "resolve transport reachability before app-layer claims",
        })
        self.assertIn("Parent A baseline summary", brief)
        self.assertIn("GET /flag timed out", brief)
        self.assertIn("Attack surface", brief)

    def test_web_children_are_seeded_from_parent_baseline(self):
        import inspect
        src = inspect.getsource(ClaudeSwarm.hunt)
        self.assertIn("h.web_mode and parent_recon_brief", src)
        self.assertIn("Start from Parent A's baseline model", src)

    def test_live_web_timeout_only_recon_blocks_before_children(self):
        shim = _ReconShim("active")
        shim._target_class = "WEB_API"
        shim.scope = Scope(
            program="web",
            dynamic_targets=[DynamicTarget("http://192.0.2.10/flag.txt", "bounty", "generic")],
        )
        blocker = shim._live_web_recon_blocker({
            "summary": "GET /flag.txt timed out; no HTTP status/headers/body observed.",
            "attack_surface": ["GET exact URL status=none marker=curl timeout"],
            "top_hypothesis": "No concrete app URL or token was observed; fetch composition is blocked.",
            "tracks": [{"investigate": ["Needs reachable in-scope app URL before testing trusted-origin fetch."]}],
        })
        self.assertIn("transport/vantage blocker", blocker)

    def test_live_web_recon_blocker_allows_real_response_or_surface(self):
        shim = _ReconShim("active")
        shim._target_class = "WEB_API"
        shim.scope = Scope(
            program="web",
            dynamic_targets=[DynamicTarget("https://app.example.test/api", "bounty", "rest")],
        )
        self.assertEqual(shim._live_web_recon_blocker({
            "summary": "GET /api status=401 with WWW-Authenticate header.",
            "attack_surface": ["GET https://app.example.test/api status=401"],
            "tracks": [{"investigate": ["Map auth flow and object authorization."]}],
        }), "")
        self.assertEqual(shim._live_web_recon_blocker({
            "summary": "Flag endpoint timed out, but an in-scope app URL exposes an import webhook.",
            "attack_surface": ["GET exact URL timeout", "POST /import accepts attacker URL"],
            "tracks": [{"investigate": ["Test server-side fetch callback safely."]}],
        }), "")


class TestRuntimeKnobs(unittest.TestCase):
    def tearDown(self):
        for key in (
            "P1HUNT_RECON_TURNS",
            "P1HUNT_FUZZ_CAMPAIGNS",
            "P1HUNT_HUNTER_TIMEOUT",
            "P1HUNT_MAX_CONCURRENCY",
            "P1HUNT_SIDE_LANE_CONCURRENCY",
            "P1HUNT_DEEP_DISCOVERY",
        ):
            os.environ.pop(key, None)

    def test_malformed_numeric_env_values_fall_back(self):
        os.environ["P1HUNT_RECON_TURNS"] = "deep"
        os.environ["P1HUNT_FUZZ_CAMPAIGNS"] = "many"
        os.environ["P1HUNT_HUNTER_TIMEOUT"] = "soon"

        self.assertEqual(_env_int("P1HUNT_RECON_TURNS", 45, minimum=20), 45)
        self.assertEqual(_env_int("P1HUNT_FUZZ_CAMPAIGNS", 1, minimum=0), 1)
        self.assertEqual(_env_float("P1HUNT_HUNTER_TIMEOUT", 1200.0, minimum=1.0), 1200.0)

    def test_reload_reports_concurrency_only_when_effective_value_changes(self):
        swarm = types.SimpleNamespace(
            _deep_discovery=False,
            _max_concurrency=3,
            _side_lane_concurrency=1,
            _cost_cap=None,
            _max_criticals=None,
            _debate_max=3,
            _deepdive_on=True,
            config=Config(),
        )

        unchanged = _refresh_swarm_knobs(swarm)
        self.assertNotIn("child_concurrency", unchanged)
        self.assertNotIn("side_lane_concurrency", unchanged)

        os.environ["P1HUNT_MAX_CONCURRENCY"] = "5"
        os.environ["P1HUNT_SIDE_LANE_CONCURRENCY"] = "2"
        changed = _refresh_swarm_knobs(swarm)
        self.assertIn("child_concurrency", changed)
        self.assertIn("side_lane_concurrency", changed)


class _TracksShim:
    _fallback_tracks = ClaudeSwarm._fallback_tracks
    _repo_component_tracks = ClaudeSwarm._repo_component_tracks

    def _enumerate_targets(self, limit=30):
        return ["src/payments/settlement.sol", "src/payments/vault.sol", "src/router/dispatch.sol"]

    def _out_of_scope(self, _rel):
        return False

    _deep_discovery = False
    _target_class = "OTHER"


class TestFlowDecomposition(unittest.TestCase):
    def test_fallback_is_repo_derived_not_preset_lenses(self):
        tracks = _TracksShim()._fallback_tracks()
        themes = [t["theme"] for t in tracks]
        self.assertTrue(all(t.startswith("derived:") for t in themes))
        self.assertTrue(any("payments" in t or "settlement" in t or "vault" in t for t in themes))
        self.assertTrue(all(t["invariants"] == [] for t in tracks))
        self.assertFalse(any("authorization-boundary" == t for t in themes))
        self.assertFalse(any("composition-and-trust-seams" == t for t in themes))

    def test_deep_mode_does_not_inject_evm_or_crypto_preset_tracks(self):
        class _AnyClass(_TracksShim):
            _deep_discovery = True
            _target_class = "CRYPTO_LIB"

            def _enumerate_targets(self, limit=180):
                return [
                    "src/protocol/engine.cpp",
                    "src/protocol/client.cpp",
                    "src/crypto/proof.c",
                    "contracts/Primary.sol",
                    "contracts/router/Router.sol",
                ]

        themes = [t["theme"] for t in _AnyClass()._fallback_tracks()]
        forbidden = {
            "entrypoint-order-lifecycle",
            "conduit-approval-routing",
            "composition-reference-differential",
            "bam-ecdsa-proof-and-share-binding",
            "cmp-ecdsa-mta-paillier-signing",
            "paillier-zkp-parser-canonicality",
        }
        self.assertTrue(all(t.startswith("derived:") for t in themes))
        self.assertFalse(forbidden.intersection(themes))

    def test_parse_json_prefers_complete_tracks_object_after_status_object(self):
        parsed = _parse_json_object(
            '{"status":"working"}\n'
            '{"summary":"s","tracks":[{"theme":"engine","focus_files":["src/protocol/engine.cpp"]}]}'
        )
        self.assertEqual(parsed["summary"], "s")
        self.assertEqual(parsed["tracks"][0]["theme"], "engine")


class TestRateLimitHeadroom(unittest.TestCase):
    def test_no_downgrade_flag_is_read_in_session(self):
        import inspect
        from p1hunt.agents import claude_session
        src = inspect.getsource(claude_session)
        # the flag must gate the candidate-model list (no silent Opus->Sonnet when set)
        self.assertIn("P1HUNT_NO_MODEL_DOWNGRADE", src)
        self.assertIn("no_downgrade", src)


class TestScopeNotePropagation(unittest.TestCase):
    def test_hunters_receive_engagement_specific_scope_note(self):
        import inspect
        from p1hunt.agents.claude_swarm import ClaudeSwarm

        src = inspect.getsource(ClaudeSwarm.hunt)
        self.assertIn('getattr(self.scope, "scope_note", "")', src)
        self.assertIn("h.scope_note =", src)
        self.assertIn("so.scope_note =", src)


class TestParentAScopeRetry(unittest.TestCase):
    def _swarm(self, tmp: str) -> ClaudeSwarm:
        from p1hunt.config import Config
        from p1hunt.main import build_scope
        from p1hunt.orchestrator.blackboard import Blackboard
        from p1hunt.orchestrator.bus import MessageBus
        from p1hunt.orchestrator.event_log import EventLog

        log = EventLog()
        cfg = Config()
        cfg.use_claude = True
        cfg.models.engine = "codex"
        cfg.models.discovery_engine = "codex"
        return ClaudeSwarm(build_scope("retry-scope", tmp), tmp, config=cfg, bus=MessageBus(log),
                           blackboard=Blackboard(log), event_log=log)

    def test_scope_retries_non_json_parent_a_response_before_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "contracts").mkdir()
            Path(tmp, "contracts", "Primary.sol").write_text("contract Primary {}\n", encoding="utf-8")
            sw = self._swarm(tmp)

            class _Session:
                def __init__(self, text):
                    self.text = text

                async def run(self, *_args, **_kwargs):
                    return SessionResult(ok=True, text=self.text, tool_calls=2)

            sessions = [
                _Session("I mapped the repo but forgot the requested JSON."),
                _Session(
                    '{"summary":"s","target_class":"EVM_CONTRACT","workspace_root":".",'
                    '"critical_means":"asset loss","tracks":[{"theme":"orders",'
                    '"subsystem":"orders","focus_files":["contracts/Primary.sol"],'
                    '"invariants":["attacker must never fill cancelled order"],'
                    '"investigate":["cancel then fulfill"]}]}'
                ),
            ]

            with mock.patch("p1hunt.agents.claude_session.make_session",
                            side_effect=lambda **_kwargs: sessions.pop(0)):
                plan = asyncio.run(sw._scope(None))

            self.assertEqual(plan["summary"], "s")
            self.assertEqual(plan["tracks"][0]["subsystem"], "orders")
            events = [e.data.get("event") for e in sw.log.events if e.agent == "parent_a"]
            self.assertIn("scope_parse_retry", events)
            self.assertNotIn("scope_repo_derived_fallback", events)


if __name__ == "__main__":
    unittest.main()
