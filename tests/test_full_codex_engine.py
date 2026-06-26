"""Full-swarm engine selection: with P1HUNT_ENGINE=codex EVERY role runs on Codex (nothing depends
on Claude Code), via the make_session factory; plus the generic guarantee-breaking lens."""

import os
import types
import unittest
from unittest import mock

from p1hunt.agents.claude_session import make_session, ClaudeSession, engine_available
from p1hunt.agents.codex_session import CodexSession
from p1hunt.agents import claude_hunter, claude_swarm
from p1hunt.config import Config


_COMMON = dict(agent_name="x", on_event=lambda *a: None, guard_check=lambda *a: (True, "ok"),
               max_turns=8)


class TestEngineFactory(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("P1HUNT_ENGINE", None)

    def test_default_is_codex(self):
        os.environ.pop("P1HUNT_ENGINE", None)
        self.assertIsInstance(make_session(model="claude-opus-4-8", **_COMMON), CodexSession)

    def test_global_codex_routes_all_roles(self):
        os.environ["P1HUNT_ENGINE"] = "codex"
        # any role, given only a claude model, still becomes a CodexSession
        self.assertIsInstance(make_session(model="claude-opus-4-8", **_COMMON), CodexSession)

    def test_explicit_engine_arg_overrides_env(self):
        os.environ["P1HUNT_ENGINE"] = "codex"
        self.assertIsInstance(make_session(model="m", engine="claude", **_COMMON), ClaudeSession)
        os.environ["P1HUNT_ENGINE"] = "claude"
        self.assertIsInstance(make_session(model="m", engine="codex", **_COMMON), CodexSession)

    def test_engine_available(self):
        self.assertIsInstance(engine_available("codex"), bool)
        self.assertIsInstance(engine_available("claude"), bool)


class TestNoClaudeSessionLeftInConstructors(unittest.TestCase):
    """Every role must build sessions through the factory, so codex-global swaps them all."""
    def test_no_direct_ClaudeSession_constructor_calls(self):
        import inspect
        from p1hunt import intake_agent
        from p1hunt.agents import fuzz_engine
        for mod in (claude_hunter, claude_swarm, fuzz_engine, intake_agent):
            src = inspect.getsource(mod)
            self.assertNotIn("ClaudeSession(", src,
                             f"{mod.__name__} still constructs ClaudeSession directly (must use make_session)")


class TestConfigGlobalEngine(unittest.TestCase):
    def tearDown(self):
        for k in ("P1HUNT_ENGINE", "P1HUNT_DISCOVERY_ENGINE", "P1HUNT_USE_AGENT",
                  "P1HUNT_USE_CLAUDE", "P1HUNT_RUN_MODE"):
            os.environ.pop(k, None)

    def test_global_codex_makes_discovery_follow(self):
        os.environ.pop("P1HUNT_DISCOVERY_ENGINE", None)
        m = Config.from_env().models
        self.assertEqual(m.engine, "codex")
        self.assertEqual(m.discovery_engine, "codex")  # follows the global engine

    def test_hybrid_discovery_override(self):
        os.environ["P1HUNT_ENGINE"] = "claude"
        os.environ["P1HUNT_DISCOVERY_ENGINE"] = "codex"
        m = Config.from_env().models
        self.assertEqual(m.engine, "claude")
        self.assertEqual(m.discovery_engine, "codex")

    def test_active_mode_kept_when_selected_engine_is_runnable(self):
        os.environ["P1HUNT_ENGINE"] = "codex"
        os.environ["P1HUNT_RUN_MODE"] = "active"
        with mock.patch("p1hunt.agents.claude_session.engine_available", return_value=True):
            cfg = Config.from_env()
        self.assertTrue(cfg.use_claude)
        self.assertEqual(cfg.run_mode, "active")

    def test_active_mode_downgrades_only_when_no_agent_brain_runs(self):
        os.environ["P1HUNT_ENGINE"] = "codex"
        os.environ["P1HUNT_RUN_MODE"] = "active"
        with mock.patch("p1hunt.agents.claude_session.engine_available", return_value=False):
            cfg = Config.from_env()
        self.assertFalse(cfg.use_claude)
        self.assertEqual(cfg.run_mode, "dry_run")

    def test_legacy_discovery_codex_promotes_whole_cli_run(self):
        from p1hunt.main import _configure_cli_engine
        cfg = Config()
        cfg.models.engine = "claude"
        cfg.models.discovery_engine = "claude"
        args = types.SimpleNamespace(engine=None, discovery_engine="codex",
                                     offline=False, no_claude=False)
        with mock.patch("p1hunt.agents.claude_session.engine_available", return_value=True):
            _configure_cli_engine(cfg, args)
        self.assertEqual(cfg.models.engine, "codex")
        self.assertEqual(cfg.models.discovery_engine, "codex")
        self.assertTrue(cfg.use_claude)

    def test_cli_engine_override_downgrades_active_when_engine_unavailable(self):
        from p1hunt.main import _configure_cli_engine
        cfg = Config()
        cfg.run_mode = "active"
        args = types.SimpleNamespace(engine="codex", discovery_engine=None,
                                     offline=False, no_claude=False)
        with mock.patch("p1hunt.agents.claude_session.engine_available", return_value=False):
            _configure_cli_engine(cfg, args)
        self.assertFalse(cfg.use_claude)
        self.assertEqual(cfg.run_mode, "dry_run")

    def test_offline_cli_switch_downgrades_active_mode(self):
        from p1hunt.main import _configure_cli_engine
        cfg = Config()
        cfg.run_mode = "active"
        args = types.SimpleNamespace(engine=None, discovery_engine=None,
                                     offline=True, no_claude=False)
        _configure_cli_engine(cfg, args)
        self.assertFalse(cfg.use_claude)
        self.assertEqual(cfg.run_mode, "dry_run")


class TestGuaranteeBreakingLens(unittest.TestCase):
    """The REAL (non-preset) fix: derive each component's guarantees and break them — class-agnostic,
    not an enumerated bug list. Must NOT hardcode a specific bug class."""
    def test_hunt_prompt_drives_guarantee_breaking_not_bug_shapes(self):
        p = claude_hunter.hunt_prompt("trusted-execution", "extract the key", 1, [], None, None)
        self.assertIn("BREAK A GUARANTEE", p)
        self.assertIn("DERIVE", p)
        # explicitly tells it not to limit itself to known bug shapes (anti-preset)
        self.assertTrue("pattern-match" in p.lower() or "shapes you already know" in p.lower())

    def test_recon_derives_guarantees(self):
        s = ClaudeSwarm_scope_prompt_text()
        self.assertIn("DERIVE THE GUARANTEES", s)
        self.assertIn("MINE THE TESTS", s)
        self.assertIn("recon_strategy", s)
        self.assertNotIn("RESEARCH HISTORICAL PATTERNS", s)
        self.assertNotIn("known critical bug", s.lower())

    def test_hunt_prompt_does_not_render_known_pattern_feed(self):
        p = claude_hunter.hunt_prompt(
            "component", "top impact", 1, [], None, None,
            known_patterns=["external call before state update"],
            static_leads=["preset scanner hit"],
        )
        self.assertNotIn("external call before state update", p)
        self.assertNotIn("preset scanner hit", p)

    def test_web_map_prompt_is_black_box_not_repo_mapping(self):
        p = claude_hunter.web_map_prompt(
            "exact flag endpoint",
            "retrieve protected proof artifact",
            base_urls=["http://192.0.2.10/flag.txt"],
            egress_hosts=["192.0.2.10"],
            investigate=["determine baseline status"],
            scope_note="Special live target only.",
        )
        self.assertIn("black-box WEB/API", p)
        self.assertIn("Do NOT map a repository", p)
        self.assertIn("subdomain enumeration is not", p)
        self.assertIn("URL, method, timestamp/status/header/body", p)
        self.assertIn("Source file:line citations are not required", p)

    def test_resteer_is_coverage_and_novelty_driven(self):
        import inspect
        from p1hunt.agents import claude_swarm
        src = inspect.getsource(claude_swarm.ClaudeSwarm._resteer_prompt)
        self.assertIn("COVERAGE", src)
        self.assertIn("NOVELTY", src)
        self.assertIn("UN-ATTACKED", src)

    def test_live_blackboard_has_high_severity_fastlane(self):
        import inspect
        from p1hunt.agents import claude_swarm
        src = inspect.getsource(claude_swarm.ClaudeSwarm.hunt)
        self.assertIn("P1HUNT_LIVE_FASTLANE", src)
        self.assertIn("live_fastlane", src)
        self.assertIn("high/critical blackboard post", src)

    def test_fallback_file_ranker_has_no_protocol_presets(self):
        banned = {"mta", "paillier", "ring_pedersen", "ecdsa", "eddsa", "schnorr", "cosigner"}
        self.assertFalse(banned & set(claude_swarm.ClaudeSwarm._SEC_KEYWORDS))

    def test_exploit_dev_breaks_a_property(self):
        from p1hunt.agents.claude_hunter import exploit_dev_prompt, ClaudeFinding
        f = ClaudeFinding(title="t", severity="high", file="f", line=1, lens="x",
                          root_cause="r", reproduction="r", counterfactual="c", confidence="m")
        self.assertIn("SECURITY GUARANTEE", exploit_dev_prompt(f, ""))


class TestAttributionGate(unittest.TestCase):
    """Gate hardening: a 'critical' whose exploit relies on a self-supplied impl of a pure-virtual
    (=0) interface (integrator responsibility) must NOT be confirmed — stops the recurring
    over-confirmation of the presig-reuse / persistency class."""
    def test_prompt_requires_attribution(self):
        from p1hunt.agents.claude_hunter import exploit_dev_prompt, ClaudeFinding
        f = ClaudeFinding(title="t", severity="high", file="f", line=1, lens="x",
                          root_cause="r", reproduction="r", counterfactual="c", confidence="m")
        p = exploit_dev_prompt(f, "")
        self.assertIn("relies_on_abstract_interface", p)
        self.assertIn("pure-virtual", p)

    def test_develop_enforces_attribution_gate(self):
        import inspect
        from p1hunt.agents.claude_hunter import ClaudeExploitDeveloper
        src = inspect.getsource(ClaudeExploitDeveloper.develop)
        if "relies_on_abstract_interface" not in src:
            src = inspect.getsource(inspect.getmodule(ClaudeExploitDeveloper))
        self.assertIn("relies_on_abstract_interface", src)
        self.assertIn("not abstract", src)  # achieved = ... and not abstract


def ClaudeSwarm_scope_prompt_text() -> str:
    """Render _scope_prompt without constructing a full swarm (bind the method to a tiny shim)."""
    import inspect
    from p1hunt.agents import claude_swarm
    return inspect.getsource(claude_swarm.ClaudeSwarm._scope_prompt)


if __name__ == "__main__":
    unittest.main()
