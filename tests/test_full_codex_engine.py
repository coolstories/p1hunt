"""Full-swarm engine selection: with P1HUNT_ENGINE=codex EVERY role runs on Codex (nothing depends
on Claude Code), via the make_session factory; plus the cross-invocation/replay reasoning lens that
was the gap behind the missed Paillier-Blum re-randomization P1."""

import os
import unittest

from p1hunt.agents.claude_session import make_session, ClaudeSession, engine_available
from p1hunt.agents.codex_session import CodexSession
from p1hunt.agents import claude_hunter, claude_swarm
from p1hunt.config import Config


_COMMON = dict(agent_name="x", on_event=lambda *a: None, guard_check=lambda *a: (True, "ok"),
               max_turns=8)


class TestEngineFactory(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("P1HUNT_ENGINE", None)

    def test_default_is_claude(self):
        os.environ.pop("P1HUNT_ENGINE", None)
        self.assertIsInstance(make_session(model="claude-opus-4-8", **_COMMON), ClaudeSession)

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
        for mod in (claude_hunter, claude_swarm):
            src = inspect.getsource(mod)
            self.assertNotIn("ClaudeSession(", src,
                             f"{mod.__name__} still constructs ClaudeSession directly (must use make_session)")


class TestConfigGlobalEngine(unittest.TestCase):
    def tearDown(self):
        for k in ("P1HUNT_ENGINE", "P1HUNT_DISCOVERY_ENGINE", "P1HUNT_USE_CLAUDE"):
            os.environ.pop(k, None)

    def test_global_codex_makes_discovery_follow(self):
        os.environ["P1HUNT_ENGINE"] = "codex"
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

    def test_resteer_is_coverage_and_novelty_driven(self):
        import inspect
        from p1hunt.agents import claude_swarm
        src = inspect.getsource(claude_swarm.ClaudeSwarm._resteer_prompt)
        self.assertIn("COVERAGE", src)
        self.assertIn("NOVELTY", src)
        self.assertIn("UN-ATTACKED", src)

    def test_exploit_dev_breaks_a_property(self):
        from p1hunt.agents.claude_hunter import exploit_dev_prompt, ClaudeFinding
        f = ClaudeFinding(title="t", severity="high", file="f", line=1, lens="x",
                          root_cause="r", reproduction="r", counterfactual="c", confidence="m")
        self.assertIn("SECURITY GUARANTEE", exploit_dev_prompt(f, ""))


def ClaudeSwarm_scope_prompt_text() -> str:
    """Render _scope_prompt without constructing a full swarm (bind the method to a tiny shim)."""
    import inspect
    from p1hunt.agents import claude_swarm
    return inspect.getsource(claude_swarm.ClaudeSwarm._scope_prompt)


if __name__ == "__main__":
    unittest.main()
