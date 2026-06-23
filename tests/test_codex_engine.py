"""The optional Codex (GPT-5.5-Codex xhigh) discovery engine: config wiring, the CodexSession
command/stream contract, and the hunter's engine factory. No Codex CLI is spawned."""

import os
import unittest

from p1hunt.config import Config
from p1hunt.agents.codex_session import CodexSession, codex_available
from p1hunt.agents.claude_session import ClaudeSession
from p1hunt.agents.claude_hunter import ClaudeHunter


class TestConfigSelector(unittest.TestCase):
    def tearDown(self):
        for k in ("P1HUNT_DISCOVERY_ENGINE", "P1HUNT_CODEX_MODEL", "P1HUNT_CODEX_EFFORT"):
            os.environ.pop(k, None)

    def test_default_is_claude(self):
        os.environ.pop("P1HUNT_DISCOVERY_ENGINE", None)
        self.assertEqual(Config.from_env().models.discovery_engine, "claude")

    def test_env_selects_codex_and_params(self):
        os.environ["P1HUNT_DISCOVERY_ENGINE"] = "codex"
        os.environ["P1HUNT_CODEX_MODEL"] = "gpt-5.5-codex"
        os.environ["P1HUNT_CODEX_EFFORT"] = "xhigh"
        m = Config.from_env().models
        self.assertEqual(m.discovery_engine, "codex")
        self.assertEqual(m.codex_model, "gpt-5.5-codex")
        self.assertEqual(m.codex_effort, "xhigh")

    def test_garbage_engine_falls_back_to_claude(self):
        os.environ["P1HUNT_DISCOVERY_ENGINE"] = "gpt4"
        self.assertEqual(Config.from_env().models.discovery_engine, "claude")


class TestCodexCommand(unittest.TestCase):
    def test_build_cmd_has_model_effort_sandbox_cwd(self):
        s = CodexSession(agent_name="child_b1", model="gpt-5.5-codex", effort="xhigh")
        cmd = s._build_cmd("/work/repo", "/tmp/last.txt")
        self.assertIn("codex", cmd)
        self.assertIn("exec", cmd)
        self.assertIn("--json", cmd)
        self.assertIn("--model", cmd)
        self.assertIn("gpt-5.5-codex", cmd)
        self.assertIn('model_reasoning_effort="xhigh"', cmd)
        self.assertIn("workspace-write", cmd)              # OS sandbox jail
        self.assertIn("/work/repo", cmd)                   # --cd workspace
        self.assertIn("/tmp/last.txt", cmd)

    def test_empty_model_omits_model_flag(self):
        # ChatGPT-account auth rejects explicit slugs -> empty model must omit --model (account default)
        cmd = CodexSession(agent_name="a", model="")._build_cmd("/r", "/t")
        self.assertNotIn("--model", cmd)

    def test_network_off_by_default_on_when_allowed(self):
        off = CodexSession(agent_name="a", allow_web=False)._build_cmd("/r", "/t")
        self.assertNotIn("sandbox_workspace_write.network_access=true", off)

        class _Perms:
            allow_network = True
        on = CodexSession(agent_name="a", allow_web=True, perms=_Perms())._build_cmd("/r", "/t")
        self.assertIn("sandbox_workspace_write.network_access=true", on)


class TestCodexStreamMapping(unittest.TestCase):
    def _session(self):
        self.events = []
        return CodexSession(agent_name="child_b1",
                            on_event=lambda a, k, d: self.events.append((k, d)))

    def test_maps_reasoning_command_and_message(self):
        s = self._session()
        acc = []
        s._handle_line('{"type":"item.completed","item":{"type":"reasoning","text":"thinking hard"}}', acc)
        s._handle_line('{"type":"item.completed","item":{"type":"command_execution","command":"grep -rn rand src"}}', acc)
        s._handle_line('{"type":"item.completed","item":{"type":"agent_message","text":"final answer"}}', acc)
        kinds = [k for k, _ in self.events]
        self.assertIn("thinking", kinds)
        self.assertIn("tool_call", kinds)
        self.assertIn("output", kinds)
        self.assertEqual(s.tool_calls, 1)
        self.assertIn("final answer", "".join(acc))

    def test_error_event_is_captured(self):
        s = self._session()
        acc = []
        s._handle_line('{"type":"error","message":"401 Unauthorized: Missing bearer"}', acc)
        self.assertIn("401", s._stream_error)
        self.assertEqual(acc, [])  # not treated as output

    def test_bad_json_is_ignored(self):
        s = self._session()
        acc = []
        s._handle_line("Codex v1.2 starting…", acc)   # non-JSON banner
        s._handle_line("", acc)
        self.assertEqual(self.events, [])


class TestModelFailover(unittest.TestCase):
    def setUp(self):
        import p1hunt.agents.codex_session as cs
        self.cs = cs
        cs._MODEL_COOLDOWN.clear()

    def _s(self):
        return self.cs.CodexSession(agent_name="child_b1", model="", fallback_models=["gpt-5.3-codex-spark"])

    def test_chain_primary_first(self):
        self.assertEqual(self._s()._model_chain(), ["", "gpt-5.3-codex-spark"])

    def test_failover_then_failback(self):
        s = self._s()
        self.assertEqual(s._pick_model(), "")                       # primary preferred
        self.cs._mark_cooldown("", 240)                             # GPT-5.5 rate-limited
        self.assertEqual(s._pick_model(), "gpt-5.3-codex-spark")    # -> fail over to Spark
        self.assertIn("", self.cs.model_cooldowns())
        self.cs._clear_cooldown("")                                 # GPT-5.5 quota resets (e.g. 23:11)
        self.assertEqual(s._pick_model(), "")                       # -> fail back to GPT-5.5

    def test_all_cooling_returns_none(self):
        s = self._s()
        self.cs._mark_cooldown("", 240)
        self.cs._mark_cooldown("gpt-5.3-codex-spark", 240)
        self.assertIsNone(s._pick_model())                          # -> wrapper will wait-and-retry

    def test_err_classification(self):
        self.assertEqual(self.cs._err_kind("You've hit your usage limit"), "rate_limited")
        self.assertEqual(self.cs._err_kind("429 Too Many Requests"), "rate_limited")
        self.assertEqual(self.cs._err_kind("401 Unauthorized"), "auth")
        self.assertEqual(self.cs._err_kind("model not supported"), "auth")
        self.assertEqual(self.cs._err_kind("random failure"), "")


class TestHunterFactory(unittest.TestCase):
    def _hunter(self):
        return ClaudeHunter("child_b1", theme="signing", model="claude-opus-4-8",
                            on_event=lambda *a: None, guard_check=lambda *a: (True, "ok"))

    def test_default_engine_is_claude_session(self):
        self.assertIsInstance(self._hunter()._make_session(10), ClaudeSession)

    def test_codex_engine_yields_codex_session(self):
        h = self._hunter()
        h.discovery_engine = "codex"
        h.codex_model = "gpt-5.5-codex"
        h.codex_effort = "xhigh"
        sess = h._make_session(10)
        self.assertIsInstance(sess, CodexSession)
        self.assertEqual(sess.model, "gpt-5.5-codex")
        self.assertEqual(sess.effort, "xhigh")

    def test_codex_available_is_bool(self):
        self.assertIsInstance(codex_available(), bool)


if __name__ == "__main__":
    unittest.main()
