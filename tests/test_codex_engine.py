"""Codex engine wiring: config defaults, CodexSession command/stream contract, and the hunter's
engine factory. No Codex CLI is spawned."""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from p1hunt.config import Config
from p1hunt.agents.codex_session import (
    CodexSession,
    codex_available,
    _looks_output_overflow,
    _progress_for_command,
    _progress_target,
    _with_io_discipline,
)
from p1hunt.agents.claude_session import ClaudeSession
from p1hunt.agents.claude_hunter import ClaudeHunter


class TestConfigSelector(unittest.TestCase):
    def tearDown(self):
        for k in ("P1HUNT_ENGINE", "P1HUNT_DISCOVERY_ENGINE", "P1HUNT_CODEX_MODEL",
                  "P1HUNT_CODEX_EFFORT", "P1HUNT_USE_AGENT", "P1HUNT_USE_CLAUDE"):
            os.environ.pop(k, None)

    def test_default_is_codex(self):
        os.environ.pop("P1HUNT_ENGINE", None)
        os.environ.pop("P1HUNT_DISCOVERY_ENGINE", None)
        m = Config.from_env().models
        self.assertEqual(m.engine, "codex")
        self.assertEqual(m.discovery_engine, "codex")

    def test_env_selects_codex_and_params(self):
        os.environ["P1HUNT_DISCOVERY_ENGINE"] = "codex"
        os.environ["P1HUNT_CODEX_MODEL"] = "gpt-5.5-codex"
        os.environ["P1HUNT_CODEX_EFFORT"] = "xhigh"
        m = Config.from_env().models
        self.assertEqual(m.discovery_engine, "codex")
        self.assertEqual(m.codex_model, "gpt-5.5-codex")
        self.assertEqual(m.codex_effort, "xhigh")

    def test_garbage_discovery_engine_falls_back_to_global_codex(self):
        os.environ["P1HUNT_DISCOVERY_ENGINE"] = "gpt4"
        self.assertEqual(Config.from_env().models.discovery_engine, "codex")


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
        self.assertIn("workspace-write", cmd)              # default OS sandbox jail
        self.assertIn("--add-dir", cmd)                    # user-local tooling roots for safe installs
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
        self.assertIn("danger-full-access", on)
        self.assertNotIn("sandbox_workspace_write.network_access=true", on)

    def test_install_off_omits_user_local_write_roots(self):
        class _Perms:
            allow_install = False
        cmd = CodexSession(agent_name="a", perms=_Perms())._build_cmd("/r", "/t")
        self.assertNotIn("--add-dir", cmd)


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

    def test_command_events_emit_operator_progress(self):
        os.environ["P1HUNT_VERBOSE_PROGRESS"] = "1"
        s = self._session()
        acc = []
        try:
            line = json.dumps({
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "command": "nl -ba src/common/cosigner/mta.cpp | sed -n '1125,1285p'",
                },
            })
            s._handle_line(line, acc)
            messages = [d for k, d in self.events if k == "message"]
            self.assertTrue(any(d.get("phase") == "progress" for d in messages))
            self.assertTrue(any("mta.cpp" in d.get("detail", "") for d in messages))
        finally:
            os.environ.pop("P1HUNT_VERBOSE_PROGRESS", None)

    def test_command_progress_is_quiet_by_default(self):
        s = self._session()
        acc = []
        line = json.dumps({
            "type": "item.completed",
            "item": {"type": "command_execution", "command": "curl -i https://example.test/"},
        })
        s._handle_line(line, acc)
        kinds = [k for k, _ in self.events]
        self.assertIn("tool_call", kinds)
        self.assertNotIn("message", kinds)

    def test_duplicate_command_events_are_dropped(self):
        s = self._session()
        acc = []
        line = json.dumps({
            "type": "item.completed",
            "item": {"type": "command_execution", "command": "pwd"},
        })
        s._handle_line(line, acc)
        s._handle_line(line, acc)
        self.assertEqual([k for k, _ in self.events].count("tool_call"), 1)
        self.assertEqual(s.tool_calls, 1)

    def test_progress_helpers_describe_observable_work(self):
        self.assertIn("searching", _progress_for_command("rg -n 'verify' src/common"))
        self.assertIn("reading source window", _progress_for_command("sed -n '1,120p' include/cosigner/types.h"))
        self.assertEqual(_progress_target("nl -ba src/x.cpp | sed -n '1,80p'"), "src/x.cpp")

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

    def test_output_overflow_is_classified_separately_from_rate_limit(self):
        self.assertTrue(_looks_output_overflow("Separator is found, but chunk is longer than limit"))
        self.assertTrue(_looks_output_overflow("Separator is not found, and chunk exceed the limit"))
        self.assertFalse(_looks_output_overflow("You've hit your usage limit"))

    def test_raw_output_overflow_exception_is_retryable(self):
        import inspect
        src = inspect.getsource(CodexSession._run_once)
        self.assertIn('tag = "output_overflow" if _looks_output_overflow(err) else err', src)

    def test_io_discipline_enforces_reasoned_bounded_code_reads(self):
        wrapped = _with_io_discipline("hunt this code", retry=True)
        self.assertIn("Reason your way to the code", wrapped)
        self.assertIn("Cite shipped file:line", wrapped)
        self.assertIn("No command may print more than about 120 lines", wrapped)
        self.assertEqual(wrapped.count("P1HUNT HARD IO"), 1)


class TestCodexJumpstart(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        import p1hunt.agents.codex_session as cs
        from p1hunt import session_limit
        self.cs = cs
        self.session_limit = session_limit
        self.old_throttle = session_limit.THROTTLE_FILE
        self.tmp = tempfile.TemporaryDirectory()
        session_limit.THROTTLE_FILE = Path(self.tmp.name) / "throttle.json"
        cs._MODEL_COOLDOWN.clear()

    def tearDown(self):
        self.cs._MODEL_COOLDOWN.clear()
        self.session_limit.THROTTLE_FILE = self.old_throttle
        self.tmp.cleanup()

    def test_stale_manual_clear_is_ignored(self):
        self.session_limit.THROTTLE_FILE.write_text(json.dumps({
            "throttled": False,
            "manual": True,
            "at": 1000.0,
        }), encoding="utf-8")
        self.assertFalse(self.cs._operator_jumpstart_requested(1001.0))

    async def test_manual_clear_cuts_codex_cooldown_immediately(self):
        events = []
        self.session_limit.THROTTLE_FILE.write_text(json.dumps({
            "throttled": False,
            "manual": True,
            "at": time.time(),
        }), encoding="utf-8")
        self.cs._mark_cooldown("", 240)
        s = self.cs.CodexSession(agent_name="poc_prover",
                                 on_event=lambda a, k, d: events.append((a, k, d)))
        slept = await s._await_cooldown_or_jumpstart(60)
        self.assertLess(slept, 1.0)
        self.assertEqual(self.cs.model_cooldowns(), {})
        self.assertTrue(any(d.get("event") == "model_status" and d.get("state") == "available"
                            for _a, _k, d in events))


class TestHunterFactory(unittest.TestCase):
    def _hunter(self):
        return ClaudeHunter("child_b1", theme="signing", model="claude-opus-4-8",
                            on_event=lambda *a: None, guard_check=lambda *a: (True, "ok"))

    def test_default_engine_is_codex_session(self):
        os.environ.pop("P1HUNT_ENGINE", None)
        self.assertIsInstance(self._hunter()._make_session(10), CodexSession)

    def test_explicit_claude_engine_yields_claude_session(self):
        h = self._hunter()
        h.discovery_engine = "claude"
        self.assertIsInstance(h._make_session(10), ClaudeSession)

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
