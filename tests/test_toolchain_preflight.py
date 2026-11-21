"""Does the hunt notice when it CANNOT prove anything?

`reproduced=True` from a class runner is the only thing in this package that promotes a
finding to confirmed. So a toolchain that cannot execute a harness is a hard ceiling of
zero confirmed findings — and nothing else about the run looks wrong. The agents reason,
harnesses get written, the runner is invoked, and every result comes back ran=False with
an infrastructure note buried in one event payload.

That is not a hypothetical. A measurement run against the local range hit it: a stale
`anchorpy` pytest plugin, whose `solders` dependency no longer exports the module it
imports, made `pytest` exit 1 during plugin loading. Every harness would have died before
collecting a test. The per-finding classification was CORRECT — INFRASTRUCTURE ERROR,
ran=False, stays a candidate — and that is precisely what made it invisible: one broken
harness looks like a bad harness, not a bad machine.

So the rule these tests hold is: a dead proof layer must be as loud as a dead reasoning
layer, and a preflight must never return a reassuring answer about something it did not
actually test.
"""

from __future__ import annotations

import asyncio
import subprocess
import unittest
from unittest import mock

from p1hunt.runners import base as B


class TestPreflightProbesForReal(unittest.TestCase):
    def test_a_working_pytest_reports_ok(self):
        res = B.preflight_pytest()
        # This machine's pytest may legitimately be broken (that is how this was found),
        # so assert the SHAPE and the self-consistency, not the verdict.
        self.assertIn("ok", res)
        self.assertEqual(res["tool"], "pytest")
        if res["ok"]:
            self.assertEqual(res["fix"], "")
        else:
            self.assertTrue(res["fix"], "a failure must come with a fix the operator can act on")
            self.assertTrue(res["detail"])

    def test_it_actually_executes_a_test_rather_than_checking_the_binary_exists(self):
        """`pytest --version` succeeds on the broken install. Only running a test catches it."""
        calls = []
        real = subprocess.run

        def _spy(argv, **kw):
            calls.append(list(argv))
            return real(argv, **kw)

        with mock.patch.object(B.subprocess, "run", _spy):
            B.preflight_pytest()
        self.assertTrue(calls, "preflight ran no subprocess at all")
        argv = calls[0]
        self.assertEqual(argv[0], "pytest")
        self.assertNotIn("--version", argv)
        self.assertTrue(any(a.endswith(".py") for a in argv),
                        f"preflight must run a real test file, got {argv}")

    def test_a_missing_pytest_is_reported_not_crashed(self):
        with mock.patch.object(B, "tool_available", lambda t: False):
            res = B.preflight_pytest()
        self.assertFalse(res["ok"])
        self.assertIn("PATH", res["detail"])
        self.assertTrue(res["fix"])

    def test_a_plugin_that_raises_on_import_is_named_with_its_workaround(self):
        """The operator needs the plugin's NAME; 'pytest is broken' is not actionable."""
        fake = subprocess.CompletedProcess(
            args=["pytest"], returncode=1, stdout="",
            stderr=('File "/x/lib/python3.11/site-packages/anchorpy/__init__.py", line 6\n'
                    "ModuleNotFoundError: No module named 'solders.rpc'\n"))
        with mock.patch.object(B.subprocess, "run", lambda *a, **k: fake):
            res = B.preflight_pytest()
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_plugin"], "anchorpy")
        self.assertIn("-p no:anchorpy", res["fix"])
        self.assertIn("solders.rpc", res["detail"])

    def test_a_preflight_that_cannot_run_does_not_raise(self):
        def _boom(*a, **k):
            raise OSError("exec format error")

        with mock.patch.object(B.subprocess, "run", _boom):
            res = B.preflight_pytest()
        self.assertFalse(res["ok"])
        self.assertIn("exec format error", res["detail"])


class TestPreflightNeverReassuresAboutWhatItDidNotTest(unittest.TestCase):
    """The error this function exists to prevent, applied to itself."""

    def test_a_class_with_no_runner_is_not_ok(self):
        with mock.patch.object(B, "select_runner", lambda *a, **k: None):
            res = B.toolchain_preflight("WEB_API")
        self.assertFalse(res["ok"])
        self.assertFalse(res["checked"])
        self.assertIn("nothing can be reproduced", res["detail"])

    def test_a_non_pytest_class_is_marked_unchecked_rather_than_healthy(self):
        res = B.toolchain_preflight("EVM_CONTRACT")
        self.assertFalse(res["checked"], "must not claim to have probed the EVM toolchain")
        self.assertIn("not probed", res["detail"])

    def test_the_web_class_is_actually_checked(self):
        res = B.toolchain_preflight("WEB_API")
        self.assertTrue(res["checked"])
        self.assertEqual(res["tool"], "pytest")

    def test_the_generic_fallback_class_is_checked_too(self):
        """OTHER falls back to WebRunner, which drives pytest, so it must be probed."""
        self.assertTrue(B.toolchain_preflight("OTHER")["checked"])


class _Emitter:
    def __init__(self):
        self.events = []

    def __call__(self, agent, kind, data):
        self.events.append((agent, kind, data))

    def find(self, event):
        return [d for _, _, d in self.events if d.get("event") == event]


class TestTheHuntShoutsAboutIt(unittest.TestCase):
    """Wiring: the swarm must emit the HIGH-severity warning, not swallow the result."""

    def _swarm(self):
        from p1hunt.agents.claude_swarm import ClaudeSwarm

        s = object.__new__(ClaudeSwarm)
        s.name = "parent_a"
        s._target_class = "WEB_API"
        s._subclass = ""
        s._emit = _Emitter()
        return s

    def test_a_broken_toolchain_emits_high_severity_with_impact_and_fix(self):
        s = self._swarm()
        broken = {"checked": True, "ok": False, "tool": "pytest",
                  "broken_plugin": "anchorpy", "detail": "ModuleNotFoundError",
                  "fix": "run with PYTEST_ADDOPTS='-p no:anchorpy'"}
        with mock.patch("p1hunt.runners.base.toolchain_preflight", lambda *a, **k: broken):
            asyncio.run(s._preflight_runner_toolchain())
        warn = s._emit.find("toolchain_broken")
        self.assertEqual(len(warn), 1)
        self.assertEqual(warn[0]["severity"], "HIGH")
        self.assertEqual(warn[0]["broken_plugin"], "anchorpy")
        self.assertIn("capped at zero", warn[0]["impact"])
        # The operator's likeliest misreading, pre-empted in the payload itself.
        self.assertIn("no bugs here", warn[0]["impact"])
        self.assertIn("no:anchorpy", warn[0]["fix"])

    def test_a_healthy_toolchain_emits_a_quiet_ok(self):
        s = self._swarm()
        good = {"checked": True, "ok": True, "tool": "pytest", "detail": "clean",
                "fix": "", "broken_plugin": ""}
        with mock.patch("p1hunt.runners.base.toolchain_preflight", lambda *a, **k: good):
            asyncio.run(s._preflight_runner_toolchain())
        self.assertEqual(s._emit.find("toolchain_broken"), [])
        ok = s._emit.find("toolchain_preflight")
        self.assertEqual(len(ok), 1)
        self.assertTrue(ok[0]["ok"])

    def test_a_preflight_exception_is_reported_and_does_not_abort_the_hunt(self):
        s = self._swarm()

        def _boom(*a, **k):
            raise RuntimeError("preflight exploded")

        with mock.patch("p1hunt.runners.base.toolchain_preflight", _boom):
            asyncio.run(s._preflight_runner_toolchain())  # must not raise
        self.assertEqual(len(s._emit.find("toolchain_preflight_failed")), 1)

    def test_the_preflight_runs_before_the_hunt_arms_its_environment(self):
        """Ordering is the whole value: after the first round it has already cost money."""
        import inspect

        from p1hunt.agents.claude_swarm import ClaudeSwarm

        src = inspect.getsource(ClaudeSwarm)
        pre = src.index("await self._preflight_runner_toolchain()")
        arm = src.index("await self._arm_environment(tracks)")
        self.assertLess(pre, arm,
                        "the toolchain check must precede environment arming / hunting")


if __name__ == "__main__":
    unittest.main()
