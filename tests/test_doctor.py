"""`p1hunt doctor`: would a hunt started right now MEAN anything?

Every expensive failure this project has had was the same shape -- one dead layer behind a
healthy-looking run, producing an honest-looking nothing that reads as "no bugs here":

  * the provider's safety classifier refused the planning brief, then later refused all
    five hunters and the fuzzer, and the hunt still reported success;
  * Playwright's sync api could not start inside the event loop, so live recon never ran
    and the planner silently got no facts at all;
  * a stale pytest plugin killed every proof harness before collection, which caps the
    confirmed count at zero no matter how good the hunt is.

A hunt is long and costs real money, so every one of those is worth checking first. What
these tests hold is the property that makes the command trustworthy: **it never reports
health it did not verify**, and every non-OK verdict carries an actionable fix. A doctor
that says GO when a layer is dead is worse than no doctor, because it converts an unknown
into false confidence.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from p1hunt import doctor as D


class TestVerdictsAreHonest(unittest.TestCase):
    def test_a_check_that_was_not_performed_is_not_ok(self):
        """The core property. 'Unchecked' and 'healthy' must never be the same answer."""
        rep = D.run_doctor(skip_browser=True)
        browser = next(c for c in rep.checks if c.name.startswith("browser"))
        self.assertEqual(browser.verdict, D.UNCHECKED)
        self.assertFalse(browser.ok)
        self.assertIn("skipped", browser.detail)

    def test_every_non_ok_check_carries_a_fix_or_an_impact(self):
        """A complaint without an action is noise the operator learns to ignore."""
        rep = D.run_doctor(skip_browser=True)
        for c in rep.checks:
            if c.verdict in (D.FAIL, D.WARN):
                with self.subTest(check=c.name):
                    self.assertTrue(c.fix or c.impact,
                                    f"{c.name} failed with no fix and no impact")

    def test_go_is_false_when_anything_fails(self):
        rep = D.Report(checks=[D.Check("a", D.OK), D.Check("b", D.FAIL, fix="x")])
        self.assertFalse(rep.go)
        self.assertEqual(len(rep.failures), 1)

    def test_a_warning_alone_does_not_block_a_run(self):
        """WARN means degraded, not dead. Conflating them would make the gate useless."""
        rep = D.Report(checks=[D.Check("a", D.OK), D.Check("b", D.WARN, fix="x")])
        self.assertTrue(rep.go)
        self.assertEqual(len(rep.warnings), 1)

    def test_an_unchecked_item_does_not_block_but_is_reported(self):
        rep = D.Report(checks=[D.Check("a", D.OK), D.Check("b", D.UNCHECKED, fix="probe it")])
        self.assertTrue(rep.go)
        self.assertIn("GO, with gaps", D.render(rep))


class TestTheNoGoMessagePreemptsTheMisreading(unittest.TestCase):
    """The whole point is to stop a meaningless clean result being believed."""

    def test_no_go_says_the_run_would_still_report_success(self):
        rep = D.Report(checks=[D.Check("pytest: runs a test", D.FAIL,
                                       "broken", fix="f", impact="i")])
        text = D.render(rep)
        self.assertIn("NO-GO", text)
        self.assertIn("would still", text)
        self.assertIn("report success", text)
        self.assertIn("would mean nothing about the target", text)

    def test_the_fix_and_the_cost_are_both_printed(self):
        rep = D.Report(checks=[D.Check("x", D.FAIL, "d",
                                       fix="DO THIS THING", impact="LOSE THAT THING")])
        text = D.render(rep)
        self.assertIn("DO THIS THING", text)
        self.assertIn("LOSE THAT THING", text)

    def test_a_fully_clean_report_says_go_plainly(self):
        rep = D.Report(checks=[D.Check("a", D.OK), D.Check("b", D.OK)])
        self.assertIn("GO. Every check passed.", D.render(rep))


class TestRoleAcceptanceIsReadNeverAssumed(unittest.TestCase):
    """A refused role returns no findings, which is indistinguishable from a clean result.

    So acceptance is the one thing the doctor must never guess about -- it costs a session
    per role to measure, so the doctor reads the probe artifact and says UNCHECKED when
    there is none, with the command to produce one.
    """

    def _probe_file(self, rows) -> Path:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(rows, tmp)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return Path(tmp.name)

    def test_a_missing_probe_is_unchecked_with_the_command_to_run(self):
        c = D.check_engine_roles("codex", Path("/definitely/not/here.json"))
        self.assertEqual(c.verdict, D.UNCHECKED)
        self.assertIn("probe_refusal.py", c.fix)
        self.assertIn("unknown", c.impact)

    def test_all_accepted_is_ok(self):
        f = self._probe_file([{"prompt": "web_hunt", "verdict": "ACCEPTED"},
                              {"prompt": "materialize", "verdict": "ACCEPTED"}])
        c = D.check_engine_roles("claude", f)
        self.assertEqual(c.verdict, D.OK)

    def test_a_refused_hunting_role_is_fatal(self):
        f = self._probe_file([{"prompt": "web_hunt", "verdict": "REFUSED"},
                              {"prompt": "web_map", "verdict": "ACCEPTED"}])
        c = D.check_engine_roles("codex", f)
        self.assertEqual(c.verdict, D.FAIL)
        self.assertIn("cannot produce a confirmed finding", c.impact)
        self.assertIn("will not help", c.fix)

    def test_a_truncated_proof_role_is_fatal_too(self):
        """TRUNCATED is not acceptance: a half-written harness proves nothing."""
        f = self._probe_file([{"prompt": "materialize", "verdict": "TRUNCATED"}])
        self.assertEqual(D.check_engine_roles("claude", f).verdict, D.FAIL)

    def test_an_empty_proof_role_is_fatal_too(self):
        f = self._probe_file([{"prompt": "repair", "verdict": "EMPTY"}])
        self.assertEqual(D.check_engine_roles("claude", f).verdict, D.FAIL)

    def test_a_degraded_non_critical_role_is_only_a_warning(self):
        """fuzz and the triage roles are enhancers; losing them is not losing the hunt."""
        f = self._probe_file([{"prompt": "web_hunt", "verdict": "ACCEPTED"},
                              {"prompt": "fuzz", "verdict": "REFUSED"}])
        c = D.check_engine_roles("codex", f)
        self.assertEqual(c.verdict, D.WARN)
        self.assertIn("rest of the hunt still runs", c.impact)

    def test_a_corrupt_probe_artifact_is_unchecked_not_ok(self):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        tmp.write("{not json")
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        self.assertEqual(D.check_engine_roles("codex", Path(tmp.name)).verdict, D.UNCHECKED)


class TestTheToolchainCheckActuallyExecutes(unittest.TestCase):
    def test_a_broken_pytest_is_fatal_with_its_cost_stated(self):
        broken = {"ok": False, "detail": "exit 1: ModuleNotFoundError", "fix": "repair it",
                  "broken_plugin": "", "addopts": "", "tool": "pytest"}
        with mock.patch("p1hunt.runners.base.preflight_pytest", lambda **k: broken):
            c = D.check_pytest_runs()
        self.assertEqual(c.verdict, D.FAIL)
        self.assertIn("capped at zero", c.impact)

    def test_a_self_healed_pytest_is_a_warning_that_says_it_is_scoped(self):
        """The workaround touches p1hunt's subprocesses only; say so, since disabling
        someone's plugin is a real intrusion."""
        healed = {"ok": True, "detail": "the 'anchorpy' plugin raises on import",
                  "fix": "", "broken_plugin": "anchorpy", "addopts": "-p no:anchorpy",
                  "tool": "pytest"}
        with mock.patch("p1hunt.runners.base.preflight_pytest", lambda **k: healed):
            c = D.check_pytest_runs()
        self.assertEqual(c.verdict, D.WARN)
        self.assertIn("-p no:anchorpy", c.fix)
        self.assertIn("harness processes only", c.fix)
        self.assertIn("does not touch your environment", c.impact)

    def test_a_clean_pytest_is_ok_with_no_fix(self):
        clean = {"ok": True, "detail": "clean", "fix": "", "broken_plugin": "",
                 "addopts": "", "tool": "pytest"}
        with mock.patch("p1hunt.runners.base.preflight_pytest", lambda **k: clean):
            c = D.check_pytest_runs()
        self.assertEqual(c.verdict, D.OK)


class TestTheWorkaroundIsScopedAndVerified(unittest.TestCase):
    """Disabling a third-party plugin is an intrusion, so it is narrow and never a guess."""

    def test_the_preflight_only_reports_a_flag_it_verified(self):
        from p1hunt.runners import base as B

        calls = []
        real = B.subprocess.run

        def _spy(argv, **kw):
            calls.append((kw.get("env") or {}).get("PYTEST_ADDOPTS"))
            return real(argv, **kw)

        with mock.patch.object(B.subprocess, "run", _spy):
            res = B.preflight_pytest()
        if res.get("addopts"):
            # It must have RE-RUN pytest with the flag before claiming it works.
            self.assertIn(res["addopts"],
                          [c for c in calls if c] or [""],
                          f"workaround was not verified by a second run; calls={calls}")

    def test_the_workaround_is_applied_only_to_pytest_invocations(self):
        from p1hunt.runners import base as B
        src = __import__("inspect").getsource(B.run_command)
        self.assertIn('argv[0] == "pytest"', src)
        self.assertIn("pytest_plugin_workaround", src)

    def test_the_workaround_is_announced_not_applied_silently(self):
        from p1hunt.runners import base as B
        src = __import__("inspect").getsource(B.run_command)
        self.assertIn("pytest_plugin_workaround", src)
        self.assertIn("harness processes", src)


class TestDoctorIsUsableAsAGate(unittest.TestCase):
    def test_the_cli_returns_nonzero_on_no_go(self):
        import inspect

        from p1hunt import main as M
        src = inspect.getsource(M._doctor)
        self.assertIn("return 0 if rep.go else 1", src)

    def test_the_command_is_registered(self):
        from p1hunt import main as M
        src = __import__("inspect").getsource(M.main)
        self.assertIn('sub.add_parser(\n        "doctor"', src)

    def test_a_real_pass_does_not_raise(self):
        """The doctor must never be the thing that breaks; it is a diagnostic."""
        rep = D.run_doctor(skip_browser=True)
        self.assertTrue(rep.checks)
        self.assertIsInstance(D.render(rep, engine="codex"), str)


if __name__ == "__main__":
    unittest.main()
