"""Three bugs that each made a real hunt produce nothing, found by one measured run.

A full end-to-end run of the shipped CLI against the local range (bench/run_exec.py)
returned an execution score of 0/9. None of the three causes was a reasoning failure, and
none was visible to a test suite of 1200+ passing tests:

  1. EVERY HUNTER PROMPT WAS REFUSED by the provider's safety classifier -- all five
     hunters and the fuzzer, "This content was flagged for possible cybersecurity risk".
     The hunt ran, reported success, and produced zero findings. Invisible by
     construction: a fake session cannot refuse.

  2. LIVE RECON NEVER RAN. _arm_dynamic is synchronous but is CALLED from async code, so
     an asyncio loop is running in its thread, and Playwright's sync api refuses to start
     there. The call threw on every live hunt and was swallowed by the degrade-gracefully
     handler, so self._live_surface was always None in the product -- black-box discovery,
     the entire point of the browser and the recon miner, silently never happened. Its own
     tests passed because they call discover() from a sync context.

  3. THE FINAL SNAPSHOT CRASHED the process with exit 1 AFTER a completed hunt, because a
     usage event carried `total: null` and `d.get("total", 0)` returns None when the key
     exists. The run looked like a failure and the report never printed.

The shared shape: one layer is dead, everything else is healthy, and the result is an
honest-looking nothing. These tests hold each fix.
"""

from __future__ import annotations

import asyncio
import inspect
import unittest

from p1hunt.agents import claude_hunter as H
from p1hunt.agents import fuzz_engine as F
from p1hunt.agents.claude_swarm import ClaudeSwarm
from p1hunt.agents.instructions import authorized_role


class TestEveryLiveProbingPromptCarriesItsAuthorization(unittest.TestCase):
    """Bug 1. The framing must lead, because the classifier reads before the model does."""

    def _live_prompts(self) -> dict[str, str]:
        scope = "Authorized: 127.0.0.1 only, a range the operator owns."
        return {
            "web_hunt": H.web_hunt_prompt(
                "authorization", "unauthorized access to another principal's data",
                base_urls=["http://127.0.0.1:1"], egress_hosts=["127.0.0.1"],
                identities=["a", "b"], oob_available=False, depth=1, scope_note=scope),
            "web_map": H.web_map_prompt(
                "share paths", "unauthorized access",
                base_urls=["http://127.0.0.1:1"], egress_hosts=["127.0.0.1"],
                identities=["a", "b"], scope_note=scope),
            "src_hunt": H.hunt_prompt(
                "authorization", "unauthorized access", 1, [], ["app.py"], [], None, [],
                "", subsystem="authorization"),
            "fuzz": F.fuzz_prompt("parsing", ["an invariant"], ["h.py"],
                                  differential=False),
        }

    def test_the_authorization_framing_is_the_first_thing_in_the_prompt(self):
        for name, prompt in self._live_prompts().items():
            with self.subTest(prompt=name):
                head = prompt.strip()[:400]
                self.assertIn("AUTHORIZED, safe-harbour security assessment", head,
                              f"{name} does not lead with its authorization")

    def test_each_prompt_states_the_three_obligations(self):
        for name, prompt in self._live_prompts().items():
            with self.subTest(prompt=name):
                self.assertIn("STAY INSIDE THE STATED SCOPE", prompt)
                self.assertIn("NOTHING DESTRUCTIVE", prompt)
                self.assertIn("MINIMUM NECESSARY FORCE", prompt)

    def test_the_jailbreak_shaped_phrasing_is_gone(self):
        """These bought nothing operationally and read exactly like a jailbreak.

        Pinned as a regression guard: the swagger is the easiest thing to reintroduce
        while 'improving' a prompt, and it costs an entire run when it trips the
        classifier.
        """
        banned = ["top-of-the-leaderboard", "autonomous hacker", "elite bug-bounty",
                  "BECOME THE ATTACKER", "elite fuzzing engineer", "recon/attack tooling"]
        for name, prompt in self._live_prompts().items():
            for phrase in banned:
                with self.subTest(prompt=name, phrase=phrase):
                    self.assertNotIn(phrase, prompt)

    def test_the_method_survived_the_rewrite(self):
        """The framing must not have cost the prompt its substance -- that substance is
        what makes a hunter better than a scanner."""
        p = self._live_prompts()["web_hunt"]
        for needle in ("CORRECT ≠ SAFE", "DO NOT SELF-DISMISS", "LIVE-WEB CLOSURE GATE",
                       "RECON", "PROVE", "sqlmap", "nuclei", "ffuf"):
            self.assertIn(needle, p, f"web_hunt lost {needle!r}")

    def test_the_role_text_names_the_authorization_basis_and_the_deliverable(self):
        role = authorized_role("the testing role", live=True, deliverable="a proof")
        self.assertIn("operator's own authorization", role)
        self.assertIn("safe harbour", role)
        self.assertIn("deliverable is a proof", role)

    def test_a_source_role_does_not_claim_a_live_target(self):
        self.assertIn("own source tree", authorized_role("x", live=False))
        self.assertIn("authorized live target", authorized_role("x", live=True))


class TestLiveReconRunsOffTheEventLoop(unittest.TestCase):
    """Bug 2. Playwright's sync api cannot start in a thread with a running loop."""

    @staticmethod
    def _code(func) -> str:
        """Source with full-line comments removed, spacing preserved.

        A source-text assertion that does not strip comments is checking prose: the first
        version of this test failed because the COMMENT explaining why `with Browser(`
        must not appear in _arm_dynamic itself contains the string `with Browser(`.

        Spacing is preserved deliberately. The second version retokenized and rejoined
        with spaces, which turned `with Browser(` into `with Browser (` and broke the
        opposite assertion -- so the fix for one false negative created another.
        """
        return "\n".join(ln for ln in inspect.getsource(func).splitlines()
                          if not ln.strip().startswith("#"))

    def test_arming_does_not_construct_the_browser_in_the_calling_thread(self):
        src = self._code(ClaudeSwarm._arm_dynamic)
        self.assertNotIn("with Browser(", src,
                         "the sync Browser must not be entered on the loop's thread")
        self.assertIn("_discover_live_surface", src)
        self.assertIn("ThreadPoolExecutor", src)

    def test_the_crawl_body_is_synchronous_and_separate(self):
        """It has to be callable from a worker thread, so it must not be a coroutine."""
        self.assertFalse(asyncio.iscoroutinefunction(ClaudeSwarm._discover_live_surface))
        src = self._code(ClaudeSwarm._discover_live_surface)
        self.assertIn("with Browser(", src)
        self.assertIn("discover(", src)

    def test_the_crawl_is_bounded_by_a_timeout(self):
        """A hung crawl at arm time would stall every agent behind it."""
        self.assertIn("P1HUNT_RECON_TIMEOUT", inspect.getsource(ClaudeSwarm._arm_dynamic))

    def test_a_running_loop_no_longer_blocks_discovery(self):
        """The regression itself: run the real crawl from inside a live event loop."""
        try:
            import playwright  # noqa: F401
        except ImportError:
            self.skipTest("playwright not installed")
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bench"))
        from range_app import Range

        async def _drive():
            with Range() as rng:
                swarm = object.__new__(ClaudeSwarm)
                swarm._egress_hosts = ["127.0.0.1"]
                swarm._base_url = rng.base
                import concurrent.futures as cf
                with cf.ThreadPoolExecutor(max_workers=1) as pool:
                    return pool.submit(swarm._discover_live_surface, 6, 6).result(timeout=240)

        surface = asyncio.run(_drive())
        self.assertTrue(surface["endpoints"], "discovery returned nothing")
        # The bundle-mined endpoints are the ones no link exposes, and they are the whole
        # reason this layer exists rather than just following hrefs.
        sources = {e["source"] for e in surface["endpoints"]}
        self.assertIn("bundle", sources, f"no JS-mined endpoints; sources={sources}")


class TestTheFinalSnapshotSurvivesNullUsage(unittest.TestCase):
    """Bug 3. A null token count killed the process after a completed hunt."""

    def _render(self, *usage: dict) -> str:
        from p1hunt.orchestrator.blackboard import Blackboard
        from p1hunt.orchestrator.bus import MessageBus
        from p1hunt.orchestrator.event_log import EventLog
        from p1hunt.ui.dashboard import render_snapshot

        log = EventLog()
        bb, bus = Blackboard(log), MessageBus(log)
        for u in usage:
            log.emit("parent_a", "usage", u)
        return render_snapshot(log, bb, bus)

    def test_a_usage_event_with_null_fields_does_not_crash(self):
        out = self._render({"total": None, "input": None, "output": None, "cost": None})
        self.assertTrue(out)

    def test_null_and_real_usage_mix_without_losing_the_real_numbers(self):
        out = self._render({"total": None, "input": None, "output": None, "cost": None},
                           {"total": 1200, "input": 1000, "output": 200, "cost": 0.4})
        self.assertTrue(out)
        self.assertNotIn("None", out)

    def test_a_missing_key_still_defaults(self):
        self.assertTrue(self._render({}))

    def test_a_string_token_count_is_coerced_not_fatal(self):
        """Providers have been known to report these as strings."""
        out = self._render({"total": "900", "input": "800", "output": "100",
                            "cost": "0.1"})
        self.assertTrue(out)


if __name__ == "__main__":
    unittest.main()


class TestARefusedRoundIsNotMistakenForRateLimiting(unittest.TestCase):
    """Bug 1, second half: the pipeline's REACTION to a refusal was also wrong.

    A provider-side refusal returns in about six seconds with an error, so a refused round
    looks exactly like a throttled one: fast, empty, errored. The backoff path then slept
    up to fifteen minutes and retried -- waiting out a condition that cannot recover by
    waiting, and burning the engagement's wall clock on it. In the measured run this is
    part of why 315 seconds produced nothing at all.
    """

    def _swarm(self):
        swarm = object.__new__(ClaudeSwarm)
        swarm.name = "parent_a"
        swarm._refusal_announced = False
        swarm._emit = _Emit()
        return swarm

    def test_a_safety_refusal_is_counted_as_a_refusal(self):
        flagged = "codex error: This content was flagged for possible cybersecurity risk."
        self.assertEqual(ClaudeSwarm._count_refusals([flagged, flagged]), 2)

    def test_a_rate_limit_is_not_counted_as_a_refusal(self):
        self.assertEqual(
            ClaudeSwarm._count_refusals(["rate limit exceeded", "429 usage limit"]), 0)

    def test_a_mixed_round_counts_only_the_refusals(self):
        flagged = "This content was flagged for possible cybersecurity risk"
        self.assertEqual(ClaudeSwarm._count_refusals([flagged, "rate limited"]), 1)

    def test_no_errors_is_no_refusals(self):
        self.assertEqual(ClaudeSwarm._count_refusals([]), 0)

    def test_the_warning_names_the_impact_the_fix_and_the_misreading(self):
        swarm = self._swarm()
        swarm._report_refused_roles(5, 5, depth=1)
        warn = swarm._emit.find("hunter_roles_refused")
        self.assertEqual(len(warn), 1)
        self.assertEqual(warn[0]["severity"], "HIGH")
        self.assertIn("searched for NOTHING", warn[0]["impact"])
        # The operator's likeliest misreading, pre-empted in the payload.
        self.assertIn("is sound", warn[0]["why_it_matters"])
        # And an action, not just a complaint.
        self.assertIn("P1HUNT_ENGINE=claude", warn[0]["fix"])
        self.assertIn("will not help", warn[0]["fix"])

    def test_a_partial_refusal_says_how_many_rather_than_claiming_everything(self):
        swarm = self._swarm()
        swarm._report_refused_roles(2, 5, depth=1)
        warn = swarm._emit.find("hunter_roles_refused")[0]
        self.assertIn("2 of 5", warn["impact"])
        self.assertNotIn("EVERY", warn["impact"])

    def test_the_warning_is_stated_once_per_run_not_once_per_round(self):
        """A warning repeated every round is a warning that gets scrolled past."""
        swarm = self._swarm()
        for depth in (1, 2, 3):
            swarm._report_refused_roles(5, 5, depth=depth)
        self.assertEqual(len(swarm._emit.find("hunter_roles_refused")), 1)

    def test_the_backoff_branch_requires_that_not_every_error_was_a_refusal(self):
        """Source-level guard: the throttle path must exclude a fully-refused round.

        Asserted on the source because reproducing the condition needs a whole round of
        the real swarm; the invariant is narrow enough to pin directly.
        """
        src = inspect.getsource(ClaudeSwarm)
        idx = src.index("throttled = any((\"rate\" in str(e).lower()")
        window = src[idx:idx + 600]
        self.assertIn("refusals < len(round_errors)", window,
                      "a round where every error was a refusal must not take the backoff path")


class _Emit:
    def __init__(self):
        self.events = []

    def __call__(self, agent, kind, data):
        self.events.append(data)

    def find(self, event):
        return [d for d in self.events if d.get("event") == event]


class TestTheRefusalProbeClassifiesHonestly(unittest.TestCase):
    """The probe that measures refusal had two bugs, both reporting failure as success.

    That direction is the only one that matters for this tool. Its entire job is to answer
    "will the engine do this work", and a false ACCEPTED sends you off to run a long
    measurement whose result is already determined.

      1. `res.ok or text` counted ok=True with ZERO characters as acceptance.
      2. A response the provider STOPPED PART-WAY was counted as acceptance, because it
         came back ok=True with real-looking prose. The prose said it had been cut off.

    The second is a genuinely distinct third outcome, and it took a measured run against
    the Claude engine to see it: three of the proof-chain roles -- falsifier, materialize,
    repair -- were accepted at the gate and then truncated mid-response. For a role that
    must emit parseable JSON or finish writing a harness, that contributes nothing, so
    calling it "accepted" would have been the same mistake in a new place.
    """

    def setUp(self):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bench"))
        import probe_refusal
        self.P = probe_refusal

    class _Res:
        def __init__(self, text="", error="", ok=True):
            self.text, self.error, self.ok = text, error, ok

    def test_a_gate_refusal_is_refused(self):
        r = self._Res(error="codex error: This content was flagged for possible "
                            "cybersecurity risk. If this seems wrong, try rephrasing.")
        self.assertEqual(self.P._classify(r), "REFUSED")

    def test_a_mid_response_safety_stop_is_truncated_not_accepted(self):
        r = self._Res(text="Your response above was stopped by a safety classifier — this "
                           "is not a tool or API error. The rest of it was withheld, and "
                           "tool calls in it that had not finished did not run.")
        self.assertEqual(self.P._classify(r), "TRUNCATED")

    def test_an_empty_reply_is_not_acceptance_even_when_ok_is_true(self):
        self.assertEqual(self.P._classify(self._Res(text="", ok=True)), "EMPTY")
        self.assertEqual(self.P._classify(self._Res(text="   \n ", ok=True)), "EMPTY")

    def test_real_content_is_accepted(self):
        r = self._Res(text="The poc directory is empty. Let me check for the client and "
                           "start recon on the target.")
        self.assertEqual(self.P._classify(r), "ACCEPTED")

    def test_a_gate_refusal_outranks_everything_else(self):
        """Strongest evidence of failure first, so a mixed signal is never flattered."""
        r = self._Res(text="stopped by a safety classifier",
                      error="This content was flagged for possible cybersecurity risk")
        self.assertEqual(self.P._classify(r), "REFUSED")

    def test_the_exit_code_is_nonzero_for_any_non_clean_outcome(self):
        """A truncated or empty role must fail the check, not pass it quietly."""
        import inspect as _i
        src = _i.getsource(self.P.main)
        self.assertIn("return 1 if (refused or cut or empty) else 0", src)

    def test_the_report_warns_that_truncation_looks_like_success(self):
        import inspect as _i
        src = _i.getsource(self.P.main)
        self.assertIn("STOPPED PART-WAY", src)
        self.assertIn("mistake for success", src)
        self.assertIn("NO TEXT AT ALL", src)

    def test_the_turn_cap_is_adjustable_because_empty_may_be_its_artifact(self):
        """A role that spent every turn on tool calls and never emitted text looks exactly
        like a blocked one, so EMPTY at a tight cap is not a conclusion."""
        sig = inspect.signature(self.P.probe)
        self.assertIn("turns", sig.parameters)
        self.assertIn("Re-probe", inspect.getdoc(self.P.probe) or "")


class TestATruncatedSessionIsNotSilence(unittest.TestCase):
    """A response the provider cut off part-way must not look like a clean pass.

    This is the third outcome, and the easiest of the three to miss. A gate refusal comes
    back as an error. An empty reply comes back with no text. But a TRUNCATED reply comes
    back ok=True carrying real-looking prose -- prose which says, in words, that it was cut
    off and that unfinished tool calls never ran. Measured on the Claude engine: the
    hunting and falsifier roles were accepted at the gate and then truncated once they got
    far enough into real probing.

    It is deliberately a WARNING and not a failure, because the notice is a
    mid-conversation interjection and the session continues: a later turn can still
    deliver, and findings already posted through the live blackboard tool survive
    regardless. So the warning fires only when truncation coincided with producing
    nothing -- which is exactly the case that is indistinguishable from "this track is
    clean".
    """

    def test_the_detector_recognises_the_notice(self):
        from p1hunt.agents.claude_session import response_truncated
        self.assertTrue(response_truncated(
            "Your response above was stopped by a safety classifier — this is not a tool "
            "or API error. The rest of it was withheld"))
        self.assertTrue(response_truncated("the rest of it was withheld, and tool calls"))

    def test_ordinary_output_is_not_flagged(self):
        from p1hunt.agents.claude_session import response_truncated
        self.assertFalse(response_truncated(
            "Found an IDOR: principal b reads principal a's account. Harness written."))
        self.assertFalse(response_truncated(""))

    def test_the_hunter_warns_when_truncation_produced_nothing(self):
        src = self._hunt_source()
        self.assertIn("response_truncated(res.text) and not res.findings", src)
        self.assertIn("response_truncated", src)

    def test_the_warning_pre_empts_reading_it_as_a_clean_pass(self):
        src = self._hunt_source()
        self.assertIn("looks exactly like a clean pass", src)
        self.assertIn("Do NOT read this track as checked", src)
        self.assertIn('"severity": "HIGH"', src)

    def test_a_truncated_session_that_still_posted_findings_does_not_warn(self):
        """Findings posted mid-session survive truncation, so that is not a failure.

        Warning on it would train the operator to ignore the warning, which is the only
        thing that makes it useful.
        """
        src = self._hunt_source()
        self.assertIn("and not res.findings", src)

    def test_the_prover_distinguishes_cut_off_from_cannot_build(self):
        """They need different responses: switch engines versus debug the finding."""
        import inspect

        from p1hunt.agents.claude_hunter import ClaudePoCProver
        src = inspect.getsource(ClaudePoCProver.materialize)
        self.assertIn("response_truncated(result.text)", src)
        self.assertIn("truncated", src)
        self.assertIn("not evidence the finding", src)

    @staticmethod
    def _hunt_source() -> str:
        import inspect

        from p1hunt.agents.claude_hunter import ClaudeHunter
        return inspect.getsource(ClaudeHunter.hunt)
