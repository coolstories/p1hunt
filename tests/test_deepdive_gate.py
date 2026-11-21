"""Exploit-development depth phase: a critical is confirmed ONLY when a real attacker-win was
demonstrated (the finding's key is in _exploit_proven). A believed primitive — even one debate
upheld — is NOT a confirmed critical until the exploit is actually developed. This is the organ
that separates 'found an anomaly' from 'landed a critical'.
"""

import types
import unittest
import inspect

from p1hunt.agents.claude_hunter import ClaudeExploitDeveloper, exploit_dev_prompt
from p1hunt.agents.claude_session import ClaudeFinding
from p1hunt.agents.claude_swarm import ClaudeSwarm


def _f(title, severity="critical", file="src/mta.cpp"):
    return types.SimpleNamespace(title=title, severity=severity, file=file)


class _Shim:
    _finding_key = ClaudeSwarm._finding_key
    _confirmed_crits = ClaudeSwarm._confirmed_crits

    def __init__(self):
        self._debate_max = 0
        self.config = types.SimpleNamespace(use_claude=True)
        self._debate_rejected = set()
        self._debate_upheld = set()
        self._debate_downgraded = {}
        self._deepdive_on = True            # depth phase is the authority for criticals
        self._exploit_proven = set()


class _RubricShim:
    _rubric_priority_terms = ClaudeSwarm._rubric_priority_terms
    _candidate_priority_text = ClaudeSwarm._candidate_priority_text
    _rubric_lead_score = ClaudeSwarm._rubric_lead_score

    def __init__(self):
        self.scope = types.SimpleNamespace(
            severity_taxonomy={
                "Critical": "account takeover or fund withdrawal from protected assets",
                "High": "limited account impact",
            },
            scope_note="Prioritize proof of direct asset loss.",
            safe_harbor_text="",
        )


class TestDeepDiveGate(unittest.TestCase):
    def test_primitive_not_confirmed_until_exploit_proven(self):
        s = _Shim()
        f = _f("MtA decrypt-before-verify (primitive)")
        self.assertEqual(s._confirmed_crits([f]), [])        # believed primitive -> NOT a critical
        s._exploit_proven.add(s._finding_key(f))
        self.assertEqual(s._confirmed_crits([f]), [f])       # attacker-win demonstrated -> critical

    def test_debate_upheld_alone_is_not_enough_under_deepdive(self):
        s = _Shim()
        s._debate_max = 3
        s._debate_upheld = {s._finding_key(_f("X"))}          # passed debate...
        f = _f("X")
        self.assertEqual(s._confirmed_crits([f]), [])         # ...but no demonstrated exploit -> not critical

    def test_rejected_still_excluded(self):
        s = _Shim()
        f = _f("rejected one")
        s._exploit_proven.add(s._finding_key(f))
        s._debate_rejected.add(s._finding_key(f))             # reject overrides everything
        self.assertEqual(s._confirmed_crits([f]), [])

    def test_deepdive_priority_is_derived_from_program_rubric(self):
        s = _RubricShim()
        terms = s._rubric_priority_terms()
        asset_loss = types.SimpleNamespace(
            title="Fund withdrawal invariant bypass",
            severity="high",
            root_cause="missing authorization on asset withdrawal",
            counterfactual="attacker withdraws protected assets",
        )
        generic = types.SimpleNamespace(
            title="Cache invalidation edge case",
            severity="high",
            root_cause="stale metadata",
            counterfactual="minor user confusion",
        )
        self.assertIn("withdrawal", terms)
        self.assertGreater(s._rubric_lead_score(asset_loss, terms),
                           s._rubric_lead_score(generic, terms))

    def test_exploit_depth_is_backgrounded_not_round_blocking(self):
        src = inspect.getsource(ClaudeSwarm.hunt)
        self.assertIn("self._exploit_tasks", src)
        self.assertIn("asyncio.create_task(_run_exploit_depth", src)
        self.assertIn("exploit_background_started", src)

    def test_fastlane_does_not_cancel_child_discovery_by_default(self):
        src = inspect.getsource(ClaudeSwarm.hunt)
        self.assertIn('P1HUNT_FASTLANE_CUT_DISCOVERY", "0"', src)
        self.assertIn("child discovery continues", src)

    def test_fuzz_campaigns_are_backgrounded_not_child_round_blocking(self):
        src = inspect.getsource(ClaudeSwarm.hunt)
        self.assertIn("fuzz_background_started", src)
        self.assertIn("self._fuzz_tasks", src)
        self.assertIn("self._round_tasks = [asyncio.ensure_future(_run(h)) for h in hunters]", src)
        self.assertNotIn("self._round_tasks += [asyncio.ensure_future(_run_fuzz", src)

    def test_side_lanes_do_not_consume_child_discovery_slots(self):
        init_src = inspect.getsource(ClaudeSwarm.__init__)
        hunt_src = inspect.getsource(ClaudeSwarm.hunt)
        self.assertIn("self.side_sem", init_src)
        self.assertIn("P1HUNT_DEEP_DISCOVERY_CONCURRENCY", init_src)
        self.assertIn("async with self.side_sem", hunt_src)


class TestExploitDevPrompt(unittest.TestCase):
    def test_prompt_demands_full_chain_and_attribution(self):
        f = ClaudeFinding(title="t", severity="medium", file="mta.cpp", line=1, root_cause="r",
                          counterfactual="c", reproduction="x", lens="trusted-execution", confidence="high")
        p = exploit_dev_prompt(f, "Critical=key/rogue-sig <1000 aborts", ".p1hunt-poc").lower()
        # "WORLD-CLASS exploit developer and cryptanalyst" became "the proof-depth role"
        # when every model-facing prompt gained its authorization preamble. The METHOD is
        # what this test is really protecting, and all of it is still asserted below --
        # the dropped phrase was swagger that bought nothing and read like a jailbreak.
        for must in ("proof-depth", "attacker-win", "cryptanalysis", "lattice",
                     "multi-party", "shipped", "aborts", "impossibility"):
            self.assertIn(must, p)

    def test_prompt_demands_composition_and_independent_win_check_without_presets(self):
        f = ClaudeFinding(title="t", severity="medium", file="src/x.cpp", line=1, root_cause="r",
                          counterfactual="c", reproduction="x", lens="trusted-execution", confidence="high")
        p = exploit_dev_prompt(f, "Critical=top-tier target impact", ".p1hunt-poc").lower()
        for must in (
            "composition step",
            "honest target code",
            "non-degenerate",
            "independently check",
            "raw checker input",
            "fixed message/object/state",
        ):
            self.assertIn(must, p)
        for banned in ("fireblocks", "eddsa", "mta", "seaport", "paillier"):
            self.assertNotIn(banned, p)

    def test_prompt_robust_to_promoted_Finding_type(self):
        # The promoted Finding has NO .file/.line/.reproduction/.lens (those are ClaudeFinding's).
        # The depth phase runs on it too, so the prompt must not crash and must show a location.
        poc = types.SimpleNamespace(path="src/common/cosigner/mta.cpp")
        promoted = types.SimpleNamespace(title="MtA decrypt-before-verify", root_cause="rc",
                                         counterfactual="cf", severity_rationale="how it repro'd",
                                         poc=poc, severity="critical")
        p = exploit_dev_prompt(promoted, "Critical=key/rogue-sig <1000 aborts", ".p1hunt-poc")
        self.assertIn("MtA decrypt-before-verify", p)
        self.assertIn("mta.cpp", p)  # location resolved from poc.path

    def test_developer_is_constructible(self):
        dev = ClaudeExploitDeveloper("exploit_dev", model="m", on_event=lambda *a: None,
                                     guard_check=None, max_turns=60)
        self.assertEqual(dev.max_turns, 60)


if __name__ == "__main__":
    unittest.main()
