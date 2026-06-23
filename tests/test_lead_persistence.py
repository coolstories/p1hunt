"""Tenacity: a promising lead is RE-attacked with a different angle across rounds instead of being
abandoned after one failed PoC. A lead closes only on a proven win or a rigorous impossibility, or
after a hard attempt cap (then parked, never silently dropped). Failed attempts decay priority so
the engine rotates leads but keeps cycling back."""

import unittest

from p1hunt.agents.claude_swarm import ClaudeSwarm
from p1hunt.agents.claude_hunter import exploit_dev_prompt, ClaudeFinding


class _Shim:
    """Bind the pursuit helpers without constructing the whole swarm."""
    _lead_attempts = ClaudeSwarm._lead_attempts
    _lead_status = ClaudeSwarm._lead_status
    _lead_open = ClaudeSwarm._lead_open
    _record_lead_attempt = ClaudeSwarm._record_lead_attempt

    def __init__(self, max_attempts=5):
        self._lead_log = {}
        self._lead_max_attempts = max_attempts
        self._exploit_proven = set()


class TestPursuitState(unittest.TestCase):
    def test_lead_stays_open_after_one_failed_attempt(self):
        s = _Shim()
        st = s._record_lead_attempt("k", {"strategy": "direct PoC", "why_failed": "gate aborts"})
        self.assertEqual(st, "open")
        self.assertTrue(s._lead_open("k"))           # NOT abandoned after one failure
        self.assertEqual(s._lead_attempts("k"), 1)

    def test_priority_decays_with_attempts(self):
        s = _Shim()
        for _ in range(3):
            s._record_lead_attempt("k", {"strategy": "x", "why_failed": "y"})
        self.assertEqual(s._lead_attempts("k"), 3)   # decay = attempts*penalty in the loop

    def test_attempt_cap_parks_lead_not_dropped(self):
        s = _Shim(max_attempts=3)
        for _ in range(3):
            s._record_lead_attempt("k", {"strategy": "x", "why_failed": "y"})
        self.assertEqual(s._lead_status("k"), "maxed")
        self.assertFalse(s._lead_open("k"))          # stops pursuing after the cap...
        # ...but the record persists (parked for human review, not silently dropped)
        self.assertIn("k", s._lead_log)
        self.assertEqual(len(s._lead_log["k"]["attempts"]), 3)

    def test_rigorous_impossibility_exhausts_immediately(self):
        s = _Shim()
        st = s._record_lead_attempt("k", {"strategy": "lattice", "why_failed": "n/a",
                                          "exhausted": True, "impossibility": "challenge re-pins A"})
        self.assertEqual(st, "exhausted")
        self.assertFalse(s._lead_open("k"))          # a real impossibility closes it

    def test_proven_lead_not_repursued(self):
        s = _Shim()
        s._exploit_proven.add("k")
        self.assertFalse(s._lead_open("k"))


class TestPersistencePrompt(unittest.TestCase):
    def _finding(self):
        return ClaudeFinding(title="biased nonce", severity="high", file="x.c", line=1,
                             lens="trusted-execution", root_cause="rc", reproduction="rp",
                             counterfactual="cf", confidence="med")

    def test_prompt_carries_prior_attempts_and_demands_pivot(self):
        prior = [{"strategy": "direct PoC", "why_failed": "verify re-pins the value"}]
        p = exploit_dev_prompt(self._finding(), "", prior_attempts=prior)
        self.assertIn("PRIOR ATTEMPTS", p)
        self.assertIn("direct PoC", p)
        self.assertIn("DIFFERENT angle", p)
        self.assertIn("exhausted", p)               # the schema now distinguishes failed vs impossible

    def test_prompt_without_prior_has_no_attempt_block(self):
        p = exploit_dev_prompt(self._finding(), "")
        self.assertNotIn("PRIOR ATTEMPTS", p)


if __name__ == "__main__":
    unittest.main()
