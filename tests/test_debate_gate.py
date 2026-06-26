"""Debate gate: a critical is a CONFIRMED critical ONLY if it survived the debate panel.

Reproduces the bug the operator hit (a debate-rejected finding still appearing as a confirmed
critical) and locks in the fix: _confirmed_crits enforces reject/downgrade/uphold by a STABLE key,
so promotion re-running each round can never resurrect a rejected/downgraded/un-upheld critical.
"""

import types
import unittest

from p1hunt.agents.claude_swarm import ClaudeSwarm
from p1hunt.models import ArtifactRef, Finding


def _f(title, severity="critical", file="src/x.cpp"):
    return types.SimpleNamespace(title=title, severity=severity, file=file)


def _promoted(title, severity="critical", path="poc.cpp"):
    return Finding(
        id="F1",
        hypothesis_id="H1",
        title=title,
        root_cause="rc",
        poc=ArtifactRef(id="A1", kind="repro", path=path, description="", reproduced=True),
        severity=severity,
        severity_rationale="r",
        counterfactual="c",
        remediation="fix",
        safe_harbor_attestation="att",
        verified=True,
    )


class _Shim:
    """Minimal stand-in carrying just the state the two methods read (no full swarm construction)."""
    _finding_key = ClaudeSwarm._finding_key
    _confirmed_crits = ClaudeSwarm._confirmed_crits

    def __init__(self, debate_on=True):
        self._debate_max = 3 if debate_on else 0
        self.config = types.SimpleNamespace(use_claude=True)
        self._debate_rejected = set()
        self._debate_upheld = set()
        self._debate_downgraded = {}
        self._deepdive_on = False   # these tests exercise the DEBATE gate path
        self._exploit_proven = set()


class TestDebateGate(unittest.TestCase):
    def test_critical_not_confirmed_until_upheld(self):
        s = _Shim(debate_on=True)
        f = _f("Key recovery via X")
        self.assertEqual(s._confirmed_crits([f]), [])          # pending debate -> NOT confirmed
        s._debate_upheld.add(s._finding_key(f))
        self.assertEqual(s._confirmed_crits([f]), [f])         # upheld -> confirmed

    def test_rejected_never_confirmed_even_if_repromoted(self):
        s = _Shim(debate_on=True)
        f = _f("Refresh freeze (off-rubric)")
        s._debate_rejected.add(s._finding_key(f))
        # A fresh object (re-found next round, new id) with the same title+file must also be excluded.
        again = _f("Refresh freeze (off-rubric)")
        self.assertEqual(s._confirmed_crits([f, again]), [])

    def test_downgraded_not_a_confirmed_critical(self):
        s = _Shim(debate_on=True)
        f = _f("Schnorr unsound PoK")
        s._debate_upheld.add(s._finding_key(f))  # even if also marked upheld...
        s._debate_downgraded[s._finding_key(f)] = "medium"  # ...downgrade wins
        self.assertEqual(s._confirmed_crits([f]), [])

    def test_debate_disabled_falls_back_to_severity(self):
        s = _Shim(debate_on=False)  # _debate_max == 0
        f = _f("Some critical")
        self.assertEqual(s._confirmed_crits([f]), [f])  # no panel -> severity alone decides

    def test_stable_key_is_title_plus_file(self):
        s = _Shim()
        self.assertEqual(s._finding_key(_f("ABC", file="a.cpp")), s._finding_key(_f("abc", file="a.cpp")))
        self.assertNotEqual(s._finding_key(_f("ABC", file="a.cpp")), s._finding_key(_f("ABC", file="b.cpp")))

    def test_promoted_finding_key_uses_poc_path(self):
        s = _Shim()
        self.assertEqual(
            s._finding_key(_promoted("ABC", path="a.cpp")),
            s._finding_key(_promoted("abc", path="a.cpp")),
        )
        self.assertNotEqual(
            s._finding_key(_promoted("ABC", path="a.cpp")),
            s._finding_key(_promoted("ABC", path="b.cpp")),
        )


if __name__ == "__main__":
    unittest.main()
