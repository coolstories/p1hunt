"""The three depth/decomposition/rate-limit fixes that attack the 'shallow scanner' failure mode:
  1. deep-discovery raises the per-hunter turn floor (sustained reasoning, not 28-turn passes),
  2. track decomposition gives each track the FULL file set + a cross-cutting composition track
     (no disjoint round-robin slices that sever compositional bugs),
  3. (rate-limit headroom is an env-gated session behavior — covered by the prompt/flag presence).
"""

import os
import types
import unittest

from p1hunt.agents.claude_swarm import ClaudeSwarm, _LENSES


class _TurnsShim:
    _hunter_base_turns = ClaudeSwarm._hunter_base_turns

    def __init__(self, deep):
        self._deep_discovery = deep


class TestDeepDiscoveryTurns(unittest.TestCase):
    def setUp(self):
        os.environ.pop("P1HUNT_HUNTER_TURNS", None)

    def test_deep_mode_raises_turn_floor(self):
        self.assertEqual(_TurnsShim(deep=False)._hunter_base_turns(), 28)
        self.assertEqual(_TurnsShim(deep=True)._hunter_base_turns(), 80)

    def test_env_override_wins_over_deep_default(self):
        os.environ["P1HUNT_HUNTER_TURNS"] = "120"
        try:
            self.assertEqual(_TurnsShim(deep=True)._hunter_base_turns(), 120)
            self.assertEqual(_TurnsShim(deep=False)._hunter_base_turns(), 120)
        finally:
            os.environ.pop("P1HUNT_HUNTER_TURNS", None)


class _TracksShim:
    _fallback_tracks = ClaudeSwarm._fallback_tracks

    def _enumerate_targets(self, limit=30):
        return ["a.sol", "b.sol", "c.sol", "d.sol", "e.sol"]


class TestFlowDecomposition(unittest.TestCase):
    def test_every_track_gets_full_file_set_not_a_disjoint_slice(self):
        tracks = _TracksShim()._fallback_tracks()
        files = ["a.sol", "b.sol", "c.sol", "d.sol", "e.sol"]
        for t in tracks:
            self.assertEqual(sorted(t["focus_files"]), sorted(files),
                             f"track {t['theme']} got a fragment, not the full flow")

    def test_adds_a_cross_cutting_composition_track(self):
        themes = [t["theme"] for t in _TracksShim()._fallback_tracks()]
        self.assertIn("composition-and-trust-seams", themes)
        # all the base lenses still present too
        for lens in _LENSES:
            self.assertIn(lens, themes)
        self.assertEqual(len(themes), len(_LENSES) + 1)


class TestRateLimitHeadroom(unittest.TestCase):
    def test_no_downgrade_flag_is_read_in_session(self):
        import inspect
        from p1hunt.agents import claude_session
        src = inspect.getsource(claude_session)
        # the flag must gate the candidate-model list (no silent Opus->Sonnet when set)
        self.assertIn("P1HUNT_NO_MODEL_DOWNGRADE", src)
        self.assertIn("no_downgrade", src)


if __name__ == "__main__":
    unittest.main()
