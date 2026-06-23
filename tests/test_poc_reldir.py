"""PoC-harness placement: harnesses must land where the target's toolchain can RUN them.

Root cause of the Seaport run finding nothing: PoCs were written to `.p1hunt-poc/`, which is outside
a Foundry project's `src`/`test` tree, so `forge test` reported "No tests found" and remappings broke
— every PoC silently never executed. `_poc_reldir` now nests PoCs inside the project's configured
`test` dir for Foundry targets, and the prompts embed that path.
"""

import tempfile
import unittest
from pathlib import Path

from p1hunt.agents.claude_hunter import materialize_prompt, repair_prompt
from p1hunt.agents.claude_session import ClaudeFinding
from p1hunt.agents.claude_swarm import _poc_reldir


def _finding():
    return ClaudeFinding(
        title="t", severity="critical", file="x.sol", line=1, root_cause="r",
        counterfactual="c", reproduction="rep", lens="asset-custody", confidence="high",
    )


class TestPocReldir(unittest.TestCase):
    def test_foundry_explicit_test_dir(self):
        d = tempfile.mkdtemp()
        Path(d, "foundry.toml").write_text("[profile.default]\nsrc='contracts'\ntest='test/foundry'\n")
        self.assertEqual(_poc_reldir(d), "test/foundry/p1hunt")

    def test_foundry_default_test_dir(self):
        d = tempfile.mkdtemp()
        Path(d, "foundry.toml").write_text("[profile.default]\nsrc='src'\n")  # no test key → default 'test'
        self.assertEqual(_poc_reldir(d), "test/p1hunt")

    def test_non_foundry_falls_back(self):
        self.assertEqual(_poc_reldir(tempfile.mkdtemp()), ".p1hunt-poc")

    def test_first_test_key_is_default_profile(self):
        # Seaport-like: multiple profiles; the default profile's test path must win.
        d = tempfile.mkdtemp()
        Path(d, "foundry.toml").write_text(
            "[profile.default]\nsrc='contracts'\ntest='test/foundry'\n"
            "[profile.reference]\nsrc='reference'\ntest='test/foundry'\n")
        self.assertEqual(_poc_reldir(d), "test/foundry/p1hunt")


class TestPromptsEmbedDir(unittest.TestCase):
    def test_materialize_uses_threaded_dir(self):
        mp = materialize_prompt(_finding(), poc_reldir="test/foundry/p1hunt")
        self.assertIn("test/foundry/p1hunt", mp)
        self.assertNotIn(".p1hunt-poc", mp)

    def test_repair_uses_threaded_dir(self):
        rp = repair_prompt(_finding(), {"harness_path": "x"}, "boom", poc_reldir="test/foundry/p1hunt")
        self.assertIn("test/foundry/p1hunt", rp)
        self.assertNotIn(".p1hunt-poc", rp)

    def test_default_still_p1hunt_poc(self):
        self.assertIn(".p1hunt-poc", materialize_prompt(_finding()))


if __name__ == "__main__":
    unittest.main()
