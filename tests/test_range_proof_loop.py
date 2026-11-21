"""The CEILING of the execution loop: can a correct harness be judged reproduced at all?

The execution measurement (bench/run_exec.py) asks whether the hunt writes a harness that
proves a planted defect. That number is bounded by something the model has no influence
over: whether the deterministic runner, pointed at this range with a CORRECT harness,
returns reproduced=True. If it cannot, the measurement is capped for reasons that have
nothing to do with the hunt's intelligence, and a low score would be misread as a
reasoning failure.

So these tests hand the REAL WebRunner hand-written harnesses -- no model involved -- and
check the verdict, including both directions of the `expect` convention and the cases that
must NOT be read as proof. This is the control for the execution measurement, and it is
the test that would have caught the broken pytest plugin on this machine as a toolchain
fault rather than as nine mysterious non-reproductions.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))

from range_app import Range  # noqa: E402

from p1hunt.runners.base import ReproSpec, preflight_pytest, select_runner  # noqa: E402

_PRE = preflight_pytest()
# The workaround the preflight VERIFIED, applied to the harness subprocess the runner
# spawns. Without it a broken plugin on the host machine masquerades as nine failures.
if not _PRE["ok"] and _PRE.get("broken_plugin"):
    os.environ["PYTEST_ADDOPTS"] = (
        os.environ.get("PYTEST_ADDOPTS", "") + f" -p no:{_PRE['broken_plugin']}").strip()
    _PRE = preflight_pytest()

_SKIP = None if _PRE["ok"] else f"pytest cannot run here: {_PRE['detail']}"


# A harness that performs the attack and ASSERTS IT WORKED -> expect="pass".
# This is the authz shape: bob reads alice's account, so a 200 is the bug.
_IDOR_PROOF = '''
import json
import os
import urllib.request

BASE = os.environ["RANGE_BASE"].rstrip("/")


def _get(path, token=None):
    req = urllib.request.Request(BASE + path)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def test_bob_reads_alices_account():
    status, body = _get("/api/v1/me", "alice")
    assert status == 200, body
    alice_account = json.loads(body)["account_id"]
    status, body = _get("/api/v1/accounts/" + alice_account, "bob")
    # The crossing: a principal reads an object it does not own.
    assert status == 200, "expected the unauthorized read to succeed"
    assert "alice" in body, body
'''

# The same defect written the OTHER way round: a harness asserting the SECURE behaviour,
# which the bug makes FAIL -> expect="fail".
_IDOR_INVARIANT = '''
import json
import os
import urllib.request

BASE = os.environ["RANGE_BASE"].rstrip("/")


def _get(path, token=None):
    req = urllib.request.Request(BASE + path)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def test_b_cannot_read_a_object():
    status, body = _get("/api/v1/me", "alice")
    alice_account = json.loads(body)["account_id"]
    status, _ = _get("/api/v1/accounts/" + alice_account, "bob")
    assert status in (401, 403, 404), "bob must not be able to read alice's account"
'''

# The render-gate defect: the SAME resource served two ways, differing only by one header.
# Proof is the COMPARISON, which is why no single response looks wrong.
_GATE_PROOF = '''
import os
import urllib.request

BASE = os.environ["RANGE_BASE"].rstrip("/")
SID = "550e8400-e29b-41d4-a716-446655440000"
MARKER = "ZXq<b>ZXq"


def _share(mobile):
    req = urllib.request.Request(BASE + "/share/" + SID + "?note=ZXq%3Cb%3EZXq")
    req.add_header("Cookie", "range_session=alice")
    if mobile:
        req.add_header("X-Range-Host", "m.range")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode()


def test_mobile_host_skips_the_render_gate():
    apex = _share(False)
    mobile = _share(True)
    assert MARKER not in apex, "the apex must escape it for a session-bearing viewer"
    assert MARKER in mobile, "the mobile host must emit it raw -- this is the defect"
'''

# A harness pointed at a decoy, written as an exploit assertion. It must FAIL, and the
# runner must therefore NOT report it as reproduced.
_DECOY_PROOF = '''
import os
import urllib.error
import urllib.request

BASE = os.environ["RANGE_BASE"].rstrip("/")


def _get(path, token):
    req = urllib.request.Request(BASE + path)
    req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code


def test_bob_reads_alices_order():
    assert _get("/api/v1/me/orders/alice-1", "bob") == 200, "scoped endpoint refused"
'''

# A harness that cannot even import. Must be an INFRASTRUCTURE error, never a proof --
# under expect="fail" the naive reading of "it errored" is "the bug is real".
_BROKEN_HARNESS = '''
import this_module_does_not_exist_anywhere  # noqa


def test_never_runs():
    assert False
'''


@unittest.skipIf(_SKIP, _SKIP or "")
class TestTheRunnerCanJudgeARealProof(unittest.TestCase):
    """No model anywhere in these tests. Hand-written harness, real runner, live range."""

    @classmethod
    def setUpClass(cls):
        cls.rng = Range()
        cls.rng.__enter__()
        cls.runner = select_runner("WEB_API")
        assert cls.runner is not None

    @classmethod
    def tearDownClass(cls):
        cls.rng.__exit__()

    def _run(self, source: str, *, expect: str, name: str = "test_harness.py") -> object:
        box = tempfile.mkdtemp(prefix="range_proof_")
        self.addCleanup(shutil.rmtree, box, True)
        poc = Path(box) / ".p1hunt-poc"
        poc.mkdir(parents=True)
        (poc / name).write_text(source, encoding="utf-8")
        prior = os.environ.get("RANGE_BASE")
        os.environ["RANGE_BASE"] = self.rng.base
        try:
            spec = ReproSpec(
                harness_path=f".p1hunt-poc/{name}", expect=expect, kind="differential",
                target_code_attribution="the range's own handler for this route",
                non_target_attribution="the harness supplies only the two test tokens",
            )
            return self.runner.run(box, spec, timeout=180.0)
        finally:
            if prior is None:
                os.environ.pop("RANGE_BASE", None)
            else:
                os.environ["RANGE_BASE"] = prior

    def test_an_exploit_assertion_that_holds_is_reproduced(self):
        res = self._run(_IDOR_PROOF, expect="pass")
        self.assertTrue(res.ran, res.detail)
        self.assertTrue(res.reproduced, res.detail or res.stdout_excerpt)
        self.assertEqual(res.runner, "web")

    def test_the_same_defect_as_a_broken_invariant_is_reproduced(self):
        """Both directions of the `expect` convention must work on the same real bug.

        Inverting this convention is a correctness bug in BOTH directions -- it either
        reports every refusal as a finding or every finding as a refusal -- so the live
        check covers both spellings rather than trusting the parser's unit tests.
        """
        res = self._run(_IDOR_INVARIANT, expect="fail")
        self.assertTrue(res.ran, res.detail)
        self.assertTrue(res.reproduced, res.detail or res.stdout_excerpt)

    def test_the_render_gate_comparison_is_reproducible(self):
        """The class a wordlist cannot reach, proved by differential and judged by a runner."""
        res = self._run(_GATE_PROOF, expect="pass")
        self.assertTrue(res.ran, res.detail)
        self.assertTrue(res.reproduced, res.detail or res.stdout_excerpt)

    def test_a_harness_pointed_at_correct_code_is_not_reproduced(self):
        res = self._run(_DECOY_PROOF, expect="pass")
        self.assertTrue(res.ran, res.detail)
        self.assertFalse(res.reproduced, res.detail)

    def test_a_harness_that_cannot_import_is_infrastructure_not_proof(self):
        """expect='fail' plus an import error is the trap: 'it errored' is not 'it's real'."""
        res = self._run(_BROKEN_HARNESS, expect="fail")
        self.assertFalse(res.reproduced, res.detail)
        self.assertFalse(res.ran, "a harness that never collected must report ran=False")

    def test_a_missing_harness_is_not_proof(self):
        box = tempfile.mkdtemp(prefix="range_proof_")
        self.addCleanup(shutil.rmtree, box, True)
        spec = ReproSpec(harness_path=".p1hunt-poc/nope.py", expect="pass",
                         target_code_attribution="x")
        res = self.runner.run(box, spec, timeout=60.0)
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)


@unittest.skipIf(_SKIP, _SKIP or "")
class TestTheAttributionGateStillApplies(unittest.TestCase):
    """A proof that cannot say what it is a proof OF must not promote anything."""

    def test_a_spec_with_no_target_attribution_is_blocked(self):
        spec = ReproSpec(harness_path=".p1hunt-poc/x.py", expect="pass")
        self.assertIn("target_code_attribution", spec.attribution_blocker())

    def test_a_spec_leaning_on_harness_behaviour_is_blocked(self):
        spec = ReproSpec(harness_path=".p1hunt-poc/x.py", expect="pass",
                         target_code_attribution="the route",
                         relies_on_non_target_behavior=True,
                         attribution_notes="the harness stubbed the authz call")
        self.assertIn("harness", spec.attribution_blocker())


class TestThisControlIsHonestAboutItsEnvironment(unittest.TestCase):
    def test_the_suite_says_why_it_skipped_rather_than_passing_vacuously(self):
        """A skipped control must be visible. Silence here is how a capped measurement
        gets mistaken for a reasoning failure."""
        if _SKIP:
            self.assertIn("pytest cannot run", _SKIP)
        else:
            self.assertTrue(_PRE["ok"])


if __name__ == "__main__":
    unittest.main()
