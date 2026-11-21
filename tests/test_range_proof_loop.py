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


class TestTheHarnessPathIsResolvedTheWayAProverReportsIt(unittest.TestCase):
    """The single missing path prefix that made every proof unreachable.

    A measured end-to-end run got all the way through: the hunters wrote eight real
    harnesses, the verifier called the finding real citing live request evidence, and the
    prover materialized a harness. Then the runner reported

        "harness missing or outside the sandbox — finding stays a candidate"

    and the whole chain produced nothing. The cause was one line: the prover reported the
    FILENAME it had just written ("test_bola_idor.py"), while the runner resolved against
    the workspace ROOT, where the file lives at ".p1hunt-poc/test_bola_idor.py".

    Resolving the bare name in the runner is the right place for the fix. Requiring a
    model to get a path prefix exactly right, in every role, every time, is a worse
    contract than looking in the one directory harnesses are written to -- and the failure
    mode of getting it wrong is silent and total.

    The containment property is NOT relaxed by any of this, which the escape tests below
    exist to hold: whatever is returned is inside the workspace.
    """

    def setUp(self):
        self.box = Path(tempfile.mkdtemp(prefix="harness_path_"))
        self.addCleanup(shutil.rmtree, self.box, True)
        self.poc = self.box / ".p1hunt-poc"
        self.poc.mkdir()
        (self.poc / "test_h.py").write_text("def test_x():\n    pass\n", encoding="utf-8")

    def test_a_bare_filename_resolves_into_the_poc_directory(self):
        """Exactly what the prover reported in the measured run."""
        from p1hunt.runners.base import safe_harness_path
        found = safe_harness_path(str(self.box), "test_h.py")
        self.assertIsNotNone(found, "a bare filename must resolve")
        self.assertEqual(found.name, "test_h.py")
        self.assertTrue(str(found).endswith(".p1hunt-poc/test_h.py"))

    def test_the_documented_relative_path_still_resolves(self):
        from p1hunt.runners.base import safe_harness_path
        for spelling in (".p1hunt-poc/test_h.py", "./.p1hunt-poc/test_h.py"):
            with self.subTest(path=spelling):
                self.assertIsNotNone(safe_harness_path(str(self.box), spelling))

    def test_a_harness_in_a_subdirectory_is_found_by_name(self):
        from p1hunt.runners.base import safe_harness_path
        nested = self.poc / "web"
        nested.mkdir()
        (nested / "test_deep.py").write_text("def test_y():\n    pass\n", encoding="utf-8")
        found = safe_harness_path(str(self.box), "test_deep.py")
        self.assertIsNotNone(found, "a bare name must be found recursively under the PoC dir")
        self.assertEqual(found.name, "test_deep.py")

    def test_a_foundry_style_poc_directory_also_resolves(self):
        from p1hunt.runners.base import safe_harness_path
        alt = self.box / "test" / "p1hunt"
        alt.mkdir(parents=True)
        (alt / "Probe.t.sol").write_text("// x\n", encoding="utf-8")
        self.assertIsNotNone(safe_harness_path(str(self.box), "Probe.t.sol"))

    def test_a_genuinely_missing_harness_is_still_none(self):
        """The laxity must not swallow the real 'no harness' case."""
        from p1hunt.runners.base import safe_harness_path
        self.assertIsNone(safe_harness_path(str(self.box), "test_does_not_exist.py"))
        self.assertIsNone(safe_harness_path(str(self.box), ""))

    def test_a_directory_is_not_a_harness(self):
        from p1hunt.runners.base import safe_harness_path
        self.assertIsNone(safe_harness_path(str(self.box), ".p1hunt-poc"))

    def test_containment_still_holds_absolutely(self):
        """The security property the function exists for. Relaxing resolution must not
        relax this: a runner must never be pointable at a host file."""
        from p1hunt.runners.base import safe_harness_path
        for escape in ("/etc/passwd", "../../../../etc/passwd",
                       ".p1hunt-poc/../../../../etc/passwd",
                       "/tmp/../etc/passwd"):
            with self.subTest(path=escape):
                self.assertIsNone(safe_harness_path(str(self.box), escape),
                                  f"{escape!r} escaped the workspace")

    def test_a_symlink_out_of_the_workspace_is_refused(self):
        from p1hunt.runners.base import safe_harness_path
        outside = Path(tempfile.mkdtemp(prefix="outside_"))
        self.addCleanup(shutil.rmtree, outside, True)
        target = outside / "evil.py"
        target.write_text("print('x')\n", encoding="utf-8")
        link = self.poc / "test_link.py"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlinks unavailable")
        self.assertIsNone(safe_harness_path(str(self.box), "test_link.py"),
                          "a symlink leaving the workspace must be refused")


@unittest.skipIf(_SKIP, _SKIP or "")
class TestTheHuntersOwnHarnessReproduces(unittest.TestCase):
    """End to end, with no model in the loop: a harness a REAL hunt wrote, re-executed.

    bench/harnesses_from_run/ holds the harnesses a live hunt against this range actually
    produced. This replays the one whose ReproSpec the event stream recorded
    (test_bola_idor.py, expect="pass") through the real runner, using the exact BARE
    FILENAME the prover reported -- the input that used to resolve to nothing.

    Only that one is asserted. The others' declared `expect` is not in the artifacts, and
    `expect` cannot be searched for: under expect="fail" ANY failing test counts as "bug
    demonstrated", so trying both values and keeping whichever reproduces manufactures a
    result. The prover declares it; the scorer does not get to choose it.
    """

    HARNESS_DIR = Path(__file__).resolve().parents[1] / "bench" / "harnesses_from_run"

    def test_the_recorded_harness_reproduces_from_a_bare_filename(self):
        from p1hunt.runners.base import ReproSpec, select_runner

        harness = self.HARNESS_DIR / "test_bola_idor.py"
        if not harness.is_file():
            self.skipTest("no preserved harness from a live run")
        box = Path(tempfile.mkdtemp(prefix="hunter_harness_"))
        self.addCleanup(shutil.rmtree, box, True)
        shutil.copytree(self.HARNESS_DIR, box / ".p1hunt-poc")
        # The shipped client the harness imports.
        import p1hunt.dynamic.client as _c
        shutil.copy2(_c.__file__, box / ".p1hunt-poc" / "p1hunt_dyn.py")

        rng = Range()
        rng.__enter__()
        self.addCleanup(rng.__exit__)
        prior = {k: os.environ.get(k) for k in
                 ("P1HUNT_BASE_URL", "P1HUNT_EGRESS_ALLOWLIST",
                  "P1HUNT_TOKEN_A", "P1HUNT_TOKEN_B")}

        def _restore():
            for k, v in prior.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        self.addCleanup(_restore)
        os.environ.update({"P1HUNT_BASE_URL": rng.base,
                           "P1HUNT_EGRESS_ALLOWLIST": "127.0.0.1",
                           "P1HUNT_TOKEN_A": "alice", "P1HUNT_TOKEN_B": "bob"})

        spec = ReproSpec(
            harness_path="test_bola_idor.py",     # BARE, as the prover reported it
            expect="pass",                         # as the prover declared it
            kind="differential",
            target_code_attribution="GET /api/v1/accounts/{uuid} has no ownership check",
            non_target_attribution="only the two scope-provided test identities",
        )
        res = select_runner("WEB_API").run(str(box), spec, timeout=180.0)
        self.assertTrue(res.ran, f"the harness did not run: {res.detail}")
        self.assertTrue(res.reproduced,
                        f"the hunt's own proof did not reproduce: {res.detail}\n"
                        f"{res.stdout_excerpt[-600:]}")
        self.assertIn("pytest", res.command)
