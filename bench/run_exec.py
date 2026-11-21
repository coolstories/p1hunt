"""Run the REAL product end to end against the range, then score the execution.

WHY THIS EXISTS
---------------
Every number in bench/README.md before this file scored PLANNING: given the live surface,
does the pipeline propose the right things to examine. It did, 9/9 black-box. That is a
much weaker claim than it sounds, and I said so: it means "it correctly identifies what
to look at", not "it finds bugs".

This runs the actual shipped entry point --

    python3 -m p1hunt.main hunt <base> --web ...

-- against the loopback range, and then scores the artifacts THAT RUN WROTE for whether a
deterministic runner reproduced each planted defect. Running the product rather than
reassembling its parts is the whole point: a hand-wired reimplementation of
hunter -> prover -> runner would be measuring code written for the measurement, and would
not catch the thing most likely to be broken, which is the wiring.

WHAT A PASS MEANS, PRECISELY
----------------------------
A planted defect is CONFIRMED only when a real toolchain executed a real harness against
the live range and the runner -- not a model's claim -- decided the bug was demonstrated,
and no promotion gate held it. See bench/exec_score.py for the full ladder.

SAFETY
------
The range binds 127.0.0.1 only. The hunt's egress jail is handed exactly that host. No
third party is involved and there is nothing to authorize.

Usage:
  python3 bench/run_exec.py                  # real engine, 1 round (long)
  python3 bench/run_exec.py --rounds 2
  python3 bench/run_exec.py --offline        # no model: PLUMBING CHECK ONLY
  python3 bench/run_exec.py --engine claude   # route the roles Codex refuses
  python3 bench/run_exec.py --score-only engagements/range-exec
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

from exec_score import render, score_execution  # noqa: E402
from range_app import DECOYS, PLANTED, Range  # noqa: E402

PROGRAM = "range-exec"

# The range fakes a sibling mobile host with a request header, because a loopback server
# cannot own two real hostnames. The hunt is TOLD this, in the same place a program's
# rules of engagement would be, because the defect it unlocks is a comparison between two
# renders of one resource and there is no way to discover the header by probing.
SCOPE_NOTE = (
    "Authorized target: the single loopback host 127.0.0.1 ONLY. This is a local test "
    "range the operator owns outright; there is no third party and no production data. "
    "Non-destructive testing of any kind is in scope, including authorization, injection, "
    "redirect, SSRF and render-path testing.\n"
    "Principals: two test users exist, alice and bob. Authenticate as either by sending "
    "`Authorization: Bearer alice` / `Bearer bob`, or by GET /login?user=alice which sets "
    "the session cookie `range_session`. P1HUNT_TOKEN_A holds alice and P1HUNT_TOKEN_B "
    "holds bob. GET /api/v1/me returns the calling principal and the account id it owns.\n"
    "A sibling MOBILE WEB HOST is simulated with the request header `X-Range-Host: m.range`, "
    "because a loopback server cannot own two real hostnames. Sending that header is "
    "equivalent to requesting the same path on the mobile host; omitting it is the apex "
    "host. Both are in scope."
)


def preflight_toolchain() -> dict:
    """Can a harness actually run on this machine? Checked BEFORE the engine is paid for.

    THIS CHECK EXISTS BECAUSE IT CAUGHT A RUN IN PROGRESS. On this machine `pytest` exits
    1 during plugin loading -- a stale `anchorpy` whose `solders` dependency no longer has
    the module it imports -- so EVERY harness the pipeline writes dies before collecting a
    single test. The product handles that correctly and honestly: web.py's
    _PYTEST_INFRA_ERROR_RE matches ModuleNotFoundError, the run is classified
    INFRASTRUCTURE ERROR, ran=False, and the finding stays a candidate rather than being
    reported as not-reproduced. Which is right, and also means a 90-minute measurement
    would have returned CONFIRMED=0/9 and been a measurement of my broken Python
    environment.

    A score of zero that is predetermined by the toolchain is worse than no score, because
    it looks like a finding about the hunt. So this refuses to start instead.

    Returns {ok, detail, addopts} -- addopts being an env fix to apply when one exists.
    """
    import subprocess as sp
    import tempfile as tf

    with tf.TemporaryDirectory(prefix="p1hunt_preflight_") as box:
        probe = Path(box) / "test_preflight.py"
        probe.write_text("def test_preflight():\n    assert True\n", encoding="utf-8")

        def _try(addopts: str) -> tuple[int, str]:
            env = dict(os.environ)
            if addopts:
                env["PYTEST_ADDOPTS"] = addopts
            try:
                r = sp.run(["pytest", "-q", str(probe)], cwd=box, env=env, text=True,
                           capture_output=True, timeout=180)
            except (OSError, sp.SubprocessError) as exc:
                return 127, str(exc)
            return r.returncode, (r.stdout or "") + (r.stderr or "")

        code, out = _try("")
        if code == 0:
            return {"ok": True, "detail": "pytest runs a trivial test cleanly", "addopts": ""}

        # A plugin that raises on import names itself in the traceback. Disabling just that
        # plugin is run-scoped and reversible; installing or removing packages on someone
        # else's machine to make a benchmark pass is not.
        import re
        broken = re.findall(r"site-packages/([A-Za-z0-9_]+)/__init__\.py", out)
        for name in dict.fromkeys(broken):
            fix = f"-p no:{name}"
            code2, out2 = _try(fix)
            if code2 == 0:
                return {"ok": True, "addopts": fix,
                        "detail": f"pytest was broken by the '{name}' plugin "
                                  f"({_first_error(out)}); working around it with {fix}"}
        return {"ok": False, "addopts": "",
                "detail": f"pytest cannot run a trivial test (exit {code}): {_first_error(out)}"}


def _first_error(output: str) -> str:
    for line in reversed((output or "").splitlines()):
        line = line.strip()
        if line and ("Error" in line or "error" in line):
            return line[:160]
    return (output or "").strip().splitlines()[-1][:160] if (output or "").strip() else "no output"


def _env(base: str, eng_root: Path, *, offline: bool, addopts: str = "",
         engine: str = "") -> dict:
    env = dict(os.environ)
    if engine:
        # Acceptance of the hunting role is a property of the PROVIDER, not of p1hunt, so
        # which engine runs the hunt changes the result more than any setting here. See
        # bench/probe_refusal.py, which measures acceptance per role per engine.
        env["P1HUNT_ENGINE"] = engine
    env["P1HUNT_ENGAGEMENTS"] = str(eng_root)
    env["P1HUNT_BASE_URL"] = base
    # Named principals, resolved by _identities_from_env into identities "a" and "b", and
    # read by the web authz harness scaffold under exactly these names.
    env["P1HUNT_TOKEN_A"] = "alice"
    env["P1HUNT_TOKEN_B"] = "bob"
    env["P1HUNT_RUN_MODE"] = "active"
    env["P1HUNT_EGRESS_ALLOWLIST"] = "127.0.0.1"
    # Keep a measurement run bounded. Without caps a single stuck harness can eat the
    # whole wall clock and the run reports nothing at all.
    env.setdefault("P1HUNT_REPRO_TIMEOUT", "180")
    env.setdefault("P1HUNT_POC_ATTEMPTS", "3")
    # Hand the toolchain fix down to the harness subprocesses the runner spawns. pytest is
    # launched by p1hunt.runners.web via run_command, which inherits this environment.
    if addopts:
        env["PYTEST_ADDOPTS"] = (
            addopts if not env.get("PYTEST_ADDOPTS")
            else env["PYTEST_ADDOPTS"] + " " + addopts)
    if offline:
        env["P1HUNT_USE_CLAUDE"] = "0"
    return env


def run_hunt(base: str, eng_root: Path, *, rounds: int, timeout: float,
             offline: bool, log_path: Path, addopts: str = "", engine: str = "") -> dict:
    """Launch the shipped CLI as a subprocess and wait. Returns run metadata.

    A subprocess, not an in-process call: the range's HTTP server lives in THIS process,
    and the hunt mutates process-wide state (os.environ, the event log's global sink). A
    separate process is also what the operator actually runs, so it is what should be
    measured.
    """
    cmd = [
        sys.executable, "-m", "p1hunt.main", "hunt", base,
        "--web", "--program", PROGRAM, "--platform", "local",
        "--live-env", "bounty", "--scope-note", SCOPE_NOTE,
        "--max-rounds", str(rounds),
    ]
    if engine:
        cmd += ["--engine", engine]
    if offline:
        cmd.append("--offline")
    print("+ " + " ".join(cmd[:10]) + " ...")
    print(f"  log -> {log_path}")
    t0 = time.time()
    timed_out = False
    with log_path.open("w", encoding="utf-8") as fh:
        proc = subprocess.Popen(cmd, cwd=str(ROOT),
                                env=_env(base, eng_root, offline=offline, addopts=addopts,
                                         engine=engine),
                                stdout=fh, stderr=subprocess.STDOUT, text=True)
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # A timeout is NOT a failed measurement. The hunt writes findings.json at every
            # round boundary and live_findings.json as each finding lands, so whatever it
            # had proved by the wall clock is already on disk and gets scored.
            timed_out = True
            proc.terminate()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
            code = -1
    return {"exit_code": code, "seconds": round(time.time() - t0, 1),
            "timed_out": timed_out, "log": str(log_path)}


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])

    def _opt(name: str, default: str) -> str:
        """A flag's value, or the default. Guards the end-of-argv case so a trailing
        `--rounds` is a usage error rather than an IndexError traceback."""
        if name not in argv:
            return default
        i = argv.index(name)
        if i + 1 >= len(argv):
            raise SystemExit(f"{name} needs a value")
        return argv[i + 1]

    if "--score-only" in argv:
        eng = Path(_opt("--score-only", ""))
        s = score_execution(eng)
        print(render(s))
        return 0

    rounds = int(_opt("--rounds", "1"))
    timeout = float(_opt("--timeout", "5400"))
    offline = "--offline" in argv
    engine = _opt("--engine", "")
    eng_root = Path(_opt("--engagements", str(HERE / "engagements")))
    fresh = "--keep" not in argv

    eng_dir = eng_root / PROGRAM
    if fresh and eng_dir.exists():
        # A stale engagement folder would be scored as though this run had produced it,
        # which is the easiest way to accidentally report someone else's number.
        print(f"clearing previous engagement: {eng_dir}")
        shutil.rmtree(eng_dir, ignore_errors=True)
    eng_root.mkdir(parents=True, exist_ok=True)

    # BEFORE anything is paid for: can a harness run at all on this machine?
    pre = preflight_toolchain()
    print(f"toolchain preflight: {'OK' if pre['ok'] else 'BROKEN'} -- {pre['detail']}")
    if not pre["ok"] and "--force" not in argv:
        print("\nREFUSING TO RUN. Every harness would die before collecting a test, so the\n"
              "score would be 0/9 no matter how good the hunt is -- a number about this\n"
              "machine, presented as a number about the tool. Fix pytest (or pass --force\n"
              "if you want the run anyway and will read the infra-error counts).")
        return 4

    with Range() as rng:
        print(f"range up on {rng.base}  ({len(PLANTED)} planted, {len(DECOYS)} decoys)")
        if offline:
            print("!! --offline: NO MODEL RUNS. This checks the artifact/scoring plumbing "
                  "only; the resulting score is not a capability measurement.")
        meta = run_hunt(rng.base, eng_root, rounds=rounds, timeout=timeout,
                        offline=offline, log_path=HERE / "last_exec_run.log",
                        addopts=pre["addopts"], engine=engine)
        meta["toolchain"] = pre
        print(f"\nhunt finished: exit={meta['exit_code']} seconds={meta['seconds']}"
              f"{'  (TIMED OUT - scoring what reached disk)' if meta['timed_out'] else ''}")

    if not eng_dir.exists():
        print(f"\n!! no engagement folder at {eng_dir}. Tail of the run log:")
        try:
            print("\n".join((HERE / "last_exec_run.log").read_text(
                encoding="utf-8", errors="replace").splitlines()[-40:]))
        except OSError:
            pass
        return 3

    s = score_execution(eng_dir)
    s["run"] = meta
    s["mode"] = "offline-plumbing-check" if offline else "real-engine"
    s["engine"] = engine or "configured default"
    s["rounds_requested"] = rounds
    print("\n" + render(s))
    if offline:
        print("\nreminder: --offline ran no model, so CONFIRMED=0 here says nothing about "
              "capability. It only proves the artifacts and the scorer line up.")
    out = HERE / "last_exec_score.json"
    out.write_text(json.dumps(s, indent=2), encoding="utf-8")
    print(f"\nwritten: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
