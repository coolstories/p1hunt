"""Does the provider's safety classifier ACCEPT each model-facing prompt? Measured.

WHY THIS IS A STANDING TOOL AND NOT A ONE-OFF
---------------------------------------------
A provider-side classifier reads a prompt before the model does. When it refuses, the
session returns "This content was flagged for possible cybersecurity risk" and that ROLE
IS GONE for the run -- while everything around it reports success. The pipeline then
produces an honest-looking nothing.

The failure is invisible to the test suite by construction: 1200+ tests pass with fake
sessions, and a fake session cannot refuse. It has now bitten twice. First the planning
brief, fixed with authorization framing. Then -- found by the first real end-to-end run
against the range -- ALL FIVE hunters and the fuzzer, every single one, so the execution
score was 0/9 for a reason that had nothing to do with whether the pipeline can find bugs.

So acceptance is a thing to MEASURE, per prompt, against the real engine, and to re-measure
whenever a prompt is edited or a model changes. One session per prompt; cheap next to a
wasted hunt.

Usage:
  python3 bench/probe_refusal.py              # probe every prompt
  python3 bench/probe_refusal.py web_hunt     # probe one
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from p1hunt.agents import claude_hunter as H  # noqa: E402
from p1hunt.agents import fuzz_engine as F  # noqa: E402
from p1hunt.agents.claude_session import ClaudeFinding, make_session  # noqa: E402
from p1hunt.config import Config  # noqa: E402
from p1hunt.dynamic import triage as T  # noqa: E402

SCOPE = ("Authorized target: the single loopback host 127.0.0.1 ONLY, a local test range "
         "the operator owns outright. No third party, no production data. Test identities "
         "alice and bob are supplied as P1HUNT_TOKEN_A / P1HUNT_TOKEN_B.")


# A plausible live-web finding, so the downstream roles get something real to chew on.
# The whole CHAIN has to be accepted, not just the hunters: if the prover is refused, no
# harness is ever written, nothing is ever executed, and the confirmed count is zero for
# the same invisible reason.
_FINDING = ClaudeFinding(
    title="An account endpoint returns another principal's record",
    severity="high", file="http://127.0.0.1/api/v1/accounts/{id}", line=0,
    lens="authorization",
    root_cause="the handler resolves the id from the path and never checks it against the "
               "calling session's own account",
    reproduction="authenticate as principal B, request principal A's account id, observe 200",
    counterfactual="B reads A's record, which B has no authorization to see",
    confidence="medium", evidence="two requests differing only in the bearer identity",
    concrete_loss="data",
    target_code_attribution="the account route's missing ownership check",
    non_target_attribution="the harness supplies only the two scope-provided test tokens",
)


def _prompts(base: str) -> dict[str, str]:
    """One representative prompt per model-facing role in the chain.

    Ordered the way the pipeline runs them, because a refusal anywhere in the chain caps
    the whole thing: recon -> hunt -> falsify -> materialize -> repair -> exploit depth.
    """
    return {
        "web_hunt": H.web_hunt_prompt(
            "authorization and object access", "unauthorized access to another "
            "principal's data, or script execution on the application's origin",
            base_urls=[base], egress_hosts=["127.0.0.1"], identities=["a", "b"],
            oob_available=False, depth=1, scope_note=SCOPE),
        "web_map": H.web_map_prompt(
            "share and render paths", "unauthorized access or script execution",
            base_urls=[base], egress_hosts=["127.0.0.1"], identities=["a", "b"],
            scope_note=SCOPE),
        "src_hunt": H.hunt_prompt(
            "authorization", "unauthorized access to another principal's data",
            1, [], ["app.py"], [], None, [], "", subsystem="authorization"),
        "fuzz": F.fuzz_prompt(
            "request parsing",
            ["a parsed request never reaches a handler with an unvalidated principal"],
            ["handler.py"], differential=False),
        # --- downstream: without these, a found bug is never proved -------------------
        "falsifier": H.verify_prompt(_FINDING, live_web=True, base_url=base,
                                     egress_hosts=["127.0.0.1"]),
        "materialize": H.materialize_prompt(_FINDING),
        "repair": H.repair_prompt(
            _FINDING, {"harness_path": ".p1hunt-poc/t.py", "expect": "pass"},
            "1 failed: assert 403 == 200", "."),
        "exploit_dev": H.exploit_dev_prompt(_FINDING, "unauthorized access to another "
                                                      "principal's data is critical"),
    }


def _session(name: str, engine: str = "", turns: int = 2):
    """A short session on the chosen engine.

    ``engine`` overrides the configured one, because the point of this tool is to COMPARE
    engines: acceptance is a property of the provider, so "which roles can this engine
    actually do" is the question, and it has a different answer per engine.
    """
    cfg = Config()
    m = cfg.models
    return make_session(model=m.worker, engine=(engine or m.engine), effort=m.codex_effort,
                        codex_model=m.codex_model, agent_name=f"probe:{name}",
                        max_turns=turns)


# A response the provider STOPPED PART-WAY, rather than refusing at the gate. This is a
# third outcome and it took a measured run to notice it: the session returns ok=True with
# real-looking text, so a naive check calls it accepted, but the content was withheld and
# any unfinished tool call never ran. For this pipeline that is nearly as bad as a refusal
# -- a truncated reply is unparseable, the role contributes nothing, and the hunt reports
# no findings for a reason nobody can see.
_PARTIAL_MARKERS = (
    "stopped by a safety classifier",
    "the rest of it was withheld",
    "response above was stopped",
)

# WHAT TRUNCATED DOES AND DOES NOT TELL YOU -- a limit of this tool, stated here because
# acting on it as if it were fatal would be as wrong as ignoring it.
#
# The notice is a MID-CONVERSATION interjection: the session continues afterwards, and the
# model can recover on a later turn. This probe reads the LAST message at the turn cap, so
# TRUNCATED means "the final turn was cut", which is ambiguous between:
#
#   (a) fatally cut -- the role never emits its JSON / never finishes the harness; and
#   (b) one turn got cut and the session carried on to a usable result.
#
# The measured evidence that this is a real ambiguity: web_hunt came back ACCEPTED at
# max_turns=2 and TRUNCATED at max_turns=6. The longer run did not get worse; it got
# further, far enough into real probing for a response-level classifier to fire on the
# model's own in-progress output. Raising the cap changes the answer, which means the
# answer is about where the cap lands, not only about the role.
#
# So TRUNCATED is a flag to go and measure the real thing (bench/run_exec.py), not a
# verdict that the role is dead. It fails this check because an unresolved ambiguity in
# the find-and-prove chain should stop you spending money on a long hunt -- not because
# the role is known to be broken.


def _classify(res) -> str:
    """ACCEPTED / REFUSED / TRUNCATED / EMPTY, strongest evidence of failure first.

    TWO BUGS LIVED HERE, both of which reported a failure as a success -- the flattering
    direction, which is the one that matters for a tool whose whole job is to tell you
    whether the engine will do the work:

      1. `res.ok or text` treated ok=True with ZERO characters as acceptance. An empty
         reply is not acceptance; it is a role that produced nothing.
      2. A mid-response safety stop was counted as acceptance because the reply was
         non-empty and ok. The text says plainly that it was cut off.
    """
    text = (res.text or "").strip()
    if T.classify_failure(text, res.error or "") == T.REASON_REFUSED:
        return "REFUSED"
    low = text.lower()
    if any(m in low for m in _PARTIAL_MARKERS):
        return "TRUNCATED"
    if not text:
        return "EMPTY"
    return "ACCEPTED"


async def probe(name: str, prompt: str, cwd: str, engine: str = "",
                turns: int = 2) -> dict:
    """Run ONE short session and classify the outcome.

    The turn cap is a real confound and has to be adjustable. Two turns is enough to learn
    whether the provider will READ the prompt and begin, which is the acceptance question.
    It is NOT enough to conclude anything from an empty reply: a role that spent both turns
    on tool calls and never emitted text looks identical to one that was blocked. Re-probe
    an EMPTY result with --turns before believing it.
    """
    t0 = time.time()
    try:
        res = await _session(name, engine, turns).run(prompt, cwd)
    except Exception as exc:
        return {"prompt": name, "verdict": "ERROR", "detail": str(exc)[:200],
                "seconds": round(time.time() - t0, 1)}
    verdict = _classify(res)
    return {"prompt": name, "engine": engine or "configured", "verdict": verdict,
            "turns": turns, "ok": bool(res.ok),
            "chars": len(res.text or ""), "error": (res.error or "")[:200],
            "head": (res.text or "").strip()[:200],
            "seconds": round(time.time() - t0, 1)}


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    engine = ""
    if "--engine" in argv:
        i = argv.index("--engine")
        engine = argv[i + 1]
        del argv[i:i + 2]
    turns = 2
    if "--turns" in argv:
        i = argv.index("--turns")
        turns = int(argv[i + 1])
        del argv[i:i + 2]
    wanted = [a for a in argv if not a.startswith("-")]

    from range_app import Range
    with Range() as rng:
        os.environ.setdefault("P1HUNT_EGRESS_ALLOWLIST", "127.0.0.1")
        os.environ.setdefault("P1HUNT_TOKEN_A", "alice")
        os.environ.setdefault("P1HUNT_TOKEN_B", "bob")
        prompts = {k: v for k, v in _prompts(rng.base).items() if v}
        if wanted:
            prompts = {k: v for k, v in prompts.items() if k in wanted}
        if not prompts:
            print(f"no such prompt. available: {', '.join(_prompts(rng.base))}")
            return 2
        box = tempfile.mkdtemp(prefix="probe_refusal_")
        print(f"probing {len(prompts)} prompt(s) against engine "
              f"'{engine or Config().models.engine}' at max_turns={turns} "
              f"(one session each)\n")
        out = []
        for name, prompt in prompts.items():
            print(f"-- {name} ({len(prompt)} chars) ...", flush=True)
            r = asyncio.run(probe(name, prompt, box, engine, turns))
            out.append(r)
            mark = {"ACCEPTED": "ok  ", "REFUSED": "REFUSED", "EMPTY": "EMPTY",
                    "TRUNCATED": "CUT OFF", "ERROR": "error"}.get(r["verdict"], "?")
            print(f"   {mark}  {r['verdict']:9} {r['seconds']}s  "
                  f"{(r.get('error') or r.get('head') or '')[:120]}\n")

    refused = [r for r in out if r["verdict"] == "REFUSED"]
    cut = [r for r in out if r["verdict"] == "TRUNCATED"]
    empty = [r for r in out if r["verdict"] == "EMPTY"]
    print("=" * 60)
    for r in out:
        print(f"  {r['verdict']:10} {r['prompt']}")
    if refused:
        print(f"\n!! {len(refused)} role(s) REFUSED at the gate. Each is a DEAD ROLE: the pipeline "
              f"will run,\n   report success, and produce nothing from it.")
    if cut:
        print(f"\n!! {len(cut)} role(s) had the response STOPPED PART-WAY by a safety classifier "
              f"({', '.join(r['prompt'] for r in cut)}).\n   The session returns ok=True with "
              f"real-looking text, so this is easy to mistake for success -- but the content was\n"
              f"   withheld and unfinished tool calls never ran. For a role that must emit parseable "
              f"JSON or write a\n   harness, a truncated reply contributes nothing.")
    if empty:
        print(f"\n!! {len(empty)} role(s) returned NO TEXT AT ALL "
              f"({', '.join(r['prompt'] for r in empty)}).\n   Not acceptance: a role that produces "
              f"nothing is indistinguishable from one that found nothing.")
    if not (refused or cut or empty):
        print("\nevery probed role was accepted and produced content.")
    suffix = (f"_{engine}" if engine else "") + (f"_t{turns}" if turns != 2 else "")
    (HERE / f"last_refusal_probe{suffix}.json").write_text(
        json.dumps(out, indent=2), encoding="utf-8")
    print(f"written: {HERE / f'last_refusal_probe{suffix}.json'}")
    return 1 if (refused or cut or empty) else 0


if __name__ == "__main__":
    raise SystemExit(main())
