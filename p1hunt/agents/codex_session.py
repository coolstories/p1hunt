"""Codex engine for every live AI role in the swarm.

``CodexSession`` is a drop-in for ``ClaudeSession`` (same constructor shape + ``run()`` ->
``SessionResult``) that drives OpenAI's ``codex`` CLI (GPT-6.1 Sol, the account default) at xhigh
reasoning effort
instead of the Claude Agent SDK. It streams Codex's ``--json`` event log into the SAME event
model the cockpit renders (thinking / tool_call / output / usage), and parses the final message
with the shared ``parse_findings`` so existing prompt-role wrappers can run unchanged.

SAFETY — WHAT IS ACTUALLY ENFORCED (read this before pointing the default engine at a live
program; ``engine`` defaults to ``"codex"`` in ``config.py``, so this IS the default path):

  1. P1HUNT'S OWN BASH/EGRESS JAIL, ENFORCED PRE-EXEC. Every shell command Codex wants to run is
     routed through ``claude_session.bash_safety`` — the SAME jail the Claude engine runs under —
     by a Codex ``PreToolUse`` hook (``_CodexEgressGate``). A command that would contact a host
     outside the authorized egress allowlist is DENIED BEFORE THE PROCESS IS SPAWNED, by Codex's
     tool router. This is real enforcement, not a prompt. It replaces the previous state of this
     module, in which ``guard_check`` and ``egress_hosts`` were stored and NEVER READ, and the
     only thing keeping requests in scope was the prompt text.
  2. CODEX'S OS SANDBOX, pinned to the workspace via ``--cd`` and ``--sandbox workspace-write``.
     ``danger-full-access`` is NEVER used: it is unrestricted host filesystem AND unrestricted
     host network, which is precisely the containment hole this module used to open the moment
     live web was armed. Live web now gets ``workspace-write`` plus the narrow
     ``sandbox_workspace_write.network_access=true`` switch, which is the narrowest network
     setting codex-cli 0.166.0 offers.
  3. The prompt. Advisory only. It was never a control and is not counted as one here.

AND WHAT IS NOT — the residual risk, stated plainly:
  * The hook is a COMMAND-SHAPE check, so it inherits ``bash_egress_ok``'s limits: a destination
    computed at runtime inside a script Codex writes carries no host to extract.
    ``uninspectable_egress`` denies the cheap shapes of that; a blocklist is not airtight.
  * codex-cli FAILS OPEN on hook malfunction (verified empirically against 0.166.0: a hook that
    exits non-zero, times out, prints malformed JSON, or is missing lets the command run, and
    says nothing on stderr). The gate is therefore written to be un-crashable and to DENY on any
    internal error, and ``_attest_gate`` detects the fail-open case after the fact (shell commands
    ran, yet the gate was never consulted) and warns loudly — see ``_CodexEgressGate``.
  * codex-cli offers no host/domain allowlist for its own sandbox. ``sandbox_workspace_write``
    exposes ``network_access`` as a BOOLEAN only; the domain-level allowlist lives in its MITM
    proxy, which is gated behind the ``network_proxy`` feature flag (``experimental``, off).
  * Registering a hook non-interactively requires ``--dangerously-bypass-hook-trust``, which is a
    BLANKET trust bypass — it would also un-gate a ``.codex/`` config inside the TARGET repo, i.e.
    attacker-authored code execution. We pin the workspace to ``trust_level = "untrusted"`` in the
    same invocation to keep the target's own hooks disabled, and warn when the target ships one.
  * Hard containment still needs a container/VM with a real network policy. The gate closes the
    agent-level hole; it is not a substitute for a netns/firewall boundary.
"""

from __future__ import annotations

import asyncio
import atexit
import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

from .claude_session import SessionResult, parse_findings, _looks_rate_limited

# Inactivity timeout: Codex deep-reasoning turns can be quiet longer than the Claude stream, so
# default higher than the SDK's 300s. The swarm's per-hunter wall-clock cap still bounds the whole
# hunt regardless. Raise via P1HUNT_CODEX_TIMEOUT.
CODEX_TIMEOUT = float(os.environ.get("P1HUNT_CODEX_TIMEOUT", "900"))

# Empty = use the codex account's DEFAULT model (required for ChatGPT-account auth, which rejects
# explicit slugs like gpt-6.1-sol). Leaving this empty is self-updating: it picks up whatever the
# CLI's current default is (GPT-6.1 Sol on codex-cli 0.166.0). Set P1HUNT_CODEX_MODEL to pin a slug
# (e.g. with an API key).
DEFAULT_CODEX_MODEL = os.environ.get("P1HUNT_CODEX_MODEL", "")
DEFAULT_CODEX_EFFORT = os.environ.get("P1HUNT_CODEX_EFFORT", "xhigh")
# Fallback models (e.g. GPT-6-Luna) run at their own (lower) effort to stretch a capped quota. The
# PRIMARY (GPT-6.1 Sol) keeps xhigh — that's the deep-reasoning pass that actually finds P1s.
DEFAULT_CODEX_FALLBACK_EFFORT = os.environ.get("P1HUNT_CODEX_FALLBACK_EFFORT", "high")
try:
    OUTPUT_OVERFLOW_RETRIES = max(0, int(os.environ.get("P1HUNT_CODEX_OUTPUT_RETRIES", "1") or 0))
except ValueError:
    OUTPUT_OVERFLOW_RETRIES = 1

_IO_DISCIPLINE_MARKER = "--- P1HUNT HARD IO + CODE-REASONING CONTRACT ---"
_IO_DISCIPLINE = f"""{_IO_DISCIPLINE_MARKER}
Reason your way to the code; do not drown your session in command output.
- First build a compact map from targeted searches, then inspect only the exact functions/windows
  needed for the current hypothesis. Cite shipped file:line for every security claim.
- Never run unbounded broad dumps (`cat`/`nl`/`sed` over whole large files, recursive `find` dumps,
  or `rg --files` without a small cap). Cap broad output with `head -n 120` or equivalent; inspect
  source in <=160-line windows; use `rg -n -m` for symbol searches.
- Large files must be studied by decomposition: search symbols, read narrow windows, and summarize
  the invariant/entrypoint/state transition you actually need. Preserve context for reasoning,
  PoC construction, and proof.
- A finding requires target-owned evidence: exact in-scope code path, attacker-controlled input,
  protected quantity affected, and either a runnable proof or the precise blocker.
"""

_OUTPUT_OVERFLOW_RECOVERY_MARKER = "--- P1HUNT OUTPUT OVERFLOW RECOVERY ---"
_OUTPUT_OVERFLOW_RECOVERY = f"""{_OUTPUT_OVERFLOW_RECOVERY_MARKER}
Your previous Codex attempt failed because tool output exceeded the event parser limit. Continue the
same task from scratch, but obey these extra limits strictly:
- No command may print more than about 120 lines unless it is the final JSON answer.
- If you need a big file, locate symbols with capped `rg`, then read one <=120-line window at a time.
- Do not repeat the command shape that overflowed. Produce compact JSON at the end.
"""


# Rate-limit handling. On a usage/rate limit we wait this long then retry, repeatedly, until it
# clears — and meanwhile FAIL OVER to a non-exhausted fallback model (e.g. GPT-6-Luna when
# GPT-6.1 Sol is capped). The primary is always preferred, so the instant its cooldown lapses (its quota
# resets) the engine FAILS BACK to it automatically.
RETRY_WAIT = float(os.environ.get("P1HUNT_RATE_LIMIT_WAIT", "240"))       # 4 minutes
MAX_WAIT = float(os.environ.get("P1HUNT_RATE_LIMIT_MAX_WAIT", "3600"))    # cap one session's waiting

# Shared across every CodexSession in the process: model slug -> epoch when usable again.
_MODEL_COOLDOWN: dict[str, float] = {}


def _model_cooling(model: str) -> float:
    """Seconds until ``model`` is usable again (0 = available now)."""
    return max(0.0, _MODEL_COOLDOWN.get(model, 0.0) - time.time())


def _mark_cooldown(model: str, seconds: float) -> None:
    _MODEL_COOLDOWN[model] = time.time() + seconds


def _clear_cooldown(model: str) -> None:
    _MODEL_COOLDOWN.pop(model, None)


def model_cooldowns() -> dict:
    """Observed per-model cooldown remaining (seconds) — for the UI model-status tab."""
    now = time.time()
    return {m: max(0, int(ts - now)) for m, ts in _MODEL_COOLDOWN.items() if ts > now}


def _operator_jumpstart_requested(since_ts: float) -> bool:
    """True when the shared web/CLI jumpstart button was clicked after ``since_ts``.

    Codex keeps its own per-model cooldown map in this process. The web server runs in a different
    process, so the only reliable cross-process signal is the shared throttle file written by
    ``/api/session-limit-check`` and ``p1hunt jumpstart``.
    """
    try:
        from .. import session_limit
        doc = session_limit.read_throttle(session_limit.THROTTLE_FILE)
        at = float(doc.get("at") or 0.0)
        return bool(doc.get("manual")) and not bool(doc.get("throttled", True)) and at >= since_ts
    except (OSError, TypeError, ValueError):
        return False


def _err_kind(s: str) -> str:
    """Classify a codex error: 'rate_limited' (retry/fail-over) vs 'auth' (non-retryable) vs ''."""
    s = (s or "").lower()
    if any(k in s for k in ("usage limit", "rate limit", "rate-limit", "quota", "429",
                            "try again", "too many requests")):
        return "rate_limited"
    if any(k in s for k in ("401", "unauthor", "not supported", "invalid_request", "no auth")):
        return "auth"
    return ""


def _looks_output_overflow(s: str) -> bool:
    """True for Codex/PTY parser failures caused by oversized tool output chunks."""
    s = (s or "").lower()
    return any(k in s for k in (
        "chunk is longer than limit",
        "chunk exceed the limit",
        "separator is found, but chunk",
        "separator is not found",
        "output exceeded",
        "event parser limit",
    ))


def _with_io_discipline(prompt: str, *, retry: bool = False) -> str:
    """Append the global code-reasoning / bounded-output contract once per Codex turn."""
    prompt = prompt or ""
    if _IO_DISCIPLINE_MARKER not in prompt:
        prompt = prompt.rstrip() + "\n\n" + _IO_DISCIPLINE
    if retry and _OUTPUT_OVERFLOW_RECOVERY_MARKER not in prompt:
        prompt = prompt.rstrip() + "\n\n" + _OUTPUT_OVERFLOW_RECOVERY
    return prompt


def codex_available() -> bool:
    """True when the ``codex`` CLI is on PATH (the discovery engine can actually run)."""
    return shutil.which("codex") is not None


# =================================================================================================
# THE EGRESS GATE — real, pre-exec enforcement for engine=codex
# =================================================================================================
# codex-cli 0.166.0 ships a stable, on-by-default ``hooks`` feature with Claude-Code-shaped wire
# contracts. A ``PreToolUse`` hook receives the tool call on stdin and answers on stdout; a
# ``permissionDecision: "deny"`` is enforced by the TOOL ROUTER, before the process is spawned.
# Verified empirically against the installed 0.166.0:
#   * registering the hook with ``-c 'hooks.PreToolUse=[...]'`` works — no file is written into the
#     operator's ``$CODEX_HOME`` and their config is never mutated;
#   * ``--dangerously-bypass-hook-trust`` is REQUIRED (without it the hook silently never runs,
#     and ``-c bypass_hook_trust=true`` is explicitly ignored);
#   * the hook sees ``tool_name == "Bash"`` and ``tool_input == {"command": "<shell string>"}``,
#     normalized by Codex even though the wire tool is unified-exec;
#   * a denied command produces NO ``command_execution`` item in the ``--json`` stream at all and
#     leaves no side effect on disk, while an allowed one runs normally;
#   * the model is shown the deny REASON, so it can adapt instead of looping.
_GATE_MARKER = "P1HUNT-CODEX-EGRESS-GATE"
_GATE_HOOK_TIMEOUT = 30
# Codex error ITEMS that are advisory notices, not run failures. ``--dangerously-bypass-hook-trust``
# and an unknown-model-metadata notice both arrive as ``item.type == "error"``; treating them as a
# stream error would let a benign notice overwrite (or masquerade as) a real failure.
_ADVISORY_ERRORS = (
    "dangerously-bypass-hook-trust",
    "model metadata for",
    "enabled hooks may run without review",
)

# The hook script. Written to a private temp dir at session start, registered via ``-c``, and run
# by the host python for EVERY Bash tool call Codex attempts.
#
# DESIGN CONSTRAINT: codex-cli fails OPEN on hook malfunction, so this script must not be able to
# malfunction. It is stdlib-only, has a single bare ``except BaseException`` safety net that emits
# a DENY, emits exactly one JSON object ever, and denies rather than guesses on every unexpected
# input. It re-imports p1hunt's real jail rather than reimplementing it, so there is ONE definition
# of "allowed" across both engines.
_GATE_SCRIPT = r'''#!/usr/bin/env python3
"""P1HUNT Codex PreToolUse egress gate (GENERATED — do not edit; see agents/codex_session.py).

Reads one Codex ``pre-tool-use.command.input`` object on stdin, routes the shell command through
p1hunt's own bash/egress jail, and answers with ``permissionDecision: allow|deny`` on stdout.
Codex enforces a deny in its tool router, BEFORE the command is spawned.

FAIL-CLOSED BY CONSTRUCTION: every error path denies. Codex itself fails OPEN when a hook breaks,
so the only safe thing this script can do is never break -- and deny when it cannot decide.
"""
import json
import sys
import time

MARKER = "P1HUNT-CODEX-EGRESS-GATE"
_EMITTED = [False]


def _emit(decision, reason):
    """Answer Codex. Exactly once per run: a second object on stdout is malformed output, which
    codex-cli treats as a broken hook and FAILS OPEN on."""
    if _EMITTED[0]:
        return
    _EMITTED[0] = True
    sys.stdout.write(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny" if decision == "deny" else "allow",
        # A deny with an empty reason is rejected by codex-cli, so never let this be blank.
        "permissionDecisionReason": ("%s: %s" % (MARKER, reason or "no reason given"))[:1800],
    }}))
    sys.stdout.flush()


def _record(log_path, entry):
    """Append one decision to the gate's audit log.

    The log is not just telemetry: it is how ``_attest_gate`` proves the gate was actually
    consulted (codex-cli emits nothing about hooks in its ``--json`` stream, and fails open in
    silence). A gate that cannot write its audit trail cannot be shown to have run, so it DENIES
    rather than allow unprovable traffic."""
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
        fh.flush()


def _build_checker(cfg):
    """The jail, imported from p1hunt so both engines share ONE definition of "allowed"."""
    root = str(cfg.get("repo_root") or "")
    if root and root not in sys.path:
        sys.path.insert(0, root)
    hosts = [str(h) for h in (cfg.get("egress_hosts") or []) if str(h).strip()]
    workspace = str(cfg.get("workspace") or "") or None

    class _Perms(object):
        """Parent A's permission posture, rebuilt from the serialized config."""
        allow_network = bool(cfg.get("allow_network", True))
        allow_install = bool(cfg.get("allow_install", True))
        deny_commands = list(cfg.get("deny_commands") or [])

    try:
        from p1hunt.agents.claude_session import bash_safety
    except Exception:
        # Narrower fallback: the pure egress jail alone (no workspace write/read confinement).
        # Still a real host check -- and if THIS import fails too we deny everything, which is
        # the only honest outcome when the policy cannot be loaded.
        from p1hunt.dynamic.egress import bash_egress_ok

        def _check(command):
            return bash_egress_ok(command, hosts)
        return _check, "egress-only (bash_safety unavailable)"

    def _check(command):
        return bash_safety(command, workspace, hosts, _Perms)
    return _check, "bash_safety"


def main():
    try:
        cfg_path = sys.argv[1]
    except IndexError:
        _emit("deny", "the gate was invoked with no policy-config path -- denying (fail closed)")
        return
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            cfg = json.load(fh)
        log_path = str(cfg["log"])
    except Exception as exc:
        _emit("deny", "the gate could not read its own policy config (%s: %s) -- denying "
                      "(fail closed)" % (type(exc).__name__, exc))
        return

    def _decide(decision, reason, **extra):
        entry = {"ts": time.time(), "decision": decision, "reason": reason}
        entry.update(extra)
        try:
            _record(log_path, entry)
        except Exception as exc:
            _emit("deny", "the gate could not write its audit log (%s: %s); an unauditable "
                          "command is not an authorized one -- denying" % (type(exc).__name__, exc))
            return
        _emit(decision, reason)

    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("hook input is not a JSON object")
    except Exception as exc:
        _decide("deny", "unparseable hook input (%s) -- denying (fail closed)" % exc)
        return
    if str(event.get("hook_event_name") or "") != "PreToolUse":
        # Not ours to judge; say nothing rather than allow something we did not inspect.
        _EMITTED[0] = True
        sys.stdout.write(json.dumps({"continue": True}))
        sys.stdout.flush()
        return

    tool = str(event.get("tool_name") or "")
    tool_input = event.get("tool_input")
    if tool != "Bash":
        # File/patch tools are confined by Codex's own ``workspace-write`` sandbox + ``--cd``.
        # This gate is the COMMAND and NETWORK jail; it does not second-guess that boundary.
        _decide("allow", "non-shell tool %r is governed by the workspace sandbox" % tool,
                tool=tool)
        return
    if not isinstance(tool_input, dict):
        _decide("deny", "Bash call carried no inspectable tool_input -- denying (fail closed)")
        return
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        _decide("deny", "Bash call carried no command string to check -- denying (fail closed)")
        return

    try:
        check, engine = _build_checker(cfg)
    except Exception as exc:
        _decide("deny", "the gate could not load p1hunt's jail (%s: %s); with no policy there is "
                        "no authorization -- denying" % (type(exc).__name__, exc),
                command=command[:600])
        return
    try:
        ok, why = check(command)
    except Exception as exc:
        _decide("deny", "the jail raised while checking this command (%s: %s) -- denying "
                        "(fail closed)" % (type(exc).__name__, exc), command=command[:600])
        return
    _decide("allow" if ok else "deny", str(why), command=command[:600], jail=engine)


if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:  # noqa: BLE001 - the whole point: NOTHING may escape uninspected
        try:
            _emit("deny", "the gate itself failed (%s: %s) -- denying (fail closed)"
                          % (type(exc).__name__, exc))
        except BaseException:
            pass
'''


class _CodexEgressGate:
    """A live, pre-exec egress/bash jail for one ``codex exec`` invocation.

    Materializes :data:`_GATE_SCRIPT` plus a JSON policy file into a private temp dir and hands
    back the ``codex exec`` arguments that register it as a ``PreToolUse`` hook. After the run,
    :meth:`decisions` is the audit trail and :meth:`consulted` is the liveness proof.

    WHY A LIVENESS PROOF IS PART OF THE DESIGN: codex-cli fails OPEN when a hook breaks and says
    nothing about it in the ``--json`` stream, so "no denials" is indistinguishable from "the gate
    never ran" unless we check. ``_attest_gate`` compares the gate's decision count against the
    shell commands Codex actually executed; shell activity with an empty log means the containment
    was not in effect, and that gets a loud warning rather than silence.
    """

    def __init__(self, *, workspace: str, egress_hosts: list[str] | None,
                 perms: object | None = None) -> None:
        self.workspace = str(Path(workspace).resolve())
        self.egress_hosts = [str(h) for h in (egress_hosts or []) if str(h).strip()]
        self.perms = perms
        self.dir: str = ""
        self.script: str = ""
        self.config: str = ""
        self.log: str = ""
        self.hook_command: str = ""
        self.error: str = ""

    # --- installation -----------------------------------------------------
    def install(self) -> bool:
        """Materialize the gate. Returns False (with ``self.error`` set) if it cannot be built —
        the caller then refuses to arm live web rather than running uncontained."""
        try:
            repo_root = str(Path(__file__).resolve().parents[2])
            self.dir = tempfile.mkdtemp(prefix="p1hunt-codex-gate-")
            # Belt and braces: ``_release_gate`` removes this on every normal exit path, but a
            # crashed hunt would otherwise leave the generated script, the policy (which names the
            # engagement's authorized hosts) and the decision log sitting in $TMPDIR.
            atexit.register(shutil.rmtree, self.dir, ignore_errors=True)
            self.script = os.path.join(self.dir, "p1hunt_codex_gate.py")
            self.config = os.path.join(self.dir, "policy.json")
            self.log = os.path.join(self.dir, "decisions.jsonl")
            with open(self.script, "w", encoding="utf-8") as fh:
                fh.write(_GATE_SCRIPT)
            os.chmod(self.script, 0o700)
            policy = {
                "repo_root": repo_root,
                "workspace": self.workspace,
                "egress_hosts": self.egress_hosts,
                "allow_network": bool(getattr(self.perms, "allow_network", True))
                if self.perms is not None else True,
                "allow_install": bool(getattr(self.perms, "allow_install", True))
                if self.perms is not None else True,
                "deny_commands": [str(c) for c in
                                  (getattr(self.perms, "deny_commands", None) or [])]
                if self.perms is not None else [],
                "log": self.log,
            }
            with open(self.config, "w", encoding="utf-8") as fh:
                json.dump(policy, fh)
            # Create the log now so a 0-line read is "the gate never ran", not "no file".
            with open(self.log, "a", encoding="utf-8"):
                pass
            # Codex takes the hook as a COMMAND STRING, and we cannot know whether it shell-splits
            # or shlex-splits it. Either way a path containing whitespace would make the hook fail
            # to launch — and codex-cli fails OPEN on that, silently. So the command must contain
            # no whitespace at all, which is achieved rather than assumed.
            ok, detail = self._pin_hook_command()
            if not ok:
                self.error = detail
                return False
            # Prove the gate answers BEFORE we rely on it: a self-test on a command that must be
            # denied (an off-allowlist host) and one that must be allowed. This is the one check
            # that distinguishes a working gate from codex-cli's silent fail-open.
            ok, detail = self._self_test()
            if not ok:
                self.error = detail
                return False
        except OSError as exc:
            self.error = f"could not materialize the egress gate: {exc}"
            return False
        return True

    def _pin_hook_command(self) -> tuple[bool, str]:
        """Build a whitespace-free ``<python> <script> <config>`` command, or fail the install.

        The temp dir is under ``$TMPDIR`` (no spaces on a normal system), but ``sys.executable``
        can easily sit under a home directory with a space. Rather than guess how codex-cli splits
        the string, symlink the interpreter into the gate dir and use the link. If the result still
        contains whitespace, the gate REFUSES to install — a hook that might not launch is worse
        than no hook, because it reads as containment while providing none."""
        python = self._python()
        if any(ch.isspace() for ch in python):
            link = os.path.join(self.dir, "python3")
            try:
                os.symlink(python, link)
                python = link
            except OSError as exc:
                return False, (f"the python interpreter path {python!r} contains whitespace and "
                               f"could not be symlinked into the gate dir ({exc}); codex-cli "
                               "would silently fail to launch the hook")
        command = f"{python} {self.script} {self.config}"
        spaced = [p for p in (python, self.script, self.config) if any(c.isspace() for c in p)]
        if spaced:
            return False, (f"the egress-gate hook command would contain whitespace ({spaced}); "
                           "codex-cli would silently fail to launch it and then fail OPEN, so the "
                           "gate refuses to install rather than pretend to contain anything")
        self.hook_command = command
        return True, command

    def _self_test(self) -> tuple[bool, str]:
        """Run the gate script in-process-adjacent (a plain subprocess) on two fixed commands and
        confirm it denies the off-allowlist one and allows a benign local one. Cheap (~0.5s) and
        it catches a broken interpreter, a bad import path, or an unwritable log BEFORE Codex
        starts — i.e. before codex-cli's fail-open can hide it."""
        import subprocess

        cases = (
            ("curl https://p1hunt-gate-selftest.invalid/probe", "deny"),
            ("echo p1hunt-gate-selftest", "allow"),
        )
        for command, want in cases:
            payload = json.dumps({
                "hook_event_name": "PreToolUse", "tool_name": "Bash",
                "tool_input": {"command": command},
                "session_id": "selftest", "turn_id": "selftest", "tool_use_id": "selftest",
                "cwd": self.workspace, "model": "selftest", "permission_mode": "selftest",
                "transcript_path": "",
            })
            try:
                proc = subprocess.run(
                    [self._python(), self.script, self.config],
                    input=payload.encode(), capture_output=True, timeout=60, check=False)
            except (OSError, subprocess.SubprocessError) as exc:
                return False, f"gate self-test could not run the hook script: {exc}"
            try:
                got = json.loads(proc.stdout.decode("utf-8", "replace"))
                decision = got["hookSpecificOutput"]["permissionDecision"]
                reason = str(got["hookSpecificOutput"].get("permissionDecisionReason", ""))
            except (ValueError, KeyError, TypeError):
                return False, ("gate self-test got no usable verdict from the hook script "
                               f"(stdout={proc.stdout[:200]!r} stderr={proc.stderr[:200]!r})")
            if decision == want:
                continue
            # One legitimate way the ALLOW probe can be denied: the operator's own posture
            # (Parent A's ``deny_commands``) forbids it. That is the policy working, not a broken
            # gate, so it does not block installation. Everything else does.
            if want == "allow" and decision == "deny" and "permission policy" in reason:
                continue
            return False, (f"gate self-test FAILED: {command!r} should be {want!r} but the "
                           f"gate said {decision!r} ({reason[:160]}) — the jail is not behaving "
                           "as configured")
        # Decisions from the self-test must not pollute the liveness count.
        try:
            with open(self.log, "w", encoding="utf-8"):
                pass
        except OSError as exc:
            return False, f"gate self-test could not reset its audit log: {exc}"
        return True, "gate self-test passed (denies off-allowlist, allows local)"

    @staticmethod
    def _python() -> str:
        """The interpreter that runs the hook. ``sys.executable`` is the one we know can import
        p1hunt; fall back to PATH only when it is unavailable (frozen/embedded hosts)."""
        return sys.executable or shutil.which("python3") or "python3"

    def codex_args(self) -> list[str]:
        """The ``codex exec`` arguments that register this gate.

        ``--dangerously-bypass-hook-trust`` is unavoidable: without it codex-cli silently skips
        the hook in a non-interactive run (verified), and ``-c bypass_hook_trust=true`` is ignored.
        Because that flag bypasses trust for EVERY hook source — including a ``.codex/`` config
        inside the target repo, which is attacker-authored content — the same invocation pins the
        workspace to ``trust_level = "untrusted"``, which keeps the target's own hooks disabled.
        """
        hook = ('hooks.PreToolUse=[{matcher="*",hooks=[{type="command",command='
                f'{json.dumps(self.hook_command)},timeout={_GATE_HOOK_TIMEOUT}}}]}}]')
        return [
            "--dangerously-bypass-hook-trust",
            "-c", hook,
            # Keep the TARGET repo's own hooks/config/exec-policies disabled despite the blanket
            # trust bypass above. Without this, a `.codex/hooks.json` committed to the target runs
            # arbitrary commands at session start — "even without a model request".
            "-c", f"projects.{json.dumps(self.workspace)}.trust_level=\"untrusted\"",
            # The target's `.rules` execpolicy files are attacker-authored too, and a policy that
            # wants approval does not block under `-a never`. Do not load them.
            "--ignore-rules",
        ]

    def target_ships_codex_config(self) -> list[str]:
        """Paths of any Codex config the TARGET repo ships. Those stay disabled (see
        :meth:`codex_args`), but the operator should know the target tried."""
        found: list[str] = []
        for rel in (".codex/hooks.json", ".codex/config.toml", ".codex/rules", "hooks.json"):
            p = Path(self.workspace) / rel
            try:
                if p.exists():
                    found.append(str(p))
            except OSError:
                continue
        return found

    # --- audit ------------------------------------------------------------
    def decisions(self) -> list[dict]:
        """Every decision the gate recorded this run (the safe-harbor audit trail)."""
        out: list[dict] = []
        if not self.log:
            return out
        try:
            with open(self.log, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if isinstance(rec, dict):
                        out.append(rec)
        except OSError:
            return out
        return out

    def denials(self) -> list[dict]:
        return [d for d in self.decisions() if d.get("decision") == "deny"]

    def consulted(self) -> int:
        """How many times the gate was actually asked. 0 after Codex ran shell commands means
        codex-cli failed open and the containment was NOT in effect."""
        return len(self.decisions())

    def cleanup(self) -> None:
        if self.dir:
            shutil.rmtree(self.dir, ignore_errors=True)
            self.dir = ""


def _gate_enabled() -> bool:
    """The gate is ON by default. ``P1HUNT_CODEX_GATE=0|off|false`` disables it — an operator
    override that is always announced with a loud banner, never a silent fail-open."""
    return os.environ.get("P1HUNT_CODEX_GATE", "1").strip().lower() not in ("0", "off", "false", "no")


def _ungated_live_web_allowed() -> bool:
    """Whether the operator has explicitly accepted running live web with NO p1hunt-level egress
    enforcement. Default: no — live web is refused instead of silently uncontained."""
    return os.environ.get("P1HUNT_CODEX_ALLOW_UNGATED_WEB", "").strip().lower() in ("1", "yes", "true")


def _banner(lines: list[str]) -> str:
    """The repo's loud-warning shape (mirrors main.py's DEGRADED MODE banner)."""
    body = "\n".join(f"!! {ln}" for ln in lines)
    return "\n" + "!" * 78 + "\n" + body + "\n" + "!" * 78 + "\n"


class CodexSession:
    """One Codex hunting session, streamed and workspace-jailed — interface-compatible with
    ``ClaudeSession`` so the hunter can use either engine for discovery."""

    def __init__(
        self,
        *,
        agent_name: str,
        model: str | None = None,
        on_event: Callable[[str, str, dict], None] | None = None,
        guard_check: Callable[[str, dict], tuple[bool, str]] | None = None,
        max_turns: int = 24,
        finding_sink: Callable[[dict], None] | None = None,
        allow_web: bool = False,
        egress_hosts: list[str] | None = None,
        perms: object | None = None,
        web_budget: int | None = None,
        effort: str | None = None,
        fallback_models: list | None = None,
        fallback_effort: str | None = None,
    ) -> None:
        self.agent_name = agent_name
        # Preserve an explicit "" (means "account default — omit --model"); None falls back to default.
        self.model = model if model is not None else DEFAULT_CODEX_MODEL
        self.effort = effort or DEFAULT_CODEX_EFFORT                       # primary (GPT-6.1 Sol) -> xhigh
        self.fallback_effort = fallback_effort or DEFAULT_CODEX_FALLBACK_EFFORT  # GPT-6-Luna etc. -> high
        # Failover chain: tried in order when the primary is rate-limited. Default: GPT-6-Luna.
        if fallback_models is None:
            _env = os.environ.get("P1HUNT_CODEX_FALLBACKS", "gpt-6-luna")
            fallback_models = [m.strip() for m in _env.split(",") if m.strip()]
        self.fallback_models = fallback_models
        self.on_event = on_event or (lambda *_: None)
        # ScopeGuard's in-process tool hook cannot wrap a tool call that happens inside the codex
        # CLI's own process, so it is not the enforcement point for this engine — ``_CodexEgressGate``
        # is (it runs the SAME ``bash_safety`` jail as a Codex PreToolUse hook, pre-exec). Kept for
        # interface parity with ClaudeSession, and deliberately NOT described as containment.
        self.guard_check = guard_check
        self.max_turns = max_turns              # advisory only — Codex self-terminates a turn
        self.finding_sink = finding_sink
        self.allow_web = allow_web
        # The authorized egress allowlist. READ, not stored-and-ignored: it is serialized into the
        # gate's policy file and enforced on every shell command (see ``_ensure_gate``).
        self.egress_hosts = egress_hosts
        self.perms = perms
        self.web_budget = web_budget
        self.tool_calls = 0
        self._stream_error = ""   # set if Codex streams an error event (auth/401/rate-limit/etc.)
        self._last_progress_sig = ""
        self._last_tool_sig = ("", 0.0)
        self._gate: _CodexEgressGate | None = None
        self._gate_error = ""          # why the gate could not be installed, if it could not
        self._gate_announced = False   # the posture banner is printed once per session
        self.gate_failed_open = False  # set by _attest_gate when codex-cli bypassed the hook

    def _network_allowed(self) -> bool:
        """Network only if the engagement posture allows it AND web is granted to this agent."""
        net_ok = getattr(self.perms, "allow_network", True) if self.perms is not None else True
        return bool(self.allow_web and net_ok)

    def _installs_allowed(self) -> bool:
        return bool(getattr(self.perms, "allow_install", True)) if self.perms is not None else True

    def _install_write_dirs(self) -> list[str]:
        """User-local writable roots for non-destructive tool provisioning under Codex's sandbox.

        Codex's workspace-write sandbox is the right default, but it blocks useful installs such as
        `pip --user`, `cargo install`, or a local `jq` binary. When Parent A allows installs, expose
        the standard per-user tool/cache locations without granting full host write access.
        """
        if not self._installs_allowed():
            return []
        home = Path.home()
        candidates = [
            home / ".local",
            home / ".cache",
            home / ".cargo",
            home / ".rustup",
            home / "go",
            home / ".npm",
            home / ".config" / "npm",
        ]
        out: list[str] = []
        for p in candidates:
            try:
                p.mkdir(parents=True, exist_ok=True)
                out.append(str(p))
            except OSError:
                continue
        return out

    def _model_chain(self) -> list:
        """Models to try, primary first. Failback is automatic: the primary stays first, so once its
        cooldown lapses it's chosen again over any fallback."""
        chain = [self.model]
        for m in self.fallback_models:
            if m != self.model:
                chain.append(m)
        return chain

    def _pick_model(self):
        """The highest-priority model NOT currently cooling down, or None if all are cooling."""
        for m in self._model_chain():
            if _model_cooling(m) <= 0:
                return m
        return None

    def _effort_for(self, model) -> str:
        """Per-model reasoning effort: the primary (GPT-6.1 Sol) gets the full xhigh deep-reasoning
        pass; fallbacks (GPT-6-Luna) get a lower effort to stretch a capped quota."""
        return self.effort if model == self.model else self.fallback_effort

    def _ensure_gate(self, cwd: str) -> _CodexEgressGate | None:
        """Install (once) the ``PreToolUse`` egress gate for this session.

        Returns the gate, or None when it is disabled or could not be built — in which case
        ``self._gate_error`` says why and ``run()`` refuses to arm live web."""
        if self._gate is not None:
            return self._gate
        if not _gate_enabled():
            self._gate_error = "disabled by P1HUNT_CODEX_GATE"
            return None
        gate = _CodexEgressGate(workspace=cwd, egress_hosts=self.egress_hosts, perms=self.perms)
        if not gate.install():
            self._gate_error = gate.error or "gate installation failed"
            gate.cleanup()
            return None
        self._gate = gate
        self._gate_error = ""
        return gate

    def _release_gate(self) -> None:
        if self._gate is not None:
            self._gate.cleanup()
            self._gate = None

    def _build_cmd(self, cwd: str, last_msg_file: str, model=None) -> list[str]:
        """The codex argv (no shell). Pinned to the workspace, configured reasoning, JSONL events,
        and the p1hunt egress gate registered as a ``PreToolUse`` hook.
        Factored out so it's unit-testable without spawning Codex."""
        if model is None:
            model = self.model
        network_allowed = self._network_allowed()
        # ALWAYS ``workspace-write``. ``danger-full-access`` used to be selected the moment live
        # web was armed, which handed the agent unrestricted host filesystem AND unrestricted host
        # network — the opposite of containment, and exactly when containment matters most. Live
        # web now gets the workspace sandbox plus the narrow network switch below, which is the
        # narrowest network setting codex-cli 0.166.0 offers (there is no host allowlist: the
        # domain-level control lives in its experimental, off-by-default MITM proxy).
        sandbox = "workspace-write"
        cmd = [
            "codex", "exec",
            "--json",                       # structured event stream we map to cockpit events
            "--skip-git-repo-check",        # the target may not be a git repo
            "--cd", str(Path(cwd).resolve()), # workspace jail (absolute; subprocess cwd is also set)
            "--sandbox", sandbox,           # OS-level jail; NEVER danger-full-access
            "--output-last-message", last_msg_file,
            "-c", f'model_reasoning_effort="{self._effort_for(model)}"',
        ]
        for d in self._install_write_dirs():
            cmd += ["--add-dir", d]
        # Only pin a model when one is configured. ChatGPT-account auth rejects explicit slugs
        # (e.g. gpt-6.1-sol) and runs the account default — so an empty model => omit --model.
        if model and str(model).strip():
            cmd += ["--model", str(model)]
        if network_allowed:
            cmd += ["-c", "sandbox_workspace_write.network_access=true"]
        gate = self._ensure_gate(cwd)
        if gate is not None:
            cmd += gate.codex_args()
        return cmd

    # --- containment posture: say exactly what is enforced, every session -------------------
    def _announce_posture(self, cwd: str) -> None:
        """State the containment posture once per session, in the operator's face when it is weak.

        TRUTH IN ADVERTISING IS THE FLOOR HERE. The module used to claim "P1HUNT's egress policy
        and prompts keep requests in scope" while reading neither ``egress_hosts`` nor
        ``guard_check``. An operator must be able to tell, from the run output alone, whether host
        containment is ENFORCED or merely hoped for."""
        if self._gate_announced:
            return
        self._gate_announced = True
        gate = self._ensure_gate(cwd)
        live_web = self._network_allowed()
        hosts = [str(h) for h in (self.egress_hosts or []) if str(h).strip()]
        if gate is not None:
            shipped = gate.target_ships_codex_config()
            self.on_event(self.agent_name, "lifecycle", {
                "event": "codex_egress_gate",
                "enforcement": "pre-exec PreToolUse hook running p1hunt bash_safety",
                "sandbox": "workspace-write",
                "network_access": live_web,
                "egress_allowlist": hosts or ["(unarmed: loopback + build/registry hosts only)"],
                "target_codex_config": shipped,
                "detail": "every shell command is checked against the authorized egress allowlist "
                          "BEFORE it runs; a denied command is never spawned",
            })
            if shipped:
                msg = _banner([
                    "TARGET SHIPS ITS OWN CODEX CONFIG — it stays DISABLED, but know it is there.",
                    f"Found: {', '.join(shipped[:4])}",
                    "p1hunt pins the workspace to trust_level=\"untrusted\" and passes",
                    "--ignore-rules, so the target's hooks/exec-policies do not run. If you ever",
                    "drop those flags, that config becomes attacker-controlled code execution.",
                ])
                print(msg)
                self.on_event(self.agent_name, "lifecycle", {
                    "event": "codex_target_hooks_present", "severity": "HIGH",
                    "paths": shipped[:8],
                    "mitigation": "workspace pinned untrusted + --ignore-rules"})
            return
        # No gate. This is the state the operator must never discover by accident.
        why = self._gate_error or "unknown"
        lines = [
            "engine=codex is running with NO P1HUNT-LEVEL EGRESS ENFORCEMENT.",
            f"Cause: {why}.",
            "Containment rests ENTIRELY on Codex's own sandbox, which has NO host allowlist:",
            "its network setting is a boolean, so with network on, the agent's shell can reach",
            "ANY host. p1hunt's allowlist and the prompt are ADVISORY in this state — a prompt",
            "is not a control. One out-of-scope request violates the program's rules of",
            "engagement.",
        ]
        if live_web:
            lines.append("LIVE WEB IS ARMED. Set P1HUNT_CODEX_GATE=1 (and fix the cause above),")
            lines.append("or accept it explicitly with P1HUNT_CODEX_ALLOW_UNGATED_WEB=1.")
        print(_banner(lines))
        self.on_event(self.agent_name, "lifecycle", {
            "event": "codex_egress_gate", "severity": "HIGH",
            "enforcement": "NONE (p1hunt level) — Codex sandbox only, which has no host allowlist",
            "cause": why, "network_access": live_web,
            "warning": "engine=codex has no p1hunt egress enforcement; the allowlist and prompt "
                       "are advisory only",
        })

    def _attest_gate(self) -> None:
        """Prove, after the fact, that the gate was actually in effect — and shout if it was not.

        codex-cli FAILS OPEN on hook malfunction and reports nothing about hooks in its ``--json``
        stream, so a clean run is indistinguishable from a bypassed gate unless we compare. Codex
        emits a ``command_execution`` item only for commands it ACTUALLY RAN (a denied one
        produces no item at all), so ``tool_calls`` counts executed shell commands: executed
        commands with an empty decision log means the hook never ran and nothing was contained."""
        gate = self._gate
        if gate is None:
            return
        decisions = gate.decisions()
        denials = [d for d in decisions if d.get("decision") == "deny"]
        if denials:
            self.on_event(self.agent_name, "lifecycle", {
                "event": "codex_egress_denied", "count": len(denials),
                "commands": [str(d.get("command", ""))[:200] for d in denials[:10]],
                "reasons": [str(d.get("reason", ""))[:200] for d in denials[:10]],
                "detail": "the egress gate refused these commands before they ran"})
        if self.tool_calls > 0 and not decisions:
            self.gate_failed_open = True
            print(_banner([
                "CODEX BYPASSED THE P1HUNT EGRESS GATE — containment was NOT in effect.",
                f"Codex executed {self.tool_calls} shell command(s) and the gate was never",
                "consulted even once. codex-cli fails OPEN when a hook malfunctions and says",
                "nothing about it, so treat every command this session ran as UNCHECKED and",
                "assume it may have contacted an out-of-scope host.",
                "Live web will be REFUSED for the rest of this process unless you set",
                "P1HUNT_CODEX_ALLOW_UNGATED_WEB=1.",
            ]))
            self.on_event(self.agent_name, "lifecycle", {
                "event": "codex_egress_gate_bypassed", "severity": "CRITICAL",
                "tool_calls": self.tool_calls, "gate_decisions": 0,
                "warning": "codex-cli did not consult the PreToolUse gate; commands ran unchecked"})
            return
        self.on_event(self.agent_name, "lifecycle", {
            "event": "codex_egress_attested", "checked": len(decisions),
            "denied": len(denials), "executed": self.tool_calls,
            "detail": "every shell command this session ran passed p1hunt's bash/egress jail"})

    def _emit_item(self, item: dict, acc: list[str]) -> None:
        """Map one Codex stream item to a cockpit event (best-effort; tolerant of schema drift)."""
        itype = str(item.get("type") or item.get("item_type") or "")
        if itype in ("reasoning", "thinking"):
            txt = str(item.get("text") or item.get("content") or "")
            if txt:
                self.on_event(self.agent_name, "thinking", {"text": txt[:6000], "extended": True})
        elif itype in ("command_execution", "command", "exec", "local_shell_call"):
            cmd = str(item.get("command") or item.get("cmd") or item.get("input") or "")
            sig = f"Bash|{cmd}"
            now = time.monotonic()
            if sig == self._last_tool_sig[0] and now - self._last_tool_sig[1] < 2.0:
                return
            self._last_tool_sig = (sig, now)
            self.tool_calls += 1
            self.on_event(self.agent_name, "tool_call", {"tool": "Bash", "target": cmd[:600]})
            out = _command_output(item)
            if out:
                self.on_event(self.agent_name, "tool_output", {"text": out[:6000]})
            if os.environ.get("P1HUNT_VERBOSE_PROGRESS", "").strip() in ("1", "true", "yes"):
                self._emit_progress_for_command(cmd)
        elif itype in ("file_change", "patch", "apply_patch"):
            tgt = str(item.get("path") or item.get("files") or item.get("summary") or "")
            self.tool_calls += 1
            self.on_event(self.agent_name, "tool_call", {"tool": "Edit", "target": str(tgt)[:600]})
        elif itype in ("agent_message", "message", "assistant_message", "output_text"):
            txt = str(item.get("text") or item.get("content") or "")
            if txt:
                acc.append(txt)
                self.on_event(self.agent_name, "output", {"text": txt[:6000]})

    def _emit_progress_for_command(self, cmd: str) -> None:
        """Emit operator-readable progress for long Codex turns.

        Codex may not expose private reasoning text, and we should not invent it. The operator still
        needs to know what the agent is doing, so derive a concise status from observable actions:
        file reads, symbol searches, tests, builds, and proof runs.
        """
        msg = _progress_for_command(cmd)
        if not msg:
            return
        sig = f"{msg}|{cmd[:160]}"
        if sig == self._last_progress_sig:
            return
        self._last_progress_sig = sig
        self.on_event(self.agent_name, "message", {
            "phase": "progress",
            "detail": msg,
            "target": _progress_target(cmd),
        })

    def _handle_line(self, line: str, acc: list[str]) -> None:
        """Parse one JSONL line from ``codex exec --json`` and emit the matching event."""
        line = line.strip()
        if not line:
            return
        try:
            ev = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return  # non-JSON banner/log line — ignore
        if not isinstance(ev, dict):
            return
        etype = str(ev.get("type") or "")
        # Codex exits 0 even when the run failed (auth/401/quota) — it just streams error events.
        # Capture them so run() reports a real failure instead of a silent empty "success".
        if etype == "error" or (isinstance(ev.get("item"), dict) and ev["item"].get("type") == "error"):
            msg = str(ev.get("message") or (ev.get("item") or {}).get("message") or "error")
            low = msg.lower()
            # Codex files ADVISORY notices as error items — the hook-trust banner this engine now
            # triggers by design, and an unknown-model-metadata note. Recording them as the stream
            # error would let a benign notice overwrite (or impersonate) a real auth/quota failure.
            if any(tok in low for tok in _ADVISORY_ERRORS):
                self.on_event(self.agent_name, "lifecycle",
                              {"event": "codex_notice", "detail": msg[:200]})
                return
            self._stream_error = msg[:300]
            return
        if "item" in ev and isinstance(ev["item"], dict):
            self._emit_item(ev["item"], acc)
        elif etype in ("reasoning", "thinking", "command_execution", "agent_message",
                       "message", "file_change", "patch"):
            self._emit_item(ev, acc)
        elif etype in ("turn.completed", "usage") or "usage" in ev:
            u = ev.get("usage") or {}
            if isinstance(u, dict):
                tot = int(u.get("total_tokens") or u.get("total") or 0) or None
                self.on_event(self.agent_name, "usage",
                              {"total": tot, "input": u.get("input_tokens"),
                               "output": u.get("output_tokens"), "engine": "codex"})

    async def run(self, prompt: str, cwd: str, *, lens: str = "") -> SessionResult:
        """Run Codex with automatic rate-limit handling: prefer the primary model, FAIL OVER to a
        fallback (e.g. GPT-6-Luna) while the primary is cooling, WAIT-and-retry (4 min) when every model
        is capped, and FAIL BACK to the primary the instant its quota resets.

        Wraps the whole session in the egress gate's lifetime: the gate is installed before the
        first attempt and torn down on every exit path, so its temp dir never outlives the run."""
        try:
            return await self._run_gated(prompt, cwd, lens=lens)
        finally:
            self._release_gate()

    async def _run_gated(self, prompt: str, cwd: str, *, lens: str = "") -> SessionResult:
        if not codex_available():
            return SessionResult(ok=False, text="",
                                 error="codex CLI unavailable — install/authenticate the `codex` CLI or run deterministic mode")
        # Install the gate, say what is enforced BEFORE anything runs, then refuse to arm live web
        # uncontained. The install must come first: the posture banner only prints once per session
        # object, so it cannot be what brings the gate up on a second run().
        self._ensure_gate(cwd)
        self._announce_posture(cwd)
        refusal = self._refuse_ungated_live_web()
        if refusal is not None:
            return refusal
        waited = 0.0
        overflow_retries = 0
        while True:
            model = self._pick_model()
            if model is None:  # every model is cooling down -> wait, then re-check (auto fail-back)
                chain = self._model_chain()
                wait = min(RETRY_WAIT, max(1.0, min(_model_cooling(m) for m in chain)))
                if waited + wait > MAX_WAIT:
                    return SessionResult(ok=False, error="rate_limited",
                                         text="all codex models rate-limited — gave up this session")
                self.on_event(self.agent_name, "lifecycle",
                              {"event": "codex_rate_wait", "wait_s": int(wait),
                               "detail": f"all codex models rate-limited — waiting {int(wait)}s then retrying"})
                slept = await self._await_cooldown_or_jumpstart(wait)
                waited += slept
                continue
            run_prompt = _with_io_discipline(prompt, retry=overflow_retries > 0)
            res = await self._run_once(run_prompt, cwd, lens=lens, model=model)
            # Prove the gate was in effect for what just ran (codex-cli fails open in silence).
            self._attest_gate()
            if res.error == "output_overflow" and overflow_retries < OUTPUT_OVERFLOW_RETRIES:
                overflow_retries += 1
                self.on_event(self.agent_name, "lifecycle",
                              {"event": "codex_output_retry",
                               "attempt": overflow_retries,
                               "detail": "tool output overflowed; retrying with strict capped-output instructions"})
                continue
            if res.error == "rate_limited":
                _mark_cooldown(model, RETRY_WAIT)   # cool this model, loop -> fail over or wait
                self.on_event(self.agent_name, "lifecycle",
                              {"event": "model_status", "engine": "codex",
                               "model": model or "codex-default", "state": "rate_limited",
                               "cooldown_s": int(RETRY_WAIT)})
                continue
            if res.ok:                              # this model worked -> it's healthy again
                if _model_cooling(model) > 0 or model in _MODEL_COOLDOWN:
                    _clear_cooldown(model)
                    self.on_event(self.agent_name, "lifecycle",
                                  {"event": "model_status", "engine": "codex",
                                   "model": model or "codex-default", "state": "available"})
            return res                              # success, or a non-retryable error (auth/etc.)

    def _refuse_ungated_live_web(self) -> SessionResult | None:
        """Refuse to run a LIVE-WEB Codex session with no p1hunt egress enforcement.

        Deny-by-default applied to the containment layer itself. With live web armed and no gate,
        the agent's shell can reach any host on the internet (Codex's network setting is a boolean,
        not an allowlist) and nothing in p1hunt would see it — which is how a hunt ends up
        contacting an out-of-scope host and getting the operator banned. A static (no-network)
        session is NOT refused: it has nothing to leak and the OS sandbox still confines it.

        The operator can still proceed with ``P1HUNT_CODEX_ALLOW_UNGATED_WEB=1`` — an explicit,
        auditable acknowledgement, not a default."""
        if not self._network_allowed():
            return None
        if self._gate is not None and not self.gate_failed_open:
            return None
        if _ungated_live_web_allowed():
            self.on_event(self.agent_name, "lifecycle", {
                "event": "codex_ungated_web_acknowledged", "severity": "HIGH",
                "cause": self._gate_error or ("gate bypassed by codex-cli"
                                              if self.gate_failed_open else "no gate"),
                "warning": "operator set P1HUNT_CODEX_ALLOW_UNGATED_WEB=1 — live web is running "
                           "with NO p1hunt egress enforcement"})
            return None
        why = ("codex-cli bypassed the egress gate earlier in this process"
               if self.gate_failed_open else (self._gate_error or "the egress gate is unavailable"))
        detail = (
            "REFUSING to arm live web under engine=codex with no p1hunt egress enforcement "
            f"({why}). Codex's sandbox has no host allowlist, so an unchecked shell could contact "
            "any host and violate the program's rules of engagement. Fix the gate "
            "(P1HUNT_CODEX_GATE=1), switch to engine=claude, or accept the risk explicitly with "
            "P1HUNT_CODEX_ALLOW_UNGATED_WEB=1.")
        self.on_event(self.agent_name, "lifecycle", {
            "event": "codex_live_web_refused", "severity": "CRITICAL",
            "cause": why, "detail": detail})
        return SessionResult(ok=False, text="", error=f"egress_unenforced: {detail}")

    async def _await_cooldown_or_jumpstart(self, wait: float) -> float:
        """Wait for a Codex retry window, but let the operator's web jumpstart cut it short."""
        started = time.time() - 1.0
        deadline = time.monotonic() + max(0.0, float(wait))
        slept = 0.0
        while True:
            if _operator_jumpstart_requested(started):
                _MODEL_COOLDOWN.clear()
                self.on_event(self.agent_name, "lifecycle",
                              {"event": "model_status", "engine": "codex",
                               "model": "all", "state": "available",
                               "detail": "operator jumpstart — clearing Codex cooldowns and retrying now"})
                return slept
            rem = deadline - time.monotonic()
            if rem <= 0:
                return slept
            step = min(rem, 5.0)
            await asyncio.sleep(step)
            slept += step

    async def _run_once(self, prompt: str, cwd: str, *, lens: str = "", model=None) -> SessionResult:
        if model is None:
            model = self.model
        self._stream_error = ""
        prompt = _with_io_discipline(prompt)

        fd, last_msg_file = tempfile.mkstemp(prefix="p1hunt-codex-", suffix=".txt")
        os.close(fd)
        # LIVE BLACKBOARD: Codex has no post_finding MCP tool (only ClaudeSession does), so without
        # this the blackboard stays EMPTY during a long Codex hunt. Give Codex a file protocol — it
        # appends each finding as a JSON line the moment it finds one, and we tail that file during
        # the run and post live (parity with Claude's write-only blackboard tool).
        live_file = os.path.join(cwd, ".p1hunt_live_findings.jsonl")
        try:
            if os.path.exists(live_file):
                os.remove(live_file)
        except OSError:
            pass
        if self.finding_sink is not None:
            prompt = prompt + (
                "\n\n--- LIVE FINDINGS PROTOCOL (do this IN ADDITION to your final JSON) ---\n"
                "Post useful leads early, but never post a bare hunch. Before writing a blackboard line, "
                "do a focused depth check: identify the exact sink/endpoint/file:line, try the smallest "
                "safe PoC or escalation path you can, and record what blocked confirmation if anything. "
                "Then append ONE compact JSON line to ./.p1hunt_live_findings.jsonl (create if missing), e.g.:\n"
                "  printf '%s\\n' '{\"title\":\"...\",\"severity\":\"critical|high|medium|low\","
                "\"file\":\"path\",\"line\":N,\"root_cause\":\"...\",\"evidence\":\"...\","
                "\"attempted_escalation\":\"what you tried to prove impact\","
                "\"verification_depth\":\"code/request/PoC evidence already checked\","
                "\"blocked_by\":\"what still prevents confirmed critical, or empty\"}' >> .p1hunt_live_findings.jsonl\n"
                "One JSON object per line, appended as you go — this posts it to the team blackboard "
                "as a candidate for Parent A's verifier/prover/deep-dive pipeline. Still return your full final JSON too.")
        if self._installs_allowed():
            prompt = prompt + (
                "\n\n--- TOOLING PERMISSION ---\n"
                "If an audit utility is missing, install it yourself instead of degrading analysis. "
                "Prefer user-local, non-destructive installs that land under ~/.local, ~/.cache, "
                "~/.cargo, ~/go, or the workspace: examples include pip --user/pipx, cargo install, "
                "go install, npm with a user prefix, downloading a single official static binary, or "
                "project-local npm/pip/cargo dependencies. Do not run destructive host operations "
                "(disk formatting, reboot/shutdown, rm -rf /, secret scraping) and do not touch "
                "out-of-scope services. After installing, use the tool and keep hunting.")
        cmd = self._build_cmd(cwd, last_msg_file, model)
        self.on_event(self.agent_name, "lifecycle",
                      {"event": "codex_start", "model": model or "codex-default", "effort": self._effort_for(model)})
        acc: list[str] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=cwd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (FileNotFoundError, OSError) as exc:
            os.unlink(last_msg_file)
            return SessionResult(ok=False, text="", error=f"codex spawn failed: {exc}")

        # Feed the prompt on stdin (avoids argv length limits on large hunt prompts).
        try:
            proc.stdin.write(prompt.encode("utf-8", "replace"))
            await proc.stdin.drain()
            proc.stdin.close()
        except (BrokenPipeError, ConnectionResetError):
            pass

        posted: set = set()

        def _post(d: dict) -> None:
            """Post a finding to the blackboard sink once (dedup by title|file across live + final)."""
            if self.finding_sink is None or not isinstance(d, dict) or not d.get("title"):
                return
            key = f"{str(d.get('title',''))[:120].lower()}|{d.get('file','')}"
            if key in posted:
                return
            posted.add(key)
            try:
                self.finding_sink(d)
            except Exception:
                pass

        live_off = [0]

        def _drain_live() -> None:
            """Tail the live-findings file and post any NEW lines to the blackboard sink."""
            if self.finding_sink is None:
                return
            try:
                with open(live_file, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(live_off[0])
                    chunk = fh.read()
                    live_off[0] = fh.tell()
            except OSError:
                return
            for ln in chunk.splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    d = json.loads(ln)
                except (json.JSONDecodeError, ValueError):
                    continue
                _post(d)   # -> hunter posts it to the blackboard live (deduped)

        async def _drain() -> None:
            assert proc.stdout is not None
            last_wait = time.time()
            while True:
                try:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=30.0)
                except asyncio.TimeoutError:
                    now = time.time()
                    if now - last_wait >= 60.0:
                        last_wait = now
                        self.on_event(self.agent_name, "lifecycle", {
                            "event": "codex_waiting",
                            "detail": "reasoning over gathered evidence; waiting for next command or answer",
                        })
                    continue
                if not line:
                    break
                last_wait = time.time()
                self._handle_line(line.decode("utf-8", "replace"), acc)
                _drain_live()   # post findings the instant Codex writes them

        try:
            await _drain()
            await asyncio.wait_for(proc.wait(), timeout=CODEX_TIMEOUT)
            _drain_live()       # final sweep for any last-written findings
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            text = _read_and_unlink(last_msg_file) or "\n".join(acc)
            return SessionResult(ok=False, text=text, error="rate_limited", tool_calls=self.tool_calls)
        except Exception as exc:  # pragma: no cover - defensive
            _read_and_unlink(last_msg_file)
            err = str(exc)
            tag = "output_overflow" if _looks_output_overflow(err) else err
            return SessionResult(ok=False, text="\n".join(acc), error=tag, tool_calls=self.tool_calls)

        text = _read_and_unlink(last_msg_file) or "\n".join(acc)
        rc = proc.returncode or 0
        # A streamed error with no usable output = a failed run even though Codex exited 0.
        if self._stream_error and not text.strip():
            kind = _err_kind(self._stream_error)
            tag = "output_overflow" if _looks_output_overflow(self._stream_error) else (
                "rate_limited" if kind == "rate_limited" else
                f"auth: {self._stream_error[:160]}" if kind == "auth" else f"codex error: {self._stream_error[:160]}")
            self.on_event(self.agent_name, "lifecycle", {"event": "codex_error", "detail": self._stream_error[:200]})
            return SessionResult(ok=False, text="", error=tag, tool_calls=self.tool_calls)
        if rc != 0:
            stderr = b""
            try:
                stderr = await proc.stderr.read()
            except Exception:
                pass
            err_full = stderr.decode("utf-8", "replace")
            err = err_full[:400]
            combined = err_full + "\n" + text
            kind = _err_kind(combined)
            tag = "output_overflow" if _looks_output_overflow(combined) else (
                "rate_limited" if kind == "rate_limited" else f"codex exit {rc}: {err}")
            self.on_event(self.agent_name, "lifecycle", {"event": "codex_error", "detail": tag[:200]})
            return SessionResult(ok=False, text=text, error=tag, tool_calls=self.tool_calls)

        # Final sweep: post any findings from the final report not already posted live (deduped).
        _drain_live()
        if self.finding_sink is not None:
            for cf in parse_findings(text, lens):
                _post(cf.__dict__ if hasattr(cf, "__dict__") else {})
        try:
            os.remove(live_file)
        except OSError:
            pass
        self.on_event(self.agent_name, "lifecycle",
                      {"event": "codex_done", "tool_calls": self.tool_calls, "findings": len(posted)})
        return SessionResult(ok=True, text=text, tool_calls=self.tool_calls)


def _read_and_unlink(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except OSError:
        data = ""
    try:
        os.unlink(path)
    except OSError:
        pass
    return data


def _stringify_output(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    try:
        return json.dumps(value, ensure_ascii=False)
    except TypeError:
        return str(value)


def _command_output(item: dict) -> str:
    """Extract capped shell output from Codex command events when the stream includes it."""
    chunks: list[str] = []
    for key in ("output", "stdout", "stderr"):
        txt = _stringify_output(item.get(key)).strip()
        if txt:
            chunks.append(f"{key}: {txt}" if key == "stderr" else txt)
    result = item.get("result")
    if isinstance(result, dict):
        for key in ("output", "stdout", "stderr"):
            txt = _stringify_output(result.get(key)).strip()
            if txt:
                chunks.append(f"{key}: {txt}" if key == "stderr" else txt)
        code = result.get("exit_code", result.get("returncode"))
        if code not in (None, ""):
            chunks.append(f"exit={code}")
    code = item.get("exit_code", item.get("returncode"))
    if code not in (None, ""):
        chunks.append(f"exit={code}")
    out = "\n".join(chunks).strip()
    return out[:6000]


def _progress_target(cmd: str) -> str:
    """Best-effort file/command target for UI progress text."""
    cmd = str(cmd or "")
    patterns = [
        r"\bsed\s+-n\s+['\"][^'\"]+['\"]\s+([^|;&]+)",
        r"\bnl\s+-ba\s+([^|;&]+)",
        r"\bcat\s+([^|;&]+)",
        r"\b(?:forge|npm|pytest|ctest|cmake|make|cargo|go)\b\s*([^;&|]*)",
    ]
    for pat in patterns:
        m = re.search(pat, cmd)
        if m:
            return m.group(1).strip().strip("'\"")[:160]
    if "rg " in cmd:
        return "symbol search"
    return ""


def _progress_for_command(cmd: str) -> str:
    """Human-readable description of observable work, never hidden chain-of-thought."""
    raw = str(cmd or "")
    c = raw.lower()
    target = _progress_target(raw)
    if "rg --files" in c or "find " in c and "-type f" in c:
        return "mapping repository files and in-scope components"
    if re.search(r"\brg\b", c):
        return "searching for entrypoints, checks, and attacker-controlled data flow"
    if re.search(r"\b(sed|nl|cat)\b", c):
        if target:
            return f"reading source window: {target}"
        return "reading source window"
    if "forge test" in c or "forge " in c:
        return "running Foundry validation or proof harness"
    if "pytest" in c or "ctest" in c or re.search(r"\bmake\b", c) or "cmake" in c:
        return "building or running local tests"
    if "git status" in c:
        return "checking workspace state"
    if "curl " in c:
        return "checking authorized local/web endpoint"
    return ""
