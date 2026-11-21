"""Reproduction-runner contract — the deterministic verdict layer (spec §10, §1 NOTHING PRESET).

The believe-but-verify floor used to end at a Claude session JUDGING its own proof. That is too
loose for a P1 hunter: a "critical" could be promoted on the model's say-so. This module replaces
the judgement with EXECUTION. A ``ReproductionRunner``:

  * takes a ``ReproSpec`` (what harness was materialized into the sandbox, and what outcome
    DEMONSTRATES the bug), produced by the prover when it writes real harness files;
  * DERIVES the toolchain command itself from the harness path + kind (it never blindly executes
    a model-supplied command string — that would be an injection sink), runs it with the target's
    real toolchain, and PARSES the real output;
  * returns a structured :class:`ReproResult` whose ``reproduced`` flag is computed deterministically
    from the parsed result, plus REAL coverage parsed from the tool (not model-reported).

NOTHING PRESET: a runner is generic per TARGET CLASS, selected by :func:`select_runner` from the
class derived from the actual target — never a per-target/per-program playbook.

OFFLINE-GRACEFUL: if the toolchain is absent, the harness is missing, or the command cannot launch,
a runner returns ``ran=False`` / ``reproduced=False`` — so the finding stays a CANDIDATE and is
never promoted to a confirmed critical. Every subprocess is bounded by a timeout and never raises.
The same applies to a harness that broke before it could test anything (a collection/import error)
and to a request an edge/WAF answered instead of the target: neither is evidence about the target,
so both report ``ran=False`` rather than a verdict. See ``ReproSpec.expect`` below and the
``expect`` convention in ``p1hunt/runners/web.py`` for which outcome demonstrates a bug.
"""

from __future__ import annotations

import importlib
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol, runtime_checkable

# (agent, kind, data) — mirrors EventEmit in agents/claude_session.py so wiring is thin.
EventEmit = Callable[[str, str, dict], None]


@dataclass
class ReproResult:
    """The deterministic outcome of executing a proof harness. ``reproduced`` is the ONLY thing
    that may promote a finding to a confirmed critical (see ClaudeSwarm)."""

    ran: bool = False                                   # did the toolchain actually execute?
    reproduced: bool = False                            # did execution DEMONSTRATE the bug?
    command: str = ""                                   # the exact command the runner ran
    artifact_paths: list[str] = field(default_factory=list)
    stdout_excerpt: str = ""                            # bounded slice of the real tool output
    coverage: dict = field(default_factory=dict)        # REAL coverage parsed from the tool
    detail: str = ""                                    # why reproduced / not (parsed evidence)
    runner: str = ""                                    # which runner produced this
    target_code_attribution: str = ""
    non_target_attribution: str = ""
    attribution_notes: str = ""
    counterfactual_gate: dict = field(default_factory=dict)
    impact_blocker: str = ""

    def to_dict(self) -> dict:
        return {
            "ran": self.ran, "reproduced": self.reproduced, "command": self.command,
            "artifact_paths": list(self.artifact_paths), "stdout_excerpt": self.stdout_excerpt,
            "coverage": dict(self.coverage), "detail": self.detail, "runner": self.runner,
            "target_code_attribution": self.target_code_attribution,
            "non_target_attribution": self.non_target_attribution,
            "attribution_notes": self.attribution_notes,
            "counterfactual_gate": dict(self.counterfactual_gate),
            "impact_blocker": self.impact_blocker,
        }


@dataclass
class ReproSpec:
    """What the prover materialized, and what outcome proves the bug. Produced as JSON by the
    PoC prover when it writes a runnable harness into the sandbox."""

    harness_path: str = ""        # path to the materialized harness, relative to the workdir
    command: str = ""             # advisory only — runners DERIVE their own argv (no exec of this)
    kind: str = ""                # invariant|fork|differential|call-sequence|exploit|property|policy|...
    # Which direction the HARNESS'S OWN assertions point — not the desired outcome of the run.
    # 'fail' (the default): the harness asserts the SECURE behavior (attacker refused, invariant
    #   holds), so the bug is DEMONSTRATED when the targeted test FAILS. Every refusal-asserting
    #   harness is 'fail' — including all web authz/payments/GraphQL scaffolds.
    # 'pass': the harness asserts the INSECURE behavior (it performs the exploit and asserts it
    #   worked), so the bug is DEMONSTRATED when the targeted test PASSES.
    # Litmus test: asserting a 403 => 'fail'; asserting a 200 on another principal's object =>
    # 'pass'. The full convention (and why inverting it is a correctness bug in both directions)
    # lives in p1hunt/runners/web.py's module docstring.
    expect: str = "fail"
    test_name: str = ""           # specific test/function to target, if any
    target_code_attribution: str = ""     # exact in-scope target behavior/file:line that owns the defect
    non_target_attribution: str = ""      # harness/mock/scaffold behavior used only to drive the target
    relies_on_non_target_behavior: bool = False  # true => not a target-owned confirmed finding
    attribution_notes: str = ""
    finding_claim: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)

    @staticmethod
    def from_dict(d: dict | None) -> "ReproSpec":
        d = d or {}
        extra = d.get("extra") if isinstance(d.get("extra"), dict) else {}

        def _field(name: str, default: object = "") -> object:
            return d.get(name, extra.get(name, default))

        def _truthy(v: object) -> bool:
            if isinstance(v, bool):
                return v
            if isinstance(v, (int, float)):
                return bool(v)
            return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}

        return ReproSpec(
            harness_path=str(d.get("harness_path", d.get("poc_path", ""))).strip(),
            command=str(d.get("command", "")).strip(),
            kind=str(d.get("kind", "")).strip().lower(),
            expect=(str(d.get("expect", "fail")).strip().lower() or "fail"),
            test_name=str(d.get("test_name", "")).strip(),
            target_code_attribution=str(_field("target_code_attribution", "") or "").strip(),
            non_target_attribution=str(_field("non_target_attribution", "") or "").strip(),
            relies_on_non_target_behavior=_truthy(_field("relies_on_non_target_behavior", False)),
            attribution_notes=str(_field("attribution_notes", "") or "").strip(),
            finding_claim=dict(_field("finding_claim", {}) or {}) if isinstance(_field("finding_claim", {}), dict) else {},
            extra=extra,
        )

    def expects_fail(self) -> bool:
        return self.expect != "pass"

    def attribution_blocker(self) -> str:
        """Return a reason this spec cannot promote a confirmed target finding.

        Low-level runners intentionally remain dumb executors so their unit tests can exercise parser
        mechanics. The autonomous promotion boundary calls this method before a harness result counts:
        every reproduced bug must attribute the defective behavior to the in-scope target, not to a
        harness, mock, fixture, local scaffold, external service, or integrator-only implementation.
        """
        if self.relies_on_non_target_behavior:
            return self.attribution_notes or self.non_target_attribution or (
                "proof depends on behavior outside the in-scope target"
            )
        if not self.target_code_attribution:
            return "missing target_code_attribution; cannot tell whether the defect is target-owned"
        return ""


@runtime_checkable
class ReproductionRunner(Protocol):
    """A class-specific deterministic executor. ``name`` identifies it; ``supports`` declares which
    classes it covers; ``run`` executes the materialized harness and returns a verdict."""

    name: str

    def supports(self, target_class: str, subclass: str = "") -> bool: ...

    def run(self, workdir: str, spec: ReproSpec, *, timeout: float = 600.0,
            on_event: EventEmit | None = None) -> ReproResult: ...


# ---------------------------------------------------------------------------
# Shared helpers for concrete runners (keep execution deterministic + contained).
# ---------------------------------------------------------------------------
def tool_available(tool: str) -> bool:
    try:
        return shutil.which(tool) is not None
    except Exception:  # pragma: no cover
        return False


def safe_harness_path(workdir: str, harness_path: str) -> Path | None:
    """Resolve ``harness_path`` against ``workdir`` and return it ONLY if it stays inside the
    workdir (the workspace/sandbox) and exists. Prevents a runner from being pointed at an
    arbitrary out-of-workspace file. Returns None otherwise."""
    if not harness_path:
        return None
    root = Path(workdir).resolve()
    p = Path(harness_path)
    if not p.is_absolute():
        p = root / p
    try:
        p = p.resolve()
        p.relative_to(root)          # must stay within the workspace
    except (OSError, ValueError):
        return None
    return p if p.exists() else None


def excerpt(text: str, limit: int = 4000) -> str:
    """A bounded, tail-biased slice of tool output (failures + counterexamples live at the end)."""
    if not text:
        return ""
    text = text.strip()
    if len(text) <= limit:
        return text
    head = text[: limit // 3]
    tail = text[-(limit - limit // 3):]
    return head + "\n...[truncated]...\n" + tail


def run_command(
    argv: list[str], cwd: str, *, timeout: float = 600.0, tools_required: tuple[str, ...] = (),
    on_event: EventEmit | None = None, runner: str = "runner",
) -> tuple[bool, int, str]:
    """Execute a fixed argv (NO shell) bounded by ``timeout``. Returns ``(ran, exit_code, output)``.

    ``ran`` is False when a required tool is missing or the process cannot launch — that maps to
    "stays a candidate", never a false critical. Never raises; the event sink, if any, sees the
    command + result for observability."""
    for t in tools_required:
        if not tool_available(t):
            if on_event:
                _emit(on_event, runner, {"event": "toolchain_missing", "tool": t, "ran": False})
            return False, 127, f"toolchain '{t}' not available — finding stays a candidate"
    if on_event:
        _emit(on_event, runner, {"event": "exec", "command": " ".join(argv)})
    try:
        tmpdir = Path(cwd) / ".p1hunt-tmp"
        tmpdir.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["TMPDIR"] = str(tmpdir)
        env["TEMP"] = str(tmpdir)
        env["TMP"] = str(tmpdir)
        proc = subprocess.run(  # noqa: S603 — fixed argv (runner-derived), shell=False
            argv, cwd=str(cwd), capture_output=True, text=True, timeout=timeout, check=False,
            env=env,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if on_event:
            _emit(on_event, runner, {"event": "exec_done", "exit": proc.returncode, "bytes": len(out)})
        return True, proc.returncode, out
    except subprocess.TimeoutExpired as exc:
        out = ""
        for chunk in (getattr(exc, "stdout", None), getattr(exc, "stderr", None)):
            if isinstance(chunk, bytes):
                out += chunk.decode("utf-8", "ignore")
            elif isinstance(chunk, str):
                out += chunk
        if on_event:
            _emit(on_event, runner, {"event": "exec_timeout", "seconds": timeout})
        return True, 124, f"[timed out after {timeout:.0f}s]\n{out}"
    except (OSError, ValueError, Exception) as exc:  # never let a launch fault escape
        if on_event:
            _emit(on_event, runner, {"event": "exec_error", "detail": str(exc)})
        return False, 1, f"failed to launch: {exc}"


def _emit(on_event: EventEmit | None, runner: str, data: dict) -> None:
    if on_event is None:
        return
    try:
        on_event(f"runner:{runner}", "lifecycle", data)
    except Exception:
        pass


def missing_harness_result(spec: ReproSpec, runner: str, reason: str) -> ReproResult:
    """A uniform 'could not run' verdict (toolchain/harness absent) — stays a candidate."""
    return ReproResult(ran=False, reproduced=False, command="", runner=runner,
                       artifact_paths=([spec.harness_path] if spec.harness_path else []),
                       detail=reason)


# ---------------------------------------------------------------------------
# Class -> runner registry. Lazy import so a missing/broken optional runner module never breaks
# importing this module (or the rest of the system). Returns None when no runner fits — the
# caller then keeps the finding as a candidate (NOTHING PRESET: no fabricated reproduction).
# ---------------------------------------------------------------------------
_REGISTRY: dict[str, tuple[str, str]] = {
    "EVM_CONTRACT": ("p1hunt.runners.evm", "EvmRunner"),
    "WEB_API": ("p1hunt.runners.web", "WebRunner"),
    "CRYPTO_LIB": ("p1hunt.runners.crypto", "CryptoRunner"),
    "INFRA": ("p1hunt.runners.infra", "InfraRunner"),
    "SUPPLY_CHAIN": ("p1hunt.runners.supply_chain", "SupplyChainRunner"),
    "MOBILE_APP": ("p1hunt.runners.mobile", "MobileRunner"),
}
# Fallbacks tried (in order) when the class has no dedicated runner — a generic property/API
# runner can still execute a pytest/property harness for an OTHER/unknown target.
_FALLBACKS: tuple[tuple[str, str], ...] = (("p1hunt.runners.web", "WebRunner"),)


def _instantiate(mod_name: str, cls_name: str) -> ReproductionRunner | None:
    try:
        module = importlib.import_module(mod_name)
        runner = getattr(module, cls_name)()
        return runner
    except Exception:
        return None


def select_runner(target_class: str, subclass: str = "") -> ReproductionRunner | None:
    """Pick the deterministic runner for the derived target class (NOTHING PRESET — keyed on the
    class observed at runtime). Returns None if none fits, so the finding stays a candidate."""
    key = (target_class or "").upper()
    order: list[tuple[str, str]] = []
    if key in _REGISTRY:
        order.append(_REGISTRY[key])
    order.extend(fb for fb in _FALLBACKS if fb not in order)
    for mod_name, cls_name in order:
        runner = _instantiate(mod_name, cls_name)
        if runner is not None:
            try:
                if runner.supports(target_class, subclass):
                    return runner
            except Exception:
                continue
    return None
