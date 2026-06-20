"""EVM_CONTRACT reproduction runner (Foundry) — the deterministic verdict for Solidity proofs.

GAP THIS CLOSES: for an EVM target the prover materializes a Foundry harness (an ``invariant_*``
handler, a differential/exploit ``test*``, or a fork test). Until now that proof was JUDGED by a
model. This runner EXECUTES it with the target's real toolchain (``forge``) and computes
``reproduced`` deterministically from the parsed run + REAL coverage from ``forge coverage``.

NOTHING PRESET (spec §1): nothing here is per-program/per-protocol. The argv is DERIVED generically
from the materialized harness path + the spec ``kind`` (invariant|fork|differential|call-sequence|
exploit) — class-level Foundry knowledge only, no product names, endpoints, or playbooks.

OFFLINE-GRACEFUL: if ``forge`` is absent, the harness is missing, or the command faults, the runner
returns ``ran=False`` / ``reproduced=False`` (finding stays a candidate). Every subprocess is bounded
by a timeout and never raises out of a public method. Coverage is a SEPARATE best-effort bounded call
whose failure can never affect ``reproduced``.
"""

from __future__ import annotations

import os
import re
from typing import Any

from ..agents.fuzz_engine import parse_forge_output
from .base import (
    EventEmit,
    ReproResult,
    ReproSpec,
    excerpt,
    missing_harness_result,
    run_command,
    safe_harness_path,
)

# Foundry test-result summary line, e.g. "Test result: FAILED. 3 passed; 1 failed; 0 skipped".
_RESULT_LINE = re.compile(
    r"Test result:\s*(?P<verdict>OK|FAILED)\.\s*(?P<passed>\d+)\s+passed;\s*(?P<failed>\d+)\s+failed",
    re.IGNORECASE,
)
# Per-test pass lines, e.g. "[PASS] testFoo() (gas: 1234)" or "[PASS] invariant_x() (runs: 256, ...)".
_PASS_LINE = re.compile(r"\[PASS\]\s*(?P<name>[A-Za-z0-9_]+)")
# A forge coverage table row, e.g.
# "| src/Vault.sol | 92.31% (24/26) | 80.00% (8/10) | 50.00% (1/2) | 100.00% (3/3) |".
_COV_ROW = re.compile(
    r"\|\s*(?P<file>[^\|]+?)\s*\|\s*(?P<lines>\d+(?:\.\d+)?)%\s*\(\s*(?P<lhit>\d+)\s*/\s*(?P<ltot>\d+)\s*\)",
)

# Generic Foundry kinds this class-level runner understands (NOTHING PRESET — these are framework
# concepts, not target-specific). All map to the same `forge test` argv shape.
_KINDS = ("invariant", "fork", "differential", "call-sequence", "exploit", "property")


def _targeted(name: str, spec: ReproSpec) -> bool:
    """Did this test/invariant match what the spec asked us to prove? When the spec names a specific
    ``test_name`` we honor it exactly; otherwise any failing invariant/test is in scope."""
    if spec.test_name:
        return name == spec.test_name
    return True


def parse_forge(output: str, exit_code: int, spec: ReproSpec) -> dict[str, Any]:
    """PURE parser: turn a real ``forge test -vvv`` run into a deterministic verdict + coverage.

    Honors :meth:`ReproSpec.expects_fail`:
      * ``expect="fail"`` (invariant/property/differential style): ``reproduced`` iff a TARGETED
        invariant/test FAILED with a real assertion/counterexample (via ``parse_forge_output``).
      * ``expect="pass"`` (exploit style): ``reproduced`` iff the targeted test PASSED and the run
        reported NO failures — the exploit assertion held.

    Returns ``{reproduced, detail, coverage}`` where ``coverage["covered_symbols"]`` lists the
    tests/invariants the run actually exercised (PASS + FAIL names)."""
    text = output or ""
    failures = parse_forge_output(text)  # [{test, is_invariant, counterexample, detail}, ...]
    passed_names = []
    seen: set[str] = set()
    for m in _PASS_LINE.finditer(text):
        nm = m.group("name")
        if nm not in seen:
            seen.add(nm)
            passed_names.append(nm)

    failed_names = [f["test"] for f in failures]
    covered_symbols = list(dict.fromkeys(passed_names + failed_names))

    # Aggregate summary (best-effort — forge may print one or more "Test result:" lines).
    total_failed = 0
    total_passed = 0
    saw_summary = False
    for m in _RESULT_LINE.finditer(text):
        saw_summary = True
        total_passed += int(m.group("passed"))
        total_failed += int(m.group("failed"))

    coverage: dict[str, Any] = {"covered_symbols": covered_symbols}
    if saw_summary:
        coverage["tests_passed"] = total_passed
        coverage["tests_failed"] = total_failed

    targeted_failures = [f for f in failures if _targeted(f["test"], spec)]

    if spec.expects_fail():
        # The bug is DEMONSTRATED by a broken invariant/assertion with a counterexample.
        hit = None
        for f in targeted_failures:
            # Prefer a failure carrying a real counterexample/sequence (the PoC for free).
            if f.get("counterexample") or f.get("is_invariant"):
                hit = f
                break
        if hit is None and targeted_failures:
            hit = targeted_failures[0]
        if hit is not None:
            cex = hit.get("counterexample") or ""
            why = "invariant broken" if hit.get("is_invariant") else "assertion failed"
            detail = (
                f"{why}: {hit['test']} FAILED"
                + (f" — counterexample {cex}" if cex else "")
                + (f" — {hit['detail']}" if hit.get("detail") else "")
            )
            return {"reproduced": True, "detail": detail[:600], "coverage": coverage}
        if failed_names:
            # Failures occurred but none matched the targeted test name — not a reproduction.
            return {
                "reproduced": False,
                "detail": (
                    f"forge reported failures {failed_names[:5]} but none matched targeted "
                    f"test '{spec.test_name}'"
                ),
                "coverage": coverage,
            }
        return {
            "reproduced": False,
            "detail": "no invariant/test failed — invariants held on what was fuzzed",
            "coverage": coverage,
        }

    # expect == "pass": the exploit assertion must have HELD (targeted test passed, zero failures).
    targeted_passed = [n for n in passed_names if _targeted(n, spec)]
    if total_failed == 0 and not failed_names and (targeted_passed or (passed_names and not spec.test_name)):
        which = targeted_passed or passed_names
        return {
            "reproduced": True,
            "detail": f"exploit assertion held: {which[:5]} PASSED with no failures",
            "coverage": coverage,
        }
    if failed_names:
        return {
            "reproduced": False,
            "detail": f"expected exploit to PASS but forge reported failures {failed_names[:5]}",
            "coverage": coverage,
        }
    return {
        "reproduced": False,
        "detail": (
            f"targeted test '{spec.test_name}' did not pass"
            if spec.test_name
            else "no passing exploit test observed"
        ),
        "coverage": coverage,
    }


def parse_forge_coverage(output: str) -> dict[str, Any]:
    """PURE parser for a ``forge coverage`` % table. Returns per-file line coverage and a rolled-up
    total. Empty dict when no table is present (coverage is always best-effort)."""
    rows: list[dict[str, Any]] = []
    hit = 0
    tot = 0
    for m in _COV_ROW.finditer(output or ""):
        f = m.group("file").strip()
        if not f or f.lower() in {"file", "total"} or set(f) <= {"-"}:
            continue
        lhit = int(m.group("lhit"))
        ltot = int(m.group("ltot"))
        rows.append({"file": f, "lines_pct": float(m.group("lines")), "lines": f"{lhit}/{ltot}"})
        hit += lhit
        tot += ltot
    if not rows:
        return {}
    out: dict[str, Any] = {"files": rows}
    if tot:
        out["line_coverage_pct"] = round(100.0 * hit / tot, 2)
    return out


class EvmRunner:
    """Foundry-backed deterministic reproduction runner for EVM_CONTRACT targets (spec §10)."""

    name = "evm"

    def supports(self, target_class: str, subclass: str = "") -> bool:
        return (target_class or "").strip().upper() == "EVM_CONTRACT"

    def _build_argv(self, harness: str, spec: ReproSpec) -> list[str]:
        """DERIVE the forge argv from the materialized harness + kind + test_name. NEVER execs
        ``spec.command`` (model-supplied; injection sink)."""
        argv = ["forge", "test", "--match-path", harness, "-vvv"]
        if spec.test_name:
            argv += ["--match-test", spec.test_name]
        if spec.kind == "fork":
            fork_url = os.environ.get("P1HUNT_FORK_URL", "").strip()
            if fork_url:
                argv += ["--fork-url", fork_url]
        return argv

    def run(
        self,
        workdir: str,
        spec: ReproSpec,
        *,
        timeout: float = 600.0,
        on_event: EventEmit | None = None,
    ) -> ReproResult:
        harness = safe_harness_path(workdir, spec.harness_path)
        if harness is None:
            return missing_harness_result(
                spec, self.name, "harness missing or outside workspace — finding stays a candidate"
            )

        argv = self._build_argv(str(harness), spec)
        ran, exit_code, output = run_command(
            argv, workdir, timeout=timeout, tools_required=("forge",),
            on_event=on_event, runner=self.name,
        )
        command = " ".join(argv)
        if not ran:
            return ReproResult(
                ran=False, reproduced=False, command=command, runner=self.name,
                artifact_paths=[spec.harness_path] if spec.harness_path else [],
                stdout_excerpt=excerpt(output), detail=output,
            )

        parsed = parse_forge(output, exit_code, spec)
        coverage = dict(parsed.get("coverage") or {})

        # Best-effort REAL coverage in a SEPARATE bounded call. Its failure NEVER affects reproduced.
        try:
            cov_timeout = max(30.0, min(timeout, 300.0))
            cran, _cexit, coutput = run_command(
                ["forge", "coverage", "--match-path", str(harness)], workdir,
                timeout=cov_timeout, tools_required=("forge",),
                on_event=on_event, runner=self.name,
            )
            if cran:
                table = parse_forge_coverage(coutput)
                if table:
                    coverage.update(table)
        except Exception:  # pragma: no cover — coverage is strictly best-effort
            pass

        return ReproResult(
            ran=True,
            reproduced=bool(parsed.get("reproduced")),
            command=command,
            runner=self.name,
            artifact_paths=[spec.harness_path] if spec.harness_path else [],
            stdout_excerpt=excerpt(output),
            coverage=coverage,
            detail=str(parsed.get("detail", "")),
        )
