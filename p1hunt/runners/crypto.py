"""Reproduction runner for CRYPTO_LIB / native-code targets (spec §10, §1 NOTHING PRESET).

The gap this closes: a cryptographic-library finding (a broken property, a differential
mismatch against a reference, a recovered key, a constant-time violation, a forged signature)
can only be PROMOTED to a confirmed critical when the target's OWN test toolchain executes a
materialized harness and the result deterministically demonstrates the bug. A model judging its
own proof is not enough for a P1 hunter.

This runner is GENERIC PER TARGET CLASS — nothing is preset per program/library/algorithm. It
observes the materialized workspace and DERIVES the toolchain from the build files actually
present:

  * ``go.mod``        -> ``go test`` (or ``go test -fuzz`` for kind=="fuzz")
  * ``Cargo.toml``    -> ``cargo test`` (or ``cargo fuzz run`` for kind=="fuzz" when cargo-fuzz exists)
  * a ``.py`` harness -> ``pytest``

It NEVER executes ``spec.command`` (model-supplied -> injection sink); the argv is derived from
the validated harness path + ``spec.kind`` + ``spec.test_name``. Subprocesses are bounded by a
timeout and never raise. If the toolchain or harness is absent it returns ``ran=False`` so the
finding stays a candidate (OFFLINE-GRACEFUL).

``expect`` semantics for crypto (honored via :meth:`ReproSpec.expects_fail`):
  * ``expect="fail"``  — a property / differential / invariant test whose FAILURE (a real
    assertion failure or counterexample) demonstrates the bug.
  * ``expect="pass"``  — an exploit / key-recovery / forgery test whose PASS demonstrates it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from p1hunt.runners.base import (
    EventEmit,
    ReproResult,
    ReproSpec,
    excerpt,
    missing_harness_result,
    run_command,
    safe_harness_path,
    tool_available,
)

__all__ = ["CryptoRunner", "parse_go", "parse_cargo", "parse_pytest"]

# Toolchains, in detection order. Each entry: (build-file marker, primary tool).
_GO_MOD = "go.mod"
_CARGO_TOML = "Cargo.toml"

# ---------------------------------------------------------------------------
# Pure parsers — no I/O, deterministic, unit-tested with realistic sample output.
# Each returns {reproduced: bool, detail: str, coverage: dict}. ``reproduced`` honors
# spec.expects_fail(): for expect="fail" the targeted property test must FAIL with a real
# assertion/counterexample; for expect="pass" the targeted exploit test must PASS.
# ---------------------------------------------------------------------------

# go test result lines, e.g. "--- FAIL: TestSign (0.01s)" / "--- PASS: TestSign (0.00s)"
_GO_RESULT = re.compile(r"^--- (PASS|FAIL): (\S+)", re.MULTILINE)
# go test -cover, e.g. "ok   pkg/crypto   0.123s  coverage: 87.5% of statements"
_GO_COVER = re.compile(r"coverage:\s*([\d.]+)%")
# go test final verdict lines
_GO_OK = re.compile(r"^ok\s", re.MULTILINE)
_GO_FAIL = re.compile(r"^FAIL", re.MULTILINE)
# go fuzz crash, e.g. "Failing input written to testdata/fuzz/FuzzX/abcd"
_GO_FUZZ_CRASH = re.compile(r"Failing input written to (\S+)")


def parse_go(output: str, exit_code: int, spec: ReproSpec) -> dict[str, Any]:
    """Parse ``go test`` / ``go test -fuzz`` output into a verdict."""
    failed = [m.group(2) for m in _GO_RESULT.finditer(output) if m.group(1) == "FAIL"]
    passed = [m.group(2) for m in _GO_RESULT.finditer(output) if m.group(1) == "PASS"]
    cover_m = _GO_COVER.search(output)
    fuzz_crash = _GO_FUZZ_CRASH.search(output)

    coverage: dict[str, Any] = {}
    if cover_m:
        coverage["statement_pct"] = float(cover_m.group(1))
    # Covered symbols = the tests actually exercised (pass or fail); for fuzz, the target.
    covered = passed + failed
    if fuzz_crash:
        coverage["crasher"] = fuzz_crash.group(1)
        if spec.test_name and spec.test_name not in covered:
            covered.append(spec.test_name)
    if covered:
        coverage["covered_symbols"] = covered

    target = spec.test_name
    if spec.expects_fail():
        # A property/differential test FAILING (or a fuzz crasher) demonstrates the bug.
        if fuzz_crash:
            return {"reproduced": True,
                    "detail": f"go fuzz found a failing input: {fuzz_crash.group(1)}",
                    "coverage": coverage}
        if target:
            hit = target in failed
            detail = (f"targeted test {target} FAILED (property/invariant broken)" if hit
                      else f"targeted test {target} did not fail "
                           f"(failed={failed or 'none'}, exit={exit_code})")
            return {"reproduced": hit, "detail": detail, "coverage": coverage}
        # No specific target: any real test failure demonstrates the broken property.
        real_fail = bool(failed) or (exit_code != 0 and bool(_GO_FAIL.search(output)))
        detail = (f"go test reported failures: {failed or 'package-level FAIL'}" if real_fail
                  else f"go test passed — property held (exit={exit_code})")
        return {"reproduced": real_fail, "detail": detail, "coverage": coverage}

    # expect="pass": the exploit/key-recovery test must PASS to demonstrate the bug.
    if target:
        hit = target in passed and target not in failed
        detail = (f"exploit test {target} PASSED (bug demonstrated)" if hit
                  else f"exploit test {target} did not pass "
                       f"(failed={failed or 'none'}, exit={exit_code})")
        return {"reproduced": hit, "detail": detail, "coverage": coverage}
    clean = exit_code == 0 and not failed and bool(_GO_OK.search(output))
    detail = ("go test passed — exploit assertions held" if clean
              else f"go test did not pass cleanly (failed={failed or 'none'}, exit={exit_code})")
    return {"reproduced": clean, "detail": detail, "coverage": coverage}


# cargo test result lines, e.g. "test sign::verifies ... FAILED" / "... ok"
_CARGO_RESULT = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)", re.MULTILINE)
# cargo summary, e.g. "test result: FAILED. 3 passed; 1 failed; 0 ignored"
_CARGO_SUMMARY = re.compile(
    r"test result:\s*(ok|FAILED)\.\s*(\d+)\s+passed;\s*(\d+)\s+failed", re.MULTILINE)
# cargo fuzz crash, e.g. "Failing input: fuzz/artifacts/target/crash-abcd"
_CARGO_FUZZ_CRASH = re.compile(r"(?:Failing input|artifact_prefix.*?crash-\S+|crash-[0-9a-f]+)")
_CARGO_FUZZ_CRASH_PATH = re.compile(r"((?:fuzz/artifacts/\S+|\S*crash-[0-9a-f]+))")


def parse_cargo(output: str, exit_code: int, spec: ReproSpec) -> dict[str, Any]:
    """Parse ``cargo test`` / ``cargo fuzz run`` output into a verdict."""
    failed = [m.group(1) for m in _CARGO_RESULT.finditer(output) if m.group(2) == "FAILED"]
    passed = [m.group(1) for m in _CARGO_RESULT.finditer(output) if m.group(2) == "ok"]
    summary = _CARGO_SUMMARY.search(output)
    fuzz_crash = _CARGO_FUZZ_CRASH.search(output) if spec.kind == "fuzz" else None

    coverage: dict[str, Any] = {}
    if summary:
        coverage["passed"] = int(summary.group(2))
        coverage["failed"] = int(summary.group(3))
    covered = passed + failed
    if fuzz_crash:
        path_m = _CARGO_FUZZ_CRASH_PATH.search(output)
        if path_m:
            coverage["crasher"] = path_m.group(1)
        if spec.test_name and spec.test_name not in covered:
            covered.append(spec.test_name)
    if covered:
        coverage["covered_symbols"] = covered

    target = spec.test_name
    if spec.expects_fail():
        if fuzz_crash:
            return {"reproduced": True,
                    "detail": f"cargo fuzz found a crash: {coverage.get('crasher', 'crash')}",
                    "coverage": coverage}
        if target:
            hit = any(target == f or target in f for f in failed)
            detail = (f"targeted test {target} FAILED (property/invariant broken)" if hit
                      else f"targeted test {target} did not fail "
                           f"(failed={failed or 'none'}, exit={exit_code})")
            return {"reproduced": hit, "detail": detail, "coverage": coverage}
        real_fail = bool(failed) or (summary is not None and summary.group(1) == "FAILED")
        detail = (f"cargo test reported failures: {failed or 'summary FAILED'}" if real_fail
                  else f"cargo test passed — property held (exit={exit_code})")
        return {"reproduced": real_fail, "detail": detail, "coverage": coverage}

    # expect="pass"
    if target:
        hit = any(target == p or target in p for p in passed) and \
            not any(target == f or target in f for f in failed)
        detail = (f"exploit test {target} PASSED (bug demonstrated)" if hit
                  else f"exploit test {target} did not pass "
                       f"(failed={failed or 'none'}, exit={exit_code})")
        return {"reproduced": hit, "detail": detail, "coverage": coverage}
    clean = (exit_code == 0 and not failed
             and (summary is None or summary.group(1) == "ok"))
    detail = ("cargo test passed — exploit assertions held" if clean
              else f"cargo test did not pass cleanly (failed={failed or 'none'}, exit={exit_code})")
    return {"reproduced": clean, "detail": detail, "coverage": coverage}


# pytest result lines / summary, e.g. "test_x.py::test_sign FAILED" and "1 failed, 2 passed"
_PYTEST_NODE = re.compile(r"^(\S+::\S+)\s+(PASSED|FAILED|ERROR)", re.MULTILINE)
_PYTEST_FAIL_HDR = re.compile(r"^FAILED\s+(\S+)", re.MULTILINE)
_PYTEST_PASS_HDR = re.compile(r"^PASSED\s+(\S+)", re.MULTILINE)
_PYTEST_SUMMARY = re.compile(r"(\d+)\s+failed", re.MULTILINE)
_PYTEST_PASS_SUMMARY = re.compile(r"(\d+)\s+passed", re.MULTILINE)
_PYTEST_NO_TESTS = re.compile(r"no tests ran", re.IGNORECASE)


def parse_pytest(output: str, exit_code: int, spec: ReproSpec) -> dict[str, Any]:
    """Parse ``pytest -q`` output into a verdict."""
    nodes_failed = [m.group(1) for m in _PYTEST_NODE.finditer(output)
                    if m.group(2) in ("FAILED", "ERROR")]
    nodes_passed = [m.group(1) for m in _PYTEST_NODE.finditer(output) if m.group(2) == "PASSED"]
    nodes_failed += _PYTEST_FAIL_HDR.findall(output)
    nodes_passed += _PYTEST_PASS_HDR.findall(output)
    # Dedup, preserve order.
    failed = list(dict.fromkeys(nodes_failed))
    passed = list(dict.fromkeys(nodes_passed))

    n_failed_m = _PYTEST_SUMMARY.search(output)
    n_passed_m = _PYTEST_PASS_SUMMARY.search(output)
    n_failed = int(n_failed_m.group(1)) if n_failed_m else len(failed)
    n_passed = int(n_passed_m.group(1)) if n_passed_m else len(passed)

    coverage: dict[str, Any] = {"failed": n_failed, "passed": n_passed}
    covered = passed + failed
    if covered:
        coverage["covered_symbols"] = covered

    no_tests = bool(_PYTEST_NO_TESTS.search(output)) or (n_failed == 0 and n_passed == 0
                                                         and not failed and not passed)
    target = spec.test_name

    def _matches(name: str, names: list[str]) -> bool:
        return any(name == n or name in n for n in names)

    if spec.expects_fail():
        if target:
            hit = _matches(target, failed)
            detail = (f"targeted test {target} FAILED (property/invariant broken)" if hit
                      else f"targeted test {target} did not fail "
                           f"(failed={failed or 'none'}, exit={exit_code})")
            return {"reproduced": hit, "detail": detail, "coverage": coverage}
        real_fail = (n_failed > 0 or bool(failed)) and not no_tests
        detail = (f"pytest reported {n_failed} failure(s): {failed or 'see output'}" if real_fail
                  else "pytest reported no failures — property held"
                       if not no_tests else "pytest ran no tests (inconclusive)")
        return {"reproduced": real_fail, "detail": detail, "coverage": coverage}

    # expect="pass"
    if target:
        hit = _matches(target, passed) and not _matches(target, failed)
        detail = (f"exploit test {target} PASSED (bug demonstrated)" if hit
                  else f"exploit test {target} did not pass "
                       f"(failed={failed or 'none'}, exit={exit_code})")
        return {"reproduced": hit, "detail": detail, "coverage": coverage}
    clean = exit_code == 0 and n_failed == 0 and not failed and not no_tests
    detail = ("pytest passed — exploit assertions held" if clean
              else "pytest did not pass cleanly"
                   if not no_tests else "pytest ran no tests (inconclusive)")
    return {"reproduced": clean, "detail": detail, "coverage": coverage}


# ---------------------------------------------------------------------------
# Concrete runner.
# ---------------------------------------------------------------------------
class CryptoRunner:
    """Deterministic executor for CRYPTO_LIB and native-code targets (registry name ``crypto``)."""

    name = "crypto"

    def supports(self, target_class: str, subclass: str = "") -> bool:
        cls = (target_class or "").strip().upper()
        return cls in ("CRYPTO_LIB", "NATIVE", "NATIVE_CODE")

    def run(self, workdir: str, spec: ReproSpec, *, timeout: float = 600.0,
            on_event: EventEmit | None = None) -> ReproResult:
        harness = safe_harness_path(workdir, spec.harness_path)
        if harness is None:
            return missing_harness_result(
                spec, self.name, "harness path missing or outside workspace — stays candidate")

        root = Path(workdir).resolve()
        toolchain = self._detect_toolchain(root, harness, spec)
        if toolchain is None:
            return missing_harness_result(
                spec, self.name,
                "no recognized toolchain (go.mod/Cargo.toml/.py harness) — stays candidate")

        tool, argv, parser = toolchain
        if not tool_available(tool):
            return missing_harness_result(
                spec, self.name, f"toolchain '{tool}' not available — stays candidate")

        ran, exit_code, output = run_command(
            argv, str(root), timeout=timeout, tools_required=(tool,),
            on_event=on_event, runner=self.name,
        )
        command = " ".join(argv)
        if not ran:
            return missing_harness_result(spec, self.name, output or "toolchain did not run")

        parsed = parser(output, exit_code, spec)
        return ReproResult(
            ran=True,
            reproduced=bool(parsed.get("reproduced", False)),
            command=command,
            artifact_paths=[spec.harness_path] if spec.harness_path else [],
            stdout_excerpt=excerpt(output),
            coverage=parsed.get("coverage", {}) or {},
            detail=parsed.get("detail", ""),
            runner=self.name,
        )

    # -- toolchain derivation (NOTHING PRESET: chosen from files present in the workspace) ----
    def _detect_toolchain(self, root: Path, harness: Path, spec: ReproSpec):
        """Return (tool, argv, parser) derived from build files present, or None.

        ``go`` (go.mod) and ``cargo`` (Cargo.toml) operate on the workspace package; the ``.py``
        harness path is validated and executed via pytest. Never execs spec.command."""
        # go.mod present -> go test (or go test -fuzz for kind=="fuzz")
        if (root / _GO_MOD).is_file():
            return ("go", _go_argv(spec), parse_go)
        # Cargo.toml present -> cargo test (or cargo fuzz run when cargo-fuzz exists)
        if (root / _CARGO_TOML).is_file():
            return _cargo_toolchain(spec)
        # else: a python harness
        if harness.suffix == ".py":
            return ("pytest", ["pytest", "-q", str(harness)], parse_pytest)
        return None


# ---------------------------------------------------------------------------
# Argv builders (module-level, pure given the spec) — derive the command from spec.kind +
# spec.test_name. They never include spec.command.
# ---------------------------------------------------------------------------
def _go_argv(spec: ReproSpec) -> list[str]:
    if spec.kind == "fuzz" and spec.test_name:
        return ["go", "test", "-fuzz", spec.test_name, "-fuzztime", "30s", "./..."]
    return ["go", "test", "-run", spec.test_name or ".", "-count=1", "-cover", "./..."]


def _cargo_toolchain(spec: ReproSpec):
    if spec.kind == "fuzz" and tool_available("cargo-fuzz") and spec.test_name:
        # `cargo fuzz` is provided by the `cargo-fuzz` binary; argv invokes the cargo subcommand.
        return ("cargo", ["cargo", "fuzz", "run", spec.test_name, "--", "-max_total_time=30"],
                parse_cargo)
    argv = ["cargo", "test"]
    if spec.test_name:
        argv.append(spec.test_name)
    return ("cargo", argv, parse_cargo)
