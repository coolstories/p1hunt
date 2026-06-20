"""Web/API reproduction runner — the deterministic verdict layer for WEB_API targets and the
generic OTHER/unknown fallback (spec §10, §1 NOTHING PRESET).

The gap this closes: a web/authz finding ("an unauthenticated request reached an admin route",
"an IDOR returned another tenant's record") must not be promoted on a Claude session's say-so. A
prover materializes a runnable harness into the sandbox — a pytest property/exploit script, or a
Playwright/Node end-to-end script — and this runner DERIVES the toolchain argv itself from the
harness file (never executing the model-supplied ``spec.command`` — that would be an injection
sink), runs it under the real toolchain, and PARSES the real output into a deterministic verdict
plus REAL coverage (pytest-cov TOTAL% / per-file lines + exercised test ids).

NOTHING PRESET: the toolchain is selected purely by the harness file extension observed at runtime
(``*.py`` -> pytest, ``*.spec.ts``/``*.test.ts``/``*.spec.js`` -> Playwright, else -> node). There
is no per-program/per-route/per-endpoint literal anywhere here — only class-level derivation.

OFFLINE-GRACEFUL: if the harness is missing/out-of-sandbox or the toolchain is absent, the runner
returns ``ran=False`` / ``reproduced=False`` (the finding stays a candidate). Every subprocess is
bounded by a timeout and never raises out of a public method.
"""

from __future__ import annotations

import re
from pathlib import Path

from p1hunt.runners.base import (
    EventEmit,
    ReproResult,
    ReproSpec,
    excerpt,
    missing_harness_result,
    run_command,
    safe_harness_path,
)

# Harness-file suffixes that select the JS/TS e2e (Playwright) toolchain rather than plain node.
_PLAYWRIGHT_SUFFIXES: tuple[str, ...] = (".spec.ts", ".test.ts", ".spec.js", ".test.js")


# ---------------------------------------------------------------------------
# Pure parsers (UNIT-TESTED with sample tool output — no subprocess involved).
# ---------------------------------------------------------------------------
# pytest summary line, e.g. "==== 1 failed, 3 passed, 1 error in 0.12s ====".
_PYTEST_COUNT_RE = re.compile(r"(\d+)\s+(passed|failed|error|errors|xfailed|xpassed|skipped)")
# A failing/erroring test id, e.g. "FAILED tests/test_authz.py::test_idor - AssertionError".
_PYTEST_FAIL_ID_RE = re.compile(r"^(?:FAILED|ERROR)\s+(\S+)", re.MULTILINE)
# A collected/passing test id from verbose output, e.g. "tests/x.py::test_y PASSED".
_PYTEST_PASS_ID_RE = re.compile(r"^(\S+::\S+)\s+PASSED", re.MULTILINE)
# pytest-cov total line, e.g. "TOTAL    120    18    85%".
_COV_TOTAL_RE = re.compile(r"^TOTAL\s+(\d+)\s+(\d+)\s+(\d+)%", re.MULTILINE)
# pytest-cov per-file line, e.g. "app/routes.py   40   4   90%".
_COV_FILE_RE = re.compile(r"^([\w./\\-]+\.py)\s+(\d+)\s+(\d+)\s+(\d+)%(?:\s+([\d,\-\s]+))?$", re.MULTILINE)


def _pytest_counts(output: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for num, label in _PYTEST_COUNT_RE.findall(output):
        key = "error" if label in ("error", "errors") else label
        counts[key] = counts.get(key, 0) + int(num)
    return counts


def _parse_pytest_cov(output: str) -> dict:
    """Extract pytest-cov coverage (TOTAL% + per-file line stats) when present."""
    cov: dict = {}
    total = _COV_TOTAL_RE.search(output)
    if total:
        stmts, miss, pct = (int(total.group(i)) for i in (1, 2, 3))
        cov["total_percent"] = pct
        cov["statements"] = stmts
        cov["missed"] = miss
    files: dict[str, dict] = {}
    for m in _COV_FILE_RE.finditer(output):
        name = m.group(1)
        if name.upper() == "TOTAL":
            continue
        files[name] = {
            "statements": int(m.group(2)),
            "missed": int(m.group(3)),
            "percent": int(m.group(4)),
        }
    if files:
        cov["files"] = files
    return cov


def parse_pytest(output: str, exit_code: int, spec: ReproSpec) -> dict:
    """Deterministic verdict from pytest output.

    Honors ``spec.expects_fail()``: for an invariant/property harness (expect='fail') the bug is
    DEMONSTRATED when the targeted test FAILED with a real assertion/error; for an exploit/authz
    PoC (expect='pass') the bug is DEMONSTRATED when the targeted test PASSED — the unauthorized
    action succeeded and its assertion held.
    """
    output = output or ""
    counts = _pytest_counts(output)
    passed = counts.get("passed", 0)
    failed = counts.get("failed", 0)
    errors = counts.get("error", 0)
    fail_ids = _PYTEST_FAIL_ID_RE.findall(output)
    pass_ids = _PYTEST_PASS_ID_RE.findall(output)

    coverage = _parse_pytest_cov(output)
    # Exercised symbols: prefer explicit test ids, fall back to the failing ids.
    covered = list(dict.fromkeys(pass_ids + fail_ids))
    if covered:
        coverage["covered_symbols"] = covered

    expects_fail = spec.expects_fail()
    no_tests_ran = (passed + failed + errors) == 0

    if no_tests_ran:
        reproduced = False
        detail = "pytest collected/ran no tests — finding stays a candidate"
    elif expects_fail:
        reproduced = (failed + errors) > 0
        if reproduced:
            shown = ", ".join(fail_ids[:5]) if fail_ids else "(unnamed)"
            detail = (
                f"invariant/property harness broke: {failed} failed, {errors} errored "
                f"[{shown}] — bug demonstrated (expect=fail)"
            )
        else:
            detail = f"all {passed} test(s) passed; expected a failure to demonstrate the bug"
    else:  # expect == "pass": exploit/authz assertion that the attack worked
        reproduced = (failed + errors) == 0 and passed > 0
        if reproduced:
            shown = ", ".join(pass_ids[:5]) if pass_ids else "(unnamed)"
            detail = (
                f"exploit/authz assertion held: {passed} passed [{shown}] — the unauthorized "
                f"action succeeded (expect=pass)"
            )
        else:
            detail = (
                f"exploit assertion did NOT hold: {failed} failed, {errors} errored — "
                "attack not demonstrated"
            )
    return {"reproduced": reproduced, "detail": detail, "coverage": coverage}


# A Playwright summary, e.g. "2 passed (1.2s)" / "1 failed" / "1 flaky".
_PW_COUNT_RE = re.compile(r"(\d+)\s+(passed|failed|flaky|skipped|did not run)")
# A Playwright failing spec line, e.g. "  1) [chromium] › authz.spec.ts:12:3 › admin reachable".
_PW_FAIL_ID_RE = re.compile(r"^\s*\d+\)\s+(.+?)\s*$", re.MULTILINE)
# A passing/ok line in list-reporter output, e.g. "  ✓  1 authz.spec.ts:12:3 › admin reachable".
_PW_OK_ID_RE = re.compile(r"^\s*[✓√]\s+\d*\s*(.+?)\s*(?:\(\d+(?:\.\d+)?m?s\))?\s*$", re.MULTILINE)


def parse_playwright(output: str, exit_code: int, spec: ReproSpec) -> dict:
    """Deterministic verdict from Playwright (or plain ``node``) output.

    Same ``spec.expects_fail()`` semantics as :func:`parse_pytest`. When no Playwright summary is
    present (a bare ``node`` script), fall back to the process exit code: exit 0 == the script's
    assertions held.
    """
    output = output or ""
    counts = {label: int(num) for num, label in _PW_COUNT_RE.findall(output)}
    passed = counts.get("passed", 0)
    failed = counts.get("failed", 0) + counts.get("flaky", 0)
    fail_ids = [s.strip() for s in _PW_FAIL_ID_RE.findall(output) if s.strip()]
    ok_ids = [s.strip() for s in _PW_OK_ID_RE.findall(output) if s.strip()]

    coverage: dict = {}
    covered = list(dict.fromkeys(ok_ids + fail_ids))
    if covered:
        coverage["covered_symbols"] = covered

    expects_fail = spec.expects_fail()
    has_summary = bool(counts)

    if not has_summary:
        # Plain node harness with no test-runner summary: rely on exit code.
        held = exit_code == 0
        if expects_fail:
            reproduced = not held
            detail = (
                "node harness exited non-zero (assertion broke) — bug demonstrated (expect=fail)"
                if reproduced
                else "node harness exited 0; expected a failure to demonstrate the bug"
            )
        else:
            reproduced = held
            detail = (
                "node harness exited 0 (exploit assertion held) — unauthorized action "
                "succeeded (expect=pass)"
                if reproduced
                else f"node harness exited {exit_code}; exploit not demonstrated"
            )
        return {"reproduced": reproduced, "detail": detail, "coverage": coverage}

    if expects_fail:
        reproduced = failed > 0
        if reproduced:
            shown = "; ".join(fail_ids[:5]) if fail_ids else "(unnamed)"
            detail = f"e2e invariant broke: {failed} failed [{shown}] — bug demonstrated (expect=fail)"
        else:
            detail = f"all {passed} spec(s) passed; expected a failure to demonstrate the bug"
    else:
        reproduced = failed == 0 and passed > 0
        if reproduced:
            shown = "; ".join(ok_ids[:5]) if ok_ids else "(unnamed)"
            detail = (
                f"e2e exploit assertion held: {passed} passed [{shown}] — unauthorized action "
                "succeeded (expect=pass)"
            )
        else:
            detail = f"exploit spec did NOT hold: {failed} failed — attack not demonstrated"
    return {"reproduced": reproduced, "detail": detail, "coverage": coverage}


# ---------------------------------------------------------------------------
# Toolchain selection — derived purely from the harness file (NOTHING PRESET).
# ---------------------------------------------------------------------------
def _select_toolchain(harness: Path, spec: ReproSpec) -> tuple[str, list[str], tuple[str, ...]]:
    """Return ``(tool, argv, tools_required)`` derived from the materialized harness + spec.

    No model-supplied command string is ever executed — the argv is built here from the validated
    harness path, its extension, and ``spec.test_name``.
    """
    name = harness.name.lower()
    path_str = str(harness)
    if name.endswith(_PLAYWRIGHT_SUFFIXES):
        argv = ["npx", "playwright", "test", path_str]
        if spec.test_name:
            argv += ["-g", spec.test_name]
        return "npx", argv, ("npx",)
    if name.endswith(".py"):
        argv = ["pytest", "-q", path_str]
        if spec.test_name:
            argv += ["-k", spec.test_name]
        # Best-effort coverage of the harness's package dir; pytest ignores --cov gracefully if the
        # plugin is absent only when it IS installed, so this is purely opportunistic.
        argv += ["--cov", str(harness.parent), "--cov-report=term-missing"]
        return "pytest", argv, ("pytest",)
    # Anything else (.js/.mjs/.cjs/...) runs as a plain node script.
    return "node", ["node", path_str], ("node",)


class WebRunner:
    """Deterministic reproduction runner for WEB_API targets and the generic OTHER fallback."""

    name = "web"

    def supports(self, target_class: str, subclass: str = "") -> bool:
        cls = (target_class or "").upper()
        # WEB_API is the dedicated class; everything else (OTHER/unknown) falls back here, except
        # classes that have their own dedicated runner in the registry.
        dedicated = {"EVM_CONTRACT", "CRYPTO_LIB", "INFRA", "SUPPLY_CHAIN", "MOBILE_APP"}
        return cls == "WEB_API" or cls not in dedicated

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
                spec, self.name,
                "harness missing or outside the sandbox — finding stays a candidate",
            )

        tool, argv, tools_required = _select_toolchain(harness, spec)
        ran, exit_code, output = run_command(
            argv, workdir, timeout=timeout, tools_required=tools_required,
            on_event=on_event, runner=self.name,
        )
        command = " ".join(argv)
        if not ran:
            return ReproResult(
                ran=False, reproduced=False, command=command, runner=self.name,
                artifact_paths=[spec.harness_path], stdout_excerpt=excerpt(output),
                detail=output or f"toolchain '{tool}' did not run — finding stays a candidate",
            )

        if tool == "pytest":
            parsed = parse_pytest(output, exit_code, spec)
        else:
            parsed = parse_playwright(output, exit_code, spec)

        return ReproResult(
            ran=True,
            reproduced=bool(parsed["reproduced"]),
            command=command,
            runner=self.name,
            artifact_paths=[spec.harness_path],
            stdout_excerpt=excerpt(output),
            coverage=parsed.get("coverage", {}),
            detail=parsed.get("detail", ""),
        )
