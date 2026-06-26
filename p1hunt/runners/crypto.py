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

__all__ = ["CryptoRunner", "parse_go", "parse_cargo", "parse_pytest", "native_verdict"]

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


# A recognized fault/assertion/sanitizer report — the ONLY thing that turns a non-zero native
# run into a reproduction. A bare non-zero exit (e.g. a broken harness, a missing input file) is
# NOT a reproduction: that would let a spurious crash promote a fake P1, defeating the artifact
# floor (§10). Sanitizers (built in below) make real memory/UB bugs emit one of these markers.
_NATIVE_BUG_MARKER = re.compile(
    r"(?i)(?:Address|Undefined(?:Behavior)?|Leak|Thread|Memory)Sanitizer"
    r"|SUMMARY:\s*\w*Sanitizer"
    r"|runtime error:"
    r"|heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow"
    r"|use-after-(?:free|return|scope)|double-free|attempting free on address"
    r"|Assertion\b.*\bfailed|assertion\b.*\bfailed"
    r"|\bAborted\b|\(core dumped\)|Segmentation fault|Floating point exception"
    r"|ERROR:\s*libFuzzer|libFuzzer:\s*(?:deadly signal|out-of-memory|timeout)"
    r"|panicked at"
)


def native_verdict(output: str, exit_code: int, spec: ReproSpec) -> dict[str, Any]:
    """PURE verdict for a compiled C/C++ harness run — deterministic, unit-tested.

    ``expect="fail"`` (property/invariant/differential): reproduced ONLY when the run printed a
    recognized fault/assertion/sanitizer report (``_NATIVE_BUG_MARKER``). A non-zero exit WITHOUT
    such a marker stays a candidate — it is more likely a broken harness than a demonstrated bug,
    and the artifact floor must not be bought with an ambiguous crash.

    ``expect="pass"`` (exploit/forgery): reproduced when the binary exited 0 AND printed no fault
    marker — i.e. the exploit assertion held cleanly.
    """
    text = output or ""
    marker = bool(_NATIVE_BUG_MARKER.search(text))
    if spec.expects_fail():
        if marker:
            return {"reproduced": True,
                    "detail": "native harness reported a fault/assertion/sanitizer error "
                              f"(exit={exit_code}) — bug demonstrated",
                    "coverage": {}}
        if exit_code != 0:
            return {"reproduced": False,
                    "detail": f"harness exited non-zero (exit={exit_code}) but printed NO recognized "
                              "fault/assertion/sanitizer marker — stays candidate (harness may be broken)",
                    "coverage": {}}
        return {"reproduced": False,
                "detail": "native harness ran clean — the property held", "coverage": {}}
    # expect == "pass"
    clean = exit_code == 0 and not marker
    detail = ("exploit assertion held (clean exit, no fault)" if clean
              else f"exploit did not hold cleanly (exit={exit_code}, fault_marker={marker})")
    return {"reproduced": clean, "detail": detail, "coverage": {}}


# ---------------------------------------------------------------------------
# Concrete runner.
# ---------------------------------------------------------------------------
_LIB_RE = re.compile(r"^lib(.+?)\.(so|a)$")


def _discover_link_flags(root: Path, *, max_libs: int = 8) -> list[str]:
    """Discover libraries the build actually produced under ``root`` and return link flags
    (``-L``/``-l``/``-Wl,-rpath``) so a native harness can link the REAL in-scope library. Pure
    discovery of what's on disk — no per-target names. Shared libs (preferred) carry their own
    NEEDED deps, so linking the built target library can pull its transitive dependencies. Empty
    when the build produced nothing to link (then a harness must be self-contained, exactly as
    before)."""
    names: list[str] = []
    libdirs: list[str] = []
    try:
        found = sorted(root.rglob("lib*.so")) + sorted(root.rglob("lib*.a"))
    except OSError:
        return []
    for p in found:
        if not p.is_file():
            continue
        m = _LIB_RE.match(p.name)
        if not m:
            continue
        nm = m.group(1)
        if nm in names:
            continue
        names.append(nm)
        d = str(p.parent)
        if d not in libdirs:
            libdirs.append(d)
        if len(names) >= max_libs:
            break
    if not names:
        return []
    flags: list[str] = []
    for d in libdirs:
        flags += [f"-L{d}", f"-Wl,-rpath,{d}"]
    flags += [f"-l{nm}" for nm in names]
    flags.append("-lpthread")
    return flags


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
        # Native C/C++ harness: compile it, then run the binary. This is the path that lets a C++
        # crypto/MPC finding actually REPRODUCE (Go/Rust/Python already have toolchains below).
        if harness.suffix.lower() in (".c", ".cc", ".cpp", ".cxx"):
            return self._run_native(root, harness, spec, timeout, on_event)
        # Shell-script harness: an MPC PoC often needs a build+drive script (configure, compile a
        # multi-party harness against the real lib, run it). Execute it and judge by the SAME
        # marker/exit-code logic as native (a sanitizer/assert/abort marker or a clean exit).
        if harness.suffix.lower() == ".sh":
            return self._run_script(root, harness, spec, timeout, on_event)
        # CMake harness: the lib's own test framework. Configure → build → ctest; verdict from ctest.
        if harness.name == "CMakeLists.txt" or harness.suffix.lower() == ".cmake":
            return self._run_cmake(root, harness, spec, timeout, on_event)
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

    # -- native C/C++ compile-and-run (class-level; NOTHING PRESET) ---------------------------
    def _run_native(self, root: Path, harness: Path, spec: ReproSpec, timeout: float,
                    on_event: EventEmit | None) -> ReproResult:
        """Compile a C/C++ harness (preferring a sanitizer build) and run the binary; the verdict is
        decided by :func:`native_verdict`, which is MARKER-GATED — a bare non-zero exit alone is NOT
        a reproduction (it may just be a broken harness). For expect='fail' the bug is demonstrated
        by a sanitizer/assert/abort marker (or a libFuzzer crash); for expect='pass' by a clean exit
        of the exploit assertion. A standalone harness compiles as-is; one that must link the in-scope
        library compiles only if its includes resolve — if it cannot compile, the finding stays a
        candidate (offline-graceful), never a false reproduction."""
        is_c = harness.suffix.lower() == ".c"
        compiler = next((c for c in (("cc", "gcc", "clang") if is_c else ("c++", "g++", "clang++"))
                         if tool_available(c)), None)
        if compiler is None:
            return missing_harness_result(
                spec, self.name, "no C/C++ compiler (cc/c++) available — stays candidate")
        binary = root / ".p1hunt-poc" / (harness.stem + ".p1bin")
        binary.parent.mkdir(parents=True, exist_ok=True)
        std = [] if is_c else ["-std=c++17"]
        # Derived include dirs so a harness that #includes the in-scope library's headers resolves
        # them (generic, not per-target). The build tree (built by build_env) is where compiled
        # objects/libs land for linking.
        includes = [f"-I{root}", f"-I{root / 'include'}", f"-I{root / 'src'}", f"-I{root / 'build'}"]
        # Link any library the build actually produced (generic discovery — NOTHING preset), with
        # rpath, so a harness that exercises the in-scope library links + runs.
        # Shared libs carry their own NEEDED deps (crypto/zstd/...); this is what lets a real
        # lib-dependent PoC deterministically CONFIRM instead of only compiling toy reimplementations.
        link = _discover_link_flags(root)
        # libFuzzer harness? (defines LLVMFuzzerTestOneInput) — drive it with the fuzzer runtime.
        try:
            is_fuzzer = "LLVMFuzzerTestOneInput" in harness.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            is_fuzzer = False
        # Sanitizers make REAL memory/UB bugs emit a recognized marker (the only thing that promotes
        # an expect="fail" run). Try a sanitized build first; fall back to a plain build for
        # toolchains/harnesses that can't link the sanitizer/fuzzer runtime (then verdict relies on
        # assertions/aborts only — still marker-gated, never a bare non-zero exit).
        san = "fuzzer,address,undefined" if is_fuzzer else "address,undefined"
        ctimeout = max(30.0, min(timeout, 300.0))
        base = [compiler, *std, "-g", "-O1", "-fno-omit-frame-pointer", *includes]
        cran, cexit, cout = run_command(
            [*base, f"-fsanitize={san}", str(harness), "-o", str(binary), *link], str(root),
            timeout=ctimeout, tools_required=(compiler,), on_event=on_event, runner=self.name)
        sanitized = cran and cexit == 0 and binary.exists()
        if not sanitized:
            cran, cexit, cout = run_command(
                [compiler, *std, "-O2", *includes, str(harness), "-o", str(binary), *link], str(root),
                timeout=ctimeout, tools_required=(compiler,), on_event=on_event, runner=self.name)
            if not cran or cexit != 0 or not binary.exists():
                return missing_harness_result(
                    spec, self.name, f"harness did not compile ({compiler}): {excerpt(cout, 600)}")
        # Run the harness. A libFuzzer binary needs a bounded campaign; a plain harness just runs.
        run_argv = [str(binary)] + (["-runs=200000", "-max_total_time=30"] if is_fuzzer and sanitized else [])
        ran, exit_code, output = run_command(
            run_argv, str(root), timeout=timeout, on_event=on_event, runner=self.name)
        command = (f"{compiler} {'-fsanitize=' + san + ' ' if sanitized else ''}{harness.name} "
                   f"-o {binary.name} && ./{binary.name}")
        if not ran:
            return missing_harness_result(spec, self.name, output or "binary did not run")
        parsed = native_verdict(output, exit_code, spec)
        return ReproResult(
            ran=True, reproduced=bool(parsed["reproduced"]), command=command,
            artifact_paths=[spec.harness_path] if spec.harness_path else [],
            stdout_excerpt=excerpt(output), detail=parsed["detail"],
            coverage=parsed.get("coverage", {}) or {}, runner=self.name)

    def _run_script(self, root: Path, harness: Path, spec: ReproSpec, timeout: float,
                    on_event: EventEmit | None) -> ReproResult:
        """Execute a PoC shell script (the agent's build+drive script) and judge it with the SAME
        marker/exit-code logic as a native run. The script is in the sandbox (.p1hunt-poc) and runs
        in the workspace; bounded by timeout, never raises. NOTHING PRESET — we run the script the
        agent materialized, we do not synthesize commands."""
        ran, exit_code, output = run_command(
            ["bash", str(harness)], str(root), timeout=timeout,
            tools_required=("bash",), on_event=on_event, runner=self.name)
        if not ran:
            return missing_harness_result(spec, self.name, output or "script did not run")
        parsed = native_verdict(output, exit_code, spec)
        return ReproResult(
            ran=True, reproduced=bool(parsed["reproduced"]),
            command=f"bash {harness.name}", artifact_paths=[spec.harness_path],
            stdout_excerpt=excerpt(output), detail=parsed["detail"],
            coverage=parsed.get("coverage", {}) or {}, runner=self.name)

    def _run_cmake(self, root: Path, harness: Path, spec: ReproSpec, timeout: float,
                   on_event: EventEmit | None) -> ReproResult:
        """Configure → build → ctest a CMake harness (the lib's own test framework). Verdict from
        ctest: expect='fail' reproduces when a test FAILS; expect='pass' reproduces when ALL pass.
        A configure/build failure leaves the finding a candidate (offline-graceful)."""
        if not tool_available("cmake"):
            return missing_harness_result(spec, self.name, "cmake not available — stays candidate")
        src = harness.parent
        build = src / "build"
        budget = max(60.0, timeout)
        cfg_ran, cfg_exit, cfg_out = run_command(
            ["cmake", "-S", str(src), "-B", str(build)], str(root),
            timeout=min(budget, 300.0), tools_required=("cmake",), on_event=on_event, runner=self.name)
        if not cfg_ran or cfg_exit != 0:
            return missing_harness_result(spec, self.name, f"cmake configure failed: {excerpt(cfg_out, 500)}")
        b_ran, b_exit, b_out = run_command(
            ["cmake", "--build", str(build)], str(root),
            timeout=min(budget, 600.0), tools_required=("cmake",), on_event=on_event, runner=self.name)
        if not b_ran or b_exit != 0:
            return missing_harness_result(spec, self.name, f"cmake build failed: {excerpt(b_out, 500)}")
        t_ran, t_exit, t_out = run_command(
            ["ctest", "--test-dir", str(build), "--output-on-failure"], str(root),
            timeout=budget, tools_required=("ctest",), on_event=on_event, runner=self.name)
        if not t_ran:
            return missing_harness_result(spec, self.name, "ctest did not run — stays candidate")
        all_passed = t_exit == 0
        if spec.expects_fail():
            reproduced = not all_passed   # a failing test demonstrates the broken invariant
            detail = ("ctest reported a FAILING test (bug demonstrated, expect=fail)" if reproduced
                      else "all ctest tests passed; expected a failure to demonstrate the bug")
        else:
            reproduced = all_passed       # the exploit assertion held
            detail = ("ctest: all tests passed (exploit assertion held, expect=pass)" if reproduced
                      else "ctest reported failures; exploit not demonstrated")
        return ReproResult(
            ran=True, reproduced=reproduced, command="cmake build && ctest",
            artifact_paths=[spec.harness_path], stdout_excerpt=excerpt(t_out),
            detail=detail, coverage={}, runner=self.name)

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
