"""Unit tests for p1hunt.tools.build_env (Module 1: build-environment bootstrap).

PURE logic only — no real network/build/git/forge/npm/cargo is executed. detect_build_system
runs against fixture repos built in a tempdir; summarize_build_output runs against sample
forge/hardhat/cargo logs (success + failure). bootstrap_environment is exercised only in its
offline-graceful branches (unknown repo, allow_network=False) which need no external tool.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from p1hunt.tools.build_env import (
    BuildPlan,
    BuildReport,
    bootstrap_environment,
    detect_build_system,
    summarize_build_output,
    toolchain_available,
)


def _write(root: Path, rel: str, content: str = "") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class DetectBuildSystemTest(unittest.TestCase):
    def test_foundry_repo_with_submodules(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "foundry.toml", "[profile.default]\nsolc_version = '0.8.17'\nsrc = 'src'\n")
            _write(root, ".gitmodules", '[submodule "lib/forge-std"]\n  path = lib/forge-std\n')
            _write(root, "remappings.txt", "forge-std/=lib/forge-std/src/\n")
            _write(root, "lib/forge-std/src/Test.sol", "// lib")
            _write(root, "src/Market.sol", "pragma solidity ^0.8.17;\ncontract M {}\n")
            plan = detect_build_system(str(root))
            self.assertEqual(plan.toolchain, "foundry")
            self.assertEqual(plan.build_command, "forge build")
            self.assertIn("git submodule update --init --recursive", plan.provision_commands)
            self.assertIn("forge install", plan.provision_commands)
            self.assertIn("foundry.toml", plan.config_files)
            self.assertIn(".gitmodules", plan.config_files)
            self.assertTrue(plan.needs_network)
            self.assertEqual(plan.solc_version, "0.8.17")

    def test_foundry_without_submodules_still_detected(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "foundry.toml", "[profile.default]\n")
            _write(root, "src/A.sol", "pragma solidity 0.8.20;\n")
            plan = detect_build_system(str(root))
            self.assertEqual(plan.toolchain, "foundry")
            # No submodules/lib -> no submodule provisioning, but still forge install.
            self.assertNotIn("git submodule update --init --recursive", plan.provision_commands)
            self.assertIn("forge install", plan.provision_commands)
            self.assertEqual(plan.solc_version, "0.8.20")

    def test_hardhat_repo(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "hardhat.config.ts", "export default { solidity: { version: '0.8.19' } };")
            _write(root, "package.json", '{"name":"x"}')
            _write(root, "package-lock.json", "{}")
            plan = detect_build_system(str(root))
            self.assertEqual(plan.toolchain, "hardhat")
            self.assertEqual(plan.build_command, "npx hardhat compile")
            self.assertEqual(plan.provision_commands, ["npm ci"])
            self.assertEqual(plan.solc_version, "0.8.19")

    def test_npm_repo_without_lockfile_uses_install(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "package.json", '{"name":"x","scripts":{"build":"tsc"}}')
            plan = detect_build_system(str(root))
            self.assertEqual(plan.toolchain, "npm")
            self.assertEqual(plan.provision_commands, ["npm install"])

    def test_npm_repo_with_lockfile_uses_ci(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "package.json", '{"name":"x"}')
            _write(root, "package-lock.json", "{}")
            plan = detect_build_system(str(root))
            self.assertEqual(plan.toolchain, "npm")
            self.assertEqual(plan.provision_commands, ["npm ci"])

    def test_cargo_repo(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "Cargo.toml", "[package]\nname='x'\n")
            _write(root, "Cargo.lock", "")
            plan = detect_build_system(str(root))
            self.assertEqual(plan.toolchain, "cargo")
            self.assertEqual(plan.provision_commands, ["cargo fetch"])
            self.assertEqual(plan.build_command, "cargo build")

    def test_go_repo(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "go.mod", "module x\n")
            plan = detect_build_system(str(root))
            self.assertEqual(plan.toolchain, "go")
            self.assertEqual(plan.build_command, "go build ./...")

    def test_cmake_preferred_over_make(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "CMakeLists.txt", "project(x)")
            _write(root, "Makefile", "all:\n\t echo")
            plan = detect_build_system(str(root))
            self.assertEqual(plan.toolchain, "cmake")

    def test_make_repo(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "Makefile", "all:\n\techo hi")
            plan = detect_build_system(str(root))
            self.assertEqual(plan.toolchain, "make")
            self.assertEqual(plan.build_command, "make")
            self.assertFalse(plan.needs_network)

    def test_unknown_repo(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "README.md", "hello")
            plan = detect_build_system(d)
            self.assertEqual(plan.toolchain, "unknown")

    def test_missing_dir_is_unknown(self) -> None:
        plan = detect_build_system("/nonexistent/path/xyz123")
        self.assertEqual(plan.toolchain, "unknown")

    def test_foundry_beats_npm_when_both_present(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "foundry.toml", "[profile.default]\n")
            _write(root, "package.json", '{"name":"x"}')
            plan = detect_build_system(str(root))
            self.assertEqual(plan.toolchain, "foundry")


class SummarizeBuildOutputTest(unittest.TestCase):
    def test_forge_success(self) -> None:
        out = "[⠊] Compiling...\n[⠒] Compiling 42 files with 0.8.17\nCompiler run successful!"
        s = summarize_build_output(out, "foundry")
        self.assertTrue(s["compiled"])
        self.assertEqual(s["errors"], [])

    def test_forge_success_with_warnings(self) -> None:
        out = (
            "Compiling 10 files with 0.8.17\n"
            "Warning (2018): Function state mutability can be restricted to view\n"
            "Compiler run successful with warnings"
        )
        s = summarize_build_output(out, "foundry")
        self.assertTrue(s["compiled"])
        self.assertGreaterEqual(s["warnings"], 1)

    def test_forge_failure_missing_source(self) -> None:
        out = (
            "Error (6275): Source \"lib/forge-std/src/Test.sol\" not found: File not found.\n"
            "Compilation failed"
        )
        s = summarize_build_output(out, "foundry")
        self.assertFalse(s["compiled"])
        self.assertTrue(s["errors"])

    def test_forge_failure_type_error(self) -> None:
        out = "TypeError: Member \"foo\" not found.\nCompilation failed"
        s = summarize_build_output(out, "foundry")
        self.assertFalse(s["compiled"])
        self.assertTrue(any("TypeError" in e for e in s["errors"]))

    def test_hardhat_success(self) -> None:
        out = "Compiled 3 Solidity files successfully"
        s = summarize_build_output(out, "hardhat")
        self.assertTrue(s["compiled"])

    def test_cargo_success(self) -> None:
        out = "   Compiling x v0.1.0\n    Finished dev [unoptimized + debuginfo] target(s) in 1.23s"
        s = summarize_build_output(out, "cargo")
        self.assertTrue(s["compiled"])
        self.assertEqual(s["errors"], [])

    def test_cargo_failure(self) -> None:
        out = (
            "error[E0425]: cannot find value `x` in this scope\n"
            "error: aborting due to previous error\n"
            "error: could not compile `x`"
        )
        s = summarize_build_output(out, "cargo")
        self.assertFalse(s["compiled"])
        self.assertTrue(s["errors"])

    def test_empty_output_not_compiled(self) -> None:
        self.assertFalse(summarize_build_output("", "foundry")["compiled"])
        self.assertFalse(summarize_build_output("", "cargo")["compiled"])

    def test_generic_success_and_failure(self) -> None:
        self.assertTrue(summarize_build_output("Build complete", "make")["compiled"])
        self.assertFalse(summarize_build_output("error: linker failed", "make")["compiled"])

    def test_cache_warm_foundry_is_success(self) -> None:
        # A cache-warm `forge build` prints no success marker — must NOT be read as a failure.
        for marker in ("No files changed, compilation skipped", "Nothing to compile"):
            s = summarize_build_output(marker, "foundry")
            self.assertTrue(s["compiled"], marker)
            self.assertFalse(s["failed"], marker)

    def test_failed_flag_exposed(self) -> None:
        # `failed` is True only on positive failure evidence; clean/silent output is not failed.
        self.assertTrue(summarize_build_output("Error (1234): something", "foundry")["failed"])
        self.assertFalse(summarize_build_output("", "go")["failed"])      # silent success
        self.assertFalse(summarize_build_output("", "foundry")["failed"])


class BootstrapEnvironmentTest(unittest.TestCase):
    """Only the offline-graceful branches that need no external tooling."""

    def test_unknown_repo_not_attempted(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "README.md", "x")
            rep = bootstrap_environment(d)
            self.assertIsInstance(rep, BuildReport)
            self.assertEqual(rep.toolchain, "unknown")
            self.assertFalse(rep.attempted)
            self.assertFalse(rep.compiles)
            self.assertTrue(rep.remediation)

    def test_network_required_but_disallowed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "foundry.toml", "[profile.default]\n")
            rep = bootstrap_environment(d, allow_network=False)
            self.assertEqual(rep.toolchain, "foundry")
            self.assertFalse(rep.attempted)
            self.assertIn("network", rep.remediation.lower())

    def test_missing_primary_toolchain_reports_remediation(self) -> None:
        # If forge is genuinely absent on this host, the foundry path must report it cleanly.
        if toolchain_available("forge"):
            self.skipTest("forge present; cannot exercise the missing-toolchain branch")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "foundry.toml", "[profile.default]\n")
            rep = bootstrap_environment(d, allow_network=True)
            self.assertEqual(rep.toolchain, "foundry")
            self.assertFalse(rep.attempted)
            self.assertIn("forge", rep.toolchain_missing)
            self.assertIn("foundryup", rep.remediation)

    def test_never_raises_on_bad_path(self) -> None:
        rep = bootstrap_environment("/nonexistent/xyz123")
        self.assertEqual(rep.toolchain, "unknown")
        self.assertFalse(rep.attempted)

    def test_events_emitted_for_skip_when_tool_missing(self) -> None:
        # With a make repo and make ABSENT, bootstrap should not raise and should remediate.
        # We force-absent `make` (rather than relying on the host) so the test is hermetic and
        # never spawns a real build tool — `make` has needs_network=False, so allow_network alone
        # would not stop it from running on a host where make is installed.
        from unittest import mock

        events: list[tuple] = []
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "Makefile", "all:\n\techo hi")
            with mock.patch("p1hunt.tools.build_env.toolchain_available", return_value=False):
                rep = bootstrap_environment(d, on_event=lambda *a: events.append(a), allow_network=False)
            self.assertEqual(rep.toolchain, "make")
            self.assertFalse(rep.attempted)            # primary tool missing -> not attempted
            self.assertIn("make", rep.toolchain_missing)
            self.assertTrue(rep.remediation)           # tells the operator how to install it
            self.assertIsInstance(rep, BuildReport)

    def _fake_run(self, stdout: str):
        from types import SimpleNamespace

        def _run(cmd, **kw):
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        return _run

    def test_silent_success_build_is_green(self) -> None:
        # A toolchain that is SILENT on success (e.g. `go build`) exits 0 with no marker — must be
        # reported as compiling, not false-RED'd (which would misdirect the whole hunt).
        from unittest import mock

        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "go.mod", "module x\n")
            with mock.patch("p1hunt.tools.build_env.toolchain_available", return_value=True), \
                 mock.patch("p1hunt.tools.build_env.subprocess.run", side_effect=self._fake_run("")):
                rep = bootstrap_environment(d, allow_network=True)
            self.assertEqual(rep.toolchain, "go")
            self.assertTrue(rep.attempted)
            self.assertTrue(rep.compiles, rep.diagnostics)   # exit 0 + no error line == green

    def test_cache_warm_foundry_build_is_green(self) -> None:
        from unittest import mock

        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "foundry.toml", "[profile.default]\nsolc='0.8.19'\n")
            with mock.patch("p1hunt.tools.build_env.toolchain_available", return_value=True), \
                 mock.patch("p1hunt.tools.build_env.subprocess.run",
                            side_effect=self._fake_run("No files changed, compilation skipped")):
                rep = bootstrap_environment(d, allow_network=True)
            self.assertEqual(rep.toolchain, "foundry")
            self.assertTrue(rep.compiles, rep.diagnostics)

    def test_error_in_output_is_red_even_on_exit_zero(self) -> None:
        from unittest import mock

        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "go.mod", "module x\n")
            with mock.patch("p1hunt.tools.build_env.toolchain_available", return_value=True), \
                 mock.patch("p1hunt.tools.build_env.subprocess.run",
                            side_effect=self._fake_run("error: cannot find package\n")):
                rep = bootstrap_environment(d, allow_network=True)
            self.assertFalse(rep.compiles)   # positive failure evidence overrides exit 0


class ToolchainAvailableTest(unittest.TestCase):
    def test_known_present_tool(self) -> None:
        # `ls` (or `cmd`) effectively always present; at minimum python is.
        import sys
        self.assertTrue(toolchain_available(Path(sys.executable).name) or toolchain_available("python3"))

    def test_absent_tool_is_false(self) -> None:
        self.assertFalse(toolchain_available("definitely_not_a_real_tool_zzz_999"))


if __name__ == "__main__":
    unittest.main()
