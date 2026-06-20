"""Tests for toolchain auto-provisioning (p1hunt/tools/build_env.ensure_foundry).

The reproduction gate that promotes a candidate to a CONFIRMED critical cannot execute a harness
without Foundry; on an EVM target with no ``forge`` every candidate is quarantined forever. These
tests lock in the unblocker's logic WITHOUT touching the network or installing anything: the
short-circuit when forge is present, the safe no-op when auto-install is disabled, the no-network
guard, and the PATH/dir helpers. They never weaken the artifact floor — promotion still requires a
real reproduction; this only makes the tool that performs it available.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

import p1hunt.tools.build_env as be
from p1hunt.config import Config


class FoundryBinDir(unittest.TestCase):
    def test_honors_foundry_dir(self) -> None:
        with mock.patch.dict(os.environ, {"FOUNDRY_DIR": "/tmp/fnd"}, clear=False):
            self.assertEqual(be._foundry_bin_dir(), Path("/tmp/fnd") / "bin")

    def test_default_is_home_foundry(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "FOUNDRY_DIR"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(be._foundry_bin_dir(), Path.home() / ".foundry" / "bin")


class PrependPath(unittest.TestCase):
    def test_idempotent_prepend(self) -> None:
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin"}, clear=False):
            be._prepend_path(Path("/opt/x/bin"))
            self.assertTrue(os.environ["PATH"].startswith("/opt/x/bin"))
            before = os.environ["PATH"]
            be._prepend_path(Path("/opt/x/bin"))  # again — no duplicate
            self.assertEqual(os.environ["PATH"], before)


class ActivatePath(unittest.TestCase):
    def test_prepends_existing_foundry_bin(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            bindir = Path(d) / "bin"
            bindir.mkdir()
            with mock.patch.object(be, "_foundry_bin_dir", return_value=bindir), \
                 mock.patch.dict(os.environ, {"PATH": "/usr/bin"}, clear=False):
                self.assertTrue(be.activate_foundry_path())
                self.assertTrue(os.environ["PATH"].startswith(str(bindir)))

    def test_no_dir_is_false(self) -> None:
        with mock.patch.object(be, "_foundry_bin_dir", return_value=Path("/no/such/foundry/bin")):
            self.assertFalse(be.activate_foundry_path())


class EnsureFoundry(unittest.TestCase):
    def test_short_circuit_when_forge_present(self) -> None:
        with mock.patch.object(be, "toolchain_available", return_value=True), \
             mock.patch.object(be.subprocess, "run", side_effect=AssertionError("must not exec")) as run:
            out = be.ensure_foundry(allow_install=True, allow_network=True)
            self.assertTrue(out["forge"])
            self.assertFalse(out["installed"])  # already there -> not installed by us
            run.assert_not_called()

    def test_no_install_when_disabled(self) -> None:
        with mock.patch.object(be, "toolchain_available", return_value=False), \
             mock.patch.object(be.subprocess, "run", side_effect=AssertionError("must not exec")) as run:
            out = be.ensure_foundry(allow_install=False, allow_network=True)
            self.assertFalse(out["forge"])
            self.assertIn("disabled", out["detail"])
            self.assertTrue(out["remediation"])
            run.assert_not_called()

    def test_no_network_guard(self) -> None:
        with mock.patch.object(be, "toolchain_available", return_value=False), \
             mock.patch.object(be.subprocess, "run", side_effect=AssertionError("must not exec")) as run:
            out = be.ensure_foundry(allow_install=True, allow_network=False)
            self.assertFalse(out["forge"])
            self.assertIn("network", out["detail"])
            run.assert_not_called()

    def test_never_raises_on_installer_failure(self) -> None:
        # forge stays missing; foundryup absent (isolate from any real install on this machine via
        # an empty FOUNDRY bin dir); network fetch raises -> graceful structured result, no crash.
        import tempfile

        with tempfile.TemporaryDirectory() as empty, \
             mock.patch.object(be, "toolchain_available", return_value=False), \
             mock.patch.object(be, "_foundry_bin_dir", return_value=Path(empty) / "bin"), \
             mock.patch.object(be.shutil, "which", return_value=None), \
             mock.patch("urllib.request.urlopen", side_effect=OSError("no route")):
            out = be.ensure_foundry(allow_install=True, allow_network=True)
            self.assertFalse(out["forge"])
            self.assertTrue(out["remediation"])
            self.assertIn("failed", out["detail"].lower())


class ConfigWiring(unittest.TestCase):
    def test_env_flag_enables_auto_install(self) -> None:
        with mock.patch.dict(os.environ, {"P1HUNT_AUTO_INSTALL_TOOLCHAIN": "1"}, clear=False):
            self.assertTrue(Config.from_env().auto_install_toolchain)

    def test_default_off(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "P1HUNT_AUTO_INSTALL_TOOLCHAIN"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertFalse(Config.from_env().auto_install_toolchain)


if __name__ == "__main__":
    unittest.main()
