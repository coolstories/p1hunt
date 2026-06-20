"""Tests for the Parent-A-owned runtime permission posture (PermissionPolicy).

Permissions are now layered: (1) the workspace boundary (where agents may act), (2) the
ScopeGuard semantic policy (out-of-scope / destructive / live-egress), and (3) this
PermissionPolicy — what agents may DO inside the jail (network / installs / specific
commands). Parent A OWNS layer 3: it is derived from the program rules and can be TIGHTENED
during recon, never loosened past the floor. These tests cover derivation, the clamp, the
bash enforcement, and the swarm's apply hook. Pure-logic; no SDK, no network.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from p1hunt.agents.claude_session import bash_safety
from p1hunt.config import Config
from p1hunt.models import Asset, Scope, TargetClass
from p1hunt.safety.policies import PermissionPolicy, derive_permission_policy


def _scope(rules=None, safe_harbor="", note="") -> Scope:
    return Scope(
        program="P", platform="local", disclosure_channel="x", safe_harbor_text=safe_harbor,
        severity_taxonomy={"P1": "critical"}, in_scope=[Asset("a", "repo", "repo", "repo", "local")],
        out_of_scope=[], rules=rules or [], rate_limit="10/min", scope_note=note,
    )


class Derivation(unittest.TestCase):
    def test_default_allows_network_and_install(self) -> None:
        p = derive_permission_policy(_scope(rules=["Use owned accounts."]))
        self.assertTrue(p.allow_network)
        self.assertTrue(p.allow_install)

    def test_no_network_rule_turns_egress_off(self) -> None:
        p = derive_permission_policy(_scope(rules=["Local harness only.", "No network."]))
        self.assertFalse(p.allow_network)

    def test_crypto_lib_class_is_offline(self) -> None:
        p = derive_permission_policy(_scope(rules=["analyze the library"]), TargetClass.CRYPTO_LIB)
        self.assertFalse(p.allow_network)

    def test_no_install_phrase(self) -> None:
        p = derive_permission_policy(_scope(safe_harbor="Do not install new dependencies."))
        self.assertFalse(p.allow_install)


class Clamp(unittest.TestCase):
    def test_tighten_only_cannot_reenable(self) -> None:
        floor = PermissionPolicy(allow_network=False, allow_install=True)
        # Parent A tries to re-enable network — must stay OFF (clamp).
        out = floor.tightened_with({"allow_network": True, "allow_install": False})
        self.assertFalse(out.allow_network)   # cannot loosen
        self.assertFalse(out.allow_install)   # can tighten

    def test_deny_commands_merge(self) -> None:
        floor = PermissionPolicy(deny_commands=["foundryup"])
        out = floor.tightened_with({"deny_commands": ["rm -rf", "foundryup"]})
        self.assertEqual(sorted(out.deny_commands), ["foundryup", "rm -rf"])

    def test_none_is_noop_copy(self) -> None:
        floor = PermissionPolicy(allow_network=False, deny_commands=["x"])
        out = floor.tightened_with(None)
        self.assertFalse(out.allow_network)
        self.assertEqual(out.deny_commands, ["x"])


class BashEnforcement(unittest.TestCase):
    def test_default_policy_none_is_permissive(self) -> None:
        # Unchanged loosened-jail behavior when no Parent-A policy is set.
        for cmd in ("curl https://api.test/x", "pip install requests", "git push origin main"):
            self.assertTrue(bash_safety(cmd, policy=None)[0], cmd)

    def test_network_off_denies_egress(self) -> None:
        pol = PermissionPolicy(allow_network=False)
        for cmd in ("curl https://api.test/x", "wget http://x", "git push origin main"):
            ok, why = bash_safety(cmd, policy=pol)
            self.assertFalse(ok, cmd)
            self.assertIn("network egress is OFF", why)
        # Local, non-network work is still allowed.
        self.assertTrue(bash_safety("forge test -vvv", policy=pol)[0])
        self.assertTrue(bash_safety("grep -rn ecrecover .", policy=pol)[0])

    def test_install_off_denies_installs(self) -> None:
        pol = PermissionPolicy(allow_install=False)
        for cmd in ("pip install requests", "npm install", "cargo install rg", "forge install x"):
            ok, why = bash_safety(cmd, policy=pol)
            self.assertFalse(ok, cmd)
            self.assertIn("installs are OFF", why)
        self.assertTrue(bash_safety("cargo build", policy=pol)[0])  # build is fine

    def test_deny_commands_substring(self) -> None:
        pol = PermissionPolicy(deny_commands=["foundryup"])
        ok, why = bash_safety("foundryup --version", policy=pol)
        self.assertFalse(ok)
        self.assertIn("blocked command", why)

    def test_jail_escape_still_denied_regardless(self) -> None:
        # The invariant floor (jail-escape) is independent of the posture.
        self.assertFalse(bash_safety("sudo rm -rf /", policy=PermissionPolicy())[0])


class ToolInstall(unittest.TestCase):
    """Agents may install ANY tool they need (incl. sudo package managers, installer scripts) —
    but catastrophic ops stay denied, sudo-non-install stays denied, and the operator can switch
    installs off via PermissionPolicy."""

    def test_standard_installs_allowed(self) -> None:
        for cmd in ("sudo apt-get install -y cmake clang", "brew install foundry",
                    "pip install slither-analyzer", "pipx install mythril",
                    "cargo install cargo-fuzz", "npm i -g hardhat", "foundryup",
                    "rustup toolchain install nightly", "go install x/y@latest",
                    "curl -L https://foundry.paradigm.xyz | bash", "solc-select install 0.8.21"):
            ok, why = bash_safety(cmd)
            self.assertTrue(ok, f"should allow install: {cmd} ({why})")

    def test_catastrophic_denied_even_with_install(self) -> None:
        for cmd in ("sudo apt install x && rm -rf /", "mkfs.ext4 /dev/sda", "sudo reboot",
                    "shutdown now", "dd if=/dev/zero of=/dev/sda"):
            ok, _ = bash_safety(cmd)
            self.assertFalse(ok, f"must deny catastrophic: {cmd}")

    def test_sudo_non_install_still_denied(self) -> None:
        for cmd in ("sudo systemctl restart nginx", "sudo bash -c 'cat /etc/shadow'", "mount /dev/sda /mnt"):
            self.assertFalse(bash_safety(cmd)[0], cmd)

    def test_operator_can_disable_installs(self) -> None:
        pol = PermissionPolicy(allow_install=False)
        self.assertFalse(bash_safety("sudo apt install x", policy=pol)[0])
        self.assertFalse(bash_safety("pip install requests", policy=pol)[0])

    def test_install_works_under_no_egress_posture(self) -> None:
        # Provisioning a tool is not target egress, so an install is allowed even when network is off.
        pol = PermissionPolicy(allow_network=False, allow_install=True)
        self.assertTrue(bash_safety("pip install slither-analyzer", policy=pol)[0])


class SwarmControl(unittest.TestCase):
    def _swarm(self, scope):
        from p1hunt.agents.claude_swarm import ClaudeSwarm
        from p1hunt.orchestrator.blackboard import Blackboard
        from p1hunt.orchestrator.bus import MessageBus
        from p1hunt.orchestrator.event_log import EventLog

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / "src").mkdir(parents=True)
            log = EventLog()
            return ClaudeSwarm(scope, str(repo), config=Config.from_env(),
                               bus=MessageBus(log), blackboard=Blackboard(log), event_log=log)

    def test_init_derives_from_rules(self) -> None:
        swarm = self._swarm(_scope(rules=["No network.", "Local harness only."]))
        self.assertFalse(swarm._perms.allow_network)

    def test_parent_a_can_tighten_not_loosen(self) -> None:
        swarm = self._swarm(_scope(rules=["No network."]))  # floor: network OFF
        swarm._apply_permission_policy({"allow_network": True, "allow_install": False})
        self.assertFalse(swarm._perms.allow_network)  # Parent A cannot re-enable
        self.assertFalse(swarm._perms.allow_install)  # Parent A tightened installs off

    def test_parent_a_adds_deny_commands(self) -> None:
        swarm = self._swarm(_scope(rules=["Use owned accounts."]))
        swarm._apply_permission_policy({"deny_commands": ["rm -rf"]})
        self.assertIn("rm -rf", swarm._perms.deny_commands)


if __name__ == "__main__":
    unittest.main()
