"""Unit tests for p1hunt/tools/evm_fork.py — pure/graceful-degradation paths only.

These tests NEVER spawn anvil and NEVER touch the network: anvil-dependent helpers are
exercised with ``fork_available`` forced False (anvil absent), and the dry-run / env-
validation paths need no chain at all.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from p1hunt.tools import evm_fork
from p1hunt.tools.evm_fork import EvmFork, ForkHandle


def _run(coro):
    return asyncio.run(coro)


class DryRunShapeTests(unittest.TestCase):
    def test_dry_run_returns_plan_without_performing(self):
        tool = EvmFork(active=False)
        res = _run(tool.run({"environment": "fork", "invariant": "sum_balances"}))
        self.assertTrue(res.ok)
        self.assertEqual(res.tool, "evm_fork")
        self.assertIn("[dry-run]", res.summary)
        self.assertEqual(res.data["environment"], "fork")
        self.assertEqual(res.data["invariant"], "sum_balances")
        self.assertFalse(res.data["performed"])

    def test_dry_run_defaults_environment_to_fork(self):
        res = _run(EvmFork(active=False).run({}))
        self.assertTrue(res.ok)
        self.assertEqual(res.data["environment"], "fork")
        self.assertFalse(res.data["performed"])


class EnvValidationTests(unittest.TestCase):
    def test_non_sandbox_environment_rejected(self):
        for env in ("mainnet", "prod", "ethereum"):
            res = _run(EvmFork(active=True).run({"environment": env}))
            self.assertFalse(res.ok, env)
            self.assertIn("not a sandbox", res.summary)

    def test_sandbox_environments_accepted_in_dry_run(self):
        for env in ("fork", "testnet", "local"):
            res = _run(EvmFork(active=False).run({"environment": env}))
            self.assertTrue(res.ok, env)


class ForkAvailabilityTests(unittest.TestCase):
    def test_fork_available_true_when_anvil_on_path(self):
        with mock.patch.object(evm_fork, "which", return_value="/usr/local/bin/anvil"):
            self.assertTrue(evm_fork.fork_available())

    def test_fork_available_false_when_anvil_absent(self):
        with mock.patch.object(evm_fork, "which", return_value=None):
            self.assertFalse(evm_fork.fork_available())


class StartForkGracefulTests(unittest.TestCase):
    def test_start_returns_none_without_rpc_url(self):
        # No subprocess, no anvil dependency at all.
        self.assertIsNone(evm_fork.start_anvil_fork(""))

    def test_start_returns_none_when_anvil_missing(self):
        with mock.patch.object(evm_fork, "fork_available", return_value=False):
            # Spawn must never be attempted when anvil is absent.
            with mock.patch.object(evm_fork.subprocess, "Popen") as popen:
                handle = evm_fork.start_anvil_fork("http://example.invalid")
            self.assertIsNone(handle)
            popen.assert_not_called()

    def test_start_emits_remediation_event_when_anvil_missing(self):
        events: list[tuple] = []

        def sink(channel, phase, payload):
            events.append((channel, phase, payload))

        with mock.patch.object(evm_fork, "fork_available", return_value=False):
            evm_fork.start_anvil_fork("http://example.invalid", on_event=sink)

        self.assertTrue(events)
        channel, phase, payload = events[-1]
        self.assertEqual(channel, "evm_fork")
        self.assertFalse(payload.get("started", True))
        self.assertIn("foundry", payload.get("remediation", ""))


class StopForkTests(unittest.TestCase):
    def test_stop_none_is_safe(self):
        evm_fork.stop_anvil_fork(None)  # must not raise

    def test_stop_terminates_running_process(self):
        proc = mock.Mock()
        proc.poll.return_value = None  # still running
        handle = ForkHandle(endpoint="http://127.0.0.1:1", port=1, pid=123, process=proc)
        evm_fork.stop_anvil_fork(handle)
        proc.terminate.assert_called_once()
        proc.wait.assert_called()

    def test_stop_dead_process_skips_terminate(self):
        proc = mock.Mock()
        proc.poll.return_value = 0  # already exited
        handle = ForkHandle(endpoint="http://127.0.0.1:1", port=1, pid=123, process=proc)
        evm_fork.stop_anvil_fork(handle)
        proc.terminate.assert_not_called()

    def test_stop_handle_without_process_is_safe(self):
        handle = ForkHandle(endpoint="http://127.0.0.1:1", port=1, pid=1, process=None)
        evm_fork.stop_anvil_fork(handle)  # must not raise


class ActiveRunGracefulTests(unittest.TestCase):
    def test_active_run_reports_unavailable_when_anvil_missing(self):
        with mock.patch.object(evm_fork, "fork_available", return_value=False):
            res = _run(EvmFork(active=True).run({"environment": "fork", "rpc_url": "http://example.invalid"}))
        self.assertFalse(res.ok)
        self.assertIn("anvil not installed", res.summary)

    def test_active_run_uses_env_var_rpc_url(self):
        with mock.patch.object(evm_fork, "fork_available", return_value=False):
            with mock.patch.dict(evm_fork.os.environ, {"P1HUNT_FORK_RPC_URL": "http://example.invalid"}):
                res = _run(EvmFork(active=True).run({"environment": "fork"}))
        self.assertFalse(res.ok)
        self.assertIn("anvil not installed", res.summary)

    def test_active_run_without_rpc_falls_back_to_invariant(self):
        # No rpc_url and no env var -> classic active invariant path, no fork spawned.
        with mock.patch.dict(evm_fork.os.environ, {}, clear=True):
            res = _run(EvmFork(active=True).run({"environment": "local", "invariant": "x"}))
        self.assertTrue(res.ok)
        self.assertTrue(res.data["performed"])
        self.assertEqual(res.data["environment"], "local")

    def test_active_run_reports_failure_when_start_returns_none(self):
        with mock.patch.object(evm_fork, "fork_available", return_value=True):
            with mock.patch.object(evm_fork, "start_anvil_fork", return_value=None):
                res = _run(EvmFork(active=True).run({"environment": "fork", "rpc_url": "http://example.invalid"}))
        self.assertFalse(res.ok)
        self.assertIn("failed to start", res.summary)

    def test_active_run_success_shape_with_mocked_handle(self):
        handle = ForkHandle(endpoint="http://127.0.0.1:8545", port=8545, pid=1, process=mock.Mock())
        with mock.patch.object(evm_fork, "fork_available", return_value=True):
            with mock.patch.object(evm_fork, "start_anvil_fork", return_value=handle):
                res = _run(EvmFork(active=True).run({"environment": "fork", "rpc_url": "http://example.invalid"}))
        self.assertTrue(res.ok)
        self.assertIn("started local fork", res.summary)
        self.assertEqual(res.data["endpoint"], "http://127.0.0.1:8545")
        self.assertEqual(res.data["port"], 8545)
        self.assertTrue(res.data["performed"])


class FreePortTests(unittest.TestCase):
    def test_free_port_is_in_valid_range(self):
        port = evm_fork._free_port()
        self.assertGreater(port, 0)
        self.assertLess(port, 65536)


if __name__ == "__main__":
    unittest.main()
