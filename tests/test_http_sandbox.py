"""The real (scope-checked) http_sandbox tool + its ScopeGuard wrapper (spec §12)."""

from __future__ import annotations

import asyncio
import unittest

from p1hunt.models import Asset, DynamicTarget, Scope, TargetClass
from p1hunt.safety.policies import derive_scopeguard_policy
from p1hunt.safety.scopeguard import ScopeGuard
from p1hunt.tools.base import GuardedTool
from p1hunt.tools.http_sandbox import HttpSandbox


def _run(coro):
    return asyncio.run(coro)


class TestHttpSandboxDirect(unittest.TestCase):
    def test_dry_run_never_performs(self):
        r = _run(HttpSandbox(active=False).run({"url": "https://api.example.com/x", "http_method": "GET"}))
        self.assertTrue(r.ok)
        self.assertFalse(r.data["performed"])
        self.assertIn("dry-run", r.summary)

    def test_unknown_method_rejected(self):
        r = _run(HttpSandbox(active=True).run({"url": "https://api.example.com/x", "http_method": "TRACE"}))
        self.assertFalse(r.ok)

    def test_missing_url(self):
        r = _run(HttpSandbox(active=True).run({"http_method": "GET"}))
        self.assertFalse(r.ok)

    def test_active_offline_graceful(self):
        # An unresolvable host returns ok=False, never raises (offline-graceful).
        r = _run(HttpSandbox(active=True, timeout=2).run(
            {"url": "http://127.0.0.1:1/never", "http_method": "GET"}))
        self.assertFalse(r.ok)
        self.assertFalse(r.data["performed"])


class TestHttpSandboxGuarded(unittest.TestCase):
    def _guard(self, run_mode="active"):
        scope = Scope(
            program="P", safe_harbor_text="x", severity_taxonomy={"P1": "critical"},
            in_scope=[Asset("a1", "https://uat.example.com", "domain", "https://uat.example.com", "uat")],
            rate_limit="60 per minute",
            dynamic_targets=[DynamicTarget("https://uat.example.com", "uat")],
        )
        policy = derive_scopeguard_policy(scope, TargetClass.WEB_API, run_mode=run_mode)
        return ScopeGuard(policy, unattended=True)

    def test_guard_blocks_out_of_scope(self):
        tool = GuardedTool(HttpSandbox(active=False), self._guard(), "child_b1")
        r = _run(tool.run({"url": "https://evil.com/x", "http_method": "GET"}))
        self.assertTrue(r.denied)

    def test_guard_allows_in_scope_dryrun(self):
        tool = GuardedTool(HttpSandbox(active=False), self._guard(), "child_b1")
        r = _run(tool.run({"url": "https://uat.example.com/api", "http_method": "GET"}))
        self.assertTrue(r.ok)
        self.assertFalse(r.denied)


if __name__ == "__main__":
    unittest.main()
