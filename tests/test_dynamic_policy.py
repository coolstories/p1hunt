"""Authorization of scoped live testing + the ScopeGuard egress gate (spec §9).

Deny-by-default is the contract: nothing live is permitted unless run_mode is active AND a
non-production dynamic target is declared. Production is never authorized.
"""

from __future__ import annotations

import unittest

from p1hunt.models import Asset, DynamicTarget, Scope, TargetClass
from p1hunt.safety.policies import authorize_dynamic, derive_scopeguard_policy
from p1hunt.safety.scopeguard import ScopeGuard


def _scope(*targets: DynamicTarget) -> Scope:
    return Scope(
        program="P", safe_harbor_text="x", severity_taxonomy={"P1": "critical"},
        in_scope=[Asset("a1", "https://uat.example.com", "domain", "https://uat.example.com", "uat")],
        rules=["No production writes."], rate_limit="30 per minute",
        dynamic_targets=list(targets),
    )


class TestAuthorizeDynamic(unittest.TestCase):
    def test_dry_run_never_unlocks(self):
        p = derive_scopeguard_policy(_scope(DynamicTarget("https://uat.example.com", "uat")),
                                     TargetClass.WEB_API)  # default dry_run
        self.assertEqual(p.egress_allowlist, [])
        self.assertNotIn("POST", p.allowed_http_methods)

    def test_active_unlocks_non_production(self):
        p = derive_scopeguard_policy(_scope(DynamicTarget("https://uat.example.com", "uat")),
                                     TargetClass.WEB_API, run_mode="active")
        self.assertIn("uat.example.com", p.egress_allowlist)
        for m in ("GET", "POST", "PUT", "PATCH"):
            self.assertIn(m, p.allowed_http_methods)

    def test_delete_stays_denied(self):
        p = derive_scopeguard_policy(_scope(DynamicTarget("https://uat.example.com", "uat")),
                                     TargetClass.WEB_API, run_mode="active")
        self.assertNotIn("DELETE", p.allowed_http_methods)

    def test_production_target_rejected(self):
        scope = _scope(DynamicTarget("https://prod.example.com", "production"),
                       DynamicTarget("https://uat.example.com", "uat"))
        p = derive_scopeguard_policy(scope, TargetClass.WEB_API, run_mode="active")
        self.assertIn("uat.example.com", p.egress_allowlist)
        self.assertNotIn("prod.example.com", p.egress_allowlist)

    def test_no_target_no_unlock(self):
        p = derive_scopeguard_policy(_scope(), TargetClass.WEB_API, run_mode="active")
        self.assertEqual(p.egress_allowlist, [])

    def test_summary_reports_rejected(self):
        scope = _scope(DynamicTarget("https://prod.example.com", "production"))
        p = derive_scopeguard_policy(scope, TargetClass.WEB_API, run_mode="active")
        summary = authorize_dynamic(p, scope)  # call directly to read the summary
        self.assertFalse(summary["enabled"])
        self.assertTrue(any("prod.example.com" in r for r in summary["rejected"]))


class TestScopeGuardEgress(unittest.TestCase):
    def _guard(self, run_mode="active"):
        scope = _scope(DynamicTarget("https://uat.example.com", "uat"))
        policy = derive_scopeguard_policy(scope, TargetClass.WEB_API, run_mode=run_mode)
        return ScopeGuard(policy, unattended=True)

    def test_get_in_scope_allowed(self):
        d = self._guard().check_egress("child_b1", "https://uat.example.com/api/users", method="GET")
        self.assertTrue(d.allow)

    def test_get_out_of_scope_denied(self):
        d = self._guard().check_egress("child_b1", "https://evil.com/x", method="GET")
        self.assertFalse(d.allow)

    def test_post_allowed_when_active(self):
        d = self._guard().check_egress("child_b1", "https://uat.example.com/api/orders", method="POST")
        self.assertTrue(d.allow)

    def test_delete_denied(self):
        d = self._guard().check_egress("child_b1", "https://uat.example.com/api/orders/1", method="DELETE")
        self.assertFalse(d.allow)

    def test_no_live_contact_in_dry_run(self):
        # dry_run -> empty egress allowlist -> even an in-scope host is refused for live contact.
        d = self._guard(run_mode="dry_run").check_egress("child_b1", "https://uat.example.com/x")
        self.assertFalse(d.allow)

    def test_loopback_allowed(self):
        d = self._guard().check_egress("child_b1", "http://127.0.0.1:9001/cb", method="POST")
        self.assertTrue(d.allow)


class TestConfigProductionRefused(unittest.TestCase):
    def test_production_env_yields_no_target(self):
        from p1hunt.config import Config
        c = Config()
        c.live_base_url = "https://prod.example.com"
        c.live_environment = "production"
        self.assertEqual(c.dynamic_targets(), [])  # production is refused, not relabeled to uat

    def test_uat_env_yields_target(self):
        from p1hunt.config import Config
        c = Config()
        c.live_base_url = "https://uat.example.com"
        c.live_environment = "uat"
        targets = c.dynamic_targets()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].environment, "uat")


if __name__ == "__main__":
    unittest.main()
