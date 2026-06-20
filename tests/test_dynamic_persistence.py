"""Scope persistence for live targets/identities — secrets are REDACTED on disk (spec §9)."""

from __future__ import annotations

import os
import unittest

from p1hunt.engagement import scope_from_dict, scope_to_dict
from p1hunt.models import Asset, DynamicTarget, Scope, TestIdentity


def _scope() -> Scope:
    return Scope(
        program="P", safe_harbor_text="x", severity_taxonomy={"P1": "critical"},
        in_scope=[Asset("a1", "https://uat.example.com", "domain", "https://uat.example.com", "uat")],
        dynamic_targets=[DynamicTarget("https://uat.example.com", "uat", "rest")],
        test_identities=[TestIdentity("A", token_env="P1HUNT_TOKEN_A"),
                         TestIdentity("B", token="literal-secret")],
    )


class TestPersistence(unittest.TestCase):
    def test_literal_token_redacted_on_disk(self):
        d = scope_to_dict(_scope())
        idents = {i["name"]: i for i in d["test_identities"]}
        self.assertEqual(idents["B"]["token"], "<redacted>")  # literal secret never persisted
        self.assertEqual(idents["A"]["token"], "")
        self.assertEqual(idents["A"]["token_env"], "P1HUNT_TOKEN_A")  # env-var NAME is fine to keep

    def test_round_trip_preserves_structure(self):
        s2 = scope_from_dict(scope_to_dict(_scope()))
        self.assertEqual(len(s2.dynamic_targets), 1)
        self.assertEqual(s2.dynamic_targets[0].base_url, "https://uat.example.com")
        self.assertEqual([i.name for i in s2.test_identities], ["A", "B"])

    def test_redacted_token_not_used_as_credential(self):
        s2 = scope_from_dict(scope_to_dict(_scope()))
        b = next(i for i in s2.test_identities if i.name == "B")
        self.assertEqual(b.resolve(), "")  # the sentinel is treated as absent, never sent as a bearer

    def test_env_identity_resolves_at_runtime(self):
        os.environ["P1HUNT_TOKEN_A"] = "runtime-secret"
        try:
            s2 = scope_from_dict(scope_to_dict(_scope()))
            a = next(i for i in s2.test_identities if i.name == "A")
            self.assertEqual(a.resolve(), "runtime-secret")
        finally:
            del os.environ["P1HUNT_TOKEN_A"]


if __name__ == "__main__":
    unittest.main()
