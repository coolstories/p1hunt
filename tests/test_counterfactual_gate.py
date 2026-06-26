import tempfile
import unittest
from pathlib import Path

from p1hunt.counterfactual_gate import assess_counterfactual_proof


class CounterfactualGateTests(unittest.TestCase):
    def _claim(self, **kw):
        base = {
            "attacker_model": "malicious coordinator",
            "attacker_controls": "request fields and peer messages",
            "attacker_does_not_control": "honest client private share and signing authorization",
            "trust_boundary": "client signing authorization boundary",
            "honest_victim": "honest client",
            "honest_secret_or_resource": "honest client private share",
            "precommitted_value": "existing client key and approval policy",
            "victim_state_before": "client policy denies the signing request",
            "victim_state_after": "target emits a valid partial signature",
            "absent_bug_expected_behavior": "target calls authorization hook and rejects before signing",
            "loss_type": "control",
            "exploit_path": "coordinator sends unauthorized signing request to target client API",
        }
        base.update(kw)
        return base

    def _gate(self, source: str, *, loss: str = "control", claim=None):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "poc.cpp"
            p.write_text(source, encoding="utf-8")
            return assess_counterfactual_proof(
                workspace=td,
                harness_paths=["poc.cpp"],
                concrete_loss=loss,
                counterfactual="attacker gains control of protected state",
                finding_claim=claim if claim is not None else self._claim(),
            )

    def test_blocks_self_controlled_artifact(self):
        gate = self._gate(
            """
            auto attacker_scalar = 7;
            auto forged_source_share = attacker_scalar;
            auto zero_share = 0;
            auto chosen_digest = make_digest();
            assert(forged_signature_valid(chosen_digest));
            """
        )
        self.assertFalse(gate.p1_ok)
        self.assertIn("self-controlled", gate.reason)

    def test_blocks_when_no_concrete_loss(self):
        gate = self._gate(
            """
            auto honest_server_secret = random_share();
            auto victim_resource = protected_state();
            assert(attacker_reads(victim_resource));
            """,
            loss="none",
            claim=self._claim(loss_type="none"),
        )
        self.assertFalse(gate.p1_ok)

    def test_blocks_when_schema_incomplete(self):
        gate = self._gate(
            """
            auto honest_server_secret = random_share();
            auto victim_resource = protected_state();
            assert(attacker_reads(victim_resource));
            """,
            claim={"attacker_model": "malicious peer"},
        )
        self.assertFalse(gate.p1_ok)
        self.assertIn("severity schema incomplete", gate.reason)
        self.assertFalse(gate.severity_predicates["honest_boundary"])

    def test_allows_honest_authz_boundary_proof(self):
        gate = self._gate(
            """
            auto honest_client_share = random_share();
            auto server_private_share = random_share();
            denying_client_platform.forbid_all_authorization();
            assert(client_on_start_signing_calls == 0);
            assert(valid_final_signature_from_target_code);
            """
        )
        self.assertTrue(gate.p1_ok)
        self.assertTrue(all(gate.severity_predicates.values()))
        self.assertTrue(gate.has_honest_secret_or_resource)
        self.assertTrue(gate.has_authorization_boundary)

    def test_allows_malicious_peer_control_when_honest_secret_is_consumed(self):
        gate = self._gate(
            """
            auto honest_client_private_share = random_share();       // not revealed to attacker
            auto attacker_zero_server_share = 0;                     // attacker controls its own MPC share
            auto attacker_identity_server_nonce = identity_point();
            auto chosen_message = attacker_chosen_message();
            auto client_partial = honest_client_signs(
                honest_client_private_share,
                attacker_identity_server_nonce,
                chosen_message);
            assert(client_partial_is_full_signature_under_vault_key(client_partial));
            """,
            claim=self._claim(
                attacker_model="malicious MPC server participating in normal 2-of-2 setup",
                attacker_controls="its own contributed share, its own nonce point, and the requested message",
                attacker_does_not_control="honest client private share or client signing policy",
                trust_boundary="MPC peer share validation and client signing boundary",
                honest_victim="honest EdDSA client",
                honest_secret_or_resource="honest client private share",
                precommitted_value="vault public key created by the setup protocol",
                victim_state_before="without identity-share acceptance, the setup or signing request aborts before a rogue signature exists",
                victim_state_after="honest client response is a full valid signature under the vault key",
                absent_bug_expected_behavior="reject identity public share or identity peer nonce before producing s",
                loss_type="control",
            ),
        )
        self.assertTrue(gate.p1_ok)
        self.assertTrue(gate.self_controlled_setup)
        self.assertTrue(gate.attacker_constructs_artifact)
        self.assertTrue(gate.has_honest_secret_or_resource)


if __name__ == "__main__":
    unittest.main()
