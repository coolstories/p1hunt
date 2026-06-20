"""Unit tests for p1hunt/severity.py — the deterministic SeverityMapper.

These are pure, hermetic tests: no network, no model, no toolchain. They assert the mapper maps to
the PROGRAM'S OWN taxonomy labels (NOTHING PRESET) and honors the critical-gate rule.
"""

from __future__ import annotations

import unittest

from p1hunt.severity import ImpactAssessment, SeverityMapper, detect_critical_key


# Two materially different program taxonomies — the mapper must use each program's own labels.
TAX_P = {
    "P1": "Critical: authorization bypass, asset-custody loss, or sensitive data at scale.",
    "P2": "High: a protected privileged operation with prerequisites.",
    "P3": "Medium: limited data or narrow reachability.",
    "P4": "Low / informational.",
}
TAX_NAMED = {
    "Critical": "Full account/asset compromise.",
    "High": "Significant unauthorized access.",
    "Medium": "Limited impact.",
    "Low": "Informational.",
}


def _full() -> ImpactAssessment:
    return ImpactAssessment(
        reproduced=True, protected_asset=True, attacker_capability=True,
        concrete_loss="funds", in_scope=True, note="forge test broke the solvency invariant",
    )


class DetectCriticalKey(unittest.TestCase):
    def test_p1_style(self):
        self.assertEqual(detect_critical_key(TAX_P), "P1")

    def test_named_style(self):
        self.assertEqual(detect_critical_key(TAX_NAMED), "Critical")

    def test_definition_hint_when_key_opaque(self):
        tax = {"TierA": "the most severe / critical issues", "TierB": "low"}
        self.assertEqual(detect_critical_key(tax), "TierA")

    def test_first_key_fallback(self):
        tax = {"Alpha": "biggest", "Beta": "smaller"}
        self.assertEqual(detect_critical_key(tax), "Alpha")

    def test_empty_taxonomy(self):
        self.assertEqual(detect_critical_key({}), "critical")

    def test_no_false_substring_match(self):
        # "shipping" contains "p1"? no — boundary guard. "low-priority" should not be critical.
        tax = {"shipping-bug": "x", "main": "the critical case"}
        self.assertEqual(detect_critical_key(tax), "main")


class TopTier(unittest.TestCase):
    def test_all_criteria_p1(self):
        m = SeverityMapper(TAX_P)
        label, rationale = m.map(_full())
        self.assertEqual(label, "P1")
        self.assertTrue(m.is_p1(_full()))
        self.assertIn("funds", rationale)

    def test_all_criteria_named(self):
        m = SeverityMapper(TAX_NAMED)
        label, _ = m.map(_full())
        self.assertEqual(label, "Critical")
        self.assertTrue(m.is_p1(_full()))

    def test_note_quoted_in_rationale(self):
        m = SeverityMapper(TAX_P)
        _, rationale = m.map(_full())
        self.assertIn("solvency invariant", rationale)


class NotTopTier(unittest.TestCase):
    def test_unreproduced_never_top(self):
        m = SeverityMapper(TAX_P)
        imp = _full()
        imp.reproduced = False
        label, rationale = m.map(imp)
        self.assertNotEqual(label, "P1")
        self.assertFalse(m.is_p1(imp))
        self.assertIn("Candidate", label)
        self.assertIn("Reproduction is required", rationale)

    def test_out_of_scope(self):
        m = SeverityMapper(TAX_P)
        imp = _full()
        imp.in_scope = False
        label, rationale = m.map(imp)
        self.assertEqual(label, "Out-of-scope")
        self.assertFalse(m.is_p1(imp))
        self.assertIn("scope", rationale.lower())

    def test_no_concrete_loss_not_top(self):
        m = SeverityMapper(TAX_P)
        imp = _full()
        imp.concrete_loss = "none"
        label, _ = m.map(imp)
        self.assertNotEqual(label, "P1")
        self.assertFalse(m.is_p1(imp))

    def test_missing_protected_asset_not_top(self):
        m = SeverityMapper(TAX_P)
        imp = _full()
        imp.protected_asset = False
        label, _ = m.map(imp)
        self.assertNotEqual(label, "P1")

    def test_missing_attacker_capability_not_top(self):
        m = SeverityMapper(TAX_P)
        imp = _full()
        imp.attacker_capability = False
        label, _ = m.map(imp)
        self.assertNotEqual(label, "P1")


class StepDown(unittest.TestCase):
    def test_two_strong_signals_maps_high(self):
        m = SeverityMapper(TAX_P)
        # reproduced + protected_asset + attacker_capability, but no concrete loss -> 2 strong.
        imp = ImpactAssessment(
            reproduced=True, protected_asset=True, attacker_capability=True,
            concrete_loss="none", in_scope=True,
        )
        label, _ = m.map(imp)
        self.assertEqual(label, "P2")  # program's High label

    def test_one_strong_signal_maps_medium(self):
        m = SeverityMapper(TAX_P)
        imp = ImpactAssessment(
            reproduced=True, protected_asset=True, attacker_capability=False,
            concrete_loss="none", in_scope=True,
        )
        label, _ = m.map(imp)
        self.assertEqual(label, "P3")  # program's Medium label

    def test_no_strong_signal_maps_low(self):
        m = SeverityMapper(TAX_P)
        imp = ImpactAssessment(
            reproduced=True, protected_asset=False, attacker_capability=False,
            concrete_loss="none", in_scope=True,
        )
        label, _ = m.map(imp)
        self.assertEqual(label, "P4")  # program's Low label

    def test_step_down_named_taxonomy(self):
        m = SeverityMapper(TAX_NAMED)
        imp = ImpactAssessment(
            reproduced=True, protected_asset=True, attacker_capability=True,
            concrete_loss="none", in_scope=True,
        )
        self.assertEqual(m.map(imp)[0], "High")

    def test_generic_label_when_tier_absent(self):
        # Program publishes only a critical tier; lower tiers fall back to generic labels.
        m = SeverityMapper({"OnlyCrit": "the critical case"})
        imp = ImpactAssessment(
            reproduced=True, protected_asset=True, attacker_capability=True,
            concrete_loss="none", in_scope=True,
        )
        label, _ = m.map(imp)
        self.assertEqual(label, "High")  # generic fallback, NOT the critical key
        self.assertNotEqual(label, "OnlyCrit")


class LabelForTier(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(SeverityMapper(TAX_P).label_for_tier("critical"), "P1")
        self.assertEqual(SeverityMapper(TAX_NAMED).label_for_tier("critical"), "Critical")

    def test_lower_never_reuses_critical_key(self):
        m = SeverityMapper({"OnlyCrit": "critical"})
        self.assertNotEqual(m.label_for_tier("high"), "OnlyCrit")
        self.assertEqual(m.label_for_tier("high"), "High")

    def test_loss_normalization(self):
        imp = ImpactAssessment(concrete_loss="FUNDS")
        self.assertEqual(imp.normalized_loss(), "funds")
        imp2 = ImpactAssessment(concrete_loss="garbage")
        self.assertEqual(imp2.normalized_loss(), "none")


if __name__ == "__main__":
    unittest.main()
