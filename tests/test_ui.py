"""Tests for the unified UI design language (ui/theme.py) and the rendered surfaces.

Covers the shared theme (agent identity, severity, cards, formatters), the polished end-of-run
snapshot (dashboard.render_snapshot), and the cockpit's finding-card rows (tui_app). Pure-logic
and string assertions — no curses/TTY needed (cards are requested with color off).
"""

from __future__ import annotations

import unittest

from p1hunt.ui import theme as T


class Theme(unittest.TestCase):
    def test_fmt_tokens(self) -> None:
        self.assertEqual(T.fmt_tokens(2_500_000), "2.50M")
        self.assertEqual(T.fmt_tokens(1500), "1.5K")
        self.assertEqual(T.fmt_tokens(42), "42")

    def test_fmt_duration(self) -> None:
        self.assertEqual(T.fmt_duration(45), "45s")
        self.assertEqual(T.fmt_duration(742), "12m22s")
        self.assertTrue(T.fmt_duration(3700).startswith("1h"))

    def test_agent_identity(self) -> None:
        self.assertEqual(T.agent_identity("parent_a")[0], "A")
        self.assertEqual(T.agent_identity("child_b2")[0], "B2")
        self.assertEqual(T.agent_identity("falsifier")[0], "F")
        self.assertEqual(T.agent_identity("poc_prover")[0], "PoC")
        # child-C subagents inherit the parent's identity + indent in the tag
        self.assertTrue(T.agent_tag("child_b1.C3", color=False).strip().startswith("[B1]"))

    def test_severity_rank_orders_worst_first(self) -> None:
        self.assertLess(T.sev_rank("critical"), T.sev_rank("high"))
        self.assertLess(T.sev_rank("high"), T.sev_rank("medium"))
        self.assertLess(T.sev_rank("medium"), T.sev_rank("low"))

    def test_finding_card_contains_essentials(self) -> None:
        card = T.finding_card(severity="critical", title="Forged proof accepted",
                              location="src/mta.cpp:9", counterfactual="key theft",
                              reproduced_by="yes", remediation="bind challenge", color=False)
        self.assertIn("P1 · CONFIRMED", card)
        self.assertIn("Forged proof accepted", card)
        self.assertIn("src/mta.cpp:9", card)
        self.assertIn("reproduced", card)
        self.assertIn("fix:", card)
        # box is rectangular: every rendered line is the same display width
        widths = {len(T.strip_ansi(ln)) for ln in card.splitlines()}
        self.assertEqual(len(widths), 1, f"card not aligned: {widths}")

    def test_candidate_card_says_candidate(self) -> None:
        card = T.finding_card(severity="high", title="x", confirmed=False, color=False)
        self.assertIn("CANDIDATE", card)

    def test_report_card_leads_with_p1(self) -> None:
        rc = T.report_card(program="Fireblocks MPC", status="REPORT_READY", rounds=6, reframes=5,
                           p1_count=1, candidate_count=12, tokens_total=1_240_000, cost=4.1,
                           elapsed_s=742, target_class="CRYPTO_LIB", color=False)
        self.assertIn("Fireblocks MPC", rc)
        self.assertIn("P1 found   1 confirmed", rc)
        self.assertIn("CRYPTO_LIB", rc)


class Snapshot(unittest.TestCase):
    def _finding(self, sev="critical"):
        from p1hunt.models import ArtifactRef, Finding
        return Finding(
            id="FND_1", hypothesis_id="HYP_1", title="Forged range proof accepted",
            root_cause="missing transcript binding",
            poc=ArtifactRef(id="art1", kind="repro", path="src/mta.cpp:214",
                            description="reproduced by ctest", reproduced=True),
            severity=sev, severity_rationale="critical: key theft",
            counterfactual="a crafted proof shifts the key share", remediation="bind the challenge",
            safe_harbor_attestation="ok")

    def test_render_snapshot_shows_report_and_finding_cards(self) -> None:
        from p1hunt.orchestrator.blackboard import Blackboard
        from p1hunt.orchestrator.bus import MessageBus
        from p1hunt.orchestrator.event_log import EventLog
        from p1hunt.ui.dashboard import render_snapshot

        log = EventLog()
        bb = Blackboard(log)
        bus = MessageBus(log)
        bb.add_finding(self._finding("critical"))
        out = render_snapshot(log, bb, bus)
        self.assertIn("P1HUNT", out)
        self.assertIn("P1 found", out)
        self.assertIn("Forged range proof accepted", out)
        self.assertIn("P1 · CONFIRMED", out)

    def test_render_snapshot_empty_is_graceful(self) -> None:
        from p1hunt.orchestrator.blackboard import Blackboard
        from p1hunt.orchestrator.bus import MessageBus
        from p1hunt.orchestrator.event_log import EventLog
        from p1hunt.ui.dashboard import render_snapshot

        log = EventLog()
        out = render_snapshot(log, Blackboard(log), MessageBus(log))
        self.assertIn("P1 found   0 confirmed", out)
        self.assertIn("no findings confirmed yet", out)


class CockpitCards(unittest.TestCase):
    def test_findings_tab_emits_aligned_card(self) -> None:
        from p1hunt.ui.tui_app import TuiState

        s = TuiState("Fireblocks MPC")
        s.ingest("parent_a", "finding", {"id": "F1", "title": "Forged proof", "severity": "critical",
                                         "location": "src/mta.cpp:9", "counterfactual": "key theft",
                                         "remediation": "bind challenge", "reproduced": True})
        rows = s.thread_entries("findings")
        card = [(tag, text) for tag, text in rows if tag.startswith("card")]
        self.assertTrue(any(t == "card_b" for t, _ in card), "expected a card border/title row")
        self.assertTrue(any("Forged proof" in text for _, text in card))
        # all box rows share one width → aligned
        widths = {len(text) for _, text in card}
        self.assertEqual(len(widths), 1, f"cockpit card not aligned: {widths}")

    def test_header_leads_with_p1_and_round(self) -> None:
        from p1hunt.ui.tui_app import TuiState

        s = TuiState("Fireblocks MPC")
        s.ingest("parent_a", "message", {"phase": "round", "round": 3})
        s.ingest("parent_a", "finding", {"id": "F1", "title": "x", "severity": "critical"})
        h = s.header()
        self.assertIn("1 P1", h)
        self.assertIn("r3", h)


class ThinkingVsAnswer(unittest.TestCase):
    """The model's reasoning (thinking) and its printed ANSWER (output) are distinct: thinking is
    collapsible (toggle with 'o'), the answer always renders. Regression for the bug where the
    answer was mislabeled 'thinking' and vanished into the collapsed reasoning."""

    def test_thinking_and_output_are_separate_tags(self) -> None:
        from p1hunt.ui.tui_app import TuiState
        s = TuiState()
        s.ingest("child_b1", "thinking", {"text": "reason about the MtA step"})
        s.ingest("child_b1", "output", {"text": "I found it: the **range proof** is unbound."})
        tags = [t for t, _ in s.thread_entries("child_b1")]
        self.assertIn("thinking", tags)
        self.assertIn("output", tags)

    def test_toggle_thinking_flag(self) -> None:
        from p1hunt.ui.tui_app import TuiState
        s = TuiState()
        self.assertFalse(s.show_thinking)   # collapsed by default
        s.toggle_thinking()
        self.assertTrue(s.show_thinking)    # 'o' expands it

    def test_streamed_block_not_duplicated_by_final(self) -> None:
        from p1hunt.ui.tui_app import TuiState
        s = TuiState()
        s.ingest("b", "stream_start", {"block": "text"})
        s.ingest("b", "stream", {"text": "the answer"})
        s.ingest("b", "tool_call", {"tool": "Read", "target": "x"})  # flushes the stream → one line
        s.ingest("b", "output", {"text": "the answer"})              # duplicate FINAL block
        answers = [x for t, x in s.thread_entries("b") if t == "output"]
        self.assertEqual(len(answers), 1, answers)

    def test_final_block_shown_when_not_streamed(self) -> None:
        # thinking streamed, but the answer arrived WHOLE (no deltas) — it must still render.
        from p1hunt.ui.tui_app import TuiState
        s = TuiState()
        s.ingest("b", "stream_start", {"block": "thinking"})
        s.ingest("b", "stream", {"text": "thinking…", "thinking": True})
        s.ingest("b", "output", {"text": "the whole answer"})
        answers = [x for t, x in s.thread_entries("b") if t == "output"]
        self.assertTrue(any("the whole answer" in a for a in answers), answers)


class Markdown(unittest.TestCase):
    def test_md_to_ansi_styles_and_strips(self) -> None:
        styled = T.md_to_ansi("a **b** `c`", color=True)
        self.assertIn("\033[1m", styled)   # bold
        self.assertIn("\033[7m", styled)   # code chip
        self.assertEqual(T.md_to_ansi("a **b** `c`", color=False), "a b c")  # markers stripped


if __name__ == "__main__":
    unittest.main()
