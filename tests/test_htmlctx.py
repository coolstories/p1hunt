"""Context-aware escaping analysis, pinned against REAL captured renders.

The fixtures in TestRealChatGPTRenders are verbatim fragments from a live
engagement: the vulnerable render that produced a paid P1, and the fixed render
that closed it. They are the regression floor. Twice during that hunt a raw "<"
in the census was read as "still vulnerable" when it sat inside a double-quoted
attribute and was inert; these tests exist so the analyzer cannot repeat it.
"""

from __future__ import annotations

import unittest

from p1hunt.dynamic import htmlctx as H


class TestContextDetection(unittest.TestCase):
    def ctx(self, html, needle="MARK"):
        return H.html_context_at(html, html.index(needle))

    def test_character_data(self):
        self.assertEqual(self.ctx("<p>MARK</p>")["context"], H.TEXT)

    def test_double_quoted_attribute(self):
        c = self.ctx('<div title="MARK">x</div>')
        self.assertEqual(c["context"], H.ATTR_DQ)
        self.assertEqual(c["attr"], "title")
        self.assertEqual(c["tag"], "div")

    def test_single_quoted_attribute(self):
        c = self.ctx("<div title='MARK'>x</div>")
        self.assertEqual(c["context"], H.ATTR_SQ)

    def test_unquoted_attribute(self):
        c = self.ctx("<div title=MARK>x</div>")
        self.assertEqual(c["context"], H.ATTR_UNQ)

    def test_attribute_value_after_whitespace_around_equals(self):
        c = self.ctx('<div title =  "MARK">x</div>')
        self.assertEqual(c["context"], H.ATTR_DQ)
        self.assertEqual(c["attr"], "title")

    def test_script_is_rawtext(self):
        c = self.ctx('<script>var a="MARK";</script>')
        self.assertEqual(c["context"], H.SCRIPT)
        self.assertFalse(H.entities_decode_in(c["context"]))

    def test_style_is_rawtext(self):
        self.assertEqual(self.ctx("<style>.a{content:'MARK'}</style>")["context"], H.STYLE)

    def test_title_is_rcdata(self):
        c = self.ctx("<title>MARK</title>")
        self.assertEqual(c["context"], H.RCDATA)
        self.assertTrue(H.entities_decode_in(c["context"]))

    def test_textarea_is_rcdata(self):
        self.assertEqual(self.ctx("<textarea>MARK</textarea>")["context"], H.RCDATA)

    def test_comment(self):
        self.assertEqual(self.ctx("<!-- MARK -->")["context"], H.COMMENT)

    def test_text_after_a_closed_script_is_not_still_script(self):
        c = self.ctx('<script>var a=1;</script><p>MARK</p>')
        self.assertEqual(c["context"], H.TEXT)

    def test_text_after_a_closed_attribute_is_not_still_attribute(self):
        c = self.ctx('<div class="a">MARK</div>')
        self.assertEqual(c["context"], H.TEXT)

    def test_angle_bracket_inside_attribute_does_not_open_a_tag(self):
        # The exact shape that caused a false "still vulnerable" read in the field.
        c = self.ctx('<input value="<script>x</script>" data-x="MARK">')
        self.assertEqual(c["context"], H.ATTR_DQ)
        self.assertEqual(c["attr"], "data-x")

    def test_lone_angle_bracket_in_data_is_not_a_tag(self):
        self.assertEqual(self.ctx("<p>a < b MARK</p>")["context"], H.TEXT)

    def test_closing_tag_name_is_matched_case_insensitively(self):
        c = self.ctx("<title>a</TITLE><p>MARK</p>")
        self.assertEqual(c["context"], H.TEXT)


class TestDangerRules(unittest.TestCase):
    def test_text_node_fears_only_the_angle_bracket(self):
        self.assertEqual(set(H.dangerous_chars(H.TEXT)), {"<"})

    def test_double_quoted_attribute_fears_only_its_quote(self):
        d = H.dangerous_chars(H.ATTR_DQ, "title")
        self.assertEqual(set(d), {'"'})
        self.assertNotIn("<", d)   # inert here -- the whole point

    def test_unquoted_attribute_fears_whitespace(self):
        d = H.dangerous_chars(H.ATTR_UNQ, "title")
        self.assertIn(" ", d)
        self.assertIn(">", d)

    def test_rawtext_fears_only_the_closing_sequence(self):
        self.assertEqual(set(H.dangerous_chars(H.SCRIPT, "", "script")), {"</"})

    def test_entities_do_not_decode_in_rawtext(self):
        self.assertFalse(H.entities_decode_in(H.SCRIPT))
        self.assertFalse(H.entities_decode_in(H.STYLE))
        self.assertTrue(H.entities_decode_in(H.TEXT))
        self.assertTrue(H.entities_decode_in(H.ATTR_DQ))
        self.assertTrue(H.entities_decode_in(H.RCDATA))

    def test_event_handler_attribute_is_a_js_sink(self):
        self.assertTrue(H.js_sink(H.ATTR_DQ, "onclick"))
        self.assertTrue(H.js_sink(H.ATTR_DQ, "onerror"))
        self.assertFalse(H.js_sink(H.ATTR_DQ, "title"))

    def test_url_attributes_are_url_sinks(self):
        self.assertTrue(H.url_sink(H.ATTR_DQ, "href"))
        self.assertTrue(H.url_sink(H.ATTR_DQ, "formaction"))
        self.assertFalse(H.url_sink(H.ATTR_DQ, "title"))
        self.assertFalse(H.url_sink(H.TEXT, "href"))


class TestCensusVerdicts(unittest.TestCase):
    def one(self, html, marker="MK"):
        recs = H.census(html, marker)
        self.assertTrue(recs, f"marker not located in {html!r}")
        return recs[0]

    def test_raw_angle_bracket_in_text_is_a_breakout(self):
        r = self.one("<p>MK<script>alert(1)</script>MK</p>")
        self.assertEqual(r["verdict"], "BREAKOUT")
        self.assertEqual(r["context"], H.TEXT)

    def test_escaped_angle_bracket_in_text_is_inert(self):
        r = self.one("<p>MK&lt;script&gt;alert(1)&lt;/script&gt;MK</p>")
        self.assertEqual(r["verdict"], "INERT")

    def test_raw_angle_bracket_in_quoted_attribute_is_inert(self):
        r = self.one('<input value="MK<script>x</script>MK">')
        self.assertEqual(r["context"], H.ATTR_DQ)
        self.assertEqual(r["verdict"], "INERT")

    def test_raw_quote_in_quoted_attribute_is_a_breakout(self):
        r = self.one('<input value="MK" onfocus=alert(1) x="MK">')
        self.assertEqual(r["verdict"], "BREAKOUT")

    def test_whitespace_in_unquoted_attribute_is_a_breakout(self):
        r = self.one("<input value=MK onfocus=alert(1) MK>")
        self.assertEqual(r["verdict"], "BREAKOUT")
        self.assertEqual(r["context"], H.ATTR_UNQ)

    def test_quote_in_script_string_is_inert_without_the_closing_tag(self):
        r = self.one('<script>var a="MK&quot;MK";</script>')
        self.assertEqual(r["context"], H.SCRIPT)
        self.assertEqual(r["verdict"], "INERT")
        self.assertFalse(r["entities_decode"])

    def test_closing_script_sequence_is_a_breakout(self):
        r = self.one('<script>var a="MK</script><img src=x onerror=alert(1)>MK";</script>')
        self.assertEqual(r["verdict"], "BREAKOUT")

    def test_javascript_scheme_in_href_is_flagged_even_fully_escaped(self):
        r = self.one('<a href="MKjavascript:alert(1)MK">x</a>')
        self.assertEqual(r["verdict"], "SCHEME")
        self.assertTrue(r["url_sink"])

    def test_double_decode_in_attribute_is_flagged(self):
        # Our "&" survived raw AND an entity is present: it decodes to a real quote.
        r = self.one('<input value="{MK&quot;a&quot;:1MK}">')
        self.assertEqual(r["verdict"], "DOUBLE_DECODE")

    def test_double_encoded_ampersand_in_attribute_is_inert(self):
        r = self.one('<input value="{MK&amp;quot;a&amp;quot;MK}">')
        self.assertEqual(r["verdict"], "INERT")

    def test_census_finds_every_occurrence(self):
        html = "<p>MKaMK</p><div title='MKbMK'></div><script>MKcMK</script>"
        recs = H.census(html, "MK")
        self.assertEqual([r["context"] for r in recs][:3],
                         [H.TEXT, H.ATTR_SQ, H.SCRIPT])

    def test_breakouts_filters_to_real_findings(self):
        html = '<p>MK&lt;MK</p><input value="MK" x=1 y="MK">'
        recs = H.census(html, "MK")
        bad = H.breakouts(recs)
        self.assertTrue(all(r["verdict"] != "INERT" for r in bad))
        self.assertTrue(bad, "the attribute breakout should survive the filter")


class TestRealChatGPTRenders(unittest.TestCase):
    """Verbatim fragments from a live engagement. The regression floor."""

    # --- the VULNERABLE render that produced the paid P1 -------------------
    VULN = ('<div class="msg"><p>ZXB<form></form>'
            '<script src=data:text/javascript,document.title=1></script>ZXB</p></div>')

    def test_the_paid_p1_is_detected(self):
        recs = H.census(self.VULN, "ZXB")
        self.assertEqual(recs[0]["context"], H.TEXT)
        self.assertEqual(recs[0]["verdict"], "BREAKOUT",
                         "the analyzer must still catch the original finding")

    # --- the FIXED render, four sinks, all correctly escaped --------------
    FIXED_TITLE = "<title>ZXBT&lt;&gt;&quot;'&amp;/ZXBT</title>"
    FIXED_ARIA = ('<div class="x" aria-label="ZXBT<>&quot;\'&amp;/ZXBT" '
                  'data-web-mobile-conversation=""><div>')
    FIXED_SCRIPT = ('<script>window.__d={"conversationSurface":{"label":'
                    '"ZXBT\\u003c>\\"\'&/ZXBT","shareTitle":"ZXBT\\u003c>\\"\'&/ZXBT"}}</script>')
    FIXED_TEXTNODE = ('<p data-user-message-copy="">ZXBA&amp;quot;onfocus=alert(1) '
                      'autofocus zzz=&amp;quot;ZXBA</p>')
    FIXED_ATTR_JSON = ('<input type="hidden" value="{&quot;content&quot;:&quot;'
                       'ZXBA&amp;quot;onfocus=alert(1) autofocus zzz=&amp;quot;ZXBA&quot;}">')

    def test_fixed_title_sink_is_inert(self):
        r = H.census(self.FIXED_TITLE, "ZXBT")[0]
        self.assertEqual(r["context"], H.RCDATA)
        self.assertEqual(r["verdict"], "INERT")

    def test_fixed_aria_label_raw_angle_brackets_are_inert(self):
        # Raw "<" and ">" ARE present here. They are inert: quoted attribute.
        r = H.census(self.FIXED_ARIA, "ZXBT")[0]
        self.assertEqual(r["context"], H.ATTR_DQ)
        self.assertIn("<", r["snippet"])
        self.assertEqual(r["verdict"], "INERT",
                         "raw < inside a double-quoted attribute is not a finding")

    def test_fixed_script_json_is_inert(self):
        r = H.census(self.FIXED_SCRIPT, "ZXBT")[0]
        self.assertEqual(r["context"], H.SCRIPT)
        self.assertEqual(r["verdict"], "INERT")
        self.assertFalse(r["entities_decode"],
                         "&quot; inside <script> is six literal characters")

    def test_fixed_text_node_double_encoding_is_inert(self):
        r = H.census(self.FIXED_TEXTNODE, "ZXBA")[0]
        self.assertEqual(r["context"], H.TEXT)
        self.assertEqual(r["verdict"], "INERT")

    def test_fixed_hidden_input_json_is_inert(self):
        # The sink the "&-not-escaped" hypothesis targeted. "&amp;" present => safe.
        r = H.census(self.FIXED_ATTR_JSON, "ZXBA")[0]
        self.assertEqual(r["context"], H.ATTR_DQ)
        self.assertEqual(r["verdict"], "INERT")

    def test_no_sink_of_the_fixed_render_reports_a_finding(self):
        for name, frag, mk in (
            ("title", self.FIXED_TITLE, "ZXBT"),
            ("aria", self.FIXED_ARIA, "ZXBT"),
            ("script", self.FIXED_SCRIPT, "ZXBT"),
            ("textnode", self.FIXED_TEXTNODE, "ZXBA"),
            ("attrjson", self.FIXED_ATTR_JSON, "ZXBA"),
        ):
            with self.subTest(sink=name):
                self.assertEqual(H.breakouts(H.census(frag, mk)), [],
                                 f"{name}: fixed render must produce zero findings")

    def test_the_hypothetical_regression_would_be_caught(self):
        # If they ever stop escaping "&" in the hidden-input sink, this is the shape.
        regressed = ('<input type="hidden" value="{&quot;content&quot;:&quot;'
                     'ZXBA&quot;onfocus=alert(1) autofocus zzz=&quot;ZXBA&quot;}">')
        r = H.census(regressed, "ZXBA")[0]
        self.assertEqual(r["verdict"], "DOUBLE_DECODE")


class TestStructuralEvidence(unittest.TestCase):
    """A breakout always moves the tokenizer. That is stronger than char counting."""

    def one(self, html, marker="MK"):
        return H.census(html, marker)[0]

    def test_attribute_breakout_is_structural(self):
        r = self.one('<input value="MK" onfocus=alert(1) x="MK">')
        self.assertEqual(r["verdict"], "BREAKOUT")
        self.assertEqual(r["evidence"], "structural")
        self.assertTrue(r["state_change"])

    def test_script_breakout_is_structural(self):
        r = self.one('<script>var a="MK</script><img src=x onerror=alert(1)>MK";</script>')
        self.assertEqual(r["evidence"], "structural")
        self.assertEqual(r["context"], H.SCRIPT)
        self.assertEqual(r["close_context"], H.TEXT)

    def test_unquoted_attribute_breakout_is_structural(self):
        r = self.one("<input value=MK onfocus=alert(1) MK>")
        self.assertEqual(r["evidence"], "structural")

    def test_text_node_breakout_is_character_evidence(self):
        # Context does not change -- still character data -- so the raw "<" carries it.
        r = self.one("<p>MK<script>alert(1)</script>MK</p>")
        self.assertEqual(r["verdict"], "BREAKOUT")
        self.assertEqual(r["evidence"], "character")

    def test_inert_landing_reports_no_evidence(self):
        r = self.one('<input value="MK&lt;&gt;MK">')
        self.assertEqual(r["verdict"], "INERT")
        self.assertEqual(r["evidence"], "none")

    def test_unpaired_marker_cannot_claim_a_state_change(self):
        r = self.one("<p>MK</p>")
        self.assertFalse(r["paired"])
        self.assertFalse(r["state_change"])


class TestDifferentialCensus(unittest.TestCase):
    """Separates "our metacharacters moved the parser" from "the app uses many sinks"."""

    def test_multi_sink_layout_alone_is_not_a_finding(self):
        # The app emits the value into a text node AND an attribute. With a benign
        # marker that shape is already present, so it is the app's layout, not our bug.
        control = '<p>OK</p><input value="OK">'
        probe = '<p>MK</p><input value="MK">'
        d = H.differential_census(control, probe, "OK", "MK")
        self.assertFalse(d["layout_changed"])
        self.assertEqual(d["confirmed"], [],
                         "identical sink layout must not be reported as an injection")

    def test_a_real_breakout_survives_the_differential(self):
        control = '<input value="OK" title="OK">'
        probe = '<input value="MK" onfocus=alert(1) title="MK">'
        d = H.differential_census(control, probe, "OK", "MK")
        self.assertTrue(d["layout_changed"])
        self.assertTrue(d["confirmed"])
        self.assertEqual(d["confirmed"][0]["evidence"], "structural")

    def test_character_evidence_survives_even_with_unchanged_layout(self):
        # Raw "<" in a text node is a finding regardless of layout stability.
        control = "<p>OKxOK</p>"
        probe = "<p>MK<img src=x>MK</p>"
        d = H.differential_census(control, probe, "OK", "MK")
        self.assertTrue(d["confirmed"])
        self.assertEqual(d["confirmed"][0]["evidence"], "character")

    def test_fully_escaped_probe_confirms_nothing(self):
        control = "<p>OK</p>"
        probe = "<p>MK&lt;img src=x&gt;MK</p>"
        d = H.differential_census(control, probe, "OK", "MK")
        self.assertEqual(d["confirmed"], [])

    def test_real_fixed_chatgpt_render_confirms_nothing(self):
        control = ("<title>OK</title><div aria-label=\"OK\"></div>"
                   "<script>window.__d={\"label\":\"OK\"}</script>")
        probe = (TestRealChatGPTRenders.FIXED_TITLE
                 + TestRealChatGPTRenders.FIXED_ARIA
                 + TestRealChatGPTRenders.FIXED_SCRIPT)
        d = H.differential_census(control, probe, "OK", "ZXBT")
        self.assertEqual(d["confirmed"], [],
                         "the shipped fix must survive a differential census")


if __name__ == "__main__":
    unittest.main()
