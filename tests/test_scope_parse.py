"""Deriving in-scope hosts from pasted bug-bounty scope text.

THIS PARSER HAS MISFIRED TWICE IN PRODUCTION USE, both times sending a launch at hosts
that were not the program's assets. The console used to ask for a free-text "target URL",
an operator pasted the URL they had -- the HackerOne program PAGE -- and a hunt was aimed
at HackerOne's own website. Deriving hosts from the scope text fixed that specific
mistake and introduced three more:

  1. A bare bullet list is indistinguishable from an asset table, so a pasted policy page
     contributed `apple.com`, `google.com` and `atlassian.com` -- nav links, customer
     logos and other programs -- to an egress allowlist.
  2. `com.anthropic.claude`, an ANDROID BUNDLE ID sitting in the scope table beside the
     web assets, parsed as the hostname `anthropic.claude`, because ".claude" is five
     alphabetic characters and nothing required a real TLD.
  3. Hosts were mined out of PROSE: `m.range` from a sentence describing a request
     header, `example.com` from a `security@example.com` contact address, and
     `docs.example.com` from a link to the policy -- while the actual asset, a bare
     `127.0.0.1`, was missed entirely.

So the rules these tests hold are: read asset ENTRIES, not sentences; a hostname needs a
real TLD; and above all SHOW THE EVIDENCE, because a parser that returns a bare list gives
an operator no way to tell a table row from a footer link.
"""

from __future__ import annotations

import unittest

from p1hunt.web.scope_parse import is_platform_host, parse_scope


class TestARealAssetTable(unittest.TestCase):
    TABLE = """In scope
| *.anthropic.com | Domain | Critical |
| api.anthropic.com | API | Critical |
| claude.ai | Domain | Critical |
| com.anthropic.claude | Android app | High |
| github.com/anthropics/sdk | Source | Low |

Out of scope
  - status.anthropic.com
  Do not test: support.anthropic.com
"""

    def setUp(self):
        self.r = parse_scope(self.TABLE,
                             program_url="https://hackerone.com/anthropic/policy_scopes")

    def test_the_web_assets_are_derived(self):
        self.assertEqual(self.r["in_scope"],
                         ["anthropic.com", "api.anthropic.com", "claude.ai"])

    def test_a_wildcard_widens_but_a_named_host_does_not(self):
        """This fixture contains BOTH spellings, and they must behave differently.

        `*.anthropic.com` authorizes the apex. `api.anthropic.com`, named without a
        wildcard, authorizes that host only -- and loses nothing, because the egress jail
        already matches anything beneath an entry. An earlier version collapsed both,
        which against a real scope turned one SaaS tenant into a whole vendor.
        """
        self.assertIn("anthropic.com", self.r["in_scope"])      # from *.anthropic.com
        self.assertIn("api.anthropic.com", self.r["in_scope"])  # named exactly

    def test_an_android_bundle_id_is_not_a_hostname(self):
        self.assertNotIn("anthropic.claude", self.r["in_scope"])
        self.assertNotIn("anthropic.claude", [f["host"] for f in self.r["flagged"]])

    def test_the_source_host_is_flagged_not_targeted(self):
        self.assertNotIn("github.com", self.r["in_scope"])
        flagged = {f["host"]: f["why"] for f in self.r["flagged"]}
        self.assertIn("github.com", flagged)
        self.assertIn("READ", flagged["github.com"])

    def test_exclusions_are_read_including_an_inline_one(self):
        self.assertEqual(self.r["out_of_scope"],
                         ["status.anthropic.com", "support.anthropic.com"])

    def test_the_program_page_host_is_never_an_asset(self):
        self.assertNotIn("hackerone.com", self.r["in_scope"])
        flagged = {f["host"]: f["why"] for f in self.r["flagged"]}
        self.assertIn("hackerone.com", flagged)
        self.assertIn("not an asset", flagged["hackerone.com"])

    def test_table_rows_count_as_strong_evidence(self):
        self.assertEqual(sorted(self.r["strong"]),
                         ["anthropic.com", "api.anthropic.com", "claude.ai"])
        self.assertFalse(self.r["suspicious_spread"])

    def test_every_host_carries_the_line_it_came_from(self):
        """Without this the operator cannot audit the parser's conclusion."""
        for host in self.r["in_scope"]:
            ev = self.r["evidence"][host]
            self.assertTrue(ev["line"], f"{host} has no evidence line")
            self.assertTrue(ev["strong"])


class TestAWholePolicyPagePastedIn(unittest.TestCase):
    """The failure that reached a launch: nav, logos and other programs as bullets."""

    PAGE = """Programs
  - shopify.com
  - gitlab-partner.com
  - atlassian.com
  - anthropic.com
  - claude.ai
  - apps.apple.com
"""

    def setUp(self):
        self.r = parse_scope(self.PAGE,
                             program_url="https://hackerone.com/anthropic/policy_scopes")

    def test_no_bullet_only_host_counts_as_strong(self):
        """A nav list, a customer-logo list and an asset list are all bullets."""
        self.assertEqual(self.r["strong"], [])

    def test_a_wide_unrelated_spread_is_called_suspicious(self):
        """The signature of a pasted page. The UI pre-ticks nothing when this is set."""
        self.assertTrue(self.r["suspicious_spread"])

    def test_the_unrelated_hosts_are_still_shown_not_silently_dropped(self):
        """Dropping them would be its own bug: the operator must see everything found, and
        a legitimate asset that happens to be bullet-listed must remain tickable. The
        safety comes from nothing being PRE-TICKED, not from hiding rows."""
        for host in ("shopify.com", "atlassian.com", "anthropic.com"):
            with self.subTest(host=host):
                self.assertIn(host, self.r["in_scope"])
                self.assertIn(host, self.r["evidence"])

    def test_a_store_host_is_filtered_even_from_a_bullet_list(self):
        self.assertNotIn("apps.apple.com", self.r["in_scope"])
        self.assertIn("apps.apple.com", [f["host"] for f in self.r["flagged"]])


class TestProseIsNotAnAssetList(unittest.TestCase):
    PROSE = """In scope
  127.0.0.1

Notes
  A sibling mobile host is simulated with the header X-Range-Host: m.range.
  Contact security@example.com with questions.
  See https://docs.example.com/policy for the full text.
"""

    def setUp(self):
        self.r = parse_scope(self.PROSE)

    def test_the_real_asset_is_found_including_an_ip(self):
        self.assertIn("127.0.0.1", self.r["in_scope"])

    def test_a_host_named_in_a_sentence_is_not_an_asset(self):
        """`m.range` came from a sentence describing a header AND has no real TLD, so it
        is dropped outright rather than demoted. Either rule alone would have stopped it;
        both apply."""
        self.assertNotIn("m.range", self.r["in_scope"])
        self.assertNotIn("m.range", self.r["mentioned"])

    def test_a_real_host_in_a_sentence_is_demoted_not_dropped(self):
        """The demotion path still has to work for a host with a valid TLD, or a
        legitimate asset mentioned only in the notes becomes unreachable."""
        r = parse_scope("Notes\n  The mobile host m.example.com serves the same route.\n")
        self.assertNotIn("m.example.com", r["in_scope"])
        self.assertIn("m.example.com", r["mentioned"])

    def test_a_contact_email_contributes_nothing(self):
        self.assertNotIn("example.com", self.r["in_scope"])
        self.assertNotIn("example.com", self.r["mentioned"])

    def test_a_docs_link_is_only_mentioned(self):
        self.assertNotIn("docs.example.com", self.r["in_scope"])
        self.assertIn("docs.example.com", self.r["mentioned"])


class TestTldPlausibility(unittest.TestCase):
    def test_a_fake_tld_is_refused(self):
        for junk in ("com.anthropic.claude", "io.example.app", "app.js", "config.yaml",
                     "v1.2.3", "org.apache.commons"):
            with self.subTest(token=junk):
                self.assertEqual(parse_scope(f"| {junk} | Asset |")["in_scope"], [])

    def test_real_tlds_are_accepted(self):
        for good in ("example.com", "example.ai", "example.io", "example.dev",
                     "example.co.uk", "example.org"):
            with self.subTest(host=good):
                self.assertTrue(parse_scope(f"| {good} | Domain | Critical |")["in_scope"],
                                f"{good} should parse")


class TestPlatformDetection(unittest.TestCase):
    def test_the_known_platforms(self):
        for host in ("hackerone.com", "https://bugcrowd.com/x", "www.intigriti.com",
                     "yeswehack.com", "immunefi.com"):
            with self.subTest(host=host):
                self.assertTrue(is_platform_host(host))

    def test_an_ordinary_target_is_not_a_platform(self):
        for host in ("anthropic.com", "claude.ai", "api.example.com", "127.0.0.1"):
            with self.subTest(host=host):
                self.assertFalse(is_platform_host(host))


class TestItNeverRaises(unittest.TestCase):
    """A parser in front of a launch button must degrade, not throw."""

    def test_odd_input(self):
        for text in ("", "   ", "\n\n", "no hosts here at all", "|||", "." * 500,
                     "http://", "....", "a.b", "\x00\x01"):
            with self.subTest(text=text[:20]):
                r = parse_scope(text)
                self.assertIsInstance(r["in_scope"], list)
                self.assertIn("evidence", r)

    def test_a_large_paste_is_handled(self):
        r = parse_scope("| example.com | Domain |\n" * 5000)
        self.assertEqual(r["in_scope"], ["example.com"])


if __name__ == "__main__":
    unittest.main()


class TestARealProgramScope(unittest.TestCase):
    """Anthropic's published HackerOne scope, which exposed the worst bug in this file.

    The parser used to collapse every host to its registrable domain, on the reasoning
    that the egress jail matches subdomains so an apex is a convenient superset. Against
    this scope that produced:

        anthropic.atlassian.com                 ->  atlassian.com   (ALL of Atlassian)
        https://apps.apple.com/us/app/claude/.. ->  apple.com       (ALL of Apple)
        support/docs/console/api.anthropic.com  ->  anthropic.com   (every subdomain)

    The first two are third-party infrastructure the program explicitly disclaims
    authorization over. The third is simply broader than what was granted: four hosts are
    named individually and no wildcard appears. A scope naming one tenant host on a SaaS
    domain authorizes that tenant, never the vendor -- so apex collapsing now requires an
    explicit `*.`, and the exact host loses nothing because the jail already matches
    beneath it.
    """

    SCOPE = """support.anthropic.com
[Non-Core]
Domain
Official Clients
[Core]
Claude iOS App:
https://apps.apple.com/us/app/claude/id6473753684
Claude Android App:
https://play.google.com/store/apps/details?id=com.anthropic.claude
Claude Desktop:
https://claude.ai/download
github.com/anthropics
[Non-Core]
Source code
docs.anthropic.com
[Non-Core]
Domain
console.anthropic.com
[Core]
Domain
claude.ai
[Core]
Domain
Claude in Chrome
[Non-Core]
https://chromewebstore.google.com/detail/claude/fcoeoabgfenejglbffodgkkbkcdhcgfn
api.anthropic.com
[Core]
Domain
anthropic.atlassian.com
[Non-Core]
Domain
"""

    def setUp(self):
        self.r = parse_scope(
            self.SCOPE, program_url="https://hackerone.com/anthropic/policy_scopes")

    def test_it_derives_exactly_the_named_domains(self):
        self.assertEqual(self.r["in_scope"], [
            "anthropic.atlassian.com",
            "api.anthropic.com",
            "claude.ai",
            "console.anthropic.com",
            "docs.anthropic.com",
            "support.anthropic.com",
        ])

    def test_a_saas_tenant_never_becomes_the_whole_vendor(self):
        """The dangerous one. Authorizing atlassian.com would point an automated hunt at
        Atlassian's infrastructure, which the program disclaims in writing."""
        self.assertNotIn("atlassian.com", self.r["in_scope"])
        self.assertIn("anthropic.atlassian.com", self.r["in_scope"])

    def test_individually_named_subdomains_do_not_become_the_apex(self):
        self.assertNotIn("anthropic.com", self.r["in_scope"])

    def test_an_app_store_link_is_not_an_asset(self):
        for host in ("apple.com", "apps.apple.com", "google.com", "play.google.com",
                     "chromewebstore.google.com"):
            with self.subTest(host=host):
                self.assertNotIn(host, self.r["in_scope"])

    def test_the_store_host_is_flagged_with_the_reason(self):
        flagged = {f["host"]: f["why"] for f in self.r["flagged"]}
        self.assertIn("apps.apple.com", flagged)
        self.assertIn("store operator", flagged["apps.apple.com"])

    def test_the_source_repo_is_not_a_live_target(self):
        self.assertNotIn("github.com", self.r["in_scope"])

    def test_the_program_page_host_is_excluded(self):
        self.assertNotIn("hackerone.com", self.r["in_scope"])


class TestWildcardsStillWiden(unittest.TestCase):
    """The narrowing must not break the case a wildcard legitimately covers."""

    def test_a_wildcard_collapses_to_the_apex(self):
        self.assertEqual(
            parse_scope("| *.example.com | Domain | Critical |")["in_scope"],
            ["example.com"])

    def test_a_named_host_stays_exact(self):
        self.assertEqual(
            parse_scope("| api.example.com | Domain | Critical |")["in_scope"],
            ["api.example.com"])

    def test_a_mixed_scope_keeps_both_behaviours(self):
        r = parse_scope("""| *.example.com | Domain | Critical |
| tenant.vendor.com | Domain | High |
""")
        self.assertEqual(r["in_scope"], ["example.com", "tenant.vendor.com"])
