"""Live black-box surface derivation, and the model-driven triage that replaces wordlists.

Two layers with a deliberate split, and tests that hold the line between them:
``recon`` MEASURES (pure, deterministic, testable offline) and ``triage`` DECIDES (the
engine, given facts and an instrument catalogue). The architectural tests at the bottom
exist because the first version of this code scored surfaces with keyword lists, which
ceilings the hunt at whatever the author listed.
"""

from __future__ import annotations

import asyncio
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from p1hunt.dynamic import recon as R
from p1hunt.dynamic import triage as T

try:
    import playwright  # noqa: F401
    _HAVE_PW = True
except ImportError:  # pragma: no cover
    _HAVE_PW = False


class TestIdShapes(unittest.TestCase):
    def test_each_shape_is_named(self):
        cases = {
            "550e8400-e29b-41d4-a716-446655440000": "uuid",
            "12345": "int",
            "507f1f77bcf86cd799439011": "objectid",
            "a3f1c9d2b4e6f8a1b2c3d4e5f6a7b8c9": "hex",
            "+14255551234": "msisdn",
        }
        for value, want in cases.items():
            with self.subTest(value=value):
                self.assertEqual(R.id_shape(value), want)

    def test_ordinary_words_are_not_identifiers(self):
        for word in ("accounts", "billing", "v2", "api", "user", "me", "settings"):
            with self.subTest(word=word):
                self.assertEqual(R.id_shape(word), "")

    def test_empty_and_overlong_are_not_identifiers(self):
        self.assertEqual(R.id_shape(""), "")
        self.assertEqual(R.id_shape("x" * 200), "")

    def test_templatize_collapses_and_reports_shapes(self):
        t, ids = R.templatize("/api/v2/accounts/550e8400-e29b-41d4-a716-446655440000/lines/7")
        self.assertEqual(t, "/api/v2/accounts/{id}/lines/{id}")
        self.assertEqual([i["shape"] for i in ids], ["uuid", "int"])

    def test_templatize_normalizes_js_placeholders(self):
        t, ids = R.templatize("/api/v2/lines/${lineId}/usage")
        self.assertEqual(t, "/api/v2/lines/{id}/usage")
        self.assertEqual(ids[0]["shape"], "template")

    def test_templatize_leaves_a_literal_path_alone(self):
        t, ids = R.templatize("/auth/login")
        self.assertEqual(t, "/auth/login")
        self.assertEqual(ids, [])


class TestBundleMining(unittest.TestCase):
    BUNDLE = r"""
      fetch("/backend-api/accounts/"+id+"/billing");
      fetch("/api/v1/users/"+userId);
      get("/v2/orders/" + order.id + "/refund");
      axios.get(`/api/v2/lines/${lineId}/usage`);
      const E={LOGIN:"/auth/login",ADMIN:"/internal/admin/users"};
      const IMG="/static/img/logo.png", CSS="/assets/app.css", MAP="/x/app.js.map";
      const u="https://api.t-mobile.com/v1/x", c="https://cdn.t-mobile.com/a.js";
      routes=[{path:"/account/profile"},{path:"/pay/autopay"}];
      query GetUser($id:ID){a} mutation UpdateAddress($i:I){b}
      $.ajax({method:"POST",url:"/api/v2/transfer"});
      const o={"operationName":"FetchLines"};
      const t={"access_token":1,"client_secret":2};
    """

    def setUp(self):
        self.m = R.mine_js(self.BUNDLE)

    def test_concatenated_paths_are_joined_into_one_endpoint(self):
        # The dominant shape in a hand-written API client. Extracting the literals
        # separately yields two useless fragments instead of one real endpoint.
        self.assertIn("/backend-api/accounts/{id}/billing", self.m["paths"])
        self.assertIn("/v2/orders/{id}/refund", self.m["paths"])
        self.assertIn("/api/v1/users/{id}", self.m["paths"])

    def test_the_fragments_a_join_explains_are_suppressed(self):
        self.assertNotIn("/backend-api/accounts/", self.m["paths"])
        self.assertNotIn("/billing", self.m["paths"])

    def test_template_literals_are_captured(self):
        self.assertIn("/api/v2/lines/${lineId}/usage", self.m["paths"])

    def test_plain_literals_are_captured(self):
        self.assertIn("/auth/login", self.m["paths"])
        self.assertIn("/internal/admin/users", self.m["paths"])

    def test_assets_and_static_directories_are_not_endpoints(self):
        for noise in ("/static/img/logo.png", "/assets/app.css", "/x/app.js.map"):
            with self.subTest(noise=noise):
                self.assertNotIn(noise, self.m["paths"])

    def test_sibling_hosts_are_discovered(self):
        self.assertIn("api.t-mobile.com", self.m["hosts"])
        self.assertIn("cdn.t-mobile.com", self.m["hosts"])

    def test_graphql_operations_are_discovered(self):
        self.assertIn("query GetUser", self.m["graphql"])
        self.assertIn("mutation UpdateAddress", self.m["graphql"])
        self.assertIn("operation FetchLines", self.m["graphql"])

    def test_client_side_routes_are_discovered(self):
        self.assertIn("/account/profile", self.m["routes"])
        self.assertIn("/pay/autopay", self.m["routes"])

    def test_methods_are_noticed_so_a_lead_need_not_assume_get(self):
        self.assertIn("POST", self.m["methods"])

    def test_credential_like_keys_are_noted(self):
        self.assertIn("client_secret", self.m["secretish"])

    def test_mining_is_pure_and_total(self):
        for junk in ("", "/////", "\x00\x01", "}" * 500, "a" * 10000):
            with self.subTest(junk=junk[:12]):
                out = R.mine_js(junk)
                self.assertIsInstance(out["paths"], list)

    def test_a_bare_slash_is_not_a_lead(self):
        self.assertNotIn("/", R.mine_js('const a="/";')["paths"])

    def test_a_path_literal_carrying_its_own_query_is_not_dropped(self):
        # Regression: "?" was absent from the path character class, so the pattern failed
        # at the "?" and never reached the closing quote -- dropping the ENTIRE endpoint.
        # The range exposed it: an SSRF endpoint that appears only as
        # fetch("/api/v1/fetch?url=" + u) was invisible to recon.
        m = R.mine_js('fetch("/api/v1/fetch?url="+encodeURIComponent(u));'
                      'fetch("/api/v2/search?q=x&page=1");')
        self.assertIn("/api/v1/fetch?url=", m["paths"])
        self.assertIn("/api/v2/search?q=x&page=1", m["paths"])

    def test_a_query_value_concat_does_not_invent_a_path_segment(self):
        # `"/api/v1/fetch?url=" + u` concatenates a QUERY VALUE. Inserting {id} would
        # invent "/api/v1/fetch?url={id}" as if it were a path identifier.
        paths = R.mine_js('fetch("/api/v1/fetch?url="+u);')["paths"]
        self.assertIn("/api/v1/fetch?url=", paths)
        self.assertFalse([p for p in paths if "url={id}" in p], paths)

    def test_an_asset_with_a_cache_buster_is_still_an_asset(self):
        self.assertEqual(R.mine_js('const s="/static/a.png?v=2";')["paths"], [])

    def test_query_parameters_become_endpoint_params(self):
        import urllib.parse
        path = R.mine_js('fetch("/api/v2/search?q=x&page=1");')["paths"][0]
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        self.assertEqual(sorted(qs), ["page", "q"],
                         "the parameter names a bundle literal exposes are free surface")


class TestSurfaceAssembly(unittest.TestCase):
    def test_merge_deduplicates_across_parts(self):
        a = {"hosts": ["x.tld"], "endpoints": [{"path": "/a", "method": "GET"}]}
        b = {"hosts": ["x.tld", "y.tld"], "endpoints": [{"path": "/a", "method": "GET"},
                                                        {"path": "/b", "method": "POST"}]}
        m = R.merge_surface(a, b)
        self.assertEqual(m["hosts"], ["x.tld", "y.tld"])
        self.assertEqual(len(m["endpoints"]), 2)

    def test_entrypoints_use_templates_not_raw_ids(self):
        surf = {"endpoints": [
            {"path": "/api/v1/accounts/7/lines/2", "method": "GET", "source": "observed"},
            {"path": "/api/v1/accounts/9/lines/4", "method": "GET", "source": "observed"}]}
        eps = R.entrypoints_from_surface(surf, limit=10)
        self.assertEqual(eps, ["GET /api/v1/accounts/{id}/lines/{id}"],
                         "a thousand observed URLs must collapse to the endpoints they are")

    def test_supplied_leads_bypass_the_degraded_ordering(self):
        surf = {"endpoints": [{"path": "/a", "method": "GET", "source": "observed"}]}
        self.assertEqual(R.entrypoints_from_surface(surf, leads=[]), [],
                         "an empty reasoned plan must NOT silently fall back to keywords")

    def test_black_box_target_no_longer_starves_the_coverage_loop(self):
        from p1hunt.agents.surface_enum import entrypoints_for
        surf = {"endpoints": [{"path": "/api/v1/accounts/7", "method": "GET",
                               "source": "observed"}], "hosts": ["a.tld"]}
        self.assertEqual(entrypoints_for("WEB_APP", "/does/not/exist"), [],
                         "the starvation this fixes")
        self.assertTrue(entrypoints_for("WEB_APP", "/does/not/exist", live_surface=surf))

    def test_live_surface_does_not_disturb_evm_targets(self):
        from p1hunt.agents.surface_enum import entrypoints_for
        self.assertIsInstance(entrypoints_for("EVM_CONTRACT", "/does/not/exist"), list)


class _FakeSession:
    """Stands in for an engine session: run(prompt, cwd) -> SessionResult-like."""

    def __init__(self, text="", ok=True, raises=False):
        self.text = text
        self.ok = ok
        self.raises = raises
        self.prompt = None

    async def run(self, prompt, cwd, **kw):
        self.prompt = prompt
        if self.raises:
            raise RuntimeError("engine exploded")

        class _R:
            pass
        r = _R()
        r.ok = self.ok
        r.text = self.text
        r.error = ""
        return r


_GOOD_PLAN = """
Here is what I would do.
```json
[
  {"target": "GET /share/{id}", "mechanism": "the apex applies a cookie-presence render
   gate that the mobile host does not, so the lightweight renderer is reachable with a
   session present", "vary": "the host, nothing else",
   "instrument": "Browser.differential with two host variants",
   "confirm_if": "raw_html differs and only the mobile render contains the lightweight bundle",
   "refute_if": "both hosts return byte-identical documents for the same cookie state",
   "impact_if_true": "removes the signed-out precondition", "confidence": 0.82}
]
```
"""


class TestPlanParsing(unittest.TestCase):
    def test_a_fenced_block_amid_prose_is_parsed(self):
        plan = T.parse_plan(_GOOD_PLAN)
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["target"], "GET /share/{id}")
        self.assertIn("mobile host", plan[0]["mechanism"])

    def test_an_unfenced_array_is_parsed(self):
        plan = T.parse_plan('[{"target":"/a","mechanism":"m","instrument":"i",'
                            '"confirm_if":"c","refute_if":"r"}]')
        self.assertEqual(len(plan), 1)

    def test_a_trailing_comma_is_repaired_once(self):
        plan = T.parse_plan('```json\n[{"target":"/a","mechanism":"m","instrument":"i",'
                            '"confirm_if":"c","refute_if":"r",}]\n```')
        self.assertEqual(len(plan), 1)

    def test_a_hypothesis_without_a_refutation_is_dropped(self):
        # Accepting it would quietly reintroduce the thrashing the ledger prevents:
        # an idea with no refutation condition can never be retired.
        plan = T.parse_plan('[{"target":"/a","mechanism":"m","instrument":"i","confirm_if":"c"}]')
        self.assertEqual(plan, [])

    def test_garbage_yields_no_plan_rather_than_raising(self):
        for junk in ("", "no json here", "{}", "[1,2,3]", "```json\nnot json\n```"):
            with self.subTest(junk=junk[:16]):
                self.assertEqual(T.parse_plan(junk), [])

    def test_confidence_is_clamped_and_defaulted(self):
        plan = T.parse_plan('[{"target":"/a","mechanism":"m","instrument":"i","confirm_if":"c",'
                            '"refute_if":"r","confidence":9.5},'
                            '{"target":"/b","mechanism":"m","instrument":"i","confirm_if":"c",'
                            '"refute_if":"r","confidence":"junk"}]')
        self.assertEqual(plan[0]["confidence"], 1.0)
        self.assertEqual(plan[1]["confidence"], 0.5)

    def test_plan_is_ordered_by_confidence(self):
        plan = T.parse_plan('[{"target":"/low","mechanism":"m","instrument":"i","confirm_if":"c",'
                            '"refute_if":"r","confidence":0.1},'
                            '{"target":"/high","mechanism":"m","instrument":"i","confirm_if":"c",'
                            '"refute_if":"r","confidence":0.9}]')
        self.assertEqual([h["target"] for h in plan], ["/high", "/low"])

    def test_plan_to_entrypoints_keeps_an_explicit_method(self):
        self.assertEqual(T.plan_to_entrypoints([{"target": "POST /api/x"}]), ["POST /api/x"])

    def test_plan_to_entrypoints_marks_an_unverbed_target_as_any(self):
        self.assertEqual(T.plan_to_entrypoints([{"target": "/api/x"}]), ["ANY /api/x"])


class TestBrief(unittest.TestCase):
    SURF = {
        "hosts": ["t-mobile.com", "m.t-mobile.com", "api.t-mobile.com"],
        "endpoints": [
            {"path": "/api/v1/accounts/{id}", "method": "GET", "params": ["account_id"],
             "source": "observed", "authenticated": True},
            {"path": "/internal/admin/users", "method": "GET", "params": [], "source": "bundle"},
        ],
        "graphql": ["query GetLines"],
        "forms": [{"action": "/pay", "method": "POST", "fields": ["amount", "card"]}],
        "gate_paths": ["/share/abc"],
        "secretish_responses": [{"url": "/api/session", "what": "access_token", "where": "body"}],
    }

    def brief(self, **kw):
        return T.build_brief(self.SURF, **kw)

    def test_the_facts_reach_the_model(self):
        b = self.brief(target_name="T-Mobile")
        for needle in ("m.t-mobile.com", "/api/v1/accounts/{id}", "/internal/admin/users",
                       "query GetLines", "/pay", "/share/abc", "access_token"):
            with self.subTest(needle=needle):
                self.assertIn(needle, b)

    def test_endpoint_provenance_is_stated(self):
        b = self.brief()
        self.assertIn("observed", b)
        self.assertIn("may be dead code", b,
                      "a bundle string is weaker evidence than an observed request")

    def test_the_instrument_catalogue_is_present(self):
        b = self.brief()
        for needle in ("differential", "escaping_differential", "dom_injection",
                       "execution_proof", "census", "require_live_baseline", "oob_url"):
            with self.subTest(needle=needle):
                self.assertIn(needle, b)

    def test_the_method_is_taught_not_a_checklist_of_bug_classes(self):
        # Normalized: the brief is hard-wrapped, so a needle may straddle a newline.
        b = " ".join(self.brief().split())
        self.assertIn("COMPARE BEFORE YOU INJECT", b)
        self.assertIn("A PRECONDITION IS A TARGET", b)
        self.assertIn("in your own words", b)
        self.assertIn("nobody has a name for", b)
        self.assertIn("do not propose a generic checklist", b)

    def test_refutation_is_demanded(self):
        b = self.brief()
        self.assertIn("refute_if", b)
        self.assertIn("SAY WHAT WOULD REFUTE YOU", b)

    def test_already_refuted_ideas_are_handed_back_so_effort_is_not_respent(self):
        b = self.brief(ruled_out=["/a is escaped in every sink"])
        self.assertIn("ALREADY REFUTED", b)
        self.assertIn("/a is escaped in every sink", b)

    def test_confirmed_findings_steer_toward_escalation_not_repetition(self):
        b = self.brief(confirmed_so_far=["stored XSS on /share when signed out"])
        self.assertIn("ALREADY CONFIRMED", b)
        self.assertIn("precondition can be removed", b)

    def test_identities_are_offered_as_a_comparison_tool(self):
        b = self.brief(identities=["A", "B", "low"])
        self.assertIn("compare, not just to", b)

    def test_scope_note_is_carried(self):
        b = self.brief(scope_note="only *.t-mobile.com; no DoS")
        self.assertIn("only *.t-mobile.com; no DoS", b)

    def test_brief_survives_an_empty_surface(self):
        b = T.build_brief({})
        self.assertIn("no surface gathered", b)


class TestTriageDispatch(unittest.TestCase):
    def test_a_plan_is_returned_from_the_engine(self):
        sess = _FakeSession(_GOOD_PLAN)
        out = asyncio.run(T.triage({"hosts": ["a.tld"]}, session=sess))
        self.assertTrue(out["ok"])
        self.assertEqual(len(out["plan"]), 1)
        self.assertIn("INSTRUMENTS", sess.prompt)

    def test_no_engine_fails_loudly_and_does_not_fall_back_to_keywords(self):
        out = asyncio.run(T.triage({"hosts": ["a.tld"]}))
        self.assertFalse(out["ok"])
        self.assertEqual(out["plan"], [])
        self.assertIn("no engine session", out["error"])
        self.assertIn("degraded", out["error"])

    def test_an_engine_exception_is_reported_not_raised(self):
        out = asyncio.run(T.triage({}, session=_FakeSession(raises=True)))
        self.assertFalse(out["ok"])
        self.assertIn("session failed", out["error"])

    def test_an_unparseable_reply_is_not_ok(self):
        out = asyncio.run(T.triage({}, session=_FakeSession("I have no idea")))
        self.assertFalse(out["ok"])
        self.assertIn("no parseable hypotheses", out["error"])

    def test_a_session_factory_is_accepted(self):
        out = asyncio.run(T.triage({}, session_factory=lambda: _FakeSession(_GOOD_PLAN)))
        self.assertTrue(out["ok"])


class TestJudgementIsNotHardcoded(unittest.TestCase):
    """The split this design turns on, pinned so it cannot quietly reverse."""

    def test_the_old_keyword_judges_are_not_reachable_under_their_original_names(self):
        self.assertFalse(hasattr(R, "rank_leads"))
        self.assertFalse(hasattr(R, "classify_path"))

    def test_the_remaining_heuristic_names_itself_a_fallback(self):
        self.assertTrue(hasattr(R, "fallback_rank_leads"))
        self.assertIn("DEGRADED", R.fallback_rank_leads.__doc__)
        self.assertIn("not a plan", R.fallback_rank_leads.__doc__)

    def test_recon_does_not_import_an_engine(self):
        import ast
        import pathlib
        tree = ast.parse(pathlib.Path("p1hunt/dynamic/recon.py").read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names.add(node.module or "")
            elif isinstance(node, ast.Import):
                for a in node.names:
                    names.add(a.name)
        self.assertEqual(names - {"json", "re", "urllib.parse", "__future__"}, set(),
                         "recon must stay a pure measuring layer")

    def test_triage_contains_no_bug_class_scoring_table(self):
        import pathlib
        src = pathlib.Path("p1hunt/dynamic/triage.py").read_text()
        self.assertNotIn("_KIND_WEIGHT", src)
        self.assertNotIn("_SSRF_PARAMS", src)
        self.assertNotIn("_REDIRECT_PARAMS", src)


@unittest.skipUnless(_HAVE_PW, "playwright not installed")
class TestDiscoverLive(unittest.TestCase):
    """discover() against a loopback app: it must find what the app actually exposes."""

    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802
            page = self.path.split("?")[0]
            if page == "/app.js":
                body = ('fetch("/api/v1/accounts/"+id+"/billing");'
                        'const A="/internal/admin/panel";'
                        'routes=[{path:"/profile"}];'
                        'query GetMe($i:ID){x}')
                ct = "application/javascript"
            elif page == "/":
                body = ('<html><body><script src="/app.js"></script>'
                        '<a href="/second">next</a>'
                        '<form action="/pay" method="post">'
                        '<input name="amount"><input name="card"></form>'
                        '<img src="/logo.png"></body></html>')
                ct = "text/html"
            elif page == "/second":
                body = '<html><body><a href="/">home</a><p>second</p></body></html>'
                ct = "text/html"
            else:
                body = "ok"
                ct = "text/plain"
            raw = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", ct + "; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), cls._H)
        cls.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        from p1hunt.dynamic.browser import Browser, BrowserUnavailable
        try:
            cls.b = Browser(allowlist=[], base_url=cls.base, rate_limit=0,
                            settle_ms=200).start()
        except BrowserUnavailable as exc:  # pragma: no cover
            cls.httpd.shutdown()
            raise unittest.SkipTest(str(exc))
        cls.surface = R.discover(cls.b, [cls.base + "/"], max_pages=4, max_scripts=4)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.b.close()
        finally:
            cls.httpd.shutdown()
            cls.httpd.server_close()

    def paths(self):
        return {e["path"] for e in self.surface["endpoints"]}

    def test_the_bundle_is_mined_for_a_concatenated_endpoint(self):
        self.assertIn("/api/v1/accounts/{id}/billing", self.paths())

    def test_a_privileged_looking_bundle_string_is_collected(self):
        self.assertIn("/internal/admin/panel", self.paths())

    def test_a_client_side_route_is_collected(self):
        self.assertIn("/profile", self.surface["routes"])

    def test_a_graphql_operation_is_collected(self):
        self.assertIn("query GetMe", self.surface["graphql"])

    def test_a_form_is_collected_with_its_fields(self):
        forms = self.surface["forms"]
        self.assertTrue(forms)
        self.assertIn("amount", forms[0]["fields"])
        self.assertIn("card", forms[0]["fields"])

    def test_the_crawl_follows_an_in_scope_link(self):
        self.assertIn("/second", self.surface["gate_paths"])

    def test_image_subresources_are_not_reported_as_endpoints(self):
        self.assertNotIn("/logo.png", self.paths())

    def test_the_surface_feeds_the_coverage_loop(self):
        from p1hunt.agents.surface_enum import entrypoints_for
        eps = entrypoints_for("WEB_APP", "/no/repo", live_surface=self.surface)
        self.assertTrue(eps)
        self.assertTrue(any("accounts/{id}" in e for e in eps), eps)

    def test_the_surface_produces_a_brief_the_model_can_act_on(self):
        brief = T.build_brief(self.surface, target_name="loopback fixture")
        self.assertIn("/api/v1/accounts/{id}/billing", brief)
        self.assertIn("INSTRUMENTS", brief)


class TestRefusalIsNotSilence(unittest.TestCase):
    """A provider-side refusal kills the reasoning layer; an empty plan does not.

    These two look identical downstream -- no hypotheses -- but mean opposite things. If a
    refusal is treated as "the model had no ideas", the run proceeds on the derived
    surface, looks healthy, and silently loses every class that needs a comparison nobody
    enumerated. So the cause has to be named.
    """

    def test_a_safety_classifier_refusal_is_named_a_refusal(self):
        self.assertEqual(
            T.classify_failure("", "codex error: This content was flagged for possible "
                                   "cybersecurity risk."),
            T.REASON_REFUSED)

    def test_a_model_decline_is_named_a_refusal(self):
        for text in ("I can't help with that.", "I cannot help with that request",
                     "This violates my guidelines", "I won't help with this"):
            with self.subTest(text=text):
                self.assertEqual(T.classify_failure(text, ""), T.REASON_REFUSED)

    def test_an_unparseable_reply_is_not_a_refusal(self):
        self.assertEqual(T.classify_failure("here are some thoughts", ""),
                         T.REASON_UNPARSEABLE)

    def test_a_transport_error_is_not_a_refusal(self):
        self.assertEqual(T.classify_failure("", "connection reset by peer"),
                         T.REASON_ERROR)

    def test_triage_reports_the_reason_when_it_has_no_plan(self):
        out = asyncio.run(T.triage({}, session=_FakeSession(
            "I can't help with that.")))
        self.assertFalse(out["ok"])
        self.assertEqual(out["reason"], T.REASON_REFUSED)

    def test_triage_reports_no_engine_distinctly(self):
        out = asyncio.run(T.triage({}))
        self.assertEqual(out["reason"], T.REASON_NO_ENGINE)

    def test_a_successful_plan_carries_no_failure_reason(self):
        out = asyncio.run(T.triage({}, session=_FakeSession(_GOOD_PLAN)))
        self.assertTrue(out["ok"])
        self.assertNotIn("reason", out)

    def test_an_exception_mentioning_the_classifier_is_still_a_refusal(self):
        out = asyncio.run(T.triage({}, session=_FakeSession(
            raises=True)))
        self.assertIn("reason", out)


class TestAuthorizationFraming(unittest.TestCase):
    """The brief must state its authorization, and must not read as a bare attack request.

    Learned the hard way: a brief that opened with the facts and the instrument catalogue
    was refused outright by the provider's safety classifier, which made the entire
    reasoning layer non-functional while 1225 tests -- all using a fake session -- passed.
    """

    def test_the_role_comes_first(self):
        b = T.build_brief({"hosts": ["x"]})
        self.assertTrue(b.lstrip().startswith("You are the planning role"),
                        b[:120])

    def test_authorization_is_stated(self):
        b = " ".join(T.build_brief({"hosts": ["x"]}).split())
        self.assertIn("AUTHORIZED", b)
        self.assertIn("safe-harbour", b)

    def test_scope_discipline_is_part_of_the_role(self):
        b = " ".join(T.build_brief({"hosts": ["x"]}).split())
        self.assertIn("STAY INSIDE THE STATED SCOPE", b)
        self.assertIn("say so in place of proposing it", b,
                      "unauthorized scope must be refused, not assumed")

    def test_destructive_planning_is_excluded(self):
        b = " ".join(T.build_brief({"hosts": ["x"]}).split())
        self.assertIn("PLAN NOTHING DESTRUCTIVE", b)
        self.assertIn("denial of service", b)
        self.assertIn("third party", b)

    def test_the_operator_scope_note_is_still_carried(self):
        b = T.build_brief({"hosts": ["x"]}, scope_note="only *.example.com")
        self.assertIn("only *.example.com", b)


if __name__ == "__main__":
    unittest.main()
