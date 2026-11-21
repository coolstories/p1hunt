"""The scope-jailed recon browser, exercised against a real browser and a real server.

No live internet traffic: a loopback HTTP server serves fixtures that reproduce the
shapes that matter -- a raw text-node reflection, an inert attribute reflection, a
server-safe page with a DOM-based sink, an executing payload, an out-of-scope
subresource, and a cookie-gated render.

The jail tests are the important ones. A browser resolves its own DNS, follows its own
redirects and loads subresources from any origin a page names; ``context.route`` is the
only chokepoint, so these assert that subresources and navigations are both checked and
that the handler fails CLOSED.
"""

from __future__ import annotations

import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from p1hunt.dynamic import browser as B
from p1hunt.dynamic import htmlctx as H

try:
    import playwright  # noqa: F401
    _HAVE_PW = True
except ImportError:  # pragma: no cover
    _HAVE_PW = False


def _q(path: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlsplit(path).query).get("q", [""])[0]


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#39;"))


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, body: str, status: int = 200):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        path = self.path
        q = _q(path)
        page = path.split("?")[0]

        if page == "/vuln":          # raw reflection into character data
            return self._send(f"<html><body><p>{q}</p></body></html>")
        if page == "/safe":          # correctly escaped
            return self._send(f"<html><body><p>{_esc(q)}</p></body></html>")
        if page == "/attr":          # raw <> but escaped quote: INERT, must not be reported
            v = q.replace('"', "&quot;").replace("&", "&amp;")
            return self._send(f'<html><body><input value="{v}"></body></html>')
        if page == "/dom":           # server-safe, DOM-unsafe
            return self._send(
                "<html><body><div id=o></div><script>"
                "var p=new URLSearchParams(location.search);"
                "document.getElementById('o').innerHTML=p.get('q')||'';"
                "</script></body></html>")
        if page == "/exec":          # actually executes
            return self._send(f"<html><body>{q}</body></html>")
        if page == "/sub":           # names an out-of-scope subresource
            return self._send(
                "<html><body><img src='https://blocked.example.net/pixel.png'>"
                "<p>sub</p></body></html>")
        if page == "/gated":         # renders differently with a cookie present
            has = "gate=" in (self.headers.get("Cookie") or "")
            return self._send("<html><body><p>SAFE_RENDER</p></body></html>" if has
                              else f"<html><body><p>OPEN_RENDER {q}</p></body></html>")
        if page == "/msg":           # registers a message listener
            return self._send(
                "<html><body><script>window.addEventListener('message',"
                "function(e){document.title=e.data});</script></body></html>")
        return self._send("<html><body>ok</body></html>")


class _Server:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestVendoredJailParity(unittest.TestCase):
    """``browser.py`` ships standalone into the PoC sandbox and so cannot import
    ``dynamic/egress.py``; the jail is duplicated. These pin the copy to the original."""

    _HOSTS = (
        "", "example.com", "EXAMPLE.com.", "https://api.example.com/x?y=1",
        "user:pw@api.example.com:8443", "api.example.com:8443", "[::1]:8080", "::1",
        "127.0.0.1", "localhost", "app.localhost", "0.0.0.0", "attacker.tld",
        "https://example.com.attacker.tld/", "sub.sub.example.com", "nohost",
        "http://[2001:db8::1]:443/p",
    )

    def test_norm_host_matches_egress(self):
        from p1hunt.dynamic import egress
        for v in self._HOSTS:
            with self.subTest(v=v):
                self.assertEqual(B._norm_host(v), egress.normalize_host(v))

    def test_allowed_matches_egress_host_in_allowlist(self):
        from p1hunt.dynamic import egress
        for allow in ([], ["example.com"], ["uat.example.com", "example.org"]):
            for v in self._HOSTS:
                with self.subTest(allow=allow, v=v):
                    h = B._norm_host(v)
                    mine = B._allowed(v, allow)
                    theirs = bool(h) and (egress.is_loopback(h)
                                          or egress.host_in_allowlist(h, allow)
                                          or h.endswith(".localhost"))
                    self.assertEqual(mine, theirs)

    def test_parity_with_client_py(self):
        from p1hunt.dynamic import client
        for v in self._HOSTS:
            with self.subTest(v=v):
                self.assertEqual(B._norm_host(v), client._norm_host(v))
                self.assertEqual(B._allowed(v, ["example.com"]),
                                 client._allowed(v, ["example.com"]))


class TestScopeDecisionsAreFailClosed(unittest.TestCase):
    def test_allowlisted_host_passes(self):
        ok, _ = B.url_allowed("https://example.com/a", ["example.com"])
        self.assertTrue(ok)

    def test_subdomain_of_allowlisted_host_passes(self):
        ok, _ = B.url_allowed("https://api.example.com/a", ["example.com"])
        self.assertTrue(ok)

    def test_suffix_confusion_is_refused(self):
        ok, why = B.url_allowed("https://example.com.attacker.tld/a", ["example.com"])
        self.assertFalse(ok, why)

    def test_unknown_host_is_refused(self):
        self.assertFalse(B.url_allowed("https://evil.tld/a", ["example.com"])[0])

    def test_empty_allowlist_refuses_everything_remote(self):
        self.assertFalse(B.url_allowed("https://example.com/a", [])[0])

    def test_loopback_is_always_reachable(self):
        self.assertTrue(B.url_allowed("http://127.0.0.1:9/a", [])[0])

    def test_non_http_scheme_is_refused(self):
        for u in ("file:///etc/passwd", "ftp://example.com/x", "gopher://example.com"):
            with self.subTest(u=u):
                self.assertFalse(B.url_allowed(u, ["example.com"])[0])

    def test_browser_internal_schemes_do_not_egress(self):
        for u in ("about:blank", "data:text/html,x", "blob:https://x/y"):
            with self.subTest(u=u):
                self.assertTrue(B.url_allowed(u, [])[0])

    def test_empty_url_is_refused(self):
        self.assertFalse(B.url_allowed("", ["example.com"])[0])

    def test_unauthorized_base_url_raises_rather_than_widening_scope(self):
        with self.assertRaises(B.BrowserScopeError):
            B.Browser(allowlist=["example.com"], base_url="https://evil.tld/")

    def test_allowlist_is_not_widened_by_base_url(self):
        b = B.Browser(allowlist=["example.com"], base_url="https://api.example.com/")
        self.assertEqual(b.allowlist, ["example.com"])


@unittest.skipUnless(_HAVE_PW, "playwright not installed")
class TestLiveBrowser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = _Server()
        try:
            cls.b = B.Browser(allowlist=[], base_url=cls.srv.base,
                              rate_limit=0, settle_ms=250).start()
        except B.BrowserUnavailable as exc:  # pragma: no cover
            cls.srv.stop()
            raise unittest.SkipTest(str(exc))

    @classmethod
    def tearDownClass(cls):
        try:
            cls.b.close()
        finally:
            cls.srv.stop()

    # -- the jail, with a real browser ---------------------------------------
    def test_out_of_scope_subresource_is_blocked(self):
        obs = self.b.goto("/sub")
        hosts = [r["reason"] for r in obs.blocked]
        self.assertTrue(obs.blocked, "the out-of-scope image must be intercepted")
        self.assertTrue(any("blocked.example.net" in r["url"] for r in obs.blocked), obs.blocked)
        self.assertTrue(any("not in egress allowlist" in h for h in hosts), hosts)

    def test_in_scope_page_still_loads_while_subresource_is_blocked(self):
        obs = self.b.goto("/sub")
        self.assertIn("sub", obs.text or "")

    def test_out_of_scope_navigation_raises_before_any_request(self):
        with self.assertRaises(B.BrowserScopeError):
            self.b.goto("https://blocked.example.net/x")

    def test_cookie_for_an_unauthorized_host_is_refused(self):
        with self.assertRaises(B.BrowserScopeError):
            self.b.set_identity("x", cookies=[{"name": "a", "value": "b",
                                               "domain": "evil.tld", "path": "/"}])

    # -- both layers, kept apart --------------------------------------------
    def test_raw_html_is_the_servers_bytes_not_the_dom(self):
        obs = self.b.goto("/dom?q=" + urllib.parse.quote("<b>BOLD</b>"))
        self.assertNotIn("<b>BOLD</b>", obs.raw_html or "",
                         "the server never sent that markup")
        self.assertIn("<b>BOLD</b>", obs.dom_html or "",
                      "the DOM has it because a script wrote it")

    def test_server_never_reflects_into_the_dom_fixture(self):
        obs = self.b.goto("/dom?q=" + urllib.parse.quote(H.PROBE))
        self.assertEqual(obs.findings(H.PROBE_TOKEN, layer="raw"), [],
                         "the server puts nothing of ours in the document")

    def test_char_evidence_is_absent_from_a_serialized_dom_by_construction(self):
        # page.content() serializes, and serialization re-escapes text nodes, so the
        # absence of char evidence in the DOM layer proves nothing. Pinned so nobody
        # later reads an empty dom census as "safe".
        obs = self.b.goto("/dom?q=" + urllib.parse.quote(H.PROBE))
        self.assertIn("p1hZ", obs.dom_html or "")
        self.assertNotIn("p1hZ<>", obs.dom_html or "",
                         "the serializer escapes it; char evidence is impossible here")

    # -- DOM-level injection is judged on STRUCTURE -------------------------
    def test_dom_injection_detects_elements_built_from_our_input(self):
        self.b.goto("/dom?q=" + urllib.parse.quote("p1hZ<img src=x>p1hZ"))
        res = self.b.dom_injection("p1hZ")
        self.assertTrue(res["finding"], res)
        self.assertIn("img", res["elementsBetween"])

    def test_dom_injection_detects_an_injected_attribute_name(self):
        self.b.goto("/dom?q=" + urllib.parse.quote('<b p1hZattr="1">x</b>'))
        res = self.b.dom_injection("p1hZ")
        self.assertTrue(res["finding"], res)
        self.assertTrue(res["attrNames"], res)

    def test_dom_injection_clears_a_payload_that_stays_text(self):
        # "<>" alone builds no element, so it is correctly not a finding.
        self.b.goto("/dom?q=" + urllib.parse.quote(H.PROBE))
        res = self.b.dom_injection(H.PROBE_TOKEN)
        self.assertFalse(res["finding"], res)

    def test_dom_injection_clears_a_server_escaped_page(self):
        self.b.goto("/safe?q=" + urllib.parse.quote("p1hZ<img src=x>p1hZ"))
        res = self.b.dom_injection("p1hZ")
        self.assertFalse(res["finding"], res)

    def test_escaping_differential_on_the_dom_layer_confirms_the_sink(self):
        out = self.b.escaping_differential(
            lambda mk: self.b.goto("/dom?q=" + urllib.parse.quote(
                "p1hZ<img src=x>p1hZ" if mk == H.PROBE_TOKEN else mk)),
            B.CONTROL_MARKER, H.PROBE_TOKEN, layer="dom")
        self.assertTrue(out["dom_injection"]["finding"], out["dom_injection"])
        self.assertTrue(out["confirmed"])

    # -- context-aware verdicts on real renders -----------------------------
    def test_raw_text_node_reflection_is_a_finding(self):
        obs = self.b.goto("/vuln?q=" + urllib.parse.quote(H.PROBE))
        recs = obs.findings(H.PROBE_TOKEN, layer="raw")
        self.assertTrue(recs)
        self.assertEqual(recs[0]["context"], H.TEXT)

    def test_escaped_reflection_is_not_a_finding(self):
        obs = self.b.goto("/safe?q=" + urllib.parse.quote(H.PROBE))
        self.assertEqual(obs.findings(H.PROBE_TOKEN, layer="raw"), [])

    def test_inert_attribute_reflection_is_not_a_finding(self):
        # Raw < and > inside a quoted attribute whose quote is escaped: no bug.
        obs = self.b.goto("/attr?q=" + urllib.parse.quote(H.PROBE))
        recs = obs.census(H.PROBE_TOKEN, layer="raw")
        self.assertTrue(recs, "the marker must be located")
        self.assertEqual(recs[0]["context"], H.ATTR_DQ)
        self.assertEqual(obs.findings(H.PROBE_TOKEN, layer="raw"), [],
                         "raw <> in a quoted attribute is inert")

    # -- execution is observed, not inferred --------------------------------
    def test_execution_oracle_records_a_real_alert(self):
        obs = self.b.goto("/exec?q=" + urllib.parse.quote("<script>alert('p1hFIRED')</script>"))
        self.assertTrue(obs.executed, f"oracle saw nothing: {obs.execution_proof}")
        self.assertTrue(any("p1hFIRED" in str(e.get("detail")) for e in obs.execution_proof),
                        obs.execution_proof)

    def test_no_execution_on_an_escaped_page(self):
        obs = self.b.goto("/safe?q=" + urllib.parse.quote("<script>alert(1)</script>"))
        self.assertFalse(obs.executed)

    def test_dom_sink_write_is_recorded(self):
        obs = self.b.goto("/dom?q=" + urllib.parse.quote("<i>x</i>"))
        self.assertTrue(any("innerHTML" in s["sink"] for s in obs.sinks), obs.sinks)

    def test_message_listener_is_captured(self):
        obs = self.b.goto("/msg")
        self.assertTrue(obs.message_listeners)

    # -- the differential ----------------------------------------------------
    def test_differential_detects_a_cookie_gated_render(self):
        d = self.b.differential("/gated?q=hello", [
            {"name": "no-cookie"},
            {"name": "with-cookie",
             "cookies": [{"name": "gate", "value": "1", "domain": "127.0.0.1", "path": "/"}]},
        ])
        self.assertTrue(d["diffs"][0]["raw_differs"])
        obs = d["observations"]
        self.assertIn("OPEN_RENDER", obs["no-cookie"].raw_html)
        self.assertIn("SAFE_RENDER", obs["with-cookie"].raw_html)

    def test_differential_reports_no_change_for_a_stable_page(self):
        d = self.b.differential("/safe?q=x", [{"name": "a"}, {"name": "b"}])
        self.assertFalse(d["diffs"][0]["raw_differs"])

    def test_escaping_differential_confirms_a_real_injection(self):
        out = self.b.escaping_differential(
            lambda mk: self.b.goto("/vuln?q=" + urllib.parse.quote(
                H.PROBE if mk == H.PROBE_TOKEN else mk)),
            B.CONTROL_MARKER, H.PROBE_TOKEN)
        self.assertTrue(out["confirmed"])

    def test_escaping_differential_clears_an_escaped_page(self):
        out = self.b.escaping_differential(
            lambda mk: self.b.goto("/safe?q=" + urllib.parse.quote(
                H.PROBE if mk == H.PROBE_TOKEN else mk)),
            B.CONTROL_MARKER, H.PROBE_TOKEN)
        self.assertEqual(out["confirmed"], [])

    def test_escaping_differential_clears_an_inert_attribute_sink(self):
        out = self.b.escaping_differential(
            lambda mk: self.b.goto("/attr?q=" + urllib.parse.quote(
                H.PROBE if mk == H.PROBE_TOKEN else mk)),
            B.CONTROL_MARKER, H.PROBE_TOKEN)
        self.assertEqual(out["confirmed"], [],
                         "an inert attribute reflection must not be reported")


class TestShippedStandalone(unittest.TestCase):
    """browser.py runs in the PoC sandbox with no ``p1hunt`` package on sys.path."""

    def _src(self, name):
        import importlib, pathlib as _pl
        mod = importlib.import_module(f"p1hunt.dynamic.{name}")
        return _pl.Path(mod.__file__).read_text(encoding="utf-8")

    def test_browser_imports_no_p1hunt_module_except_the_guarded_analyzer(self):
        import ast
        tree = ast.parse(self._src("browser"))
        bad = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if node.level and all(a.name != "htmlctx" for a in node.names):
                    bad.append(f"relative import of {mod or '.'}")
                if mod.startswith("p1hunt"):
                    bad.append(f"absolute import of {mod}")
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.startswith("p1hunt"):
                        bad.append(f"import {a.name}")
        self.assertEqual(bad, [], f"browser.py must be shippable standalone: {bad}")

    def test_htmlctx_imports_nothing_outside_the_stdlib(self):
        import ast
        tree = ast.parse(self._src("htmlctx"))
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.level:
                    mods.add(".")
                elif node.module:
                    mods.add(node.module.split(".")[0])
            elif isinstance(node, ast.Import):
                for a in node.names:
                    mods.add(a.name.split(".")[0])
        self.assertEqual(mods - {"re", "bisect", "functools", "__future__"}, set(),
                         f"htmlctx must be stdlib-only, got {sorted(mods)}")

    def test_the_analyzer_is_shipped_under_the_name_the_fallback_import_uses(self):
        # browser.py's sandbox path is a bare ``import htmlctx``, so _arm_dynamic must
        # write the file as exactly "htmlctx.py". A rename on either side silently
        # removes the whole DOM/escaping capability from every harness.
        import pathlib as _pl
        swarm = _pl.Path("p1hunt/agents/claude_swarm.py").read_text(encoding="utf-8")
        self.assertIn('"..dynamic.htmlctx", "htmlctx.py"', swarm)
        self.assertIn('"..dynamic.browser", "p1hunt_browser.py"', swarm)
        self.assertIn('"..dynamic.client", "p1hunt_dyn.py"', swarm)
        self.assertIn('"..dynamic.recon", "p1hunt_recon.py"', swarm)
        src = self._src("browser")
        self.assertIn("import htmlctx", src)

    def test_browser_module_refuses_to_run_without_its_analyzer(self):
        # A try/except ImportError that swallowed a missing analyzer would be fail-open.
        src = self._src("browser")
        self.assertIn("raise RuntimeError", src)
        self.assertIn("do not continue without the escaping analyzer", src)

    def test_live_note_teaches_the_browser_and_the_method(self):
        from p1hunt.agents.harness_scaffold import _live_testing_note
        note = _live_testing_note("https://target.example")
        for needle in ("p1hunt_browser", "differential", "dom_injection",
                       "escaping_differential", "obs.executed", "raw_html", "dom_html"):
            with self.subTest(needle=needle):
                self.assertIn(needle, note)

    def test_live_note_warns_that_blocked_subresources_are_not_findings(self):
        from p1hunt.agents.harness_scaffold import _live_testing_note
        note = _live_testing_note("https://target.example")
        self.assertIn("blocked", note)
        self.assertIn("is not itself a finding", note)

    def test_live_note_states_the_serialization_limit(self):
        from p1hunt.agents.harness_scaffold import _live_testing_note
        note = _live_testing_note("https://target.example")
        self.assertIn("SERIALIZATION", note)

    def test_browser_does_not_disable_csp(self):
        # bypass_csp would manufacture findings a real victim's browser would not have.
        self.assertNotIn("bypass_csp=True", self._src("browser"))


if __name__ == "__main__":
    unittest.main()
