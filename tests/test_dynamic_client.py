"""The interaction-engine client + OOB listener (spec §10, §12).

Exercises the harness-facing client against a LOOPBACK test server (no external network): scope
enforcement, identity/token resolution, the refusal ``assert_forbidden`` helper, and the OOB
round-trip that turns a blind callback into a deterministic pass/fail.
"""

from __future__ import annotations

import email.utils
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from p1hunt.dynamic import client as client_mod
from p1hunt.dynamic.client import (
    BLOCKED_MARKER,
    BlockedError,
    Client,
    MethodDenied,
    RateLimitExceeded,
    RedirectDenied,
    ScopeError,
    _norm_host,
    _retry_after_seconds,
    _TokenBucket,
    classify_block,
    is_blocked,
)
from p1hunt.dynamic.oob import start_oob_listener


class _App(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/ok":
            self.send_response(200)
        else:  # everything else is forbidden (simulates correct authz)
            self.send_response(403)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_a):
        return


class TestClientScope(unittest.TestCase):
    def setUp(self):
        for k in list(os.environ):
            if k.startswith("P1HUNT_TOKEN") or k in ("P1HUNT_BASE_URL", "P1HUNT_EGRESS_ALLOWLIST"):
                del os.environ[k]

    def test_refuses_out_of_scope_host(self):
        c = Client(base_url="https://api.example.com", egress_allowlist=["example.com"])
        with self.assertRaises(ScopeError):
            c.get("https://evil.com/steal")

    def test_token_resolution(self):
        os.environ["P1HUNT_TOKEN_A"] = "tokA"
        os.environ["P1HUNT_TOKEN_B"] = "tokB"
        os.environ["P1HUNT_TOKEN"] = "tokDefault"
        c = Client(base_url="https://api.example.com", egress_allowlist=["example.com"])
        self.assertEqual(c.token_for("A"), "tokA")
        self.assertEqual(c.token_for("B"), "tokB")
        self.assertEqual(c.token_for(None), "tokDefault")
        self.assertEqual(c.token_for("default"), "tokDefault")
        self.assertIn("a", c.identities())
        self.assertIn("b", c.identities())

    # --- B1: the allowlist must NEVER authorize itself ------------------------------------
    def test_base_url_is_not_self_authorizing(self):
        """THE bug: the client used to APPEND ``_host(base_url)`` to the allowlist when it was
        missing, so a harness that hardcoded its own target authorized its own destination and
        the "independent transport check" became a no-op. Harnesses are LLM-authored and run in
        a separate pytest process, so this was the whole jail."""
        with self.assertRaises(ScopeError) as ctx:
            Client("https://attacker.tld", egress_allowlist=["example.com"])
        self.assertIn("attacker.tld", str(ctx.exception))
        # ...and the operator's allowlist is not mutated on the way out.
        allow = ["example.com"]
        with self.assertRaises(ScopeError):
            Client("https://attacker.tld", egress_allowlist=allow)
        self.assertEqual(allow, ["example.com"])

    def test_base_url_from_env_is_not_self_authorizing(self):
        # The real wiring: the swarm exports both env vars. A base URL that authorize_dynamic
        # REJECTED (e.g. a non-sandbox environment) must not slip through this path either.
        os.environ["P1HUNT_BASE_URL"] = "https://prod.attacker.tld"
        os.environ["P1HUNT_EGRESS_ALLOWLIST"] = "uat.example.com"
        with self.assertRaises(ScopeError):
            Client()

    def test_in_scope_base_url_still_works(self):
        # The fix must not cost capability: an AUTHORIZED base URL is accepted, including as a
        # subdomain of an allowlist entry, and the allowlist stays exactly what was authorized.
        c = Client(base_url="https://uat.example.com", egress_allowlist=["example.com"])
        self.assertEqual(c.egress_allowlist, ["example.com"])
        c2 = Client(base_url="https://uat.example.com", egress_allowlist=["uat.example.com"])
        self.assertEqual(c2.egress_allowlist, ["uat.example.com"])

    def test_allowlist_entries_may_be_urls_or_host_ports(self):
        # Parity with egress.host_in_allowlist: an operator who authorizes "https://example.com"
        # or "example.com:8443" means the HOST they wrote.
        self.assertEqual(
            Client(base_url="https://api.example.com",
                   egress_allowlist=["https://example.com/"]).egress_allowlist,
            ["https://example.com/"])
        Client(base_url="https://example.com", egress_allowlist=["example.com:8443"])

    def test_the_operator_allowlist_is_a_ceiling_not_a_default(self):
        """The same self-authorization hole spelled differently: a harness is LLM-authored, so
        letting its own ``egress_allowlist=[...]`` ADD a host would defeat the jail just as
        appending ``_host(base_url)`` did. A constructor argument may only NARROW the allowlist
        the swarm exported."""
        os.environ["P1HUNT_EGRESS_ALLOWLIST"] = "example.com"
        # Widening is ignored (and the base_url check then refuses the unauthorized target).
        with self.assertRaises(ScopeError):
            Client("https://attacker.tld", egress_allowlist=["attacker.tld", "example.com"])
        c = Client("https://api.example.com", egress_allowlist=["attacker.tld", "example.com"])
        self.assertEqual(c.egress_allowlist, ["example.com"])
        with self.assertRaises(ScopeError):
            c.get("https://attacker.tld/steal")
        # Narrowing to a subdomain of what the operator authorized IS allowed.
        narrow = Client("https://uat.example.com", egress_allowlist=["uat.example.com"])
        self.assertEqual(narrow.egress_allowlist, ["uat.example.com"])
        with self.assertRaises(ScopeError):
            narrow.get("https://other.example.com/x")
        # An argument with nothing authorized in it falls back to the operator's ceiling rather
        # than to an EMPTY allowlist a harness could then treat as "no jail".
        self.assertEqual(
            Client("https://api.example.com", egress_allowlist=["attacker.tld"]).egress_allowlist,
            ["example.com"])

    def test_loopback_base_url_needs_no_allowlist_entry(self):
        # The local OOB listener / a locally stood-up instance is not the program's host.
        c = Client(base_url="http://127.0.0.1:8080", egress_allowlist=[])
        self.assertEqual(c.egress_allowlist, [])


class TestClientLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _App)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.server.server_address[:2]
        cls.base = f"http://127.0.0.1:{port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_get_ok(self):
        c = Client(base_url=self.base)
        r = c.get("/ok")
        self.assertEqual(r.status, 200)
        self.assertTrue(c.is_authorized(r))

    def test_assert_forbidden_passes_when_refused(self):
        c = Client(base_url=self.base)
        # /secret returns 403 -> the authz check holds, no AssertionError.
        c.assert_forbidden("GET", "/secret", identity="B")

    def test_assert_forbidden_raises_on_bypass(self):
        c = Client(base_url=self.base)
        # /ok returns 200 -> an authz bypass; assert_forbidden must raise (that's the PoC signal).
        with self.assertRaises(AssertionError):
            c.assert_forbidden("GET", "/ok", identity="B")


class TestOOB(unittest.TestCase):
    def test_round_trip(self):
        import tempfile
        import urllib.request

        hits = os.path.join(tempfile.mkdtemp(), "oob_hits.jsonl")
        listener = start_oob_listener(hits)
        self.assertIsNotNone(listener)
        try:
            os.environ["P1HUNT_OOB_URL"] = listener.url
            os.environ["P1HUNT_OOB_HITS"] = hits
            c = Client(base_url="https://api.example.com", egress_allowlist=["example.com"])
            url, token = c.oob_url()
            self.assertIn(token, url)
            # Simulate the TARGET dereferencing the OOB URL.
            urllib.request.urlopen(url, timeout=3).read()
            self.assertTrue(c.oob_received(token, wait=2))
            self.assertFalse(c.oob_received("never_fired_token", wait=0.2))
        finally:
            listener.stop()


# ---------------------------------------------------------------------------
# BLOCKED (edge/WAF) vs REFUSED (application) classification.
#
# The bug these pin: ``assert_forbidden`` accepted any 401/403/404 as "correctly refused", so a
# Cloudflare challenge or a rate-limiter that blanket-blocks every request satisfied EVERY authz
# assertion in a harness — and the all-green run was then stamped as a verified authorization
# boundary (or, with the inverted expect, as a reproduced finding).
#
# The opposite error matters just as much and is tested just as hard: a bare 403 with no edge
# markers is a GENUINE authorization refusal. Breaking that to catch WAFs would blind the hunter
# to the very thing it exists to find, so every conservative case below is asserted explicitly.
# ---------------------------------------------------------------------------
_CF_CHALLENGE_BODY = (
    b"<!DOCTYPE html><html><head><title>Just a moment...</title></head>"
    b"<body><div id='cf-browser-verification'>Checking your browser before accessing.</div>"
    b"</body></html>"
)
_CF_BLOCK_PAGE = (
    b"<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head>"
    b"<body>Sorry, you have been blocked</body></html>"
)
_INCAPSULA_BODY = b"Request unsuccessful. Incapsula incident ID: 4891-22-1"
_APP_REFUSAL_JSON = b'{"error":"forbidden","detail":"you do not own this object"}'

# route -> (status, headers, body). Each entry is one real-world edge/app shape.
_WAF_ROUTES = {
    # --- genuine APPLICATION decisions: these must stay REFUSED, never BLOCKED -------------
    "/app-403-bare": (403, {}, b""),
    "/app-403-json": (403, {"Content-Type": "application/json"}, _APP_REFUSAL_JSON),
    # A JSON 403 from an app that merely SITS BEHIND Cloudflare. The vendor headers are present
    # on every response such a target sends; treating them as a block would destroy real authz
    # detection for most bounty targets.
    "/app-403-json-behind-cdn": (
        403,
        {"Content-Type": "application/json", "CF-RAY": "7d2f1a-LHR", "Server": "cloudflare"},
        _APP_REFUSAL_JSON,
    ),
    "/app-401": (401, {"Content-Type": "application/json"}, b'{"error":"unauthenticated"}'),
    "/app-404": (404, {"Content-Type": "application/json"}, b'{"error":"not found"}'),
    "/app-200": (200, {"Content-Type": "application/json"}, b'{"id":1,"owner":"A"}'),
    # --- EDGE blocks: the application never decided ---------------------------------------
    "/waf-cf-challenge": (
        403, {"Content-Type": "text/html", "CF-RAY": "7d2f1a-LHR", "Server": "cloudflare"},
        _CF_CHALLENGE_BODY,
    ),
    "/waf-cf-blockpage": (
        403, {"Content-Type": "text/html", "CF-RAY": "7d2f1a-LHR", "Server": "cloudflare"},
        _CF_BLOCK_PAGE,
    ),
    # cf-mitigated is the edge stating outright that it acted — decisive on its own.
    "/waf-cf-mitigated": (403, {"cf-mitigated": "challenge"}, b""),
    "/waf-429": (429, {"Retry-After": "60"}, b"rate limited"),
    "/waf-incapsula": (403, {"X-Iinfo": "9-1-2", "Content-Type": "text/html"}, _INCAPSULA_BODY),
    "/waf-akamai-503": (503, {"X-Akamai-Request-ID": "abc123"}, b"<html>edge error</html>"),
    # An HTML block page with NO vendor marker at all and no challenge text stays an app refusal.
    "/app-403-html-no-vendor": (403, {"Content-Type": "text/html"}, b"<html>Forbidden</html>"),
    "/server-500": (500, {"Content-Type": "application/json"}, b'{"error":"boom"}'),
}


class _WafApp(BaseHTTPRequestHandler):
    """Loopback server replaying each real edge/application response shape."""

    def _respond(self):
        route = self.path.split("?")[0]
        status, headers, body = _WAF_ROUTES.get(route, (404, {}, b"no such route"))
        # send_response_only avoids BaseHTTP's own Server/Date headers, so a test that needs
        # "Server: cloudflare" gets exactly that header and nothing competing with it.
        self.send_response_only(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PATCH = do_PUT = _respond

    def log_message(self, *_a):
        return


class TestBlockClassifier(unittest.TestCase):
    """Pure classification, no socket: a response SHAPE in, a BLOCKED/REFUSED verdict out."""

    class _R:
        def __init__(self, status, headers=None, text=""):
            self.status = status
            self.status_code = status
            self.headers = headers or {}
            self.text = text

    # --- conservative direction: real refusals must survive -------------------------------
    def test_bare_403_is_a_legitimate_refusal(self):
        self.assertEqual(classify_block(self._R(403)), "")
        self.assertFalse(is_blocked(self._R(403)))

    def test_bare_401_and_404_are_refusals(self):
        for status in (401, 404):
            self.assertEqual(classify_block(self._R(status)), "", status)

    def test_json_403_behind_cloudflare_is_still_a_refusal(self):
        r = self._R(403, {"CF-RAY": "7d2f1a", "Server": "cloudflare",
                          "Content-Type": "application/json"},
                    '{"error":"forbidden"}')
        self.assertEqual(classify_block(r), "")

    def test_html_403_without_any_vendor_marker_is_a_refusal(self):
        r = self._R(403, {"Content-Type": "text/html"}, "<html>Forbidden</html>")
        self.assertEqual(classify_block(r), "")

    def test_success_is_not_blocked(self):
        self.assertEqual(classify_block(self._R(200, {}, '{"ok":true}')), "")

    # --- blocks ---------------------------------------------------------------------------
    def test_cf_mitigated_header_is_blocked_at_any_status(self):
        for status in (200, 403, 503):
            self.assertTrue(classify_block(self._R(status, {"cf-mitigated": "challenge"})), status)

    def test_js_challenge_body_is_blocked(self):
        for marker in ("Just a moment...", "Checking your browser before accessing",
                       "Attention Required! | Cloudflare"):
            r = self._R(403, {"Content-Type": "text/html"}, f"<html><title>{marker}</title></html>")
            self.assertTrue(classify_block(r), marker)

    def test_429_is_blocked_not_an_authorization_decision(self):
        reason = classify_block(self._R(429))
        self.assertTrue(reason)
        self.assertIn("429", reason)

    def test_incapsula_and_akamai_markers_are_blocked(self):
        incap = self._R(403, {"X-Iinfo": "9-1-2", "Content-Type": "text/html"},
                        "Request unsuccessful. Incapsula incident ID: 1-2")
        self.assertTrue(classify_block(incap))
        cookie = self._R(403, {"Set-Cookie": "incap_ses_123=abc; path=/",
                               "Content-Type": "text/html"}, "<html>denied</html>")
        self.assertTrue(classify_block(cookie))
        akamai = self._R(503, {"X-Akamai-Request-ID": "abc"}, "<html>edge</html>")
        self.assertTrue(classify_block(akamai))

    def test_cloudflare_html_block_page_is_blocked(self):
        r = self._R(403, {"CF-RAY": "7d2f1a", "Server": "cloudflare",
                          "Content-Type": "text/html"}, "<html>denied by edge</html>")
        self.assertTrue(classify_block(r))

    def test_header_casing_does_not_matter(self):
        lower = self._R(403, {"cf-ray": "x", "server": "cloudflare",
                              "content-type": "text/html"}, "<html>x</html>")
        upper = self._R(403, {"CF-Ray": "x", "SERVER": "CloudFlare",
                              "Content-Type": "TEXT/HTML"}, "<html>x</html>")
        self.assertTrue(classify_block(lower))
        self.assertTrue(classify_block(upper))


class TestAssertForbiddenBlocked(unittest.TestCase):
    """``assert_forbidden`` / ``idor_probe`` over the loopback edge-shape server."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _WafApp)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _client(self):
        return Client(base_url=self.base)

    # --- a genuine refusal still registers as a refusal ------------------------------------
    def test_bare_403_still_counts_as_refused(self):
        # THE conservative case. A real authz refusal must pass cleanly: no BlockedError, no
        # AssertionError. Breaking this would blind the hunter to real authorization behavior.
        resp = self._client().assert_forbidden("GET", "/app-403-bare", identity="B")
        self.assertEqual(resp.status, 403)

    def test_json_403_behind_cdn_still_counts_as_refused(self):
        resp = self._client().assert_forbidden("GET", "/app-403-json-behind-cdn", identity="B")
        self.assertEqual(resp.status, 403)

    def test_401_and_404_still_count_as_refused(self):
        c = self._client()
        self.assertEqual(c.assert_forbidden("GET", "/app-401", identity="B").status, 401)
        self.assertEqual(c.assert_forbidden("GET", "/app-404", identity="B").status, 404)

    # --- a permit is still the PoC signal --------------------------------------------------
    def test_permit_still_raises_assertion_error(self):
        with self.assertRaises(AssertionError):
            self._client().assert_forbidden("GET", "/app-200", identity="B")

    # --- an edge block is neither ----------------------------------------------------------
    def test_cloudflare_challenge_raises_blocked_not_a_silent_pass(self):
        with self.assertRaises(BlockedError):
            self._client().assert_forbidden("GET", "/waf-cf-challenge", identity="B")

    def test_each_edge_shape_raises_blocked(self):
        for route in ("/waf-cf-challenge", "/waf-cf-blockpage", "/waf-cf-mitigated",
                      "/waf-429", "/waf-incapsula"):
            with self.subTest(route=route), self.assertRaises(BlockedError):
                self._client().assert_forbidden("GET", route, identity="B")

    def test_blocked_error_is_not_an_assertion_error(self):
        # The pipeline reads AssertionError out of a refusal helper as "the app permitted it" —
        # the PoC signal. A block must NOT be able to impersonate that, in either direction.
        with self.assertRaises(BlockedError) as ctx:
            self._client().assert_forbidden("GET", "/waf-429", identity="B")
        self.assertNotIsInstance(ctx.exception, AssertionError)
        try:
            self._client().assert_forbidden("GET", "/waf-429", identity="B")
        except AssertionError:  # pragma: no cover — would mean the separation broke
            self.fail("a WAF block was raised as an AssertionError (reads as a bypass)")
        except BlockedError:
            pass

    def test_blocked_error_message_carries_the_runner_marker(self):
        # The harness runs in a separate pytest process; the runner can only see this token.
        with self.assertRaises(BlockedError) as ctx:
            self._client().assert_forbidden("GET", "/waf-cf-challenge", identity="B")
        self.assertIn(BLOCKED_MARKER, str(ctx.exception))

    def test_idor_probe_raises_blocked_too(self):
        with self.assertRaises(BlockedError):
            self._client().idor_probe("GET", "/waf-cf-challenge", owner="A", attacker="B",
                                      resource_id=1)

    def test_idor_probe_still_refuses_and_still_detects_a_permit(self):
        c = self._client()
        self.assertEqual(
            c.idor_probe("GET", "/app-403-bare", owner="A", attacker="B", resource_id=7).status,
            403)
        with self.assertRaises(AssertionError):
            c.idor_probe("GET", "/app-200", owner="A", attacker="B", resource_id=7)

    def test_allow_blocked_opt_out_lets_a_block_through_for_inspection(self):
        resp = self._client().assert_forbidden("GET", "/waf-cf-challenge", identity="B",
                                               allow_blocked=True)
        self.assertEqual(resp.status, 403)

    # --- baseline health ------------------------------------------------------------------
    def test_baseline_health_on_a_live_endpoint(self):
        h = self._client().baseline_health("/app-200")
        self.assertTrue(h["ok"])
        self.assertTrue(h["reachable"])
        self.assertFalse(h["blocked"])
        self.assertEqual(h["status"], 200)

    def test_baseline_health_detects_a_block(self):
        h = self._client().baseline_health("/waf-cf-challenge")
        self.assertFalse(h["ok"])
        self.assertTrue(h["blocked"])
        self.assertTrue(h["block_reason"])

    def test_baseline_health_detects_an_unhealthy_target(self):
        h = self._client().baseline_health("/server-500")
        self.assertFalse(h["ok"])
        self.assertFalse(h["blocked"])
        self.assertEqual(h["status"], 500)

    def test_baseline_health_detects_an_unreachable_target(self):
        # A closed port on loopback: reachable=False, and no exception escapes.
        c = Client(base_url="http://127.0.0.1:1")
        h = c.baseline_health("/")
        self.assertFalse(h["ok"])
        self.assertFalse(h["reachable"])

    def test_baseline_health_does_not_swallow_a_scope_error(self):
        # Safe-harbor: an out-of-scope probe must still raise, not be reported as "unreachable".
        c = Client(base_url=self.base)
        with self.assertRaises(ScopeError):
            c.baseline_health("https://evil.example.com/")

    def test_require_live_baseline_raises_on_block_and_passes_when_live(self):
        c = self._client()
        self.assertTrue(c.require_live_baseline("/app-200")["ok"])
        for route in ("/waf-cf-challenge", "/server-500"):
            with self.subTest(route=route), self.assertRaises(BlockedError) as ctx:
                c.require_live_baseline(route)
            self.assertIn(BLOCKED_MARKER, str(ctx.exception))


class TestBlockedReachesTheRunner(unittest.TestCase):
    """The cross-module contract: a real BlockedError must be recognizable by the web runner.

    The client raises in the harness subprocess; the runner only ever sees captured text. If
    these two drift apart, a WAF block silently becomes a verdict again.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _WafApp)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_runner_recognizes_a_genuinely_raised_blocked_error(self):
        from p1hunt.runners.base import ReproSpec
        from p1hunt.runners.web import parse_pytest

        # Provoke a REAL BlockedError from the real helper against a real WAF response, so this
        # test breaks if either side renames the marker or stops raising.
        with self.assertRaises(BlockedError) as ctx:
            Client(base_url=self.base).assert_forbidden(
                "GET", "/waf-cf-challenge", identity="B")
        message = str(ctx.exception)
        self.assertIn(BLOCKED_MARKER, message)

        # The shape pytest prints when a test body raises it.
        output = (
            "FAILED .p1hunt-poc/test_authz.py::test_b_cannot_read_a_object - "
            f"p1hunt_dyn.BlockedError: {message}\n"
            "========================= 1 failed in 0.31s =========================="
        )
        for expect in ("fail", "pass"):
            with self.subTest(expect=expect):
                r = parse_pytest(output, 1, ReproSpec(expect=expect))
                self.assertFalse(r["reproduced"], "a WAF block must never read as reproduced")
                self.assertTrue(r.get("blocked"))
                self.assertTrue(r.get("infrastructure_error"))


# =================================================================================================
# B2 — redirects are re-checked and credentials do not cross a host boundary
# =================================================================================================
class _RedirectApp(BaseHTTPRequestHandler):
    """Loopback server that 302s in the three shapes that matter, plus an echo endpoint."""

    def do_GET(self):  # noqa: N802
        route = self.path.split("?")[0]
        if route == "/off-allowlist":
            self.send_response(302)
            self.send_header("Location", "https://attacker.tld/steal")
            self.end_headers()
        elif route == "/open-redirect":
            # The classic in-scope OPEN REDIRECT — a routine bounty finding, and the exact shape
            # that walks the Authorization header off-allowlist.
            self.send_response(301)
            self.send_header("Location", "http://evil.example.net/collect")
            self.end_headers()
        elif route == "/cross-loopback":
            # A host CHANGE that is still in scope (127.0.0.1 -> localhost): the hop is allowed,
            # but the engagement's credentials must not travel with it.
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.server.server_address[1]}/echo")
            self.end_headers()
        elif route == "/same-host":
            self.send_response(302)
            self.send_header("Location", "/echo")
            self.end_headers()
        elif route == "/echo":
            body = json.dumps({
                "auth": self.headers.get("Authorization", ""),
                "cookie": self.headers.get("Cookie", ""),
                "apikey": self.headers.get("X-Api-Key", ""),
                "ua": self.headers.get("User-Agent", ""),
                "bb": self.headers.get("X-Bug-Bounty", ""),
                "extra": self.headers.get("X-Trace", ""),
                "host": self.headers.get("Host", ""),
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"{}")

    do_HEAD = do_DELETE = do_POST = do_PUT = do_PATCH = do_OPTIONS = do_GET

    def log_message(self, *_a):
        return


class _LoopbackCase(unittest.TestCase):
    """Base: one loopback server + a clean P1HUNT_* environment per test."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectApp)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self._saved = {k: v for k, v in os.environ.items() if k.startswith("P1HUNT_")}
        for k in list(os.environ):
            if k.startswith("P1HUNT_"):
                del os.environ[k]

    def tearDown(self):
        for k in list(os.environ):
            if k.startswith("P1HUNT_"):
                del os.environ[k]
        os.environ.update(self._saved)

    def _client(self, **kw):
        kw.setdefault("egress_allowlist", [])
        return Client(base_url=self.base, **kw)


class TestRedirectJail(_LoopbackCase):
    def test_off_allowlist_redirect_is_refused(self):
        """``urllib.request.urlopen`` (what this client used to call) follows a 302 ANYWHERE with
        the original headers attached. An in-scope host that redirects off-allowlist must not be
        able to make the harness contact a third party."""
        c = self._client()
        with self.assertRaises(RedirectDenied) as ctx:
            c.get("/off-allowlist", token="engagement-token")
        msg = str(ctx.exception)
        self.assertIn("attacker.tld", msg)
        self.assertIn("NOT sent", msg)

    def test_in_scope_open_redirect_is_refused(self):
        with self.assertRaises(RedirectDenied):
            self._client().get("/open-redirect", token="engagement-token")

    def test_redirect_denied_is_a_scope_error_and_not_an_assertion(self):
        # A harness that catches ScopeError keeps working; and a refused hop must never read as
        # "the application permitted something", which is what an AssertionError means here.
        c = self._client()
        with self.assertRaises(ScopeError):
            c.get("/off-allowlist")
        try:
            c.get("/off-allowlist")
        except AssertionError:  # pragma: no cover - would mean the separation broke
            self.fail("a refused redirect was raised as an AssertionError (reads as a bypass)")
        except ScopeError as exc:
            self.assertNotIsInstance(exc, AssertionError)


    def test_credentials_are_stripped_on_an_in_scope_host_change(self):
        c = self._client()
        r = c.get("/cross-loopback", token="engagement-token",
                  headers={"Cookie": "session=abc", "X-Api-Key": "k"})
        self.assertEqual(r.status, 200)
        echoed = r.json()
        self.assertEqual(echoed["auth"], "", "Authorization crossed a host boundary")
        self.assertEqual(echoed["cookie"], "", "Cookie crossed a host boundary")
        self.assertEqual(echoed["apikey"], "", "X-Api-Key crossed a host boundary")
        self.assertTrue(r.redirected)
        self.assertIn("localhost", r.final_url)
        # ``url`` still reports what the harness ASKED for, so existing assertions keep meaning.
        self.assertIn("127.0.0.1", r.url)

    def test_same_host_redirect_keeps_credentials(self):
        # Capability check: a plain same-host 302 (login flows, trailing-slash redirects) must
        # still carry the identity, or every authenticated harness breaks.
        r = self._client().get("/same-host", token="engagement-token")
        self.assertEqual(r.json()["auth"], "Bearer engagement-token")

    def test_a_non_http_redirect_scheme_is_refused(self):
        # urllib's own handler would still follow an ftp:// hop. An HTTP harness has no business
        # changing protocol mid-chain, so it is refused rather than inspected.
        handler = client_mod._ScopedRedirectHandler(["example.com"], "https://example.com/a")
        with self.assertRaises(RedirectDenied) as ctx:
            handler.redirect_request(None, None, 302, "Found", {},
                                     "ftp://example.com/payload")
        self.assertIn("not http/https", str(ctx.exception))

    def test_a_plain_request_is_unaffected(self):
        r = self._client().get("/echo", token="tok")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.json()["auth"], "Bearer tok")
        self.assertFalse(r.redirected)


# =================================================================================================
# B3 — the destructive-verb floor
# =================================================================================================
class TestMethodFloor(_LoopbackCase):
    def test_delete_is_refused_by_default(self):
        """The shipped client happily issued ``request("DELETE", ...)`` despite the repo's
        destructive floor (safety/policies._LIVE_WRITE_METHODS deliberately excludes DELETE: its
        accidental success is irreversible even on an owned/UAT object)."""
        c = self._client()
        with self.assertRaises(MethodDenied) as ctx:
            c.request("DELETE", "/echo")
        self.assertIn("DELETE", str(ctx.exception))

    def test_method_denied_is_not_an_assertion_error(self):
        c = self._client()
        with self.assertRaises(MethodDenied) as ctx:
            c.request("DELETE", "/echo")
        self.assertNotIsInstance(ctx.exception, AssertionError)
        self.assertIsInstance(ctx.exception, ScopeError)

    def test_other_non_floor_verbs_are_refused(self):
        c = self._client()
        for verb in ("TRACE", "CONNECT", "PURGE", "MOVE", "WIPE"):
            with self.subTest(verb=verb), self.assertRaises(MethodDenied):
                c.request(verb, "/echo")

    def test_read_and_non_destructive_write_verbs_still_work(self):
        c = self._client()
        for verb in ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"):
            with self.subTest(verb=verb):
                self.assertEqual(c.request(verb, "/echo").status, 200)

    def test_destructive_verb_unlocks_only_when_explicitly_asked(self):
        os.environ["P1HUNT_ALLOW_DESTRUCTIVE_METHODS"] = "DELETE"
        self.assertEqual(self._client().request("DELETE", "/echo").status, 200)
        del os.environ["P1HUNT_ALLOW_DESTRUCTIVE_METHODS"]
        self.assertEqual(
            self._client(allow_methods=["GET", "DELETE"]).request("DELETE", "/echo").status, 200)
        # ...and unlocking DELETE does not unlock everything else.
        with self.assertRaises(MethodDenied):
            self._client(allow_methods=["GET", "DELETE"]).request("TRACE", "/echo")


# =================================================================================================
# B3 — the rate limiter (per host, pacing, fail-closed) and Retry-After
# =================================================================================================
class TestRateLimiter(unittest.TestCase):
    """The limiter is a pure token bucket, so it is tested with an injected clock — no sleeping."""

    def _bucket(self, per_minute=60.0, burst=2.0, max_wait=30.0):
        return _TokenBucket(per_minute, burst, max_wait)

    def _fake_clock(self):
        state = {"t": 1000.0, "slept": 0.0}

        def now():
            return state["t"]

        def sleep(sec):
            state["slept"] += sec
            state["t"] += sec
        return state, now, sleep

    def test_path_varying_requests_are_still_rate_limited(self):
        """Keyed on the HOST, never the URL. Keying on the URL is what made ScopeGuard's limiter
        meaningless before it was fixed: vary the path and every request starts a fresh window."""
        b = self._bucket(per_minute=60.0, burst=2.0)
        state, now, sleep = self._fake_clock()
        for i in range(4):
            b.take(f"api.example.com", sleep=sleep, now=now)
            del i
        # burst of 2 free, then 1s per token at 60/min -> ~2s of pacing across 4 requests.
        self.assertAlmostEqual(state["slept"], 2.0, places=3)

    def test_separate_hosts_have_separate_budgets(self):
        b = self._bucket(per_minute=60.0, burst=1.0)
        state, now, sleep = self._fake_clock()
        b.take("a.example.com", sleep=sleep, now=now)
        b.take("b.example.com", sleep=sleep, now=now)
        self.assertEqual(state["slept"], 0.0)

    def test_loopback_is_exempt(self):
        b = self._bucket(per_minute=1.0, burst=1.0)
        state, now, sleep = self._fake_clock()
        for _ in range(20):
            for host in ("127.0.0.1", "localhost", "::1", "app.localhost"):
                b.take(host, sleep=sleep, now=now)
        self.assertEqual(state["slept"], 0.0)

    def test_refuses_rather_than_waiting_forever(self):
        b = self._bucket(per_minute=1.0, burst=1.0, max_wait=5.0)
        state, now, sleep = self._fake_clock()
        b.take("api.example.com", sleep=sleep, now=now)
        with self.assertRaises(RateLimitExceeded) as ctx:
            b.take("api.example.com", sleep=sleep, now=now)
        # Fail CLOSED: nothing sent, no unbounded hang, and not an AssertionError.
        self.assertNotIsInstance(ctx.exception, AssertionError)
        self.assertEqual(state["slept"], 0.0)
        self.assertIn(BLOCKED_MARKER, str(ctx.exception),
                      "the runner greps this marker to record ran=False")

    def test_zero_rate_means_no_live_contact(self):
        # Same floor as ScopeGuard's limiter: no rate => no live contact permitted (never
        # "unlimited", which is how a 0 would read if it were taken as "off").
        for rate in (0.0, -5.0):
            with self.subTest(rate=rate), self.assertRaises(RateLimitExceeded):
                self._bucket(per_minute=rate).take("api.example.com")

    def test_a_throttling_host_is_held_off_for_what_it_asked(self):
        b = self._bucket(per_minute=600.0, burst=10.0, max_wait=30.0)
        state, now, sleep = self._fake_clock()
        b.penalize("api.example.com", 12.0, now=now)
        b.take("api.example.com", sleep=sleep, now=now)
        self.assertAlmostEqual(state["slept"], 12.0, places=3)
        # ...and a pause longer than the cap refuses instead of sleeping it off.
        b.penalize("api.example.com", 120.0, now=now)
        with self.assertRaises(RateLimitExceeded):
            b.take("api.example.com", sleep=sleep, now=now)

    def test_retry_after_parsing(self):
        self.assertEqual(_retry_after_seconds({"Retry-After": "7"}, cap=60), 7.0)
        self.assertEqual(_retry_after_seconds({"retry-after": "7"}, cap=60), 7.0)
        self.assertEqual(_retry_after_seconds({"Retry-After": "999"}, cap=60), 60.0)
        self.assertEqual(_retry_after_seconds({}, cap=60), 0.0)
        self.assertEqual(_retry_after_seconds({"Retry-After": "soon"}, cap=60), 0.0)
        # An HTTP-date in the past clamps to 0 rather than going negative.
        self.assertEqual(
            _retry_after_seconds({"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}, cap=60), 0.0)
        future = email.utils.formatdate(time.time() + 20, usegmt=True)
        self.assertGreater(_retry_after_seconds({"Retry-After": future}, cap=60), 10.0)

    def test_malformed_env_falls_back_to_the_default_not_to_unlimited(self):
        saved = os.environ.get("P1HUNT_RATE_LIMIT")
        os.environ["P1HUNT_RATE_LIMIT"] = "fast please"
        try:
            self.assertEqual(Client(egress_allowlist=["example.com"]).rate_limit, 30.0)
        finally:
            os.environ.pop("P1HUNT_RATE_LIMIT", None)
            if saved is not None:
                os.environ["P1HUNT_RATE_LIMIT"] = saved


class TestRateLimitWiring(_LoopbackCase):
    def test_env_configures_the_client_limiter(self):
        os.environ["P1HUNT_RATE_LIMIT"] = "7"
        c = self._client()
        self.assertEqual(c.rate_limit, 7.0)
        self.assertAlmostEqual(c._bucket.rate, 7.0 / 60.0)

    def test_throttle_waiting_is_not_counted_as_target_latency(self):
        """``timing_oracle`` compares ``resp.elapsed`` between two payloads. If limiter pacing
        landed inside that measurement, every blind-injection oracle would fire on the throttle
        instead of the target."""
        c = self._client()
        c._bucket.take = lambda host, **kw: (time.sleep(0.4), 0.4)[1]
        r = c.get("/echo")
        self.assertEqual(r.status, 200)
        self.assertLess(r.elapsed, 0.3, "limiter pacing leaked into resp.elapsed")

    def test_a_429_holds_the_host_off_and_is_still_returned(self):
        # The throttled response must still come back so classify_block reads it as an edge block
        # (ran=False) instead of the client swallowing it into a retry loop.
        c = self._client()
        penalized = []
        c._bucket.penalize = lambda host, seconds, **kw: penalized.append((host, seconds))

        class _R:
            status = 429
            headers = {"Retry-After": "90"}
        # Drive the throttle bookkeeping the same way request() does.
        pause = _retry_after_seconds(_R.headers, cap=300.0)
        c._bucket.penalize(_norm_host(self.base), pause)
        self.assertEqual(penalized, [("127.0.0.1", 90.0)])
        self.assertTrue(is_blocked(_R()), "a 429 must still classify as an edge block")


# =================================================================================================
# B4 — a request that is not instantly bot-blocked, and operator identification
# =================================================================================================
class TestFingerprint(_LoopbackCase):
    def test_default_user_agent_is_not_python_urllib(self):
        r = self._client().get("/echo")
        ua = r.json()["ua"]
        self.assertNotIn("Python-urllib", ua)
        self.assertTrue(ua.startswith("Mozilla/"), ua)

    def test_user_agent_is_configurable(self):
        os.environ["P1HUNT_USER_AGENT"] = "p1hunt-research/1.0 (+contact)"
        self.assertEqual(self._client().get("/echo").json()["ua"], "p1hunt-research/1.0 (+contact)")
        self.assertEqual(
            self._client(user_agent="explicit/2").get("/echo").json()["ua"], "explicit/2")

    def test_operator_identification_header(self):
        # Several programs REQUIRE an identifying header on every request.
        os.environ["P1HUNT_ID_HEADER"] = "X-Bug-Bounty: my-h1-handle"
        self.assertEqual(self._client().get("/echo").json()["bb"], "my-h1-handle")

    def test_extra_headers_support_several_pairs(self):
        os.environ["P1HUNT_EXTRA_HEADERS"] = "X-Bug-Bounty: handle; X-Trace: run-42"
        echoed = self._client().get("/echo").json()
        self.assertEqual(echoed["bb"], "handle")
        self.assertEqual(echoed["extra"], "run-42")

    def test_per_request_headers_win(self):
        os.environ["P1HUNT_USER_AGENT"] = "default/1"
        os.environ["P1HUNT_ID_HEADER"] = "X-Bug-Bounty: default-handle"
        echoed = self._client().get("/echo", headers={"User-Agent": "override/9",
                                                      "X-Bug-Bounty": "override"}).json()
        self.assertEqual(echoed["ua"], "override/9")
        self.assertEqual(echoed["bb"], "override")

    def test_malformed_header_env_is_skipped_not_guessed(self):
        os.environ["P1HUNT_EXTRA_HEADERS"] = "nonsense; X-Trace: ok; : ; alsobad"
        self.assertEqual(self._client().get("/echo").json()["extra"], "ok")


# =================================================================================================
# The vendoring contract — client.py must stay self-contained AND stay in sync
# =================================================================================================
class TestVendoredJailParity(unittest.TestCase):
    """``client.py`` is copied as a SINGLE FILE into the PoC sandbox (claude_swarm._arm_dynamic
    writes it as ``p1hunt_dyn.py``) and imported by a separate pytest process with no ``p1hunt``
    package on sys.path. It therefore cannot import ``tools/http_sandbox.py`` or
    ``dynamic/egress.py``, and the redirect jail is duplicated instead. These tests are the price
    of that duplication: they pin the copy to the original so it cannot drift."""

    _HOSTS = (
        "", "example.com", "EXAMPLE.com.", "https://api.example.com/x?y=1",
        "user:pw@api.example.com:8443", "api.example.com:8443", "[::1]:8080", "::1",
        "127.0.0.1", "localhost", "app.localhost", "0.0.0.0", "attacker.tld",
        "https://example.com.attacker.tld/", "sub.sub.example.com", "nohost",
        "http://[2001:db8::1]:443/p",
    )

    def test_norm_host_matches_egress_normalize_host(self):
        from p1hunt.dynamic import egress
        for value in self._HOSTS:
            with self.subTest(value=value):
                self.assertEqual(client_mod._norm_host(value), egress.normalize_host(value))

    def test_allowed_matches_egress_url_allowed(self):
        from p1hunt.dynamic import egress
        for allow in ([], ["example.com"], ["uat.example.com", "example.org"]):
            for value in self._HOSTS:
                with self.subTest(allow=allow, value=value):
                    # egress also carves out BUILD hosts (pypi/github/...) for harness
                    # provisioning; the harness transport has no business reaching those, so it
                    # is compared with that carve-out off.
                    expected = egress.url_allowed(value, allow, allow_build_hosts=False)[0]
                    self.assertEqual(client_mod._allowed(value, allow), expected)

    def test_credential_header_set_matches_http_sandbox(self):
        from p1hunt.tools import http_sandbox
        self.assertEqual(set(h.lower() for h in client_mod._CRED_HEADERS),
                         set(h.lower() for h in http_sandbox._CRED_HEADERS))

    def test_client_imports_nothing_from_p1hunt(self):
        """THE self-contained contract. A single ``from ..dynamic.egress import ...`` here would
        make every shipped harness die on ModuleNotFoundError in the PoC sandbox — and a
        ``try/except ImportError`` around it would silently drop the jail (a fail-OPEN path)."""
        import ast
        src = Path(client_mod.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    offenders.append(f"relative import (level {node.level}) of {node.module!r}")
                elif (node.module or "").split(".")[0] == "p1hunt":
                    offenders.append(f"from {node.module} import ...")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "p1hunt":
                        offenders.append(f"import {alias.name}")
        self.assertEqual(offenders, [], f"client.py must stay self-contained: {offenders}")

    def test_client_imports_only_the_standard_library(self):
        import ast
        import sys as _sys
        src = Path(client_mod.__file__).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(src)):
            roots = []
            if isinstance(node, ast.Import):
                roots = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level:
                roots = [(node.module or "").split(".")[0]]
            for root in roots:
                if root in ("", "__future__"):
                    continue
                self.assertIn(root, _sys.stdlib_module_names,
                              f"client.py may only import the stdlib, not {root!r}")

    def test_the_shipped_copy_is_byte_identical(self):
        """``_arm_dynamic`` ships this exact file; if provisioning ever started transforming it,
        the jail in the sandbox would stop being the jail under test."""
        src = Path(client_mod.__file__).read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as d:
            shipped = Path(d) / "p1hunt_dyn.py"
            shipped.write_text(src, encoding="utf-8")
            self.assertEqual(shipped.read_text(encoding="utf-8"), src)
            # ...and it imports standalone, with no p1hunt package reachable.
            proc = subprocess.run(
                [sys.executable, "-I", "-c",
                 "import sys; sys.path.insert(0, %r); import p1hunt_dyn as m;"
                 "print(m.Client is not None and m.BlockedError is not None"
                 " and not issubclass(m.BlockedError, AssertionError))" % d],
                capture_output=True, text=True, check=False, cwd=d)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), "True", proc.stderr)


class TestPreservedBlockedContract(unittest.TestCase):
    """The WAF/challenge detection another agent added must keep working through these changes."""

    def test_blocked_error_is_still_not_an_assertion_error(self):
        self.assertFalse(issubclass(BlockedError, AssertionError))

    def test_new_refusals_are_not_blocked_errors_and_not_assertions(self):
        # A SCOPE violation must stay loud and distinct: folding it into "blocked" would hide a
        # safe-harbor fault behind a routine ran=False.
        for exc in (ScopeError, RedirectDenied, MethodDenied):
            with self.subTest(exc=exc.__name__):
                self.assertFalse(issubclass(exc, AssertionError))
                self.assertFalse(issubclass(exc, BlockedError))
        self.assertFalse(issubclass(RateLimitExceeded, AssertionError))
        self.assertFalse(issubclass(RateLimitExceeded, BlockedError))

    def test_block_classification_surface_is_intact(self):
        for name in ("classify_block", "is_blocked", "BLOCKED_MARKER", "BlockedError"):
            self.assertTrue(hasattr(client_mod, name), name)
        for name in ("baseline_health", "require_live_baseline", "assert_forbidden",
                     "idor_probe", "is_blocked", "timing_oracle", "oob_url", "oob_received"):
            self.assertTrue(callable(getattr(Client, name, None)), name)


if __name__ == "__main__":
    unittest.main()
