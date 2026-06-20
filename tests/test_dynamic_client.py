"""The interaction-engine client + OOB listener (spec §10, §12).

Exercises the harness-facing client against a LOOPBACK test server (no external network): scope
enforcement, identity/token resolution, the IDOR ``assert_forbidden`` helper, and the OOB
round-trip that turns a blind callback into a deterministic pass/fail.
"""

from __future__ import annotations

import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from p1hunt.dynamic.client import Client, ScopeError
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
        c = Client(base_url="https://api.example.com")
        with self.assertRaises(ScopeError):
            c.get("https://evil.com/steal")

    def test_token_resolution(self):
        os.environ["P1HUNT_TOKEN_A"] = "tokA"
        os.environ["P1HUNT_TOKEN_B"] = "tokB"
        os.environ["P1HUNT_TOKEN"] = "tokDefault"
        c = Client(base_url="https://api.example.com")
        self.assertEqual(c.token_for("A"), "tokA")
        self.assertEqual(c.token_for("B"), "tokB")
        self.assertEqual(c.token_for(None), "tokDefault")
        self.assertEqual(c.token_for("default"), "tokDefault")
        self.assertIn("a", c.identities())
        self.assertIn("b", c.identities())

    def test_egress_allowlist_includes_base_host(self):
        c = Client(base_url="https://uat.example.com")
        self.assertIn("uat.example.com", c.egress_allowlist)


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
            c = Client(base_url="https://api.example.com")
            url, token = c.oob_url()
            self.assertIn(token, url)
            # Simulate the TARGET dereferencing the OOB URL (blind SSRF callback).
            urllib.request.urlopen(url, timeout=3).read()
            self.assertTrue(c.oob_received(token, wait=2))
            self.assertFalse(c.oob_received("never_fired_token", wait=0.2))
        finally:
            listener.stop()


if __name__ == "__main__":
    unittest.main()
