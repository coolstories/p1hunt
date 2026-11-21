"""Payment-authorization / CSRF lens — live target 127.0.0.1:62395.

Root cause under test: the authenticated session cookie `range_session` is issued
WITHOUT HttpOnly, SameSite, or Secure, and every cookie-authenticated endpoint
(including `/api/v1/session`, which returns live bearer access/session tokens)
accepts *ambient* cookie auth with NO CSRF token and NO Origin/Referer check.

Consequences (each asserted as the SECURE invariant, so a FAIL == the live bug):
  * COOKIE-FLAGS : Set-Cookie lacks HttpOnly + SameSite  -> cookie is readable by
                   same-origin JS (chains with the confirmed /preview DOM XSS) and
                   is auto-attached cross-site.
  * AMBIENT-AUTH : GET /api/v1/session authenticated ONLY by the cookie leaks
                   accessToken(rng_) + sessionToken(rngs_).
  * CSRF-WRITE   : POST /api/v1/pay is accepted with a cross-origin Origin/Referer
                   and cookie auth, with no CSRF token (no anti-forgery control).
  * LOGIN-CSRF   : GET /login?user=<x> sets the session cookie with no anti-CSRF,
                   enabling silent session fixation / login-CSRF.

Run:
  python3 -m pytest .p1hunt-poc/test_csrf_session_cookie.py -v -s
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p1hunt_dyn import Client  # noqa: E402


def client():
    return Client()


def _set_cookie():
    r = client().get("/login?user=alice")
    return r.headers.get("Set-Cookie", "")


def test_cookie_has_httponly_and_samesite():
    """COOKIE-FLAGS: an auth cookie must be HttpOnly and SameSite to resist theft/CSRF."""
    sc = _set_cookie().lower()
    print("Set-Cookie:", sc)
    assert "httponly" in sc, f"range_session set WITHOUT HttpOnly (JS-readable): {sc!r}"
    assert "samesite" in sc, f"range_session set WITHOUT SameSite (cross-site attachable): {sc!r}"


def test_ambient_cookie_auth_does_not_leak_tokens():
    """AMBIENT-AUTH: a bare cookie must not hand out bearer access/session tokens."""
    r = client().get("/api/v1/session", headers={"Cookie": "range_session=alice"})
    body = r.text
    print("session(cookie-only):", r.status, body[:120])
    leaked = ("rng_" in body) or ("rngs_" in body) or ("accessToken" in body)
    assert not leaked, "cookie-only ambient auth leaked access/session tokens via /api/v1/session"


def test_state_change_requires_csrf_token():
    """CSRF-WRITE: a state-changing POST carrying a cross-origin Origin must be rejected."""
    r = client().post(
        "/api/v1/pay",
        headers={
            "Cookie": "range_session=alice",
            "Origin": "http://127.0.0.1:9",
            "Referer": "http://127.0.0.1:9/attacker",
        },
        json={"to": "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "amount": 500},
    )
    print("pay(cross-origin,cookie):", r.status, r.text[:120])
    assert r.status in (401, 403), (
        f"state-changing POST accepted cross-origin with no CSRF token: {r.status} {r.text[:120]}")


def test_login_is_not_csrf_forgeable():
    """LOGIN-CSRF: setting the session via a bare GET enables silent login-CSRF/fixation."""
    r = client().get("/login?user=bob")
    sc = r.headers.get("Set-Cookie", "")
    print("login GET Set-Cookie:", sc)
    # A GET that mutates auth state with no token is CSRF-forgeable.
    assert "range_session" not in sc, (
        f"GET /login sets session cookie with no anti-CSRF control: {sc!r}")
