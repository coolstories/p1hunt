"""Deterministic reproduction of the broken authorization invariants on the
/api/v1/accounts and /api/v1/invoices subsystem (live target 127.0.0.1:62395).

Each test asserts the SECURE (correct) behavior, so each assertion FAILS on the
vulnerable target — the failure IS the proof. me/orders is included as a control:
it is correctly scoped and PASSES, demonstrating the harness distinguishes a real
break from a safe endpoint.

ReproSpec:
  expect = fail      # a reproduced bug makes these invariant assertions FAIL
  run    = python3 -m pytest .p1hunt-poc/test_repro_bola.py -v

Run:
  python3 -m pytest .p1hunt-poc/test_repro_bola.py -v -s
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p1hunt_dyn import Client  # noqa: E402

ALICE_ACCT = "550e8400-e29b-41d4-a716-446655440000"


def client():
    return Client()


def test_invoice_requires_auth():
    """INV-AUTH: an unauthenticated caller must NOT read an invoice."""
    r = client().get("/api/v1/invoices/1")  # no Authorization header
    assert r.status in (401, 403), (
        f"unauthenticated read of /api/v1/invoices/1 returned {r.status}: {r.text[:200]}")


def test_invoice_owner_binding():
    """INV-OWN/INV-ENUM: alice must NOT read bob's invoice via a guessable integer id."""
    c = client()
    r = c.get("/api/v1/invoices/2", identity="a")  # invoice 2 is owned by bob
    if 200 <= r.status < 300:
        owner = (r.json() or {}).get("owner")
        assert owner == "alice", (
            f"alice read invoice 2 owned by {owner!r}: {r.text[:200]}")


def test_account_requires_auth():
    """INV-AUTH: an unauthenticated caller must NOT read an account."""
    r = client().get(f"/api/v1/accounts/{ALICE_ACCT}")  # no auth
    assert r.status in (401, 403), (
        f"unauthenticated read of account returned {r.status}: {r.text[:200]}")


def test_account_owner_binding():
    """INV-OWN: bob must NOT read alice's account by UUID."""
    c = client()
    r = c.get(f"/api/v1/accounts/{ALICE_ACCT}", identity="b")  # alice's account, bob calling
    if 200 <= r.status < 300:
        owner = (r.json() or {}).get("owner")
        assert owner == "bob", (
            f"bob read account {ALICE_ACCT} owned by {owner!r}: {r.text[:200]}")


def test_orders_scoped_control():
    """CONTROL: me/orders is correctly scoped — alice's cross-order read is refused.

    This assertion is expected to PASS, proving the subsystem *can* enforce
    ownership and the accounts/invoices breaks are genuine omissions, not harness error.
    """
    c = client()
    r = c.get("/api/v1/me/orders/1", identity="a")
    assert r.status == 403, f"expected 403 scoping on me/orders, got {r.status}: {r.text[:200]}"
