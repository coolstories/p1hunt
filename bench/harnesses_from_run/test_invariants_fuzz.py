"""Stateful invariant-fuzzing harness for the /api/v1/accounts, /api/v1/invoices,
/api/v1/me/orders subsystem of the live authorized target (http://127.0.0.1:62395).

This is a property-based request loop (the web-API analogue of a Foundry invariant
campaign): it drives the REAL in-scope HTTP entrypoints through the shipped,
scope-enforced client (p1hunt_dyn.Client) with randomized identities and object ids
in random sequences, and asserts the subsystem's authorization invariants AFTER EVERY
call. A broken invariant is captured with its exact counterexample sequence.

Invariants under test (any break = critical):
  INV-OWN   : a 200 object read's "owner" MUST equal the caller's own principal.
  INV-AUTH  : an UNAUTHENTICATED caller MUST NOT receive a 200 invoice/account body.
  INV-ENUM  : numeric invoice ids MUST NOT be enumerable across tenants
              (a fixed caller must not read ids owned by other principals).
  INV-ORDERS: /api/v1/me/orders/{id} MUST stay scoped to the caller.

Run:
  python3 -m pytest .p1hunt-poc/test_invariants_fuzz.py -v -s
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p1hunt_dyn import Client  # noqa: E402

# Identity map: harness identity token -> the principal the server authenticates it as.
# (resolved live from /api/v1/me so the harness never hard-codes ownership).
IDENTITIES = ["a", "b", None]          # None == no Authorization header (unauthenticated)
ACCOUNT_UUIDS = [
    "550e8400-e29b-41d4-a716-446655440000",  # alice's (published publicly on home page)
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",  # bob's
]
INVOICE_IDS = list(range(1, 9))
ORDER_IDS = list(range(1, 5))


def whoami(client, identity):
    """Resolve the caller's true principal from the server (None -> 'anonymous')."""
    r = client.get("/api/v1/me", identity=identity)
    if r.status == 200:
        return r.json().get("user")
    return None  # unauthenticated


class Violation(AssertionError):
    pass


def check_object_read(kind, obj_id, identity, caller, resp, trace):
    """Assert the three read invariants on one object-read response."""
    is_2xx = 200 <= resp.status < 300
    body = resp.text[:300]
    step = f"{kind} id={obj_id!r} as identity={identity!r} (caller={caller!r}) -> {resp.status} {body}"
    trace.append(step)

    if not is_2xx:
        return  # a refusal (401/403/404) is the safe outcome for any of these

    data = resp.json() or {}
    owner = data.get("owner")

    # INV-AUTH: unauthenticated principals may not read any invoice/account body.
    if caller is None:
        raise Violation(
            "INV-AUTH BROKEN: unauthenticated caller received a 200 "
            f"{kind} body.\n  sequence:\n    " + "\n    ".join(trace))

    # INV-OWN / INV-ENUM: a served object's owner must be the caller.
    if owner is not None and owner != caller:
        raise Violation(
            f"INV-OWN/INV-ENUM BROKEN: caller {caller!r} read {kind} {obj_id!r} "
            f"owned by {owner!r}.\n  sequence:\n    " + "\n    ".join(trace))


def check_orders(obj_id, identity, caller, resp, trace):
    is_2xx = 200 <= resp.status < 300
    step = f"orders id={obj_id!r} as identity={identity!r} (caller={caller!r}) -> {resp.status} {resp.text[:200]}"
    trace.append(step)
    if not is_2xx:
        return
    data = resp.json() or {}
    owner = data.get("owner") or data.get("user")
    if caller is None:
        raise Violation("INV-ORDERS BROKEN: unauthenticated caller read an order.\n  "
                        + "\n    ".join(trace))
    if owner is not None and owner != caller:
        raise Violation(
            f"INV-ORDERS BROKEN: caller {caller!r} read order {obj_id!r} owned by {owner!r}.\n  "
            + "\n    ".join(trace))


def run_campaign(seed, steps):
    """One randomized stateful sequence. Returns None on all-pass, or the Violation."""
    rng = random.Random(seed)
    client = Client()
    # resolve true principal for each identity once
    caller_of = {i: whoami(client, i) for i in IDENTITIES}
    trace = [f"seed={seed} identity->principal map: {caller_of}"]
    for _ in range(steps):
        kind = rng.choice(["invoice", "account", "orders"])
        identity = rng.choice(IDENTITIES)
        caller = caller_of[identity]
        try:
            if kind == "invoice":
                oid = rng.choice(INVOICE_IDS)
                r = client.get(f"/api/v1/invoices/{oid}", identity=identity)
                check_object_read("invoice", oid, identity, caller, r, trace)
            elif kind == "account":
                oid = rng.choice(ACCOUNT_UUIDS)
                r = client.get(f"/api/v1/accounts/{oid}", identity=identity)
                check_object_read("account", oid, identity, caller, r, trace)
            else:
                oid = rng.choice(ORDER_IDS)
                r = client.get(f"/api/v1/me/orders/{oid}", identity=identity)
                check_orders(oid, identity, caller, r, trace)
        except Violation:
            raise
    return None


def test_stateful_invariant_campaign():
    """Deep stateful campaign: many randomized sequences, invariants checked every call.

    Expectation of a CORRECT system: all sequences pass. On this target the campaign
    MUST fail with a counterexample proving a cross-tenant / unauth object read.
    """
    first_violation = None
    seeds_run = 0
    # modest run count keeps the live target unstressed; the bugs are deterministic so
    # even a few short sequences surface them.
    for seed in range(40):
        seeds_run += 1
        try:
            run_campaign(seed, steps=12)
        except Violation as v:
            first_violation = (seed, v)
            break
    if first_violation is not None:
        seed, v = first_violation
        raise AssertionError(
            f"Invariant campaign FAILED after {seeds_run} seed(s). "
            f"Counterexample seed={seed}:\n{v}")
    # if we reach here the invariants held across the whole campaign
    print(f"All {seeds_run} seeds passed — invariants held.")


if __name__ == "__main__":
    # direct, framework-free run for quick reproduction
    try:
        test_stateful_invariant_campaign()
        print("CAMPAIGN PASSED (no violation found)")
    except AssertionError as e:
        print("CAMPAIGN FAILED (invariant broken):")
        print(e)
        sys.exit(1)
