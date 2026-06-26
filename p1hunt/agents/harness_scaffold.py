"""Harness scaffolding for the fuzzer (spec gap: reach PAST authentication/approval gates).

A blind fuzzer that throws random calldata at a hardened contract reverts at the very first
signature/permit/role check and covers nothing — the value-moving logic where the real critical
lives is never executed. This module closes that gap WITHOUT presetting a target shape: it derives
the in-scope external entrypoints from the actual Solidity and emits a concrete, copy-startable
Foundry test SKELETON of generic EVM MECHANICS — deploy the real contracts + adversarial mock
tokens (reentrancy callback, fee-on-transfer/rebasing), and, for any entrypoint that authenticates
a signed struct, build a VALID instance and sign it with `vm.sign` over the CONTRACT'S OWN
domain separator + typehash — then drive the real entrypoints with that valid input. The model
derives the actual struct/field shapes and invariants from the target's ABI/AST; nothing about an
order/marketplace/AMM/etc. is assumed.

Everything here is PURE (filesystem reads only) — no Claude, no network, no toolchain. The
skeleton is generic class-level methodology the model adapts to the specific target; it names no
specific protocol or target shape.
"""

from __future__ import annotations

import re
from pathlib import Path

from p1hunt.classify.subclass import detect_crypto_subclass, detect_web_subclass

_IGNORE_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "vendor", "target", ".venv",
    ".p1hunt-poc", "out", "cache", "artifacts", "lib", "broadcast",
}

# An external/public Solidity function declaration. We capture the name and the (possibly
# multi-line) parameter region; visibility may follow modifiers/returns so we look ahead.
_SOL_FUNC = re.compile(
    r"function\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{]*?)\)"
    r"(?P<tail>[^;{]*?)(?:\{|;)",
    re.DOTALL,
)


def _sol_files(repo_path: str, focus_files: list[str] | None = None) -> list[Path]:
    """In-scope .sol files. Honors focus_files (a curated subset) when provided, else scans."""
    root = Path(repo_path)
    if focus_files:
        out: list[Path] = []
        for f in focus_files:
            p = (root / f) if not Path(f).is_absolute() else Path(f)
            if p.suffix.lower() == ".sol" and p.is_file():
                out.append(p)
        if out:
            return out
    if not root.exists():
        return []
    files: list[Path] = []
    for path in sorted(root.rglob("*.sol")):
        if not path.is_file():
            continue
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            rel_parts = path.parts
        if any(part in _IGNORE_DIRS for part in rel_parts):
            continue
        files.append(path)
    return files


def detect_evm_entrypoints(
    repo_path: str, focus_files: list[str] | None = None, *, limit: int = 40
) -> list[str]:
    """Grep external/public Solidity function signatures in the in-scope .sol files.

    Returns a de-duplicated list of compact signatures like ``fulfillOrder(Order,bytes32)`` —
    the attack surface a harness must drive. Pure (reads files only); never raises."""
    sigs: list[str] = []
    seen: set[str] = set()
    for path in _sol_files(repo_path, focus_files):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in _SOL_FUNC.finditer(text):
            tail = m.group("tail") or ""
            visibility = tail.lower()
            if "external" not in visibility and "public" not in visibility:
                continue
            name = m.group("name")
            params = " ".join((m.group("params") or "").split())
            # Reduce each parameter to its leading type token for a compact, stable signature.
            types: list[str] = []
            for part in (p.strip() for p in params.split(",")):
                if not part:
                    continue
                types.append(part.split()[0])
            sig = f"{name}({','.join(types)})"
            if sig in seen:
                continue
            seen.add(sig)
            sigs.append(sig)
            if len(sigs) >= limit:
                return sigs
    return sigs


def _evm_skeleton(
    subsystem: str,
    focus_files: list[str],
    signals: list[str] | None,
    fork_url: str,
    entrypoints: list[str] | None,
) -> str:
    files = "\n  - ".join(focus_files[:8]) if focus_files else "(find the in-scope contracts)"
    eps = ", ".join((entrypoints or [])[:12]) or "(enumerate the external/public entrypoints)"
    sig_note = (
        "\nObserved EVM signals to weaponize into invariants/assertions:\n  - "
        + "\n  - ".join(signals[:8])
        if signals else ""
    )
    fork_note = (
        f"\nRun against a real fork (state of live tokens/proxies):\n"
        f"    forge test --fork-url {fork_url} --match-path ./.p1hunt-poc/Harness.t.sol -vvv\n"
        if fork_url else
        "\nRun locally:\n    forge test --match-path ./.p1hunt-poc/Harness.t.sol -vvv\n"
    )
    return f"""SCAFFOLD — Foundry harness for the EVM '{subsystem}' subsystem (target class: EVM_CONTRACT).
NOTHING PRESET: this is generic EVM test MECHANICS. Derive the actual shape of every input from
the TARGET'S OWN ABI/AST — do not assume any protocol shape, vocabulary, or struct layout.

In-scope contracts:
  - {files}
External/public entrypoints to drive: {eps}{sig_note}

REACH PAST THE GATES (the reason a blind fuzzer covers nothing): for EACH external entrypoint,
read its parameter types from the ABI/AST (forge inspect <C> abi, or solc --ast-compact-json).
Then satisfy whatever gate that entrypoint imposes, derived from the code — NOT assumed:
  - If a parameter is a STRUCT the contract verifies a signature over (the contract exposes a
    DOMAIN_SEPARATOR / a typehash / builds a `\\x19\\x01` digest), construct a VALID instance of
    THAT struct and sign it with vm.sign over the contract's OWN domain separator + typehash, then
    fuzz the struct's numeric/array fields (named from the REAL layout) — never the signature.
  - If it's gated by a permit / nonce / role / allowance, satisfy that gate first.
  - Otherwise drive the entrypoint with fuzzed args directly.
This is what lets the fuzzer reach the value-moving logic where critical bugs live, for ANY
contract shape — not just one protocol family.

SETUP CHECKLIST (in setUp() — a harness that doesn't exercise the real state-change proves nothing):
  1. Deploy the IN-SCOPE contract(s) and any dependencies they need (router/registry/etc.).
  2. If the contract MOVES TOKENS, deploy mock ERC20/ERC721/ERC1155 for each standard it touches,
     PLUS adversarial-semantics mocks that surface the highest-yield accounting bugs WITHOUT a fork:
       - a TRANSFER-CALLBACK token (ERC777 `tokensReceived` / ERC1155 `onERC1155Received`) whose
         hook RE-ENTERS the entrypoint (exercises reentrancy past a naive guard);
       - a FEE-ON-TRANSFER / deflationary mock whose transfer delivers LESS than requested, and a
         rebasing mock whose balances drift ("declared amount != received amount" bugs).
     (Skip the token mocks for a pure-logic contract that moves no tokens.)
  3. Mint balances to the actors and SET APPROVALS on whatever spender the code actually pulls
     from (the contract or a router it routes through — wrong approvals make every call revert on
     transferFrom, not on the bug).
  4. Use deterministic actors from known private keys so signatures verify:
        uint256 senderPk = 0xA11CE; address sender = vm.addr(senderPk);

COPY-STARTABLE SKELETON (substitute the REAL contract/struct/entrypoint names you derived — it is
guidance, not required to compile as-is):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
// import the IN-SCOPE contract(s) and the struct types its entrypoints take here.

contract Harness is Test {{
    uint256 internal senderPk = 0xA11CE;
    address internal sender;

    Target internal target;            // the in-scope contract (use its REAL name)
    MockERC20 internal erc20;          // include token mocks only if the contract moves tokens
    MockFeeOnTransferERC20 internal feeToken;   // delivers < amount on transfer (deflationary)
    MockCallbackToken internal hookToken;        // transfer hook re-enters `target`

    function setUp() public {{
        sender = vm.addr(senderPk);
        target = new Target(/* constructor args */);
        erc20 = new MockERC20();
        feeToken = new MockFeeOnTransferERC20();
        hookToken = new MockCallbackToken(address(target));
        _mintAndApprove(sender);
    }}

    function _mintAndApprove(address who) internal {{
        erc20.mint(who, type(uint128).max);
        vm.prank(who);
        erc20.approve(address(target) /* or the real spender */, type(uint256).max);
    }}

    // Sign a struct the contract authenticates, using ITS OWN domain separator + typehash so the
    // signature verifies. Mirror the contract's real typehash for the struct you derived.
    function _sign(uint256 pk, bytes32 structHash) internal view returns (bytes memory) {{
        bytes32 domainSep = target.DOMAIN_SEPARATOR();  // or rebuild EIP712Domain locally
        bytes32 digest = keccak256(abi.encodePacked("\\x19\\x01", domainSep, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }}

    // Fuzz the VALUE/SHAPE of the real input past a VALID gate, then assert a DERIVED invariant.
    function testFuzz_invariantHolds(uint128 amount) public {{
        vm.assume(amount > 0);
        // 1. build a valid input for the chosen entrypoint (sign it if the code requires).
        // 2. snapshot the balances/state the invariant is about.
        uint256 inBefore = erc20.balanceOf(address(target));
        // 3. call the REAL entrypoint with the valid, fuzzed input.
        //    vm.prank(sender); target.<realEntrypoint>(<built input>);
        // 4. assert a CONSERVATION invariant derived from the code: value out == value in minus
        //    declared fees; the contract never pays out more of an asset than it holds; supply is
        //    conserved. A divergence here is a critical.
        assertGe(erc20.balanceOf(address(target)), inBefore - amount);
    }}

    // Fee-on-transfer accounting (no fork needed): route a transfer through `feeToken` and assert
    // the contract books the amount ACTUALLY RECEIVED, never the declared amount.
    function testFuzz_feeOnTransferConservation(uint128 amount) public {{
        vm.assume(amount > 1e6);
        // ... drive the entrypoint with feeToken, assert no party books value that never arrived ...
    }}
}}
```

INVARIANTS TO ASSERT — DERIVE THESE FROM THIS CONTRACT (do NOT assume a protocol's invariants):
read each state-changing function's require/assert/accounting and `// invariant:`/NatSpec comments
and turn them into checks worded against the REAL functions. The one class-level invariant that
always applies to a value-moving contract is ASSET CONSERVATION (value out == value in minus
declared fees; the contract never releases more of an asset than it holds). Everything else —
single-spend of one-time actions, monotonic nonces, access-control rules, fill/amount bounds —
must be derived from the code's OWN guards and accounting, not presumed.{fork_note}
ITERATE: make it COMPILE and actually fuzz first; fix harness bugs (wrong approvals / wrong domain
separator make EVERYTHING revert and prove nothing). A failing assertion WITH the forge
counterexample IS your PoC."""


def _generic_skeleton(target_class: str, subsystem: str, focus_files: list[str], fork_url: str) -> str:
    files = "\n  - ".join(focus_files[:8]) if focus_files else "(find the relevant in-scope files)"
    run_hint = (
        f"\nIf a fork/endpoint is relevant, point the harness at: {fork_url}" if fork_url else ""
    )
    return f"""SCAFFOLD — build a REAL harness for the '{subsystem}' subsystem (target class: {target_class}).

Do NOT reimplement a toy version. Build a harness in the TARGET'S OWN framework against the
ACTUAL in-scope code and RUN it:
  - Go        -> `go test -fuzz=Fuzz...` with a property the system must uphold
  - Rust      -> `cargo fuzz` / `proptest` over the real API
  - Python    -> Hypothesis / pytest property tests
  - web API   -> an authenticated property-based request loop (UAT/owned env only)
  - native/C  -> a libFuzzer/AFL harness or a unit fuzz test

In-scope files to target:
  - {files}

METHOD: (1) deploy/instantiate the REAL components and any dependencies/mocks they need; (2) if
an entrypoint is gated by auth/signatures/tokens, construct a VALID credential first so the
fuzzer reaches the interesting logic instead of bouncing off the gate; (3) assert the
system's invariants after every operation; (4) RUN it until an invariant breaks (a finding,
with the counterexample as proof) or you have covered a wide input space.{run_hint}

A failing property WITH a reproducing input IS your PoC."""


# ===========================================================================
# Non-EVM class/subclass scaffold generators.
#
# Each generator returns a CONCRETE, copy-startable harness template in the
# right framework for the TARGET CLASS, the invariants to assert, the run
# command + materialized file path, AND the EXPECTED-OUTCOME wording that
# pairs with ReproSpec.expect (it states explicitly whether a reproduced bug
# makes the test FAIL or PASS). Everything is generic to the CLASS — no
# per-target/product literals, no hardcoded endpoints. The harness reads
# target/credentials from the ENVIRONMENT at runtime so nothing is preset.
# ===========================================================================

# The materialized harness file the runner derives its argv from (kept in sync
# with the runners, which look under ./.p1hunt-poc/).
_POC_DIR = "./.p1hunt-poc"


def _files_block(focus_files: list[str]) -> str:
    return "\n  - ".join(focus_files[:8]) if focus_files else "(find the relevant in-scope files)"


def _web_authz_skeleton(subsystem: str, focus_files: list[str], target_url: str) -> str:
    """Two-principal resource-boundary harness — pytest + requests, expect='pass' (bug = an
    unexpected cross-principal permit, so the assertion that it FAILS does not hold)."""
    files = _files_block(focus_files)
    base = target_url or "(read from P1HUNT_BASE_URL)"
    poc = f"{_POC_DIR}/test_authz.py"
    return f"""SCAFFOLD — pytest+requests cross-principal resource-boundary harness for the
'{subsystem}' subsystem (target class: WEB_API, subclass: access-boundary).

In-scope files to derive object/route shapes from:
  - {files}

GOAL: authenticate as two SEPARATE principals (user A and user B / two tenants), have A create or
own an object, then drive every in-scope route as B against A's object id / cross-tenant resource
and assert B is REFUSED. NOTHING PRESET: base URL + both credential sets come from the environment
so no target literal is baked in.

MATERIALIZE THIS at {poc} and RUN:
    P1HUNT_BASE_URL=... pytest {poc} -v

EXPECTED OUTCOME (ReproSpec.expect="pass"): the bug is DEMONSTRATED when an assertion that the
unauthorized access is BLOCKED FAILS — i.e. B successfully read/wrote A's object (status 2xx where
a 403/404 was required). A reproduced finding makes the targeted test FAIL with that assertion;
a clean target keeps the test PASSING (every cross-principal request refused).

```python
import os
import pytest
import requests

BASE = os.environ["P1HUNT_BASE_URL"].rstrip("/")
# Two independent principals / tenants — supplied via env, never hardcoded.
TOKEN_A = os.environ["P1HUNT_TOKEN_A"]
TOKEN_B = os.environ["P1HUNT_TOKEN_B"]


def _h(token):
    return {{"Authorization": f"Bearer {{token}}"}}


@pytest.fixture
def owned_object_id():
    # A creates/owns a resource on an in-scope collection route (adapt path + payload to the ABI).
    r = requests.post(f"{{BASE}}/<in-scope-collection>", headers=_h(TOKEN_A),
                      json={{"name": "p1hunt"}}, timeout=15)
    r.raise_for_status()
    return r.json()["id"]


def test_b_cannot_read_a_object(owned_object_id):
    # B requests A's object by id. MUST be refused.
    r = requests.get(f"{{BASE}}/<in-scope-collection>/{{owned_object_id}}",
                     headers=_h(TOKEN_B), timeout=15)
    assert r.status_code in (401, 403, 404), (
        f"UNEXPECTED PERMIT: B read A's object (status {{r.status_code}})")


def test_b_cannot_write_a_object(owned_object_id):
    r = requests.patch(f"{{BASE}}/<in-scope-collection>/{{owned_object_id}}",
                       headers=_h(TOKEN_B), json={{"name": "hijacked"}}, timeout=15)
    assert r.status_code in (401, 403, 404), (
        f"UNEXPECTED PERMIT: B wrote A's object (status {{r.status_code}})")


def test_tenant_isolation_on_list(owned_object_id):
    # A's object id must never appear in B's collection listing (cross-tenant leak).
    r = requests.get(f"{{BASE}}/<in-scope-collection>", headers=_h(TOKEN_B), timeout=15)
    ids = {{str(o.get("id")) for o in r.json().get("items", r.json() if isinstance(r.json(), list) else [])}}
    assert str(owned_object_id) not in ids, "TENANT LEAK: A's object visible to B"
```

INVARIANTS TO ASSERT (break ANY = critical): a principal can never read or mutate another
principal's object by id; listings never cross the tenant boundary; an unauthenticated
or wrong-role request to a protected route is refused; ownership is enforced server-side, not by a
client-supplied tenant/user field.

ITERATE: enumerate EVERY in-scope route (from the files above) as B against A's ids; sequential /
guessable ids and UUIDs both count. A single 2xx where a refusal was required IS your PoC."""


def _web_payment_skeleton(subsystem: str, focus_files: list[str], target_url: str) -> str:
    """Web payment / accounting / idempotency — pytest, expect='pass' (bug = conservation broken:
    a double-credit / value created, so the assertion that balances are conserved does not hold)."""
    files = _files_block(focus_files)
    poc = f"{_POC_DIR}/test_payments.py"
    return f"""SCAFFOLD — pytest payment/accounting/idempotency harness for the '{subsystem}'
subsystem (target class: WEB_API, subclass: payments/accounting).

In-scope files to derive charge/refund/transfer routes from:
  - {files}

GOAL: replay a charge/refund with a REUSED idempotency key, a TAMPERED amount/currency, and
negative/zero amounts; assert CONSERVATION — no double-credit, no value created from nothing, no
negative-amount refund inflating a balance. Base URL + credentials come from the environment.

MATERIALIZE THIS at {poc} and RUN:
    P1HUNT_BASE_URL=... pytest {poc} -v

EXPECTED OUTCOME (ReproSpec.expect="pass"): the bug is DEMONSTRATED when a conservation assertion
FAILS — the same idempotency key charged twice, a tampered amount was honored, or a negative/zero
amount moved value. A reproduced finding makes the targeted test FAIL; a sound ledger keeps every
test PASSING.

```python
import os, uuid
import pytest
import requests

BASE = os.environ["P1HUNT_BASE_URL"].rstrip("/")
TOKEN = os.environ["P1HUNT_TOKEN"]
H = {{"Authorization": f"Bearer {{TOKEN}}"}}


def _balance():
    r = requests.get(f"{{BASE}}/<in-scope-balance-route>", headers=H, timeout=15)
    r.raise_for_status()
    return int(r.json()["balance_minor"])  # integer minor units; adapt field


def _charge(amount, currency="USD", idem=None, **extra):
    headers = dict(H)
    if idem:
        headers["Idempotency-Key"] = idem
    return requests.post(f"{{BASE}}/<in-scope-charge-route>", headers=headers,
                         json={{"amount_minor": amount, "currency": currency, **extra}}, timeout=15)


def test_idempotency_key_not_replayable():
    idem = str(uuid.uuid4())
    before = _balance()
    r1 = _charge(1000, idem=idem)
    r2 = _charge(1000, idem=idem)  # same key — MUST NOT charge twice
    moved = _balance() - before
    assert moved == (r1.json().get("amount_minor", 1000)), (
        f"DOUBLE CHARGE: idempotency key replayed, balance moved {{moved}}")


def test_amount_tampering_rejected():
    # Server must price authoritatively; a client-supplied amount must not override it.
    r = _charge(1, currency="USD", server_priced_item="<in-scope-item>")
    assert r.status_code >= 400 or r.json().get("amount_minor") != 1, (
        "AMOUNT TAMPER: client-supplied amount honored over server price")


@pytest.mark.parametrize("amount", [0, -100, -1])
def test_no_value_created_from_nonpositive(amount):
    before = _balance()
    _charge(amount)
    assert _balance() >= before, f"VALUE CREATED: non-positive amount {{amount}} increased balance"


def test_refund_conserves_value():
    before = _balance()
    c = _charge(500, idem=str(uuid.uuid4()))
    cid = c.json()["id"]
    requests.post(f"{{BASE}}/<in-scope-refund-route>", headers=H,
                  json={{"charge_id": cid, "amount_minor": 500}}, timeout=15)
    # net effect of charge+full refund is zero — never a net credit.
    assert _balance() <= before, "VALUE CREATED: charge+refund left a net credit"
```

INVARIANTS TO ASSERT (break ANY = critical): a reused idempotency key charges exactly once; the
server prices authoritatively (client amount/currency cannot inflate or deflate value); refunds
never exceed the captured amount; non-positive amounts never increase any balance; sum of ledger
entries is conserved across replays (no value created or destroyed).

ITERATE: race two identical-idem requests concurrently; replay refunds; mix currencies. Any net
value created or any second charge under one key IS your PoC."""


def _graphql_skeleton(subsystem: str, focus_files: list[str], target_url: str) -> str:
    """GraphQL resolver auth — pytest, expect='pass' (bug = field-level authz bypassed: a
    protected field/mutation returned data to an unauthorized role)."""
    files = _files_block(focus_files)
    poc = f"{_POC_DIR}/test_graphql_authz.py"
    return f"""SCAFFOLD — pytest GraphQL resolver-authorization harness for the '{subsystem}'
subsystem (target class: WEB_API, subclass: graphql).

In-scope schema/resolver files to derive types/fields from:
  - {files}

GOAL: issue queries/mutations as an UNAUTHORIZED role and assert field-level authz is NOT bypassed,
including via introspection, field aliasing, and batched/array operations (amplification). Endpoint
+ tokens come from the environment.

MATERIALIZE THIS at {poc} and RUN:
    P1HUNT_GQL_URL=... pytest {poc} -v

EXPECTED OUTCOME (ReproSpec.expect="pass"): the bug is DEMONSTRATED when an assertion that the
unauthorized role is DENIED FAILS — a protected field/mutation returned data (no top-level
`errors`, non-null `data`) to a role that should be refused, or an alias/batch slipped past a guard.
A reproduced finding makes the targeted test FAIL; a correctly-guarded schema keeps tests PASSING.

```python
import os
import pytest
import requests

URL = os.environ["P1HUNT_GQL_URL"]
LOW_ROLE_TOKEN = os.environ["P1HUNT_TOKEN_LOW"]   # an under-privileged principal
H = {{"Authorization": f"Bearer {{LOW_ROLE_TOKEN}}"}}


def _gql(query, variables=None):
    return requests.post(URL, headers=H, json={{"query": query, "variables": variables or {{}}}},
                         timeout=15).json()


def _denied(resp):
    # Authz denial = error and/or null data on the protected field.
    return bool(resp.get("errors")) or resp.get("data") in (None, {{}})


def test_protected_field_denied_to_low_role():
    resp = _gql("query {{ <in-scope-protected-field> {{ id }} }}")
    assert _denied(resp), f"UNEXPECTED FIELD PERMIT: low role read protected field: {{resp}}"


def test_protected_mutation_denied_to_low_role():
    resp = _gql("mutation {{ <in-scope-privileged-mutation>(input: {{}}) {{ ok }} }}")
    assert _denied(resp), f"UNEXPECTED MUTATION PERMIT: low role ran privileged mutation: {{resp}}"


def test_alias_does_not_bypass_authz():
    # Aliasing must not change the authz decision for the same protected field.
    resp = _gql("query {{ a: <in-scope-protected-field> {{ id }} b: <in-scope-protected-field> {{ id }} }}")
    assert _denied(resp), f"UNEXPECTED ALIAS PERMIT: {{resp}}"


def test_batch_amplification_each_still_authorized():
    # A batched/array request must apply authz to EVERY operation, not just the first.
    batch = [{{"query": "query {{ <in-scope-protected-field> {{ id }} }}"}} for _ in range(5)]
    resps = requests.post(URL, headers=H, json=batch, timeout=15).json()
    assert all(_denied(r) for r in resps), f"BATCH AMPLIFICATION BYPASS: {{resps}}"


def test_introspection_not_leaking_protected_shape():
    # If introspection is meant to be disabled for this role, it must be refused.
    resp = _gql("query {{ __schema {{ types {{ name }} }} }}")
    # Treat a full type list returned to a low role as a finding only if the schema gates it.
    assert _denied(resp) or "__schema" not in str(resp), "INTROSPECTION LEAK to low role"
```

INVARIANTS TO ASSERT (break ANY = critical): a protected field/mutation is refused to an
unauthorized role; aliasing a field never changes its authz decision; every operation in a
batched/array request is authorized independently (no amplification past the first); introspection
respects role gating; resolver-level authz is enforced, not just top-level operation auth.

ITERATE: enumerate every protected type/field/mutation from the schema files above; try aliases,
fragments, and large batches. Any non-null data to the low role IS your PoC."""


def _crypto_skeleton(subsystem: str, subclass: str, focus_files: list[str]) -> str:
    """Crypto signature / domain-separation / nonce-misuse — pytest property/differential test,
    expect='fail' (bug = an invariant such as non-malleability / domain separation / nonce
    uniqueness is BROKEN, so the property assertion FAILS)."""
    files = _files_block(focus_files)
    poc = f"{_POC_DIR}/test_crypto_props.py"
    return f"""SCAFFOLD — pytest property/differential harness for the '{subsystem}' crypto
subsystem (target class: CRYPTO_LIB, subclass: {subclass}).

In-scope crypto source to bind against (call the REAL API, do not reimplement it):
  - {files}

GOAL: assert the class invariants over RANDOMIZED inputs — signature non-malleability (low-s; a
flipped-s variant must not verify), domain separation (a signature/MAC valid in one context must
not verify in another), and nonce/IV uniqueness (no reuse across operations). Prefer the lib's
native test runner if it has one; otherwise drive the real API from Python. If a reference
implementation exists, add a DIFFERENTIAL test where divergence => bug.

MATERIALIZE THIS at {poc} and RUN:
    pytest {poc} -v

EXPECTED OUTCOME (ReproSpec.expect="fail"): the bug is DEMONSTRATED when a property assertion
FAILS / a counterexample is found — e.g. a malleated (high-s) signature still verifies, a
cross-context signature verifies, or a nonce/IV repeats. A reproduced finding makes the targeted
property test FAIL; a sound implementation keeps every property PASSING.

```python
import os
import pytest

# Bind to the REAL in-scope library API (import the module under test; adapt names to the ABI).
# from target_lib import sign, verify, derive_nonce, SECP_N

SECP_N = int(os.environ.get("P1HUNT_CURVE_ORDER", "0"))  # set for the curve under test


def _low_s(s):
    return s <= SECP_N // 2


def test_signature_non_malleability():
    msg, sk = b"p1hunt", b"\\x01" * 32
    sig = sign(msg, sk)                       # (r, s) or DER — adapt
    r, s = sig
    assert _low_s(s), "MALLEABILITY: signer emitted a high-s signature"
    malleated = (r, SECP_N - s)               # the other valid s
    assert not verify(msg, malleated, sk), "MALLEABILITY: high-s variant still verifies"


def test_domain_separation_across_contexts():
    msg, sk = b"p1hunt", b"\\x02" * 32
    sig_ctx_a = sign(msg, sk, context=b"A")
    # A signature bound to context A must NOT verify under context B.
    assert not verify(msg, sig_ctx_a, sk, context=b"B"), (
        "DOMAIN SEPARATION: signature valid across distinct contexts")


def test_nonce_uniqueness():
    msg, sk = b"p1hunt", b"\\x03" * 32
    nonces = {{derive_nonce(msg + bytes([i]), sk) for i in range(256)}}
    assert len(nonces) == 256, "NONCE REUSE: derive_nonce collided across distinct inputs"


@pytest.mark.skipif(SECP_N == 0, reason="set P1HUNT_CURVE_ORDER for differential test")
def test_differential_against_reference():
    # If a trusted reference impl is available, sign/verify the SAME inputs through both and
    # assert byte-identical acceptance decisions. Any divergence is a bug.
    msg, sk = b"p1hunt", b"\\x04" * 32
    assert verify(msg, sign(msg, sk), sk) == reference_verify(msg, reference_sign(msg, sk), sk)
```

INVARIANTS TO ASSERT (break ANY = critical): signatures are non-malleable (low-s enforced; the
complementary s must not verify); a signature/MAC is bound to its domain/context and never verifies
in another; nonces/IVs are unique per operation (no reuse, no predictable derivation); a reference
and the implementation agree on every accept/reject decision (differential).

ITERATE: feed many random keys/messages/contexts; if the lib has its own test framework, run that
too. A single malleated signature that verifies, a cross-context acceptance, or a nonce collision
IS your PoC."""


def _supply_chain_skeleton(subsystem: str, focus_files: list[str]) -> str:
    """Supply-chain install/build compromise — semgrep ruleset over install/build scripts,
    expect='fail' (a rule MATCH = a malicious pattern present = the bug is reproduced)."""
    files = _files_block(focus_files)
    poc = f"{_POC_DIR}/supply_chain.semgrep.yml"
    return f"""SCAFFOLD — semgrep ruleset over install/build scripts for the '{subsystem}'
subsystem (target class: SUPPLY_CHAIN).

In-scope install/build manifests + scripts to scan:
  - {files}

GOAL: detect a malicious or unsafe install/build step — a postinstall/preinstall hook that fetches
and executes remote code, dependency-confusion (an internal package resolvable from a public
registry), a likely typosquat, or an UNVERIFIED downloaded artifact (no checksum/signature). The
rules are CLASS-level patterns, not a per-package allowlist.

MATERIALIZE THIS at {poc} and RUN:
    semgrep --config {poc} --error --json <in-scope-paths>

EXPECTED OUTCOME (ReproSpec.expect="fail"): a finding is reproduced when semgrep REPORTS A MATCH
(a rule fired => a malicious/unsafe pattern is present). No matches = clean. (The runner parses the
match list; a non-empty results array is the reproduction.)

```yaml
rules:
  - id: install-hook-fetches-and-executes-remote-code
    languages: [bash, generic]
    severity: ERROR
    message: install/build hook downloads and executes remote code (supply-chain RCE)
    patterns:
      - pattern-either:
          - pattern-regex: (curl|wget)\\s+[^|]*\\|\\s*(sh|bash|python|node)
          - pattern-regex: (curl|wget)[^\\n]*-o\\s+\\S+[\\s\\S]*?(chmod\\s+\\+x|\\./)
          - pattern-regex: (eval|exec)\\s*\\(\\s*(require\\(|fetch\\(|https?\\.get)

  - id: npm-lifecycle-hook-runs-network-or-shell
    languages: [json, generic]
    severity: WARNING
    message: package lifecycle hook (preinstall/postinstall) runs network/shell — review for malware
    pattern-regex: "\\"(pre|post)?install\\"\\s*:\\s*\\"[^\\"]*(curl|wget|node\\s+-e|eval|base64\\s+-d)[^\\"]*\\""

  - id: dependency-confusion-public-fetch-of-internal-scope
    languages: [generic]
    severity: ERROR
    message: internal-scoped dependency resolvable from a public registry (dependency confusion)
    pattern-regex: registry\\.npmjs\\.org[\\s\\S]*@<internal-scope>/

  - id: unverified-downloaded-artifact
    languages: [generic]
    severity: WARNING
    message: artifact downloaded without checksum/signature verification
    patterns:
      - pattern-regex: (curl|wget|ADD\\s+https?://)\\S+
      - pattern-not-regex: (sha256sum|sha512|gpg\\s+--verify|cosign\\s+verify|--checksum)
```

INVARIANTS TO ASSERT (a MATCH on ANY = critical): no install/build hook fetches+executes remote
code; lifecycle hooks do not run opaque network/shell payloads; internal-scoped packages are not
resolvable from public registries (dependency confusion); every downloaded build artifact is
checksum-/signature-verified; dependency names are not near-miss typosquats of popular packages.

ITERATE: widen the rules to every install/build entrypoint (package.json scripts, Makefiles,
Dockerfiles, CI yml, setup.py). A single rule match IS your PoC."""


def _infra_skeleton(subsystem: str, focus_files: list[str]) -> str:
    """Cloud/IaC privilege-escalation + public exposure — OPA/conftest (rego) policy over the IaC,
    expect='fail' (a policy DENY/violation = the bug is reproduced)."""
    files = _files_block(focus_files)
    poc = f"{_POC_DIR}/iac_policy.rego"
    return f"""SCAFFOLD — OPA/conftest (rego) policy over the IaC for the '{subsystem}' subsystem
(target class: INFRA / IaC).

In-scope IaC to scan (Terraform plan JSON / CloudFormation / k8s manifests):
  - {files}

GOAL: assert no privilege-escalation and no public exposure — no wildcard IAM action/resource, no
public data-store or control-plane, no secret embedded in IaC. CLASS-level policy, not a per-account
allowlist.

MATERIALIZE THIS at {poc} and RUN:
    conftest test --policy {poc} <in-scope-iac-files>
  (or:  opa eval -d {poc} -i <iac>.json "data.p1hunt.deny")

EXPECTED OUTCOME (ReproSpec.expect="fail"): a finding is reproduced when the policy DENIES — i.e.
conftest reports failures / `deny` is non-empty (a wildcard IAM grant, a public data-store/
control-plane, or a secret in IaC was found). No denials = clean. (The runner parses the
failure/deny count; a non-empty set is the reproduction.)

```rego
package p1hunt

# Wildcard IAM: an action or resource of "*" is privilege escalation.
deny[msg] {{
    some r
    stmt := input.resource[r].policy.Statement[_]
    stmt.Effect == "Allow"
    stmt.Action[_] == "*"
    msg := sprintf("WILDCARD IAM: resource %v grants Action '*'", [r])
}}

deny[msg] {{
    some r
    stmt := input.resource[r].policy.Statement[_]
    stmt.Effect == "Allow"
    stmt.Resource[_] == "*"
    msg := sprintf("WILDCARD IAM: resource %v grants Resource '*'", [r])
}}

# Public data-store / control-plane exposure.
deny[msg] {{
    some r
    res := input.resource[r]
    res.acl == "public-read"
    msg := sprintf("PUBLIC DATA STORE: %v is publicly readable", [r])
}}

deny[msg] {{
    some r
    cidr := input.resource[r].ingress[_].cidr_blocks[_]
    cidr == "0.0.0.0/0"
    msg := sprintf("PUBLIC CONTROL PLANE: %v open to 0.0.0.0/0", [r])
}}

# Secret material embedded directly in IaC.
deny[msg] {{
    some r, k
    v := input.resource[r][k]
    is_string(v)
    regex.match(`(?i)(secret|password|api[_-]?key|private[_-]?key)`, k)
    count(v) > 0
    msg := sprintf("SECRET IN IAC: %v.%v hardcodes a credential", [r, k])
}}
```

INVARIANTS TO ASSERT (a DENY on ANY = critical): no IAM statement grants Action or Resource "*";
no data-store is publicly readable/writable; no control-plane/SG is open to 0.0.0.0/0; no secret/
credential is hardcoded in IaC; least-privilege is the default.

ITERATE: render Terraform to plan JSON (`terraform show -json`) so the policy sees resolved values;
extend deny rules to every resource type in scope. A single deny IS your PoC."""


def _mobile_skeleton(subsystem: str, focus_files: list[str]) -> str:
    """Mobile local auth/session/storage/backend-trust — static check over manifest/plist/resources,
    expect='fail' (an insecure-config violation found = the bug is reproduced)."""
    files = _files_block(focus_files)
    poc = f"{_POC_DIR}/test_mobile_config.py"
    return f"""SCAFFOLD — static-analysis harness over the mobile app config for the '{subsystem}'
subsystem (target class: MOBILE_APP).

In-scope config/resources to inspect (AndroidManifest.xml / Info.plist / resource XML):
  - {files}

GOAL: statically flag insecure local posture — exported components without a permission guard, a
debuggable build, cleartext traffic / no certificate pinning, embedded secrets, and
allowBackup=true. Pure file parsing with the stdlib (no device, no network). CLASS-level checks, no
per-app literals.

MATERIALIZE THIS at {poc} and RUN:
    pytest {poc} -v

EXPECTED OUTCOME (ReproSpec.expect="fail"): the bug is DEMONSTRATED when a check assertion FAILS —
a violation was found (an unguarded exported component, debuggable=true, cleartext allowed, an
embedded secret, or allowBackup=true). A reproduced finding makes the targeted test FAIL; a
hardened config keeps every test PASSING.

```python
import os, re
import xml.etree.ElementTree as ET
import pytest

ANDROID = "http://schemas.android.com/apk/res/android"
MANIFEST = os.environ.get("P1HUNT_MANIFEST", "AndroidManifest.xml")
_SECRET = re.compile(r"(?i)(api[_-]?key|secret|password|private[_-]?key|token)\\s*[=:]\\s*\\S+")


def _attr(el, name):
    return el.get(f"{{{{{{ANDROID}}}}}}{{name}}")  # android: namespaced attribute


def _load():
    return ET.parse(MANIFEST).getroot()


def test_no_unguarded_exported_component():
    root = _load()
    for tag in ("activity", "service", "receiver", "provider"):
        for el in root.iter(tag):
            exported = _attr(el, "exported")
            if exported == "true" and not _attr(el, "permission"):
                pytest.fail(f"EXPORTED WITHOUT GUARD: {{tag}} {{_attr(el, 'name')}}")


def test_not_debuggable():
    app = _load().find("application")
    assert _attr(app, "debuggable") != "true", "DEBUGGABLE build shipped"


def test_no_cleartext_traffic():
    app = _load().find("application")
    assert _attr(app, "usesCleartextTraffic") != "true", "CLEARTEXT traffic allowed (no TLS pinning)"


def test_backup_disabled():
    app = _load().find("application")
    assert _attr(app, "allowBackup") != "true", "allowBackup=true leaks local data via adb backup"


def test_no_embedded_secrets():
    # Scan in-scope resource/config files for credential material.
    for path in os.environ.get("P1HUNT_RESOURCE_FILES", "").split(os.pathsep):
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8", errors="ignore") as f:
                assert not _SECRET.search(f.read()), f"EMBEDDED SECRET in {{path}}"
```

INVARIANTS TO ASSERT (any violation = critical): every exported component is permission-guarded;
the shipped build is not debuggable; cleartext traffic is disabled and TLS pinning is in place; no
secret/credential is embedded in the binary/resources; allowBackup is false (no adb-backup data
exfiltration); the client never trusts a local auth/session decision the backend should make.

ITERATE: for iOS apply the same checks to Info.plist (NSAppTransportSecurity exceptions, ATS
arbitrary loads, URL schemes) and scan resource bundles. A single violation IS your PoC."""


def _live_testing_note(target_url: str) -> str:
    """Appended to a web scaffold when an AUTHORIZED live target is armed: tells the harness it can
    interact for real and points it at the shipped, scope-enforced client + OOB listener."""
    return f"""

🌐 LIVE TARGET ARMED (authorized, scope-enforced). An authorized running instance is reachable at
{target_url} and credentials are in the environment. Your harness can make REAL requests — that is
how a web critical is PROVEN, not by reading alone. Use the shipped client (already copied into
./.p1hunt-poc/ as `p1hunt_dyn.py`) which enforces scope and handles identities + OOB for you:

    from p1hunt_dyn import Client
    c = Client()                                  # reads base URL + egress allowlist from env
    a = c.get('/me', identity='A')                # authenticate as principal A (env token)
    c.assert_forbidden('GET', f'/objects/{{oid}}', identity='B')   # B must be refused
    url, tok = c.oob_url()                         # feed `url` to callback/fetch behavior, then
    assert c.oob_received(tok)                     # assert the target called back (proof)

The egress jail confines every request to the in-scope host(s); a request elsewhere raises. Set
your ReproSpec expect so a reproduced bug makes the targeted test FAIL (an authz/forbidden
assertion that does NOT hold = the bypass). Only contact {target_url} and loopback."""


def scaffold_block(
    target_class: str,
    subsystem: str,
    focus_files: list[str],
    *,
    signals: list[str] | None = None,
    fork_url: str = "",
    entrypoints: list[str] | None = None,
    repo_path: str = "",
    target_url: str = "",
) -> str:
    """Return a prompt fragment that scaffolds a real, runnable harness for the target class.

    For ``EVM_CONTRACT`` this is a concrete Foundry test skeleton (setUp deploying the in-scope
    contracts + reentrancy-capable mock tokens, ``_signOrder`` via ``vm.sign`` over a real
    EIP-712 digest, ``_mintAndApprove``, ``_buildOrder``, a tiny merkle helper, and — when the
    target is an order marketplace — instructions to construct a VALID signed order so the
    fuzzer reaches the combiner/applier/transfer logic past signature validation).

    For NON-EVM classes it routes to a concrete, class/subclass-specific generator that emits a
    copy-startable harness in the right framework, the invariants to assert, the exact
    materialized file path + run command, AND the expected-outcome wording paired with
    ``ReproSpec.expect`` (whether a reproduced bug makes the test FAIL or PASS):

      * ``WEB_API`` — subclass-routed via ``detect_web_subclass`` (scanning ``repo_path``):
        ``auth`` -> resource-boundary checks (pytest+requests, expect='pass'); ``payments`` ->
        accounting/idempotency conservation (pytest, expect='pass'); ``graphql`` -> resolver
        field-authz (pytest, expect='pass'); else a generic web property loop.
      * ``CRYPTO_LIB`` — ``detect_crypto_subclass`` selects the subclass; a pytest property/
        differential harness for non-malleability / domain-separation / nonce-misuse
        (expect='fail').
      * ``SUPPLY_CHAIN`` — a semgrep ruleset over install/build scripts (expect='fail',
        a rule match = reproduction).
      * ``INFRA`` — an OPA/conftest (rego) policy over the IaC (expect='fail', a deny = repro).
      * ``MOBILE_APP`` — a stdlib static check over manifest/plist/resources (expect='fail').

    Anything else falls back to a concise generic "build a REAL harness in the target's own
    framework and RUN it" block. Generic to the CLASS — names no specific protocol. Pure.

    ``repo_path`` (the audit target root) should be passed by callers so order-marketplace and
    web/crypto subclass detection scans the target; without it, detection falls back to inferring
    a root from ``focus_files`` relative to the process cwd."""
    tc = (target_class or "").upper()
    # A scannable root requires either an explicit repo_path (the orchestrator knows the target)
    # or a focus file that actually resolves on disk. When neither exists, subclass detection has
    # nothing real to scan and would mis-read the process cwd — so we keep `root` empty and the
    # class generators fall back to their generic form (and EVM to a non-marketplace skeleton).
    root = repo_path or _focus_root(focus_files)
    if not repo_path and root == ".":
        root = ""  # no genuine target on disk — do not scan cwd
    if tc == "EVM_CONTRACT":
        # One generic EVM scaffold — NOTHING PRESET. It instructs deriving the valid-input shape
        # and any signature/permit/role gate from the target's OWN ABI/typehash, so it works for
        # any contract shape (no marketplace/order/AMM/etc. assumption).
        return _evm_skeleton(subsystem, focus_files, signals, fork_url, entrypoints)
    if tc == "WEB_API":
        sub = detect_web_subclass(root, signals) if root else "generic-web"
        live = _live_testing_note(target_url) if target_url else ""
        if sub == "auth":
            return _web_authz_skeleton(subsystem, focus_files, target_url) + live
        if sub == "payments":
            return _web_payment_skeleton(subsystem, focus_files, target_url) + live
        if sub == "graphql":
            return _graphql_skeleton(subsystem, focus_files, target_url) + live
        return _generic_skeleton(target_class or "unknown", subsystem, focus_files, fork_url) + live
    if tc == "CRYPTO_LIB":
        sub = detect_crypto_subclass(root, signals) if root else "generic-crypto"
        return _crypto_skeleton(subsystem, sub, focus_files)
    if tc == "SUPPLY_CHAIN":
        return _supply_chain_skeleton(subsystem, focus_files)
    if tc == "INFRA":
        return _infra_skeleton(subsystem, focus_files)
    if tc == "MOBILE_APP":
        return _mobile_skeleton(subsystem, focus_files)
    return _generic_skeleton(target_class or "unknown", subsystem, focus_files, fork_url)


def _focus_root(focus_files: list[str]) -> str:
    """Best-effort repo root from the focus files so the web/crypto subclass detectors can read
    them. The orchestrator passes focus files (relative to repo root); we infer a common existing
    ancestor directory to scan. Falls back to "." (cwd). Never raises."""
    for f in focus_files or []:
        try:
            p = Path(f)
            if p.is_file():
                return str(p.parent)
            if p.is_absolute() and p.parent.exists():
                return str(p.parent)
        except OSError:
            continue
    return "."
