"""Shared detector knowledge: severity, base reproducibility, and remediation per signal.

Centralized so the scan view, the reasoner, and Parent A agree. Values are derivation
knowledge (generic per-signal), not a per-target playbook.
"""

from __future__ import annotations

# signal id -> (severity, base reproducibility before depth/corroboration)
SIGNAL_PROFILE: dict[str, tuple[str, float]] = {
    "secret-in-source": ("critical", 0.74),
    "command-injection": ("critical", 0.58),
    "unsafe-deser": ("critical", 0.56),
    "evm-tx-origin": ("critical", 0.66),
    "evm-delegatecall": ("critical", 0.52),
    "evm-reentrancy": ("critical", 0.58),
    # Hardened-EVM high-value detectors (classify/evm_signals.py EVM_SIGNALS). Tuned to SURVIVE on
    # battle-tested, assembly-heavy code: a guard token nearby does not clear a low-level primitive
    # class, so these persist as leads and are confirmed by depth (see reasoner._HARDENED_AWARE).
    "evm-unchecked-call": ("critical", 0.58),
    "evm-bare-ecrecover": ("critical", 0.62),
    "evm-div-before-mul": ("high", 0.50),
    "evm-raw-delegatecall": ("critical", 0.58),
    "evm-reentrancy-call": ("critical", 0.56),
    "mass-assignment": ("critical", 0.54),
    "jwt-no-verify": ("critical", 0.58),
    "auth-missing": ("critical", 0.50),
    "ci-privileged-pr": ("critical", 0.52),
    "cloud-wildcard-iam": ("critical", 0.56),
    "authz-fail-open": ("critical", 0.52),
    "idor-direct-object": ("critical", 0.42),
    "ssti": ("critical", 0.52),
    "open-redirect": ("high", 0.42),
    "ssrf": ("high", 0.46),
    "sql-injection": ("high", 0.48),
    "nosql-injection": ("high", 0.46),
    "path-traversal": ("high", 0.46),
    "xss-sink": ("high", 0.44),
    "weak-crypto": ("high", 0.42),
    "xxe": ("high", 0.46),
    "cors-wildcard-creds": ("high", 0.46),
    "insecure-random-token": ("high", 0.40),
    "prototype-pollution": ("high", 0.40),
    "invariant-comment": ("medium", 0.30),
}

SEVERITY_DEFAULT = ("high", 0.40)

REMEDIATION: dict[str, str] = {
    "secret-in-source": "Revoke and rotate the credential, move secrets to a managed store, add secret scanning to CI.",
    "command-injection": "Avoid shell execution; use fixed argument arrays and allowlisted values.",
    "unsafe-deser": "Use safe parsers, disable arbitrary object construction, validate schemas before parsing.",
    "evm-tx-origin": "Use msg.sender with explicit role checks; test calls through intermediate contracts.",
    "evm-delegatecall": "Restrict privileged primitives to audited upgrade paths; validate targets; add invariant tests.",
    "evm-reentrancy": "Apply checks-effects-interactions, use a reentrancy guard, update state before external calls.",
    "mass-assignment": "Use DTO/schema allowlists; separate privileged writes; add negative tests for protected fields.",
    "jwt-no-verify": "Verify issuer, audience, expiry, and signature with an allowlisted algorithm.",
    "auth-missing": "Require authentication/authorization middleware on every state-changing or sensitive route.",
    "ci-privileged-pr": "Separate untrusted PR validation from privileged workflows; pin least-privilege permissions.",
    "cloud-wildcard-iam": "Replace wildcard principals/actions/resources with least-privilege; add policy-as-code checks.",
    "authz-fail-open": "Centralize authorization, deny by default, require ownership/role, add negative regression tests.",
    "idor-direct-object": "Bind object lookup to the authenticated principal and tenant; test cross-user negatives.",
    "ssti": "Never render user input as a template; use a logic-less or sandboxed template engine.",
    "open-redirect": "Validate redirect targets against an allowlist; never trust user-supplied next/return URLs.",
    "ssrf": "Enforce a destination allowlist, block internal ranges, disable redirects, validate parsed URLs.",
    "sql-injection": "Use parameterized queries / bind variables; test metacharacters against local fixtures.",
    "nosql-injection": "Use typed query builders; reject operator objects ($where/$gt) from untrusted input.",
    "path-traversal": "Resolve against a fixed base, reject traversal after normalization, use opaque file IDs.",
    "xss-sink": "Escape/encode on output, avoid innerHTML/dangerouslySetInnerHTML, use a strict CSP.",
    "weak-crypto": "Replace MD5/SHA1/DES/ECB with vetted primitives (SHA-256+, AES-GCM); use authenticated encryption.",
    "xxe": "Disable DTDs, external entities, and external schemas; use hardened parser defaults.",
    "cors-wildcard-creds": "Use an explicit origin allowlist; never combine wildcard origin with credentials.",
    "insecure-random-token": "Use a CSPRNG (secrets/crypto.randomBytes) for tokens, keys, and nonces.",
    "prototype-pollution": "Reject __proto__/constructor keys; use null-prototype objects and schema validation.",
    "invariant-comment": "Encode the invariant as an enforced check and a property/invariant test on every path.",
}


def severity_of(signal_id: str) -> str:
    return SIGNAL_PROFILE.get(signal_id, SEVERITY_DEFAULT)[0]


def base_reproducibility(signal_id: str) -> float:
    return SIGNAL_PROFILE.get(signal_id, SEVERITY_DEFAULT)[1]


def remediation_for(signal_id: str) -> str:
    return REMEDIATION.get(signal_id, "Fix the root cause and add a regression test.")
