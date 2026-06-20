"""ScopeGuardPolicy derivation (spec §6 step 5, §9).

The *floor* is invariant (in-scope only; sandbox/fork-only writes; non-destructive;
least-data; no ``ask`` unattended). The *specific contents* — which environments count
as a sandbox, which chain IDs, which HTTP verbs — are derived per engagement from the
target class and the parsed program rules. There are no per-target playbooks here, only
derivation rules.
"""

from __future__ import annotations

from ..models import Scope, ScopeGuardPolicy, TargetClass

# Invariant safety floor — these are *categories of prohibited action*, not a target
# playbook. They apply to every engagement regardless of class (§2.7, §17).
_DESTRUCTIVE_FLOOR = [
    "delete",
    "drop",
    "truncate",
    "destroy",
    "shutdown",
    "selfdestruct",
    "suicide",
    "spam",
    "flood",
    "dos",
    "denial-of-service",
    "bruteforce",
    "credential-stuff",
    "phish",
    "exfiltrate",
    "persist",
    "lateral-move",
    "mainnet-write",
    "prod-write",
    "production-write",
    "lockout",
    "ransom",
]


def _rate_from_rules(scope: Scope) -> int:
    text = " ".join(scope.rules) + " " + scope.rate_limit
    for token in text.replace("/", " ").split():
        if token.isdigit():
            return int(token)
    return 30


def derive_scopeguard_policy(scope: Scope, target_class: TargetClass) -> ScopeGuardPolicy:
    """Derive the engagement-specific guard policy.

    Class-specific *derivation rules* (not presets) tighten the sandbox and method
    allowlists. e.g. EVM -> fork-only, no mainnet tx; CRYPTO_LIB -> local harness, no
    network; MOBILE/INFRA -> UAT only, never touch a production service even with valid
    creds.
    """
    allow_writes = any(
        "live" in r.lower() or "authenticated test" in r.lower() for r in scope.rules
    )
    methods = ["GET", "HEAD", "OPTIONS"] if allow_writes else ["GET", "HEAD"]

    # Sandbox + chain derivation by class.
    if target_class is TargetClass.EVM_CONTRACT:
        sandbox = ["local", "fork", "testnet"]
        chain_ids: list[int] = []  # populated by acquisition; mainnet IDs never added here
    elif target_class is TargetClass.CRYPTO_LIB:
        sandbox = ["local"]  # local harness only, no network
        methods = []
        chain_ids = []
    elif target_class in (TargetClass.MOBILE_APP, TargetClass.WEB_API, TargetClass.INFRA):
        sandbox = ["local", "uat"]  # UAT only; never a production broker/service
        chain_ids = []
    elif target_class is TargetClass.SUPPLY_CHAIN:
        sandbox = ["local"]
        chain_ids = []
    else:
        sandbox = ["local"]
        chain_ids = []

    out_of_scope = [a.value for a in scope.out_of_scope] + [a.value for a in scope.ambiguous]

    return ScopeGuardPolicy(
        allowlist=[a.value for a in scope.in_scope],
        destructive_denylist=list(_DESTRUCTIVE_FLOOR),
        out_of_scope_denylist=out_of_scope,
        sandbox_environments=sandbox,
        allowed_http_methods=methods,
        allowed_chain_ids=chain_ids,
        max_requests_per_minute=_rate_from_rules(scope),
        unattended_mode=True,
        run_mode="dry_run",
        evidence_mode="least-data",
    )
