"""ScopeGuardPolicy derivation (spec §6 step 5, §9).

The *floor* is invariant (in-scope only; sandbox/fork-only writes; non-destructive;
least-data; no ``ask`` unattended). The *specific contents* — which environments count
as a sandbox, which chain IDs, which HTTP verbs — are derived per engagement from the
target class and the parsed program rules. There are no per-target playbooks here, only
derivation rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..dynamic.egress import normalize_host
from ..models import Scope, ScopeGuardPolicy, TargetClass

# Environments that count as an authorized safe-harbor sandbox for LIVE testing. Production is
# deliberately absent — a dynamic target declared "production" is never authorized for contact.
# "bounty" = an authorized PUBLIC bug-bounty program whose published safe harbor permits in-scope
# testing of the live (production) service — e.g. HackerOne/Bugcrowd programs like T-Mobile. The
# operator opts into it explicitly (--live-env bounty); the bare label "production" is still REFUSED
# so a misconfig can never silently authorize an unscoped prod target. The destructive floor
# (no DELETE, no data destruction, no DoS) and the egress jail (in-scope hosts only) STILL apply.
_SANDBOX_ENVIRONMENTS = ("uat", "owned", "testnet", "local", "staging", "bounty")
# Write HTTP verbs unlocked for AUTHORIZED live testing. DELETE is intentionally excluded — it is
# the one common verb whose accidental success is irreversible even on an owned/UAT object.
_LIVE_WRITE_METHODS = ("POST", "PUT", "PATCH")

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


@dataclass
class PermissionPolicy:
    """Runtime permissions for the live workspace-jail (spec §6 step 5, §9) — what the hunting
    agents may DO inside the in-scope folder, distinct from WHERE they may act (the workspace
    boundary) and from the ScopeGuard semantic policy (out-of-scope / destructive / live egress).

    Parent A OWNS this: it is derived from the program rules (``derive_permission_policy``) and may
    be TIGHTENED by Parent A's recon (``tightened_with``), never loosened past the derived floor.
    Defaults preserve the loosened jail model (network + installs allowed inside the folder); a
    program that forbids network or requires a local-only harness flips them off. Jail-escape
    commands (sudo/mount/disk) and out-of-workspace reads/writes are NOT governed here — they are
    always denied (the invariant floor)."""

    allow_network: bool = True       # network egress from bash (curl/wget/git push/clone) + web tools
    allow_install: bool = True       # dependency installs (npm/pip/cargo/go/apt/brew …)
    deny_commands: list[str] = field(default_factory=list)  # extra command substrings Parent A blocks
    note: str = ""                   # human-readable reason for the chosen posture

    def tightened_with(self, other: "PermissionPolicy | dict | None") -> "PermissionPolicy":
        """Return a copy that can only become MORE restrictive (clamp). Parent A may turn a
        permission OFF or ADD denials; it can never re-enable one past this floor."""
        if other is None:
            return PermissionPolicy(self.allow_network, self.allow_install, list(self.deny_commands), self.note)
        if isinstance(other, dict):
            other = PermissionPolicy(
                allow_network=bool(other.get("allow_network", self.allow_network)),
                allow_install=bool(other.get("allow_install", self.allow_install)),
                deny_commands=[str(c) for c in (other.get("deny_commands") or []) if str(c).strip()],
                note=str(other.get("note", "") or ""),
            )
        return PermissionPolicy(
            allow_network=self.allow_network and other.allow_network,   # AND only → clamp tighter
            allow_install=self.allow_install and other.allow_install,
            deny_commands=list(dict.fromkeys([*self.deny_commands, *other.deny_commands])),
            note=other.note or self.note,
        )


_NO_NETWORK_HINTS = ("no network", "no internet", "offline", "local harness only", "no outbound",
                     "air-gapped", "airgapped", "without network", "local-only", "no egress")
_NO_INSTALL_HINTS = ("no install", "do not install", "no dependency install", "no package install",
                     "no new dependencies")


def derive_permission_policy(scope: Scope, target_class: TargetClass | None = None) -> PermissionPolicy:
    """Initial runtime-permission posture DERIVED from the program rules + target class; Parent A
    refines it during recon. NOTHING PRESET — read the rules text, not a per-target playbook. A
    crypto library (local harness, no network) starts locked down; a web/API program that permits
    authorized live testing keeps network on."""
    text = " ".join([*(scope.rules or []), scope.safe_harbor_text or "",
                     getattr(scope, "scope_note", "") or ""]).lower()
    allow_network = not any(h in text for h in _NO_NETWORK_HINTS)
    allow_install = not any(h in text for h in _NO_INSTALL_HINTS)
    if target_class is TargetClass.CRYPTO_LIB:
        allow_network = False  # mirrors the ScopeGuard CRYPTO_LIB floor: local harness, no network
    note = "derived from program rules" + ("" if allow_network else "; network OFF") \
        + ("" if allow_install else "; installs OFF")
    return PermissionPolicy(allow_network=allow_network, allow_install=allow_install, note=note)


def _rate_from_rules(scope: Scope) -> int:
    text = " ".join(scope.rules) + " " + scope.rate_limit
    for token in text.replace("/", " ").split():
        if token.isdigit():
            return int(token)
    return 30


def derive_scopeguard_policy(
    scope: Scope, target_class: TargetClass, *, run_mode: str = "dry_run"
) -> ScopeGuardPolicy:
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

    policy = ScopeGuardPolicy(
        allowlist=[a.value for a in scope.in_scope],
        destructive_denylist=list(_DESTRUCTIVE_FLOOR),
        out_of_scope_denylist=out_of_scope,
        sandbox_environments=sandbox,
        allowed_http_methods=methods,
        allowed_chain_ids=chain_ids,
        egress_allowlist=[],
        max_requests_per_minute=_rate_from_rules(scope),
        unattended_mode=True,
        run_mode=run_mode if run_mode in ("dry_run", "active") else "dry_run",
        evidence_mode="least-data",
    )
    # If a live target is authorized AND we're in active mode, unlock scoped live testing.
    authorize_dynamic(policy, scope)
    return policy


def authorize_dynamic(policy: ScopeGuardPolicy, scope: Scope) -> dict:
    """Unlock AUTHORIZED, scoped live dynamic testing on ``policy`` IN PLACE, and return a summary
    of what was enabled (for the audit log).

    Deny-by-default is preserved: this does nothing unless (a) ``policy.run_mode == "active"`` and
    (b) the scope declares at least one dynamic target in a non-production sandbox environment. A
    target whose environment is "production" (or anything outside the sandbox set) is NEVER
    authorized — its host is not added to the egress allowlist, so contact stays denied.

    When it does fire it: seeds the egress allowlist with the authorized hosts (the live jail),
    adds their environment to the sandbox set, and unlocks the non-destructive write methods
    (POST/PUT/PATCH) needed to demonstrate IDOR/business-logic — DELETE stays denied."""
    enabled_hosts: list[str] = []
    enabled_envs: set[str] = set()
    rejected: list[str] = []
    if policy.run_mode != "active":
        return {"enabled": False, "reason": "run_mode is not active", "hosts": [], "rejected": []}
    for tgt in getattr(scope, "dynamic_targets", None) or []:
        env = str(getattr(tgt, "environment", "")).strip().lower()
        host = normalize_host(getattr(tgt, "base_url", ""))
        if not host:
            continue
        if env not in _SANDBOX_ENVIRONMENTS:
            rejected.append(f"{host} ({env or 'unspecified'} — not an authorized sandbox env)")
            continue
        if host not in enabled_hosts:
            enabled_hosts.append(host)
        enabled_envs.add(env)
    if not enabled_hosts:
        return {"enabled": False, "reason": "no authorized non-production dynamic target",
                "hosts": [], "rejected": rejected}
    policy.egress_allowlist = list(dict.fromkeys([*policy.egress_allowlist, *enabled_hosts]))
    policy.sandbox_environments = list(dict.fromkeys([*policy.sandbox_environments, *enabled_envs]))
    policy.allowed_http_methods = list(dict.fromkeys(
        [*policy.allowed_http_methods, "GET", "HEAD", "OPTIONS", *_LIVE_WRITE_METHODS]))
    return {"enabled": True, "hosts": enabled_hosts, "environments": sorted(enabled_envs),
            "rejected": rejected, "methods": list(policy.allowed_http_methods)}
