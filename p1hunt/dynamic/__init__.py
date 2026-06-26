"""Authorized live dynamic-interaction subsystem (spec §9, §12).

Many bug-bounty criticals cannot be found by reading source alone; they are found by interacting
with a running, authorized target as a real attacker would. This package gives the swarm that
capability while staying inside safe
harbor: every outbound request is confined to an explicit, derived host allowlist (the egress
jail), gated by ScopeGuard, rate-limited, and restricted to authorized sandbox environments
(UAT / owned-account / testnet / local) — never production.

It is INERT by default: with no dynamic target declared and dry-run mode, nothing here changes
behavior. It activates only when an operator authorizes a live target at intake AND run_mode is
active (see ``safety.policies.authorize_dynamic``).

Modules:
  * ``egress``  — pure host-allowlist enforcement (the safe-harbor floor for any live contact).
  * ``client``  — the interaction engine harnesses import: multi-identity sessions, scope-checked
                  requests, differential refusal helpers, and input-behavior oracles. Stdlib only.
  * ``oob``     — a loopback out-of-band interaction listener so callback-based behavior can be
                  confirmed by a harness assertion.
"""

from __future__ import annotations
