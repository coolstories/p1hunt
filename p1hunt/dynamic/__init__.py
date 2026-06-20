"""Authorized live dynamic-interaction subsystem (spec §9, §12).

Most bug-bounty criticals — IDOR/BOLA, auth bypass, SSRF, injection, business-logic — cannot
be found by reading source; they are found by INTERACTING with a running, authorized target as a
real attacker would. This package gives the swarm that capability while staying inside safe
harbor: every outbound request is confined to an explicit, derived host allowlist (the egress
jail), gated by ScopeGuard, rate-limited, and restricted to authorized sandbox environments
(UAT / owned-account / testnet / local) — never production.

It is INERT by default: with no dynamic target declared and dry-run mode, nothing here changes
behavior. It activates only when an operator authorizes a live target at intake AND run_mode is
active (see ``safety.policies.authorize_dynamic``).

Modules:
  * ``egress``  — pure host-allowlist enforcement (the safe-harbor floor for any live contact).
  * ``client``  — the interaction engine harnesses import: multi-identity sessions, scope-checked
                  requests, IDOR/BOLA differential helpers, injection oracles. Stdlib only.
  * ``oob``     — a loopback out-of-band interaction listener so blind SSRF/injection can be
                  CONFIRMED (the harness asserts the callback fired).
"""

from __future__ import annotations
