"""P1HUNT Threat Operations Center — a zero-dependency local web dashboard.

A stdlib-only HTTP server (no Flask/Next/build step) that tails an engagement's append-only event
stream (``events.jsonl``) plus ``findings.json`` and serves a live ops-center UI. Read-only, binds
to loopback by default. Launch with ``python -m p1hunt.web`` or ``python -m p1hunt.main web``.
"""

from __future__ import annotations
