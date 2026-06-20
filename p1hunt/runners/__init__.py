"""Deterministic reproduction runners (spec §10 — believe, but VERIFY by execution).

A runner EXECUTES a materialized proof harness with the target's real toolchain and DECIDES
reproduction from the parsed exit code / output — it never asks the model whether it worked. A
critical/P1 is promoted ONLY when a runner returns ``reproduced=True``.

NOTHING PRESET: runners are generic per TARGET CLASS, selected by the class derived from the
actual target at runtime — never a per-target script. See ``base.py`` for the contract.
"""
