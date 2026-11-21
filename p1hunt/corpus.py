"""Persistent fuzz corpus + coverage ledger (spec gap: campaign memory).

The swarm currently re-explores the same surfaces every round: each fuzz/invariant
campaign starts cold, rediscovers the same counterexamples, and never learns which
entrypoints it already covered. This module gives the orchestrator a per-subsystem
*memory* that COMPOUNDS across rounds — prior counterexamples become seeds, observed
coverage tells the next campaign which entrypoints are still dark, and round counts let
budgets escalate breadth instead of repeating work.

Storage is a single JSON file (``<engagement_dir>/corpus.json``); there is no network and
no external tool. Missing or corrupt state is tolerated — a fresh, empty store is used —
so a half-written ledger never crashes an engagement.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

_IDENT = re.compile(r"[A-Za-z_]\w*")


def _bare_name(symbol: object) -> str:
    """Bare function name from a signature or symbol: the identifier just before ``(``.

    Detected entrypoints are full signatures (``fulfillOrder(Order,bytes32)``) while a fuzzer's
    self-reported covered symbol is often just the name (``fulfillOrder``) or a short phrase — so
    coverage matching must compare on the bare name, lowercased."""
    head = str(symbol or "").split("(")[0]
    found = _IDENT.findall(head)
    return found[-1].lower() if found else ""


def _coverage_key(symbol: object) -> str:
    """The identity of one entrypoint for coverage matching.

    Two shapes of entrypoint exist and they cannot share a keying rule:

    * a FUNCTION SIGNATURE (``fulfillOrder(Order,bytes32)``) keys on its bare name, because a
      fuzzer reports coverage as just ``fulfillOrder``; and
    * a ROUTE / ENDPOINT (``GET /doc/{p}``) keys on the WHOLE normalized string. Keying a route
      on its last identifier would make every parameterized route collide on the placeholder —
      ``GET /doc/{p}`` and ``GET /users/{p}`` would look like one entrypoint, and all but the
      first would be silently dropped from the uncovered list.
    """

    text = " ".join(str(symbol or "").split())
    if "/" in text:
        return text.lower()
    return _bare_name(text)


def _covered_names(covered_symbols: Iterable[str] | None) -> set[str]:
    """Everything the reported coverage can be matched against, lowercased: each symbol's whole
    route-style key (when it looks like a route) plus every identifier token it contains — so a
    detected entrypoint counts as covered if either form shows up in the report."""
    names: set[str] = set()
    for s in covered_symbols or []:
        text = " ".join(str(s or "").split())
        if "/" in text:
            names.add(text.lower())
        for tok in _IDENT.findall(text):
            names.add(tok.lower())
    return names


@dataclass
class SubsystemCoverage:
    """The accumulated knowledge for one subsystem across all prior campaigns."""

    subsystem: str
    counterexamples: list[str] = field(default_factory=list)
    coverage_notes: list[str] = field(default_factory=list)
    covered_symbols: list[str] = field(default_factory=list)
    rounds: int = 0


def _dedup_extend(base: list[str], extra: Iterable[str] | None) -> None:
    """Append items from ``extra`` to ``base`` preserving order, skipping blanks/dupes."""

    if not extra:
        return
    seen = set(base)
    for item in extra:
        if item is None:
            continue
        text = str(item).strip()
        if not text or text in seen:
            continue
        base.append(text)
        seen.add(text)


class CorpusStore:
    """A persistent, per-subsystem corpus + coverage ledger.

    All mutating operations merge-and-dedup, bump the subsystem round counter, and persist
    immediately so an interrupted engagement still resumes with everything learned so far.
    """

    def __init__(self, engagement_dir: str | Path) -> None:
        self._dir = Path(engagement_dir)
        self._path = self._dir / "corpus.json"
        # subsystem -> SubsystemCoverage
        self._subsystems: dict[str, SubsystemCoverage] = {}
        self.load()

    # ------------------------------------------------------------------ io --
    def load(self) -> None:
        """Load the ledger from disk, tolerating a missing or corrupt file."""

        self._subsystems = {}
        try:
            raw = self._path.read_text(encoding="utf-8")
        except (OSError, FileNotFoundError):
            return
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            # Corrupt JSON — start empty rather than crash the engagement.
            return
        if not isinstance(data, dict):
            return
        records = data.get("subsystems")
        if not isinstance(records, dict):
            return
        for name, rec in records.items():
            if not isinstance(rec, dict):
                continue
            cov = SubsystemCoverage(subsystem=str(name))
            _dedup_extend(cov.counterexamples, _as_list(rec.get("counterexamples")))
            _dedup_extend(cov.coverage_notes, _as_list(rec.get("coverage_notes")))
            _dedup_extend(cov.covered_symbols, _as_list(rec.get("covered_symbols")))
            try:
                cov.rounds = int(rec.get("rounds", 0))
            except (ValueError, TypeError):
                cov.rounds = 0
            self._subsystems[cov.subsystem] = cov

    def save(self) -> None:
        """Persist the ledger as JSON, creating the engagement dir if needed."""

        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "subsystems": {
                    name: {
                        "subsystem": cov.subsystem,
                        "counterexamples": cov.counterexamples,
                        "coverage_notes": cov.coverage_notes,
                        "covered_symbols": cov.covered_symbols,
                        "rounds": cov.rounds,
                    }
                    for name, cov in self._subsystems.items()
                }
            }
            self._path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        except OSError:
            # Persistence is best-effort; an unwritable dir must never abort a campaign.
            return

    # -------------------------------------------------------------- mutate --
    def record(
        self,
        subsystem: str,
        *,
        counterexamples: Iterable[str] | None = None,
        coverage_notes: Iterable[str] | None = None,
        covered_symbols: Iterable[str] | None = None,
    ) -> None:
        """Merge a campaign's results into the subsystem, bump its round, and save."""

        name = str(subsystem).strip() or "unknown"
        cov = self._subsystems.get(name)
        if cov is None:
            cov = SubsystemCoverage(subsystem=name)
            self._subsystems[name] = cov
        _dedup_extend(cov.counterexamples, counterexamples)
        _dedup_extend(cov.coverage_notes, coverage_notes)
        _dedup_extend(cov.covered_symbols, covered_symbols)
        cov.rounds += 1
        self.save()

    # --------------------------------------------------------------- query --
    def seeds_for(self, subsystem: str) -> list[str]:
        """Prior counterexamples for this subsystem, to reuse as fuzz seeds / avoid repeats."""

        cov = self._subsystems.get(str(subsystem).strip())
        return list(cov.counterexamples) if cov else []

    def coverage_for(self, subsystem: str) -> SubsystemCoverage:
        """The accumulated coverage record (a fresh empty one if never seen)."""

        name = str(subsystem).strip()
        cov = self._subsystems.get(name)
        if cov is None:
            return SubsystemCoverage(subsystem=name)
        # Return a copy so callers can't mutate the ledger out from under us.
        return SubsystemCoverage(
            subsystem=cov.subsystem,
            counterexamples=list(cov.counterexamples),
            coverage_notes=list(cov.coverage_notes),
            covered_symbols=list(cov.covered_symbols),
            rounds=cov.rounds,
        )

    def uncovered_hint(self, subsystem: str, entrypoints: list[str]) -> str:
        """A short directive naming entrypoints not yet covered, or "" when none remain.

        Drives the next campaign at dark code instead of re-covering what is already hit.
        Returns "" when no entrypoints are known or all are already covered.
        """

        if not entrypoints:
            return ""
        cov = self._subsystems.get(str(subsystem).strip())
        # Match on the bare function name: entrypoints are full signatures, covered symbols are
        # the fuzzer's free-form self-report — an exact-string compare would never match and would
        # re-steer the campaign at code it already hit every round.
        covered = _covered_names(cov.covered_symbols if cov else [])
        uncovered: list[str] = []
        seen: set[str] = set()
        for ep in entrypoints:
            if ep is None:
                continue
            text = str(ep).strip()
            key = _coverage_key(text) or text.lower()
            if not text or key in seen or key in covered:
                continue
            uncovered.append(text)
            seen.add(key)
        if not uncovered:
            return ""
        return (
            "Target these still-uncovered entrypoints first: " + ", ".join(uncovered) + "."
        )


def _as_list(value: object) -> list[str]:
    """Coerce a persisted field to a list of strings, tolerating bad shapes."""

    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return []
