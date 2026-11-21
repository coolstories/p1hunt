"""Falsification ledger — append-only memory of what has already been ruled out.

The never-quit loop (spec §8) has one failure mode that looks like persistence but is not:
re-testing a dead end. A reframe that rotates back to a hypothesis the swarm already killed
spends budget to re-derive a known negative, and across enough rounds the loop simply cycles.
This module gives the orchestrator a durable, keyed record of **every hypothesis tested and
how it came out**, so:

  (a) the reframe path can ask ``already_falsified(hypothesis)`` and refuse to re-issue a
      closed frame — persistence stops looping and starts compounding; and

  (b) a FAMILY of related falsifications composes into an ARCHITECTURAL CONCLUSION: when
      every member of a variant class is closed, and the mechanisms that closed them are
      recorded, "this variant class is architecturally impossible" becomes a supported,
      reportable confidence artifact rather than discarded work.

Storage is one append-only JSONL file (``<engagement_dir>/falsified.jsonl``) plus derived
markdown conclusions under ``<engagement_dir>/conclusions/`` — the same engagement-folder
convention as ``corpus.json`` and ``state.json``, so the ledger survives a process restart and
a resumed hunt reads back everything learned so far.

SCOPE OF MEMORY: the ledger is **per engagement**, deliberately. It is not the cross-engagement
``memory`` store, which is sanitized metadata only precisely so it can never become a hidden
preset feed. Hypothesis text is engagement-local research state; it never travels to another
target, so recording it here cannot seed priors into a future hunt (§1 NOTHING PRESET).

Everything in the top half of this module is a PURE function (keying, normalization, family
grouping, conclusion composition) and is exhaustively unit-testable without a filesystem.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# Outcome vocabulary. These are *epistemic states of a test*, not bug classes — the ledger has
# no opinion about what was tested, only about whether the test closed the question.
OUTCOME_FALSIFIED = "falsified"      # tested and ruled out — do not re-issue
OUTCOME_SURVIVED = "survived"        # tested and still live — keep pursuing
OUTCOME_ATTEMPTED = "attempted"      # tried, no verdict yet (bounds retries, does not close)
OUTCOME_INCONCLUSIVE = "inconclusive"  # could not be decided (no tooling / no access)
OUTCOME_CONCLUSION = "conclusion"    # bookkeeping: an architectural conclusion was emitted

_OUTCOMES = (
    OUTCOME_FALSIFIED,
    OUTCOME_SURVIVED,
    OUTCOME_ATTEMPTED,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_CONCLUSION,
)

_WS = re.compile(r"\s+")
_NOISE = re.compile(r"[^a-z0-9 ]+")
# Field width. Deliberately GENEROUS: the orchestrator reading this back runs on a long-context
# model, and a hypothesis truncated to a stub is worse than useless as a loop guard — two
# different dead ends can truncate to the same prefix and the ledger silently conflates them.
# Still bounded, because a ledger line is a record, not a transcript.
_MAX_TEXT = 1200
_MAX_FAMILY = 160


# --------------------------------------------------------------------- pure --
def normalize_hypothesis(text: object) -> str:
    """Canonical form of a hypothesis statement, for stable keying across rewordings.

    Lowercased, punctuation-stripped, whitespace-collapsed. This is what makes a key survive a
    REFRAME: the same claim phrased slightly differently by a later round still keys the same, so
    ``already_falsified`` actually fires instead of letting a cosmetic rewrite through."""

    s = str(text or "").strip().lower()
    s = _NOISE.sub(" ", s)
    return _WS.sub(" ", s).strip()


def hypothesis_key(text: object) -> str:
    """A short, stable, content-addressed key for a hypothesis. "" for an empty hypothesis."""

    norm = normalize_hypothesis(text)
    if not norm:
        return ""
    return hashlib.sha1(norm.encode("utf-8")).hexdigest()[:16]


def _clean(value: object, limit: int = _MAX_TEXT) -> str:
    return " ".join(str(value or "").split())[:limit]


def _normalize_outcome(outcome: object) -> str:
    o = str(outcome or "").strip().lower()
    return o if o in _OUTCOMES else OUTCOME_ATTEMPTED


@dataclass(frozen=True)
class LedgerRecord:
    """One append-only line: a hypothesis, how it came out, and what closed it."""

    key: str
    hypothesis: str
    outcome: str
    family: str = ""       # the variant CLASS this hypothesis belongs to (for composition)
    mechanism: str = ""    # what blocked it — the raw reason, as reported by whoever tested it
    note: str = ""
    agent: str = ""
    ts: float = 0.0

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "hypothesis": self.hypothesis,
            "outcome": self.outcome,
            "family": self.family,
            "mechanism": self.mechanism,
            "note": self.note,
            "agent": self.agent,
            "ts": self.ts,
        }


@dataclass(frozen=True)
class ArchitecturalConclusion:
    """A well-supported NEGATIVE: an entire variant class closed, with the mechanisms that close
    it. This is a reportable confidence artifact — it tells the operator (and the report) that a
    whole branch of the search space is exhausted *and why*, which is what lets a hunt stop
    re-testing it forever and conclude a variant is architecturally impossible."""

    family: str
    closed_count: int
    mechanisms: tuple[str, ...]
    statement: str
    members: tuple[str, ...] = ()

    def as_markdown(self) -> str:
        lines = [
            f"# Architectural conclusion: {self.family}",
            "",
            self.statement,
            "",
            f"- Falsified variants in this class: {self.closed_count}",
            "- Blocking mechanisms observed:",
            *[f"  - {m}" for m in self.mechanisms],
        ]
        if self.members:
            lines += ["", "## Variants tested and ruled out", ""]
            lines += [f"- {m}" for m in self.members]
        lines += [
            "",
            "A negative of this shape is evidence, not waste: every variant in the class was "
            "tested and each was blocked by a named mechanism, so the class is closed rather "
            "than merely unexplored.",
            "",
        ]
        return "\n".join(lines)


def group_by_family(records: Iterable[LedgerRecord]) -> dict[str, list[LedgerRecord]]:
    """Records grouped by family, preserving insertion order. Unfamilied records are skipped."""

    out: dict[str, list[LedgerRecord]] = {}
    for rec in records:
        fam = (rec.family or "").strip()
        if not fam:
            continue
        out.setdefault(fam, []).append(rec)
    return out


def compose_conclusion(
    family: str, records: Iterable[LedgerRecord], *, min_members: int = 3
) -> ArchitecturalConclusion | None:
    """Compose an architectural conclusion for ``family``, or None when it is not yet supported.

    A family is CLOSED only when (1) at least ``min_members`` distinct hypotheses in it were
    falsified, and (2) nothing in it survived. A single surviving member means the class is still
    live — the correct answer then is "keep hunting", not "architecturally impossible"."""

    recs = [r for r in records if (r.family or "").strip() == (family or "").strip()]
    if not recs:
        return None
    if any(r.outcome == OUTCOME_SURVIVED for r in recs):
        return None
    falsified: dict[str, LedgerRecord] = {}
    for rec in recs:
        if rec.outcome == OUTCOME_FALSIFIED and rec.key:
            falsified.setdefault(rec.key, rec)
    if len(falsified) < max(1, int(min_members)):
        return None

    mechanisms: list[str] = []
    seen: set[str] = set()
    for rec in falsified.values():
        mech = (rec.mechanism or "").strip()
        if not mech:
            continue
        low = mech.lower()
        if low in seen:
            continue
        seen.add(low)
        mechanisms.append(mech)

    mech_text = (
        " ".join(
            [
                f"Independent mechanisms account for every failure: {'; '.join(mechanisms)}."
            ]
        )
        if mechanisms
        else "No variant produced the required effect, and no single compensating mechanism "
             "explains all of them (mechanisms were not recorded)."
    )
    statement = (
        f"Variant class '{family}' is CLOSED after {len(falsified)} distinct falsified variant(s) "
        f"with no survivors. {mech_text} Further variants of this class should not be re-tested "
        f"without new information that invalidates one of those mechanisms."
    )
    return ArchitecturalConclusion(
        family=(family or "").strip(),
        closed_count=len(falsified),
        mechanisms=tuple(mechanisms),
        statement=statement,
        members=tuple(r.hypothesis for r in falsified.values()),
    )


def conclusion_min_members() -> int:
    """How many falsified variants a family needs before it is declared closed.

    Dial: ``P1HUNT_CONCLUSION_MIN_MEMBERS`` (default 3). Lower = quicker to declare a class
    closed (cheaper, more likely to close a class early); higher = more evidence per conclusion."""

    raw = str(os.environ.get("P1HUNT_CONCLUSION_MIN_MEMBERS", "")).strip()
    if raw.isdigit() and int(raw) >= 1:
        return int(raw)
    return 3


# ----------------------------------------------------------------------- io --
class FalsificationLedger:
    """Append-only, restart-surviving record of tested hypotheses. Never raises.

    ``engagement_dir=None`` keeps the ledger in memory only (still fully functional for the
    running process) so an orchestrator with no engagement folder yet degrades instead of
    failing — the offline-graceful posture the rest of the package uses."""

    FILENAME = "falsified.jsonl"

    def __init__(self, engagement_dir: str | Path | None = None) -> None:
        self._dir = Path(engagement_dir) if engagement_dir else None
        self._path = (self._dir / self.FILENAME) if self._dir else None
        self._records: list[LedgerRecord] = []
        self._emitted_conclusions: set[str] = set()
        self.load()

    # --- io ---------------------------------------------------------------
    @property
    def path(self) -> Path | None:
        return self._path

    def load(self) -> None:
        """Read the ledger back, tolerating a missing file and skipping corrupt lines.

        A half-written final line (killed mid-append) must not lose the lines before it, so each
        line is parsed independently."""

        self._records = []
        self._emitted_conclusions = set()
        if self._path is None:
            return
        try:
            raw = self._path.read_text(encoding="utf-8")
        except (OSError, FileNotFoundError):
            return
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except (ValueError, TypeError):
                continue  # corrupt line — skip it, keep the rest
            if not isinstance(doc, dict):
                continue
            rec = LedgerRecord(
                key=str(doc.get("key", "")),
                hypothesis=str(doc.get("hypothesis", "")),
                outcome=_normalize_outcome(doc.get("outcome")),
                family=str(doc.get("family", "")),
                mechanism=str(doc.get("mechanism", "")),
                note=str(doc.get("note", "")),
                agent=str(doc.get("agent", "")),
                ts=_as_float(doc.get("ts")),
            )
            self._records.append(rec)
            if rec.outcome == OUTCOME_CONCLUSION and rec.family:
                self._emitted_conclusions.add(rec.family)

    def _append(self, rec: LedgerRecord) -> None:
        self._records.append(rec)
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec.as_dict(), sort_keys=True) + "\n")
        except OSError:
            return  # persistence is best-effort; an unwritable dir never aborts a hunt

    # --- write ------------------------------------------------------------
    def record(
        self,
        hypothesis: str,
        *,
        outcome: str = OUTCOME_FALSIFIED,
        family: str = "",
        mechanism: str = "",
        note: str = "",
        agent: str = "",
    ) -> LedgerRecord | None:
        """Append one outcome. Returns the record, or None for an empty hypothesis."""

        text = _clean(hypothesis)
        key = hypothesis_key(text)
        if not key:
            return None
        rec = LedgerRecord(
            key=key,
            hypothesis=text,
            outcome=_normalize_outcome(outcome),
            family=_clean(family, _MAX_FAMILY),
            mechanism=_clean(mechanism),
            note=_clean(note),
            agent=_clean(agent, 60),
            ts=time.time(),
        )
        self._append(rec)
        return rec

    def falsify(self, hypothesis: str, *, mechanism: str = "", family: str = "",
                note: str = "", agent: str = "") -> LedgerRecord | None:
        """Convenience: record a hypothesis as ruled out, with what blocked it."""

        return self.record(hypothesis, outcome=OUTCOME_FALSIFIED, family=family,
                           mechanism=mechanism, note=note, agent=agent)

    def note_attempt(self, hypothesis: str, *, family: str = "", note: str = "",
                     agent: str = "") -> LedgerRecord | None:
        """Record that a hypothesis was TRIED without closing it — this is what bounds retries
        (an escalation loop reads ``attempts`` to stop after N passes) without wrongly declaring
        a question answered."""

        return self.record(hypothesis, outcome=OUTCOME_ATTEMPTED, family=family,
                           note=note, agent=agent)

    # --- read -------------------------------------------------------------
    def records(self) -> list[LedgerRecord]:
        return list(self._records)

    def records_for(self, hypothesis: str) -> list[LedgerRecord]:
        key = hypothesis_key(hypothesis)
        return [r for r in self._records if r.key == key] if key else []

    def already_falsified(self, hypothesis: str) -> bool:
        """True iff this hypothesis (in any wording that normalizes the same) was ruled out.

        THE reframe guard. A later SURVIVED record re-opens it: new information beats an old
        negative, so a hypothesis is only closed while its most recent verdict says so."""

        recs = self.records_for(hypothesis)
        if not recs:
            return False
        verdicts = [r for r in recs if r.outcome in (OUTCOME_FALSIFIED, OUTCOME_SURVIVED)]
        if not verdicts:
            return False
        return verdicts[-1].outcome == OUTCOME_FALSIFIED

    def attempts(self, hypothesis: str) -> int:
        """How many times this hypothesis has been recorded at all (any outcome)."""

        return len(self.records_for(hypothesis))

    def outcome_of(self, hypothesis: str) -> str:
        recs = self.records_for(hypothesis)
        return recs[-1].outcome if recs else ""

    def families(self) -> dict[str, list[LedgerRecord]]:
        return group_by_family(self._records)

    def conclusion_for(self, family: str, *, min_members: int | None = None) -> ArchitecturalConclusion | None:
        """The architectural conclusion for one family, if it is supported yet."""

        mm = conclusion_min_members() if min_members is None else min_members
        return compose_conclusion(family, self._records, min_members=mm)

    def new_conclusions(self, *, min_members: int | None = None) -> list[ArchitecturalConclusion]:
        """Every family that just became closed and has NOT been emitted before.

        Emitting is recorded in the ledger itself, so a conclusion is announced once per
        engagement even across process restarts."""

        out: list[ArchitecturalConclusion] = []
        for family in self.families():
            if family in self._emitted_conclusions:
                continue
            conclusion = self.conclusion_for(family, min_members=min_members)
            if conclusion is None:
                continue
            self._emitted_conclusions.add(family)
            self.record(
                f"architectural conclusion emitted for variant class {family}",
                outcome=OUTCOME_CONCLUSION,
                family=family,
                note=conclusion.statement,
                agent="ledger",
            )
            out.append(conclusion)
        return out

    def write_conclusion(self, conclusion: ArchitecturalConclusion) -> str:
        """Persist a conclusion as a markdown artifact; returns its path ("" when not persisted)."""

        if self._dir is None or not conclusion.family:
            return ""
        slug = re.sub(r"[^a-z0-9]+", "-", conclusion.family.lower()).strip("-") or "class"
        target = self._dir / "conclusions" / f"{slug}.md"
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(conclusion.as_markdown(), encoding="utf-8")
        except OSError:
            return ""
        return str(target)

    def summary(self) -> dict:
        """Compact counts for the event log / operator view."""

        counts: dict[str, int] = {}
        for rec in self._records:
            counts[rec.outcome] = counts.get(rec.outcome, 0) + 1
        return {
            "records": len(self._records),
            "distinct_hypotheses": len({r.key for r in self._records if r.key}),
            "falsified": counts.get(OUTCOME_FALSIFIED, 0),
            "survived": counts.get(OUTCOME_SURVIVED, 0),
            "attempted": counts.get(OUTCOME_ATTEMPTED, 0),
            "families": len(self.families()),
            "conclusions": len(self._emitted_conclusions),
        }


def _as_float(value: object) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
