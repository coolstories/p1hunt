"""The reasoner — pluggable "brain" behind every agent (spec §3, §10).

Agents are SDK sessions when credentials exist; in **dry-run** (the default, §13) a
deterministic reasoner stands in so the whole swarm — derivation, delegation, never-quit,
believe-but-verify, observability — runs and is testable without any live API call.

Believe-but-verify is enforced here and only here can an artifact be marked
``reproduced=True``. The deterministic reasoner only reproduces when the *actual code*
corroborates the claim; a stated invariant or a guarded sink is NOT enough. Persistence
(more creative paths over more rounds) raises corroboration depth — modelling a hunter
who keeps going — but the artifact floor is never bought with effort alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..classify.signals import SignalHit
from ..knowledge import SEVERITY_DEFAULT, SIGNAL_PROFILE as _SIGNAL_PROFILE
from ..models import ArtifactRef, Hypothesis, new_id

# Per-signal severity + base reproducibility is the CANONICAL table in knowledge.py (imported as
# _SIGNAL_PROFILE) so the scan view, the reasoner, and Parent A never drift. Critical signals can
# become P1 findings; the float is how strongly the bare signal corroborates impact before depth.

# Nearby tokens that indicate a compensating control — the Falsifier uses these to kill
# overclaims, and they lower reproduction score.
_MITIGATIONS = re.compile(
    r"sanitize|escape|allowlist|whitelist|parameteri[sz]ed|requireOwner|assertOwner"
    r"|ownerOnly|onlyOwner|verifyJwt|verifySignature|hasRole|checkPermission|zod\.|joi\.",
    re.IGNORECASE,
)

_REPRO_THRESHOLD = 0.70

# Hardened-aware detectors: high-value Solidity bug *classes* (classify/evm_signals.py) that
# survive on heavily-audited, assembly-heavy code. The OPTIMISTIC prior ("a P1 exists, find it")
# applies most here: on hardened EVM a nearby `require`/`onlyOwner`/`verifySignature` almost never
# means THIS low-level primitive is mitigated, so a guard token must NOT auto-kill the lead. It
# only lowers the score by a small, surmountable amount — persistence (deeper analysis over
# rounds) can still corroborate it. Generic web/cloud signals keep the strict kill-on-mitigation
# behaviour (those guards usually DO cover the sink), so false positives stay suppressed there.
_HARDENED_AWARE = frozenset({
    "evm-unchecked-call",
    "evm-bare-ecrecover",
    "evm-div-before-mul",
    "evm-raw-delegatecall",
    "evm-reentrancy-call",
})
# A guard token next to a hardened-EVM primitive is a soft signal, not a verdict.
_HARDENED_MITIGATION_PENALTY = 0.15


@dataclass
class Verdict:
    killed: bool
    reason: str


class Reasoner(Protocol):
    def validate(self, hyp: Hypothesis, hit: SignalHit, artifact_dir: str, depth: int) -> ArtifactRef | None: ...
    def falsify(self, hit: SignalHit, artifact_dir: str, depth: int) -> Verdict: ...
    def counterfactual(self, hit: SignalHit) -> str: ...
    def severity(self, hit: SignalHit) -> str: ...


class DeterministicReasoner:
    """Default dry-run brain. No network, no LLM, fully reproducible."""

    def severity(self, hit: SignalHit) -> str:
        return _SIGNAL_PROFILE.get(hit.signal.id, SEVERITY_DEFAULT)[0]

    def _score(self, hit: SignalHit, artifact_dir: str, depth: int) -> float:
        base = _SIGNAL_PROFILE.get(hit.signal.id, SEVERITY_DEFAULT)[1]
        corroboration = self._corroboration(hit, artifact_dir)
        # Persistence: each reframe/round adds analytical depth (capped), never aggression.
        depth_bonus = min(0.30, 0.12 * max(0, depth - 1))
        mitigation = self._mitigation_penalty(hit, artifact_dir)
        return base + 0.08 * corroboration + depth_bonus - mitigation

    def validate(
        self, hyp: Hypothesis, hit: SignalHit, artifact_dir: str, depth: int
    ) -> ArtifactRef | None:
        """Attempt safe reproduction. Returns a reproduced artifact ONLY on real corroboration."""
        score = self._score(hit, artifact_dir, depth)
        reproduced = score >= _REPRO_THRESHOLD
        if not reproduced:
            return None
        return ArtifactRef(
            id=new_id("art"),
            kind="repro",
            path=f"{hit.file}:{hit.line}",
            description=(
                f"Safe reproduction of '{hit.signal.title}' at {hit.file}:{hit.line} "
                f"(corroboration score {score:.2f}; environment "
                f"{hyp.safe_validation_plan.environment}). {hit.signal.rationale}"
            ),
            reproduced=True,
        )

    def falsify(self, hit: SignalHit, artifact_dir: str, depth: int) -> Verdict:
        """Adversarial pass with the opposite prior — try to kill the candidate (§10).

        On generic signals a compensating control near the sink kills the candidate outright
        (those guards usually cover the sink — keeps false positives down). On hardened-EVM
        detectors a nearby guard is NOT a kill: a low-level primitive class is rarely neutered by
        an adjacent check, so the lead persists and must be out-corroborated by depth instead of
        discarded — this is the "there IS a P1, find it" stance applied where it belongs."""
        hardened = hit.signal.id in _HARDENED_AWARE
        if not hardened and self._mitigation_penalty(hit, artifact_dir) > 0:
            return Verdict(True, "a compensating control is present near the sink")
        score = self._score(hit, artifact_dir, depth)
        if score < _REPRO_THRESHOLD:
            return Verdict(True, f"impact not corroborated (score {score:.2f} < {_REPRO_THRESHOLD})")
        return Verdict(False, "survives adversarial review: reachable, uncontrolled, critical impact")

    def counterfactual(self, hit: SignalHit) -> str:
        return (
            f"Before this bug, an actor cannot {self._capability(hit.signal.lens)}. "
            f"Because of it, a reachable actor can — crossing the {hit.signal.lens} boundary "
            f"at {hit.file}:{hit.line}."
        )

    # --- helpers ----------------------------------------------------------
    def _corroboration(self, hit: SignalHit, artifact_dir: str) -> int:
        """Count other distinct signal lenses present in the same file (related weakness)."""
        path = Path(artifact_dir) / hit.file
        if not path.exists():
            return 0
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return 0
        from ..classify.signals import SIGNALS  # local import to avoid cycle

        lenses = {s.lens for s in SIGNALS if s.id != hit.signal.id and s.pattern.search(text)}
        return len(lenses)

    def _mitigation_penalty(self, hit: SignalHit, artifact_dir: str) -> float:
        path = Path(artifact_dir) / hit.file
        if not path.exists():
            return 0.0
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return 0.0
        lo = max(0, hit.line - 4)
        hi = min(len(lines), hit.line + 3)
        window = "\n".join(lines[lo:hi])
        if not _MITIGATIONS.search(window):
            return 0.0
        # Hardened-EVM primitives: a nearby guard is a soft hint, not a neutralizer — keep the
        # lead alive (small penalty) so persistence can still confirm it. Generic sinks: the
        # adjacent control usually covers them, so the full penalty stands.
        return _HARDENED_MITIGATION_PENALTY if hit.signal.id in _HARDENED_AWARE else 0.5

    @staticmethod
    def _capability(lens: str) -> str:
        return {
            "authorization-boundary": "cross a privilege, tenant, or ownership boundary",
            "asset-custody": "move, freeze, or expose high-value assets",
            "trusted-execution": "influence trusted execution, signing, or release output",
            "confidentiality": "read sensitive data across users or tenants",
            "business-logic": "break a core accounting or settlement invariant",
            "availability-if-allowed": "degrade availability",
        }.get(lens, "cross a critical trust boundary")


def make_reasoner(run_mode: str = "dry_run") -> Reasoner:
    """Return the active reasoner. The SDK-backed brain is wired in when credentials exist;
    until then the deterministic reasoner keeps the swarm fully functional (§3, §13)."""
    if run_mode == "active":
        try:
            from .sdk_reasoner import SdkReasoner  # optional, requires claude-agent-sdk

            return SdkReasoner()
        except Exception:
            return DeterministicReasoner()
    return DeterministicReasoner()
