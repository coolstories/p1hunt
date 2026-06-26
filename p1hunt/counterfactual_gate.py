"""Deterministic counterfactual gate for reproduced PoCs.

The runner proves existence: a harness compiled and produced the expected result. This
module checks the next question before a reproduced result can become P1 evidence:
did the harness demonstrate an attacker win against protected material or authority
the attacker does not control?

The checks are intentionally generic. They do not encode target names or bug classes;
they look for proof structure that should exist in any serious security PoC.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


_LOSS_TYPES = {"funds", "data", "control", "availability"}


@dataclass
class FindingClaim:
    """Severity schema the prover must fill before reproduced behavior earns severity.

    Empty fields are meaningful: they make the corresponding predicate fail. A vacuous
    PoC can still reproduce behavior, but it cannot honestly fill this schema.
    """

    attacker_model: str = ""
    attacker_controls: str = ""
    attacker_does_not_control: str = ""
    trust_boundary: str = ""
    honest_victim: str = ""
    honest_secret_or_resource: str = ""
    precommitted_value: str = ""
    victim_state_before: str = ""
    victim_state_after: str = ""
    absent_bug_expected_behavior: str = ""
    loss_type: str = ""
    exploit_path: str = ""

    @staticmethod
    def from_dict(d: dict | None) -> "FindingClaim":
        d = d or {}
        return FindingClaim(
            attacker_model=str(d.get("attacker_model", "") or "").strip(),
            attacker_controls=str(d.get("attacker_controls", "") or "").strip(),
            attacker_does_not_control=str(d.get("attacker_does_not_control", "") or "").strip(),
            trust_boundary=str(d.get("trust_boundary", "") or "").strip(),
            honest_victim=str(d.get("honest_victim", "") or "").strip(),
            honest_secret_or_resource=str(d.get("honest_secret_or_resource", "") or "").strip(),
            precommitted_value=str(d.get("precommitted_value", "") or "").strip(),
            victim_state_before=str(d.get("victim_state_before", "") or "").strip(),
            victim_state_after=str(d.get("victim_state_after", "") or "").strip(),
            absent_bug_expected_behavior=str(d.get("absent_bug_expected_behavior", "") or "").strip(),
            loss_type=str(d.get("loss_type", d.get("concrete_loss", "")) or "").strip().lower(),
            exploit_path=str(d.get("exploit_path", "") or "").strip(),
        )

    def to_dict(self) -> dict:
        return {
            "attacker_model": self.attacker_model,
            "attacker_controls": self.attacker_controls,
            "attacker_does_not_control": self.attacker_does_not_control,
            "trust_boundary": self.trust_boundary,
            "honest_victim": self.honest_victim,
            "honest_secret_or_resource": self.honest_secret_or_resource,
            "precommitted_value": self.precommitted_value,
            "victim_state_before": self.victim_state_before,
            "victim_state_after": self.victim_state_after,
            "absent_bug_expected_behavior": self.absent_bug_expected_behavior,
            "loss_type": self.loss_type,
            "exploit_path": self.exploit_path,
        }

    def predicates(self) -> dict[str, bool]:
        return {
            "realistic_attacker": bool(self.attacker_model and self.attacker_controls and self.trust_boundary),
            "honest_boundary": bool(
                self.honest_victim
                and self.honest_secret_or_resource
                and self.attacker_does_not_control
            ),
            "valuable_target": bool(self.precommitted_value),
            "victim_state_delta": bool(
                self.victim_state_before
                and self.victim_state_after
                and self.absent_bug_expected_behavior
                and self.loss_type in _LOSS_TYPES
            ),
        }


@dataclass
class CounterfactualGateResult:
    p1_ok: bool
    severity_band: str
    severity_predicates: dict[str, bool]
    finding_claim: dict
    has_concrete_loss: bool
    has_honest_secret_or_resource: bool
    has_authorization_boundary: bool
    self_controlled_setup: bool
    attacker_constructs_artifact: bool
    reason: str
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "p1_ok": self.p1_ok,
            "severity_band": self.severity_band,
            "severity_predicates": dict(self.severity_predicates),
            "finding_claim": dict(self.finding_claim),
            "has_concrete_loss": self.has_concrete_loss,
            "has_honest_secret_or_resource": self.has_honest_secret_or_resource,
            "has_authorization_boundary": self.has_authorization_boundary,
            "self_controlled_setup": self.self_controlled_setup,
            "attacker_constructs_artifact": self.attacker_constructs_artifact,
            "reason": self.reason,
            "notes": list(self.notes),
        }


def _read_rel(workspace: str, rel: str, *, max_bytes: int = 180_000) -> str:
    if not rel:
        return ""
    root = Path(workspace).resolve()
    p = (root / rel.split(":", 1)[0]).resolve()
    try:
        if p != root and not str(p).startswith(str(root) + "/"):
            return ""
        if not p.is_file():
            return ""
        return p.read_text(encoding="utf-8", errors="replace")[:max_bytes]
    except OSError:
        return ""


def _has(pattern: str, text: str) -> bool:
    return bool(re.search(pattern, text, re.I | re.S))


def _severity_band(predicates: dict[str, bool], *, p1_ok: bool, has_concrete_loss: bool) -> str:
    """Calibrate severity without forcing every failed-P1 proof to low.

    Critical requires all predicates. High is for reproduced behavior with a real honest boundary
    plus concrete victim delta, but one missing top-tier predicate. Medium has partial but material
    security evidence. Low is weak/self-contained behavior only.
    """
    if p1_ok:
        return "critical"
    if (
        has_concrete_loss
        and predicates.get("honest_boundary")
        and predicates.get("victim_state_delta")
        and (predicates.get("realistic_attacker") or predicates.get("valuable_target"))
    ):
        return "high"
    strong = sum(1 for ok in predicates.values() if ok)
    if has_concrete_loss and strong >= 2:
        return "medium"
    return "low"


def assess_counterfactual_proof(
    *,
    workspace: str,
    harness_paths: list[str],
    stdout_excerpt: str = "",
    detail: str = "",
    finding_text: str = "",
    concrete_loss: str = "",
    counterfactual: str = "",
    finding_claim: dict | None = None,
) -> CounterfactualGateResult:
    """Return whether a reproduced harness is strong enough for P1 promotion.

    This is a conservative guard. Failure does not mean the bug is false; it means the
    current artifact did not prove severity. Exploit-depth can still pursue the lead.
    """

    sources = [_read_rel(workspace, p) for p in harness_paths]
    text = "\n".join([*sources, stdout_excerpt, detail, finding_text, counterfactual]).lower()
    notes: list[str] = []

    claim = FindingClaim.from_dict(finding_claim)
    predicates = claim.predicates()
    missing_predicates = [name for name, ok in predicates.items() if not ok]

    loss = (claim.loss_type or concrete_loss or "").strip().lower()
    has_concrete_loss = loss in _LOSS_TYPES
    if not has_concrete_loss:
        notes.append("no structured concrete_loss in funds|data|control|availability")

    actor = r"(victim|honest|target|tenant|owner|admin|server|client|account|user|holder|defender)"
    protected = r"(secret|private|share|nonce|key|token|credential|session|authorization|permission|approval|balance|fund|asset|resource|state)"
    has_honest_secret_or_resource = (
        _has(actor + r"[^;\n]{0,120}" + protected, text)
        or _has(protected + r"[^;\n]{0,120}" + actor, text)
    )
    if has_honest_secret_or_resource:
        notes.append("proof mentions a protected honest/victim resource or secret")

    has_authorization_boundary = _has(
        r"(deny|denied|forbid|forbidden|unauthori[sz]ed|permission|policy|tenant|"
        r"on_start|prepare_for|authorize|authz|access control|caller)",
        text,
    )
    if has_authorization_boundary:
        notes.append("proof exercises an authorization or policy boundary")

    self_controlled_setup = _has(
        r"(attacker[_ -]?(scalar|share|secret|key|nonce|private)|"
        r"(attacker|malicious)[_a-z0-9 -]{0,60}(scalar|share|secret|key|nonce|private)|"
        r"fake[_ -]?(partial|share|player|party|signature|map)|"
        r"forged[_ -]?(source|partial|share|map|proof)|"
        r"zero[_ -]?(share|scalar|secret)|"
        r"zero[_a-z0-9 -]{0,60}(share|scalar|secret)|"
        r"one[_ -]?player|single[_ -]?player|caller[_ -]?controlled|"
        r"all[_ -]?(shares|partials|inputs|parties).{0,80}(attacker|harness|caller))",
        text,
    )
    if self_controlled_setup:
        notes.append("harness appears to supply attacker-controlled shares/secrets/partials")

    attacker_constructs_artifact = _has(
        r"(chosen[_ -]?(digest|message|hash)|"
        r"forge[ds]?[_ -]?(signature|sig|artifact)|"
        r"construct[sed]?[_ -]?(valid|signature|sig)|"
        r"pick[sed]?[_ -]?(u|v|r|s)|"
        r"self[_ -]?(signed|generated|verified))",
        text,
    )
    if attacker_constructs_artifact:
        notes.append("harness appears to construct or choose the verified artifact itself")

    schema_ok = all(predicates.values())
    p1_ok = (
        schema_ok
        and has_concrete_loss
        and (has_honest_secret_or_resource or has_authorization_boundary)
        and not (
            attacker_constructs_artifact
            and self_controlled_setup
            and not has_honest_secret_or_resource
        )
    )

    if p1_ok:
        reason = "all severity predicates pass: reproduced behavior defeats an honest protected boundary and causes a concrete victim-state delta"
    elif missing_predicates:
        reason = "severity schema incomplete; missing predicates: " + ", ".join(missing_predicates)
    elif self_controlled_setup and attacker_constructs_artifact:
        reason = "reproduced harness appears self-controlled: attacker/harness supplies the material and constructs the winning artifact"
    elif not (has_honest_secret_or_resource or has_authorization_boundary):
        reason = "reproduced harness does not show an honest-held protected resource/secret or authorization boundary"
    else:
        reason = "reproduced harness does not prove top-tier counterfactual impact"

    return CounterfactualGateResult(
        p1_ok=p1_ok,
        severity_band=_severity_band(predicates, p1_ok=p1_ok, has_concrete_loss=has_concrete_loss),
        severity_predicates=predicates,
        finding_claim=claim.to_dict(),
        has_concrete_loss=has_concrete_loss,
        has_honest_secret_or_resource=has_honest_secret_or_resource,
        has_authorization_boundary=has_authorization_boundary,
        self_controlled_setup=self_controlled_setup,
        attacker_constructs_artifact=attacker_constructs_artifact,
        reason=reason,
        notes=notes,
    )
