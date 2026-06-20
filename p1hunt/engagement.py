"""Engagement intake (spec §2.3, §15.1).

Creates the engagement folder before any testing begins, with program.md, scope.json,
target_snapshot.json, safety_policy.json, notes/, and artifacts/. If any record cannot be
created confidently — ambiguous or empty scope — the status becomes
``BLOCKED_NEEDS_HUMAN_SCOPE_DECISION`` and no tool call is attempted (§16).
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from .classify.classifier import classify_artifacts
from .models import Asset, DynamicTarget, EngagementStatus, Scope, TestIdentity
from .safety.policies import derive_scopeguard_policy


def _asset(d: dict) -> Asset:
    return Asset(
        id=d.get("id", ""),
        label=d.get("label", ""),
        kind=d.get("kind", d.get("type", "other")),
        value=d["value"],
        environment=d.get("environment", "unknown"),
    )


def _dynamic_target(d: dict) -> DynamicTarget:
    return DynamicTarget(
        base_url=d.get("base_url", ""),
        environment=d.get("environment", "uat"),
        kind=d.get("kind", "rest"),
        note=d.get("note", ""),
    )


def _identity(d: dict) -> TestIdentity:
    return TestIdentity(
        name=d.get("name", ""),
        token=d.get("token", ""),  # usually absent/redacted on disk — supplied via env at runtime
        token_env=d.get("token_env", ""),
        role=d.get("role", ""),
        note=d.get("note", ""),
    )


def scope_from_dict(d: dict) -> Scope:
    return Scope(
        program=d["program"],
        platform=d.get("platform", ""),
        disclosure_channel=d.get("disclosure_channel", ""),
        safe_harbor_text=d.get("safe_harbor_text", ""),
        severity_taxonomy=d.get("severity_taxonomy", {}),
        in_scope=[_asset(a) for a in d.get("in_scope", [])],
        out_of_scope=[_asset(a) for a in d.get("out_of_scope", [])],
        ambiguous=[_asset(a) for a in d.get("ambiguous", [])],
        rules=d.get("rules", []),
        rate_limit=d.get("rate_limit", ""),
        source_urls=d.get("source_urls", []),
        dynamic_targets=[_dynamic_target(t) for t in d.get("dynamic_targets", [])],
        test_identities=[_identity(i) for i in d.get("test_identities", [])],
    )


def scope_to_dict(scope: Scope) -> dict:
    return {
        "program": scope.program,
        "platform": scope.platform,
        "disclosure_channel": scope.disclosure_channel,
        "safe_harbor_text": scope.safe_harbor_text,
        "severity_taxonomy": scope.severity_taxonomy,
        "in_scope": [dataclasses.asdict(a) for a in scope.in_scope],
        "out_of_scope": [dataclasses.asdict(a) for a in scope.out_of_scope],
        "ambiguous": [dataclasses.asdict(a) for a in scope.ambiguous],
        "rules": scope.rules,
        "rate_limit": scope.rate_limit,
        "source_urls": scope.source_urls,
        "dynamic_targets": [dataclasses.asdict(t) for t in scope.dynamic_targets],
        # REDACT live credentials on disk: persist the env-var NAME, never the secret value. The
        # token is re-supplied via the environment at runtime (see TestIdentity.resolve).
        "test_identities": [
            {"name": i.name, "token": "<redacted>" if i.token else "",
             "token_env": i.token_env, "role": i.role, "note": i.note}
            for i in scope.test_identities
        ],
    }


@dataclasses.dataclass
class Engagement:
    id: str
    folder: Path
    scope: Scope
    artifact_dir: str
    status: EngagementStatus


def create_engagement(
    scope: Scope,
    artifact_dir: str,
    *,
    engagements_root: str = "engagements",
    engagement_id: str | None = None,
) -> Engagement:
    """Write the intake records and return the engagement with a computed status."""
    eng_id = engagement_id or scope.program.lower().replace(" ", "-")[:40] or "engagement"
    folder = Path(engagements_root) / eng_id
    (folder / "notes").mkdir(parents=True, exist_ok=True)
    (folder / "artifacts").mkdir(parents=True, exist_ok=True)

    status = _intake_status(scope)
    target_class = classify_artifacts(artifact_dir, scope)
    policy = derive_scopeguard_policy(scope, target_class)

    _write_program_md(folder / "program.md", scope, status)
    _write_json(folder / "scope.json", scope_to_dict(scope))
    _write_json(
        folder / "target_snapshot.json",
        {"artifact_dir": str(Path(artifact_dir).resolve()), "target_class": target_class.value},
    )
    _write_json(folder / "safety_policy.json", dataclasses.asdict(policy))

    return Engagement(
        id=eng_id, folder=folder, scope=scope, artifact_dir=artifact_dir, status=status
    )


def _intake_status(scope: Scope) -> EngagementStatus:
    if not scope.in_scope or scope.ambiguous:
        return EngagementStatus.BLOCKED_NEEDS_HUMAN_SCOPE_DECISION
    if not scope.safe_harbor_text or not scope.severity_taxonomy:
        return EngagementStatus.BLOCKED_NEEDS_HUMAN_SCOPE_DECISION
    return EngagementStatus.READY


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _write_program_md(path: Path, scope: Scope, status: EngagementStatus) -> None:
    lines = [
        f"# {scope.program}",
        "",
        f"- Platform: {scope.platform}",
        f"- Disclosure channel: {scope.disclosure_channel}",
        f"- Intake status: {status.value}",
        f"- Rate limit: {scope.rate_limit}",
        "",
        "## Safe harbor",
        "",
        scope.safe_harbor_text or "(missing — blocks intake)",
        "",
        "## Severity taxonomy (program's own)",
        "",
        *[f"- {k}: {v}" for k, v in scope.severity_taxonomy.items()],
        "",
        "## In scope",
        "",
        *[f"- {a.label}: `{a.value}` ({a.environment})" for a in scope.in_scope],
        "",
        "## Out of scope",
        "",
        *[f"- {a.label}: `{a.value}`" for a in scope.out_of_scope],
        "",
        "## Rules",
        "",
        *[f"- {r}" for r in scope.rules],
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
