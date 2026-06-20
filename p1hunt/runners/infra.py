"""Deterministic reproduction runner for the INFRA target class — cloud / IaC policy checks.

Gap this closes (spec §10, §1 NOTHING PRESET): for an infrastructure-as-code target the bug is a
PRESENT policy violation (a misconfigured resource, an over-broad IAM grant, a public bucket, an
unencrypted volume, ...). The believe-but-verify floor must not promote such a finding on the
model's say-so; it must run a real policy engine over the materialized harness and PARSE the
finding out of the engine's own JSON.

NOTHING PRESET: this runner is generic per TARGET CLASS. It does NOT know any product, resource
name, rule, or policy ahead of time. It DERIVES the toolchain from what was actually materialized
into the sandbox — a semgrep ruleset (``*.yml`` / ``*.yaml`` under the harness dir or named in
``spec.extra["rules"]``), an OPA/rego policy (``*.rego``), or a checkov-style directory scan — and
parses whatever rule ids / resources the engine flags as REAL coverage.

OFFLINE-GRACEFUL: if the chosen engine is absent, the harness is missing, or the process cannot
launch, the runner returns ``ran=False`` / ``reproduced=False`` (the finding stays a candidate).
Every subprocess is bounded by a timeout and the public ``run`` never raises.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from p1hunt.runners.base import (
    EventEmit,
    ReproResult,
    ReproSpec,
    excerpt,
    missing_harness_result,
    run_command,
    safe_harness_path,
)

# Tool selected per harness, keyed to the required external binary.
_TOOL_SEMGREP = "semgrep"
_TOOL_CONFTEST = "conftest"
_TOOL_CHECKOV = "checkov"


# ---------------------------------------------------------------------------
# Toolchain selection — derived from what the prover actually materialized.
# ---------------------------------------------------------------------------
def _rules_from_extra(spec: ReproSpec) -> list[str]:
    raw = spec.extra.get("rules") if isinstance(spec.extra, dict) else None
    if isinstance(raw, str):
        return [raw] if raw.strip() else []
    if isinstance(raw, (list, tuple)):
        return [str(r) for r in raw if str(r).strip()]
    return []


def select_tool(harness: Path, spec: ReproSpec) -> tuple[str, str]:
    """Choose the policy engine + the directory to scan from the materialized harness.

    Generic, class-level derivation only (NOTHING PRESET): semgrep when a YAML ruleset is present,
    conftest when a rego policy is present, checkov as the directory-scan fallback. Returns
    ``(tool, target_dir)``. ``spec.kind`` may force a tool when it names one of the engines.
    """
    base_dir = harness if harness.is_dir() else harness.parent
    target = str(base_dir)

    kind = (spec.kind or "").lower()
    if _TOOL_CONFTEST in kind or "rego" in kind or "opa" in kind:
        return _TOOL_CONFTEST, target
    if _TOOL_CHECKOV in kind:
        return _TOOL_CHECKOV, target
    if _TOOL_SEMGREP in kind:
        return _TOOL_SEMGREP, target

    # Otherwise derive from files present in/around the harness.
    if _rules_from_extra(spec):
        return _TOOL_SEMGREP, target
    try:
        if any(base_dir.glob("*.rego")):
            return _TOOL_CONFTEST, target
        if any(base_dir.glob("*.yml")) or any(base_dir.glob("*.yaml")):
            return _TOOL_SEMGREP, target
    except OSError:
        pass
    return _TOOL_CHECKOV, target


def _semgrep_config(harness: Path, spec: ReproSpec) -> str:
    """The ``--config`` argument for semgrep: explicit rules from extra win, else any YAML found."""
    explicit = _rules_from_extra(spec)
    if explicit:
        return explicit[0]
    base_dir = harness if harness.is_dir() else harness.parent
    try:
        for pat in ("*.yml", "*.yaml"):
            for rule in sorted(base_dir.glob(pat)):
                return str(rule)
    except OSError:
        pass
    return str(base_dir)


def build_argv(tool: str, harness: Path, spec: ReproSpec) -> list[str]:
    """Derive the fixed argv for the chosen engine — NEVER the model-supplied ``spec.command``."""
    base_dir = harness if harness.is_dir() else harness.parent
    target = str(base_dir)
    if tool == _TOOL_SEMGREP:
        return ["semgrep", "--error", "--json", "--config", _semgrep_config(harness, spec), target]
    if tool == _TOOL_CONFTEST:
        return ["conftest", "test", "--output", "json", target]
    return ["checkov", "-d", target, "-o", "json"]


# ---------------------------------------------------------------------------
# Pure parser — UNIT TESTED with real sample JSON from each engine.
# ---------------------------------------------------------------------------
def _loads(output: str) -> Any:
    """Tolerant JSON load: engines may print a banner before the JSON body."""
    text = (output or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    # Find the first balanced JSON object or array embedded in the output.
    for opener, closer in (("[", "]"), ("{", "}")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except (ValueError, TypeError):
                continue
    return None


def _semgrep_findings(doc: Any) -> tuple[list[str], list[str]]:
    """Return ``(rule_ids, resources)`` flagged by semgrep."""
    rule_ids: list[str] = []
    resources: list[str] = []
    results = doc.get("results") if isinstance(doc, dict) else None
    if isinstance(results, list):
        for r in results:
            if not isinstance(r, dict):
                continue
            rid = r.get("check_id") or r.get("rule_id")
            if rid:
                rule_ids.append(str(rid))
            path = r.get("path")
            if path:
                resources.append(str(path))
    return rule_ids, resources


def _conftest_findings(doc: Any) -> tuple[list[str], list[str], int]:
    """Return ``(messages, flagged_symbols, failure_count)`` from conftest's JSON array.

    A block's namespace/filename is recorded as a flagged symbol ONLY when that block actually
    failed — a clean block must not look like coverage of a violation.
    """
    messages: list[str] = []
    symbols: list[str] = []
    failures = 0
    blocks = doc if isinstance(doc, list) else ([doc] if isinstance(doc, dict) else [])
    for block in blocks:
        if not isinstance(block, dict):
            continue
        items = block.get("failures")
        block_failed = isinstance(items, list) and len(items) > 0
        if isinstance(items, list):
            for it in items:
                failures += 1
                if isinstance(it, dict):
                    msg = it.get("msg") or it.get("message")
                    if msg:
                        messages.append(str(msg))
                    meta = it.get("metadata")
                    rid = meta.get("rule") if isinstance(meta, dict) else None
                    if rid:
                        symbols.append(str(rid))
                elif isinstance(it, str):
                    messages.append(it)
        if block_failed:
            ns = block.get("namespace") or block.get("filename")
            if ns:
                symbols.append(str(ns))
    return messages, symbols, failures


def _checkov_findings(doc: Any) -> tuple[list[str], list[str]]:
    """Return ``(check_ids, resources)`` from checkov's failed_checks."""
    check_ids: list[str] = []
    resources: list[str] = []
    blocks = doc if isinstance(doc, list) else ([doc] if isinstance(doc, dict) else [])
    for block in blocks:
        if not isinstance(block, dict):
            continue
        results = block.get("results")
        failed = results.get("failed_checks") if isinstance(results, dict) else None
        if isinstance(failed, list):
            for f in failed:
                if not isinstance(f, dict):
                    continue
                cid = f.get("check_id")
                if cid:
                    check_ids.append(str(cid))
                res = f.get("resource")
                if res:
                    resources.append(str(res))
    return check_ids, resources


def parse_policy(output: str, exit_code: int, spec: ReproSpec, tool: str) -> dict:
    """Parse a policy engine's JSON into a deterministic verdict.

    For IaC the bug is a PRESENT violation, so ``reproduced`` is True when at least one matching
    violation/finding is parsed (the ``expect="pass"`` / "violation-present" semantics). When the
    prover instead set ``expect="fail"`` (invariant style — the policy MUST hold and a failure
    demonstrates the bug), a clean run with zero violations is what proves the bug.

    Returns ``{reproduced: bool, detail: str, coverage: dict}``. ``coverage["covered_symbols"]`` is
    the rule ids / resources the engine actually flagged.
    """
    doc = _loads(output)
    rule_ids: list[str] = []
    resources: list[str] = []
    messages: list[str] = []

    if tool == _TOOL_SEMGREP:
        rule_ids, resources = _semgrep_findings(doc)
        violation_count = len(rule_ids)
    elif tool == _TOOL_CONFTEST:
        # ``rule_ids`` holds the flagged symbols (rule names + failed namespaces); the violation
        # count is the real failure count so symbol enrichment never inflates it.
        messages, rule_ids, violation_count = _conftest_findings(doc)
    else:  # checkov
        rule_ids, resources = _checkov_findings(doc)
        violation_count = len(rule_ids)

    if doc is None:
        # No parseable JSON — we cannot assert anything; treat as no findings parsed.
        violation_count = 0

    covered: list[str] = []
    for sym in rule_ids + resources:
        if sym and sym not in covered:
            covered.append(sym)

    coverage: dict[str, Any] = {}
    if covered:
        coverage["covered_symbols"] = covered
    if rule_ids:
        coverage["rule_ids"] = sorted(set(rule_ids))
    if resources:
        coverage["resources"] = sorted(set(resources))
    coverage["violation_count"] = violation_count

    present = violation_count > 0
    # Honor the spec's outcome semantics. Default INFRA semantics: a present violation = bug.
    if spec.expects_fail():
        # 'fail' = the policy/invariant was expected to HOLD; a clean pass (no violation) proves
        # the bug, OR a non-zero engine exit with no parseable findings is inconclusive.
        reproduced = (doc is not None) and (not present)
        if reproduced:
            detail = "policy invariant held clean (no violations) — demonstrates the targeted gap"
        elif doc is None:
            detail = "no parseable policy output — engine produced no JSON; stays a candidate"
        else:
            detail = f"policy flagged {violation_count} violation(s); invariant did not hold clean"
    else:
        reproduced = present
        if reproduced:
            head = ", ".join((rule_ids or messages)[:5])
            detail = f"{tool} flagged {violation_count} violation(s): {head}"
        elif doc is None:
            detail = "no parseable policy output — engine produced no JSON; stays a candidate"
        else:
            detail = f"{tool} reported no matching violations"

    return {"reproduced": reproduced, "detail": detail, "coverage": coverage}


# ---------------------------------------------------------------------------
# Concrete runner.
# ---------------------------------------------------------------------------
class InfraRunner:
    """Executes a materialized IaC/cloud policy harness with a real policy engine and parses the
    finding deterministically (NOTHING PRESET: engine + target derived from the harness)."""

    name = "infra"

    def supports(self, target_class: str, subclass: str = "") -> bool:
        return (target_class or "").strip().upper() == "INFRA"

    def run(
        self,
        workdir: str,
        spec: ReproSpec,
        *,
        timeout: float = 600.0,
        on_event: EventEmit | None = None,
    ) -> ReproResult:
        harness = safe_harness_path(workdir, spec.harness_path)
        if harness is None:
            return missing_harness_result(
                spec, self.name, "policy harness missing or outside the workspace — stays a candidate"
            )

        tool = select_tool(harness, spec)[0]
        argv = build_argv(tool, harness, spec)

        ran, exit_code, output = run_command(
            argv,
            workdir,
            timeout=timeout,
            tools_required=(tool,),
            on_event=on_event,
            runner=self.name,
        )
        command = " ".join(argv)
        if not ran:
            return missing_harness_result(
                spec, self.name, f"policy engine '{tool}' unavailable — {excerpt(output, 200)}"
            )

        parsed = parse_policy(output, exit_code, spec, tool)
        return ReproResult(
            ran=True,
            reproduced=bool(parsed["reproduced"]),
            command=command,
            artifact_paths=[spec.harness_path] if spec.harness_path else [],
            stdout_excerpt=excerpt(output),
            coverage=parsed["coverage"],
            detail=parsed["detail"],
            runner=self.name,
        )
