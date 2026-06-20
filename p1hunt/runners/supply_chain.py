"""SUPPLY_CHAIN reproduction runner — install/build-compromise verification (spec §10, §1).

The gap this closes: a supply-chain finding (malicious postinstall, dependency-confusion /
typosquat, unverified build artifact, exfil during install) can only be PROMOTED to a confirmed
critical when execution DEMONSTRATES the compromise — never on a model's say-so. This runner takes
a materialized harness (the install/build scripts the prover staged into the sandbox) and runs one
of two DETERMINISTIC modes against it:

  * ``static``  — runs a semgrep ruleset over the install/build surface (package.json scripts,
    setup.py, ``*.sh``, CI YAML) looking for malicious postinstall/build patterns, and parses the
    semgrep JSON for findings.
  * ``dynamic`` — runs the target's DECLARED build/install (``npm ci`` / ``npm run build`` /
    ``python setup.py build`` — derived from the harness, never from the model's command string)
    and parses the captured log for compromise indicators (network egress, writes outside the
    workspace, exfil patterns).

NOTHING PRESET: the mode and the argv are DERIVED from the observed harness + ``spec.kind`` at
runtime — there is no per-program playbook, no product name, no hardcoded endpoint. The indicator
vocabulary is class-level (generic supply-chain compromise signals), not per-target.

OFFLINE-GRACEFUL: semgrep / npm / python absent, harness missing, or the process unable to launch
all yield ``ran=False`` / ``reproduced=False`` (a candidate, never a false critical). Every
subprocess is bounded by a timeout and this module never raises out of a public function.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from p1hunt.runners.base import (
    EventEmit,
    ReproResult,
    ReproSpec,
    excerpt,
    missing_harness_result,
    run_command,
    safe_harness_path,
)

# Class-level (NOT per-target) compromise indicators scanned in a dynamic build/install log.
# Each is a generic supply-chain attack signal: exfil via curl/wget piped to a shell, raw socket
# egress, base64-decoded payload execution, writes outside the workspace, credential harvesting.
# Generic enough to fire on any program's compromised install — no product/endpoint literals.
_DYNAMIC_INDICATORS: tuple[tuple[str, str], ...] = (
    (r"\bcurl\b[^\n]*\|\s*(?:sh|bash|python|node)\b", "remote script piped to a shell during install"),
    (r"\bwget\b[^\n]*\|\s*(?:sh|bash|python|node)\b", "remote script piped to a shell during install"),
    (r"\bnc\b\s+-[^\n]*\d{2,5}", "raw netcat egress during install"),
    (r"/dev/tcp/", "raw TCP socket egress during install"),
    (r"base64\s+(?:-d|--decode)\b", "base64-decoded payload executed during install"),
    (r"\beval\s*\(\s*atob\s*\(", "obfuscated eval(atob(...)) payload during install"),
    (r"(?:exfil|exfiltrat)", "explicit exfiltration indicator in build log"),
    (r"(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|\.ssh/id_rsa|\.npmrc|\.env)\b",
     "credential/secret material read during install"),
    (r"EACCES[^\n]*(?:/etc/|/usr/|/root/|\$HOME)", "write attempt outside the workspace"),
    (r"dependency[- ]confusion", "dependency-confusion indicator in build log"),
    (r"typosquat", "typosquat indicator in build log"),
)

# semgrep finding metadata that marks a result as a supply-chain compromise. Class-level: any rule
# whose id/message/category names a malicious-script / dependency-confusion / typosquat / unverified
# artifact pattern counts. No per-rule allowlist baked in beyond these generic signals.
_STATIC_SIGNALS: tuple[str, ...] = (
    "postinstall", "preinstall", "install-script", "malicious", "exfil", "exfiltrat",
    "dependency-confusion", "dependency_confusion", "typosquat", "unverified", "untrusted",
    "supply-chain", "supply_chain", "obfuscat", "reverse-shell", "reverse_shell", "backdoor",
)

# Build/install entrypoints DERIVED from the materialized harness (file name / manifest present),
# mapped to the deterministic argv + the tool it requires. NOTHING PRESET: chosen by what the
# observed harness actually is, not by the target's identity.
_DYNAMIC_BUILDS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("setup.py", ("python", "setup.py", "build"), "python"),
    ("package.json", ("npm", "ci"), "npm"),
)


def _looks_like_finding(obj: dict) -> tuple[bool, str]:
    """Decide whether one semgrep result object is a supply-chain compromise + its label."""
    haystack_parts = [
        str(obj.get("check_id", "")),
        str(obj.get("rule_id", "")),
    ]
    extra = obj.get("extra")
    if isinstance(extra, dict):
        haystack_parts.append(str(extra.get("message", "")))
        meta = extra.get("metadata")
        if isinstance(meta, dict):
            haystack_parts.append(str(meta.get("category", "")))
            haystack_parts.append(" ".join(str(x) for x in (meta.get("cwe") or [])))
    hay = " ".join(haystack_parts).lower()
    for sig in _STATIC_SIGNALS:
        if sig in hay:
            return True, sig
    # A semgrep result with --error is still a real finding even if its label is unfamiliar.
    return bool(haystack_parts[0]), ""


def _parse_static(output: str, exit_code: int, spec: ReproSpec) -> dict:
    """Parse semgrep JSON for malicious install/build findings."""
    covered: list[str] = []
    findings: list[str] = []
    matched_signals: list[str] = []
    parsed_ok = False
    data: dict = {}
    try:
        data = json.loads(output)
        parsed_ok = isinstance(data, dict)
    except (ValueError, TypeError):
        parsed_ok = False

    if parsed_ok:
        results = data.get("results")
        if isinstance(results, list):
            for r in results:
                if not isinstance(r, dict):
                    continue
                path = str(r.get("path", "")).strip()
                if path and path not in covered:
                    covered.append(path)
                is_find, sig = _looks_like_finding(r)
                if is_find:
                    label = sig or str(r.get("check_id", "rule"))
                    findings.append(f"{path or '?'}: {label}")
                    if sig and sig not in matched_signals:
                        matched_signals.append(sig)
        # semgrep also reports scanned paths under paths.scanned
        paths = data.get("paths")
        if isinstance(paths, dict):
            for p in paths.get("scanned", []) or []:
                p = str(p).strip()
                if p and p not in covered:
                    covered.append(p)

    has_finding = bool(findings)
    # spec.expects_fail(): default 'fail' (an invariant/policy violation DEMONSTRATES the bug) ->
    # reproduced when a malicious finding exists. 'pass' (the clean-build assertion HELD) -> only
    # reproduced when the scan came back clean.
    if spec.expects_fail():
        reproduced = has_finding
    else:
        reproduced = parsed_ok and not has_finding

    if not parsed_ok:
        detail = "semgrep output was not parseable JSON — finding stays a candidate"
        reproduced = False
    elif has_finding:
        detail = "malicious install/build finding(s): " + "; ".join(findings[:8])
    else:
        detail = "semgrep scan clean — no malicious install/build pattern found"

    coverage: dict = {"covered_symbols": covered, "tool": "semgrep", "findings": len(findings)}
    if matched_signals:
        coverage["signals"] = matched_signals
    return {"reproduced": reproduced, "detail": detail, "coverage": coverage}


def _parse_dynamic(output: str, exit_code: int, spec: ReproSpec) -> dict:
    """Parse a build/install log for runtime compromise indicators."""
    text = output or ""
    hits: list[str] = []
    seen: set[str] = set()
    for pattern, label in _DYNAMIC_INDICATORS:
        if re.search(pattern, text, re.IGNORECASE):
            if label not in seen:
                seen.add(label)
                hits.append(label)

    # Scripts/deps inspected = the build entrypoints that appear in the log surface, plus any
    # script-name tokens the log echoes (npm prints "> pkg@ver postinstall"). Generic extraction.
    covered: list[str] = []
    for m in re.finditer(r">\s*[\w@./-]+\s+(\w[\w:-]*)\b", text):
        tok = m.group(1)
        if tok not in covered:
            covered.append(tok)
    for name in ("preinstall", "install", "postinstall", "prepare", "build"):
        if re.search(rf"\b{name}\b", text) and name not in covered:
            covered.append(name)

    has_indicator = bool(hits)
    if spec.expects_fail():
        reproduced = has_indicator
    else:
        # 'pass': the build is asserted clean; it reproduced (held) only if no indicator + success.
        reproduced = (not has_indicator) and exit_code == 0

    if has_indicator:
        detail = "compromise indicator(s) in build/install log: " + "; ".join(hits[:8])
    else:
        detail = "build/install log clean — no compromise indicator detected"

    coverage: dict = {"covered_symbols": covered, "tool": "build", "indicators": len(hits),
                      "exit_code": exit_code}
    if hits:
        coverage["matched"] = hits
    return {"reproduced": reproduced, "detail": detail, "coverage": coverage}


def parse_supply(output: str, exit_code: int, spec: ReproSpec, mode: str) -> dict:
    """PURE parser — turn raw tool output into ``{reproduced, detail, coverage}``.

    ``mode`` selects the parsing strategy: ``static`` (semgrep JSON) or ``dynamic`` (build log).
    ``reproduced`` honors ``spec.expects_fail()``: for the default ``expect='fail'`` a detected
    compromise/violation DEMONSTRATES the bug; for ``expect='pass'`` a clean build that HELD does.
    Never raises.
    """
    try:
        if (mode or "").strip().lower() == "static":
            return _parse_static(output, exit_code, spec)
        return _parse_dynamic(output, exit_code, spec)
    except Exception as exc:  # pragma: no cover — defensive; parser must never raise
        return {"reproduced": False, "detail": f"parse error: {exc}",
                "coverage": {"covered_symbols": []}}


class SupplyChainRunner:
    """Deterministic install/build-compromise runner for the SUPPLY_CHAIN target class."""

    name = "supply_chain"

    def supports(self, target_class: str, subclass: str = "") -> bool:
        return (target_class or "").upper() == "SUPPLY_CHAIN"

    # -- mode + argv derivation (NOTHING PRESET: from the harness + kind, never the target id) --
    def _mode(self, spec: ReproSpec, harness: Path) -> str:
        """Static when the kind/harness points at a ruleset scan; dynamic when at a build."""
        kind = (spec.kind or "").lower()
        if kind in ("static", "policy", "semgrep", "scan"):
            return "static"
        if kind in ("dynamic", "build", "install", "exploit", "call-sequence"):
            return "dynamic"
        # Infer from the harness: a *.yml/*.yaml/.semgrep ruleset, or an extra-declared ruleset,
        # means static; otherwise treat a manifest/build root as dynamic.
        suffix = harness.suffix.lower()
        if suffix in (".yml", ".yaml") or "semgrep" in harness.name.lower():
            return "static"
        if isinstance(spec.extra, dict) and spec.extra.get("rules"):
            return "static"
        return "dynamic"

    def _scan_target(self, harness: Path) -> Path:
        """The directory to scan/build: the harness dir, or the harness itself if it's a dir."""
        return harness if harness.is_dir() else harness.parent

    def _ruleset(self, spec: ReproSpec, harness: Path) -> str:
        """The semgrep --config value, derived from harness/extra. Defaults to semgrep's bundled
        security pack (``p/ci``) when none is materialized — class-level, not per-target."""
        if isinstance(spec.extra, dict):
            rules = spec.extra.get("rules") or spec.extra.get("config")
            if rules:
                # If a relative rules file was materialized, validate containment.
                rp = safe_harness_path(str(harness.parent.parent), str(rules)) if not str(rules).startswith("p/") else None
                return str(rp) if rp else str(rules)
        # A materialized YAML harness IS the ruleset.
        if harness.suffix.lower() in (".yml", ".yaml"):
            return str(harness)
        return "p/ci"

    def _static_argv(self, spec: ReproSpec, harness: Path) -> tuple[list[str], str, str]:
        rules = self._ruleset(spec, harness)
        target = self._scan_target(harness)
        argv = ["semgrep", "--error", "--json", "--config", rules, str(target)]
        return argv, "semgrep", "static"

    def _dynamic_argv(self, spec: ReproSpec, harness: Path) -> tuple[list[str], str, str] | None:
        """Derive the declared build/install argv from the materialized harness."""
        target_dir = self._scan_target(harness)
        # Honor a test_name that names a specific npm script (e.g. "build") -> npm run <script>.
        if spec.test_name and (target_dir / "package.json").exists():
            script = re.sub(r"[^\w:-]", "", spec.test_name)[:64]
            if script and script != "ci":
                return ["npm", "run", script], "npm", "dynamic"
        for marker, argv, tool in _DYNAMIC_BUILDS:
            if (target_dir / marker).exists() or harness.name == marker:
                return list(argv), tool, "dynamic"
        return None

    def run(self, workdir: str, spec: ReproSpec, *, timeout: float = 600.0,
            on_event: EventEmit | None = None) -> ReproResult:
        harness = safe_harness_path(workdir, spec.harness_path)
        if harness is None:
            return missing_harness_result(spec, self.name,
                                          "harness missing or outside the workspace")

        mode = self._mode(spec, harness)
        if mode == "static":
            argv, tool, mode = self._static_argv(spec, harness)
        else:
            derived = self._dynamic_argv(spec, harness)
            if derived is None:
                return missing_harness_result(
                    spec, self.name,
                    "no declared build/install entrypoint found in the harness")
            argv, tool, mode = derived

        target_dir = self._scan_target(harness)
        ran, exit_code, output = run_command(
            argv, str(target_dir), timeout=timeout, tools_required=(tool,),
            on_event=on_event, runner=self.name,
        )
        if not ran:
            return missing_harness_result(spec, self.name, output)

        parsed = parse_supply(output, exit_code, spec, mode)
        return ReproResult(
            ran=True,
            reproduced=bool(parsed.get("reproduced", False)),
            command=" ".join(argv),
            artifact_paths=[spec.harness_path] if spec.harness_path else [],
            stdout_excerpt=excerpt(output),
            coverage=parsed.get("coverage", {}) or {},
            detail=parsed.get("detail", ""),
            runner=self.name,
        )
