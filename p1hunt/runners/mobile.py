"""Mobile-app reproduction runner — the static trust-boundary verdict layer for MOBILE_APP.

GAP this closes: a mobile finding ("the app exposes an unguarded exported component", "it ships
debuggable", "it permits cleartext / pins nothing", "a secret is baked into resources", "backup is
allowed so local storage is extractable") used to rest on a Claude judgement. This runner replaces
that with a DETERMINISTIC static inspection of the materialized package manifest/resources: it
parses the real ``AndroidManifest.xml`` (or iOS ``Info.plist`` / extracted strings) and decides
whether the SPECIFIC insecure trust-boundary condition the spec targets is actually PRESENT.

Scope: STATIC only. Dynamic emulation (booting an emulator / instrumenting a running app) is out of
scope here — when no static evidence exists the finding stays a CANDIDATE (``ran``/``reproduced``
False), never a fabricated critical.

NOTHING PRESET (spec §1): there are NO per-app, per-package, or per-component literals. The runner
reasons only at the TARGET-CLASS level — generic Android/iOS manifest trust-boundary attributes
(``android:exported``, ``android:debuggable``, ``usesCleartextTraffic``, ``android:allowBackup``,
ATS ``NSAllowsArbitraryLoads``, embedded-secret material) — derived from the observed package at
runtime. Which condition matters is taken from the spec the prover produced, not a built-in playbook.

OFFLINE-GRACEFUL / HERMETIC: prefers ``apkanalyzer`` when present but otherwise reads the
already-extracted files in the workdir directly; if the tool is absent AND no manifest file is
materialized, it returns a structured "did not run" result. No network, no Claude, no emulator.
"""

from __future__ import annotations

import re
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
    tool_available,
)

# Manifest/plist file names a materialized mobile package commonly exposes (class-level, not
# per-app). The runner looks for any of these inside the workdir/harness when no apkanalyzer.
_MANIFEST_NAMES: tuple[str, ...] = (
    "AndroidManifest.xml",
    "Info.plist",
    "strings.xml",
)

# Generic trust-boundary condition keywords -> what the spec might target. Used only to MATCH the
# spec's intent against parsed evidence; never to assert a finding by itself.
_CONDITION_HINTS: dict[str, tuple[str, ...]] = {
    "exported": ("export", "component", "intent", "activity", "service", "receiver", "provider"),
    "debuggable": ("debug",),
    "cleartext": ("cleartext", "clear-text", "http", "tls", "ssl", "pin", "ats", "arbitrary"),
    "backup": ("backup", "allowbackup", "local storage", "extract"),
    "secret": ("secret", "key", "token", "credential", "apikey", "api_key", "password", "material"),
}

# Heuristic patterns for an embedded secret baked into resources/strings (generic shapes, not a
# per-app literal): long base64-ish blobs, AWS-style keys, bearer/jwt-ish tokens, private-key PEM.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"AKIA[0-9A-Z]{16}"),                                 # AWS access key id shape
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),  # embedded private key
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT shape
    re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[=:>\"']{1,3}\s*[A-Za-z0-9/+_-]{12,}"),
)


def _which_condition(spec: ReproSpec) -> str:
    """Derive which generic trust-boundary condition this spec targets, from its free-text fields
    (kind/test_name/extra/command — all advisory). Returns a canonical key from ``_CONDITION_HINTS``
    or "" when undetermined (then the parser reports any condition it can prove)."""
    hay = " ".join(
        str(x)
        for x in (
            spec.kind,
            spec.test_name,
            spec.command,
            spec.extra.get("condition", "") if isinstance(spec.extra, dict) else "",
            spec.extra.get("target", "") if isinstance(spec.extra, dict) else "",
        )
    ).lower()
    for cond, hints in _CONDITION_HINTS.items():
        if cond in hay:
            return cond
        if any(h in hay for h in hints):
            return cond
    return ""


def _attr(tag: str, name: str) -> str | None:
    """Extract attribute ``name`` from a raw XML/plist ``tag`` string (namespace-insensitive)."""
    m = re.search(rf"{re.escape(name)}\s*=\s*\"([^\"]*)\"", tag)
    return m.group(1) if m else None


def _truthy_xml(val: str | None) -> bool:
    return (val or "").strip().lower() in {"true", "1", "yes"}


# Components that cross a trust boundary when exported without a permission guard (generic Android
# component classes, not per-app names).
_COMPONENT_TAGS: tuple[str, ...] = ("activity", "service", "receiver", "provider", "activity-alias")


def _scan_exported_components(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Find Android components and decide which are an exported-with-no-guard trust-boundary hole.

    A component is a hole when it is exported (explicitly ``android:exported="true"``, or has an
    ``<intent-filter>`` which implicitly exports it) AND carries no ``android:permission`` guard.
    Returns ``(holes, inspected_names)`` where each hole is a small generic dict."""
    holes: list[dict[str, Any]] = []
    inspected: list[str] = []
    for tag_name in _COMPONENT_TAGS:
        # Match a full element (open+close) OR a self-closing element for this component type.
        pattern = re.compile(
            rf"<{tag_name}\b(?P<attrs>[^>]*?)(?:/>|>(?P<body>.*?)</{tag_name}>)",
            re.DOTALL | re.IGNORECASE,
        )
        for m in pattern.finditer(text):
            attrs = m.group("attrs") or ""
            body = m.group("body") or ""
            name = _attr(attrs, "android:name") or _attr(attrs, "name") or f"<{tag_name}>"
            inspected.append(name)
            exported_attr = _attr(attrs, "android:exported")
            has_intent_filter = bool(re.search(r"<intent-filter\b", body, re.IGNORECASE))
            if exported_attr is not None:
                exported = _truthy_xml(exported_attr)
            else:
                # Implicit export: a component with an intent-filter and no explicit flag is exported.
                exported = has_intent_filter
            if not exported:
                continue
            guarded = (
                _attr(attrs, "android:permission") is not None
                or _attr(attrs, "permission") is not None
            )
            if not guarded:
                holes.append(
                    {
                        "component": name,
                        "type": tag_name,
                        "exported": "explicit" if exported_attr is not None else "implicit",
                        "guarded": False,
                    }
                )
    return holes, inspected


def parse_mobile(manifest_or_output: str, spec: ReproSpec) -> dict:
    """PURE parser: given raw manifest/plist/strings text (from apkanalyzer or extracted files) and
    the targeted spec, decide whether the SPECIFIC insecure trust-boundary condition is present and
    exploitable.

    Returns ``{reproduced, detail, coverage}``. ``coverage["covered_symbols"]`` lists the manifest
    entries/components actually inspected. Honors ``spec.expects_fail()``:

    * expect="fail" (property/invariant style): the targeted insecure condition being PRESENT is the
      broken invariant -> ``reproduced=True`` when the hole exists.
    * expect="pass" (exploit-assertion style): the exploit (presence of the hole) HOLDING is the
      demonstration -> also ``reproduced=True`` when the hole exists.

    Either way, the condition must actually be observable in the static evidence; absence/hardening
    yields ``reproduced=False``."""
    text = manifest_or_output or ""
    cond = _which_condition(spec)
    covered: list[str] = []
    evidence: list[str] = []

    # --- Exported component with no permission guard -------------------------------------------
    comp_holes, comp_inspected = _scan_exported_components(text)
    covered.extend(comp_inspected)

    # --- android:debuggable="true" ------------------------------------------------------------
    debuggable = False
    app_m = re.search(r"<application\b([^>]*)>", text, re.IGNORECASE)
    if app_m:
        covered.append("application")
        debuggable = _truthy_xml(_attr(app_m.group(1), "android:debuggable"))
        if _truthy_xml(_attr(app_m.group(1), "android:debuggable")):
            evidence.append('application android:debuggable="true"')

    # --- Cleartext traffic permitted / arbitrary loads (Android usesCleartextTraffic + iOS ATS) -
    cleartext = False
    if app_m and _truthy_xml(_attr(app_m.group(1), "android:usesCleartextTraffic")):
        cleartext = True
        evidence.append('application android:usesCleartextTraffic="true"')
    # network_security_config-style / plist: arbitrary loads / cleartextTrafficPermitted true.
    if re.search(r"cleartextTrafficPermitted\s*=\s*\"true\"", text, re.IGNORECASE):
        cleartext = True
        covered.append("cleartextTrafficPermitted")
        evidence.append('cleartextTrafficPermitted="true"')
    if re.search(r"NSAllowsArbitraryLoads", text):
        # iOS ATS: <key>NSAllowsArbitraryLoads</key><true/>
        m = re.search(r"NSAllowsArbitraryLoads\s*</key>\s*<\s*(true)\s*/?\s*>", text, re.IGNORECASE)
        covered.append("NSAllowsArbitraryLoads")
        if m:
            cleartext = True
            evidence.append("NSAllowsArbitraryLoads=true (ATS disabled)")

    # --- android:allowBackup="true" (local storage extractable) --------------------------------
    backup = False
    if app_m and _truthy_xml(_attr(app_m.group(1), "android:allowBackup")):
        backup = True
        evidence.append('application android:allowBackup="true"')

    # --- Embedded secret/material in resources/strings -----------------------------------------
    secret_hits: list[str] = []
    for pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            frag = m.group(0)
            secret_hits.append(frag[:24] + ("…" if len(frag) > 24 else ""))
    if secret_hits:
        covered.append("resources/strings")

    # Map each canonical condition to (present, human detail).
    present: dict[str, tuple[bool, str]] = {
        "exported": (
            bool(comp_holes),
            "exported component(s) with no permission guard: "
            + ", ".join(h["component"] for h in comp_holes),
        ),
        "debuggable": (debuggable, "app ships android:debuggable=\"true\""),
        "cleartext": (cleartext, "; ".join(e for e in evidence if "clear" in e.lower()
                                            or "arbitrary" in e.lower() or "ATS" in e)
                                 or "cleartext / arbitrary network traffic permitted"),
        "backup": (backup, "app allows backup (android:allowBackup=\"true\") — local storage extractable"),
        "secret": (bool(secret_hits), "secret material embedded in resources: " + ", ".join(secret_hits)),
    }

    # Decide which condition(s) demonstrate the targeted bug.
    if cond:
        is_present, why = present.get(cond, (False, ""))
        targeted = [(cond, is_present, why)]
    else:
        # No explicit target -> any provable insecure condition demonstrates it.
        targeted = [(k, v[0], v[1]) for k, v in present.items()]

    hit = next(((k, why) for (k, p, why) in targeted if p), None)

    # de-dup covered while preserving order
    seen: set[str] = set()
    covered_unique = [c for c in covered if not (c in seen or seen.add(c))]
    coverage = {
        "covered_symbols": covered_unique,
        "components_inspected": len(comp_inspected),
        "exported_holes": len(comp_holes),
    }

    if hit is None:
        target_desc = cond or "any insecure trust-boundary condition"
        return {
            "reproduced": False,
            "detail": (
                f"static inspection found no exploitable trust-boundary condition for "
                f"'{target_desc}'; package appears hardened for the targeted property"
            ),
            "coverage": coverage,
        }

    cond_name, why = hit
    # reproduced is True for BOTH expect modes when the insecure condition is statically proven:
    # for expect='fail' the present hole IS the broken invariant; for expect='pass' the exploit
    # (the hole) holds. The static demonstration is identical; we record the framing in detail.
    framing = "broken invariant" if spec.expects_fail() else "exploit assertion held"
    return {
        "reproduced": True,
        "detail": f"[{cond_name}] {why} ({framing})",
        "coverage": coverage,
    }


def _read_materialized_manifest(workdir: str, spec: ReproSpec) -> tuple[str, list[str]]:
    """Read manifest/plist/strings text from the materialized harness or workdir (no tool needed).

    Returns ``(text, artifact_paths)``. ``text`` is the concatenation of any manifest-class files
    found (so a single parse sees Android manifest + network config + iOS plist together). Empty
    string when nothing materialized."""
    parts: list[str] = []
    artifacts: list[str] = []

    # 1) If the harness_path itself points at a readable manifest/file, use it (containment-checked).
    hp = safe_harness_path(workdir, spec.harness_path)
    candidates: list[Path] = []
    if hp is not None:
        if hp.is_file():
            candidates.append(hp)
        elif hp.is_dir():
            for name in _MANIFEST_NAMES:
                candidates.extend(sorted(hp.rglob(name)))

    # 2) Otherwise scan the workdir for the class-level manifest names.
    if not candidates:
        root = Path(workdir)
        if root.is_dir():
            for name in _MANIFEST_NAMES:
                candidates.extend(sorted(root.rglob(name)))

    seen: set[str] = set()
    for path in candidates:
        try:
            rp = str(path.resolve())
        except OSError:
            continue
        if rp in seen:
            continue
        seen.add(rp)
        try:
            parts.append(path.read_text(encoding="utf-8", errors="ignore"))
            artifacts.append(rp)
        except OSError:
            continue
    return "\n".join(parts), artifacts


class MobileRunner:
    """Static reproduction runner for MOBILE_APP packages (Android APK / iOS IPA).

    Prefers ``apkanalyzer manifest print <apk>`` when both the tool and an ``.apk`` are present;
    otherwise reads already-extracted manifest/plist/strings files from the workdir directly. The
    verdict is computed by the pure :func:`parse_mobile`."""

    name = "mobile"

    def supports(self, target_class: str, subclass: str = "") -> bool:
        return (target_class or "").strip().upper() == "MOBILE_APP"

    def _find_apk(self, workdir: str, spec: ReproSpec) -> Path | None:
        """Locate a materialized ``.apk`` (containment-checked) for apkanalyzer, if any."""
        hp = safe_harness_path(workdir, spec.harness_path)
        if hp is not None:
            if hp.is_file() and hp.suffix.lower() == ".apk":
                return hp
            if hp.is_dir():
                apks = sorted(hp.rglob("*.apk"))
                if apks:
                    return apks[0]
        root = Path(workdir)
        if root.is_dir():
            apks = sorted(root.rglob("*.apk"))
            if apks:
                return apks[0]
        return None

    def run(
        self,
        workdir: str,
        spec: ReproSpec,
        *,
        timeout: float = 600.0,
        on_event: EventEmit | None = None,
    ) -> ReproResult:
        apk = self._find_apk(workdir, spec)
        use_tool = apk is not None and tool_available("apkanalyzer")

        manifest_text = ""
        artifacts: list[str] = []
        command = ""
        stdout = ""

        if use_tool:
            argv = ["apkanalyzer", "manifest", "print", str(apk)]
            command = " ".join(argv)
            ran, exit_code, output = run_command(
                argv,
                cwd=workdir,
                timeout=timeout,
                tools_required=("apkanalyzer",),
                on_event=on_event,
                runner=self.name,
            )
            if not ran:
                return missing_harness_result(
                    spec, self.name, "apkanalyzer not available — finding stays a candidate"
                )
            manifest_text = output
            stdout = output
            artifacts = [str(apk)]
        else:
            manifest_text, artifacts = _read_materialized_manifest(workdir, spec)
            stdout = manifest_text
            command = "(static read of materialized manifest/plist/strings — no toolchain)"

        if not manifest_text.strip():
            return missing_harness_result(
                spec,
                self.name,
                "no apkanalyzer and no materialized manifest/plist/strings in workdir — "
                "static reproduction did not run; finding stays a candidate",
            )

        parsed = parse_mobile(manifest_text, spec)
        return ReproResult(
            ran=True,
            reproduced=bool(parsed.get("reproduced", False)),
            command=command,
            artifact_paths=artifacts or ([spec.harness_path] if spec.harness_path else []),
            stdout_excerpt=excerpt(stdout),
            coverage=parsed.get("coverage", {}) or {},
            detail=parsed.get("detail", ""),
            runner=self.name,
        )
