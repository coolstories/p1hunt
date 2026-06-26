"""TargetClass from artifacts (spec §6 step 1).

Classification reads the *artifacts themselves* — file extensions, build files, manifest
contents — not a hardcoded per-target list. A Solidity repo, a C++ crypto library, an
APK, and a set of hosts each fall out to a different class, which is what makes the
downstream plan diverge (§6 acceptance).
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..models import Asset, Scope, TargetClass

_EVM_MARKERS = ("foundry.toml", "hardhat.config.js", "hardhat.config.ts", "truffle-config.js")
_CRYPTO_MARKERS = ("CMakeLists.txt", "configure.ac", "Cargo.toml")
_SUPPLY_MARKERS = (".github/workflows", "setup.py", "pyproject.toml", "package.json")


def classify_artifacts(artifact_dir: str | Path, scope: Scope | None = None) -> TargetClass:
    """Classify an acquired target snapshot directory.

    Signal precedence: explicit asset kinds (from scope) -> on-disk build markers ->
    file-extension census -> OTHER.
    """
    root = Path(artifact_dir)

    if scope is not None:
        if scope.dynamic_targets:
            return TargetClass.WEB_API
        by_asset = _from_assets(scope.in_scope)
        if by_asset is not None:
            return by_asset

    if not root.exists():
        return TargetClass.OTHER

    names = {p.name for p in root.rglob("*") if p.is_file()}
    rel = {str(p.relative_to(root)) for p in root.rglob("*")}

    if any(m in names for m in _EVM_MARKERS) or _has_ext(root, ".sol"):
        return TargetClass.EVM_CONTRACT
    if _has_ext(root, ".apk") or "AndroidManifest.xml" in names:
        return TargetClass.MOBILE_APP
    if any(m in names or m in rel for m in (".github/workflows",)) and not _has_ext(root, ".sol"):
        # a workflow dir alongside packaging files signals supply-chain
        if any(m in names for m in _SUPPLY_MARKERS):
            return TargetClass.SUPPLY_CHAIN
    if _has_ext(root, ".cpp", ".cc", ".hpp", ".h") and any(m in names for m in _CRYPTO_MARKERS):
        return TargetClass.CRYPTO_LIB

    census = _extension_census(root)
    if census.get(".sol", 0):
        return TargetClass.EVM_CONTRACT
    web = sum(census.get(ext, 0) for ext in (".ts", ".tsx", ".js", ".py", ".go", ".rb", ".php"))
    if web and _looks_like_web(root):
        return TargetClass.WEB_API
    if any(census.get(ext, 0) for ext in (".tf", ".yaml", ".yml")) and _looks_like_infra(root):
        return TargetClass.INFRA
    if web:
        return TargetClass.WEB_API
    return TargetClass.OTHER


def _from_assets(assets: list[Asset]) -> TargetClass | None:
    kinds = Counter(a.kind for a in assets)
    if kinds.get("contract"):
        return TargetClass.EVM_CONTRACT
    if kinds.get("apk"):
        return TargetClass.MOBILE_APP
    if kinds.get("package"):
        return TargetClass.SUPPLY_CHAIN
    if kinds.get("host") and not kinds.get("repo"):
        return TargetClass.INFRA
    return None


def _has_ext(root: Path, *exts: str) -> bool:
    for path in root.rglob("*"):
        if path.suffix.lower() in exts:
            return True
    return False


def _extension_census(root: Path) -> Counter:
    counter: Counter = Counter()
    for path in root.rglob("*"):
        if path.is_file():
            counter[path.suffix.lower()] += 1
    return counter


def _looks_like_web(root: Path) -> bool:
    needles = ("express", "fastify", "flask", "django", "router", "route", "request", "@app.")
    return _contains_any(root, needles)


def _looks_like_infra(root: Path) -> bool:
    needles = ('resource "aws_', "Principal", "iam_policy", "security_group", "0.0.0.0/0")
    return _contains_any(root, needles)


def _contains_any(root: Path, needles: tuple[str, ...], *, max_files: int = 200) -> bool:
    scanned = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in (
            ".ts", ".tsx", ".js", ".py", ".go", ".rb", ".php", ".tf", ".yaml", ".yml"
        ):
            continue
        scanned += 1
        if scanned > max_files:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(n in text for n in needles):
            return True
    return False
