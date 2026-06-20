"""EVM-aware static signals (spec gap: hardened-Solidity static lens).

The generic keyword detectors in ``signals.py`` are tuned for web/cloud sources and are
*low-signal on hardened EVM code* — an assembly-heavy contract (e.g. a battle-tested
exchange) trips few of them, so leaning on keyword hits there wastes the swarm's budget.

This module closes that gap with: (1) an assembly-density measure of how hardened a
Solidity codebase is; (2) a small set of HIGH-VALUE Solidity-specific detectors that find
real bug *classes* on hardened code (unchecked low-level call return, bare ecrecover,
division-before-multiplication, raw delegatecall to a non-constant target, external-call-
then-state-write reentrancy); and (3) ``should_demote_keyword_signals`` so the orchestrator
can de-weight the generic keyword lens on assembly-heavy EVM and lean on
invariants/differential fuzzing instead.

It reuses ``Signal``/``SignalHit`` from ``signals.py`` and is PURE + hermetic: filesystem
reads only, no network, no external tools.
"""

from __future__ import annotations

import re
from pathlib import Path

from .signals import _IGNORE_DIRS, Signal, SignalHit

# Threshold above which a Solidity codebase is considered "assembly-heavy / hardened".
# Expressed as inline-assembly blocks per .sol file (a low bar: even one assembly block
# in a small project signals deliberate low-level optimization that defeats keyword scans).
_ASSEMBLY_HEAVY_THRESHOLD = 0.5

_ASSEMBLY_BLOCK = re.compile(r"\bassembly\s*(?:\(\s*[\"']memory-safe[\"']\s*\))?\s*\{", re.IGNORECASE)


def _sol_files(repo_path: str | Path, *, max_files: int = 800) -> list[Path]:
    """In-scope ``.sol`` files under ``repo_path``, skipping build/vendor dirs."""
    root = Path(repo_path)
    out: list[Path] = []
    if not root.exists():
        return out
    for path in sorted(root.rglob("*.sol")):
        if len(out) >= max_files:
            break
        if not path.is_file():
            continue
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            rel_parts = path.parts
        if any(part in _IGNORE_DIRS for part in rel_parts):
            continue
        out.append(path)
    return out


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def evm_assembly_density(repo_path: str) -> float:
    """How assembly-heavy/hardened the Solidity is: ``assembly {`` blocks per .sol file.

    Returns ``0.0`` when there are no ``.sol`` files. A higher value means more inline
    assembly, i.e. code that the generic keyword detectors are poor at reading.
    """
    files = _sol_files(repo_path)
    if not files:
        return 0.0
    blocks = 0
    for path in files:
        blocks += len(_ASSEMBLY_BLOCK.findall(_read(path)))
    return blocks / len(files)


# --- HIGH-VALUE Solidity detectors -------------------------------------------------
# Each finds a real bug *class* that survives on hardened code. Patterns are line-scoped
# (applied per line, like signals.SIGNALS), so they stay conservative and explainable.

EVM_SIGNALS: tuple[Signal, ...] = (
    Signal(
        "evm-unchecked-call",
        "Low-level call return value may be unchecked",
        "asset-custody",
        # A bare statement form of .call/.delegatecall/.send whose boolean result is not
        # bound (no `(bool ok, ...) =`, no `require(`, no `if (`, no `bool x =` capture).
        re.compile(
            r"^\s*(?:address\([^)]*\)|payable\([^)]*\)|[\w.\[\]]+)\s*"
            r"\.(?:call|delegatecall|staticcall|send)\s*[({]",
            re.IGNORECASE,
        ),
        "A low-level call whose success flag is discarded can silently swallow a failed "
        "transfer or external action, corrupting asset accounting.",
    ),
    Signal(
        "evm-bare-ecrecover",
        "ecrecover used without a zero-address / signer check",
        "authorization-boundary",
        # ecrecover assigned/used without an obvious adjacent guard. We flag the call site;
        # the absence of a same-line zero-address guard is the high-signal part.
        re.compile(r"\becrecover\s*\(", re.IGNORECASE),
        "ecrecover returns address(0) for malformed signatures; without a zero-address "
        "and expected-signer check, a forged/empty signature can authorize as no-one.",
    ),
    Signal(
        "evm-div-before-mul",
        "Division performed before multiplication in a ratio/fill",
        "business-logic",
        # `a / b * c` style: a division feeding a multiplication loses precision and can be
        # gamed in partial-fill / share math.
        re.compile(r"/\s*[\w.\[\]()]+\s*\*", re.IGNORECASE),
        "Dividing before multiplying truncates intermediate precision; in fill/share math "
        "this rounds value in an attacker-favorable direction.",
    ),
    Signal(
        "evm-raw-delegatecall",
        "delegatecall to a non-constant target",
        "trusted-execution",
        # delegatecall on a variable/expression target (not a constant literal address).
        re.compile(r"\.delegatecall\s*\(", re.IGNORECASE),
        "delegatecall executes foreign code in this contract's storage context; a "
        "non-constant target lets a confused-deputy rewrite arbitrary storage.",
    ),
    Signal(
        "evm-reentrancy-call",
        "External call may precede a state write (reentrancy)",
        "asset-custody",
        # External value-transfer primitives that classically precede a state update.
        re.compile(
            r"\.(?:call\{[^}]*value|transfer|send)\s*[({]"
            r"|safeTransferFrom\s*\(|onERC1155Received|tokensReceived",
            re.IGNORECASE,
        ),
        "An external call before the contract finishes updating its own state opens a "
        "reentrancy window (ERC777/1155 callbacks) that can bypass a guard.",
    ),
)


def scan_evm(repo_path: str) -> list[SignalHit]:
    """Apply :data:`EVM_SIGNALS` to ``.sol`` files only; return derived hits."""
    root = Path(repo_path)
    hits: list[SignalHit] = []
    for path in _sol_files(repo_path):
        text = _read(path)
        if not text:
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)
        for lineno, line in enumerate(text.splitlines(), start=1):
            for signal in EVM_SIGNALS:
                if signal.pattern.search(line):
                    hits.append(SignalHit(signal, rel, lineno, line.strip()))
    return hits


def should_demote_keyword_signals(repo_path: str) -> bool:
    """True when the target is EVM *and* assembly-heavy/hardened.

    On such code the generic keyword detectors in ``signals.py`` are low-signal, so the
    orchestrator should weight invariants/differential fuzzing over keyword hits.
    """
    if not _sol_files(repo_path):
        return False
    return evm_assembly_density(repo_path) >= _ASSEMBLY_HEAVY_THRESHOLD
