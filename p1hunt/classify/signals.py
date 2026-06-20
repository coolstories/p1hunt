"""Generic critical-impact detectors (spec §2.4 lenses).

These are *derivation primitives*, not a per-target playbook: each is a generic pattern
keyed to a critical-impact lens. They are applied to whatever artifacts were actually
acquired, so the surfaces and hypothesis seeds they produce are derived from the target
in front of us — never a hardcoded surface or hypothesis list for a specific program.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Signal:
    id: str
    title: str
    lens: str
    pattern: re.Pattern[str]
    rationale: str


# Lens vocabulary mirrors spec §2.4. Patterns are generic, not target-specific.
SIGNALS: tuple[Signal, ...] = (
    Signal(
        "authz-fail-open",
        "Authorization decision may fail open",
        "authorization-boundary",
        re.compile(
            r"return\s+true\s*;?\s*//\s*(todo|temporary|debug|fixme)"
            r"|if\s*\([^)]*(admin|owner|role|permission)[^)]*\)\s*{\s*return\s+true",
            re.IGNORECASE,
        ),
        "Authorization-sensitive code path appears to grant success without a complete check.",
    ),
    Signal(
        "idor-direct-object",
        "Direct object access may miss ownership/tenant check",
        "authorization-boundary",
        re.compile(
            r"(findUnique|findById|findOne|getObject)\s*\([^;\n]*(params\.id|query\.id|body\.id|req\.params)",
            re.IGNORECASE,
        ),
        "A user-controlled identifier is used without an adjacent ownership/tenant constraint.",
    ),
    Signal(
        "jwt-no-verify",
        "JWT may be trusted without signature verification",
        "authorization-boundary",
        re.compile(r"jwt\.decode|verify\s*:\s*false|algorithms\s*:\s*\[\s*[\"']none[\"']", re.IGNORECASE),
        "Token handling may accept unsigned or tampered identity claims.",
    ),
    Signal(
        "mass-assignment",
        "Mass assignment may set privileged fields",
        "authorization-boundary",
        re.compile(
            r"(create|update|save)\s*\([^;\n]*(req\.body|request\.body|body)[^;\n]*"
            r"(role|admin|isAdmin|owner|permissions|balance|tenantId|orgId)",
            re.IGNORECASE,
        ),
        "Request-controlled objects may write privileged fields without an allowlist.",
    ),
    Signal(
        "secret-in-source",
        "Credential appears hardcoded in source",
        "trusted-execution",
        re.compile(
            r"(private[_-]?key|api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][A-Za-z0-9_./+=-]{20,}[\"']",
            re.IGNORECASE,
        ),
        "An embedded credential can undermine signing, deployment, or service boundaries.",
    ),
    Signal(
        "command-injection",
        "User input may reach command execution",
        "trusted-execution",
        re.compile(
            r"(exec|execSync|spawn|system|popen|ProcessBuilder)\s*\([^;\n]*(req\.|params|query|body|argv|input)",
            re.IGNORECASE,
        ),
        "Untrusted input may flow into OS command execution.",
    ),
    Signal(
        "unsafe-deser",
        "Untrusted data may reach unsafe deserialization",
        "trusted-execution",
        re.compile(
            r"(pickle\.loads|yaml\.load\s*\(|ObjectInputStream|unserialize\s*\(|Marshal\.load"
            r"|eval\s*\([^;\n]*(req\.|params|query|body|input))",
            re.IGNORECASE,
        ),
        "Untrusted input may reach a deserializer or evaluator that constructs privileged objects.",
    ),
    Signal(
        "sql-injection",
        "Query construction may allow injection",
        "confidentiality",
        re.compile(
            r"((select|update|delete|insert)\s+[^;\n]*\$\{[^}]+}"
            r"|query\s*\([^;\n]*(\+|concat\()[^;\n]*(req\.|params|query|body))",
            re.IGNORECASE,
        ),
        "Queries assembled by interpolation from untrusted input can cross data boundaries.",
    ),
    Signal(
        "path-traversal",
        "User-controlled path may reach file access",
        "confidentiality",
        re.compile(
            r"(readFile|readFileSync|createReadStream|sendFile|open)\s*\([^;\n]*(req\.|params|query|body|filename|path)",
            re.IGNORECASE,
        ),
        "A file path may include user input without normalization and containment.",
    ),
    Signal(
        "ssrf",
        "User-controlled URL may be fetched by trusted server",
        "authorization-boundary",
        re.compile(r"(fetch|axios\.(get|post)|request|got)\s*\([^;\n]*(req\.|params|query|body|url)", re.IGNORECASE),
        "A server-side network client may accept an attacker-controlled destination.",
    ),
    Signal(
        "evm-tx-origin",
        "Contract authorization may rely on tx.origin",
        "asset-custody",
        re.compile(r"tx\.origin", re.IGNORECASE),
        "tx.origin auth can confuse the initiating wallet with the immediate caller.",
    ),
    Signal(
        "evm-delegatecall",
        "Powerful EVM primitive may be reachable",
        "trusted-execution",
        re.compile(r"(delegatecall\s*\(|selfdestruct\s*\(|suicide\s*\()", re.IGNORECASE),
        "delegatecall/selfdestruct can alter storage, control flow, or contract lifetime if reachable.",
    ),
    Signal(
        "ci-privileged-pr",
        "CI may expose privileged token to untrusted PRs",
        "trusted-execution",
        re.compile(
            r"(pull_request_target|permissions\s*:\s*write-all|GITHUB_TOKEN[^;\n]*(write|admin))",
            re.IGNORECASE,
        ),
        "Untrusted PR code combined with privileged tokens can affect supply-chain integrity.",
    ),
    Signal(
        "cloud-wildcard-iam",
        "Cloud policy may grant public/wildcard access",
        "confidentiality",
        re.compile(
            r"(\"Principal\"\s*:\s*\"\*\"|\"Action\"\s*:\s*\"\*\"|allUsers|public-read"
            r"|0\.0\.0\.0/0[^;\n]*(admin|ssh|rdp|database))",
            re.IGNORECASE,
        ),
        "Broad public or wildcard access near sensitive resources can expose data or privilege.",
    ),
    Signal(
        "invariant-comment",
        "Stated invariant may be violable",
        "business-logic",
        re.compile(r"(invariant|must\s+equal|should\s+never|assert\s*\()", re.IGNORECASE),
        "An explicitly stated invariant is a high-value target for a business-logic break.",
    ),
)

_SCAN_EXTS = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".java", ".kt", ".rb",
    ".php", ".cs", ".rs", ".sol", ".swift", ".yml", ".yaml", ".json", ".tf", ".toml",
    ".xml", ".env", ".conf", ".properties",
}

_IGNORE_DIRS = {"node_modules", ".git", ".next", "dist", "build", "vendor", "target", ".venv", ".p1hunt-poc"}


@dataclass
class SignalHit:
    signal: Signal
    file: str
    line: int
    snippet: str


def scan_artifacts(artifact_dir: str | Path, *, max_files: int = 800) -> list[SignalHit]:
    """Apply every generic detector to the acquired artifacts; return derived hits."""
    root = Path(artifact_dir)
    hits: list[SignalHit] = []
    scanned = 0
    if not root.exists():
        return hits
    for path in sorted(root.rglob("*")):
        if scanned >= max_files:
            break
        if not path.is_file() or path.suffix.lower() not in _SCAN_EXTS:
            continue
        # Only ignore build dirs *inside* the scan root — never the root's own ancestors.
        if any(part in _IGNORE_DIRS for part in path.relative_to(root).parts):
            continue
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for lineno, line in enumerate(text.splitlines(), start=1):
            for signal in SIGNALS:
                if signal.pattern.search(line):
                    hits.append(SignalHit(signal, rel, lineno, _redact(line.strip())))
    return hits


def _redact(snippet: str) -> str:
    return re.sub(
        r"([\"'])([A-Za-z0-9_./+=-]{8})([A-Za-z0-9_./+=-]{8,})([\"'])",
        r"\1\2...[redacted]\4",
        snippet,
    )
