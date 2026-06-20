"""build_env — controlled build-environment bootstrap for the audit target (spec gap:
build-environment bootstrap).

The unblocker. Differential/invariant fuzzers and PoC provers produce nothing until the
target actually *compiles* — a hardened Solidity project (Foundry + git submodules) must be
provisioned (submodules fetched, deps installed) and built green before any harness can
deploy it. This module:

  * ``detect_build_system`` — PURE filesystem read that classifies the toolchain and the
    exact provisioning + build commands a target needs (foundry/hardhat/npm/cargo/go/make/
    cmake), with no execution.
  * ``summarize_build_output`` — PURE parser that turns raw forge/hardhat/cargo output into
    ``{compiled, errors, warnings}`` so callers can decide green/red without re-running.
  * ``toolchain_available`` — ``shutil.which`` probe.
  * ``bootstrap_environment`` — a CONTROLLED, logged provisioning step (separate from the
    agent bash filter): it runs ONLY commands from an internal allowlist of provisioning
    verbs, each emitted via ``on_event`` and bounded by a timeout. It NEVER raises out of
    the public surface and NEVER hangs; absent toolchains and subprocess failures come back
    as a structured ``BuildReport`` with diagnostics + remediation.

OFFLINE-GRACEFUL + HERMETIC: importing this module and running its unit tests needs no
network, no forge/anvil/git/npm/cargo. Every subprocess call passes a timeout and is
guarded; a missing tool yields ``attempted=False`` + remediation rather than an exception.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# (agent, kind, data) — mirrors EventEmit in agents/claude_session.py so wiring is thin.
EventEmit = Callable[[str, str, dict], None]


@dataclass
class BuildPlan:
    """How a target is provisioned and built — derived purely from its files."""

    toolchain: str  # foundry|hardhat|cargo|go|npm|make|cmake|unknown
    provision_commands: list[str] = field(default_factory=list)
    build_command: str = ""
    config_files: list[str] = field(default_factory=list)
    solc_version: str = ""
    needs_network: bool = False


@dataclass
class BuildReport:
    """Outcome of a bootstrap attempt — always structured, never an exception."""

    toolchain: str
    compiles: bool = False
    attempted: bool = False
    commands_run: list[str] = field(default_factory=list)
    diagnostics: str = ""
    remediation: str = ""
    toolchain_missing: list[str] = field(default_factory=list)


# Provisioning allowlist — the ONLY shapes bootstrap_environment will execute. This is a
# controlled audit-target provisioner, deliberately narrower than the agent bash filter:
# nothing here can broadcast, exfiltrate, or escape the repo. Each entry is matched by exact
# token prefix so e.g. "forge build" cannot smuggle "; rm -rf /".
_PROVISION_ALLOWLIST: tuple[tuple[str, ...], ...] = (
    ("git", "submodule", "update", "--init", "--recursive"),
    ("forge", "install"),
    ("forge", "build"),
    ("npm", "ci"),
    ("npm", "install"),
    ("npx", "hardhat", "compile"),
    ("cargo", "fetch"),
    ("cargo", "build"),
    ("go", "build", "./..."),
    ("make",),
    ("cmake", "-S", ".", "-B", "build"),   # CMake configure (out-of-source)
    ("cmake", "--build", "build"),          # CMake build
)

_REMEDIATION_FOUNDRY = "install foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"
_REMEDIATION_GIT = "install git (e.g. xcode-select --install or your package manager)"
_REMEDIATION_NODE = "install node + npm (https://nodejs.org) then re-run npm ci"
_REMEDIATION_CARGO = "install rust toolchain: curl https://sh.rustup.rs -sSf | sh"
_REMEDIATION_GO = "install go (https://go.dev/dl) then re-run go build ./..."
_REMEDIATION_MAKE = "install make/build tools for this platform"


# ---------------------------------------------------------------------------
# PURE detection (filesystem read only)
# ---------------------------------------------------------------------------
def _exists(repo: Path, *names: str) -> list[str]:
    return [n for n in names if (repo / n).exists()]


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _parse_solc_version(repo: Path, config_files: list[str]) -> str:
    """Best-effort solc version from foundry.toml / hardhat config / a pragma. Generic — no
    target-specific assumptions."""
    import re

    for name in config_files:
        text = _read_text(repo / name)
        if not text:
            continue
        m = re.search(r"solc(?:_version|\s*version)?\s*[:=]\s*['\"]?v?([0-9]+\.[0-9]+\.[0-9]+)", text, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"version\s*:\s*['\"]v?([0-9]+\.[0-9]+\.[0-9]+)['\"]", text)
        if m:
            return m.group(1)
    # Fall back to the first pragma we can find in a shallow scan of src/contracts.
    for sub in ("src", "contracts", "."):
        base = repo / sub if sub != "." else repo
        if not base.is_dir():
            continue
        for sol in sorted(base.glob("*.sol"))[:8]:
            m = re.search(r"pragma\s+solidity\s+[^;]*?([0-9]+\.[0-9]+\.[0-9]+)", _read_text(sol))
            if m:
                return m.group(1)
    return ""


def detect_build_system(repo_path: str) -> BuildPlan:
    """Classify the toolchain and derive provisioning + build commands — PURE, no execution.

    Detection order favors the most specific/authoritative marker. Foundry wins over a bare
    hardhat/npm marker when ``foundry.toml`` is present (hardened Solidity targets often carry
    a package.json too). Network need is set when the target has submodules or a manifest that
    must fetch dependencies.
    """
    repo = Path(repo_path)
    if not repo.is_dir():
        return BuildPlan(toolchain="unknown")

    has_gitmodules = (repo / ".gitmodules").exists()
    has_lib = (repo / "lib").is_dir()

    # --- Foundry: foundry.toml is authoritative; remappings.txt / lib/ corroborate.
    foundry_cfgs = _exists(repo, "foundry.toml", "remappings.txt")
    if "foundry.toml" in foundry_cfgs or (has_lib and (repo / "remappings.txt").exists()):
        cfgs = [c for c in ("foundry.toml", "remappings.txt") if (repo / c).exists()]
        if has_gitmodules:
            cfgs.append(".gitmodules")
        provision: list[str] = []
        # Submodule deps must be fetched before forge build, or imports fail to resolve.
        if has_gitmodules or has_lib:
            provision.append("git submodule update --init --recursive")
        provision.append("forge install")
        return BuildPlan(
            toolchain="foundry",
            provision_commands=provision,
            build_command="forge build",
            config_files=cfgs,
            solc_version=_parse_solc_version(repo, ["foundry.toml"]),
            needs_network=True,  # submodules / forge install reach the network
        )

    # --- Hardhat: a hardhat config (+ package.json) drives npm install then hardhat compile.
    hardhat_cfgs = _exists(repo, "hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs")
    if hardhat_cfgs:
        cfgs = list(hardhat_cfgs)
        pkg = _exists(repo, "package.json")
        cfgs.extend(pkg)
        lock = _exists(repo, "package-lock.json", "yarn.lock", "pnpm-lock.yaml")
        provision = ["npm ci" if "package-lock.json" in lock else "npm install"]
        return BuildPlan(
            toolchain="hardhat",
            provision_commands=provision,
            build_command="npx hardhat compile",
            config_files=cfgs + lock,
            solc_version=_parse_solc_version(repo, list(hardhat_cfgs)),
            needs_network=True,
        )

    # --- Cargo (Rust).
    if (repo / "Cargo.toml").exists():
        return BuildPlan(
            toolchain="cargo",
            provision_commands=["cargo fetch"],
            build_command="cargo build",
            config_files=_exists(repo, "Cargo.toml", "Cargo.lock"),
            needs_network=True,  # cargo fetch resolves crates over the network
        )

    # --- Go.
    if (repo / "go.mod").exists():
        return BuildPlan(
            toolchain="go",
            provision_commands=[],
            build_command="go build ./...",
            config_files=_exists(repo, "go.mod", "go.sum"),
            needs_network=True,  # module resolution may fetch
        )

    # --- npm / node (no hardhat): package.json drives install + (best-effort) build.
    if (repo / "package.json").exists():
        lock = _exists(repo, "package-lock.json", "yarn.lock", "pnpm-lock.yaml")
        provision = ["npm ci" if "package-lock.json" in lock else "npm install"]
        return BuildPlan(
            toolchain="npm",
            provision_commands=provision,
            build_command="npm run build",
            config_files=["package.json"] + lock,
            needs_network=True,
        )

    # --- CMake before Make (a CMake project often ships a generated Makefile too).
    if (repo / "CMakeLists.txt").exists():
        # Provision = (fetch submodules if any) then CONFIGURE out-of-source; build = compile that
        # tree. Without the configure step `cmake --build` has nothing to build. Submodules /
        # FetchContent dependencies reach the network, so flag it when submodules are present.
        provision = []
        if has_gitmodules:
            provision.append("git submodule update --init --recursive")
        provision.append("cmake -S . -B build")
        return BuildPlan(
            toolchain="cmake",
            provision_commands=provision,
            build_command="cmake --build build",
            config_files=["CMakeLists.txt"] + ([".gitmodules"] if has_gitmodules else []),
            needs_network=has_gitmodules,
        )

    # --- Make.
    makefiles = _exists(repo, "Makefile", "makefile", "GNUmakefile")
    if makefiles:
        return BuildPlan(
            toolchain="make",
            provision_commands=[],
            build_command="make",
            config_files=makefiles,
            needs_network=False,
        )

    return BuildPlan(toolchain="unknown")


# ---------------------------------------------------------------------------
# PURE output parsing
# ---------------------------------------------------------------------------
def summarize_build_output(text: str, toolchain: str) -> dict:
    """Parse raw build output into ``{compiled, errors, warnings}`` — PURE.

    Heuristics are per-toolchain but deliberately conservative: an ``error`` line or an
    explicit failure marker means ``compiled=False``; a clean success marker (and no error
    line) means ``compiled=True``. Unknown/empty output is treated as not-compiled so callers
    never report a false green.
    """
    import re

    result = {"compiled": False, "failed": False, "errors": [], "warnings": 0}
    if not text:
        return result

    lines = text.splitlines()
    errors: list[str] = []
    warnings = 0
    tc = (toolchain or "").lower()

    # Generic warning count works across forge/hardhat/cargo.
    warnings = len(re.findall(r"(?im)^\s*(warning)\b", text)) or len(re.findall(r"(?i)\bwarning[:s]", text))

    if tc in ("foundry", "hardhat"):
        # Solidity compilers print "Error (NNNN):" / "Error:" / "CompilerError"; forge prints
        # "Compiler run successful" on green, "Compilation failed" on red, and — when artifacts
        # are already current (cache-warm: very common after a submodule fetch or on resume) —
        # "No files changed, compilation skipped" with NO success marker. Treat that skip marker
        # as success so a green up-to-date build is not reported as a failure.
        for ln in lines:
            if re.search(r"(?i)\b(Error|CompilerError|DeclarationError|TypeError|ParserError)\b\s*(\([0-9]+\))?\s*:", ln):
                errors.append(ln.strip())
        failed = bool(re.search(r"(?i)compilation\s+failed|build\s+failed|error\b.*compil", text)) or bool(errors)
        success = bool(re.search(
            r"(?i)compiler\s+run\s+successful|compiled\s+\d+\s+|successfully\s+compiled|build\s+succeeded"
            r"|no\s+files?\s+changed|compilation\s+skipped|nothing\s+to\s+compile", text))
        result["compiled"] = success and not failed
    elif tc == "cargo":
        for ln in lines:
            if re.search(r"(?im)^\s*error(\[E\d+\])?\s*:", ln):
                errors.append(ln.strip())
        failed = bool(errors) or bool(re.search(r"(?i)could not compile|build failed", text))
        success = bool(re.search(r"(?i)\bFinished\b.*(dev|release|target|profile)|\bFinished\b\s+`?(dev|release)", text)) \
            or bool(re.search(r"(?i)^\s*Finished\b", text, re.MULTILINE))
        result["compiled"] = success and not failed
    else:
        # Generic (go/make/cmake/npm/…): many of these are SILENT on success (`go build`/`make`
        # print nothing). So failure is the signal: a line that looks like an error fails it.
        # `compiled` is True when a positive marker is present, but callers that know the command
        # exited 0 should rely on `failed`/`errors` (see bootstrap) rather than requiring a marker.
        for ln in lines:
            if re.search(r"(?im)^\s*error\b|\berror:\s|\bbuild failed\b", ln):
                errors.append(ln.strip())
        failed = bool(errors)
        success = bool(re.search(r"(?i)\b(success|succeeded|built|build complete|done|ok)\b", text))
        result["compiled"] = success and not errors

    # Cap the captured error lines so a huge log can't bloat the report.
    result["failed"] = failed
    result["errors"] = errors[:50]
    result["warnings"] = warnings
    return result


# ---------------------------------------------------------------------------
# Toolchain probing + controlled bootstrap
# ---------------------------------------------------------------------------
def toolchain_available(tool: str) -> bool:
    """True if ``tool`` is on PATH. Pure probe; never raises."""
    try:
        return shutil.which(tool) is not None
    except Exception:  # pragma: no cover - shutil.which is robust, belt-and-suspenders
        return False


def _command_allowed(cmd: str) -> bool:
    """A command may run only if its FULL token list exactly equals an allowlist entry — and it
    carries no shell metacharacters (we run without a shell, but reject them defensively). Exact
    (not prefix) matching means no extra/trailing argv can ride along on an allowlisted verb, so
    even if a future change let a derived string reach here it could not smuggle extra flags."""
    if any(ch in cmd for ch in (";", "|", "&", "$", "`", ">", "<", "\n")):
        return False
    return tuple(cmd.split()) in _PROVISION_ALLOWLIST


def _missing_for(cmd: str) -> str:
    """Return the leading executable of an allowlisted command (its PATH dependency)."""
    return cmd.split()[0] if cmd.split() else ""


def _remediation_for_tool(tool: str) -> str:
    return {
        "forge": _REMEDIATION_FOUNDRY,
        "git": _REMEDIATION_GIT,
        "npm": _REMEDIATION_NODE,
        "npx": _REMEDIATION_NODE,
        "cargo": _REMEDIATION_CARGO,
        "go": _REMEDIATION_GO,
        "make": _REMEDIATION_MAKE,
    }.get(tool, f"install {tool} and re-run")


def _diagnose(toolchain: str, summary: dict, stderr: str) -> str:
    """Turn build output into a pointed diagnosis for Foundry's common green-blockers
    (missing submodule, solc version mismatch, unresolved remapping) plus a generic fallback."""
    blob = "\n".join(summary.get("errors", [])) + "\n" + (stderr or "")
    low = blob.lower()
    hints: list[str] = []
    if toolchain == "foundry":
        if "source" in low and ("not found" in low or "file not found" in low or "could not find" in low):
            hints.append("an import did not resolve — likely a missing git submodule; run "
                         "`git submodule update --init --recursive` (or `forge install`) first")
        if "remapping" in low or ("@" in blob and "not found" in low):
            hints.append("a remapping may be unresolved — check remappings.txt / foundry.toml profiles")
        if "source file requires different compiler version" in low or "pragma" in low or "compiler version" in low:
            hints.append("solc pragma/version mismatch — pin the solc version in foundry.toml")
    if summary.get("errors"):
        hints.append("compiler errors: " + "; ".join(summary["errors"][:5]))
    if not hints and stderr.strip():
        hints.append(stderr.strip()[:400])
    return " | ".join(hints) if hints else "build did not reach a successful-compile marker"


def _run_one(cmd: str, cwd: Path, timeout: float, on_event: EventEmit | None, report: BuildReport) -> tuple[int, str]:
    """Execute a single allowlisted command (no shell), bounded by ``timeout``. Returns
    ``(exit_code, combined_output)``; on any failure to even launch, returns a non-zero code
    with a structured message. NEVER raises."""
    if on_event:
        on_event("build_env", "lifecycle", {"event": "command_start", "command": cmd, "cwd": str(cwd)})
    tool = _missing_for(cmd)
    if not toolchain_available(tool):
        if tool not in report.toolchain_missing:
            report.toolchain_missing.append(tool)
        msg = f"{tool} not installed"
        if on_event:
            on_event("build_env", "lifecycle", {"event": "command_skip", "command": cmd, "reason": msg})
        return 127, msg
    try:
        proc = subprocess.run(  # noqa: S603 — argv is allowlisted + shell=False
            cmd.split(),
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if on_event:
            on_event("build_env", "lifecycle",
                     {"event": "command_done", "command": cmd, "exit": proc.returncode, "bytes": len(out)})
        return proc.returncode, out
    except subprocess.TimeoutExpired:
        msg = f"timed out after {timeout:.0f}s"
        if on_event:
            on_event("build_env", "lifecycle", {"event": "command_timeout", "command": cmd, "reason": msg})
        return 124, msg
    except (OSError, ValueError, Exception) as exc:  # never let a subprocess fault escape
        msg = f"failed to run: {exc}"
        if on_event:
            on_event("build_env", "lifecycle", {"event": "command_error", "command": cmd, "reason": msg})
        return 1, msg


_FOUNDRY_INSTALLER_URL = "https://foundry.paradigm.xyz"


def _foundry_bin_dir() -> Path:
    """Where foundryup installs the toolchain (honors FOUNDRY_DIR)."""
    import os as _os

    base = _os.environ.get("FOUNDRY_DIR", "").strip()
    root = Path(base) if base else Path.home() / ".foundry"
    return root / "bin"


def _prepend_path(directory: Path) -> None:
    """Make ``directory`` visible to this process (and children) for the rest of the run, so a
    freshly-installed toolchain is usable immediately without a shell restart. Idempotent."""
    import os as _os

    d = str(directory)
    parts = _os.environ.get("PATH", "").split(_os.pathsep)
    if d not in parts:
        _os.environ["PATH"] = d + _os.pathsep + _os.environ.get("PATH", "")


def activate_foundry_path() -> bool:
    """Make an ALREADY-installed Foundry discoverable: prepend ``~/.foundry/bin`` (or
    ``$FOUNDRY_DIR/bin``) to this process's PATH when it exists. foundryup installs there but only
    edits shell rc files, so a non-login process (a hunt, ``status``) otherwise can't see ``forge``.
    Returns True if the dir exists. Idempotent; never raises."""
    bin_dir = _foundry_bin_dir()
    try:
        if bin_dir.is_dir():
            _prepend_path(bin_dir)
            return True
    except OSError:
        pass
    return False


def ensure_foundry(
    *,
    on_event: EventEmit | None = None,
    allow_network: bool = True,
    allow_install: bool = False,
    timeout: float = 600.0,
) -> dict:
    """Make the Foundry toolchain (``forge``/``anvil``) available — the single biggest unblocker
    for confirmed criticals on EVM targets, since the reproduction gate cannot execute a harness
    without it.

    Returns ``{"forge", "anvil", "installed", "detail", "remediation"}``. Behaviour:

    * ``forge`` already on PATH → short-circuit (``installed=False``), nothing executed.
    * ``allow_install=False`` → report missing + remediation, execute nothing (the safe default).
    * else run ``foundryup`` if present; otherwise (``allow_network``) download the OFFICIAL
      installer to a temp file and run it to bootstrap ``foundryup``, then run ``foundryup``.

    Every step is logged via ``on_event`` and bounded by ``timeout``. NEVER raises. This installs a
    well-known toolchain only; it does NOT touch the artifact floor — promotion still requires a
    deterministic reproduction. Executing a remote installer is gated behind ``allow_install`` on
    purpose (off by default)."""
    import os as _os
    import tempfile
    import urllib.request

    bin_dir = _foundry_bin_dir()
    _prepend_path(bin_dir)  # a prior install may already be on disk but off this process's PATH

    def _result(detail: str, remediation: str = "") -> dict:
        return {
            "forge": toolchain_available("forge"),
            "anvil": toolchain_available("anvil"),
            "installed": toolchain_available("forge") and "short-circuit" not in detail,
            "detail": detail,
            "remediation": remediation,
        }

    if toolchain_available("forge"):
        if on_event:
            on_event("build_env", "lifecycle", {"event": "toolchain_present", "tool": "forge"})
        return {"forge": True, "anvil": toolchain_available("anvil"), "installed": False,
                "detail": "forge already on PATH (short-circuit)", "remediation": ""}

    if not allow_install:
        if on_event:
            on_event("build_env", "lifecycle",
                     {"event": "toolchain_missing", "tool": "forge",
                      "detail": "auto-install disabled; reproduction gate cannot fire"})
        return _result("forge missing and auto-install disabled", _REMEDIATION_FOUNDRY)

    if not allow_network:
        return _result("forge missing; auto-install needs network but allow_network=False",
                       _REMEDIATION_FOUNDRY)

    if on_event:
        on_event("build_env", "lifecycle", {"event": "toolchain_install_start", "tool": "foundry"})

    # 1) Bootstrap `foundryup` if it isn't installed yet (download the official installer, run it).
    foundryup = shutil.which("foundryup") or str(bin_dir / "foundryup")
    if not Path(foundryup).exists() and shutil.which("foundryup") is None:
        try:
            req = urllib.request.Request(  # a UA is required — the CDN 403s the default python-urllib agent
                _FOUNDRY_INSTALLER_URL,
                headers={"User-Agent": "p1hunt/0.1 (+safe-harbor toolchain provisioner)"},
            )
            with urllib.request.urlopen(req, timeout=min(timeout, 120)) as resp:  # noqa: S310 - https official installer
                script = resp.read().decode("utf-8", "ignore")
            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
                fh.write(script)
                installer = fh.name
            if on_event:
                on_event("build_env", "lifecycle",
                         {"event": "installer_fetched", "url": _FOUNDRY_INSTALLER_URL, "bytes": len(script)})
            code = subprocess.run(  # noqa: S603 - explicit bash on a fetched, logged installer (gated by allow_install)
                ["bash", installer], capture_output=True, text=True, timeout=timeout, check=False,
                env={**_os.environ, "FOUNDRY_DIR": str(bin_dir.parent)},
            ).returncode
            if on_event:
                on_event("build_env", "lifecycle", {"event": "installer_done", "exit": code})
        except Exception as exc:  # network/launch failure must never crash the hunt
            if on_event:
                on_event("build_env", "lifecycle", {"event": "installer_error", "detail": str(exc)})
            return _result(f"foundryup bootstrap failed: {exc}", _REMEDIATION_FOUNDRY)
        _prepend_path(bin_dir)
        foundryup = shutil.which("foundryup") or str(bin_dir / "foundryup")

    # 2) Run foundryup to install/refresh forge/anvil/cast into the foundry bin dir.
    if not Path(foundryup).exists() and shutil.which("foundryup") is None:
        return _result("foundryup not available after bootstrap", _REMEDIATION_FOUNDRY)
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [foundryup], capture_output=True, text=True, timeout=timeout, check=False,
            env={**_os.environ, "FOUNDRY_DIR": str(bin_dir.parent)},
        )
        if on_event:
            on_event("build_env", "lifecycle",
                     {"event": "foundryup_done", "exit": proc.returncode,
                      "bytes": len((proc.stdout or "") + (proc.stderr or ""))})
    except Exception as exc:
        if on_event:
            on_event("build_env", "lifecycle", {"event": "foundryup_error", "detail": str(exc)})
        return _result(f"foundryup run failed: {exc}", _REMEDIATION_FOUNDRY)

    _prepend_path(bin_dir)
    ok = toolchain_available("forge")
    return _result("installed forge via foundryup" if ok else "foundryup ran but forge still missing",
                   "" if ok else _REMEDIATION_FOUNDRY)


def bootstrap_environment(
    repo_path: str,
    *,
    on_event: EventEmit | None = None,
    allow_network: bool = True,
    timeout: float = 900.0,
) -> BuildReport:
    """Controlled, logged provisioning + build of the audit target.

    Detects the build system, then runs ONLY allowlisted provisioning verbs followed by the
    build command, each bounded by ``timeout`` and emitted via ``on_event``. Green for Foundry
    means: ``git submodule update --init --recursive`` (when submodules/lib present) succeeds,
    ``forge build`` exits 0, AND ``summarize_build_output`` reports ``compiled``. Always returns
    a structured ``BuildReport`` — never raises, never hangs.

    Safe in a repo with no build files (``toolchain="unknown"``, ``attempted=False``). When the
    plan needs network and ``allow_network`` is False, returns ``attempted=False`` with a
    remediation directive instead of touching the network.
    """
    plan = detect_build_system(repo_path)
    report = BuildReport(toolchain=plan.toolchain)
    repo = Path(repo_path)

    if plan.toolchain == "unknown":
        report.remediation = "no recognized build system; cannot bootstrap automatically"
        return report

    if plan.needs_network and not allow_network:
        report.remediation = (
            f"{plan.toolchain} provisioning needs network (submodules/dependency fetch) but "
            "allow_network=False; provision the target manually then re-run: "
            + " && ".join(plan.provision_commands + [plan.build_command])
        )
        return report

    # Pre-flight: which provisioning/build tools are even present. A missing PRIMARY toolchain
    # (forge/cargo/go/make/npm) means we cannot attempt at all — report it cleanly.
    primary = {"foundry": "forge", "hardhat": "npx", "npm": "npm", "cargo": "cargo",
               "go": "go", "make": "make", "cmake": "cmake"}.get(plan.toolchain, plan.toolchain)
    if not toolchain_available(primary):
        report.toolchain_missing.append(primary)
        report.remediation = _remediation_for_tool(primary)
        report.diagnostics = f"{primary} is not on PATH; cannot bootstrap {plan.toolchain} target"
        return report

    report.attempted = True
    sequence = [c for c in plan.provision_commands if _command_allowed(c)]
    if _command_allowed(plan.build_command):
        sequence.append(plan.build_command)
    elif plan.build_command:
        # Build command is outside the provisioning allowlist (e.g. "npm run build",
        # "cmake --build ."): we still record it for the operator but do not execute it.
        report.diagnostics = (
            f"build step '{plan.build_command}' is outside the provisioning allowlist; "
            "run it manually after provisioning"
        )

    last_output = ""
    for cmd in sequence:
        report.commands_run.append(cmd)
        code, out = _run_one(cmd, repo, timeout, on_event, report)
        last_output = out
        if code != 0:
            summary = summarize_build_output(out, plan.toolchain)
            tool = _missing_for(cmd)
            if code == 127:  # tool missing mid-sequence
                report.remediation = _remediation_for_tool(tool)
                report.diagnostics = f"`{cmd}` could not run: {out}"
            elif code == 124:  # timeout
                report.remediation = f"increase the timeout (current {timeout:.0f}s) or provision `{cmd}` manually"
                report.diagnostics = f"`{cmd}` {out}"
            else:
                report.diagnostics = f"`{cmd}` failed (exit {code}): " + _diagnose(plan.toolchain, summary, out)
                report.remediation = report.remediation or (
                    "resolve the diagnosed build failure above, then re-run the bootstrap"
                )
            report.compiles = False
            return report

    # All commands exited 0. Trust the exit code as the source of truth: the build is GREEN unless
    # its OUTPUT shows positive failure evidence (compiler error lines or an explicit failure
    # marker). Requiring a success marker false-REDs the many toolchains that are SILENT on success
    # (`go build`, `make`) and a cache-warm `forge build` ("No files changed") — which would then
    # wrongly tell the whole swarm to "fix" an already-green build. (forge/cargo/go/make all exit
    # non-zero on a real compile error, so reaching here already means the command succeeded.)
    summary = summarize_build_output(last_output, plan.toolchain)
    report.compiles = not (summary.get("failed") or summary.get("errors"))
    if not report.compiles:
        report.diagnostics = _diagnose(plan.toolchain, summary, last_output)
        if plan.solc_version and plan.toolchain in ("foundry", "hardhat"):
            report.remediation = ((report.remediation + " ") if report.remediation else "") + \
                f"(target pins solc {plan.solc_version} — ensure that compiler is installed/available)"
        report.remediation = report.remediation or "build commands exited 0 but the log shows errors; inspect it"
    return report
