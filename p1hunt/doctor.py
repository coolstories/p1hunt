"""Pre-flight: will a hunt actually work on this machine, right now?

WHY THIS EXISTS
---------------
Every expensive failure this project has had was the same shape: ONE layer was dead,
everything around it reported success, and the run produced an honest-looking nothing that
reads as "no bugs here". The list is not hypothetical -- each item below cost a real run:

  * the provider's safety classifier refused the planning brief; later it refused all five
    hunters and the fuzzer, and the hunt still reported success;
  * Playwright's sync api could not start inside the event loop, so live recon never ran
    at all and the planner silently got no facts;
  * a stale pytest plugin made every proof harness die before collection, which caps
    confirmed findings at zero no matter how good the hunt is;
  * a null token count crashed the final report after a completed hunt.

A hunt is long and costs real money. Everything here is cheap and checkable BEFORE that
spend, so the question "is this run going to be meaningful" gets answered up front instead
of being inferred from a disappointing result.

Each check returns a verdict and, when it fails, THE FIX. A check that cannot be performed
reports itself as unchecked rather than ok -- claiming a layer is healthy because it was
never tested is the exact error this module exists to prevent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Verdicts, worst first for sorting a summary.
FAIL = "FAIL"          # a hunt on this machine cannot produce a confirmed finding
WARN = "WARN"          # degraded: the hunt runs but loses a capability
UNCHECKED = "SKIP"     # not probed; says so rather than claiming ok
OK = "OK"


@dataclass
class Check:
    name: str
    verdict: str
    detail: str = ""
    fix: str = ""
    # What a hunt LOSES if this stays broken. Stated per check because "FAIL" alone does
    # not tell an operator whether to stop or proceed.
    impact: str = ""

    @property
    def ok(self) -> bool:
        return self.verdict == OK


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, c: Check) -> Check:
        self.checks.append(c)
        return c

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.verdict == FAIL]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.verdict == WARN]

    @property
    def go(self) -> bool:
        """Can a hunt on this machine produce a CONFIRMED finding at all?"""
        return not self.failures


def _import_ok(module: str) -> bool:
    import importlib.util
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def check_python_deps() -> list[Check]:
    """The harness toolchain's own imports. Declared in pyproject for exactly this reason:
    a harness that cannot `import requests` dies, and a dead harness used to be readable as
    a demonstrated bug."""
    out = []
    for mod, why, fix in (
        ("requests", "the web proof harnesses import it",
         "pip install 'requests>=2.31'"),
        ("pytest", "the web runner executes harnesses with it",
         "pip install 'pytest>=7'"),
    ):
        present = _import_ok(mod)
        out.append(Check(
            name=f"python: {mod}",
            verdict=OK if present else FAIL,
            detail=why if present else f"not importable -- {why}",
            fix="" if present else fix,
            impact="" if present else "no proof harness can run, so nothing can be confirmed",
        ))
    return out


def check_pytest_runs() -> Check:
    """Does pytest EXECUTE a trivial test? `pytest --version` is not the same question.

    On the development machine a stale `anchorpy` plugin made pytest exit 1 during plugin
    loading: the binary was present and `--version` worked, and every harness would have
    died before collecting a single test.
    """
    from .runners.base import preflight_pytest

    res = preflight_pytest()
    if res["ok"] and not res.get("addopts"):
        return Check("pytest: runs a test", OK, res["detail"])
    if res["ok"]:
        # Not a blocker: the runner applies this VERIFIED flag to its own harness
        # subprocesses (see runners.base.run_command). Still surfaced, because disabling
        # someone's plugin is a real intrusion and because the durable fix is theirs.
        return Check(
            "pytest: runs a test", WARN,
            res["detail"],
            fix=f"harnesses will run — p1hunt applies '{res['addopts']}' to its own harness "
                f"processes only. To clear this properly, repair or remove the "
                f"'{res.get('broken_plugin')}' package.",
            impact="none for this run; the workaround is scoped to p1hunt's subprocesses and "
                   "does not touch your environment",
        )
    return Check(
        "pytest: runs a test", FAIL, res["detail"], fix=res["fix"],
        impact="every proof harness dies before collection, so the confirmed count is "
               "capped at zero regardless of what the hunt finds",
    )


def check_browser() -> Check:
    """Can a real browser launch? Black-box discovery and every DOM finding need it."""
    if not _import_ok("playwright"):
        return Check(
            "browser: playwright", FAIL,
            "playwright is not importable",
            fix="pip install playwright && python3 -m playwright install chromium",
            impact="no live recon and no DOM-layer findings: the planner gets an empty "
                   "surface and black-box discovery does not happen",
        )
    try:
        from .dynamic.browser import Browser
    except Exception as exc:
        return Check("browser: module", FAIL, f"p1hunt browser module failed to import: {exc}",
                     fix="check that htmlctx.py is intact beside browser.py",
                     impact="no live recon and no DOM-layer findings")
    # Launch it. The browser BINARY is a separate install from the python package, and the
    # error for a missing binary ("Executable doesn't exist") only appears on launch.
    try:
        with Browser(allowlist=[], rate_limit=0) as _b:
            pass
    except Exception as exc:
        msg = str(exc)
        binary_missing = "Executable doesn" in msg or "playwright install" in msg
        return Check(
            "browser: launches", FAIL,
            f"chromium did not launch: {msg[:160]}",
            fix=("python3 -m playwright install chromium" if binary_missing
                 else "check the playwright install and sandbox permissions"),
            impact="no live recon and no DOM-layer findings",
        )
    return Check("browser: launches", OK, "chromium launched and closed cleanly")


def check_engine(engine: str) -> Check:
    """Is the configured engine's CLI/SDK actually present and runnable?"""
    from .agents.claude_session import sdk_available

    if engine == "codex":
        try:
            from .agents.codex_session import codex_available
            present = codex_available()
        except Exception:
            present = False
        return Check(
            "engine: codex CLI", OK if present else FAIL,
            "the codex CLI is on PATH" if present else "the codex CLI is not on PATH",
            fix="" if present else "install and authenticate the codex CLI, or set "
                                   "P1HUNT_ENGINE=claude",
            impact="" if present else "no model runs: the hunt falls back to the "
                                      "deterministic brain, which cannot find a real P1",
        )
    present = sdk_available()
    return Check(
        "engine: claude SDK", OK if present else FAIL,
        "claude_agent_sdk is importable" if present else "claude_agent_sdk is not installed",
        fix="" if present else "pip install 'claude-agent-sdk>=0.2.105'  (the project's "
                               "declared `agent` extra)",
        impact="" if present else "no model runs on this engine",
    )


def check_engine_roles(engine: str, probe_file: Path | None = None) -> Check:
    """Does the provider ACCEPT each role? Read from the last probe, never guessed.

    This is the check that cannot be done cheaply -- it costs one short session per role --
    so `p1hunt doctor` reads the artifact `bench/probe_refusal.py` leaves behind and tells
    you to run it when there is none. Reporting UNCHECKED here is the point: a refused role
    returns no findings, which is indistinguishable from a clean result, so assuming
    acceptance is how a meaningless run gets mistaken for a real one.
    """
    import json

    path = probe_file or (Path(__file__).resolve().parent.parent / "bench"
                          / (f"last_refusal_probe_{engine}.json" if engine != "codex"
                             else "last_refusal_probe.json"))
    cmd = (f"python3 bench/probe_refusal.py"
           + (f" --engine {engine}" if engine != "codex" else ""))
    if not path.is_file():
        return Check(
            "engine: role acceptance", UNCHECKED,
            f"no probe artifact at {path.name} -- acceptance is unknown for '{engine}'",
            fix=f"run: {cmd}",
            impact="unknown. If the provider refuses a role, that role contributes nothing "
                   "and the hunt still reports success",
        )
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return Check("engine: role acceptance", UNCHECKED,
                     f"could not read {path.name}: {exc}", fix=f"re-run: {cmd}")
    bad = [r for r in rows if r.get("verdict") not in (None, "ACCEPTED")]
    names = ", ".join(f"{r['prompt']}={r['verdict']}" for r in bad)
    if not bad:
        return Check("engine: role acceptance", OK,
                     f"all {len(rows)} probed roles accepted on '{engine}'")
    # A refused HUNTING or PROVING role is fatal; the triage roles are degradation.
    fatal_roles = {"web_hunt", "web_map", "falsifier", "materialize", "repair"}
    fatal = [r for r in bad if r.get("prompt") in fatal_roles]
    return Check(
        "engine: role acceptance", FAIL if fatal else WARN,
        f"{len(bad)} of {len(rows)} probed roles not accepted on '{engine}': {names}",
        fix=("switch engines for these roles (P1HUNT_ENGINE=claude, or a different "
             "P1HUNT_CODEX_MODEL) and re-probe. Retrying the same engine will not help: a "
             "refusal is permanent, not a transient limit"),
        impact=("the find-and-prove chain is broken, so the hunt cannot produce a confirmed "
                "finding and will report a clean-looking nothing"
                if fatal else "those roles contribute nothing; the rest of the hunt still runs"),
    )


def check_engagements_root(root: str) -> Check:
    p = Path(root)
    try:
        p.mkdir(parents=True, exist_ok=True)
        probe = p / ".p1hunt-doctor-write-test"
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return Check("output: engagements root", FAIL, f"{p} is not writable: {exc}",
                     fix="set P1HUNT_ENGAGEMENTS to a writable directory",
                     impact="findings, the event stream and the ledger cannot be persisted")
    return Check("output: engagements root", OK, str(p.resolve()))


def check_run_mode(run_mode: str, use_agent: bool) -> Check:
    """`run_mode=active` is what authorizes live testing; without it the hunt is static."""
    if not use_agent:
        return Check("posture: run mode", FAIL,
                     f"run_mode={run_mode} and the live brain is OFF",
                     fix="install/authenticate the engine CLI (see above); the deterministic "
                         "offline brain cannot find a real P1",
                     impact="regex-only scanning: a clean result means nothing")
    if run_mode != "active":
        return Check("posture: run mode", WARN, f"run_mode={run_mode}",
                     fix="`hunt --web` forces active automatically; for other modes set "
                         "P1HUNT_RUN_MODE=active",
                     impact="live HTTP testing stays disabled, so a web target is not probed")
    return Check("posture: run mode", OK, "active (live testing authorized by the operator)")


def run_doctor(*, engine: str | None = None, probe_file: Path | None = None,
               skip_browser: bool = False) -> Report:
    """Every cheap check, in one pass. Never raises."""
    from .config import Config

    cfg = Config.from_env()
    eng = (engine or cfg.models.engine or "codex").strip().lower()

    rep = Report()
    for c in check_python_deps():
        rep.add(c)
    rep.add(check_pytest_runs())
    if skip_browser:
        rep.add(Check("browser: launches", UNCHECKED, "skipped by request",
                      fix="re-run without --no-browser to actually test it"))
    else:
        rep.add(check_browser())
    rep.add(check_engine(eng))
    rep.add(check_engine_roles(eng, probe_file))
    rep.add(check_engagements_root(cfg.engagements_root))
    rep.add(check_run_mode(cfg.run_mode, bool(cfg.use_claude)))
    return rep


def render(rep: Report, *, engine: str = "") -> str:
    lines = ["", f"p1hunt doctor — can a hunt produce a confirmed finding here?"
                 f"{f'   [engine: {engine}]' if engine else ''}", ""]
    mark = {OK: "  ok  ", FAIL: " FAIL ", WARN: " warn ", UNCHECKED: " skip "}
    for c in rep.checks:
        lines.append(f"[{mark.get(c.verdict, '  ?   ')}] {c.name:28} {c.detail[:88]}")
    lines.append("")
    if rep.go and not rep.warnings and not [c for c in rep.checks if c.verdict == UNCHECKED]:
        lines.append("GO. Every check passed.")
    elif rep.go:
        lines.append("GO, with gaps. Nothing blocks a confirmed finding, but read these:")
    else:
        lines.append("NO-GO. A hunt started now CANNOT produce a confirmed finding, and it "
                     "would still\n        report success. Fix the FAIL items first — a clean "
                     "result from this machine\n        would mean nothing about the target.")
    for c in rep.checks:
        if c.verdict in (FAIL, WARN, UNCHECKED) and (c.fix or c.impact):
            lines.append("")
            lines.append(f"  {c.verdict}  {c.name}")
            if c.impact:
                lines.append(f"      cost if ignored: {c.impact}")
            if c.fix:
                lines.append(f"      fix:             {c.fix}")
    lines.append("")
    return "\n".join(lines)
