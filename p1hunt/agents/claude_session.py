"""Claude Agent SDK session — the real detector (spec §3).

The AI *is* the detector. Each agent is a real Claude session (via the Claude Agent SDK,
driven by the locally authenticated `claude` CLI — no API key needed) that reads the
target with read-only tools, reasons about it, and reports structured findings. Every SDK
message (tool call, reasoning) is teed to the event log so the operator sees Claude work
live, and a ScopeGuard-backed ``can_use_tool`` hook gates every tool call (§9 — real
subagent coverage). When the SDK or `claude` CLI is unavailable, callers fall back to the
deterministic offline brain so the system still runs and tests stay hermetic.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Full hunting capability: read the code, run read-only analysis in a shell, and research
# the web (CVEs, advisories, dependency versions, exploit patterns). Writes and destructive
# actions are blocked by the ScopeGuard below — safe-harbor (§9, §17).
HUNT_TOOLS = ["Read", "Grep", "Glob", "Bash", "Write", "Edit", "WebSearch", "WebFetch"]
_RESEARCH_TOOLS = {"WebSearch", "WebFetch"}
_FILE_TOOLS = {"Read", "Grep", "Glob"}
_WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}  # allowed ONLY in the PoC sandbox

# WORKSPACE-JAIL policy: the agent may do ANYTHING inside the in-scope workspace folder (read,
# write, build, install deps, run servers, make network calls, fuzz, create/delete files). The
# ONLY commands denied are JAIL-ESCAPE — privilege escalation / system control / catastrophic
# disk — because they are exactly what would let the agent break OUT of the single in-scope
# folder, which is the one hard guardrail. (Network egress and package installs are allowed: they
# do not by themselves escape the folder. Out-of-workspace file writes and out-of-workspace secret
# reads are handled below via path checks, not a command blocklist.)
_ESCAPE = re.compile(
    r"""(?ix)
    \b(sudo|doas|su|shutdown|reboot|halt|poweroff|mount|umount|diskutil|launchctl|
        systemctl|service|crontab)\b
    | \b(mkfs|fdisk|parted)\b | \bdd\b[^\n|;&]*\bof=\s*/dev/
    """,
)
# CATASTROPHIC ops that are NEVER allowed — not even as part of a tool install. These can brick the
# host or wipe the disk, which no "install a tool" task can justify; checked before everything else.
_CATASTROPHIC = re.compile(
    r"""(?ix)
    \b(shutdown|reboot|halt|poweroff)\b
    | \b(mkfs\w*|mkswap|wipefs|fdisk|parted|sgdisk)\b
    | \bdd\b[^\n|;&]*\bof=\s*/dev/
    | :\s*\(\s*\)\s*\{                                  # fork bomb  :(){ :|:& };:
    | \brm\b\s+(?:-\S+\s+)*(?:/|/\*|~|\$HOME)(?:\s|$)   # rm -rf /  ·  rm -rf ~
    """,
)
# TOOL INSTALL — the agent may install ANY tool it needs to do the audit (compilers, analyzers,
# fuzzers, Foundry, language toolchains, system packages), via the standard mechanisms INCLUDING
# sudo package managers and official installer scripts. A command recognized here is permitted even
# under a sudo block, an out-of-workspace write (installs land in /usr/local etc.), or a no-egress
# posture (fetching a tool to install is PROVISIONING, not data egress to the target). Catastrophic
# ops above are still denied first. Gated by PermissionPolicy.allow_install (default on).
_TOOL_INSTALL = re.compile(
    r"""(?ix)
    (?:\bsudo\s+|\bdoas\s+)?                                  # optional privilege for system pkgs
    (?:
        (?:apt|apt-get|aptitude|yum|dnf|apk|pacman|zypper|snap|brew|port|nix-env|nix|emerge|pkg|xbps-install)
            \s+(?:install|add|-S|-i|in|reinstall|update|upgrade|tap|bootstrap)
      | (?:pip3?|pipx|uv|conda|mamba|poetry|pdm)\s+(?:install|add|sync)
      | (?:npm|pnpm|yarn|bun)\s+(?:i|install|ci|add|global)
      | cargo\s+(?:install|add|fetch|binstall)
      | go\s+(?:install|get)
      | (?:gem|luarocks|opam|cabal|stack|cpan|composer)\s+(?:install|add|i)
      | (?:rustup|foundryup|nvm|asdf|sdk|gvm|pyenv|rbenv|goenv|volta|solc-select|svm)\b
      | (?:add-apt-repository|apt-key)\b
      | (?:make|cmake|ninja|meson)\s+install\b
      | (?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)   # official installer scripts
    )""",
)
# Secret/credential paths — reading or touching them is out of scope (mirrors the file guard).
_SENSITIVE_FS = re.compile(
    r"""(?ix)
    /\.(ssh|aws|gnupg|kube|docker|npmrc|pypirc|netrc|git-credentials)\b
    | \bid_(rsa|ed25519|ecdsa|dsa)\b | \.pem(\b|$) | \.p12(\b|$) | /etc/(shadow|sudoers|master\.passwd)
    | \bkeychain\b | \bsecring\b | wallet\.dat | \.kdbx | \.keystore
    """,
)
# File-mutating verbs — allowed inside the workspace, denied only on OUT-OF-WORKSPACE targets.
_WRITE_VERB = re.compile(
    r"(?ix)\b(rm|rmdir|unlink|shred|truncate|chmod|chown|chgrp|chflags|mv|cp|tee|ln|dd)\b|\bsed\s+-[a-z]*i\b")
_REDIRECT_TARGET = re.compile(r">>?\s*['\"]?\s*([~/][^\s'\";|&()<>]*)")


def _abs_path_tokens(cmd: str) -> list[str]:
    # Include `@` and `,` as delimiters so exfil forms like `curl -d @~/.aws/credentials` and
    # comma-joined args still surface their absolute/home path tokens. A leading `.` (relative
    # path like ./secrets) is NOT a delimiter, so relative in-workspace paths are not mis-flagged.
    return [m.group(1) for m in re.finditer(r"(?:^|[\s'\"=(<>|&;:@,])(~[^\s'\";|&()<>]*|/[^\s'\";|&()<>]*)", cmd)]


def _out_of_workspace(p: str, workspace: str | None = None) -> bool:
    """A path is IN the workspace if it's relative (resolved from the workspace CWD), under the
    given ``workspace`` root, or under /tmp scratch / a harmless /dev sink. Every other absolute
    or home path is OUTSIDE — the one hard guardrail. With no workspace, only relative + /tmp +
    /dev sinks count as inside (the conservative default)."""
    if p.startswith(("/dev/null", "/dev/stdout", "/dev/stderr")):
        return False
    if p in ("/tmp", "/private/tmp", "/var/tmp") or p.startswith(("/tmp/", "/private/tmp/", "/var/tmp/")):
        return False
    if not (p.startswith("/") or p.startswith("~")):
        return False  # relative → resolves inside the workspace CWD
    if workspace:
        try:
            root = os.path.realpath(os.path.expanduser(workspace))
            cand = os.path.realpath(os.path.expanduser(p))
            if cand == root or cand.startswith(root + os.sep):
                return False
        except OSError:
            pass
    return True


_RL_PHRASES = (
    "session limit", "usage limit", "rate limit", "rate_limit", "rate-limited", "ratelimit",
    "too many requests", "429", "overloaded", "capacity", "quota", "try again later",
    "you've hit your", "you have hit your", "upgrade to increase",
)


def _looks_rate_limited(text: str) -> bool:
    """Detect a usage/session/rate-limit / overload notice anywhere in the response so the
    swarm backs off cleanly instead of silently degrading or spinning. (No length cap — the
    notice can arrive embedded in a longer assistant turn.)"""
    if not text:
        return False
    t = text.lower()
    if any(p in t for p in _RL_PHRASES):
        return True
    return "limit" in t and ("reset" in t or "reached" in t or "exceeded" in t)


# ---------------------------------------------------------------------------
# Process-wide THROTTLE GATE. When ANY session detects a rate-limit/overload/hang, it trips a
# shared cooldown; every other session waits on it before starting. This turns a rate limit
# from a destructive spin (or a silent hang) into a coordinated, self-recovering backoff — the
# whole swarm pauses together and resumes the moment the window clears. Pure in-process state
# (no asyncio primitives at import time); a tiny status file lets external tools see throttle.
# ---------------------------------------------------------------------------
_THROTTLE = {"until": 0.0, "strikes": 0}
_THROTTLE_FILE = os.environ.get("P1HUNT_THROTTLE_FILE", "/tmp/p1hunt_throttle.json")
# INACTIVITY timeout: if the SDK streams NO message for this long, the session is stuck/throttled
# (a healthy session streams thinking + tool events continuously). Kills hangs without killing
# legit long work. Raise via P1HUNT_SESSION_TIMEOUT if PoC test runs legitimately go silent longer.
SESSION_TIMEOUT = float(os.environ.get("P1HUNT_SESSION_TIMEOUT", "300"))


def _throttle_remaining() -> float:
    return max(0.0, _THROTTLE["until"] - time.monotonic())


def _trip_throttle(reason: str = "") -> float:
    """Escalate the shared cooldown (exponential w/ jitter, 30s → 15min) and persist it."""
    _THROTTLE["strikes"] = min(_THROTTLE["strikes"] + 1, 6)
    jitter = (os.getpid() % 7)  # cheap, loop-safe spread so sessions don't thunder together
    backoff = min(900.0, 30.0 * (2 ** (_THROTTLE["strikes"] - 1))) + jitter
    _THROTTLE["until"] = time.monotonic() + backoff
    try:
        with open(_THROTTLE_FILE, "w") as fh:
            json.dump({"throttled": True, "seconds": round(backoff), "strikes": _THROTTLE["strikes"],
                       "reason": reason, "at": time.time()}, fh)
    except OSError:
        pass
    return backoff


def _clear_throttle() -> None:
    """A clean success means the window is open again — reset strikes and clear the gate."""
    if _THROTTLE["strikes"] or _THROTTLE["until"]:
        _THROTTLE.update(until=0.0, strikes=0)
        try:
            with open(_THROTTLE_FILE, "w") as fh:
                json.dump({"throttled": False, "at": time.time()}, fh)
        except OSError:
            pass


def _throttle_manually_cleared() -> bool:
    """True if an operator ran `p1hunt jumpstart` — wrote {throttled:false, manual:true} to the
    throttle file — telling a waiting swarm to retry NOW instead of finishing its cooldown."""
    try:
        with open(_THROTTLE_FILE) as fh:
            d = json.load(fh)
        return bool(d.get("manual")) and not d.get("throttled", True)
    except (OSError, ValueError):
        return False


async def _await_throttle(on_event: Callable, agent: str) -> None:
    """Block until the shared cooldown clears (or an operator jump-starts it), surfacing a
    heartbeat so the UI shows the wait. Re-checks every ≤20s so a manual jumpstart cuts in fast."""
    while True:
        if _throttle_manually_cleared():
            _THROTTLE.update(until=0.0, strikes=0)
            on_event(agent, "lifecycle", {"event": "backoff", "reason": "operator jumpstart — resuming now"})
            return
        rem = _throttle_remaining()
        if rem <= 0:
            return
        on_event(agent, "lifecycle",
                 {"event": "backoff", "reason": f"rate-limit cooldown — waiting {int(rem)}s before next attempt"})
        await asyncio.sleep(min(rem, 20.0))


# Parent-A permission posture enforcement (PermissionPolicy). Network egress verbs and dependency
# installs are allowed by DEFAULT (loosened jail); these patterns are consulted ONLY when Parent A
# has tightened the posture (allow_network/allow_install False) — so the common path is unaffected.
_NET_CMD = re.compile(
    r"""(?ix)\b(curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|ftp|rsync|aria2c)\b
        | \bgit\s+(push|clone|fetch|pull|remote|ls-remote)\b""")
_INSTALL_CMD = re.compile(
    r"""(?ix)\b(npm|pnpm|yarn)\s+(i|install|ci|add)\b | \bpip3?\s+(install|download)\b
        | \bcargo\s+(install|fetch)\b | \bgo\s+(get|install)\b | \b(apt|apt-get|yum|dnf|apk|brew|gem)\s+(install|add)\b
        | \bforge\s+install\b""")


def bash_safety(
    command: str, workspace: str | None = None, egress_hosts: list[str] | None = None,
    policy: "object | None" = None,
) -> tuple[bool, str]:
    """WORKSPACE-JAIL model: the ONE hard guardrail is the in-scope folder (``workspace``). INSIDE
    it the agent may do WHATEVER it needs — build, install dependencies, run servers, make network
    calls, fuzz, create/delete files. We deny ONLY what reaches OUTSIDE the folder or breaks out of
    it: (1) privilege-escalation / system-control / catastrophic-disk commands (they escape the
    jail), (2) file creation/mutation/redirect targeting a path outside the workspace, and (3)
    reads of known secret/credential paths outside the workspace.

    TOOL INSTALLS: the agent may install ANY tool it needs for the audit — compilers, static
    analyzers, fuzzers, Foundry, language toolchains, system packages — through the standard
    mechanisms, INCLUDING sudo package managers and official installer scripts (``_TOOL_INSTALL``).
    A recognized install is permitted even though it uses sudo, writes to /usr/local, or fetches
    over the network under a no-egress posture (provisioning a tool is not a jail escape or target
    egress). Only the CATASTROPHIC ops (``_CATASTROPHIC``: disk-wipe / power / rm -rf /) are denied
    unconditionally, and the operator can still switch installs off via ``PermissionPolicy``.

    NETWORK EGRESS: by default (``egress_hosts is None`` — pure static analysis) network egress and
    package installs are ALLOWED; they do not escape the folder boundary. When live dynamic testing
    is ARMED, the caller passes the authorized egress allowlist, and this becomes a NETWORK jail
    too: any command that would contact a host outside the allowlist (and not loopback / a build
    registry) is denied — so authorized testing can never reach a third party's or production
    system. This is the safe-harbor enforcement point for live HTTP from the agent's shell.

    NOTE: comprehensive read-confinement for arbitrary bash is not enforceable here (a determined
    `cat /some/abs/path` is not fully blocked); the strict, fully-enforced read/write confinement
    is on the Read/Grep/Glob/Write/Edit TOOLS (see ClaudeSwarm._guard_check) plus the agent's CWD
    being the workspace. For hard isolation, run the engagement inside a container/VM."""
    if not command or not command.strip():
        return False, "empty command"
    cmd = command.strip()
    if all(ln.strip().startswith("#") for ln in cmd.splitlines() if ln.strip()):
        return True, "comment (no-op)"
    # 0. CATASTROPHIC ops are denied unconditionally — even if combined with an install.
    if _CATASTROPHIC.search(cmd):
        return False, "out of scope: catastrophic disk/power command — denied"
    # 1. TOOL INSTALL — the agent may install any tool it needs (compilers, analyzers, Foundry,
    # package managers, toolchains), incl. via sudo / installer scripts. Permitted before the
    # sudo/escape, egress, and out-of-workspace-write checks (an install writes to /usr/local and
    # fetches from a registry — that is provisioning, not a jail escape or target egress). Honors
    # the operator/Parent-A install posture and any explicitly blocked commands.
    install_ok = getattr(policy, "allow_install", True) if policy is not None else True
    if install_ok and _TOOL_INSTALL.search(cmd):
        if policy is not None:
            low = cmd.lower()
            for d in (str(c).lower() for c in getattr(policy, "deny_commands", []) or []):
                if d and d in low:
                    return False, f"denied by Parent A's permission policy (blocked command: {d})"
        return True, "tool install (provisioning) — allowed"
    if _ESCAPE.search(cmd):
        return False, "out of scope: privilege/system/disk command would escape the workspace jail — denied"
    # NETWORK JAIL (only when live testing is armed): confine outbound contact to in-scope hosts.
    if egress_hosts is not None:
        from ..dynamic.egress import bash_egress_ok

        ok, reason = bash_egress_ok(cmd, egress_hosts)
        if not ok:
            return False, reason
    # Reading a KNOWN secret/credential path that lies OUTSIDE the workspace is out of scope.
    if _SENSITIVE_FS.search(cmd):
        for p in _abs_path_tokens(cmd):
            if _SENSITIVE_FS.search(p) and _out_of_workspace(p, workspace):
                return False, f"out of scope: reads a secret/credential path outside the workspace ({p}) — denied"
    # Creating/mutating/redirecting a file OUTSIDE the workspace is out of scope.
    if _WRITE_VERB.search(cmd):
        for p in _abs_path_tokens(cmd):
            if _out_of_workspace(p, workspace):
                return False, f"out of scope: writes/deletes a path outside the workspace ({p}) — denied"
    m = _REDIRECT_TARGET.search(cmd)
    if m and _out_of_workspace(m.group(1), workspace):
        return False, f"out of scope: redirect into a path outside the workspace ({m.group(1)}) — denied"
    # PARENT-A PERMISSION POSTURE (only restricts further; default policy=None is a no-op). Parent A
    # may forbid network egress and/or dependency installs for this engagement (e.g. an offline
    # crypto-lib audit), or block specific commands it deems unsafe for this target.
    if policy is not None:
        deny_cmds = [str(c).lower() for c in getattr(policy, "deny_commands", []) or []]
        low = cmd.lower()
        for d in deny_cmds:
            if d and d in low:
                return False, f"denied by Parent A's permission policy (blocked command: {d})"
        if not getattr(policy, "allow_network", True) and _NET_CMD.search(cmd):
            return False, "denied: network egress is OFF for this engagement (Parent A permission policy)"
        if not getattr(policy, "allow_install", True) and _INSTALL_CMD.search(cmd):
            return False, "denied: dependency installs are OFF for this engagement (Parent A permission policy)"
    return True, "allowed (in-workspace: free to do whatever it needs)"


def _remap_into_repo(path: str, cwd: str) -> str | None:
    """If an agent references a non-existent ABSOLUTE path whose tail nonetheless exists inside
    the repo (``cwd``), return the real in-repo path. Models often hallucinate a $HOME-style
    prefix (e.g. /Users/you/contracts/lib/X.sol) instead of using a repo-relative path; without
    this they burn a denied turn and retry. We transparently map the longest matching tail."""
    if not path or not os.path.isabs(path) or os.path.exists(path):
        return None
    parts = Path(path).parts  # ('/', 'Users', 'you', 'contracts', 'lib', 'X.sol')
    for i in range(1, len(parts)):  # try progressively shorter tails; longest match wins
        cand = os.path.join(cwd, *parts[i:])
        if os.path.exists(cand):
            return cand
    return None


def _remap_poc_path(path: str, cwd: str) -> str | None:
    """Route a PoC write that targets a hallucinated ``.p1hunt-poc`` location into the REAL
    sandbox (``cwd/.p1hunt-poc``). Models often build a wrong absolute prefix
    (e.g. /Users/you/Documents/target/.p1hunt-poc/X) — without this the write is denied even
    though it intended the sandbox. New PoC files don't exist yet, so ``_remap_into_repo`` (which
    requires the target to exist) can't help here."""
    if not path or ".p1hunt-poc" not in path:
        return None
    sandbox = os.path.normpath(os.path.join(cwd, ".p1hunt-poc"))
    norm = os.path.normpath(path)
    if norm == sandbox or norm.startswith(sandbox + os.sep):
        return None  # already correctly inside the sandbox
    idx = path.rfind(".p1hunt-poc")
    tail = path[idx + len(".p1hunt-poc"):].lstrip("/\\") or "poc.txt"
    return os.path.join(sandbox, tail)


def _remap_tool_input(tool_input: dict, cwd: str) -> dict | None:
    """Return a patched copy of ``tool_input`` with a bad path corrected: a ``.p1hunt-poc`` write
    routed into the real sandbox, or a bad absolute read path remapped into the repo. None if no
    change is needed."""
    for key in ("file_path", "path"):
        raw = tool_input.get(key)
        if isinstance(raw, str) and raw:
            fixed = _remap_poc_path(raw, cwd) or _remap_into_repo(raw, cwd)
            if fixed:
                patched = dict(tool_input)
                patched[key] = fixed
                return patched
    return None


def sdk_available() -> bool:
    try:
        import claude_agent_sdk  # noqa: F401
        import shutil

        return shutil.which("claude") is not None
    except Exception:
        return False


@dataclass
class ClaudeFinding:
    title: str
    severity: str
    file: str
    line: int
    lens: str
    root_cause: str
    reproduction: str
    counterfactual: str
    confidence: str
    evidence: str = ""
    # Model-DERIVED impact facts (NOTHING PRESET — no keyword table classifies these): the agent
    # states the concrete loss it observed and a remediation specific to this root cause. Used by
    # the deterministic severity gate (concrete_loss) and the report (remediation).
    concrete_loss: str = ""   # funds | data | control | availability | none
    remediation: str = ""
    target_code_attribution: str = ""
    non_target_attribution: str = ""
    relies_on_non_target_behavior: bool = False
    attribution_notes: str = ""

    @staticmethod
    def from_dict(d: dict, lens_default: str) -> "ClaudeFinding":
        def _truthy(v: object) -> bool:
            if isinstance(v, bool):
                return v
            if isinstance(v, (int, float)):
                return bool(v)
            return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}

        return ClaudeFinding(
            title=str(d.get("title", "untitled")).strip(),
            severity=str(d.get("severity", "medium")).lower().strip(),
            file=str(d.get("file", "")).strip(),
            line=int(d.get("line", 0) or 0),
            lens=str(d.get("lens", lens_default)).strip() or lens_default,
            root_cause=str(d.get("root_cause", d.get("why", ""))).strip(),
            reproduction=str(d.get("reproduction", d.get("repro", ""))).strip(),
            counterfactual=str(d.get("counterfactual", "")).strip(),
            confidence=str(d.get("confidence", "medium")).lower().strip(),
            evidence=str(d.get("evidence", "")).strip(),
            concrete_loss=str(d.get("concrete_loss", d.get("loss", ""))).lower().strip(),
            remediation=str(d.get("remediation", d.get("fix", ""))).strip(),
            target_code_attribution=str(d.get("target_code_attribution", d.get("target_attribution", ""))).strip(),
            non_target_attribution=str(d.get("non_target_attribution", d.get("harness_attribution", ""))).strip(),
            relies_on_non_target_behavior=_truthy(d.get("relies_on_non_target_behavior", False)),
            attribution_notes=str(d.get("attribution_notes", d.get("attribution", ""))).strip(),
        )


@dataclass
class SessionResult:
    ok: bool
    text: str
    findings: list[ClaudeFinding] = field(default_factory=list)
    error: str = ""
    tool_calls: int = 0


EventEmit = Callable[[str, str, dict], None]  # (agent, kind, data)


class ClaudeSession:
    """One read-only Claude hunting/verification session, streamed and gated."""

    def __init__(
        self,
        *,
        agent_name: str,
        model: str | None = None,
        on_event: EventEmit | None = None,
        guard_check: Callable[[str, dict], tuple[bool, str]] | None = None,
        max_turns: int = 24,
        finding_sink: Callable[[dict], None] | None = None,
        allow_web: bool = True,
        egress_hosts: list[str] | None = None,
        perms: object | None = None,
        web_budget: int | None = None,
    ) -> None:
        self.agent_name = agent_name
        self.model = model
        self.on_event = on_event or (lambda *_: None)
        self.guard_check = guard_check
        self.max_turns = max_turns
        # Hard cap on WebSearch/WebFetch calls for this session (None = uncapped). Stops a stuck
        # agent from degenerating into endless web searching (e.g. looking up "<product> P1s")
        # instead of analyzing the code — web is for technique/spec, not for the answer.
        self.web_budget = web_budget
        self._web_calls = 0
        # When live testing is armed, the authorized egress allowlist confines the agent's bash
        # network calls to in-scope hosts (None = static mode, no network confinement). §9.
        self.egress_hosts = egress_hosts
        # Parent A's per-engagement PermissionPolicy (network/install/deny posture). None = the
        # default loosened jail. Honored in _decide for Bash and the web tools. §6/§9.
        self.perms = perms
        # If set, exposes a write-only ``post_finding`` blackboard tool to this session: the
        # agent can WRITE findings the moment it confirms one, but gets no tool to READ the board
        # back (so a stuck hunter cannot copy another's work). §11 write-only access model.
        self.finding_sink = finding_sink
        self.allow_web = allow_web  # hunters run with this False — web is a distraction + context bloat
        self.tool_calls = 0

    async def run(self, prompt: str, cwd: str, *, lens: str = "") -> SessionResult:
        if not sdk_available():
            return SessionResult(ok=False, text="", error="claude-agent-sdk/CLI unavailable")
        try:
            from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, HookMatcher
        except Exception as exc:  # pragma: no cover
            return SessionResult(ok=False, text="", error=f"sdk import failed: {exc}")

        # The workspace-jail decision for one tool call. Returns (allowed, reason, updated_input).
        # `updated_input` transparently corrects a hallucinated absolute path into the real in-repo
        # path so the agent doesn't waste a turn. NOTHING here raises — the hook below is fail-closed.
        def _decide(tool_name: str, tool_input: dict) -> tuple[bool, str, dict | None]:
            updated_input = None
            if tool_name in _FILE_TOOLS or tool_name in _WRITE_TOOLS:
                remapped = _remap_tool_input(tool_input, cwd)
                if remapped is not None:
                    updated_input = remapped
                    tool_input = remapped
            if tool_name in _RESEARCH_TOOLS:
                # Web tools need both the agent's web grant AND Parent A's network permission.
                net_ok = getattr(self.perms, "allow_network", True) if self.perms is not None else True
                if not net_ok:
                    return False, "web disabled: network egress is OFF for this engagement (Parent A policy)", None
                if not self.allow_web:
                    return False, "web disabled for this agent — focus on the code", None
                # Budget cap: a few searches for technique/spec, then back to the code. Prevents the
                # "gave up and kept searching for the product's prior disclosures" failure mode.
                if self.web_budget is not None and self._web_calls >= self.web_budget:
                    return False, (f"web research budget exhausted ({self.web_budget} searches) — "
                                   "the answer is in the CODE, not the web; analyze it"), None
                self._web_calls += 1
                return True, "web research (technique/spec)", None
            if tool_name in ("Task", "Agent"):
                # Sub-agent dispatch is allowed; the sub-agent's OWN tool calls hit this same hook,
                # so the workspace-jail still gates everything it does. Emit a lifecycle marker so the
                # cockpit shows "working (sub-agent)" instead of the thread looking FROZEN while the
                # sub-agent reads silently (the main cause of an agent appearing stuck).
                _desc = str(tool_input.get("description") or tool_input.get("prompt") or "deep read")[:80]
                self.on_event(self.agent_name, "lifecycle",
                              {"event": "subagent", "detail": f"dispatched sub-agent: {_desc}"})
                return True, "sub-agent dispatch", None
            if tool_name.startswith("mcp__p1hunt__"):
                return True, "blackboard write (write-only)", None
            if tool_name in ("AskUserQuestion", "ask_user_question"):
                return (
                    False,
                    "operator is unavailable; proceed autonomously with best judgment unless a safety/scope stop condition is reached",
                    None,
                )
            if tool_name in _FILE_TOOLS:
                if self.guard_check is not None:
                    a, r = self.guard_check(tool_name, tool_input)
                    return a, r, updated_input
                return True, "read-only file tool", updated_input
            if tool_name in _WRITE_TOOLS:
                if self.guard_check is not None:
                    a, r = self.guard_check(tool_name, tool_input)
                    return a, r, updated_input
                return False, "no workspace guard configured", None
            if tool_name == "Bash":
                a, r = bash_safety(str(tool_input.get("command", "")), workspace=cwd,
                                   egress_hosts=self.egress_hosts, policy=self.perms)
                return a, r, None
            # Unknown tools (TodoWrite, etc.) are read-only/harmless to the workspace — allow.
            return True, f"{tool_name} (no workspace effect)", None

        # PreToolUse HOOK — the SOLE gate for EVERY tool call (incl. sub-agents), independent of the
        # CLI's permission rules. (`can_use_tool` only fires on an "ask" decision and is bypassed for
        # anything settings/sandbox pre-resolve — see SDK types.py; the hook fires regardless.) It is
        # FAIL-CLOSED: any internal error denies. Paired with permission_mode="bypassPermissions" so
        # an allowed write/forge actually runs instead of hitting a headless "ask"→deny.
        async def pre_tool_use_hook(input_data: dict, tool_use_id: Any, context: Any) -> dict:
            try:
                data = input_data or {}
                tool_name = str(data.get("tool_name", ""))
                tool_input = dict(data.get("tool_input", {}) or {})
                allowed, reason, updated = _decide(tool_name, tool_input)
            except Exception as exc:  # never let the gate raise — deny on any fault
                tool_name, tool_input, allowed, reason, updated = (
                    str((input_data or {}).get("tool_name", "?")), {}, False,
                    f"gate error (fail-closed): {exc}", None)
            self.on_event(
                "scopeguard", "guard_decision",
                {"allow": allowed, "reason": reason, "tool": tool_name, "agent": self.agent_name,
                 "target": str(tool_input.get("file_path") or tool_input.get("path")
                              or tool_input.get("command") or tool_input.get("query") or cwd)[:160]},
            )
            spec: dict[str, Any] = {"hookEventName": "PreToolUse",
                                    "permissionDecision": "allow" if allowed else "deny"}
            if not allowed:
                spec["permissionDecisionReason"] = reason
            elif updated is not None:
                spec["updatedInput"] = updated
            return {"hookSpecificOutput": spec}

        # SUB-AGENT permission path. The PreToolUse hook gates the main session, but Task/Agent
        # sub-agents route their tool calls through a `can_use_tool` CALLBACK that must return a
        # PermissionResult object (returning a dict faults it → the sub-agent falls back to read-only,
        # breaking delegated harness writes). Provide it (reusing the same _decide jail) so sub-agent
        # writes/forge work too. Imported defensively so the offline suite (no SDK) stays hermetic.
        try:
            from claude_agent_sdk import PermissionResultAllow, PermissionResultDeny
            _HAVE_PERM = True
        except Exception:
            _HAVE_PERM = False

        async def can_use_tool(tool_name: str, tool_input: dict, *_a: Any, **_k: Any) -> Any:
            try:
                allowed, reason, updated = _decide(str(tool_name), dict(tool_input or {}))
            except Exception as exc:
                allowed, reason, updated = False, f"gate error (fail-closed): {exc}", None
            self.on_event(
                "scopeguard", "guard_decision",
                {"allow": allowed, "reason": reason, "tool": tool_name, "agent": self.agent_name,
                 "target": str((tool_input or {}).get("file_path") or (tool_input or {}).get("path")
                              or (tool_input or {}).get("command") or (tool_input or {}).get("query") or cwd)[:160]},
            )
            if allowed:
                return PermissionResultAllow(updated_input=updated) if updated is not None else PermissionResultAllow()
            return PermissionResultDeny(message=reason)

        # Write-only blackboard tool (§11): hunters may POST findings the instant they confirm
        # one, but have no tool to read the board back. Built only when a sink is provided.
        mcp_servers: dict = {}
        if self.finding_sink is not None:
            try:
                from claude_agent_sdk import create_sdk_mcp_server, tool as _sdk_tool

                _sink = self.finding_sink

                @_sdk_tool(
                    "post_finding",
                    "Post a code/request-substantiated finding to the shared blackboard after a focused "
                    "depth check — WRITE-ONLY (you cannot read the board back). Include what evidence "
                    "you checked, what escalation/proof you attempted, and what still blocks confirmed "
                    "critical status. Also separate the target-owned defect from anything supplied "
                    "by your harness, mocks, fixtures, accounts, local setup, external services, or "
                    "integrator-only implementations; set relies_on_non_target_behavior=true if the "
                    "win depends on those. Parent A will route it through verifier/prover/deep-dive.",
                    {"title": str, "severity": str, "file": str, "line": int,
                     "root_cause": str, "counterfactual": str, "evidence": str, "reproduction": str,
                     "attempted_escalation": str, "verification_depth": str, "blocked_by": str,
                     "target_code_attribution": str, "non_target_attribution": str,
                     "relies_on_non_target_behavior": bool, "attribution_notes": str},
                )
                async def post_finding(args: dict) -> dict:
                    # The finding is actually captured when we observe this tool call in the
                    # stream (_consume) — that path is reliable regardless of MCP dispatch. This
                    # handler just acknowledges so the model continues hunting.
                    return {"content": [{"type": "text",
                                         "text": "Recorded to the blackboard (write-only). Keep hunting for more."}]}

                mcp_servers = {"p1hunt": create_sdk_mcp_server("p1hunt", tools=[post_finding])}
            except Exception:
                mcp_servers = {}

        async def _attempt(model: str | None) -> SessionResult:
            # Streaming-mode client gated by a PreToolUse HOOK (the workspace-jail). We use
            # permission_mode="bypassPermissions" so an APPROVED write/forge actually executes
            # instead of hitting a headless "ask"→deny, and setting_sources=[] so the operator's
            # ~/.claude settings (allow/deny lists, defaultMode) cannot pre-resolve or override our
            # gate — the hook is the SOLE authority for every tool call, sub-agents included (§3, §9).
            options = ClaudeAgentOptions(
                cwd=cwd,
                permission_mode="bypassPermissions",
                setting_sources=[],
                hooks={"PreToolUse": [HookMatcher(hooks=[pre_tool_use_hook])]},
                # can_use_tool covers the sub-agent permission path (PermissionResult, not a dict).
                **({"can_use_tool": can_use_tool} if _HAVE_PERM else {}),
                max_turns=self.max_turns,
                include_partial_messages=True,  # stream Claude's exact thinking token-by-token
                **({"mcp_servers": mcp_servers} if mcp_servers else {}),
                **({"model": model} if model else {}),
            )
            final_text = ""

            async def _drive() -> None:
                nonlocal final_text
                async with ClaudeSDKClient(options=options) as client:
                    await client.query(prompt)
                    agen = client.receive_response()
                    while True:
                        # INACTIVITY guard: each next-message wait is bounded — a hung/throttled
                        # SDK that streams nothing for SESSION_TIMEOUT is aborted (not left to hang).
                        try:
                            message = await asyncio.wait_for(agen.__anext__(), timeout=SESSION_TIMEOUT)
                        except StopAsyncIteration:
                            break
                        final_text = self._consume(message) or final_text

            try:
                await _drive()
            except asyncio.TimeoutError:
                return SessionResult(ok=False, text=final_text, error="rate_limited", tool_calls=self.tool_calls)
            except Exception as exc:
                err = str(exc)
                tag = "rate_limited" if _looks_rate_limited(err) else err
                return SessionResult(ok=False, text=final_text, error=tag, tool_calls=self.tool_calls)
            if _looks_rate_limited(final_text):
                return SessionResult(ok=False, text=final_text, error="rate_limited", tool_calls=self.tool_calls)
            return SessionResult(ok=True, text=final_text, findings=parse_findings(final_text, lens),
                                 tool_calls=self.tool_calls)

        # THROTTLE GATE: if the swarm is in a shared rate-limit cooldown, wait it out BEFORE
        # attempting (so we never spin/hammer the API). Resumes the instant the window clears.
        await _await_throttle(self.on_event, self.agent_name)

        # Try the configured model; if it is usage/rate-limited (Opus throttles first), normally
        # downgrade and retry so the swarm keeps working. But silently dropping a DEEP reasoning
        # agent from Opus to Sonnet mid-hunt quietly degrades discovery quality — so when
        # P1HUNT_NO_MODEL_DOWNGRADE=1, we do NOT downgrade: we trip the shared cooldown and wait,
        # then retry on the SAME (strongest) model. Keeps every discovery turn at full capability.
        no_downgrade = os.environ.get("P1HUNT_NO_MODEL_DOWNGRADE", "0") == "1"
        candidates: list[str | None] = [self.model]
        if not no_downgrade:
            for m in ("sonnet", None):
                if m not in candidates:
                    candidates.append(m)
        last = SessionResult(ok=False, text="", error="no attempt")
        for model in candidates:
            last = await _attempt(model)
            if last.ok:
                _clear_throttle()  # window is open again — release the whole swarm
                self.on_event(self.agent_name, "lifecycle",
                              {"event": "model_status", "engine": "claude",
                               "model": str(model or self.model), "state": "available"})
                return last
            if last.error != "rate_limited":
                return last
            self.on_event(self.agent_name, "lifecycle",
                          {"event": "model_downgrade", "from": str(model), "reason": "usage/rate limit"})
            self.on_event(self.agent_name, "lifecycle",
                          {"event": "model_status", "engine": "claude",
                           "model": str(model or self.model), "state": "rate_limited"})
        # Every model was throttled → trip the shared cooldown so all sessions back off together.
        backoff = _trip_throttle(reason=f"{self.agent_name} exhausted all models")
        self.on_event(self.agent_name, "lifecycle",
                      {"event": "backoff", "reason": f"all models rate-limited — swarm cooling down {int(backoff)}s"})
        return SessionResult(ok=False, text=last.text, error="rate_limited",
                             tool_calls=self.tool_calls)

    def _consume(self, message: Any) -> str | None:
        """Tee one SDK message to the event log; return final text if present. Handles partial
        StreamEvents so the operator sees Claude's EXACT thinking stream live, token by token."""
        usage = getattr(message, "usage", None)
        if isinstance(usage, dict):
            total = (
                usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
                + usage.get("cache_read_input_tokens", 0) + usage.get("cache_creation_input_tokens", 0)
            )
            self.on_event(self.agent_name, "usage", {
                "input": usage.get("input_tokens", 0), "output": usage.get("output_tokens", 0),
                "total": total, "cost": getattr(message, "total_cost_usd", 0) or 0,
            })
        result = getattr(message, "result", None)
        if isinstance(result, str):
            return result

        # StreamEvent — raw Anthropic stream event carrying partial deltas (live tokens).
        ev = getattr(message, "event", None)
        if isinstance(ev, dict):
            etype = ev.get("type")
            if etype == "content_block_start":
                cb = ev.get("content_block", {}) or {}
                if cb.get("type") in ("text", "thinking"):
                    self.on_event(self.agent_name, "stream_start", {"block": cb.get("type")})
            elif etype == "content_block_delta":
                delta = ev.get("delta", {}) or {}
                dt = delta.get("type")
                if dt == "text_delta" and delta.get("text"):
                    self.on_event(self.agent_name, "stream", {"text": delta["text"]})
                elif dt == "thinking_delta" and delta.get("thinking"):
                    self.on_event(self.agent_name, "stream", {"text": delta["thinking"], "thinking": True})
            return None

        # AssistantMessage — complete blocks: capture final text, tool calls, extended thinking.
        content = getattr(getattr(message, "message", None), "content", None)
        if content is None:
            content = getattr(message, "content", None)
        if not isinstance(content, list):
            return None

        text_out = None
        for block in content:
            tname = getattr(block, "name", None)
            if tname:  # ToolUseBlock
                self.tool_calls += 1
                tinput = getattr(block, "input", {}) or {}
                # Write-only blackboard: capture the finding the moment the hunter posts it. We
                # read it straight off the tool-use block (reliable regardless of MCP dispatch).
                if tname == "mcp__p1hunt__post_finding" and self.finding_sink is not None:
                    try:
                        self.finding_sink(dict(tinput))
                    except Exception:
                        pass
                # Show the most descriptive field per tool: Read/Write→file_path, Grep→pattern,
                # Bash→command, WebSearch→query, WebFetch→url. Collapse whitespace so multi-line
                # Bash commands render as a single readable line.
                target = (tinput.get("file_path") or tinput.get("path") or tinput.get("command")
                          or tinput.get("pattern") or tinput.get("query") or tinput.get("url") or "")
                target = " ".join(str(target).split())[:160]
                self.on_event(self.agent_name, "tool_call", {"tool": tname, "target": target})
                continue
            thinking = getattr(block, "thinking", None)
            if thinking:  # extended ThinkingBlock (full)
                self.on_event(self.agent_name, "thinking", {"text": str(thinking)[:6000], "extended": True})
                continue
            text = getattr(block, "text", None)
            if text and text.strip():
                # The model's PRINTED ANSWER (not its reasoning). Emit it as a distinct "output"
                # event so the UI shows it like Claude Code's response — separate from the dim,
                # collapsible "thinking". (Was previously mislabeled "thinking", so the answer
                # vanished into the collapsed reasoning.)
                self.on_event(self.agent_name, "output", {"text": text.strip()[:6000]})
                text_out = text
        return text_out


def parse_ruled_out(text: str) -> list[str]:
    """Extract the optional ``ruled_out`` ledger (short 'investigated, not exploitable' notes)
    from a hunter's JSON reply, so the next round skips re-checking the same dead-ends."""
    if not text:
        return []
    cands = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        cands.append(m.group(0))
    for raw in cands:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and isinstance(data.get("ruled_out"), list):
            return [str(x).strip() for x in data["ruled_out"] if str(x).strip()][:12]
    return []


def parse_findings(text: str, lens_default: str = "") -> list[ClaudeFinding]:
    """Extract findings from a Claude reply. Accepts a JSON array, a JSON object, or a
    ```json fenced block; tolerates surrounding prose."""
    if not text:
        return []
    blocks = re.findall(r"```(?:json)?\s*(\[.*?\]|\{.*?\})\s*```", text, re.DOTALL)
    candidates = list(blocks)
    if not candidates:
        m = re.search(r"\[\s*\{.*\}\s*\]", text, re.DOTALL) or re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            candidates.append(m.group(0))

    for raw in candidates:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        items = data if isinstance(data, list) else data.get("findings", [data]) if isinstance(data, dict) else []
        out = [ClaudeFinding.from_dict(d, lens_default) for d in items if isinstance(d, dict) and d.get("title")]
        if out:
            return out
    return []


def engine_available(engine: str) -> bool:
    """Is the chosen AI engine runnable? 'codex' needs the codex CLI; 'claude' needs the SDK/CLI."""
    if (engine or "").strip().lower() == "codex":
        try:
            from .codex_session import codex_available
            return codex_available()
        except Exception:
            return False
    return sdk_available()


def make_session(*, model=None, engine: str | None = None, effort: str | None = None,
                 codex_model: str | None = None, **kwargs):
    """Engine-agnostic session factory used by EVERY role (orchestrator, hunters, falsifier, prover,
    exploit-developer, debate, dedup, fuzz). With engine='codex' the whole swarm runs on Codex and
    NOTHING depends on Claude Code. CodexSession is interface-compatible (run(prompt,cwd)->SessionResult).

    engine resolves to: the explicit arg, else $P1HUNT_ENGINE, else 'codex'. The Claude-tier `model`
    is ignored for Codex (Codex uses its account default / $P1HUNT_CODEX_MODEL + per-tier effort).
    """
    import os as _os
    eng = (engine or _os.environ.get("P1HUNT_ENGINE", "codex")).strip().lower()
    if eng not in ("codex", "claude"):
        eng = "codex"
    if eng == "codex":
        from .codex_session import CodexSession
        ck = dict(kwargs)
        if effort:
            ck["effort"] = effort
        if codex_model is not None:
            ck["model"] = codex_model
        return CodexSession(**ck)
    return ClaudeSession(model=model, **kwargs)
