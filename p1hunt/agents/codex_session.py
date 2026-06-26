"""Codex engine for every live AI role in the swarm.

``CodexSession`` is a drop-in for ``ClaudeSession`` (same constructor shape + ``run()`` ->
``SessionResult``) that drives OpenAI's ``codex`` CLI (GPT-5.5-Codex) at xhigh reasoning effort
instead of the Claude Agent SDK. It streams Codex's ``--json`` event log into the SAME event
model the cockpit renders (thinking / tool_call / output / usage), and parses the final message
with the shared ``parse_findings`` so existing prompt-role wrappers can run unchanged.

SAFETY: Codex enforces its OWN OS-level sandbox. We pin it to the workspace via ``--cd`` +
``--sandbox workspace-write`` (writes confined to cwd + tmp) and keep network OFF unless the
engagement's permission posture explicitly allows it — the same workspace-jail intent as the
Claude session's per-tool guard.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Callable

from .claude_session import SessionResult, parse_findings, _looks_rate_limited

# Inactivity timeout: Codex deep-reasoning turns can be quiet longer than the Claude stream, so
# default higher than the SDK's 300s. The swarm's per-hunter wall-clock cap still bounds the whole
# hunt regardless. Raise via P1HUNT_CODEX_TIMEOUT.
CODEX_TIMEOUT = float(os.environ.get("P1HUNT_CODEX_TIMEOUT", "900"))

# Empty = use the codex account's DEFAULT model (required for ChatGPT-account auth, which rejects
# explicit slugs like gpt-5.5-codex). Set P1HUNT_CODEX_MODEL to pin a slug (e.g. with an API key).
DEFAULT_CODEX_MODEL = os.environ.get("P1HUNT_CODEX_MODEL", "")
DEFAULT_CODEX_EFFORT = os.environ.get("P1HUNT_CODEX_EFFORT", "xhigh")
# Fallback models (e.g. Spark) may not accept xhigh, so they get their own (lower) effort. The
# PRIMARY (GPT-5.5) keeps xhigh — that's the deep-reasoning pass that actually finds P1s.
DEFAULT_CODEX_FALLBACK_EFFORT = os.environ.get("P1HUNT_CODEX_FALLBACK_EFFORT", "high")
try:
    OUTPUT_OVERFLOW_RETRIES = max(0, int(os.environ.get("P1HUNT_CODEX_OUTPUT_RETRIES", "1") or 0))
except ValueError:
    OUTPUT_OVERFLOW_RETRIES = 1

_IO_DISCIPLINE_MARKER = "--- P1HUNT HARD IO + CODE-REASONING CONTRACT ---"
_IO_DISCIPLINE = f"""{_IO_DISCIPLINE_MARKER}
Reason your way to the code; do not drown your session in command output.
- First build a compact map from targeted searches, then inspect only the exact functions/windows
  needed for the current hypothesis. Cite shipped file:line for every security claim.
- Never run unbounded broad dumps (`cat`/`nl`/`sed` over whole large files, recursive `find` dumps,
  or `rg --files` without a small cap). Cap broad output with `head -n 120` or equivalent; inspect
  source in <=160-line windows; use `rg -n -m` for symbol searches.
- Large files must be studied by decomposition: search symbols, read narrow windows, and summarize
  the invariant/entrypoint/state transition you actually need. Preserve context for reasoning,
  PoC construction, and proof.
- A finding requires target-owned evidence: exact in-scope code path, attacker-controlled input,
  protected quantity affected, and either a runnable proof or the precise blocker.
"""

_OUTPUT_OVERFLOW_RECOVERY_MARKER = "--- P1HUNT OUTPUT OVERFLOW RECOVERY ---"
_OUTPUT_OVERFLOW_RECOVERY = f"""{_OUTPUT_OVERFLOW_RECOVERY_MARKER}
Your previous Codex attempt failed because tool output exceeded the event parser limit. Continue the
same task from scratch, but obey these extra limits strictly:
- No command may print more than about 120 lines unless it is the final JSON answer.
- If you need a big file, locate symbols with capped `rg`, then read one <=120-line window at a time.
- Do not repeat the command shape that overflowed. Produce compact JSON at the end.
"""


# Rate-limit handling. On a usage/rate limit we wait this long then retry, repeatedly, until it
# clears — and meanwhile FAIL OVER to a non-exhausted fallback model (e.g. GPT-5.3-Codex-Spark when
# GPT-5.5 is capped). The primary is always preferred, so the instant its cooldown lapses (its quota
# resets) the engine FAILS BACK to it automatically.
RETRY_WAIT = float(os.environ.get("P1HUNT_RATE_LIMIT_WAIT", "240"))       # 4 minutes
MAX_WAIT = float(os.environ.get("P1HUNT_RATE_LIMIT_MAX_WAIT", "3600"))    # cap one session's waiting

# Shared across every CodexSession in the process: model slug -> epoch when usable again.
_MODEL_COOLDOWN: dict[str, float] = {}


def _model_cooling(model: str) -> float:
    """Seconds until ``model`` is usable again (0 = available now)."""
    return max(0.0, _MODEL_COOLDOWN.get(model, 0.0) - time.time())


def _mark_cooldown(model: str, seconds: float) -> None:
    _MODEL_COOLDOWN[model] = time.time() + seconds


def _clear_cooldown(model: str) -> None:
    _MODEL_COOLDOWN.pop(model, None)


def model_cooldowns() -> dict:
    """Observed per-model cooldown remaining (seconds) — for the UI model-status tab."""
    now = time.time()
    return {m: max(0, int(ts - now)) for m, ts in _MODEL_COOLDOWN.items() if ts > now}


def _operator_jumpstart_requested(since_ts: float) -> bool:
    """True when the shared web/CLI jumpstart button was clicked after ``since_ts``.

    Codex keeps its own per-model cooldown map in this process. The web server runs in a different
    process, so the only reliable cross-process signal is the shared throttle file written by
    ``/api/session-limit-check`` and ``p1hunt jumpstart``.
    """
    try:
        from .. import session_limit
        doc = session_limit.read_throttle(session_limit.THROTTLE_FILE)
        at = float(doc.get("at") or 0.0)
        return bool(doc.get("manual")) and not bool(doc.get("throttled", True)) and at >= since_ts
    except (OSError, TypeError, ValueError):
        return False


def _err_kind(s: str) -> str:
    """Classify a codex error: 'rate_limited' (retry/fail-over) vs 'auth' (non-retryable) vs ''."""
    s = (s or "").lower()
    if any(k in s for k in ("usage limit", "rate limit", "rate-limit", "quota", "429",
                            "try again", "too many requests")):
        return "rate_limited"
    if any(k in s for k in ("401", "unauthor", "not supported", "invalid_request", "no auth")):
        return "auth"
    return ""


def _looks_output_overflow(s: str) -> bool:
    """True for Codex/PTY parser failures caused by oversized tool output chunks."""
    s = (s or "").lower()
    return any(k in s for k in (
        "chunk is longer than limit",
        "chunk exceed the limit",
        "separator is found, but chunk",
        "separator is not found",
        "output exceeded",
        "event parser limit",
    ))


def _with_io_discipline(prompt: str, *, retry: bool = False) -> str:
    """Append the global code-reasoning / bounded-output contract once per Codex turn."""
    prompt = prompt or ""
    if _IO_DISCIPLINE_MARKER not in prompt:
        prompt = prompt.rstrip() + "\n\n" + _IO_DISCIPLINE
    if retry and _OUTPUT_OVERFLOW_RECOVERY_MARKER not in prompt:
        prompt = prompt.rstrip() + "\n\n" + _OUTPUT_OVERFLOW_RECOVERY
    return prompt


def codex_available() -> bool:
    """True when the ``codex`` CLI is on PATH (the discovery engine can actually run)."""
    return shutil.which("codex") is not None


class CodexSession:
    """One Codex hunting session, streamed and workspace-jailed — interface-compatible with
    ``ClaudeSession`` so the hunter can use either engine for discovery."""

    def __init__(
        self,
        *,
        agent_name: str,
        model: str | None = None,
        on_event: Callable[[str, str, dict], None] | None = None,
        guard_check: Callable[[str, dict], tuple[bool, str]] | None = None,
        max_turns: int = 24,
        finding_sink: Callable[[dict], None] | None = None,
        allow_web: bool = False,
        egress_hosts: list[str] | None = None,
        perms: object | None = None,
        web_budget: int | None = None,
        effort: str | None = None,
        fallback_models: list | None = None,
        fallback_effort: str | None = None,
    ) -> None:
        self.agent_name = agent_name
        # Preserve an explicit "" (means "account default — omit --model"); None falls back to default.
        self.model = model if model is not None else DEFAULT_CODEX_MODEL
        self.effort = effort or DEFAULT_CODEX_EFFORT                       # primary (GPT-5.5) -> xhigh
        self.fallback_effort = fallback_effort or DEFAULT_CODEX_FALLBACK_EFFORT  # Spark etc. -> high
        # Failover chain: tried in order when the primary is rate-limited. Default: GPT-5.3-Codex-Spark.
        if fallback_models is None:
            _env = os.environ.get("P1HUNT_CODEX_FALLBACKS", "gpt-5.3-codex-spark")
            fallback_models = [m.strip() for m in _env.split(",") if m.strip()]
        self.fallback_models = fallback_models
        self.on_event = on_event or (lambda *_: None)
        self.guard_check = guard_check          # Codex uses its OWN sandbox; kept for interface parity
        self.max_turns = max_turns              # advisory only — Codex self-terminates a turn
        self.finding_sink = finding_sink
        self.allow_web = allow_web
        self.egress_hosts = egress_hosts
        self.perms = perms
        self.web_budget = web_budget
        self.tool_calls = 0
        self._stream_error = ""   # set if Codex streams an error event (auth/401/rate-limit/etc.)
        self._last_progress_sig = ""

    def _network_allowed(self) -> bool:
        """Network only if the engagement posture allows it AND web is granted to this agent."""
        net_ok = getattr(self.perms, "allow_network", True) if self.perms is not None else True
        return bool(self.allow_web and net_ok)

    def _installs_allowed(self) -> bool:
        return bool(getattr(self.perms, "allow_install", True)) if self.perms is not None else True

    def _install_write_dirs(self) -> list[str]:
        """User-local writable roots for non-destructive tool provisioning under Codex's sandbox.

        Codex's workspace-write sandbox is the right default, but it blocks useful installs such as
        `pip --user`, `cargo install`, or a local `jq` binary. When Parent A allows installs, expose
        the standard per-user tool/cache locations without granting full host write access.
        """
        if not self._installs_allowed():
            return []
        home = Path.home()
        candidates = [
            home / ".local",
            home / ".cache",
            home / ".cargo",
            home / ".rustup",
            home / "go",
            home / ".npm",
            home / ".config" / "npm",
        ]
        out: list[str] = []
        for p in candidates:
            try:
                p.mkdir(parents=True, exist_ok=True)
                out.append(str(p))
            except OSError:
                continue
        return out

    def _model_chain(self) -> list:
        """Models to try, primary first. Failback is automatic: the primary stays first, so once its
        cooldown lapses it's chosen again over any fallback."""
        chain = [self.model]
        for m in self.fallback_models:
            if m != self.model:
                chain.append(m)
        return chain

    def _pick_model(self):
        """The highest-priority model NOT currently cooling down, or None if all are cooling."""
        for m in self._model_chain():
            if _model_cooling(m) <= 0:
                return m
        return None

    def _effort_for(self, model) -> str:
        """Per-model reasoning effort: the primary (GPT-5.5) gets the full xhigh deep-reasoning pass;
        fallbacks (Spark) get a lower effort they actually support."""
        return self.effort if model == self.model else self.fallback_effort

    def _build_cmd(self, cwd: str, last_msg_file: str, model=None) -> list[str]:
        """The codex argv (no shell). Pinned to the workspace, configured reasoning, JSONL events.
        Factored out so it's unit-testable without spawning Codex."""
        if model is None:
            model = self.model
        cmd = [
            "codex", "exec",
            "--json",                       # structured event stream we map to cockpit events
            "--skip-git-repo-check",        # the target may not be a git repo
            "--cd", str(Path(cwd).resolve()), # workspace jail (absolute; subprocess cwd is also set)
            "--sandbox", "workspace-write", # OS sandbox: writes confined to cwd + tmp
            "--output-last-message", last_msg_file,
            "-c", f'model_reasoning_effort="{self._effort_for(model)}"',
        ]
        for d in self._install_write_dirs():
            cmd += ["--add-dir", d]
        # Only pin a model when one is configured. ChatGPT-account auth rejects explicit slugs
        # (e.g. gpt-5.5-codex) and runs the account default — so an empty model => omit --model.
        if model and str(model).strip():
            cmd += ["--model", str(model)]
        if self._network_allowed():
            cmd += ["-c", "sandbox_workspace_write.network_access=true"]
        return cmd

    def _emit_item(self, item: dict, acc: list[str]) -> None:
        """Map one Codex stream item to a cockpit event (best-effort; tolerant of schema drift)."""
        itype = str(item.get("type") or item.get("item_type") or "")
        if itype in ("reasoning", "thinking"):
            txt = str(item.get("text") or item.get("content") or "")
            if txt:
                self.on_event(self.agent_name, "thinking", {"text": txt[:6000], "extended": True})
        elif itype in ("command_execution", "command", "exec", "local_shell_call"):
            cmd = str(item.get("command") or item.get("cmd") or item.get("input") or "")
            self.tool_calls += 1
            self.on_event(self.agent_name, "tool_call", {"tool": "Bash", "target": cmd[:600]})
            self._emit_progress_for_command(cmd)
        elif itype in ("file_change", "patch", "apply_patch"):
            tgt = str(item.get("path") or item.get("files") or item.get("summary") or "")
            self.tool_calls += 1
            self.on_event(self.agent_name, "tool_call", {"tool": "Edit", "target": str(tgt)[:600]})
        elif itype in ("agent_message", "message", "assistant_message", "output_text"):
            txt = str(item.get("text") or item.get("content") or "")
            if txt:
                acc.append(txt)
                self.on_event(self.agent_name, "output", {"text": txt[:6000]})

    def _emit_progress_for_command(self, cmd: str) -> None:
        """Emit operator-readable progress for long Codex turns.

        Codex may not expose private reasoning text, and we should not invent it. The operator still
        needs to know what the agent is doing, so derive a concise status from observable actions:
        file reads, symbol searches, tests, builds, and proof runs.
        """
        msg = _progress_for_command(cmd)
        if not msg:
            return
        sig = f"{msg}|{cmd[:160]}"
        if sig == self._last_progress_sig:
            return
        self._last_progress_sig = sig
        self.on_event(self.agent_name, "message", {
            "phase": "progress",
            "detail": msg,
            "target": _progress_target(cmd),
        })

    def _handle_line(self, line: str, acc: list[str]) -> None:
        """Parse one JSONL line from ``codex exec --json`` and emit the matching event."""
        line = line.strip()
        if not line:
            return
        try:
            ev = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return  # non-JSON banner/log line — ignore
        if not isinstance(ev, dict):
            return
        etype = str(ev.get("type") or "")
        # Codex exits 0 even when the run failed (auth/401/quota) — it just streams error events.
        # Capture them so run() reports a real failure instead of a silent empty "success".
        if etype == "error" or (isinstance(ev.get("item"), dict) and ev["item"].get("type") == "error"):
            msg = str(ev.get("message") or (ev.get("item") or {}).get("message") or "error")
            self._stream_error = msg[:300]
            return
        if "item" in ev and isinstance(ev["item"], dict):
            self._emit_item(ev["item"], acc)
        elif etype in ("reasoning", "thinking", "command_execution", "agent_message",
                       "message", "file_change", "patch"):
            self._emit_item(ev, acc)
        elif etype in ("turn.completed", "usage") or "usage" in ev:
            u = ev.get("usage") or {}
            if isinstance(u, dict):
                tot = int(u.get("total_tokens") or u.get("total") or 0) or None
                self.on_event(self.agent_name, "usage",
                              {"total": tot, "input": u.get("input_tokens"),
                               "output": u.get("output_tokens"), "engine": "codex"})

    async def run(self, prompt: str, cwd: str, *, lens: str = "") -> SessionResult:
        """Run Codex with automatic rate-limit handling: prefer the primary model, FAIL OVER to a
        fallback (e.g. Spark) while the primary is cooling, WAIT-and-retry (4 min) when every model
        is capped, and FAIL BACK to the primary the instant its quota resets."""
        if not codex_available():
            return SessionResult(ok=False, text="",
                                 error="codex CLI unavailable — install/authenticate the `codex` CLI or run deterministic mode")
        waited = 0.0
        overflow_retries = 0
        while True:
            model = self._pick_model()
            if model is None:  # every model is cooling down -> wait, then re-check (auto fail-back)
                chain = self._model_chain()
                wait = min(RETRY_WAIT, max(1.0, min(_model_cooling(m) for m in chain)))
                if waited + wait > MAX_WAIT:
                    return SessionResult(ok=False, error="rate_limited",
                                         text="all codex models rate-limited — gave up this session")
                self.on_event(self.agent_name, "lifecycle",
                              {"event": "codex_rate_wait", "wait_s": int(wait),
                               "detail": f"all codex models rate-limited — waiting {int(wait)}s then retrying"})
                slept = await self._await_cooldown_or_jumpstart(wait)
                waited += slept
                continue
            run_prompt = _with_io_discipline(prompt, retry=overflow_retries > 0)
            res = await self._run_once(run_prompt, cwd, lens=lens, model=model)
            if res.error == "output_overflow" and overflow_retries < OUTPUT_OVERFLOW_RETRIES:
                overflow_retries += 1
                self.on_event(self.agent_name, "lifecycle",
                              {"event": "codex_output_retry",
                               "attempt": overflow_retries,
                               "detail": "tool output overflowed; retrying with strict capped-output instructions"})
                continue
            if res.error == "rate_limited":
                _mark_cooldown(model, RETRY_WAIT)   # cool this model, loop -> fail over or wait
                self.on_event(self.agent_name, "lifecycle",
                              {"event": "model_status", "engine": "codex",
                               "model": model or "codex-default", "state": "rate_limited",
                               "cooldown_s": int(RETRY_WAIT)})
                continue
            if res.ok:                              # this model worked -> it's healthy again
                if _model_cooling(model) > 0 or model in _MODEL_COOLDOWN:
                    _clear_cooldown(model)
                    self.on_event(self.agent_name, "lifecycle",
                                  {"event": "model_status", "engine": "codex",
                                   "model": model or "codex-default", "state": "available"})
            return res                              # success, or a non-retryable error (auth/etc.)

    async def _await_cooldown_or_jumpstart(self, wait: float) -> float:
        """Wait for a Codex retry window, but let the operator's web jumpstart cut it short."""
        started = time.time() - 1.0
        deadline = time.monotonic() + max(0.0, float(wait))
        slept = 0.0
        while True:
            if _operator_jumpstart_requested(started):
                _MODEL_COOLDOWN.clear()
                self.on_event(self.agent_name, "lifecycle",
                              {"event": "model_status", "engine": "codex",
                               "model": "all", "state": "available",
                               "detail": "operator jumpstart — clearing Codex cooldowns and retrying now"})
                return slept
            rem = deadline - time.monotonic()
            if rem <= 0:
                return slept
            step = min(rem, 5.0)
            await asyncio.sleep(step)
            slept += step

    async def _run_once(self, prompt: str, cwd: str, *, lens: str = "", model=None) -> SessionResult:
        if model is None:
            model = self.model
        self._stream_error = ""
        prompt = _with_io_discipline(prompt)

        fd, last_msg_file = tempfile.mkstemp(prefix="p1hunt-codex-", suffix=".txt")
        os.close(fd)
        # LIVE BLACKBOARD: Codex has no post_finding MCP tool (only ClaudeSession does), so without
        # this the blackboard stays EMPTY during a long Codex hunt. Give Codex a file protocol — it
        # appends each finding as a JSON line the moment it finds one, and we tail that file during
        # the run and post live (parity with Claude's write-only blackboard tool).
        live_file = os.path.join(cwd, ".p1hunt_live_findings.jsonl")
        try:
            if os.path.exists(live_file):
                os.remove(live_file)
        except OSError:
            pass
        if self.finding_sink is not None:
            prompt = prompt + (
                "\n\n--- LIVE FINDINGS PROTOCOL (do this IN ADDITION to your final JSON) ---\n"
                "Post useful leads early, but never post a bare hunch. Before writing a blackboard line, "
                "do a focused depth check: identify the exact sink/endpoint/file:line, try the smallest "
                "safe PoC or escalation path you can, and record what blocked confirmation if anything. "
                "Then append ONE compact JSON line to ./.p1hunt_live_findings.jsonl (create if missing), e.g.:\n"
                "  printf '%s\\n' '{\"title\":\"...\",\"severity\":\"critical|high|medium|low\","
                "\"file\":\"path\",\"line\":N,\"root_cause\":\"...\",\"evidence\":\"...\","
                "\"attempted_escalation\":\"what you tried to prove impact\","
                "\"verification_depth\":\"code/request/PoC evidence already checked\","
                "\"blocked_by\":\"what still prevents confirmed critical, or empty\"}' >> .p1hunt_live_findings.jsonl\n"
                "One JSON object per line, appended as you go — this posts it to the team blackboard "
                "as a candidate for Parent A's verifier/prover/deep-dive pipeline. Still return your full final JSON too.")
        if self._installs_allowed():
            prompt = prompt + (
                "\n\n--- TOOLING PERMISSION ---\n"
                "If an audit utility is missing, install it yourself instead of degrading analysis. "
                "Prefer user-local, non-destructive installs that land under ~/.local, ~/.cache, "
                "~/.cargo, ~/go, or the workspace: examples include pip --user/pipx, cargo install, "
                "go install, npm with a user prefix, downloading a single official static binary, or "
                "project-local npm/pip/cargo dependencies. Do not run destructive host operations "
                "(disk formatting, reboot/shutdown, rm -rf /, secret scraping) and do not touch "
                "out-of-scope services. After installing, use the tool and keep hunting.")
        cmd = self._build_cmd(cwd, last_msg_file, model)
        self.on_event(self.agent_name, "lifecycle",
                      {"event": "codex_start", "model": model or "codex-default", "effort": self._effort_for(model)})
        acc: list[str] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=cwd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (FileNotFoundError, OSError) as exc:
            os.unlink(last_msg_file)
            return SessionResult(ok=False, text="", error=f"codex spawn failed: {exc}")

        # Feed the prompt on stdin (avoids argv length limits on large hunt prompts).
        try:
            proc.stdin.write(prompt.encode("utf-8", "replace"))
            await proc.stdin.drain()
            proc.stdin.close()
        except (BrokenPipeError, ConnectionResetError):
            pass

        posted: set = set()

        def _post(d: dict) -> None:
            """Post a finding to the blackboard sink once (dedup by title|file across live + final)."""
            if self.finding_sink is None or not isinstance(d, dict) or not d.get("title"):
                return
            key = f"{str(d.get('title',''))[:120].lower()}|{d.get('file','')}"
            if key in posted:
                return
            posted.add(key)
            try:
                self.finding_sink(d)
            except Exception:
                pass

        live_off = [0]

        def _drain_live() -> None:
            """Tail the live-findings file and post any NEW lines to the blackboard sink."""
            if self.finding_sink is None:
                return
            try:
                with open(live_file, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(live_off[0])
                    chunk = fh.read()
                    live_off[0] = fh.tell()
            except OSError:
                return
            for ln in chunk.splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    d = json.loads(ln)
                except (json.JSONDecodeError, ValueError):
                    continue
                _post(d)   # -> hunter posts it to the blackboard live (deduped)

        async def _drain() -> None:
            assert proc.stdout is not None
            last_wait = time.time()
            while True:
                try:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=30.0)
                except asyncio.TimeoutError:
                    now = time.time()
                    if now - last_wait >= 60.0:
                        last_wait = now
                        self.on_event(self.agent_name, "lifecycle", {
                            "event": "codex_waiting",
                            "detail": "reasoning over gathered evidence; waiting for next command or answer",
                        })
                    continue
                if not line:
                    break
                last_wait = time.time()
                self._handle_line(line.decode("utf-8", "replace"), acc)
                _drain_live()   # post findings the instant Codex writes them

        try:
            await _drain()
            await asyncio.wait_for(proc.wait(), timeout=CODEX_TIMEOUT)
            _drain_live()       # final sweep for any last-written findings
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            text = _read_and_unlink(last_msg_file) or "\n".join(acc)
            return SessionResult(ok=False, text=text, error="rate_limited", tool_calls=self.tool_calls)
        except Exception as exc:  # pragma: no cover - defensive
            _read_and_unlink(last_msg_file)
            return SessionResult(ok=False, text="\n".join(acc), error=str(exc), tool_calls=self.tool_calls)

        text = _read_and_unlink(last_msg_file) or "\n".join(acc)
        rc = proc.returncode or 0
        # A streamed error with no usable output = a failed run even though Codex exited 0.
        if self._stream_error and not text.strip():
            kind = _err_kind(self._stream_error)
            tag = "output_overflow" if _looks_output_overflow(self._stream_error) else (
                "rate_limited" if kind == "rate_limited" else
                f"auth: {self._stream_error[:160]}" if kind == "auth" else f"codex error: {self._stream_error[:160]}")
            self.on_event(self.agent_name, "lifecycle", {"event": "codex_error", "detail": self._stream_error[:200]})
            return SessionResult(ok=False, text="", error=tag, tool_calls=self.tool_calls)
        if rc != 0:
            stderr = b""
            try:
                stderr = await proc.stderr.read()
            except Exception:
                pass
            err_full = stderr.decode("utf-8", "replace")
            err = err_full[:400]
            combined = err_full + "\n" + text
            kind = _err_kind(combined)
            tag = "output_overflow" if _looks_output_overflow(combined) else (
                "rate_limited" if kind == "rate_limited" else f"codex exit {rc}: {err}")
            self.on_event(self.agent_name, "lifecycle", {"event": "codex_error", "detail": tag[:200]})
            return SessionResult(ok=False, text=text, error=tag, tool_calls=self.tool_calls)

        # Final sweep: post any findings from the final report not already posted live (deduped).
        _drain_live()
        if self.finding_sink is not None:
            for cf in parse_findings(text, lens):
                _post(cf.__dict__ if hasattr(cf, "__dict__") else {})
        try:
            os.remove(live_file)
        except OSError:
            pass
        self.on_event(self.agent_name, "lifecycle",
                      {"event": "codex_done", "tool_calls": self.tool_calls, "findings": len(posted)})
        return SessionResult(ok=True, text=text, tool_calls=self.tool_calls)


def _read_and_unlink(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except OSError:
        data = ""
    try:
        os.unlink(path)
    except OSError:
        pass
    return data


def _progress_target(cmd: str) -> str:
    """Best-effort file/command target for UI progress text."""
    cmd = str(cmd or "")
    patterns = [
        r"\bsed\s+-n\s+['\"][^'\"]+['\"]\s+([^|;&]+)",
        r"\bnl\s+-ba\s+([^|;&]+)",
        r"\bcat\s+([^|;&]+)",
        r"\b(?:forge|npm|pytest|ctest|cmake|make|cargo|go)\b\s*([^;&|]*)",
    ]
    for pat in patterns:
        m = re.search(pat, cmd)
        if m:
            return m.group(1).strip().strip("'\"")[:160]
    if "rg " in cmd:
        return "symbol search"
    return ""


def _progress_for_command(cmd: str) -> str:
    """Human-readable description of observable work, never hidden chain-of-thought."""
    raw = str(cmd or "")
    c = raw.lower()
    target = _progress_target(raw)
    if "rg --files" in c or "find " in c and "-type f" in c:
        return "mapping repository files and in-scope components"
    if re.search(r"\brg\b", c):
        return "searching for entrypoints, checks, and attacker-controlled data flow"
    if re.search(r"\b(sed|nl|cat)\b", c):
        if target:
            return f"reading source window: {target}"
        return "reading source window"
    if "forge test" in c or "forge " in c:
        return "running Foundry validation or proof harness"
    if "pytest" in c or "ctest" in c or re.search(r"\bmake\b", c) or "cmake" in c:
        return "building or running local tests"
    if "git status" in c:
        return "checking workspace state"
    if "curl " in c:
        return "checking authorized local/web endpoint"
    return ""
