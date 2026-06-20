"""Claude swarm orchestrator — Parent A driving real Claude agents (spec §6-§10).

The AI is the detector. Parent A derives the plan, assigns each ranked lens to a Child B
(a real Claude hunting session), and runs the never-quit loop: every round each Child B
hunts its lens with a fresh creative angle; the Falsifier (a real Claude session with the
opposite prior) tries to refute each candidate; only a confirmed, reachable critical is
promoted. On a dry round it reframes and digs deeper — it does not give up until a critical
is confirmed or the operator stops.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from ..config import Config
from ..models import (
    ArtifactRef,
    EngagementStatus,
    Finding,
    Hypothesis,
    HypState,
    SafeValidationPlan,
    Scope,
    new_id,
)
from ..orchestrator.blackboard import Blackboard
from ..orchestrator.bus import MessageBus
from ..orchestrator.event_log import EventLog
from ..safety.scopeguard import ScopeGuard
from .claude_hunter import ClaudeHunter, ClaudePoCProver, ClaudeVerifier
from .claude_session import ClaudeFinding
from .fuzz_engine import ClaudeFuzzer
from .derive import derive_plan
from .harness_scaffold import detect_evm_entrypoints
from .parent_a import HuntResult
from ..corpus import CorpusStore
from ..classify.evm_signals import evm_assembly_density, scan_combined
from ..runners.base import ReproSpec, select_runner
from ..severity import ImpactAssessment, SeverityMapper
from ..tools.build_env import BuildReport, bootstrap_environment, ensure_foundry, toolchain_available
from ..tools.evm_fork import fork_available, start_anvil_fork, stop_anvil_fork

_LENSES = [
    "authorization-boundary",
    "asset-custody",
    "trusted-execution",
    "confidentiality",
    "business-logic",
]


class ClaudeSwarm:
    def __init__(
        self,
        scope: Scope,
        repo_path: str,
        *,
        config: Config,
        bus: MessageBus,
        blackboard: Blackboard,
        event_log: EventLog,
        max_concurrency: int = 3,
    ) -> None:
        self.scope = scope
        self.repo_path = repo_path
        self.config = config
        self.bus = bus
        self.bb = blackboard
        self.log = event_log
        self.sem = asyncio.Semaphore(max_concurrency)
        self.name = "parent_a"
        self._safety_event = False
        self._reframes = 0
        self._hyp_by_finding: dict[int, Hypothesis] = {}
        self._focus_by_lens: dict[str, list[str]] = {}
        # Live operator control channel (§11): notices pushed via `p1hunt notify` are read at
        # each round boundary and injected into the next round's hunter prompts — e.g. "new code
        # is now available, keep hunting" — so a running hunt absorbs updates without a restart.
        self._notices: list[str] = []
        self._known_patterns: list[str] = []  # historical bug patterns (Pillar 3) for fuzzers/hunters
        self._control_offset = 0
        # Self-healing watchdog: if the whole swarm goes silent (a hung session blocking the
        # round, or an API rate-limit) for STALL_SECONDS, Parent A diagnoses and fixes it.
        import time as _t
        self._last_activity = _t.monotonic()
        self._round_tasks: list = []
        self._active_guard = None
        self._healing = False
        self._heals = 0
        # PoC sandbox: the ONLY place agents may write (proof-of-concept files), never source.
        self.poc_dir = Path(repo_path) / ".p1hunt-poc"
        self.poc_dir.mkdir(parents=True, exist_ok=True)
        self.bus.register(self.name, "parent")
        # THE ONE HARD GUARDRAIL: the in-scope workspace folder. Agents may do anything INSIDE it
        # (read/write/edit/run/install/network); every file read/write/edit OUTSIDE it is denied.
        # Defaults to the acquired target folder; Parent A ratifies/sets it during recon (clamped
        # to the acquired tree so the boundary can never escape what was authorized).
        self._workspace_root: str = str(Path(repo_path).resolve())
        # --- environment-arming state (set in hunt() via _arm_environment, all graceful) ---
        self._target_class: str = ""          # e.g. "EVM_CONTRACT" — from derive_plan
        self._build: BuildReport | None = None  # build-bootstrap outcome (compiles? diagnostics)
        self._fork_handle = None               # running local anvil fork (EVM, when configured)
        self._fork_url: str = ""               # http://127.0.0.1:PORT agents reach via --fork-url
        self._corpus: CorpusStore | None = None  # cross-round fuzz corpus + coverage memory
        self._subclass: str = ""                # protocol category, only if Parent A names one in recon
        self._entrypoints_by_subsystem: dict[str, list[str]] = {}
        # DERIVED static leads (Solidity-aware scan of the ACTUAL code) — concrete suspect
        # primitives handed to each hunter so the live AI starts from "here is a P1, prove it"
        # rather than a cold read. Populated in _arm_environment; never a preset playbook.
        self._scan_hits: list = []
        # --- live dynamic-testing state (armed in hunt()/_arm_environment when authorized) ---
        # None = static mode (no live target / dry-run); a list = the authorized egress allowlist
        # that confines every agent's outbound request to in-scope hosts (the live safe-harbor jail).
        self._egress_hosts: list[str] | None = None
        self._base_url: str = ""                 # the primary authorized dynamic target base URL
        self._oob = None                         # running loopback OOB interaction listener
        self._dynamic_env_keys: list[str] = []   # env vars _arm_dynamic exported (cleared on exit)
        # COST GUARD: a never-quit run has no natural end, so accumulate spend (from session usage
        # events) and, if the operator set a ceiling, stop GRACEFULLY when it's hit. Default off
        # (None) so behavior is unchanged unless P1HUNT_MAX_COST_USD is set, but the running total
        # is always emitted so spend is never invisible.
        self._spend_usd: float = 0.0
        try:
            _cap = float(os.environ.get("P1HUNT_MAX_COST_USD", "0") or 0)
        except ValueError:
            _cap = 0.0
        self._cost_cap: float | None = _cap if _cap > 0 else None
        # CROSS-ENGAGEMENT MEMORY: learn from our OWN confirmed findings across engagements. Records
        # on promote; recalled at arm time as fallible "hunt a new variant" priors (NOTHING PRESET —
        # derived from past wins, not a baked-in catalog). Disable with P1HUNT_MEMORY=0.
        self._memory = None
        try:
            from ..memory import MemoryStore, default_memory_path, memory_enabled
            if memory_enabled():
                self._memory = MemoryStore(default_memory_path(config.engagements_root))
        except Exception:
            self._memory = None
        # PARENT-A-OWNED runtime permission posture (network/install/deny inside the jail). Starts
        # derived from the program rules; Parent A TIGHTENS it during recon (_apply_permission_policy)
        # and it is threaded into every agent session. §6 step 5 / §9.
        from ..safety.policies import derive_permission_policy
        self._perms = derive_permission_policy(scope)
        # Deterministic severity mapper bound to THIS program's own taxonomy (no preset tiers).
        self._severity = SeverityMapper(getattr(scope, "severity_taxonomy", {}) or {})

    def _emit(self, agent: str, kind: str, data: dict) -> None:
        import time as _t
        self._last_activity = _t.monotonic()  # any event = the swarm is alive (watchdog signal)
        if kind == "usage":  # accumulate spend so a never-quit run can be cost-bounded + visible
            try:
                self._spend_usd += float(data.get("cost", 0) or 0)
            except (TypeError, ValueError):
                pass
        self.log.emit(agent, kind, data)

    # --- self-healing watchdog (§8 never-quit) ----------------------------
    STALL_SECONDS = 300  # 5 min of TOTAL silence = a hung session or a rate-limit stall

    async def _watchdog(self) -> None:
        """Background task: if the swarm emits NOTHING for STALL_SECONDS, self-heal."""
        import time as _t

        while True:
            await asyncio.sleep(20)
            idle = _t.monotonic() - self._last_activity
            if idle >= self.STALL_SECONDS and not self._healing and self._round_tasks:
                self._healing = True
                try:
                    await self._self_heal(idle)
                except Exception as exc:
                    self._emit(self.name, "lifecycle", {"event": "heal_failed", "detail": str(exc)})
                finally:
                    self._last_activity = _t.monotonic()
                    self._healing = False

    async def _self_heal(self, idle: float) -> None:
        """Parent A figures out what's wrong (hung session / rate-limit) and fixes it: cancel the
        stuck round so it can't block forever, inject a corrective directive, back off if throttled."""
        self._heals += 1
        self._emit(self.name, "lifecycle",
                   {"event": "stall_detected", "idle_s": int(idle), "heal": self._heals})
        # 1) Cancel the stuck round so it cannot block the never-quit loop forever.
        cancelled = 0
        for t in list(self._round_tasks):
            if not t.done():
                t.cancel()
                cancelled += 1
        # 2) Parent A diagnoses the cause and writes a corrective directive for the next round.
        diag = await self._diagnose(idle)
        notice = diag.get("notice")
        if notice:
            self._notices.append(notice)
            self._emit(self.name, "message", {"phase": "notice", "notice": "🩺 self-heal: " + notice})
        self._emit(self.name, "lifecycle",
                   {"event": "self_healed", "cancelled": cancelled,
                    "rate_limited": bool(diag.get("rate_limited")), "diagnosis": str(diag.get("diagnosis", ""))[:160]})
        # 3) If it looks like a rate-limit, back off before the next round.
        if diag.get("rate_limited"):
            self._emit(self.name, "lifecycle", {"event": "backoff", "reason": "rate limit — pausing 60s"})
            await asyncio.sleep(60)

    async def _diagnose(self, idle: float) -> dict:
        """Heuristic-first (rate-limit signals in recent events) + a short, timeout-safe Parent A
        reasoning pass. Never blocks: if the diagnosis call itself stalls, fall back to the heuristic."""
        # Heuristic: repeated model downgrades / limit messages = rate-limited.
        recent = list(getattr(self.log, "events", []))[-250:]
        def _ev(e):
            d = getattr(e, "data", None)
            return getattr(e, "kind", ""), (d if isinstance(d, dict) else {})
        rl_hits = sum(1 for e in recent
                      for k, d in [_ev(e)]
                      if k == "lifecycle" and (d.get("event") == "model_downgrade"
                                               or "limit" in str(d.get("reason", "")).lower()))
        rate_limited = rl_hits >= 2
        notice = None
        diagnosis = f"silent {int(idle)}s; downgrade/limit signals={rl_hits}"
        if self.config.use_claude:
            try:
                from .claude_session import ClaudeSession
                prompt = (
                    f"You are Parent A, lead of an autonomous security hunt. The swarm produced NO "
                    f"activity for {int(idle)} seconds — it stalled (a hunter session hung, or the "
                    f"model API is rate-limited). I have cancelled the stuck round. In one or two "
                    f"sentences write a CORRECTIVE directive for the hunters' next round to avoid the "
                    f"stall — e.g. be decisive, write a small PoC and RUN it instead of reading "
                    f"endlessly, delegate big reads to sub-agents, don't spiral. Return ONLY JSON: "
                    f'{{"rate_limited": true|false, "diagnosis": "...", "notice": "<the directive>"}}')
                sess = ClaudeSession(agent_name=self.name, model=self.config.models.orchestrator,
                                     on_event=self._emit, guard_check=None, max_turns=3, allow_web=False,
                                     perms=self._perms, egress_hosts=self._egress_hosts)
                res = await asyncio.wait_for(sess.run(prompt, self.repo_path), timeout=90)
                parsed = _parse_json_object(res.text)
                if parsed.get("notice"):
                    notice = str(parsed["notice"])
                if parsed.get("diagnosis"):
                    diagnosis = str(parsed["diagnosis"])
                rate_limited = rate_limited or bool(parsed.get("rate_limited"))
            except Exception:
                pass  # diagnosis itself stalled/failed → heuristic fallback below
        if not notice:
            notice = ("Last round STALLED. Next round be DECISIVE: form one attack hypothesis fast, "
                      "write a SMALL PoC and RUN it instead of reading endlessly, delegate big reads "
                      "to sub-agents, and never re-read whole files.")
        return {"rate_limited": rate_limited, "diagnosis": diagnosis, "notice": notice}

    def _scope_guidance(self) -> str:
        """Rules-of-engagement + differential guidance injected into recon and hunter prompts."""
        globs = list(getattr(self.scope, "out_of_scope_globs", None) or [])
        note = str(getattr(self.scope, "scope_note", "") or "").strip()
        if not globs and not note:
            return ""
        parts = []
        if note:
            parts.append(note)
        if globs:
            parts.append(
                "IN-SCOPE = the deployed/production code ONLY. OUT-OF-SCOPE (do NOT report findings "
                "here; these are not deployed): " + ", ".join(globs) + ". If one of those paths is a "
                "readable MIRROR of the optimized in-scope code (e.g. a 'reference' implementation), "
                "use it ONLY to understand the optimized code and to DIFF them — any behavioral "
                "divergence between the two is a likely real bug — but every reported finding MUST "
                "cite an IN-SCOPE deployed file and line."
            )
        return "\n\nSCOPE / RULES OF ENGAGEMENT: " + " ".join(parts)

    def _out_of_scope(self, rel_path: str) -> bool:
        import fnmatch

        p = str(rel_path or "").lstrip("./")
        for g in getattr(self.scope, "out_of_scope_globs", None) or []:
            g = g.strip()
            if not g:
                continue
            # Match a glob, an exact path, or a DIRECTORY prefix (with a path-separator boundary).
            # The boundary matters: a bare prefix test would wrongly mark `references/X.sol`
            # out-of-scope for a glob `ref*` and silently drop an in-scope finding.
            base = g.rstrip("*")
            if fnmatch.fnmatch(p, g) or p == base.rstrip("/") or p.startswith(base.rstrip("/") + "/"):
                return True
            # A trailing-* glob (e.g. "reference/*", "test*") still matches by fnmatch above; a bare
            # token without "/" or "*" is treated as a directory, handled by the boundary check above.
        return False

    def _write_findings_json(self, findings, candidates, needs_human=None) -> None:
        """Persist the current findings to ``findings.json`` in the engagement folder. Called at
        every round boundary (so it's always fresh) and on stop/cap — when the scan is stopped,
        the latest findings are already on disk. ``needs_human`` is the prominent tier of believed-
        real, high-confidence P1s that could not be auto-reproduced (surfaced, not buried)."""
        import json as _json
        import time as _time
        from pathlib import Path

        path = getattr(self.log, "path", None)
        if path is None:
            return
        out = Path(path).with_name("findings.json")
        crits = [f for f in findings if f.severity == "critical"]
        nh = needs_human or []
        doc = {
            "program": self.scope.program,
            "updated": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
            "counts": {"confirmed_critical": len(crits), "needs_human_review": len(nh),
                       "candidates": len(candidates)},
            "confirmed_criticals": [
                {"title": f.title, "severity": f.severity, "verified": getattr(f, "verified", True),
                 "location": getattr(f.poc, "path", ""), "root_cause": f.root_cause,
                 "counterfactual": f.counterfactual, "remediation": f.remediation}
                for f in crits
            ],
            # Reasoned P1s a human should look at FIRST — strong reasoning, only the mechanical
            # proof is missing. Listed prominently above the raw candidate dump.
            "needs_human_review": [
                {"title": f.title, "severity": f.severity, "location": getattr(f.poc, "path", ""),
                 "root_cause": f.root_cause, "counterfactual": f.counterfactual,
                 "why_unproven": getattr(f.poc, "description", ""), "remediation": f.remediation}
                for f in nh
            ],
            "candidates": [c.__dict__ for c in candidates],
        }
        try:
            out.write_text(_json.dumps(doc, indent=2), encoding="utf-8")
            self._emit(self.name, "lifecycle",
                       {"event": "findings_written", "path": str(out), "criticals": len(crits),
                        "needs_human_review": len(nh), "candidates": len(candidates)})
        except OSError:
            pass

    def _write_state(self, tracks, critical_means, hunters, findings, all_candidates, seen, depth,
                     oracle_desc: str = "") -> None:
        """Persist a full RESUMABLE snapshot to ``state.json`` every round: the DERIVED tracks
        (so a resume skips cold reconnaissance), each track's ruled-out ledger + directive (so it
        never re-walks dead ends), the candidate set + dedup keys, and the round number. A killed
        or rate-limited run can be jump-started from exactly here — no progress lost, no re-scope."""
        import json as _json
        import time as _time
        from pathlib import Path

        path = getattr(self.log, "path", None)
        if path is None:
            return
        out = Path(path).with_name("state.json")
        doc = {
            "program": self.scope.program,
            "updated": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
            "depth": depth,
            "critical_means": str(critical_means),
            "seen": list(seen),
            "known_patterns": list(self._known_patterns),
            "oracle_desc": str(oracle_desc),
            "tracks": [
                {"theme": h.theme, "subsystem": getattr(h, "subsystem", h.theme),
                 "fuzz_mode": getattr(h, "fuzz_mode", ""),
                 "focus_files": list(h.focus_files), "investigate": list(h.investigate),
                 "invariants": list(getattr(h, "invariants", [])),
                 "directive": getattr(h, "_directive", ""), "ruled_out": list(getattr(h, "_ruled_out", [])),
                 # The accumulating subsystem MODEL — persisted so a resumed run keeps its depth
                 # (round N+1 continues from the understanding built in rounds 1..N, never re-derives).
                 "model": getattr(h, "_model", "")}
                for h in hunters
            ],
            "candidates": [c.__dict__ for c in all_candidates],
            "confirmed": [{"title": f.title, "severity": f.severity} for f in findings],
        }
        try:
            out.write_text(_json.dumps(doc, indent=2), encoding="utf-8")
        except OSError:
            pass

    def _load_resume_state(self) -> dict | None:
        """If P1HUNT_RESUME is set and a state.json sits in this engagement folder, load it so the
        hunt continues from the saved round/tracks/candidates instead of starting cold."""
        import json as _json
        from pathlib import Path

        if not os.environ.get("P1HUNT_RESUME"):
            return None
        path = getattr(self.log, "path", None)
        if path is None:
            return None
        state = Path(path).with_name("state.json")
        if not state.exists():
            return None
        try:
            doc = _json.loads(state.read_text(encoding="utf-8"))
            self._emit(self.name, "lifecycle",
                       {"event": "resumed", "from_round": doc.get("depth", 0),
                        "tracks": len(doc.get("tracks", [])), "candidates": len(doc.get("candidates", []))})
            return doc
        except (OSError, ValueError):
            return None

    def _resteer_prompt(self, digest: list[dict], depth: int, critical_means: str, crit_count: int) -> str:
        import json as _json

        return (
            f"You are Parent A, the lead of this security audit, reviewing the team between rounds. "
            f"Round {depth} just finished. 'Critical' for this target = {critical_means}\n\n"
            f"Confirmed criticals so far: {crit_count}. Here is where each track stands (its findings "
            f"this round and what it has investigated-and-ruled-out):\n\n"
            f"{_json.dumps(digest, indent=2)}\n\n"
            "Your job: for EACH track, write a short, SPECIFIC directive for its next round that gets "
            "it somewhere — acknowledge what it did, then steer it: go deeper on a promising thread, "
            "ABANDON an exhausted angle, cross-pollinate with another track's lead, or pivot it to "
            "specific files (e.g. the in-scope deployed code). If a track is exhausted, repurpose it "
            "to a fresh angle no one is covering. You may read the code to ground your steer.\n\n"
            "Return ONLY JSON:\n"
            '{"directives": [{"track": <1-based index>, "directive": "<your steer, 1-3 sentences>", '
            '"focus_files": ["optional","new","relative/paths","to","redirect","this","track"]}]}'
        )

    async def _resteer(self, hunters, per_hunter_findings, depth, critical_means, findings, guard) -> None:
        """Parent A synthesizes the round and personalizes each hunter's next-round prompt."""
        if not self.config.use_claude or not hunters:
            return
        from .claude_session import ClaudeSession

        digest = []
        for i, (h, finds) in enumerate(zip(hunters, per_hunter_findings), start=1):
            entry = {
                "track": i,
                "theme": h.theme,
                "findings_this_round": [f"[{f.severity}] {f.title}" for f in finds][:6],
                "ruled_out": list(h._ruled_out)[-10:],
            }
            # Surface fuzz coverage so the steer can push each track at the code still in the dark.
            if self._corpus is not None:
                cov = self._corpus.coverage_for(h.subsystem)
                eps = self._entrypoints_for(h.subsystem, h.focus_files)
                uncovered = self._corpus.uncovered_hint(h.subsystem, eps)
                entry["fuzz_rounds"] = cov.rounds
                if cov.covered_symbols:
                    entry["covered_symbols"] = cov.covered_symbols[:8]
                if uncovered:
                    entry["uncovered"] = uncovered
            digest.append(entry)
        crit_count = sum(f.severity == "critical" for f in findings)
        self._emit(self.name, "message", {"phase": "resteer", "round": depth, "detail": "reviewing the team"})
        session = ClaudeSession(
            agent_name=self.name, model=self.config.models.orchestrator, on_event=self._emit,
            guard_check=self._guard_check(guard, self.name), max_turns=12,
            perms=self._perms, egress_hosts=self._egress_hosts,
        )
        try:
            res = await session.run(self._resteer_prompt(digest, depth, critical_means, crit_count), self.repo_path)
        except Exception as exc:
            self._emit(self.name, "lifecycle", {"event": "resteer_failed", "detail": str(exc)})
            return
        parsed = _parse_json_object(res.text)
        directives = parsed.get("directives") if isinstance(parsed, dict) else None
        if not isinstance(directives, list):
            return
        applied = 0
        for d in directives:
            if not isinstance(d, dict):
                continue
            idx = d.get("track")
            if not isinstance(idx, int) or not (1 <= idx <= len(hunters)):
                continue
            h = hunters[idx - 1]
            steer = str(d.get("directive", "")).strip()
            if steer:
                h._directive = steer
                applied += 1
            new_focus = [str(p).strip() for p in (d.get("focus_files") or []) if str(p).strip()]
            if new_focus:
                h.focus_files = new_focus
            self._emit(self.name, "message",
                       {"to": h.agent_name, "kind": "assign", "lens": f"re-steer → {h.theme}",
                        "investigate": [steer[:160]] if steer else [], "focus": h.focus_files[:4]})
        self._emit(self.name, "message", {"phase": "resteered", "round": depth, "count": applied})

    def _drain_control(self) -> None:
        """Read any new directives from the engagement's ``control.jsonl`` (written by
        ``p1hunt notify``) and turn them into operator notices for the next round, or a stop."""
        import json as _json
        from pathlib import Path

        path = getattr(self.log, "path", None)
        if path is None:
            return
        ctrl = Path(path).with_name("control.jsonl")
        if not ctrl.exists():
            return
        try:
            with ctrl.open("r", encoding="utf-8") as fh:
                fh.seek(self._control_offset)
                new = fh.read()
                self._control_offset = fh.tell()
        except OSError:
            return
        for line in new.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = _json.loads(line)
            except Exception:
                continue
            if d.get("kind") == "stop":
                self._safety_event = True
                self._emit(self.name, "lifecycle", {"event": "stop", "reason": "operator notify: stop"})
                continue
            msg = str(d.get("message", "")).strip()
            paths = [str(p).strip() for p in (d.get("paths") or []) if str(p).strip()]
            notice = msg + (f"  [new code now available at: {', '.join(paths)}]" if paths else "")
            if notice:
                self._notices.append(notice)
                self._emit(self.name, "message", {"phase": "notice", "notice": notice})

    def _guard_check(self, guard: ScopeGuard, agent: str):
        """The ONE hard guardrail, enforced on every file tool (Read/Grep/Glob/Write/Edit/…):
        the target must stay INSIDE the workspace folder Parent A set. Inside it the agent is
        unconstrained — it may read, write, or edit anything (incl. the target's own source and
        secrets, which are the audit). Any path OUTSIDE the workspace — read OR write — is out of
        scope and denied. Reads ``self._workspace_root`` dynamically so Parent A's choice applies
        even to closures built earlier."""
        from pathlib import Path

        write_tools = {"Write", "Edit", "MultiEdit", "NotebookEdit"}

        def _within(p: Path, root: Path) -> bool:
            try:
                p.resolve().relative_to(root)
                return True
            except ValueError:
                return False

        def check(tool: str, tinput: dict) -> tuple[bool, str]:
            workspace = Path(self._workspace_root).resolve()
            is_write = tool in write_tools
            verb = "write" if is_write else "read"
            raw = tinput.get("file_path") or tinput.get("path")
            if not raw:  # Grep/Glob by pattern operate within the workspace CWD
                # Record the JAIL's real verdict (the workspace is the authority for file ops), not a
                # dry_run re-evaluation that would mis-stamp an in-scope op — so attestation is accurate.
                guard.record(agent, tool, str(workspace), allow=True, reason="in-workspace pattern op")
                return True, "in-workspace pattern op"
            p = Path(raw)
            if not p.is_absolute():
                p = workspace / p
            inside = _within(p, workspace)
            reason = (f"in-workspace {verb}" if inside
                      else f"OUT OF SCOPE: {verb} target is outside the workspace ({workspace}) — denied")
            guard.record(agent, tool, str(p), allow=inside, reason=reason)
            return inside, reason

        return check

    # --- environment arming (the P1 unblocker: build + fork + packs + corpus) ----
    async def _arm_environment(self, tracks: list[dict]) -> None:
        """Before the first round: select class-level packs, surface EVM static leads, BUILD the
        target so harnesses can deploy it, start a local mainnet fork (EVM, if configured), and
        open the persistent corpus. All steps are graceful — a missing toolchain/fork/pack never
        stops the hunt; it just narrows what the team can do this run."""
        repo = self.repo_path
        tc = self._target_class

        # Discover an already-installed Foundry (~/.foundry/bin) up front so the reproduction gate
        # finds forge/anvil even when this process started without them on PATH.
        if tc == "EVM_CONTRACT":
            try:
                from ..tools.build_env import activate_foundry_path
                activate_foundry_path()
            except Exception:
                pass

        # 1) NOTHING PRESET: invariants and known bug-patterns come ONLY from Parent A's recon
        # (derived from the ACTUAL code + web research on THIS specific target — see _scope()).
        # No class/subclass invariant or bug-pattern packs are injected. A track Parent A left
        # without invariants is hunted with the in-session "derive the invariants from the code
        # yourself" path the hunter/fuzzer prompts already instruct — never a generic floor.
        # `self._known_patterns` and each track's `invariants` are populated by recon, not here.

        # 2) Optional DERIVED observation (a property of the actual code, not a preset): how
        # assembly-heavy the EVM source is, so the team leans on invariant/differential search
        # over shallow reading on hardened targets. No static vulnerability-signal leads injected.
        if tc == "EVM_CONTRACT":
            try:
                density = evm_assembly_density(repo)
            except Exception:
                density = 0.0
            self._emit(self.name, "lifecycle",
                       {"event": "code_shape", "assembly_density": round(density, 2),
                        "hint": ("assembly-heavy — prefer invariant/differential search over keyword reading"
                                 if density >= 0.5 else "lean on derived invariants + differential testing")})

        # DERIVED static leads: a Solidity-aware scan of the ACTUAL code surfaces concrete
        # high-value bug-class primitives (unchecked low-level call, bare ecrecover, raw
        # delegatecall, div-before-mul, reentrant external call) the hunters then reason about and
        # PROVE-or-kill. These are derived from the target in front of us (NOTHING PRESET); they
        # are hints, not a checklist, and findings still only promote on a reproduced artifact.
        try:
            self._scan_hits = scan_combined(repo)
        except Exception:
            self._scan_hits = []
        if self._scan_hits:
            self._emit(self.name, "lifecycle",
                       {"event": "static_leads", "count": len(self._scan_hits),
                        "sample": [f"{h.signal.id} @ {h.file}:{h.line}" for h in self._scan_hits[:4]]})

        # 2b) TOOLCHAIN PROVISIONING — the biggest unblocker for confirmed criticals. The
        # reproduction gate cannot EXECUTE a harness without forge, so on an EVM target with no
        # forge every candidate is quarantined forever. When opted in (auto_install_toolchain +
        # network), install Foundry now so the deterministic runner can actually fire. Off the
        # event loop; fully graceful — a failed install just leaves the gate as it was.
        if (tc == "EVM_CONTRACT" and self.config.auto_install_toolchain
                and self.config.provision_network and not toolchain_available("forge")):
            try:
                tj = await asyncio.to_thread(
                    ensure_foundry, on_event=self._emit, allow_network=self.config.provision_network,
                    allow_install=True)
                self._emit(self.name, "lifecycle",
                           {"event": "toolchain_ready" if tj.get("forge") else "toolchain_unavailable",
                            "forge": tj.get("forge"), "anvil": tj.get("anvil"),
                            "installed": tj.get("installed"), "detail": tj.get("detail", "")[:200]})
            except Exception as exc:  # provisioning must never abort a hunt
                self._emit(self.name, "lifecycle", {"event": "toolchain_install_error", "detail": str(exc)})

        # 3) Build bootstrap — the unblocker. Compile the target (fetch submodules, install deps)
        # so the fuzz/PoC stages can deploy and run the REAL code. Off the event loop (subprocess).
        if self.config.provision:
            try:
                self._build = await asyncio.to_thread(
                    bootstrap_environment, repo, on_event=self._emit,
                    allow_network=self.config.provision_network)
            except Exception as exc:
                self._build = None
                self._emit("build_env", "lifecycle", {"event": "bootstrap_error", "detail": str(exc)})
            if self._build is not None:
                self._emit("build_env", "lifecycle",
                           {"event": "build_status", "toolchain": self._build.toolchain,
                            "compiles": self._build.compiles, "attempted": self._build.attempted,
                            "diagnostics": (self._build.diagnostics or "")[:300],
                            "remediation": (self._build.remediation or "")[:200]})

        # 4) Local mainnet fork (EVM + an rpc configured + anvil present): PoCs/fuzzers reach real
        # on-chain token/proxy state at http://127.0.0.1:PORT. Localhost only; never a mainnet write.
        if tc == "EVM_CONTRACT" and self.config.fork_rpc_url and fork_available():
            handle = await asyncio.to_thread(
                start_anvil_fork, self.config.fork_rpc_url,
                block=self.config.fork_block, on_event=self._emit)
            if handle is not None:
                self._fork_handle = handle
                self._fork_url = handle.endpoint
                os.environ["P1HUNT_FORK_URL"] = handle.endpoint  # child `forge` inherits this
                self._emit(self.name, "lifecycle", {"event": "fork_ready", "endpoint": handle.endpoint})
        elif tc == "EVM_CONTRACT" and self.config.fork_rpc_url and not fork_available():
            self._emit(self.name, "lifecycle",
                       {"event": "fork_unavailable", "reason": "anvil not installed; PoCs run on local-deploy harnesses only"})

        # 5) Persistent corpus + coverage ledger, keyed to the engagement folder.
        path = getattr(self.log, "path", None)
        if path is not None:
            try:
                self._corpus = CorpusStore(Path(path).parent)
            except Exception:
                self._corpus = None

        # 6) LIVE DYNAMIC TARGET (the bug-bounty unblocker for web/API/auth criticals). When an
        # authorized non-production target was unlocked above, wire it up so the EXISTING web
        # reproduction harnesses actually fire: export the env vars they read, ship the scope-
        # enforced interaction client into the PoC sandbox, and start the loopback OOB listener so
        # blind SSRF/injection can be CONFIRMED. All graceful — any failure just narrows the run.
        if self._egress_hosts is not None:
            self._arm_dynamic()

        # 7) TOOLCHAIN CHECK (loud). The confirmed-critical gate can ONLY fire if the class's
        # reproduction toolchain is installed — without it EVERY finding is quarantined forever, no
        # matter how good the reasoning. Warn unmissably (and say how to fix) so this never fails silently.
        self._warn_if_no_repro_toolchain()

        # 8) CROSS-ENGAGEMENT MEMORY recall: seed known_patterns with OUR OWN past confirmed findings
        # on similar targets (fallible priors — hunt NEW variants; the old instances are likely
        # patched). Merged into the SAME channel recon already uses; Parent A still derives the hunt.
        if self._memory is not None:
            try:
                priors = self._memory.recall(self._target_class, self._subclass, limit=8)
            except Exception:
                priors = []
            if priors:
                have = {p.lower()[:80] for p in self._known_patterns}
                added = [p for p in priors if p.lower()[:80] not in have]
                self._known_patterns = (self._known_patterns + added)[:16]
                if added:
                    self._emit(self.name, "lifecycle",
                               {"event": "memory_recalled", "count": len(added),
                                "source": "own confirmed findings on similar targets",
                                "sample": added[:3]})

    def _repro_tools_for_class(self) -> list[str]:
        """The reproduction toolchain(s) that can EXECUTE a PoC for the derived class (any one
        suffices). Class-level routing only — no per-target knowledge."""
        tc = (self._target_class or "").upper()
        return {
            "EVM_CONTRACT": ["forge"],
            "CRYPTO_LIB": ["go", "cargo", "pytest", "cc", "gcc", "clang", "c++", "g++", "clang++"],
            "WEB_API": ["pytest", "node", "npx"],
            "INFRA": ["semgrep", "conftest", "checkov"],
            "SUPPLY_CHAIN": ["npm", "python3", "semgrep"],
            "MOBILE_APP": ["apkanalyzer"],
        }.get(tc, ["pytest", "node", "go", "cargo"])

    def _warn_if_no_repro_toolchain(self) -> None:
        """Emit a loud warning when NO reproduction toolchain for the class is on PATH — confirmed
        P1s are impossible until one is installed. Mobile is static-only (manifest reads need no
        tool), so it is exempt."""
        tc = (self._target_class or "").upper()
        if tc == "MOBILE_APP":
            return
        tools = self._repro_tools_for_class()
        if any(toolchain_available(t) for t in tools):
            return
        how = ("set P1HUNT_AUTO_INSTALL_TOOLCHAIN=1 (with network) to auto-install Foundry"
               if tc == "EVM_CONTRACT" else f"install one of: {', '.join(tools[:4])}")
        self._emit(self.name, "lifecycle",
                   {"event": "toolchain_missing_warning", "severity": "HIGH", "class": tc,
                    "needed_any_of": tools[:6],
                    "impact": "NO confirmed P1 can be produced — every finding will be quarantined "
                              "as a candidate / needs-human until a reproduction toolchain exists",
                    "fix": how})

    def _arm_dynamic(self) -> None:
        """Export the live-target environment the web harnesses + shipped client read, ship the
        client into the PoC sandbox, and start the OOB listener. Fully graceful. Every env var it
        sets is recorded in ``self._dynamic_env_keys`` so ``_disarm_dynamic`` can clear exactly
        those on hunt exit — a later in-process run can NEVER inherit this target's allowlist or
        credentials (the values are run-scoped, so plain assignment is used, not setdefault)."""
        keys: list[str] = []

        def _set(key: str, value: str) -> None:
            os.environ[key] = value
            keys.append(key)

        # Export the egress allowlist so the shipped client + harnesses enforce the same jail.
        _set("P1HUNT_EGRESS_ALLOWLIST", ",".join(self._egress_hosts or []))
        # Base URLs by kind (rest vs graphql), so the right harness env var is populated.
        for tgt in self.scope.dynamic_targets:
            if not tgt.base_url or tgt.environment.lower() == "production":
                continue
            _set("P1HUNT_GQL_URL" if (tgt.kind or "rest").lower() == "graphql" else "P1HUNT_BASE_URL",
                 tgt.base_url)
        # Test identities -> the token env vars the harnesses/client resolve (A/B/LOW/default).
        for ident in self.scope.test_identities:
            tok = ident.resolve()
            if not tok:
                continue
            name = (ident.name or "").strip().lower()
            _set("P1HUNT_TOKEN" if name in ("", "default") else f"P1HUNT_TOKEN_{name.upper()}", tok)
        # OOB interaction listener (loopback) for blind SSRF/injection confirmation.
        try:
            from ..dynamic.oob import start_oob_listener
            hits = self.poc_dir / "oob_hits.jsonl"
            self._oob = start_oob_listener(hits)
            if self._oob is not None:
                _set("P1HUNT_OOB_URL", self._oob.url)
                _set("P1HUNT_OOB_HITS", str(hits))
        except Exception:
            self._oob = None
        self._dynamic_env_keys = keys
        # Ship the scope-enforced client into the PoC sandbox so harnesses can `import p1hunt_dyn`.
        shipped = False
        try:
            from ..dynamic import client as _client_mod
            src = Path(_client_mod.__file__).read_text(encoding="utf-8")
            (self.poc_dir / "p1hunt_dyn.py").write_text(src, encoding="utf-8")
            shipped = True
        except Exception:
            shipped = False
        idents = [i.name for i in self.scope.test_identities if i.resolve()]
        self._emit(self.name, "lifecycle",
                   {"event": "dynamic_armed", "base_url": self._base_url,
                    "egress": list(self._egress_hosts or []), "identities": idents,
                    "oob": bool(self._oob), "client_shipped": shipped})

    def _stop_fork(self) -> None:
        """Tear down the local fork (no-op when none was started). Called at every hunt exit.
        Also clears the inherited fork-URL env var so a torn-down (dead) endpoint can't leak into
        a later child process or a subsequent in-process hunt."""
        if self._fork_handle is not None:
            try:
                stop_anvil_fork(self._fork_handle)
            finally:
                self._fork_handle = None
        self._fork_url = ""
        os.environ.pop("P1HUNT_FORK_URL", None)
        # Clear EVERY env var dynamic-arming exported (egress allowlist, base/gql URLs, identity
        # tokens, OOB) so a subsequent in-process hunt can't inherit this target's scope/creds.
        for key in getattr(self, "_dynamic_env_keys", []) or []:
            os.environ.pop(key, None)
        self._dynamic_env_keys = []
        # Tear down the live-testing OOB listener too (this is the universal hunt-exit hook).
        if self._oob is not None:
            try:
                self._oob.stop()
            finally:
                self._oob = None
        os.environ.pop("P1HUNT_OOB_URL", None)

    def _build_status_line(self) -> str:
        """One line telling hunters/fuzzers whether the target compiles — gated FIRST so they
        fix the build before fuzzing (a harness that can't deploy the real code proves nothing)."""
        b = self._build
        if b is None:
            return ""
        if b.compiles:
            return (f"BUILD: the target COMPILES ✓ (toolchain={b.toolchain}). Deploy the REAL contracts "
                    "and run forge/test harnesses against them directly.")
        if not b.attempted:
            return (f"BUILD: not auto-provisioned (toolchain={b.toolchain}). {b.remediation} "
                    "Provision + compile the target YOURSELF first (fetch submodules / install deps).")
        return (f"BUILD: the target does NOT yet compile (toolchain={b.toolchain}). {b.diagnostics} "
                f"FIX THE BUILD FIRST: {b.remediation} — only then can a PoC/fuzz harness deploy it.")

    def _entrypoints_for(self, subsystem: str, focus_files: list[str]) -> list[str]:
        """Cached external/public entrypoints for an EVM subsystem (the real attack surface);
        empty for non-EVM targets. Drives both the harness scaffold and coverage steering."""
        if self._target_class != "EVM_CONTRACT":
            return []
        if subsystem not in self._entrypoints_by_subsystem:
            try:
                self._entrypoints_by_subsystem[subsystem] = detect_evm_entrypoints(self.repo_path, focus_files)
            except Exception:
                self._entrypoints_by_subsystem[subsystem] = []
        return self._entrypoints_by_subsystem[subsystem]

    def _hunter_base_turns(self) -> int:
        """Base per-round turn budget for a hunter (P1HUNT_HUNTER_TURNS). Adaptive budget scales
        promising tracks UP from this and lets exhausted ones fall back to it (see hunt loop)."""
        try:
            return max(8, int(os.environ.get("P1HUNT_HUNTER_TURNS", "28")))
        except ValueError:
            return 28

    def _retune_budgets(self, hunters, per_hunter) -> None:
        """ADAPTIVE BUDGET (§8): pour more turns into the tracks showing real leads and let cold
        tracks fall back to base — so Parent A spends the swarm's effort where a P1 is likeliest.
        A track that surfaced a critical/high candidate this round gets a larger next-round budget
        (capped); a dry track returns to base. Promotion still requires a reproduced artifact, so
        this only reallocates effort, never lowers the bar."""
        base = self._hunter_base_turns()
        cap = int(base * 1.7)
        for h, finds in zip(hunters, per_hunter):
            promising = any(getattr(f, "severity", "") in ("critical", "high") for f in (finds or []))
            new_turns = cap if promising else base
            if new_turns != h.max_turns:
                self._emit(self.name, "lifecycle",
                           {"event": "budget_retuned", "track": h.theme,
                            "turns": new_turns, "reason": "promising lead" if promising else "base"})
            h.max_turns = new_turns

    def _scaffold_for(self, subsystem: str, focus_files: list[str]) -> str:
        """Reproduction MECHANICS for the PoC — NOTHING PRESET. It deliberately carries NO bug
        methodology, no attack recipe, no class-specific test skeleton (those would be preset
        knowledge): the hunter DERIVES the harness shape and the property to check himself from his
        own analysis. This note only states the mechanics that are derived from the actual target —
        build the harness in the target's OWN framework against the REAL code, how the deterministic
        runner judges it (expect=fail/pass), and the concrete resources that exist for THIS run (a
        compiling build, a local fork, an authorized live endpoint + the shipped scope-safe client)."""
        lines = [
            f"PROVE IT (reproduction mechanics — derive the harness YOURSELF, no template): build a "
            f"real, runnable PoC for the '{subsystem}' work into ./.p1hunt-poc/, in the TARGET'S OWN "
            "test framework, exercising the REAL in-scope code (not a re-implementation). Decide the "
            "property/attack to check from YOUR analysis. Run it; a deterministic runner re-runs it "
            "and decides reproduction. Set ReproSpec.expect = 'fail' if a reproduced bug makes a "
            "correctness/invariant assertion FAIL, or 'pass' if a reproduced exploit assertion HOLDS.",
        ]
        bs = self._build_status_line()
        if bs:
            lines.append(bs)
        if self._fork_url:
            lines.append(f"A local fork is available at {self._fork_url} (use it only if the PoC "
                         "needs real forked state).")
        if self._egress_hosts is not None and self._base_url:
            lines.append(
                f"LIVE TARGET ARMED (authorized): an authorized instance is reachable at "
                f"{self._base_url} with credentials in the environment. A scope-enforced client is "
                "shipped at ./.p1hunt-poc/p1hunt_dyn.py (from p1hunt_dyn import Client) — it confines "
                "every request to the in-scope host(s); contacting anything else raises. Use real "
                "requests to PROVE the bug; only contact the authorized host and loopback.")
        return "\n\n".join(lines)

    def _static_leads_for(self, focus_files: list[str]) -> list[str]:
        """Derived static leads relevant to this hunter: those whose file matches one of the
        hunter's focus files, else the strongest few overall. Formatted as one line each. Skips
        out-of-scope (non-deployed) files so a hunter never chases a lead it cannot report."""
        if not self._scan_hits:
            return []
        focus = {f.strip().lstrip("./") for f in (focus_files or []) if f and f.strip()}

        def _matches(rel: str) -> bool:
            if not focus:
                return False
            r = rel.lstrip("./")
            return any(r == f or r.endswith("/" + f) or f.endswith("/" + r) or r.startswith(f) for f in focus)

        scored = [h for h in self._scan_hits if not self._out_of_scope(h.file)]
        chosen = [h for h in scored if _matches(h.file)] or scored[:8]
        return [f"{h.signal.title} — {h.file}:{h.line} (lens: {h.signal.lens}; class: {h.signal.id})"
                for h in chosen[:12]]

    async def hunt(self, max_rounds: int | None = None) -> HuntResult:
        """Never-stop: hunt round after round until a critical is confirmed or the operator
        stops. ``max_rounds`` is an optional safety cap (None = truly unbounded, §8)."""
        # §6 derivation: classify, derive policy/surfaces (the lenses to assign).
        self._emit(self.name, "message", {"phase": "derivation", "program": self.scope.program})
        plan = derive_plan(self.scope, self.repo_path)
        self._target_class = getattr(plan.target_class, "name", str(plan.target_class))
        # Refine Parent A's permission posture now that the target CLASS is known (e.g. a crypto
        # lib defaults to no-network); Parent A may tighten it further during recon below.
        from ..safety.policies import derive_permission_policy
        self._perms = derive_permission_policy(self.scope, plan.target_class).tightened_with(self._perms)
        self.bb.set_scope(self.scope)
        self.bb.set_plan(plan)

        policy = plan.scopeguard_policy
        policy.allowlist = list(dict.fromkeys([*policy.allowlist, self.repo_path, str(self.poc_dir)]))
        # Propagate the operator's run mode into the ENFORCED policy and (only then) authorize any
        # scoped live testing. Deny-by-default holds: with no authorized non-production dynamic
        # target, authorize_dynamic is a no-op and the egress jail stays empty (no live contact).
        from ..safety.policies import authorize_dynamic
        policy.run_mode = self.config.run_mode if self.config.run_mode in ("dry_run", "active") else "dry_run"
        auth = authorize_dynamic(policy, self.scope)
        if auth.get("enabled"):
            self._egress_hosts = list(policy.egress_allowlist)
            self._base_url = next((t.base_url for t in self.scope.dynamic_targets
                                   if t.base_url and t.environment.lower() != "production"), "")
            self._emit(self.name, "lifecycle",
                       {"event": "dynamic_authorized", "hosts": auth["hosts"],
                        "environments": auth.get("environments", []), "methods": auth.get("methods", []),
                        "rejected": auth.get("rejected", [])})
        elif auth.get("rejected"):
            self._emit(self.name, "lifecycle",
                       {"event": "dynamic_rejected", "reason": auth.get("reason", ""),
                        "rejected": auth["rejected"]})
        guard = ScopeGuard(policy, on_decision=None, unattended=self.config.unattended)
        self._active_guard = guard
        # Start the self-healing watchdog (cancelled in the finally below).
        watchdog = asyncio.ensure_future(self._watchdog())
        try:

            # RESUME / JUMPSTART: if a saved snapshot exists, continue from the derived tracks +
            # candidates + round instead of re-running cold reconnaissance (no progress lost).
            resume = self._load_resume_state()
            oracle_desc = ""  # Parent A's own characterization of the differential oracle (generic)
            if resume:
                critical_means = resume.get("critical_means") or plan.impact_definition
                tracks = (resume.get("tracks") or self._fallback_tracks())[:6]
                self._known_patterns = list(resume.get("known_patterns", []) or [])
                oracle_desc = str(resume.get("oracle_desc", "") or "")
            else:
                # NOTHING PRESET (§1): Parent A performs COLD reconnaissance of the target and
                # DERIVES the subsystems/invariants/tracks itself (Pillar 2) plus the historical bug
                # patterns to hunt new variants of (Pillar 3) — no playbook, no checklist.
                scope_plan = await self._scope(guard)
                critical_means = scope_plan.get("critical_means") or plan.impact_definition
                tracks = (scope_plan.get("tracks") or self._fallback_tracks())[:6]
                self._known_patterns = [str(p).strip() for p in (scope_plan.get("known_patterns") or [])
                                        if str(p).strip()][:12]
                _orc = scope_plan.get("differential_oracle") or {}
                if isinstance(_orc, dict) and _orc.get("exists"):
                    oracle_desc = str(_orc.get("description", "")).strip()
                # PARENT A CONTROLS THE CLASS: he READ the target and decided what it is; his call
                # is authoritative for which reproduction toolchain re-runs his PoC (the deterministic
                # classifier is only the offline/no-LLM fallback). This is what lets the swarm hunt a
                # crypto/MPC library, a parser, anything — because Parent A recognizes it himself, with
                # NOTHING preset. Only override when he named a class we have a runner for.
                _recon_class = str(scope_plan.get("target_class", "") or "").strip().upper()
                if _recon_class in ("EVM_CONTRACT", "CRYPTO_LIB", "WEB_API", "MOBILE_APP",
                                    "INFRA", "SUPPLY_CHAIN", "OTHER"):
                    if _recon_class != self._target_class:
                        self._emit(self.name, "lifecycle",
                                   {"event": "class_reconciled", "from": self._target_class,
                                    "to": _recon_class, "by": "parent_a recon"})
                    self._target_class = _recon_class
                # Protocol category, ONLY if Parent A named one from the code (not token-counted).
                self._subclass = str(scope_plan.get("target_subclass", "") or "").strip()
                # PARENT A CONTROLS PERMISSIONS: apply its recon-chosen posture (clamped tighter only).
                self._apply_permission_policy(scope_plan.get("permissions"))
                self._emit(self.name, "message",
                           {"phase": "scoped", "summary": str(scope_plan.get("summary", ""))[:400],
                            "critical_means": str(critical_means)[:300], "tracks": len(tracks),
                            "known_patterns": len(self._known_patterns)})
                if self._known_patterns:
                    self._emit(self.name, "lifecycle",
                               {"event": "patterns_loaded", "count": len(self._known_patterns),
                                "sample": self._known_patterns[:3]})

            # Arm the environment ONCE before any round: BUILD the target (submodules + compile) so
            # harnesses can deploy it, start a local mainnet fork when configured, and open the
            # persistent corpus. Invariants/patterns are NOT injected here — they come from Parent A's
            # recon (derived from the actual code + web research), so nothing preset reaches the hunt.
            await self._arm_environment(tracks)

            # One Child B per DERIVED track (a real Claude hunter), plus the Falsifier.
            # Scoped web (technique/spec only) is on with a hard per-session search budget so a
            # stuck hunter can't rabbit-hole into "<product> known bugs" (P1HUNT_WEB_BUDGET, 0=off).
            try:
                _web_budget = max(0, int(os.environ.get("P1HUNT_WEB_BUDGET", "5")))
            except ValueError:
                _web_budget = 5
            _base_turns = self._hunter_base_turns()
            hunters: list[ClaudeHunter] = []
            for i, tr in enumerate(tracks, start=1):
                name = f"child_b{i}"
                self.bus.register(name, "worker")
                h = ClaudeHunter(name, theme=str(tr.get("theme", f"track {i}")),
                                 model=self.config.models.worker, on_event=self._emit,
                                 guard_check=self._guard_check(guard, name),
                                 max_turns=_base_turns, allow_web=(_web_budget > 0),
                                 web_budget=_web_budget)
                h.focus_files = list(tr.get("focus_files", []) or [])
                h.investigate = list(tr.get("investigate", []) or [])
                # Deep subsystem ownership (Pillar 2): the hunter OWNS this subsystem and its invariants.
                h.subsystem = str(tr.get("subsystem", "") or tr.get("theme", "") or f"track {i}")
                h.invariants = [str(x) for x in (tr.get("invariants") or []) if str(x).strip()]
                h.fuzz_mode = str(tr.get("fuzz_mode", "") or "")
                h.perms = self._perms  # Parent A's permission posture for this engagement
                h.egress_hosts = self._egress_hosts  # live-testing host jail (None = static mode)
                if resume:  # restore this track's memory so it resumes at depth, not from scratch
                    h._ruled_out = list(tr.get("ruled_out", []) or [])
                    h._directive = str(tr.get("directive", "") or "")
                    h._model = str(tr.get("model", "") or "")  # restore the accumulated model (skips re-map)
                hunters.append(h)
                self._emit(self.name, "message",
                           {"to": name, "kind": "assign", "lens": h.theme, "mission": h.subsystem,
                            "investigate": h.investigate[:4], "focus": h.focus_files[:4],
                            "invariants": h.invariants[:4]})
            # SECOND OPINION (opt-in, P1HUNT_SECOND_OPINION=1): a fully INDEPENDENT hunter on the
            # top-ranked subsystem (its own blank model — it maps and reasons from scratch). Two
            # minds on the crown-jewel mechanism catch what one misses; the dedup set + Falsifier
            # are the comparator. Off by default because it costs an extra session per round.
            if os.environ.get("P1HUNT_SECOND_OPINION") == "1" and tracks and not resume:
                tr0 = tracks[0]
                so = ClaudeHunter("child_b1_2nd", theme=str(tr0.get("theme", "track 1")),
                                  model=self.config.models.worker, on_event=self._emit,
                                  guard_check=self._guard_check(guard, "child_b1_2nd"),
                                  max_turns=_base_turns, allow_web=(_web_budget > 0), web_budget=_web_budget)
                self.bus.register("child_b1_2nd", "worker")
                so.focus_files = list(tr0.get("focus_files", []) or [])
                so.subsystem = str(tr0.get("subsystem", "") or tr0.get("theme", "") or "track 1")
                so.invariants = [str(x) for x in (tr0.get("invariants") or []) if str(x).strip()]
                so.perms = self._perms
                so.egress_hosts = self._egress_hosts
                hunters.append(so)
                self._emit(self.name, "lifecycle",
                           {"event": "second_opinion", "subsystem": so.subsystem,
                            "detail": "independent hunter on the top subsystem (diversity)"})
            self.bus.register("falsifier", "falsifier")
            verifier = ClaudeVerifier("falsifier", model=self.config.models.falsifier, on_event=self._emit,
                                      guard_check=self._guard_check(guard, "falsifier"))
            verifier.perms = self._perms
            verifier.egress_hosts = self._egress_hosts
            # The PoC prover runs ONLY after the Falsifier believes a finding is real (so we never
            # build a PoC for an intended/non-bug), and can REFUTE it if it won't actually reproduce.
            self.bus.register("poc_prover", "prover")
            prover = ClaudePoCProver("poc_prover", model=self.config.models.falsifier, on_event=self._emit,
                                     guard_check=self._guard_check(guard, "poc_prover"))
            prover.perms = self._perms
            prover.egress_hosts = self._egress_hosts

            # FUZZING ENGINE (Pillar 1): one campaign per top subsystem. If a reference impl exists,
            # the first is a DIFFERENTIAL campaign (optimized vs reference) — the highest-yield search
            # on heavily-audited code. Fuzzers use the strong model (harness-writing + forge iteration
            # is demanding) and run concurrently with the hunters each round.
            # Prefer Parent A's OWN determination of the differential oracle (generic, from its recon);
            # fall back to a cheap structural guess only if Parent A didn't characterize one.
            reference_hint = oracle_desc or self._detect_reference()
            if reference_hint:
                self._emit(self.name, "lifecycle",
                           {"event": "reference_detected",
                            "detail": reference_hint[:160],
                            "source": "parent_a" if oracle_desc else "structural-fallback"})
            # FUZZING IS THE SIDE DISH: the bulk of the round is the reasoning hunters (one per
            # track); only a small number of fuzz campaigns run alongside them. Default 1
            # (the single highest-value subsystem, differential if an oracle exists); override
            # with P1HUNT_FUZZ_CAMPAIGNS. This keeps most of the compute on reasoning-to-a-bug.
            try:
                _n_fuzz = max(0, int(os.environ.get("P1HUNT_FUZZ_CAMPAIGNS", "1")))
            except ValueError:
                _n_fuzz = 1
            fuzz_assignments = self._fuzz_assignments(tracks, reference_hint, max_n=_n_fuzz)
            fuzzers: list[ClaudeFuzzer] = []
            for i, asn in enumerate(fuzz_assignments, start=1):
                fname = f"fuzzer_{i}"
                self.bus.register(fname, "fuzzer")
                _fz = ClaudeFuzzer(fname, model=self.config.models.falsifier, on_event=self._emit,
                                   guard_check=self._guard_check(guard, fname))
                _fz.perms = self._perms
                _fz.egress_hosts = self._egress_hosts
                fuzzers.append(_fz)
                self._emit(self.name, "message",
                           {"to": fname, "kind": "assign",
                            "mode": "differential" if asn["differential"] else "invariant",
                            "subsystem": asn["subsystem"], "invariants": asn["invariants"][:4]})

            findings: list[Finding] = []
            all_candidates: list[ClaudeFinding] = []
            needs_human: list[Finding] = []  # believed-real, high-confidence, but not auto-reproduced
            seen: set[str] = set()
            prior_titles: list[str] = []
            start_depth = 0
            if resume:  # restore the candidate set + dedup keys + round counter
                for cd in resume.get("candidates", []):
                    try:
                        all_candidates.append(ClaudeFinding(**cd))
                    except (TypeError, ValueError):
                        pass
                seen |= set(resume.get("seen", []))
                prior_titles = [c.title for c in all_candidates]
                start_depth = int(resume.get("depth", 0) or 0)

            depth = start_depth
            while True:
                depth += 1
                if max_rounds is not None and depth > max_rounds:
                    self._emit(self.name, "lifecycle", {"event": "cap_reached", "round": depth - 1})
                    self._write_findings_json(findings, all_candidates, needs_human)
                    watchdog.cancel()
                    self._stop_fork()
                    status = EngagementStatus.REPORT_READY if findings else EngagementStatus.RUNNING
                    return self._result(status, plan, guard, findings, all_candidates, depth - 1)
                if self.bb.has_stop(self.name) or self._safety_event:
                    self._emit(self.name, "lifecycle", {"event": "stop", "reason": "operator/safety"})
                    self._write_findings_json(findings, all_candidates, needs_human)
                    watchdog.cancel()
                    self._stop_fork()
                    return self._result(EngagementStatus.STOPPED, plan, guard, findings, all_candidates, depth)
                # COST CEILING (opt-in): stop a never-quit run gracefully once the operator's budget
                # is spent — no surprise unbounded bills. Spend is emitted every round regardless.
                if self._cost_cap is not None and self._spend_usd >= self._cost_cap:
                    self._emit(self.name, "lifecycle",
                               {"event": "cost_cap_reached", "spent_usd": round(self._spend_usd, 2),
                                "cap_usd": self._cost_cap, "round": depth - 1})
                    self._write_findings_json(findings, all_candidates, needs_human)
                    watchdog.cancel()
                    self._stop_fork()
                    status = EngagementStatus.REPORT_READY if findings else EngagementStatus.RUNNING
                    return self._result(status, plan, guard, findings, all_candidates, depth - 1)

                self._drain_control()  # pick up any `p1hunt notify` directives before this round
                self._emit(self.name, "message", {"phase": "round", "round": depth, "lenses": len(hunters)})
                import time as _t
                round_start = _t.monotonic()
                round_errors: list[str] = []

                # Fan out: every Child B hunts its derived track this round (bounded concurrency).
                # Each hunter has a WALL-CLOCK cap so one that keeps emitting can't grind forever and
                # block the round (the inactivity timeout only catches SILENCE, not endless grinding).
                hunter_cap = float(os.environ.get("P1HUNT_HUNTER_TIMEOUT", "1200"))  # 20 min/round/hunter

                async def _run(h: ClaudeHunter) -> list[ClaudeFinding]:
                    async with self.sem:
                        try:
                            res = await asyncio.wait_for(
                                h.hunt(critical_means + self._scope_guidance(), self.repo_path, depth,
                                       prior_titles, focus_files=h.focus_files, investigate=h.investigate,
                                       notices=list(self._notices), invariants=h.invariants,
                                       known_patterns=self._known_patterns, subsystem=h.subsystem,
                                       scaffold=self._scaffold_for(h.subsystem, h.focus_files),
                                       build_status=self._build_status_line(),
                                       static_leads=self._static_leads_for(h.focus_files)),
                                timeout=hunter_cap)
                        except asyncio.TimeoutError:
                            # Force the round to close: this track contributes nothing this round and
                            # gets a fresh session next round (so it can't stall the whole swarm).
                            self._emit(h.agent_name, "lifecycle",
                                       {"event": "hunter_timeout",
                                        "detail": f"exceeded {int(hunter_cap)}s wall-clock — cut so the round can complete"})
                            return []
                        if res.error:
                            round_errors.append(res.error)
                            self._emit(h.agent_name, "lifecycle", {"event": "error", "detail": res.error})
                        return res.findings

                # FUZZING PHASE (Pillar 1): alongside the hunters, run invariant + differential fuzzing
                # campaigns that SEARCH for invariant violations instead of guessing. A campaign's
                # findings arrive with a forge counterexample (a reproducing sequence) — high-signal,
                # and they feed the same Falsifier→PoC pipeline so harness artifacts still get rejected.
                async def _run_fuzz(fz: ClaudeFuzzer, asn: dict) -> list[ClaudeFinding]:
                    async with self.sem:
                        subsystem = asn["subsystem"]
                        focus = asn["focus_files"]
                        eps = self._entrypoints_for(subsystem, focus)
                        # Cross-round memory: reuse prior counterexamples as seeds and steer at the
                        # entrypoints not yet covered, so rounds COMPOUND instead of re-exploring.
                        seeds = self._corpus.seeds_for(subsystem) if self._corpus else []
                        cov_hint = self._corpus.uncovered_hint(subsystem, eps) if self._corpus else ""
                        try:
                            fnds, cov, covered = await asyncio.wait_for(
                                fz.campaign(subsystem, asn["invariants"], focus,
                                            self.repo_path, differential=asn["differential"],
                                            reference_hint=reference_hint, known_patterns=self._known_patterns,
                                            scaffold=self._scaffold_for(subsystem, focus),
                                            fork_url=self._fork_url, build_status=self._build_status_line(),
                                            coverage_hint=cov_hint, entrypoints=eps, seeds=seeds),
                                timeout=hunter_cap)
                        except asyncio.TimeoutError:
                            self._emit(fz.agent_name, "lifecycle",
                                       {"event": "hunter_timeout", "detail": f"fuzz campaign exceeded {int(hunter_cap)}s — cut"})
                            return []
                        except Exception as exc:  # a harness/parse failure must not kill the round
                            round_errors.append(str(exc))
                            return []
                        if self._corpus is not None:
                            try:
                                self._corpus.record(
                                    subsystem,
                                    counterexamples=[f.reproduction for f in fnds if f.reproduction],
                                    coverage_notes=cov, covered_symbols=covered)
                            except Exception:
                                pass
                        return fnds

                # Expose this round's tasks so the watchdog can cancel them if they stall.
                self._round_tasks = [asyncio.ensure_future(_run(h)) for h in hunters]
                self._round_tasks += [asyncio.ensure_future(_run_fuzz(fz, asn))
                                      for fz, asn in zip(fuzzers, fuzz_assignments)]
                results = await asyncio.gather(*self._round_tasks, return_exceptions=True)
                self._round_tasks = []
                round_findings: list[ClaudeFinding] = []
                for r in results:
                    if isinstance(r, list):
                        round_findings.extend(r)

                # Dedupe, record as hypotheses/candidates for full visibility.
                fresh: list[ClaudeFinding] = []
                for cf in round_findings:
                    key = f"{cf.file}:{cf.line}:{cf.title.lower()[:40]}"
                    if key in seen:
                        continue
                    seen.add(key)
                    fresh.append(cf)
                    all_candidates.append(cf)
                    prior_titles.append(cf.title)
                    self._record_hypothesis(cf)

                # Verify the strong candidates (believe-but-verify, §10). Out-of-scope findings (e.g.
                # in a non-deployed reference impl) stay visible as candidates but are NEVER verified
                # or promoted to P1s — they don't burn Falsifier/PoC budget and can't become a payout.
                strong = []
                for cf in fresh:
                    if cf.severity not in ("critical", "high"):
                        continue
                    if self._out_of_scope(cf.file):
                        self._emit("falsifier", "message",
                                   {"verdict": "out-of-scope", "title": cf.title,
                                    "reason": f"{cf.file} is out of scope (not deployed) — not promoted"})
                        continue
                    strong.append(cf)
                # COST/TIME GUARD: the verify→materialize→repair→reproduce pipeline is serial and
                # each candidate is expensive (multiple Opus sessions + up to 3×600s reproduce). Cap
                # how many we verify per round to the STRONGEST few (critical before high; high before
                # medium confidence) so a noisy round can't blow up into hours / unbounded spend. The
                # rest stay visible as candidates and get another shot next round.
                _sev_rank = {"critical": 0, "high": 1}
                _conf_rank = {"high": 0, "medium": 1, "low": 2}
                strong.sort(key=lambda c: (_sev_rank.get(c.severity, 2),
                                           _conf_rank.get(str(c.confidence).lower(), 3)))
                try:
                    _max_verify = max(1, int(os.environ.get("P1HUNT_MAX_VERIFY", "6")))
                except ValueError:
                    _max_verify = 6
                if len(strong) > _max_verify:
                    self._emit(self.name, "lifecycle",
                               {"event": "verify_capped", "verifying": _max_verify,
                                "deferred": len(strong) - _max_verify,
                                "reason": "top candidates verified this round; the rest carry to next round"})
                    strong = strong[:_max_verify]
                _verify_cap = float(os.environ.get("P1HUNT_VERIFY_TIMEOUT", "900"))
                for cf in strong:
                  # GUARD: one malformed candidate must NEVER crash the never-quit hunt. Any error in
                  # this candidate's verify/prove/promote is logged and skipped; the loop continues.
                  try:
                    status, _severity, reason = await asyncio.wait_for(
                        verifier.verify(cf, self.repo_path), timeout=_verify_cap)
                    hyp = self._hyp_by_finding.get(id(cf))
                    if status == "refuted":
                        if hyp:
                            self.bb.set_state(hyp.id, HypState.FALSIFIED)
                        continue
                    # STRICT REPRODUCED-CRITICAL GATE (§10): the Falsifier only earns the candidate a
                    # chance to be PROVEN. The prover MATERIALIZES a runnable harness into the sandbox;
                    # a DETERMINISTIC class runner then EXECUTES it and decides reproduction from the
                    # real toolchain output — never the model's say-so. NOTHING is promoted to a
                    # confirmed finding unless reproduced=True; otherwise it stays a candidate.
                    _scaffold = self._scaffold_for(cf.lens or "subsystem", [cf.file] if cf.file else [])
                    spec_dict = await asyncio.wait_for(
                        prover.materialize(cf, self.repo_path, scaffold=_scaffold, fork_url=self._fork_url),
                        timeout=_verify_cap)
                    repro = await self._reproduce(cf, spec_dict)
                    # POC ITERATION LOOP: if the harness didn't reproduce, feed the REAL runner output
                    # back to the prover to FIX it and rerun — up to P1HUNT_POC_ATTEMPTS times. This
                    # converts reasoned-but-unproven P1s into confirmed ones (one-shot proof misses
                    # the many bugs whose harness just needs a compile fix / better setup).
                    try:
                        _max_attempts = max(1, int(os.environ.get("P1HUNT_POC_ATTEMPTS", "3")))
                    except ValueError:
                        _max_attempts = 3
                    _attempt = 1
                    while spec_dict and not (repro and repro.reproduced) and _attempt < _max_attempts:
                        feedback = (repro.detail or repro.stdout_excerpt) if repro else "no harness was produced"
                        self._emit("poc_prover", "lifecycle",
                                   {"event": "poc_retry", "title": cf.title, "attempt": _attempt + 1,
                                    "of": _max_attempts})
                        new_spec = await asyncio.wait_for(
                            prover.repair(cf, spec_dict, str(feedback), self.repo_path,
                                          scaffold=_scaffold, fork_url=self._fork_url),
                            timeout=_verify_cap)
                        if not new_spec:
                            break
                        spec_dict = new_spec
                        repro = await self._reproduce(cf, spec_dict)
                        _attempt += 1
                    reproduced = bool(repro and repro.reproduced)
                    # Ingest REAL coverage (parsed from the tool, not model-reported) into the corpus.
                    if repro is not None and repro.coverage and self._corpus is not None:
                        try:
                            self._corpus.record(cf.lens or "subsystem",
                                                covered_symbols=list(repro.coverage.get("covered_symbols", [])))
                        except Exception:
                            pass
                    # Deterministic severity — map REAL impact facts to THIS program's taxonomy.
                    impact = self._impact_of(cf, reproduced)
                    sev_label, sev_rationale = self._severity.map(impact)
                    if not reproduced:
                        if hyp:
                            self.bb.set_state(hyp.id, HypState.CANDIDATE)
                        self._emit("poc_prover", "lifecycle",
                                   {"event": "candidate_not_reproduced", "title": cf.title,
                                    "ran": bool(repro and repro.ran), "severity": sev_label,
                                    "detail": (repro.detail[:200] if repro else "no harness/runner — stays a candidate")})
                        # SURFACE FOR HUMAN REVIEW (don't bury it): the Falsifier believes it's real
                        # and the finder claims a concrete, high-confidence loss — it just couldn't be
                        # auto-reproduced (hard-to-harness class, missing toolchain, multi-step setup).
                        # A reasoned P1 a human should look at is the MOST valuable output, not the
                        # least. It is clearly marked verified=False — the reproduced=confirmed floor
                        # is untouched; this is a separate, prominent "needs human" tier.
                        # SURFACE WIDELY: the Falsifier already believes it's real and it's a
                        # critical/high in scope — surface it for a human even if the finder didn't
                        # phrase the loss as one of the exact literal words or hedged confidence.
                        # Missing a real P1 because of a string mismatch is the worst outcome; a human
                        # triages false positives cheaply. (status here is 'real' or 'unverified'.)
                        if status == "real" and not self._out_of_scope(cf.file):
                            f = self._surface_for_human(cf, reason, sev_label, guard,
                                                        ran=bool(repro and repro.ran),
                                                        detail=(repro.detail if repro else ""))
                            needs_human.append(f)
                            self._emit(self.name, "lifecycle",
                                       {"event": "needs_human_review", "title": cf.title,
                                        "severity": sev_label, "confidence": cf.confidence,
                                        "concrete_loss": cf.concrete_loss,
                                        "reason": "Falsifier-believed P1, not auto-reproduced — REVIEW"})
                        continue
                    # Reproduced by a real runner -> a CONFIRMED finding (tier from the mapper).
                    tier = self._norm_tier(sev_label, self._severity.is_p1(impact))
                    if hyp:
                        self.bb.set_state(hyp.id, HypState.CONFIRMED)
                    findings.append(self._promote(cf, f"{sev_rationale} | falsifier: {reason}", guard,
                                                  repro=repro, severity_label=sev_label, tier=tier))
                  except asyncio.TimeoutError:
                    self._emit("poc_prover", "lifecycle",
                               {"event": "verify_timeout", "title": cf.title,
                                "detail": f"verify/prove exceeded {int(_verify_cap)}s — deferred to next round"})
                  except Exception as exc:
                    # One bad candidate must not kill the never-quit hunt (§8).
                    self._emit("poc_prover", "lifecycle",
                               {"event": "candidate_verify_error", "title": cf.title, "detail": str(exc)[:200]})

                # Find ALL criticals — do NOT stop at the first. Keep hunting/reframing across
                # rounds (every lens deepening its angle) until the round cap or an operator stop,
                # so multiple independent P1s surface rather than just the first one found.
                crit = sum(f.severity == "critical" for f in findings)
                self._emit(self.name, "message",
                           {"phase": "round_summary", "round": depth, "criticals_total": crit,
                            "candidates_total": len(all_candidates), "needs_human": len(needs_human),
                            "spent_usd": round(self._spend_usd, 2),
                            "cost_cap_usd": self._cost_cap})
                # Persist findings each round so a later stop/kill always leaves them on disk.
                self._write_findings_json(findings, all_candidates, needs_human)
                # Persist a full RESUMABLE snapshot so a kill/rate-limit can be jump-started from here.
                self._write_state(tracks, critical_means, hunters, findings, all_candidates, seen, depth,
                                  oracle_desc=reference_hint)

                # Rate-limit / dead-round BACKOFF (§8): a round that finished FAST and produced nothing
                # (or whose sessions errored as rate-limited) means we're throttled — do NOT spin empty
                # rounds hammering the API. Sleep with exponential backoff so the limit can recover.
                round_dur = _t.monotonic() - round_start
                throttled = any(("rate" in str(e).lower() or "limit" in str(e).lower() or "usage" in str(e).lower())
                                for e in round_errors)
                if throttled or (round_dur < 45 and not fresh and round_errors):
                    self._rl_strikes = getattr(self, "_rl_strikes", 0) + 1
                    backoff = min(900, 30 * (2 ** min(self._rl_strikes - 1, 5)))  # 30s→…→15min cap
                    self._emit(self.name, "lifecycle",
                               {"event": "backoff", "strikes": self._rl_strikes,
                                "reason": f"empty/fast round, likely rate-limited ({len(round_errors)} errored) — pausing {backoff}s"})
                    await asyncio.sleep(backoff)
                    continue  # skip re-steer while throttled (it would just fail too) — retry the round
                self._rl_strikes = 0

                # Strategic re-steer (§6): Parent A reviews where every track stands — each track's
                # findings + its ruled-out ledger + the cross-track blackboard — and writes a
                # personalized directive (and may re-scope focus files) for each hunter's next round.
                per_hunter = [r if isinstance(r, list) else [] for r in results]
                # ADAPTIVE BUDGET: give the promising tracks more turns next round, cold ones base.
                self._retune_budgets(hunters, per_hunter[:len(hunters)])
                await self._resteer(hunters, per_hunter, depth, critical_means, findings, guard)

                # Deepen each track's analysis next round, never quit on a dry spell.
                self._reframes += len(hunters)
                self._emit(self.name, "reframe", {"reason": f"round {depth} done; every track deepens its "
                                                  "analysis next pass, without escalating aggressiveness"})
                # loop continues — the session does not stop until a critical is confirmed or
                # the operator issues a stop directive (§8, never-quit).
        finally:
            # Always tear down the watchdog task and any local anvil fork, even on an
            # exception path (the two in-loop returns also do this; both are idempotent).
            watchdog.cancel()
            self._stop_fork()

    # --- helpers ----------------------------------------------------------
    _SEC_KEYWORDS = (
        "verify", "proof", "zero_knowledge", "zk", "sign", "mta", "keygen", "key", "commit",
        "paillier", "ring_pedersen", "range", "ecdsa", "eddsa", "schnorr", "cosigner", "crypto",
        "auth", "token", "session", "permission", "nonce", "refresh", "share",
    )
    _SRC_EXTS = {".cpp", ".cc", ".c", ".h", ".hpp", ".go", ".rs", ".py", ".ts", ".js", ".tsx",
                 ".sol", ".java", ".kt", ".rb", ".php"}

    # --- fuzzing-engine support (Pillar 1) --------------------------------
    _REF_MARKERS = ("reference/", "/reference/", "_reference", "reference_impl", "/spec/", "/specs/")

    def _detect_reference(self) -> str:
        """FALLBACK ONLY: a cheap structural guess at a second implementation, used only if Parent A
        did not characterize the differential oracle itself. Parent A's own determination (from its
        recon) is always preferred — this is a safety net, not the source of truth."""
        repo = Path(self.repo_path)
        ref_files = []
        try:
            for p in repo.rglob("*"):
                if not p.is_file():
                    continue
                low = str(p.relative_to(repo)).lower()
                if any(m in low for m in self._REF_MARKERS) or p.name.startswith("Reference"):
                    ref_files.append(str(p.relative_to(repo)))
                    if len(ref_files) >= 6:
                        break
        except OSError:
            pass
        if not ref_files:
            return ""
        return (f"A second implementation may exist in this repo (e.g. {', '.join(ref_files[:4])}). "
                "If it mirrors the in-scope code, use it as the differential ORACLE — drive identical "
                "inputs through both and assert equality.")

    def _fuzz_assignments(self, tracks: list[dict], reference_hint: str, max_n: int = 1) -> list[dict]:
        """Thin executor of PARENT A's plan: one fuzzing campaign per top subsystem, in the MODE
        Parent A chose for it (its `fuzz_mode`). No target-specific heuristics — if Parent A said a
        subsystem is best attacked differentially (and an oracle exists), that campaign is
        differential; otherwise it's a stateful-invariant campaign."""
        have_oracle = bool(reference_hint)
        out: list[dict] = []
        for i, tr in enumerate(tracks[:max_n]):
            subsystem = str(tr.get("subsystem") or tr.get("theme") or f"subsystem {i+1}")
            invariants = [str(x) for x in (tr.get("invariants") or tr.get("investigate") or []) if str(x).strip()]
            focus = [str(x) for x in (tr.get("focus_files") or []) if str(x).strip()]
            mode = str(tr.get("fuzz_mode", "")).lower()
            # Parent A's call. Differential is the single highest-yield technique on hardened,
            # heavily-audited code, so when an oracle exists make it the DEFAULT for EVERY subsystem
            # Parent A didn't explicitly mark 'invariant' (not just the first) — more concurrent
            # differential campaigns = more chances to surface a behavioral divergence (a P1).
            differential = (mode == "differential") if mode in ("differential", "invariant") else have_oracle
            out.append({
                "subsystem": subsystem, "invariants": invariants[:8], "focus_files": focus[:8],
                "differential": differential and have_oracle,
            })
        return out

    def _enumerate_targets(self, limit: int = 30) -> list[str]:
        """Parent A reads the repo structure and ranks source files by security relevance
        (impl over headers, security keywords in path, larger files weighted) so coverage
        can be partitioned across agents. Tests/benchmarks deprioritized."""
        repo = Path(self.repo_path)
        scored: list[tuple[int, str]] = []
        for p in repo.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in self._SRC_EXTS:
                continue
            rel = str(p.relative_to(repo))
            low = rel.lower()
            if any(seg in low for seg in ("/test/", "/tests/", "test/", "benchmark", "/.", "example")):
                continue
            score = sum(2 for k in self._SEC_KEYWORDS if k in low)
            if p.suffix.lower() in (".cpp", ".cc", ".c", ".go", ".rs"):
                score += 1  # implementation over headers
            try:
                if p.stat().st_size > 8000:
                    score += 1  # bigger files hide more
            except OSError:
                pass
            scored.append((score, rel))
        scored.sort(key=lambda t: (-t[0], t[1]))
        return [rel for _, rel in scored[:limit]]

    # --- Parent A cold reconnaissance (§6, NOTHING PRESET) ----------------
    def _scope_prompt(self) -> str:
        return (
            "You are Parent A, the LEAD of this security audit and the BRAIN of the whole hunt. Your "
            "recon decides everything downstream — which subsystems are owned, which invariants are "
            "chased, which order they're worked, where the team's effort goes. A mediocre recon caps "
            "the whole hunt; an elite one is how a P1 gets found. Do this like the best auditor alive.\n\n"
            "You have NO prior knowledge of this target beyond the source in the current working "
            "directory — it could be a smart contract, a crypto/MPC library, a web/API service, a "
            "parser, a kernel module, anything. Explore it READ-ONLY (Read, Grep, Glob, read-only "
            "Bash, WebSearch, WebFetch) and DESIGN the entire hunt yourself. Derive EVERYTHING from "
            "what you OBSERVE — never assume a technology, a language, or a bug list.\n\n"
            "MINDSET: reason like an ATTACKER pursuing a WIN, not a reviewer checking correctness. "
            "CORRECT ≠ SAFE — a faithful implementation of a flawed rule, or a perfectly-correct "
            "computation fed an input the attacker chose, still loses funds/control/data. You are "
            "looking for OUTCOMES an attacker can force, not for code that looks wrong.\n\n"
            "READ DEEPLY: this is the one phase where breadth AND depth both matter. DISPATCH SUB-"
            "AGENTS (Agent/Task) to read whole subsystems and return rich, file-anchored summaries; "
            "reason over those. Cite real file:line for every claim — never guess. Spend real effort "
            "here; the rest of the hunt inherits the quality of this map.\n\n"
            "1) UNDERSTAND the system: what it is, its language/stack, how it's built and tested, "
            "what it's FOR, and what 'critical' means for THIS specific system (the maximum attacker "
            "win — theft, takeover, key/secret extraction, permanent loss/freeze, integrity break).\n\n"
            "2) MAP THE ATTACK SURFACE & ACTORS precisely. Enumerate every EXTERNALLY-REACHABLE "
            "entrypoint (public/external functions, routes, message handlers, protocol rounds, "
            "deserializers — name + file:line). Enumerate each ACTOR and EXACTLY what it controls and "
            "may call (e.g. unauthenticated user / low-priv or other-tenant user / counterparty / a "
            "single MALICIOUS participant among honest ones / a compromised dependency). Mark the "
            "TRUST BOUNDARIES and, for each, what is ASSUMED to be true across it and who can violate "
            "that assumption. This surface is the foundation everything else builds on.\n\n"
            "3) CROWN JEWELS & FLOWS. Identify where value / authority / funds / secrets / privileged "
            "state concentrate — the few places where a bug is catastrophic. Trace the critical "
            "value, authorization, and data FLOWS end to end (across functions/files/contracts/"
            "parties). The P1 is almost always on one of these flows.\n\n"
            "4) WHERE THE BUGS HIDE (derive from THIS code, not a checklist). From what you actually "
            "read, flag the highest-risk SEAMS: where two correct pieces COMPOSE unsafely; external "
            "calls / callbacks / re-entrancy; arithmetic — rounding, precision, signedness, overflow, "
            "unit/decimal confusion; access-control / ownership / tenancy checks that are missing on "
            "one path or trust a client-supplied field; implicit assumptions a check RELIES ON that an "
            "attacker can break; the most complex / optimized / assembly / hand-rolled-crypto code; "
            "upgrade/migration/init paths; anything that looks recently changed or uniquely intricate. "
            "These are WHERE to point the team.\n\n"
            "5) FIND A DIFFERENTIAL ORACLE (high-yield). Is there a SECOND implementation of the same "
            "logic to compare against — a reference/spec impl, an older/alternative version, a known "
            "library implementing the same primitive, or the documented spec itself? If so, say where "
            "and how the pieces pair up — any divergence on the same input is a likely bug. Else say "
            "none exists.\n\n"
            "6) RESEARCH HISTORICAL PATTERNS (WebSearch/WebFetch). Identify what this project IS, then "
            "research the known critical bug CLASSES for its category and past audit findings/CVEs/"
            "disclosed exploits for it and its close peers. The old bugs are patched — you want the "
            "PATTERNS so the team hunts NEW VARIANTS. Short, concrete, checkable statements.\n\n"
            "7) DECOMPOSE & RANK (deep ownership, not breadth). Split the in-scope code into up to 6 "
            "cohesive SUBSYSTEMS (each a distinct mechanism); one track OWNS each end-to-end. ORDER "
            "the tracks MOST-DANGEROUS-FIRST — by (attacker reachability × blast radius × how likely "
            "a subtle bug hides here); the first track is worked first and deepest, so put the "
            "crown-jewel mechanism there. For EACH subsystem: name the ATTACKER'S WIN conditions and "
            "the PROTECTED QUANTITIES that must never move the wrong way; then DERIVE the INVARIANTS "
            "as 'what an attacker must NEVER be able to cause' — phrased as the OUTCOME, not as 'the "
            "code checks X'. CAUTION: an invariant copied from what the code already asserts MISSES "
            "the bug where the code faithfully does the wrong thing. Ground each in the real code "
            "(accounting/conservation math, require/assert/revert, role/modifier guards, the "
            "properties its own tests assert), state it as a machine-checkable property a fuzzer can "
            "assert, and cite file:line. No generic textbook properties — every one SPECIFIC to THIS "
            "code. Point focus_files at the exact IN-SCOPE files. Choose each subsystem's SEARCH "
            "STRATEGY: 'differential' (if the oracle covers it) or 'invariant' (stateful fuzzing).\n\n"
            "8) PLACE YOUR BET. State the SINGLE most promising hypothesis — where YOU would bet the "
            "P1 is, citing the code, and the first concrete attacker move to test it. Be decisive.\n\n"
            "Your hunters AND an automated fuzzer will PROVE or disprove each lead by writing and "
            "RUNNING real tests/harnesses against the actual target — never by reading alone."
            + self._scope_guidance() + "\n\n"
            "\n\nWORKSPACE GUARDRAIL: you operate under ONE hard rule — you may do ANYTHING you "
            "need (read, write, build, install, run, fuzz, network) but ONLY INSIDE the in-scope "
            "workspace folder; nothing outside it may be read or written. State the workspace root "
            "as a path relative to the current directory (use \".\" for the whole acquired folder, "
            "or a subfolder that contains all the in-scope code). It is clamped to the acquired "
            "tree and locked as the hard guardrail.\n\n"
            "PERMISSIONS — you also SET the runtime permission posture for the team (it can only "
            "RESTRICT, never expand, the rules-derived floor). Decide from the program rules + what "
            "this target needs: does proving a bug here require NETWORK egress (web research / "
            "fetching deps) or can it be fully local? Are dependency INSTALLS needed to build, or is "
            "the repo self-contained / does the program forbid them? Are there commands that should "
            "be blocked outright for this target? Default to allowing what the work genuinely needs "
            "and turning OFF what it doesn't (e.g. an offline crypto-lib audit: network off).\n\n"
            "Return ONLY JSON:\n"
            '{"summary":"...",'
            # target_class is used ONLY to route which toolchain RE-RUNS your PoC (forge / go / '
            # cargo / pytest / native-cc / web). Pick the one that fits how THIS target is built and
            # tested — derived from what you observed, not from any list of bugs. Use OTHER if none fit.
            '"target_class":"<one of: EVM_CONTRACT | CRYPTO_LIB | WEB_API | MOBILE_APP | INFRA | '
            'SUPPLY_CHAIN | OTHER — whichever matches how this target builds/tests>",'
            '"threat_model":"...",'
            '"target_subclass":"<one-word category you DERIVED from the code, or \"\">",'
            '"workspace_root":"<relative path to the in-scope folder, or \".\">",'
            '"permissions":{"allow_network":true|false,"allow_install":true|false,'
            '"deny_commands":["<substring of any command to block for this target>",...],'
            '"note":"<one line: why this posture fits this engagement>"},'
            '"critical_means":"<the maximum attacker win for THIS system>",'
            '"crown_jewels":["<where value/authority/secrets concentrate — file:line>",...],'
            '"attack_surface":["<externally-reachable entrypoint + which actor controls it — file:line>",...],'
            '"differential_oracle":{"exists":true|false,"description":"where the second '
            'implementation/spec is and how it pairs with the in-scope code, or why none exists"},'
            '"known_patterns":["<known bug pattern to hunt a NEW variant of in this code>",...],'
            '"top_hypothesis":"<the single place you would bet the P1 is, citing code + the first move to test it>",'
            # tracks MUST be ORDERED most-dangerous-first (track 0 is worked first/deepest).
            '"tracks":[{"theme":"...","subsystem":"...","fuzz_mode":"differential|invariant",'
            '"expected_severity":"critical|high|medium","attacker_reachability":"high|medium|low",'
            '"focus_files":["relative/path",...],'
            '"invariants":["<machine-checkable property an attacker must never be able to break>",...],'
            '"investigate":["concrete attacker move to attempt IN THIS CODE",...]}]}'
        )

    async def _scope(self, guard: ScopeGuard) -> dict:
        if not self.config.use_claude:
            return {"tracks": self._fallback_tracks()}
        from .claude_session import ClaudeSession

        self._emit(self.name, "message",
                   {"phase": "scoping", "detail": "cold reconnaissance — no prior knowledge of the target"})
        try:
            _recon_turns = max(20, int(os.environ.get("P1HUNT_RECON_TURNS", "45")))
        except ValueError:
            _recon_turns = 45
        session = ClaudeSession(
            agent_name=self.name, model=self.config.models.orchestrator, on_event=self._emit,
            guard_check=self._guard_check(guard, self.name), max_turns=_recon_turns,
            perms=self._perms, egress_hosts=self._egress_hosts,
        )
        result = await session.run(self._scope_prompt(), self.repo_path)
        parsed = _parse_json_object(result.text)
        self._apply_workspace_guardrail((parsed or {}).get("workspace_root"))
        if not parsed or not parsed.get("tracks"):
            self._emit(self.name, "lifecycle", {"event": "scope_fallback", "reason": "no tracks derived"})
            return {"tracks": self._fallback_tracks(),
                    "critical_means": (parsed or {}).get("critical_means"),
                    "summary": (parsed or {}).get("summary", "")}
        # Surface Parent A's recon reasoning so the operator can see the map it drew (and judge it).
        self._emit(self.name, "lifecycle",
                   {"event": "recon", "crown_jewels": (parsed.get("crown_jewels") or [])[:5],
                    "attack_surface": (parsed.get("attack_surface") or [])[:6],
                    "top_hypothesis": str(parsed.get("top_hypothesis", ""))[:300],
                    "tracks": [t.get("subsystem") or t.get("theme") for t in (parsed.get("tracks") or [])][:6]})
        return parsed

    def _apply_workspace_guardrail(self, workspace_root: str | None) -> None:
        """Parent A decides the workspace folder; we LOCK it as the one hard guardrail. The choice
        is CLAMPED to the acquired target tree — Parent A may narrow the boundary to an in-scope
        subfolder but can never widen it past what was authorized/acquired. Defaults to the whole
        acquired folder. Always emitted so the operator can see the enforced boundary."""
        acquired = Path(self.repo_path).resolve()
        chosen = acquired
        narrowed = False
        if workspace_root and str(workspace_root).strip() not in ("", "."):
            cand = Path(str(workspace_root).strip())
            if not cand.is_absolute():
                cand = acquired / cand
            try:
                cand = cand.resolve()
                cand.relative_to(acquired)  # must stay within the acquired tree (no escape)
                if cand.is_dir():
                    chosen, narrowed = cand, (cand != acquired)
            except (ValueError, OSError):
                chosen = acquired  # outside the acquired tree -> ignore, keep the safe default
        self._workspace_root = str(chosen)
        # If Parent A narrowed the boundary, keep the PoC sandbox inside it so writes stay in scope.
        if narrowed:
            self.poc_dir = Path(self._workspace_root) / ".p1hunt-poc"
            try:
                self.poc_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
        self._emit(self.name, "lifecycle",
                   {"event": "workspace_guardrail", "set_by": "parent_a",
                    "workspace": self._workspace_root, "narrowed": narrowed,
                    "policy": "agents may do ANYTHING inside this folder; every file read/write/edit outside it is denied"})

    def _apply_permission_policy(self, permissions: object | None) -> None:
        """PARENT A CONTROLS PERMISSIONS. Apply the permission posture Parent A chose during recon,
        CLAMPED so it can only become MORE restrictive than the rules-derived floor (it may turn
        network/installs OFF or add denied commands; it can never re-enable them). The result is the
        single posture every agent session enforces. Always emitted so the operator sees the boundary
        Parent A set (analogous to the workspace guardrail)."""
        self._perms = self._perms.tightened_with(permissions if isinstance(permissions, dict) else None)
        self._emit(self.name, "lifecycle",
                   {"event": "permission_policy", "set_by": "parent_a",
                    "allow_network": self._perms.allow_network,
                    "allow_install": self._perms.allow_install,
                    "deny_commands": self._perms.deny_commands[:8],
                    "note": self._perms.note,
                    "policy": "agents may act freely inside the workspace EXCEPT as restricted here; "
                              "this can only tighten the rules-derived floor, never loosen it"})

    def _fallback_tracks(self) -> list[dict]:
        """Only when no Claude brain is available (offline/tests): generic lens tracks with a
        mechanical file partition. No bug-class hints."""
        files = self._enumerate_targets()
        return [
            {"theme": lens, "focus_files": files[i :: len(_LENSES)], "investigate": []}
            for i, lens in enumerate(_LENSES)
        ]

    def _record_hypothesis(self, cf: ClaudeFinding) -> None:
        hyp = Hypothesis(
            id=new_id("HYP"),
            claim=f"{cf.title} at {cf.file}:{cf.line}",
            owner_agent="child_b",
            lens=cf.lens,
            target_assets=[self.repo_path],
            assumptions=[cf.root_cause] if cf.root_cause else [],
            safe_validation_plan=SafeValidationPlan("local", "read-only", "synthetic/owned"),
            stop_conditions=["out of scope", "third-party data", "destructive action"],
            evidence_required=["Claude-cited code evidence", "adversarial verification"],
            state=HypState.CANDIDATE,
            counterfactual=cf.counterfactual or None,
        )
        self.bb.add_hypothesis(hyp)
        self._hyp_by_finding[id(cf)] = hyp

    # --- deterministic reproduction + severity gate (§10, §1 NOTHING PRESET) ----------
    async def _reproduce(self, cf: ClaudeFinding, spec_dict: dict | None):
        """Run the materialized harness through the DETERMINISTIC class runner. Returns a
        ReproResult (or None when there is no harness/runner). Never raises; offloaded to a thread
        so a long toolchain run doesn't block the event loop."""
        if not spec_dict:
            return None
        runner = select_runner(self._target_class, self._subclass)
        if runner is None:
            self._emit("poc_prover", "lifecycle",
                       {"event": "no_runner", "class": self._target_class,
                        "detail": "no deterministic runner for this class — stays a candidate"})
            return None
        try:
            spec = ReproSpec.from_dict(spec_dict)
            timeout = float(os.environ.get("P1HUNT_REPRO_TIMEOUT", "600"))
            repro = await asyncio.to_thread(runner.run, self._workspace_root, spec,
                                            timeout=timeout, on_event=self._emit)
        except Exception as exc:
            self._emit("poc_prover", "lifecycle", {"event": "runner_error", "detail": str(exc)})
            return None
        self._emit("poc_prover", "lifecycle",
                   {"event": "reproduction", "runner": repro.runner, "ran": repro.ran,
                    "reproduced": repro.reproduced, "command": repro.command[:200],
                    "detail": (repro.detail or "")[:200]})
        return repro

    _LOSS_TYPES = ("funds", "data", "control", "availability")

    def _impact_of(self, cf: ClaudeFinding, reproduced: bool) -> "ImpactAssessment":
        """Build an ImpactAssessment from DERIVED facts — NOTHING PRESET. ``reproduced`` and
        ``in_scope`` are deterministic (runner + ScopeGuard). The concrete loss is whatever the
        agent itself STATED it demonstrated (cf.concrete_loss), not a keyword guess — if the agent
        could not articulate a concrete loss, it is 'none' and the finding is not auto-promoted to
        P1 (it stays a candidate for human review, which is the correct conservative behavior)."""
        loss = (cf.concrete_loss or "").strip().lower()
        loss = loss if loss in self._LOSS_TYPES else "none"
        capability = bool((cf.counterfactual or "").strip())
        return ImpactAssessment(
            reproduced=reproduced, protected_asset=(loss != "none"),
            attacker_capability=capability, concrete_loss=loss,
            in_scope=not self._out_of_scope(cf.file), note=(cf.counterfactual or "")[:200],
        )

    def _norm_tier(self, sev_label: str, is_p1: bool) -> str:
        """Map the program's taxonomy label back to a normalized tier for Finding.severity."""
        if is_p1:
            return "critical"
        for tier in ("critical", "high", "medium", "low"):
            if sev_label == self._severity.label_for_tier(tier):
                return tier
        return "high"

    def _promote(self, cf: ClaudeFinding, rationale: str, guard: ScopeGuard, *,
                 repro, severity_label: str, tier: str) -> Finding:
        """Build a CONFIRMED finding. Only ever called for a DETERMINISTICALLY reproduced candidate,
        so the artifact is reproduced=True and carries the real runner command + output excerpt."""
        cmd = getattr(repro, "command", "") or ""
        arts = list(getattr(repro, "artifact_paths", []) or [])
        proof = getattr(repro, "detail", "") or getattr(repro, "stdout_excerpt", "")
        artifact = ArtifactRef(
            id=new_id("art"), kind="repro",
            path=(arts[0] if arts else f"{cf.file}:{cf.line}"),
            description=f"REPRODUCED by {getattr(repro, 'runner', 'runner')} runner via `{cmd}` — {proof[:280]}",
            reproduced=True,
        )
        self.bb.add_artifact(artifact)
        # Remediation is DERIVED by the finder for THIS root cause (NOTHING PRESET — no bug-id
        # remediation table). Fall back to a single generic instruction only if it didn't state one.
        remediation = cf.remediation or "Fix the root cause and add a regression test that fails before the fix and passes after."
        finding = Finding(
            id=new_id("FND"),
            hypothesis_id=self._hyp_by_finding.get(id(cf), Hypothesis(
                id="?", claim="", owner_agent="", lens=cf.lens, target_assets=[], assumptions=[],
                safe_validation_plan=SafeValidationPlan("", "", ""), stop_conditions=[], evidence_required=[])).id,
            title=cf.title,
            root_cause=cf.root_cause,
            poc=artifact,
            severity=tier,
            severity_rationale=f"[{severity_label}] PoC-REPRODUCED (deterministic runner). {rationale}",
            counterfactual=cf.counterfactual,
            remediation=remediation,
            safe_harbor_attestation=guard.attestation(),
            verified=True,
        )
        self.bb.add_finding(finding)
        # LEARN: persist this CONFIRMED finding (generalized) to cross-engagement memory so future
        # engagements on similar targets start with it as a "hunt a new variant" prior.
        if self._memory is not None:
            try:
                self._memory.record(
                    target_class=self._target_class, subclass=self._subclass,
                    finding={"program": self.scope.program, "title": cf.title, "lens": cf.lens,
                             "severity": tier, "root_cause": cf.root_cause,
                             "counterfactual": cf.counterfactual,
                             "harness_kind": getattr(repro, "runner", "")})
            except Exception:
                pass
        return finding

    def _surface_for_human(self, cf: ClaudeFinding, rationale: str, severity_label: str,
                           guard: ScopeGuard, *, ran: bool, detail: str) -> Finding:
        """Build a NEEDS-HUMAN-REVIEW finding: believed-real + high-confidence + concrete-loss, but
        not auto-reproduced. Marked verified=False and given an UNreproduced artifact, so it never
        counts as a confirmed critical (the reproduced=confirmed floor is intact) — it is surfaced
        prominently for a human precisely because the reasoning is strong and only the mechanical
        proof is missing. This is the opposite of burying it as a nondescript candidate."""
        why = ("ran but did not deterministically demonstrate the bug" if ran
               else "no runnable harness/toolchain to auto-reproduce")
        artifact = ArtifactRef(
            id=new_id("art"), kind="reasoned",
            path=f"{cf.file}:{cf.line}",
            description=f"NOT auto-reproduced ({why}); reasoned P1 for human verification — {str(detail)[:240]}",
            reproduced=False,
        )
        return Finding(
            id=new_id("FND"),
            hypothesis_id=self._hyp_by_finding.get(id(cf), Hypothesis(
                id="?", claim="", owner_agent="", lens=cf.lens, target_assets=[], assumptions=[],
                safe_validation_plan=SafeValidationPlan("", "", ""), stop_conditions=[], evidence_required=[])).id,
            title=cf.title,
            root_cause=cf.root_cause,
            poc=artifact,
            severity=severity_label,
            severity_rationale=f"[{severity_label}] NEEDS HUMAN REVIEW — believed real (high confidence, "
                               f"concrete loss: {cf.concrete_loss}) but not auto-reproduced. {rationale}",
            counterfactual=cf.counterfactual,
            remediation=cf.remediation or "Verify manually, then fix the root cause and add a regression test.",
            safe_harbor_attestation=guard.attestation(),
            verified=False,
        )

    def trigger_safety_event(self, reason: str) -> None:
        self._safety_event = True
        self._emit(self.name, "lifecycle", {"event": "safety_event", "reason": reason})

    def _result(self, status, plan, guard, findings, candidates, rounds) -> HuntResult:
        return HuntResult(
            status=status, plan=plan, rounds_run=rounds, findings=findings,
            reframes=self._reframes, demoted_to_warm_pool=False, attestation=guard.attestation(),
            candidates=[c.__dict__ for c in candidates], brain="claude",
        )


def _parse_json_object(text: str) -> dict:
    """Extract the first JSON object from a Claude reply (fenced block or inline)."""
    import json
    import re

    if not text:
        return {}
    cands = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        cands.append(m.group(0))
    for raw in cands:
        try:
            d = json.loads(raw)
            if isinstance(d, dict):
                return d
        except json.JSONDecodeError:
            continue
    return {}
