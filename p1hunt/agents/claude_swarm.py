"""AI swarm orchestrator — Parent A driving prompt-role agents (spec §6-§10).

The AI is the detector. Parent A derives the plan, assigns each ranked lens to a Child B, and runs
the never-quit loop: every round each Child B hunts its lens with a fresh creative angle; the
Falsifier tries to refute each candidate; only a confirmed, reachable critical is promoted. On a
dry round it reframes and digs deeper — it does not give up until a critical is confirmed or the
operator stops. Codex is the default runtime engine for every role.
"""

from __future__ import annotations

import asyncio
import json
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
from .claude_hunter import (
    ClaudeDebate,
    ClaudeDeduplicator,
    ClaudeExploitDeveloper,
    ClaudeHunter,
    ClaudePoCProver,
    ClaudeVerifier,
)
from .claude_session import ClaudeFinding
from .fuzz_engine import ClaudeFuzzer
from .derive import derive_plan
from .harness_scaffold import detect_evm_entrypoints
from .parent_a import HuntResult
from ..corpus import CorpusStore
from ..classify.evm_signals import evm_assembly_density
from ..counterfactual_gate import assess_counterfactual_proof
from ..runners.base import ReproSpec, select_runner
from ..severity import ImpactAssessment, SeverityMapper
from ..tools.build_env import BuildReport, bootstrap_environment, ensure_foundry, toolchain_available
from ..tools.evm_fork import fork_available, start_anvil_fork, stop_anvil_fork

def normalize_exploit_tier(tier: str) -> str:
    """Normalize exploit-depth verdict tiers without inflating lower severity to critical."""
    tier = str(tier or "").strip().lower()
    return tier if tier in ("critical", "high", "medium", "low") else "high"


def _env_int(name: str, default: int, *, minimum: int | None = None) -> int:
    try:
        value = int(os.environ.get(name, str(default)) or default)
    except (TypeError, ValueError):
        value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


def _env_float(name: str, default: float, *, minimum: float | None = None) -> float:
    try:
        value = float(os.environ.get(name, str(default)) or default)
    except (TypeError, ValueError):
        value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


def _poc_reldir(repo_path) -> str:
    """The relative dir (under the target repo) where PoC harnesses must be written so the target's
    OWN toolchain can actually RUN them.

    For a Foundry project this MUST sit inside the project's configured ``test`` tree: files outside
    ``src``/``test`` are not compiled, so ``forge test --match-path`` reports "No tests found" and
            project-local remappings fail to resolve. This was the single biggest reason real PoCs
    never executed (every harness was written to ``.p1hunt-poc/``, which Foundry ignores). We nest
    under ``<test_dir>/p1hunt`` so the harnesses are discovered, compile, and resolve imports, while
    staying clearly separated from the project's own tests. Non-Foundry targets keep ``.p1hunt-poc``.
    """
    import re
    try:
        ft = Path(repo_path) / "foundry.toml"
        if ft.is_file():
            # First `test = '...'` is the default profile's test dir (Foundry convention).
            m = re.search(r"(?m)^\s*test\s*=\s*['\"]([^'\"]+)['\"]", ft.read_text(encoding="utf-8", errors="replace"))
            test_dir = (m.group(1).strip().rstrip("/") if m else "test") or "test"
            return f"{test_dir}/p1hunt"
    except Exception:
        pass
    return ".p1hunt-poc"


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
        self._configure_engine()
        self.bus = bus
        self.bb = blackboard
        self.log = event_log
        # DEEP-DISCOVERY mode: trade breadth for sustained depth — fewer concurrent hunters, each
        # with a much larger turn + wall-clock budget, so a single hard lead gets the hours of
        # compounding reasoning a hardened-target critical needs (instead of many short shallow
        # passes). Also reduces parallel API load -> less rate-limit downgrade (see Fix #3).
        self._deep_discovery = os.environ.get("P1HUNT_DEEP_DISCOVERY", "0") == "1"
        _mc_env = _env_int("P1HUNT_MAX_CONCURRENCY", 0)
        if _mc_env > 0:
            max_concurrency = _mc_env
        elif self._deep_discovery:
            _deep_conc = _env_int("P1HUNT_DEEP_DISCOVERY_CONCURRENCY", 3, minimum=1)
            max_concurrency = min(max_concurrency, _deep_conc)  # fewer, deeper hunters -> full quota each
        self._max_concurrency = max_concurrency
        self.sem = asyncio.Semaphore(max_concurrency)
        _side_conc = _env_int("P1HUNT_SIDE_LANE_CONCURRENCY", 1, minimum=1)
        self._side_lane_concurrency = _side_conc
        self.side_sem = asyncio.Semaphore(_side_conc)
        self.name = "parent_a"
        self._safety_event = False
        self._paused = False
        self._reframes = 0
        self._hyp_by_finding: dict[int, Hypothesis] = {}
        self._focus_by_lens: dict[str, list[str]] = {}
        # Live operator control channel (§11): notices pushed via `p1hunt notify` are read at
        # each round boundary and injected into the next round's hunter prompts — e.g. "new code
        # is now available, keep hunting" — so a running hunt absorbs updates without a restart.
        self._notices: list[str] = []
        self._known_patterns: list[str] = []  # retained only for old resume files; not injected
        self._control_offset = 0
        # Self-healing watchdog: if the whole swarm goes silent (a hung session blocking the
        # round, or an API rate-limit) for STALL_SECONDS, Parent A diagnoses and fixes it.
        import time as _t
        self._last_activity = _t.monotonic()
        self._round_tasks: list = []
        self._fuzz_tasks: dict[str, asyncio.Task] = {}
        self._active_guard = None
        self._healing = False

        self._heals = 0
        # PoC sandbox: the ONLY place agents may write (proof-of-concept files), never source.
        # For a Foundry target this MUST live inside the project's configured `test` tree — otherwise
        # `forge test` cannot compile/discover the harness and remappings break (the #1 reason every
        # PoC silently never ran on Foundry-style targets). See _poc_reldir.
        self.poc_reldir = _poc_reldir(repo_path)
        self.poc_dir = Path(repo_path) / self.poc_reldir
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
        # Preset-free guard: no deterministic scanner hits are handed to hunters as leads.
        self._scan_hits: list = []
        # --- live dynamic-testing state (armed in hunt()/_arm_environment when authorized) ---
        # The authorized egress allowlist that confines every agent's outbound request to in-scope
        # hosts (the live safe-harbor jail). It is ALWAYS A LIST and is NEVER None: an empty list
        # is the UNARMED posture, which the jail reads as "loopback + build/registry hosts only".
        # Passing None used to mean "no confinement at all" downstream (bash_safety skipped the
        # jail entirely), so a dry-run with no authorized target could curl anything on the
        # internet. ``_dynamic_armed`` — not "is the allowlist None" — now answers "is live
        # testing authorized", so arming state and confinement can never be conflated again.
        self._egress_hosts: list[str] = []
        self._dynamic_armed: bool = False
        # Latch so the HIGH-severity refusal warning is stated once per run, not once per
        # round -- a repeated warning gets scrolled past, which defeats the point.
        self._refusal_announced: bool = False
        self._base_url: str = ""                 # the primary authorized dynamic target base URL
        self._oob = None                         # running loopback OOB interaction listener
        self._dynamic_env_keys: list[str] = []   # env vars _arm_dynamic exported (cleared on exit)
        # COST GUARD: a never-quit run has no natural end, so accumulate spend (from session usage
        # events) and, if the operator set a ceiling, stop GRACEFULLY when it's hit. Default off
        # (None) so behavior is unchanged unless P1HUNT_MAX_COST_USD is set, but the running total
        # is always emitted so spend is never invisible.
        self._spend_usd: float = 0.0
        _cap = _env_float("P1HUNT_MAX_COST_USD", 0.0)
        self._cost_cap: float | None = _cap if _cap > 0 else None
        # STOP-AFTER-N-CRITICALS: once this many criticals are CONFIRMED, stop gracefully. Blank/
        # unset/0 = never-quit (the default). No LLM cost — a simple round-boundary check.
        _mc = _env_int("P1HUNT_MAX_CRITICALS", 0)
        self._max_criticals: int | None = _mc if _mc > 0 else None
        # Confirmation-time dedup (on by default; cheap, only fires when prior confirmed exist) and
        # the round-end debate panel on confirmed criticals (capped for token cost; 0 disables).
        self._dedup_on = os.environ.get("P1HUNT_DEDUP", "1") != "0"
        self._debate_max = _env_int("P1HUNT_DEBATE_MAX", 3, minimum=0)
        # Debate-panel ledgers, keyed by a STABLE finding key (not the ephemeral id) so a finding
        # that is re-found in a later round inherits its prior debate verdict. A critical is only
        # ever written as a CONFIRMED critical if debate UPHELD it (when debate is enabled); a
        # rejected one can never come back, and a downgraded one is recorded at its lowered severity.
        self._debated: set[str] = set()           # keys already adjudicated by the panel
        self._debate_rejected: set[str] = set()   # keys debate rejected -> never confirmed
        self._debate_upheld: set[str] = set()     # keys debate upheld -> eligible to be confirmed
        self._debate_downgraded: dict[str, str] = {}  # key -> downgraded severity
        self._debate_errors: dict[str, int] = {}
        self._debate_error_max = _env_int("P1HUNT_DEBATE_ERROR_MAX", 2, minimum=1)
        # EXPLOIT-DEVELOPMENT DEPTH PHASE: the organ that turns a believed primitive into a PROVEN
        # attacker-win. When enabled, a critical is confirmed ONLY if this phase demonstrated the
        # rubric's attacker-win in shipped code (primitive != critical). Bounded by top-N per round.
        self._deepdive_on = os.environ.get("P1HUNT_DEEPDIVE", "1") != "0"
        self._deepdive_top_n = _env_int("P1HUNT_DEEPDIVE_TOP_N", 4, minimum=1)
        self._deepdive_turns = _env_int("P1HUNT_DEEPDIVE_TURNS", 60, minimum=20)
        self._exploit_proven: set[str] = set()    # keys with a DEMONSTRATED attacker-win (shipped code)
        self._exploit_tasks: dict[str, asyncio.Task] = {}  # non-blocking exploit-depth tasks by finding key
        self._deepdived: set[str] = set()         # legacy; pursuit now tracked in _lead_log
        # PERSISTENT LEAD PURSUIT (tenacity): a promising lead is RE-attacked with a DIFFERENT angle
        # across rounds instead of being abandoned after one failed PoC. Each key maps to
        # {"attempts": [{strategy, why_failed}], "status": "open|proven|exhausted|maxed"}. A lead
        # closes ONLY on a proven win or a rigorous cross-angle impossibility; after a hard attempt
        # cap it is PARKED (needs_human), never silently dropped. Failed attempts decay its priority
        # so the engine rotates to fresher leads but keeps cycling back.
        self._lead_log: dict[str, dict] = {}
        self._lead_max_attempts = _env_int("P1HUNT_LEAD_MAX_ATTEMPTS", 10, minimum=1)
        # Parent A intervention ledger: every serious candidate gets an explicit pipeline state
        # ("blackboard posted" -> "falsifier real" -> "repro blocked" -> "deep-dive queued" ->
        # "debate upheld"/"confirmed"). This prevents the bad UX where a verifier says "real" and
        # the operator cannot tell why it is not in confirmed criticals yet.
        self._candidate_status: dict[str, dict] = {}
        self._operator_triage: list[dict] = []
        self._agent_directives: dict[str, list[str]] = {}
        self._live_hunters: list = []
        self._live_roles: dict[str, object] = {}
        # Cross-engagement memory is disabled by default in preset-free mode. Operators can still
        # explicitly enable the store for experiments, but live hunts never need it.
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

    def _configure_engine(self) -> None:
        eng = (getattr(self.config.models, "engine", "") or "codex").strip().lower()
        if eng not in ("codex", "claude"):
            eng = "codex"
        disc = (getattr(self.config.models, "discovery_engine", "") or eng).strip().lower()
        if disc not in ("codex", "claude"):
            disc = eng
        self.config.models.engine = eng
        self.config.models.discovery_engine = disc
        os.environ["P1HUNT_ENGINE"] = eng
        os.environ["P1HUNT_DISCOVERY_ENGINE"] = disc

    def _role_engine_kwargs(self) -> dict:
        return {
            "engine": self.config.models.engine,
            "codex_model": self.config.models.codex_model,
            "codex_effort": self.config.models.codex_effort,
        }

    def _apply_role_engine(self, role) -> None:
        for key, value in self._role_engine_kwargs().items():
            setattr(role, key, value)

    def _cpu_pct(self) -> float:
        """Process+children CPU% since the last call (covers the swarm and agent subprocesses).
        Best-effort: 0.0 if unavailable. Used for the UI status panel."""
        import os as _os
        import time as _t
        try:
            ti = _os.times()
            cpu = ti.user + ti.system + ti.children_user + ti.children_system
            now = _t.monotonic()
            prev_cpu = getattr(self, "_prev_cpu", None)
            prev_t = getattr(self, "_prev_cpu_t", None)
            self._prev_cpu, self._prev_cpu_t = cpu, now
            if prev_cpu is None or prev_t is None:
                return 0.0
            dt = now - prev_t
            return round(100.0 * (cpu - prev_cpu) / dt, 1) if dt > 0 else 0.0
        except Exception:
            return 0.0

    def _emit(self, agent: str, kind: str, data: dict) -> None:
        import time as _t
        self._last_activity = _t.monotonic()  # any event = the swarm is alive (watchdog signal)
        if kind == "usage":  # accumulate spend so a never-quit run can be cost-bounded + visible
            try:
                self._spend_usd += float(data.get("cost", 0) or 0)
            except (TypeError, ValueError):
                pass
        event = self.log.emit(agent, kind, data)
        if kind == "finding_reported":
            self._record_live_finding(agent, data, event_id=event.id, ts=event.ts)

    def _engagement_dir(self) -> Path | None:
        path = getattr(self.log, "path", None)
        return Path(path).parent if path is not None else None

    def _artifact_path(self, raw: str) -> Path | None:
        if not raw:
            return None
        p = Path(str(raw))
        if not p.is_absolute():
            p = Path(self.repo_path) / p
        try:
            rp = p.resolve()
            rp.relative_to(Path(self.repo_path).resolve())
        except (OSError, ValueError):
            return None
        return rp if rp.exists() else None

    def _candidate_doc(self, item) -> dict:
        """JSON-safe finding/candidate shape used by live ledger, findings.json, and artifact packs."""
        import dataclasses as _dc

        if isinstance(item, dict):
            raw = dict(item)
        elif _dc.is_dataclass(item):
            raw = _dc.asdict(item)
        elif hasattr(item, "__dict__"):
            raw = dict(item.__dict__)
        else:
            raw = {"title": str(item)}

        poc = raw.get("poc")
        if _dc.is_dataclass(poc):
            raw["poc"] = _dc.asdict(poc)
        elif hasattr(poc, "__dict__"):
            raw["poc"] = dict(poc.__dict__)
        elif poc is None:
            raw.pop("poc", None)

        if "location" not in raw or not raw.get("location"):
            loc = raw.get("file") or ""
            if raw.get("line") not in (None, "", 0):
                loc = f"{loc}:{raw.get('line')}" if loc else str(raw.get("line"))
            if not loc and isinstance(raw.get("poc"), dict):
                loc = raw["poc"].get("path", "")
            raw["location"] = loc
        raw["title"] = str(raw.get("title") or raw.get("hyp") or "").strip()
        raw["severity"] = str(raw.get("severity") or "candidate").strip().lower()
        return raw

    def _finding_key_from_doc(self, doc: dict) -> str:
        import hashlib as _hashlib
        import re as _re

        def _norm(v: object) -> str:
            return _re.sub(r"\s+", " ", str(v or "").strip().lower())

        loc = _norm(doc.get("location") or doc.get("file") or doc.get("endpoint") or doc.get("url"))
        root = _norm(doc.get("root_cause"))
        if loc and root:
            basis = "\x1f".join((loc, root[:500]))
        elif loc:
            basis = "\x1f".join((loc, _norm(doc.get("title"))[:240]))
        else:
            basis = "\x1f".join((_norm(doc.get("title"))[:240], root[:500]))
        return _hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]

    def _pipeline_status_for_doc(self, key: str, doc: dict) -> dict | None:
        """Find exact or location-equivalent pipeline state for UI rows.

        Live blackboard titles often evolve as Parent A/deep-dive rewrites a lead. The UI should not
        show the original wording as stuck at POST if an equivalent file:line lead is already being
        verified or exploited.
        """
        candidates: list[dict] = []
        status = self._candidate_status.get(key)
        if status:
            candidates.append(status)
        loc = str(doc.get("location") or doc.get("file") or "").strip()
        if loc:
            candidates.extend(
                s for s in self._candidate_status.values()
                if str(s.get("location") or "").strip() == loc
            )
        if not candidates:
            return None
        return max(candidates, key=lambda s: float(s.get("updated_ts") or 0))

    def _read_live_findings(self) -> list[dict]:
        eng = self._engagement_dir()
        if eng is None:
            return []
        path = eng / "live_findings.json"
        try:
            import json as _json
            doc = _json.loads(path.read_text(encoding="utf-8"))
            cands = doc.get("candidates", [])
            return cands if isinstance(cands, list) else []
        except (OSError, ValueError):
            return []

    def _live_findings_as_candidates(self) -> list[ClaudeFinding]:
        """Convert live blackboard posts into normal verifier candidates.

        Live posts are valuable precisely because they arrive before a long model turn finishes. They
        must not remain dashboard-only records; Parent A should pull them into the same
        falsifier/prover/deep-dive queue as final JSON findings.
        """
        import re as _re

        out: list[ClaudeFinding] = []
        for raw in self._read_live_findings():
            if not isinstance(raw, dict) or not raw.get("title"):
                continue
            d = dict(raw)
            loc = str(d.get("location") or d.get("path") or d.get("endpoint") or d.get("url") or "")
            if not d.get("file") and loc:
                m = _re.match(r"^(.+?):(\d+)$", loc)
                if m:
                    d["file"] = m.group(1)
                    d.setdefault("line", int(m.group(2)))
                else:
                    d["file"] = loc
            if not d.get("line"):
                d["line"] = 0
            d.setdefault("lens", str(d.get("agent") or "blackboard"))
            d.setdefault("confidence", "medium")
            d.setdefault("root_cause", str(d.get("evidence") or d.get("why") or ""))
            d.setdefault("reproduction", str(d.get("attempted_escalation")
                                             or d.get("verification_depth") or ""))
            d.setdefault("counterfactual", str(d.get("impact") or d.get("counterfactual") or ""))
            try:
                out.append(ClaudeFinding.from_dict(d, str(d.get("lens") or "blackboard")))
            except Exception:
                continue
        return out

    def _write_json_atomic(self, path: Path, doc: dict) -> None:
        import json as _json
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(_json.dumps(doc, indent=2, sort_keys=True, default=str), encoding="utf-8")
        tmp.replace(path)

    def _rubric_text(self) -> str:
        import json as _json
        taxonomy = getattr(self.scope, "severity_taxonomy", {}) or {}
        scope_note = getattr(self.scope, "scope_note", "") or getattr(self.scope, "safe_harbor_text", "") or ""
        parts = [f"# Program Rubric\n\nProgram: {self.scope.program}\n"]
        if taxonomy:
            parts.append("Severity taxonomy:\n\n```json\n" + _json.dumps(taxonomy, indent=2, sort_keys=True) + "\n```\n")
        if scope_note:
            parts.append("Scope / reward note:\n\n" + scope_note.strip() + "\n")
        if not taxonomy and not scope_note:
            parts.append("No engagement-specific severity taxonomy was captured.\n")
        return "\n".join(parts)

    def _write_artifact_pack(self, doc: dict) -> None:
        eng = self._engagement_dir()
        if eng is None:
            return
        key = doc.get("dedup_key") or self._finding_key_from_doc(doc)
        out = eng / "report_artifacts" / str(key)
        try:
            out.mkdir(parents=True, exist_ok=True)
            self._write_json_atomic(out / "finding.json", doc)
            (out / "rubric.md").write_text(self._rubric_text(), encoding="utf-8")
            raw_path = doc.get("file") or doc.get("path") or ""
            src = self._artifact_path(str(raw_path))
            if src is not None and src.is_file():
                try:
                    line = int(doc.get("line") or 0)
                except (TypeError, ValueError):
                    line = 0
                lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
                if line > 0:
                    lo, hi = max(1, line - 30), min(len(lines), line + 30)
                else:
                    lo, hi = 1, min(len(lines), 120)
                excerpt = "\n".join(f"{i}: {lines[i-1]}" for i in range(lo, hi + 1))
                (out / "source_excerpt.txt").write_text(excerpt, encoding="utf-8")
            poc = doc.get("poc") if isinstance(doc.get("poc"), dict) else {}
            poc_src = self._artifact_path(str(poc.get("path", ""))) if poc else None
            if poc_src is not None and poc_src.is_file():
                import shutil as _shutil
                _shutil.copy2(poc_src, out / ("poc_" + poc_src.name))
        except OSError:
            return

    def _record_live_finding(self, agent: str, data: dict, *, event_id: str, ts: float) -> None:
        """Immediately persist a posted finding before the model session returns.

        This is the crash-resilience path for long scans: live findings are no longer only visible in
        events.jsonl until the round boundary writes findings.json.
        """
        import time as _time

        eng = self._engagement_dir()
        if eng is None:
            return
        payload = data.get("finding") if isinstance(data.get("finding"), dict) else data
        doc = self._candidate_doc(payload)
        if not doc.get("title"):
            return
        doc["agent"] = agent
        doc["status"] = doc.get("status") or "live_candidate"
        doc.setdefault("verification_depth", "posted by finder; Parent A verification/proof pending")
        doc["first_seen_ts"] = float(ts)
        doc["last_seen_ts"] = float(ts)
        doc["event_ids"] = [event_id]
        doc["event_count"] = 1
        doc["dedup_key"] = self._finding_key_from_doc(doc)
        reported_status = str(doc.get("status") or "").strip().lower()
        verified = bool(doc.get("verified")) or "confirmed" in reported_status or "reproduced" in reported_status
        self._record_candidate_status(
            doc,
            stage="operator_verified" if verified else "blackboard",
            status=(reported_status or "confirmed_critical_reproduced") if verified else "posted",
            target_agent="parent_a" if verified else agent,
            next_action=(
                "Parent A should preserve confirmed-critical status, polish the report, and continue only for a cleaner or second P1."
                if verified else
                "Parent A will verify, materialize proof, run reproduction, then deep-dive if needed."
            ),
            blocked_by="" if verified else "awaiting_parent_pipeline",
            reason=str(doc.get("verification_depth") or doc.get("evidence") or doc.get("root_cause") or "")[:240],
        )

        existing = self._read_live_findings()
        merged: dict[str, dict] = {}
        for old in existing:
            if not isinstance(old, dict):
                continue
            key = old.get("dedup_key") or self._finding_key_from_doc(old)
            old["dedup_key"] = key
            merged[key] = old
        cur = merged.get(doc["dedup_key"])
        if cur:
            cur.update({k: v for k, v in doc.items() if v not in (None, "", [])})
            cur["first_seen_ts"] = min(float(cur.get("first_seen_ts") or ts), float(ts))
            cur["last_seen_ts"] = float(ts)
            ids = list(dict.fromkeys([*(cur.get("event_ids") or []), event_id]))
            cur["event_ids"] = ids[-20:]
            cur["event_count"] = int(cur.get("event_count") or 1) + 1
            doc = cur
        merged[doc["dedup_key"]] = doc
        cands = sorted(
            (self._apply_pipeline_status(v) for v in merged.values()),
            key=lambda x: float(x.get("last_seen_ts") or 0),
            reverse=True,
        )
        live_doc = {
            "program": self.scope.program,
            "updated": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
            "counts": {"candidates": len(cands)},
            "candidates": cands,
        }
        try:
            self._write_json_atomic(eng / "live_findings.json", live_doc)
            self._write_findings_snapshot_from_live(cands)
            self._write_artifact_pack(doc)
        except OSError:
            return

    def _merge_live_candidates(self, candidates) -> list[dict]:
        merged: dict[str, dict] = {}
        for c in candidates:
            doc = self._candidate_doc(c)
            if not doc.get("title"):
                continue
            key = doc.get("dedup_key") or self._finding_key_from_doc(doc)
            doc["dedup_key"] = key
            merged[key] = self._apply_pipeline_status(doc)
        for doc in self._read_live_findings():
            if not isinstance(doc, dict) or not doc.get("title"):
                continue
            key = doc.get("dedup_key") or self._finding_key_from_doc(doc)
            doc["dedup_key"] = key
            merged.setdefault(key, self._apply_pipeline_status(doc))
        return list(merged.values())

    def _write_findings_snapshot_from_live(self, live_candidates: list[dict]) -> None:
        eng = self._engagement_dir()
        if eng is None:
            return
        path = eng / "findings.json"
        try:
            import json as _json
            doc = _json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        except (OSError, ValueError):
            doc = {}
        doc.setdefault("program", self.scope.program)
        doc["updated"] = __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime())
        doc.setdefault("confirmed_criticals", [])
        doc.setdefault("needs_human_review", [])
        existing = doc.get("candidates", []) if isinstance(doc.get("candidates"), list) else []
        merged: dict[str, dict] = {}
        for cand in [*existing, *live_candidates]:
            if not isinstance(cand, dict):
                continue
            key = cand.get("dedup_key") or self._finding_key_from_doc(cand)
            cand["dedup_key"] = key
            merged[key] = self._apply_pipeline_status(cand)
        doc["candidates"] = list(merged.values())
        doc["counts"] = {
            "confirmed_critical": len(doc.get("confirmed_criticals") or []),
            "needs_human_review": len(doc.get("needs_human_review") or []),
            "candidates": len(doc["candidates"]),
        }
        self._write_json_atomic(path, doc)

    def _candidate_key_doc(self, item) -> tuple[str, dict]:
        doc = self._candidate_doc(item)
        key = str(doc.get("dedup_key") or self._finding_key_from_doc(doc))
        doc["dedup_key"] = key
        return key, doc

    def _record_candidate_status(self, item, *, stage: str, status: str,
                                 next_action: str = "", blocked_by: str = "",
                                 reason: str = "", target_agent: str = "parent_a") -> str:
        """Parent-A-owned state machine for one candidate's promotion path."""
        import time as _time

        key, doc = self._candidate_key_doc(item)
        rec = dict(self._candidate_status.get(key) or {})
        history = list(rec.get("history") or [])
        entry = {
            "ts": _time.time(),
            "stage": stage,
            "status": status,
            "agent": self.name,
            "target_agent": target_agent,
            "next_action": next_action,
            "blocked_by": blocked_by,
            "reason": reason[:500],
        }
        history.append(entry)
        rec.update({
            "dedup_key": key,
            "title": doc.get("title", ""),
            "severity": doc.get("severity", ""),
            "location": doc.get("location") or doc.get("file", ""),
            "stage": stage,
            "status": status,
            "agent": self.name,
            "target_agent": target_agent,
            "next_action": next_action,
            "blocked_by": blocked_by,
            "reason": reason[:500],
            "updated_ts": entry["ts"],
            "history": history[-12:],
        })
        self._candidate_status[key] = rec
        self._emit(self.name, "lifecycle", {
            "event": "candidate_status",
            "dedup_key": key,
            "title": rec["title"],
            "severity": rec["severity"],
            "stage": stage,
            "status": status,
            "target_agent": target_agent,
            "next_action": next_action,
            "blocked_by": blocked_by,
            "reason": reason[:240],
        })
        return key

    def _parent_intervene(self, item, *, target_agent: str, directive: str,
                          reason: str, blocked_by: str = "") -> None:
        """Parent A explicitly tells the next service what to do with a stalled/high-value lead."""
        key = self._record_candidate_status(
            item,
            stage="parent_a",
            status="intervened",
            target_agent=target_agent,
            next_action=directive,
            blocked_by=blocked_by,
            reason=reason,
        )
        note = f"[{key}] {directive}"
        self._agent_directives.setdefault(target_agent, []).insert(0, note)
        self._emit(self.name, "message", {
            "phase": "intervention",
            "to": target_agent,
            "title": self._candidate_doc(item).get("title", ""),
            "dedup_key": key,
            "blocked_by": blocked_by,
            "reason": reason[:240],
            "directive": directive,
        })

    def _mark_fastlane_pending(self, item, *, cut_discovery: bool) -> None:
        """Show that Parent A has seen a hot blackboard lead before the round ends."""
        pipe = self._pipeline_for(item)
        current = str(pipe.get("status") or "").strip().lower()
        if current and current not in {
            "posted",
            "live_candidate",
            "candidate",
            "selected_for_verification",
            "fastlane_pending_verification",
        }:
            return
        self._record_candidate_status(
            item,
            stage="VERIFY",
            status="selected_for_verification" if cut_discovery else "fastlane_pending_verification",
            target_agent="falsifier",
            next_action=(
                "Child discovery was cut short; verify, materialize proof, then deep-dive."
                if cut_discovery else
                "Queued for verifier/proof at round close; child discovery is still running."
            ),
            blocked_by="" if cut_discovery else "round_in_progress",
            reason="high/critical blackboard post observed by live fastlane",
        )

    def _pipeline_for(self, item) -> dict:
        key, _doc = self._candidate_key_doc(item)
        return dict(self._candidate_status.get(key) or {})

    def _apply_pipeline_status(self, doc: dict) -> dict:
        key = str(doc.get("dedup_key") or self._finding_key_from_doc(doc))
        status = self._pipeline_status_for_doc(key, doc)
        if status:
            doc["pipeline"] = {
                k: v for k, v in status.items()
                if k in ("stage", "status", "target_agent", "next_action", "blocked_by",
                         "agent", "reason", "updated_ts", "history")
            }
        return doc

    def _matches_triage(self, item, triage: dict) -> bool:
        key, doc = self._candidate_key_doc(item)
        wanted_key = str(triage.get("finding_key") or "").strip()
        wanted_title = str(triage.get("title") or "").strip().lower()
        title = str(doc.get("title") or "").lower()
        return bool((wanted_key and wanted_key == key)
                    or (wanted_title and (wanted_title == title or wanted_title in title)))

    def _is_operator_priority(self, item) -> bool:
        return any(self._matches_triage(item, t) for t in self._operator_triage)

    def _operator_notes_for(self, agent: str, item=None) -> str:
        notes = list(self._agent_directives.get(agent, []) or [])
        notes += list(self._agent_directives.get("*", []) or [])
        if item is not None:
            for t in self._operator_triage:
                if self._matches_triage(item, t):
                    msg = str(t.get("message") or "").strip()
                    action = str(t.get("action") or "").strip()
                    notes.insert(0, f"Operator triage: {action or 'prioritize this finding now'}"
                                    + (f". Note: {msg}" if msg else ""))
        if not notes:
            return ""
        return "\n".join(f"- {n}" for n in notes[:8])

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
                from .claude_session import make_session
                prompt = (
                    f"You are Parent A, lead of an autonomous security hunt. The swarm produced NO "
                    f"activity for {int(idle)} seconds — it stalled (a hunter session hung, or the "
                    f"model API is rate-limited). I have cancelled the stuck round. In one or two "
                    f"sentences write a CORRECTIVE directive for the hunters' next round to avoid the "
                    f"stall — e.g. be decisive, write a small PoC and RUN it instead of reading "
                    f"endlessly, delegate big reads to sub-agents, don't spiral. Return ONLY JSON: "
                    f'{{"rate_limited": true|false, "diagnosis": "...", "notice": "<the directive>"}}')
                sess = make_session(agent_name=self.name, model=self.config.models.orchestrator,
                                     on_event=self._emit, guard_check=None, max_turns=3,
                                     engine=self.config.models.engine,
                                     effort=self.config.models.codex_effort,
                                     codex_model=self.config.models.codex_model,
                                     allow_web=False,
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

    def _finding_key(self, f) -> str:
        """A STABLE identity for a finding across rounds (title + file), so debate verdicts persist
        even when the finding is re-discovered with a fresh ephemeral id."""
        loc = getattr(f, "file", "") or getattr(getattr(f, "poc", None), "path", "") or ""
        return f"{(getattr(f, 'title', '') or '').strip().lower()[:140]}|{loc}"

    def _lead_attempts(self, key: str) -> int:
        return len(self._lead_log.get(key, {}).get("attempts", []))

    def _lead_status(self, key: str) -> str:
        return self._lead_log.get(key, {}).get("status", "open")

    def _lead_open(self, key: str) -> bool:
        """True if this lead should still be PURSUED — not proven, not exhausted, not over the
        attempt cap. This is what makes the engine tenacious instead of one-and-done."""
        if key in self._exploit_proven:
            return False
        if self._lead_status(key) in ("proven", "exhausted", "maxed"):
            return False
        return self._lead_attempts(key) < self._lead_max_attempts

    def _harvest_exploit_tasks(self) -> None:
        """Surface failed background exploit tasks and clear completed task handles."""
        for key, task in list(self._exploit_tasks.items()):
            if not task.done():
                continue
            self._exploit_tasks.pop(key, None)
            try:
                task.result()
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                self._emit(
                    self.name,
                    "lifecycle",
                    {"event": "exploit_background_error", "key": key, "detail": str(exc)[:200]},
                )

    async def _cancel_exploit_tasks(self) -> None:
        """Cancel exploit-depth tasks on shutdown so no agent lane survives the hunt."""
        tasks = [task for task in self._exploit_tasks.values() if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._exploit_tasks.clear()

    async def _cancel_fuzz_tasks(self) -> None:
        """Cancel non-blocking fuzz campaigns on shutdown."""
        tasks = [task for task in self._fuzz_tasks.values() if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._fuzz_tasks.clear()

    def _record_lead_attempt(self, key: str, verdict: dict | None) -> str:
        """Log one failed attempt and decide the lead's next state: 'exhausted' (rigorous
        impossibility -> stop), 'maxed' (hit the attempt cap -> park as needs_human), or 'open'
        (keep pursuing next round with a fresh angle). Returns the new status."""
        rec = self._lead_log.setdefault(key, {"attempts": [], "status": "open"})
        v = verdict or {}
        rec["attempts"].append({
            "strategy": str(v.get("strategy", "") or "attempt")[:200],
            "why_failed": str(v.get("why_failed", "") or v.get("impossibility", "")
                              or v.get("evidence", ""))[:300],
        })
        if v.get("exhausted"):
            rec["status"] = "exhausted"
        elif len(rec["attempts"]) >= self._lead_max_attempts:
            rec["status"] = "maxed"
        else:
            rec["status"] = "open"
        return rec["status"]

    def _rubric_priority_terms(self) -> set[str]:
        """Program-derived terms that describe what this engagement pays as serious impact.

        The exploit-depth queue used to contain crypto-specific keywords. That made one target class
        better served than others and violated the spec's "nothing preset" rule. This derives terms
        from the captured severity taxonomy and scope text for the current program instead.
        """
        import re as _re

        taxonomy = getattr(self.scope, "severity_taxonomy", {}) or {}
        parts: list[str] = []
        if isinstance(taxonomy, dict):
            for k, v in taxonomy.items():
                parts.append(str(k))
                parts.append(str(v))
        parts.append(str(getattr(self.scope, "scope_note", "") or ""))
        parts.append(str(getattr(self.scope, "safe_harbor_text", "") or ""))
        text = " ".join(parts).lower()
        stop = {
            "about", "above", "after", "against", "also", "attack", "attacker", "before",
            "being", "below", "between", "could", "from", "have", "into", "less", "more",
            "only", "other", "program", "scope", "severity", "than", "that", "their", "this",
            "through", "triggering", "under", "without", "with", "would",
        }
        terms: set[str] = set()
        for tok in _re.findall(r"[a-z][a-z0-9_-]{3,}", text):
            tok = tok.strip("_-")
            if len(tok) < 4 or tok in stop or tok.isdigit():
                continue
            terms.add(tok)
            if len(terms) >= 80:
                break
        return terms

    def _candidate_priority_text(self, f) -> str:
        vals: list[str] = []
        for attr in (
            "title", "severity", "root_cause", "counterfactual", "reproduction",
            "remediation", "severity_rationale", "confidence", "lens", "file",
        ):
            vals.append(str(getattr(f, attr, "") or ""))
        poc = getattr(f, "poc", None)
        if poc is not None:
            vals.append(str(getattr(poc, "description", "") or ""))
            vals.append(str(getattr(poc, "path", "") or ""))
        return " ".join(vals).lower()

    def _rubric_lead_score(self, f, terms: set[str] | None = None) -> float:
        """Rank leads for scarce exploit-depth time using engagement-derived rubric signals."""
        terms = terms if terms is not None else self._rubric_priority_terms()
        text = self._candidate_priority_text(f)
        sev = str(getattr(f, "severity", "") or "").lower()
        score = {"critical": 8.0, "high": 5.0, "medium": 2.0}.get(sev, 0.5)
        if getattr(f, "verified", False):
            score += 1.5
        if str(getattr(f, "counterfactual", "") or "").strip():
            score += 1.0
        matches = [t for t in terms if t and t in text]
        score += min(12.0, 2.0 * len(matches))
        return score

    def _confirmed_crits(self, findings) -> list:
        """The findings that count as CONFIRMED CRITICALS — the single source of truth, enforcing the
        debate gate. A critical qualifies ONLY if: (a) debate did not reject it, (b) it isn't
        debate-downgraded below critical, and (c) when the debate panel is enabled, debate UPHELD it.
        Pending-debate criticals are intentionally NOT confirmed yet (they confirm once upheld)."""
        gate = bool(self._debate_max) and self.config.use_claude
        deepdive = self._deepdive_on and self.config.use_claude
        out = []
        for f in findings:
            key = self._finding_key(f)
            if key in self._debate_rejected:
                continue
            sev = self._debate_downgraded.get(key, getattr(f, "severity", ""))
            if sev != "critical":
                continue
            if deepdive:
                # GOLD STANDARD: a critical is confirmed ONLY if the exploit-development phase
                # demonstrated the attacker-win in shipped code. A primitive is not a critical.
                if key not in self._exploit_proven:
                    continue
            elif gate and key not in self._debate_upheld:
                continue  # no deep-dive: fall back to the debate gate
            out.append(f)
        return out

    def _write_findings_json(self, findings, candidates, needs_human=None) -> None:
        """Persist the current findings to ``findings.json`` in the engagement folder. Called at
        every round boundary (so it's always fresh) and on stop/cap — when the scan is stopped,
        the latest findings are already on disk. ``needs_human`` is kept as the compatibility field
        name for the prominent autonomous-follow-up tier: believed-real, high-confidence P1s that
        could not be auto-reproduced yet (surfaced and kept in the bot pipeline, not buried)."""
        import json as _json
        import time as _time
        from pathlib import Path

        path = getattr(self.log, "path", None)
        if path is None:
            return
        out = Path(path).with_name("findings.json")
        crits = self._confirmed_crits(findings)  # debate-gated: only criticals that survived the panel
        nh = needs_human or []

        def _finding_doc(f, *, human: bool = False) -> dict:
            poc = getattr(f, "poc", None)
            loc = getattr(poc, "path", "") if poc is not None else getattr(f, "file", "")
            doc = {
                "title": getattr(f, "title", ""),
                "severity": getattr(f, "severity", ""),
                "verified": getattr(f, "verified", not human),
                "location": loc,
                "root_cause": getattr(f, "root_cause", ""),
                "counterfactual": getattr(f, "counterfactual", ""),
                "remediation": getattr(f, "remediation", ""),
            }
            if human:
                doc["why_unproven"] = getattr(poc, "description", "") if poc is not None else ""
            doc["dedup_key"] = self._finding_key_from_doc(doc)
            return self._apply_pipeline_status(doc)

        candidate_docs = self._merge_live_candidates(candidates)
        doc = {
            "program": self.scope.program,
            "updated": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
            "counts": {"confirmed_critical": len(crits), "needs_human_review": len(nh),
                       "candidates": len(candidate_docs)},
            "confirmed_criticals": [_finding_doc(f) for f in crits],
            # Reasoned P1s the autonomous pipeline should keep attacking FIRST — strong reasoning,
            # only the mechanical proof is missing. Listed prominently above the raw candidate dump.
            "needs_human_review": [_finding_doc(f, human=True) for f in nh],
            "candidates": candidate_docs,
        }
        try:
            out.write_text(_json.dumps(doc, indent=2, default=str), encoding="utf-8")
            for f in [*doc["confirmed_criticals"], *doc["needs_human_review"], *doc["candidates"]]:
                self._write_artifact_pack(f)
            self._emit(self.name, "lifecycle",
                       {"event": "findings_written", "path": str(out), "criticals": len(crits),
                        "needs_human_review": len(nh), "candidates": len(candidate_docs)})
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
            "known_patterns": [],
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

    def _resteer_prompt(
        self,
        digest: list[dict],
        depth: int,
        critical_means: str,
        crit_count: int,
        notices: list[str] | None = None,
    ) -> str:
        import json as _json

        notice_text = (
            "\n\nOPERATOR / RUNTIME NOTICES TO HONOR IN THIS RESTEER:\n- "
            + "\n- ".join([str(n) for n in (notices or [])[-8:]])
            if notices else ""
        )
        return (
            f"You are Parent A running a COVERAGE + NOVELTY review between rounds. Round {depth} finished. "
            f"'Critical' for this target = {critical_means}. Confirmed criticals so far: {crit_count}.\n\n"
            f"Per-track state (findings this round + what each ruled out):\n{_json.dumps(digest, indent=2)}\n\n"
            "The failure mode after many rounds is REPETITION: tracks re-attacking the same components the "
            "same way, so the team keeps re-covering its own blind spots and never reaches a bug CLASS it "
            "hasn't tried. A real P1 almost always lives in an angle nobody has attacked yet. Your job is to "
            "MAXIMIZE COVERAGE and FORCE NOVELTY:\n"
            " 1. COVERAGE MAP: across ALL tracks, which security GUARANTEES / components / attack ANGLES have "
            "already been seriously attacked (and exhausted), and — the high-value part — which guarantees "
            "that components PROMISE has NOBODY tried to break yet? Derive the un-attacked guarantees.\n"
            " 2. For EACH track, steer it to an UN-ATTACKED guarantee or a FUNDAMENTALLY DIFFERENT angle than "
            "it and its peers have already used — do NOT let it repeat a frame already tried. Name the "
            "specific guarantee to break and why it's unexplored; abandon exhausted threads.\n"
            " 3. The goal is a NOVEL critical — steer AWAY from anything already found or ruled out, toward "
            "the unexplored. Re-deriving a known/obvious issue is not progress.\n"
            "You may read the code/tests to ground the steer.\n\n"
            f"{notice_text}\n\n"
            "Return ONLY JSON:\n"
            '{"directives": [{"track": <1-based index>, "directive": "<steer to an unexplored guarantee/angle, '
            '1-3 sentences>", "focus_files": ["optional","new","relative/paths"]}]}'
        )

    async def _resteer(self, hunters, per_hunter_findings, depth, critical_means, findings, guard) -> None:
        """Parent A synthesizes the round and personalizes each hunter's next-round prompt."""
        if not self.config.use_claude or not hunters:
            return
        from .claude_session import make_session

        self._drain_control()
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
        session = make_session(
            agent_name=self.name, model=self.config.models.orchestrator, on_event=self._emit,
            guard_check=self._guard_check(guard, self.name), max_turns=12,
            engine=self.config.models.engine,
            effort=self.config.models.codex_effort,
            codex_model=self.config.models.codex_model,
            perms=self._perms, egress_hosts=self._egress_hosts,
        )
        try:
            res = await session.run(
                self._resteer_prompt(digest, depth, critical_means, crit_count, list(self._notices)),
                self.repo_path,
            )
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
                self._paused = False
                self._emit(self.name, "lifecycle", {
                    "event": "stop",
                    "reason": str(d.get("message") or "operator requested stop")[:240],
                    "source": str(d.get("source") or "control"),
                })
                continue
            if d.get("kind") == "pause":
                self._paused = True
                self._emit(self.name, "lifecycle", {
                    "event": "pause",
                    "reason": str(d.get("message") or "operator requested pause")[:240],
                    "source": str(d.get("source") or "control"),
                })
                continue
            if d.get("kind") == "resume":
                self._paused = False
                self._emit(self.name, "lifecycle", {
                    "event": "resume",
                    "reason": str(d.get("message") or "operator requested resume")[:240],
                    "source": str(d.get("source") or "control"),
                })
                continue
            if d.get("kind") in ("reload", "hot_reload"):
                mods = [str(m).strip() for m in (d.get("modules") or []) if str(m).strip()]
                msg = str(d.get("message", "")).strip()
                try:
                    from ..runtime_reload import apply_runtime_reload

                    out = apply_runtime_reload(self, modules=mods or None)
                    self._emit(self.name, "lifecycle",
                               {"event": "runtime_reload", "status": "applied",
                                "modules": out.get("reloaded", [])[:20],
                                "rebound": out.get("rebound", [])[:20],
                                "refreshed": out.get("refreshed", [])[:20],
                                "skipped": out.get("skipped", {}),
                                "detail": out.get("limitations", "")[:500]})
                    self._notices.insert(
                        0,
                        "Runtime hot reload applied at round boundary: future role calls use refreshed "
                        "prompt/session/helper modules; main hunt-loop bytecode changes may still need resume.",
                    )
                    if msg:
                        self._notices.insert(0, msg)
                except Exception as exc:
                    self._emit(self.name, "lifecycle",
                               {"event": "runtime_reload", "status": "failed",
                                "detail": str(exc)[:500]})
                    if msg:
                        self._notices.insert(0, msg)
                continue
            if d.get("kind") == "triage":
                key = str(d.get("finding_key") or "").strip()
                title = str(d.get("title") or "").strip()
                msg = str(d.get("message") or "").strip()
                target_agent = str(d.get("target_agent") or "parent_a").strip() or "parent_a"
                source_agent = str(d.get("source_agent") or self.name).strip() or self.name
                action = str(d.get("action") or "prioritize verifier/prover/deep-dive now").strip()
                notice = (
                    "TRIAGE NOW: prioritize verifier/prover/deep-dive on "
                    + (f"finding key {key}" if key else f"finding '{title}'")
                    + (f". Operator note: {msg}" if msg else ".")
                )
                triage = {
                    "finding_key": key,
                    "title": title,
                    "message": msg,
                    "target_agent": target_agent,
                    "action": action,
                }
                self._operator_triage.append(triage)
                self._agent_directives.setdefault(target_agent, []).insert(0, notice + f" Action: {action}")
                self._notices.insert(0, notice)
                self._emit(source_agent, "message", {
                    "phase": "intervention",
                    "to": target_agent,
                    "title": title,
                    "dedup_key": key,
                    "reason": msg,
                    "directive": action,
                    "notice": notice,
                })
                continue
            msg = str(d.get("message", "")).strip()
            paths = [str(p).strip() for p in (d.get("paths") or []) if str(p).strip()]
            notice = msg + (f"  [new code now available at: {', '.join(paths)}]" if paths else "")
            if notice:
                self._notices.append(notice)
                self._emit(self.name, "message", {"phase": "notice", "notice": notice})

    async def _pause_gate(self, findings, all_candidates, needs_human) -> None:
        """Hold the swarm at a round boundary until a resume or stop directive arrives."""
        import asyncio as _asyncio
        import time as _t

        announced = False
        while self._paused and not self._safety_event:
            if not announced:
                self._write_findings_json(findings, all_candidates, needs_human)
                self._emit(self.name, "lifecycle", {
                    "event": "paused",
                    "reason": "operator pause active; waiting for resume or stop",
                })
                announced = True
            self._last_activity = _t.monotonic()
            await _asyncio.sleep(2.0)
            self._drain_control()

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

    # --- environment arming (build + fork + corpus) ----
    async def _arm_environment(self, tracks: list[dict]) -> None:
        """Before the first round: build the target so harnesses can run, start a local fork when
        configured, and open the persistent corpus. All steps are graceful — a missing toolchain/fork never
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

        # 1) NOTHING PRESET: invariants come only from Parent A's recon over this target.
        # No class/subclass invariant packs are injected. A track Parent A left
        # without invariants is hunted with the in-session "derive the invariants from the code
        # yourself" path the hunter/fuzzer prompts already instruct — never a generic floor.
        # Track invariants are populated by recon, not here.

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

        # No preset static leads are injected into hunters. Parent A must derive hunt tracks,
        # invariants, and hypotheses from the target during recon; deterministic scanners are not
        # allowed to front-run that reasoning with canned failure modes.
        self._scan_hits = []

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
        # callback-based behavior can be CONFIRMED. All graceful — any failure just narrows the run.
        if self._dynamic_armed:
            self._arm_dynamic()
            # The reasoning pass over the live surface. Awaited HERE because this is the
            # first async context after arming, and because every later mechanism wants
            # its output: the plan drives entrypoints, and it is handed to each hunter.
            await self._plan_live_attack()

        # 7) TOOLCHAIN CHECK (loud). The confirmed-critical gate can ONLY fire if the class's
        # reproduction toolchain is installed — without it EVERY finding is quarantined forever, no
        # matter how good the reasoning. Warn unmissably (and say how to fix) so this never fails silently.
        self._warn_if_no_repro_toolchain()

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
        # OOB interaction listener (loopback) for callback-based confirmation.
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
        # Ship the scope-enforced interaction modules into the PoC sandbox so a harness can
        # `import p1hunt_dyn` (HTTP) and `import p1hunt_browser` (a real browser).
        #
        # Each file is copied, not imported from the package: the harness runs as a separate
        # pytest process with no `p1hunt` on sys.path. browser.py falls back to a bare
        # `import htmlctx`, so htmlctx MUST land beside it under that exact name or the
        # browser module raises at import (it refuses to run without its analyzer).
        #
        # Reported per file. A single `shipped` bool hid which module was missing, and a
        # harness that cannot import the browser silently loses the whole DOM bug class.
        ship_report: dict[str, bool] = {}
        for mod_path, dest in (("..dynamic.client", "p1hunt_dyn.py"),
                               ("..dynamic.browser", "p1hunt_browser.py"),
                               ("..dynamic.htmlctx", "htmlctx.py"),
                               ("..dynamic.recon", "p1hunt_recon.py")):
            try:
                import importlib
                mod = importlib.import_module(mod_path, package=__package__)
                src = Path(mod.__file__).read_text(encoding="utf-8")
                (self.poc_dir / dest).write_text(src, encoding="utf-8")
                ship_report[dest] = True
            except Exception:
                ship_report[dest] = False
        shipped = ship_report.get("p1hunt_dyn.py", False)
        # DERIVE THE SURFACE FROM THE LIVE TARGET. Bounded, read-only, and entirely
        # optional: a failure here degrades to the repo-derived surface (empty for a
        # black-box target) rather than stopping the hunt. It runs once at arm time
        # because every later mechanism -- coverage steering, the ledger, escalation --
        # needs something concrete to work on.
        self._live_surface = None
        if self._base_url and (self._egress_hosts or []):
            try:
                pages = int(os.environ.get("P1HUNT_RECON_PAGES", "10") or 10)
                scripts = int(os.environ.get("P1HUNT_RECON_SCRIPTS", "20") or 20)
                # OFF THE EVENT LOOP THREAD. Playwright's SYNC api refuses to start when
                # an asyncio loop is running in the calling thread ("It looks like you are
                # using Playwright Sync API inside the asyncio loop"). This method is
                # synchronous, but it is CALLED from async code, so a loop IS running here
                # -- and the direct `with Browser(...)` therefore threw on EVERY live hunt
                # and was swallowed by the degrade-gracefully handler below.
                #
                # The consequence was total and silent: self._live_surface was always None
                # in the product, the planner got no facts to reason over, and black-box
                # discovery -- the whole point of the browser and the recon miner -- never
                # happened at all. It passed its own tests because those call discover()
                # from a sync context, and so does bench/run_range.py, which is why the
                # measured planning numbers were real while the product got nothing.
                #
                # A plain worker thread, not asyncio.to_thread: there is no `await`
                # available in a sync method. A fresh thread has no loop of its own, which
                # is exactly what the sync api needs, and the timeout keeps a slow crawl
                # from stalling every agent queued behind arming.
                import concurrent.futures as _cf

                with _cf.ThreadPoolExecutor(max_workers=1) as _pool:
                    self._live_surface = _pool.submit(
                        self._discover_live_surface, max(1, pages), max(0, scripts)
                    ).result(timeout=_env_float("P1HUNT_RECON_TIMEOUT", 300.0, minimum=10.0))
            except Exception as exc:
                self._live_surface = None
                self._emit(self.name, "lifecycle",
                           {"event": "live_recon_failed", "error": str(exc)[:300]})
        surf = self._live_surface or {}
        idents = [i.name for i in self.scope.test_identities if i.resolve()]
        self._emit(self.name, "lifecycle",
                   {"event": "dynamic_armed", "base_url": self._base_url,
                    "recon_endpoints": len(surf.get("endpoints") or []),
                    "recon_hosts": len(surf.get("hosts") or []),
                    "recon_graphql": len(surf.get("graphql") or []),
                    "egress": list(self._egress_hosts or []), "identities": idents,
                    "oob": bool(self._oob), "client_shipped": shipped,
                    "shipped": dict(ship_report),
                    "browser_shipped": ship_report.get("p1hunt_browser.py", False)
                                       and ship_report.get("htmlctx.py", False)})

    def _discover_live_surface(self, pages: int, scripts: int) -> dict:
        """Crawl the authorized base URL and mine its surface. SYNCHRONOUS on purpose.

        Must be called off the event loop (see the to_thread call in _arm_dynamic):
        Playwright's sync api raises if a loop is running in the calling thread.
        """
        from ..dynamic.browser import Browser
        from ..dynamic.recon import discover

        with Browser(allowlist=list(self._egress_hosts or []),
                     base_url=self._base_url) as browser:
            return discover(browser, [self._base_url], max_pages=pages, max_scripts=scripts)

    async def _plan_live_attack(self) -> None:
        """Ask the engine what to attack on THIS target, given the live surface.

        This is the judgement step, and it is deliberately a model call rather than a
        scoring table: the comparisons that produce criticals (serve one resource to two
        hosts and diff; remove a precondition; skip a step) are not enumerable in
        advance, so a keyword list ceilings the hunt at whatever its author listed.

        Entirely optional. No surface, no engine, or an unparseable reply all degrade to
        "no plan" and the hunt proceeds on the derived surface alone -- it never falls
        back to a heuristic dressed up as reasoning, and it never blocks the run.
        """
        self._live_plan = []
        self._live_entrypoints = []
        surface = getattr(self, "_live_surface", None)
        if not surface or not (surface.get("endpoints") or surface.get("hosts")):
            return
        try:
            from ..dynamic import triage as _triage

            # What the ledger has already RULED OUT, so the planner does not re-spend
            # effort on it. Each line carries the mechanism that closed it, because
            # "refuted" without a reason invites the same idea back in new words.
            ruled_out: list[str] = []
            ledger = getattr(self, "ledger", None)
            if ledger is not None:
                try:
                    from ..ledger import OUTCOME_FALSIFIED

                    for rec in ledger.records():
                        if rec.outcome != OUTCOME_FALSIFIED:
                            continue
                        line = rec.hypothesis
                        if rec.mechanism:
                            line += f"  [closed by: {rec.mechanism}]"
                        ruled_out.append(line[:300])
                        if len(ruled_out) >= 40:
                            break
                except Exception:
                    ruled_out = []
            idents = [i.name for i in self.scope.test_identities if i.resolve()]
            # Reasoning tier: the falsifier/orchestrator model, not the worker tier.
            session = self._make_planning_session()
            out = await _triage.triage(
                surface, session=session, cwd=self.repo_path or ".",
                target_name=self._base_url or "",
                scope_note=self._scope_note_for_plan(),
                ruled_out=ruled_out, identities=idents,
            )
            self._live_plan = out.get("plan") or []
            if self._live_plan:
                self._live_entrypoints = _triage.plan_to_entrypoints(self._live_plan)
            self._emit(self.name, "lifecycle",
                       {"event": "live_plan", "ok": bool(out.get("ok")),
                        "hypotheses": len(self._live_plan),
                        "reason": out.get("reason", ""),
                        "error": (out.get("error") or "")[:300],
                        "targets": [h.get("target", "")[:120] for h in self._live_plan[:10]]})
            # A PROVIDER-SIDE REFUSAL is not an empty plan. It means the reasoning layer
            # is dead for this run while everything else still appears to work, so the
            # run would quietly fall back to the derived surface and look healthy. Shout.
            if out.get("reason") == _triage.REASON_REFUSED:
                self._emit(self.name, "lifecycle", {
                    "event": "live_plan_refused", "severity": "HIGH",
                    "impact": "the REASONING layer produced nothing: the hunt is running on the "
                              "derived surface alone, with no model-authored hypotheses, so the "
                              "classes that require a comparison nobody listed will not be "
                              "attempted",
                    "detail": (out.get("error") or "")[:300],
                    "fix": "the provider's safety classifier refused the planning request. "
                           "Confirm the engagement is authorized, then re-run; if it persists, "
                           "switch engine (P1HUNT_ENGINE=claude) or model "
                           "(P1HUNT_CODEX_MODEL) -- do NOT interpret the empty plan as "
                           "'no bugs here'",
                })
        except Exception as exc:
            self._live_plan = []
            self._live_entrypoints = []
            self._emit(self.name, "lifecycle",
                       {"event": "live_plan_failed", "error": str(exc)[:300]})

    def _make_planning_session(self):
        """A session on the REASONING tier for the planning pass."""
        from .claude_session import make_session

        m = self.config.models
        return make_session(model=m.falsifier or m.orchestrator,
                            engine=m.engine, effort=m.codex_effort,
                            codex_model=m.codex_model,
                            agent_name=f"{self.name}:planner",
                            on_event=self._emit)

    def _scope_note_for_plan(self) -> str:
        """The rules of engagement, stated to the planner so it cannot plan out of scope."""
        hosts = ", ".join(self._egress_hosts or []) or "(none authorized)"
        return (f"Authorized hosts ONLY: {hosts}. Every instrument enforces this and a request "
                f"elsewhere raises. Do not plan anything destructive, any denial of service, or "
                f"any action against a third party. Non-production target.")

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
        """Cached external/public entrypoints for a subsystem (the real attack surface).

        CLASS-AGNOSTIC: EVM still resolves to Solidity signature enumeration (unchanged, it is
        delegated to detect_evm_entrypoints); web/API and every other class now resolve to real
        routes/operations instead of []. A NON-EMPTY result here is what lets rounds COMPOUND --
        it feeds CorpusStore.uncovered_hint, so round N+1 is steered at what round N never
        reached. Drives both the harness scaffold and coverage steering."""
        if subsystem not in self._entrypoints_by_subsystem:
            try:
                from .surface_enum import entrypoints_for

                # live_surface is what keeps a BLACK-BOX target from resolving to [].
                # A bounty target has no repository, so every repo-derived source is
                # empty and the coverage loop has nothing to compound on. A surface
                # derived from the running target arrives in the same shape.
                # Order of trust: a REASONED plan over this target, then the surface
                # derived from it, then the repository. live_surface is what keeps a
                # black-box target from resolving to [] at all.
                planned = list(getattr(self, "_live_entrypoints", None) or [])
                if planned:
                    self._entrypoints_by_subsystem[subsystem] = planned
                else:
                    self._entrypoints_by_subsystem[subsystem] = entrypoints_for(
                        self._target_class, self.repo_path, focus_files,
                        live_surface=getattr(self, "_live_surface", None),
                    )
            except Exception:
                self._entrypoints_by_subsystem[subsystem] = []
        return self._entrypoints_by_subsystem[subsystem]

    def _hunter_base_turns(self) -> int:
        """Base per-round turn budget for a hunter (P1HUNT_HUNTER_TURNS). Adaptive budget scales
        promising tracks UP from this and lets exhausted ones fall back to it (see hunt loop)."""
        # Deep-discovery raises the floor so a hunter can sustain a long, compounding investigation
        # within a round (its accumulated `model` already carries across rounds). Env always wins.
        _default = 80 if self._deep_discovery else 28
        return _env_int("P1HUNT_HUNTER_TURNS", _default, minimum=8)

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
        if self._dynamic_armed and self._base_url:
            lines.append(
                f"LIVE TARGET ARMED (authorized): an authorized instance is reachable at "
                f"{self._base_url} with credentials in the environment. A scope-enforced client is "
                "shipped at ./.p1hunt-poc/p1hunt_dyn.py (from p1hunt_dyn import Client) — it confines "
                "every request to the in-scope host(s); contacting anything else raises. Use real "
                "requests to PROVE the bug; only contact the authorized host and loopback.")
            lines.append(
                "A REAL BROWSER is shipped too, at ./.p1hunt-poc/p1hunt_browser.py (with "
                "htmlctx.py beside it): from p1hunt_browser import Browser. Use it when the target "
                "renders HTML — the HTTP client cannot execute JavaScript, so without it a "
                "single-page app's rendered output, its DOM sinks and its client-side routes are "
                "invisible. It is jailed at the same chokepoint, subresources included.")
        # A plan DERIVED FROM THIS TARGET, not a preset recipe. The no-preset rule above
        # exists so a hunter is never handed someone's generic attack template and stops
        # thinking; this is the opposite — it is the output of a reasoning pass over the
        # live surface of the target in front of it, it is explicitly labelled a starting
        # point the hunter may discard, and each item states what would refute it.
        plan = list(getattr(self, "_live_plan", None) or [])
        if plan:
            try:
                from .harness_scaffold import plan_note

                note = plan_note(plan)
                if note:
                    lines.append(note)
            except Exception:
                pass
        return "\n\n".join(lines)

    def _static_leads_for(self, focus_files: list[str]) -> list[str]:
        """Preset-free mode: static scanner hits are never injected as hunter leads."""
        return []

    def _parent_recon_brief(self, scope_plan: dict | None) -> str:
        """Compact Parent-A-owned baseline for live web children.

        Parent A owns the boring but essential web facts: authorized targets, reachability,
        observed statuses/errors, scope limits, crown jewels, and top hypothesis. Children should
        attack from this shared model instead of rediscovering basic transport state on every track.
        """
        if not isinstance(scope_plan, dict):
            return ""
        parts: list[str] = []
        summary = str(scope_plan.get("summary", "") or "").strip()
        if summary:
            parts.append("Parent A baseline summary: " + summary[:1200])
        critical = str(scope_plan.get("critical_means", "") or "").strip()
        if critical:
            parts.append("Critical bar: " + critical[:700])
        for label, key, limit in (
            ("Crown jewels", "crown_jewels", 5),
            ("Attack surface", "attack_surface", 8),
        ):
            vals = [str(x).strip() for x in (scope_plan.get(key) or []) if str(x).strip()][:limit]
            if vals:
                parts.append(label + ": " + " | ".join(vals)[:1600])
        hyp = str(scope_plan.get("top_hypothesis", "") or "").strip()
        if hyp:
            parts.append("Parent A top hypothesis: " + hyp[:700])
        return "\n".join(parts)[:5000]

    def _live_web_recon_blocker(self, scope_plan: dict | None) -> str:
        """Return a blocker when a live-web run has no actionable surface to hand to children.

        Exact live targets that only time out are not a security hypothesis. If Parent A found no
        HTTP response, no app/API/auth URL, no credentials, and no trusted-origin/fetch primitive,
        spawning children just burns turns re-measuring transport. This gate is deliberately
        evidence-based and generic: any observed response or concrete app surface keeps the run open.
        """
        if not self._has_live_web_targets() or not isinstance(scope_plan, dict):
            return ""
        import re

        fields: list[str] = []
        for key in ("summary", "threat_model", "critical_means", "top_hypothesis", "target_subclass"):
            fields.append(str(scope_plan.get(key, "") or ""))
        for key in ("crown_jewels", "attack_surface"):
            fields.extend(str(x) for x in (scope_plan.get(key) or []))
        for tr in (scope_plan.get("tracks") or []):
            if isinstance(tr, dict):
                fields.extend(str(x) for x in (tr.get("investigate") or []))
                fields.extend(str(x) for x in (tr.get("focus_files") or []))
        text = "\n".join(fields).lower()
        if not text.strip():
            return ""

        has_transport_blocker = any(
            marker in text
            for marker in (
                "timed out", "timeout", "connect timeout", "connection timed", "no http status",
                "no status/headers/body", "no http response", "transport blocker",
            )
        )
        observed_response = bool(re.search(r"\bstatus\s*[=: ]\s*[1-5]\d\d\b", text) or "http/1." in text)
        concrete_surface = any(
            marker in text
            for marker in (
                "accepts attacker url", "accepts attacker-controlled url", "attacker-controlled url",
                "exposes an import", "webhook", "url-fetch", "server-side fetch", "callback endpoint",
                "posted url", "url parameter", "import endpoint",
            )
        )
        missing_surface = any(
            marker in text
            for marker in (
                "no concrete app", "no concrete web", "no tenant/app url", "not observed/provided",
                "not observed in authorized", "no p1hunt_token", "no identities", "no token",
                "no reachable", "missing in-scope", "absent concrete app",
            )
        )
        if has_transport_blocker and not observed_response and not concrete_surface and missing_surface:
            return (
                "live web transport/vantage blocker: Parent A observed only timeout/no-response "
                "behavior and no concrete in-scope app/API/auth/fetch primitive to compose into a P1. "
                "Provide a reachable in-scope app URL, authorized test identity, or routed vantage."
            )
        return ""

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

        import time as _t0mod
        self._hunt_t0 = _t0mod.monotonic()  # hunt start, for the UI status panel's true uptime
        # SETTINGS SNAPSHOT for the UI: the operative knobs in one event the cockpit can render.
        m = self.config.models
        if m.engine == "codex":
            codex_desc = f"codex:{m.codex_model or 'default'}/{m.codex_effort}"
            model_map = {
                "orchestrator": codex_desc,
                "worker": codex_desc,
                "falsifier": codex_desc,
                "poc_prover": codex_desc,
                "exploit_dev": codex_desc,
                "fuzzer": codex_desc,
                "debate": codex_desc,
                "dedup": codex_desc,
            }
        else:
            model_map = {"orchestrator": m.orchestrator,
                         "worker": m.worker,
                         "falsifier": m.falsifier,
                         "poc_prover": m.falsifier,
                         "exploit_dev": m.falsifier,
                         "fuzzer": m.falsifier,
                         "debate": m.falsifier,
                         "dedup": m.warm_pool}
        self._emit(self.name, "lifecycle", {
            "event": "settings", "program": self.scope.program, "target_class": self._target_class,
            "max_criticals": self._max_criticals, "max_rounds": max_rounds,
            "dedup": self._dedup_on, "debate_max": self._debate_max,
            "deepdive": self._deepdive_on, "deepdive_top_n": self._deepdive_top_n,
            "deepdive_turns": self._deepdive_turns, "lead_max_attempts": self._lead_max_attempts,
            "deep_discovery": self._deep_discovery,
            "no_model_downgrade": os.environ.get("P1HUNT_NO_MODEL_DOWNGRADE", "0") == "1",
            "run_mode": self.config.run_mode, "cost_cap_usd": self._cost_cap,
            "engine": m.engine, "discovery_engine": m.discovery_engine,
            "role_routing": "all_roles" if m.engine == "codex" else "legacy_claude",
            "models": model_map,
            "fuzz_campaigns": _env_int("P1HUNT_FUZZ_CAMPAIGNS", 1, minimum=0),
            "second_opinion": os.environ.get("P1HUNT_SECOND_OPINION") == "1",
            "recon_mode": self._recon_mode(),
            "recon_turns": _env_int("P1HUNT_RECON_TURNS", 45, minimum=20)})

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
            self._dynamic_armed = True
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
            scope_plan = None
            if resume:
                critical_means = resume.get("critical_means") or plan.impact_definition
                tracks = (resume.get("tracks") or self._fallback_tracks())[:6]
                self._known_patterns = []
                oracle_desc = str(resume.get("oracle_desc", "") or "")
                parent_recon_brief = ""
            else:
                # NOTHING PRESET (§1): Parent A performs COLD reconnaissance of the target and
                # DERIVES the subsystems/invariants/tracks itself from this source tree.
                scope_plan = await self._scope(guard)
                parent_recon_brief = self._parent_recon_brief(scope_plan)
                critical_means = scope_plan.get("critical_means") or plan.impact_definition
                tracks = (scope_plan.get("tracks") or self._fallback_tracks())[:6]
                self._known_patterns = []
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
                            "known_patterns": 0})

            # CAN A PROOF EVEN RUN? Asked once, before any model time is spent, because
            # `reproduced=True` from a class runner is the ONLY thing that promotes a
            # finding — so a broken toolchain is a hard ceiling of zero confirmed
            # findings while every other part of the run looks healthy.
            #
            # This is the same failure SHAPE as a provider-side refusal of the planning
            # brief, and it gets the same volume. It was found by a measurement run: a
            # stale pytest plugin on the author's own machine killed every harness before
            # collection, and the per-finding classification was correct and therefore
            # invisible (one broken harness looks like a bad harness, not a bad machine).
            await self._preflight_runner_toolchain()

            # Arm the environment ONCE before any round: BUILD the target (submodules + compile) so
            # harnesses can deploy it, start a local mainnet fork when configured, and open the
            # persistent corpus. Invariants are not injected here; Parent A derives them from code.
            await self._arm_environment(tracks)

            # One Child B per DERIVED track, plus verifier/prover/depth roles.
            # Scoped web (technique/spec only) is on with a hard per-session search budget so a
            # stuck hunter can't rabbit-hole into "<product> prior disclosures" (P1HUNT_WEB_BUDGET, 0=off).
            _web_budget = _env_int("P1HUNT_WEB_BUDGET", 5, minimum=0)
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
                h.egress_hosts = self._egress_hosts  # host jail (empty = unarmed: loopback/build only)
                h.poc_reldir = self.poc_reldir  # where forge can actually compile/run PoCs
                h.discovery_engine = self.config.models.discovery_engine
                h.codex_model = self.config.models.codex_model
                h.codex_effort = self.config.models.codex_effort
                # Live web-app pentest context (XBOW-style). web_mode flips the hunter to the
                # black-box HTTP methodology when an authorized live target is armed.
                h.web_mode = self._dynamic_armed
                h.base_urls = [getattr(t, "base_url", "") for t in (self.scope.dynamic_targets or [])]
                h.identities = [getattr(idn, "name", "") for idn in (getattr(self.scope, "test_identities", None) or [])]
                h.oob_available = self._oob is not None
                h.scope_note = (getattr(self.scope, "scope_note", "")
                                or getattr(self.scope, "safe_harbor_text", "") or "")
                if resume:  # restore this track's memory so it resumes at depth, not from scratch
                    h._ruled_out = list(tr.get("ruled_out", []) or [])
                    h._directive = str(tr.get("directive", "") or "")
                    h._model = str(tr.get("model", "") or "")  # restore the accumulated model (skips re-map)
                elif h.web_mode and parent_recon_brief:
                    h._model = parent_recon_brief
                    h._directive = (
                        "Start from Parent A's baseline model. Do not redo broad reachability, "
                        "route, or status probing unless your track needs one narrow confirmation. "
                        "Spend your turns on the track-specific attacker-win question."
                    )
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
                so.poc_reldir = self.poc_reldir
                so.discovery_engine = self.config.models.discovery_engine
                so.codex_model = self.config.models.codex_model
                so.codex_effort = self.config.models.codex_effort
                so.web_mode = self._dynamic_armed
                so.base_urls = [getattr(t, "base_url", "") for t in (self.scope.dynamic_targets or [])]
                so.identities = [getattr(idn, "name", "") for idn in (getattr(self.scope, "test_identities", None) or [])]
                so.oob_available = self._oob is not None
                so.scope_note = (getattr(self.scope, "scope_note", "")
                                 or getattr(self.scope, "safe_harbor_text", "") or "")
                if so.web_mode and parent_recon_brief:
                    so._model = parent_recon_brief
                    so._directive = (
                        "Start from Parent A's baseline model. Do not redo broad reachability, "
                        "route, or status probing unless one narrow confirmation is necessary."
                    )
                hunters.append(so)
                self._emit(self.name, "lifecycle",
                           {"event": "second_opinion", "subsystem": so.subsystem,
                            "detail": "independent hunter on the top subsystem (diversity)"})
            self._live_hunters = hunters
            self.bus.register("falsifier", "falsifier")
            verifier = ClaudeVerifier("falsifier", model=self.config.models.falsifier, on_event=self._emit,
                                      guard_check=self._guard_check(guard, "falsifier"))
            verifier.perms = self._perms
            verifier.egress_hosts = self._egress_hosts
            verifier.web_mode = self._dynamic_armed
            verifier.base_url = self._base_url
            verifier.poc_reldir = self.poc_reldir
            self._apply_role_engine(verifier)
            # The PoC prover runs ONLY after the Falsifier believes a finding is real (so we never
            # build a PoC for an intended/non-bug), and can REFUTE it if it won't actually reproduce.
            self.bus.register("poc_prover", "prover")
            prover = ClaudePoCProver("poc_prover", model=self.config.models.falsifier, on_event=self._emit,
                                     guard_check=self._guard_check(guard, "poc_prover"))
            prover.perms = self._perms
            prover.egress_hosts = self._egress_hosts
            prover.poc_reldir = self.poc_reldir
            self._apply_role_engine(prover)
            # EXPLOIT-DEVELOPMENT depth phase (strong model, large turn budget, sustained focus):
            # takes a believed primitive and builds the full attacker-WIN exploit, or proves it can't.
            self.bus.register("exploit_dev", "prover")
            developer = ClaudeExploitDeveloper("exploit_dev", model=self.config.models.falsifier,
                                               on_event=self._emit,
                                               guard_check=self._guard_check(guard, "exploit_dev"),
                                               max_turns=self._deepdive_turns)
            developer.perms = self._perms
            developer.egress_hosts = self._egress_hosts
            developer.poc_reldir = self.poc_reldir
            self._apply_role_engine(developer)
            # Dedup agent (cheap model — confirmation-gate de-duplication) and the debate panel
            # (strong model — round-end adversarial re-test of confirmed criticals).
            self.bus.register("dedup", "verifier")
            deduper = ClaudeDeduplicator("dedup", model=self.config.models.warm_pool, on_event=self._emit,
                                         guard_check=self._guard_check(guard, "dedup"))
            deduper.perms = self._perms
            deduper.egress_hosts = self._egress_hosts
            self._apply_role_engine(deduper)
            self.bus.register("debate", "verifier")
            debate = ClaudeDebate("debate", model=self.config.models.falsifier, on_event=self._emit,
                                  guard_check=self._guard_check(guard, "debate"))
            debate.perms = self._perms
            debate.egress_hosts = self._egress_hosts
            self._apply_role_engine(debate)

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
            _n_fuzz = _env_int("P1HUNT_FUZZ_CAMPAIGNS", 1, minimum=0)
            fuzz_assignments = self._fuzz_assignments(tracks, reference_hint, max_n=_n_fuzz)
            fuzzers: list[ClaudeFuzzer] = []
            for i, asn in enumerate(fuzz_assignments, start=1):
                fname = f"fuzzer_{i}"
                self.bus.register(fname, "fuzzer")
                _fz = ClaudeFuzzer(fname, model=self.config.models.falsifier, on_event=self._emit,
                                   guard_check=self._guard_check(guard, fname))
                _fz.perms = self._perms
                _fz.egress_hosts = self._egress_hosts
                _fz.poc_reldir = self.poc_reldir
                self._apply_role_engine(_fz)
                fuzzers.append(_fz)
                self._emit(self.name, "message",
                           {"to": fname, "kind": "assign",
                            "mode": "differential" if asn["differential"] else "invariant",
                            "subsystem": asn["subsystem"], "invariants": asn["invariants"][:4]})
            self._live_roles = {
                "verifier": verifier,
                "poc_prover": prover,
                "exploit_dev": developer,
                "dedup": deduper,
                "debate": debate,
                "fuzzers": fuzzers,
            }

            findings: list[Finding] = []
            all_candidates: list[ClaudeFinding] = []
            needs_human: list[Finding] = []  # believed-real, high-confidence, but not auto-reproduced
            seen: set[str] = set()
            prior_titles: list[str] = []
            start_depth = 0
            if not resume:
                blocker = self._live_web_recon_blocker(scope_plan)
                if blocker:
                    self._emit(self.name, "lifecycle", {
                        "event": "live_web_blocked",
                        "reason": blocker,
                        "next_action": "Provide a reachable in-scope app/API URL, authorized test identity, or routed vantage before relaunching.",
                    })
                    self._write_findings_json(findings, all_candidates, needs_human)
                    watchdog.cancel()
                    self._stop_fork()
                    return self._result(
                        EngagementStatus.BLOCKED_NEEDS_HUMAN_SCOPE_DECISION,
                        plan,
                        guard,
                        findings,
                        all_candidates,
                        0,
                        needs_human,
                    )
            if resume:  # restore the candidate set + dedup keys + round counter
                for cd in resume.get("candidates", []):
                    try:
                        all_candidates.append(ClaudeFinding(**cd))
                    except (TypeError, ValueError):
                        pass
                seen |= set(resume.get("seen", []))
                prior_titles = [c.title for c in all_candidates]
                start_depth = int(resume.get("depth", 0) or 0)

            def _ingest_background_candidates(cands: list[ClaudeFinding], *, source: str) -> None:
                for cf in cands:
                    key = f"{cf.file}:{cf.line}:{cf.title.lower()[:40]}"
                    if key in seen:
                        continue
                    seen.add(key)
                    all_candidates.append(cf)
                    prior_titles.append(cf.title)
                    self._record_hypothesis(cf)
                    self._record_candidate_status(
                        cf, stage=source, status="queued",
                        target_agent="parent_a",
                        next_action="Parent A will pick this up in the next verifier/proof pipeline pass.",
                        blocked_by="awaiting_parent_pipeline",
                        reason=f"reported by {source} background lane",
                    )

            depth = start_depth
            while True:
                depth += 1
                self._harvest_exploit_tasks()
                if max_rounds is not None and depth > max_rounds:
                    self._emit(self.name, "lifecycle", {"event": "cap_reached", "round": depth - 1})
                    self._write_findings_json(findings, all_candidates, needs_human)
                    watchdog.cancel()
                    self._stop_fork()
                    status = EngagementStatus.REPORT_READY if findings else EngagementStatus.RUNNING
                    return self._result(status, plan, guard, findings, all_candidates, depth - 1, needs_human)
                if self.bb.has_stop(self.name) or self._safety_event:
                    self._emit(self.name, "lifecycle", {"event": "stop", "reason": "operator/safety"})
                    self._write_findings_json(findings, all_candidates, needs_human)
                    watchdog.cancel()
                    self._stop_fork()
                    return self._result(EngagementStatus.STOPPED, plan, guard, findings, all_candidates, depth, needs_human)
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
                    return self._result(status, plan, guard, findings, all_candidates, depth - 1, needs_human)

                self._drain_control()  # pick up any `p1hunt notify` directives before this round
                if self.bb.has_stop(self.name) or self._safety_event:
                    self._emit(self.name, "lifecycle", {"event": "stop", "reason": "operator/safety"})
                    self._write_findings_json(findings, all_candidates, needs_human)
                    watchdog.cancel()
                    self._stop_fork()
                    return self._result(EngagementStatus.STOPPED, plan, guard, findings, all_candidates, depth, needs_human)
                await self._pause_gate(findings, all_candidates, needs_human)
                if self.bb.has_stop(self.name) or self._safety_event:
                    self._emit(self.name, "lifecycle", {"event": "stop", "reason": "operator/safety"})
                    self._write_findings_json(findings, all_candidates, needs_human)
                    watchdog.cancel()
                    self._stop_fork()
                    return self._result(EngagementStatus.STOPPED, plan, guard, findings, all_candidates, depth, needs_human)
                self._emit(self.name, "message", {"phase": "round", "round": depth, "lenses": len(hunters)})
                import time as _t
                round_start = _t.monotonic()
                round_errors: list[str] = []

                # Fan out: every Child B hunts its derived track this round (bounded concurrency).
                # Each hunter has a WALL-CLOCK cap so one that keeps emitting can't grind forever and
                # block the round (the inactivity timeout only catches SILENCE, not endless grinding).
                # Wall-clock per hunter per round. Deep-discovery extends it to 1h so a sustained
                # investigation isn't guillotined mid-reasoning (the #1 cause of shallow passes). Env wins.
                hunter_cap = _env_float(
                    "P1HUNT_HUNTER_TIMEOUT",
                    3600.0 if self._deep_discovery else 1200.0,
                    minimum=1.0,
                )

                async def _run(h: ClaudeHunter) -> list[ClaudeFinding]:
                    async with self.sem:
                        try:
                            res = await asyncio.wait_for(
                                h.hunt(critical_means + self._scope_guidance(), self.repo_path, depth,
                                       prior_titles, focus_files=h.focus_files, investigate=h.investigate,
                                       notices=list(self._notices), invariants=h.invariants,
                                       known_patterns=[], subsystem=h.subsystem,
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
                    async with self.side_sem:
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
                                            reference_hint=reference_hint, known_patterns=[],
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

                # Expose this round's CHILD tasks so the watchdog can cancel them if they stall. While
                # they run, poll the live blackboard and surface high/critical posts. By default this
                # does NOT cancel active child discovery; operators who prefer the old "drop
                # discovery and verify immediately" behavior can set P1HUNT_FASTLANE_CUT_DISCOVERY=1.
                self._round_tasks = [asyncio.ensure_future(_run(h)) for h in hunters]
                for fz, asn in zip(fuzzers, fuzz_assignments):
                    fkey = f"{fz.agent_name}:{asn['subsystem']}:{asn['differential']}"
                    if fkey in self._fuzz_tasks and not self._fuzz_tasks[fkey].done():
                        continue
                    task = asyncio.ensure_future(_run_fuzz(fz, asn))
                    self._fuzz_tasks[fkey] = task

                    def _done(t, *, key=fkey, agent=fz.agent_name) -> None:
                        self._fuzz_tasks.pop(key, None)
                        try:
                            result = t.result()
                        except asyncio.CancelledError:
                            return
                        except Exception as exc:
                            self._emit(agent, "lifecycle",
                                       {"event": "fuzz_background_error", "detail": str(exc)[:200]})
                            return
                        _ingest_background_candidates(result, source=agent)

                    task.add_done_callback(_done)
                    self._emit(self.name, "lifecycle",
                               {"event": "fuzz_background_started",
                                "agent": fz.agent_name,
                                "subsystem": asn["subsystem"],
                                "detail": "fuzz campaign is running without blocking child discovery"})
                results = []
                pending = set(self._round_tasks)
                fastlane = os.environ.get("P1HUNT_LIVE_FASTLANE", "1") != "0"
                cut_for_fastlane = os.environ.get("P1HUNT_FASTLANE_CUT_DISCOVERY", "0") == "1"
                fastlane_seen: set[str] = set()
                poll_s = _env_float("P1HUNT_LIVE_CANDIDATE_POLL", 15.0, minimum=5.0)
                while pending:
                    done, pending = await asyncio.wait(pending, timeout=poll_s,
                                                       return_when=asyncio.FIRST_COMPLETED)
                    for task in done:
                        try:
                            results.append(task.result())
                        except Exception as exc:
                            results.append(exc)
                    if fastlane:
                        hot = [
                            c for c in self._live_findings_as_candidates()
                            if c.severity in ("critical", "high")
                            and not self._out_of_scope(c.file)
                            and not getattr(c, "relies_on_non_target_behavior", False)
                        ]
                        new_hot = [c for c in hot if self._finding_key(c) not in fastlane_seen]
                        if new_hot:
                            fastlane_seen.update(self._finding_key(c) for c in new_hot)
                            for cand in new_hot:
                                self._mark_fastlane_pending(cand, cut_discovery=cut_for_fastlane)
                            self._emit(self.name, "lifecycle",
                                       {"event": "live_fastlane",
                                        "count": len(new_hot),
                                        "reason": ("high/critical blackboard post cut discovery short for immediate verification"
                                                   if cut_for_fastlane
                                                   else "high/critical blackboard post observed; child discovery continues")})
                            if cut_for_fastlane:
                                for task in pending:
                                    task.cancel()
                                if pending:
                                    results.extend(await asyncio.gather(*pending, return_exceptions=True))
                                pending = set()
                                break
                self._round_tasks = []
                round_findings: list[ClaudeFinding] = []
                for r in results:
                    if isinstance(r, list):
                        round_findings.extend(r)
                live_candidates = self._live_findings_as_candidates()
                if live_candidates:
                    round_findings.extend(live_candidates)
                    self._emit(self.name, "lifecycle",
                               {"event": "live_candidates_queued",
                                "count": len(live_candidates),
                                "reason": "blackboard posts are entering the verifier/prover pipeline"})

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
                    if getattr(cf, "relies_on_non_target_behavior", False):
                        self._record_candidate_status(
                            cf, stage="parent_a", status="attribution_blocked",
                            target_agent="parent_a",
                            next_action="Do not promote unless the defect is re-attributed to target-owned behavior.",
                            blocked_by="non_target_behavior",
                            reason=(cf.attribution_notes or cf.non_target_attribution or
                                    "finder says the win depends on non-target behavior"),
                        )
                        continue
                    if self._out_of_scope(cf.file):
                        self._emit("falsifier", "message",
                                   {"verdict": "out-of-scope", "title": cf.title,
                                    "reason": f"{cf.file} is out of scope (not deployed) — not promoted"})
                        continue
                    strong.append(cf)
                    self._record_candidate_status(
                        cf, stage="parent_a", status="selected_for_verification",
                        target_agent="falsifier",
                        next_action="Adversarial verification, then proof materialization if it survives.",
                    )
                # Operator/Parent-A triage can pull an older candidate back into the verifier/prover
                # lane. Without this, `p1hunt triage` only writes a notice and a stale candidate may
                # never be re-entered because the verify loop used to process only this round's fresh
                # findings.
                existing_keys = {self._candidate_key_doc(c)[0] for c in strong}
                for cf in all_candidates:
                    if cf.severity not in ("critical", "high") or self._out_of_scope(cf.file):
                        continue
                    if getattr(cf, "relies_on_non_target_behavior", False):
                        continue
                    key, _doc = self._candidate_key_doc(cf)
                    if key in existing_keys or not self._is_operator_priority(cf):
                        continue
                    strong.insert(0, cf)
                    existing_keys.add(key)
                    self._parent_intervene(
                        cf,
                        target_agent="falsifier",
                        blocked_by="operator_triage",
                        reason="Operator/Parent A requested this existing candidate be pulled back into the proof pipeline.",
                        directive="Re-run adversarial verification, then immediately hand surviving evidence to PoC/deep-dive.",
                    )
                # COST/TIME GUARD: the verify→materialize→repair→reproduce pipeline is serial and
                # each candidate is expensive (multiple Opus sessions + up to 3×600s reproduce). Cap
                # how many we verify per round to the STRONGEST few (critical before high; high before
                # medium confidence) so a noisy round can't blow up into hours / unbounded spend. The
                # rest stay visible as candidates and get another shot next round.
                _sev_rank = {"critical": 0, "high": 1}
                _conf_rank = {"high": 0, "medium": 1, "low": 2}
                strong.sort(key=lambda c: (_sev_rank.get(c.severity, 2),
                                           _conf_rank.get(str(c.confidence).lower(), 3)))
                _max_verify = _env_int("P1HUNT_MAX_VERIFY", 10, minimum=1)
                if len(strong) > _max_verify:
                    self._emit(self.name, "lifecycle",
                               {"event": "verify_capped", "verifying": _max_verify,
                                "deferred": len(strong) - _max_verify,
                                "reason": "top candidates verified this round; the rest carry to next round"})
                    strong = strong[:_max_verify]
                _verify_cap = _env_float("P1HUNT_VERIFY_TIMEOUT", 900.0, minimum=1.0)
                for cf in strong:
                  # GUARD: one malformed candidate must NEVER crash the never-quit hunt. Any error in
                  # this candidate's verify/prove/promote is logged and skipped; the loop continues.
                  try:
                    self._record_candidate_status(
                        cf, stage="verifier", status="running", target_agent="falsifier",
                        next_action="Decide real/refuted/unverified from direct evidence.",
                    )
                    status, _severity, reason = await asyncio.wait_for(
                        verifier.verify(cf, self.repo_path,
                                        operator_notes=self._operator_notes_for("falsifier", cf)),
                        timeout=_verify_cap)
                    self._record_candidate_status(
                        cf, stage="verifier", status=status, target_agent="falsifier",
                        next_action=("Materialize a runnable proof harness."
                                     if status == "real" else "Keep as candidate unless re-triaged."),
                        blocked_by=("" if status == "real" else status),
                        reason=reason,
                    )
                    hyp = self._hyp_by_finding.get(id(cf))
                    if status == "refuted":
                        if hyp:
                            self.bb.set_state(hyp.id, HypState.FALSIFIED)
                        continue
                    if status == "real":
                        self._parent_intervene(
                            cf,
                            target_agent="poc_prover",
                            blocked_by="not_reproduced_yet",
                            reason="Falsifier validated the finding as real, but confirmation requires deterministic reproduction and, when enabled, exploit-depth proof.",
                            directive="Build and run the smallest complete proof harness now; if a class runner cannot prove it, preserve evidence and hand it to exploit_developer.",
                        )
                    # STRICT REPRODUCED-CRITICAL GATE (§10): the Falsifier only earns the candidate a
                    # chance to be PROVEN. The prover MATERIALIZES a runnable harness into the sandbox;
                    # a DETERMINISTIC class runner then EXECUTES it and decides reproduction from the
                    # real toolchain output — never the model's say-so. NOTHING is promoted to a
                    # confirmed finding unless reproduced=True; otherwise it stays a candidate.
                    _scaffold = self._scaffold_for(cf.lens or "subsystem", [cf.file] if cf.file else [])
                    self._record_candidate_status(
                        cf, stage="poc_prover", status="materializing", target_agent="poc_prover",
                        next_action="Write runnable harness under the PoC sandbox.",
                    )
                    spec_dict = await asyncio.wait_for(
                        prover.materialize(cf, self.repo_path, scaffold=_scaffold, fork_url=self._fork_url,
                                           operator_notes=self._operator_notes_for("poc_prover", cf)),
                        timeout=_verify_cap)
                    self._record_candidate_status(
                        cf, stage="poc_prover",
                        status="harness_materialized" if spec_dict else "no_harness",
                        target_agent="poc_prover",
                        next_action="Run deterministic reproduction." if spec_dict else "Escalate to deep-dive/manual review.",
                        blocked_by="" if spec_dict else "materialization_failed",
                        reason=str((spec_dict or {}).get("notes", ""))[:240] if isinstance(spec_dict, dict) else "",
                    )
                    repro = await self._reproduce(cf, spec_dict)
                    self._record_candidate_status(
                        cf, stage="runner",
                        status=("reproduced" if bool(repro and repro.reproduced)
                                else "not_reproduced"),
                        target_agent="poc_prover",
                        next_action=("Run counterfactual/severity gate."
                                     if bool(repro and repro.reproduced)
                                     else "Parent A will queue exploit-depth proof or needs-human review."),
                        blocked_by="" if bool(repro and repro.reproduced) else "deterministic_reproduction_missing",
                        reason=(getattr(repro, "detail", "") or getattr(repro, "stdout_excerpt", "") or "")[:240] if repro else "",
                    )
                    # POC ITERATION LOOP: if the harness didn't reproduce, feed the REAL runner output
                    # back to the prover to FIX it and rerun — up to P1HUNT_POC_ATTEMPTS times. This
                    # converts reasoned-but-unproven P1s into confirmed ones (one-shot proof misses
                    # the many bugs whose harness just needs a compile fix / better setup).
                    _max_attempts = _env_int("P1HUNT_POC_ATTEMPTS", 5, minimum=1)
                    _attempt = 1
                    while spec_dict and not (repro and repro.reproduced) and _attempt < _max_attempts:
                        feedback = (repro.detail or repro.stdout_excerpt) if repro else "no harness was produced"
                        self._emit("poc_prover", "lifecycle",
                                   {"event": "poc_retry", "title": cf.title, "attempt": _attempt + 1,
                                    "of": _max_attempts})
                        new_spec = await asyncio.wait_for(
                            prover.repair(cf, spec_dict, str(feedback), self.repo_path,
                                          scaffold=_scaffold, fork_url=self._fork_url,
                                          operator_notes=self._operator_notes_for("poc_prover", cf)),
                            timeout=_verify_cap)
                        if not new_spec:
                            break
                        spec_dict = new_spec
                        repro = await self._reproduce(cf, spec_dict)
                        self._record_candidate_status(
                            cf, stage="runner",
                            status=("reproduced" if bool(repro and repro.reproduced)
                                    else "not_reproduced"),
                            target_agent="poc_prover",
                            next_action=("Run counterfactual/severity gate."
                                         if bool(repro and repro.reproduced)
                                         else "Continue repair attempts or queue exploit-depth proof."),
                            blocked_by="" if bool(repro and repro.reproduced) else "deterministic_reproduction_missing",
                            reason=(getattr(repro, "detail", "") or getattr(repro, "stdout_excerpt", "") or "")[:240] if repro else "",
                        )
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
                    impact = self._impact_of(cf, reproduced, repro)
                    sev_label, sev_rationale = self._severity.map(impact)
                    if not reproduced:
                        if hyp:
                            self.bb.set_state(hyp.id, HypState.CANDIDATE)
                        self._emit("poc_prover", "lifecycle",
                                   {"event": "candidate_not_reproduced", "title": cf.title,
                                    "ran": bool(repro and repro.ran), "severity": sev_label,
                                    "detail": (repro.detail[:200] if repro else "no harness/runner — stays a candidate")})
                        # SURFACE FOR AUTONOMOUS FOLLOW-UP (don't bury it): the Falsifier believes it's real
                        # and the finder claims a concrete, high-confidence loss — it just couldn't be
                        # auto-reproduced (hard-to-harness class, missing toolchain, multi-step setup).
                        # A reasoned P1 the bot should keep attacking is the MOST valuable output, not the
                        # least. It is clearly marked verified=False — the reproduced=confirmed floor
                        # is untouched; this is a separate, prominent autonomous follow-up tier.
                        # SURFACE WIDELY: the Falsifier already believes it's real and it's a
                        # critical/high in scope — surface it for a human even if the finder didn't
                        # phrase the loss as one of the exact literal words or hedged confidence.
                        # Missing a real P1 because of a string mismatch is the worst outcome; a human
                        # triages false positives cheaply. (status here is 'real' or 'unverified'.)
                        if status == "real" and not self._out_of_scope(cf.file):
                            self._parent_intervene(
                                cf,
                                target_agent="exploit_developer",
                                blocked_by="deterministic_reproduction_missing",
                                reason="Falsifier says real, but the deterministic runner did not prove the attacker win.",
                                directive="Sustain focus on this lead: close the full attacker-win chain or produce a rigorous blocker.",
                            )
                            f = self._surface_for_human(cf, reason, sev_label, guard,
                                                        ran=bool(repro and repro.ran),
                                                        detail=(repro.detail if repro else ""))
                            needs_human.append(f)
                            self._record_candidate_status(
                                cf, stage="parent_a", status="autonomous_followup",
                                target_agent="exploit_developer",
                                next_action="Exploit-depth phase must close the attacker-win or park with a precise blocker.",
                                blocked_by="not_confirmed_until_attacker_win_is_proven",
                                reason="Falsifier-believed lead was not auto-reproduced.",
                            )
                            self._emit(self.name, "lifecycle",
                                       {"event": "autonomous_followup", "title": cf.title,
                                        "severity": sev_label, "confidence": cf.confidence,
                                        "concrete_loss": cf.concrete_loss,
                                        "reason": "Falsifier-believed P1, not auto-reproduced — queued for exploit-depth"})
                        continue
                    # Reproduced by a real runner -> confirmed evidence. It only enters the critical
                    # confirmation lanes if the counterfactual/severity gates make it critical.
                    tier = self._norm_tier(sev_label, self._severity.is_p1(impact))
                    is_critical = tier == "critical"
                    # DEDUP GATE: before publishing, check it isn't the SAME root cause as one already
                    # confirmed (the swarm re-finds one bug many ways across rounds/hunters). Duplicate
                    # -> drop quietly; distinct -> publish. Only runs when prior confirmed exist.
                    if self._dedup_on and findings:
                        try:
                            is_dup, of_idx, why = await asyncio.wait_for(
                                deduper.is_duplicate(cf, findings, self.repo_path), timeout=_verify_cap)
                        except Exception:
                            is_dup, of_idx, why = False, 0, "dedup error (kept)"
                        if is_dup:
                            if hyp:
                                self.bb.set_state(hyp.id, HypState.CONFIRMED)
                            self._emit(self.name, "lifecycle",
                                       {"event": "duplicate_dropped", "title": cf.title,
                                        "of": of_idx, "reason": why[:160]})
                            continue
                    if hyp:
                        self.bb.set_state(hyp.id, HypState.CONFIRMED)
                    promoted = self._promote(cf, f"{sev_rationale} | falsifier: {reason}", guard,
                                             repro=repro, severity_label=sev_label, tier=tier)
                    findings.append(promoted)
                    self._record_candidate_status(
                        promoted, stage="parent_a",
                        status=("reproduced_pending_deepdive" if is_critical and self._deepdive_on and self.config.use_claude
                                else "reproduced_pending_debate" if is_critical and self._debate_max and self.config.use_claude
                                else "confirmed" if is_critical else "confirmed_noncritical"),
                        target_agent=("exploit_developer" if is_critical and self._deepdive_on and self.config.use_claude
                                      else "debate" if is_critical and self._debate_max and self.config.use_claude
                                      else "parent_a"),
                        next_action=("Demonstrate full attacker-win in exploit-depth phase."
                                     if is_critical and self._deepdive_on and self.config.use_claude
                                     else "Run debate panel before counting as confirmed critical."
                                     if is_critical and self._debate_max and self.config.use_claude
                                     else "Count in confirmed criticals." if is_critical
                                     else "Keep as lower-severity evidence; continue hunting for P1."),
                        blocked_by=("deepdive_attacker_win_required" if is_critical and self._deepdive_on and self.config.use_claude
                                    else "debate_uphold_required" if is_critical and self._debate_max and self.config.use_claude
                                    else (getattr(repro, "impact_blocker", "") or "")),
                    )
                  except asyncio.TimeoutError:
                    self._record_candidate_status(
                        cf, stage="parent_a", status="deferred",
                        target_agent="poc_prover",
                        next_action="Retry verifier/prover next round.",
                        blocked_by="verify_timeout",
                    )
                    self._emit("poc_prover", "lifecycle",
                               {"event": "verify_timeout", "title": cf.title,
                                "detail": f"verify/prove exceeded {int(_verify_cap)}s — deferred to next round"})
                  except Exception as exc:
                    self._record_candidate_status(
                        cf, stage="parent_a", status="deferred",
                        target_agent="poc_prover",
                        next_action="Retry verifier/prover next round after fixing pipeline error.",
                        blocked_by="candidate_verify_error",
                        reason=str(exc)[:240],
                    )
                    # One bad candidate must not kill the never-quit hunt (§8).
                    self._emit("poc_prover", "lifecycle",
                               {"event": "candidate_verify_error", "title": cf.title, "detail": str(exc)[:200]})

                # EXPLOIT-DEVELOPMENT DEPTH PHASE (background lane): take the top believed-real
                # primitives (needs-human P1s + un-proven criticals) and SUSTAIN focus to build the
                # full attacker-win exploit. ONLY a demonstrated win in shipped code promotes to a
                # confirmed critical (a primitive is not a critical). This used to be awaited at
                # round-end, which starved child discovery whenever exploit_dev ran long.
                if self._deepdive_on and self.config.use_claude:
                    _dt = _env_float("P1HUNT_DEEPDIVE_TIMEOUT", 3600.0, minimum=1.0)
                    rubric = (getattr(self.scope, "scope_note", "")
                              or getattr(self.scope, "safe_harbor_text", "") or "")
                    # The pool is needs-human P1s + un-proven criticals + candidates whose text
                    # matches this PROGRAM'S captured severity/rubric language. No target-specific
                    # keywords: each engagement's taxonomy decides what deserves scarce exploit-depth.
                    rubric_terms = self._rubric_priority_terms()

                    def _promise(_f) -> float:
                        return self._rubric_lead_score(_f, rubric_terms)

                    inrubric_cands = [c for c in all_candidates
                                      if _promise(c) >= 5.0]
                    pool = (list(needs_human)
                            + [f for f in findings if f.severity == "critical"
                               and self._finding_key(f) not in self._exploit_proven]
                            + inrubric_cands)
                    # TENACITY: select the highest-promise leads that are still OPEN (not proven, not
                    # exhausted, under the attempt cap). A failed attempt DECAYS a lead's priority so
                    # the engine rotates to fresher leads, but keeps cycling back — it never abandons a
                    # lead after one failed PoC; it changes the angle and tries again next round.
                    def _eff_promise(_f) -> float:
                        boost = 20.0 if self._is_operator_priority(_f) else 0.0
                        return boost + _promise(_f) - 2.0 * self._lead_attempts(self._finding_key(_f))
                    pool.sort(key=_eff_promise, reverse=True)
                    todo, seen_k = [], set()
                    for f in pool:
                        k = self._finding_key(f)
                        if k in seen_k:
                            continue  # skip duplicate-looking leads in this deep-dive pass
                        if k in self._exploit_tasks:
                            continue  # exploit-depth already active; keep child discovery moving
                        if not self._lead_open(k):
                            continue  # proven / exhausted / hit the attempt cap -> stop pursuing
                        seen_k.add(k)
                        todo.append(f)
                        if len(todo) >= self._deepdive_top_n:
                            break

                    async def _run_exploit_depth(f) -> None:
                        k = self._finding_key(f)
                        prior = self._lead_log.get(k, {}).get("attempts", [])
                        try:
                            try:
                                verdict = await asyncio.wait_for(
                                    developer.develop(f, self.repo_path, rubric=rubric, scaffold="",
                                                      fork_url=self._fork_url, prior_attempts=prior,
                                                      operator_notes=self._operator_notes_for("exploit_developer", f)),
                                    timeout=_dt)
                            except Exception as exc:
                                # transient -> NOT counted as an attempt; the lead stays open and retries
                                self._record_candidate_status(
                                    f, stage="exploit_developer", status="deferred",
                                    target_agent="exploit_developer",
                                    next_action="Retry exploit-depth next round.",
                                    blocked_by="exploit_dev_error",
                                    reason=str(exc)[:240],
                                )
                                self._emit(self.name, "lifecycle",
                                           {"event": "exploit_dev_error", "title": f.title, "detail": str(exc)[:160]})
                                return
                            if verdict and verdict.get("_achieved"):
                                tier = normalize_exploit_tier(str(verdict.get("tier", "critical")))
                                f.severity = tier
                                try:
                                    f.verified = True
                                except Exception:
                                    pass
                                is_critical_win = f.severity == "critical"
                                self._exploit_proven.add(k)
                                self._lead_log.setdefault(k, {"attempts": [], "status": "open"})["status"] = "proven"
                                if f not in findings:
                                    findings.append(f)
                                    if f in needs_human:
                                        needs_human.remove(f)
                                self._record_candidate_status(
                                    f, stage="exploit_developer",
                                    status=(("exploit_confirmed_pending_debate"
                                             if self._debate_max and self.config.use_claude else "confirmed")
                                            if is_critical_win else "confirmed_noncritical"),
                                    target_agent=("debate" if is_critical_win and self._debate_max and self.config.use_claude
                                                  else "parent_a"),
                                    next_action=(("Run debate panel before counting as confirmed critical."
                                                  if self._debate_max and self.config.use_claude
                                                  else "Count in confirmed criticals.")
                                                 if is_critical_win
                                                 else "Keep as confirmed lower-severity evidence; continue hunting for P1."),
                                    blocked_by=("debate_uphold_required"
                                                if is_critical_win and self._debate_max and self.config.use_claude else ""),
                                    reason=str(verdict.get("win", ""))[:240],
                                )
                                self._emit(self.name, "lifecycle",
                                           {"event": "exploit_confirmed", "title": f.title, "tier": tier,
                                            "win": str(verdict.get("win", ""))[:160],
                                            "aborts": str(verdict.get("aborts", "")),
                                            "attempts": self._lead_attempts(k) + 1})
                            else:
                                # NOT a win -> log the failed angle and decide: keep pursuing, exhausted, or capped.
                                status = self._record_lead_attempt(k, verdict)
                                n = self._lead_attempts(k)
                                if status == "exhausted":
                                    self._record_candidate_status(
                                        f, stage="exploit_developer", status="exhausted",
                                        target_agent="parent_a",
                                        next_action="Park as needs-human with a rigorous impossibility argument.",
                                        blocked_by="exploit_chain_exhausted",
                                        reason=str((verdict or {}).get("impossibility", ""))[:240],
                                    )
                                    self._emit(self.name, "lifecycle",
                                               {"event": "exploit_exhausted", "title": f.title, "attempts": n,
                                                "detail": str((verdict or {}).get("impossibility", ""))[:200]})
                                elif status == "maxed":
                                    self._record_candidate_status(
                                        f, stage="exploit_developer", status="autonomous_backlog",
                                        target_agent="parent_a",
                                        next_action="Park with blocker; resume when new evidence, operator triage, or a fresh angle appears.",
                                        blocked_by="lead_attempt_cap",
                                        reason=str((verdict or {}).get("why_failed", ""))[:240],
                                    )
                                    self._emit(self.name, "lifecycle",
                                               {"event": "exploit_pursuit_capped", "title": f.title, "attempts": n,
                                                "detail": f"no win after {n} angles — parked with explicit blocker"})
                                else:
                                    self._record_candidate_status(
                                        f, stage="exploit_developer", status="retry_next_round",
                                        target_agent="exploit_developer",
                                        next_action=str((verdict or {}).get("next_angle", ""))[:240],
                                        blocked_by="attacker_win_not_yet_demonstrated",
                                        reason=str((verdict or {}).get("why_failed", ""))[:240],
                                    )
                                    self._emit(self.name, "lifecycle",
                                               {"event": "exploit_retry", "title": f.title, "attempts": n,
                                                "next_angle": str((verdict or {}).get("next_angle", ""))[:160],
                                                "detail": "lead still open — will try a different angle next round"})
                        finally:
                            self._exploit_tasks.pop(k, None)
                            self._write_findings_json(findings, all_candidates, needs_human)

                    for f in todo:
                        k = self._finding_key(f)
                        self._record_candidate_status(
                            f, stage="exploit_developer", status="running",
                            target_agent="exploit_developer",
                            next_action="Close the full attacker-win chain or produce a rigorous blocker.",
                            blocked_by="attacker_win_not_yet_demonstrated",
                        )
                        self._exploit_tasks[k] = asyncio.create_task(_run_exploit_depth(f))
                        self._emit(self.name, "lifecycle",
                                   {"event": "exploit_background_started", "title": f.title,
                                    "target_agent": "exploit_developer",
                                    "detail": "exploit-depth is running while child discovery continues"})

                # DEBATE PANEL (round end, CRITICALS ONLY): adversarially re-test each newly-confirmed
                # critical — a prosecutor argues to invalidate/downgrade, a defender argues it's a real
                # critical, a judge rules. reject -> remove; downgrade -> lower severity (no longer a
                # critical); uphold -> keep. Bounded by P1HUNT_DEBATE_MAX (0 disables) and deduped, so
                # only a few distinct criticals are ever debated — keeps the token cost in check.
                if self._debate_max and self.config.use_claude:
                    _vt = _env_float("P1HUNT_VERIFY_TIMEOUT", 900.0, minimum=1.0)
                    pending = [f for f in findings
                               if f.severity == "critical"
                               and self._finding_key(f) not in self._debated][:self._debate_max]
                    for f in pending:
                        key = self._finding_key(f)
                        self._record_candidate_status(
                            f, stage="debate", status="running", target_agent="debate",
                            next_action="Adjudicate uphold/downgrade/reject before counting as confirmed.",
                            blocked_by="debate_uphold_required",
                        )
                        try:
                            verdict, sev, why = await asyncio.wait_for(
                                debate.adjudicate(f, self.repo_path), timeout=_vt)
                        except Exception as exc:
                            # Retry transient debate failures, but fail closed after a small cap.
                            # Otherwise a prompt/schema bug can keep a candidate in DEBATE for hours.
                            n = self._debate_errors.get(key, 0) + 1
                            self._debate_errors[key] = n
                            if n >= self._debate_error_max:
                                self._debated.add(key)
                                self._debate_rejected.add(key)
                                findings[:] = [x for x in findings if self._finding_key(x) != key]
                                self._record_candidate_status(
                                    f, stage="debate", status="rejected", target_agent="parent_a",
                                    next_action="Do not report as confirmed; debate gate failed closed.",
                                    blocked_by="debate_error_cap",
                                    reason=str(exc)[:240],
                                )
                                self._emit(
                                    self.name,
                                    "lifecycle",
                                    {"event": "debate_error_cap", "title": f.title,
                                     "attempts": n, "detail": str(exc)[:160]},
                                )
                            else:
                                self._record_candidate_status(
                                    f, stage="debate", status="deferred", target_agent="debate",
                                    next_action=f"Retry debate next round ({n}/{self._debate_error_max}).",
                                    blocked_by="debate_error",
                                    reason=str(exc)[:240],
                                )
                                self._emit(self.name, "lifecycle",
                                           {"event": "debate_error", "title": f.title,
                                            "attempts": n, "detail": str(exc)[:160]})
                            continue
                        self._debated.add(key)
                        if verdict == "reject":
                            self._debate_rejected.add(key)  # never confirmable again
                            findings[:] = [x for x in findings if self._finding_key(x) != key]
                            self._record_candidate_status(
                                f, stage="debate", status="rejected", target_agent="parent_a",
                                next_action="Do not report as confirmed.",
                                blocked_by="debate_rejected",
                                reason=why[:240],
                            )
                            self._emit(self.name, "lifecycle",
                                       {"event": "debate_rejected", "title": f.title, "reason": why[:200]})
                        elif verdict == "downgrade":
                            f.severity = sev if sev in ("high", "medium", "low") else "high"
                            self._debate_downgraded[key] = f.severity
                            f.severity_rationale = f"[DEBATE-DOWNGRADED to {f.severity}] {why} | {f.severity_rationale}"
                            self._record_candidate_status(
                                f, stage="debate", status="downgraded", target_agent="parent_a",
                                next_action="Report only at downgraded severity if useful.",
                                blocked_by="debate_downgraded",
                                reason=why[:240],
                            )
                            self._emit(self.name, "lifecycle",
                                       {"event": "debate_downgraded", "title": f.title,
                                        "to": f.severity, "reason": why[:200]})
                        else:
                            self._debate_upheld.add(key)  # survived the panel -> now confirmable
                            self._record_candidate_status(
                                f, stage="debate", status="upheld", target_agent="parent_a",
                                next_action="Count in confirmed criticals at the next findings write.",
                                blocked_by="",
                                reason=why[:240],
                            )
                            self._emit(self.name, "lifecycle", {"event": "debate_upheld", "title": f.title})

                # Find ALL criticals — do NOT stop at the first. Keep hunting/reframing across
                # rounds (every lens deepening its angle) until the round cap or an operator stop,
                # so multiple independent P1s surface rather than just the first one found.
                crit = len(self._confirmed_crits(findings))  # debate-gated count (matches findings.json)
                self._emit(self.name, "message",
                           {"phase": "round_summary", "round": depth, "criticals_total": crit,
                            "candidates_total": len(all_candidates), "needs_human": len(needs_human),
                            "spent_usd": round(self._spend_usd, 2),
                            "cost_cap_usd": self._cost_cap, "max_criticals": self._max_criticals,
                            "cpu_pct": self._cpu_pct(),
                            "elapsed_s": int(_t.monotonic() - getattr(self, "_hunt_t0", round_start))})
                # Persist findings each round so a later stop/kill always leaves them on disk.
                self._write_findings_json(findings, all_candidates, needs_human)
                # Persist a full RESUMABLE snapshot so a kill/rate-limit can be jump-started from here.
                self._write_state(tracks, critical_means, hunters, findings, all_candidates, seen, depth,
                                  oracle_desc=reference_hint)

                # STOP-AFTER-N-CRITICALS: if the operator set a target, stop once enough criticals are
                # CONFIRMED (post-debate count). Unset = never-quit. Graceful: findings already on disk.
                if self._max_criticals is not None and crit >= self._max_criticals:
                    self._emit(self.name, "lifecycle",
                               {"event": "criticals_target_reached", "confirmed_criticals": crit,
                                "target": self._max_criticals, "round": depth})
                    watchdog.cancel()
                    self._stop_fork()
                    return self._result(EngagementStatus.REPORT_READY, plan, guard, findings, all_candidates, depth, needs_human)

                # Rate-limit / dead-round BACKOFF (§8): a round that finished FAST and produced nothing
                # (or whose sessions errored as rate-limited) means we're throttled — do NOT spin empty
                # rounds hammering the API. Sleep with exponential backoff so the limit can recover.
                round_dur = _t.monotonic() - round_start
                # A REFUSAL IS NOT A RATE LIMIT, and treating it as one is actively harmful.
                # A provider-side safety refusal returns in ~6 seconds with an error, so a
                # refused round looks exactly like a throttled one: fast, empty, errored.
                # The backoff path then slept up to 15 minutes and retried something that
                # can NEVER succeed by waiting -- burning the engagement's wall clock on a
                # permanent condition. Classify first.
                refusals = self._count_refusals(round_errors)
                if refusals:
                    self._report_refused_roles(refusals, len(round_errors), depth)
                throttled = any(("rate" in str(e).lower() or "limit" in str(e).lower() or "usage" in str(e).lower())
                                for e in round_errors) and refusals < len(round_errors)
                if throttled or (round_dur < 45 and not fresh and round_errors
                                 and refusals < len(round_errors)):
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
            await self._cancel_fuzz_tasks()
            await self._cancel_exploit_tasks()
            watchdog.cancel()
            self._stop_fork()

    # --- helpers ----------------------------------------------------------
    _SEC_KEYWORDS = (
        # Broad guarantee/data/control terms only. Parent A derives class-specific focus from the
        # actual target; this fallback ranker must not bake in a protocol, product, or bug shape.
        "access", "account", "admin", "asset", "auth", "balance", "boundary", "capability",
        "commit", "credential", "decrypt", "encrypt", "guard", "hash", "identity", "key",
        "limit", "nonce", "owner", "permission", "policy", "proof", "quota", "role",
        "secret", "session", "share", "sign", "signature", "tenant", "token", "transfer",
        "trust", "validate", "verify", "withdraw",
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
    def _recon_mode(self) -> str:
        """Cold-recon execution mode.

        Dry-run hunts may spend more model/tooling budget up front. Active runs stay conservative
        because live testing should not unexpectedly fan out additional autonomous work.
        """
        mode = os.environ.get("P1HUNT_RECON_MODE", "auto").strip().lower()
        if mode not in ("auto", "solo", "parallel"):
            mode = "auto"
        if getattr(self.config, "run_mode", "dry_run") != "dry_run" and mode == "parallel":
            return "solo"
        return mode

    def _recon_policy_text(self) -> str:
        mode = self._recon_mode()
        if mode == "solo":
            return (
                "RECON EXECUTION MODE: SOLO. Do the deep reconnaissance yourself in this Parent A "
                "turn. Do not dispatch parallel sub-agents unless a file is too large to summarize "
                "safely. You still MUST produce the full structured attacker map before children start."
            )
        if mode == "parallel":
            return (
                "RECON EXECUTION MODE: PARALLEL. This is a dry-run deep reconnaissance pass: after a "
                "brief top-level layout read, dispatch focused parallel sub-agents for the major "
                "subsystems, then synthesize their file:line-anchored maps into the final JSON. Keep "
                "each sub-agent brief targeted and bounded; do not paste giant file dumps."
            )
        return (
            "RECON EXECUTION MODE: AUTO. This is a dry-run-friendly deep reconnaissance pass. First "
            "size up the repository, then CHOOSE the most efficient method: SOLO for small/clear "
            "targets, PARALLEL for large/multi-component/protocol/crypto/reference-heavy targets, or "
            "HYBRID when Parent A should map the top level and dispatch only the expensive subsystem "
            "reads. Your choice changes HOW you read, never WHETHER recon is deep: you still MUST "
            "return the same structured attacker map before children start."
        )

    def _has_live_web_targets(self) -> bool:
        return (
            str(getattr(self, "_target_class", "") or "").upper() == "WEB_API"
            and bool(getattr(getattr(self, "scope", None), "dynamic_targets", None) or [])
        )

    def _dynamic_target_payload(self) -> str:
        targets = []
        for t in getattr(self.scope, "dynamic_targets", None) or []:
            targets.append({
                "base_url": getattr(t, "base_url", ""),
                "environment": getattr(t, "environment", ""),
                "kind": getattr(t, "kind", ""),
                "note": getattr(t, "note", ""),
            })
        return json.dumps(targets, separators=(",", ":"))

    def _live_web_scope_prompt(self) -> str:
        return (
            "You are Parent A, the LEAD of this live web/API security audit. This target was "
            "classified from authorized dynamic targets, not from a local source repository. Do NOT "
            "waste cold reconnaissance mapping nonexistent repo files. Use the workspace only for "
            "notes, request scripts, and PoCs; derive the attack surface from the live targets and "
            "scope rules below.\n\n"
            "NO PRESET LEADS: do not import a canned bug list or target-specific knowledge. Derive "
            "every hypothesis from observed responses, documented scope objectives, and concrete "
            "trust boundaries. A scanner finding alone is never enough; only attacker-win evidence "
            "matters.\n\n"
            f"AUTHORIZED LIVE TARGETS JSON: {self._dynamic_target_payload()}\n"
            f"{self._recon_policy_text()}\n\n"
            "LIVE WEB COLD RECON PLAN:\n"
            "1) Parse the authorized targets exactly. Treat exact URLs/paths as the default scope. "
            "Do not expand to a discovered host unless the scope text explicitly authorizes that "
            "host pattern. Respect every out-of-scope path/domain/method rule.\n"
            "2) Passive host discovery: if an authorized host is a domain and passive tooling is "
            "installed, run a bounded command such as `subfinder -silent -d <registrable-domain> "
            "-all` (or an equivalent passive enumerator). If the target is an IP address or exact "
            "URL-only host, say subdomain enumeration is not applicable. Discovered hosts are "
            "context until proven in-scope; do not touch them otherwise.\n"
            "3) Low-impact baseline only against in-scope targets: bounded `curl -i`, `curl -I`, "
            "`robots.txt`, `security.txt`, API docs/openapi/swagger links if advertised, and "
            "small hand-written requests that test one concrete authorization or state-transition "
            "claim. No brute force, no high-rate crawling, no DoS, no scanner-only reports.\n"
            "4) Identify actors and secrets from observed flows: unauthenticated visitor, test "
            "account, privileged endpoint, network-origin assumption, token/session boundary, "
            "server-side resource, or any special proof objective named by scope. For each actor, "
            "state what the attacker controls and what must remain protected.\n"
            "5) Derive crown jewels from the scope and observations: protected account state, "
            "privileged network/resource access, sensitive data, payment/account authority, or "
            "any concrete proof artifact the engagement says would demonstrate impact. Do not "
            "inflate severity without a victim-state delta or protected-resource proof.\n"
            "6) Build tracks from the observed web surface, ordered most-dangerous-first. Each "
            "track owns a full attacker flow, not a generic bug category. Include one composition "
            "track for seams across identity, routing, redirects/proxies, mobile/web, and backend "
            "resource access if observations show those seams exist.\n\n"
            "EVIDENCE RULES: source file citations are not required for a live web target with no "
            "local source. Instead cite concrete observations compactly: URL, method, status, key "
            "headers, response marker, redirect target, authenticated principal, and timestamp. "
            "Never fabricate file:line claims.\n\n"
            "SEVERITY HONESTY: a reproduced HTTP behavior is not a P1 by itself. Before labeling "
            "critical/high, name the honest victim/protected resource, the pre-committed valuable "
            "target, the attacker action, and the clean-vs-buggy state delta. If those cannot be "
            "named, keep the lead as candidate/medium-or-lower until proven.\n"
            + self._scope_guidance() + "\n\n"
            "WORKSPACE GUARDRAIL: use \".\" as the workspace root unless you create a narrower "
            "notes/PoC folder inside it. Network requests must stay within the authorized live "
            "target policy and the scope rules.\n\n"
            "OUTPUT BUDGET: return ONE compact JSON object under 16000 characters. No markdown, "
            "no prose before or after it. Use 4-6 tracks. Cap crown_jewels at 8, attack_surface "
            "at 12, invariants per track at 5, and investigate items per track at 5.\n\n"
            "Return ONLY JSON:\n"
            '{"summary":"...",'
            '"recon_strategy":"solo|hybrid|parallel",'
            '"target_class":"WEB_API",'
            '"threat_model":"...",'
            '"target_subclass":"<one-word category derived from observed target behavior, or \"\">",'
            '"workspace_root":".",'
            '"permissions":{"allow_network":true,"allow_install":true|false,'
            '"deny_commands":["<substring of commands/paths blocked by scope>",...],'
            '"note":"<why this posture fits the live engagement>"},'
            '"critical_means":"<maximum attacker win from the provided scope rules>",'
            '"crown_jewels":["<protected resource/authority + observed URL/status/header evidence>",...],'
            '"attack_surface":["<method URL actor-control observation>",...],'
            '"differential_oracle":{"exists":true|false,"description":"second implementation/spec/docs/alternate client observed, or none"},'
            '"top_hypothesis":"<single highest-value attacker flow to test next, grounded in observations>",'
            '"tracks":[{"theme":"...","subsystem":"...","fuzz_mode":"invariant|differential",'
            '"expected_severity":"critical|high|medium","attacker_reachability":"high|medium|low",'
            '"focus_files":["<URL or local PoC note path>",...],'
            '"invariants":["attacker must never <force protected web outcome>",...],'
            '"investigate":["specific low-impact request sequence or proof script to run"]}]}'
        )

    def _scope_prompt(self) -> str:
        if self._has_live_web_targets():
            return self._live_web_scope_prompt()
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
            "READ DEEPLY: this is the one phase where breadth AND depth both matter. The exact shape "
            "must fit the target: sometimes Parent A should read the critical files directly; "
            "sometimes it should dispatch parallel subsystem readers; often it should do a hybrid. "
            "Cite real file:line for every claim — never guess. Spend real effort here; the rest of "
            "the hunt inherits the quality of this map.\n\n"
            f"{self._recon_policy_text()}\n\n"
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
            "These are WHERE to point the team.\n"
            "   DERIVE THE GUARANTEES (this is the engine of finding a class you didn't anticipate — NOT a "
            "bug checklist). For each crown-jewel component, state what it PROMISES from what it IS and what "
            "its callers/tests rely on: the security properties an attacker must NEVER be able to break "
            "(derive them — e.g. a proof: sound + reveals nothing; a commitment: binding + hiding; a "
            "signature: unforgeable + non-malleable; a value meant unique/unpredictable: stays so; a "
            "secret/share: never leaks; an invariant the accounting must preserve). Phrase each as 'an "
            "attacker must NEVER be able to <violate property>'. The team's job is to BREAK these derived "
            "guarantees — the failure mode is whatever the break turns out to be — not to scan for known shapes.\n"
            "   MINE THE TESTS: the tests encode the contract — which operations are guarded (throw on "
            "re-call/misuse) vs permitted, and which properties the authors did and did NOT enforce. A "
            "guarantee the tests show is NOT defended is a high-value lead.\n\n"
            "5) FIND A DIFFERENTIAL ORACLE (high-yield). Is there a SECOND implementation of the same "
            "logic to compare against — a reference/spec impl, an older/alternative version, a known "
            "library implementing the same primitive, or the documented spec itself? If so, say where "
            "and how the pieces pair up — any divergence on the same input is a likely bug. Else say "
            "none exists.\n\n"
            "6) OPTIONAL TECHNICAL CONTEXT (WebSearch/WebFetch). Use web only to understand public "
            "specs, standards, APIs, deployment facts, build/tooling docs, or protocol terminology "
            "needed to read THIS code correctly. Do NOT research known vulnerability taxonomies, past "
            "audit findings, CVEs, disclosed exploits, or '<product> vulnerabilities' for this target "
            "or its peers. Convert any external context into code-specific guarantees and citations "
            "from the local repository; never into a preset lead.\n\n"
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
            "STRATEGY: 'differential' (if the oracle covers it) or 'invariant' (stateful fuzzing).\n"
            "   CROSS-CUTTING: real P1s in hardened code usually live in the SEAMS BETWEEN subsystems "
            "(a check in one composing unsafely with a flow in another), not inside one. So make ONE "
            "track explicitly own the COMPOSITION / trust-boundary seams — the end-to-end attacker "
            "FLOWS that cross subsystem lines — and give it the focus_files of EVERY subsystem the flow "
            "touches. focus_files MAY OVERLAP across tracks where a flow spans them; do NOT carve the "
            "code into disjoint slices that hide the interaction. A track must own a whole flow, not a "
            "fragment.\n\n"
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
            "OUTPUT BUDGET: the final answer must be ONE compact JSON object under 18000 characters. "
            "No markdown, no prose, no status object before or after it. Use 4-6 tracks. Cap "
            "crown_jewels at 8, attack_surface at 12, focus_files per track "
            "at 8, invariants per track at 5, and investigate items per track at 5. Keep file:line "
            "citations inside those compact strings; do not paste long notes or file contents.\n\n"
            "Return ONLY JSON:\n"
            '{"summary":"...",'
            '"recon_strategy":"solo|hybrid|parallel",'
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
        from .claude_session import make_session

        self._emit(self.name, "message",
                   {"phase": "scoping", "detail": "cold reconnaissance — no prior knowledge of the target",
                    "recon_mode": self._recon_mode()})
        try:
            _recon_turns = _env_int("P1HUNT_RECON_TURNS", 45, minimum=20)
        except ValueError:
            _recon_turns = 45
        session = make_session(
            agent_name=self.name, model=self.config.models.orchestrator, on_event=self._emit,
            guard_check=self._guard_check(guard, self.name), max_turns=_recon_turns,
            engine=self.config.models.engine,
            effort=self.config.models.codex_effort,
            codex_model=self.config.models.codex_model,
            allow_web=self._has_live_web_targets(),
            perms=self._perms, egress_hosts=self._egress_hosts,
        )
        result = await session.run(self._scope_prompt(), self.repo_path)
        parsed = _parse_json_object(result.text)
        if self._should_retry_scope_parse(result, parsed):
            self._emit(self.name, "lifecycle",
                       {"event": "scope_parse_retry",
                        "reason": "Parent A did not return parseable tracks",
                        "tool_calls": getattr(result, "tool_calls", 0)})
            retry = make_session(
                agent_name=self.name, model=self.config.models.orchestrator, on_event=self._emit,
                guard_check=self._guard_check(guard, self.name), max_turns=max(10, min(_recon_turns, 30)),
                engine=self.config.models.engine,
                effort=self.config.models.codex_effort,
                codex_model=self.config.models.codex_model,
                allow_web=self._has_live_web_targets(),
                perms=self._perms, egress_hosts=self._egress_hosts,
            )
            retry_result = await retry.run(self._scope_retry_prompt(result.text), self.repo_path)
            retry_parsed = _parse_json_object(retry_result.text)
            if retry_parsed and retry_parsed.get("tracks"):
                result, parsed = retry_result, retry_parsed
            else:
                self._emit(self.name, "lifecycle",
                           {"event": "scope_parse_retry_failed",
                            "reason": getattr(retry_result, "error", "") or "still no tracks",
                            "tool_calls": getattr(retry_result, "tool_calls", 0)})
        self._apply_workspace_guardrail((parsed or {}).get("workspace_root"))
        if not parsed or not parsed.get("tracks"):
            tracks = self._fallback_tracks()
            event = "scope_repo_derived_fallback" if self._deep_discovery else "scope_fallback"
            self._emit(self.name, "lifecycle",
                       {"event": event, "reason": "no tracks derived",
                        "tracks": [t.get("subsystem") or t.get("theme") for t in tracks[:6]]})
            return {"tracks": tracks,
                    "critical_means": (parsed or {}).get("critical_means"),
                    "summary": (parsed or {}).get("summary", "")}
        # Surface Parent A's recon reasoning so the operator can see the map it drew (and judge it).
        self._emit(self.name, "lifecycle",
                   {"event": "recon", "crown_jewels": (parsed.get("crown_jewels") or [])[:5],
                    "strategy": str(parsed.get("recon_strategy", "") or self._recon_mode())[:40],
                    "attack_surface": (parsed.get("attack_surface") or [])[:6],
                    "top_hypothesis": str(parsed.get("top_hypothesis", ""))[:300],
                    "tracks": [t.get("subsystem") or t.get("theme") for t in (parsed.get("tracks") or [])][:6]})
        return parsed

    def _should_retry_scope_parse(self, result, parsed: dict | None) -> bool:
        if os.environ.get("P1HUNT_SCOPE_RETRY", "1") == "0":
            return False
        if parsed and parsed.get("tracks"):
            return False
        err = str(getattr(result, "error", "") or "").lower()
        if "rate_limited" in err or "rate limit" in err or "session limit" in err:
            return False
        return bool(str(getattr(result, "text", "") or "").strip())

    def _scope_retry_prompt(self, prior_text: str) -> str:
        excerpt = (prior_text or "")[-8000:]
        return (
            "You are Parent A. Your previous scoping turn did useful reconnaissance but did not "
            "return a parseable plan. Do not redo the full read unless absolutely necessary; synthesize "
            "from the excerpt below and emit the plan now.\n\n"
            "Return exactly ONE compact JSON object under 12000 characters. No markdown. No prose. "
            "No status object. No second object. Use 4-6 most-dangerous-first tracks with concrete "
            "focus_files, invariants, and investigate items. Cap arrays tightly: crown_jewels <= 6, "
            "attack_surface <= 8, focus_files <= 8 per track, invariants <= 4 "
            "per track, investigate <= 4 per track.\n\n"
            "Required schema:\n"
            '{"summary":"...","recon_strategy":"solo|hybrid|parallel",'
            '"target_class":"EVM_CONTRACT|CRYPTO_LIB|WEB_API|MOBILE_APP|INFRA|SUPPLY_CHAIN|OTHER",'
            '"threat_model":"...","target_subclass":"...","workspace_root":".",'
            '"permissions":{"allow_network":true|false,"allow_install":true|false,'
            '"deny_commands":[],"note":"..."},'
            '"critical_means":"...","crown_jewels":["..."],"attack_surface":["..."],'
            '"differential_oracle":{"exists":true|false,"description":"..."},'
            '"top_hypothesis":"...",'
            '"tracks":[{"theme":"...","subsystem":"...","fuzz_mode":"differential|invariant",'
            '"expected_severity":"critical|high|medium","attacker_reachability":"high|medium|low",'
            '"focus_files":["relative/path"],"invariants":["attacker must never ..."],'
            '"investigate":["concrete attacker move"]}]}'
            "\n\nPrevious reconnaissance excerpt:\n```text\n"
            + excerpt
            + "\n```"
        )

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
            self.poc_reldir = _poc_reldir(self._workspace_root)
            self.poc_dir = Path(self._workspace_root) / self.poc_reldir
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
        """Last-resort offline/test decomposition derived only from repository names.

        Active hunts should get meaningful tracks from Parent A. If Parent A is unavailable or its
        JSON is unusable, do not insert domain lanes, failure taxonomies, or invariants. Keep the process
        alive with file clusters that force the child to derive its own threat model from code.
        """
        has_live_web_targets = getattr(self, "_has_live_web_targets", lambda: False)
        if has_live_web_targets():
            return self._web_fallback_tracks()
        return self._repo_component_tracks()

    def _web_fallback_tracks(self) -> list[dict]:
        """Last-resort live-web tracks derived from the authorized dynamic target shape.

        These are not bug classes or target-specific presets. They are the minimum attacker-flow
        ownership lanes a black-box web hunt needs when Parent A's JSON is unusable: discover the
        reachable surface, map authority, test state transitions, compose trusted-origin behavior,
        and compare advertised client/API contracts.
        """
        urls = [str(getattr(t, "base_url", "") or "").strip()
                for t in (getattr(self.scope, "dynamic_targets", None) or [])]
        urls = [u for u in urls if u]
        focus = urls[:6]
        return [
            {
                "theme": "live surface and client contracts",
                "subsystem": "reachable web surface",
                "fuzz_mode": "invariant",
                "expected_severity": "critical",
                "attacker_reachability": "high",
                "focus_files": focus,
                "invariants": [
                    "attacker must never discover a public client/API contract that exposes protected data or privileged operations without the intended authority",
                    "attacker must never use advertised routes, bundled client code, or docs to reach a protected workflow outside its intended actor boundary",
                ],
                "investigate": [
                    "Harvest only in-scope HTML, JS, robots/security metadata, redirects, forms, and advertised API contracts; extract concrete endpoints and actors.",
                    "Prioritize endpoints that move account state, return user data, create tokens, import URLs, run code, or bridge to a privileged backend.",
                ],
            },
            {
                "theme": "authorization and object boundaries",
                "subsystem": "principal-to-resource authorization",
                "fuzz_mode": "invariant",
                "expected_severity": "critical",
                "attacker_reachability": "medium",
                "focus_files": focus,
                "invariants": [
                    "attacker must never access or mutate another principal's resources by changing identifiers, tenants, sessions, or request context",
                    "attacker must never convert unauthenticated or low-authority state into privileged account control",
                ],
                "investigate": [
                    "If authorized test identities exist, compare same endpoint/object actions across identities using the scope-enforced client.",
                    "If no identities exist, map login, registration, token, tenant, and object-id surfaces without submitting destructive writes.",
                ],
            },
            {
                "theme": "trusted-origin and server-side composition",
                "subsystem": "server-side request and integration seams",
                "fuzz_mode": "invariant",
                "expected_severity": "critical",
                "attacker_reachability": "medium",
                "focus_files": focus,
                "invariants": [
                    "attacker must never cause an in-scope trusted server to fetch or act on attacker-chosen internal or protected resources",
                    "attacker must never receive sensitive response data, callbacks, or status oracles from privileged backend-origin actions",
                ],
                "investigate": [
                    "Look for concrete in-scope URL/import/webhook/preview/proxy/integration inputs before testing OOB or internal-resource composition.",
                    "Prove composition only with harmless canaries first; use protected resources only if the sink and scope are concrete.",
                ],
            },
            {
                "theme": "state-changing workflow integrity",
                "subsystem": "business actions and trust transitions",
                "fuzz_mode": "invariant",
                "expected_severity": "high",
                "attacker_reachability": "medium",
                "focus_files": focus,
                "invariants": [
                    "attacker must never complete a protected workflow by replaying, reordering, or omitting required proof steps",
                    "attacker must never make the server trust client-controlled state for security decisions",
                ],
                "investigate": [
                    "Map forms, redirects, callbacks, tokens, cookies, local storage, and API calls that advance account or data-access state.",
                    "Test only low-impact state changes on owned/synthetic accounts when credentials are supplied.",
                ],
            },
        ]

    def _repo_component_tracks(self, *, limit: int = 6) -> list[dict]:
        import re
        from collections import Counter

        files = [f for f in self._enumerate_targets(limit=180) if not self._out_of_scope(f)]
        if not files:
            return [{"theme": "repo", "subsystem": "repo", "focus_files": [],
                     "invariants": [], "investigate": []}]

        stop = {
            "src", "source", "include", "includes", "lib", "libs", "common", "internal",
            "external", "core", "main", "index", "pkg", "packages", "module", "modules",
            "test", "tests", "mock", "mocks", "spec", "specs", "util", "utils", "helper",
            "helpers", "base", "types", "type", "interface", "interfaces",
        }

        def tokens(rel: str) -> list[str]:
            parts: list[str] = []
            for part in Path(rel).with_suffix("").parts:
                parts.extend(t.lower() for t in re.split(r"[^A-Za-z0-9]+", part) if len(t) >= 3)
            return [t for t in parts if t not in stop and not t.isdigit()]

        counts = Counter(t for rel in files for t in set(tokens(rel)))
        ranked = [tok for tok, count in counts.most_common() if count >= 1]
        seeds: list[str] = []
        for tok in ranked:
            if all(tok not in s and s not in tok for s in seeds):
                seeds.append(tok)
            if len(seeds) >= limit:
                break
        if not seeds:
            seeds = ["repo"]

        tracks: list[dict] = []
        assigned: set[str] = set()
        for seed in seeds[:limit]:
            focus = [rel for rel in files if seed == "repo" or seed in tokens(rel)]
            if not focus:
                continue
            assigned.update(focus)
            tracks.append({
                "theme": f"derived:{seed}",
                "subsystem": seed,
                "fuzz_mode": "invariant",
                "expected_severity": "critical",
                "attacker_reachability": "unknown",
                "focus_files": focus[:12],
                "invariants": [],
                "investigate": [
                    f"Read the {seed} file cluster end-to-end and derive externally reachable attacker wins from cited code.",
                    "Report only after deriving target-specific invariants and running a concrete local proof attempt.",
                ],
            })
        remaining = [rel for rel in files if rel not in assigned]
        if remaining and len(tracks) < limit:
            tracks.append({
                "theme": "derived:remaining",
                "subsystem": "remaining",
                "fuzz_mode": "invariant",
                "expected_severity": "critical",
                "attacker_reachability": "unknown",
                "focus_files": remaining[:12],
                "invariants": [],
                "investigate": [
                    "Read these remaining files and decide whether they expose a real attacker-controlled path.",
                    "Derive invariants from code before proposing or testing any bug hypothesis.",
                ],
            })
        return tracks or [{"theme": "derived:repo", "subsystem": "repo", "focus_files": files[:12],
                           "invariants": [], "investigate": []}]

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
            evidence_required=["agent-cited code evidence", "adversarial verification"],
            state=HypState.CANDIDATE,
            counterfactual=cf.counterfactual or None,
        )
        self.bb.add_hypothesis(hyp)
        self._hyp_by_finding[id(cf)] = hyp

    @staticmethod
    def _count_refusals(errors: list[str]) -> int:
        """How many of this round's session errors were provider-side SAFETY refusals?

        Reuses the planner's marker list so one definition answers "was this refused"
        everywhere; a second copy would drift and then disagree about whether the run was
        dead.
        """
        from ..dynamic import triage as _triage

        count = 0
        for err in errors or []:
            if _triage.classify_failure("", str(err)) == _triage.REASON_REFUSED:
                count += 1
        return count

    def _report_refused_roles(self, refusals: int, total: int, depth: int) -> None:
        """SHOUT when the hunting layer was refused. See instructions.authorized_role.

        A measured end-to-end run had every hunter and the fuzzer refused, so the hunt
        reported a clean zero that said nothing at all about the target. The condition is
        permanent for the run -- it will not recover by retrying -- so it has to be stated
        in terms the operator cannot misread as a result.
        """
        if refusals <= 0 or self._refusal_announced:
            return
        self._refusal_announced = True
        everything = refusals >= max(1, total)
        self._emit(self.name, "lifecycle", {
            "event": "hunter_roles_refused", "severity": "HIGH",
            "refused_sessions": refusals, "errored_sessions": total, "round": depth,
            "impact": ("EVERY hunting session this round was refused by the provider's safety "
                       "classifier, so this round searched for NOTHING"
                       if everything else
                       f"{refusals} of {total} hunting sessions were refused by the provider's "
                       f"safety classifier, so those tracks searched for nothing"),
            "why_it_matters": "a refused session returns no findings, which is indistinguishable "
                              "from a clean result. Do NOT read this run as evidence the target "
                              "is sound -- it is evidence the engine would not do the work",
            "fix": "this engine/model will not accept the hunting role for this workload. Route "
                   "these roles to an engine authorized for defensive security testing "
                   "(P1HUNT_ENGINE=claude), or select a different model "
                   "(P1HUNT_CODEX_MODEL). Confirm the engagement authorization is stated in "
                   "the scope note either way. Retrying the same engine will not help: a "
                   "refusal is permanent for the run, not a transient limit",
        })

    async def _preflight_runner_toolchain(self) -> None:
        """Check the class runner can execute a harness at all, and SHOUT if it cannot.

        Never raises and never blocks the hunt: a run on a broken toolchain still has
        value (the reasoning, the ledger, the candidate queue all still work) and the
        operator may knowingly want it. What it must not do is look like a clean result.
        """
        try:
            from ..runners.base import toolchain_preflight
            pre = await asyncio.to_thread(toolchain_preflight, self._target_class,
                                          self._subclass)
        except Exception as exc:  # a diagnostic must never take down the hunt
            self._emit(self.name, "lifecycle",
                       {"event": "toolchain_preflight_failed", "error": str(exc)[:200]})
            return
        if pre.get("ok"):
            self._emit(self.name, "lifecycle",
                       {"event": "toolchain_preflight", "ok": True,
                        "checked": bool(pre.get("checked")),
                        "tool": pre.get("tool", ""), "detail": pre.get("detail", "")[:200]})
            return
        self._emit(self.name, "lifecycle", {
            "event": "toolchain_broken", "severity": "HIGH",
            "tool": pre.get("tool", ""),
            "broken_plugin": pre.get("broken_plugin", ""),
            "impact": "NO finding can be deterministically reproduced on this machine, so the "
                      "hunt's confirmed-critical count is capped at zero regardless of what it "
                      "finds. Candidates will still accumulate; every one of them will report an "
                      "infrastructure error instead of a verdict. Do NOT read a clean result "
                      "from this run as 'no bugs here'",
            "detail": pre.get("detail", "")[:300],
            "fix": pre.get("fix", "")[:300],
        })

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
            blocker = spec.attribution_blocker()
            if blocker:
                from ..runners.base import ReproResult
                self._emit("poc_prover", "lifecycle",
                           {"event": "attribution_rejected", "title": cf.title,
                            "detail": blocker[:240]})
                return ReproResult(
                    ran=False,
                    reproduced=False,
                    command="",
                    artifact_paths=([spec.harness_path] if spec.harness_path else []),
                    detail=f"attribution gate rejected proof: {blocker}",
                    runner="attribution-gate",
                    target_code_attribution=spec.target_code_attribution,
                    non_target_attribution=spec.non_target_attribution,
                    attribution_notes=spec.attribution_notes,
                )
            timeout = _env_float("P1HUNT_REPRO_TIMEOUT", 600.0, minimum=1.0)
            repro = await asyncio.to_thread(runner.run, self._workspace_root, spec,
                                            timeout=timeout, on_event=self._emit)
            repro.target_code_attribution = spec.target_code_attribution
            repro.non_target_attribution = spec.non_target_attribution
            repro.attribution_notes = spec.attribution_notes
            gate = assess_counterfactual_proof(
                workspace=self._workspace_root,
                harness_paths=[spec.harness_path, *list(repro.artifact_paths or [])],
                stdout_excerpt=repro.stdout_excerpt,
                detail=repro.detail,
                finding_text=" ".join([
                    cf.title or "",
                    cf.root_cause or "",
                    cf.reproduction or "",
                    cf.evidence or "",
                    spec.attribution_notes or "",
                    spec.non_target_attribution or "",
                ]),
                concrete_loss=cf.concrete_loss,
                counterfactual=cf.counterfactual,
                finding_claim=spec.finding_claim,
            )
            repro.counterfactual_gate = gate.to_dict()
            repro.impact_blocker = "" if gate.p1_ok else gate.reason
            self._emit(
                "poc_prover",
                "lifecycle",
                {
                    "event": "counterfactual_gate",
                    "title": cf.title,
                    "p1_ok": gate.p1_ok,
                    "reason": gate.reason[:200],
                    "notes": gate.notes[:4],
                },
            )
        except Exception as exc:
            self._emit("poc_prover", "lifecycle", {"event": "runner_error", "detail": str(exc)})
            return None
        self._emit("poc_prover", "lifecycle",
                   {"event": "reproduction", "runner": repro.runner, "ran": repro.ran,
                    "reproduced": repro.reproduced, "command": repro.command[:200],
                    "detail": (repro.detail or "")[:200],
                    "impact_blocker": (getattr(repro, "impact_blocker", "") or "")[:200]})
        return repro

    _LOSS_TYPES = ("funds", "data", "control", "availability")

    def _impact_of(self, cf: ClaudeFinding, reproduced: bool, repro=None) -> "ImpactAssessment":
        """Build an ImpactAssessment from DERIVED facts — NOTHING PRESET. ``reproduced`` and
        ``in_scope`` are deterministic (runner + ScopeGuard). The concrete loss is whatever the
        agent itself STATED it demonstrated (cf.concrete_loss), not a keyword guess — if the agent
        could not articulate a concrete loss, it is 'none' and the finding is not auto-promoted to
        P1 (it stays a candidate for human review, which is the correct conservative behavior)."""
        if getattr(cf, "relies_on_non_target_behavior", False):
            return ImpactAssessment(
                reproduced=False, protected_asset=False, attacker_capability=False,
                concrete_loss="none", in_scope=not self._out_of_scope(cf.file),
                note="attribution gate: finding depends on non-target behavior",
            )
        gate = getattr(repro, "counterfactual_gate", None) if repro is not None else None
        if reproduced and isinstance(gate, dict) and not bool(gate.get("p1_ok")):
            band = str(gate.get("severity_band") or "low").lower()
            loss = str((gate.get("finding_claim") or {}).get("loss_type") or cf.concrete_loss or "").lower()
            loss = loss if loss in self._LOSS_TYPES else "none"
            if band == "high":
                protected_asset, attacker_capability, mapped_loss = True, False, (loss if loss != "none" else "control")
            elif band == "medium":
                protected_asset, attacker_capability, mapped_loss = True, False, "none"
            else:
                protected_asset, attacker_capability, mapped_loss = False, False, "none"
            return ImpactAssessment(
                reproduced=True,
                protected_asset=protected_asset,
                attacker_capability=attacker_capability,
                concrete_loss=mapped_loss,
                in_scope=not self._out_of_scope(cf.file),
                note=(f"counterfactual gate ({band}): " + str(gate.get("reason", "")))[:200],
            )
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
        attribution = getattr(repro, "target_code_attribution", "") or cf.target_code_attribution
        setup_attr = getattr(repro, "non_target_attribution", "") or cf.non_target_attribution
        attr_note = f" Target-owned defect: {attribution[:220]}." if attribution else ""
        setup_note = f" Non-target setup only: {setup_attr[:160]}." if setup_attr else ""
        artifact = ArtifactRef(
            id=new_id("art"), kind="repro",
            path=(arts[0] if arts else f"{cf.file}:{cf.line}"),
            description=(
                f"REPRODUCED by {getattr(repro, 'runner', 'runner')} runner via `{cmd}` — "
                f"{proof[:280]}{attr_note}{setup_note}"
            ),
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
        # Optional operational memory: keep runner/outcome metadata only. Do not persist the title,
        # root cause, counterfactual, lens, or any reusable failure pattern.
        if self._memory is not None:
            try:
                self._memory.record(
                    target_class=self._target_class, subclass=self._subclass,
                    finding={"severity": tier, "harness_kind": getattr(repro, "runner", ""),
                             "outcome": "confirmed_reproduced"})
            except Exception:
                pass
        return finding

    def _surface_for_human(self, cf: ClaudeFinding, rationale: str, severity_label: str,
                           guard: ScopeGuard, *, ran: bool, detail: str) -> Finding:
        """Build an AUTONOMOUS-FOLLOW-UP finding: believed-real + high-confidence + concrete-loss, but
        not auto-reproduced. Marked verified=False and given an UNreproduced artifact, so it never
        counts as a confirmed critical (the reproduced=confirmed floor is intact). It is surfaced
        prominently and kept in the exploit-depth queue precisely because the reasoning is strong and
        only the mechanical proof is missing."""
        why = ("ran but did not deterministically demonstrate the bug" if ran
               else "no runnable harness/toolchain to auto-reproduce")
        artifact = ArtifactRef(
            id=new_id("art"), kind="reasoned",
            path=f"{cf.file}:{cf.line}",
            description=f"NOT auto-reproduced ({why}); reasoned P1 queued for autonomous follow-up — {str(detail)[:240]}",
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
            severity_rationale=f"[{severity_label}] AUTONOMOUS FOLLOW-UP — believed real (high confidence, "
                               f"concrete loss: {cf.concrete_loss}) but not auto-reproduced yet. {rationale}",
            counterfactual=cf.counterfactual,
            remediation=cf.remediation or "Complete autonomous proof, then fix the root cause and add a regression test.",
            safe_harbor_attestation=guard.attestation(),
            verified=False,
        )

    def trigger_safety_event(self, reason: str) -> None:
        self._safety_event = True
        self._emit(self.name, "lifecycle", {"event": "safety_event", "reason": reason})

    def _result(self, status, plan, guard, findings, candidates, rounds, needs_human=None) -> HuntResult:
        return HuntResult(
            status=status, plan=plan, rounds_run=rounds, findings=findings,
            reframes=self._reframes, demoted_to_warm_pool=False, attestation=guard.attestation(),
            candidates=[c.__dict__ for c in candidates],
            needs_human=[getattr(f, "__dict__", f) for f in (needs_human or [])],
            brain=self.config.models.engine if self.config.use_claude else "deterministic",
        )


def _parse_json_object(text: str) -> dict:
    """Extract the first JSON object from an agent reply (fenced block or inline)."""
    import json
    import re

    if not text:
        return {}
    sources = re.findall(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    sources.append(text)
    decoder = json.JSONDecoder()
    found: list[dict] = []
    for raw in sources:
        for idx, ch in enumerate(raw):
            if ch != "{":
                continue
            try:
                d, _end = decoder.raw_decode(raw[idx:])
            except json.JSONDecodeError:
                continue
            if isinstance(d, dict):
                found.append(d)
    if not found:
        return {}
    return next((d for d in found if d.get("tracks")), found[0])
