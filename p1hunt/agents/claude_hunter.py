"""Claude-backed hunting + adversarial verification (spec §7, §10).

NOTHING PRESET (§1, §2). Child B is NOT handed a hardcoded checklist or per-class playbook.
It hunts on a track whose theme, focus files, and investigation questions were *derived by
Parent A* from a cold reconnaissance of this specific target. The only fixed parts are
generic methodology (read the real code thoroughly, cite file:line, prefer a reproducible
critical) — no knowledge of the target or its bugs is injected. The Falsifier is a real
Claude session with the opposite prior that tries to refute each candidate.
"""

from __future__ import annotations

from .claude_session import ClaudeFinding, ClaudeSession, EventEmit, SessionResult, parse_ruled_out


def hunt_prompt(
    theme: str,
    critical_means: str,
    depth: int,
    prior_titles: list[str],
    focus_files: list[str] | None,
    investigate: list[str] | None,
    notices: list[str] | None = None,
    ruled_out: list[str] | None = None,
    directive: str | None = None,
    invariants: list[str] | None = None,
    known_patterns: list[str] | None = None,
    subsystem: str | None = None,
    scaffold: str = "",
    build_status: str = "",
) -> str:
    sub = subsystem or theme
    inv_block = (
        "\n\nINVARIANTS your subsystem MUST uphold (your job is to BREAK one — each is a concrete "
        "property a test/fuzzer can check):\n  - " + "\n  - ".join(invariants[:8])
        if invariants else ""
    )
    pattern_block = (
        "\n\n🧬 KNOWN BUG PATTERNS (from this protocol's history + its class — the old bugs are "
        "patched; hunt for a NEW VARIANT of each pattern in THIS code):\n  - "
        + "\n  - ".join(known_patterns[:10])
        if known_patterns else ""
    )
    steer = (
        f"\n\n🧭 YOUR LEAD (Parent A) REVIEWED THE TEAM'S PROGRESS AND GIVES YOU THIS DIRECTIVE "
        f"FOR THIS ROUND — follow it:\n{directive.strip()}"
        if directive and directive.strip()
        else ""
    )
    ledger = (
        "\n\nALREADY INVESTIGATED & RULED OUT in earlier passes (do NOT re-derive these — build "
        "BEYOND them. They are leads from your past self and MAY BE WRONG, so revisit any if you "
        "find new evidence):\n  - " + "\n  - ".join(ruled_out[-16:])
        if ruled_out
        else ""
    )
    notice_block = (
        "\n\n📨 OPERATOR NOTICES (new code or instructions are now available — ACT ON THESE and "
        "keep hunting; do not stop):\n  - " + "\n  - ".join(notices)
        if notices
        else ""
    )
    avoid = (
        "\nAlready reported by the team (find something NEW or a deeper/chained variant): "
        + "; ".join(prior_titles[-8:])
        if prior_titles
        else ""
    )
    coverage = (
        "\nFiles Parent A assigned to you (read them closely first, then follow callers/"
        "callees outward):\n  - " + "\n  - ".join(focus_files)
        if focus_files
        else ""
    )
    todo = (
        "\nParent A's scoping of THIS target flagged these things for you to investigate:\n  - "
        + "\n  - ".join(investigate)
        if investigate
        else ""
    )
    deepen = (
        ""
        if depth == 1
        else f"\nThis is investigation pass {depth}. The surface-level checks are done — go "
        "deeper: question the assumptions behind each security mechanism, and look for what "
        "only a careful second or third reading of the real code reveals."
    )
    build_block = ("\n\n🏗️ " + build_status) if build_status else ""
    scaffold_block_text = ("\n\n" + scaffold) if scaffold else ""
    return f"""You are a relentless, world-class security researcher who OWNS the '{sub}' subsystem of
this target end-to-end. PRIOR: assume a critical vulnerability EXISTS in your subsystem — keep
digging until you find it. You are not skimming the whole codebase; you go DEEP on YOUR subsystem:
build its COMPLETE invariant map, enumerate every external entrypoint and every state transition it
has, and attack each one until an invariant breaks.

Target: the code in the current working directory. Investigate the ACTUAL code with Grep, Glob,
read-only Bash, targeted Read, and SUB-AGENTS (no web — analyze the code, not the internet).
Cite real files and line numbers — never guess. Use paths RELATIVE to the current working directory (the repository root) — do not use
absolute paths or read outside the repo (those are blocked). You may write a proof-of-concept ONLY into ./.p1hunt-poc/ and run it with read-only-
safe Bash; never modify the target source and do nothing destructive.

What counts as critical here (Parent A's read of this system): {critical_means}{inv_block}{pattern_block}{steer}{notice_block}{ledger}{coverage}{todo}{deepen}{avoid}{build_block}{scaffold_block_text}

Method — REASON YOUR WAY TO THE BUG, then PROVE it. On hardened, heavily-audited code the remaining
criticals are SUBTLE: they are found by deep, adversarial REASONING about the actual logic, not by
spraying random inputs. Spend the MAJORITY of your effort reasoning:
 (1) Build the COMPLETE model of your subsystem — every external entrypoint, every state variable it
     touches, every invariant it must uphold, every trust/authorization boundary and assumption.
 (2) Trace the real value / authorization / data flows END TO END, across functions and across
     contracts. Ask concretely: what does each require/check/assert ASSUME, and can an attacker
     reach this state with that assumption violated? Where do two individually-correct pieces COMPOSE
     into an unsafe whole? What edge case did the auditors AND the reference implementation overlook
     — zero / type(max) / empty or duplicate arrays / a callback re-entering mid-update / rounding
     or precision / an aliased or dirty value / a check present on one path but missing on another /
     ordering between operations? Develop SEVERAL concrete, code-cited hypotheses and argue each both
     ways (why it WOULD be exploitable, and why it might not) — that argument is where the P1 lives.
 (3) For the strongest hypothesis, write a MINIMAL proof-of-concept in the target's own harness (a
     Foundry/forge test, pytest, go/cargo test, or an authenticated request) into ./.p1hunt-poc/ and
     RUN it against the REAL code. The RUN is the JUDGE: it CONFIRMS the bug your reasoning found, or
     disproves it — record a disproof in ruled_out and reason toward the next hypothesis. Reading and
     reasoning FIND the bug; the PoC run PROVES it (and a finding is only promoted once it reproduces).
Never declare "safe" or "exploitable" from reasoning alone — but understand that the reasoning is
where the critical actually comes from. Differential/invariant FUZZING runs SEPARATELY (a dedicated
fuzzer owns that search); reach for a quick property or differential check yourself only when your
reasoning points at one specific invariant worth searching around — do NOT turn your own session
into a blind fuzzing loop. Prefer ONE reasoned, PoC-proven critical over many shallow notes.

CONTEXT DISCIPLINE (critical — your context window is limited and you WILL stall if you fill it):
do NOT read large files into your own session. To study any file beyond a one-line grep, DISPATCH
A SUB-AGENT (the Agent/Task tool): tell it exactly what to read and to return ONLY the relevant
functions, line numbers, and logic for your hypothesis — then reason over its short summary.
Read directly yourself ONLY for tiny targeted confirmations (grep to find the line, then Read a
<=60-line window with offset/limit). Keep YOUR context lean for forming hypotheses, writing the
PoC, and the final report — never re-read whole files you've already seen.

As soon as you develop a CREDIBLE LEAD or suspected finding — even before you are 100% certain —
call the post_finding tool to record it to the shared blackboard (write-only; you cannot read it
back), then keep digging. Don't sit on leads: the Falsifier and the PoC prover downstream sort
real bugs from intended/guarded behavior and retract the false ones, so it is SAFE and expected to
post anything genuinely suspicious (medium confidence or higher) with its in-scope file:line — not
only slam-dunk criticals. Always also include every finding in your final JSON below.

Report ONLY a JSON object (no prose) with two keys:
{{"findings": [{{"title": "...", "severity": "critical|high|medium", "lens": "{theme}",
   "file": "relative/path", "line": 123,
   "root_cause": "why it is exploitable, citing the code",
   "reproduction": "safe, minimal steps to demonstrate (local/fork/UAT/owned only)",
   "counterfactual": "what an attacker can do BECAUSE of this bug that they could not before",
   "concrete_loss": "the loss you ACTUALLY demonstrate — one of funds|data|control|availability|none (none if no concrete loss yet)",
   "remediation": "the specific fix for THIS root cause (one line, derived from the code — not generic)",
   "confidence": "high|medium|low",
   "poc": "path to the PoC you wrote under .p1hunt-poc + the command to run it + what running it showed (the proof) — or 'static' if you could not yet run one",
   "evidence": "the exact code/flow + PoC run output that proves it"}}],
 "ruled_out": ["<one short line: what you investigated and why it is NOT exploitable — so the "
               "next pass skips it>", "..."]}}
"findings" may be [] if you found nothing solid. ALWAYS fill "ruled_out" with what you checked
this pass (the mechanisms you traced and dismissed, with the reason), so future passes go deeper
instead of re-deriving your dead-ends."""


def verify_prompt(f: ClaudeFinding) -> str:
    return f"""You are an adversarial Falsifier. PRIOR: this reported finding is WRONG until proven.
Investigate the code in the current working directory with Read/Grep/Glob/Bash and try to
REFUTE it. Is it actually reachable by an attacker? Is there a compensating control,
validation, or check that neutralizes it? Is the severity overclaimed? Is it intended
behavior?

Reported finding:
- title: {f.title}
- severity: {f.severity}
- location: {f.file}:{f.line}
- root cause: {f.root_cause}
- counterfactual: {f.counterfactual}

Default to refuted when uncertain. Reply ONLY with JSON:
{{"verdict": "real|refuted", "severity": "critical|high|medium|low",
  "reachable": true|false, "reason": "evidence from the code for your verdict"}}"""


class ClaudeHunter:
    def __init__(self, agent_name: str, *, theme: str, model: str | None, on_event: EventEmit, guard_check, max_turns: int = 28) -> None:
        self.agent_name = agent_name
        self.theme = theme
        self.model = model
        self.on_event = on_event
        self.guard_check = guard_check
        self.max_turns = max_turns
        # Per-round memory: a compact "investigated & ruled out" ledger carried into the next
        # round so this hunter doesn't re-walk its own dead-ends (anti-redundancy, not gospel).
        self._ruled_out: list[str] = []
        # Personalized steer written by Parent A between rounds after reviewing the team's
        # cross-track progress (set by ClaudeSwarm._resteer); empty on the first round.
        self._directive: str = ""
        # Deep subsystem ownership (Pillar 2): the mechanism this hunter owns + its invariants.
        self.subsystem: str = theme
        self.invariants: list[str] = []
        self.focus_files: list[str] = []
        self.investigate: list[str] = []

    async def hunt(
        self, critical_means: str, repo_path: str, depth: int, prior_titles: list[str],
        focus_files: list[str] | None = None, investigate: list[str] | None = None,
        notices: list[str] | None = None, invariants: list[str] | None = None,
        known_patterns: list[str] | None = None, subsystem: str | None = None,
        scaffold: str = "", build_status: str = "",
    ) -> SessionResult:
        # Live, write-only blackboard channel: when the hunter calls post_finding mid-session,
        # we record it and emit it immediately (it shows on the blackboard + Findings tab) — the
        # hunter has no way to read the board back.
        live: list[ClaudeFinding] = []

        def _sink(d: dict) -> None:
            cf = ClaudeFinding.from_dict(d, self.theme)
            live.append(cf)
            self.on_event(self.agent_name, "finding_reported",
                          {"title": cf.title, "severity": cf.severity, "file": cf.file, "line": cf.line})

        session = ClaudeSession(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns, finding_sink=_sink,
            allow_web=False,  # hunters analyze the code; no web (distraction + context bloat)
        )
        prompt = hunt_prompt(self.theme, critical_means, depth, prior_titles, focus_files,
                             investigate, notices, self._ruled_out, self._directive,
                             invariants=invariants, known_patterns=known_patterns,
                             subsystem=subsystem or self.subsystem,
                             scaffold=scaffold, build_status=build_status)
        self.on_event(self.agent_name, "message",
                      {"phase": "hunt", "lens": self.theme, "depth": depth, "focus": (focus_files or [])[:4]})
        res = await session.run(prompt, repo_path, lens=self.theme)
        # Union the live-posted findings with the final-JSON findings (dedup by location+title),
        # so a finding posted via the tool is never lost even if omitted from the final JSON.
        if live:
            keyed = {f"{f.file}:{f.line}:{f.title.lower()[:40]}": f for f in res.findings}
            for f in live:
                keyed.setdefault(f"{f.file}:{f.line}:{f.title.lower()[:40]}", f)
            res = SessionResult(ok=res.ok, text=res.text, findings=list(keyed.values()),
                                error=res.error, tool_calls=res.tool_calls)
        # Grow the ruled-out ledger for next round (deduped, capped to avoid prompt bloat).
        for note in parse_ruled_out(res.text):
            if note not in self._ruled_out:
                self._ruled_out.append(note)
        self._ruled_out = self._ruled_out[-16:]
        return res


class ClaudeVerifier:
    def __init__(self, agent_name: str, *, model: str | None, on_event: EventEmit, guard_check, max_turns: int = 18) -> None:
        self.agent_name = agent_name
        self.model = model
        self.on_event = on_event
        self.guard_check = guard_check
        self.max_turns = max_turns

    async def verify(self, finding: ClaudeFinding, repo_path: str) -> tuple[str, str, str]:
        """Returns (status, severity, reason) where status is 'real' | 'refuted' | 'unverified'.
        A transient/unparseable verification is 'unverified' — NOT 'refuted' — so real
        candidates are never silently dropped when the verifier session fails."""
        session = ClaudeSession(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
        )
        result = await session.run(verify_prompt(finding), repo_path, lens=finding.lens)
        if not result.ok:
            status, severity, reason = "unverified", finding.severity, f"verifier session failed: {result.error}"
        else:
            verdict = _parse_verdict(result.text)
            v = str(verdict.get("verdict", "")).lower()
            if v == "real" and verdict.get("reachable", True):
                status = "real"
            elif v == "refuted":
                status = "refuted"
            else:
                status = "unverified"  # no parseable verdict (transient) — keep the candidate
            severity = str(verdict.get("severity", finding.severity)).lower()
            reason = str(verdict.get("reason", "verifier returned no parseable verdict"))
        self.on_event(self.agent_name, "message",
                      {"verdict": status, "title": finding.title, "reason": reason[:200]})
        return status, severity, reason


def poc_prompt(f: ClaudeFinding) -> str:
    return f"""You are an exploit engineer. The finding below has ALREADY PASSED adversarial review
and is believed to be a REAL bug. Your job: PROVE it dynamically by building the smallest possible
proof-of-concept and ACTUALLY RUNNING it against the real target code.

Finding:
- title: {f.title}
- severity: {f.severity}
- location: {f.file}:{f.line}
- root cause: {f.root_cause}
- counterfactual (what the attacker gains): {f.counterfactual}
- reproduction idea: {f.reproduction}

Rules:
- Write PoC files ONLY into ./.p1hunt-poc/ . NEVER modify the target source; nothing destructive.
- Use read-only-safe Bash to compile/test/fuzz the ACTUAL target (e.g. forge test, go test, pytest,
  cargo test, gcc). Build a minimal harness that triggers the bug and RUN it.
- A real PoC executes and demonstrates the counterfactual (value moved, check bypassed, invariant
  broken) — not a description, an actual run.

Then judge HONESTLY — this is the whole point:
- PoC reproduces the bug  -> "proven".
- After a genuine attempt it does NOT reproduce (the code actually guards it, or the behavior is
  intended/safe) -> "not_reproduced", and state exactly why. This is valuable: it means the static
  review was fooled, and we must DROP the finding.
- You genuinely cannot build a harness (missing toolchain/deps) -> "inconclusive".

Reply ONLY with JSON:
{{"verdict": "proven|not_reproduced|inconclusive",
  "summary": "what you built, what running it showed, and why it proves/disproves the bug",
  "poc_path": "relative path to your PoC under .p1hunt-poc/, or ''"}}"""


def materialize_prompt(f: ClaudeFinding, scaffold: str = "", fork_url: str = "") -> str:
    scaffold_block = ("\n\nUse this class-appropriate scaffold as your starting point:\n" + scaffold) if scaffold else ""
    fork_note = (f"\nA local fork is available at {fork_url} (use it if the harness needs real on-chain state)."
                 if fork_url else "")
    return f"""You are an exploit engineer. The finding below passed adversarial review and is BELIEVED real.
Do NOT judge whether it works — a DETERMINISTIC runner will execute your harness and decide. Your ONE job is
to MATERIALIZE a real, runnable proof HARNESS on disk that the runner can execute unattended.

Finding:
- title: {f.title}
- location: {f.file}:{f.line}
- root cause: {f.root_cause}
- counterfactual (what the attacker gains): {f.counterfactual}
- reproduction idea: {f.reproduction}{scaffold_block}{fork_note}

Rules:
- Actually CREATE the harness file(s) with the Write tool under ./.p1hunt-poc/ . Make a COMPLETE, runnable
  harness against the REAL in-scope code (compiles/loads, drives the real entrypoints) — not a sketch or a
  description. You MAY run it once locally to shake out build errors; the runner makes the official verdict.
- Decide the EXPECT semantics precisely: "fail" if a reproduced bug makes the harness test FAIL (invariant /
  property / differential style — the assertion of correctness breaks), or "pass" if a reproduced bug makes
  an exploit assertion PASS (the attack succeeded).

Reply ONLY with a JSON object describing what you materialized (no prose):
{{"harness_path": "<relative path under .p1hunt-poc to the file the runner should execute>",
  "kind": "invariant|fork|differential|call-sequence|exploit|property|policy",
  "expect": "fail|pass",
  "test_name": "<the specific test/function to target, or ''>",
  "command": "<the command you would run; advisory only — the runner derives its own>",
  "notes": "<what the harness does and why its outcome proves the bug>"}}"""


class ClaudePoCProver:
    """Runs ONLY after the Falsifier believes a finding is real. Its job is to MATERIALIZE a real,
    runnable proof harness into the sandbox (and declare a ReproSpec); a deterministic class runner
    then EXECUTES it and decides reproduction. (``prove`` — the older self-judging path — is kept
    for callers that want a one-shot Claude verdict, but the swarm uses ``materialize`` + a runner.)"""

    def __init__(self, agent_name: str, *, model: str | None, on_event: EventEmit, guard_check, max_turns: int = 26) -> None:
        self.agent_name = agent_name
        self.model = model
        self.on_event = on_event
        self.guard_check = guard_check
        self.max_turns = max_turns

    async def materialize(self, finding: ClaudeFinding, repo_path: str, *,
                          scaffold: str = "", fork_url: str = "") -> dict | None:
        """Write a runnable harness into the sandbox and return a ReproSpec dict (or None on
        failure). The deterministic runner — not this session — decides reproduction."""
        self.on_event(self.agent_name, "message",
                      {"phase": "materialize", "title": finding.title, "file": finding.file})
        session = ClaudeSession(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
        )
        result = await session.run(materialize_prompt(finding, scaffold, fork_url), repo_path, lens=finding.lens)
        if not result.ok:
            self.on_event(self.agent_name, "lifecycle",
                          {"event": "materialize_failed", "title": finding.title, "detail": result.error})
            return None
        spec = _parse_verdict(result.text)
        if not spec or not spec.get("harness_path"):
            self.on_event(self.agent_name, "lifecycle",
                          {"event": "materialize_empty", "title": finding.title})
            return None
        self.on_event(self.agent_name, "message",
                      {"verdict": "harness materialized", "title": finding.title,
                       "harness": str(spec.get("harness_path", ""))[:160], "expect": spec.get("expect", "")})
        return spec

    async def prove(self, finding: ClaudeFinding, repo_path: str) -> tuple[str, str, str]:
        """Returns (verdict, summary, poc_path); verdict ∈ proven | not_reproduced | inconclusive."""
        self.on_event(self.agent_name, "message",
                      {"phase": "poc", "title": finding.title, "severity": finding.severity})
        session = ClaudeSession(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
        )
        result = await session.run(poc_prompt(finding), repo_path, lens=finding.lens)
        if not result.ok:
            return "inconclusive", f"PoC session failed: {result.error}", ""
        d = _parse_verdict(result.text)
        verdict = str(d.get("verdict", "inconclusive")).lower().strip()
        if verdict not in ("proven", "not_reproduced", "inconclusive"):
            verdict = "inconclusive"
        summary = str(d.get("summary", ""))
        self.on_event(self.agent_name, "message",
                      {"verdict": f"PoC {verdict}", "title": finding.title, "reason": summary[:200]})
        return verdict, summary, str(d.get("poc_path", ""))


def _parse_verdict(text: str) -> dict:
    import json
    import re

    m = re.search(r"\{.*\}", text or "", re.DOTALL)
    if not m:
        return {}  # caller treats a missing verdict as 'unverified', not 'refuted'
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return {}
