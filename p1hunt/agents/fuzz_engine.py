"""Invariant + differential fuzzing engine (the P1-finding centerpiece).

Reading-based hunting converges on the textbook checklists auditors already closed. Mature
code yields its remaining bugs to SEARCH, not reasoning: define the invariants a system must
uphold, then let a fuzzer hammer the real code with randomized sequences until one breaks — or
drive identical random inputs through two implementations of the same logic (optimized vs a
reference/spec/older version) and flag any divergence. A violation arrives WITH a reproducing
counterexample, i.e. the PoC for free.

This module is language-agnostic by design (the prompt picks the harness for the target's own
toolchain — Foundry `invariant_*`/fuzz tests for Solidity, `go test -fuzz`, `cargo fuzz`,
Hypothesis/pytest, a property test for a web API). It degrades gracefully with no Claude brain
(returns nothing) so the offline test suite stays hermetic.
"""

from __future__ import annotations

import json
import re

from .claude_session import ClaudeFinding, ClaudeSession, EventEmit, SessionResult, make_session


_ATTRIBUTION_GATE = """ATTRIBUTION GATE (applies to EVERY fuzz finding):
The broken invariant must be caused by the in-scope target code/behavior. Do not report a finding
whose failure is only caused by your handler, mock, fixture, scaffold, local test config, fake token,
fork setup, external service, dependency not shipped/pinned by the target, or an integrator-only
implementation/obligation. A harness can drive hostile states, but the defect must be target-owned.
For each finding, separate target_code_attribution, non_target_attribution, and
relies_on_non_target_behavior."""


# --- deterministic forge-output parsing (unit-testable, no Claude needed) ------------------
_FAIL_LINE = re.compile(r"\[FAIL[^\]]*\]\s*(?P<name>[A-Za-z0-9_]+)")
_COUNTEREX = re.compile(r"(?:counterexample|Counterexample|args=)\s*[:=]?\s*(?P<args>[\[(].*?[\])])")
_INVARIANT = re.compile(r"invariant_[A-Za-z0-9_]+")


def parse_forge_output(text: str) -> list[dict]:
    """Extract failing tests + any counterexample/sequence forge printed. Pure function: feed it
    `forge test -vvv` output, get back the violations. Used to turn a fuzzer's run into findings
    even if the model's own JSON is sloppy."""
    if not text:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for m in _FAIL_LINE.finditer(text):
        name = m.group("name")
        if name in seen:
            continue
        seen.add(name)
        # grab a window after the failing test name for its counterexample/trace
        window = text[m.end(): m.end() + 600]
        cex = _COUNTEREX.search(window)
        out.append({
            "test": name,
            "is_invariant": bool(_INVARIANT.search(name)),
            "counterexample": (cex.group("args")[:300] if cex else ""),
            "detail": " ".join(window.split())[:280],
        })
    return out


def fuzz_prompt(
    subsystem: str,
    invariants: list[str],
    focus_files: list[str],
    *,
    differential: bool,
    reference_hint: str = "",
    known_patterns: list[str] | None = None,
    prior_counterexamples: list[str] | None = None,
    scaffold: str = "",
    fork_url: str = "",
    build_status: str = "",
    coverage_hint: str = "",
    entrypoints: list[str] | None = None,
    poc_reldir: str = ".p1hunt-poc",
) -> str:
    inv = "\n  - ".join(invariants) if invariants else "(derive the invariants yourself from the code)"
    files = "\n  - ".join(focus_files[:8]) if focus_files else "(find the relevant in-scope files)"
    # Preset-free mode: fuzzers get only Parent A's code-derived invariants and target files.
    patt = ""
    prior = (
        "\n\nAlready-tried fuzz harnesses that found nothing (vary the approach — new invariants, "
        "wider input ranges, longer sequences, different entrypoints):\n  - "
        + "\n  - ".join(prior_counterexamples[-8:])
        if prior_counterexamples else ""
    )
    # The build must be green or the harness can't deploy the real code — this is gated FIRST.
    build_block = ("\n\n🏗️ " + build_status + "\n") if build_status else ""
    # A concrete harness scaffold so the fuzzer reaches PAST gates (signatures/approvals) into
    # the value-moving logic instead of bouncing off the first check and covering nothing.
    scaffold_block_text = ("\n\n" + scaffold + "\n") if scaffold else ""
    ep_block = (
        "\n\nEXTERNAL ENTRYPOINTS to drive (the real attack surface): " + ", ".join(entrypoints[:14])
        if entrypoints else ""
    )
    cov_block = ("\n\n🎯 COVERAGE DIRECTIVE (from prior rounds): " + coverage_hint) if coverage_hint else ""
    fork_line = (
        f"\n   A LOCAL MAINNET FORK is available at {fork_url} — run against real on-chain token/"
        f"proxy state with `forge test --fork-url {fork_url} ...` so fee-on-transfer / rebasing / "
        "callback behavior is realistic, not mocked."
        if fork_url else ""
    )
    if differential:
        mode = (
            "MODE: DIFFERENTIAL FUZZING. A second implementation of this exact logic exists (a "
            f"reference/spec/older version). {reference_hint}\nDrive the SAME randomized inputs "
            "through BOTH the in-scope (optimized) implementation and the reference, and assert "
            "their observable results are IDENTICAL — return values, resulting state, AND "
            "error/throw-or-not (and the error where it matters). ANY divergence on any input is a "
            "real bug in the in-scope code (the reference is the oracle). Fuzz a WIDE input space: "
            "boundary values (zero, one, min/max of each type), empty/duplicate/degenerate inputs, "
            "exotic enum/variant values, and adversarial orderings/encodings. Make the fuzzer try "
            "to MANUFACTURE a divergence. (Use the scaffold above for the target's concrete shapes.)"
        )
    else:
        mode = (
            "MODE: STATEFUL INVARIANT FUZZING. Write a handler that calls the subsystem's real "
            "entrypoints with fuzzed arguments in random sequences, and assert the invariants below "
            "hold after EVERY call. Configure deep, high-run campaigns (many runs, long call "
            "sequences). A broken invariant with a counterexample sequence is a real finding."
        )
    return f"""You are an elite fuzzing engineer hunting a CRITICAL bug in the '{subsystem}' subsystem.
You do NOT guess — you SEARCH. Build a real fuzzing harness against the ACTUAL in-scope code and
run it until it either breaks an invariant (a finding, with the counterexample as proof) or you
have genuinely exhausted a wide input space (record what you covered).{build_block}
{mode}

Invariants this subsystem MUST uphold (break ANY of them = critical):
  - {inv}

Start from these in-scope files (use paths RELATIVE to the repo root):
  - {files}{ep_block}{patt}{prior}{cov_block}{scaffold_block_text}
METHOD (execution is the whole point):
0. FIRST make the target BUILD. If the build status above says it does not compile, fix that
   before anything else (fetch git submodules, resolve remappings, pin solc) — a harness that
   can't deploy the real code proves nothing. Then build your harness against the REAL contracts.
   If a tool you need is missing (forge/anvil, cmake, a compiler, a fuzzer), INSTALL it yourself —
   sudo package manager, pip/cargo/npm/go, or an official installer are all permitted.
1. Write a fuzzing/invariant harness in the target's OWN test framework into ./{poc_reldir}/ (this path
   is ALREADY inside the project's build/test tree, so the toolchain compiles & discovers it and imports
   resolve — do NOT write tests elsewhere or forge will report "No tests found") —
   for Solidity a Foundry test (a `Handler` contract + `invariant_*` functions, or a `testFuzz_*`/
   differential test); for Go `go test -fuzz`; for Rust `cargo fuzz`/`proptest`; for Python
   Hypothesis; for a web API a property-based request loop. Target the REAL contracts/functions,
   not a toy reimplementation. Use the SCAFFOLD above so you reach PAST gates (signatures, approvals)
   into the value-moving logic.
2. RUN it for real (e.g. `forge test --match-path '{poc_reldir}/X.t.sol' -vvv`, raising fuzz runs/
   depth via flags or a foundry.toml profile). Iterate until it COMPILES and actually fuzzes — fix
   harness bugs; a harness that doesn't run proves nothing.{fork_line}
3. Read the result. A FAILED invariant / divergence / failing assertion WITH a counterexample =
   a real finding; capture the exact counterexample (the inputs/sequence) — that IS your PoC.
   Distinguish a real protocol violation from a harness artifact (an unrealistic setup the protocol
   would never allow); only report real ones. If the whole campaign passes, the invariants HOLD on
   what you fuzzed — record the coverage so the next pass widens it.

{_ATTRIBUTION_GATE}

CONTEXT DISCIPLINE: don't read large files into your own context — DISPATCH SUB-AGENTS (Agent/Task
tool) to extract the exact function signatures/ABIs/struct layouts you need to build the harness,
then reason over their short summaries. Keep your own context for writing + running the harness.

Report ONLY JSON:
{{"findings": [{{"title": "...", "severity": "critical|high|medium", "lens": "{subsystem}",
   "file": "relative/path", "line": 123,
   "root_cause": "the invariant broken and why, citing the code",
   "reproduction": "the harness path + command + the counterexample inputs that break it",
   "counterfactual": "what an attacker achieves with this divergence/violation",
   "concrete_loss": "the loss actually demonstrated — funds|data|control|availability|none",
   "remediation": "the specific fix for THIS root cause (derived, not generic)",
   "confidence": "high|medium|low",
   "poc": "path to the harness under {poc_reldir} + command + the forge counterexample output proving it",
   "evidence": "the exact failing assertion + counterexample sequence from the run",
   "target_code_attribution": "the exact in-scope target behavior/file:line/function that owns the defect",
   "non_target_attribution": "what your handler/mocks/fixtures/fork setup supplied",
   "relies_on_non_target_behavior": false,
   "attribution_notes": "why this is target-owned and not a harness/setup artifact"}}],
 "coverage": ["<what input space / invariants you fuzzed and how deep, so the next pass widens it>"],
 "covered": ["<the exact entrypoints/functions your harness actually EXERCISED this round (so the next pass targets the dark ones)>"]}}
"findings" is [] if the campaign found no violation — that is a valid, useful result (record coverage)."""


class ClaudeFuzzer:
    """Generates and RUNS an invariant or differential fuzzing campaign against the real code.
    Its findings arrive with a forge counterexample, so they are high-signal — they still go
    through the Falsifier (to reject harness artifacts) before promotion."""

    def __init__(self, agent_name: str, *, model: str | None, on_event: EventEmit, guard_check,
                 max_turns: int = 34) -> None:
        self.agent_name = agent_name
        self.model = model
        self.on_event = on_event
        self.guard_check = guard_check
        self.max_turns = max_turns
        self._coverage: list[str] = []

    async def campaign(
        self, subsystem: str, invariants: list[str], focus_files: list[str], repo_path: str, *,
        differential: bool = False, reference_hint: str = "",
        known_patterns: list[str] | None = None,
        scaffold: str = "", fork_url: str = "", build_status: str = "",
        coverage_hint: str = "", entrypoints: list[str] | None = None,
        seeds: list[str] | None = None,
    ) -> tuple[list[ClaudeFinding], list[str], list[str]]:
        """Run one campaign. Returns ``(findings, coverage, covered_symbols)``.

        Findings are pre-backed by a counterexample run. ``coverage`` is what input-space/
        invariants were exercised (so the next pass widens), and ``covered_symbols`` are the
        entrypoints actually driven (so the orchestrator's corpus can steer the next pass at the
        still-dark code). ``seeds`` (prior counterexamples from the persistent corpus) and a
        ``coverage_hint`` (uncovered entrypoints) make rounds COMPOUND instead of re-exploring.
        """
        live: list[ClaudeFinding] = []

        def _sink(d: dict) -> None:
            cf = ClaudeFinding.from_dict(d, subsystem)
            live.append(cf)
            self.on_event(self.agent_name, "finding_reported",
                          {"title": cf.title, "severity": cf.severity, "file": cf.file, "line": cf.line,
                           "finding": cf.__dict__})

        session = make_session(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns, finding_sink=_sink,
            engine=getattr(self, "engine", None),
            effort=getattr(self, "codex_effort", None),
            codex_model=getattr(self, "codex_model", None),
            allow_web=False, perms=getattr(self, "perms", None),
            egress_hosts=getattr(self, "egress_hosts", None),
        )
        self.on_event(self.agent_name, "message",
                      {"phase": "fuzz", "subsystem": subsystem,
                       "mode": "differential" if differential else "invariant",
                       "invariants": len(invariants)})
        # Seed the "already tried / vary the approach" ledger with both this fuzzer's own prior
        # coverage and the persistent corpus seeds carried in by the orchestrator.
        prior = list(self._coverage)
        for s in (seeds or []):
            if s and s not in prior:
                prior.append(s)
        prompt = fuzz_prompt(subsystem, invariants, focus_files, differential=differential,
                             reference_hint=reference_hint, known_patterns=known_patterns,
                             prior_counterexamples=prior, scaffold=scaffold, fork_url=fork_url,
                             build_status=build_status, coverage_hint=coverage_hint,
                             entrypoints=entrypoints,
                             poc_reldir=getattr(self, "poc_reldir", ".p1hunt-poc"))
        res: SessionResult = await session.run(prompt, repo_path, lens=subsystem)
        parsed = _parse_obj(res.text)
        findings = list(live)
        keyed = {f"{f.file}:{f.line}:{f.title.lower()[:40]}": f for f in findings}
        for d in (parsed.get("findings") or []):
            try:
                cf = ClaudeFinding.from_dict(d, subsystem)
            except Exception:
                continue
            keyed.setdefault(f"{cf.file}:{cf.line}:{cf.title.lower()[:40]}", cf)
        for c in (parsed.get("coverage") or []):
            if isinstance(c, str) and c.strip() and c not in self._coverage:
                self._coverage.append(c.strip())
        self._coverage = self._coverage[-12:]
        covered = [str(c).strip() for c in (parsed.get("covered") or []) if str(c).strip()]
        return list(keyed.values()), self._coverage, covered


def _parse_obj(text: str) -> dict:
    m = re.search(r"\{.*\}", text or "", re.DOTALL)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return {}
