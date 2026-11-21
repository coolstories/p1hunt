"""Prompt-role wrappers for hunting + adversarial verification (spec §7, §10).

NOTHING PRESET (§1, §2). Child B is NOT handed a hardcoded checklist or per-class playbook.
It hunts on a track whose theme, focus files, and investigation questions were *derived by
Parent A* from a cold reconnaissance of this specific target. The only fixed parts are
generic methodology (read the real code thoroughly, cite file:line, prefer a reproducible
critical) — no knowledge of the target or its bugs is injected. The runtime engine is selected
through ``make_session``; Codex is the default for every role.
"""

from __future__ import annotations

from .claude_session import (ClaudeFinding, ClaudeSession, EventEmit, SessionResult,
                             make_session, parse_ruled_out, response_truncated)
from .instructions import authorized_role


_ATTRIBUTION_GATE = """ATTRIBUTION GATE (applies to EVERY finding):
The root cause must be owned by the in-scope target under test. A harness may drive the target, mock
neighbors, create fixtures, choose hostile inputs, or simulate protocol peers, but the DEFECT cannot
be in the harness, mock, fixture, scaffold, local test config, fake service, external dependency not
shipped/pinned by the target, operator account setup, deployment assumption, or an integrator-only
implementation/obligation. If the exploit only works because of behavior you supplied outside the
target, it is NOT a confirmed target finding; report it as a candidate/blocker.

For every finding/proof, explicitly separate:
- target_code_attribution: the exact in-scope target behavior/file:line/endpoint that is defective.
- non_target_attribution: what the harness/mocks/fixtures/external setup did, and why that is not
  the defect.
- relies_on_non_target_behavior: true if the attacker win depends on non-target behavior or an
  assumption outside the target; those cannot be promoted as confirmed target bugs."""


_FINDING_CLAIM_JSON = '''"finding_claim": {"attacker_model": "who the attacker is under the program trust model",
    "attacker_controls": "inputs/calls/roles/material the attacker controls",
    "attacker_does_not_control": "honest secret/resource/authorization/state the attacker does NOT control",
    "trust_boundary": "the target trust boundary crossed",
    "honest_victim": "the honest party/account/key/tenant/resource owner harmed",
    "honest_secret_or_resource": "the protected secret/resource/authority defeated",
    "precommitted_value": "valuable target state that existed before the exploit",
    "victim_state_before": "victim/protected state before exploit",
    "victim_state_after": "victim/protected state after exploit",
    "absent_bug_expected_behavior": "what target code should have done without the bug",
    "loss_type": "funds|data|control|availability|none",
    "exploit_path": "short end-to-end attacker path from input to victim-state delta"}'''


def _engine_kwargs(owner, *, discovery: bool = False) -> dict:
    """Return explicit engine args for a prompt-role wrapper."""
    engine = getattr(owner, "discovery_engine", None) if discovery else getattr(owner, "engine", None)
    return {
        "engine": engine,
        "effort": getattr(owner, "codex_effort", None),
        "codex_model": getattr(owner, "codex_model", None),
    }


# Built once at import: the authorization framing each model-facing prompt leads with.
# See instructions.authorized_role for why this must come first.
_ROLE_WEB_HUNT = authorized_role(
    "the testing role",
    live=True,
    deliverable="a runnable proof harness plus the exact requests that demonstrate the issue")
_ROLE_WEB_MAP = authorized_role(
    "the reconnaissance role",
    live=True,
    deliverable="an accurate map of the application's surface and the questions worth settling")
_ROLE_SRC_HUNT = authorized_role(
    "the code-review role",
    live=False,
    deliverable="a specific, file-anchored weakness with a reproducible demonstration")
# THE PROVE CHAIN. Added after a measured probe: these four were the only model-facing
# prompts still opening bare, and three of them (falsifier, materialize, repair) were the
# three the Claude engine accepted at the gate and then STOPPED PART-WAY -- which for a
# role that must emit parseable JSON or finish writing a harness contributes nothing.
#
# Their old openers also oversold what they are: "exploit engineer", "WORLD-CLASS exploit
# developer and cryptanalyst". The actual job is narrower and more defensible -- take one
# believed finding and either break it or produce a harness a deterministic runner can
# execute -- and saying so plainly is both accurate and what the framing needs.
_ROLE_FALSIFY = authorized_role(
    "the verification role",
    live=True,
    deliverable="an honest verdict on whether this reported weakness is real, with the "
                "evidence that settles it either way")
_ROLE_FALSIFY_SRC = authorized_role(
    "the verification role",
    live=False,
    deliverable="an honest verdict on whether this reported weakness is real, with the "
                "evidence that settles it either way")
_ROLE_PROVE = authorized_role(
    "the proof role",
    live=False,
    deliverable="a runnable harness that demonstrates the weakness, so a defender can "
                "confirm the fix")
_ROLE_DEPTH = authorized_role(
    "the proof-depth role",
    live=False,
    deliverable="a demonstration of how far this weakness actually reaches, so its "
                "severity is a measured fact rather than a guess")
_ROLE_SRC_MAP = authorized_role(
    "the code-mapping role",
    live=False,
    deliverable="an accurate model of this subsystem's entrypoints, state and trust "
                "boundaries, and the questions worth settling about them")
# The triage roles. Lower risk -- they weigh an existing finding rather than probe a
# system -- but framed too, because the cost of being wrong about that is a dead role and
# the cost of the framing is nothing. Measured by bench/probe_refusal.py like the rest.
_ROLE_TRIAGE = authorized_role(
    "the finding-triage role",
    live=False,
    deliverable="a correct duplicate/not-duplicate decision, so the same weakness is not "
                "reported twice")
_ROLE_JUDGE = authorized_role(
    "the adjudication role",
    live=False,
    deliverable="a defensible severity decision on a finding two reviewers disagree about")


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
    static_leads: list[str] | None = None,
    model: str = "",
    allow_web: bool = False,
    poc_reldir: str = ".p1hunt-poc",
) -> str:
    sub = subsystem or theme
    model_block = (
        "\n\n🧠 YOUR ACCUMULATED MODEL of this subsystem (built in your mapping pass and DEEPENED "
        "every round — this is your memory, so you never re-derive: ATTACK from it, and as you learn "
        "more, CORRECT and EXTEND it in `model_update` below):\n" + model.strip()
        if model and model.strip() else ""
    )
    web_block = (
        "\n\nWEB (limited — for TECHNIQUE, never the answer): you MAY use WebSearch/WebFetch to "
        "understand the SPEC, a cryptographic/protocol PRIMITIVE, public API behavior, or tooling "
        "needed to read this system correctly. The web does NOT contain the bug for THIS "
        "target — do NOT search for this program's prior disclosures/CVEs/'<product> vulnerabilities', "
        "do NOT research historical vulnerability classes for the target or its peers, and do NOT "
        "use the web as somewhere to go when stuck. A few searches at most; then return to the code. "
        "The vulnerability is found in the ACTUAL code, by YOU."
        if allow_web else ""
    )
    # Preset-free mode: callers may keep passing this argument for API compatibility, but static
    # scanner hits are never rendered into the hunter prompt. Parent A must derive all real leads.
    leads_block = ""
    inv_block = (
        "\n\nINVARIANTS your subsystem MUST uphold (your job is to BREAK one — each is a concrete "
        "property a test/fuzzer can check):\n  - " + "\n  - ".join(invariants[:8])
        if invariants else ""
    )
    # Preset-free mode: never render known failure-pattern feeds into hunter prompts.
    pattern_block = ""
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
    return f"""{_ROLE_SRC_HUNT}
You OWN the '{sub}' subsystem of
this target end-to-end. PRIOR: assume a critical vulnerability EXISTS in your subsystem — keep
digging until you find it. You are not skimming the whole codebase; you go DEEP on YOUR subsystem:
build its COMPLETE invariant map, enumerate every external entrypoint and every state transition it
has, and attack each one until an invariant breaks.

Target: the code in the current working directory. Investigate the ACTUAL code with Grep, Glob,
read-only Bash, targeted Read, and SUB-AGENTS (no web — analyze the code, not the internet).
Cite real files and line numbers — never guess. Use paths RELATIVE to the current working directory (the repository root) — do not use
absolute paths or read outside the repo (those are blocked). You may write a proof-of-concept ONLY into ./{poc_reldir}/ (already inside the
project's build/test tree so the toolchain compiles & discovers it — for Foundry: `forge test --match-path '{poc_reldir}/<file>.t.sol'`) and run it with read-only-
safe Bash; never modify the target source and do nothing destructive.
TOOLS: if a tool you need is not installed (a compiler, cmake, a static analyzer like slither/
mythril/semgrep, a fuzzer, Foundry, a language toolchain), just INSTALL it yourself — the system
package manager (sudo apt/brew/yum), pip/pipx/cargo/npm/go, or an official installer script are all
permitted. Provision what the audit needs, then use it.

What counts as critical here (Parent A's read of this system): {critical_means}{model_block}{inv_block}{pattern_block}{leads_block}{steer}{notice_block}{ledger}{coverage}{todo}{deepen}{avoid}{web_block}{build_block}{scaffold_block_text}

Method — REASON ADVERSARIALLY TOWARD AN ATTACKER WIN, then PROVE it. THE TRAP TO AVOID: confirming
the code is INTERNALLY CONSISTENT ("the math checks out", "the logic is correct", "there's a check
here") and concluding it is safe. CORRECT ≠ SAFE. A faithful implementation of a flawed rule, or a
perfectly-correct computation handed an input the ATTACKER chose, still loses funds / control / data.
(Trivial illustration of the WRONG conclusion: a withdraw() whose arithmetic is provably correct can
still let a caller pass amount = -100 and CREDIT their own balance — the math was never the question;
the attacker's control over the input was.) So never reason from "is this code correct"; reason from
"can the attacker WIN". Spend the MAJORITY of your effort here:
 (1) State the attacker's WIN conditions for this subsystem and the PROTECTED QUANTITIES that must
     never move the wrong way (who owns what; what must conserve; who is allowed to do what). Build
     the complete model: every external entrypoint, every ATTACKER-CONTROLLED input, every state
     variable touched, every trust/authorization boundary — and what assumption each check RELIES ON.
 (2) For each entrypoint, reason from the position of someone trying to misuse it. Take
     every input to the worst value its type/encoding/protocol still ACCEPTS — negative / zero / min / max, out-of-domain, aliased or
     duplicated, malformed, reordered, replayed, stale, or a value that is individually "valid" but
     hostile in context — and trace it END TO END to a protected quantity. The question for every
     check is not "is it correct" but "does it actually CONSTRAIN this hostile value to the domain
     the rest of the logic silently assumes, BEFORE it moves a protected quantity, on EVERY reachable
     path?" Look for: where two individually-correct pieces COMPOSE into an unsafe whole; where the
     INTENT itself is exploitable (not just its implementation); a check present on one path but
     missing on another; ordering / reentrancy / precision / signedness / domain assumptions. Develop
     SEVERAL concrete, code-cited hypotheses and, for each, argue concretely whether the attacker can
     reach the win or is genuinely blocked — that argument is where the P1 lives.
 (2b) BREAK A GUARANTEE — do NOT pattern-match known bug shapes (that only finds bugs you already
     know; a real P1 is usually a class you didn't anticipate). Every component PROMISES something:
     DERIVE what THIS one must guarantee from what it IS and what its callers/tests rely on — the
     security properties an attacker must never break (you know the definitions: e.g. a proof must be
     sound AND reveal nothing about its witness; a commitment must bind AND hide; a signature must be
     unforgeable + non-malleable; a value meant to be unique/unpredictable must stay so; a secret/share
     must never leak). Pick ONE guarantee, write the implicit argument for WHY it holds HERE, then find
     the exact step in that argument that does NOT actually hold in the code — testing it under EVERY
     condition the attacker controls: all input values, ordering, REPETITION/replay of the same call,
     concurrency, partial/malicious participation, and the full value-domain of every field. The gap
     between the promised property and the implementation is where the critical lives; the bug CLASS is
     whatever that gap turns out to be. Read the TESTS too — they encode the contract (what's guarded vs
     permitted) and reveal which guarantees the authors did and did not enforce.
 (3) For the strongest hypothesis, write a MINIMAL proof-of-concept in the target's own harness (a
     Foundry/forge test, pytest, go/cargo test, or an authenticated request) into ./{poc_reldir}/ and
     RUN it against the REAL code. The RUN is the JUDGE: it CONFIRMS the bug your reasoning found, or
     disproves it — record a disproof in ruled_out and reason toward the next hypothesis. Reading and
     reasoning FIND the bug; the PoC run PROVES it (and a finding is only promoted once it reproduces).
 (4) DO NOT SELF-DISMISS. A hypothesis that touches a protected quantity (value, ownership, authorization,
     signatures) which you could NOT actually DISPROVE with a runnable PoC is INCONCLUSIVE, not safe —
     report it as a finding (the Falsifier + deterministic runner are the judges, not your prose). Only
     move a lead to ruled_out when a RUN disproved it, or you can cite the exact line+argument that makes
     the attacker-win unreachable. "The math checks out" / "this is cryptographically sound" / "the code
     enforces this" are NOT disproofs. If forge can't run your harness, FIX the harness (it goes under
     ./{poc_reldir}/, which IS in the build tree) — never downgrade a real lead to "safe" because tooling failed.
Never call something "safe" because the logic is correct or a check exists: "safe" requires showing
the attacker CANNOT reach any win — that every attacker-controlled input is constrained on every
path. If you cannot show that, you have a lead, not a clean bill of health. Differential/invariant
FUZZING runs SEPARATELY (a dedicated
fuzzer owns that search); reach for a quick property or differential check yourself only when your
reasoning points at one specific invariant worth searching around — do NOT turn your own session
into a blind fuzzing loop. Prefer ONE reasoned, PoC-proven critical over many shallow notes.

CONTEXT + TOKEN DISCIPLINE (critical — your context window is limited and you WILL stall if you fill it):
do NOT read large files into your own session. To study any file beyond a one-line grep, DISPATCH
A SUB-AGENT (the Agent/Task tool): tell it exactly what to read and to return ONLY the relevant
functions, line numbers, and logic for your hypothesis — then reason over its short summary.
Read directly yourself ONLY for tiny targeted confirmations (grep to find the line, then Read a
<=60-line window with offset/limit). Keep YOUR context lean for forming hypotheses, writing the
PoC, and the final report — never re-read whole files you've already seen. Your `model_update`
must be compact working memory, not a transcript: keep cited entrypoints, state/trust boundaries,
attacker-controlled inputs, invariants, open attack threads, PoC/blockers, and new deltas only.
Do not paste source code, command output, or repeated prose into `model_update`.

As soon as you develop a CREDIBLE LEAD with concrete evidence, call the post_finding tool to record
it to the shared blackboard (write-only; you cannot read it back), then keep digging. Do NOT post a
bare hunch: first do a focused depth check, cite the exact sink/endpoint/file:line, try the smallest
safe PoC/escalation path you can, and state what still blocks confirmed-critical status. The
blackboard post is a CANDIDATE for Parent A's verifier/prover/deep-dive pipeline, not a confirmed
finding. Always also include every finding in your final JSON below.

{_ATTRIBUTION_GATE}

Report ONLY a JSON object (no prose) with two keys:
{{"findings": [{{"title": "...", "severity": "critical|high|medium", "lens": "{theme}",
   "file": "relative/path", "line": 123,
   "root_cause": "why it is exploitable, citing the code",
   "reproduction": "safe, minimal steps to demonstrate (local/fork/UAT/owned only)",
   "counterfactual": "what an attacker can do BECAUSE of this bug that they could not before",
   "concrete_loss": "the loss you ACTUALLY demonstrate — one of funds|data|control|availability|none (none if no concrete loss yet)",
   "remediation": "the specific fix for THIS root cause (one line, derived from the code — not generic)",
   "confidence": "high|medium|low",
   "poc": "path to the PoC you wrote under {poc_reldir} + the command to run it + what running it showed (the proof) — or 'static' if you could not yet run one",
   "evidence": "the exact code/flow + PoC run output that proves it",
	   "target_code_attribution": "the in-scope target-owned behavior/file:line/endpoint that is actually defective",
	   "non_target_attribution": "what your harness/mocks/fixtures/external setup supplied, and why that is not the defect",
	   "relies_on_non_target_behavior": false,
	   "attribution_notes": "one sentence separating target-owned defect from test harness/setup assumptions",
	   {_FINDING_CLAIM_JSON}}}],
 "ruled_out": ["<one short line: what you investigated and why it is NOT exploitable — so the "
               "next pass skips it>", "..."],
 "model_update": "<compact carried-forward memory, max ~5000 chars: cited entrypoints/state/trust "
                 "boundaries/attacker inputs/invariants, attacks tried + outcomes, open threads, "
                 "current best hypothesis, and exact blockers. Deltas only; no pasted source/output.>"}}
"findings" may be [] if you found nothing solid. ALWAYS fill "ruled_out" with what you checked
this pass, AND ALWAYS fill "model_update" so future passes go DEEPER instead of re-deriving."""


def web_hunt_prompt(
    theme: str,
    critical_means: str,
    *,
    base_urls: list[str],
    egress_hosts: list[str],
    identities: list[str],
    oob_available: bool,
    depth: int,
    prior_titles: list[str] | None = None,
    ruled_out: list[str] | None = None,
    directive: str | None = None,
    notices: list[str] | None = None,
    scope_note: str = "",
    poc_reldir: str = ".p1hunt-poc",
) -> str:
    """Black-box / gray-box WEB-APP pentest methodology for a LIVE authorized target (XBOW-style).

    Used instead of the source-reasoning hunt_prompt when the engagement has an authorized live HTTP
    target. Emits the SAME findings JSON shape so the verify→PoC→reproduce pipeline is unchanged; for
    a web finding ``file`` carries the endpoint/URL and ``line`` is 0."""
    hosts = ", ".join(egress_hosts) or "(the authorized in-scope hosts)"
    urls = "\n  - ".join(base_urls) if base_urls else "(see the scope)"
    ids = ", ".join(identities) if identities else "none supplied (set P1HUNT_TOKEN_A / P1HUNT_TOKEN_B to test authz)"
    oob = ("An OOB listener is RUNNING — use p1hunt_dyn.oob_url(token)/oob_received(token) to CONFIRM "
           "callback-based behavior (the proof is the target calling back)."
           if oob_available else "No OOB listener this run — prefer in-band proofs.")
    prior = ("\nAlready reported (do not repeat): " + "; ".join((prior_titles or [])[:12])) if prior_titles else ""
    rl = ("\nAlready RULED OUT (skip): " + "; ".join((ruled_out or [])[:14])) if ruled_out else ""
    steer = ("\n\n🧭 PARENT A'S DIRECTIVE FOR THIS ROUND (do this first): " + directive) if directive else ""
    notice = ("\n\n📨 OPERATOR NOTICES: " + " | ".join(notices)) if notices else ""
    note = ("\n\nRULES OF ENGAGEMENT (from the program): " + scope_note) if scope_note else ""
    # The authorization preamble goes FIRST. Every one of this prompt's five hunter
    # sessions was refused by the provider's safety classifier in a measured run; the
    # fix is the framing, and the swagger that used to open this prompt ("elite
    # bug-bounty pentester", "think top-of-the-leaderboard autonomous hacker") bought
    # nothing operationally while reading exactly like a jailbreak. See
    # instructions.authorized_role.
    return f"""{_ROLE_WEB_HUNT}
You own the '{theme}' angle of this assessment. Round {depth}.

AUTHORIZED LIVE TARGET(S):
  - {urls}
In-scope hosts (every request is HARD-CONFINED to these by an egress jail — anything else is blocked
before a packet leaves): {hosts}
Test identities available: {ids}
{oob}{note}{steer}{notice}{prior}{rl}

BLACK-BOX MODE: this is not a source repository audit. Do not spend turns on `git ls-files`,
`git remote`, broad `rg --files`, or backend source mapping unless you have first harvested a real
source artifact such as JS/OpenAPI/docs from the live target. The durable evidence is request/response
behavior and repeatable PoC scripts under ./{poc_reldir}/.

SAFE HARBOR — NON-NEGOTIABLE (you are a guest on a real system):
 - Touch ONLY in-scope hosts. Never an out-of-scope host, never a third party.
 - NON-DESTRUCTIVE ONLY: no DELETE of others' data, no account takeover beyond minimal proof, no
   mass actions, no spam, no data exfiltration beyond the few bytes needed to PROVE the bug.
 - NO DoS / NO load testing / NO aggressive brute-force. Respect rate limits; throttle. A scanner
   you run must be rate-limited and pointed only at in-scope hosts.
 - Use ONLY your own test accounts / synthetic data. Minimize blast radius. Stop if you might harm.

YOUR TOOLBELT:
 - A scope-ENFORCED HTTP client is shipped into ./{poc_reldir}/p1hunt_dyn.py — `from p1hunt_dyn import
   Client`. It gives multi-identity sessions, differential refusal helpers, input-behavior oracles
   (timing/boolean/reflection), and OOB confirmation. Every request it makes is scope-checked.
   PREFER it for proofs.
 - You may INSTALL and run standard assessment tooling, ONLY against in-scope hosts and
   rate-limited: httpx, nuclei (safe templates), ffuf/feroxbuster (gentle), katana/gau/waybackurls
   (endpoint discovery), subfinder/amass (subdomain enum — keep results in-scope), gf, jwt_tool, sqlmap
   (--level low, never --dump of real data), graphql introspection. The egress jail confines them too.

METHOD — RECON → MODEL → ATTACK-TO-WIN → PROVE (spend most effort on attack + proof):
 1. RECON the attack surface of the in-scope hosts: live subdomains, endpoints, parameters, HTTP
    methods, content types, auth flows, roles, cookies/JWTs, GraphQL schema (introspection),
    JS bundles (extract API routes, hidden endpoints, secrets/keys), error pages, headers, CORS.
    Build a concrete map: for each endpoint — who SHOULD be allowed to do what, and what
    object IDs / tenants / roles exist.
 2. For the '{theme}' angle, reason from the position of someone who wants to misuse this
    application, and look for outcomes that would matter, not checklist items.
    Derive the win conditions from the real app map and the program rubric: which principals exist,
    what objects/resources/funds/privileges each should control, which workflows change state, where
    the server consumes attacker-chosen data, and what outcome would cross the program's critical bar.
   What "critical" means for this program: {critical_means}
 3. CORRECT ≠ SAFE: a 200 OK or a working feature is not safety. Reason "can the attacker WIN" —
    e.g. an endpoint that faithfully returns a record is a CRITICAL if it returns ANOTHER user's
    record for an attacker-chosen id. Develop several concrete, request-cited hypotheses per pass.
 4. PROVE the strongest one DETERMINISTICALLY against the LIVE target. Write a runnable harness under
    ./{poc_reldir}/ — a pytest using p1hunt_dyn (e.g. one principal is unexpectedly permitted on
    another principal's resource, or `oob_received(token)` is True after the request). The RUN is
    the JUDGE. A real PoC shows the win (unauthorized data/control moved; the callback fired; a
    protected workflow accepted an impossible state) — not a description.
 5. DO NOT SELF-DISMISS. A real-impact hypothesis you could not DISPROVE with a run is INCONCLUSIVE,
    not safe — report it (the verifier + runner judge). Record genuine disproofs in ruled_out.

LIVE-WEB CLOSURE GATE:
 - A timeout, refused TCP connection, blocked route, missing token, or absent concrete app URL is a
   BLOCKER, not a disproof of the vulnerability class. Do not write "ruled out" as if target
   behavior was proven safe when no HTTP response or authenticated flow was observed.
 - Before closing an exact-URL HTTP track, perform a bounded deep pass against ONLY the authorized
   URL(s): baseline GET/HEAD, safe OPTIONS where allowed, method comparison, Host-preserved request,
   Connection: close, Accept-Encoding: identity, a single Range or conditional request if safe,
   HTTP/1.0 vs HTTP/1.1 when useful, explicit port/scheme comparison, route/proxy evidence, and
   paired-endpoint comparison when multiple exact URLs are in scope.
 - If that pass still produces no application response, put it in model_update as a transport or
   vantage blocker with the exact next evidence needed. Do not post low findings for "no response"
   and do not spend the rest of the run congratulating a timeout.

You may POST a strong finding mid-pass via the blackboard tool after a focused depth check or the
moment a PoC demonstrates the win. Include the request/PoC evidence, attempted escalation, and any
blocker that prevents confirmed-critical status.

{_ATTRIBUTION_GATE}

Reply ONLY with JSON (same shape the pipeline expects):
{{"findings": [{{"title": "...", "severity": "critical|high|medium", "lens": "{theme}",
   "file": "<the vulnerable URL/endpoint, e.g. https://host/api/v2/orders/{{id}}>", "line": 0,
   "root_cause": "the exact request(s) + why the server is exploitable",
   "reproduction": "the minimal request sequence / harness path + command that demonstrates it",
   "counterfactual": "what the attacker achieves that they could not before (whose data/funds/control)",
   "concrete_loss": "funds|data|control|availability|none",
   "remediation": "the specific fix (server-side authz check / param binding / etc.)",
   "confidence": "high|medium|low",
   "poc": "harness path under {poc_reldir} + command + what running it showed (the proof) — or 'static'",
   "evidence": "the exact requests/responses (redacted) + PoC output proving it",
   "target_code_attribution": "the in-scope live target behavior/endpoint/request path that is defective",
   "non_target_attribution": "what your client, tokens, OOB listener, fixture data, or local harness supplied",
   "relies_on_non_target_behavior": false,
   "attribution_notes": "one sentence separating target-owned behavior from test setup"}}],
 "ruled_out": ["<endpoint/class checked and why it is NOT exploitable>", "..."],
 "model_update": "<your DEEPENED attack-surface map + open threads + best current hypothesis to carry "
                 "into the next round (endpoints, params, roles, IDs, what you tried + outcomes)>"}}
"findings" may be []. Fill ruled_out only for real disproofs; put unresolved blockers and next
tests in model_update so the next round goes deeper."""


def map_prompt(
    subsystem: str,
    critical_means: str,
    focus_files: list[str] | None,
    investigate: list[str] | None,
    invariants: list[str] | None = None,
    known_patterns: list[str] | None = None,
    allow_web: bool = False,
) -> str:
    """The MAP phase — run ONCE before attacking. Reading is ENCOURAGED here (the usual keep-context-
    lean rule is relaxed): the deliverable is a durable, thorough MODEL of the subsystem that every
    later round attacks from, so depth COMPOUNDS instead of being re-derived each round."""
    files = ("\nStart from these in-scope files, then follow callers/callees outward:\n  - "
             + "\n  - ".join(focus_files) if focus_files else "")
    todo = ("\nParent A flagged these to understand:\n  - " + "\n  - ".join(investigate)
            if investigate else "")
    inv = ("\nInvariants Parent A derived (frame each as 'what an attacker must never cause'):\n  - "
           + "\n  - ".join(invariants[:8]) if invariants else "")
    patt = ""
    web = ("\nYou MAY consult the web to understand the SPEC or a primitive for this kind of system "
           "(technique only — never search for this product's prior disclosures). A few searches at most."
           if allow_web else "")
    return f"""{_ROLE_SRC_MAP}
You will OWN the '{subsystem}' subsystem. This
is the MAP phase — you are NOT attacking yet and NOT writing a PoC. Your ONE deliverable is a
COMPLETE, durable MODEL of this subsystem that you (and your future rounds) will attack from.

UNLIKE later rounds, reading is ENCOURAGED here: read the subsystem's real code thoroughly (use
sub-agents for breadth, but genuinely understand it). Be token-efficient: collect facts from
targeted windows and return a compact security map, not pasted source or command output. Cite real
file:line throughout.{files}{todo}{inv}{patt}{web}

What "critical" means here: {critical_means}

Build the model. Cover, concretely and citing code:
 - every EXTERNAL entrypoint (name + signature + file:line) an attacker can call;
 - every state variable / storage it reads and writes;
 - the trust / authorization boundaries, and exactly what assumption each check RELIES ON;
 - every ATTACKER-CONTROLLED input and the FULL value domain its type/encoding accepts;
 - the PROTECTED QUANTITIES (what must conserve / who owns what / who may do what) and the
   attacker's WIN conditions (what outcome = a critical here);
 - the value / authorization / data FLOWS end to end, across functions and files;
 - the invariants, each phrased as "what an attacker must NEVER be able to cause" (remember:
   correct code is not safe code — a faithful implementation of a flawed rule still loses).
Then rank the most promising SUSPICION THREADS to attack next (where an assumption looks reachable-
ly violable, where two correct pieces compose unsafely, where intent itself may be exploitable).

Report ONLY JSON:
{{"model": "<thorough but compact structured model, max ~5000 chars, with file:line citations — "
          "entrypoints, state, trust boundaries, attacker inputs, protected quantities, flows, "
          "invariants, and the few highest-value open threads. No pasted source/output.>",
 "threads": ["<ranked, concrete attack thread to pursue, citing where>", "..."]}}"""


def web_map_prompt(
    subsystem: str,
    critical_means: str,
    *,
    base_urls: list[str] | None = None,
    egress_hosts: list[str] | None = None,
    identities: list[str] | None = None,
    investigate: list[str] | None = None,
    invariants: list[str] | None = None,
    scope_note: str = "",
    poc_reldir: str = ".p1hunt-poc",
) -> str:
    """Live WEB_API MAP phase. Unlike map_prompt(), this must not assume backend source exists."""
    urls = "\n  - ".join(base_urls or []) or "(see the authorized target environment)"
    hosts = ", ".join(egress_hosts or []) or "(authorized host allowlist from environment)"
    ids = ", ".join(identities or []) or "none supplied"
    todo = ("\nParent A flagged these live checks/threads:\n  - " + "\n  - ".join(investigate or [])
            if investigate else "")
    inv = ("\nScope-derived guarantees to model:\n  - " + "\n  - ".join((invariants or [])[:8])
           if invariants else "")
    note = ("\nRules of engagement:\n" + scope_note.strip()) if scope_note and scope_note.strip() else ""
    return f"""{_ROLE_WEB_MAP}
You are mapping the '{subsystem}' flow for this AUTHORIZED
black-box WEB/API engagement. This is the MAP phase: build a durable attack model from live
observations. Do NOT map a repository, do NOT run git discovery, and do NOT search for backend
source unless Parent A explicitly listed source artifacts. The current directory is an evidence
workspace only.

AUTHORIZED TARGETS:
  - {urls}
Authorized egress hosts: {hosts}
Test identities: {ids}
Scope client: ./{poc_reldir}/p1hunt_dyn.py (prefer it for any repeatable proof harness).{note}{todo}{inv}

What "critical" means here: {critical_means}

Web MAP rules:
 - Start with low-impact observations only: exact authorized URL(s), HEAD/GET, redirect chain,
   status, headers that change behavior, authentication challenges, response markers, and advertised
   docs. Keep requests bounded and non-destructive.
 - If the authorized host is an IP address or exact URL-only target, subdomain enumeration is not
   applicable. If it is a domain and passive tooling is installed, passive discovery is context only;
   do not touch discovered hosts unless scope explicitly authorizes them.
 - Model actors and protected resources from observed behavior and scope: unauthenticated caller,
   supplied test identities, account/resource owner, internal network gate, proof artifact, or
   special objective. Do not inflate severity without a protected-resource or victim-state delta.
 - For every command/result you rely on, cite the concrete URL, method, timestamp/status/header/body
   marker. Source file:line citations are not required for black-box web.
 - If networking is blocked or times out, state that as a blocker and propose the smallest next
   request to resolve it. Do not invent target behavior.

Return ONLY JSON:
{{"model": "<compact live-web model, max ~5000 chars: observed endpoints, statuses/headers/body markers,
            actors, protected resources, trust boundaries, blocked checks, and open attacker-win threads>",
 "threads": ["<ranked concrete next request sequence or proof harness to pursue>", "..."]}}"""


def _json_object_candidates(text: str):
    """Yield balanced top-level JSON-looking objects from noisy model output.

    A greedy ``{.*}`` regex silently loses valid JSON whenever the agent prints prose/tool output with
    extra braces. This scanner is small but respects quoted strings and escapes, which is enough for
    the structured objects our prompts request.
    """
    start = None
    depth = 0
    in_string = False
    escaped = False
    for i, ch in enumerate(text or ""):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                yield text[start:i + 1]
                start = None


def parse_model_update(text: str) -> str:
    """Extract the ``model_update`` (or ``model``) field a hunter/mapper emitted, so it can be
    carried into the next round as the hunter's persistent memory. "" when absent/unparseable."""
    import json

    for raw in _json_object_candidates(text or ""):
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(d, dict):
            val = d.get("model_update") or d.get("model")
            if isinstance(val, str) and val.strip():
                return compact_model_memory(val.strip())
    return ""


def _model_memory_limit() -> int:
    """Maximum carried-forward subsystem memory. This is prompt cost control, not analysis depth."""
    import os

    try:
        return max(1200, int(os.environ.get("P1HUNT_MODEL_MEMORY_CHARS", "5000") or 5000))
    except ValueError:
        return 5000


def compact_model_memory(model: str, *, limit: int | None = None) -> str:
    """Keep high-signal, cited subsystem memory while preventing prompt growth across rounds.

    The model is a working map, not a transcript. Preserve lines likely to contain the reusable
    attack surface: entrypoints, state/trust boundaries, attacker-controlled inputs, invariants,
    flows, open hypotheses, blockers, and file:line citations. Drop duplicated prose first.
    """
    import re

    model = (model or "").strip()
    if not model:
        return ""
    limit = _model_memory_limit() if limit is None else max(1200, int(limit))
    lines: list[str] = []
    seen: set[str] = set()
    for raw in model.replace("\r\n", "\n").replace("\r", "\n").splitlines():
        line = re.sub(r"\s+", " ", raw.strip())
        if not line:
            continue
        if len(line) > 260:
            line = line[:257].rstrip() + "..."
        key = re.sub(r"[^a-z0-9:/._-]+", " ", line.lower()).strip()
        if key in seen:
            continue
        seen.add(key)
        lines.append(line)

    if len("\n".join(lines)) <= limit:
        return "\n".join(lines)

    high_signal = re.compile(
        r"(\bentry|external|callable|state|storage|trust|auth|permission|signature|zone|"
        r"attacker|input|domain|protected|asset|fund|owner|flow|sink|invariant|never|"
        r"hypothesis|thread|blocked|blocker|poc|proof|repro|ruled|line|:[0-9]{1,6}\b)",
        re.IGNORECASE,
    )
    ordered = [ln for ln in lines if high_signal.search(ln)] + [ln for ln in lines if not high_signal.search(ln)]
    out: list[str] = []
    used = 0
    footer = "\n[model memory compacted: keep future updates to cited deltas, open attack threads, and blockers]"
    budget = max(0, limit - len(footer))
    for ln in ordered:
        add = len(ln) + (1 if out else 0)
        if used + add > budget:
            continue
        out.append(ln)
        used += add
    if not out:
        return model[:limit].rstrip()
    return "\n".join(out).rstrip() + footer


def _parse_threads(text: str) -> list[str]:
    """Extract the ranked ``threads`` list a mapping pass emitted (its attack to-do)."""
    import json

    for raw in _json_object_candidates(text or ""):
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(d, dict) and isinstance(d.get("threads"), list):
            return [str(t).strip() for t in d["threads"] if str(t).strip()][:8]
    return []


def verify_prompt(
    f: ClaudeFinding,
    *,
    live_web: bool = False,
    base_url: str = "",
    egress_hosts: list[str] | None = None,
    poc_reldir: str = ".p1hunt-poc",
    operator_notes: str = "",
) -> str:
    finding = f"""Reported finding:
- title: {f.title}
- severity: {f.severity}
- location: {f.file}:{f.line}
- root cause: {f.root_cause}
- counterfactual: {f.counterfactual}"""
    op = ("\n\nPARENT A / OPERATOR DIRECTIVES FOR THIS VERIFICATION:\n"
          + operator_notes.strip()) if operator_notes and operator_notes.strip() else ""

    if live_web:
        hosts = ", ".join(egress_hosts or []) or "(authorized host allowlist from environment)"
        return f"""{_ROLE_FALSIFY}
You are the adversarial check on a BLACK-BOX live web finding.
PRIOR: the reported finding is WRONG until proven, but backend source may NOT be present.

Current working directory is an evidence workspace: harvested JS/OpenAPI/docs and PoCs under ./{poc_reldir}/.
Do NOT get stuck trying to trace backend route source if it is absent. For a black-box web finding,
the live HTTP result is the evidence.
Keep every search bounded: use `rg --files | head -200`, `rg -n -m 50 ...`, or targeted paths.
Never run an unbounded recursive grep over bundled/minified JS; huge tool output can break the verifier session.

Authorized target: {base_url or "(from P1HUNT_BASE_URL)"}
Authorized egress hosts: {hosts}
PoC/client path: ./{poc_reldir}/p1hunt_dyn.py

How to verify:
- First inspect ./{poc_reldir}/ for a PoC matching the endpoint/parameter/title and run the smallest
  relevant test with pytest if present.
- For unauthenticated claims, ensure the request explicitly sends no Authorization, e.g. the shipped
  Client must be called with token="" so an ambient P1HUNT_TOKEN is not added.
- For callback/fetch claims, "real" means the live server uses an attacker-controlled destination
  or returns a server-side connection/discovery error containing the unique marker, loopback/private
  host, or constructed URL. An OOB hit also counts.
- Refute only if a live, in-scope request shows authentication blocks the sink before processing,
  destination validation rejects the attacker URL before any outbound dereference, or the PoC evidence
  is incoherent. Lack of backend source is NOT a refutation.
- If no relevant PoC/evidence can be run or inspected, return verdict "real" with reachable=false
  and explain that the state is unverified; the orchestrator will keep it as a candidate.
- Apply the attribution gate below. If the reported win depends on the local client/harness, fixture
  data, OOB listener, token/account setup, external service, or any behavior outside the in-scope
  live target, it is not a confirmed target bug.

{_ATTRIBUTION_GATE}

{finding}{op}

Reply ONLY with JSON:
{{"verdict": "real|refuted", "severity": "critical|high|medium|low",
  "reachable": true|false,
  "target_code_attribution": "the in-scope target endpoint/behavior that owns the defect, or ''",
	  "non_target_attribution": "what the client/harness/OOB/token setup supplied, or ''",
	  "relies_on_non_target_behavior": true|false,
	  "attribution_notes": "why the defect is or is not target-owned",
	  {_FINDING_CLAIM_JSON},
	  "reason": "cite the live request/pytest/OOB evidence for real, or the specific live block for refuted"}}"""

    return f"""{_ROLE_FALSIFY_SRC}
You are the adversarial check. PRIOR: this reported finding is WRONG until proven.
Investigate the code in the current working directory with Read/Grep/Glob/Bash and try to REFUTE it.
Keep every search bounded: use `rg --files | head -200`, `rg -n -m 50 ...`, or targeted paths.
Never run an unbounded recursive grep over generated/minified bundles; huge tool output can break the verifier session.

But refute it the RIGHT way. "The code is correct" / "the math checks out" / "there is a check here"
is NOT a refutation — correct code still loses funds when the attacker controls the input (a
provably-correct withdraw() that accepts amount = -100 still credits the attacker). To REFUTE, you
must show the attacker is actually BLOCKED: that a control CONSTRAINS the hostile value/state to the
domain the rest of the logic assumes, BEFORE it moves the protected quantity, on EVERY reachable path
(no alternate entrypoint, no missing branch, no compose-around). To CONFIRM (verdict "real"), show a
concrete attacker-controlled value/sequence that reaches the bad outcome. Only "intended AND safe
behavior" or a control that demonstrably blocks every path is a refutation; "looks correct" is not.

{_ATTRIBUTION_GATE}

{finding}{op}

Default to refuted ONLY when you have shown the attacker is blocked (or the finding is incoherent) —
not merely because the code reads as correct. Reply ONLY with JSON:
{{"verdict": "real|refuted", "severity": "critical|high|medium|low",
  "reachable": true|false,
  "target_code_attribution": "the exact in-scope target file:line/function/behavior that owns the defect, or ''",
	  "non_target_attribution": "what the harness/mocks/fixtures/external setup supplied, or ''",
	  "relies_on_non_target_behavior": true|false,
	  "attribution_notes": "why the defect is or is not target-owned",
	  {_FINDING_CLAIM_JSON},
	  "reason": "evidence from the code for your verdict — for 'refuted', the "
	  "specific control + why it blocks the attacker on every path; for 'real', the attacker value/path"}}"""


class ClaudeHunter:
    def __init__(self, agent_name: str, *, theme: str, model: str | None, on_event: EventEmit,
                 guard_check, max_turns: int = 28, map_turns: int = 22,
                 allow_web: bool = True, web_budget: int = 5) -> None:
        self.agent_name = agent_name
        self.theme = theme
        self.model = model
        self.on_event = on_event
        self.guard_check = guard_check
        self.max_turns = max_turns
        self.map_turns = map_turns          # reading-generous budget for the one-time MAP phase
        self.allow_web = allow_web          # scoped web (technique/spec only; budgeted below)
        self.web_budget = web_budget        # max web searches per session (anti-rabbit-hole)
        # Per-round memory: a compact "investigated & ruled out" ledger carried into the next
        # round so this hunter doesn't re-walk its own dead-ends (anti-redundancy, not gospel).
        self._ruled_out: list[str] = []
        # PERSISTENT SUBSYSTEM MODEL (the big unlock): a written, accumulating understanding of this
        # subsystem (entrypoints/state/assumptions/attacks-tried/open-threads) built in the MAP phase
        # and DEEPENED every round, so round N starts where N-1 ended instead of re-deriving.
        self._model: str = ""
        # Personalized steer written by Parent A between rounds after reviewing the team's
        # cross-track progress (set by ClaudeSwarm._resteer); empty on the first round.
        self._directive: str = ""
        # Deep subsystem ownership (Pillar 2): the mechanism this hunter owns + its invariants.
        self.subsystem: str = theme
        self.invariants: list[str] = []
        self.focus_files: list[str] = []
        self.investigate: list[str] = []

    def _net(self) -> bool:
        """Web is on only if the agent is granted it AND Parent A's posture allows network."""
        perms = getattr(self, "perms", None)
        net_ok = getattr(perms, "allow_network", True) if perms is not None else True
        return self.allow_web and net_ok

    def _make_session(self, max_turns: int, finding_sink=None):
        """Build the discovery session for this hunter.

        The prompt and parser are engine-agnostic; Codex-global runs use the same prompt through a
        CodexSession instead of the legacy Claude SDK session.
        """
        common = dict(
            agent_name=self.agent_name, on_event=self.on_event, guard_check=self.guard_check,
            max_turns=max_turns, finding_sink=finding_sink,
            allow_web=self.allow_web, web_budget=self.web_budget,
            perms=getattr(self, "perms", None), egress_hosts=getattr(self, "egress_hosts", None),
        )
        return make_session(model=self.model, **_engine_kwargs(self, discovery=True), **common)

    async def _map(self, critical_means: str, repo_path: str, invariants, known_patterns,
                   subsystem: str) -> None:
        """Run the one-time MAP phase: read the subsystem deeply, produce the persistent model +
        ranked attack threads. Populates ``self._model`` and seeds ``self.investigate`` so the
        attack phase reasons over a real model. Graceful — if it fails, hunting proceeds modelless."""
        session = self._make_session(self.map_turns)
        self.on_event(self.agent_name, "message",
                      {"phase": "map", "lens": self.theme, "subsystem": subsystem})
        if getattr(self, "web_mode", False):
            prompt = web_map_prompt(
                subsystem, critical_means,
                base_urls=list(getattr(self, "base_urls", []) or []),
                egress_hosts=list(getattr(self, "egress_hosts", []) or []),
                identities=list(getattr(self, "identities", []) or []),
                investigate=self.investigate,
                invariants=invariants,
                scope_note=getattr(self, "scope_note", ""),
                poc_reldir=getattr(self, "poc_reldir", ".p1hunt-poc"),
            )
        else:
            prompt = map_prompt(subsystem, critical_means, self.focus_files, self.investigate,
                                invariants=invariants, known_patterns=known_patterns, allow_web=self._net())
        res = await session.run(prompt, repo_path, lens=self.theme)
        parsed_model = parse_model_update(res.text)
        if parsed_model:
            self._model = parsed_model
        parsed_threads = _parse_threads(res.text)
        for t in parsed_threads:
            if t not in self.investigate:
                self.investigate.append(t)
        self.on_event(self.agent_name, "message",
                      {"phase": "mapped" if parsed_model else "model_unparsed",
                       "lens": self.theme, "model_chars": len(self._model),
                       "threads": len(parsed_threads)})

    async def hunt(
        self, critical_means: str, repo_path: str, depth: int, prior_titles: list[str],
        focus_files: list[str] | None = None, investigate: list[str] | None = None,
        notices: list[str] | None = None, invariants: list[str] | None = None,
        known_patterns: list[str] | None = None, subsystem: str | None = None,
        scaffold: str = "", build_status: str = "", static_leads: list[str] | None = None,
    ) -> SessionResult:
        sub = subsystem or self.subsystem
        # TWO-PHASE: on the first encounter with this subsystem (no model yet), MAP it deeply before
        # attacking. Subsequent rounds skip mapping and attack from the accumulated model.
        if not self._model:
            try:
                await self._map(critical_means, repo_path, invariants, known_patterns, sub)
            except Exception as exc:  # mapping must never abort the hunt
                self.on_event(self.agent_name, "lifecycle", {"event": "map_failed", "detail": str(exc)})

        # Live, write-only blackboard channel: when the hunter calls post_finding mid-session,
        # we record it and emit it immediately (it shows on the blackboard + Findings tab) — the
        # hunter has no way to read the board back.
        live: list[ClaudeFinding] = []

        def _sink(d: dict) -> None:
            cf = ClaudeFinding.from_dict(d, self.theme)
            live.append(cf)
            self.on_event(self.agent_name, "finding_reported",
                          {"title": cf.title, "severity": cf.severity, "file": cf.file, "line": cf.line,
                           "finding": cf.__dict__})

        session = self._make_session(self.max_turns, finding_sink=_sink)
        if getattr(self, "web_mode", False):
            # LIVE web-app pentest: use the black-box methodology against the authorized target.
            prompt = web_hunt_prompt(
                self.theme, critical_means,
                base_urls=list(getattr(self, "base_urls", []) or []),
                egress_hosts=list(getattr(self, "egress_hosts", []) or []),
                identities=list(getattr(self, "identities", []) or []),
                oob_available=bool(getattr(self, "oob_available", False)),
                depth=depth, prior_titles=prior_titles, ruled_out=self._ruled_out,
                directive=self._directive, notices=notices,
                scope_note=getattr(self, "scope_note", ""),
                poc_reldir=getattr(self, "poc_reldir", ".p1hunt-poc"))
        else:
            prompt = hunt_prompt(self.theme, critical_means, depth, prior_titles, focus_files,
                                 investigate, notices, self._ruled_out, self._directive,
                                 invariants=invariants, known_patterns=known_patterns,
                                 subsystem=sub, scaffold=scaffold, build_status=build_status,
                                 static_leads=static_leads, model=self._model, allow_web=self._net(),
                                 poc_reldir=getattr(self, "poc_reldir", ".p1hunt-poc"))
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
        # A TRUNCATED REPLY THAT PRODUCED NOTHING is indistinguishable from a clean pass,
        # so say it out loud. Findings posted mid-session through the blackboard tool
        # survive truncation (that is what the `live` list above is for), which is why
        # this only fires when there is genuinely nothing to show.
        if response_truncated(res.text) and not res.findings:
            self.on_event(self.agent_name, "lifecycle", {
                "event": "response_truncated", "severity": "HIGH", "lens": self.theme,
                "impact": "the provider cut this hunting session off part-way and it "
                          "produced no findings, which looks exactly like a clean pass. "
                          "Do NOT read this track as checked",
                "fix": "re-run this track, or move these roles to an engine that completes "
                       "them (see `p1hunt doctor` and bench/probe_refusal.py)",
            })
        # Grow the ruled-out ledger for next round (deduped, capped to avoid prompt bloat).
        for note in parse_ruled_out(res.text):
            if note not in self._ruled_out:
                self._ruled_out.append(note)
        self._ruled_out = self._ruled_out[-16:]
        # DEEPEN the persistent model with what this round learned, so next round compounds.
        self._model = parse_model_update(res.text) or self._model
        return res


class ClaudeVerifier:
    def __init__(self, agent_name: str, *, model: str | None, on_event: EventEmit, guard_check, max_turns: int = 18) -> None:
        self.agent_name = agent_name
        self.model = model
        self.on_event = on_event
        self.guard_check = guard_check
        self.max_turns = max_turns

    async def verify(self, finding: ClaudeFinding, repo_path: str, *, operator_notes: str = "") -> tuple[str, str, str]:
        """Returns (status, severity, reason) where status is 'real' | 'refuted' | 'unverified'.
        A transient/unparseable verification is 'unverified' — NOT 'refuted' — so real
        candidates are never silently dropped when the verifier session fails."""
        session = make_session(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            **_engine_kwargs(self),
            perms=getattr(self, "perms", None),
            egress_hosts=getattr(self, "egress_hosts", None),
            allow_web=bool(getattr(self, "web_mode", False)),
            web_budget=2 if getattr(self, "web_mode", False) else 0,
        )
        result = await session.run(
            verify_prompt(
                finding,
                live_web=bool(getattr(self, "web_mode", False)),
                base_url=str(getattr(self, "base_url", "") or ""),
                egress_hosts=list(getattr(self, "egress_hosts", []) or []),
                poc_reldir=str(getattr(self, "poc_reldir", ".p1hunt-poc") or ".p1hunt-poc"),
                operator_notes=operator_notes,
            ),
            repo_path,
            lens=finding.lens,
        )
        if not result.ok:
            status, severity, reason = "unverified", finding.severity, f"verifier session failed: {result.error}"
        else:
            verdict = _parse_verdict(result.text)
            v = str(verdict.get("verdict", "")).lower()
            attribution_bad = _truthy(verdict.get("relies_on_non_target_behavior", False))
            if v == "real" and attribution_bad:
                status = "refuted"
            elif v == "real" and verdict.get("reachable", True):
                status = "real"
            elif v == "refuted":
                status = "refuted"
            else:
                status = "unverified"  # no parseable verdict (transient) — keep the candidate
            severity = str(verdict.get("severity", finding.severity)).lower()
            reason = str(verdict.get("reason", "verifier returned no parseable verdict"))
            if attribution_bad:
                note = str(verdict.get("attribution_notes") or verdict.get("non_target_attribution") or "").strip()
                reason = "attribution gate failed: " + (note or reason)
        self.on_event(self.agent_name, "message",
                      {"verdict": status, "title": finding.title, "reason": reason[:200]})
        return status, severity, reason


def poc_prompt(f: ClaudeFinding, poc_reldir: str = ".p1hunt-poc") -> str:
    return f"""{_ROLE_PROVE}
The finding below has ALREADY PASSED adversarial review
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
- Write PoC files ONLY into ./{poc_reldir}/ (inside the build/test tree so the toolchain runs it). NEVER modify the target source; nothing destructive.
- If a tool you need to build/run the PoC is missing (forge/anvil, cmake, a compiler, a fuzzer),
  INSTALL it yourself — sudo package manager, pip/cargo/npm/go, or an official installer are allowed.
- Use read-only-safe Bash to compile/test/fuzz the ACTUAL target (e.g. forge test, go test, pytest,
  cargo test, gcc). Build a minimal harness that triggers the bug and RUN it.
- A real PoC executes and demonstrates the counterfactual (value moved, check bypassed, invariant
  broken) — not a description, an actual run.

{_ATTRIBUTION_GATE}

Then judge HONESTLY — this is the whole point:
- PoC reproduces the bug  -> "proven".
- After a genuine attempt it does NOT reproduce (the code actually guards it, or the behavior is
  intended/safe) -> "not_reproduced", and state exactly why. This is valuable: it means the static
  review was fooled, and we must DROP the finding.
- You genuinely cannot build a harness (missing toolchain/deps) -> "inconclusive".

Reply ONLY with JSON:
{{"verdict": "proven|not_reproduced|inconclusive",
  "summary": "what you built, what running it showed, and why it proves/disproves the bug",
  "poc_path": "relative path to your PoC under {poc_reldir}/, or ''",
  "target_code_attribution": "the exact in-scope target behavior/file:line/endpoint that owns the defect",
  "non_target_attribution": "what your harness/mocks/fixtures/external setup supplied",
  "relies_on_non_target_behavior": true|false,
  "attribution_notes": "why this is target-owned, or why it is only a harness/setup issue"}}"""


def materialize_prompt(f: ClaudeFinding, scaffold: str = "", fork_url: str = "",
                       poc_reldir: str = ".p1hunt-poc", operator_notes: str = "") -> str:
    scaffold_block = ("\n\nUse this class-appropriate scaffold as your starting point:\n" + scaffold) if scaffold else ""
    fork_note = (f"\nA local fork is available at {fork_url} (use it if the harness needs real on-chain state)."
                 if fork_url else "")
    op = ("\n\nPARENT A / OPERATOR DIRECTIVES FOR THIS PROOF STEP:\n"
          + operator_notes.strip()) if operator_notes and operator_notes.strip() else ""
    return f"""{_ROLE_PROVE}
The finding below passed adversarial review and is BELIEVED real.
Do NOT judge whether it works — a DETERMINISTIC runner will execute your harness and decide. Your ONE job is
to MATERIALIZE a real, runnable proof HARNESS on disk that the runner can execute unattended.

Finding:
- title: {f.title}
- location: {f.file}:{f.line}
- root cause: {f.root_cause}
- counterfactual (what the attacker gains): {f.counterfactual}
- reproduction idea: {f.reproduction}{scaffold_block}{fork_note}{op}

Rules:
- If a tool you need is missing (forge/anvil, cmake, a compiler, a fuzzer), INSTALL it yourself —
  sudo package manager, pip/cargo/npm/go, or an official installer are all permitted.
- Actually CREATE the harness file(s) with the Write tool under ./{poc_reldir}/ (this path is already
	  inside the project's build/test tree so the toolchain compiles, discovers, and resolves imports for it —
	  do NOT invent another location). Make a COMPLETE, runnable harness against the REAL in-scope code
	  (compiles/loads, drives the real entrypoints) — not a sketch. For a Foundry target, run it with
	  `forge test --match-path '{poc_reldir}/<file>.t.sol' -vvv`. You MAY run it once locally to shake out
	  build errors; the deterministic runner makes the official verdict.
- Decide the EXPECT semantics precisely: "fail" if a reproduced bug makes the harness test FAIL (invariant /
  property / differential style — the assertion of correctness breaks), or "pass" if a reproduced bug makes
  an exploit assertion PASS (the attack succeeded).
- Fill `finding_claim` honestly. Reproduction alone proves behavior, not severity. A P1/critical proof must
  name the attacker, what they control, what they do NOT control, the honest victim/protected resource,
  the pre-existing valuable target, and the victim-state delta that would not happen absent the bug.
  If you cannot fill a field truthfully, leave it empty; the severity gate will keep it below critical.
- Before claiming P1, run this mental check: does the PoC consume a secret/resource the attacker does NOT
  know or control? If every share, nonce, key, authorization decision, and verified artifact was generated
  by the attacker/harness, label it reproduced behavior, not critical. A malicious participant may control
  its OWN protocol share/nonce; that is only P1 evidence when the proof also shows an honest party's
  protected share/resource is defeated and the victim state changes.
- Use non-degenerate honest material in severity PoCs. Do not prove top-tier impact only with zero,
  identity, one, empty, base/default, or otherwise trivial honest secrets/resources unless the target
  can force exactly that value. Prefer randomized or independently generated honest state, and print/assert
  the checks that show it is not a trivial fixture.
- If the exploit artifact is a signature, token, proof, receipt, capability, state root, balance/state
  delta, or any other "winning" object, verify it with an INDEPENDENT target/spec checker whenever
  one exists, not only the same combiner/finalizer that produced it. Print/assert the raw checker input
  and result, plus the pre-committed message/object/state being checked.
- For protocol or multi-actor targets, include at least one composed chain attempt: attacker poisons or
  relaxes only what the attacker legitimately controls, an honest actor responds with non-degenerate
  protected material, and the harness proves the final attacker-win artifact/state against the target or
  a standard verifier. Do not stop at "the primitive was accepted" if a later honest response is needed
  to reach the program's top-tier impact.

{_ATTRIBUTION_GATE}

Reply ONLY with a JSON object describing what you materialized (no prose):
{{"harness_path": "<relative path under {poc_reldir} to the file the runner should execute>",
  "kind": "invariant|fork|differential|call-sequence|exploit|property|policy",
  "expect": "fail|pass",
	  "test_name": "<the specific test/function to target, or ''>",
	  "command": "<the command you would run; advisory only — the runner derives its own>",
	  "notes": "<what the harness does and why its outcome proves the bug>",
	  "target_code_attribution": "the exact in-scope target behavior/file:line/endpoint that owns the defect",
	  "non_target_attribution": "what your harness/mocks/fixtures/external setup supplied",
	  "relies_on_non_target_behavior": true|false,
	  "attribution_notes": "why this is target-owned, or why it is only a harness/setup issue",
	  {_FINDING_CLAIM_JSON}}}"""


def repair_prompt(f: ClaudeFinding, prior_spec: dict, runner_output: str,
                  scaffold: str = "", fork_url: str = "", poc_reldir: str = ".p1hunt-poc",
                  operator_notes: str = "") -> str:
    scaffold_block = ("\n\nClass-appropriate scaffold for reference:\n" + scaffold) if scaffold else ""
    fork_note = (f"\nA local fork is available at {fork_url}." if fork_url else "")
    op = ("\n\nPARENT A / OPERATOR DIRECTIVES FOR THIS REPAIR STEP:\n"
          + operator_notes.strip()) if operator_notes and operator_notes.strip() else ""
    prior = str(prior_spec.get("harness_path", "")) if isinstance(prior_spec, dict) else ""
    return f"""{_ROLE_PROVE}
You are ITERATING on a proof harness. Your previous harness did NOT
reproduce the bug yet. Read the REAL runner output below, find why, and FIX the harness so it
compiles/runs and actually demonstrates the bug. This is normal — real PoCs take a few iterations.

Finding:
- title: {f.title}
- location: {f.file}:{f.line}
- root cause: {f.root_cause}
- counterfactual (what the attacker gains): {f.counterfactual}
- reproduction idea: {f.reproduction}

Previous harness: {prior}
REAL RUNNER OUTPUT (what actually happened — fix THIS):
{runner_output[:2500]}

Diagnose and fix: a build/compile error (resolve imports/deps, fix syntax/types) → fix it; the test
ran but the bug didn't trigger (wrong setup, didn't reach the sink past a gate, wrong attacker input,
wrong expect semantics) → correct it; the harness tested the wrong thing → rewrite it against the
REAL in-scope code. Edit/replace the file(s) under ./{poc_reldir}/ with the Write tool. You MAY run it
once locally to shake out errors; the deterministic runner makes the official verdict.{scaffold_block}{fork_note}
{op}

If, after a GENUINE fix attempt, the bug truly does NOT reproduce (the code actually guards it), say
so in notes — that is a valid, useful outcome.

	{_ATTRIBUTION_GATE}

	Reply ONLY with the updated ReproSpec JSON (same shape):
{{"harness_path": "<relative path under {poc_reldir} to the file the runner should execute>",
  "kind": "invariant|fork|differential|call-sequence|exploit|property|policy",
  "expect": "fail|pass",
	  "test_name": "<the specific test/function to target, or ''>",
	  "command": "<advisory only — the runner derives its own>",
	  "notes": "<what you changed and why it now proves the bug, or why it genuinely does not reproduce>",
	  "target_code_attribution": "the exact in-scope target behavior/file:line/endpoint that owns the defect",
	  "non_target_attribution": "what your harness/mocks/fixtures/external setup supplied",
	  "relies_on_non_target_behavior": true|false,
	  "attribution_notes": "why this is target-owned, or why it is only a harness/setup issue",
	  {_FINDING_CLAIM_JSON}}}"""


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
                          scaffold: str = "", fork_url: str = "", operator_notes: str = "") -> dict | None:
        """Write a runnable harness into the sandbox and return a ReproSpec dict (or None on
        failure). The deterministic runner — not this session — decides reproduction."""
        self.on_event(self.agent_name, "message",
                      {"phase": "materialize", "title": finding.title, "file": finding.file})
        session = make_session(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            **_engine_kwargs(self),
            perms=getattr(self, "perms", None),
            egress_hosts=getattr(self, "egress_hosts", None),
        )
        result = await session.run(
            materialize_prompt(finding, scaffold, fork_url, getattr(self, "poc_reldir", ".p1hunt-poc"),
                               operator_notes=operator_notes),
            repo_path, lens=finding.lens)
        if not result.ok:
            self.on_event(self.agent_name, "lifecycle",
                          {"event": "materialize_failed", "title": finding.title, "detail": result.error})
            return None
        spec = _parse_verdict(result.text)
        if not spec or not spec.get("harness_path"):
            # Distinguish "the model could not build a harness" from "the provider cut it
            # off". They need completely different responses, and lumping them together
            # sends you debugging the wrong one.
            cut = response_truncated(result.text)
            self.on_event(self.agent_name, "lifecycle",
                          {"event": "materialize_empty", "title": finding.title,
                           "truncated": cut,
                           "severity": "HIGH" if cut else "",
                           "detail": ("the provider cut this proof session off part-way, so no "
                                      "harness was written -- this is not evidence the finding "
                                      "is unprovable" if cut else
                                      "the session returned no harness path")})
            return None
        self.on_event(self.agent_name, "message",
                      {"verdict": "harness materialized", "title": finding.title,
                       "harness": str(spec.get("harness_path", ""))[:160], "expect": spec.get("expect", "")})
        return spec

    async def repair(self, finding: ClaudeFinding, prior_spec: dict, runner_output: str,
                     repo_path: str, *, scaffold: str = "", fork_url: str = "",
                     operator_notes: str = "") -> dict | None:
        """The PoC ITERATION step: the prior harness did NOT reproduce. Feed the real runner output
        back so the prover FIXES the harness (compile error, wrong setup, mis-stated expect, didn't
        reach the sink) and returns an updated ReproSpec — or None if it cannot. This turns one-shot
        proof into a run→read-failure→fix→rerun loop, converting reasoned bugs into confirmed ones."""
        self.on_event(self.agent_name, "message",
                      {"phase": "repair", "title": finding.title, "file": finding.file})
        session = make_session(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            **_engine_kwargs(self),
            perms=getattr(self, "perms", None),
            egress_hosts=getattr(self, "egress_hosts", None),
        )
        result = await session.run(
            repair_prompt(finding, prior_spec, runner_output, scaffold, fork_url,
                          getattr(self, "poc_reldir", ".p1hunt-poc"),
                          operator_notes=operator_notes), repo_path, lens=finding.lens)
        if not result.ok:
            return None
        spec = _parse_verdict(result.text)
        if not spec or not spec.get("harness_path"):
            return None
        self.on_event(self.agent_name, "message",
                      {"verdict": "harness repaired", "title": finding.title,
                       "harness": str(spec.get("harness_path", ""))[:160], "expect": spec.get("expect", "")})
        return spec

    async def prove(self, finding: ClaudeFinding, repo_path: str) -> tuple[str, str, str]:
        """Returns (verdict, summary, poc_path); verdict ∈ proven | not_reproduced | inconclusive."""
        self.on_event(self.agent_name, "message",
                      {"phase": "poc", "title": finding.title, "severity": finding.severity})
        session = make_session(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            **_engine_kwargs(self),
            perms=getattr(self, "perms", None),
            egress_hosts=getattr(self, "egress_hosts", None),
        )
        result = await session.run(
            poc_prompt(finding, getattr(self, "poc_reldir", ".p1hunt-poc")), repo_path, lens=finding.lens)
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


def _truthy(v: object) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


# ===========================================================================
# Deduplicator — at the confirmation gate, decides whether a newly-confirmed
# finding is the SAME underlying bug (same root cause / same fix) as one already
# confirmed, even if title/file/line differ. One cheap call; only invoked when
# there is at least one prior confirmed finding to compare against.
# ===========================================================================
def dedup_prompt(f: ClaudeFinding, existing: list) -> str:
    lst = "\n".join(
        f"  {i + 1}. [{e.severity}] {e.title} @ {getattr(e.poc,'path','')} — {e.root_cause[:160]}"
        for i, e in enumerate(existing))
    return f"""{_ROLE_TRIAGE}
A new finding was just CONFIRMED. Decide if it is
the SAME underlying vulnerability as one ALREADY confirmed — same ROOT CAUSE and same FIX — even if
the title, file, or line number differs. Two different symptoms of one root cause = DUPLICATE. A
genuinely distinct bug (different root cause, needs a separate fix) = NOT a duplicate.

NEW finding:
- title: {f.title}
- location: {f.file}:{f.line}
- root cause: {f.root_cause}
- counterfactual: {f.counterfactual}

ALREADY CONFIRMED (compare against each):
{lst}

Reply ONLY JSON: {{"duplicate": true|false, "of": <1-based index of the match, or 0>,
  "reason": "one line — why it is or isn't the same root cause"}}"""


def exploit_dev_prompt(f: ClaudeFinding, rubric: str, poc_reldir: str = ".p1hunt-poc",
                       prior_attempts: list | None = None, operator_notes: str = "") -> str:
    """The EXPLOIT-DEVELOPMENT depth phase — the organ that turns a believed PRIMITIVE into a proven
    attacker-WIN (or a rigorous impossibility). This is the long-horizon, sustained-focus job that
    separates an interesting primitive from a Critical: it builds the full multi-step / multi-party /
    cryptanalytic chain and DEMONSTRATES the win against shipped code, measured against the rubric."""
    rub = rubric.strip() if rubric else (
        "Critical = a deterministic, reproduced attacker win that satisfies the engagement's top "
        "severity definition. Lower tiers are incomplete chains, bounded impact, or unclosed "
        "primitives. Measure cost, attempts, prerequisites, and blast radius precisely.")
    # Robust to BOTH ClaudeFinding (.file/.line/.reproduction/.lens) and the promoted Finding
    # (.poc.path, .severity_rationale; no .file/.line) — the depth phase runs on either.
    title = getattr(f, "title", "")
    _file = getattr(f, "file", None) or getattr(getattr(f, "poc", None), "path", "") or getattr(f, "location", "")
    _line = getattr(f, "line", "")
    loc = (f"{_file}:{_line}" if (_file and _line) else (_file or "(see root cause)"))
    root = getattr(f, "root_cause", "")
    cfac = getattr(f, "counterfactual", "") or ""
    repro = getattr(f, "reproduction", "") or getattr(f, "severity_rationale", "") or ""
    # PERSISTENT PURSUIT: prior failed angles on THIS SAME lead, so this attempt PIVOTS instead of
    # repeating a dead end. A single failed PoC never closes a lead — only a proven win or a rigorous
    # cross-angle impossibility does.
    persist = ""
    if prior_attempts:
        _lines = "\n".join(
            f"  attempt {i}: TRIED {str(a.get('strategy','?'))[:160]}  ->  FAILED: {str(a.get('why_failed','?'))[:200]}"
            for i, a in enumerate(prior_attempts, 1))
        persist = (
            f"\n\nPRIOR ATTEMPTS ON THIS EXACT LEAD ({len(prior_attempts)} so far — do NOT repeat them):\n"
            f"{_lines}\n"
            "This is a PERSISTENT pursuit, not a one-shot. Take a FUNDAMENTALLY DIFFERENT angle than every "
            "attempt above — change ONE of: the threat model, which party you play, the parameter regime, "
            "the protocol round, or the technique (direct PoC -> lattice/statistical -> chain with another "
            "primitive -> relax an assumption -> fault/abort oracle). Build on what the failures TAUGHT you. "
            "Do NOT declare exhausted just because a PoC failed — only if you can prove the win is impossible "
            "across ALL remaining angles.")
    op = ("\n\nPARENT A / OPERATOR DIRECTIVES FOR THIS DEPTH ATTEMPT:\n"
          + operator_notes.strip()) if operator_notes and operator_notes.strip() else ""
    return f"""{_ROLE_DEPTH}
You are handed ONE believed
primitive (an anomaly another agent found in the target's shipped code). Spotting it was the easy
10%. Your job is the hard 90%: BUILD THE FULL EXPLOIT that achieves the program's attacker-WIN — or
prove rigorously that the chain cannot close. Take as many steps as you need; this is deep, sustained
work, not a one-shot.

THE PRIMITIVE:
- title: {title}
- location (shipped code): {loc}
- root cause: {root}
- the win it MIGHT enable: {cfac}
- how it was found / repro idea: {repro}

THE BAR (score your result against THIS exactly):
{rub}{persist}{op}

METHOD — close the chain end to end, against the REAL shipped code:
 1. MODEL THE FULL ATTACK PATH. From the primitive to the attacker-win: every step, every value the
    attacker controls, every thing they observe, every protocol round. Write it down before coding.
    Frame the target as a SECURITY GUARANTEE to break (soundness/hiding/binding/unforgeability/secrecy/
    uniqueness — whatever this component promises), and use WHATEVER technique breaks that property —
    do not restrict yourself to bug shapes you already know. Generic primitives that surface novel
    breaks: re-run/replay the same secret-dependent op and DIFF/COMBINE outputs; differential vs a
    reference/spec; statistical/lattice recovery; multi-party adversarial simulation; driving every
    field to its full value-domain. The exploit is the concrete violation of the promised property.
    When a primitive is accepted but not itself the win, explicitly try the COMPOSITION step: feed the
    accepted primitive into the next honest-party/protected-resource operation, let honest target code
    respond using non-degenerate state the attacker does not know/control, and test whether that response
    becomes a final winning artifact/state.
 2. BUILD THE REAL ENVIRONMENT. Deploy / drive the ACTUAL library (not a toy). If the protocol is
    multi-party, SIMULATE ALL parties and play the malicious one(s) yourself. Reach PAST the gates
    (real keygen, real signing) into the value-moving logic. Put harnesses under ./{poc_reldir}/.
 3. DO THE CRYPTANALYSIS, don't hand-wave it. If the win needs math, RUN it: install and use sage,
    fpylll, sympy, numpy, pari/gp, etc. (you may install anything). Collect samples across MANY
    sessions; run nonce-bias / lattice (LLL/BKZ) / statistical key-bit recovery; build fault/abort
    ORACLES and measure how many aborts a real attacker needs. The deliverable is a NUMBER (key
    recovered, or N bits leaked, in K aborts) — not "this could leak".
 4. MEASURE against the rubric. Did you achieve the exact top-tier attacker win, under realistic
    prerequisites and with measured attempts/cost/blast radius? That determines the tier. Half a
    chain is not a critical.
 5. INDEPENDENTLY CHECK THE WIN. If the output is a signature/token/proof/capability/receipt/state
    transition/balance change, validate the raw final artifact/state with an independent target/spec
    checker or invariant, not only with the routine that produced it. Print/assert the raw checker input,
    the fixed message/object/state chosen before the run, and the checker result.

HARD RULES (these are what triage checks — do not fool yourself):
 - The bug MUST be owned by the in-scope target's own shipped/compiled/runtime behavior. If your
   exploit only works because of a concrete implementation, fixture, mock, fake service, local
   config, deployment assumption, account setup, external dependency, or protocol peer behavior that
   YOU supplied outside the target, it is INVALID — you exploited your own setup, not the target.
   Pure-virtual (= 0) interfaces are one example, not the only one. State explicitly that your PoC
   drives target-owned code/behavior and separate every non-target assumption.
 - CORRECT ≠ SAFE, but PRIMITIVE ≠ CRITICAL. Only an actually-demonstrated attacker-win counts. If
   you cannot close it, say so HONESTLY with the exact step that blocks it — a rigorous impossibility
   is a valuable, truthful result. Do NOT inflate a soundness bug into a critical.
 - Do not rely on degenerate honest state for severity unless the target can force it. Top-tier PoCs
   should use independently generated/randomized honest secrets/resources and print/assert that the
   honest material is not a trivial zero/one/identity/default/base fixture.

{_ATTRIBUTION_GATE}

Reply ONLY with JSON:
{{"achieved": true|false,
  "tier": "critical|high|medium|low|none",
  "win": "exactly what you demonstrated (e.g. 'recovered full ECDSA private key, x·G==pubkey')",
  "aborts": "how many failures/aborts the attack needed (number or estimate), or 'n/a'",
  "harness_path": "<relative path under {poc_reldir} to the runnable exploit, or ''>",
  "evidence": "the real run output that proves the win (or the precise step that blocks it)",
  "shipped_code": true|false,
  "shipped_function": "the exact shipped function + file:line where the BUG lives (the real defect, not your harness)",
  "target_code_attribution": "the exact in-scope target-owned behavior/file:line/endpoint that owns the defect",
  "non_target_attribution": "what mocks/fixtures/scaffold/external setup/integrator behavior supplied, if anything",
  "relies_on_non_target_behavior": true|false,
  "relies_on_abstract_interface": true|false,
  "attribution_notes": "set relies_on_non_target_behavior=TRUE if the win depends on behavior outside the in-scope target: harness, mock, fixture, external service, deployment/account assumption, dependency not shipped by target, or pure-virtual/integrator-only implementation. Set relies_on_abstract_interface=TRUE for the pure-virtual subset.",
  "strategy": "the SPECIFIC angle you tried THIS attempt (one line — so the next attempt won't repeat it)",
  "why_failed": "if not achieved: the exact step that blocked THIS angle",
  "next_angle": "if not achieved and NOT impossible: a different, concrete angle worth trying next",
  "exhausted": true|false,
  "impossibility": "if exhausted: the rigorous argument for why the win is impossible across ALL angles"}}"""


class ClaudeExploitDeveloper:
    """Depth-phase agent: takes ONE believed primitive and SUSTAINS focus (large turn budget, no
    per-round reset) to build the full attacker-WIN exploit against shipped code, or prove it can't.
    This is the function that was missing — the difference between finding an anomaly and landing a
    critical. A finding is only promoted to a confirmed CRITICAL when this agent demonstrates the
    rubric's attacker-win in shipped code."""

    def __init__(self, agent_name: str, *, model: str | None, on_event: EventEmit, guard_check,
                 max_turns: int = 60) -> None:
        self.agent_name = agent_name
        self.model = model
        self.on_event = on_event
        self.guard_check = guard_check
        self.max_turns = max_turns

    async def develop(self, finding: ClaudeFinding, repo_path: str, *, rubric: str = "",
                      scaffold: str = "", fork_url: str = "",
                      prior_attempts: list | None = None, operator_notes: str = "") -> dict | None:
        """Run the sustained exploit-development session. Returns a verdict dict (or None on failure):
        achieved/tier/win/aborts/harness_path/evidence/shipped_code/impossibility."""
        _loc = getattr(finding, "file", None) or getattr(getattr(finding, "poc", None), "path", "")
        _lens = getattr(finding, "lens", "") or "trusted-execution"
        self.on_event(self.agent_name, "message",
                      {"phase": "exploit_dev", "title": getattr(finding, "title", ""), "file": _loc,
                       "attempt": len(prior_attempts or []) + 1})
        session = make_session(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            **_engine_kwargs(self),
            perms=getattr(self, "perms", None),
            egress_hosts=getattr(self, "egress_hosts", None),
        )
        prompt = exploit_dev_prompt(finding, rubric, getattr(self, "poc_reldir", ".p1hunt-poc"),
                                    prior_attempts=prior_attempts, operator_notes=operator_notes)
        result = await session.run(prompt, repo_path, lens=_lens)
        if not result.ok:
            self.on_event(self.agent_name, "lifecycle",
                          {"event": "exploit_dev_failed", "title": finding.title, "detail": result.error})
            return None
        v = _parse_verdict(result.text)
        if not v:
            return None
        # ATTRIBUTION GATE: a win that leans on non-target behavior (harness/mock/fixture/fake
        # service/local config/external dependency/integrator-only implementation) is INVALID, even
        # if the harness "demonstrates" it. Pure-virtual (=0) interfaces are one example.
        abstract = _truthy(v.get("relies_on_abstract_interface", False))
        non_target = _truthy(v.get("relies_on_non_target_behavior", False))
        missing_target = not str(v.get("target_code_attribution") or v.get("shipped_function") or "").strip()
        achieved = (
            _truthy(v.get("achieved"))
            and _truthy(v.get("shipped_code", True))
            and not abstract
            and not non_target
            and not missing_target
        )
        if (abstract or non_target or missing_target) and _truthy(v.get("achieved")):
            self.on_event(self.agent_name, "lifecycle",
                          {"event": "exploit_rejected_attribution", "title": finding.title,
                           "detail": "win relies on non-target behavior or lacks target-code attribution; "
                                     "not confirmed as a target-owned bug"})
        self.on_event(self.agent_name, "lifecycle",
                      {"event": "exploit_developed" if achieved else "exploit_not_closed",
                       "title": finding.title, "tier": v.get("tier", "none"),
                       "win": str(v.get("win", ""))[:160], "aborts": str(v.get("aborts", "")),
                       "shipped_code": _truthy(v.get("shipped_code", True)),
                       "shipped_function": str(v.get("shipped_function", ""))[:160],
                       "target_code_attribution": str(v.get("target_code_attribution", ""))[:160],
                       "relies_on_non_target_behavior": non_target,
                       "relies_on_abstract_interface": abstract,
                       "strategy": str(v.get("strategy", ""))[:160],
                       "exhausted": bool(v.get("exhausted")),
                       "next_angle": str(v.get("next_angle", ""))[:160],
                       "detail": str(v.get("evidence") or v.get("impossibility") or "")[:200]})
        v["_achieved"] = achieved
        return v


class ClaudeDeduplicator:
    """Semantic dedup at the confirmation gate (cheap model). Returns (is_dup, of_index, reason)."""

    def __init__(self, agent_name: str, *, model: str | None, on_event: EventEmit, guard_check,
                 max_turns: int = 6) -> None:
        self.agent_name = agent_name
        self.model = model
        self.on_event = on_event
        self.guard_check = guard_check
        self.max_turns = max_turns

    async def is_duplicate(self, finding: ClaudeFinding, existing: list, repo_path: str) -> tuple[bool, int, str]:
        if not existing:
            return False, 0, "nothing to compare against"
        session = make_session(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            **_engine_kwargs(self),
            perms=getattr(self, "perms", None), egress_hosts=getattr(self, "egress_hosts", None))
        res = await session.run(dedup_prompt(finding, existing), repo_path, lens=finding.lens)
        if not res.ok:
            return False, 0, f"dedup session failed: {res.error}"  # fail-open: keep the finding
        d = _parse_verdict(res.text)
        dup = bool(d.get("duplicate"))
        self.on_event(self.agent_name, "message",
                      {"verdict": "duplicate" if dup else "distinct", "title": finding.title,
                       "reason": str(d.get("reason", ""))[:160]})
        return dup, int(d.get("of", 0) or 0), str(d.get("reason", ""))


# ===========================================================================
# Debate panel — runs at round end on confirmed CRITICAL findings only. A
# prosecutor argues to invalidate/downgrade, a defender argues it is a genuine
# critical, and a judge reads BOTH (plus the code) and rules: uphold | downgrade
# | reject. This is the final adversarial gate on the highest-stakes findings.
# ===========================================================================
def _finding_view(f) -> dict:
    """Normalize ClaudeFinding and promoted Finding for late pipeline prompts."""
    poc = getattr(f, "poc", None)
    _file = getattr(f, "file", None) or getattr(poc, "path", "") or getattr(f, "location", "")
    _line = getattr(f, "line", "")
    loc = f"{_file}:{_line}" if _file and _line else (_file or "(see evidence)")
    return {
        "title": getattr(f, "title", ""),
        "severity": getattr(f, "severity", ""),
        "location": loc,
        "root_cause": getattr(f, "root_cause", ""),
        "counterfactual": getattr(f, "counterfactual", ""),
        "evidence": (
            getattr(f, "reproduction", "")
            or getattr(f, "severity_rationale", "")
            or getattr(poc, "description", "")
            or ""
        ),
        "lens": getattr(f, "lens", "") or "critical-review",
    }


def debate_prompt(f: ClaudeFinding, role: str) -> str:
    fv = _finding_view(f)
    if role == "prosecutor":
        stance = ("You are the PROSECUTOR. Make the strongest possible case that this CONFIRMED "
                  "critical is WRONG, overstated, unreachable, intended behavior, or only a lower "
                  "severity. Read the code; cite specifics; attack the reachability, the assumptions, "
                  "the impact, and the severity. Be ruthless but truthful.")
    else:
        stance = ("You are the DEFENDER. Make the strongest possible case that this is a GENUINE "
                  "critical: show the attacker is real and in-model, the impact is real (key/funds/"
                  "control), and the severity is justified. Read the code; cite specifics; pre-empt "
                  "the obvious objections.")
    return f"""{_ROLE_JUDGE}
{stance}

CONFIRMED critical under debate:
- title: {fv["title"]}
- location: {fv["location"]}
- root cause: {fv["root_cause"]}
- counterfactual: {fv["counterfactual"]}
- evidence/repro: {fv["evidence"]}

COUNTERFACTUAL-SEVERITY BAR:
- Reject or downgrade if the proof only shows that the harness can generate inputs, partials, shares,
  signatures, accounts, messages, or artifacts it already controls.
- For a critical, identify the honest-held secret/resource/authorization boundary the attacker defeats.
- State the defender escape hatches: attacker controls every role, needs a victim to run code, out-of-scope
  integration policy, missing stored state, missing tenant/key binding, no protected asset loss.

{_ATTRIBUTION_GATE}

Investigate the code in the working directory (Read/Grep/Glob/Bash) to ground your argument.
Reply ONLY JSON: {{"argument": "your strongest case, citing file:line",
  "severity": "critical|high|medium|low",
  "honest_secret_or_resource": "what protected value/resource the attacker defeats, or ''",
  "attacker_controls_all_material_inputs": true|false,
  "defender_escape_hatches": "strongest objections a defender can raise",
  "target_code_attribution": "the target-owned behavior/file:line/endpoint that owns the defect, or ''",
  "relies_on_non_target_behavior": true|false,
  "attribution_notes": "why this is target-owned or why it is only harness/setup behavior"}}"""


def debate_judge_prompt(f: ClaudeFinding, prosecution: str, defense: str) -> str:
    fv = _finding_view(f)
    return f"""{_ROLE_JUDGE}
You are the JUDGE. Two reviewers debated a CONFIRMED critical. Weigh BOTH arguments
against the actual code and rule impartially. Prefer truth over either side; do not rubber-stamp.

Finding: {fv["title"]}  ({fv["location"]})
Root cause: {fv["root_cause"]}

PROSECUTION (argues invalidate/downgrade):
{prosecution[:1500]}

DEFENSE (argues genuine critical):
{defense[:1500]}

{_ATTRIBUTION_GATE}

Rule: 'uphold' (stays a confirmed critical), 'downgrade' (real but lower severity — give it), or
'reject' (not a valid finding / false positive). Reject if the win is owned by non-target behavior
or the target-owned defect is not attributable. Also reject/downgrade if the PoC lacks an honest-held
protected secret/resource or authorization boundary and only proves a self-controlled artifact.
Reply ONLY JSON:
{{"verdict": "uphold|downgrade|reject", "severity": "critical|high|medium|low",
  "honest_secret_or_resource": "what protected value/resource the attacker defeats, or ''",
  "attacker_controls_all_material_inputs": true|false,
  "defender_escape_hatches": "strongest objections a defender can raise",
  "target_code_attribution": "the target-owned behavior/file:line/endpoint that owns the defect, or ''",
  "relies_on_non_target_behavior": true|false,
  "attribution_notes": "why this is target-owned or why it is only harness/setup behavior",
  "reason": "the deciding evidence from the code"}}"""


class ClaudeDebate:
    """Prosecutor + defender + judge over one confirmed critical. Returns (verdict, severity, reason)."""

    def __init__(self, agent_name: str, *, model: str | None, on_event: EventEmit, guard_check,
                 max_turns: int = 12) -> None:
        self.agent_name = agent_name
        self.model = model
        self.on_event = on_event
        self.guard_check = guard_check
        self.max_turns = max_turns

    async def _argue(self, finding: ClaudeFinding, role: str, repo_path: str) -> str:
        session = make_session(
            agent_name=f"{self.agent_name}:{role}", model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            **_engine_kwargs(self),
            perms=getattr(self, "perms", None), egress_hosts=getattr(self, "egress_hosts", None))
        res = await session.run(debate_prompt(finding, role), repo_path, lens=_finding_view(finding)["lens"])
        return str(_parse_verdict(res.text).get("argument", res.text))[:1800] if res.ok else ""

    async def adjudicate(self, finding: ClaudeFinding, repo_path: str) -> tuple[str, str, str]:
        fv = _finding_view(finding)
        self.on_event(self.agent_name, "message", {"phase": "debate", "title": fv["title"]})
        prosecution = await self._argue(finding, "prosecutor", repo_path)
        defense = await self._argue(finding, "defender", repo_path)
        judge = make_session(
            agent_name=f"{self.agent_name}:judge", model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            **_engine_kwargs(self),
            perms=getattr(self, "perms", None), egress_hosts=getattr(self, "egress_hosts", None))
        res = await judge.run(debate_judge_prompt(finding, prosecution, defense), repo_path, lens=fv["lens"])
        d = _parse_verdict(res.text) if res.ok else {}
        if not d:
            raise RuntimeError("debate judge returned no parseable verdict")
        verdict = str(d.get("verdict", "")).lower().strip()
        if verdict not in ("uphold", "downgrade", "reject"):
            raise RuntimeError(f"debate judge returned invalid verdict: {verdict or '<empty>'}")
        if verdict == "uphold" and _truthy(d.get("relies_on_non_target_behavior", False)):
            verdict = "reject"
        if verdict == "uphold" and _truthy(d.get("attacker_controls_all_material_inputs", False)):
            verdict = "downgrade"
        severity = str(d.get("severity", finding.severity)).lower().strip()
        reason = str(d.get("reason", ""))
        if verdict == "reject" and _truthy(d.get("relies_on_non_target_behavior", False)):
            note = str(d.get("attribution_notes") or "").strip()
            reason = "attribution gate failed: " + (note or reason)
        self.on_event(self.agent_name, "message",
                      {"verdict": f"debate:{verdict}", "title": finding.title, "reason": reason[:160]})
        return verdict, severity, reason
