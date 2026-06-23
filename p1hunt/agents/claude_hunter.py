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
        "understand the SPEC, a cryptographic/protocol PRIMITIVE, or a known ATTACK CLASS for this "
        "kind of system, to sharpen HOW you attack. The web does NOT contain the bug for THIS "
        "target — do NOT search for this program's disclosed bugs/CVEs/'<product> vulnerabilities', "
        "and do NOT use the web as somewhere to go when stuck. A few searches at most; then return "
        "to the code. The vulnerability is found in the ACTUAL code, by YOU."
        if allow_web else ""
    )
    leads_block = (
        "\n\n🔬 DERIVED STATIC LEADS (high-value bug-CLASS primitives a Solidity-aware scan found in "
        "the actual code — these are starting points DERIVED from this target, not a checklist and "
        "MAYBE WRONG; for each, reason whether it is reachable with its guard's assumption violated, "
        "then PROVE or kill it):\n  - " + "\n  - ".join(static_leads[:12])
        if static_leads else ""
    )
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
 (2) For each entrypoint, BECOME THE ATTACKER. Take every input to the worst value its
     type/encoding/protocol still ACCEPTS — negative / zero / min / max, out-of-domain, aliased or
     duplicated, malformed, reordered, replayed, stale, or a value that is individually "valid" but
     hostile in context — and trace it END TO END to a protected quantity. The question for every
     check is not "is it correct" but "does it actually CONSTRAIN this hostile value to the domain
     the rest of the logic silently assumes, BEFORE it moves a protected quantity, on EVERY reachable
     path?" Look for: where two individually-correct pieces COMPOSE into an unsafe whole; where the
     INTENT itself is exploitable (not just its implementation); a check present on one path but
     missing on another; ordering / reentrancy / precision / signedness / domain assumptions. Develop
     SEVERAL concrete, code-cited hypotheses and, for each, argue concretely whether the attacker can
     reach the win or is genuinely blocked — that argument is where the P1 lives.
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
   "poc": "path to the PoC you wrote under {poc_reldir} + the command to run it + what running it showed (the proof) — or 'static' if you could not yet run one",
   "evidence": "the exact code/flow + PoC run output that proves it"}}],
 "ruled_out": ["<one short line: what you investigated and why it is NOT exploitable — so the "
               "next pass skips it>", "..."],
 "model_update": "<your DEEPENED model of this subsystem to carry into the next round — the same "
                 "structure as the model above, updated with everything you learned this pass "
                 "(entrypoints, state, assumptions, attacks tried + outcomes, open threads, current "
                 "best hypothesis). This is your memory; write it so next round starts where you "
                 "ended, not from scratch.>"}}
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
           "blind SSRF/XXE/injection (the proof is the target calling back)."
           if oob_available else "No OOB listener this run — prefer in-band proofs.")
    prior = ("\nAlready reported (do not repeat): " + "; ".join((prior_titles or [])[:12])) if prior_titles else ""
    rl = ("\nAlready RULED OUT (skip): " + "; ".join((ruled_out or [])[:14])) if ruled_out else ""
    steer = ("\n\n🧭 PARENT A'S DIRECTIVE FOR THIS ROUND (do this first): " + directive) if directive else ""
    notice = ("\n\n📨 OPERATOR NOTICES: " + " | ".join(notices)) if notices else ""
    note = ("\n\nRULES OF ENGAGEMENT (from the program): " + scope_note) if scope_note else ""
    return f"""You are an elite bug-bounty web pentester (think top-of-the-leaderboard autonomous hacker)
owning the '{theme}' angle of an AUTHORIZED engagement against a LIVE target. Round {depth}.

AUTHORIZED LIVE TARGET(S):
  - {urls}
In-scope hosts (every request is HARD-CONFINED to these by an egress jail — anything else is blocked
before a packet leaves): {hosts}
Test identities available: {ids}
{oob}{note}{steer}{notice}{prior}{rl}

SAFE HARBOR — NON-NEGOTIABLE (you are a guest on a real system):
 - Touch ONLY in-scope hosts. Never an out-of-scope host, never a third party.
 - NON-DESTRUCTIVE ONLY: no DELETE of others' data, no account takeover beyond minimal proof, no
   mass actions, no spam, no data exfiltration beyond the few bytes needed to PROVE the bug.
 - NO DoS / NO load testing / NO aggressive brute-force. Respect rate limits; throttle. A scanner
   you run must be rate-limited and pointed only at in-scope hosts.
 - Use ONLY your own test accounts / synthetic data. Minimize blast radius. Stop if you might harm.

YOUR TOOLBELT:
 - A scope-ENFORCED HTTP client is shipped into ./{poc_reldir}/p1hunt_dyn.py — `from p1hunt_dyn import
   Client`. It gives multi-identity sessions (auth as A vs B — the core of IDOR/BOLA), differential
   authz helpers (idor_probe / assert_forbidden), injection oracles (timing/boolean/reflection), and
   OOB confirmation. Every request it makes is scope-checked. PREFER it for proofs.
 - You may INSTALL and run standard recon/attack tooling, but ONLY against in-scope hosts and
   rate-limited: httpx, nuclei (with safe templates), ffuf/feroxbuster (gentle), katana/gau/waybackurls
   (endpoint discovery), subfinder/amass (subdomain enum — keep results in-scope), gf, jwt_tool, sqlmap
   (--level low, no --dump of real data), graphql introspection. The egress jail confines them too.

METHOD — RECON → MODEL → ATTACK-TO-WIN → PROVE (spend most effort on attack + proof):
 1. RECON the attack surface of the in-scope hosts: live subdomains, endpoints, parameters, HTTP
    methods, content types, auth flows, roles, cookies/JWTs, GraphQL schema (introspection),
    JS bundles (extract API routes, hidden endpoints, secrets/keys), error pages, headers, CORS.
    Build a concrete map: for each endpoint — who SHOULD be allowed to do what, and what
    object IDs / tenants / roles exist.
 2. For the '{theme}' angle, BECOME THE ATTACKER and hunt attacker-WIN outcomes (not a checklist —
    chase impact). The win classes that pay as P1 here:
    • Broken access control / IDOR / BOLA: identity B reads or MUTATES A's object; horizontal &
      vertical privilege escalation; missing function-level authz; tenant isolation break.
    • Authn / session: auth bypass, JWT alg/sig/claim flaws, OAuth/SAML misconfig, password-reset
      poisoning, 2FA bypass, session fixation, predictable tokens.
    • SSRF (incl. BLIND via OOB), XXE, request smuggling.
    • Injection: SQL/NoSQL, command, SSTI, LDAP, GraphQL — drive to data read/RCE.
    • Stored/reflected/DOM XSS where it yields account/session impact; CSRF on state-changing actions.
    • Business logic: price/quantity/discount manipulation, race conditions (TOCTOU), workflow &
      payment bypass, negative amounts, replay.
    • Info disclosure: secrets/keys in JS or responses, debug/admin endpoints, exposed internal APIs,
      directory listing; CORS misconfig; subdomain takeover.
   What "critical" means for this program: {critical_means}
 3. CORRECT ≠ SAFE: a 200 OK or a working feature is not safety. Reason "can the attacker WIN" —
    e.g. an endpoint that faithfully returns a record is a CRITICAL if it returns ANOTHER user's
    record for an attacker-chosen id. Develop several concrete, request-cited hypotheses per pass.
 4. PROVE the strongest one DETERMINISTICALLY against the LIVE target. Write a runnable harness under
    ./{poc_reldir}/ — a pytest using p1hunt_dyn (e.g. `idor_probe(a, b, url)` returns A's data to B;
    or `oob_received(token)` is True after the request). The RUN is the JUDGE. A real PoC shows the
    win (B got A's data; the callback fired; the price became negative) — not a description.
 5. DO NOT SELF-DISMISS. A real-impact hypothesis you could not DISPROVE with a run is INCONCLUSIVE,
    not safe — report it (the verifier + runner judge). Record genuine disproofs in ruled_out.

You may POST a strong finding mid-pass via the blackboard tool the moment a PoC demonstrates the win.
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
   "evidence": "the exact requests/responses (redacted) + PoC output proving it"}}],
 "ruled_out": ["<endpoint/class checked and why it is NOT exploitable>", "..."],
 "model_update": "<your DEEPENED attack-surface map + open threads + best current hypothesis to carry "
                 "into the next round (endpoints, params, roles, IDs, what you tried + outcomes)>"}}
"findings" may be []. ALWAYS fill ruled_out and model_update so the next round goes deeper."""


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
    patt = ("\nKnown attack CLASSES for this kind of system (hunt NEW variants, don't copy):\n  - "
            + "\n  - ".join(known_patterns[:10]) if known_patterns else "")
    web = ("\nYou MAY consult the web to understand the SPEC or a primitive for this kind of system "
           "(technique only — never search for this product's known bugs). A few searches at most."
           if allow_web else "")
    return f"""You are a world-class security researcher who will OWN the '{subsystem}' subsystem. This
is the MAP phase — you are NOT attacking yet and NOT writing a PoC. Your ONE deliverable is a
COMPLETE, durable MODEL of this subsystem that you (and your future rounds) will attack from.

UNLIKE later rounds, reading is ENCOURAGED here: read the subsystem's real code thoroughly (use
sub-agents for breadth, but genuinely understand it). Cite real file:line throughout.{files}{todo}{inv}{patt}{web}

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
{{"model": "<a thorough, structured model of this subsystem as described above, with file:line "
          "citations — this becomes your persistent memory>",
 "threads": ["<ranked, concrete attack thread to pursue, citing where>", "..."]}}"""


def parse_model_update(text: str) -> str:
    """Extract the ``model_update`` (or ``model``) field a hunter/mapper emitted, so it can be
    carried into the next round as the hunter's persistent memory. "" when absent/unparseable."""
    import json
    import re

    for raw in re.findall(r"\{.*\}", text or "", re.DOTALL):
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(d, dict):
            val = d.get("model_update") or d.get("model")
            if isinstance(val, str) and val.strip():
                return val.strip()
    return ""


def _parse_threads(text: str) -> list[str]:
    """Extract the ranked ``threads`` list a mapping pass emitted (its attack to-do)."""
    import json
    import re

    for raw in re.findall(r"\{.*\}", text or "", re.DOTALL):
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(d, dict) and isinstance(d.get("threads"), list):
            return [str(t).strip() for t in d["threads"] if str(t).strip()][:8]
    return []


def verify_prompt(f: ClaudeFinding) -> str:
    return f"""You are an adversarial Falsifier. PRIOR: this reported finding is WRONG until proven.
Investigate the code in the current working directory with Read/Grep/Glob/Bash and try to REFUTE it.

But refute it the RIGHT way. "The code is correct" / "the math checks out" / "there is a check here"
is NOT a refutation — correct code still loses funds when the attacker controls the input (a
provably-correct withdraw() that accepts amount = -100 still credits the attacker). To REFUTE, you
must show the attacker is actually BLOCKED: that a control CONSTRAINS the hostile value/state to the
domain the rest of the logic assumes, BEFORE it moves the protected quantity, on EVERY reachable path
(no alternate entrypoint, no missing branch, no compose-around). To CONFIRM (verdict "real"), show a
concrete attacker-controlled value/sequence that reaches the bad outcome. Only "intended AND safe
behavior" or a control that demonstrably blocks every path is a refutation; "looks correct" is not.

Reported finding:
- title: {f.title}
- severity: {f.severity}
- location: {f.file}:{f.line}
- root cause: {f.root_cause}
- counterfactual: {f.counterfactual}

Default to refuted ONLY when you have shown the attacker is blocked (or the finding is incoherent) —
not merely because the code reads as correct. Reply ONLY with JSON:
{{"verdict": "real|refuted", "severity": "critical|high|medium|low",
  "reachable": true|false, "reason": "evidence from the code for your verdict — for 'refuted', the "
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
        """Build the DISCOVERY session for this hunter — Claude by default, or the optional Codex
        engine (GPT-5.5-Codex xhigh) when `discovery_engine == 'codex'`. Both are interface-
        compatible (run(prompt,cwd)->SessionResult), so map+hunt are engine-agnostic. Only the
        discovery phase is swapped; verification/PoC/depth stay on Claude."""
        common = dict(
            agent_name=self.agent_name, on_event=self.on_event, guard_check=self.guard_check,
            max_turns=max_turns, finding_sink=finding_sink,
            allow_web=self.allow_web, web_budget=self.web_budget,
            perms=getattr(self, "perms", None), egress_hosts=getattr(self, "egress_hosts", None),
        )
        if getattr(self, "discovery_engine", "claude") == "codex":
            from .codex_session import CodexSession
            return CodexSession(model=getattr(self, "codex_model", None),
                                effort=getattr(self, "codex_effort", None), **common)
        return ClaudeSession(model=self.model, **common)

    async def _map(self, critical_means: str, repo_path: str, invariants, known_patterns,
                   subsystem: str) -> None:
        """Run the one-time MAP phase: read the subsystem deeply, produce the persistent model +
        ranked attack threads. Populates ``self._model`` and seeds ``self.investigate`` so the
        attack phase reasons over a real model. Graceful — if it fails, hunting proceeds modelless."""
        session = self._make_session(self.map_turns)
        self.on_event(self.agent_name, "message",
                      {"phase": "map", "lens": self.theme, "subsystem": subsystem})
        prompt = map_prompt(subsystem, critical_means, self.focus_files, self.investigate,
                            invariants=invariants, known_patterns=known_patterns, allow_web=self._net())
        res = await session.run(prompt, repo_path, lens=self.theme)
        self._model = parse_model_update(res.text) or self._model
        for t in _parse_threads(res.text):
            if t not in self.investigate:
                self.investigate.append(t)
        self.on_event(self.agent_name, "message",
                      {"phase": "mapped", "lens": self.theme, "model_chars": len(self._model)})

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
                          {"title": cf.title, "severity": cf.severity, "file": cf.file, "line": cf.line})

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

    async def verify(self, finding: ClaudeFinding, repo_path: str) -> tuple[str, str, str]:
        """Returns (status, severity, reason) where status is 'real' | 'refuted' | 'unverified'.
        A transient/unparseable verification is 'unverified' — NOT 'refuted' — so real
        candidates are never silently dropped when the verifier session fails."""
        session = ClaudeSession(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            perms=getattr(self, "perms", None),
            egress_hosts=getattr(self, "egress_hosts", None),
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


def poc_prompt(f: ClaudeFinding, poc_reldir: str = ".p1hunt-poc") -> str:
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
- Write PoC files ONLY into ./{poc_reldir}/ (inside the build/test tree so the toolchain runs it). NEVER modify the target source; nothing destructive.
- If a tool you need to build/run the PoC is missing (forge/anvil, cmake, a compiler, a fuzzer),
  INSTALL it yourself — sudo package manager, pip/cargo/npm/go, or an official installer are allowed.
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
  "poc_path": "relative path to your PoC under {poc_reldir}/, or ''"}}"""


def materialize_prompt(f: ClaudeFinding, scaffold: str = "", fork_url: str = "", poc_reldir: str = ".p1hunt-poc") -> str:
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

Reply ONLY with a JSON object describing what you materialized (no prose):
{{"harness_path": "<relative path under {poc_reldir} to the file the runner should execute>",
  "kind": "invariant|fork|differential|call-sequence|exploit|property|policy",
  "expect": "fail|pass",
  "test_name": "<the specific test/function to target, or ''>",
  "command": "<the command you would run; advisory only — the runner derives its own>",
  "notes": "<what the harness does and why its outcome proves the bug>"}}"""


def repair_prompt(f: ClaudeFinding, prior_spec: dict, runner_output: str,
                  scaffold: str = "", fork_url: str = "", poc_reldir: str = ".p1hunt-poc") -> str:
    scaffold_block = ("\n\nClass-appropriate scaffold for reference:\n" + scaffold) if scaffold else ""
    fork_note = (f"\nA local fork is available at {fork_url}." if fork_url else "")
    prior = str(prior_spec.get("harness_path", "")) if isinstance(prior_spec, dict) else ""
    return f"""You are an exploit engineer ITERATING on a proof harness. Your previous harness did NOT
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

If, after a GENUINE fix attempt, the bug truly does NOT reproduce (the code actually guards it), say
so in notes — that is a valid, useful outcome. Reply ONLY with the updated ReproSpec JSON (same shape):
{{"harness_path": "<relative path under {poc_reldir} to the file the runner should execute>",
  "kind": "invariant|fork|differential|call-sequence|exploit|property|policy",
  "expect": "fail|pass",
  "test_name": "<the specific test/function to target, or ''>",
  "command": "<advisory only — the runner derives its own>",
  "notes": "<what you changed and why it now proves the bug, or why it genuinely does not reproduce>"}}"""


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
            perms=getattr(self, "perms", None),
            egress_hosts=getattr(self, "egress_hosts", None),
        )
        result = await session.run(
            materialize_prompt(finding, scaffold, fork_url, getattr(self, "poc_reldir", ".p1hunt-poc")),
            repo_path, lens=finding.lens)
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

    async def repair(self, finding: ClaudeFinding, prior_spec: dict, runner_output: str,
                     repo_path: str, *, scaffold: str = "", fork_url: str = "") -> dict | None:
        """The PoC ITERATION step: the prior harness did NOT reproduce. Feed the real runner output
        back so the prover FIXES the harness (compile error, wrong setup, mis-stated expect, didn't
        reach the sink) and returns an updated ReproSpec — or None if it cannot. This turns one-shot
        proof into a run→read-failure→fix→rerun loop, converting reasoned bugs into confirmed ones."""
        self.on_event(self.agent_name, "message",
                      {"phase": "repair", "title": finding.title, "file": finding.file})
        session = ClaudeSession(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            perms=getattr(self, "perms", None),
            egress_hosts=getattr(self, "egress_hosts", None),
        )
        result = await session.run(
            repair_prompt(finding, prior_spec, runner_output, scaffold, fork_url,
                          getattr(self, "poc_reldir", ".p1hunt-poc")), repo_path, lens=finding.lens)
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
        session = ClaudeSession(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
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
    return f"""You are a finding-triage deduplicator. A new finding was just CONFIRMED. Decide if it is
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
                       prior_attempts: list | None = None) -> str:
    """The EXPLOIT-DEVELOPMENT depth phase — the organ that turns a believed PRIMITIVE into a proven
    attacker-WIN (or a rigorous impossibility). This is the long-horizon, sustained-focus job that
    separates a Medium soundness bug from a Critical: it builds the full multi-step / multi-party /
    cryptanalytic chain and DEMONSTRATES the win against shipped code, measured against the rubric."""
    rub = rubric.strip() if rubric else (
        "Critical = extract the private key or forge a rogue signature; Medium = leak key bits or "
        "memory corruption. Count failures/aborts: a smaller abort budget is a higher tier.")
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
    return f"""You are a WORLD-CLASS exploit developer and cryptanalyst. You are handed ONE believed
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
{rub}{persist}

METHOD — close the chain end to end, against the REAL shipped code:
 1. MODEL THE FULL ATTACK PATH. From the primitive to the attacker-win: every step, every value the
    attacker controls, every thing they observe, every protocol round. Write it down before coding.
 2. BUILD THE REAL ENVIRONMENT. Deploy / drive the ACTUAL library (not a toy). If the protocol is
    multi-party, SIMULATE ALL parties and play the malicious one(s) yourself. Reach PAST the gates
    (real keygen, real signing) into the value-moving logic. Put harnesses under ./{poc_reldir}/.
 3. DO THE CRYPTANALYSIS, don't hand-wave it. If the win needs math, RUN it: install and use sage,
    fpylll, sympy, numpy, pari/gp, etc. (you may install anything). Collect samples across MANY
    sessions; run nonce-bias / lattice (LLL/BKZ) / statistical key-bit recovery; build fault/abort
    ORACLES and measure how many aborts a real attacker needs. The deliverable is a NUMBER (key
    recovered, or N bits leaked, in K aborts) — not "this could leak".
 4. MEASURE against the rubric. Did you EXTRACT the key / FORGE a signature, and within what abort
    budget? That determines the tier. Half a chain is not a critical.

HARD RULES (these are what triage checks — do not fool yourself):
 - The bug MUST be in the library's OWN shipped/compiled code. If your exploit only works because of
   a concrete implementation YOU wrote for an abstract / pure-virtual (= 0) interface, it is INVALID
   — you exploited your own mock, not the library. State explicitly that your PoC drives shipped code.
 - CORRECT ≠ SAFE, but PRIMITIVE ≠ CRITICAL. Only an actually-demonstrated attacker-win counts. If
   you cannot close it, say so HONESTLY with the exact step that blocks it — a rigorous impossibility
   is a valuable, truthful result. Do NOT inflate a soundness bug into a critical.

Reply ONLY with JSON:
{{"achieved": true|false,
  "tier": "critical|high|medium|low|none",
  "win": "exactly what you demonstrated (e.g. 'recovered full ECDSA private key, x·G==pubkey')",
  "aborts": "how many failures/aborts the attack needed (number or estimate), or 'n/a'",
  "harness_path": "<relative path under {poc_reldir} to the runnable exploit, or ''>",
  "evidence": "the real run output that proves the win (or the precise step that blocks it)",
  "shipped_code": true|false,
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
                      prior_attempts: list | None = None) -> dict | None:
        """Run the sustained exploit-development session. Returns a verdict dict (or None on failure):
        achieved/tier/win/aborts/harness_path/evidence/shipped_code/impossibility."""
        _loc = getattr(finding, "file", None) or getattr(getattr(finding, "poc", None), "path", "")
        _lens = getattr(finding, "lens", "") or "trusted-execution"
        self.on_event(self.agent_name, "message",
                      {"phase": "exploit_dev", "title": getattr(finding, "title", ""), "file": _loc,
                       "attempt": len(prior_attempts or []) + 1})
        session = ClaudeSession(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            perms=getattr(self, "perms", None),
            egress_hosts=getattr(self, "egress_hosts", None),
        )
        prompt = exploit_dev_prompt(finding, rubric, getattr(self, "poc_reldir", ".p1hunt-poc"),
                                    prior_attempts=prior_attempts)
        result = await session.run(prompt, repo_path, lens=_lens)
        if not result.ok:
            self.on_event(self.agent_name, "lifecycle",
                          {"event": "exploit_dev_failed", "title": finding.title, "detail": result.error})
            return None
        v = _parse_verdict(result.text)
        if not v:
            return None
        achieved = bool(v.get("achieved")) and bool(v.get("shipped_code", True))
        self.on_event(self.agent_name, "lifecycle",
                      {"event": "exploit_developed" if achieved else "exploit_not_closed",
                       "title": finding.title, "tier": v.get("tier", "none"),
                       "win": str(v.get("win", ""))[:160], "aborts": str(v.get("aborts", "")),
                       "shipped_code": bool(v.get("shipped_code", True)),
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
        session = ClaudeSession(
            agent_name=self.agent_name, model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
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
def debate_prompt(f: ClaudeFinding, role: str) -> str:
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
    return f"""{stance}

CONFIRMED critical under debate:
- title: {f.title}
- location: {f.file}:{f.line}
- root cause: {f.root_cause}
- counterfactual: {f.counterfactual}
- evidence/repro: {f.reproduction}

Investigate the code in the working directory (Read/Grep/Glob/Bash) to ground your argument.
Reply ONLY JSON: {{"argument": "your strongest case, citing file:line", "severity": "critical|high|medium|low"}}"""


def debate_judge_prompt(f: ClaudeFinding, prosecution: str, defense: str) -> str:
    return f"""You are the JUDGE. Two researchers debated a CONFIRMED critical. Weigh BOTH arguments
against the actual code and rule impartially. Prefer truth over either side; do not rubber-stamp.

Finding: {f.title}  ({f.file}:{f.line})
Root cause: {f.root_cause}

PROSECUTION (argues invalidate/downgrade):
{prosecution[:1500]}

DEFENSE (argues genuine critical):
{defense[:1500]}

Rule: 'uphold' (stays a confirmed critical), 'downgrade' (real but lower severity — give it), or
'reject' (not a valid finding / false positive). Reply ONLY JSON:
{{"verdict": "uphold|downgrade|reject", "severity": "critical|high|medium|low",
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
        session = ClaudeSession(
            agent_name=f"{self.agent_name}:{role}", model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            perms=getattr(self, "perms", None), egress_hosts=getattr(self, "egress_hosts", None))
        res = await session.run(debate_prompt(finding, role), repo_path, lens=finding.lens)
        return str(_parse_verdict(res.text).get("argument", res.text))[:1800] if res.ok else ""

    async def adjudicate(self, finding: ClaudeFinding, repo_path: str) -> tuple[str, str, str]:
        self.on_event(self.agent_name, "message", {"phase": "debate", "title": finding.title})
        prosecution = await self._argue(finding, "prosecutor", repo_path)
        defense = await self._argue(finding, "defender", repo_path)
        judge = ClaudeSession(
            agent_name=f"{self.agent_name}:judge", model=self.model, on_event=self.on_event,
            guard_check=self.guard_check, max_turns=self.max_turns,
            perms=getattr(self, "perms", None), egress_hosts=getattr(self, "egress_hosts", None))
        res = await judge.run(debate_judge_prompt(finding, prosecution, defense), repo_path, lens=finding.lens)
        d = _parse_verdict(res.text) if res.ok else {}
        verdict = str(d.get("verdict", "uphold")).lower().strip()
        if verdict not in ("uphold", "downgrade", "reject"):
            verdict = "uphold"  # a failed/unparseable judge never silently drops a confirmed critical
        severity = str(d.get("severity", finding.severity)).lower().strip()
        reason = str(d.get("reason", ""))
        self.on_event(self.agent_name, "message",
                      {"verdict": f"debate:{verdict}", "title": finding.title, "reason": reason[:160]})
        return verdict, severity, reason
