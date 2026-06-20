# spec.md — Authorized Critical Bug-Bounty Workflow

> Build target for a cybersecurity research workflow and optional agentic
> implementation. This document is the contract. Where it says **MUST**, it is a hard
> requirement with a corresponding acceptance test. The workflow is only for
> authorized bug-bounty programs and MUST remain inside the program's scope,
> safe-harbor language, rate limits, and disclosure rules.
>is it a terminal app.

---

## 1. Goal

Build an end-to-end workflow that takes one authorized, in-scope target from a
bug-bounty program (Bugcrowd, HackerOne, Immunefi, Cantina, etc.) and drives the
research process to high-impact findings, especially critical/P1 candidates,
**while staying inside the program's safe harbor at all times**.

The workflow starts at program intake, derives the target-specific plan, performs
bounded reconnaissance and analysis, tests hypotheses only in approved environments,
requires reproduced evidence before severity claims, and produces a human-reviewed
report. It is not an exploit kit, scanner spammer, or autonomous submission bot.

It runs as a swarm of cooperating agents (Parent **A**, Child **B**, Child **C**)
that share discoveries and talk to each other through a blackboard and an
orchestrator-mediated message bus. **Not** via `claude -p` subprocesses — agents are
long-lived sessions on the Claude Agent SDK.

The same workflow can also be run manually by a human researcher. In agentic mode, the
agents accelerate triage, code review, hypothesis generation, and evidence packaging;
they do not weaken authorization, safety, or human-review requirements.

## 2. Non-negotiable principles (the only things that are preset)

Everything domain-specific is **derived at runtime** by Parent A (§6) or by the
human operator during manual use. The *only* things baked in are:

1. **NOTHING PRESET.** No hardcoded surface lists, hypothesis lists, tool sets, or
   per-target playbooks. Parent A classifies the target and generates the plan. A
   Solidity repo, a C++ crypto library, an APK, and a set of hosts MUST each produce
   a different derived plan, toolset, and safety policy.
2. **Authorization first.** No research begins until the program, asset, rules,
   identity requirements, rate limits, and disclosure channel are recorded. If scope
   is ambiguous, the workflow pauses for human clarification.
3. **Safety floor (safe harbor).** Every tool call passes a code-level gate (§9).
   In-scope only; sandbox/fork-only writes; non-destructive; least-data proof;
   no `ask` in unattended mode; the system never buys progress by escalating
   aggressiveness or inflating severity. The floor is invariant; its *specific
   contents* (e.g. "fork-only" vs "no production broker") are derived per engagement.
4. **Criticality requires impact, not vibes.** A finding is critical only when the
   program's own severity taxonomy says the reproduced impact is critical. Promising
   code smells, theoretical exploit paths, noisy scanner output, and "could maybe"
   chains stay as hypotheses.
5. **Minimize contact with live systems.** Prefer source review, local builds,
   forks, testnets, UAT, and synthetic accounts. Live target interaction is
   read-only, rate-limited, and only when the program explicitly permits it.
6. **Least-data evidence.** Never collect, retain, or display more third-party data
   than needed to prove impact. Use synthetic data, redaction, hashes, counts, or
   screenshots of owned test accounts whenever possible.
7. **No destructive validation.** Denial of service, persistence, lateral movement,
   malware behavior, social engineering, credential stuffing, destructive writes,
   and out-of-scope pivoting are prohibited even if they might demonstrate impact.
8. **Believe but verify.** Agents hunt with the working assumption that a P1 exists
   (drives persistence), but a finding is only ever promoted on a **reproduced
   artifact** — never on reasoning alone (§10).
9. **Total observability.** The operator can see everything and tap into any
   addressable agent at any time, without halting the swarm (§11).
10. **Human-in-the-loop.** The system never auto-submits. It surfaces verified
   candidates for human review.

## 2.1 Workflow at a glance

Every engagement follows the same control flow, but the actual surfaces, tests, and
tools are derived from the target and the program rules:

1. **Program intake:** capture safe harbor, assets, exclusions, severity taxonomy,
   rate limits, identity requirements, and disclosure channel.
2. **Scope normalization:** convert program text into machine-checkable allowlists,
   denylists, sandbox definitions, and rate policies.
3. **Target acquisition:** clone repositories, fetch released artifacts, configure
   forks/testnets/UAT accounts, and record immutable hashes or versions.
4. **Target classification:** identify the target class, trust boundaries, critical
   assets, build/runtime requirements, and approved testing environment.
5. **Surface mapping:** enumerate reachable surfaces inside scope and rank them by
   likely critical impact, privilege boundary, asset sensitivity, and testability.
6. **Hypothesis generation:** derive target-specific claims about how a critical
   impact might occur, each with a safe validation plan and explicit stop condition.
7. **Non-destructive analysis:** run source review, dependency review, configuration
   review, static analysis, local dynamic tests, and approved low-rate live checks.
8. **Evidence reproduction:** reproduce candidates in a local sandbox, fork, testnet,
   UAT tenant, or owned account, preserving logs and exact steps.
9. **Falsification:** attempt to disprove the candidate, reduce severity, identify
   duplicates, and separate root cause from symptoms.
10. **Severity mapping:** compare reproduced impact against the program taxonomy,
    including counterfactual impact and compensating controls.
11. **Report preparation:** produce a concise, reproducible, least-data report with
    safe-harbor attestation and remediation guidance.
12. **Human review and submission:** a human verifies authorization, evidence,
    wording, severity, and disclosure channel before any report is submitted.

## 2.2 Research phase contract

Each phase produces a durable artifact before the next phase may start:

- **Intake:** output a `Scope` record with source URLs, timestamps, rules, and
  taxonomy. Promotion requires human confirmation that the program is open and the
  asset is in scope.
- **Safety:** output a `ScopeGuardPolicy` with allowlist, denylist, sandbox, and
  rate policy. Promotion requires guard tests that deny out-of-scope and destructive
  actions.
- **Acquisition:** output an immutable target snapshot and environment notes.
  Promotion requires proof that only approved assets were fetched or contacted.
- **Mapping:** output a ranked surface map with trust boundaries. Promotion requires
  every surface to map back to an in-scope asset.
- **Hypothesis:** output a hypothesis backlog with a safe validation plan. Promotion
  requires each hypothesis to have a non-destructive proof strategy.
- **Testing:** output logs, local/fork/UAT results, and reproduction notes. Promotion
  requires no production harm and no third-party data exposure.
- **Verification:** output a reproduced artifact and falsifier result. Promotion
  requires the candidate to survive adversarial review.
- **Reporting:** output a draft report and safe-harbor attestation. Promotion
  requires human reviewer approval of scope, impact, and wording.

## 2.3 Engagement intake checklist

The workflow MUST create an engagement folder before any testing begins. It contains:

- `program.md`: program URL, platform, current status, disclosure channel, bounty
  table, severity taxonomy, safe-harbor language, and timestamps.
- `scope.json`: normalized in-scope assets, out-of-scope assets, ambiguous assets,
  account requirements, allowed environments, prohibited actions, and rate limits.
- `target_snapshot.json`: repository commits, release versions, package hashes,
  APK hashes, contract addresses, deployment networks, or hostnames approved for the
  engagement.
- `safety_policy.json`: derived `ScopeGuardPolicy`, including sandbox definitions,
  allowed protocols, allowed HTTP methods, allowed chain IDs, account boundaries,
  maximum request rates, and hard denials.
- `notes/`: human-readable running notes, evidence summaries, and decision logs.
- `artifacts/`: immutable evidence, local reproduction output, screenshots from
  owned accounts, redacted logs, and generated reports.

If any of these records cannot be created confidently, the engagement status becomes
`BLOCKED_NEEDS_HUMAN_SCOPE_DECISION`.

## 2.4 Critical-impact lenses

The workflow prioritizes surfaces by credible critical impact under the program's own
taxonomy. These lenses guide prioritization; they are not preset exploit playbooks.

- **Authorization boundary:** Can an unprivileged or unrelated user cross a privilege,
  tenant, wallet, organization, role, or ownership boundary?
- **Asset custody:** Can funds, tokens, keys, private content, paid entitlements, or
  other high-value assets be transferred, frozen, altered, or exposed beyond intended
  access?
- **Integrity of trusted execution:** Can build, update, signing, governance, oracle,
  admin, CI/CD, release, plugin, or dependency paths be influenced in a way that
  changes trusted output?
- **Confidentiality at scale:** Can sensitive data be accessed across many users,
  tenants, accounts, repositories, wallets, or private records? Proof MUST use
  least-data evidence and avoid third-party exposure.
- **Availability where allowed:** Only consider availability impact when the program
  explicitly accepts it and provides a safe validation method. Destructive load,
  resource exhaustion, or production DoS is prohibited.
- **Business-logic invariants:** Can core invariants be broken, such as accounting
  balance, one-time redemption, escrow release, vote weight, liquidation safety,
  pricing integrity, entitlement checks, or settlement finality?

The output is a ranked `ImpactSurface` list. Each item names the protected asset,
trust boundary, likely impact, safe validation environment, and why the program might
classify the result as critical.

## 2.5 Target-class starting points

Parent A derives the actual plan from artifacts, but these are the kinds of context it
MUST extract for common target classes:

- **Web applications and APIs:** routes, authentication model, authorization model,
  tenant boundaries, sensitive objects, state-changing operations, webhook handlers,
  upload/import flows, admin paths, integrations, and rate limits.
- **Source repositories and libraries:** build system, public API, unsafe primitives,
  dependency graph, serialization/parsing boundaries, cryptographic assumptions,
  memory-safety assumptions, release process, and tests that encode invariants.
- **Mobile apps:** package identity, API endpoints, local storage, inter-app
  communication, certificate/network configuration, feature flags, embedded secrets,
  and server-side authorization assumptions. Testing MUST use owned devices/accounts
  and approved environments.
- **Smart contracts and blockchain systems:** deployed addresses, chain IDs,
  privileged roles, upgrade paths, asset custody, accounting invariants, oracle
  dependencies, governance flow, bridge/messaging paths, and fork/testnet
  reproduction requirements.
- **Cloud and infrastructure assets:** only program-approved hosts, management
  planes, exposed metadata, identity boundaries, storage permissions, CI/CD links,
  logging/audit visibility, and non-destructive configuration evidence.
- **Supply-chain and CI/CD systems:** package names, registry ownership, release
  provenance, signing rules, workflow permissions, dependency update paths, and
  maintainer/admin boundaries.

## 2.6 Hypothesis format

Every hypothesis MUST be written before testing:

```yaml
id: HYP-0001
claim: "Specific target behavior might allow a specific critical impact."
target_assets:
  - "Only in-scope assets from scope.json"
critical_lens: "authorization-boundary | asset-custody | trusted-execution | confidentiality | availability-if-allowed | business-logic"
assumptions:
  - "What must be true for this to matter"
safe_validation_plan:
  environment: "local | fork | testnet | UAT | owned-account live check"
  max_contact: "read-only or explicitly permitted low-rate action"
  data_handling: "synthetic, owned, redacted, or aggregate only"
stop_conditions:
  - "Out-of-scope asset encountered"
  - "Unexpected third-party data appears"
  - "Validation requires destructive behavior"
evidence_required:
  - "Minimal artifact that proves or falsifies the claim"
status: "OPEN"
```

No agent may test a hypothesis that lacks `safe_validation_plan` and
`stop_conditions`.

## 2.7 Safe testing rules

The workflow allows research that is authorized, bounded, and reproducible. It denies
actions that are destructive, out of scope, or unnecessary to prove impact.

Allowed by default:

- Reading and analyzing in-scope source code, binaries, metadata, public docs, and
  program-provided artifacts.
- Running local builds, unit tests, static analyzers, dependency review, fuzzing or
  property tests against local code, and fork/testnet simulations.
- Using owned accounts, test tenants, UAT environments, or explicitly approved
  sandboxes to validate access-control and business-logic assumptions.
- Making low-rate, non-destructive live checks only when the program allows live
  testing and the target is unambiguously in scope.

Denied by default:

- Out-of-scope contact, pivoting, social engineering, phishing, credential attacks,
  malware behavior, persistence, lateral movement, or attempts to evade monitoring.
- Destructive writes, mass actions, spam, payment abuse, production DoS, lockouts, or
  actions likely to degrade service for other users.
- Accessing, downloading, retaining, or displaying third-party data beyond the minimum
  safe proof. If unexpected third-party data appears, stop and record the event.
- Bypassing platform rules to increase impact, including creating unauthorized
  accounts, exceeding rate limits, or testing excluded vulnerability classes.

## 2.8 Evidence standard for critical findings

A critical candidate MUST include:

- A precise root-cause claim tied to code, configuration, protocol design, or business
  logic.
- A reproduced artifact from an approved environment showing impact without
  destructive side effects.
- A counterfactual statement: what the actor could do before the bug, what they can do
  because of the bug, and why that delta maps to the program's critical severity.
- ScopeGuard audit excerpts proving all touched assets were in scope and every action
  stayed inside the safe validation plan.
- A minimal reproduction path that a triager can follow safely with owned data or a
  sandbox/fork.
- Clear remediation guidance that fixes the root cause, not only the observed symptom.

Candidates missing any of these stay as `Hypothesis` or `CANDIDATE`, never `Finding`.

## 2.9 Report package

The final human-reviewed report package contains:

- **Title:** concise impact and affected component.
- **Summary:** one paragraph describing the root cause and safe reproduced impact.
- **Program scope:** in-scope asset identifiers and any relevant rule references.
- **Severity rationale:** mapping to the program taxonomy, led by the counterfactual.
- **Reproduction:** safe, minimal steps using sandbox/fork/UAT/owned-account data.
- **Evidence:** redacted screenshots, logs, hashes, test output, or fork traces.
- **Impact:** what an attacker could achieve, realistic prerequisites, and limits.
- **Remediation:** concrete fixes and suggested regression tests.
- **Safe-harbor attestation:** what was touched, what was not touched, rate limits
  observed, data minimization choices, and stop conditions respected.
- **Disclosure notes:** duplicate search, related prior reports if known, and open
  questions for the triage team.

## 3. Stack & dependencies

- **Language:** Python 3.11+, asyncio throughout.
- **Agent runtime:** `claude-agent-sdk` (the renamed successor to the Claude Code
  SDK). Use `ClaudeSDKClient` for long-lived agents, `ClaudeAgentOptions`, `HookMatcher`,
  `AgentDefinition`, and the `@tool` / MCP mechanism for custom tools.
  - Agent SDK (Python): https://platform.claude.com/docs/en/agent-sdk/python
  - Hooks: https://platform.claude.com/docs/en/agent-sdk/hooks
  - Subagents: https://platform.claude.com/docs/en/agent-sdk/subagents
  - Repo: https://github.com/anthropics/claude-agent-sdk-python
- **Models (verify current strings):** orchestrator/verifier `claude-opus-4-8`,
  workers `claude-sonnet-4-6`, warm-pool watcher `claude-haiku-4-5`.
- **Per-engagement tooling** (installed only when the derivation step selects it):
  Foundry/anvil for EVM forks; static-analysis runners; APK tooling; a sandboxed
  HTTP client. These are **interfaces** (§12), not bundled exploit kits.
- **Storage:** append-only event log (JSONL) + a blackboard store (SQLite or JSON).
- **UI:** a read/subscribe dashboard over the event log + a control channel (§11).

> SDK gotchas to honor: subagents start with **blank context** (pass everything in
> the prompt); subagents do **not** inherit parent permissions (hooks MUST be
> registered so they cover subagent sessions); the interactive ask-the-user tool
> **fails silently with no TTY** — so in unattended mode hooks resolve to allow/deny,
> never `ask`; `permission_mode` does not auto-read settings — set it explicitly.

## 4. High-level architecture

```
                ┌─────────────────────────────────────────┐
   operator ───▶│  Observability UI  +  Control Channel    │
                └───────────────┬─────────────────────────┘
                                │ subscribe / inject
        ┌───────────────────────▼────────────────────────┐
        │                 ORCHESTRATOR (process)          │
        │  agent registry · message bus · event log tee   │
        └───┬───────────────┬───────────────────┬─────────┘
            │               │                   │
      ┌─────▼─────┐   ┌─────▼─────┐       ┌──────▼──────┐
      │ Parent A  │   │ Child B1  │  ...  │  Falsifier  │
      │ (Opus,    │   │ (Sonnet,  │       │  (Opus,     │
      │ long-     │   │ long-     │       │  adversarial│
      │ lived)    │   │ lived)    │       │  prior)     │
      └─────┬─────┘   └─────┬─────┘       └─────────────┘
            │               │ spawns SDK subagents
            │         ┌─────▼─────┐
            │         │ Child C*  │ (ephemeral, blank-context fan-out)
            │         └───────────┘
            ▼
   ┌──────────────────┐     every tool call from every agent
   │   BLACKBOARD      │◀──▶ passes the SCOPEGUARD PreToolUse hook
   │ scope · plan ·    │     (§9) before execution
   │ hypotheses ·      │
   │ artifacts · ctrl  │
   └──────────────────┘
```

- **Parent A** and each **Child B** are independent long-lived `ClaudeSDKClient`
  sessions owned by the Orchestrator. They are individually **addressable**
  (operator can tap in / inject). They communicate only through the Orchestrator's
  message bus and the blackboard — never directly, never via `claude -p`.
- **Child C** agents are **ephemeral SDK subagents** spawned inside a B session via
  the `agents` param for parallel hypothesis testing. Observed through the event log.
- **Falsifier** is a dedicated agent with the *opposite* prior (§10).

## 5. Data models

```python
class TargetClass(Enum):
    EVM_CONTRACT; CRYPTO_LIB; MOBILE_APP; WEB_API; INFRA; OTHER  # derived, extensible

@dataclass
class Scope:
    program: str                 # e.g. "OpenSea (Bugcrowd)"
    in_scope: list[Asset]        # addresses, domains, repos, package names, APK refs
    out_of_scope: list[Asset]
    safe_harbor_text: str
    severity_taxonomy: dict      # the PROGRAM'S own chart (VRT / CVSS / custom CCI / Immunefi)
    rules: list[str]             # raw program rules (parsed into policy by §6)

@dataclass
class EngagementPlan:            # 100% derived by Parent A — nothing preset
    target_class: TargetClass
    toolset: list[str]           # which tool modules to enable
    surface_ranking: list[str]   # ordered by reachability→impact for THIS target
    hypothesis_seeds: list[str]
    scopeguard_policy: ScopeGuardPolicy   # engagement-specific (§9)
    impact_definition: str       # what "P1" means under THIS program's taxonomy

class HypState(Enum): OPEN; TESTING; FALSIFIED; CANDIDATE; CONFIRMED

@dataclass
class Hypothesis:
    id: str; claim: str; owner_agent: str
    state: HypState
    evidence: list[ArtifactRef]  # falsifying tests OR reproducing PoC
    counterfactual: str | None   # filled before promotion (§10)

@dataclass
class Finding:                   # exists ONLY when backed by a reproduced artifact
    hypothesis_id: str; title: str; root_cause: str
    poc: ArtifactRef             # MUST be present and reproduced
    severity: str; severity_rationale: str  # leads with counterfactual
    safe_harbor_attestation: str # what was/wasn't touched (from the audit log)

@dataclass
class ControlDirective:          # operator → agent, consumed at hook checkpoint
    target_agent: str; kind: str  # "steer" | "pause" | "resume" | "stop" | "focus"
    payload: str

@dataclass
class Event:                     # everything tees here → observability
    ts: float; agent: str; kind: str  # message | tool_call | guard_decision | bb_write | reframe | finding
    data: dict
```

## 6. Derivation engine (replaces all presets)

Parent A's first action on every engagement. **MUST** run before any work is delegated.

Inputs: `Scope` (brief + parsed rules + the program's own severity taxonomy) and the
in-scope **artifacts** themselves (clone the repo / download the APK / resolve the
hosts / locate the library).

Steps:
1. **Classify** the target into a `TargetClass` from the artifacts (repo language &
   build system, presence of an APK, live hosts, a header-only crypto lib, etc.).
2. **Select toolset** appropriate to the class (§12) — and *only* that toolset.
3. **Rank the surface** by reachability→impact **for this target**, using the
   program's own taxonomy to define what counts as P1 (weight for any program
   quirks parsed from rules, e.g. non-template penalties).
4. **Seed hypothesis classes** emergent from the surface — not a fixed list.
5. **Derive the ScopeGuard policy** (§9): the engagement-specific allowlist and
   non-destructive denylist (e.g. EVM_CONTRACT → "fork-only, no mainnet tx";
   MOBILE_APP/INFRA → "UAT only, do NOT connect to any production broker/service even
   with valid creds; demonstrate capability without touching prod; flag disclosure
   obligations"; CRYPTO_LIB → "local harness only, no network").
6. Write the `EngagementPlan` to the blackboard. This is the engagement.

**Acceptance:** feeding three different scopes (an EVM repo, a C++ crypto lib, an
APK+hosts set) MUST yield three materially different `EngagementPlan`s with no shared
hardcoded surface/hypothesis/tool content.

## 7. Agents & delegation

- **Parent A** (`claude-opus-4-8`): runs §6, decomposes the plan into tracks, assigns
  each to a Child B via the message bus, watches the blackboard, joins cross-track
  threads, runs the never-quit loop (§8) and the severity gate (§10). Carries the
  optimistic "a P1 exists" prior.
- **Child B** (`claude-sonnet-4-6`, long-lived, addressable): owns one track. May spawn
  **Child C** ephemeral subagents for parallel hypotheses. Reports results to the
  blackboard. Persistence policy is bounded in cost/safety, unbounded in creativity.
- **Child C** (ephemeral subagent): one narrow hypothesis, blank context — B MUST pack
  all needed context into the spawn prompt. Returns a result string + artifact refs.
- **Falsifier** (`claude-opus-4-8`, adversarial prior): receives every CANDIDATE and
  tries to kill it (wrong / duplicate / overclaimed). Only survivors are promoted.

Tool scoping per agent via `allowed_tools` / `disallowed_tools`; recon/analysis agents
get read-only tools; any tool capable of side effects sits behind the ScopeGuard.

## 8. Never-quit control loop

Parent A does **not** self-terminate. Implement with a `Stop` hook:

```
on Stop(agent=A):
    if operator_issued_stop() or safety_event_active():
        return {}                       # allow stop
    else:
        reframe = next_frame(current_state)   # rotate lens / surface, NOT re-run
        return {"decision": "block", "reason": reframe}   # force continue, redirected
```

- **Stop is allowed only** on (a) operator `stop` directive, or (b) a safety/scope
  event. Saturation/dry-spell is **not** a stop — it triggers a **reframe** (rotate
  the analytical lens or move to an unexplored ranked surface) and, when expensive
  frames saturate, **tier demotion**: A keeps running on the `claude-haiku-4-5`
  warm-pool cadence, re-escalating to Opus only when **novelty** arrives (new audit,
  sibling-protocol bug, new technique, changed on-chain state).
- Budgets are **throttles, not stops** — exhausting a budget demotes to warm-pool, it
  does not end the engagement.
- Reframe MUST change the *frame*, never the *aggressiveness*, and never leave the
  sandbox.

## 9. ScopeGuard — the safety chokepoint (MUST)

A `PreToolUse` hook registered globally so it covers **A, B, C, and the Falsifier**
(subagents do not inherit permissions). Default `permission_mode` is the most
restrictive; default run mode is **dry-run** (active actions disabled until explicitly
enabled by config + an in-scope check).

```
on PreToolUse(tool, input):
    log(Event guard_decision, ...)            # every decision is logged (audit trail)
    if not in_scope(target_of(input), plan.scopeguard_policy.allowlist):
        return deny("out of scope")
    if matches(input, plan.scopeguard_policy.destructive_denylist):
        return deny("destructive / prohibited by safe harbor")
    if would_write_outside_sandbox(input):    # mainnet tx, prod connection, etc.
        return deny("writes restricted to sandbox/fork")
    if rate_limited(target_of(input)):
        return deny("rate limit")
    return allow()
    # NEVER return "ask" in unattended mode.
```

- The destructive denylist and the sandbox definition come from the **derived**
  `ScopeGuardPolicy` (§6), not from a global constant.
- The guard decision log **is** the safe-harbor audit trail; every `Finding` carries a
  `safe_harbor_attestation` generated from it.
- The system MUST be incapable of constructing a prohibited action — the safe path is
  "no such tool is available," with the guard as the backstop.

## 10. Believe-but-verify

- **Optimistic hunt:** A and B operate as if a P1 exists. This governs *effort and
  persistence only*.
- **Adversarial verdict:** a candidate moves OPEN → TESTING → CANDIDATE only on a
  **reproduced artifact** (a PoC/fork-test that fails the target invariant, a secret
  that actually decrypts, etc.). No artifact ⇒ it stays a `Hypothesis`, never a
  `Finding`. This is the anti-hallucination floor and it is a hard gate.
- **Falsifier pass:** every CANDIDATE is handed to the Falsifier (opposite prior) to
  be killed. Survivors only → CONFIRMED.
- **Counterfactual severity gate:** before any finding is written, A MUST state the
  counterfactual ("what could an attacker do *without* this bug?") and map impact onto
  the program's own taxonomy. Severity rationale leads with the counterfactual, not a
  dollar figure. Inflating severity to justify runtime is a prohibited "buy progress"
  move (§2.2).

## 11. Observability & control plane

- **Tee everything:** every agent's messages, tool calls, guard decisions, blackboard
  writes, reframes, and findings emit `Event`s to one append-only log. The UI
  subscribes for a live, complete view — including the full ScopeGuard decision stream.
- **Tap in:** the operator can attach to any **addressable** agent (A, any B, the
  Falsifier) and read its live transcript.
- **Inject without halting:** operator `ControlDirective`s ride a control channel;
  each agent consumes any pending directive at its next hook checkpoint (a
  `PreToolUse`/`UserPromptSubmit` hook reads and injects it as context). `pause`/`resume`
  via `defer`. Child C (ephemeral) is observed via the event log and steered through
  its parent B.
- A `stop` directive is one of the two legitimate stop-conditions in §8.

## 12. Tool modules (interface contract)

Tools are pluggable and **non-destructive by construction**. The system ships the
*interfaces* and safe defaults; the researcher supplies domain logic. No module may
contain weaponized/destructive payloads.

```python
class Tool(Protocol):
    name: str
    read_only: bool
    async def run(self, args: dict) -> ToolResult: ...   # always behind ScopeGuard
```

Examples of safe modules the derivation step may select:
- `source_fetch` (clone/read in-scope repos) — read-only
- `evm_fork` (anvil fork RPC reader, Foundry invariant-test runner) — sandbox-only
- `static_analysis` (run analyzers over source) — read-only
- `apk_inspect` (decompile + static secret scan) — read-only
- `http_sandbox` (UAT/sandbox HTTP with a method allowlist, no destructive verbs) —
  scope-checked, rate-limited

## 13. Configuration

- `models`: per-tier model strings (verify current).
- `run_mode`: `dry_run` (default) | `active` (active still fully gated by ScopeGuard).
- `budgets`: per-track token/time ceilings — **throttle to warm-pool**, never stop.
- `program_registry`: how to fetch a program's brief, rules, and severity taxonomy.
- `warm_pool_cadence`: how often demoted engagements re-check for novelty.

## 14. Module layout

```
orchestrator/
  __init__.py
  bus.py            # message bus + agent registry
  event_log.py      # append-only tee, UI subscription
  blackboard.py     # scope, plan, hypotheses, artifacts, control channel
agents/
  parent_a.py       # derivation (§6), delegation, never-quit (§8), severity gate (§10)
  child_b.py        # track worker, spawns C
  falsifier.py      # adversarial verifier
  prompts/          # role system prompts (the priors live here, in text)
safety/
  scopeguard.py     # PreToolUse hook + policy derivation
  policies.py       # ScopeGuardPolicy types (contents derived, not preset)
tools/
  base.py           # Tool protocol + ScopeGuard wrapper
  evm_fork.py  static_analysis.py  apk_inspect.py  http_sandbox.py  source_fetch.py
classify/
  classifier.py     # TargetClass from artifacts
ui/
  dashboard.py      # subscribe to event_log; render transcripts; send directives
config.py  main.py
```

## 15. Build order (milestones)

1. Engagement intake records: `program.md`, `scope.json`, `target_snapshot.json`,
   `safety_policy.json`, `notes/`, and `artifacts/`.
2. Manual workflow runner that enforces phase artifacts and promotion gates (§2.2).
3. Orchestrator + blackboard + event log + a no-op echo agent.
4. ScopeGuard PreToolUse hook in **dry-run**, with deny tests passing (§16) — safety
   before capability.
5. Classifier + derivation engine (§6); assert three-scope divergence.
6. Parent A delegation + Child B + Child C fan-out.
7. Never-quit Stop hook + reframe + warm-pool demotion.
8. Believe-but-verify: artifact floor, Falsifier, counterfactual gate.
9. Report package generator with safe-harbor attestation and human-review checklist.
10. Observability UI + tap-in/inject + pause/resume.
11. One real non-destructive tool module end-to-end (e.g. `evm_fork`).

## 16. Acceptance tests (MUST pass)

- **Program intake required:** no analysis starts unless `program.md`, `scope.json`,
  `target_snapshot.json`, and `safety_policy.json` exist and reference the current
  program rules.
- **Ambiguous scope blocks:** an asset not clearly in scope puts the engagement into
  `BLOCKED_NEEDS_HUMAN_SCOPE_DECISION`; no tool call is attempted.
- **Phase gates enforced:** mapping cannot start before acquisition artifacts exist;
  testing cannot start before a hypothesis has a safe validation plan and stop
  conditions.
- **Nothing preset:** three distinct scopes → three distinct `EngagementPlan`s; grep
  shows no hardcoded surface/hypothesis/tool list outside the derivation output.
- **Out-of-scope denied:** a tool call targeting an out-of-scope asset is denied and
  logged.
- **Destructive denied:** a mainnet write / production-service connection / destructive
  HTTP verb is denied regardless of phrasing or which agent requests it.
- **Subagent coverage:** a Child C tool call is gated by the same ScopeGuard.
- **No-`ask` unattended:** the guard never returns `ask`; no path depends on the TTY
  prompt.
- **Never-quit:** with no stop directive and no safety event, A's `Stop` is blocked and
  a *reframe* is issued (not a re-run of the prior frame).
- **Stop honored:** an operator `stop` directive halts A within N seconds.
- **Hypothesis safety:** a hypothesis with no `safe_validation_plan`, no
  `stop_conditions`, or a destructive validation path is rejected before testing.
- **Artifact floor:** a candidate without a reproduced artifact is never promoted to
  `Finding`.
- **Falsifier gate:** a deliberately overclaimed candidate is demoted by the Falsifier.
- **Least-data evidence:** a report package that includes unnecessary third-party data
  or unredacted sensitive data fails review.
- **Audit trail:** every `Finding` carries a `safe_harbor_attestation` derived from the
  guard decision log.
- **Human review required:** no report can be submitted until a human approves scope,
  impact, evidence, wording, and disclosure channel.
- **Tap-in:** the operator can attach to any addressable agent and inject a directive
  consumed at its next checkpoint without halting the swarm.

## 17. Non-goals & hard prohibitions

- **No** `claude -p` subprocesses; agents are SDK sessions.
- **No** mainnet transactions, production-service connections, destructive actions,
  production DoS, or data exfiltration. Evidence must be least-data, synthetic,
  owned-account, redacted, aggregate, or sandbox/fork-only.
- **No** auto-submission; a human reviews every candidate.
- **No** fabricated findings; no promotion without a reproduced artifact.
- **No** buying progress by escalating aggressiveness or inflating severity.
- **No** preset per-target playbooks; the plan is always derived.
- **No** weaponized/destructive payloads in tool modules.