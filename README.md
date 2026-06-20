# p1hunt — authorized critical bug-bounty swarm

**`spec.md` is the contract.** This package implements it: a never-quit, safe-harbor swarm
that drives one authorized, in-scope target toward *reproduced* critical findings while
staying inside the program's safe harbor at all times. It defaults to **dry-run** and runs
fully — derivation, delegation, never-quit hunt, believe-but-verify, total observability —
with **no credentials and no live API calls**. The Claude Agent SDK is an optional "brain"
that slots in when credentials exist (`pip install -e .[agent]`).

## Run

```sh
python3 -m p1hunt.main demo --kind web --rounds 8 --live   # watch every event stream by
python3 -m p1hunt.main demo --kind evm --report out.md     # EVM target, write the report
python3 -m p1hunt.main status
```

## Acceptance tests (spec §16 — all MUST pass)

```sh
python3 -m unittest discover -s tests -v
```

## How the code maps to the spec

| Spec | Module |
| --- | --- |
| §5 data models | `p1hunt/models.py` |
| §6 derivation (nothing preset) | `p1hunt/agents/derive.py`, `p1hunt/classify/` |
| §7 agents (A / B / C / Falsifier) | `p1hunt/agents/parent_a.py`, `child_b.py`, `falsifier.py` |
| §7 specific creative delegation | `p1hunt/agents/instructions.py` |
| §8 never-quit loop + reframe + warm pool | `parent_a.ParentA.on_stop` / `hunt` |
| §9 ScopeGuard chokepoint | `p1hunt/safety/scopeguard.py`, `policies.py` |
| §10 believe-but-verify (artifact floor) | `p1hunt/agents/reasoner.py` |
| §4/§11 orchestrator + observability | `p1hunt/orchestrator/`, `p1hunt/ui/dashboard.py` |
| §12 safe tool modules | `p1hunt/tools/` |
| §2.3 engagement intake / §2.2 phase gates | `p1hunt/engagement.py`, `p1hunt/workflow.py` |
| §2.9 report package | `p1hunt/report.py` |
| §13 config | `p1hunt/config.py` |
| §15 entrypoint | `p1hunt/main.py` |

## The three things that make it "crazy good"

- **See it all (§11):** every message, tool call, guard decision, blackboard write,
  reframe, and finding tees to one append-only log; `--live` streams the whole thing,
  and `render_snapshot` gives a point-in-time view. The operator can tap any addressable
  agent and inject directives without halting the swarm.
- **Won't give up (§8, §10):** on a dry spell Parent A *reframes* (rotate lens/surface,
  deepen analysis) rather than stopping, demoting to a warm pool and re-escalating on
  novelty. Corroboration depth climbs with persistence, so a weak signal that fails round 1
  is confirmed after several reframes — **never** by escalating aggressiveness, and never
  promoted without a reproduced artifact.
- **Specific, creative delegation (§7):** Parent A hands Child B a concrete, file-anchored
  brief (lens, exact start points, creative analytical paths, safe environment, stop
  conditions) — not "do better." Child B packs full context into each blank-context Child C
  with exactly one creative path to pursue.

## Safety posture

Defensive, authorized research only. Deny-by-default ScopeGuard; sandbox/fork/UAT/owned
evidence only; least-data; no destructive validation; no auto-submission; a human approves
every report. See `spec.md` §17 for the hard prohibitions.

> The earlier TypeScript/Next.js prototype (`app/`, `cli/`, `lib/`, `package.json`) predates
> this spec and does not conform to it. It is left untouched; the `p1hunt/` Python package is
> the spec-conformant implementation.
