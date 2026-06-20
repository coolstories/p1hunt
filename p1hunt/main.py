"""Entrypoint — wires the full workflow (spec §15 build order).

intake -> phase gates -> derivation -> delegation -> never-quit hunt -> report, with the
live observability dashboard and the control plane. Defaults to dry-run; the deterministic
reasoner keeps the whole pipeline runnable with no credentials.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import time
from pathlib import Path

from .acquire import acquire_target, looks_like_repo
from .agents.claude_swarm import ClaudeSwarm
from .agents.derive import derive_plan
from .agents.parent_a import HuntResult, ParentA
from .config import Config
from .engagement import create_engagement
from .models import Asset, EngagementStatus, Scope
from .samples import _TAXONOMY  # shared severity taxonomy for ad-hoc scopes
from .orchestrator.blackboard import Blackboard
from .orchestrator.bus import MessageBus
from .orchestrator.event_log import EventLog
from .report import render_report
from .safety.scopeguard import ScopeGuard
from .samples import sample_evm_scope, sample_web_scope, write_vulnerable_target
from .ui.dashboard import TranscriptWriter, render_snapshot
from .ui.tui import LiveTui
from .workflow import Phase, WorkflowRunner


async def run_engagement(
    scope: Scope,
    artifact_dir: str,
    *,
    config: Config,
    rounds: int | None = 8,
    live: bool = False,
    event_log: EventLog | None = None,
) -> tuple[HuntResult | None, Blackboard, EventLog, MessageBus, str]:
    log = event_log or EventLog()
    bus = MessageBus(log)
    bb = Blackboard(log)
    dashboard = LiveTui(log) if live else None
    runner = WorkflowRunner()

    # --- intake (§2.3) ---
    eng = create_engagement(scope, artifact_dir, engagements_root=config.engagements_root)
    log.redirect(eng.folder / "events.jsonl")  # full event stream -> `p1hunt watch` can replay/follow
    transcripts = TranscriptWriter(log, eng.folder / "notes")  # persist each agent's transcript (§11)
    log.emit("operator", "lifecycle", {"event": "intake", "status": eng.status.value, "folder": str(eng.folder)})
    if eng.status is EngagementStatus.BLOCKED_NEEDS_HUMAN_SCOPE_DECISION:
        log.emit("operator", "lifecycle", {"event": "blocked", "reason": "ambiguous/empty scope — no tool call attempted"})
        if dashboard:
            dashboard.close()
        transcripts.close()
        return None, bb, log, bus, "BLOCKED_NEEDS_HUMAN_SCOPE_DECISION"
    runner.complete(Phase.INTAKE, gate_passed=True)

    # --- safety gate (§15.4): the guard MUST deny out-of-scope + destructive before capability ---
    plan = derive_plan(scope, artifact_dir)
    guard = ScopeGuard(plan.scopeguard_policy, on_decision=None, unattended=config.unattended)
    oos = guard.pre_tool_use("parent_a", "http_sandbox", {"target": "evil.example.net", "live": True})
    first_asset = scope.in_scope[0].value if scope.in_scope else "x"
    dest = guard.pre_tool_use(
        "parent_a", "evm_fork", {"target": first_asset, "action": "selfdestruct", "environment": "fork"}
    )
    runner.complete(Phase.SAFETY, gate_passed=(not oos.allow and not dest.allow))
    runner.complete(Phase.ACQUISITION, gate_passed=Path(artifact_dir).exists())
    runner.complete(Phase.MAPPING, gate_passed=len(plan.surface_ranking) > 0)

    # --- delegation + never-quit hunt (§7, §8, §10) ---
    if config.use_claude:
        # The AI is the detector: a real Claude swarm reads the code and hunts.
        log.emit("operator", "lifecycle", {"event": "brain", "detail": "claude-agent-sdk swarm"})
        swarm = ClaudeSwarm(scope, artifact_dir, config=config, bus=bus, blackboard=bb, event_log=log)
        runner.complete(Phase.HYPOTHESIS, gate_passed=True)
        result = await swarm.hunt(max_rounds=rounds)  # None = never stop until a critical
    else:
        log.emit("operator", "lifecycle", {"event": "brain", "detail": "deterministic offline reasoner"})
        parent = ParentA(scope, artifact_dir, config=config, bus=bus, blackboard=bb, event_log=log)
        parent.derive()
        parent.setup_tracks()
        runner.complete(Phase.HYPOTHESIS, gate_passed=True)
        result = await parent.hunt(max_rounds=rounds if rounds is not None else 8)
    runner.complete(Phase.TESTING, gate_passed=result.status is not EngagementStatus.STOPPED)
    runner.complete(Phase.VERIFICATION, gate_passed=True)

    report = render_report(scope, result)
    runner.complete(Phase.REPORTING, gate_passed=True)  # the DRAFT is ready; human still approves

    if dashboard:
        dashboard.close()
    transcripts.close()
    return result, bb, log, bus, report


def _demo(args: argparse.Namespace) -> int:
    config = Config.from_env()
    target_dir = Path(config.engagements_root) / f"demo-target-{args.kind}"
    if target_dir.exists():
        shutil.rmtree(target_dir)  # fresh artifacts per kind — no stale cross-target files
    scope = sample_evm_scope() if args.kind == "evm" else sample_web_scope()
    write_vulnerable_target(target_dir, kind=args.kind)

    result, bb, log, bus, report = asyncio.run(
        run_engagement(scope, str(target_dir), config=config, rounds=args.rounds, live=args.live)
    )
    print(render_snapshot(log, bb, bus))
    if result is None:
        print("\nEngagement BLOCKED — needs a human scope decision.")
        return 2
    print("\n" + report)
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
        print(f"\nReport written to {args.report}")
    print(
        f"\nResult: {result.status.value} | rounds={result.rounds_run} | reframes={result.reframes} | "
        f"critical_confirmed={result.confirmed_critical}"
    )
    return 0


def build_scope(
    program: str,
    target_value: str,
    *,
    platform: str = "local",
    safe_harbor: str = "",
    rate_limit: str = "30 requests per minute for approved live checks",
    environment: str = "local",
    out_of_scope_globs: list[str] | None = None,
    scope_note: str = "",
) -> Scope:
    """Build a minimal authorized Scope for a single in-scope target (repo URL or path)."""
    kind = "repo" if (looks_like_repo(target_value) or Path(target_value).exists()) else "domain"
    return Scope(
        program=program,
        platform=platform,
        disclosure_channel="(set at intake)",
        safe_harbor_text=safe_harbor
        or "Authorized local/fork/UAT/owned-account testing only. No production writes, DoS, "
        "credential use, or third-party data access.",
        severity_taxonomy=dict(_TAXONOMY),
        in_scope=[Asset("a1", target_value, kind, target_value, environment)],
        out_of_scope=[],
        rules=["Use only owned accounts or synthetic data.", "No production writes."],
        rate_limit=rate_limit,
        source_urls=[],
        out_of_scope_globs=out_of_scope_globs or [],
        scope_note=scope_note or "",
    )


def _hunt(args: argparse.Namespace) -> int:
    config = Config.from_env()
    if args.no_claude:
        config.use_claude = False
    if getattr(args, "resume", False):
        # Continue from the saved snapshot (state.json) in the existing engagement folder —
        # skips cold reconnaissance, restores tracks/candidates/ruled-out/round. (Reuses the
        # same folder because the eng_id is derived from the program, so do NOT wipe it.)
        os.environ["P1HUNT_RESUME"] = "1"
        print("↻ RESUME mode: continuing from saved state (no cold re-scope).")
    program = args.program or f"Ad-hoc engagement ({args.target})"
    oos = [g.strip() for g in (args.out_of_scope or "").split(",") if g.strip()]
    scope = build_scope(program, args.target, platform=args.platform,
                        out_of_scope_globs=oos, scope_note=getattr(args, "scope_note", "") or "")
    max_rounds = args.max_rounds  # None => never stop until a critical is confirmed

    # Acquisition (§2.1): clone a repo URL, or use a local path as-is.
    eng_id = "".join(c if c.isalnum() else "-" for c in program.lower())[:40] or "engagement"
    eng_folder = Path(config.engagements_root) / eng_id
    if looks_like_repo(args.target):
        print(f"Acquiring {args.target} ...")
        acq = acquire_target([args.target], eng_folder, progress=lambda m: print(f"  {m}"))
        for note in acq.notes:
            print(f"  note: {note}")
        artifact_dir = acq.artifact_dir
    else:
        artifact_dir = str(Path(args.target).resolve())
        if not Path(artifact_dir).exists():
            print(f"target path does not exist: {artifact_dir}")
            return 2

    cap = "never-stop (until a critical)" if max_rounds is None else f"max {max_rounds} rounds"
    print(f"\nHunting {artifact_dir}  (brain: {'claude' if config.use_claude else 'deterministic'}, {cap})\n")
    if getattr(args, "tui", False):
        out = run_with_tui(scope, artifact_dir, config=config, rounds=max_rounds, program=program)
        if not out:
            print("Hunt ended.")
            return 0
        result, bb, log, bus, report = out
    else:
        result, bb, log, bus, report = asyncio.run(
            run_engagement(scope, artifact_dir, config=config, rounds=max_rounds, live=args.live)
        )
    print(render_snapshot(log, bb, bus))
    if result is None:
        print("\nEngagement BLOCKED — needs a human scope decision.")
        return 2
    print("\n" + report)
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
        print(f"\nReport written to {args.report}")
    print(
        f"\nResult: {result.status.value} | brain={result.brain} | rounds={result.rounds_run} | "
        f"candidates={len(result.candidates)} | critical_confirmed={result.confirmed_critical}"
    )
    return 0


def run_with_tui(scope: Scope, artifact_dir: str, *, config: Config, rounds: int | None, program: str):
    """Run the hunt in a background thread while the interactive curses cockpit renders it.
    Returns the (result, bb, log, bus, report) tuple."""
    import threading

    from .ui.tui_app import TuiState, run_tui

    log = EventLog()
    state = TuiState(program)
    log.subscribe(lambda e: state.ingest(e.agent, e.kind, e.data))
    box: dict = {}
    done = threading.Event()

    def _bg() -> None:
        try:
            box["out"] = asyncio.run(
                run_engagement(scope, artifact_dir, config=config, rounds=rounds, live=False, event_log=log)
            )
        finally:
            done.set()

    worker = threading.Thread(target=_bg, daemon=True)
    worker.start()
    run_tui(state, done.is_set)  # blocks until the operator quits (q)
    worker.join(timeout=2)
    return box.get("out")


def _ask(question: str, *, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        ans = input(f"\033[36m?\033[0m {question}{suffix}\n  > ").strip()
    except EOFError:
        ans = ""
    return ans or default


def _platform_of(url: str) -> str:
    u = url.lower()
    for p in ("immunefi", "hackerone", "bugcrowd", "cantina", "code4rena", "sherlock", "hackenproof"):
        if p in u:
            return p
    return "bug-bounty"


def _scope_from_brief(name: str, brief: dict, repo_value: str, platform: str) -> Scope:
    rules = brief.get("rules") or ["Use only owned accounts or synthetic data.", "No production writes.", "No DoS."]
    crit = brief.get("critical_means") or _TAXONOMY["P1"]
    return Scope(
        program=name, platform=platform, disclosure_channel="(per program page)",
        safe_harbor_text=" ".join(rules)[:1200] or "Authorized local/fork/UAT/owned-account testing only.",
        severity_taxonomy={**_TAXONOMY, "P1": crit},
        in_scope=[Asset("a1", repo_value, "repo", repo_value, "local")],
        out_of_scope=[], rules=rules, rate_limit=brief.get("rate_limit") or "as stated by the program",
        source_urls=brief.get("_url", []),
    )


def interactive() -> int:
    """`p1hunt` with no arguments: interview -> fetch + read rules -> confirm -> hunt."""
    from .intake_agent import research_program
    from .ui.tui import banner

    config = Config.from_env()
    banner("interactive intake", sys.stdout)
    print("Authorized safe-harbor research only.\n")

    name = _ask("What bug bounty do you want to hunt? (engagement name, e.g. 'Fireblocks MPC')")
    if not name:
        print("An engagement name is required. Exiting.")
        return 1
    url = _ask("Program URL (Immunefi / HackerOne / Bugcrowd / etc.)")
    focus = _ask("Audit a specific area? (e.g. 'Seaport' in OpenSea) — or press Enter to hunt everything")
    platform = _platform_of(url)

    brief: dict = {}
    if url and config.use_claude:
        print("\n\033[36m⠋ Fetching the program and reading the rules…\033[0m")
        brief = asyncio.run(research_program(name, url, focus, model=config.models.orchestrator))
    if not brief.get("_ok"):
        print("  (could not auto-read the program — I'll ask you directly.)")

    # --- scope confirmed ---
    print("\n\033[32m✓ Scope confirmed\033[0m")
    if brief.get("summary"):
        print(f"  {brief['summary']}")
    if brief.get("critical_means"):
        print(f"  Critical here: {brief['critical_means']}")
    if brief.get("rules"):
        print("  Rules: " + "; ".join(brief["rules"][:4]))
    repos = [r for r in (brief.get("repos") or []) if r]
    if repos:
        print(f"  In-scope source: {', '.join(repos[:3])}")
    if focus and brief.get("focus_paths"):
        print(f"  Focus '{focus}' → {', '.join(brief['focus_paths'][:3])}")

    if not repos:
        manual = _ask("Which source repo or local path should I audit?", default=focus or "")
        if not manual:
            print("No source to audit. Exiting.")
            return 1
        repos = [manual]

    eng_id = "".join(c if c.isalnum() else "-" for c in name.lower())[:40] or "engagement"
    eng_folder = Path(config.engagements_root) / eng_id
    print("\n\033[36m⠋ Acquiring source…\033[0m")
    acq = acquire_target(repos[:1], eng_folder, progress=lambda m: print(f"  {m}"))
    if not Path(acq.artifact_dir).exists():
        print("Could not acquire the source. Exiting.")
        return 2
    artifact_dir = acq.artifact_dir
    # Narrow to the focus path inside the repo, if one was identified and exists.
    for fp in brief.get("focus_paths") or ([] if not focus else [focus]):
        cand = Path(artifact_dir) / fp
        if cand.exists():
            artifact_dir = str(cand)
            print(f"  scoped to {fp}")
            break

    scope = _scope_from_brief(name, brief, repos[0], platform)
    if _ask("\nStart the hunt to find a critical? (yes/no)", default="yes").lower() not in ("y", "yes"):
        print("Not started. Your scope is saved under " + str(eng_folder))
        return 0

    print("\n  opening the live cockpit…  (↑/↓ switch agent · q to quit)")
    out = run_with_tui(scope, artifact_dir, config=config, rounds=3, program=name)
    if not out:
        print("Hunt ended.")
        return 0
    result, bb, log, bus, report = out
    print("\n" + render_snapshot(log, bb, bus))
    if result is not None:
        print("\n" + report)
        print(f"\nResult: {result.status.value} | candidates={len(result.candidates)} | "
              f"critical_confirmed={result.confirmed_critical}")
        print(f"Replay anytime:  python3 -m p1hunt.main watch {eng_folder}")
    return 0


def _new(args: argparse.Namespace) -> int:
    from .intake_wizard import run_wizard

    config = Config.from_env()
    outcome = run_wizard()
    if outcome is None:
        return 1
    scope, in_scope = outcome

    eng_id = scope.program.lower().replace(" ", "-")[:40] or "engagement"
    eng_folder = Path(config.engagements_root) / eng_id
    print("\nAcquiring in-scope target(s) ...")
    acq = acquire_target(in_scope, eng_folder, progress=lambda m: print(f"  {m}"))
    for note in acq.notes:
        print(f"  note: {note}")
    if not Path(acq.artifact_dir).exists():
        print("Nothing acquired to hunt. Aborting.")
        return 2

    cap = "never-stop (until a critical)" if args.max_rounds is None else f"max {args.max_rounds} rounds"
    print(f"\nHunting {acq.artifact_dir}  (brain: {'claude' if config.use_claude else 'deterministic'}, {cap})\n")
    result, bb, log, bus, report = asyncio.run(
        run_engagement(scope, acq.artifact_dir, config=config, rounds=args.max_rounds, live=args.live)
    )
    print(render_snapshot(log, bb, bus))
    if result is None:
        print("\nEngagement BLOCKED — needs a human scope decision.")
        return 2
    print("\n" + report)
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
        print(f"\nReport written to {args.report}")
    print(f"\nResult: {result.status.value} | brain={result.brain} | rounds={result.rounds_run} | "
          f"candidates={len(result.candidates)} | critical_confirmed={result.confirmed_critical}")
    return 0


def _watch(args: argparse.Namespace) -> int:
    if getattr(args, "tui", False):
        from .ui.tui_app import watch_tui

        watch_tui(args.target)
        return 0
    from .ui.tui import watch

    watch(args.target, follow=args.follow)
    return 0


def _notify(args: argparse.Namespace) -> int:
    """Push a live directive to a RUNNING hunt via its control.jsonl — e.g. 'new code is now
    available, keep hunting' — so it absorbs the update at the next round without a restart."""
    import json

    target = Path(args.target)
    if target.is_dir():
        ctrl = target / "control.jsonl"
    elif target.name == "events.jsonl":
        ctrl = target.with_name("control.jsonl")
    else:
        ctrl = target
    if not args.stop and not args.message and not args.paths:
        print("nothing to send — provide --message and/or --paths, or --stop")
        return 2
    rec = {
        "kind": "stop" if args.stop else "notify",
        "message": args.message or "",
        "paths": [p.strip() for p in args.paths.split(",")] if args.paths else [],
    }
    ctrl.parent.mkdir(parents=True, exist_ok=True)
    with ctrl.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    print(f"✓ notice queued → {ctrl}\n  {rec}\n(the running hunt picks it up at its next round boundary)")
    return 0


def _jumpstart(args: argparse.Namespace) -> int:
    """Operator override for the rate-limit gate. Writes a manual-clear to the shared throttle
    file: any RUNNING hunt that is cooling down picks it up within ~20s and retries immediately.
    If the hunt PROCESS has died, also print the one-liner to resume it from saved state."""
    from .agents.claude_session import _THROTTLE_FILE, _throttle_remaining

    try:
        with open(_THROTTLE_FILE, "w") as fh:
            json.dump({"throttled": False, "manual": True, "at": time.time()}, fh)
        print(f"✓ jumpstart sent (throttle file: {_THROTTLE_FILE}).")
    except OSError as exc:
        print(f"could not write throttle file: {exc}")
        return 2
    print("  • A running, cooling-down hunt will retry within ~20s.")
    print("  • If the hunt process has DIED, resume it from saved state (no progress lost) with:")
    print("      p1hunt hunt <target> --program <same name> [same flags] --resume")
    return 0


def _status(_args: argparse.Namespace) -> int:
    config = Config.from_env()
    from .agents.claude_session import _THROTTLE_FILE, sdk_available

    throttle = "clear"
    try:
        with open(_THROTTLE_FILE) as fh:
            d = json.load(fh)
        if d.get("throttled"):
            throttle = f"THROTTLED (~{d.get('seconds','?')}s, strike {d.get('strikes','?')}): {d.get('reason','')}"
    except (OSError, ValueError):
        pass
    print(f"rate-limit gate: {throttle}")

    print(f"detector brain: {'claude-agent-sdk swarm' if config.use_claude else 'deterministic offline'}")
    print(f"claude SDK available: {sdk_available()}")
    print(f"run_mode: {config.run_mode}")
    print(f"permission_mode: {config.permission_mode} (never 'ask' unattended)")
    print(f"models: {config.models.orchestrator} / {config.models.worker} / {config.models.warm_pool}")
    print(f"engagements_root: {config.engagements_root}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # No arguments -> the interactive launcher (the default experience).
    if not argv and len(sys.argv) <= 1:
        return interactive()

    parser = argparse.ArgumentParser(prog="p1hunt", description="Authorized critical bug-bounty swarm (spec.md is the contract).")
    sub = parser.add_subparsers(dest="command", required=False)

    demo = sub.add_parser("demo", help="Run a full safe-harbor hunt against a synthetic owned target.")
    demo.add_argument("--kind", choices=["web", "evm"], default="web")
    demo.add_argument("--rounds", type=int, default=8)
    demo.add_argument("--live", action="store_true", help="Stream every event live (total observability).")
    demo.add_argument("--report", help="Write the draft report to this path.")
    demo.set_defaults(func=_demo)

    hunt = sub.add_parser("hunt", help="Hunt a REAL target (local path or repo URL) with the Claude swarm.")
    hunt.add_argument("target", help="Local path to a repo, or a git/GitHub URL to clone.")
    hunt.add_argument("--program", help="Program/engagement name.")
    hunt.add_argument("--platform", default="local")
    hunt.add_argument("--max-rounds", type=int, default=None, dest="max_rounds",
                      help="Optional safety cap. Default: never stop until a critical is confirmed.")
    hunt.add_argument("--live", action="store_true", help="Stream Claude's reasoning and tool calls live (scrolling).")
    hunt.add_argument("--tui", action="store_true", help="Interactive cockpit: ↑/↓ switch agents, Blackboard tab, token usage.")
    hunt.add_argument("--report", help="Write the draft report to this path.")
    hunt.add_argument("--out-of-scope", dest="out_of_scope",
                      help="Comma-separated path globs that are present but NOT the in-scope deployed code "
                           "(e.g. 'reference/*,test/*,contracts/helpers/*'). Findings here are never promoted; "
                           "the code is used only as a differential oracle.")
    hunt.add_argument("--scope-note", dest="scope_note",
                      help="Rules-of-engagement note surfaced to Parent A and the hunters.")
    hunt.add_argument("--no-claude", action="store_true", help="Force the deterministic offline brain.")
    hunt.add_argument("--resume", action="store_true",
                      help="Continue a prior run from its saved state.json (skip cold re-scope; restore "
                           "tracks, candidates, ruled-out ledgers, and round). Use the SAME --program.")
    hunt.set_defaults(func=_hunt)

    new = sub.add_parser("new", help="Interactive intake: it asks for the program + scope URL, fetches, then hunts.")
    new.add_argument("--max-rounds", type=int, default=None, dest="max_rounds",
                     help="Optional safety cap. Default: never stop until a critical is confirmed.")
    new.add_argument("--live", action="store_true", default=True, help="Stream the swarm live (default on).")
    new.add_argument("--report", help="Write the draft report to this path.")
    new.set_defaults(func=_new)

    watch = sub.add_parser("watch", help="Claude-Code-style live/replay viewer of a hunt (agent transcripts + blackboard).")
    watch.add_argument("target", help="Engagement folder or events.jsonl path.")
    watch.add_argument("--follow", "-f", action="store_true", help="Tail the run live (Ctrl-C to stop).")
    watch.add_argument("--tui", action="store_true", help="Interactive cockpit: ↑/↓ switch agents, Blackboard tab, token usage.")
    watch.set_defaults(func=_watch)

    notify = sub.add_parser("notify", help="Send a live notice to a RUNNING hunt (e.g. new code is available) without restarting it.")
    notify.add_argument("target", help="Engagement folder or events.jsonl path of the running hunt.")
    notify.add_argument("--message", "-m", help="Notice text for the agents (e.g. 'production code is now at lib/seaport-core/src/lib — hunt it').")
    notify.add_argument("--paths", help="Comma-separated new-code paths to highlight to the agents.")
    notify.add_argument("--stop", action="store_true", help="Tell the running hunt to stop after the current round.")
    notify.set_defaults(func=_notify)

    status = sub.add_parser("status", help="Show detector brain, run mode, models, rate-limit gate, and config.")
    status.set_defaults(func=_status)

    jump = sub.add_parser("jumpstart", help="Override the rate-limit cooldown: tell a waiting hunt to retry NOW (and print how to resume a dead one).")
    jump.set_defaults(func=_jumpstart)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        return interactive()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
