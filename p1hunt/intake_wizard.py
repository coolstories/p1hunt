"""Interactive intake wizard (spec §2.3, §15.1).

Asks the operator for the program, scope, and target; optionally fetches the program/scope
page (read-only); builds and confirms the Scope (the human authorization step); and returns
what the swarm needs to start. No research begins until authorization is recorded (§2).
"""

from __future__ import annotations

from .acquire import fetch_text, looks_like_repo
from .models import Asset, DynamicTarget, Scope, TestIdentity
from .samples import _TAXONOMY


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        ans = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        ans = ""
    return ans or default


def _ask_list(prompt: str) -> list[str]:
    raw = _ask(prompt)
    return [item.strip() for item in raw.split(",") if item.strip()]


def run_wizard() -> tuple[Scope, list[str]] | None:
    """Returns (scope, in_scope_values) or None if the operator aborts."""
    print("\n=== P1Hunt intake — authorized safe-harbor research only ===\n")
    program = _ask("Program / engagement name")
    if not program:
        print("A program name is required. Aborting intake.")
        return None
    platform = _ask("Platform (HackerOne / Bugcrowd / Immunefi / internal)", "internal")
    scope_url = _ask("Program / scope URL to fetch (optional)")

    safe_harbor = ""
    source_urls: list[str] = []
    if scope_url:
        print(f"Fetching {scope_url} ...")
        try:
            text = fetch_text(scope_url)
            source_urls = [scope_url]
            safe_harbor = _excerpt(text)
            print(f"  fetched {len(text)} chars; captured a scope excerpt for the record.")
        except Exception as exc:
            print(f"  could not fetch ({exc}); continuing with manual scope.")

    in_scope = _ask_list("In-scope target(s) — repo URL(s) or local path(s), comma-separated")
    if not in_scope:
        print("At least one in-scope target is required. Aborting intake.")
        return None
    out_scope = _ask_list("Out-of-scope asset(s), comma-separated (optional)")
    rate = _ask("Rate limit for any approved live checks", "30 requests per minute")
    disclosure = _ask("Disclosure channel (email / URL)", "(set before submission)")

    # Optional LIVE dynamic target (the unblocker for web/API/auth criticals). Only a non-
    # production authorized instance. Credentials are read from the ENVIRONMENT (never typed here),
    # so they are not echoed or persisted; the wizard records only which env vars to read.
    dynamic_targets: list[DynamicTarget] = []
    test_identities: list[TestIdentity] = []
    base_url = _ask("Authorized LIVE base URL to test (UAT/owned/testnet — blank to skip)")
    if base_url:
        live_env = _ask("Environment of that URL (uat/owned/testnet/staging/local)", "uat").lower()
        if live_env == "production":
            print("  production is never an authorized live target — recording as static-only.")
        else:
            kind = "graphql" if "graphql" in base_url.lower() else "rest"
            dynamic_targets.append(DynamicTarget(base_url=base_url, environment=live_env, kind=kind))
            print("  Provide two test principals' tokens via env vars (NOT typed here): "
                  "P1HUNT_TOKEN_A and P1HUNT_TOKEN_B (the core of IDOR/BOLA testing).")
            for nm in ("A", "B"):
                if _ask(f"  Will P1HUNT_TOKEN_{nm} be set for principal {nm}? (yes/no)", "yes").lower() in ("y", "yes"):
                    test_identities.append(TestIdentity(name=nm, token_env=f"P1HUNT_TOKEN_{nm}"))

    scope = Scope(
        program=program,
        platform=platform,
        disclosure_channel=disclosure,
        safe_harbor_text=safe_harbor
        or "Authorized local/fork/UAT/owned-account testing only. No production writes, DoS, "
        "credential use, or third-party data access.",
        severity_taxonomy=dict(_TAXONOMY),
        in_scope=[
            Asset(f"a{i}", v, "repo" if looks_like_repo(v) else "other", v, "local")
            for i, v in enumerate(in_scope, start=1)
        ],
        out_of_scope=[Asset(f"o{i}", v, "other", v, "production") for i, v in enumerate(out_scope, start=1)],
        rules=["Use only owned accounts or synthetic data.", "No production writes.", "No DoS."],
        rate_limit=rate,
        source_urls=source_urls,
        dynamic_targets=dynamic_targets,
        test_identities=test_identities,
    )

    print("\n--- Confirm scope (your authorization) ---")
    print(f"  Program: {program} ({platform})")
    print(f"  In scope: {', '.join(in_scope)}")
    print(f"  Out of scope: {', '.join(out_scope) or 'none listed'}")
    print(f"  Rate limit: {rate}")
    if dynamic_targets:
        print(f"  Live target: {', '.join(t.base_url + ' [' + t.environment + ']' for t in dynamic_targets)}")
        print(f"  Test identities (tokens from env): {', '.join(i.name for i in test_identities) or 'none'}")
    if _ask("Authorize this engagement and begin? (yes/no)", "yes").lower() not in ("y", "yes"):
        print("Not authorized. Aborting.")
        return None
    return scope, in_scope
