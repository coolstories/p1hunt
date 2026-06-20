"""ScopeGuard — the safety chokepoint (spec §9, MUST).

A ``PreToolUse`` hook registered globally so it covers **A, B, C, and the Falsifier**
(subagents do not inherit permissions, §3). Default ``permission_mode`` is the most
restrictive; default run mode is **dry-run** — active actions are disabled until
explicitly enabled by config *and* an in-scope check.

Every decision is logged: the guard decision log **is** the safe-harbor audit trail, and
every ``Finding`` carries a ``safe_harbor_attestation`` generated from it (§9, §2.8).

The guard **never** returns ``ask`` in unattended mode — the interactive prompt fails
silently with no TTY (§3), so hooks resolve to allow/deny only.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable

from ..models import GuardDecision, ScopeGuardPolicy


class RateLimiter:
    """Sliding-window limiter, per target. A breach is a *deny*, never a wait-then-send."""

    def __init__(self, max_per_minute: int) -> None:
        self.max_per_minute = max_per_minute
        self._hits: dict[str, deque[float]] = {}

    def allow(self, target: str, now: float | None = None) -> bool:
        if self.max_per_minute <= 0:
            return False  # no rate => no live contact permitted
        now = now if now is not None else time.time()
        window = self._hits.setdefault(target, deque())
        while window and now - window[0] > 60.0:
            window.popleft()
        if len(window) >= self.max_per_minute:
            return False
        window.append(now)
        return True


# Verbs that mutate state. Only permitted inside a sandbox environment (§9).
_WRITE_VERBS = (
    "write",
    "post",
    "put",
    "patch",
    "delete",
    "transfer",
    "send",
    "deploy",
    "approve",
    "mint",
    "sign",
    "exec",
)


class ScopeGuard:
    """The PreToolUse gate. Deny-by-default; the safe path is 'no such tool exists'."""

    def __init__(
        self,
        policy: ScopeGuardPolicy,
        *,
        on_decision: Callable[[GuardDecision], None] | None = None,
        unattended: bool = True,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.policy = policy
        self.unattended = unattended
        self._on_decision = on_decision
        self._rate = rate_limiter or RateLimiter(policy.max_requests_per_minute)
        self.decisions: list[GuardDecision] = []

    # --- the hook ---------------------------------------------------------
    def pre_tool_use(self, agent: str, tool: str, tool_input: dict) -> GuardDecision:
        """Evaluate one tool call. Returns a GuardDecision; callers MUST honor allow."""
        target = self._target_of(tool_input)
        action = f"{tool} {tool_input.get('action', '')}".strip()
        decision = self._evaluate(agent, tool, action, target, tool_input)
        self.decisions.append(decision)
        if self._on_decision is not None:
            self._on_decision(decision)
        return decision

    def _evaluate(
        self, agent: str, tool: str, action: str, target: str, tool_input: dict
    ) -> GuardDecision:
        a = action.lower()
        t = target.lower()
        environment = str(tool_input.get("environment", "")).lower()
        read_only = bool(tool_input.get("read_only", False))
        writes = any(v in a for v in _WRITE_VERBS) and not read_only

        # 1. In-scope allowlist (substring match against derived allowlist).
        if not self.policy.allowlist or not any(
            allowed.lower() in t for allowed in self.policy.allowlist
        ):
            return self._deny(agent, tool, target, "out of scope")

        # 2. Out-of-scope denylist (explicit exclusions + ambiguous assets).
        if any(d.lower() in t for d in self.policy.out_of_scope_denylist):
            return self._deny(agent, tool, target, "target is on the out-of-scope denylist")

        # 3. Destructive / prohibited by safe harbor.
        if any(term in a or term in t for term in self.policy.destructive_denylist):
            return self._deny(agent, tool, target, "destructive / prohibited by safe harbor")

        # 4. Writes restricted to the sandbox/fork (no mainnet tx, no prod connection).
        if writes:
            if self.policy.run_mode != "active":
                return self._deny(agent, tool, target, "active actions disabled (dry-run)")
            if environment and environment not in self.policy.sandbox_environments:
                return self._deny(
                    agent, tool, target, "writes restricted to sandbox/fork/UAT"
                )
            if not environment:
                return self._deny(agent, tool, target, "write without a declared sandbox env")

        # 5. HTTP method allowlist (when a method is declared).
        method = str(tool_input.get("http_method", "")).upper()
        if method and method not in self.policy.allowed_http_methods:
            return self._deny(agent, tool, target, f"HTTP method {method} not permitted")

        # 6. Chain-ID allowlist for on-chain reads (mainnet IDs are never allowlisted).
        chain_id = tool_input.get("chain_id")
        if chain_id is not None and chain_id not in self.policy.allowed_chain_ids:
            return self._deny(agent, tool, target, f"chain id {chain_id} not permitted")

        # 7. Rate limit on any live contact.
        if tool_input.get("live") and not self._rate.allow(target):
            return self._deny(agent, tool, target, "rate limit")

        # NEVER return "ask" in unattended mode — allow/deny only.
        return self._allow(agent, tool, target)

    # --- helpers ----------------------------------------------------------
    @staticmethod
    def _target_of(tool_input: dict) -> str:
        for key in ("target", "url", "host", "address", "file_path", "path", "repo", "asset"):
            if key in tool_input and tool_input[key]:
                return str(tool_input[key])
        return ""

    def _allow(self, agent: str, tool: str, target: str) -> GuardDecision:
        return GuardDecision(
            allow=True,
            reason="in scope, non-destructive, sandbox-compatible",
            tool=tool,
            target=target,
            agent=agent,
        )

    def _deny(self, agent: str, tool: str, target: str, reason: str) -> GuardDecision:
        return GuardDecision(allow=False, reason=reason, tool=tool, target=target, agent=agent)

    # --- attestation ------------------------------------------------------
    def attestation(self) -> str:
        """Safe-harbor attestation derived from the guard decision log (§2.8, §9)."""
        allowed = [d for d in self.decisions if d.allow]
        denied = [d for d in self.decisions if not d.allow]
        touched = sorted({d.target for d in allowed if d.target})
        blocked_reasons = sorted({d.reason for d in denied})
        return (
            f"ScopeGuard recorded {len(self.decisions)} decision(s): "
            f"{len(allowed)} allowed, {len(denied)} denied. "
            f"In-scope assets touched: {', '.join(touched) or 'none'}. "
            f"Blocked categories: {', '.join(blocked_reasons) or 'none'}. "
            f"Run mode: {self.policy.run_mode}; evidence mode: {self.policy.evidence_mode}."
        )
