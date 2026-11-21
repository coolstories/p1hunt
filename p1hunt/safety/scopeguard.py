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

from ..dynamic.egress import normalize_host, url_allowed
from ..models import GuardDecision, ScopeGuardPolicy


class RateLimiter:
    """Sliding-window limiter, per TARGET HOST. A breach is a *deny*, never a wait-then-send.

    Keyed on the host, never the full URL: keying on the URL made the limit meaningless, because
    varying only the path (or adding a cache-busting query) started a fresh window — 6/6 requests
    passed a ``max_per_minute=2`` limit. The rate limit exists to honor a program's rate-of-
    engagement ceiling for a HOST, so the host is the key."""

    def __init__(self, max_per_minute: int) -> None:
        self.max_per_minute = max_per_minute
        self._hits: dict[str, deque[float]] = {}

    @staticmethod
    def key_for(target: str) -> str:
        """The limiter key: the normalized host, falling back to the raw target when it has no
        host-like part (e.g. a local tool target), so a non-URL target is still rate-limited."""
        return normalize_host(target) or str(target or "").strip().lower()

    def allow(self, target: str, now: float | None = None) -> bool:
        if self.max_per_minute <= 0:
            return False  # no rate => no live contact permitted
        now = now if now is not None else time.time()
        window = self._hits.setdefault(self.key_for(target), deque())
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


def _is_url(target: str) -> bool:
    """A target that is itself an http(s) URL is a live network call regardless of which key it
    arrived under — so it must go through the egress jail, never the substring asset allowlist."""
    return target.lower().startswith(("http://", "https://"))


# Keys whose value names WHERE a call will connect. On a network call EVERY one of these is run
# through the egress jail, because the guard cannot know which key the tool will read. It used to
# evaluate a single "primary" target chosen by key order — ``target`` before ``url`` — while
# ``tools.http_sandbox`` reads ``url``: ``{"target": in-scope, "url": attacker}`` was ALLOWED and
# the audit trail logged the in-scope host that was never contacted.
_CONNECT_KEYS = frozenset({
    "url", "urls", "target", "targets", "host", "hosts", "address", "addresses",
    "endpoint", "endpoints", "uri", "uris", "base_url", "origin", "proxy", "callback_url",
})
# Keys that carry PAYLOAD, not a destination. A URL inside a body/header/param is the TARGET's
# egress (an SSRF probe, a Host-header test, an OOB callback payload) — legitimate authorized
# testing — so it is deliberately NOT treated as this call's connection target.
_PAYLOAD_KEYS = frozenset({
    "body", "data", "json", "payload", "headers", "params", "query", "form", "cookies",
    "content", "files", "prompt", "command", "reason", "note", "notes", "description",
})


def _connect_urls(tool_input: dict) -> list[str]:
    """Every value in ``tool_input`` that names a host this call would CONTACT: anything under a
    ``_CONNECT_KEYS`` key, plus any bare http(s) URL under a key that is not payload. Ordered,
    de-duplicated; ``url`` first when present so the logged target is what the tool really uses."""
    out: list[str] = []

    def _add(value: object) -> None:
        s = str(value).strip()
        if s and s not in out:
            out.append(s)

    for key in ("url", "target"):  # the two the tools actually read, in the tools' own order
        if tool_input.get(key):
            _add(tool_input[key])
    for key, value in tool_input.items():
        k = str(key).lower()
        if k in _PAYLOAD_KEYS:
            continue
        values = value if isinstance(value, (list, tuple, set)) else [value]
        for v in values:
            if isinstance(v, str) and v.strip() and (k in _CONNECT_KEYS or _is_url(v)):
                _add(v)
    return out


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

    def check_egress(self, agent: str, url: str, *, method: str = "GET") -> GuardDecision:
        """Vet one outbound request against the egress jail (host allowlist + method + rate). A
        thin wrapper over the gate for direct callers (the HTTP tool, the live client)."""
        return self.pre_tool_use(agent, "http", {"url": url, "http_method": method, "live": True})

    def record(self, agent: str, tool: str, target: str, *, allow: bool, reason: str) -> GuardDecision:
        """Record a decision MADE ELSEWHERE into the audit trail, verbatim.

        The workspace-jail (ClaudeSwarm._guard_check) is the authority for file-tool calls: a write
        into the in-scope sandbox is allowed even in dry_run (dry_run forbids touching LIVE systems,
        not writing local PoC files — §9 'sandbox/fork-only writes'). Re-deriving such a write through
        ``pre_tool_use`` would wrongly stamp it a dry_run DENY and make ``attestation`` undercount the
        in-scope actions actually performed. This logs the jail's REAL verdict so the safe-harbor
        attestation matches what happened."""
        decision = GuardDecision(allow=allow, reason=reason, tool=tool, target=target, agent=agent)
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

        # 0. LIVE NETWORK CALL (a URL or an explicit HTTP method) — the egress jail is the
        # authority for "in scope" here, not the substring allowlist. A request may reach ONLY an
        # authorized host (or loopback); destructive verbs, the HTTP-method allowlist, and the
        # rate limit still apply below. With an empty egress allowlist (no live target authorized)
        # url_allowed denies everything, so the safe default is "no live contact".
        # Accept either verb key (http_method / method) and any URL-bearing key so a live request
        # can never sidestep this branch by naming its fields differently than the gate expects.
        method = str(tool_input.get("http_method", tool_input.get("method", ""))).upper()
        is_network = bool(method) or bool(tool_input.get("url")) or _is_url(target)
        if is_network:
            from ..dynamic.egress import is_loopback

            # EVERY url-bearing value is checked, not just the one key ``_target_of`` picked: the
            # TOOL decides which key it reads, so an alias (``target`` vs ``url``) must not be able
            # to show the guard one host and hand the tool another.
            urls = _connect_urls(tool_input) or ([target] if target else [])
            # The audit trail must name what is ACTUALLY contacted — all of it, not the first key
            # that happened to parse (the safe-harbor attestation is generated from this log).
            logged = ", ".join(urls) if urls else target
            if not urls:  # a network call with nothing to check is denied (fail-closed)
                return self._deny(agent, tool, target, "no host in target")
            # In dry-run, NO live contact except loopback (a local OOB listener / local app). Even a
            # build/registry host requires active mode — so dry_run can never reach a remote host.
            if self.policy.run_mode != "active" and not all(is_loopback(u) for u in urls):
                return self._deny(agent, tool, logged, "live contact disabled (dry-run)")
            for candidate in urls:
                ok, why = url_allowed(candidate, self.policy.egress_allowlist)
                if not ok:
                    return self._deny(agent, tool, candidate, why)
            t_all = " ".join([t, *(u.lower() for u in urls)])
            if any(term in a or term in t_all for term in self.policy.destructive_denylist):
                return self._deny(agent, tool, logged, "destructive / prohibited by safe harbor")
            if method and method not in self.policy.allowed_http_methods:
                return self._deny(agent, tool, logged, f"HTTP method {method} not permitted")
            if not self._rate.allow(urls[0] if urls else target):  # host-keyed (see RateLimiter)
                return self._deny(agent, tool, logged, "rate limit")
            return self._allow(agent, tool, logged)

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
        # ``url`` FIRST: it is the key the network tools actually connect to (``http_sandbox``
        # reads ``args["url"]``), so the primary/logged target must agree with the tool. With
        # ``target`` first, ``{"target": in-scope, "url": attacker}`` logged the in-scope host.
        # (The network branch additionally checks EVERY connect key — see ``_connect_urls``.)
        for key in ("url", "target", "host", "address", "file_path", "path", "repo", "asset"):
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
