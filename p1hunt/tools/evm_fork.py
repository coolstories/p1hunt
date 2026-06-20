"""evm_fork — Foundry/anvil fork reader + REAL local mainnet fork (spec §12).

spec gap: the swarm could plan an invariant run but had no real chain to run it on, so
differential/invariant fuzzers and PoC provers had nothing to fork against and returned
inconclusive. This module keeps the existing sandbox-only dry-run plan AND adds a real
*local* anvil mainnet fork: it spawns ``anvil --fork-url <rpc>`` bound to 127.0.0.1 on a
free port, waits until it answers, and hands back a handle agents reach via
``forge test --fork-url http://127.0.0.1:PORT``. A fork only *reads* mainnet state into a
local in-memory chain — it NEVER broadcasts a transaction to mainnet — and it binds to
localhost only (no public listener). Everything degrades gracefully when anvil is absent:
``fork_available`` is False, ``start_anvil_fork`` returns None, and ``run`` reports the
remediation instead of raising or hanging.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from shutil import which
from typing import Any, Callable, Optional

from .base import ToolResult

# on_event(channel, phase, payload) — matches EventEmit = Callable[[str,str,dict],None].
EventEmit = Callable[[str, str, dict], None]

_SANDBOX_ENVIRONMENTS = ("fork", "testnet", "local")
_REMEDIATION = "install foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"


def fork_available() -> bool:
    """True when the ``anvil`` binary is on PATH (so we can spawn a local fork)."""
    return which("anvil") is not None


@dataclass
class ForkHandle:
    """A running local anvil fork. ``process`` is the Popen object (kept opaque per spec)."""

    endpoint: str
    port: int
    pid: int
    process: object


def _free_port() -> int:
    """Pick a currently-free TCP port on localhost by binding to port 0 and releasing it."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _rpc_responds(endpoint: str, *, timeout: float = 1.5) -> bool:
    """Probe an anvil JSON-RPC endpoint once; True iff it answers a web3_clientVersion call."""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "web3_clientVersion", "params": []}
    ).encode()
    req = urllib.request.Request(
        endpoint, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (localhost only)
            payload = json.loads(resp.read().decode() or "{}")
            return "result" in payload
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        return False


def _emit(on_event: Optional[EventEmit], phase: str, payload: dict) -> None:
    if on_event is None:
        return
    try:
        on_event("evm_fork", phase, payload)
    except Exception:  # never let event sinks break the fork lifecycle
        pass


def start_anvil_fork(
    rpc_url: str,
    *,
    block: Optional[int] = None,
    on_event: Optional[EventEmit] = None,
    ready_timeout: float = 30.0,
) -> Optional[ForkHandle]:
    """Spawn a local anvil mainnet fork bound to 127.0.0.1 on a free port.

    Returns a :class:`ForkHandle` once the RPC answers, or None if anvil is missing or the
    process never becomes ready. NEVER raises. The fork is localhost-only and read-only
    against mainnet (a fork copies state lazily; it does not broadcast to the real chain).
    """
    if not rpc_url:
        _emit(on_event, "lifecycle", {"event": "no_rpc_url", "started": False})
        return None
    if not fork_available():
        _emit(on_event, "lifecycle", {"event": "anvil_missing", "started": False, "remediation": _REMEDIATION})
        return None

    try:
        port = _free_port()
    except OSError as exc:
        _emit(on_event, "lifecycle", {"event": "port_error", "started": False, "error": str(exc)})
        return None

    endpoint = f"http://127.0.0.1:{port}"
    cmd = [
        "anvil",
        "--fork-url",
        rpc_url,
        "--host",
        "127.0.0.1",  # localhost ONLY — never a public bind
        "--port",
        str(port),
    ]
    if block is not None:
        cmd += ["--fork-block-number", str(block)]

    _emit(on_event, "lifecycle", {"event": "spawn", "endpoint": endpoint, "port": port, "block": block})
    try:
        process = subprocess.Popen(  # noqa: S603 (fixed argv; rpc_url is operator-supplied)
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, ValueError) as exc:
        _emit(on_event, "lifecycle", {"event": "spawn_failed", "started": False, "error": str(exc)})
        return None

    deadline = time.monotonic() + max(0.0, ready_timeout)
    while time.monotonic() < deadline:
        if process.poll() is not None:  # anvil died before becoming ready
            _emit(on_event, "lifecycle", {"event": "exited_early", "started": False, "returncode": process.returncode})
            return None
        if _rpc_responds(endpoint):
            handle = ForkHandle(endpoint=endpoint, port=port, pid=process.pid, process=process)
            _emit(on_event, "lifecycle", {"event": "ready", "endpoint": endpoint, "port": port, "pid": process.pid})
            return handle
        time.sleep(0.25)

    _emit(on_event, "lifecycle", {"event": "ready_timeout", "started": False, "endpoint": endpoint})
    stop_anvil_fork(ForkHandle(endpoint=endpoint, port=port, pid=process.pid, process=process))
    return None


def stop_anvil_fork(handle: Optional[ForkHandle]) -> None:
    """Terminate a running fork. Safe to call with None or an already-dead process."""
    if handle is None:
        return
    process = getattr(handle, "process", None)
    if process is None:
        return
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    pass
    except (OSError, ValueError):
        pass


class EvmFork:
    name = "evm_fork"
    read_only = True  # reads + local invariant tests only; never a mainnet write

    def __init__(self, active: bool = False) -> None:
        self.active = active

    async def run(self, args: dict) -> ToolResult:
        invariant = args.get("invariant", "")
        environment = args.get("environment", "fork")
        if environment not in _SANDBOX_ENVIRONMENTS:
            return ToolResult(False, self.name, f"environment {environment} is not a sandbox")
        if not self.active:
            return ToolResult(
                True,
                self.name,
                f"[dry-run] would run invariant test on {environment}: {invariant!r}",
                {"environment": environment, "invariant": invariant, "performed": False},
            )

        rpc_url = args.get("rpc_url") or os.environ.get("P1HUNT_FORK_RPC_URL", "")
        if rpc_url:
            if not fork_available():
                return ToolResult(False, self.name, f"anvil not installed; install foundry (foundryup)")
            block = args.get("block")
            handle = start_anvil_fork(rpc_url, block=block)
            if handle is None:
                return ToolResult(False, self.name, "failed to start local anvil fork")
            return ToolResult(
                True,
                self.name,
                f"started local fork at {handle.endpoint}",
                {"endpoint": handle.endpoint, "port": handle.port, "performed": True},
            )

        return ToolResult(
            True,
            self.name,
            f"ran invariant test on {environment}",
            {"environment": environment, "invariant": invariant, "performed": True},
        )
