"""Message bus + agent registry (spec §4).

Agents are individually **addressable**. They communicate only through this bus and the
blackboard — never directly, never via ``claude -p`` subprocesses (§17). The operator can
tap into any addressable agent and inject directives without halting the swarm (§11).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .event_log import EventLog


@dataclass
class Message:
    sender: str
    recipient: str
    kind: str  # "assign" | "report" | "steer" | "query" | "ack"
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentHandle:
    name: str
    role: str  # "parent" | "worker" | "falsifier" | "echo"
    inbox: "asyncio.Queue[Message]"
    addressable: bool = True


class MessageBus:
    def __init__(self, event_log: "EventLog") -> None:
        self._log = event_log
        self._agents: dict[str, AgentHandle] = {}
        self._taps: dict[str, list[Callable[[Message], None]]] = {}

    def register(self, name: str, role: str, *, addressable: bool = True) -> AgentHandle:
        handle = AgentHandle(name=name, role=role, inbox=asyncio.Queue(), addressable=addressable)
        self._agents[name] = handle
        self._log.emit("orchestrator", "lifecycle", {"event": "register", "agent": name, "role": role})
        return handle

    def unregister(self, name: str) -> None:
        self._agents.pop(name, None)
        self._log.emit("orchestrator", "lifecycle", {"event": "unregister", "agent": name})

    def registry(self) -> list[AgentHandle]:
        return list(self._agents.values())

    def addressable_agents(self) -> list[str]:
        return [h.name for h in self._agents.values() if h.addressable]

    async def send(self, message: Message) -> None:
        self._log.emit(
            message.sender,
            "message",
            {"to": message.recipient, "kind": message.kind, "payload": message.payload},
        )
        target = self._agents.get(message.recipient)
        if target is None:
            self._log.emit("orchestrator", "lifecycle", {"event": "dead_letter", "to": message.recipient})
            return
        await target.inbox.put(message)
        for tap in self._taps.get(message.recipient, []):
            tap(message)

    def tap(self, agent: str, callback: Callable[[Message], None]) -> Callable[[], None]:
        """Operator tap-in: observe an addressable agent's inbound traffic live (§11)."""
        self._taps.setdefault(agent, []).append(callback)

        def _untap() -> None:
            if callback in self._taps.get(agent, []):
                self._taps[agent].remove(callback)

        return _untap


async def run_agent_loop(
    handle: AgentHandle,
    handler: Callable[[Message], Awaitable[None]],
    stop: "asyncio.Event",
) -> None:
    """Drive one long-lived agent: pull messages until stopped."""
    while not stop.is_set():
        try:
            message = await asyncio.wait_for(handle.inbox.get(), timeout=0.1)
        except asyncio.TimeoutError:
            continue
        await handler(message)
