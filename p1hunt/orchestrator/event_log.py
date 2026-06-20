"""Append-only event log + UI subscription (spec §11).

Tee everything: every agent message, tool call, guard decision, blackboard write,
reframe, and finding emits an ``Event`` here. The UI subscribes for a live, complete
view — including the full ScopeGuard decision stream.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..models import Event


def _encode(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if hasattr(obj, "value"):  # Enum
        return obj.value
    return str(obj)


class EventLog:
    """One append-only log. Synchronous append (durable) + async fan-out to subscribers."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.events: list[Event] = []
        self._subscribers: list[Callable[[Event], None]] = []
        self._queues: list[asyncio.Queue[Event]] = []

    def redirect(self, path: str | Path) -> None:
        """Point the log at a JSONL file and flush everything emitted so far (so the file is
        a complete record once the engagement folder is known)."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            for event in self.events:
                handle.write(json.dumps(
                    {"id": event.id, "ts": event.ts, "agent": event.agent,
                     "kind": event.kind, "data": event.data}, default=_encode) + "\n")

    # Live-only ephemera (token deltas) — streamed to subscribers but not persisted/kept.
    _TRANSIENT = {"stream", "stream_start"}

    def emit(self, agent: str, kind: str, data: dict | None = None) -> Event:
        event = Event(agent=agent, kind=kind, data=data or {})
        if kind not in self._TRANSIENT:
            self.events.append(event)
        if kind not in self._TRANSIENT and self.path is not None:
            line = json.dumps(
                {
                    "id": event.id,
                    "ts": event.ts,
                    "agent": event.agent,
                    "kind": event.kind,
                    "data": event.data,
                },
                default=_encode,
            )
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        for sub in list(self._subscribers):
            sub(event)
        for queue in list(self._queues):
            queue.put_nowait(event)
        return event

    def subscribe(self, callback: Callable[[Event], None]) -> Callable[[], None]:
        """Synchronous subscription. Returns an unsubscribe handle."""
        self._subscribers.append(callback)

        def _unsub() -> None:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

        return _unsub

    def stream(self) -> asyncio.Queue[Event]:
        """An async queue that receives every subsequent event (for the live UI)."""
        queue: asyncio.Queue[Event] = asyncio.Queue()
        self._queues.append(queue)
        return queue

    def tail(self, n: int = 40, *, kind: str | None = None) -> list[Event]:
        items = [e for e in self.events if kind is None or e.kind == kind]
        return items[-n:]

    def since(self, ts: float) -> list[Event]:
        return [e for e in self.events if e.ts >= ts]


def now() -> float:
    return time.time()
