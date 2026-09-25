"""Structured event bus for agent-to-agent coordination."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4


@dataclass(frozen=True)
class InvestigationEvent:
    type: str
    source: str
    payload: dict = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid4().hex[:12])
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


class EventBus:
    def __init__(self):
        self.history: list[InvestigationEvent] = []
        self._subscribers: dict[str, list[Callable[[InvestigationEvent], None]]] = {}

    def subscribe(self, event_type: str, handler: Callable[[InvestigationEvent], None]) -> None:
        self._subscribers.setdefault(event_type, []).append(handler)

    def publish(self, event_type: str, source: str, **payload) -> InvestigationEvent:
        event = InvestigationEvent(event_type, source, payload)
        self.history.append(event)
        for handler in (*self._subscribers.get(event_type, []), *self._subscribers.get("*", [])):
            handler(event)
        return event

    def events(self, event_type: str | None = None) -> list[dict]:
        events = self.history if event_type is None else [event for event in self.history if event.type == event_type]
        return [event.to_dict() for event in events]
