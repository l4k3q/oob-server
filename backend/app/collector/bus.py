from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select

from ..db import session_scope
from ..models import Event, OobToken

log = logging.getLogger(__name__)


@dataclass
class HitEvent:
    protocol: str
    token: Optional[str]
    remote_addr: str
    summary: str
    raw: dict[str, Any]
    created_at: datetime


class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[HitEvent]] = set()

    async def publish(self, event: HitEvent) -> None:
        token_id: Optional[int] = None
        if event.token:
            async with session_scope() as session:
                res = await session.execute(select(OobToken.id).where(OobToken.token == event.token))
                token_id = res.scalar_one_or_none()
                row = Event(
                    token_id=token_id,
                    protocol=event.protocol,
                    remote_addr=event.remote_addr,
                    summary=event.summary[:500],
                    raw=event.raw,
                )
                session.add(row)
                await session.commit()
        else:
            async with session_scope() as session:
                row = Event(
                    token_id=None,
                    protocol=event.protocol,
                    remote_addr=event.remote_addr,
                    summary=event.summary[:500],
                    raw=event.raw,
                )
                session.add(row)
                await session.commit()
        dead: list[asyncio.Queue[HitEvent]] = []
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._subscribers.discard(q)

    def subscribe(self) -> asyncio.Queue[HitEvent]:
        q: asyncio.Queue[HitEvent] = asyncio.Queue(maxsize=256)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[HitEvent]) -> None:
        self._subscribers.discard(q)


bus = EventBus()


def to_dict(event: HitEvent) -> dict[str, Any]:
    d = asdict(event)
    d["created_at"] = event.created_at.isoformat()
    return d
