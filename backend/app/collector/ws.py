from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..security import decode_token
from .bus import bus, to_dict

log = logging.getLogger(__name__)
router = APIRouter()


@router.websocket("/ws/events")
async def ws_events(ws: WebSocket) -> None:
    token = ws.query_params.get("access_token")
    payload = decode_token(token) if token else None
    if not payload:
        await ws.close(code=4401)
        return
    await ws.accept()
    q = bus.subscribe()
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=15)
                await ws.send_text(json.dumps(to_dict(event), default=str))
            except asyncio.TimeoutError:
                await ws.send_text(json.dumps({"protocol": "ping"}))
    except WebSocketDisconnect:
        pass
    finally:
        bus.unsubscribe(q)
