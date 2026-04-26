from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..config import get_settings
from ..db import get_session
from ..models import Event, OobToken, Project, User
from ..schemas import EventOut, OobTokenIn, OobTokenOut
from .service import build_callback_urls

router = APIRouter(prefix="/api/tokens", tags=["tokens"])


def _to_out(t: OobToken) -> OobTokenOut:
    s = get_settings()
    return OobTokenOut(
        id=t.id,
        token=t.token,
        project_id=t.project_id,
        label=t.label,
        protocols=t.protocols or [],
        intent=t.intent,
        payload_spec=t.payload_spec or {},
        created_at=t.created_at,
        urls=build_callback_urls(t.token, t.protocols or [], s),
    )


@router.post("", response_model=OobTokenOut, status_code=status.HTTP_201_CREATED)
async def create_token(
    body: OobTokenIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> OobTokenOut:
    project = await session.get(Project, body.project_id)
    if not project or project.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    tok = OobToken(
        project_id=body.project_id,
        label=body.label,
        protocols=body.protocols,
        intent=body.intent,
        payload_spec=body.payload_spec,
    )
    session.add(tok)
    await session.commit()
    await session.refresh(tok)
    return _to_out(tok)


@router.get("", response_model=list[OobTokenOut])
async def list_tokens(
    project_id: int | None = None,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> list[OobTokenOut]:
    q = select(OobToken).join(Project, Project.id == OobToken.project_id).where(Project.owner_id == user.id)
    if project_id:
        q = q.where(OobToken.project_id == project_id)
    q = q.order_by(OobToken.id.desc())
    res = await session.execute(q)
    return [_to_out(t) for t in res.scalars()]


@router.get("/{token}", response_model=OobTokenOut)
async def get_token(
    token: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> OobTokenOut:
    res = await session.execute(
        select(OobToken).join(Project).where(OobToken.token == token, Project.owner_id == user.id)
    )
    t = res.scalar_one_or_none()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    return _to_out(t)


@router.get("/{token}/events", response_model=list[EventOut])
async def token_events(
    token: str,
    limit: int = Query(100, le=1000),
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> list[Event]:
    res = await session.execute(
        select(OobToken.id).join(Project).where(OobToken.token == token, Project.owner_id == user.id)
    )
    tid = res.scalar_one_or_none()
    if tid is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    res2 = await session.execute(
        select(Event).where(Event.token_id == tid).order_by(Event.id.desc()).limit(limit)
    )
    return list(res2.scalars())


@router.delete("/{token}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_token(
    token: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    res = await session.execute(
        select(OobToken).join(Project).where(OobToken.token == token, Project.owner_id == user.id)
    )
    t = res.scalar_one_or_none()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    await session.delete(t)
    await session.commit()
