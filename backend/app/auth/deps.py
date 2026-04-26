from __future__ import annotations

from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import User
from ..security import decode_token

oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


async def current_user(
    token: Optional[str] = Depends(oauth2),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    session: AsyncSession = Depends(get_session),
) -> User:
    if token:
        payload = decode_token(token)
        if payload and (username := payload.get("sub")):
            res = await session.execute(select(User).where(User.username == username))
            if user := res.scalar_one_or_none():
                return user
    if x_api_key:
        res = await session.execute(select(User).where(User.api_key == x_api_key))
        if user := res.scalar_one_or_none():
            return user
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")


async def admin_user(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin only")
    return user
