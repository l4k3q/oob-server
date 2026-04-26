from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import User
from ..schemas import TokenResponse, UserOut, UserRegister
from ..security import create_access_token, hash_password, verify_password
from .deps import current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=UserOut)
async def register(body: UserRegister, session: AsyncSession = Depends(get_session)) -> User:
    exists = await session.scalar(select(User).where(User.username == body.username))
    if exists:
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
    total = await session.scalar(select(func.count(User.id)))
    user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        is_admin=(total == 0),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    user = await session.scalar(select(User).where(User.username == form.username))
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password")
    return TokenResponse(access_token=create_access_token(user.username), api_key=user.api_key)


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(current_user)) -> User:
    return user


@router.post("/rotate-key", response_model=UserOut)
async def rotate_key(user: User = Depends(current_user), session: AsyncSession = Depends(get_session)) -> User:
    import secrets

    user.api_key = secrets.token_urlsafe(32)
    await session.commit()
    await session.refresh(user)
    return user
