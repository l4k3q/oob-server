from __future__ import annotations

import secrets
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _gen_token(n: int = 12) -> str:
    return secrets.token_hex(n // 2 + 1)[:n]


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    api_key: Mapped[str] = mapped_column(String(64), unique=True, default=lambda: secrets.token_urlsafe(32))
    is_admin: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    projects: Mapped[list["Project"]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    owner: Mapped[User] = relationship(back_populates="projects")
    tokens: Mapped[list["OobToken"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class OobToken(Base):
    __tablename__ = "oob_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token: Mapped[str] = mapped_column(String(32), unique=True, index=True, default=lambda: _gen_token(12))
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    label: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    protocols: Mapped[list[str]] = mapped_column(JSON, default=list)
    intent: Mapped[str] = mapped_column(String(32), default="record")
    payload_spec: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    project: Mapped[Project] = relationship(back_populates="tokens")
    events: Mapped[list["Event"]] = relationship(back_populates="token", cascade="all, delete-orphan")


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_id: Mapped[Optional[int]] = mapped_column(ForeignKey("oob_tokens.id"), nullable=True, index=True)
    protocol: Mapped[str] = mapped_column(String(16), index=True)
    remote_addr: Mapped[str] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(String(512))
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)

    token: Mapped[Optional[OobToken]] = relationship(back_populates="events")


class Agent(Base):
    """A live memshell / implant that called home."""
    __tablename__ = "agents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, default=lambda: _gen_token(16))
    token_id: Mapped[Optional[int]] = mapped_column(ForeignKey("oob_tokens.id"), nullable=True)
    framework: Mapped[str] = mapped_column(String(32), default="unknown")  # tomcat/spring/raw
    hostname: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    os: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    meta: Mapped[dict] = mapped_column(JSON, default=dict)


class AgentCommand(Base):
    __tablename__ = "agent_commands"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(32), ForeignKey("agents.agent_id"), index=True)
    cmd: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending/sent/done
    result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())
