from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field


# ---------- Auth ----------
class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=128)
    email: Optional[EmailStr] = None


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    api_key: Optional[str] = None


class UserOut(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    api_key: str
    is_admin: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Project ----------
class ProjectIn(BaseModel):
    name: str
    description: Optional[str] = None


class ProjectOut(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- OOB Token ----------
class OobTokenIn(BaseModel):
    project_id: int
    label: Optional[str] = None
    protocols: list[str] = Field(default_factory=lambda: ["http", "ldap", "rmi", "tcp"])
    intent: str = "record"  # record / jndi / jndi_reference / jndi_serialize / memshell
    payload_spec: dict[str, Any] = Field(default_factory=dict)


class OobTokenOut(BaseModel):
    id: int
    token: str
    project_id: int
    label: Optional[str] = None
    protocols: list[str]
    intent: str
    payload_spec: dict[str, Any]
    created_at: datetime
    urls: dict[str, str] = Field(default_factory=dict)

    class Config:
        from_attributes = True


# ---------- Event ----------
class EventOut(BaseModel):
    id: int
    token_id: Optional[int]
    protocol: str
    remote_addr: str
    summary: str
    raw: dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Payload ----------
class PayloadRequest(BaseModel):
    type: str  # jndi_ldap / ysoserial / java_chains / memshell
    token: Optional[str] = None
    params: dict[str, Any] = Field(default_factory=dict)


class PayloadResponse(BaseModel):
    type: str
    content_type: str = "text/plain"
    value: str
    urls: dict[str, str] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)


# ---------- Memshell ----------
class MemshellRequest(BaseModel):
    framework: str  # tomcat / spring / jetty
    type: str  # filter / servlet / listener / valve / interceptor / controller
    params: dict[str, Any] = Field(default_factory=dict)
    token: Optional[str] = None
    deliver: str = "bytecode"  # bytecode / jndi_ldap / serialize


class MemshellResponse(BaseModel):
    framework: str
    type: str
    class_name: str
    bytecode_b64: Optional[str] = None
    payload: Optional[PayloadResponse] = None
    meta: dict[str, Any] = Field(default_factory=dict)


# ---------- Agent / C2 ----------
class AgentRegister(BaseModel):
    token: Optional[str] = None
    framework: str = "unknown"
    hostname: Optional[str] = None
    os: Optional[str] = None
    meta: dict[str, Any] = Field(default_factory=dict)


class AgentOut(BaseModel):
    id: int
    agent_id: str
    framework: str
    hostname: Optional[str]
    os: Optional[str]
    last_seen: datetime
    meta: dict[str, Any]

    class Config:
        from_attributes = True


class CommandIn(BaseModel):
    cmd: str


class CommandOut(BaseModel):
    id: int
    agent_id: str
    cmd: str
    status: str
    result: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
