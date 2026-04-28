from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException, status

from .auth.deps import current_user
from .config import get_settings

router = APIRouter(prefix="/api/compile", tags=["compile"])


@router.post("")
async def compile_java(body: dict, _: str = Depends(current_user)) -> dict:
    """Compile Java source code to bytecode via sidecar javac.

    Request body:
      source      – Java source code (required)
      class_name  – public class name; auto-detected from source if omitted

    Returns:
      class_name, bytecode_b64
    """
    s = get_settings()
    try:
        async with httpx.AsyncClient(timeout=s.sidecar_timeout) as cli:
            r = await cli.post(f"{s.sidecar_url}/compile", json=body)
        if r.status_code == 200:
            return r.json()
        raise HTTPException(r.status_code, r.json().get("error", r.text[:200]))
    except httpx.ConnectError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "bytecode-service is not running")
