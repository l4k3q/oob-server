from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Request, Response

from ..collector.bus import HitEvent, bus
from ..config import get_settings

log = logging.getLogger(__name__)
router = APIRouter(prefix="/callback/http", tags=["callback"])


async def _publish(token: str, request: Request, kind: str, extra: dict | None = None) -> None:
    body = b""
    try:
        body = await request.body()
    except Exception:
        pass
    raw = {
        "method": request.method,
        "path": str(request.url.path),
        "query": dict(request.query_params),
        "headers": {k: v for k, v in request.headers.items()},
        "body_b64": base64.b64encode(body).decode() if body else "",
        "body_preview": body[:256].decode(errors="replace"),
        "kind": kind,
    }
    if extra:
        raw.update(extra)
    await bus.publish(
        HitEvent(
            protocol="http",
            token=token,
            remote_addr=request.client.host if request.client else "?",
            summary=f"HTTP {request.method} {request.url.path}?{request.url.query}",
            raw=raw,
            created_at=datetime.now(timezone.utc),
        )
    )


@router.api_route("/{token}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
async def on_token(token: str, request: Request) -> Response:
    await _publish(token, request, "ping")
    return Response(content=b"ok", media_type="text/plain")


@router.api_route(
    "/{token}/{subpath:path}",
    methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
)
async def on_token_subpath(token: str, subpath: str, request: Request) -> Response:
    s = get_settings()
    # Sub-dispatch: class byte delivery
    if subpath.startswith("class/"):
        class_name = subpath[len("class/"):].rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=s.sidecar_timeout) as cli:
                r = await cli.get(
                    f"{s.sidecar_url}/class",
                    params={"token": token, "class_name": class_name},
                )
            await _publish(
                token,
                request,
                "class_fetch",
                {"class_name": class_name, "sidecar_status": r.status_code},
            )
            if r.status_code == 200:
                return Response(content=r.content, media_type="application/java-vm")
            return Response(status_code=404, content=b"class not found")
        except Exception as e:
            log.warning("sidecar class fetch failed: %s", e)
            await _publish(
                token,
                request,
                "class_fetch_error",
                {"class_name": class_name, "error": str(e)},
            )
            return Response(status_code=502, content=b"sidecar unreachable")
    await _publish(token, request, "ping", {"subpath": subpath})
    return Response(content=b"ok", media_type="text/plain")
