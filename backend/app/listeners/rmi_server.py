"""Minimal JRMP/RMI hit collector with optional rebind via sidecar."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from ..collector.bus import HitEvent, bus
from ..config import Settings, get_settings

log = logging.getLogger(__name__)

JRMP_MAGIC = b"JRMI"


class RmiProtocol(asyncio.Protocol):
    def __init__(self, settings: Settings, token_map: dict[int, str]) -> None:
        self._settings = settings
        self._token_map = token_map
        self._buf = b""
        self._peer = ("?", 0)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[attr-defined]
        self._peer = transport.get_extra_info("peername") or ("?", 0)
        log.debug("RMI connection from %s", self._peer)

    def data_received(self, data: bytes) -> None:
        self._buf += data
        asyncio.get_running_loop().create_task(self._handle())

    async def _handle(self) -> None:
        buf = self._buf
        self._buf = b""
        # Try to extract port-encoded token (see tokens/service.py unique-port mode)
        port = self._peer[1]
        token = self._token_map.get(port)
        # Try to sniff a URL from the data (RMI JRMP handshake raw string scan)
        if not token:
            for candidate in buf.split(b"\x00"):
                s = candidate.decode(errors="ignore")
                if 8 <= len(s) <= 32 and s.isalnum():
                    token = s
                    break
        await bus.publish(
            HitEvent(
                protocol="rmi",
                token=token,
                remote_addr=f"{self._peer[0]}:{self._peer[1]}",
                summary=f"RMI connection len={len(buf)} token={token}",
                raw={"first_bytes_hex": buf[:32].hex(), "len": len(buf)},
                created_at=datetime.now(timezone.utc),
            )
        )
        # If rebind mode: ask sidecar for JRMP referral bytes and reply
        if token:
            try:
                async with httpx.AsyncClient(timeout=self._settings.sidecar_timeout) as cli:
                    r = await cli.get(
                        f"{self._settings.sidecar_url}/rmi/referral",
                        params={
                            "token": token,
                            "codebase": f"{self._settings.http_base}/callback/http/{token}/class/",
                        },
                    )
                if r.status_code == 200:
                    self.transport.write(r.content)
                    return
            except Exception as e:
                log.debug("sidecar rmi referral: %s", e)
        # Default: send JRMP handshake ack so connection closes cleanly
        try:
            self.transport.write(b"\x4e\x00\x09" + b"127.0.0.1" + b"\x00\x00\x00\x00")
        except Exception:
            pass
        self.transport.close()

    def connection_lost(self, exc: Exception | None) -> None:
        pass


_rmi_server: asyncio.base_events.Server | None = None
_token_map: dict[int, str] = {}  # port -> token for unique-port assignment


def register_token_port(port: int, token: str) -> None:
    _token_map[port] = token


async def start_rmi_server() -> asyncio.base_events.Server:
    global _rmi_server
    settings = get_settings()
    loop = asyncio.get_running_loop()
    _rmi_server = await loop.create_server(
        lambda: RmiProtocol(settings, _token_map),
        host=settings.broker_host,
        port=settings.rmi_port,
    )
    log.info("RMI listener on %s:%d", settings.broker_host, settings.rmi_port)
    return _rmi_server
