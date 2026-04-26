"""Raw TCP collector — records any raw TCP hit, tries to sniff a token from data."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from ..collector.bus import HitEvent, bus
from ..config import Settings, get_settings

log = logging.getLogger(__name__)


class TcpProtocol(asyncio.Protocol):
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._buf = b""
        self._peer = ("?", 0)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[attr-defined]
        self._peer = transport.get_extra_info("peername") or ("?", 0)

    def data_received(self, data: bytes) -> None:
        self._buf += data
        asyncio.get_running_loop().create_task(self._publish())

    async def _publish(self) -> None:
        buf = self._buf
        self._buf = b""
        # Sniff token: alphanumeric 8-32 chars in first 256 bytes
        token: str | None = None
        for part in buf[:256].split(b"\x00"):
            s = part.decode(errors="ignore").strip()
            if 8 <= len(s) <= 32 and s.isalnum():
                token = s
                break
        await bus.publish(
            HitEvent(
                protocol="tcp",
                token=token,
                remote_addr=f"{self._peer[0]}:{self._peer[1]}",
                summary=f"TCP len={len(buf)} token={token}",
                raw={"first_bytes_hex": buf[:64].hex(), "len": len(buf)},
                created_at=datetime.now(timezone.utc),
            )
        )
        self.transport.close()

    def connection_lost(self, exc: Exception | None) -> None:
        pass


async def start_tcp_server() -> asyncio.base_events.Server:
    settings = get_settings()
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: TcpProtocol(settings),
        host=settings.broker_host,
        port=settings.tcp_port,
    )
    log.info("TCP listener on %s:%d", settings.broker_host, settings.tcp_port)
    return server
