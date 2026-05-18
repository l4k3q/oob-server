"""Minimal JRMP/RMI hit collector with optional rebind via sidecar."""
from __future__ import annotations

import asyncio
import logging
import re
import struct
from datetime import datetime, timezone

import httpx

from ..collector.bus import HitEvent, bus
from ..config import Settings, get_settings

log = logging.getLogger(__name__)

JRMP_MAGIC = b"JRMI"
JRMP_VERSION = 2
STREAM_PROTOCOL = 0x4B
SINGLE_OP_PROTOCOL = 0x4C
MULTIPLEX_PROTOCOL = 0x4D
PROTOCOL_ACK = 0x4E
TRANSPORT_CALL = 0x50
TOKEN_RE = re.compile(rb"(?<![A-Za-z0-9])([A-Za-z0-9]{8,32})(?:/[A-Za-z0-9_$]+)?")


def _write_utf(value: str) -> bytes:
    data = value.encode("utf-8")
    return struct.pack(">H", len(data)) + data


def _extract_token(buf: bytes) -> str | None:
    match = TOKEN_RE.search(buf)
    if not match:
        return None
    return match.group(1).decode(errors="ignore")


class RmiProtocol(asyncio.Protocol):
    def __init__(self, settings: Settings, token_map: dict[int, str]) -> None:
        self._settings = settings
        self._token_map = token_map
        self._buf = b""
        self._peer = ("?", 0)
        self._local = ("?", 0)
        self._stage = "handshake"
        self._published = False
        self._task: asyncio.Task[None] | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[attr-defined]
        self._peer = transport.get_extra_info("peername") or ("?", 0)
        self._local = transport.get_extra_info("sockname") or ("?", 0)
        log.debug("RMI connection from %s", self._peer)

    def data_received(self, data: bytes) -> None:
        self._buf += data
        if not self._task or self._task.done():
            self._task = asyncio.get_running_loop().create_task(self._handle())

    async def _handle(self) -> None:
        while True:
            if self._stage == "handshake":
                if len(self._buf) < 7:
                    return
                magic = self._buf[:4]
                version = int.from_bytes(self._buf[4:6], "big")
                protocol = self._buf[6]
                self._buf = self._buf[7:]
                if magic != JRMP_MAGIC or version != JRMP_VERSION:
                    await self._publish(None, "invalid JRMP handshake", self._buf)
                    self.transport.close()
                    return
                if protocol == STREAM_PROTOCOL:
                    host = str(self._peer[0])
                    port = int(self._peer[1] or 0)
                    self.transport.write(bytes([PROTOCOL_ACK]) + _write_utf(host) + struct.pack(">I", port))
                    self._stage = "client_endpoint"
                    continue
                if protocol == SINGLE_OP_PROTOCOL:
                    self._stage = "call"
                    continue
                if protocol == MULTIPLEX_PROTOCOL:
                    await self._publish(None, "unsupported JRMP multiplex protocol", self._buf)
                    self.transport.close()
                    return
                await self._publish(None, f"unsupported JRMP protocol={protocol}", self._buf)
                self.transport.close()
                return

            if self._stage == "client_endpoint":
                if len(self._buf) < 2:
                    return
                host_len = int.from_bytes(self._buf[:2], "big")
                total = 2 + host_len + 4
                if len(self._buf) < total:
                    return
                self._buf = self._buf[total:]
                self._stage = "call"
                continue

            if self._stage == "call":
                if not self._buf:
                    return
                token = self._token_map.get(int(self._local[1] or 0)) or _extract_token(self._buf)
                if not token:
                    if self._buf[0] != TRANSPORT_CALL or len(self._buf) > 4096:
                        await self._publish(None, "RMI connection without token", self._buf)
                        self.transport.close()
                    return
                await self._publish(token, f"RMI registry lookup token={token}", self._buf)
                if await self._send_referral(token):
                    return
                self.transport.close()
                return

    async def _publish(self, token: str | None, summary: str, buf: bytes) -> None:
        if self._published:
            return
        self._published = True
        await bus.publish(
            HitEvent(
                protocol="rmi",
                token=token,
                remote_addr=f"{self._peer[0]}:{self._peer[1]}",
                summary=summary,
                raw={"first_bytes_hex": buf[:32].hex(), "len": len(buf), "stage": self._stage},
                created_at=datetime.now(timezone.utc),
            )
        )

    async def _send_referral(self, token: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self._settings.sidecar_timeout) as cli:
                r = await cli.get(
                    f"{self._settings.sidecar_url}/rmi/referral",
                    params={
                        "token": token,
                        "codebase": f"{self._settings.http_base}/callback/http/{token}/class/",
                    },
                )
            if r.status_code == 200 and r.content:
                self.transport.write(r.content)
                self.transport.close()
                return True
            log.debug("sidecar rmi referral status=%s body=%s", r.status_code, r.text[:120])
        except Exception as e:
            log.debug("sidecar rmi referral: %s", e)
        return False

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
