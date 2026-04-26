"""Minimal authoritative DNS server for air-gapped OOB.

Any A/AAAA/CNAME query that matches *.{dns_zone} is answered with the
public_address; the first label before the zone is treated as the OOB token.

This lets targets call home via DNS without any external resolver, as long as
you point their /etc/resolv.conf (or DHCP) at the OOBserver host.

Uses dnslib (pure Python, no system dependencies).
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from dnslib import QTYPE, RR, A, AAAA, DNSHeader, DNSRecord
from dnslib.server import BaseResolver

from ..collector.bus import HitEvent, bus
from ..config import Settings, get_settings

log = logging.getLogger(__name__)


class OobResolver:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def resolve_async(self, data: bytes, peer: tuple) -> bytes:
        try:
            request = DNSRecord.parse(data)
        except Exception:
            return b""
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")
        zone = self._settings.dns_zone.lower()
        token: str | None = None
        if qname.lower().endswith("." + zone) or qname.lower() == zone:
            token = qname[: -(len(zone) + 1)].split(".")[-1] if "." in qname else None
            ip = self._settings.public_address
            if request.q.qtype in (QTYPE.A, QTYPE.ANY):
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ip), ttl=1))
            elif request.q.qtype == QTYPE.AAAA:
                pass  # return NODATA for AAAA
        asyncio.get_running_loop().create_task(
            bus.publish(
                HitEvent(
                    protocol="dns",
                    token=token,
                    remote_addr=f"{peer[0]}:{peer[1]}",
                    summary=f"DNS {QTYPE[request.q.qtype]} {qname}",
                    raw={
                        "qname": qname,
                        "qtype": QTYPE[request.q.qtype],
                        "zone_match": qname.lower().endswith(zone),
                    },
                    created_at=datetime.now(timezone.utc),
                )
            )
        )
        return reply.pack()


class DnsUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolver: OobResolver) -> None:
        self._resolver = resolver

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[attr-defined]

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        asyncio.get_running_loop().create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: tuple) -> None:
        resp = await self._resolver.resolve_async(data, addr)
        if resp:
            self.transport.sendto(resp, addr)  # type: ignore[attr-defined]


async def start_dns_server() -> asyncio.base_events.DatagramTransport:
    settings = get_settings()
    if not settings.dns_enabled:
        log.info("DNS listener disabled (set OOBX_DNS_ENABLED=true to enable)")
        return None  # type: ignore[return-value]
    resolver = OobResolver(settings)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DnsUdpProtocol(resolver),
        local_addr=(settings.broker_host, settings.dns_port),
    )
    log.info("DNS listener on %s:%d zone=%s", settings.broker_host, settings.dns_port, settings.dns_zone)
    return transport  # type: ignore[return-value]
