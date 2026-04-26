from __future__ import annotations

from typing import Iterable

from ..config import Settings


def build_callback_urls(token: str, protocols: Iterable[str], settings: Settings) -> dict[str, str]:
    out: dict[str, str] = {}
    if "http" in protocols:
        out["http"] = f"{settings.http_base}/callback/http/{token}"
        out["http_class"] = f"{settings.http_base}/callback/http/{token}/class/"
    if "ldap" in protocols:
        out["ldap"] = f"{settings.ldap_base}/{token}"
    if "rmi" in protocols:
        out["rmi"] = f"{settings.rmi_base}/{token}"
    if "tcp" in protocols:
        out["tcp"] = f"{settings.tcp_base}/{token}"
    if "dns" in protocols and settings.dns_enabled:
        out["dns"] = f"{token}.{settings.dns_zone}"
    return out
