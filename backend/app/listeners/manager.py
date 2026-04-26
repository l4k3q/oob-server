from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)

_servers: list = []


async def start_all() -> None:
    from .dns_server import start_dns_server
    from .ldap_server import start_ldap_server
    from .rmi_server import start_rmi_server
    from .tcp_collector import start_tcp_server

    tasks = [start_ldap_server(), start_rmi_server(), start_tcp_server(), start_dns_server()]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            log.error("listener start error: %s", r)
        elif r is not None:
            _servers.append(r)


async def stop_all() -> None:
    for srv in _servers:
        try:
            if hasattr(srv, "close"):
                srv.close()
        except Exception:
            pass
    _servers.clear()
