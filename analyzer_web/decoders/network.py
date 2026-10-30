from __future__ import annotations

import json
from typing import Any

WELL_KNOWN_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",
    135: "RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    636: "LDAPS",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def decode_firewall(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes firewall profile or rule record."""
    kind = record.get("kind")
    data = record.get("data") or {}

    if kind == "profile":
        name = data.get("Name") or "Профиль"
        enabled_val = data.get("Enabled")
        enabled_str = enabled_val.get("name") if isinstance(enabled_val, dict) else str(enabled_val)
        is_enabled = enabled_str.lower() in ("true", "1")
        inbound = data.get("DefaultInboundAction", {})
        inbound_str = inbound.get("name") if isinstance(inbound, dict) else str(inbound)
        outbound = data.get("DefaultOutboundAction", {})
        outbound_str = outbound.get("name") if isinstance(outbound, dict) else str(outbound)

        return {
            "kind": "firewall_profile",
            "name": f"Профиль: {name}",
            "profile": name,
            "enabled": "Включен" if is_enabled else "ОТКЛЮЧЕН",
            "direction": "—",
            "action": f"Вход: {inbound_str} / Выход: {outbound_str}",
            "protocol": "—",
            "ports": "—",
            "application": "—",
            "is_open": not is_enabled,
        }

    # Otherwise firewall rule
    ports = record.get("ports") or []
    first_port = ports[0] if ports else {}
    proto = first_port.get("Protocol") or "Любой"
    loc_port = first_port.get("LocalPort") or "Любой"
    rem_port = first_port.get("RemotePort") or "Любой"
    port_desc = f"{proto}:{loc_port}" if loc_port != "Любой" else proto

    apps = record.get("application") or []
    first_app = apps[0] if apps else {}
    prog = first_app.get("Program") or "Любая программа"

    raw_enabled = str(record.get("enabled", "")).lower()
    is_rule_enabled = raw_enabled in ("true", "1")

    return {
        "kind": "firewall_rule",
        "name": record.get("display_name") or record.get("name") or "Правило",
        "profile": record.get("profile") or "Все",
        "enabled": "Включено" if is_rule_enabled else "Отключено",
        "direction": record.get("direction") or "Inbound",
        "action": record.get("action") or "Allow",
        "protocol": proto,
        "ports": port_desc,
        "application": prog,
        "is_open": is_rule_enabled and record.get("action") == "Allow" and record.get("direction") == "Inbound",
    }


def _bool_or_none(value: Any) -> bool | None:
    if isinstance(value, dict): value = value.get("name")
    if value is True or str(value).lower() in ("true", "1"): return True
    if value is False or str(value).lower() in ("false", "0"): return False
    return None


def decode_management(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes SMB server config, SMB shares, or WinRM listener records."""
    kind = record.get("kind")
    data = record.get("data") or {}

    if kind == "smb_server":
        smb1 = _bool_or_none(data.get("EnableSMB1Protocol"))
        smb2 = _bool_or_none(data.get("EnableSMB2Protocol"))
        req_sig = _bool_or_none(data.get("RequireSecuritySignature"))

        reasons = []
        if smb1:
            reasons.append("Включён устаревший протокол SMBv1; наличие конкретной CVE не проверено")
        if req_sig is False:
            reasons.append("Обязательная подпись SMB отключена; применимость relay требует дополнительных условий")

        return {
            "kind": "smb_server",
            "name": "Конфигурация сервера SMB",
            "path": "Служба LanmanServer",
            "details": f"SMB1: {smb1}, SMB2: {smb2}, Подпись обязательна: {req_sig}",
            "access": "Подпись: " + ("Обязательна" if req_sig else "Не обязательна" if req_sig is False else "Нет данных"),
            "has_misconfiguration": len(reasons) > 0,
            "risk_summary": "; ".join(reasons) if reasons else "По доступным полям ослабления не выявлены; это не полная оценка SMB",
        }

    if kind == "smb_share":
        share_name = data.get("Name") or "—"
        share_path = data.get("Path") or "—"
        desc = data.get("Description") or "—"
        is_special = bool(data.get("Special"))

        access = record.get("share_access") or []
        access_entries: list[str] = []
        is_world_writable = False

        for a in access:
            acc = a.get("AccountName") or ""
            act = a.get("AccessControlType", {}).get("name") if isinstance(a.get("AccessControlType"), dict) else a.get("AccessControlType", "")
            rt = a.get("AccessRight", {}).get("name") if isinstance(a.get("AccessRight"), dict) else a.get("AccessRight", "")
            entry = f"{acc}: {act} {rt}".strip()
            access_entries.append(entry)

            acc_low = acc.lower()
            broad = acc_low.split("\\")[-1] in ("everyone", "все", "users", "пользователи", "authenticated users", "domain users", "пользователи домена", "прошедшие проверку", "s-1-1-0", "s-1-5-11", "s-1-5-32-545")
            if broad and str(act).lower() == "allow":
                if str(rt).lower() in ("full", "change", "write"):
                    is_world_writable = True

        return {
            "kind": "smb_share",
            "name": f"Ресурс: {share_name}",
            "path": share_path,
            "details": desc if desc != "—" else ("Служебный ресурс" if is_special else "Пользовательский ресурс"),
            "access": ", ".join(access_entries) if access_entries else "—",
            "has_misconfiguration": is_world_writable,
            "effective_access_evaluated": False,
            "risk_summary": "В ACL шары есть разрешение записи широкой группе; NTFS, Deny и итоговый доступ требуют проверки" if is_world_writable else "Разрешение записи широкой группе в доступных ACE не найдено",
        }

    cmd = record.get("command") or ""
    if "winrm" in str(cmd).lower():
        raw_lines = [line.strip() for line in (record.get("raw") or []) if line.strip()]
        return {
            "kind": "winrm",
            "name": "Служба WinRM",
            "path": cmd,
            "details": f"Код завершения: {record.get('exit_code')}",
            "access": " ".join(raw_lines[:3]) if raw_lines else "—",
            "has_misconfiguration": False,
            "risk_summary": "Информация о WinRM",
        }

    return {
        "kind": "management_other",
        "name": str(kind or cmd or "Управление"),
        "path": "—",
        "details": str(data),
        "access": "—",
        "has_misconfiguration": False,
        "risk_summary": "—",
    }


def decode_proxy(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes netsh winhttp proxy configuration."""
    raw_lines = record.get("raw") or []
    proxy_server = None
    bypass_list = None
    for line in raw_lines:
        line_str = str(line).strip()
        if "Proxy Server(s)" in line_str:
            proxy_server = line_str.split(":", 1)[1].strip()
        elif "Bypass List" in line_str:
            bypass_list = line_str.split(":", 1)[1].strip()

    is_configured = bool(proxy_server and proxy_server != "(none)")

    return {
        "kind": "proxy",
        "name": "WinHTTP Proxy",
        "proxy_server": proxy_server or "Прямое подключение (прокси не задан)",
        "bypass_list": bypass_list or "—",
        "command": record.get("command") or "netsh winhttp show proxy",
        "is_configured": is_configured,
        "risk_summary": f"Используется прокси: {proxy_server}" if is_configured else "Прямое соединение без прокси",
    }


def decode_tcp(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes TCP socket record."""
    loc_port = record.get("local_port")
    port_name = WELL_KNOWN_PORTS.get(loc_port, "") if loc_port else ""
    port_str = f"{loc_port} ({port_name})" if port_name else str(loc_port or "—")

    state = str(record.get("state") or "—")
    is_listen = state.lower() == "listen"

    return {
        "kind": "tcp_socket",
        "local_address": record.get("local_address") or "—",
        "local_port": port_str,
        "remote_address": record.get("remote_address") or "—",
        "remote_port": record.get("remote_port") or "—",
        "state": state,
        "pid": record.get("pid"),
        "creation_time": record.get("creation_time") or "—",
        "is_listen": is_listen,
    }


def decode_udp(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes UDP endpoint record."""
    loc_port = record.get("local_port")
    port_name = WELL_KNOWN_PORTS.get(loc_port, "") if loc_port else ""
    port_str = f"{loc_port} ({port_name})" if port_name else str(loc_port or "—")

    return {
        "kind": "udp_socket",
        "local_address": record.get("local_address") or "—",
        "local_port": port_str,
        "pid": record.get("pid"),
        "creation_time": record.get("creation_time") or "—",
    }


def decode_process(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes running process record."""
    return {
        "kind": "process",
        "name": record.get("name") or "—",
        "pid": record.get("pid"),
        "parent_pid": record.get("parent_pid"),
        "path": record.get("path") or "—",
        "command_line": record.get("command_line") or "—",
        "session_id": record.get("session_id"),
        "creation_time": record.get("creation_time") or "—",
    }


def decode_interface(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes network interface record."""
    return {
        "kind": "interface",
        "name": record.get("Name") or "—",
        "description": record.get("InterfaceDescription") or "—",
        "status": record.get("Status") or "—",
        "mac": record.get("MacAddress") or "—",
        "speed": record.get("LinkSpeed") or "—",
        "virtual": "Да" if record.get("Virtual") else "Нет",
        "ifIndex": record.get("ifIndex"),
    }


def decode_address(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes IP address record."""
    return {
        "kind": "address",
        "interface": record.get("interface") or "—",
        "address": record.get("address") or "—",
        "prefix_length": record.get("prefix_length") or "—",
        "address_family": record.get("address_family") or "—",
        "state": record.get("state") or "—",
    }


def decode_route(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes route record."""
    return {
        "kind": "route",
        "destination": record.get("destination") or "—",
        "next_hop": record.get("next_hop") or "—",
        "interface": record.get("interface") or "—",
        "metric": record.get("metric"),
        "protocol": record.get("protocol") or "—",
    }


def decode_neighbor(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes neighbor / ARP record."""
    return {
        "kind": "neighbor",
        "interface": record.get("interface") or "—",
        "address": record.get("address") or record.get("ip") or "—",
        "mac": record.get("mac") or record.get("link_layer_address") or "—",
        "state": record.get("state") or "—",
    }


def decode_dns(record: dict[str, Any], is_cache: bool = False) -> dict[str, Any]:
    """Decodes DNS server or DNS cache record."""
    if is_cache:
        return {
            "kind": "dns_cache",
            "name": record.get("Entry") or "—",
            "data": record.get("Data") or "—",
            "type": record.get("Type") or "—",
            "status": "Успешно" if record.get("Status") == 0 else f"Код {record.get('Status')}",
            "ttl": record.get("TimeToLive") or "—",
        }

    servers = record.get("servers") or []
    server_str = ", ".join(servers) if isinstance(servers, list) else str(servers)
    return {
        "kind": "dns_server",
        "interface": record.get("interface") or "—",
        "servers": server_str or "—",
    }
