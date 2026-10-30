from __future__ import annotations

import base64
import os
import re
from pathlib import Path
from typing import Any

POWERSHELL_PROFILE_KEYWORDS: tuple[str, ...] = (
    "downloadstring",
    "downloadfile",
    "invoke-expression",
    "iex",
    "invoke-webrequest",
    "iwr",
    "invoke-command",
    "get-service",
    "start-service",
    "set-service",
    "get-aduser",
    "get-adcomputer",
    "get-adgroup",
    "get-smbshare",
    "new-smbshare",
    "get-netipconfiguration",
    "get-nettcpconnection",
    "get-dnsclientcache",
    "resolve-dnsname",
    "test-netconnection",
    "backup",
    "sqlcmd",
    "psql",
    "import-module",
    "install-module",
    "install-windowsfeature",
    "get-scheduledtask",
    "register-scheduledtask",
    "webclient",
    "certutil",
    "net user",
    "net group",
    "net localgroup",
    "whoami",
    "nltest",
    "rundll32",
    "reg query",
    "reg add",
    "psexec",
    "powershell -enc",
    "powershell -e ",
    "frombase64string",
    "stop-service",
    "set-executionpolicy",
)

SYSTEM_ACCOUNTS: frozenset[str] = frozenset({
    "localsystem",
    "nt authority\\localsystem",
    "nt authority\\localservice",
    "nt authority\\networkservice",
    "nt authority\\system",
    "localservice",
    "networkservice",
})


def decode_services_state(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes Get-Service / Win32_Service state snapshot record."""
    name = record.get("Name") or "—"
    disp = record.get("DisplayName") or "—"
    state = record.get("State") or "—"
    start_mode = record.get("StartMode") or "—"
    account = record.get("StartName") or "—"
    path = record.get("PathName") or "—"

    acc_low = account.strip().lower()
    is_named = bool(account and account != "—" and acc_low not in SYSTEM_ACCOUNTS and not acc_low.startswith("nt service\\"))
    is_running = state.lower() == "running"

    return {
        "kind": "service_state",
        "name": name,
        "display_name": disp,
        "state": state,
        "start_mode": start_mode,
        "account": account,
        "executable": path,
        "is_running": is_running,
        "named_account": is_named,
        "note": "Служба использует именованную учётную запись" if is_named else ("Работает" if is_running else "Остановлена"),
    }


def parse_ps_history_file(local_path: Path, profile_path: str | None = None) -> list[dict[str, Any]]:
    """Reads lines from saved ConsoleHost_history.txt and decodes each command."""
    if not local_path.is_file():
        return []

    lines: list[str] = []
    for enc in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
        try:
            lines = local_path.read_text(encoding=enc).splitlines()
            break
        except (UnicodeDecodeError, OSError):
            continue

    output: list[dict[str, Any]] = []
    for i, line in enumerate(lines):
        clean = line.strip()
        if not clean:
            continue
        clean_low = clean.lower()
        matched = [kw for kw in POWERSHELL_PROFILE_KEYWORDS if re.search(r"(?<![\w-])" + re.escape(kw) + r"(?![\w-])", clean_low)]

        output.append({
            "kind": "powershell_command",
            "name": f"Команда #{i + 1}",
            "command": clean,
            "profile": profile_path or os.path.basename(str(local_path)),
            "line": i + 1,
            "profile_signal": bool(matched),
            "keywords": ", ".join(matched) if matched else "—",
            "context_summary": f"Команда содержит профильные маркеры: {', '.join(matched)}" if matched else "Команда из истории PowerShell",
        })

    return output


def decode_powershell_history_record(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes powershell_history file metadata record when full file lines are not loaded."""
    length = record.get("length") or record.get("read_length") or 0
    return {
        "kind": "powershell_history_file",
        "name": record.get("name") or "ConsoleHost_history.txt",
        "command": record.get("path") or "—",
        "profile": record.get("profile_path") or "—",
        "line": 0,
        "profile_signal": False,
        "keywords": "—",
        "context_summary": f"История PowerShell ({length:,} байт)",
    }


def decode_explorer_history(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes Explorer MountPoints2 / TypedPaths history record."""
    val = record.get("value")
    clean_val = str(val or "")
    parsed_extra = ""

    # If base64 binary data from MountPoints2, try to extract volume string
    if record.get("encoding") == "base64" and isinstance(val, str):
        try:
            raw_bytes = base64.b64decode(val)
            # Find ASCII or UTF-16 strings inside
            matches = re.findall(rb'([a-zA-Z0-9_\-\\\#\.\:]{4,})', raw_bytes.replace(b'\x00', b''))
            found_strings = [m.decode('ascii', errors='ignore') for m in matches if len(m) >= 4]
            if found_strings:
                clean_val = " · ".join(found_strings[:4])
                parsed_extra = clean_val
        except Exception:
            pass

    return {
        "kind": "explorer_entry",
        "name": record.get("name") or "Параметр",
        "registry_path": record.get("registry_path") or record.get("branch") or "—",
        "profile": record.get("profile_path") or "—",
        "type": record.get("registry_type") or "String",
        "value": clean_val,
        "details": parsed_extra or record.get("branch") or "—",
    }


def decode_installation_log(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes Windows installation / servicing log artifact record."""
    length = record.get("length") or record.get("read_length") or 0
    size_str = f"{length:,} байт" if length else "0 байт"

    return {
        "kind": "installation_log",
        "name": record.get("name") or "log",
        "path": record.get("path") or "—",
        "size": size_str,
        "sha256": record.get("sha256") or "—",
        "last_write_time": record.get("last_write_time") or "—",
    }


def decode_office_mru(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes Office MRU recent document record."""
    return {
        "kind": "office_mru",
        "name": record.get("name") or record.get("value_name") or "Документ",
        "path": record.get("path") or record.get("value") or "—",
        "profile": record.get("profile_path") or "—",
        "last_write": record.get("last_write_time") or "—",
    }


def decode_rdp_history(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes RDP connection target history record."""
    target = record.get("data") or record.get("value") or "—"
    return {
        "kind": "rdp_target",
        "name": str(target),
        "target": str(target),
        "registry_key": record.get("value_name") or record.get("name") or "—",
        "profile": record.get("profile_path") or "—",
    }
