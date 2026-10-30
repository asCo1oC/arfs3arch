from __future__ import annotations

import os
from typing import Any

DANGEROUS_PRIVILEGES: dict[str, tuple[str, str]] = {
    "SeImpersonatePrivilege": ("critical", "Олицетворение клиента после аутентификации (Juicy/PrintPotato LPE)"),
    "SeAssignPrimaryTokenPrivilege": ("critical", "Назначение первичного токена процессу (Token Abuse LPE)"),
    "SeDebugPrivilege": ("critical", "Отладка процессов / дамп памяти LSASS (Credential Dumping)"),
    "SeTcbPrivilege": ("critical", "Работа в контексте подсистемы безопасности (Act as part of OS)"),
    "SeBackupPrivilege": ("high", "Обход ACL для чтения любых файлов (Чтение кустов SAM/SYSTEM/NTDS)"),
    "SeRestorePrivilege": ("high", "Обход ACL для записи любых файлов (Подмена системных файлов / служб)"),
    "SeTakeOwnershipPrivilege": ("high", "Смена владельца любого объекта файловой системы или реестра"),
    "SeLoadDriverPrivilege": ("high", "Загрузка драйверов режима ядра (BYOVD LPE)"),
    "SeCreateTokenPrivilege": ("critical", "Создание произвольных токенов доступа"),
    "SeEnableDelegationPrivilege": ("high", "Включение доверия учетных записей для делегирования"),
}

ADMIN_SIDS: frozenset[str] = frozenset({
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-18",      # NT AUTHORITY\SYSTEM
    "S-1-5-19",      # NT AUTHORITY\LOCAL SERVICE
    "S-1-5-20",      # NT AUTHORITY\NETWORK SERVICE
})


def decode_token(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Decodes token.raw.json into summary, privilege, and group entries."""
    output: list[dict[str, Any]] = []

    # 1. Token Summary
    env = record.get("environment") or {}
    labels = record.get("integrity_labels") or []
    integrity = "Unknown"
    if labels:
        lbl_name = labels[0].get("name", "")
        if "High" in lbl_name:
            integrity = "High"
        elif "System" in lbl_name:
            integrity = "System"
        elif "Medium" in lbl_name:
            integrity = "Medium"
        elif "Low" in lbl_name:
            integrity = "Low"
        elif "Untrusted" in lbl_name:
            integrity = "Untrusted"
        else:
            integrity = lbl_name or "Unknown"

    output.append({
        "kind": "summary",
        "name": record.get("name") or "Неизвестно",
        "sid": record.get("sid") or "—",
        "account": record.get("name") or "—",
        "domain": env.get("user_domain") or "—",
        "integrity": integrity,
        "auth_type": record.get("authentication_type") or "—",
        "impersonation": record.get("impersonation_level") or "None",
        "pid": record.get("process_id"),
        "is_64bit": "64-bit" if record.get("process_is_64bit") else "32-bit",
        "profile": env.get("user_profile") or "—",
    })

    # 2. Privileges
    for priv in record.get("privileges") or []:
        pname = priv.get("name") or ""
        raw_state = str(priv.get("state_raw") or "")
        is_enabled = "enabled" in raw_state.lower()
        danger_info = DANGEROUS_PRIVILEGES.get(pname)
        is_dangerous = danger_info is not None

        risk = "low"
        if is_dangerous:
            risk = danger_info[0] if is_enabled else "medium"

        output.append({
            "kind": "privilege",
            "name": pname,
            "state": raw_state,
            "description": priv.get("description_raw") or (danger_info[1] if danger_info else "—"),
            "is_dangerous": is_dangerous,
            "risk": risk,
            "note": danger_info[1] if danger_info else "Стандартная привилегия",
        })

    # 3. Groups
    for grp in record.get("groups") or []:
        sid = grp.get("sid") or ""
        gname = grp.get("name") or ""
        attrs = str(grp.get("attributes_raw") or "")
        is_admin = sid in ADMIN_SIDS or "administrator" in gname.lower() or "администратор" in gname.lower()
        output.append({
            "kind": "group",
            "name": gname,
            "sid": sid,
            "type": grp.get("type_raw") or "Group",
            "attributes": attrs,
            "is_admin": is_admin,
            "is_enabled": "enabled" in attrs.lower(),
        })

    return output


def decode_os(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes WMI OS or QuickFixEngineering hotfix record."""
    cls = record.get("class") or ""
    data = record.get("data") or {}

    if cls == "Win32_OperatingSystem":
        return {
            "kind": "os_info",
            "name": data.get("Caption") or "Windows",
            "version": data.get("Version") or "—",
            "build": data.get("BuildNumber") or "—",
            "arch": data.get("OSArchitecture") or "—",
            "install_date": data.get("InstallDate") or "—",
            "last_boot": data.get("LastBootUpTime") or "—",
            "system_dir": data.get("SystemDirectory") or "—",
        }
    if cls == "Win32_QuickFixEngineering":
        return {
            "kind": "hotfix",
            "name": data.get("HotFixID") or "—",
            "hotfix_id": data.get("HotFixID") or "—",
            "description": data.get("Description") or "Обновление безопасности",
            "installed_on": data.get("InstalledOn") or "—",
            "installed_by": data.get("InstalledBy") or "—",
        }

    return {
        "kind": "os_misc",
        "name": cls,
        "description": str(data),
    }


from pathlib import PureWindowsPath


def decode_profile(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes user profile record."""
    sid = str(record.get("sid") or "")
    path = record.get("path") or ""
    name = PureWindowsPath(path).name if path else sid

    acc_type = "domain_user"
    if sid.startswith("S-1-5-18") or sid.startswith("S-1-5-19") or sid.startswith("S-1-5-20"):
        acc_type = "system"
    elif sid.startswith("S-1-5-80-") or sid.startswith("S-1-5-82-"):
        acc_type = "service"
    elif sid.startswith("S-1-5-21-"):
        acc_type = "domain_or_local_user"

    return {
        "kind": "profile",
        "name": name,
        "sid": sid,
        "path": path,
        "current": bool(record.get("current")),
        "account_type": acc_type,
        "documents": record.get("documents") or "—",
        "appdata": record.get("appdata") or "—",
        "localappdata": record.get("localappdata") or "—",
        "path_source": record.get("path_source") or "—",
    }
