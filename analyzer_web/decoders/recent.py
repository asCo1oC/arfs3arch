from __future__ import annotations

import csv
import io
import os
import re
from pathlib import Path
from typing import Any

# Verified subset: https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt
KNOWN_APPIDS: dict[str, str] = {
    "ccba5a5986c77e43": "Microsoft Edge",
    "590aee7bdd69b59b": "Windows PowerShell",
    "1ced32d74a95c7bc": "Visual Studio Code",
    "f01b4d95cf55d32a": "Проводник Windows",
    "f18460fded109990": "Windows Connected Devices",
    "9b9cdc69c1c24e2b": "Блокнот (64-bit)",
    "12dc1ea8e34b5a6": "Microsoft Paint",
    "dd7c3b1adb1c168b": "Microsoft Game Bar",
    "a7ba40025dac9a67": "Microsoft Office Hub",
    "573770283dc3d854": "Windows Defender",
    "5f7b5f1e01b83767": "Проводник Windows (Quick Access)",
}

PROFILE_EXTENSIONS = {
    "Документ": (".doc", ".docx", ".xls", ".xlsx", ".pdf", ".txt", ".md", ".pptx"),
    "Конфигурация": (".config", ".conf", ".ini", ".yaml", ".yml", ".json", ".xml", ".env"),
    "Сценарий": (".ps1", ".bat", ".cmd", ".vbs", ".py", ".sql"),
    "Архив / резервная копия": (".zip", ".7z", ".rar", ".bak", ".backup"),
    "Удалённый доступ": (".rdp", ".ovpn"),
    "Ключ / сертификат": (".pem", ".key", ".pfx", ".p12", ".kdbx"),
}


def clean_basename(path: str) -> str:
    """Extract file or directory name from Windows or POSIX path string."""
    if not path:
        return ""
    p = path.replace("\\", "/").rstrip("/")
    return p.split("/")[-1] if "/" in p else p


def resolve_application(app_id: str, local_path: str = "") -> str:
    """Resolve AppId or local path to friendly application name."""
    if local_path:
        base = clean_basename(local_path).lower()
        if base.endswith(".exe"):
            mapping = {
                "msedge.exe": "Microsoft Edge",
                "code.exe": "Visual Studio Code",
                "powershell.exe": "PowerShell",
                "powershell_ise.exe": "PowerShell ISE",
                "cmd.exe": "Командная строка",
                "explorer.exe": "Проводник Windows",
                "notepad.exe": "Блокнот",
                "msedgewebview2.exe": "Microsoft Edge WebView2",
            }
            if base in mapping:
                return mapping[base]
            return os.path.splitext(clean_basename(local_path))[0]

    app_clean = (app_id or "").strip().lower()
    suffix = app_clean.split("_")[-1] if "_" in app_clean else app_clean
    if suffix in KNOWN_APPIDS:
        return KNOWN_APPIDS[suffix]
    if app_clean in KNOWN_APPIDS:
        return KNOWN_APPIDS[app_clean]

    return suffix or "Неизвестно"


def profile_tags(path: str, arguments: str) -> list[str]:
    """Return descriptive markers; their presence is not an IOC verdict."""
    extension = os.path.splitext(path)[1].lower()
    tags = [name for name, extensions in PROFILE_EXTENSIONS.items() if extension in extensions]
    if path.startswith("\\\\"):
        tags.append("Сетевой ресурс")
    return tags


def csv_source_name(file_name: str) -> str:
    """Derive clean source name from CSV file name."""
    name_low = file_name.lower()
    if "automatic" in name_low:
        return "automatic_destinations"
    if "custom" in name_low:
        return "custom_destinations"
    clean = re.sub(r"^\d+_", "", file_name)
    clean = re.sub(r"\.csv$", "", clean, flags=re.IGNORECASE)
    clean = re.sub(r"[^a-zA-Z0-9_]+", "_", clean).strip("_").lower()
    return clean or "recent_csv"


def parse_recent_csv(file_path: Path) -> list[dict[str, Any]]:
    """
    Parses a processed Recent / JumpList CSV file (AutomaticDestinations or CustomDestinations).
    """
    text = None
    for enc in ("utf-8-sig", "utf-8", "cp1251", "latin-1"):
        try:
            text = file_path.read_text(encoding=enc)
            break
        except UnicodeDecodeError:
            continue
    if not text:
        return []

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not {'SourceFile', 'AppId'} <= set(reader.fieldnames) or not {'Path', 'LocalPath', 'TargetIDAbsolutePath'} & set(reader.fieldnames):
        raise ValueError('Ожидался CSV JLECmd: SourceFile, AppId и путь назначения')
    fname_low = file_path.name.lower()
    is_custom_file = "custom" in fname_low
    records = []

    for csv_row, row in enumerate(reader, 2):
        entry_name = str(row.get("EntryName") or "").strip()
        is_custom = is_custom_file or 'customdestinations-ms' in str(row.get('SourceFile') or '').lower() or 'EntryName' in reader.fieldnames
        kind = "custom" if is_custom else "automatic"

        path = (
            str(row.get("Path") or "").strip()
            or str(row.get("LocalPath") or "").strip()
            or str(row.get("TargetIDAbsolutePath") or "").strip()
        )
        arguments = str(row.get("Arguments") or "").strip()
        app_id = str(row.get("AppId") or "").strip()
        local_path = str(row.get("LocalPath") or "").strip()
        description = str(row.get('AppIdDescription') or '').strip()
        app_name = description or resolve_application(app_id)
        if not description and app_name not in KNOWN_APPIDS.values():
            app_name = 'Неизвестное приложение'
        target_application = resolve_application('', local_path) if local_path.lower().endswith('.exe') else None

        if path:
            name = clean_basename(path)
        elif arguments:
            name = arguments[:60]
        elif entry_name:
            name = entry_name
        else:
            name = app_name

        def safe_int(v: Any) -> int | None:
            try:
                return int(v) if v is not None and str(v).strip() != "" else None
            except (ValueError, TypeError):
                return None

        interaction_count = safe_int(row.get("InteractionCount"))
        mru = safe_int(row.get("MRU"))
        file_size = safe_int(row.get("FileSize"))
        tags = profile_tags(path, arguments)

        records.append({
            "kind": kind,
            "name": name,
            "path": path,
            "entry_name": entry_name,
            "arguments": arguments,
            "application": app_name,
            "application_basis": 'JLECmd AppIdDescription' if description else 'AppID dictionary' if app_name != 'Неизвестное приложение' else 'unknown',
            "target_application": target_application,
            "app_id": app_id,
            "target_modified": str(row.get("TargetModified") or "").strip(),
            "entry_last_modified": str(row.get('LastModified') or '').strip(),
            "target_created": str(row.get("TargetCreated") or "").strip(),
            "target_accessed": str(row.get("TargetAccessed") or "").strip(),
            "interaction_count": interaction_count,
            "mru": mru,
            "file_size": file_size,
            "drive_type": str(row.get("DriveType") or "").strip(),
            "hostname": str(row.get("Hostname") or row.get("MachineID") or "").strip(),
            "mac_address": str(row.get("MacAddress") or row.get("MachineMACAddress") or "").strip(),
            "profile_signal": bool(tags),
            "profile_tags": tags,
            "source_csv": file_path.name,
            "source_csv_row": csv_row,
            "raw_csv": row,
            "profile_path": str(row.get("ProfilePath") or "").strip() or None,
            "source_file": str(row.get("SourceFile") or "").strip(),
        })

    return records
