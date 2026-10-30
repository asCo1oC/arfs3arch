from __future__ import annotations

import re
from typing import Any


# Service Type flags (bitfield)
SERVICE_TYPES: dict[int, str] = {
    0x001: "kernel_driver",
    0x002: "file_system_driver",
    0x004: "adapter",
    0x008: "recognizer_driver",
    0x010: "own_process",
    0x020: "share_process",
    0x100: "interactive",
}

# Start type
START_TYPES: dict[int, str] = {
    0: "boot",
    1: "system",
    2: "auto",
    3: "demand",
    4: "disabled",
}

# Well-known system accounts (case-insensitive comparison)
_SYSTEM_ACCOUNTS: frozenset[str] = frozenset({
    "localsystem",
    "nt authority\\localsystem",
    "nt authority\\localservice",
    "nt authority\\networkservice",
    "nt authority\\system",
    "localservice",
    "networkservice",
})

# Env-var prefixes that point to system directories (after lower-casing)
_SYSTEM_PATH_PREFIXES: tuple[str, ...] = (
    "%systemroot%",
    "%windir%",
    "\\systemroot\\",
    "system32\\",
    "\\system32\\",
    "syswow64\\",
)


def _get_value(record: dict[str, Any], name: str) -> Any:
    """Return the first matching value from the values list."""
    for v in record.get("values") or []:
        if v.get("name") == name:
            return v.get("value")
    return None


def _get_param(record: dict[str, Any], name: str) -> Any:
    """Return the first matching value from the parameters list."""
    for p in record.get("parameters") or []:
        if p.get("name") == name:
            return p.get("value")
    return None


def _parse_image_path(raw: str) -> dict[str, str | None]:
    """
    Split ImagePath into executable path and arguments.

    Handles:
      - Quoted:   "C:\\path\\to my\\svc.exe" -arg
      - Unquoted: C:\\path\\svc.exe -arg
      - Kernel:   \\SystemRoot\\System32\\drivers\\x.sys
      - Relative: System32\\drivers\\x.sys
    """
    raw = raw.strip()

    # Quoted executable
    m = re.match(r'^"([^"]+)"(.*)', raw)
    if m:
        return {"executable": m.group(1).strip(), "arguments": m.group(2).strip() or None, "quoted": True}

    # Unquoted: split at first .exe/.sys/.dll boundary (case-insensitive)
    m = re.match(r'^(.+?\.(?:exe|sys|dll|com))(.*)', raw, re.IGNORECASE)
    if m:
        return {"executable": m.group(1).strip(), "arguments": m.group(2).strip() or None, "quoted": False}

    # Fallback: whole string as executable
    return {"executable": raw, "arguments": None, "quoted": False}


def _expand_common_vars(path: str) -> str:
    """Substitute well-known env vars with readable placeholders."""
    p = path
    for var, replacement in (
        ("%SystemRoot%", r"<SystemRoot>"),
        ("%windir%", r"<SystemRoot>"),
        ("\\SystemRoot\\", r"<SystemRoot>\\"),
    ):
        p = re.sub(re.escape(var), replacement, p, flags=re.IGNORECASE)
    return p


def _decode_service_type(value: int) -> dict[str, Any]:
    flags = [name for bit, name in SERVICE_TYPES.items() if value & bit]
    # Determine the primary category
    if value & 0x001:
        category = "driver"
    elif value & 0x002:
        category = "driver"
    elif value & 0x004:
        category = "driver"
    elif value & 0x008:
        category = "driver"
    elif value & 0x010:
        category = "usermode"
    elif value & 0x020:
        category = "usermode"
    else:
        category = "unknown"
    return {"value": value, "flags": flags, "category": category, "interactive": bool(value & 0x100)}


def _is_system_account(account: str | None) -> bool:
    if not account:
        return False
    return account.strip().lower() in _SYSTEM_ACCOUNTS


def _is_system_path(executable: str | None) -> bool:
    if not executable:
        return False
    low = executable.lower()
    return any(low.startswith(p) for p in _SYSTEM_PATH_PREFIXES)


def _unquoted_space_vuln(parsed: dict[str, str | None]) -> bool:
    """
    Detect classic unquoted service path vulnerability:
    executable contains spaces, is not quoted, is not a kernel path.
    Only meaningful for usermode services (not drivers).
    """
    exe = parsed.get("executable") or ""
    if parsed.get("quoted"):
        return False
    # Kernel-style paths starting with \\ or relative System32\\ are not exploitable
    if exe.startswith("\\") or exe.lower().startswith("system32\\"):
        return False
    return " " in exe


def decode_record(record: dict[str, Any]) -> dict[str, Any]:
    """
    Decode a single services registry record into an offsec-oriented view.

    Output fields (offsec perspective):
      name            — service key name
      display_name    — human-readable name (stripped of @resource refs)
      account         — ObjectName (running account)
      account_type    — "system" | "nt_service" | "named" | "unknown"
      start_type      — decoded Start value
      start_value     — raw integer
      service_type    — decoded Type flags
      executable      — parsed binary path
      arguments       — parsed arguments
      quoted          — whether ImagePath was quoted
      service_dll     — ServiceDll from Parameters (svchost DLL)
      service_main    — ServiceMain from Parameters
      is_svchost      — executable is svchost.exe
      svchost_group   — -k <group> argument parsed from svchost invocation
      is_driver       — kernel/FS driver (not a usermode service)
      is_system_path  — executable appears to be in a system directory
      unquoted_path   — unquoted service path with spaces (privesc candidate)
      auto_elevate    — service starts automatically (auto/boot/system)
      image_path_raw  — original ImagePath string
    """
    name = record.get("name") or ""

    # --- Extract raw registry values ---
    image_path_raw: str = str(_get_value(record, "ImagePath") or "")
    display_name_raw: str = str(_get_value(record, "DisplayName") or "")
    start_raw = _get_value(record, "Start")
    type_raw = _get_value(record, "Type")
    account_raw: str | None = _get_value(record, "ObjectName")
    service_dll_raw: str | None = _get_param(record, "ServiceDll")
    service_main: str | None = _get_param(record, "ServiceMain")

    # --- Parse ImagePath ---
    parsed_path = _parse_image_path(image_path_raw) if image_path_raw else {"executable": None, "arguments": None, "quoted": False}
    executable: str | None = parsed_path["executable"]
    arguments: str | None = parsed_path["arguments"]

    # svchost detection
    is_svchost = bool(executable and re.search(r'svchost\.exe$', executable, re.IGNORECASE))
    svchost_group: str | None = None
    if is_svchost and arguments:
        m = re.search(r'-k\s+(\S+)', arguments, re.IGNORECASE)
        if m:
            svchost_group = m.group(1)

    # --- Decode service type ---
    type_decoded: dict[str, Any] | None = None
    is_driver = False
    if type_raw is not None:
        try:
            type_decoded = _decode_service_type(int(type_raw))
            is_driver = type_decoded["category"] == "driver"
        except (TypeError, ValueError):
            type_decoded = {"value": type_raw, "flags": [], "category": "unknown", "interactive": False}

    # --- Decode start type ---
    start_label: str | None = None
    if start_raw is not None:
        try:
            start_label = START_TYPES.get(int(start_raw), f"unknown_{start_raw}")
        except (TypeError, ValueError):
            start_label = None

    # --- Account classification ---
    account_type: str
    account_lower = (account_raw or "").strip().lower()
    if not account_raw:
        account_type = "unknown"
    elif account_lower in _SYSTEM_ACCOUNTS:
        account_type = "system"
    elif account_lower.startswith("nt service\\"):
        account_type = "nt_service"
    else:
        account_type = "named"  # Most interesting for offsec

    # --- Strip @resource display names ---
    display_name: str | None = None
    if display_name_raw and not display_name_raw.startswith("@"):
        display_name = display_name_raw
    elif not display_name_raw:
        display_name = None
    else:
        display_name = None  # localised @resource,id refs are noise

    # --- Offsec flags ---
    unquoted_path = _unquoted_space_vuln(parsed_path) and not is_driver
    auto_elevate = start_label in ("auto", "boot", "system")
    is_system_path_flag = _is_system_path(executable)

    return {
        "name": name,
        "display_name": display_name,
        "account": account_raw,
        "account_type": account_type,
        "start_type": start_label,
        "start_value": start_raw,
        "service_type": type_decoded,
        "executable": executable,
        "arguments": arguments,
        "quoted": parsed_path.get("quoted"),
        "service_dll": service_dll_raw,
        "service_main": service_main,
        "is_svchost": is_svchost,
        "svchost_group": svchost_group,
        "is_driver": is_driver,
        "is_system_path": is_system_path_flag,
        "unquoted_path": unquoted_path,
        "auto_elevate": auto_elevate,
        "image_path_raw": image_path_raw,
    }
