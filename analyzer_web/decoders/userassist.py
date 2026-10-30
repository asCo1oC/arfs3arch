from __future__ import annotations

import base64
import codecs
import struct
from datetime import datetime, timedelta, timezone
from typing import Any


KNOWN_FOLDERS = {
    "{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}": "Libraries",
    "{374DE290-123F-4565-9164-39C4925E467B}": "Downloads",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "%ProgramFiles%",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "%ProgramFiles(x86)%",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "%SystemRoot%",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop",
}


def _filetime(value: int) -> str | None:
    if value <= 0:
        return None
    try:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        return (epoch + timedelta(microseconds=value / 10)).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def decode_name(value: str) -> str:
    decoded = codecs.decode(value, "rot_13")
    for guid, replacement in KNOWN_FOLDERS.items():
        decoded = decoded.replace(guid, replacement).replace(guid.lower(), replacement)
    return decoded


def decode_record(record: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "raw_name": record.get("name"),
        "decoded_name": decode_name(str(record.get("name", ""))),
        "profile_sid": record.get("profile_sid"),
        "profile_path": record.get("profile_path"),
        "registry_path": record.get("path") or record.get("registry_path"),
        "run_count": None,
        "focus_count": None,
        "focus_time_ms": None,
        "last_execution_utc": None,
        "format": None,
        "decode_status": "unsupported",
        "decode_error": None,
    }
    if record.get("encoding") != "base64" or not record.get("value"):
        result["decode_error"] = "UserAssist value is not Base64 binary data"
        return result
    try:
        raw = base64.b64decode(record["value"], validate=True)
    except (ValueError, TypeError) as exc:
        result["decode_status"] = "failed"
        result["decode_error"] = f"Invalid Base64: {exc}"
        return result
    result["raw_length"] = len(raw)
    if len(raw) < 68:
        result["decode_error"] = f"Unsupported UserAssist structure length: {len(raw)}"
        return result
    try:
        result.update(
            format="win7_plus",
            run_count=struct.unpack_from("<I", raw, 4)[0],
            focus_count=struct.unpack_from("<I", raw, 8)[0],
            focus_time_ms=struct.unpack_from("<I", raw, 12)[0],
            last_execution_utc=_filetime(struct.unpack_from("<Q", raw, 60)[0]),
            decode_status="success",
        )
    except struct.error as exc:
        result["decode_status"] = "failed"
        result["decode_error"] = str(exc)
    return result
