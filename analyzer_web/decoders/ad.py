from __future__ import annotations

import base64
import struct
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any


UAC_FLAGS = {
    0x00000001: "SCRIPT", 0x00000002: "ACCOUNTDISABLE", 0x00000008: "HOMEDIR_REQUIRED",
    0x00000010: "LOCKOUT", 0x00000020: "PASSWD_NOTREQD", 0x00000040: "PASSWD_CANT_CHANGE",
    0x00000080: "ENCRYPTED_TEXT_PWD_ALLOWED", 0x00000200: "NORMAL_ACCOUNT",
    0x00000800: "INTERDOMAIN_TRUST_ACCOUNT", 0x00001000: "WORKSTATION_TRUST_ACCOUNT",
    0x00002000: "SERVER_TRUST_ACCOUNT", 0x00010000: "DONT_EXPIRE_PASSWORD",
    0x00020000: "MNS_LOGON_ACCOUNT", 0x00040000: "SMARTCARD_REQUIRED",
    0x00080000: "TRUSTED_FOR_DELEGATION", 0x00100000: "NOT_DELEGATED",
    0x00200000: "USE_DES_KEY_ONLY", 0x00400000: "DONT_REQ_PREAUTH",
    0x00800000: "PASSWORD_EXPIRED", 0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x04000000: "PARTIAL_SECRETS_ACCOUNT",
}


def decode_sid_bytes(raw: bytes) -> str:
    if len(raw) < 8:
        raise ValueError("SID is shorter than its header")
    revision, count = raw[0], raw[1]
    required = 8 + count * 4
    if len(raw) < required:
        raise ValueError("SID sub-authority array is truncated")
    authority = int.from_bytes(raw[2:8], "big")
    parts = [str(struct.unpack_from("<I", raw, 8 + i * 4)[0]) for i in range(count)]
    return "S-" + "-".join([str(revision), str(authority), *parts])


def decode_binary(value: Any) -> bytes | None:
    if not isinstance(value, dict) or value.get("encoding") != "base64":
        return None
    try:
        return base64.b64decode(value.get("value", ""), validate=True)
    except (ValueError, TypeError):
        return None


def decode_filetime(value: Any) -> str | None:
    try:
        number = int(value)
        if number <= 0 or number == 9223372036854775807:
            return None
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        return (epoch + timedelta(microseconds=number / 10)).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError):
        return None


def first(attributes: dict[str, Any], name: str) -> Any:
    value = attributes.get(name.lower())
    return value[0] if isinstance(value, list) and value else value


def normalize_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    attrs = {str(k).lower(): v for k, v in attributes.items()}
    normalized: dict[str, Any] = dict(attrs)
    sid_raw = decode_binary(first(attrs, "objectsid"))
    if sid_raw:
        try:
            normalized["objectsid_decoded"] = decode_sid_bytes(sid_raw)
        except ValueError as exc:
            normalized["objectsid_decode_error"] = str(exc)
    guid_raw = decode_binary(first(attrs, "objectguid"))
    if guid_raw and len(guid_raw) == 16:
        normalized["objectguid_decoded"] = str(uuid.UUID(bytes_le=guid_raw))
    for name in ("lastlogontimestamp", "lastlogon", "pwdlastset", "accountexpires", "badpasswordtime"):
        if name in attrs:
            normalized[name + "_utc"] = decode_filetime(first(attrs, name))
    uac = first(attrs, "useraccountcontrol")
    if uac is not None:
        try:
            number = int(uac)
            normalized["useraccountcontrol_value"] = number
            normalized["useraccountcontrol_flags"] = [name for bit, name in UAC_FLAGS.items() if number & bit]
        except (ValueError, TypeError):
            normalized["useraccountcontrol_decode_error"] = "Value is not an integer"
    group_type = first(attrs, "grouptype")
    if group_type is not None:
        try:
            unsigned = int(group_type) & 0xFFFFFFFF
            normalized["grouptype_value"] = unsigned
            normalized["group_security_enabled"] = bool(unsigned & 0x80000000)
            normalized["group_scope"] = "universal" if unsigned & 0x8 else "domain_local" if unsigned & 0x4 else "global" if unsigned & 0x2 else "unknown"
        except (ValueError, TypeError):
            normalized["grouptype_decode_error"] = "Value is not an integer"
    return normalized


def normalize_record(source: str, record: dict[str, Any]) -> dict[str, Any]:
    if "attributes" not in record:
        return {"source": source, "kind": record.get("kind", source), "data": record}
    attrs = normalize_attributes(record.get("attributes") or {})
    return {
        "source": source, "kind": source.rstrip("s"), "path": record.get("path"),
        "name": first(attrs, "samaccountname") or first(attrs, "displayname") or first(attrs, "distinguishedname"),
        "distinguished_name": first(attrs, "distinguishedname"), "sid": attrs.get("objectsid_decoded"),
        "attributes": attrs,
    }
