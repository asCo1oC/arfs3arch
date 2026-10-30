from __future__ import annotations

import os
import re
from typing import Any

# Well-known SID abbreviations in SDDL
SDDL_ALIASES: dict[str, str] = {
    "SY": "NT AUTHORITY\\SYSTEM",
    "BA": "BUILTIN\\Administrators",
    "BU": "BUILTIN\\Users",
    "BG": "BUILTIN\\Guests",
    "WD": "Everyone",
    "AU": "NT AUTHORITY\\Authenticated Users",
    "IU": "NT AUTHORITY\\INTERACTIVE",
    "SU": "NT AUTHORITY\\SERVICE",
    "NS": "NT AUTHORITY\\NETWORK SERVICE",
    "LS": "NT AUTHORITY\\LOCAL SERVICE",
    "AN": "NT AUTHORITY\\ANONYMOUS LOGON",
    "ED": "Enterprise Domain Controllers",
    "PS": "Principal Self",
    "CO": "CREATOR OWNER",
    "CG": "CREATOR GROUP",
    "AC": "ALL APPLICATION PACKAGES",
    "RC": "Restricted Code",
    "DA": "Domain Admins",
    "DU": "Domain Users",
    "DD": "Domain Computers",
    "DC": "Domain Controllers",
    "EA": "Enterprise Admins",
    "PA": "Group Policy Creator Owners",
    "SA": "Schema Admins",
    "RS": "RAS and IAS Servers",
    "RA": "RDS Remote Access Servers",
    "RD": "Terminal Server Users",
    "NO": "Network Configuration Operators",
}

# Low-privileged identities that ordinary non-admin attackers can leverage
LOW_PRIV_ALIASES: frozenset[str] = frozenset({"BU", "WD", "AU", "IU", "AN", "BG", "DU"})

LOW_PRIV_IDENTITY_PATTERNS: tuple[str, ...] = (
    "builtin\\users",
    "everyone",
    "authenticated users",
    "interactive",
    "anonymous logon",
    "builtin\\guests",
    "domain users",
)

ADMIN_GROUP_SIDS: frozenset[str] = frozenset({
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-18",      # NT AUTHORITY\SYSTEM
    "S-1-5-19",      # NT AUTHORITY\LOCAL SERVICE
    "S-1-5-20",      # NT AUTHORITY\NETWORK SERVICE
})

ADMIN_IDENTITY_PATTERNS: tuple[str, ...] = (
    "administrators",
    "администраторы",
    "domain admins",
    "администраторы домена",
    "enterprise admins",
    "администраторы предприятия",
    "schema admins",
    "system",
    "trustedinstaller",
)

WELL_KNOWN_LOW_PRIV_SIDS: frozenset[str] = frozenset({
    "S-1-1-0",       # Everyone
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # BUILTIN\Users
    "S-1-5-4",       # Interactive
    "S-1-5-2",       # Network
    "S-1-5-15",      # This Organization
})


def extract_token_context(token: dict[str, Any] | None) -> dict[str, Any]:
    """
    Extracts security principal identifiers (username, user SID, non-admin group names/SIDs)
    from identity/token to enable context-aware privilege escalation checks.
    """
    if not token or not isinstance(token, dict):
        return {
            "user_name": "",
            "user_sid": "",
            "user_names": set(),
            "user_sids": set(),
            "non_admin_group_names": set(),
            "non_admin_group_sids": set(),
            "is_admin": False,
        }

    user_name = str(token.get("name") or "").strip()
    user_sid = str(token.get("sid") or "").strip().upper()

    user_names = set()
    if user_name:
        user_names.add(user_name.lower())
        if "\\" in user_name:
            user_names.add(user_name.split("\\", 1)[1].lower())
        if "@" in user_name:
            user_names.add(user_name.split("@", 1)[0].lower())

    user_sids = set()
    if user_sid:
        user_sids.add(user_sid)

    non_admin_group_names = set()
    non_admin_group_sids = set()
    is_admin = False

    for group in token.get("groups", []):
        gsid = str(group.get("sid") or "").strip().upper()
        gname = str(group.get("name") or "").strip()
        gname_low = gname.lower()

        is_group_admin = gsid in ADMIN_GROUP_SIDS or any(p in gname_low for p in ADMIN_IDENTITY_PATTERNS)
        if is_group_admin and "Enabled group" in str(group.get("attributes_raw", "")):
            is_admin = True

        if gsid and not is_group_admin:
            non_admin_group_sids.add(gsid)

        if gname and not is_group_admin:
            non_admin_group_names.add(gname_low)
            if "\\" in gname:
                non_admin_group_names.add(gname.split("\\", 1)[1].lower())

    return {
        "user_name": user_name,
        "user_sid": user_sid,
        "user_names": user_names,
        "user_sids": user_sids,
        "non_admin_group_names": non_admin_group_names,
        "non_admin_group_sids": non_admin_group_sids,
        "is_admin": is_admin,
    }

# Service access rights
SERVICE_RIGHTS: dict[str, str] = {
    "CC": "QueryConfig",
    "DC": "ChangeConfig",
    "LC": "QueryStatus",
    "SW": "EnumDependents",
    "RP": "Start",
    "WP": "Stop",
    "DT": "PauseContinue",
    "LO": "Interrogate",
    "CR": "UserDefinedControl",
    "SD": "Delete",
    "RC": "ReadControl",
    "WD": "WriteDacl",
    "WO": "WriteOwner",
    "GA": "GenericAll",
    "GW": "GenericWrite",
    "GX": "GenericExecute",
    "GR": "GenericRead",
}

# Critical service rights that allow privilege escalation or disruption
SERVICE_VULN_RIGHTS: frozenset[str] = frozenset({"DC", "WD", "WO", "GA", "GW"})
SERVICE_START_RIGHTS: frozenset[str] = frozenset({"RP"})
SERVICE_STOP_RIGHTS: frozenset[str] = frozenset({"WP"})
SERVICE_DELETE_RIGHTS: frozenset[str] = frozenset({"SD"})

# File write/modify access rights
FILE_WRITE_KEYWORDS: frozenset[str] = frozenset({
    "fullcontrol",
    "modify",
    "write",
    "writedata",
    "createfiles",
    "appenddata",
    "writeextendedattributes",
    "writeattributes",
})

EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl", ".msi"
})

CONFIG_EXTENSIONS: frozenset[str] = frozenset({
    ".config", ".xml", ".ini", ".json", ".conf", ".cfg", ".yaml", ".yml", ".ovpn"
})


def resolve_sid(sid_str: str) -> str:
    """Translate SDDL alias to friendly name or return original SID."""
    sid_clean = sid_str.strip()
    return SDDL_ALIASES.get(sid_clean.upper(), sid_clean)


def is_low_privileged_sid(sid_str: str) -> bool:
    """Check if SID represents a standard / unprivileged security principal."""
    sid_upper = sid_str.strip().upper()
    if sid_upper in LOW_PRIV_ALIASES:
        return True
    # Standard user RID >= 1000 in domain/local SAM (e.g. S-1-5-21-...-1001)
    if re.match(r"^S-1-5-21(-\d+)+-\d{4,}$", sid_upper):
        return True
    return False


def is_low_privileged_identity(identity: str) -> bool:
    """Check if friendly identity string represents low-privileged account/group."""
    id_low = identity.strip().lower()
    return any(p in id_low for p in LOW_PRIV_IDENTITY_PATTERNS)


def parse_service_ace(ace_str: str, token_context: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """
    Parse an ACE token: (AceType;AceFlags;Rights;ObjectGuid;InheritObjectGuid;AccountSid).
    """
    parts = ace_str.strip("()").split(";")
    if len(parts) < 6:
        return None
    ace_type, ace_flags, rights_str, _, _, account_sid = parts[:6]

    # Decode rights
    rights_list = []
    # Two-letter tokens
    i = 0
    while i < len(rights_str):
        token = rights_str[i : i + 2].upper()
        if token in SERVICE_RIGHTS:
            rights_list.append(SERVICE_RIGHTS[token])
            i += 2
        else:
            i += 1

    # Check for hex mask (e.g., 0x1200a9)
    if rights_str.lower().startswith("0x"):
        try:
            mask = int(rights_str, 16)
            if mask & 0x0001:
                rights_list.append("QueryConfig")
            if mask & 0x0002:
                rights_list.append("ChangeConfig")
            if mask & 0x0004:
                rights_list.append("QueryStatus")
            if mask & 0x0008:
                rights_list.append("EnumDependents")
            if mask & 0x0010:
                rights_list.append("Start")
            if mask & 0x0020:
                rights_list.append("Stop")
            if mask & 0x0040:
                rights_list.append("PauseContinue")
            if mask & 0x0080:
                rights_list.append("Interrogate")
            if mask & 0x0100:
                rights_list.append("UserDefinedControl")
            if mask & 0x00010000:
                rights_list.append("Delete")
            if mask & 0x00020000:
                rights_list.append("ReadControl")
            if mask & 0x00040000:
                rights_list.append("WriteDacl")
            if mask & 0x00080000:
                rights_list.append("WriteOwner")
            if mask & 0x10000000:
                rights_list.append("GenericAll")
            if mask & 0x40000000:
                rights_list.append("GenericWrite")
            if mask & 0x80000000:
                rights_list.append("GenericRead")
        except ValueError:
            pass

    friendly_identity = resolve_sid(account_sid)
    sid_upper = account_sid.strip().upper()
    id_lower = friendly_identity.strip().lower()

    matches_user = False
    matches_group = False
    if token_context:
        matches_user = (sid_upper in token_context.get("user_sids", set())) or (id_lower in token_context.get("user_names", set()))
        matches_group = (sid_upper in token_context.get("non_admin_group_sids", set())) or (id_lower in token_context.get("non_admin_group_names", set()))

    is_std_low_priv = is_low_privileged_sid(account_sid) or is_low_privileged_identity(friendly_identity)
    is_low_priv = is_std_low_priv or matches_user or matches_group

    # Check for critical / notable permissions
    rights_set = set(rights_list)
    can_change_config = bool(rights_set & {"ChangeConfig", "WriteDacl", "WriteOwner", "GenericAll", "GenericWrite"})
    can_start = "Start" in rights_set
    can_stop = "Stop" in rights_set
    can_delete = "Delete" in rights_set

    return {
        "type": "Allow" if ace_type.upper() == "A" else "Deny" if ace_type.upper() == "D" else ace_type,
        "flags": ace_flags,
        "rights": rights_list,
        "rights_raw": rights_str,
        "sid": account_sid,
        "identity": friendly_identity,
        "is_low_priv": is_low_priv,
        "matches_user": matches_user,
        "matches_group": matches_group,
        "can_change_config": can_change_config,
        "can_start": can_start,
        "can_stop": can_stop,
        "can_delete": can_delete,
    }


def decode_service_acl_record(record: dict[str, Any], token_context: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Decodes a service_acl raw record (sc.exe sdshow <service>).
    """
    service = record.get("service") or ""
    raw_lines = record.get("raw") or []
    sddl = ""
    for line in raw_lines:
        line_str = str(line).strip()
        if "D:" in line_str:
            sddl = line_str[line_str.index("D:") :]
            break

    if not sddl:
        return {
            "service": service,
            "sddl": None,
            "dacl_status": "not_available" if record.get("exit_code") != 0 else "empty",
            "vulnerable": False,
            "modifiable_by_users": False,
            "user_can_modify": False,
            "user_can_start": False,
            "user_can_stop": False,
            "startable_by_users": False,
            "stoppable_by_users": False,
            "vulnerable_principals": [],
            "aces": [],
            "ace_count": 0,
            "risk_summary": "Нет данных SDDL" if record.get("exit_code") != 0 else "Пустой DACL",
        }

    # Extract all ACEs inside parentheses
    raw_aces = re.findall(r"\([^)]+\)", sddl)
    aces = []
    vulnerable_principals = set()
    user_can_modify = False
    user_can_start = False
    user_can_stop = False
    can_change_any = False
    can_start_any = False
    can_stop_any = False

    for raw_ace in raw_aces:
        parsed = parse_service_ace(raw_ace, token_context=token_context)
        if parsed:
            aces.append(parsed)
            if parsed["type"] == "Allow" and parsed["is_low_priv"]:
                is_user_match = parsed.get("matches_user") or parsed.get("matches_group")
                if parsed["can_change_config"]:
                    can_change_any = True
                    if is_user_match:
                        user_can_modify = True
                        label = f"{parsed['identity']} [Текущий токен]"
                    else:
                        label = parsed["identity"]
                    vulnerable_principals.add(f"{label} (ChangeConfig)")
                if parsed["can_start"]:
                    can_start_any = True
                    if is_user_match:
                        user_can_start = True
                if parsed["can_stop"]:
                    can_stop_any = True
                    if is_user_match:
                        user_can_stop = True

    is_vuln = can_change_any or user_can_modify

    risk_notes = []
    if user_can_modify:
        risk_notes.append("LPE: Текущий пользователь может изменить конфигурацию службы (Service ACL Abuse)")
    elif can_change_any:
        risk_notes.append("LPE: Пользователи могут изменить конфигурацию службы (ChangeConfig / WriteDacl)")
    if (user_can_start and user_can_stop) or (can_start_any and can_stop_any):
        risk_notes.append("Доступен перезапуск службы (Start/Stop)")
    elif user_can_start or can_start_any:
        risk_notes.append("Доступен запуск службы (Start)")
    elif user_can_stop or can_stop_any:
        risk_notes.append("Доступна остановка службы (Stop)")

    return {
        "service": service,
        "sddl": sddl,
        "dacl_status": "present",
        "vulnerable": is_vuln,
        "modifiable_by_users": can_change_any,
        "user_can_modify": user_can_modify,
        "user_can_start": user_can_start,
        "user_can_stop": user_can_stop,
        "startable_by_users": can_start_any,
        "stoppable_by_users": can_stop_any,
        "vulnerable_principals": sorted(vulnerable_principals),
        "aces": aces,
        "ace_count": len(aces),
        "risk_summary": "; ".join(risk_notes) if risk_notes else "Стандартные права",
    }


def classify_file_type(path: str) -> str:
    """Classify path into executable, config, directory, or other."""
    if not path:
        return "unknown"
    ext = os.path.splitext(path)[1].lower()
    if ext in EXECUTABLE_EXTENSIONS:
        return "executable"
    if ext in CONFIG_EXTENSIONS:
        return "config"
    if not ext or path.endswith("\\") or path.endswith("/"):
        return "directory"
    return "file"


def decode_file_acl_record(record: dict[str, Any], token_context: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Decodes a file_acl raw record (Get-Acl output).
    """
    path = record.get("path") or ""
    owner = record.get("owner") or ""
    group = record.get("group") or ""
    sddl = record.get("sddl") or ""
    access_list = record.get("access") or []
    file_type = classify_file_type(path)

    vulnerable_principals = []
    writable_by_users = False
    user_writable = False
    details_list = []

    for ace in access_list:
        identity = str(ace.get("identity") or "")
        id_low = identity.strip().lower()
        id_short = id_low.split("\\")[-1] if "\\" in id_low else id_low
        rights = str(ace.get("rights") or "")
        ace_type = str(ace.get("type") or "")
        inherited = bool(ace.get("inherited"))

        matches_user = False
        matches_group = False
        if token_context:
            matches_user = (id_low in token_context.get("user_names", set())) or (id_short in token_context.get("user_names", set()))
            matches_group = (id_low in token_context.get("non_admin_group_names", set())) or (id_short in token_context.get("non_admin_group_names", set()))

        if ace_type.lower() == "allow":
            # Check if rights contain write/modify keywords
            rights_lower = rights.lower()
            has_write = any(kw in rights_lower for kw in FILE_WRITE_KEYWORDS)
            is_std_low_priv = is_low_privileged_identity(identity)

            if has_write and (is_std_low_priv or matches_user or matches_group):
                writable_by_users = True
                if matches_user:
                    user_writable = True
                    vulnerable_principals.append(f"{identity} [Текущий пользователь] ({rights})")
                elif matches_group:
                    user_writable = True
                    vulnerable_principals.append(f"{identity} [Группа токена] ({rights})")
                else:
                    vulnerable_principals.append(f"{identity} ({rights})")

        details_list.append({
            "identity": identity,
            "rights": rights,
            "type": ace_type,
            "inherited": inherited,
            "matches_user": matches_user,
            "matches_group": matches_group,
        })

    is_exec = (file_type == "executable")
    is_config = (file_type == "config")
    is_high_risk = writable_by_users and is_exec
    is_config_risk = writable_by_users and is_config
    is_vuln = writable_by_users

    summary_parts = []
    if is_high_risk:
        if user_writable:
            summary_parts.append("LPE: Текущий пользователь может перезаписать исполняемый файл!")
        else:
            summary_parts.append("LPE: Исполняемый файл доступен на запись обычным пользователям!")
    elif is_config_risk:
        if user_writable:
            summary_parts.append("Текущий пользователь может изменить конфигурационный файл")
        else:
            summary_parts.append("Конфигурационный файл доступен на запись пользователям")
    elif writable_by_users and file_type == "directory":
        summary_parts.append("Каталог доступен на запись обычным пользователям")
    elif writable_by_users:
        summary_parts.append("Файл доступен на запись обычным пользователям")
    else:
        summary_parts.append("Стандартные права доступа")

    return {
        "path": path,
        "name": os.path.basename(path) if path else "",
        "file_type": file_type,
        "owner": owner,
        "group": group,
        "sddl": sddl,
        "vulnerable": is_vuln,
        "high_risk": is_high_risk,
        "config_risk": is_config_risk,
        "writable_by_users": writable_by_users,
        "user_writable": user_writable,
        "vulnerable_principals": vulnerable_principals,
        "access": details_list,
        "risk_summary": "; ".join(summary_parts),
    }
