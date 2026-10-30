from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable

from .decoders.ad import normalize_record
from .decoders.browser import parse_chromium_history, parse_firefox_history, parse_json_artifact
from .decoders.configs import decode_config_file, decode_iis, decode_role, decode_shared_text
from .decoders.identity import decode_os, decode_profile, decode_token
from .decoders.logs_misc import (
    decode_explorer_history,
    decode_installation_log,
    decode_office_mru,
    decode_powershell_history_record,
    decode_rdp_history,
    decode_services_state,
    parse_ps_history_file,
)
from .decoders.network import (
    decode_address,
    decode_dns,
    decode_firewall,
    decode_interface,
    decode_management,
    decode_neighbor,
    decode_process,
    decode_proxy,
    decode_route,
    decode_tcp,
    decode_udp,
)
from .decoders.recent import csv_source_name, parse_recent_csv
from .decoders.sddl import decode_file_acl_record, decode_service_acl_record, extract_token_context
from .decoders.service_events import decode_service_event
from .decoders.services import decode_record as decode_service
from .decoders.tasks import decode_task
from .decoders.userassist import decode_record as decode_userassist
from .decoders.ad_acl import index_acl
from .profiling import profile_observations


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def initialize(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS projects(
            id TEXT PRIMARY KEY, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE,
            hostname TEXT, username TEXT, identity TEXT, schema_version TEXT,
            status TEXT, started_at TEXT, finished_at TEXT, indexed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            metadata_json TEXT NOT NULL, errors_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sources(
            id INTEGER PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            section TEXT NOT NULL, name TEXT NOT NULL, status TEXT, record_count INTEGER NOT NULL DEFAULT 0,
            output_file TEXT, errors_json TEXT NOT NULL, summary_json TEXT NOT NULL,
            UNIQUE(project_id,section,name)
        );
        CREATE TABLE IF NOT EXISTS records(
            id INTEGER PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            section TEXT NOT NULL, source TEXT NOT NULL, ordinal INTEGER NOT NULL, data_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_records_lookup ON records(project_id,section,source,ordinal);
        CREATE TABLE IF NOT EXISTS artifacts(
            id INTEGER PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            section TEXT NOT NULL, source TEXT NOT NULL, original_path TEXT, local_path TEXT,
            name TEXT, category TEXT, profile_sid TEXT, profile_path TEXT, length INTEGER,
            sha256 TEXT, metadata_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_artifacts_project ON artifacts(project_id,section,source);
        CREATE TABLE IF NOT EXISTS decoded(
            id INTEGER PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            decoder TEXT NOT NULL, source TEXT NOT NULL, data_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_decoded_project ON decoded(project_id,decoder);
        CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            severity TEXT NOT NULL, title TEXT NOT NULL, summary TEXT NOT NULL,
            section TEXT, source TEXT, evidence_json TEXT NOT NULL
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(project_id UNINDEXED, section, source, content);
        """
    )
    db.commit()


def project_id(path: Path) -> str:
    return hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:16]


def resolve_artifact(project_root: Path, output_directory: str | None, saved_path: str | None) -> Path | None:
    if not output_directory or not saved_path:
        return None
    try:
        relative = PureWindowsPath(saved_path).relative_to(PureWindowsPath(output_directory))
    except ValueError:
        return None
    candidate = project_root.joinpath(*relative.parts).resolve()
    root = project_root.resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _insert_record(db: sqlite3.Connection, pid: str, section: str, source: str, ordinal: int, record: Any) -> None:
    text = json_text(record)
    db.execute("INSERT INTO records(project_id,section,source,ordinal,data_json) VALUES(?,?,?,?,?)", (pid, section, source, ordinal, text))
    db.execute("INSERT INTO search_index(project_id,section,source,content) VALUES(?,?,?,?)", (pid, section, source, text))


def _insert_decoded(db: sqlite3.Connection, pid: str, decoder: str, source: str, record: Any) -> None:
    db.execute("INSERT INTO decoded(project_id,decoder,source,data_json) VALUES(?,?,?,?)", (pid, decoder, source, json_text(record)))


def _insert_finding(db: sqlite3.Connection, pid: str, severity: str, title: str, summary: str, section: str, source: str, evidence: Any) -> None:
    category = "collection" if title == "Неполный источник" else "access" if section == "identity" else "profile" if severity == "info" else "configuration"
    evidence = dict(evidence) if isinstance(evidence, dict) else {"records": evidence}
    evidence["finding_type"] = category
    db.execute("INSERT INTO findings(project_id,severity,title,summary,section,source,evidence_json) VALUES(?,?,?,?,?,?,?)", (pid, severity, title, summary, section, source, json_text(evidence)))


def _records(db: sqlite3.Connection, pid: str, section: str, source: str) -> Iterable[dict[str, Any]]:
    for row in db.execute("SELECT data_json FROM records WHERE project_id=? AND section=? AND source=? ORDER BY ordinal", (pid, section, source)):
        yield json.loads(row[0])


def _index_browser(db: sqlite3.Connection, pid: str) -> None:
    rows = db.execute("SELECT name,category,profile_path,local_path FROM artifacts WHERE project_id=? AND section='browser'", (pid,)).fetchall()
    groups: dict[tuple[str, str | None], dict[str, Path]] = {}
    for row in rows:
        path = Path(row["local_path"] or "")
        if path.is_file():
            groups.setdefault((row["category"] or "unknown", row["profile_path"]), {})[row["name"]] = path
    for (browser, profile), files in groups.items():
        decoded: list[dict[str, Any]] = []
        try:
            decoded.extend(parse_firefox_history(files, profile) if browser == "firefox" else parse_chromium_history(files, browser, profile))
            for name in ("Bookmarks", "Preferences", "Secure Preferences", "Local State"):
                if name in files:
                    decoded.extend(parse_json_artifact(files[name], name, browser, profile))
        except (OSError, sqlite3.DatabaseError) as exc:
            decoded.append({"kind": "decode_error", "browser": browser, "profile_path": profile, "message": str(exc)})
        for item in decoded:
            _insert_decoded(db, pid, "browser", "browser_files", item)


def _derive_recon_findings(db: sqlite3.Connection, pid: str) -> None:
    """Derive misconfigurations and profile signals without making IOC/malware claims."""
    def decoded(decoder: str) -> list[tuple[dict[str, Any], str]]:
        result = []
        for row in db.execute("SELECT data_json,source FROM decoded WHERE project_id=? AND decoder=?", (pid, decoder)):
            item = json.loads(row["data_json"])
            if isinstance(item, dict): result.append((item, row["source"]))
        return result

    token = next(iter(_records(db, pid, "identity", "token")), {})
    privilege_notes = {
        "SeImpersonatePrivilege": ("high", "Доступна SeImpersonatePrivilege", "Контекст процесса допускает impersonation после аутентификации клиента; применимость зависит от ОС и доступных сервисов."),
        "SeAssignPrimaryTokenPrivilege": ("high", "Доступна SeAssignPrimaryTokenPrivilege", "Контекст может назначать primary token создаваемому процессу; требуется проверка практической применимости."),
        "SeDebugPrivilege": ("critical", "Доступна SeDebugPrivilege", "Контекст имеет право отладки чужих процессов и требует приоритетной проверки границ доступа."),
        "SeBackupPrivilege": ("high", "Доступна SeBackupPrivilege", "Контекст может обходить обычные проверки чтения при backup-операциях."),
        "SeRestorePrivilege": ("high", "Доступна SeRestorePrivilege", "Контекст может обходить обычные проверки записи при restore-операциях."),
        "SeTakeOwnershipPrivilege": ("high", "Доступна SeTakeOwnershipPrivilege", "Контекст может назначать себя владельцем защищённых объектов."),
        "SeLoadDriverPrivilege": ("high", "Доступна SeLoadDriverPrivilege", "Контекст допускает загрузку драйверов при выполнении дополнительных условий."),
    }
    for privilege in token.get("privileges", []):
        note = privilege_notes.get(privilege.get("name"))
        if note and str(privilege.get("state_raw", "")).lower() == "enabled":
            _insert_finding(db, pid, note[0], note[1], note[2], "identity", "token", privilege)
    for group in token.get("groups", []):
        if group.get("sid") == "S-1-5-32-544" and "Enabled group" in str(group.get("attributes_raw", "")):
            _insert_finding(db, pid, "info", "Контекст локального администратора", "В токене включена группа BUILTIN\\Administrators. Это характеристика текущего доступа, а не уязвимость.", "identity", "token", group)

    for service in _records(db, pid, "logs", "services_state"):
        account = str(service.get("StartName") or "")
        if "\\" in account and not account.upper().startswith(("NT AUTHORITY\\", "NT SERVICE\\")):
            _insert_finding(db, pid, "info", "Служба под именованной учётной записью", f"{service.get('Name')} запускается от {account}; это характеризует роль узла и потенциальную credential surface.", "logs", "services_state", service)
    ports = {21:"FTP",22:"SSH",80:"HTTP",135:"RPC",139:"NetBIOS",443:"HTTPS",445:"SMB",1433:"MSSQL",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5985:"WinRM",5986:"WinRM TLS"}
    listeners = {}
    for socket in _records(db, pid, "network", "tcp"):
        try: port = int(socket.get("local_port") or 0)
        except (TypeError, ValueError): continue
        if str(socket.get("state", "")).lower() == "listen" and port in ports:
            listeners.setdefault(port, []).append(socket)
    for port, sockets in listeners.items():
        addresses = ", ".join(sorted({str(s.get('local_address')) for s in sockets}))
        _insert_finding(db, pid, "info", f"Порт, типичный для {ports[port]}", f"TCP/{port}: {addresses}. Предположение по номеру порта; протокол и роль нужно подтвердить процессом и конфигурацией.", "network", "tcp", {"port":port,"sockets":sockets})

    for svc, _ in decoded("services"):
        if svc.get("unquoted_path"):
            _insert_finding(db, pid, "high", "Неэкранированный путь службы", f"В текущей конфигурации службы {svc.get('name')} путь с пробелами не заключён в кавычки: {svc.get('executable')}.", "logs", "services", svc)
    for acl, _ in decoded("service_acl"):
        if not (acl.get("vulnerable") or acl.get("user_can_modify") or acl.get("modifiable_by_users")): continue
        principals = ", ".join(acl.get("vulnerable_principals", [])) or "непривилегированные субъекты"
        direct = bool(acl.get("user_can_modify"))
        title = "Текущий контекст может изменять службу" if direct else "Слабая DACL службы"
        severity = "critical" if direct else "high"
        _insert_finding(db, pid, severity, title, f"Служба {acl.get('service')}: права модификации доступны субъектам {principals}. Эффективность и возможность перезапуска требуют проверки.", "permissions", "service_acl", acl)
    for acl, _ in decoded("file_acl"):
        principals = ", ".join(acl.get("vulnerable_principals", [])) or "непривилегированные субъекты"
        if acl.get("high_risk"):
            _insert_finding(db, pid, "high", "Разрешена запись в исполняемый файл", f"ACL для {acl.get('path')}: {principals}. Связь с конкретной службой, итоговый доступ и привилегированный запуск требуют проверки.", "permissions", "file_acl", acl)
        elif acl.get("config_risk"):
            _insert_finding(db, pid, "high", "Изменяемый конфигурационный файл", f"Запись в {acl.get('path')} доступна: {principals}. Требуется определить потребителя конфигурации и его контекст.", "permissions", "file_acl", acl)
    for ace, _ in decoded("ad_acl"):
        if not ace.get("is_notable_lead"): continue
        title = 'Нестандартное разрешение AD · текущий токен' if ace.get('matches_current_token') else 'Делегированное разрешение AD для проверки'
        _insert_finding(db, pid, ace.get('review_priority', 'medium'), title, (ace.get('interest_reason') or '') + '. ' + (ace.get('factual_note') or ''), "permissions", "domain_acl", ace)

    for item, _ in decoded("network"):
        if item.get("kind") == "smb_server" and item.get("has_misconfiguration"):
            _insert_finding(db, pid, "medium", "Ослабленная конфигурация SMB", item.get("risk_summary") or "Требуется проверка SMB-политик.", "network", "management", item)
        elif item.get("kind") == "smb_share" and item.get("has_misconfiguration"):
            _insert_finding(db, pid, "medium", "Шара разрешает запись широкой группе", f"{item.get('name')} ({item.get('path')}): {item.get('access')}. Итоговый доступ зависит также от NTFS и запрещающих ACE.", "network", "management", item)

    seen_ad = set()
    for obj, source in decoded("ad"):
        attrs = obj.get("attributes") or {}
        flags = set(attrs.get("useraccountcontrol_flags") or [])
        signals = []
        if attrs.get("serviceprincipalname"):
            signals.append(("info", "Учётная запись с зарегистрированными SPN"))
        if attrs.get("msds-allowedtodelegateto"):
            signals.append(("medium", "Заданы сервисы constrained delegation"))
        if attrs.get("msds-allowedtoactonbehalfofotheridentity"):
            signals.append(("medium", "Присутствует дескриптор RBCD"))
        if attrs.get("scriptpath") or attrs.get("homedirectory") or attrs.get("profilepath"):
            signals.append(("info", "Пути сценария и профиля в AD"))
        if "DONT_REQ_PREAUTH" in flags: signals.append(("high", "Для учётной записи отключена Kerberos pre-authentication"))
        if "TRUSTED_FOR_DELEGATION" in flags:
            signals.append(("info" if "SERVER_TRUST_ACCOUNT" in flags else "high", "Делегирование контроллера домена" if "SERVER_TRUST_ACCOUNT" in flags else "Настроено unconstrained delegation"))
        if "TRUSTED_TO_AUTH_FOR_DELEGATION" in flags: signals.append(("medium", "Настроено protocol transition delegation"))
        if "PASSWD_NOTREQD" in flags: signals.append(("medium", "Для учётной записи разрешён PASSWD_NOTREQD"))
        if "ENCRYPTED_TEXT_PWD_ALLOWED" in flags: signals.append(("medium", "Разрешено reversible password encryption"))
        if "USE_DES_KEY_ONLY" in flags: signals.append(("medium", "Учётная запись ограничена DES Kerberos keys"))
        for severity, title in signals:
            key = (obj.get("sid") or obj.get("distinguished_name") or obj.get("name"), title)
            if key in seen_ad: continue
            seen_ad.add(key)
            if "ACCOUNTDISABLE" in flags: severity = "info"
            details = ", ".join(sorted(flags))
            for attr in ("serviceprincipalname", "msds-allowedtodelegateto", "scriptpath", "homedirectory", "profilepath"):
                values = attrs.get(attr)
                if values:
                    details += f"; {attr}: " + ", ".join(str(v) for v in (values if isinstance(values, list) else [values]))
            note = " Требуется проверить применимость и эффективные права."
            if "PASSWD_NOTREQD" in flags: note += " PASSWD_NOTREQD не доказывает пустой пароль."
            if "ACCOUNTDISABLE" in flags: note += " Учётная запись отключена."
            _insert_finding(db, pid, severity, title, f"{obj.get('name') or obj.get('distinguished_name')}: {details}.{note}", "domain", source, obj)

    service_events = [item for item, _ in decoded("service_events") if item.get("service_name") not in (None, "—")]
    if service_events:
        drivers = sum(bool(item.get("is_driver")) for item in service_events)
        named = sorted({item.get("account_name") for item in service_events if str(item.get("account_name") or "").lower() not in ("", "—", "localsystem", "localservice", "networkservice") and not str(item.get("account_name") or "").lower().startswith(("nt authority\\", "nt service\\"))})
        _insert_finding(db, pid, "info", "Профиль установки служб", f"Зафиксировано событий установки: {len(service_events)}; драйверов: {drivers}; именованные контексты: {', '.join(named[:8]) or 'нет'}.", "logs", "service_events", {"count":len(service_events),"drivers":drivers,"named_accounts":named,"samples":service_events[:10]})
    tasks = [item for item, _ in decoded("scheduled_tasks")]
    if tasks:
        custom = [item for item in tasks if not item.get("is_vendor_task")]
        elevated = [item for item in tasks if item.get("runs_elevated")]
        interpreters = sorted({item.get("interpreter") for item in tasks if item.get("interpreter") not in (None, "—")})
        _insert_finding(db, pid, "info", "Профиль заданий планировщика", f"Всего задач: {len(tasks)}; несистемных веток: {len(custom)}; повышенных: {len(elevated)}; интерпретаторы: {', '.join(interpreters) or 'нет'}.", "logs", "scheduled_tasks", {"total":len(tasks),"custom":len(custom),"elevated":len(elevated),"interpreters":interpreters,"samples":custom[:10]})
    for title, summary, section, origin, evidence in profile_observations(decoded):
        _insert_finding(db, pid, "info", title, summary, section, origin, evidence)
    dns = [item for item, _ in decoded("network") if item.get("kind") == "dns_cache"]
    if dns:
        names = sorted({str(item.get("name")) for item in dns if item.get("name") not in (None, "—")})
        _insert_finding(db, pid, "info", "Профиль DNS-активности узла", f"Уникальных имён в кэше: {len(names)}. Это совокупный след процессов и пользователей узла, а не атрибуция конкретной учётке.", "network", "dns_cache", {"unique_names":len(names),"samples":names[:50]})

    for source in db.execute("SELECT section,name,status,errors_json FROM sources WHERE project_id=? AND status NOT IN ('success','skipped','not_found','not_applicable','unavailable')", (pid,)):
        _insert_finding(db, pid, "low", "Неполный источник", f"{source['section']}.{source['name']}: статус {source['status']}.", source["section"], source["name"], json.loads(source["errors_json"]))


def _index_recent_csvs(db: sqlite3.Connection, pid: str, recent_dir: Path) -> None:
    from .recent_profile import attribute_recent
    batches = {}
    for csv_path in sorted(recent_dir.glob("**/*.csv")):
        source_name = csv_source_name(csv_path.name)
        batch = batches.setdefault(source_name, {'records':[], 'files':[], 'errors':[]})
        batch['files'].append(str(csv_path))
        try:
            records = parse_recent_csv(csv_path)
            for record in records:
                record['source_csv'] = str(csv_path.relative_to(recent_dir))
            attribute_recent(db, pid, records)
            batch['records'].extend(records)
        except (OSError, ValueError, UnicodeError) as exc:
            batch['errors'].append({'file':str(csv_path), 'message':str(exc)})
    for source_name, batch in batches.items():
        records = batch['records']
        status = ('partial' if records else 'failed') if batch['errors'] else 'success'
        summary = {'source':source_name,'location':batch['files'],'status':status,'record_count':len(records),'errors':batch['errors']}
        db.execute("INSERT OR REPLACE INTO sources(project_id,section,name,status,record_count,output_file,errors_json,summary_json) VALUES(?,?,?,?,?,?,?,?)", (pid,'recent',source_name,status,len(records),str(recent_dir),json_text(batch['errors']),json_text(summary)))
        for ordinal, record in enumerate(records):
            _insert_record(db, pid, 'recent', source_name, ordinal, record)
            _insert_decoded(db, pid, 'recent', source_name, record)


def index_project(db: sqlite3.Connection, root: Path) -> str:
    """Replace a project atomically; retain its previous index on failure."""
    db.execute('SAVEPOINT project_import')
    try:
        pid = _index_project(db, root)
    except Exception:
        db.execute('ROLLBACK TO project_import')
        db.execute('RELEASE project_import')
        raise
    db.execute('RELEASE project_import')
    return pid


def _index_project(db: sqlite3.Connection, root: Path) -> str:
    index_path = root / "portable_collection.json"
    index = read_json(index_path)
    pid = project_id(root)
    metadata = index.get("metadata") or {}
    db.execute("DELETE FROM search_index WHERE project_id=?", (pid,))
    db.execute("DELETE FROM projects WHERE id=?", (pid,))
    identity = ""
    token_path = root / "identity" / "token.raw.json"
    token_record = None
    if token_path.is_file():
        try:
            token_records = read_json(token_path).get("records") or []
            if token_records:
                identity = token_records[0].get("name") or ""
                token_record = token_records[0]
        except (OSError, ValueError, json.JSONDecodeError): pass
    token_ctx = extract_token_context(token_record) if token_record else None
    db.execute(
        "INSERT INTO projects(id,name,path,hostname,username,identity,schema_version,status,started_at,finished_at,metadata_json,errors_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid, root.name, str(root.resolve()), metadata.get("hostname"), metadata.get("username"), identity, index.get("schema_version"), index.get("status"), metadata.get("started_at"), metadata.get("finished_at"), json_text(metadata), json_text(index.get("errors") or [])),
    )
    output_directory = metadata.get("output_directory")
    for section_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        section = section_dir.name
        for raw_path in sorted(section_dir.glob("*.raw.json")):
            source_name = raw_path.name.removesuffix(".raw.json")
            try:
                raw = read_json(raw_path)
                summary = raw.get("source") or {}
                entries = raw.get("records") or []
                db.execute("INSERT INTO sources(project_id,section,name,status,record_count,output_file,errors_json,summary_json) VALUES(?,?,?,?,?,?,?,?)", (pid, section, source_name, summary.get("status"), len(entries), str(raw_path), json_text(summary.get("errors") or []), json_text(summary)))
                for ordinal, record in enumerate(entries):
                    _insert_record(db, pid, section, source_name, ordinal, record)
                    # --- Decoders dispatch ---
                    if section == "identity":
                        if source_name == "token" and isinstance(record, dict):
                            for token_item in decode_token(record):
                                _insert_decoded(db, pid, "identity", source_name, token_item)
                        elif source_name == "os" and isinstance(record, dict):
                            _insert_decoded(db, pid, "identity", source_name, decode_os(record))
                        elif source_name == "profiles" and isinstance(record, dict):
                            _insert_decoded(db, pid, "identity", source_name, decode_profile(record))
                    elif section == "logs":
                        if source_name == "userassist" and isinstance(record, dict):
                            _insert_decoded(db, pid, "userassist", source_name, decode_userassist(record))
                        elif source_name == "services" and isinstance(record, dict):
                            _insert_decoded(db, pid, "services", source_name, decode_service(record))
                        elif source_name == "scheduled_tasks" and isinstance(record, dict):
                            _insert_decoded(db, pid, "scheduled_tasks", source_name, decode_task(record))
                        elif source_name == "service_events":
                            _insert_decoded(db, pid, "service_events", source_name, decode_service_event(record))
                        elif source_name == "services_state" and isinstance(record, dict):
                            _insert_decoded(db, pid, "services_state", source_name, decode_services_state(record))
                        elif source_name == "powershell_history" and isinstance(record, dict):
                            local = resolve_artifact(root, output_directory, record.get("saved_path")) if record.get("saved_path") else None
                            if local and local.is_file():
                                ps_items = parse_ps_history_file(local, record.get("profile_path"))
                                for item in ps_items:
                                    _insert_decoded(db, pid, "powershell_history", source_name, item)
                            else:
                                _insert_decoded(db, pid, "powershell_history", source_name, decode_powershell_history_record(record))
                        elif source_name == "explorer_history" and isinstance(record, dict):
                            _insert_decoded(db, pid, "explorer_history", source_name, decode_explorer_history(record))
                        elif source_name == "installation_logs" and isinstance(record, dict):
                            _insert_decoded(db, pid, "installation_logs", source_name, decode_installation_log(record))
                        elif source_name == "office_mru" and isinstance(record, dict):
                            _insert_decoded(db, pid, "office_mru", source_name, decode_office_mru(record))
                        elif source_name == "rdp_history" and isinstance(record, dict):
                            _insert_decoded(db, pid, "rdp_history", source_name, decode_rdp_history(record))
                    elif section == "network":
                        if source_name == "firewall" and isinstance(record, dict):
                            _insert_decoded(db, pid, "network", source_name, decode_firewall(record))
                        elif source_name == "management" and isinstance(record, dict):
                            _insert_decoded(db, pid, "network", source_name, decode_management(record))
                        elif source_name == "proxy" and isinstance(record, dict):
                            _insert_decoded(db, pid, "network", source_name, decode_proxy(record))
                        elif source_name == "tcp" and isinstance(record, dict):
                            _insert_decoded(db, pid, "network", source_name, decode_tcp(record))
                        elif source_name == "udp" and isinstance(record, dict):
                            _insert_decoded(db, pid, "network", source_name, decode_udp(record))
                        elif source_name == "processes" and isinstance(record, dict):
                            _insert_decoded(db, pid, "network", source_name, decode_process(record))
                        elif source_name == "interfaces" and isinstance(record, dict):
                            _insert_decoded(db, pid, "network", source_name, decode_interface(record))
                        elif source_name == "addresses" and isinstance(record, dict):
                            _insert_decoded(db, pid, "network", source_name, decode_address(record))
                        elif source_name == "routes" and isinstance(record, dict):
                            _insert_decoded(db, pid, "network", source_name, decode_route(record))
                        elif source_name == "neighbors" and isinstance(record, dict):
                            _insert_decoded(db, pid, "network", source_name, decode_neighbor(record))
                        elif source_name == "dns_servers" and isinstance(record, dict):
                            _insert_decoded(db, pid, "network", source_name, decode_dns(record, is_cache=False))
                        elif source_name == "dns_cache" and isinstance(record, dict):
                            _insert_decoded(db, pid, "network", source_name, decode_dns(record, is_cache=True))
                    elif section == "configs":
                        if source_name == "iis" and isinstance(record, dict):
                            _insert_decoded(db, pid, "configs", source_name, decode_iis(record))
                        elif source_name == "roles" and isinstance(record, dict):
                            _insert_decoded(db, pid, "configs", source_name, decode_role(record))
                        elif source_name == "config_files" and isinstance(record, dict):
                            _insert_decoded(db, pid, "configs", source_name, decode_config_file(record))
                        elif source_name == "shared_text_files" and isinstance(record, dict):
                            _insert_decoded(db, pid, "configs", source_name, decode_shared_text(record))
                    elif section == "permissions":
                        if source_name == "service_acl" and isinstance(record, dict):
                            _insert_decoded(db, pid, "service_acl", source_name, decode_service_acl_record(record, token_ctx))
                        elif source_name == "file_acl" and isinstance(record, dict):
                            _insert_decoded(db, pid, "file_acl", source_name, decode_file_acl_record(record, token_ctx))
                    elif section == "domain" and isinstance(record, dict):
                        _insert_decoded(db, pid, "ad", source_name, normalize_record(source_name, record))
                    if isinstance(record, dict) and record.get("saved_path"):
                        local = resolve_artifact(root, output_directory, record.get("saved_path"))
                        db.execute("INSERT INTO artifacts(project_id,section,source,original_path,local_path,name,category,profile_sid,profile_path,length,sha256,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (pid, section, source_name, record.get("path"), str(local) if local else None, record.get("name"), record.get("category") or record.get("branch"), record.get("profile_sid"), record.get("profile_path"), record.get("read_length") or record.get("length"), record.get("sha256"), json_text(record)))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                db.execute("INSERT INTO sources(project_id,section,name,status,record_count,output_file,errors_json,summary_json) VALUES(?,?,?,?,?,?,?,?)", (pid, section, source_name, "failed", 0, str(raw_path), json_text([{"message": str(exc)}]), "{}"))
        if section == "recent":
            _index_recent_csvs(db, pid, section_dir)
    index_acl(db, pid)
    _index_browser(db, pid)
    _derive_recon_findings(db, pid)
    return pid


def scan_projects(db: sqlite3.Connection, collection_root: Path) -> list[dict[str, Any]]:
    discovered: list[dict[str, Any]] = []
    for index_path in sorted(collection_root.glob("*/portable_collection.json")):
        try:
            pid = index_project(db, index_path.parent)
            discovered.append({"id": pid, "name": index_path.parent.name, "status": "indexed"})
        except Exception as exc:
            discovered.append({"name": index_path.parent.name, "status": "failed", "error": str(exc)})
    return discovered


def page(db: sqlite3.Connection, sql: str, parameters: tuple[Any, ...], limit: int, offset: int) -> dict[str, Any]:
    rows = db.execute(sql + " LIMIT ? OFFSET ?", (*parameters, limit, offset)).fetchall()
    return {"items": [dict(row) for row in rows], "limit": limit, "offset": offset}
