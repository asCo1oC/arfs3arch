from __future__ import annotations

import json
from typing import Any


def decode_iis(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes IIS worker processes, site directories, app pools, and config files."""
    kind = record.get("kind")

    if kind == "worker":
        return {
            "kind": "iis_worker",
            "name": f"Процесс w3wp.exe (PID {record.get('pid')})",
            "pool": "Default",
            "pid": record.get("pid"),
            "path": record.get("path") or "—",
            "command_line": record.get("command_line") or "—",
            "bindings": "—",
        }

    if kind == "site_directory":
        bindings = record.get("bindings") or []
        binding_strs = []
        if isinstance(bindings, list):
            for b in bindings:
                if isinstance(b, dict):
                    proto = b.get("protocol") or "http"
                    info = b.get("binding_information") or ""
                    binding_strs.append(f"{proto}://{info}")
                else:
                    binding_strs.append(str(b))
        binding_desc = ", ".join(binding_strs) if binding_strs else "—"

        return {
            "kind": "iis_site",
            "name": f"Сайт: {record.get('site') or 'IIS Site'}",
            "pool": record.get("pool") or "—",
            "pid": record.get("site_id"),
            "path": record.get("physical_path_raw") or record.get("virtual_path") or "—",
            "command_line": f"Приложение: {record.get('application') or '/'}",
            "bindings": binding_desc,
        }

    if kind == "application_pool":
        return {
            "kind": "iis_pool",
            "name": f"Пул: {record.get('name')}",
            "pool": record.get("name") or "—",
            "pid": None,
            "path": record.get("source_file") or "applicationHost.config",
            "command_line": "Пул приложений IIS",
            "bindings": "—",
        }

    # Saved config file record (e.g. DefaultAppPool.config or web.config)
    if record.get("path") or record.get("name"):
        return {
            "kind": "iis_config",
            "name": record.get("name") or "Файл конфигурации",
            "pool": "—",
            "pid": None,
            "path": record.get("path") or "—",
            "command_line": f"Размер: {record.get('length') or record.get('read_length') or 0} байт",
            "bindings": "—",
        }

    return {
        "kind": "iis_misc",
        "name": str(kind or "IIS"),
        "pool": "—",
        "pid": None,
        "path": "—",
        "command_line": str(record),
        "bindings": "—",
    }


def decode_role(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes detected server role from registry keys."""
    role = record.get("role") or ""
    values_list = record.get("values") or []
    values_map = {v.get("name"): v.get("value") for v in values_list if isinstance(v, dict)}

    if role == "iis":
        setup_str = values_map.get("SetupString") or "IIS"
        inst_path = values_map.get("InstallPath") or "—"
        www_root = values_map.get("PathWWWRoot") or "—"
        group = values_map.get("IISProgramGroup") or "—"
        return {
            "kind": "role",
            "name": "Веб-сервер Microsoft IIS",
            "role": "IIS Web Server",
            "present": "Установлен" if record.get("present") else "Отсутствует",
            "version": str(setup_str),
            "install_path": str(inst_path),
            "details": f"Корень: {www_root} · Группа: {group}",
        }

    if role == "sql_server":
        instances = values_map.get("InstalledInstances") or []
        inst_str = ", ".join(instances) if isinstance(instances, list) else str(instances)
        return {
            "kind": "role",
            "name": "СУБД Microsoft SQL Server",
            "role": "Microsoft SQL Server",
            "present": "Установлен" if record.get("present") else "Отсутствует",
            "version": inst_str or "Установлен",
            "install_path": record.get("path") or "—",
            "details": f"Экземпляры: {inst_str or 'По умолчанию'}",
        }

    return {
        "kind": "role",
        "name": f"Роль: {role}",
        "role": role,
        "present": "Установлен" if record.get("present") else "Отсутствует",
        "version": "—",
        "install_path": record.get("path") or "—",
        "details": json.dumps(values_map, ensure_ascii=False) if values_map else "—",
    }


def decode_config_file(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes captured configuration file artifact record."""
    length = record.get("length") or record.get("read_length") or 0
    size_str = f"{length:,} байт" if length else "0 байт"

    return {
        "kind": "config_file",
        "name": record.get("name") or "config",
        "path": record.get("path") or "—",
        "size": size_str,
        "sha256": record.get("sha256") or "—",
        "creation_time": record.get("creation_time") or "—",
        "last_write_time": record.get("last_write_time") or "—",
    }


def decode_shared_text(record: dict[str, Any]) -> dict[str, Any]:
    """Decodes captured shared text / script file artifact record."""
    length = record.get("length") or record.get("read_length") or 0
    size_str = f"{length:,} байт" if length else "0 байт"

    return {
        "kind": "shared_text_file",
        "name": record.get("name") or "text_file",
        "path": record.get("path") or "—",
        "size": size_str,
        "sha256": record.get("sha256") or "—",
        "creation_time": record.get("creation_time") or "—",
        "last_write_time": record.get("last_write_time") or "—",
    }
