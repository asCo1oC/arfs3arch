from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

USER_LOCATIONS = ("\\users\\", "\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\")


def decode_service_event(record: str | dict[str, Any]) -> dict[str, Any]:
    """Decode Event 7045 as historical software and host-role evidence."""
    raw_xml = record if isinstance(record, str) else record.get("xml") or record.get("raw") or ""
    empty = {"kind":"service_install","service_name":"—","name":"—","time_created":"—","computer":"—","image_path":"—","account_name":"—","start_type":"—","service_type":"—","is_driver":False,"uses_user_location":False,"profile_signal":False,"context_summary":"Нет данных XML"}
    if not isinstance(raw_xml, str) or not raw_xml.strip(): return empty
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError:
        return dict(empty, service_name="Ошибка парсинга XML", name="Ошибка парсинга XML", image_path=str(raw_xml)[:120], context_summary="Некорректный XML")
    ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    time_node = root.find(f".//{ns}TimeCreated")
    computer_node = root.find(f".//{ns}Computer")
    values = {node.attrib.get("Name"):node.text for node in root.findall(f".//{ns}EventData/{ns}Data") if node.attrib.get("Name") and node.text}
    image = values.get("ImagePath") or "—"
    service_type = values.get("ServiceType") or "—"
    is_driver = "driver" in service_type.lower() or "драйвер" in service_type.lower()
    uses_user_location = any(value in image.lower() for value in USER_LOCATIONS)
    traits = []
    if is_driver: traits.append("драйвер")
    if uses_user_location: traits.append("исходный файл в профиле/ProgramData")
    account = values.get("AccountName") or "—"
    if account not in ("—", "LocalSystem", "NT AUTHORITY\\SYSTEM"): traits.append(f"контекст {account}")
    name = values.get("ServiceName") or "—"
    return {
        "kind":"service_install", "service_name":name, "name":name,
        "time_created":time_node.attrib.get("SystemTime", "—") if time_node is not None else "—",
        "computer":computer_node.text if computer_node is not None and computer_node.text else "—",
        "image_path":image, "account_name":account, "start_type":values.get("StartType") or "—",
        "service_type":service_type, "is_driver":is_driver, "uses_user_location":uses_user_location,
        "profile_signal":bool(traits), "context_summary":"; ".join(traits) if traits else "факт установки службы",
    }
