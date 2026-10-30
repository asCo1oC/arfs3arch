from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


def chromium_time(value: Any) -> str | None:
    try:
        number = int(value)
        if number <= 0: return None
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=number)).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError): return None


def firefox_time(value: Any) -> str | None:
    try:
        number = int(value)
        if number <= 0: return None
        return datetime.fromtimestamp(number / 1_000_000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError, OSError): return None


def _query(path: Path, statements: Iterable[tuple[str, str]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        for kind, sql in statements:
            try:
                for row in connection.execute(sql):
                    item = dict(row); item["kind"] = kind; output.append(item)
            except sqlite3.DatabaseError: continue
    finally: connection.close()
    return output


def parse_chromium_history(files: dict[str, Path], browser: str, profile: str | None) -> list[dict[str, Any]]:
    if "History" not in files: return []
    with tempfile.TemporaryDirectory(prefix="portable_browser_") as temp:
        target = Path(temp) / "History"; shutil.copy2(files["History"], target)
        for sidecar in ("History-wal", "History-shm"):
            if sidecar in files: shutil.copy2(files[sidecar], Path(temp) / sidecar)
        rows = _query(target, (("history", "SELECT url,title,visit_count,typed_count,last_visit_time FROM urls ORDER BY last_visit_time DESC"), ("download", "SELECT target_path,tab_url,total_bytes,state,start_time,end_time FROM downloads ORDER BY start_time DESC")))
    for row in rows:
        row["browser"] = browser; row["profile_path"] = profile
        for field in ("last_visit_time", "start_time", "end_time"):
            if field in row: row[field + "_utc"] = chromium_time(row[field])
    return rows


def parse_firefox_history(files: dict[str, Path], profile: str | None) -> list[dict[str, Any]]:
    if "places.sqlite" not in files: return []
    with tempfile.TemporaryDirectory(prefix="portable_firefox_") as temp:
        target = Path(temp) / "places.sqlite"; shutil.copy2(files["places.sqlite"], target)
        for sidecar in ("places.sqlite-wal", "places.sqlite-shm"):
            if sidecar in files: shutil.copy2(files[sidecar], Path(temp) / sidecar)
        rows = _query(target, (("history", "SELECT url,title,visit_count,last_visit_date FROM moz_places ORDER BY last_visit_date DESC"),))
    for row in rows:
        row["browser"] = "firefox"; row["profile_path"] = profile; row["last_visit_date_utc"] = firefox_time(row.get("last_visit_date"))
    return rows


def parse_json_artifact(path: Path, name: str, browser: str, profile: str | None) -> list[dict[str, Any]]:
    try: data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError): return []
    result: list[dict[str, Any]] = []
    if name == "Bookmarks":
        def walk(node: Any, folder: list[str]) -> None:
            if isinstance(node, dict):
                if node.get("type") == "url": result.append({"kind":"bookmark","browser":browser,"profile_path":profile,"name":node.get("name"),"url":node.get("url"),"folder":"/".join(folder),"date_added":node.get("date_added")})
                for key, value in node.items(): walk(value, folder + ([str(node.get("name"))] if key == "children" and node.get("name") else []))
            elif isinstance(node, list):
                for child in node: walk(child, folder)
        walk(data.get("roots", data), [])
    elif name in {"Preferences", "Secure Preferences", "Local State"}:
        extensions = ((data.get("extensions") or {}).get("settings") or {}) if isinstance(data, dict) else {}
        for extension_id, extension in extensions.items():
            manifest = extension.get("manifest") or {}
            result.append({"kind":"extension","browser":browser,"profile_path":profile,"extension_id":extension_id,"name":manifest.get("name"),"version":manifest.get("version"),"state":extension.get("state"),"source_file":name})
    return result
