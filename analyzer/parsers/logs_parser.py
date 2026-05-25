# analyzer/parsers/logs_parser.py
import json
import yaml
import os
import codecs
import re
from typing import List, Dict, Any
from pathlib import Path

class LogsParser:
    def __init__(self, rules_path: str = None):
        if rules_path is None:
            rules_path = Path(__file__).resolve().parent.parent / "config" / "rules.yaml"
        with open(rules_path, "r", encoding="utf-8") as f:
            self.rules = yaml.safe_load(f)

    def parse(self, logs_json_path: str) -> Dict[str, Any]:
        with open(logs_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        meta = data.get("metadata", {})
        services_raw = data.get("services", [])
        ua_raw = data.get("user_assist", [])
        events_raw = data.get("service_events", [])

        services = [self._classify_service(s, meta) for s in services_raw]
        user_assist = [self._parse_userassist(u, meta) for u in ua_raw]

        return {
            "metadata": meta,
            "services": services,
            "user_assist": user_assist,
            "service_events": events_raw
        }

    def _classify_service(self, svc: Dict, meta: Dict) -> Dict:
        path = svc.get("ImagePath", "")
        start = svc.get("Start", 3)
        category = "unknown"
        tags = []
        risk = 0

        sys_paths = self.rules["services"]["system_paths"]
        susp_paths = self.rules["services"]["suspicious_paths"]
        auto_starts = self.rules["services"]["auto_start_types"]

        if any(p in path for p in sys_paths):
            category = "system"
        elif any(p in path for p in susp_paths):
            category = "suspicious"
            risk += 30
        elif "defender" in path.lower() or "security" in path.lower():
            category = "security"
            tags.append("defender")
        elif "vmware" in path.lower() or "virtual" in path.lower() or "vmci" in path.lower():
            category = "virtualization"
            tags.append("vmware")
        elif "google" in path.lower() or "chrome" in path.lower():
            category = "third_party"
            tags.append("google")
        elif "npcap" in path.lower() or "loop" in path.lower():
            category = "network_tool"
            tags.append("sniffer/loopback")

        if start in auto_starts and category not in ["system", "unknown"]:
            risk += 10
            tags.append("auto_start")

        return {
            **svc, "hostname": meta.get("hostname"), "username": meta.get("username"),
            "collection_id": meta.get("collection_id"), "category": category,
            "risk_score": risk, "tags": tags
        }

    def _parse_userassist(self, ua: Dict, meta: Dict) -> Dict:
        encoded = ua.get("name", "")
        # ROT13 декодирование имен реестра
        decoded = codecs.decode(encoded, "rot_13") if encoded else ""
        category = "unknown"
        tags = []

        lower_dec = decoded.lower()
        pentest_kw = self.rules["indicators"]["pentest_tools"]
        removable_kw = self.rules["indicators"]["removable_media_keywords"]

        if any(kw in lower_dec for kw in pentest_kw):
            category = "pentest_tool"
            tags.append("high_risk")
        elif any(kw in lower_dec for kw in removable_kw) or re.match(r"^[A-Z]:\\", decoded):
            category = "removable_media"
            tags.append("data_transfer")
        elif decoded.startswith("\\\\"):
            category = "network_path"
            tags.append("lateral_movement")
        elif "power" in lower_dec or "cmd" in lower_dec or "powershell" in lower_dec:
            category = "admin_tool"
            tags.append("cli_usage")

        return {
            **ua, "decoded_name": decoded, "hostname": meta.get("hostname"),
            "username": meta.get("username"), "collection_id": meta.get("collection_id"),
            "category": category, "tags": tags
        }
