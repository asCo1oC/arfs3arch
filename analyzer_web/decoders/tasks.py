from __future__ import annotations

import re
from typing import Any

USER_LOCATIONS = ("\\users\\", "\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\", "\\perflogs\\")
SCRIPT_EXTS = (".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".wsh")
INTERPRETERS = ("powershell", "pwsh", "cmd", "mshta", "cscript", "wscript", "bitsadmin", "curl", "certutil")


def decode_task(record: dict[str, Any]) -> dict[str, Any]:
    """Represent a task as host-profile evidence without inferring malicious intent."""
    task_name = record.get("task_name") or ""
    task_path = record.get("task_path") or "\\"
    full_path = f"{task_path.rstrip('\\')}\\{task_name}" if task_name else task_path
    principal = record.get("principal") or {}
    user_id = principal.get("user_id") or "—"
    run_level = principal.get("run_level") or "Limited"
    actions = record.get("actions") or []
    action = actions[0] if actions else {}
    execute = action.get("execute") or ""
    arguments = action.get("arguments") or ""
    triggers = record.get("triggers") or []
    trigger_types = [item.get("type") for item in triggers if item.get("type")]
    command_low = f"{execute} {arguments}".lower()
    user_low = user_id.lower()
    vendor_task = task_path.lower().startswith("\\microsoft\\windows\\")
    runs_elevated = run_level.lower() == "highestavailable" or user_low in ("system", "nt authority\\system", "s-1-5-18")
    uses_user_location = any(value in execute.lower() for value in USER_LOCATIONS)
    uses_script = any(execute.lower().endswith(ext) or ext in arguments.lower() for ext in SCRIPT_EXTS)
    interpreter = next((name for name in INTERPRETERS if re.search(rf"\b{re.escape(name)}(?:\.exe)?\b", command_low)), None)
    traits: list[str] = []
    if not vendor_task: traits.append("нештатная ветка")
    if runs_elevated: traits.append("контекст SYSTEM/Highest")
    if uses_user_location: traits.append("путь в профиле/ProgramData")
    if uses_script: traits.append("сценарий")
    if interpreter: traits.append(f"интерпретатор {interpreter}")
    return {
        "kind":"scheduled_task", "name":task_name, "path":full_path,
        "state":record.get("state") or "Unknown", "user":user_id, "run_level":run_level,
        "execute":execute or "—", "arguments":arguments or "—",
        "triggers":", ".join(trigger_types) if trigger_types else "Вручную / триггер не задан",
        "author":record.get("author") or "—", "is_vendor_task":vendor_task,
        "runs_elevated":runs_elevated, "uses_interpreter":bool(interpreter),
        "interpreter":interpreter or "—", "uses_user_location":uses_user_location,
        "profile_signal":bool(traits) and not vendor_task,
        "context_summary":"; ".join(traits) if traits else "штатная системная задача",
    }
