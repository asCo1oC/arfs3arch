"""Descriptive statistics over collected artifacts, with explicit attribution limits."""
from collections import Counter, defaultdict
from urllib.parse import urlsplit
from .recent_profile import recent_observations


def profile_observations(decoded):
    """Yield (title, summary, section, source, evidence) for per-profile activity."""
    specs = (
        ("userassist", "Профиль запусков UserAssist", "logs", "userassist"),
        ("browser", "Профиль использования браузера", "browser", "browser_files"),
        ("powershell_history", "Профиль использования PowerShell", "logs", "powershell_history"),
    )
    for decoder, title, section, source in specs:
        groups = defaultdict(list)
        for item, origin in decoded(decoder):
            if decoder == "userassist" and item.get("decode_status") != "success": continue
            if decoder == "userassist" and str(item.get("decoded_name") or "").startswith("UEME_"): continue
            if decoder == "browser" and item.get("kind") == "decode_error": continue
            if decoder == "powershell_history" and item.get("kind") != "powershell_command": continue
            profile = item.get("profile_sid") or item.get("profile_path") or item.get("profile") or ("HKCU сеанса сбора (SID не указан)" if decoder == "userassist" and str(item.get("registry_path") or "").upper().startswith("HKCU") else "Профиль не установлен")
            # Keep browser profiles and Recent CSV origins distinct when attribution is absent.
            group = (profile, item.get("browser", ""), origin if decoder == "recent" else source)
            groups[group].append(item)
        for (profile, browser, origin), rows in sorted(groups.items()):
            evidence = {"profile":profile, "browser":browser, "records":len(rows), "attribution":"Источник относится к профилю, но не доказывает присутствие конкретного человека."}
            if decoder == "userassist":
                top = sorted(rows, key=lambda r: (-(r.get("run_count") or 0), str(r.get("decoded_name"))))[:10]
                evidence["top_applications"] = [{key:r.get(key) for key in ("decoded_name","run_count","focus_count","focus_time_ms","last_execution_utc")} for r in top]
                evidence["limitation"] = "Счётчики UserAssist не являются полным журналом запусков; записи разных веток не суммируются."
                summary = f"{profile}: записей программ {len(rows)}. Наибольшие счётчики: " + ", ".join(f"{r.get('decoded_name')} ({r.get('run_count') or 0})" for r in top[:4])
            elif decoder == "browser":
                domains = Counter()
                for row in rows:
                    if row.get("kind") != "history": continue
                    try: host = urlsplit(str(row.get("url") or "")).hostname
                    except ValueError: continue
                    if host: domains[host.lower()] += 1
                evidence["record_types"] = dict(Counter(r.get("kind") for r in rows))
                evidence["top_domains_by_url_records"] = domains.most_common(15)
                evidence["limitation"] = "Количество URL-записей не равно числу посещений; фоновые обращения и синхронизация возможны."
                summary = f"{profile}, {browser}: {len(rows)} записей; доменов в истории {len(domains)}. " + ", ".join(f"{host} ({count} URL)" for host,count in domains.most_common(5))
            elif decoder == "recent":
                apps = Counter(r.get("application") or "Неизвестно" for r in rows)
                tags = Counter(tag for r in rows for tag in r.get("profile_tags", []))
                evidence.update(applications=apps.most_common(15), categories=dict(tags), network_paths=sorted({r.get("path") for r in rows if str(r.get("path") or "").startswith("\\\\")})[:30])
                evidence["limitation"] = "Recent/JumpLists отражают ссылки и взаимодействия. Наличие записи не доказывает запуск или существование файла сейчас."
                summary = f"{profile}: {len(rows)} записей. Приложения: " + ", ".join(f"{app} ({count})" for app,count in apps.most_common(5))
            else:
                counts = Counter(str(r.get("command") or "") for r in rows)
                markers = Counter(marker.strip() for r in rows for marker in str(r.get("keywords") or "").split(",") if marker.strip() not in ("", "—"))
                evidence.update(unique_commands=len(counts), markers=markers.most_common(20), frequent_commands=counts.most_common(10))
                evidence["limitation"] = "Строки истории не доказывают успешное выполнение. Время и интерактивный автор обычно отсутствуют."
                summary = f"{profile}: строк команд {len(rows)}, уникальных {len(counts)}. Маркеры: " + ", ".join(f"{marker} ({count})" for marker,count in markers.most_common(8))
            yield title, summary, section, origin, evidence
    yield from recent_observations(decoded)
