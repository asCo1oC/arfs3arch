"""JumpList attribution and descriptive activity rules; never proof of execution."""
from collections import Counter, defaultdict
import json
from .decoders.recent import clean_basename


def attribute_recent(db, pid, records):
    artifacts = defaultdict(list)
    for row in db.execute("SELECT metadata_json FROM artifacts WHERE project_id=? AND section='recent'", (pid,)):
        item = json.loads(row[0])
        for key in ('saved_path', 'path'):
            name = clean_basename(item.get(key) or '').casefold()
            if name: artifacts[name].append(item)
    for record in records:
        candidates = artifacts.get(clean_basename(record.get('source_file') or '').casefold(), [])
        identities = {(x.get('profile_sid'), x.get('profile_path')) for x in candidates if x.get('profile_sid') or x.get('profile_path')}
        if len(identities) == 1:
            sid, path = next(iter(identities))
            explicit = record.get('profile_path')
            if explicit and path and explicit.casefold() != path.casefold():
                record['attribution_basis'] = 'Конфликт профиля CSV и манифеста; автоматическая привязка отключена'
                record['profile_path'] = None
            else:
                record.update(profile_sid=sid, profile_path=path or explicit, attribution_basis='SourceFile совпал с артефактом манифеста')
        else:
            record['attribution_basis'] = 'ProfilePath указан в CSV' if record.get('profile_path') else 'Профиль не установлен; путь назначения не используется для атрибуции'


PURPOSES = {
    'Документ': 'Работа с документами',
    'Конфигурация': 'Работа с настройками ПО или служб',
    'Сценарий': 'Разработка или автоматизация',
    'Архив / резервная копия': 'Работа с архивами или резервными копиями',
    'Удалённый доступ': 'Работа с конфигурациями удалённого доступа',
    'Ключ / сертификат': 'Работа с ключевыми материалами или хранилищами паролей',
    'Сетевой ресурс': 'Работа с сетевыми ресурсами',
}
APP_PURPOSES = {
    'powershell': 'Администрирование или автоматизация',
    'visual studio': 'Разработка или редактирование исходного кода',
    'microsoft edge': 'Работа с веб-ресурсами',
    'firefox': 'Работа с веб-ресурсами',
    'chrome': 'Работа с веб-ресурсами',
    'word': 'Работа с документами',
    'excel': 'Работа с таблицами',
    'блокнот': 'Редактирование текстовых файлов',
}


def recent_observations(decoded):
    groups = defaultdict(list)
    for row, source in decoded('recent'):
        profile = row.get('profile_sid') or row.get('profile_path')
        key = profile or ('Не установлен: ' + str(row.get('source_csv') or source))
        groups[key].append(row)
    for profile, rows in sorted(groups.items()):
        # Identical re-exports must not inflate activity statistics. Keep original rows in the source view.
        unique = {}
        occurrences = Counter()
        for row in rows:
            raw = row.get('raw_csv') or {k:v for k,v in row.items() if k not in ('source_csv','source_csv_row')}
            signature = json.dumps(raw, sort_keys=True, ensure_ascii=False)
            occurrence_key = (row.get('source_csv'), signature)
            occurrences[occurrence_key] += 1
            unique.setdefault((signature, occurrences[occurrence_key]), row)
        rows_unique = list(unique.values())
        auto = [r for r in rows_unique if r.get('kind') == 'automatic']
        custom = [r for r in rows_unique if r.get('kind') == 'custom']
        apps = Counter(r.get('application') or 'Неизвестное приложение' for r in rows_unique)
        categories = Counter(tag for r in auto for tag in r.get('profile_tags', []))
        hypotheses = []
        for tag, count in categories.items():
            if tag in PURPOSES:
                hypotheses.append({'purpose':PURPOSES[tag], 'basis':tag, 'records':count, 'confidence':'предположение по типу назначения'})
        for app, count in apps.items():
            for marker, purpose in APP_PURPOSES.items():
                if marker in app.lower():
                    hypotheses.append({'purpose':purpose,'basis':app,'records':count,'confidence':'назначение ПО; использование и роль пользователя не доказаны'})
                    break
        label = next((r.get('profile_path') for r in rows_unique if r.get('profile_path')), profile)
        evidence = {
            'profile':profile, 'profile_path':label, 'records':len(rows), 'unique_records':len(rows_unique),
            'duplicate_exports_excluded':len(rows)-len(rows_unique),
            'automatic_records':len(auto), 'custom_records':len(custom), 'applications':apps.most_common(),
            'categories':dict(categories), 'possible_activities':hypotheses,
            'executable_references':sorted({r['path'] for r in rows_unique if str(r.get('path') or '').lower().endswith('.exe')}),
            'network_paths':sorted({r['path'] for r in auto if str(r.get('path') or '').startswith('\\\\')}),
            'examples':[{k:r.get(k) for k in ('application','path','kind','entry_last_modified','source_csv','source_csv_row','attribution_basis')} for r in rows_unique[:20]],
            'limitation':'AutomaticDestinations — ссылки на недавние объекты, не журнал запусков. CustomDestinations могут содержать статические задачи. InteractionCount не суммируется как число запусков. TargetModified — время файла, не действия пользователя.',
        }
        summary = f'{label}: Automatic {len(auto)}, Custom {len(custom)}. ПО: ' + ', '.join(f'{a} ({n})' for a,n in apps.most_common(6))
        if hypotheses: summary += '. Возможная деятельность: ' + '; '.join(dict.fromkeys(h['purpose'] for h in hypotheses)) + '.'
        yield 'Профиль пользователя · Jump Lists', summary, 'recent', 'jumplist_profile', evidence
