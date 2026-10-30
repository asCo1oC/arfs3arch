# as3rch_portable — Portable Evidence Analyzer

Наступательная безопасность \ сбора данных с Windows-хостов для последующего анализа через локальный веб-интерфейс. 

---

## Обзор архитектуры

```
as3rch_portable/
├── tools/
│   └── portable.ps1          # PowerShell-коллектор (однофайловый, ~1 600 строк)
│
├── analyzer_web/             # Python-анализатор (stdlib only, без pip-зависимостей)
│   ├── server.py             # HTTP-сервер (ThreadingHTTPServer + JSON API)
│   ├── core.py               # Индексирование коллекций, импорт, SQLite
│   ├── context_graph.py      # Единый evidence-backed граф проекта
│   ├── decoders/
│   │   ├── userassist.py     # ROT13 + структура Windows 7+ UserAssist
│   │   ├── browser.py        # Chromium History / Firefox places.sqlite
│   │   └── ad.py             # Нормализация SID, GUID, FILETIME, UAC, groupType
│   ├── static/
│   │   ├── index.html        # SPA-оболочка (русскоязычный интерфейс)
│   │   ├── app.js            # Клиентская логика (vanilla JS ES-модуль)
│   │   └── styles.css        # Стили
│   ├── tests/
│   │   ├── test_core.py
│   │   ├── test_decoders.py
│   │   └── test_context.py
│   └── state/
│       └── analyzer.db       # SQLite-индекс (создаётся автоматически)
│
└── output/
    └── from_portable/new/    # Каталог коллекций по умолчанию
        └── <context_name>/   # Один подкаталог = один проект
            ├── portable_collection.json
            └── <section>/
                └── *.raw.json
```

---

## Компонент 1 — Коллектор `portable.ps1`

Одиночный PowerShell-скрипт, предназначенный для запуска в ограниченных контекстах (IIS APPPOOL, WinRM, ограниченная учётка). Не требует установки модулей и не использует `USERPROFILE`/`HOME`.

### Запуск

```powershell
# Минимальный запуск (вывод в автоопределяемый каталог)
.\portable.ps1

# Явный путь вывода
.\portable.ps1 -OutputPath C:\Temp\collection

# Ограничение размера артефактов и таймаут источника
.\portable.ps1 -MaxArtifactBytes 10485760 -SourceTimeoutSeconds 60

# Только текущий профиль
.\portable.ps1 -ProfileScope Current

# Выбор источников
.\portable.ps1 -Sources identity,logs,network
.\portable.ps1 -ExcludeSources recent
```

### Параметры

| Параметр | По умолчанию | Описание |
|---|---|---|
| `-OutputPath` | *(авто)* | Каталог вывода; если пуст — подбирается из `%TEMP%`, `%LOCALAPPDATA%`, `%windir%\Temp`, `$PSScriptRoot` |
| `-MaxFileBytes` | `0` (без лимита) | Максимальный размер одного копируемого файла |
| `-MaxTotalBytes` | `0` (без лимита) | Суммарный бюджет байт для всех файлов |
| `-MaxArtifactBytes` | `0` | Лимит для артефактов браузера и конфигов |
| `-MaxSharedTextFileBytes` | `1 048 576` | Лимит для текстовых файлов (shared_text_files) |
| `-SourceTimeoutSeconds` | `120` | Кооперативный таймаут на источник |
| `-MaxDomainRecords` | `0` | Максимум записей AD |
| `-ProfileScope` | `Accessible` | `Current` — только текущий профиль; `Accessible` — все загруженные HKU-кусты |
| `-Sources` | `all` | Включить только перечисленные источники |
| `-ExcludeSources` | *(пусто)* | Исключить источники |
| `-Archive` | *(нет)* | Упаковать результат в ZIP |

### Собираемые данные

| Раздел | Источники |
|---|---|
| **identity** | Токен процесса (whoami /user, /groups, /priv), профили пользователей, информация об ОС |
| **logs** | Службы из реестра, состояние служб (WMI), история Explorer/RDP/Office MRU, история PowerShell, UserAssist, запланированные задачи, события установки служб (Event ID 7045) |
| **network** | TCP/UDP-соединения (netstat), ARP, таблица маршрутизации, сетевые адаптеры, запущенные процессы, WinRM-конфигурация |
| **configs** | IIS applicationHost.config + web.config, SQL Server ConfigurationFile.ini, Exchange, VPN-профили (OpenVPN, Cisco, WireGuard, Ivanti, Fortinet), Git, AWS, .NET UserSecrets |
| **permissions** | ACL файлов/директорий, DACL служб и DACL объектов Active Directory |
| **domain** | Объекты AD: пользователи, группы, компьютеры, объекты с SPN, делегирование, объекты с правами администратора |
| **browser** | Файлы Chromium/Firefox (History, Cookies, Bookmarks, Extensions, Preferences) |
| **recent** | LNK/Jump Lists из `%APPDATA%\Microsoft\Windows\Recent` |

### Формат вывода

Каждый источник записывается в `<section>/<source>.raw.json`:

```json
{
  "schema_version": "2.0",
  "metadata": { "hostname": "...", "username": "...", "started_at": "...", "finished_at": "...", "output_directory": "..." },
  "source": { "source": "services", "status": "success", "record_count": 42, "errors": [] },
  "records": [ ... ]
}
```

Корневой индекс — `portable_collection.json`:

```json
{
  "schema_version": "3.0",
  "status": "success",
  "metadata": { "hostname": "...", "username": "...", "started_at": "...", "finished_at": "..." },
  "errors": []
}
```

---

## Компонент 2 — Анализатор `analyzer_web`

Локальное read-only веб-приложение на Python (stdlib only). Индексирует коллекции в SQLite, предоставляет JSON API и русскоязычный браузер данных.

### Запуск

```bash
# Из корня as3rch_portable (стандартные пути)
python3 -m analyzer_web.server

# Явные параметры
python3 -m analyzer_web.server \
    --collections output/from_portable/new \
    --database analyzer_web/state/analyzer.db \
    --host 127.0.0.1 \
    --port 8765

# Без первичного сканирования (только сервер)
python3 -m analyzer_web.server --no-initial-scan
```

Интерфейс доступен на **http://127.0.0.1:8765**

> **Важно:** внешние Python/Node-зависимости **не требуются**. Используется только стандартная библиотека Python ≥ 3.9.

> **Безопасность:** сервер не содержит аутентификации. Запускайте только на локальном интерфейсе (`127.0.0.1`). Не публикуйте на внешнем адресе без reverse-proxy и контроля доступа.

### Схема базы данных (SQLite WAL)

| Таблица | Назначение |
|---|---|
| `projects` | Каталог коллекции = один проект (PK = SHA-256 пути) |
| `sources` | Источники внутри проекта (section + name) |
| `records` | Сырые JSON-записи с порядковым номером |
| `artifacts` | Скопированные файлы с SHA-256, путём и метаданными |
| `decoded` | Декодированные записи (UserAssist, browser, AD) |
| `findings` | Автоматические наблюдения с уровнем severity |
| `search_index` | FTS5-индекс по всем JSON-записям |

### REST API

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/api/projects` | Список всех проектов |
| `GET` | `/api/projects/<id>/overview` | Сводка: метрики, статусы |
| `GET` | `/api/projects/<id>/sources[?section=]` | Источники с диагностикой |
| `GET` | `/api/projects/<id>/records?section=&source=&limit=&offset=` | Сырые записи (постранично, max 1 000) |
| `GET` | `/api/projects/<id>/decoded?decoder=&kind=` | Декодированные записи |
| `GET` | `/api/projects/<id>/findings` | Наблюдения, отсортированные по severity |
| `GET` | `/api/projects/<id>/artifacts` | Список скопированных файлов |
| `GET` | `/api/projects/<id>/artifact/<artifact_id>` | Предпросмотр файла (до 512 КБ) |
| `GET` | `/api/projects/<id>/graph?section=&focus=&layers=&limit=&offset=&q=` | Единый граф контекста |
| `GET` | `/api/projects/<id>/entity?id=` | Досье объекта графа |
| `GET` | `/api/projects/<id>/search?q=` | FTS-поиск (точная фраза, max 100) |
| `POST` | `/api/rescan` | Повторное сканирование каталога коллекций |

### Декодеры

#### UserAssist (`decoders/userassist.py`)
- ROT13-декодирование имён ключей реестра
- Подстановка KNOWN_FOLDERS GUIDов (`{374DE290-…}` → `Downloads` и т.д.)
- Парсинг структуры Windows 7+: `run_count`, `focus_count`, `focus_time_ms`, `last_execution_utc` (FILETIME)

#### Browser (`decoders/browser.py`)
- **Chromium**: History (visits + urls), downloads, Bookmarks JSON, Preferences/Secure Preferences, Local State, Extensions
- **Firefox**: places.sqlite (moz_historyvisits + moz_places), downloads, Bookmarks
- Обработка из локальной копии файла (безопасно для locked-файлов браузера)

#### Active Directory (`decoders/ad.py`)
- Декодирование objectSid (байты → `S-1-…`)
- Декодирование objectGuid (bytes_le → UUID)
- FILETIME → ISO-8601 UTC (lastLogon, pwdLastSet, accountExpires и др.)
- UAC-флаги → список имён
- groupType → scope (global/domain_local/universal) + security_enabled

#### Services (`decoders/services.py`)
- Анализ `ImagePath`: извлечение бинарного пути и аргументов, определение экранирования (кавычек)
- Детекция **Unquoted Service Path** с пробелами (вектор локального повышения привилегий, CWE-428)
- Декодирование служб `svchost.exe`: извлечение группы `-k` и фактической библиотеки `ServiceDll` из параметров
- Декодирование битовых масок `Type` (драйвер / usermode, interactive) и режимов `Start` (auto, demand, boot, disabled)
- Классификация учётных записей запуска (`system`, `nt_service`, `named`) и фильтрация локализованных `@resource` DisplayName

#### Permissions: Service ACL & File ACL (`decoders/sddl.py`)
- **Контекстная корреляция с токеном процесса (`identity/token`)**: извлечение SID и имени пользователя, а также всех неадминистративных групп токена для выявления прав, доступных непосредственно текущему оператору.
- **Service ACL**: парсинг SDDL-дескрипторов безопасности служб (`sc.exe sdshow`), трансляция алиасов субъектов безопасности (`SY`, `BA`, `BU`, `WD`, `AU`, `IU`, `NS`, `LS`) и битовых масок прав доступа (`ChangeConfig`, `WriteDacl`, `WriteOwner`, `Start`, `Stop`, `Delete`).
- Определение векторов LPE: выявление прав изменения конфигурации службы (`ChangeConfig`/`WriteDacl`/`WriteOwner`/`GenericAll`) как текущим пользователем/токеном (**Service ACL Abuse**), так и непривилегированными группами (`BUILTIN\Users`, `Everyone`, `Authenticated Users`). Проверка прав перезапуска (`Start`/`Stop`).
- **File ACL**: сопоставление прав файловой системы (`FullControl`, `Modify`, `Write`, `CreateFiles`), классификация типов объектов (исполняемые бинарники служб, файлы конфигурации `.config`/`.xml`/`.ini`/`.ovpn`/etc., общие каталоги).
#### Recent & Jump Lists (`decoders/recent.py`)
- Парсинг CSV-экспортов Jump Lists (`AutomaticDestinations.csv`, `CustomDestinations.csv`, в т.ч. из каталога `procede_recent/`)
- Распознавание известных AppID приложений (Edge, VS Code, PowerShell ISE, Explorer, Notepad, cmd, Wordpad и др.)
- Извлечение целевых путей файлов, аргументов командной строки (URL, скрипты, параметры), меток времени (Created/Modified/Accessed) и счетчиков запусков (`interaction_count`, `mru`)
- Автоматический OffSec-анализ подозрительной активности: поиск запуска реверс-шеллов (`revshell.ps1`, `RS_wth_bypass.ps1`), утилит удаленного доступа/эксплуатации (`QuasarRAT`, инжекторы), обращений к дампам паролей (`passwords.json`, `autofill/passwords`, `chrome-elevator`)

### Автоматические наблюдения (Findings)

| Severity | Условие |
|---|---|
| `critical` | Модификация конфигурации службы текущим пользователем или непривилегированными учётками (Service ACL Abuse / Weak DACL: `ChangeConfig`, `WriteDacl`, `WriteOwner`) |
| `critical` | Исполняемый файл службы доступен на запись текущему пользователю или обычным пользователям (Writable Service Binary) |
| `high` | Конфигурационный файл (`.config`, `web.config`, `.ini`, `.ovpn`, etc.) доступен на запись (Writable Configuration File) |
| `high` | Подозрительная недавняя активность в Recent / JumpLists (запуск реверс-шеллов, утилит эксплуатации, обращение к дампам паролей) |
| `high` | `SeImpersonatePrivilege` включён в токене процесса |
| `high` | Группа `BUILTIN\Administrators` включена в токене |
| `high` | Обнаружен неэкранированный путь службы с пробелами (Unquoted Service Path) |
| `medium` | Служба запускается от имени именованной учётной записи (не NT AUTHORITY/NT SERVICE) |
| `medium` | Каталог или файл общего доступа доступен на запись пользователям (Writable Shared Path) |
| `info` | Открытые TCP-порты: FTP/SSH/HTTP/RPC/NetBIOS/HTTPS/SMB/MSSQL/RDP/WinRM |
| `low` | Источник завершился со статусом, отличным от `success`/`skipped`/`not_found` |

### Граф связей

Доступен для разделов: **network**, **logs**, **domain**, **identity**.

- **network**: процессы → слушающие порты → службы (сопоставление по PID; пунктир = по пути EXE)
- **logs**: службы → учётки запуска + события установки (Event ID 7045)
- **domain**: объекты AD → member/memberOf → SPN → делегирование
- **identity**: токен → группы + привилегии

Параметр `limit` (2–24, по умолчанию 18) контролирует максимальное число показываемых соседних узлов.

### Разделы веб-интерфейса

| Раздел | Описание |
|---|---|
| Обзор проекта | Метрики, хост, идентификатор, статус |
| Контекст учётной записи | identity: токен, профили, ОС |
| Логи и службы | logs: службы, история, задачи, UserAssist |
| Сеть | network: TCP/UDP, ARP, маршруты |
| Домен AD | domain: пользователи, группы, SPN |
| Конфигурации | configs: IIS, SQL Server, VPN, .NET |
| Права доступа | permissions: ACL файлов и служб |
| Браузеры | browser: история, загрузки, закладки |
| Недавние файлы | recent: Jump Lists (Automatic/Custom Destinations), LNK, история открытых файлов и параметров запуска |
| Сохранённые файлы | artifacts: предпросмотр скопированных файлов |
| Качество сбора | health: диагностика по всем источникам |

---

## Тесты

```bash
python3 -m unittest discover -s analyzer_web/tests -v
```

Покрытие:
- `test_core.py` — изоляция путей артефактов (path traversal)
- `test_decoders.py` — UserAssist, AD SID/GUID/UAC, browser parsers, recent Jump Lists CSV
- `test_context.py` — единый граф, изоляция проектов и AD ACL

---

## Известные ограничения

- Прямой парсинг бинарных Shell Bags не производится; бинарные LNK и Jump Lists обрабатываются через сырые метаданные или предварительно экспортированные CSV-отчеты.
- UserAssist нестандартных форматов (до Windows 7) остаётся с `decode_status=unsupported`.
- Браузерные SQLite обрабатываются из копии коллектора; снимок мог быть несогласованным.
- Эффективные ACL конкретной учётной записи не вычисляются.
- AD-граф использует только явные member/memberOf, servicePrincipalName и msDS-AllowedToDelegateTo.
- Граф показывает только непосредственных соседей выбранного объекта.
- Общий svchost.exe/dllhost.exe не сопоставляются со службами по пути EXE.
- Имена технических полей в деталях не переводятся.

---

## Требования

| Компонент | Требования |
|---|---|
| Коллектор | Windows PowerShell 5.1+ или PowerShell 7+; .NET 4.5+ |
| Анализатор | Python 3.9+ (только stdlib); Linux / macOS / Windows |
| Браузер | Любой современный с поддержкой ES-модулей |
