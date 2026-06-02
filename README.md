# ARFSearch v2 (WinRM)

Обзор проекта arfsearch v2 (winrm)
Это небольшая, но гибко построенная CLI‑утилита для удалённого сбора артефактов с Windows‑машин через протокол WinRM (поддержка SSH будет добавлена позже).

Она состоит из нескольких независимых компонентов, которые взаимодействуют так:


CLI  →  WinRMTransport  →  remote staging dir
     └─► deploy runner.ps1 + modules
                 │
                 └─► run module scripts (collect.ps1)
                         │
                         └─► zip → download → output/
Ниже подробно описаны основные части и типовые сценарии их применения.

1. Конфигурация
Файл	Что хранит	Пример
config/targets.json	Список удалённых хостов, учётные данные и выбранный протокол. Поддерживает обычный пароль и / или NTLM‑hash (pass‑the‑hash).	{"adminWiNTLM": {"ip":"10.33.78.189","user":"Администратор","nthash":"06ced7…","proto":"winrm"}}
config/settings.json	Параметры встроенного HTTP‑серверa, используемого для передачи файлов по WinRM.	{"http_listen_address":"10.33.78.8","http_port":8888,"http_server_auto_stop":true}
Как добавить цель – через пункт меню 2. Add target в CLI. При вводе “NTLM hash” пользователь может указать LMhash:NThash or NThash (см. cli/cli.py:115‑131).

2. Основное приложение – cli/cli.py
Функция	Описание	Ключевые места кода
Загрузка/сохранение целей	load_targets() умеет мигрировать старый формат (IP → {user,…}) в новый (name → {ip,…}).	25‑48
Главное меню	Позволяет List targets, Add target, Connect & Operate, Quit.	66‑84
Подключение	Создаёт объект WinRMTransport, передаёт корень проекта (project_root) в deploy(), после чего открывается remote_menu.	135‑189
Удалённое меню	Выбор модулей: logs, recent, browser или ALL; затем cleanup() и retrieve_archive().	198‑224
При выборе 3. Connect & Operate пользователь видит список целей, выбирает одну (по номеру, имени или IP) и запускает сессию.

3. Транспорт WinRM – cli/transport/winrm_transport.py
Компонент	Что делает	Ссылка в коде
Инициализация	Формирует URL http://<IP>:5985/wsman, создаёт NTCredential (по паролю или NTLM‑hash), открывает SPNEGOTransport и Runspace.	17‑45
Создание временной директории	Получает $env:TEMP на цели, создаёт поддиректорию collector_<8‑hex> для всех артефактов.	48‑56
Загрузка файлов	Через EvilShell.upload() отправляет runner.ps1 и весь каталог modules/.	89‑108
Деплой	Создаёт структуру runner/, modules/, output/ на удалённой машине; проверяет права администратора; сохраняет privilege.json.	110‑131
Запуск модуля	Формирует команду powershell -File runner.ps1 <module‑cmd> и выводит stdout / stderr.	144‑154
Получение архива	Находит последний *.zip в <remote_base>\output, скачивает его в локальную папку output/.	155‑171
Очистка	Удаляет удалённую staging‑директорию и закрывает Runspace.	173‑180
EvilShell – небольшая обёртка, реализующая загрузку/скачивание файлов по WinRM без использования SMB.

4. Модуль‑сборщики
Каждый модуль – отдельный каталог modules/<name>/ с описанием manifest.json и скриптом collect.ps1.

Скрипт получает путь к директории вывода ($OutputPath), собирает нужные артефакты, формирует JSON‑отчёт и сохраняет его в <OutputPath>/<module>.json.

4.1 modules/logs
Артефакт	Описание
services	Список установленных сервисов из реестра (HKLM:\SYSTEM\CurrentControlSet\Services\*).
user_assist	Raw‑данные UserAssist (Base64‑закодированные бинарные блоки).
service_events	Последние 50 событий ID 7045 (установка сервисов) из журнала System.
Скрипт – modules/logs/collect.ps1 (строки 4‑45). Формирует объект metadata (hostname, username, timestamp, module) и сохраняет как logs.json.

4.2 modules/recent
Артефакт	Описание
automatic_destinations	CSV‑файлы AutomaticDestinations из Recent‑папки, разобранные в объекты (путь, тайм‑стамп, …).
custom_destinations	CSV‑файлы CustomDestinations – аналогично.
Скрипт – modules/recent/collect.ps1 (строки 2‑66). Для анализа использует JLECmd.exe, который должен находиться рядом с скриптом (см. manifest.json → dependencies). Результат сохраняется в recent.json.

4.3 modules/browser (не просмотрено полностью)
По manifest.json в modules/browser/ присутствует файл collect.ps1, который собирает браузерные артефакты (историю, cookies, cache и т.п.) и сохраняет их в browser.json. Структура аналогична другим модулям.

4.4 “ALL” (collect all)
Команда collect all в удалённом меню последовательно вызывает все модули в каталоге modules/. После выполнения каждый модуль создаёт собственный JSON‑файл, а затем всё упаковывается в один zip‑архив, который скачивается клиентом.

5. Как работает процесс в реальном мире
Шаг 1 Подготовка целей
Открыть config/targets.json в редакторе или добавить цель через CLI.
При необходимости указать NTLM‑hash вместо пароля (полезно, если пароль неизвестен, но есть хеш).
Шаг 2 Запуск CLI

$ python cli/cli.py
=== Artifact Collector CLI (MVP) ===
[MAIN MENU]
1. List targets
2. Add target
3. Connect & Operate
q. Quit
Выбрать 3 → выбрать цель → будет выполнена попытка подключения по WinRM.
Шаг 3 Деплой и проверка прав
WinRMTransport создаёт временную папку на удалённой машине, копирует runner.ps1 + все модули, проверяет, является ли пользователь администратором, и сохраняет privilege.json.
Шаг 4 Сбор артефактов
Выбор в удалённом меню	Что происходит
1 — Run logs	Собирает сервисы, UserAssist, события 7045 → logs.json.
2 — Run recent	Запускает JLECmd, парсит Recent‑файлы → recent.json.
3 — Run browser	Сбор данных браузера (history, cookies и т.д.) → browser.json.
4 — Run ALL	Последовательно запускает все выше‑перечисленные модули.
5 — Disconnect	Останавливает HTTP‑сервер (если включён), удаляет staging‑директорию, закрывает соединение.
Шаг 5 Загрузка и дальнейший анализ
После выполнения выбранного модуля автоматически вызывается retrieve_archive().
На локальной машине в каталоге output/ появляется файл вида col_20260601_113819_1656.zip.
Пользователь может распаковать архив и изучить JSON‑отчёты (например, logs.json, recent.json, browser.json).
Шаг 6 Очистка
При выходе из меню (5) вызывается cleanup(), который удаляет полностью директорию collector_<id> на удалённом хосте, тем самым стирая все оставшиеся артефакты.
6. Типовые сценарии использования
Сценарий	Когда применяют	Что получает аналитик
Инцидент‑реакция (IR)	После обнаружения компрометации Windows‑сервера.	Список установленных сервисов, события создания сервисов (7045), пользовательскую активность (UserAssist), недавно открытые файлы (Recent), браузерную историю.
Pen‑testing – Post‑exploitation	После получения доступа к системе (например, через Pass‑the‑Hash).	Быстрый «snapshot» текущего состояния системы, проверка наличия админ‑прав (privilege.json).
Forensic‑analysis	При расследовании утечек данных.	Полный набор артефактов, упакованных в один zip‑архив, легко передаваемый в SIEM/ELK.
Аудит конфигураций	При проверке соответствия политике (e.g., отключённые сервисы).	Список всех сервисов с их типом, стартовым типом, путём к исполняемому файлу.
Тестирование защиты	Чтобы убедиться, что антивирус/EDR правильно блокирует evil_winrm и JLECmd.	При ошибке run_module выводит stderr, что позволяет увидеть, какие команды блокируются.
Автоматизированный сбор	В CI‑pipeline для периодической проверки состояния наборов Windows‑рабочих станций.	Скрипт run (внутри CI) запускает python cli/cli.py в без‑интерактивном режиме (можно добавить параметры командной строки).
7. Расширяемость проекта
Новые модули – достаточно добавить папку modules/<name>/ со manifest.json и collect.ps1.

В manifest.json задаётся requires_admin (по‑надобности), список artifacts и output_format.
collect.ps1 обязателен принимать параметр $OutputPath и сохранять JSON‑файл с тем же именем модуля.
Поддержка SSH – сейчас в cli/cli.py есть заглушка (else: print("[!] SSH transport not implemented yet.")). Добавив класс SSHTransport (по аналогии с WinRMTransport) и соответствующие зависимости, можно расширить протокол.

Дополнительные настройки – любые новые параметры (например, timeout, proxy) могут быть добавлены в config/settings.json и прочитаны в WinRMTransport.__init__.

8. Краткая карта кода (ссылки)
Файл	Что в нём	Ссылка
cli/cli.py	Основное интерактивное приложение, меню, работа с targets.json и settings.json.	cli/cli.py
cli/transport/winrm_transport.py	Класс WinRMTransport: соединение, загрузка, запуск, сбор, очистка.	cli/transport/winrm_transport.py
config/targets.json	Список целей/учётных данных.	config/targets.json
config/settings.json	Параметры HTTP‑сервера, используемого evil_winrm.	config/settings.json
modules/logs/collect.ps1	Сбор сервисов, UserAssist, событий 7045 → logs.json.	modules/logs/collect.ps1
modules/recent/collect.ps1	Анализ Recent‑папки через JLECmd.exe → recent.json.	modules/recent/collect.ps1
modules/browser/collect.ps1 (не открывался полностью)	Сбор браузерных артефактов → browser.json.	modules/browser/
runner/runner.ps1 (не открыт)	Скрипт‑обёртка, вызываемая удалённо; запускает выбранный модуль и упаковывает output/*.json в zip.	runner/runner.ps1
9. Как начать работу (пошагово)

# 1. Установить зависимости (colorama, paramiko‑/evil_winrm‑версия и т.п.)
pip install -r cli/requirements.txt   # если файл существует

# 2. Добавить цель
python cli/cli.py
#   → 2. Add target → вписать IP, User, Password/NTLM‑hash, протокол (winrm)

# 3. Подключиться и собрать артефакты
python cli/cli.py
#   → 3. Connect & Operate → выбрать цель → 4. Run ALL (или любой отдельный модуль)

# 4. После завершения будет выведено сообщение о скачанном zip‑файле.
#    Распаковать и просмотреть JSON‑отчёты:
unzip output/col_*.zip -d collected/
jq . collected/logs.json   # пример просмотра
10. Возможные улучшения (по желанию)
Направление	Что добавить
Автоматический парсинг	После загрузки zip‑архива автоматически генерировать короткие отчёты (markdown/HTML) через jq или Python‑скрипт.
Поддержка SSH	Реализовать SSHTransport (использовать paramiko) и добавить ssh‑опцию в targets.json.
Модуль‑плагин‑менеджер	Динамически сканировать modules/ и выводить их в меню без необходимости ручного обновления кода.
Отчёты в базе	Интегрировать с ELK/Graylog: после скачивания автоматически отправлять JSON в HTTP‑endpoint.
Тесты	Добавить unit‑тесты для load_targets(), WinRMTransport._run_ps() (мока) и скриптов PowerShell.
Итог
Проект – модульный, расширяемый CLI‑инструмент для удалённого сбора Windows‑артефактов через WinRM.

Он позволяет быстро собрать сервисы, историю пользовательской активности, недавние файлы и браузерные данные, упаковать их в один архив и вернуть результат на локальную машину, где их можно проанализировать в рамках инцидент‑реакции, penetration‑testing или forensic‑analysis.

Если потребуется добавить новые типы артефактов, достаточно создать новый модуль‑папку с manifest.json и collect.ps1, а остальная инфраструктура уже готова к их вызову.
